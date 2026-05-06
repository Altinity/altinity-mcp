package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/altinity/altinity-mcp/pkg/clickhouse"
	"github.com/altinity/altinity-mcp/pkg/config"
	"github.com/altinity/altinity-mcp/pkg/jwe_auth"
	altinitymcp "github.com/altinity/altinity-mcp/pkg/server"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/urfave/cli/v3"
)

var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"

	// loggingMutex protects global zerolog state during setupLogging calls
	loggingMutex sync.Mutex
)

func main() {
	if err := run(os.Args); err != nil {
		log.Fatal().Err(err).Msg("Application failed")
	}
}

// run contains the main application logic, extracted for testability
func run(args []string) error {
	app := &cli.Command{
		Name:        "altinity-mcp",
		Usage:       "Altinity MCP Server - ClickHouse Model Context Protocol Server",
		Description: "A Model Context Protocol (MCP) server that provides tools for interacting with ClickHouse databases",
		Version:     fmt.Sprintf("%s (%s) built on %s", version, commit, date),
		Authors:     []any{"Altinity <support@altinity.com>"},
		Flags: append(
			// Special flags that don't live in config.Config (file path, openapi
			// shorthand) or that are read before config is loaded (config,
			// config-reload-time). Everything else is generated from struct tags
			// in pkg/config/config.go via config.BuildFlags.
			[]cli.Flag{
				&cli.StringFlag{
					Name:    "config",
					Usage:   "Path to configuration file (YAML or JSON)",
					Sources: cli.EnvVars("CONFIG_FILE"),
				},
				&cli.IntFlag{
					Name:    "config-reload-time",
					Usage:   "Configuration reload interval in seconds (0 to disable)",
					Sources: cli.EnvVars("CONFIG_RELOAD_TIME"),
				},
				&cli.StringFlag{
					Name:    "openapi",
					Usage:   "Enable OpenAPI endpoints (disable|http|https)",
					Value:   "disable",
					Sources: cli.EnvVars("MCP_OPENAPI"),
				},
			},
			config.BuildFlags(&config.Config{})...,
		),
		Before: func(ctx context.Context, cmd *cli.Command) (context.Context, error) {
			// Setup logging
			err := setupLogging(cmd.String("log-level"))
			return ctx, err
		},
		Action: runServer,
		Commands: []*cli.Command{
			{
				Name:  "version",
				Usage: "Show version information",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					fmt.Printf("altinity-mcp version %s\n", version)
					fmt.Printf("Commit: %s\n", commit)
					fmt.Printf("Built: %s\n", date)
					return nil
				},
			},
			{
				Name:  "test-connection",
				Usage: "Test connection to ClickHouse",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					cfg, err := buildConfig(cmd)
					if err != nil {
						return err
					}
					return testConnection(ctx, cfg.ClickHouse)
				},
			},
		},
	}

	return app.Run(context.Background(), args)
}

// setupLogging configures the global logger
func setupLogging(level string) error {
	loggingMutex.Lock()
	defer loggingMutex.Unlock()

	// Configure zerolog
	zerolog.TimeFieldFormat = time.RFC3339
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: "15:04:05"})

	// Set log level
	switch strings.ToLower(level) {
	case "debug":
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	case "error":
		zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	case "warn":
		zerolog.SetGlobalLevel(zerolog.WarnLevel)
	case "info", "":
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	default:
		return fmt.Errorf("invalid log level: %s", level)
	}

	log.Debug().Str("logging_level", level).Msg("Logging configured")
	return nil
}

// createTokenInjector creates a middleware that injects JWE token from various sources into request context
func (a *application) createTokenInjector() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var token string

			// Try Authorization header (Bearer or Basic)
			authHeader := r.Header.Get("Authorization")
			if strings.HasPrefix(authHeader, "Bearer ") {
				token = strings.TrimPrefix(authHeader, "Bearer ")
			} else if strings.HasPrefix(authHeader, "Basic ") {
				token = strings.TrimPrefix(authHeader, "Basic ")
			}

			// Try x-altinity-mcp-key header
			if token == "" {
				token = r.Header.Get("x-altinity-mcp-key")
			}

			// Try to extract token from URL path
			if token == "" {
				token = r.PathValue("token")
			}

			// Inject token into request context if found
			if token != "" {
				ctx := context.WithValue(r.Context(), altinitymcp.JWETokenKey, token)
				if a.mcpServer != nil {
					if claims, err := a.mcpServer.ParseJWEClaims(token); err == nil && claims != nil {
						ctx = context.WithValue(ctx, altinitymcp.JWEClaimsKey, claims)
					}
				}
				r = r.WithContext(ctx)
			}
			next.ServeHTTP(w, r)
		})
	}
}

// dynamicToolsInjector creates a middleware that ensures dynamic tools are loaded
func (a *application) dynamicToolsInjector(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := a.mcpServer.EnsureDynamicTools(r.Context()); err != nil {
			// Log error but continue, static tools should still work
			log.Warn().Err(err).Msg("Failed to ensure dynamic tools")
		}
		next.ServeHTTP(w, r)
	})
}

// stripTrailingSlash normalizes paths to remove a single trailing slash (except root)
func stripTrailingSlash(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" && strings.HasSuffix(r.URL.Path, "/") {
			r.URL.Path = strings.TrimSuffix(r.URL.Path, "/")
		}
		next.ServeHTTP(w, r)
	})
}

// transportRoutePatterns returns the mux patterns to register for the given
// transport. Passing an empty transport string serves the MCP protocol at the
// root path ("/" and "/{token}") — used for the HTTP transport so clients
// connect to "https://server/" instead of "https://server/http".
func transportRoutePatterns(jweEnabled, oauthEnabled bool, transport string) []string {
	var base, tokenBase string
	if transport == "" {
		base = "/"
		tokenBase = "/{token}"
	} else {
		base = "/" + transport
		tokenBase = "/{token}/" + transport
	}
	if jweEnabled {
		patterns := []string{tokenBase}
		if oauthEnabled {
			patterns = append(patterns, base)
		}
		return patterns
	}
	return []string{base}
}

func openAPIRoutePatterns(jweEnabled, oauthEnabled bool) []string {
	tokenized := []string{
		"/{token}/openapi",
		"/{token}/openapi/",
		"/{token}/openapi/list_tables",
		"/{token}/openapi/describe_table",
		"/{token}/openapi/execute_query",
	}
	pathless := []string{
		"/openapi",
		"/openapi/",
		"/openapi/list_tables",
		"/openapi/describe_table",
		"/openapi/execute_query",
	}

	switch {
	case jweEnabled && oauthEnabled:
		// Exact /openapi remains unauthenticated schema discovery in combined mode.
		// Skip /openapi/ (index 1) — stripTrailingSlash handles it, and it conflicts with /{token}/openapi/.
		return append(tokenized, pathless[2:]...)
	case jweEnabled:
		return tokenized
	default:
		return pathless
	}
}

// jweTokenGeneratorHandler handles requests for generating JWE tokens.
func (a *application) jweTokenGeneratorHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	cfg := a.GetCurrentConfig()
	if cfg.Server.JWE.JWESecretKey == "" {
		http.Error(w, "Missing JWE secret key", http.StatusInternalServerError)
		return
	}
	if !cfg.Server.JWE.Enabled {
		http.Error(w, "JWE authentication is not enabled", http.StatusForbidden)
		return
	}

	var reqBody struct {
		Host                  string `json:"host"`
		Port                  int    `json:"port"`
		Database              string `json:"database"`
		Username              string `json:"username"`
		Password              string `json:"password"`
		Protocol              string `json:"protocol"`
		Expiry                int    `json:"expiry"` // in seconds
		Limit                 int    `json:"limit,omitempty"`
		TLSEnabled            bool   `json:"tls_enabled,omitempty"`
		TLSCaCert             string `json:"tls_ca_cert,omitempty"`
		TLSClientCert         string `json:"tls_client_cert,omitempty"`
		TLSClientKey          string `json:"tls_client_key,omitempty"`
		TLSInsecureSkipVerify bool   `json:"tls_insecure_skip_verify,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request body parsing error: %v", err), http.StatusBadRequest)
		return
	}

	if reqBody.Expiry == 0 {
		reqBody.Expiry = 3600 // default to 1 hour
	}

	claims := map[string]interface{}{
		"exp": time.Now().Add(time.Duration(reqBody.Expiry) * time.Second).Unix(),
	}

	// Add optional claims if provided
	if reqBody.Host != "" {
		claims["host"] = reqBody.Host
	}
	if reqBody.Port > 0 {
		claims["port"] = reqBody.Port
	}
	if reqBody.Database != "" {
		claims["database"] = reqBody.Database
	}
	if reqBody.Username != "" {
		claims["username"] = reqBody.Username
	}
	if reqBody.Password != "" {
		claims["password"] = reqBody.Password
	}
	if reqBody.Protocol != "" {
		claims["protocol"] = reqBody.Protocol
	}
	if reqBody.Limit > 0 {
		claims["limit"] = reqBody.Limit
	}
	if reqBody.TLSEnabled {
		claims["tls_enabled"] = true
		if reqBody.TLSCaCert != "" {
			claims["tls_ca_cert"] = reqBody.TLSCaCert
		}
		if reqBody.TLSClientCert != "" {
			claims["tls_client_cert"] = reqBody.TLSClientCert
		}
		if reqBody.TLSClientKey != "" {
			claims["tls_client_key"] = reqBody.TLSClientKey
		}
		if reqBody.TLSInsecureSkipVerify {
			claims["tls_insecure_skip_verify"] = true
		}
	}

	encryptedToken, err := jwe_auth.GenerateJWEToken(claims, []byte(cfg.Server.JWE.JWESecretKey), []byte(cfg.Server.JWE.JWTSecretKey))
	if err != nil {
		log.Error().Err(err).Msg("Failed to generate JWE token")
		http.Error(w, "Failed to generate JWE token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"token": encryptedToken})
}

// startHTTPServerWithTLS starts the HTTP server with or without TLS
func (a *application) startHTTPServerWithTLS(cfg config.Config, addr, transport string) error {
	if transport == "http" {
		// HTTP transport is served at root
		if cfg.Server.JWE.Enabled {
			addr += "/{token}"
		}
	} else {
		if cfg.Server.JWE.Enabled {
			addr += "/{token}/" + transport
		} else {
			addr += "/" + transport
		}
	}
	if !cfg.Server.TLS.Enabled {
		protocol := "http"
		log.Info().Str("url", fmt.Sprintf("%s://%s", protocol, addr)).Msg("HTTP server listening")
		if err := a.httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error().Err(err).Msg("HTTP server failed")
			return err
		}
	} else {
		protocol := "https"
		log.Info().Str("url", fmt.Sprintf("%s://%s", protocol, addr)).Msg("HTTPS server listening")
		tlsConfig, err := buildServerTLSConfig(&cfg.Server.TLS)
		if err != nil {
			log.Error().Err(err).Msg("Failed to build server TLS config")
			return err
		}
		a.httpSrv.TLSConfig = tlsConfig
		if err = a.httpSrv.ListenAndServeTLS(cfg.Server.TLS.CertFile, cfg.Server.TLS.KeyFile); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error().Err(err).Msg("HTTPS server failed")
			return err
		}
	}
	return nil
}

// startSTDIOServer starts the STDIO transport server
func (a *application) startSTDIOServer(mcpServer *mcp.Server) error {
	log.Info().Msg("Starting MCP server with STDIO transport")

	ctx, cancel := context.WithCancel(context.Background())
	ctx = context.WithValue(ctx, altinitymcp.CHJWEServerKey, a.mcpServer)
	defer cancel()

	// Set up signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT)

	go func() {
		<-sigChan
		cancel()
	}()

	transport := &mcp.StdioTransport{}
	if err := mcpServer.Run(ctx, transport); err != nil {
		log.Error().Err(err).Msg("STDIO server failed")
		return err
	}
	return nil
}

// startHTTPServer starts the HTTP transport server
func (a *application) startHTTPServer(cfg config.Config, mcpServer *mcp.Server) error {
	addr := fmt.Sprintf("%s:%d", cfg.Server.Address, cfg.Server.Port)
	log.Info().
		Str("address", addr).
		Msg("Starting MCP server with Streaming HTTP transport")
	openAPIProtocol := "http"
	if cfg.Server.OpenAPI.TLS {
		openAPIProtocol = "https"
	}

	authInjector := a.createMCPAuthInjector(cfg)
	serverInjector := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), altinitymcp.CHJWEServerKey, a.mcpServer)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
	serverInjectorOpenAPI := func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), altinitymcp.CHJWEServerKey, a.mcpServer)
		a.mcpServer.OpenAPIHandler(w, r.WithContext(ctx))
	}
	serverInjectorSchema := func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), altinitymcp.CHJWEServerKey, a.mcpServer)
		a.mcpServer.ServeOpenAPISchema(w, r.WithContext(ctx))
	}

	corsHandler := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", cfg.Server.CORSOrigin)
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Altinity-MCP-Key, Mcp-Protocol-Version, Referer, User-Agent")
			w.Header().Set("Access-Control-Max-Age", "86400")

			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusOK)
				return
			}

			next.ServeHTTP(w, r)
		})
	}

	var httpHandler http.Handler
	if cfg.Server.JWE.Enabled {
		log.Info().Msg("Using dynamic base path for JWE authentication")

		tokenInjector := a.createTokenInjector()
		dtInjector := a.dynamicToolsInjector
		httpServer := mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
			return mcpServer
		}, nil)

		mux := http.NewServeMux()
		transportHandler := serverInjector(tokenInjector(dtInjector(httpServer)))
		if cfg.Server.OAuth.Enabled {
			transportHandler = serverInjector(authInjector(dtInjector(httpServer)))
		}
		for _, pattern := range transportRoutePatterns(cfg.Server.JWE.Enabled, cfg.Server.OAuth.Enabled, "") {
			mux.Handle(pattern, transportHandler)
		}
		if cfg.Server.OpenAPI.Enabled {
			mux.HandleFunc("/openapi", serverInjectorSchema)
			for _, pattern := range openAPIRoutePatterns(cfg.Server.JWE.Enabled, cfg.Server.OAuth.Enabled) {
				mux.HandleFunc(pattern, serverInjectorOpenAPI)
			}
			openAPIPath := "/{token}/openapi"
			if cfg.Server.OAuth.Enabled {
				openAPIPath = "/openapi"
			}
			log.Info().Str("url", fmt.Sprintf("%s://%s:%d%s", openAPIProtocol, cfg.Server.Address, cfg.Server.Port, openAPIPath)).Msg("OpenAPI server listening")
		}
		mux.HandleFunc("/health", a.healthHandler)
		mux.HandleFunc("/livez", a.livenessHandler)
		mux.HandleFunc("/jwe-token-generator", a.jweTokenGeneratorHandler)
		a.registerOAuthHTTPRoutes(mux)
		httpHandler = stripTrailingSlash(corsHandler(mux))
	} else {
		// Use standard HTTP server without dynamic paths
		httpServer := mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
			return mcpServer
		}, nil)
		dtInjector := a.dynamicToolsInjector
		mux := http.NewServeMux()
		transportHandler := serverInjector(dtInjector(httpServer))
		if cfg.Server.OAuth.Enabled {
			transportHandler = serverInjector(authInjector(dtInjector(httpServer)))
		}
		for _, pattern := range transportRoutePatterns(cfg.Server.JWE.Enabled, cfg.Server.OAuth.Enabled, "") {
			mux.Handle(pattern, transportHandler)
		}
		if cfg.Server.OpenAPI.Enabled {
			for _, pattern := range openAPIRoutePatterns(cfg.Server.JWE.Enabled, cfg.Server.OAuth.Enabled) {
				mux.HandleFunc(pattern, serverInjectorOpenAPI)
			}
			log.Info().Str("url", fmt.Sprintf("%s://%s:%d/openapi", openAPIProtocol, cfg.Server.Address, cfg.Server.Port)).Msg("OpenAPI server listening")
		}
		mux.HandleFunc("/health", a.healthHandler)
		mux.HandleFunc("/livez", a.livenessHandler)
		mux.HandleFunc("/jwe-token-generator", a.jweTokenGeneratorHandler)
		a.registerOAuthHTTPRoutes(mux)
		httpHandler = stripTrailingSlash(corsHandler(mux))
	}

	a.setHTTPServer(&http.Server{
		Addr:    addr,
		Handler: httpHandler,
	})

	return a.startHTTPServerWithTLS(cfg, addr, "http")
}

// startSSEServer starts the SSE transport server
// Note: The official go-sdk has a dedicated SSEHandler for the legacy SSE transport
func (a *application) startSSEServer(cfg config.Config, mcpServer *mcp.Server) error {
	addr := fmt.Sprintf("%s:%d", cfg.Server.Address, cfg.Server.Port)
	log.Info().
		Str("address", addr).
		Msg("Starting MCP server with SSE transport")

	authInjector := a.createMCPAuthInjector(cfg)
	serverInjector := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), altinitymcp.CHJWEServerKey, a.mcpServer)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
	serverInjectorOpenAPI := func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), altinitymcp.CHJWEServerKey, a.mcpServer)
		a.mcpServer.OpenAPIHandler(w, r.WithContext(ctx))
	}
	serverInjectorSchema := func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), altinitymcp.CHJWEServerKey, a.mcpServer)
		a.mcpServer.ServeOpenAPISchema(w, r.WithContext(ctx))
	}

	corsHandler := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", cfg.Server.CORSOrigin)
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Altinity-MCP-Key, Mcp-Protocol-Version, Referer, User-Agent")
			w.Header().Set("Access-Control-Max-Age", "86400")

			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusOK)
				return
			}

			next.ServeHTTP(w, r)
		})
	}

	openAPIProtocol := "http"
	if cfg.Server.OpenAPI.TLS {
		openAPIProtocol = "https"
	}

	var sseHandler http.Handler
	if cfg.Server.JWE.Enabled {
		log.Info().Msg("Using dynamic base path for JWE authentication")

		tokenInjector := a.createTokenInjector()
		dtInjector := a.dynamicToolsInjector

		// Use SSEHandler for legacy SSE transport
		sseServer := mcp.NewSSEHandler(func(r *http.Request) *mcp.Server {
			return mcpServer
		}, nil)

		mux := http.NewServeMux()
		transportHandler := serverInjector(tokenInjector(dtInjector(sseServer)))
		if cfg.Server.OAuth.Enabled {
			transportHandler = serverInjector(authInjector(dtInjector(sseServer)))
		}
		for _, pattern := range transportRoutePatterns(cfg.Server.JWE.Enabled, cfg.Server.OAuth.Enabled, "sse") {
			mux.Handle(pattern, transportHandler)
		}
		if cfg.Server.OpenAPI.Enabled {
			mux.HandleFunc("/openapi", serverInjectorSchema)
			for _, pattern := range openAPIRoutePatterns(cfg.Server.JWE.Enabled, cfg.Server.OAuth.Enabled) {
				mux.HandleFunc(pattern, serverInjectorOpenAPI)
			}
			openAPIPath := "/{token}/openapi"
			if cfg.Server.OAuth.Enabled {
				openAPIPath = "/openapi"
			}
			log.Info().Str("url", fmt.Sprintf("%s://%s:%d%s", openAPIProtocol, cfg.Server.Address, cfg.Server.Port, openAPIPath)).Msg("OpenAPI server listening")
		}
		mux.HandleFunc("/health", a.healthHandler)
		mux.HandleFunc("/livez", a.livenessHandler)
		mux.HandleFunc("/jwe-token-generator", a.jweTokenGeneratorHandler)
		a.registerOAuthHTTPRoutes(mux)
		sseHandler = stripTrailingSlash(corsHandler(mux))
	} else {
		// Use SSEHandler for legacy SSE transport
		sseServer := mcp.NewSSEHandler(func(r *http.Request) *mcp.Server {
			return mcpServer
		}, nil)
		dtInjector := a.dynamicToolsInjector
		mux := http.NewServeMux()
		transportHandler := serverInjector(dtInjector(sseServer))
		if cfg.Server.OAuth.Enabled {
			transportHandler = serverInjector(authInjector(dtInjector(sseServer)))
		}
		for _, pattern := range transportRoutePatterns(cfg.Server.JWE.Enabled, cfg.Server.OAuth.Enabled, "sse") {
			mux.Handle(pattern, transportHandler)
		}
		if cfg.Server.OpenAPI.Enabled {
			for _, pattern := range openAPIRoutePatterns(cfg.Server.JWE.Enabled, cfg.Server.OAuth.Enabled) {
				mux.HandleFunc(pattern, serverInjectorOpenAPI)
			}
			log.Info().Str("url", fmt.Sprintf("%s://%s:%d/openapi", openAPIProtocol, cfg.Server.Address, cfg.Server.Port)).Msg("OpenAPI server listening")
		}
		mux.HandleFunc("/health", a.healthHandler)
		mux.HandleFunc("/livez", a.livenessHandler)
		mux.HandleFunc("/jwe-token-generator", a.jweTokenGeneratorHandler)
		a.registerOAuthHTTPRoutes(mux)
		sseHandler = stripTrailingSlash(corsHandler(mux))
	}

	a.setHTTPServer(&http.Server{
		Addr:    addr,
		Handler: sseHandler,
	})

	return a.startHTTPServerWithTLS(cfg, addr, "sse")
}

// livenessHandler provides a process-level health check endpoint for liveness probes.
func (a *application) livenessHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    "alive",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"version":   version,
	})
}

// healthHandler provides a readiness check endpoint for Kubernetes probes.
func (a *application) healthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	// Get current config (thread-safe)
	cfg := a.GetCurrentConfig()

	// For basic health check, we'll return 200 OK
	// For readiness, we should test ClickHouse connection if JWE auth is disabled
	ctx := r.Context()
	var cancel context.CancelFunc
	if !cfg.ClickHouse.ReadOnly {
		ctx, cancel = context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
	}
	status := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"version":   version,
	}

	// Test ClickHouse connection for readiness, unless credentials are per-request
	credentialsArePerRequest := cfg.Server.JWE.Enabled ||
		(cfg.Server.OAuth.Enabled && cfg.Server.OAuth.IsForwardMode())
	if !credentialsArePerRequest {
		chClient, err := clickhouse.NewClient(ctx, cfg.ClickHouse)
		if err != nil {
			log.Error().Err(err).Msg("Health check: failed to create ClickHouse client")
			status["status"] = "unhealthy"
			status["error"] = "ClickHouse connection failed"
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(status)
			return
		}
		defer func() {
			if closeErr := chClient.Close(); closeErr != nil {
				log.Warn().Err(closeErr).Msg("Health check: failed to close ClickHouse client")
			}
		}()

		if err := chClient.Ping(ctx); err != nil {
			log.Error().Err(err).Msg("Health check: ClickHouse ping failed")
			status["status"] = "unhealthy"
			status["error"] = "ClickHouse connection failed"
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(status)
			return
		}

		status["clickhouse"] = "connected"
	} else {
		status["auth"] = "per_request_credentials"
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(status)
}

// buildConfig builds the application configuration from CLI flags and config file
func buildConfig(cmd CommandInterface) (config.Config, error) {
	var cfg config.Config

	// Load from config file if specified
	configFile := cmd.String("config")
	if configFile != "" {
		log.Debug().Str("config_file", configFile).Msg("Loading configuration from file")
		fileCfg, err := config.LoadConfigFromFile(configFile)
		if err != nil {
			return cfg, fmt.Errorf("failed to load config file: %w", err)
		}
		cfg = *fileCfg
		if logErr := setupLogging(string(cfg.Logging.Level)); logErr != nil {
			return cfg, fmt.Errorf("failed setup logging %s level: %w", cfg.Logging.Level, logErr)
		}
		log.Info().Str("config_file", configFile).Msg("Configuration loaded from file")
	}

	// Override with CLI flags (CLI flags take precedence over config file)
	overrideWithCLIFlags(&cfg, cmd)
	if logErr := setupLogging(string(cfg.Logging.Level)); logErr != nil {
		return cfg, fmt.Errorf("failed setup logging %s level: %w", cfg.Logging.Level, logErr)
	}
	return cfg, nil
}

// CommandInterface defines the interface needed by overrideWithCLIFlags
type CommandInterface interface {
	StringMap(name string) map[string]string
	String(name string) string
	StringSlice(name string) []string
	Int(name string) int
	Bool(name string) bool
	IsSet(name string) bool
}

// overrideWithCLIFlags overrides config values with CLI flags if they are set.
// The bulk of the work is done by config.ApplyFlags, which walks the struct
// and copies CLI/env values into fields with `flag:` tags. This function
// only handles the special cases that don't fit the generic mechanism:
//
//   - --openapi: a single string flag that maps to two bool fields.
//   - --tool-input-settings: needs post-apply validation.
//   - --config-reload-time: lives outside the struct (used to drive the
//     reload loop) and has YAML-only-when-zero precedence semantics.
//   - enum-like string fields (transport, log-level, clickhouse-protocol):
//     unrecognised values fall back to a safe default rather than propagating
//     garbage downstream.
func overrideWithCLIFlags(cfg *config.Config, cmd CommandInterface) {
	config.ApplyFlags(cfg, cmd)

	// Defensive normalisation: garbage values for enum-like fields collapse
	// to the canonical default. Mirrors the historical switch/default
	// behaviour of the pre-reflection override path.
	switch strings.ToLower(string(cfg.ClickHouse.Protocol)) {
	case "tcp":
		cfg.ClickHouse.Protocol = config.TCPProtocol
	default:
		cfg.ClickHouse.Protocol = config.HTTPProtocol
	}
	switch strings.ToLower(string(cfg.Server.Transport)) {
	case "http":
		cfg.Server.Transport = config.HTTPTransport
	case "sse":
		cfg.Server.Transport = config.SSETransport
	default:
		cfg.Server.Transport = config.StdioTransport
	}
	switch strings.ToLower(string(cfg.Logging.Level)) {
	case "debug":
		cfg.Logging.Level = config.DebugLevel
	case "warn":
		cfg.Logging.Level = config.WarnLevel
	case "error":
		cfg.Logging.Level = config.ErrorLevel
	default:
		cfg.Logging.Level = config.InfoLevel
	}

	// --openapi: single string flag → two bool fields on OpenAPIConfig.
	switch cmd.String("openapi") {
	case "http":
		cfg.Server.OpenAPI.Enabled = true
		cfg.Server.OpenAPI.TLS = false
	case "https":
		cfg.Server.OpenAPI.Enabled = true
		cfg.Server.OpenAPI.TLS = true
	}

	// Validate tool-input-settings post-apply. Same behaviour as before:
	// terminate the process on misconfiguration so operators see it on startup.
	if len(cfg.Server.ToolInputSettings) > 0 {
		if err := altinitymcp.ValidateToolInputSettings(cfg.Server.ToolInputSettings); err != nil {
			log.Fatal().Err(err).Msg("invalid tool_input_settings configuration")
		}
	}

	// --config-reload-time precedence: CLI flag wins only when YAML left it at 0.
	if cmd.IsSet("config-reload-time") && cmd.Int("config-reload-time") > 0 && cfg.ReloadTime == 0 {
		cfg.ReloadTime = cmd.Int("config-reload-time")
	}
}

// buildServerTLSConfig creates a tls.Config from the server TLS configuration
func buildServerTLSConfig(cfg *config.ServerTLSConfig) (*tls.Config, error) {
	if !cfg.Enabled {
		return nil, nil
	}

	log.Debug().Msg("Building server TLS configuration")
	tlsConfig := &tls.Config{}

	if cfg.CaCert != "" {
		log.Debug().Str("ca_cert", cfg.CaCert).Msg("Loading server CA certificate for client auth")
		caCert, err := os.ReadFile(cfg.CaCert)
		if err != nil {
			return nil, fmt.Errorf("failed to read server CA certificate: %w", err)
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		tlsConfig.ClientCAs = caCertPool
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return tlsConfig, nil
}

// warnOAuthMisconfiguration logs warnings for OAuth configurations that are
// technically valid but likely unintended.
func warnOAuthMisconfiguration(cfg config.Config) {
	oauth := cfg.Server.OAuth
	if !oauth.Enabled {
		return
	}
	if oauth.IsGatingMode() && strings.TrimSpace(oauth.PublicAuthServerURL) == "" && strings.TrimSpace(oauth.Issuer) != "" {
		log.Warn().Msg("OAuth gating mode: public_auth_server_url is not set — " +
			"minted tokens will use the request Host as issuer, but validation expects the configured issuer; " +
			"set public_auth_server_url to match, or leave issuer empty to skip issuer validation")
	}
	// PublicResourceURL pins the canonical RFC 9728 `resource` URL (and the
	// audience the RFC 8707 resource indicator is validated against in
	// /authorize). When unset, we fall back to the request's Host header,
	// which is client-controlled — a deployment exposed via multiple hostnames
	// (internal LB + public domain) can have an attacker pass an unintended
	// resource and pass the validation. Pin it explicitly in production.
	if strings.TrimSpace(oauth.PublicResourceURL) == "" {
		log.Warn().Msg("OAuth: public_resource_url is not set — the resource indicator " +
			"validation (RFC 8707) and the advertised RFC 9728 `resource` URL fall back " +
			"to the request Host header. For production deployments behind a single canonical " +
			"hostname, set MCP_OAUTH_PUBLIC_RESOURCE_URL to lock the resource identity.")
	}
	if len(oauth.UpstreamIssuerAllowlist) == 0 && strings.TrimSpace(oauth.Issuer) == "" && oauth.IsForwardMode() {
		log.Warn().Msg("OAuth forward mode: neither oauth_issuer nor upstream_issuer_allowlist is set — " +
			"upstream identity tokens will be accepted from any signed-by-discovered-JWKS issuer. " +
			"Set MCP_OAUTH_ISSUER (single-tenant) or MCP_OAUTH_UPSTREAM_ISSUER_ALLOWLIST (multi-tenant) " +
			"to constrain accepted issuers.")
	}
}

// testConnection tests the connection to ClickHouse
func testConnection(ctx context.Context, cfg config.ClickHouseConfig) error {
	log.Info().Msg("Testing ClickHouse connection...")

	client, err := clickhouse.NewClient(ctx, cfg)
	if err != nil {
		log.Error().Err(err).Msg("Failed to create ClickHouse client")
		return err
	}
	defer func() {
		if closeErr := client.Close(); closeErr != nil {
			log.Warn().Err(closeErr).Msg("Failed to close ClickHouse client")
		}
	}()

	// Test ping
	if err := client.Ping(ctx); err != nil {
		log.Error().Err(err).Msg("ClickHouse ping failed")
		return err
	}

	// Test listing tables
	tables, err := client.ListTables(ctx, cfg.Database)
	if err != nil {
		log.Error().Err(err).Msg("Failed to list tables")
		return err
	}

	log.Info().
		Str("host", cfg.Host).
		Int("port", cfg.Port).
		Str("database", cfg.Database).
		Str("protocol", string(cfg.Protocol)).
		Int("table_count", len(tables)).
		Msg("ClickHouse connection test successful")

	// Print table information
	if len(tables) > 0 {
		fmt.Printf("\nTables in database '%s':\n", cfg.Database)
		for _, table := range tables {
			fmt.Printf("  - %s (%s)\n", table.Name, table.Engine)
		}
	} else {
		fmt.Printf("\nNo tables found in database '%s'\n", cfg.Database)
	}

	return nil
}

// runServer is the main server action
func runServer(ctx context.Context, cmd *cli.Command) error {
	cfg, err := buildConfig(cmd)
	if err != nil {
		log.Error().Err(err).Msg("Failed to build configuration")
		return err
	}

	log.Info().
		Str("version", version).
		Str("commit", commit).
		Str("build_date", date).
		Msg("Starting Altinity MCP Server")

	warnOAuthMisconfiguration(cfg)

	app, err := newApplication(ctx, cfg, cmd)
	if err != nil {
		log.Error().Err(err).Msg("Failed to initialize application")
		return err
	}
	defer app.Close()

	return app.Start()
}

type application struct {
	config           config.Config
	mcpServer        *altinitymcp.ClickHouseJWEServer
	httpSrv          *http.Server
	httpSrvMutex     sync.RWMutex
	oauthState       *oauthStateStore
	oauthStateMu     sync.Mutex
	configFile       string
	configMutex      sync.RWMutex
	stopConfigReload chan struct{}
}

// setHTTPServer sets the HTTP server with proper synchronization
func (a *application) setHTTPServer(srv *http.Server) {
	a.httpSrvMutex.Lock()
	defer a.httpSrvMutex.Unlock()
	a.httpSrv = srv
}

// getHTTPServer gets the HTTP server with proper synchronization
func (a *application) getHTTPServer() *http.Server {
	a.httpSrvMutex.RLock()
	defer a.httpSrvMutex.RUnlock()
	return a.httpSrv
}

func (a *application) getOAuthStateStore() *oauthStateStore {
	a.oauthStateMu.Lock()
	defer a.oauthStateMu.Unlock()
	if a.oauthState == nil {
		a.oauthState = newOAuthStateStore()
	}
	return a.oauthState
}

func newApplication(ctx context.Context, cfg config.Config, cmd CommandInterface) (*application, error) {
	if err := validateOAuthRuntimeConfig(cfg); err != nil {
		return nil, err
	}
	if err := validateClusterSecretConfig(cfg); err != nil {
		return nil, err
	}

	// Test connection to ClickHouse at startup, unless credentials are dynamic:
	// - JWE: each request carries its own ClickHouse credentials
	// - OAuth forward mode: static creds are cleared; bearer token arrives per-request
	skipStartupPing := cfg.Server.JWE.Enabled ||
		(cfg.Server.OAuth.Enabled && cfg.Server.OAuth.IsForwardMode())
	if !skipStartupPing {
		log.Debug().Msg("Testing ClickHouse connection...")
		chClient, err := clickhouse.NewClient(ctx, cfg.ClickHouse)
		if err != nil {
			return nil, fmt.Errorf("failed to create ClickHouse client: %w", err)
		}

		// Test connection
		if pingErr := chClient.Ping(ctx); pingErr != nil {
			log.Error().
				Err(pingErr).
				Str("host", cfg.ClickHouse.Host).
				Int("port", cfg.ClickHouse.Port).
				Str("database", cfg.ClickHouse.Database).
				Msg("ClickHouse connection test failed during application startup")
			_ = chClient.Close()
			return nil, fmt.Errorf("ClickHouse connection test failed: %w", pingErr)
		}

		log.Debug().Msg("ClickHouse connection established")
		if closeErr := chClient.Close(); closeErr != nil {
			log.Error().
				Err(closeErr).
				Msg("Failed to close ClickHouse connection after successful ping")
			return nil, fmt.Errorf("can't close clickhouse connection after ping: %w", closeErr)
		}
	} else {
		log.Debug().Msg("Skipping startup ClickHouse connection test (credentials are per-request)")
	}

	// Validate JWE secret key is set when JWE auth is enabled
	if cfg.Server.JWE.Enabled && cfg.Server.JWE.JWESecretKey == "" {
		return nil, fmt.Errorf("JWE encryption is enabled but no JWE secret key is provided")
	}

	// Create MCP server
	log.Debug().Msg("Creating MCP server...")
	mcpServer := altinitymcp.NewClickHouseMCPServer(cfg, version)

	// Move reload time from CLI flag to config
	cfg.ReloadTime = cmd.Int("config-reload-time")

	app := &application{
		config:           cfg,
		mcpServer:        mcpServer,
		oauthState:       newOAuthStateStore(),
		configFile:       cmd.String("config"),
		stopConfigReload: make(chan struct{}),
	}

	// Start config reload goroutine if enabled
	if app.configFile != "" && cfg.ReloadTime > 0 {
		go app.configReloadLoop(ctx, cmd)
	}

	return app, nil
}

func validateOAuthRuntimeConfig(cfg config.Config) error {
	if !cfg.Server.OAuth.Enabled {
		return nil
	}

	switch cfg.Server.OAuth.NormalizedMode() {
	case "forward", "gating":
	default:
		return fmt.Errorf("unsupported oauth mode: %s", cfg.Server.OAuth.Mode)
	}

	signingSecret := strings.TrimSpace(cfg.Server.OAuth.SigningSecret)
	if signingSecret == "" {
		return fmt.Errorf("oauth signing_secret is required when OAuth is enabled (used for client registration and token exchange in both forward and gating modes)")
	}
	// Defence in depth: HS256 (gating-mode access token signing) and JWE A256KW
	// (client_id + refresh-token wrap) both derive their key as SHA-256(secret).
	// SHA-256 spreads bits but doesn't add entropy — a 4-byte secret hashed
	// to 32 bytes still has only 32 bits of entropy. 32 bytes is the practical
	// minimum to make brute-force forging infeasible.
	const minSigningSecretBytes = 32
	if len(signingSecret) < minSigningSecretBytes {
		return fmt.Errorf("oauth signing_secret must be at least %d bytes (got %d) — short secrets weaken HS256 and JWE key wrapping; generate with `openssl rand -base64 32` or similar", minSigningSecretBytes, len(signingSecret))
	}

	if cfg.Server.OAuth.IsForwardMode() && cfg.ClickHouse.Protocol != config.HTTPProtocol {
		return fmt.Errorf("oauth forward mode requires clickhouse protocol http")
	}

	return nil
}

// validateClusterSecretConfig rejects invalid combinations for
// interserver-secret mode. The shared secret can only authenticate over the
// TCP native protocol; ClickHouse has no HTTP equivalent.
func validateClusterSecretConfig(cfg config.Config) error {
	if cfg.ClickHouse.ClusterSecret == "" {
		return nil
	}
	if cfg.ClickHouse.Protocol != config.TCPProtocol {
		return fmt.Errorf("clickhouse-cluster-secret requires clickhouse-protocol=tcp")
	}
	if cfg.ClickHouse.ClusterName == "" {
		return fmt.Errorf("clickhouse-cluster-secret is set but clickhouse-cluster-name is empty")
	}
	return nil
}

func (a *application) Close() {
	// Stop config reload goroutine
	if a.configFile != "" {
		close(a.stopConfigReload)
	}

	// No resources to close as the ClickHouse client is created and closed per request
	log.Debug().Msg("Application resources cleaned up")
}

// configReloadLoop periodically reloads configuration from file
func (a *application) configReloadLoop(ctx context.Context, cmd CommandInterface) {
	ticker := time.NewTicker(time.Duration(a.config.ReloadTime) * time.Second)
	defer ticker.Stop()

	log.Info().
		Str("config_file", a.configFile).
		Int("reload_interval", a.config.ReloadTime).
		Msg("Starting configuration reload loop")

	for {
		select {
		case <-ticker.C:
			if err := a.reloadConfig(cmd); err != nil {
				log.Error().
					Err(err).
					Str("config_file", a.configFile).
					Msg("Failed to reload configuration")
			}
		case <-a.stopConfigReload:
			log.Debug().Msg("Configuration reload loop stopped")
			return
		case <-ctx.Done():
			log.Debug().Msg("Configuration reload loop stopped due to context cancellation")
			return
		}
	}
}

// reloadConfig reloads configuration from file and updates the application
func (a *application) reloadConfig(cmd CommandInterface) error {
	log.Debug().Str("config_file", a.configFile).Msg("Reloading configuration")

	// Load new config from file
	newCfg, err := config.LoadConfigFromFile(a.configFile)
	if err != nil {
		return fmt.Errorf("failed to load config file: %w", err)
	}

	// Override with CLI flags
	overrideWithCLIFlags(newCfg, cmd)

	// Update logging level if changed
	a.configMutex.Lock()
	oldLogLevel := a.config.Logging.Level
	a.config = *newCfg
	a.configMutex.Unlock()

	if oldLogLevel != newCfg.Logging.Level {
		if err := setupLogging(string(newCfg.Logging.Level)); err != nil {
			log.Error().Err(err).Msg("Failed to update logging level")
		} else {
			log.Info().
				Str("old_level", string(oldLogLevel)).
				Str("new_level", string(newCfg.Logging.Level)).
				Msg("Logging level updated")
		}
	}

	// Create new MCP server with updated config
	newMCPServer := altinitymcp.NewClickHouseMCPServer(*newCfg, version)

	// Update the server (note: this doesn't restart HTTP servers, only updates the MCP server)
	a.configMutex.Lock()
	a.mcpServer = newMCPServer
	a.configMutex.Unlock()

	log.Info().Str("config_file", a.configFile).Msg("Configuration reloaded successfully")
	return nil
}

// GetCurrentConfig returns a copy of the current configuration (thread-safe)
func (a *application) GetCurrentConfig() config.Config {
	a.configMutex.RLock()
	defer a.configMutex.RUnlock()
	return a.config
}

func (a *application) Start() error {
	// Get current config (thread-safe)
	cfg := a.GetCurrentConfig()

	// Start the server based on transport type
	log.Info().
		Str("transport", string(cfg.Server.Transport)).
		Bool("jwe_enabled", cfg.Server.JWE.Enabled).
		Bool("openapi_enabled", cfg.Server.OpenAPI.Enabled).
		Msg("Starting MCP server...")

	// Access the underlying MCPServer from our ClickHouseJWEServer
	mcpServer := a.mcpServer.MCPServer

	switch cfg.Server.Transport {
	case config.StdioTransport:
		return a.startSTDIOServer(mcpServer)

	case config.HTTPTransport:
		return a.startHTTPServer(cfg, mcpServer)

	case config.SSETransport:
		return a.startSSEServer(cfg, mcpServer)

	default:
		return fmt.Errorf("unsupported transport type: %s", cfg.Server.Transport)
	}
}
