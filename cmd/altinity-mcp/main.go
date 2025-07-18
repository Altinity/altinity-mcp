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
	"strings"
	"sync"
	"time"

	"github.com/altinity/altinity-mcp/pkg/clickhouse"
	"github.com/altinity/altinity-mcp/pkg/config"
	altinitymcp "github.com/altinity/altinity-mcp/pkg/server"
	"github.com/mark3labs/mcp-go/server"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/urfave/cli/v3"
)

var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
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
		Flags: []cli.Flag{
			// Configuration file flags
			&cli.StringFlag{
				Name:    "config",
				Usage:   "Path to configuration file (YAML or JSON)",
				Value:   "",
				Sources: cli.EnvVars("CONFIG_FILE"),
			},
			&cli.IntFlag{
				Name:    "config-reload-time",
				Usage:   "Configuration reload interval in seconds (0 to disable)",
				Value:   0,
				Sources: cli.EnvVars("CONFIG_RELOAD_TIME"),
			},
			// ClickHouse configuration flags
			&cli.StringFlag{
				Name:    "clickhouse-host",
				Usage:   "ClickHouse server host",
				Value:   "localhost",
				Sources: cli.EnvVars("CLICKHOUSE_HOST"),
			},
			&cli.IntFlag{
				Name:    "clickhouse-port",
				Usage:   "ClickHouse server port",
				Value:   8123,
				Sources: cli.EnvVars("CLICKHOUSE_PORT"),
			},
			&cli.StringFlag{
				Name:    "clickhouse-database",
				Usage:   "ClickHouse database name",
				Value:   "default",
				Sources: cli.EnvVars("CLICKHOUSE_DATABASE"),
			},
			&cli.StringFlag{
				Name:    "clickhouse-username",
				Usage:   "ClickHouse username",
				Value:   "default",
				Sources: cli.EnvVars("CLICKHOUSE_USERNAME"),
			},
			&cli.StringFlag{
				Name:    "clickhouse-password",
				Usage:   "ClickHouse password",
				Value:   "",
				Sources: cli.EnvVars("CLICKHOUSE_PASSWORD"),
			},
			&cli.StringFlag{
				Name:    "clickhouse-protocol",
				Usage:   "ClickHouse connection protocol (http/tcp)",
				Value:   "http",
				Sources: cli.EnvVars("CLICKHOUSE_PROTOCOL"),
			},
			&cli.IntFlag{
				Name:    "clickhouse-max-execution-time",
				Usage:   "ClickHouse max execution time in seconds",
				Value:   600,
				Sources: cli.EnvVars("CLICKHOUSE_MAX_EXECUTION_TIME"),
			},
			&cli.BoolFlag{
				Name:    "read-only",
				Usage:   "Connect to ClickHouse in read-only mode (avoids setting session variables)",
				Value:   false,
				Sources: cli.EnvVars("CLICKHOUSE_READ_ONLY"),
			},
			// TLS configuration flags
			&cli.BoolFlag{
				Name:    "clickhouse-tls",
				Usage:   "Enable TLS for ClickHouse connection",
				Value:   false,
				Sources: cli.EnvVars("CLICKHOUSE_TLS"),
			},
			&cli.StringFlag{
				Name:    "clickhouse-tls-ca-cert",
				Usage:   "Path to CA certificate for ClickHouse connection",
				Value:   "",
				Sources: cli.EnvVars("CLICKHOUSE_TLS_CA_CERT"),
			},
			&cli.StringFlag{
				Name:    "clickhouse-tls-client-cert",
				Usage:   "Path to client certificate for ClickHouse connection",
				Value:   "",
				Sources: cli.EnvVars("CLICKHOUSE_TLS_CLIENT_CERT"),
			},
			&cli.StringFlag{
				Name:    "clickhouse-tls-client-key",
				Usage:   "Path to client key for ClickHouse connection",
				Value:   "",
				Sources: cli.EnvVars("CLICKHOUSE_TLS_CLIENT_KEY"),
			},
			&cli.BoolFlag{
				Name:    "clickhouse-tls-insecure-skip-verify",
				Usage:   "Skip server certificate verification",
				Value:   false,
				Sources: cli.EnvVars("CLICKHOUSE_TLS_INSECURE_SKIP_VERIFY"),
			},
			// Server configuration flags
			&cli.StringFlag{
				Name:    "transport",
				Usage:   "MCP transport type (stdio/http/sse)",
				Value:   "stdio",
				Sources: cli.EnvVars("MCP_TRANSPORT"),
			},
			&cli.StringFlag{
				Name:    "address",
				Usage:   "Server address for HTTP/SSE transport",
				Value:   "0.0.0.0",
				Sources: cli.EnvVars("MCP_ADDRESS"),
			},
			&cli.IntFlag{
				Name:    "port",
				Usage:   "Server port for HTTP/SSE transport",
				Value:   8080,
				Sources: cli.EnvVars("MCP_PORT"),
			},
			&cli.BoolFlag{
				Name:    "server-tls",
				Usage:   "Enable TLS for the MCP server (HTTP/SSE transports)",
				Value:   false,
				Sources: cli.EnvVars("MCP_SERVER_TLS"),
			},
			&cli.StringFlag{
				Name:    "server-tls-cert-file",
				Usage:   "Path to TLS certificate file for the MCP server",
				Value:   "",
				Sources: cli.EnvVars("MCP_SERVER_TLS_CERT_FILE"),
			},
			&cli.StringFlag{
				Name:    "server-tls-key-file",
				Usage:   "Path to TLS key file for the MCP server",
				Value:   "",
				Sources: cli.EnvVars("MCP_SERVER_TLS_KEY_FILE"),
			},
			&cli.StringFlag{
				Name:    "server-tls-ca-cert",
				Usage:   "Path to CA certificate for client certificate validation",
				Value:   "",
				Sources: cli.EnvVars("MCP_SERVER_TLS_CA_CERT"),
			},
			// Logging configuration flags
			&cli.StringFlag{
				Name:    "log-level",
				Usage:   "Logging level (debug/info/warn/error)",
				Value:   "info",
				Sources: cli.EnvVars("LOG_LEVEL"),
			},
			// JWT authentication flags
			&cli.BoolFlag{
				Name:    "allow-jwt-auth",
				Usage:   "Enable JWT authentication for ClickHouse connection",
				Value:   false,
				Sources: cli.EnvVars("MCP_ALLOW_JWT_AUTH"),
			},
			&cli.StringFlag{
				Name:    "jwt-secret-key",
				Usage:   "Secret key for JWT token verification",
				Value:   "",
				Sources: cli.EnvVars("MCP_JWT_SECRET_KEY"),
			},
			&cli.IntFlag{
				Name:    "clickhouse-limit",
				Usage:   "Default limit for query results",
				Value:   1000,
				Sources: cli.EnvVars("CLICKHOUSE_LIMIT"),
			},
			&cli.StringFlag{
				Name:    "openapi",
				Usage:   "Enable OpenAPI endpoints (disable|http|https)",
				Value:   "disable",
				Sources: cli.EnvVars("MCP_OPENAPI"),
			},
		},
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
	// Configure zerolog
	zerolog.TimeFieldFormat = time.RFC3339
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: "15:04:05"})

	// Set log level
	switch strings.ToLower(level) {
	case "debug":
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	case "info":
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	case "warn":
		zerolog.SetGlobalLevel(zerolog.WarnLevel)
	case "error":
		zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	default:
		return fmt.Errorf("invalid log level: %s", level)
	}

	log.Debug().Str("level", level).Msg("Logging configured")
	return nil
}

// createTokenInjector creates a middleware that injects JWT token from path into request context
func (a *application) createTokenInjector() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract token from path
			token := r.PathValue("token")
			if token != "" {
				// Inject token into request context
				ctx := context.WithValue(r.Context(), "jwt_token", token)
				r = r.WithContext(ctx)
			}
			next.ServeHTTP(w, r)
		})
	}
}

// startHTTPServerWithTLS starts the HTTP server with or without TLS
func (a *application) startHTTPServerWithTLS(cfg config.Config, addr, transport string) error {
	if cfg.Server.JWT.Enabled {
		addr += "/{token}/" + transport
	} else {
		addr += "/" + transport
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

// startHTTPServer starts the HTTP transport server
func (a *application) startHTTPServer(cfg config.Config, mcpServer *server.MCPServer) error {
	addr := fmt.Sprintf("%s:%d", cfg.Server.Address, cfg.Server.Port)
	log.Info().
		Str("address", addr).
		Msg("Starting MCP server with HTTP transport")

	// Create a middleware to inject the ClickHouseJWTServer into context
	serverInjector := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), "clickhouse_jwt_server", a.mcpServer)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
	serverInjectorOpenAPI := func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), "clickhouse_jwt_server", a.mcpServer)
		a.mcpServer.OpenAPIHandler(w, r.WithContext(ctx))
	}
	var httpHandler http.Handler
	if cfg.Server.JWT.Enabled {
		log.Info().Msg("Using dynamic base path for JWT authentication")

		tokenInjector := a.createTokenInjector()
		httpServer := server.NewStreamableHTTPServer(mcpServer)

		// Register custom handlers to ensure token is in the path and inject it into context
		mux := http.NewServeMux()
		mux.Handle("/{token}/http", serverInjector(tokenInjector(httpServer)))
		if cfg.Server.OpenAPI.Enabled {
			mux.HandleFunc("/{token}/openapi", serverInjectorOpenAPI)
			mux.HandleFunc("/{token}/openapi/list_tables", serverInjectorOpenAPI)
			mux.HandleFunc("/{token}/openapi/describe_table", serverInjectorOpenAPI)
			mux.HandleFunc("/{token}/openapi/query", serverInjectorOpenAPI)
			protocol := "http"
			if cfg.Server.TLS.Enabled {
				protocol = "https"
			}
			log.Info().Str("url", fmt.Sprintf("%s://%s:%d/{token}/openapi", "http", cfg.Server.Address, cfg.Server.Port)).Msg("Started OpenAPI listening")
		}
		mux.HandleFunc("/health", a.healthHandler)
		httpHandler = mux
	} else {
		// Use standard HTTP server without dynamic paths
		httpServer := server.NewStreamableHTTPServer(mcpServer)
		mux := http.NewServeMux()
		mux.Handle("/http", serverInjector(httpServer))
		if cfg.Server.OpenAPI {
			mux.HandleFunc("/openapi", serverInjectorOpenAPI)
			mux.HandleFunc("/openapi/list_tables", serverInjectorOpenAPI)
			mux.HandleFunc("/openapi/describe_table", serverInjectorOpenAPI)
			mux.HandleFunc("/openapi/query", serverInjectorOpenAPI)
			protocol := "http"
			if cfg.Server.TLS.Enabled {
				protocol = "https"
			}
			log.Info().Str("url", fmt.Sprintf("%s://%s:%d/openapi", "http", cfg.Server.Address, cfg.Server.Port)).Msg("Started OpenAPI listening")
		}
		mux.HandleFunc("/health", a.healthHandler)
		httpHandler = mux
	}

	a.httpSrv = &http.Server{
		Addr:    addr,
		Handler: httpHandler,
	}

	return a.startHTTPServerWithTLS(cfg, addr, "http")
}

// startSSEServer starts the SSE transport server
func (a *application) startSSEServer(cfg config.Config, mcpServer *server.MCPServer) error {
	addr := fmt.Sprintf("%s:%d", cfg.Server.Address, cfg.Server.Port)
	log.Info().
		Str("address", addr).
		Msg("Starting MCP server with SSE transport")

	// Create a middleware to inject the ClickHouseJWTServer into context
	serverInjector := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Inject the ClickHouseJWTServer into the context
			ctx := context.WithValue(r.Context(), "clickhouse_jwt_server", a.mcpServer)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}

	var sseHandler http.Handler
	if cfg.Server.JWT.Enabled {
		log.Info().Msg("Using dynamic base path for JWT authentication")

		tokenInjector := a.createTokenInjector()

		sseServer := server.NewSSEServer(
			mcpServer,
			server.WithDynamicBasePath(func(r *http.Request, sessionID string) string {
				// Extract token from URL and use it as path component
				token := r.PathValue("token")
				if token != "" {
					return "/" + token
				}
				return "/"
			}),
			server.WithBaseURL(fmt.Sprintf("http://%s:%d", cfg.Server.Address, cfg.Server.Port)),
			server.WithUseFullURLForMessageEndpoint(false),
		)

		// Register custom handlers to ensure token is in the path and inject it into context
		mux := http.NewServeMux()
		mux.Handle("/{token}/sse", serverInjector(tokenInjector(sseServer.SSEHandler())))
		mux.Handle("/{token}/message", serverInjector(tokenInjector(sseServer.MessageHandler())))
		if cfg.Server.OpenAPI {
			mux.HandleFunc("/{token}/openapi", func(w http.ResponseWriter, r *http.Request) {
				ctx := context.WithValue(r.Context(), "clickhouse_jwt_server", a.mcpServer)
				a.mcpServer.OpenAPIHandler(w, r.WithContext(ctx))
			})
			mux.HandleFunc("/{token}/openapi/list_tables", func(w http.ResponseWriter, r *http.Request) {
				ctx := context.WithValue(r.Context(), "clickhouse_jwt_server", a.mcpServer)
				a.mcpServer.OpenAPIHandler(w, r.WithContext(ctx))
			})
			mux.HandleFunc("/{token}/openapi/describe_table", func(w http.ResponseWriter, r *http.Request) {
				ctx := context.WithValue(r.Context(), "clickhouse_jwt_server", a.mcpServer)
				a.mcpServer.OpenAPIHandler(w, r.WithContext(ctx))
			})
			mux.HandleFunc("/{token}/openapi/query", func(w http.ResponseWriter, r *http.Request) {
				ctx := context.WithValue(r.Context(), "clickhouse_jwt_server", a.mcpServer)
				a.mcpServer.OpenAPIHandler(w, r.WithContext(ctx))
			})
			log.Info().Str("url", fmt.Sprintf("http://%s:%d/{token}/openapi", cfg.Server.Address, cfg.Server.Port)).Msg("Started OpenAPI listening")
		}
		mux.HandleFunc("/health", a.healthHandler)
		sseHandler = mux
	} else {
		// Use standard SSE server without dynamic paths
		sseServer := server.NewSSEServer(mcpServer)
		mux := http.NewServeMux()
		mux.Handle("/sse", serverInjector(sseServer))
		if cfg.Server.OpenAPI {
			mux.HandleFunc("/openapi", func(w http.ResponseWriter, r *http.Request) {
				ctx := context.WithValue(r.Context(), "clickhouse_jwt_server", a.mcpServer)
				a.mcpServer.OpenAPIHandler(w, r.WithContext(ctx))
			})
			mux.HandleFunc("/openapi/list_tables", func(w http.ResponseWriter, r *http.Request) {
				ctx := context.WithValue(r.Context(), "clickhouse_jwt_server", a.mcpServer)
				a.mcpServer.OpenAPIHandler(w, r.WithContext(ctx))
			})
			mux.HandleFunc("/openapi/describe_table", func(w http.ResponseWriter, r *http.Request) {
				ctx := context.WithValue(r.Context(), "clickhouse_jwt_server", a.mcpServer)
				a.mcpServer.OpenAPIHandler(w, r.WithContext(ctx))
			})
			mux.HandleFunc("/openapi/query", func(w http.ResponseWriter, r *http.Request) {
				ctx := context.WithValue(r.Context(), "clickhouse_jwt_server", a.mcpServer)
				a.mcpServer.OpenAPIHandler(w, r.WithContext(ctx))
			})
		}
		mux.HandleFunc("/health", a.healthHandler)
		sseHandler = mux
	}

	a.httpSrv = &http.Server{
		Addr:    addr,
		Handler: sseHandler,
	}

	return a.startHTTPServerWithTLS(cfg, addr, "sse")
}

// healthHandler provides a health check endpoint for Kubernetes probes
func (a *application) healthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	// Get current config (thread-safe)
	cfg := a.GetCurrentConfig()

	// For basic health check, we'll return 200 OK
	// For readiness, we should test ClickHouse connection if JWT auth is disabled
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	status := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"version":   version,
	}

	// If JWT auth is disabled, test ClickHouse connection for readiness
	if !cfg.Server.JWT.Enabled {
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
		status["auth"] = "jwt_enabled"
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
		log.Info().Str("config_file", configFile).Msg("Configuration loaded from file")
	}

	// Override with CLI flags (CLI flags take precedence over config file)
	overrideWithCLIFlags(&cfg, cmd)

	return cfg, nil
}

// CommandInterface defines the interface needed by overrideWithCLIFlags
type CommandInterface interface {
	String(name string) string
	Int(name string) int
	Bool(name string) bool
	IsSet(name string) bool
}

// overrideWithCLIFlags overrides config values with CLI flags if they are set
func overrideWithCLIFlags(cfg *config.Config, cmd CommandInterface) {
	// Parse ClickHouse protocol
	var chProtocol config.ClickHouseProtocol
	switch strings.ToLower(cmd.String("clickhouse-protocol")) {
	case "tcp":
		chProtocol = config.TCPProtocol
	case "http":
		chProtocol = config.HTTPProtocol
	default:
		chProtocol = config.HTTPProtocol
	}

	// Parse MCP transport
	var mcpTransport config.MCPTransport
	switch strings.ToLower(cmd.String("transport")) {
	case "stdio":
		mcpTransport = config.StdioTransport
	case "http":
		mcpTransport = config.HTTPTransport
	case "sse":
		mcpTransport = config.SSETransport
	default:
		mcpTransport = config.StdioTransport
	}

	// Parse log level
	var logLevel config.LogLevel
	switch strings.ToLower(cmd.String("log-level")) {
	case "debug":
		logLevel = config.DebugLevel
	case "info":
		logLevel = config.InfoLevel
	case "warn":
		logLevel = config.WarnLevel
	case "error":
		logLevel = config.ErrorLevel
	default:
		logLevel = config.InfoLevel
	}

	// Override ClickHouse config with CLI flags
	if cmd.IsSet("clickhouse-host") {
		cfg.ClickHouse.Host = cmd.String("clickhouse-host")
	} else if cfg.ClickHouse.Host == "" {
		cfg.ClickHouse.Host = "localhost"
	}

	if cmd.IsSet("clickhouse-port") {
		cfg.ClickHouse.Port = cmd.Int("clickhouse-port")
	} else if cfg.ClickHouse.Port == 0 {
		cfg.ClickHouse.Port = 8123
	}

	if cmd.IsSet("clickhouse-database") {
		cfg.ClickHouse.Database = cmd.String("clickhouse-database")
	} else if cfg.ClickHouse.Database == "" {
		cfg.ClickHouse.Database = "default"
	}

	if cmd.IsSet("clickhouse-username") {
		cfg.ClickHouse.Username = cmd.String("clickhouse-username")
	} else if cfg.ClickHouse.Username == "" {
		cfg.ClickHouse.Username = "default"
	}

	if cmd.IsSet("clickhouse-password") {
		cfg.ClickHouse.Password = cmd.String("clickhouse-password")
	}

	if cmd.IsSet("clickhouse-protocol") {
		cfg.ClickHouse.Protocol = chProtocol
	} else if cfg.ClickHouse.Protocol == "" {
		cfg.ClickHouse.Protocol = config.HTTPProtocol
	}

	if cmd.IsSet("read-only") {
		cfg.ClickHouse.ReadOnly = cmd.Bool("read-only")
	}

	if cmd.IsSet("clickhouse-max-execution-time") {
		cfg.ClickHouse.MaxExecutionTime = cmd.Int("clickhouse-max-execution-time")
	} else if cfg.ClickHouse.MaxExecutionTime == 0 {
		cfg.ClickHouse.MaxExecutionTime = 600
	}

	// Override TLS config with CLI flags
	if cmd.IsSet("clickhouse-tls") {
		cfg.ClickHouse.TLS.Enabled = cmd.Bool("clickhouse-tls")
	}
	if cmd.IsSet("clickhouse-tls-ca-cert") {
		cfg.ClickHouse.TLS.CaCert = cmd.String("clickhouse-tls-ca-cert")
	}
	if cmd.IsSet("clickhouse-tls-client-cert") {
		cfg.ClickHouse.TLS.ClientCert = cmd.String("clickhouse-tls-client-cert")
	}
	if cmd.IsSet("clickhouse-tls-client-key") {
		cfg.ClickHouse.TLS.ClientKey = cmd.String("clickhouse-tls-client-key")
	}
	if cmd.IsSet("clickhouse-tls-insecure-skip-verify") {
		cfg.ClickHouse.TLS.InsecureSkipVerify = cmd.Bool("clickhouse-tls-insecure-skip-verify")
	}

	// Override Server config with CLI flags
	if cmd.IsSet("transport") {
		cfg.Server.Transport = mcpTransport
	} else if cfg.Server.Transport == "" {
		cfg.Server.Transport = config.StdioTransport
	}

	if cmd.IsSet("address") {
		cfg.Server.Address = cmd.String("address")
	} else if cfg.Server.Address == "" {
		cfg.Server.Address = "0.0.0.0"
	}

	if cmd.IsSet("port") {
		cfg.Server.Port = cmd.Int("port")
	} else if cfg.Server.Port == 0 {
		cfg.Server.Port = 8080
	}

	if cmd.IsSet("openapi") {
		value := cmd.String("openapi")
		if value == "http" {
			cfg.Server.OpenAPI.Enabled = true
			cfg.Server.OpenAPI.TLS = false
		} else if value == "https" {
			cfg.Server.OpenAPI.Enabled = true
			cfg.Server.OpenAPI.TLS = true
		} else {
			cfg.Server.OpenAPI.Enabled = false
			cfg.Server.OpenAPI.TLS = false
		}
	}

	// Override Server TLS config with CLI flags
	if cmd.IsSet("server-tls") {
		cfg.Server.TLS.Enabled = cmd.Bool("server-tls")
	}
	if cmd.IsSet("server-tls-cert-file") {
		cfg.Server.TLS.CertFile = cmd.String("server-tls-cert-file")
	}
	if cmd.IsSet("server-tls-key-file") {
		cfg.Server.TLS.KeyFile = cmd.String("server-tls-key-file")
	}
	if cmd.IsSet("server-tls-ca-cert") {
		cfg.Server.TLS.CaCert = cmd.String("server-tls-ca-cert")
	}

	// Override JWT config with CLI flags
	if cmd.IsSet("allow-jwt-auth") {
		cfg.Server.JWT.Enabled = cmd.Bool("allow-jwt-auth")
	}
	if cmd.IsSet("jwt-secret-key") {
		cfg.Server.JWT.SecretKey = cmd.String("jwt-secret-key")
	}

	// Override Logging config with CLI flags
	if cmd.IsSet("log-level") {
		cfg.Logging.Level = logLevel
	} else if cfg.Logging.Level == "" {
		cfg.Logging.Level = config.InfoLevel
	}

	// Override ClickHouse Limit config with CLI flags
	if cmd.IsSet("clickhouse-limit") {
		cfg.ClickHouse.Limit = cmd.Int("clickhouse-limit")
	} else if cfg.ClickHouse.Limit == 0 {
		cfg.ClickHouse.Limit = 1000
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
	mcpServer        *altinitymcp.ClickHouseJWTServer
	httpSrv          *http.Server
	configFile       string
	configReloadTime int
	configMutex      sync.RWMutex
	stopConfigReload chan struct{}
}

func newApplication(ctx context.Context, cfg config.Config, cmd CommandInterface) (*application, error) {
	// Test connection to ClickHouse if JWT auth is not enabled
	if !cfg.Server.JWT.Enabled {
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
		log.Debug().Msg("JWT authentication enabled, skipping default ClickHouse connection test")

		// Validate JWT secret key is set when JWT auth is enabled
		if cfg.Server.JWT.SecretKey == "" {
			return nil, fmt.Errorf("JWT authentication is enabled but no secret key is provided")
		}
	}

	// Create MCP server
	log.Debug().Msg("Creating MCP server...")
	mcpServer := altinitymcp.NewClickHouseMCPServer(cfg.ClickHouse, cfg.Server.JWT)

	app := &application{
		config:           cfg,
		mcpServer:        mcpServer,
		configFile:       cmd.String("config"),
		configReloadTime: cmd.Int("config-reload-time"),
		stopConfigReload: make(chan struct{}),
	}

	// Start config reload goroutine if enabled
	if app.configFile != "" && app.configReloadTime > 0 {
		go app.configReloadLoop(ctx, cmd)
	}

	return app, nil
}

func (a *application) Close() {
	// Stop config reload goroutine
	if a.configFile != "" && a.configReloadTime > 0 {
		close(a.stopConfigReload)
	}

	// No resources to close as the ClickHouse client is created and closed per request
	log.Debug().Msg("Application resources cleaned up")
}

// configReloadLoop periodically reloads configuration from file
func (a *application) configReloadLoop(ctx context.Context, cmd CommandInterface) {
	ticker := time.NewTicker(time.Duration(a.configReloadTime) * time.Second)
	defer ticker.Stop()

	log.Info().
		Str("config_file", a.configFile).
		Int("reload_interval", a.configReloadTime).
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
	newMCPServer := altinitymcp.NewClickHouseMCPServer(newCfg.ClickHouse, newCfg.Server.JWT)

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
		Bool("jwt_enabled", cfg.Server.JWT.Enabled).
		Msg("Starting MCP server...")

	// Access the underlying MCPServer from our ClickHouseJWTServer
	mcpServer := a.mcpServer.MCPServer

	switch cfg.Server.Transport {
	case config.StdioTransport:
		log.Info().Msg("Starting MCP server with STDIO transport")
		if err := server.ServeStdio(mcpServer); err != nil {
			log.Error().Err(err).Msg("STDIO server failed")
			return err
		}

	case config.HTTPTransport:
		return a.startHTTPServer(cfg, mcpServer)

	case config.SSETransport:
		return a.startSSEServer(cfg, mcpServer)

	default:
		return fmt.Errorf("unsupported transport type: %s", cfg.Server.Transport)
	}

	return nil
}
