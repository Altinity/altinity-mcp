package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
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
	app := &cli.Command{
		Name:        "altinity-mcp",
		Usage:       "Altinity MCP Server - ClickHouse Model Context Protocol Server",
		Description: "A Model Context Protocol (MCP) server that provides tools for interacting with ClickHouse databases",
		Version:     fmt.Sprintf("%s (%s) built on %s", version, commit, date),
		Authors:     []any{"Altinity <support@altinity.com>"},
		Flags: []cli.Flag{
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
			&cli.StringFlag{
				Name:    "jwt-token-param",
				Usage:   "URL parameter name for JWT token",
				Value:   "token",
				Sources: cli.EnvVars("MCP_JWT_TOKEN_PARAM"),
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
					cfg := buildConfig(cmd)
					return testConnection(ctx, cfg.ClickHouse)
				},
			},
		},
	}

	if err := app.Run(context.Background(), os.Args); err != nil {
		log.Fatal().Err(err).Msg("Application failed")
	}
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

// buildConfig builds the application configuration from CLI flags
func buildConfig(cmd *cli.Command) config.Config {
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

	return config.Config{
		ClickHouse: config.ClickHouseConfig{
			Host:             cmd.String("clickhouse-host"),
			Port:             cmd.Int("clickhouse-port"),
			Database:         cmd.String("clickhouse-database"),
			Username:         cmd.String("clickhouse-username"),
			Password:         cmd.String("clickhouse-password"),
			Protocol:         chProtocol,
			ReadOnly:         cmd.Bool("read-only"),
			MaxExecutionTime: cmd.Int("clickhouse-max-execution-time"),
			TLS: config.TLSConfig{
				Enabled:            cmd.Bool("clickhouse-tls"),
				CaCert:             cmd.String("clickhouse-tls-ca-cert"),
				ClientCert:         cmd.String("clickhouse-tls-client-cert"),
				ClientKey:          cmd.String("clickhouse-tls-client-key"),
				InsecureSkipVerify: cmd.Bool("clickhouse-tls-insecure-skip-verify"),
			},
		},
		Server: config.ServerConfig{
			Transport: mcpTransport,
			Address:   cmd.String("address"),
			Port:      cmd.Int("port"),
			TLS: config.ServerTLSConfig{
				Enabled:  cmd.Bool("server-tls"),
				CertFile: cmd.String("server-tls-cert-file"),
				KeyFile:  cmd.String("server-tls-key-file"),
				CaCert:   cmd.String("server-tls-ca-cert"),
			},
			JWT: config.JWTConfig{
				Enabled:    cmd.Bool("allow-jwt-auth"),
				SecretKey:  cmd.String("jwt-secret-key"),
				TokenParam: cmd.String("jwt-token-param"),
			},
		},
		Logging: config.LoggingConfig{
			Level: logLevel,
		},
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
	cfg := buildConfig(cmd)

	log.Info().
		Str("version", version).
		Str("commit", commit).
		Str("build_date", date).
		Msg("Starting Altinity MCP Server")

	app, err := newApplication(ctx, cfg)
	if err != nil {
		log.Error().Err(err).Msg("Failed to initialize application")
		return err
	}
	defer app.Close()

	return app.Start()
}

type application struct {
	config    config.Config
	mcpServer *altinitymcp.ClickHouseJWTServer
	httpSrv   *http.Server
}

func newApplication(ctx context.Context, cfg config.Config) (*application, error) {
	// Test connection to ClickHouse if JWT auth is not enabled
	if !cfg.Server.JWT.Enabled {
		log.Debug().Msg("Testing ClickHouse connection...")
		chClient, err := clickhouse.NewClient(ctx, cfg.ClickHouse)
		if err != nil {
			return nil, fmt.Errorf("failed to create ClickHouse client: %w", err)
		}

		// Test connection
		if pingErr := chClient.Ping(ctx); pingErr != nil {
			_ = chClient.Close()
			return nil, fmt.Errorf("ClickHouse connection test failed: %w", pingErr)
		}

		log.Debug().Msg("ClickHouse connection established")
		if closeErr := chClient.Close(); closeErr != nil {
			return nil, fmt.Errorf("can't close clickhouse connection after ping: %w", err)
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

	return &application{
		config:    cfg,
		mcpServer: mcpServer,
	}, nil
}

func (a *application) Close() {
	// No resources to close as the ClickHouse client is created and closed per request
	log.Debug().Msg("Application resources cleaned up")
}

func (a *application) Start() error {
	// Start the server based on transport type
	log.Info().
		Str("transport", string(a.config.Server.Transport)).
		Bool("jwt_enabled", a.config.Server.JWT.Enabled).
		Msg("Starting MCP server...")

	// Access the underlying MCPServer from our ClickHouseJWTServer
	mcpServer := a.mcpServer.MCPServer

	switch a.config.Server.Transport {
	case config.StdioTransport:
		log.Info().Msg("Starting MCP server with STDIO transport")
		if err := server.ServeStdio(mcpServer); err != nil {
			log.Error().Err(err).Msg("STDIO server failed")
			return err
		}

	case config.HTTPTransport:
		addr := fmt.Sprintf("%s:%d", a.config.Server.Address, a.config.Server.Port)
		log.Info().
			Str("address", addr).
			Msg("Starting MCP server with HTTP transport")

		httpServer := server.NewStreamableHTTPServer(mcpServer)
		mux := http.NewServeMux()
		mux.Handle("/", httpServer)

		a.httpSrv = &http.Server{
			Addr:    addr,
			Handler: mux,
		}

		if !a.config.Server.TLS.Enabled {
			log.Info().Str("url", fmt.Sprintf("http://%s", addr)).Msg("HTTP server listening")
			if err := a.httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error().Err(err).Msg("HTTP server failed")
				return err
			}
		} else {
			log.Info().Str("url", fmt.Sprintf("https://%s", addr)).Msg("HTTPS server listening")
			tlsConfig, err := buildServerTLSConfig(&a.config.Server.TLS)
			if err != nil {
				log.Error().Err(err).Msg("Failed to build server TLS config")
				return err
			}
			a.httpSrv.TLSConfig = tlsConfig
			if err = a.httpSrv.ListenAndServeTLS(a.config.Server.TLS.CertFile, a.config.Server.TLS.KeyFile); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error().Err(err).Msg("HTTPS server failed")
				return err
			}
		}

	case config.SSETransport:
		addr := fmt.Sprintf("%s:%d", a.config.Server.Address, a.config.Server.Port)
		log.Info().
			Str("address", addr).
			Msg("Starting MCP server with SSE transport")

		// Check if we should use dynamic base path with JWT
		var sseHandler http.Handler
		if a.config.Server.JWT.Enabled {
			log.Info().Msg("Using dynamic base path for JWT authentication")
			sseServer := server.NewSSEServer(
				mcpServer,
				server.WithDynamicBasePath(func(r *http.Request, sessionID string) string {
					// Extract token from URL and use it as path component
					token := r.URL.Query().Get(a.config.Server.JWT.TokenParam)
					if token != "" {
						return "/" + token
					}
					return "/"
				}),
				server.WithBaseURL(fmt.Sprintf("http://%s:%d", a.config.Server.Address, a.config.Server.Port)),
				server.WithUseFullURLForMessageEndpoint(true),
			)

			// Register custom handlers to ensure token is in the path
			mux := http.NewServeMux()
			mux.Handle("/{token}/sse", sseServer.SSEHandler())
			mux.Handle("/{token}/message", sseServer.MessageHandler())
			sseHandler = mux
		} else {
			// Use standard SSE server without dynamic paths
			sseServer := server.NewSSEServer(mcpServer)
			sseHandler = sseServer
		}

		a.httpSrv = &http.Server{
			Addr:    addr,
			Handler: sseHandler,
		}

		if !a.config.Server.TLS.Enabled {
			log.Info().Str("url", fmt.Sprintf("http://%s", addr)).Msg("SSE server listening")
			if err := a.httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error().Err(err).Msg("SSE server failed")
				return err
			}
		} else {
			log.Info().Str("url", fmt.Sprintf("https://%s", addr)).Msg("SSE server listening with TLS")
			tlsConfig, err := buildServerTLSConfig(&a.config.Server.TLS)
			if err != nil {
				log.Error().Err(err).Msg("Failed to build server TLS config")
				return err
			}
			a.httpSrv.TLSConfig = tlsConfig
			if err = a.httpSrv.ListenAndServeTLS(a.config.Server.TLS.CertFile, a.config.Server.TLS.KeyFile); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error().Err(err).Msg("SSE server with TLS failed")
				return err
			}
		}

	default:
		return fmt.Errorf("unsupported transport type: %s", a.config.Server.Transport)
	}

	return nil
}
