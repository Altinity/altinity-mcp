package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/altinity/altinity-mcp/pkg/clickhouse"
	"github.com/altinity/altinity-mcp/pkg/config"
	"github.com/altinity/altinity-mcp/pkg/server"
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
	app := &cli.App{
		Name:        "altinity-mcp",
		Usage:       "Altinity MCP Server - ClickHouse Model Context Protocol Server",
		Description: "A Model Context Protocol (MCP) server that provides tools for interacting with ClickHouse databases",
		Version:     fmt.Sprintf("%s (%s) built on %s", version, commit, date),
		Authors: []*cli.Author{
			{
				Name:  "Altinity",
				Email: "support@altinity.com",
			},
		},
		Flags: []cli.Flag{
			// ClickHouse configuration flags
			&cli.StringFlag{
				Name:    "clickhouse-host",
				Usage:   "ClickHouse server host",
				Value:   "localhost",
				EnvVars: []string{"CLICKHOUSE_HOST"},
			},
			&cli.IntFlag{
				Name:    "clickhouse-port",
				Usage:   "ClickHouse server port",
				Value:   8123,
				EnvVars: []string{"CLICKHOUSE_PORT"},
			},
			&cli.StringFlag{
				Name:    "clickhouse-database",
				Usage:   "ClickHouse database name",
				Value:   "default",
				EnvVars: []string{"CLICKHOUSE_DATABASE"},
			},
			&cli.StringFlag{
				Name:    "clickhouse-username",
				Usage:   "ClickHouse username",
				Value:   "default",
				EnvVars: []string{"CLICKHOUSE_USERNAME"},
			},
			&cli.StringFlag{
				Name:    "clickhouse-password",
				Usage:   "ClickHouse password",
				Value:   "",
				EnvVars: []string{"CLICKHOUSE_PASSWORD"},
			},
			&cli.StringFlag{
				Name:    "clickhouse-protocol",
				Usage:   "ClickHouse connection protocol (http/tcp)",
				Value:   "http",
				EnvVars: []string{"CLICKHOUSE_PROTOCOL"},
			},
			// Server configuration flags
			&cli.StringFlag{
				Name:    "transport",
				Usage:   "MCP transport type (stdio/http/sse)",
				Value:   "stdio",
				EnvVars: []string{"MCP_TRANSPORT"},
			},
			&cli.StringFlag{
				Name:    "address",
				Usage:   "Server address for HTTP/SSE transport",
				Value:   "0.0.0.0",
				EnvVars: []string{"MCP_ADDRESS"},
			},
			&cli.IntFlag{
				Name:    "port",
				Usage:   "Server port for HTTP/SSE transport",
				Value:   8080,
				EnvVars: []string{"MCP_PORT"},
			},
			// Logging configuration flags
			&cli.StringFlag{
				Name:    "log-level",
				Usage:   "Logging level (debug/info/warn/error)",
				Value:   "info",
				EnvVars: []string{"LOG_LEVEL"},
			},
		},
		Before: func(ctx context.Context, cmd *cli.Command) error {
			// Setup logging
			return setupLogging(cmd.String("log-level"))
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
			Host:     cmd.String("clickhouse-host"),
			Port:     cmd.Int("clickhouse-port"),
			Database: cmd.String("clickhouse-database"),
			Username: cmd.String("clickhouse-username"),
			Password: cmd.String("clickhouse-password"),
			Protocol: chProtocol,
		},
		Server: config.ServerConfig{
			Transport: mcpTransport,
			Address:   cmd.String("address"),
			Port:      cmd.Int("port"),
		},
		Logging: config.LoggingConfig{
			Level: logLevel,
		},
	}
}

// testConnection tests the connection to ClickHouse
func testConnection(ctx context.Context, cfg config.ClickHouseConfig) error {
	log.Info().Msg("Testing ClickHouse connection...")

	client, err := clickhouse.NewClient(cfg)
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
	tables, err := client.ListTables(ctx)
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

	// Create ClickHouse client
	log.Info().Msg("Connecting to ClickHouse...")
	chClient, err := clickhouse.NewClient(cfg.ClickHouse)
	if err != nil {
		log.Error().Err(err).Msg("Failed to create ClickHouse client")
		return err
	}
	defer func() {
		if closeErr := chClient.Close(); closeErr != nil {
			log.Warn().Err(closeErr).Msg("Failed to close ClickHouse client")
		}
	}()

	// Test connection
	if err := chClient.Ping(ctx); err != nil {
		log.Error().Err(err).Msg("ClickHouse connection test failed")
		return err
	}
	log.Info().Msg("ClickHouse connection established")

	// Create MCP server
	log.Info().Msg("Creating MCP server...")
	mcpServer, err := server.NewServer(cfg, chClient)
	if err != nil {
		log.Error().Err(err).Msg("Failed to create MCP server")
		return err
	}

	// Start the server
	log.Info().
		Str("transport", string(cfg.Server.Transport)).
		Msg("Starting MCP server...")

	if err := server.StartServer(mcpServer, cfg.Server); err != nil {
		log.Error().Err(err).Msg("MCP server failed")
		return err
	}

	return nil
}
