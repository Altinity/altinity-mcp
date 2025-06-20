package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/altinity/altinity-mcp/pkg/clickhouse"
	"github.com/altinity/altinity-mcp/pkg/config"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/rs/zerolog/log"
)

// NewServer creates a new MCP server with ClickHouse integration
func NewServer(cfg config.Config, chClient *clickhouse.Client) (*server.MCPServer, error) {
	// Create MCP server with basic configuration
	srv := server.NewMCPServer(
		"Altinity MCP Server",
		"1.0.0",
		server.WithToolCapabilities(false),
		server.WithRecovery(),
	)

	// Register tools
	registerTools(srv, chClient)

	return srv, nil
}

// registerTools adds the ClickHouse tools to the MCP server
func registerTools(srv *server.MCPServer, chClient *clickhouse.Client) {
	// List Tables Tool
	listTablesTool := mcp.NewTool(
		"list_tables",
		mcp.WithDescription("Lists all tables in the ClickHouse database"),
		mcp.WithString("database",
			mcp.Description("Database name to list tables from"),
		),
	)

	srv.AddTool(listTablesTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		tables, err := chClient.ListTables(ctx)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Failed to list tables: %v", err)), nil
		}

		response := struct {
			Tables []clickhouse.TableInfo `json:"tables"`
			Count  int                    `json:"count"`
		}{
			Tables: tables,
			Count:  len(tables),
		}

		jsonData, err := json.Marshal(response)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Failed to marshal response: %v", err)), nil
		}

		return mcp.NewToolResultJSON(jsonData), nil
	})

	// Execute Query Tool
	executeQueryTool := mcp.NewTool(
		"execute_query",
		mcp.WithDescription("Executes a SQL query with optional parameters"),
		mcp.WithString("query",
			mcp.Required(),
			mcp.Description("SQL query to execute"),
		),
		mcp.WithArray("parameters",
			mcp.Description("Query parameters"),
		),
	)

	srv.AddTool(executeQueryTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		query, err := req.RequireString("query")
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		params, _ := req.GetArray("parameters")

		result, err := chClient.ExecuteQuery(ctx, query, params...)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Query execution failed: %v", err)), nil
		}

		jsonData, err := json.Marshal(result)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Failed to marshal result: %v", err)), nil
		}

		return mcp.NewToolResultJSON(jsonData), nil
	})

	log.Info().Msg("MCP tools registered")
}

// StartServer starts the MCP server with the specified transport
func StartServer(srv *server.MCPServer, cfg config.ServerConfig) error {
	log.Info().
		Str("transport", string(cfg.Transport)).
		Msg("Starting MCP server")

	// Setup signal handling for graceful shutdown
	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, os.Interrupt, syscall.SIGTERM)

	shutdownCtx, shutdown := context.WithCancel(context.Background())
	defer shutdown()

	go func() {
		sig := <-signalCh
		log.Info().
			Str("signal", sig.String()).
			Msg("Received shutdown signal")
		shutdown()
	}()

	// Start the server based on transport type
	switch cfg.Transport {
	case config.HTTPTransport:
		return startHTTPServer(srv, cfg)
	case config.SSETransport:
		return startSSEServer(srv, cfg)
	case config.StdioTransport:
		return server.ServeStdio(srv)
	default:
		return fmt.Errorf("unsupported transport type: %s", cfg.Transport)
	}
}

// startHTTPServer starts the HTTP transport server
func startHTTPServer(srv *server.MCPServer, cfg config.ServerConfig) error {
	addr := fmt.Sprintf("%s:%d", cfg.Address, cfg.Port)
	log.Info().
		Str("address", addr).
		Msg("Starting MCP server with HTTP transport")

	httpTransport := http.NewTransport(http.Config{
		Path:    "/mcp",
		Address: addr,
	})

	mux := http.NewServeMux()
	mux.Handle("/mcp", httpTransport.Handle(srv))

	httpServer := &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	go func() {
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error().Err(err).Msg("HTTP server error")
		}
	}()

	<-context.Background().Done()
	return nil
}

// startSSEServer starts the SSE transport server
func startSSEServer(srv *server.MCPServer, cfg config.ServerConfig) error {
	addr := fmt.Sprintf("%s:%d", cfg.Address, cfg.Port)
	log.Info().
		Str("address", addr).
		Msg("Starting MCP server with SSE transport")

	sseTransport := sse.NewTransport(sse.Config{
		Path:    "/mcp",
		Address: addr,
	})

	mux := http.NewServeMux()
	mux.Handle("/mcp", sseTransport.Handle(srv))

	httpServer := &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	go func() {
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error().Err(err).Msg("SSE server error")
		}
	}()

	<-context.Background().Done()
	return nil
}
