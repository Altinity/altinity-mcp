package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/altinity/altinity-mcp/pkg/clickhouse"
	"github.com/altinity/altinity-mcp/pkg/config"
	"github.com/mark3labs/mcp-go/server"
	"github.com/rs/zerolog/log"
)

// Server represents the MCP server
type Server struct {
	config      config.ServerConfig
	chClient    *clickhouse.Client
	mcpServer   *server.MCPServer
	httpServer  *http.Server
	shutdownCtx context.Context
	shutdown    context.CancelFunc
}

// ListTablesResponse represents the response for list_tables tool
type ListTablesResponse struct {
	Tables []clickhouse.TableInfo `json:"tables"`
	Count  int                    `json:"count"`
}

// ExecuteQueryRequest represents the request for execute_query tool
type ExecuteQueryRequest struct {
	Query      string        `json:"query"`
	Parameters []interface{} `json:"parameters,omitempty"`
}

// NewServer creates a new MCP server
func NewServer(cfg config.Config, chClient *clickhouse.Client) (*Server, error) {
	ctx, cancel := context.WithCancel(context.Background())

	// Create MCP server
	mcpServer := server.New(
		"Altinity MCP Server",
		"1.0.0",
		server.WithToolCapabilities(false),
	)

	srv := &Server{
		config:      cfg.Server,
		chClient:    chClient,
		mcpServer:   mcpServer,
		shutdownCtx: ctx,
		shutdown:    cancel,
	}

	// Register tools
	srv.registerTools()

	return srv, nil
}

// registerTools registers all MCP tools
func (s *Server) registerTools() {
	// List Tables Tool
	listTablesTool := mcp.NewTool(
		"list_tables",
		mcp.WithDescription("Lists all tables in the ClickHouse database"),
		mcp.WithString("database",
			mcp.Description("Database name to list tables from"),
		),
	)

	s.mcpServer.AddTool(listTablesTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		tables, err := s.chClient.ListTables(ctx)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Failed to list tables: %v", err)), nil
		}

		response := ListTablesResponse{
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

	s.mcpServer.AddTool(executeQueryTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		query, err := req.RequireString("query")
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		params, _ := req.GetArray("parameters")

		result, err := s.chClient.ExecuteQuery(ctx, query, params...)
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

// Start starts the MCP server
func (s *Server) Start() error {
	log.Info().
		Str("transport", string(s.config.Transport)).
		Msg("Starting MCP server")

	// Setup signal handling for graceful shutdown
	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, os.Interrupt, syscall.SIGTERM)

	go func() {
		sig := <-signalCh
		log.Info().
			Str("signal", sig.String()).
			Msg("Received shutdown signal")
		s.Stop()
	}()

	// Start the server based on transport type
	switch s.config.Transport {
	case config.HTTPTransport:
		return s.startHTTPServer()
	case config.SSETransport:
		return s.startSSEServer()
	case config.StdioTransport:
		return server.ServeStdio(s.mcpServer)
	default:
		return fmt.Errorf("unsupported transport type: %s", s.config.Transport)
	}
}

// startHTTPServer starts the MCP server with HTTP transport
func (s *Server) startHTTPServer() error {
	addr := fmt.Sprintf("%s:%d", s.config.Address, s.config.Port)
	log.Info().
		Str("address", addr).
		Msg("Starting MCP server with HTTP transport")

	// Create HTTP transport
	httpTransport := http.NewTransport(http.Config{
		Path:    "/mcp",
		Address: addr,
	})

	// Create HTTP server
	mux := http.NewServeMux()
	mux.Handle("/mcp", httpTransport.Handle(s.mcpServer))

	s.httpServer = &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	// Start HTTP server in a goroutine
	go func() {
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error().Err(err).Msg("HTTP server error")
		}
	}()

	// Wait for shutdown signal
	<-s.shutdownCtx.Done()
	return nil
}

// startSSEServer starts the MCP server with SSE transport
func (s *Server) startSSEServer() error {
	addr := fmt.Sprintf("%s:%d", s.config.Address, s.config.Port)
	log.Info().
		Str("address", addr).
		Msg("Starting MCP server with SSE transport")

	// Create SSE transport
	sseTransport := sse.NewTransport(sse.Config{
		Path:    "/mcp",
		Address: addr,
	})

	// Create HTTP server
	mux := http.NewServeMux()
	mux.Handle("/mcp", sseTransport.Handle(s.mcpServer))

	s.httpServer = &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	// Start HTTP server in a goroutine
	go func() {
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error().Err(err).Msg("SSE server error")
		}
	}()

	// Wait for shutdown signal
	<-s.shutdownCtx.Done()
	return nil
}

// Stop stops the MCP server
func (s *Server) Stop() {
	log.Info().Msg("Stopping MCP server")

	// Signal shutdown
	s.shutdown()

	// Shutdown HTTP server if it exists
	if s.httpServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := s.httpServer.Shutdown(ctx); err != nil {
			log.Error().Err(err).Msg("HTTP server shutdown error")
		}
		log.Info().Msg("HTTP server stopped")
	}

	log.Info().Msg("MCP server stopped")
}
