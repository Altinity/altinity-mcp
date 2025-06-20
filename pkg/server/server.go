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
	"github.com/mark3labs/mcp-go"
	"github.com/mark3labs/mcp-go/transport/http"
	"github.com/mark3labs/mcp-go/transport/stdio"
	"github.com/mark3labs/mcp-go/transport/sse"
	"github.com/rs/zerolog/log"
)

// Server represents the MCP server
type Server struct {
	config      config.ServerConfig
	chClient    *clickhouse.Client
	mcpServer   *mcp.Server
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

	// Create transport based on config
	var transport mcp.Transport
	switch cfg.Server.Transport {
	case config.HTTPTransport:
		transport = http.NewTransport(http.Config{
			Path:    "/mcp",
			Address: fmt.Sprintf("%s:%d", cfg.Server.Address, cfg.Server.Port),
		})
	case config.SSETransport:
		transport = sse.NewTransport(sse.Config{
			Path:    "/mcp",
			Address: fmt.Sprintf("%s:%d", cfg.Server.Address, cfg.Server.Port),
		})
	case config.StdioTransport:
		transport = stdio.NewTransport()
	default:
		return nil, fmt.Errorf("unsupported transport type: %s", cfg.Server.Transport)
	}

	// Initialize MCP server
	mcpServer := mcp.NewServer(transport)

	server := &Server{
		config:      cfg.Server,
		chClient:    chClient,
		mcpServer:   mcpServer,
		shutdownCtx: ctx,
		shutdown:    cancel,
	}

	// Register tools
	server.registerTools()

	return server, nil
}

// registerTools registers all MCP tools
func (s *Server) registerTools() {
	// List Tables Tool
	err := s.mcpServer.RegisterTool(mcp.Tool{
		Name:        "list_tables",
		Description: "Lists all tables in the ClickHouse database",
		Handler: func(ctx context.Context, payload json.RawMessage) (interface{}, error) {
			return s.handleListTables(ctx, payload)
		},
	})
	if err != nil {
		log.Error().Err(err).Msg("Failed to register list_tables tool")
	}

	// Execute Query Tool
	err = s.mcpServer.RegisterTool(mcp.Tool{
		Name:        "execute_query",
		Description: "Executes a SQL query with optional parameters",
		Handler: func(ctx context.Context, payload json.RawMessage) (interface{}, error) {
			return s.handleExecuteQuery(ctx, payload)
		},
	})
	if err != nil {
		log.Error().Err(err).Msg("Failed to register execute_query tool")
	}

	log.Info().Msg("MCP tools registered")
}

// handleListTables handles the list_tables tool request
func (s *Server) handleListTables(ctx context.Context, args json.RawMessage) (interface{}, error) {
	log.Debug().Msg("Handling list_tables request")

	// Execute the list tables operation
	tables, err := s.chClient.ListTables(ctx)
	if err != nil {
		log.Error().Err(err).Msg("Failed to list tables")
		return nil, fmt.Errorf("failed to list tables: %w", err)
	}

	response := ListTablesResponse{
		Tables: tables,
		Count:  len(tables),
	}

	log.Debug().
		Int("table_count", response.Count).
		Msg("Successfully listed tables")

	return response, nil
}

// handleExecuteQuery handles the execute_query tool request
func (s *Server) handleExecuteQuery(ctx context.Context, args json.RawMessage) (interface{}, error) {
	log.Debug().Msg("Handling execute_query request")

	// Parse request
	var request ExecuteQueryRequest
	if err := json.Unmarshal(args, &request); err != nil {
		log.Error().Err(err).Msg("Failed to parse execute_query request")
		return nil, fmt.Errorf("invalid request format: %w", err)
	}

	// Validate query
	if request.Query == "" {
		return nil, fmt.Errorf("query cannot be empty")
	}

	// Execute the query
	result, err := s.chClient.ExecuteQuery(ctx, request.Query, request.Parameters...)
	if err != nil {
		log.Error().
			Err(err).
			Str("query", request.Query).
			Interface("params", request.Parameters).
			Msg("Failed to execute query")
		return nil, fmt.Errorf("query execution failed: %w", err)
	}

	log.Debug().
		Int("row_count", result.Count).
		Int("column_count", len(result.Columns)).
		Str("query", request.Query).
		Msg("Successfully executed query")

	return result, nil
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
	case config.HTTPTransport, config.SSETransport:
		return s.startHTTPServer()
	case config.StdioTransport:
		return s.mcpServer.Start()
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

	// Create HTTP server
	mux := http.NewServeMux()
	mux.Handle("/mcp", s.mcpServer.Handle())

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
