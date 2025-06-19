package server

import (
	"altinity-mcp/clickhouse"
	"altinity-mcp/config"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/centralmind/mcp-golang"
	"github.com/rs/zerolog/log"
)

// Server represents the MCP server
type Server struct {
	config      config.ServerConfig
	chClient    *clickhouse.Client
	mcpServer   *mcp.Server
	httpServer  *http.Server
	tools       []mcp.Tool
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

	server := &Server{
		config:      cfg.Server,
		chClient:    chClient,
		shutdownCtx: ctx,
		shutdown:    cancel,
	}

	// Initialize MCP server
	mcpServer, err := mcp.NewServer()
	if err != nil {
		return nil, fmt.Errorf("failed to create MCP server: %w", err)
	}
	server.mcpServer = mcpServer

	// Register tools
	server.registerTools()

	return server, nil
}

// registerTools registers all MCP tools
func (s *Server) registerTools() {
	// List Tables Tool
	listTablesTool := mcp.Tool{
		Name:        "list_tables",
		Description: "Lists all tables in the ClickHouse database",
		Execute:     s.handleListTables,
		ArgsSchema: json.RawMessage(`{
			"type": "object",
			"properties": {},
			"additionalProperties": false
		}`),
	}

	// Execute Query Tool
	executeQueryTool := mcp.Tool{
		Name:        "execute_query",
		Description: "Executes a SQL query with optional parameters",
		Execute:     s.handleExecuteQuery,
		ArgsSchema: json.RawMessage(`{
			"type": "object",
			"required": ["query"],
			"properties": {
				"query": {
					"type": "string",
					"description": "SQL query to execute"
				},
				"parameters": {
					"type": "array",
					"description": "Query parameters",
					"items": {
						"type": ["string", "number", "boolean", "null"]
					}
				}
			},
			"additionalProperties": false
		}`),
	}

	// Register tools with MCP server
	s.mcpServer.RegisterTool(listTablesTool)
	s.mcpServer.RegisterTool(executeQueryTool)
	s.tools = append(s.tools, listTablesTool, executeQueryTool)

	log.Info().
		Int("tool_count", len(s.tools)).
		Msg("MCP tools registered")
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
	case config.StdioTransport:
		return s.startStdioServer()
	case config.HTTPTransport:
		return s.startHTTPServer()
	case config.SSETransport:
		return s.startSSEServer()
	default:
		return fmt.Errorf("unsupported transport type: %s", s.config.Transport)
	}
}

// startStdioServer starts the MCP server with stdio transport
func (s *Server) startStdioServer() error {
	log.Info().Msg("Starting MCP server with stdio transport")
	return s.mcpServer.ServeStdio()
}

// startHTTPServer starts the MCP server with HTTP transport
func (s *Server) startHTTPServer() error {
	addr := fmt.Sprintf("%s:%d", s.config.Address, s.config.Port)
	log.Info().
		Str("address", addr).
		Msg("Starting MCP server with HTTP transport")

	// Create HTTP server
	mux := http.NewServeMux()
	mux.Handle("/mcp", s.mcpServer.HTTPHandler())

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

	// Create HTTP server with SSE handler
	mux := http.NewServeMux()
	mux.Handle("/mcp", s.mcpServer.SSEHandler())

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
