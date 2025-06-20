package server

import (
	"context"
	"fmt"

	"github.com/altinity/altinity-mcp/pkg/clickhouse"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v3"
)

// NewServer creates a new MCP server with ClickHouse integration
func NewServer(chClient *clickhouse.Client) *server.MCPServer {
	// Create MCP server with basic configuration
	srv := server.NewMCPServer(
		"Altinity MCP Server",
		"1.0.0",
		server.WithToolCapabilities(true),
		server.WithRecovery(),
	)

	// Register tools
	registerTools(srv, chClient)

	return srv
}

// registerTools adds the ClickHouse tools to the MCP server
func registerTools(srv *server.MCPServer, chClient *clickhouse.Client) {
	// List Tables Tool
	listTablesTool := mcp.NewTool(
		"list_tables",
		mcp.WithDescription("Lists all tables in the ClickHouse database"),
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

		yamlData, err := yaml.Marshal(response)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Failed to marshal response: %v", err)), nil
		}

		return mcp.NewToolResultText(string(yamlData)), nil
	})

	// Execute Query Tool
	executeQueryTool := mcp.NewTool(
		"execute_query",
		mcp.WithDescription("Executes a SQL query and returns the results"),
		mcp.WithString("query",
			mcp.Required(),
			mcp.Description("SQL query to execute"),
		),
	)

	srv.AddTool(executeQueryTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		query, err := req.RequireString("query")
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		result, err := chClient.ExecuteQuery(ctx, query)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Query execution failed: %v", err)), nil
		}

		yamlData, err := yaml.Marshal(result)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Failed to marshal result: %v", err)), nil
		}

		return mcp.NewToolResultText(string(yamlData)), nil
	})

	log.Info().Msg("MCP tools registered")
}
