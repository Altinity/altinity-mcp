package server

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/altinity/altinity-mcp/pkg/clickhouse"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/rs/zerolog/log"
)

// NewClickHouseServer creates a new MCP server with ClickHouse integration
func NewClickHouseServer(chClient *clickhouse.Client) *server.MCPServer {
	// Create MCP server with comprehensive configuration
	srv := server.NewMCPServer(
		"Altinity ClickHouse MCP Server",
		"1.0.0",
		server.WithToolCapabilities(true),
		server.WithResourceCapabilities(true, true),
		server.WithPromptCapabilities(true),
		server.WithRecovery(),
	)

	// Register tools, resources, and prompts
	registerTools(srv, chClient)
	registerResources(srv, chClient)
	registerPrompts(srv, chClient)

	log.Info().Msg("ClickHouse MCP server initialized with tools, resources, and prompts")
	return srv
}

// registerTools adds the ClickHouse tools to the MCP server
func registerTools(srv *server.MCPServer, chClient *clickhouse.Client) {
	// List Tables Tool
	listTablesTool := mcp.NewTool(
		"list_tables",
		mcp.WithDescription("Lists all tables in the ClickHouse database with detailed information"),
	)

	srv.AddTool(listTablesTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		log.Debug().Msg("Executing list_tables tool")
		
		tables, err := chClient.ListTables(ctx)
		if err != nil {
			log.Error().Err(err).Msg("Failed to list tables")
			return mcp.NewToolResultError(fmt.Sprintf("Failed to list tables: %v", err)), nil
		}

		response := map[string]interface{}{
			"tables": tables,
			"count":  len(tables),
		}

		jsonData, err := json.MarshalIndent(response, "", "  ")
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Failed to marshal response: %v", err)), nil
		}

		return mcp.NewToolResultText(string(jsonData)), nil
	})

	// Execute Query Tool
	executeQueryTool := mcp.NewTool(
		"execute_query",
		mcp.WithDescription("Executes a SQL query against ClickHouse and returns the results"),
		mcp.WithString("query",
			mcp.Required(),
			mcp.Description("SQL query to execute (SELECT, INSERT, CREATE, etc.)"),
		),
		mcp.WithNumber("limit",
			mcp.Description("Maximum number of rows to return (default: 1000, max: 10000)"),
		),
	)

	srv.AddTool(executeQueryTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		query, err := req.RequireString("query")
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		// Get optional limit parameter
		limit := 1000.0 // default
		if limitVal, exists := req.GetArguments()["limit"]; exists {
			if l, ok := limitVal.(float64); ok {
				if l > 10000 {
					return mcp.NewToolResultError("Limit cannot exceed 10,000 rows"), nil
				}
				if l > 0 {
					limit = l
				}
			}
		}

		log.Debug().
			Str("query", query).
			Float64("limit", limit).
			Msg("Executing query")

		// Add LIMIT clause for SELECT queries if not already present
		if isSelectQuery(query) && !hasLimitClause(query) {
			query = fmt.Sprintf("%s LIMIT %.0f", strings.TrimSpace(query), limit)
		}

		result, err := chClient.ExecuteQuery(ctx, query)
		if err != nil {
			log.Error().Err(err).Str("query", query).Msg("Query execution failed")
			return mcp.NewToolResultError(fmt.Sprintf("Query execution failed: %v", err)), nil
		}

		jsonData, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Failed to marshal result: %v", err)), nil
		}

		return mcp.NewToolResultText(string(jsonData)), nil
	})

	// Describe Table Tool
	describeTableTool := mcp.NewTool(
		"describe_table",
		mcp.WithDescription("Describes the structure of a ClickHouse table including columns, types, and constraints"),
		mcp.WithString("table_name",
			mcp.Required(),
			mcp.Description("Name of the table to describe"),
		),
	)

	srv.AddTool(describeTableTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		tableName, err := req.RequireString("table_name")
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		log.Debug().Str("table", tableName).Msg("Describing table structure")

		query := `
			SELECT 
				name,
				type,
				default_kind,
				default_expression,
				comment,
				is_in_partition_key,
				is_in_sorting_key,
				is_in_primary_key,
				is_in_sampling_key
			FROM system.columns 
			WHERE database = ? AND table = ?
			ORDER BY position
		`

		result, err := chClient.ExecuteQuery(ctx, query, chClient.GetDatabase(), tableName)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Failed to describe table: %v", err)), nil
		}

		jsonData, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Failed to marshal result: %v", err)), nil
		}

		return mcp.NewToolResultText(string(jsonData)), nil
	})

	log.Info().Int("tool_count", 3).Msg("ClickHouse tools registered")
}

// registerResources adds ClickHouse resources to the MCP server
func registerResources(srv *server.MCPServer, chClient *clickhouse.Client) {
	// Database Schema Resource
	schemaResource := mcp.NewResource(
		"clickhouse://schema",
		"Database Schema",
		mcp.WithResourceDescription("Complete schema information for the ClickHouse database"),
		mcp.WithMIMEType("application/json"),
	)

	srv.AddResource(schemaResource, func(ctx context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
		log.Debug().Msg("Reading database schema resource")

		tables, err := chClient.ListTables(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get schema: %w", err)
		}

		schema := map[string]interface{}{
			"database": chClient.GetDatabase(),
			"tables":   tables,
			"count":    len(tables),
		}

		jsonData, err := json.MarshalIndent(schema, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("failed to marshal schema: %w", err)
		}

		return []mcp.ResourceContents{
			mcp.TextResourceContents{
				URI:      "clickhouse://schema",
				MIMEType: "application/json",
				Text:     string(jsonData),
			},
		}, nil
	})

	// Table Structure Template Resource
	tableTemplate := mcp.NewResourceTemplate(
		"clickhouse://table/{table_name}",
		"Table Structure",
		mcp.WithTemplateDescription("Detailed structure information for a specific table"),
		mcp.WithTemplateMIMEType("application/json"),
	)

	srv.AddResourceTemplate(tableTemplate, func(ctx context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
		// Extract table name from URI
		uri := req.Params.URI
		parts := strings.Split(uri, "/")
		if len(parts) < 3 {
			return nil, fmt.Errorf("invalid table URI format")
		}
		tableName := parts[len(parts)-1]

		log.Debug().Str("table", tableName).Msg("Reading table structure resource")

		query := `
			SELECT 
				name,
				type,
				default_kind,
				default_expression,
				comment,
				is_in_partition_key,
				is_in_sorting_key,
				is_in_primary_key,
				is_in_sampling_key
			FROM system.columns 
			WHERE database = ? AND table = ?
			ORDER BY position
		`

		result, err := chClient.ExecuteQuery(ctx, query, "default", tableName)
		if err != nil {
			return nil, fmt.Errorf("failed to get table structure: %w", err)
		}

		jsonData, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("failed to marshal table structure: %w", err)
		}

		return []mcp.ResourceContents{
			mcp.TextResourceContents{
				URI:      uri,
				MIMEType: "application/json",
				Text:     string(jsonData),
			},
		}, nil
	})

	log.Info().Int("resource_count", 2).Msg("ClickHouse resources registered")
}

// registerPrompts adds ClickHouse prompts to the MCP server
func registerPrompts(srv *server.MCPServer, chClient *clickhouse.Client) {
	// Query Builder Prompt
	queryBuilderPrompt := mcp.NewPrompt(
		"query_builder",
		mcp.WithPromptDescription("Helps build efficient ClickHouse SQL queries"),
		mcp.WithArgument("table_name",
			mcp.ArgumentDescription("Name of the table to query"),
		),
		mcp.WithArgument("query_type",
			mcp.ArgumentDescription("Type of query (select, insert, create, etc.)"),
		),
	)

	srv.AddPrompt(queryBuilderPrompt, func(ctx context.Context, req mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
		tableName := req.Params.Arguments["table_name"]
		queryType := req.Params.Arguments["query_type"]

		var promptText string
		if tableName != "" {
			promptText = fmt.Sprintf("Help me build a %s query for the ClickHouse table '%s'. ", queryType, tableName)
		} else {
			promptText = fmt.Sprintf("Help me build a %s query for ClickHouse. ", queryType)
		}

		promptText += "Consider ClickHouse-specific optimizations like:\n" +
			"- Using appropriate ORDER BY for MergeTree tables\n" +
			"- Leveraging partition pruning when possible\n" +
			"- Using PREWHERE for filtering before data reading\n" +
			"- Considering data types and compression\n" +
			"- Using appropriate JOIN algorithms\n\n" +
			"Please provide the table schema if you need structure information."

		messages := []mcp.PromptMessage{
			mcp.NewPromptMessage(
				mcp.RoleUser,
				mcp.NewTextContent(promptText),
			),
		}

		// Add table schema if table name is provided
		if tableName != "" {
			messages = append(messages, mcp.NewPromptMessage(
				mcp.RoleUser,
				mcp.NewEmbeddedResource(mcp.TextResourceContents{
					URI:      fmt.Sprintf("clickhouse://table/%s", tableName),
					MIMEType: "application/json",
					Text:     "", // Will be populated when resource is read
				}),
			))
		}

		return mcp.NewGetPromptResult(
			"ClickHouse Query Builder Assistant",
			messages,
		), nil
	})

	// Performance Analysis Prompt
	perfAnalysisPrompt := mcp.NewPrompt(
		"performance_analysis",
		mcp.WithPromptDescription("Analyzes ClickHouse query performance and suggests optimizations"),
		mcp.WithArgument("query",
			mcp.ArgumentDescription("SQL query to analyze"),
			mcp.RequiredArgument(),
		),
	)

	srv.AddPrompt(perfAnalysisPrompt, func(ctx context.Context, req mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
		query := req.Params.Arguments["query"]
		if query == "" {
			return nil, fmt.Errorf("query parameter is required")
		}

		promptText := fmt.Sprintf("Analyze this ClickHouse query for performance optimization:\n\n```sql\n%s\n```\n\n", query) +
			"Please consider:\n" +
			"- Index usage and effectiveness\n" +
			"- Partition pruning opportunities\n" +
			"- JOIN optimization strategies\n" +
			"- Memory usage patterns\n" +
			"- Parallelization potential\n" +
			"- Data compression impact\n" +
			"- Alternative query structures\n\n" +
			"Provide specific recommendations for improvement."

		return mcp.NewGetPromptResult(
			"ClickHouse Performance Analysis",
			[]mcp.PromptMessage{
				mcp.NewPromptMessage(
					mcp.RoleUser,
					mcp.NewTextContent(promptText),
				),
				mcp.NewPromptMessage(
					mcp.RoleUser,
					mcp.NewEmbeddedResource(mcp.TextResourceContents{
						URI:      "clickhouse://schema",
						MIMEType: "application/json",
						Text:     "", // Will be populated when resource is read
					}),
				),
			},
		), nil
	})

	log.Info().Int("prompt_count", 2).Msg("ClickHouse prompts registered")
}

// Helper functions
func isSelectQuery(query string) bool {
	trimmed := strings.TrimSpace(strings.ToUpper(query))
	return strings.HasPrefix(trimmed, "SELECT") || strings.HasPrefix(trimmed, "WITH")
}

func hasLimitClause(query string) bool {
	upper := strings.ToUpper(query)
	return strings.Contains(upper, " LIMIT ")
}
