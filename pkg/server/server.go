package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/altinity/altinity-mcp/pkg/clickhouse"
	"github.com/altinity/altinity-mcp/pkg/config"
	"github.com/golang-jwt/jwt/v5"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/rs/zerolog/log"
)

var (
	// ErrMissingToken is returned when JWT token is missing
	ErrMissingToken = errors.New("missing JWT token")
	// ErrInvalidToken is returned when JWT token is invalid
	ErrInvalidToken = errors.New("invalid JWT token")
)

// ClickHouseJWTServer extends MCPServer with JWT auth capabilities
type ClickHouseJWTServer struct {
	*server.MCPServer
	jwtConfig        config.JWTConfig
	clickhouseConfig config.ClickHouseConfig
}

// AltinityMCPServer @todo remove after resolve https://github.com/mark3labs/mcp-go/issues/436
type AltinityMCPServer interface {
	AddTools(tools ...server.ServerTool)
	AddTool(tool mcp.Tool, handler server.ToolHandlerFunc)
	AddPrompt(prompt mcp.Prompt, handler server.PromptHandlerFunc)
	AddPrompts(prompts ...server.ServerPrompt)
	AddResource(resource mcp.Resource, handler server.ResourceHandlerFunc)
	AddResources(resources ...server.ServerResource)
	AddResourceTemplate(template mcp.ResourceTemplate, handler server.ResourceTemplateHandlerFunc)
}

// NewClickHouseMCPServer creates a new MCP server with ClickHouse integration
func NewClickHouseMCPServer(chConfig config.ClickHouseConfig, jwtConfig config.JWTConfig) *ClickHouseJWTServer {
	// Create MCP server with comprehensive configuration
	srv := server.NewMCPServer(
		"Altinity ClickHouse MCP Server",
		"1.0.0",
		server.WithToolCapabilities(true),
		server.WithResourceCapabilities(true, true),
		server.WithPromptCapabilities(true),
		server.WithRecovery(),
	)

	chJwtServer := &ClickHouseJWTServer{
		MCPServer:        srv,
		jwtConfig:        jwtConfig,
		clickhouseConfig: chConfig,
	}

	// Register tools, resources, and prompts
	RegisterTools(chJwtServer)
	RegisterResources(chJwtServer)
	RegisterPrompts(chJwtServer)

	log.Info().
		Bool("jwt_enabled", jwtConfig.Enabled).
		Msg("ClickHouse MCP server initialized with tools, resources, and prompts")

	return chJwtServer
}

// GetClickHouseClient creates a ClickHouse client from JWT token or falls back to default config
func (s *ClickHouseJWTServer) GetClickHouseClient(ctx context.Context, tokenParam string) (*clickhouse.Client, error) {
	if !s.jwtConfig.Enabled || tokenParam == "" {
		// If JWT auth is disabled or no token provided, use the default config
		client, err := clickhouse.NewClient(ctx, s.clickhouseConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to create ClickHouse client: %w", err)
		}
		return client, nil
	}

	// Parse and validate JWT token
	token, err := jwt.Parse(tokenParam, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(s.jwtConfig.SecretKey), nil
	})

	if err != nil || !token.Valid {
		log.Error().Err(err).Msg("Invalid JWT token")
		return nil, ErrInvalidToken
	}

	// Extract ClickHouse config from token claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims format")
	}

	// Create a new ClickHouse config from the claims
	chConfig := s.clickhouseConfig // Use default as base

	if host, ok := claims["host"].(string); ok && host != "" {
		chConfig.Host = host
	}
	if port, ok := claims["port"].(float64); ok && port > 0 {
		chConfig.Port = int(port)
	}
	if database, ok := claims["database"].(string); ok && database != "" {
		chConfig.Database = database
	}
	if username, ok := claims["username"].(string); ok && username != "" {
		chConfig.Username = username
	}
	if password, ok := claims["password"].(string); ok && password != "" {
		chConfig.Password = password
	}
	if protocol, ok := claims["protocol"].(string); ok && protocol != "" {
		chConfig.Protocol = config.ClickHouseProtocol(protocol)
	}

	// Handle TLS configuration from JWT claims
	if tlsEnabled, ok := claims["tls_enabled"].(bool); ok && tlsEnabled {
		chConfig.TLS.Enabled = true

		if caCert, ok := claims["tls_ca_cert"].(string); ok && caCert != "" {
			chConfig.TLS.CaCert = caCert
		}
		if clientCert, ok := claims["tls_client_cert"].(string); ok && clientCert != "" {
			chConfig.TLS.ClientCert = clientCert
		}
		if clientKey, ok := claims["tls_client_key"].(string); ok && clientKey != "" {
			chConfig.TLS.ClientKey = clientKey
		}
		if insecureSkipVerify, ok := claims["tls_insecure_skip_verify"].(bool); ok {
			chConfig.TLS.InsecureSkipVerify = insecureSkipVerify
		}
	}

	// Create client with the configured parameters
	client, err := clickhouse.NewClient(ctx, chConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create ClickHouse client from JWT: %w", err)
	}

	return client, nil
}

// ExtractTokenFromRequest extracts JWT token from various request types
func (s *ClickHouseJWTServer) ExtractTokenFromRequest(req interface{}) string {
	tokenParam := s.jwtConfig.TokenParam

	// Extract token based on request type
	switch r := req.(type) {
	case mcp.CallToolRequest:
		// For tool requests, check if token is passed as an argument
		if args := r.GetArguments(); args != nil {
			if token, ok := args[tokenParam].(string); ok && token != "" {
				return token
			}
		}
	case mcp.ReadResourceRequest:
		// For resource requests, extract token from URI
		if r.Params.URI != "" {
			return s.extractTokenFromURI(r.Params.URI)
		}
	}

	return ""
}

// extractTokenFromURI extracts JWT token from URI
// Supports both query parameter (?token=...) and path-based token (/{token}/...)
func (s *ClickHouseJWTServer) extractTokenFromURI(uri string) string {
	tokenParam := s.jwtConfig.TokenParam

	// First try to extract from query parameters
	if strings.Contains(uri, "?") {
		uriParts := strings.Split(uri, "?")
		if len(uriParts) > 1 {
			queryParams, err := url.ParseQuery(uriParts[1])
			if err == nil {
				if token := queryParams.Get(tokenParam); token != "" {
					return token
				}
			}
		}
	}

	// For SSE transport, token might be embedded in the path
	// Expected format: clickhouse://table/{database}/{table_name}?token=...
	// or for SSE with dynamic paths: /{token}/resource_uri
	
	// Try to extract token from path segments
	// This handles cases where the SSE server uses dynamic base paths with tokens
	if strings.HasPrefix(uri, "clickhouse://") {
		// Standard resource URI - token should be in query params (handled above)
		return ""
	}

	// Handle potential path-based token extraction for SSE transport
	// If URI starts with a path segment that looks like a token, extract it
	pathParts := strings.Split(strings.TrimPrefix(uri, "/"), "/")
	if len(pathParts) > 0 && pathParts[0] != "" {
		// Simple heuristic: if first path segment looks like a JWT token (contains dots)
		if strings.Count(pathParts[0], ".") >= 2 {
			return pathParts[0]
		}
	}

	return ""
}

// RegisterTools adds the ClickHouse tools to the MCP server
func RegisterTools(srv AltinityMCPServer) {
	// List Tables Tool
	listTablesTool := mcp.NewTool(
		"list_tables",
		mcp.WithDescription("Lists all tables in a ClickHouse database with detailed information. Can be filtered by database."),
		mcp.WithString("database",
			mcp.Description("Optional: The database to list tables from. If not provided, lists tables from all databases."),
		),
	)

	srv.AddTool(listTablesTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		log.Debug().Msg("Executing list_tables tool")
		database := req.GetString("database", "")

		// Get the ClickHouse client from JWT token or default config
		chJwtServer, ok := srv.(*ClickHouseJWTServer)
		if !ok {
			return mcp.NewToolResultError("Server does not support JWT authentication"), nil
		}

		// Extract token from request or context
		token := chJwtServer.ExtractTokenFromRequest(req)
		if token == "" {
			// Try to get token from context (set by SSE server)
			if tokenFromCtx := ctx.Value("jwt_token"); tokenFromCtx != nil {
				if tokenStr, ok := tokenFromCtx.(string); ok {
					token = tokenStr
				}
			}
		}

		// Get ClickHouse client
		chClient, err := chJwtServer.GetClickHouseClient(ctx, token)
		if err != nil {
			log.Error().Err(err).Msg("Failed to get ClickHouse client")
			return mcp.NewToolResultError(fmt.Sprintf("Failed to get ClickHouse client: %v", err)), nil
		}
		defer chClient.Close()

		tables, err := chClient.ListTables(ctx, database)
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

		// Get the ClickHouse client from JWT token or default config
		chJwtServer, ok := srv.(*ClickHouseJWTServer)
		if !ok {
			return mcp.NewToolResultError("Server does not support JWT authentication"), nil
		}

		// Extract token from request or context
		token := chJwtServer.ExtractTokenFromRequest(req)
		if token == "" {
			// Try to get token from context (set by SSE server)
			if tokenFromCtx := ctx.Value("jwt_token"); tokenFromCtx != nil {
				if tokenStr, ok := tokenFromCtx.(string); ok {
					token = tokenStr
				}
			}
		}

		// Get ClickHouse client
		chClient, err := chJwtServer.GetClickHouseClient(ctx, token)
		if err != nil {
			log.Error().Err(err).Msg("Failed to get ClickHouse client")
			return mcp.NewToolResultError(fmt.Sprintf("Failed to get ClickHouse client: %v", err)), nil
		}
		defer chClient.Close()

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
		mcp.WithString("database",
			mcp.Required(),
			mcp.Description("Name of the database the table belongs to"),
		),
		mcp.WithString("table_name",
			mcp.Required(),
			mcp.Description("Name of the table to describe"),
		),
	)

	srv.AddTool(describeTableTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		database, err := req.RequireString("database")
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		tableName, err := req.RequireString("table_name")
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		log.Debug().Str("database", database).Str("table", tableName).Msg("Describing table structure")

		// Get the ClickHouse client from JWT token or default config
		chJwtServer, ok := srv.(*ClickHouseJWTServer)
		if !ok {
			return mcp.NewToolResultError("Server does not support JWT authentication"), nil
		}

		// Extract token from request or context
		token := chJwtServer.ExtractTokenFromRequest(req)
		if token == "" {
			// Try to get token from context (set by SSE server)
			if tokenFromCtx := ctx.Value("jwt_token"); tokenFromCtx != nil {
				if tokenStr, ok := tokenFromCtx.(string); ok {
					token = tokenStr
				}
			}
		}

		// Get ClickHouse client
		chClient, err := chJwtServer.GetClickHouseClient(ctx, token)
		if err != nil {
			log.Error().Err(err).Msg("Failed to get ClickHouse client")
			return mcp.NewToolResultError(fmt.Sprintf("Failed to get ClickHouse client: %v", err)), nil
		}
		defer chClient.Close()

		columns, err := chClient.DescribeTable(ctx, database, tableName)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Failed to describe table: %v", err)), nil
		}

		jsonData, err := json.MarshalIndent(columns, "", "  ")
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Failed to marshal result: %v", err)), nil
		}

		return mcp.NewToolResultText(string(jsonData)), nil
	})

	log.Info().Int("tool_count", 3).Msg("ClickHouse tools registered")
}

// RegisterResources adds ClickHouse resources to the MCP server
func RegisterResources(srv AltinityMCPServer) {
	// Database Schema Resource
	schemaResource := mcp.NewResource(
		"clickhouse://schema",
		"Database Schema",
		mcp.WithResourceDescription("Complete schema information for the ClickHouse database"),
		mcp.WithMIMEType("application/json"),
	)

	srv.AddResource(schemaResource, func(ctx context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
		log.Debug().Msg("Reading database schema resource")

		// Get the ClickHouse client from JWT token or default config
		chJwtServer, ok := srv.(*ClickHouseJWTServer)
		if !ok {
			return nil, fmt.Errorf("server does not support JWT authentication")
		}

		// Extract token from request or context
		token := chJwtServer.ExtractTokenFromRequest(req)
		if token == "" {
			// Try to get token from context (set by SSE server)
			if tokenFromCtx := ctx.Value("jwt_token"); tokenFromCtx != nil {
				if tokenStr, ok := tokenFromCtx.(string); ok {
					token = tokenStr
				}
			}
		}

		// Get ClickHouse client
		chClient, err := chJwtServer.GetClickHouseClient(ctx, token)
		if err != nil {
			log.Error().Err(err).Msg("Failed to get ClickHouse client")
			return nil, fmt.Errorf("failed to get ClickHouse client: %w", err)
		}
		defer chClient.Close()

		// With an empty database string, ListTables will return tables from all databases
		tables, err := chClient.ListTables(ctx, "")
		if err != nil {
			return nil, fmt.Errorf("failed to get schema: %w", err)
		}

		schema := map[string]interface{}{
			"tables": tables,
			"count":  len(tables),
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
		"clickhouse://table/{database}/{table_name}",
		"Table Structure",
		mcp.WithTemplateDescription("Detailed structure information for a specific table"),
		mcp.WithTemplateMIMEType("application/json"),
	)

	srv.AddResourceTemplate(tableTemplate, func(ctx context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
		// Extract database and table name from URI
		uri := req.Params.URI
		parts := strings.Split(uri, "/")
		if len(parts) < 5 { // clickhouse://table/{database}/{table_name}
			return nil, fmt.Errorf("invalid table URI format: %s", uri)
		}
		database := parts[len(parts)-2]
		tableName := parts[len(parts)-1]

		log.Debug().Str("database", database).Str("table", tableName).Msg("Reading table structure resource")

		// Get the ClickHouse client from JWT token or default config
		chJwtServer, ok := srv.(*ClickHouseJWTServer)
		if !ok {
			return nil, fmt.Errorf("server does not support JWT authentication")
		}

		// Extract token from request or context
		token := chJwtServer.ExtractTokenFromRequest(req)
		if token == "" {
			// Try to get token from context (set by SSE server)
			if tokenFromCtx := ctx.Value("jwt_token"); tokenFromCtx != nil {
				if tokenStr, ok := tokenFromCtx.(string); ok {
					token = tokenStr
				}
			}
		}

		// Get ClickHouse client
		chClient, err := chJwtServer.GetClickHouseClient(ctx, token)
		if err != nil {
			log.Error().Err(err).Msg("Failed to get ClickHouse client")
			return nil, fmt.Errorf("failed to get ClickHouse client: %w", err)
		}
		defer chClient.Close()

		columns, err := chClient.DescribeTable(ctx, database, tableName)
		if err != nil {
			return nil, fmt.Errorf("failed to get table structure: %w", err)
		}

		jsonData, err := json.MarshalIndent(columns, "", "  ")
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

// RegisterPrompts adds ClickHouse prompts to the MCP server
func RegisterPrompts(srv AltinityMCPServer) {
	// Query Builder Prompt
	queryBuilderPrompt := mcp.NewPrompt(
		"query_builder",
		mcp.WithPromptDescription("Helps build efficient ClickHouse SQL queries"),
		mcp.WithArgument("database",
			mcp.ArgumentDescription("Name of the database for the query"),
			mcp.RequiredArgument(),
		),
		mcp.WithArgument("table_name",
			mcp.ArgumentDescription("Name of the table to query"),
		),
		mcp.WithArgument("query_type",
			mcp.ArgumentDescription("Type of query (select, insert, create, etc.)"),
		),
	)

	srv.AddPrompt(queryBuilderPrompt, func(ctx context.Context, req mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
		database, ok := req.Params.Arguments["database"]
		if !ok || database == "" {
			return nil, fmt.Errorf("database parameter is required")
		}
		tableName := req.Params.Arguments["table_name"]
		queryType := req.Params.Arguments["query_type"]

		var promptText string
		if tableName != "" {
			promptText = fmt.Sprintf("Help me build a %s query for the ClickHouse table '%s.%s'. ", queryType, database, tableName)
		} else {
			promptText = fmt.Sprintf("Help me build a %s query for ClickHouse in database '%s'. ", queryType, database)
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
					URI:      fmt.Sprintf("clickhouse://table/%s/%s", database, tableName),
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
