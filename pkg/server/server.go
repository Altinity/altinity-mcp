package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
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
	Config           config.Config
}

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
func NewClickHouseMCPServer(cfg config.Config) *ClickHouseJWTServer {
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
		MCPServer: srv,
		Config:    cfg,
	}

	// Register tools, resources, and prompts
	RegisterTools(chJwtServer)
	RegisterResources(chJwtServer)
	RegisterPrompts(chJwtServer)

	log.Info().
		Bool("jwt_enabled", cfg.Server.JWT.Enabled).
		Int("default_limit", cfg.ClickHouse.Limit).
		Msg("ClickHouse MCP server initialized with tools, resources, and prompts")

	return chJwtServer
}

// GetClickHouseClient creates a ClickHouse client from JWT token or falls back to default config
func (s *ClickHouseJWTServer) GetClickHouseClient(ctx context.Context, tokenParam string) (*clickhouse.Client, error) {
	if !s.Config.Server.JWT.Enabled {
		// If JWT auth is disabled, use the default config
		client, err := clickhouse.NewClient(ctx, s.Config.ClickHouse)
		if err != nil {
			return nil, fmt.Errorf("failed to create ClickHouse client: %w", err)
		}
		return client, nil
	}

	if tokenParam == "" {
		// JWT auth is enabled but no token provided
		return nil, ErrMissingToken
	}

	// Parse and validate JWT token
	claims, err := s.parseAndValidateJWT(tokenParam)
	if err != nil {
		return nil, err
	}

	// Create ClickHouse config from JWT claims
	chConfig, err := s.buildConfigFromClaims(claims)
	if err != nil {
		return nil, err
	}

	// Create client with the configured parameters
	client, err := clickhouse.NewClient(ctx, chConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create ClickHouse client from JWT: %w", err)
	}

	return client, nil
}

// parseAndValidateJWT parses and validates a JWT token
func (s *ClickHouseJWTServer) parseAndValidateJWT(tokenParam string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenParam, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(s.Config.Server.JWT.SecretKey), nil
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

	// Validate claims against whitelist
	if err := s.validateClaimsWhitelist(claims); err != nil {
		return nil, err
	}

	return claims, nil
}

// validateClaimsWhitelist validates that JWT claims only contain allowed keys
func (s *ClickHouseJWTServer) validateClaimsWhitelist(claims jwt.MapClaims) error {
	// Define whitelist of allowed claim keys
	allowedKeys := map[string]bool{
		// Standard JWT claims
		"iss": true, // issuer
		"sub": true, // subject
		"aud": true, // audience
		"exp": true, // expiration time
		"nbf": true, // not before
		"iat": true, // issued at
		"jti": true, // JWT ID

		// ClickHouse connection claims
		"host":               true,
		"port":               true,
		"database":           true,
		"username":           true,
		"password":           true,
		"protocol":           true,
		"limit":              true,
		"read_only":          true,
		"max_execution_time": true,

		// TLS configuration claims
		"tls_enabled":              true,
		"tls_ca_cert":              true,
		"tls_client_cert":          true,
		"tls_client_key":           true,
		"tls_insecure_skip_verify": true,
	}

	// Check for any disallowed keys
	for key := range claims {
		if !allowedKeys[key] {
			return fmt.Errorf("invalid token claims format: disallowed claim key '%s'", key)
		}
	}

	return nil
}

// buildConfigFromClaims builds a ClickHouse config from JWT claims
func (s *ClickHouseJWTServer) buildConfigFromClaims(claims jwt.MapClaims) (config.ClickHouseConfig, error) {
	// Create a new ClickHouse config from the claims
	chConfig := s.ClickhouseConfig // Use default as base

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
	if limit, ok := claims["limit"].(float64); ok && limit > 0 {
		chConfig.Limit = int(limit)
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

	return chConfig, nil
}

// ExtractTokenFromCtx extracts JWT token from context
func (s *ClickHouseJWTServer) ExtractTokenFromCtx(ctx context.Context) string {
	if tokenFromCtx := ctx.Value("jwt_token"); tokenFromCtx != nil {
		if tokenStr, ok := tokenFromCtx.(string); ok {
			return tokenStr
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

	srv.AddTool(listTablesTool, HandleListTables)

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

	srv.AddTool(executeQueryTool, HandleExecuteQuery)

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

	srv.AddTool(describeTableTool, HandleDescribeTable)

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

	srv.AddResource(schemaResource, HandleSchemaResource)

	// Table Structure Template Resource
	tableTemplate := mcp.NewResourceTemplate(
		"clickhouse://table/{database}/{table_name}",
		"Table Structure",
		mcp.WithTemplateDescription("Detailed structure information for a specific table"),
		mcp.WithTemplateMIMEType("application/json"),
	)

	srv.AddResourceTemplate(tableTemplate, HandleTableResource)

	log.Info().Int("resource_count", 2).Msg("ClickHouse resources registered")
}

// HandleSchemaResource handles the schema resource
func HandleSchemaResource(ctx context.Context, _ mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
	log.Debug().Msg("Reading database schema resource")

	// Get the ClickHouse JWT server from context
	chJwtServer := GetClickHouseJWTServerFromContext(ctx)
	if chJwtServer == nil {
		return nil, fmt.Errorf("can't get JWTServer from context")
	}

	// Extract token from context
	token := chJwtServer.ExtractTokenFromCtx(ctx)

	// Get ClickHouse client
	chClient, err := chJwtServer.GetClickHouseClient(ctx, token)
	if err != nil {
		log.Error().Err(err).Msg("Failed to get ClickHouse client")
		return nil, fmt.Errorf("failed to get ClickHouse client: %w", err)
	}
	defer func() {
		if closeErr := chClient.Close(); closeErr != nil {
			log.Error().
				Err(closeErr).
				Msg("clickhouse://schema: can't close clickhouse")
		}
	}()

	// With an empty database string, ListTables will return tables from all databases
	tables, err := chClient.ListTables(ctx, "")
	if err != nil {
		log.Error().
			Err(err).
			Str("resource", "schema").
			Msg("ClickHouse operation failed: get schema")
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
}

// HandleTableResource handles the table resource
func HandleTableResource(ctx context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
	// Extract database and table name from URI
	uri := req.Params.URI
	parts := strings.Split(uri, "/")
	// expected clickhouse://table/{database}/{table_name}
	if len(parts) < 5 || parts[0] != "clickhouse:" || parts[1] != "" || parts[2] != "table" {
		return nil, fmt.Errorf("invalid table URI format: %s", uri)
	}
	database := parts[len(parts)-2]
	tableName := parts[len(parts)-1]

	// Validate that database and table name are not empty
	if database == "" || tableName == "" {
		return nil, fmt.Errorf("invalid table URI format: %s", uri)
	}

	log.Debug().Str("database", database).Str("table", tableName).Msg("Reading table structure resource")

	// Get the ClickHouse JWT server from context
	chJwtServer := GetClickHouseJWTServerFromContext(ctx)
	if chJwtServer == nil {
		return nil, fmt.Errorf("can't get JWTServer from context")
	}

	// Extract token from context
	token := chJwtServer.ExtractTokenFromCtx(ctx)

	// Get ClickHouse client
	chClient, err := chJwtServer.GetClickHouseClient(ctx, token)
	if err != nil {
		log.Error().Err(err).Msg("Failed to get ClickHouse client")
		return nil, fmt.Errorf("failed to get ClickHouse client: %w", err)
	}
	defer func() {
		if closeErr := chClient.Close(); closeErr != nil {
			log.Error().
				Err(closeErr).
				Msgf("clickhouse://table/%s/%s: can't close clickhouse", database, tableName)
		}
	}()

	columns, err := chClient.DescribeTable(ctx, database, tableName)
	if err != nil {
		log.Error().
			Err(err).
			Str("database", database).
			Str("table", tableName).
			Str("resource", "table_structure").
			Msg("ClickHouse operation failed: get table structure")
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

		// Add table schema reference if table name is provided
		if tableName != "" {
			schemaPrompt := fmt.Sprintf("\n\nTo get the table schema, use the resource: clickhouse://table/%s/%s", database, tableName)
			messages = append(messages, mcp.NewPromptMessage(
				mcp.RoleUser,
				mcp.NewTextContent(schemaPrompt),
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

		schemaPrompt := "\n\nTo get the database schema, use the resource: clickhouse://schema"

		return mcp.NewGetPromptResult(
			"ClickHouse Performance Analysis",
			[]mcp.PromptMessage{
				mcp.NewPromptMessage(
					mcp.RoleUser,
					mcp.NewTextContent(promptText+schemaPrompt),
				),
			},
		), nil
	})

	log.Info().Int("prompt_count", 2).Msg("ClickHouse prompts registered")
}

// HandleListTables implements the list_tables tool handler
func HandleListTables(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	database := req.GetString("database", "")
	log.Debug().Str("database", database).Msg("Executing list_tables tool")

	// Get the ClickHouse JWT server from context
	chJwtServer := GetClickHouseJWTServerFromContext(ctx)
	if chJwtServer == nil {
		return nil, fmt.Errorf("can't get JWTServer from context")
	}

	// Extract token from context
	token := chJwtServer.ExtractTokenFromCtx(ctx)

	// Get ClickHouse client
	chClient, err := chJwtServer.GetClickHouseClient(ctx, token)
	if err != nil {
		log.Error().Err(err).Msg("Failed to get ClickHouse client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get ClickHouse client: %v", err)), nil
	}
	defer func() {
		if closeErr := chClient.Close(); closeErr != nil {
			log.Error().
				Err(closeErr).
				Msg("list_tables: can't close clickhouse")
		}
	}()

	tables, err := chClient.ListTables(ctx, database)
	if err != nil {
		log.Error().
			Err(err).
			Str("database", database).
			Str("tool", "list_tables").
			Msg("ClickHouse operation failed: list tables")
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
}

// HandleExecuteQuery implements the execute_query tool handler
func HandleExecuteQuery(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	query, err := req.RequireString("query")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	// Get the ClickHouse JWT server from context
	chJwtServer := GetClickHouseJWTServerFromContext(ctx)
	if chJwtServer == nil {
		return nil, fmt.Errorf("can't get JWTServer from context")
	}

	// Get default limit based on server type
	defaultLimit := float64(chJwtServer.ClickhouseConfig.Limit)

	// Get optional limit parameter, use server default if not provided
	limit := defaultLimit
	if limitVal, exists := req.GetArguments()["limit"]; exists {
		if l, ok := limitVal.(float64); ok {
			if l > defaultLimit {
				return mcp.NewToolResultError(fmt.Sprintf("Limit cannot exceed %.0f rows", defaultLimit)), nil
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

	// Extract token from context
	token := chJwtServer.ExtractTokenFromCtx(ctx)

	// Get ClickHouse client
	chClient, err := chJwtServer.GetClickHouseClient(ctx, token)
	if err != nil {
		log.Error().Err(err).Msg("Failed to get ClickHouse client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get ClickHouse client: %v", err)), nil
	}
	defer func() {
		if closeErr := chClient.Close(); closeErr != nil {
			log.Error().
				Err(closeErr).
				Msg("execute_query: can't close clickhouse")
		}
	}()

	result, err := chClient.ExecuteQuery(ctx, query)
	if err != nil {
		log.Error().
			Err(err).
			Str("query", query).
			Float64("limit", limit).
			Str("tool", "execute_query").
			Msg("ClickHouse operation failed: query execution")
		return mcp.NewToolResultError(fmt.Sprintf("Query execution failed: %v", err)), nil
	}

	jsonData, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to marshal result: %v", err)), nil
	}

	return mcp.NewToolResultText(string(jsonData)), nil
}

// HandleDescribeTable implements the describe_table tool handler
func HandleDescribeTable(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	database, err := req.RequireString("database")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	tableName, err := req.RequireString("table_name")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	log.Debug().Str("database", database).Str("table", tableName).Msg("Describing table structure")

	// Get the ClickHouse JWT server from context
	chJwtServer := GetClickHouseJWTServerFromContext(ctx)
	if chJwtServer == nil {
		return nil, fmt.Errorf("can't get JWTServer from context")
	}

	// Extract token from context
	token := chJwtServer.ExtractTokenFromCtx(ctx)

	// Get ClickHouse client
	chClient, err := chJwtServer.GetClickHouseClient(ctx, token)
	if err != nil {
		log.Error().Err(err).Msg("Failed to get ClickHouse client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get ClickHouse client: %v", err)), nil
	}
	defer func() {
		if closeErr := chClient.Close(); closeErr != nil {
			log.Error().
				Err(closeErr).
				Msg("describe_table: can't close clickhouse")
		}
	}()

	columns, err := chClient.DescribeTable(ctx, database, tableName)
	if err != nil {
		log.Error().
			Err(err).
			Str("database", database).
			Str("table", tableName).
			Str("tool", "describe_table").
			Msg("ClickHouse operation failed: describe table")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to describe table: %v", err)), nil
	}

	jsonData, err := json.MarshalIndent(columns, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to marshal result: %v", err)), nil
	}

	return mcp.NewToolResultText(string(jsonData)), nil
}

// GetClickHouseJWTServerFromContext extracts the ClickHouseJWTServer from context
func GetClickHouseJWTServerFromContext(ctx context.Context) *ClickHouseJWTServer {
	if srv := ctx.Value("clickhouse_jwt_server"); srv != nil {
		if chJwtServer, ok := srv.(*ClickHouseJWTServer); ok {
			return chJwtServer
		}
	}
	return nil
}

// OpenAPIHandler handles OpenAPI schema and REST API endpoints
func (s *ClickHouseJWTServer) OpenAPIHandler(w http.ResponseWriter, r *http.Request) {
	// Get server instance from context
	chJwtServer := GetClickHouseJWTServerFromContext(r.Context())
	if chJwtServer == nil {
		http.Error(w, "can't get JWTServer from context", http.StatusInternalServerError)
		return
	}

	// Try to extract token from URL path first
	pathParts := strings.Split(r.URL.Path, "/")
	var token string
	for i, part := range pathParts {
		if part == "openapi" && i > 0 {
			token = pathParts[i-1]
			break
		}
	}

	// If no token  from path or token from OpenAI GPT tester, try other sources
	if token == "" || token == "default" {
		authHeader := r.Header.Get("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") {
			token = strings.TrimPrefix(authHeader, "Bearer ")
		} else if strings.HasPrefix(authHeader, "Basic ") {
			decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(authHeader, "Basic "))
			if err == nil {
				parts := strings.SplitN(string(decoded), ":", 2)
				if len(parts) == 2 {
					token = parts[1] // Use password as token
				} else {
					token = parts[0]
				}
			}
		}

		// Try x-altinity-mcp-key header
		if token == "" {
			token = r.Header.Get("x-altinity-mcp-key")
		}
	}

	// If JWT auth is enabled, validate token if provided
	if chJwtServer.JwtConfig.Enabled && token != "" {
		_, err := chJwtServer.parseAndValidateJWT(token)
		if err != nil {
			http.Error(w, "Invalid JWT token", http.StatusInternalServerError)
			return
		}
	}

	// Get host URL based on OpenAPI TLS configuration
	protocol := "http"
	if s.ClickhouseConfig.TLS.Enabled || s.ClickhouseConfig.TLS.CaCert != "" || s.ClickhouseConfig.TLS.ClientCert != "" {
		protocol = "https"
	}
	hostURL := fmt.Sprintf("%s://%s", protocol, r.Host)

	// Route to appropriate handler based on path suffix
	switch {
	case strings.HasSuffix(r.URL.Path, "/openapi/list_tables"):
		s.handleListTablesOpenAPI(w, r, token)
	case strings.HasSuffix(r.URL.Path, "/openapi/describe_table"):
		s.handleDescribeTableOpenAPI(w, r, token)
	case strings.HasSuffix(r.URL.Path, "/openapi/execute_query"):
		s.handleExecuteQueryOpenAPI(w, r, token)
	default:
		// Serve OpenAPI schema by default
		s.serveOpenAPISchema(w, r, hostURL)
	}
}

func (s *ClickHouseJWTServer) serveOpenAPISchema(w http.ResponseWriter, _ *http.Request, hostURL string) {
	schema := map[string]interface{}{
		"openapi": "3.1.0",
		"info": map[string]interface{}{
			"title":       "ClickHouse SQL Interface",
			"version":     "1.0.0",
			"description": "Run SQL queries against a ClickHouse instance via GPT-actions.",
		},
		"servers": []map[string]interface{}{
			{
				"url":         hostURL,
				"description": "Base OpenAPI host.",
			},
		},
		"components": map[string]interface{}{
			"schemas": map[string]interface{}{},
		},
		"paths": map[string]interface{}{
			"/{jwt_token}/openapi/list_tables": map[string]interface{}{
				"get": map[string]interface{}{
					"operationId": "list_tables",
					"summary":     "List tables in a ClickHouse database",
					"parameters": []map[string]interface{}{
						{
							"name":        "jwt_token",
							"in":          "path",
							"required":    true,
							"description": "JWT token for authentication",
							"schema": map[string]interface{}{
								"type": "string",
							},
							"x-oai-meta": map[string]interface{}{"securityType": "user_api_key"},
						},
						{
							"name":        "database",
							"in":          "query",
							"required":    false,
							"description": "Database to list tables from (omit for all DBs).",
							"schema":      map[string]interface{}{"type": "string"},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "JSON list of tables",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{"type": "string"},
								},
							},
						},
					},
				},
			},
			"/{jwt_token}/openapi/execute_query": map[string]interface{}{
				"get": map[string]interface{}{
					"operationId": "execute_query",
					"summary":     "Execute a SQL query",
					"parameters": []map[string]interface{}{
						{
							"name":        "jwt_token",
							"in":          "path",
							"required":    true,
							"description": "JWT token for authentication (default — только для тестов в редакторе).",
							"schema": map[string]interface{}{
								"type": "string",
							},
							"x-oai-meta": map[string]interface{}{"securityType": "user_api_key"},
						},
						{
							"name":        "query",
							"in":          "query",
							"required":    true,
							"description": "SQL to execute (SELECT, INSERT, etc.).",
							"schema":      map[string]interface{}{"type": "string"},
						},
						{
							"name":        "limit",
							"in":          "query",
							"required":    false,
							"description": "Max rows to return (default 1000, max 10000).",
							"schema":      map[string]interface{}{"type": "integer"},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Query result as JSON",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{"type": "string"},
								},
							},
						},
					},
				},
			},
			"/{jwt_token}/openapi/describe_table": map[string]interface{}{
				"get": map[string]interface{}{
					"operationId": "describe_table",
					"summary":     "Describe a ClickHouse table",
					"parameters": []map[string]interface{}{
						{
							"name":        "jwt_token",
							"in":          "path",
							"required":    true,
							"description": "JWT token for authentication (default — только для тестов в редакторе).",
							"schema": map[string]interface{}{
								"type": "string",
							},
							"x-oai-meta": map[string]interface{}{"securityType": "user_api_key"},
						},
						{
							"name":        "database",
							"in":          "query",
							"required":    true,
							"description": "Database containing the table.",
							"schema":      map[string]interface{}{"type": "string"},
						},
						{
							"name":        "table_name",
							"in":          "query",
							"required":    true,
							"description": "Table to describe.",
							"schema":      map[string]interface{}{"type": "string"},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Table structure as JSON",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{"type": "string"},
								},
							},
						},
					},
				},
			},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	if encodeErr := json.NewEncoder(w).Encode(schema); encodeErr != nil {
		log.Err(encodeErr).Msg("can't encode /openapi schema")
	}
}

func (s *ClickHouseJWTServer) handleListTablesOpenAPI(w http.ResponseWriter, r *http.Request, token string) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	database := r.URL.Query().Get("database")

	ctx := context.WithValue(r.Context(), "jwt_token", token)

	// Get ClickHouse client
	chClient, err := s.GetClickHouseClient(ctx, token)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get ClickHouse client: %v", err), http.StatusInternalServerError)
		return
	}
	defer func() {
		if closeErr := chClient.Close(); closeErr != nil {
			log.Error().Err(closeErr).Send()
		}
	}()

	tables, err := chClient.ListTables(ctx, database)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to list tables: %v", err), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"tables": tables,
		"count":  len(tables),
	}

	w.Header().Set("Content-Type", "application/json")
	if encodeErr := json.NewEncoder(w).Encode(response); encodeErr != nil {
		log.Err(encodeErr).Msg("can't encode /openapi/list_tables result")
	}
}

func (s *ClickHouseJWTServer) handleDescribeTableOpenAPI(w http.ResponseWriter, r *http.Request, token string) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	database := r.URL.Query().Get("database")
	tableName := r.URL.Query().Get("table_name")

	if database == "" || tableName == "" {
		http.Error(w, "Both database and table_name parameters are required", http.StatusBadRequest)
		return
	}

	ctx := context.WithValue(r.Context(), "jwt_token", token)

	// Get ClickHouse client
	chClient, err := s.GetClickHouseClient(ctx, token)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get ClickHouse client: %v", err), http.StatusInternalServerError)
		return
	}
	defer func() {
		if closeErr := chClient.Close(); closeErr != nil {
			log.Error().Err(closeErr).Send()
		}
	}()

	columns, err := chClient.DescribeTable(ctx, database, tableName)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to describe table: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if encodeErr := json.NewEncoder(w).Encode(columns); encodeErr != nil {
		log.Err(encodeErr).Msg("can't encode /openapi/describe_table result")
	}
}

func (s *ClickHouseJWTServer) handleExecuteQueryOpenAPI(w http.ResponseWriter, r *http.Request, token string) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	query := r.URL.Query().Get("query")
	if query == "" {
		http.Error(w, "Query parameter is required", http.StatusBadRequest)
		return
	}

	limitStr := r.URL.Query().Get("limit")
	limit := s.ClickhouseConfig.Limit
	if limitStr != "" {
		var err error
		limit, err = strconv.Atoi(limitStr)
		if err != nil || limit <= 0 {
			http.Error(w, "Invalid limit parameter", http.StatusBadRequest)
			return
		}
		if limit > 10000 {
			http.Error(w, "Limit cannot exceed 10000", http.StatusBadRequest)
			return
		}
	}

	// Add LIMIT clause for SELECT queries if not already present
	if isSelectQuery(query) && !hasLimitClause(query) {
		query = fmt.Sprintf("%s LIMIT %d", strings.TrimSpace(query), limit)
	}

	ctx := context.WithValue(r.Context(), "jwt_token", token)

	// Get ClickHouse client
	chClient, err := s.GetClickHouseClient(ctx, token)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get ClickHouse client: %v", err), http.StatusInternalServerError)
		return
	}
	defer func() {
		if closeErr := chClient.Close(); closeErr != nil {
			log.Error().Err(closeErr).Send()
		}
	}()

	result, err := chClient.ExecuteQuery(ctx, query)
	if err != nil {
		http.Error(w, fmt.Sprintf("Query execution failed: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if encodeErr := json.NewEncoder(w).Encode(result); encodeErr != nil {
		log.Err(encodeErr).Msg("can't encode /openapi/execute_query result")
	}
}

// Helper functions
func isSelectQuery(query string) bool {
	trimmed := strings.TrimSpace(strings.ToUpper(query))
	return strings.HasPrefix(trimmed, "SELECT") || strings.HasPrefix(trimmed, "WITH")
}

func hasLimitClause(query string) bool {
	hasLimit, _ := regexp.MatchString(`(?im)limit\s+\d+`, query)
	return hasLimit
}
