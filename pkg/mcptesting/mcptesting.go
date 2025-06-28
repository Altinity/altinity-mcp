package mcptesting

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/altinity/altinity-mcp/pkg/clickhouse"
	"github.com/altinity/altinity-mcp/pkg/config"
	altinitymcp "github.com/altinity/altinity-mcp/pkg/server"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/mcptest"
	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/require"
)

// AltinityTestServer wraps mcptest functionality to provide additional functionality
// specific to Altinity MCP server testing.
type AltinityTestServer struct {
	testServer       *mcptest.Server
	chJwtServer      *altinitymcp.ClickHouseJWTServer
	t                *testing.T
	clickhouseClient *clickhouse.Client
	chConfig         *config.ClickHouseConfig
}

// NewAltinityTestServer creates a new AltinityTestServer with a preconfigured mcptest.Server.
// It automatically registers all Altinity MCP tools, resources, and prompts.
func NewAltinityTestServer(t *testing.T, chConfig *config.ClickHouseConfig) *AltinityTestServer {
	t.Helper()

	// Create JWT config for testing (disabled by default)
	jwtConfig := config.JWTConfig{
		Enabled: false,
	}

	// Create the ClickHouse JWT server
	chJwtServer := altinitymcp.NewClickHouseMCPServer(*chConfig, jwtConfig)

	// Create an mcptest server that wraps the underlying MCP server from our ClickHouse JWT server
	testServer := mcptest.NewUnstartedServer(t)
	
	// Copy the capabilities and handlers from our ClickHouse JWT server to the test server
	// This is a bit of a hack, but necessary because mcptest.Server doesn't have a way to wrap an existing server
	copyServerConfiguration(testServer, chJwtServer, chConfig)

	return &AltinityTestServer{
		testServer:  testServer,
		chJwtServer: chJwtServer,
		t:           t,
		chConfig:    chConfig,
	}
}

// copyServerConfiguration copies the tools, resources, and prompts from the ClickHouse JWT server to the test server
func copyServerConfiguration(testServer *mcptest.Server, chJwtServer *altinitymcp.ClickHouseJWTServer, chConfig *config.ClickHouseConfig) {
	// Register tools, resources, and prompts on the test server
	// We pass the test server as the AltinityMCPServer interface, but the handlers will use the chJwtServer
	wrapper := &testServerWrapper{testServer: testServer, chJwtServer: chJwtServer, chConfig: chConfig}
	altinitymcp.RegisterTools(wrapper)
	altinitymcp.RegisterResources(wrapper)
	altinitymcp.RegisterPrompts(wrapper)
}

// testServerWrapper wraps mcptest.Server to implement the AltinityMCPServer interface
// while delegating JWT functionality to the ClickHouseJWTServer
type testServerWrapper struct {
	testServer  *mcptest.Server
	chJwtServer *altinitymcp.ClickHouseJWTServer
	chConfig    *config.ClickHouseConfig
}

func (w *testServerWrapper) AddTools(tools ...server.ServerTool) {
	// Convert server.ServerTool to mcptest.ServerTool
	for _, tool := range tools {
		w.testServer.AddTool(tool.Tool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			// Inject JWT token into context for testing (empty since JWT is disabled)
			ctx = context.WithValue(ctx, "jwt_token", "")
			return tool.Handler(ctx, req)
		})
	}
}

func (w *testServerWrapper) AddTool(tool mcp.Tool, handler server.ToolHandlerFunc) {
	// Create a custom handler that uses our ClickHouse JWT server directly
	wrappedHandler := func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		// Inject JWT token into context for testing (empty since JWT is disabled)
		ctx = context.WithValue(ctx, "jwt_token", "")
		
		// Call the handler with the ClickHouseJWTServer as the receiver
		// We need to create a custom context that will work with our server
		return w.callToolWithJWTServer(ctx, req, tool.Name)
	}
	w.testServer.AddTool(tool, wrappedHandler)
}

// callToolWithJWTServer handles tool calls by delegating to the appropriate tool handler
func (w *testServerWrapper) callToolWithJWTServer(ctx context.Context, req mcp.CallToolRequest, toolName string) (*mcp.CallToolResult, error) {
	switch toolName {
	case "list_tables":
		return w.handleListTables(ctx, req)
	case "execute_query":
		return w.handleExecuteQuery(ctx, req)
	case "describe_table":
		return w.handleDescribeTable(ctx, req)
	default:
		return mcp.NewToolResultError(fmt.Sprintf("Unknown tool: %s", toolName)), nil
	}
}

// handleListTables implements the list_tables tool logic
func (w *testServerWrapper) handleListTables(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	database := req.GetString("database", "")
	
	// Extract token from context
	token := w.chJwtServer.ExtractTokenFromCtx(ctx)
	
	// Get ClickHouse client
	chClient, err := w.chJwtServer.GetClickHouseClient(ctx, token)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get ClickHouse client: %v", err)), nil
	}
	defer func() {
		if closeErr := chClient.Close(); closeErr != nil {
			// Log error but don't fail the test
		}
	}()

	tables, err := chClient.ListTables(ctx, database)
	if err != nil {
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

// handleExecuteQuery implements the execute_query tool logic
func (w *testServerWrapper) handleExecuteQuery(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	query, err := req.RequireString("query")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	// Get optional limit parameter, use server default if not provided
	defaultLimit := float64(w.chConfig.Limit)
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

	// Add LIMIT clause for SELECT queries if not already present
	if isSelectQuery(query) && !hasLimitClause(query) {
		query = fmt.Sprintf("%s LIMIT %.0f", strings.TrimSpace(query), limit)
	}

	// Extract token from context
	token := w.chJwtServer.ExtractTokenFromCtx(ctx)

	// Get ClickHouse client
	chClient, err := w.chJwtServer.GetClickHouseClient(ctx, token)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get ClickHouse client: %v", err)), nil
	}
	defer func() {
		if closeErr := chClient.Close(); closeErr != nil {
			// Log error but don't fail the test
		}
	}()

	result, err := chClient.ExecuteQuery(ctx, query)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Query execution failed: %v", err)), nil
	}

	jsonData, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to marshal result: %v", err)), nil
	}

	return mcp.NewToolResultText(string(jsonData)), nil
}

// handleDescribeTable implements the describe_table tool logic
func (w *testServerWrapper) handleDescribeTable(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	database, err := req.RequireString("database")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	tableName, err := req.RequireString("table_name")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	// Extract token from context
	token := w.chJwtServer.ExtractTokenFromCtx(ctx)

	// Get ClickHouse client
	chClient, err := w.chJwtServer.GetClickHouseClient(ctx, token)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get ClickHouse client: %v", err)), nil
	}
	defer func() {
		if closeErr := chClient.Close(); closeErr != nil {
			// Log error but don't fail the test
		}
	}()

	columns, err := chClient.DescribeTable(ctx, database, tableName)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to describe table: %v", err)), nil
	}

	jsonData, err := json.MarshalIndent(columns, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to marshal result: %v", err)), nil
	}

	return mcp.NewToolResultText(string(jsonData)), nil
}

func (w *testServerWrapper) AddPrompt(prompt mcp.Prompt, handler server.PromptHandlerFunc) {
	w.testServer.AddPrompt(prompt, func(ctx context.Context, req mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
		// Inject JWT token into context for testing (empty since JWT is disabled)
		ctx = context.WithValue(ctx, "jwt_token", "")
		return handler(ctx, req)
	})
}

func (w *testServerWrapper) AddPrompts(prompts ...server.ServerPrompt) {
	// Convert server.ServerPrompt to mcptest.ServerPrompt
	for _, prompt := range prompts {
		w.testServer.AddPrompt(prompt.Prompt, func(ctx context.Context, req mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
			// Inject JWT token into context for testing (empty since JWT is disabled)
			ctx = context.WithValue(ctx, "jwt_token", "")
			return prompt.Handler(ctx, req)
		})
	}
}

func (w *testServerWrapper) AddResource(resource mcp.Resource, handler server.ResourceHandlerFunc) {
	// Wrap the handler to inject JWT context
	wrappedHandler := func(ctx context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
		// Inject JWT token into context for testing (empty since JWT is disabled)
		ctx = context.WithValue(ctx, "jwt_token", "")
		return handler(ctx, req)
	}
	w.testServer.AddResource(resource, wrappedHandler)
}

func (w *testServerWrapper) AddResources(resources ...server.ServerResource) {
	// Convert server.ServerResource to mcptest.ServerResource
	for _, resource := range resources {
		w.testServer.AddResource(resource.Resource, func(ctx context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
			// Inject JWT token into context for testing (empty since JWT is disabled)
			ctx = context.WithValue(ctx, "jwt_token", "")
			return resource.Handler(ctx, req)
		})
	}
}

func (w *testServerWrapper) AddResourceTemplate(template mcp.ResourceTemplate, handler server.ResourceTemplateHandlerFunc) {
	// Wrap the handler to inject JWT context
	wrappedHandler := func(ctx context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
		// Inject JWT token into context for testing (empty since JWT is disabled)
		ctx = context.WithValue(ctx, "jwt_token", "")
		return handler(ctx, req)
	}
	w.testServer.AddResourceTemplate(template, wrappedHandler)
}

// Start starts the test server and connects to the ClickHouse database if a config is provided.
func (s *AltinityTestServer) Start(ctx context.Context) error {
	// Start the underlying test server
	if err := s.testServer.Start(ctx); err != nil {
		return err
	}

	// If a ClickHouse config is provided, initialize the client
	if s.chConfig != nil {
		var err error
		s.clickhouseClient, err = clickhouse.NewClient(ctx, *s.chConfig)
		if err != nil {
			s.testServer.Close()
			return err
		}
	}

	return nil
}

// Close stops the test server and cleans up resources.
func (s *AltinityTestServer) Close() {
	// Close the ClickHouse client if it exists
	if s.clickhouseClient != nil {
		if err := s.clickhouseClient.Close(); err != nil {
			s.t.Logf("Failed to close ClickHouse client: %v", err)
		}
	}

	// Close the underlying test server
	s.testServer.Close()
}

// GetClickHouseClient returns the ClickHouse client for direct database interactions
func (s *AltinityTestServer) GetClickHouseClient() *clickhouse.Client {
	return s.clickhouseClient
}

// CallTool is a helper method to call a tool
func (s *AltinityTestServer) CallTool(ctx context.Context, toolName string, args map[string]interface{}) (*mcp.CallToolResult, error) {
	// Inject JWT token into context if we have a ClickHouse JWT server
	if s.chJwtServer != nil {
		// For testing purposes, we can inject an empty token since JWT is disabled by default
		ctx = context.WithValue(ctx, "jwt_token", "")
	}

	callReq := mcp.CallToolRequest{}
	callReq.Params.Name = toolName
	callReq.Params.Arguments = args

	return s.testServer.Client().CallTool(ctx, callReq)
}

// CallToolAndRequireSuccess calls a tool and requires that it succeeds
func (s *AltinityTestServer) CallToolAndRequireSuccess(ctx context.Context, toolName string, args map[string]interface{}) *mcp.CallToolResult {
	result, err := s.CallTool(ctx, toolName, args)
	require.NoError(s.t, err)
	require.NotNil(s.t, result)
	require.False(s.t, result.IsError, "Tool call resulted in error: %v", result)

	return result
}

// GetTextContent extracts text content from a tool result
func (s *AltinityTestServer) GetTextContent(result *mcp.CallToolResult) string {
	if len(result.Content) == 0 {
		return ""
	}
	if textContent, ok := result.Content[0].(mcp.TextContent); ok {
		return textContent.Text
	}
	return ""
}

// ReadResource is a helper method to read a resource
func (s *AltinityTestServer) ReadResource(ctx context.Context, uri string) (*mcp.ReadResourceResult, error) {
	readReq := mcp.ReadResourceRequest{}
	readReq.Params.URI = uri

	return s.testServer.Client().ReadResource(ctx, readReq)
}

// ReadResourceAndRequireSuccess reads a resource and requires that it succeeds
func (s *AltinityTestServer) ReadResourceAndRequireSuccess(ctx context.Context, uri string) *mcp.ReadResourceResult {
	result, err := s.ReadResource(ctx, uri)
	require.NoError(s.t, err)
	require.NotNil(s.t, result)
	require.NotEmpty(s.t, result.Contents)

	return result
}

// GetPrompt is a helper method to get a prompt
func (s *AltinityTestServer) GetPrompt(ctx context.Context, promptName string, args map[string]string) (*mcp.GetPromptResult, error) {
	promptReq := mcp.GetPromptRequest{}
	promptReq.Params.Name = promptName
	promptReq.Params.Arguments = args

	return s.testServer.Client().GetPrompt(ctx, promptReq)
}

// GetPromptAndRequireSuccess gets a prompt and requires that it succeeds
func (s *AltinityTestServer) GetPromptAndRequireSuccess(ctx context.Context, promptName string, args map[string]string) *mcp.GetPromptResult {
	result, err := s.GetPrompt(ctx, promptName, args)
	require.NoError(s.t, err)
	require.NotNil(s.t, result)

	return result
}

// WithClickHouseConfig sets the ClickHouse configuration for the test server
func (s *AltinityTestServer) WithClickHouseConfig(config *config.ClickHouseConfig) *AltinityTestServer {
	s.chConfig = config
	return s
}

// WithJWTAuth configures the server to use JWT authentication
func (s *AltinityTestServer) WithJWTAuth(jwtConfig config.JWTConfig) *AltinityTestServer {
	// Recreate the ClickHouse JWT server with the new JWT config
	if s.chConfig != nil {
		s.chJwtServer = altinitymcp.NewClickHouseMCPServer(*s.chConfig, jwtConfig)
	}
	return s
}

// Helper functions for query processing
func isSelectQuery(query string) bool {
	trimmed := strings.TrimSpace(strings.ToUpper(query))
	return strings.HasPrefix(trimmed, "SELECT") || strings.HasPrefix(trimmed, "WITH")
}

func hasLimitClause(query string) bool {
	hasLimit, _ := regexp.MatchString(`(?im)limit\s+\d+`, query)
	return hasLimit
}
