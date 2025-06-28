package mcptesting

import (
	"context"
	"testing"

	"github.com/altinity/altinity-mcp/pkg/clickhouse"
	"github.com/altinity/altinity-mcp/pkg/config"
	altinitymcp "github.com/altinity/altinity-mcp/pkg/server"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/mcptest"
	"github.com/mark3labs/mcp-go/server"
	"github.com/rs/zerolog/log"
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

	// Create an mcptest server first
	testServer := mcptest.NewUnstartedServer(t)
	
	// Create a ClickHouse JWT server but don't use NewClickHouseMCPServer to avoid double registration
	// Instead, create the server manually and register tools only once
	srv := server.NewMCPServer(
		"Altinity ClickHouse MCP Server",
		"1.0.0",
		server.WithToolCapabilities(true),
		server.WithResourceCapabilities(true, true),
		server.WithPromptCapabilities(true),
		server.WithRecovery(),
	)

	chJwtServer := &altinitymcp.ClickHouseJWTServer{
		MCPServer:        srv,
		JwtConfig:        jwtConfig,
		ClickhouseConfig: *chConfig,
	}
	
	// Register tools, resources, and prompts using the server wrapper (only once)
	wrapper := &testServerWrapper{testServer: testServer, chJwtServer: chJwtServer}
	altinitymcp.RegisterTools(wrapper)
	altinitymcp.RegisterResources(wrapper)
	altinitymcp.RegisterPrompts(wrapper)

	return &AltinityTestServer{
		testServer:  testServer,
		chJwtServer: chJwtServer,
		t:           t,
		chConfig:    chConfig,
	}
}

// testServerWrapper wraps mcptest.Server to implement the AltinityMCPServer interface
// while delegating JWT functionality to the ClickHouseJWTServer
type testServerWrapper struct {
	testServer  *mcptest.Server
	chJwtServer *altinitymcp.ClickHouseJWTServer
}

func (w *testServerWrapper) AddTools(tools ...server.ServerTool) {
	// Convert server.ServerTool to mcptest.ServerTool
	for _, tool := range tools {
		w.testServer.AddTool(tool.Tool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			// Inject JWT token and server into context for testing
			ctx = context.WithValue(ctx, "jwt_token", "")
			ctx = context.WithValue(ctx, "clickhouse_jwt_server", w.chJwtServer)
			return tool.Handler(ctx, req)
		})
	}
}

func (w *testServerWrapper) AddTool(tool mcp.Tool, handler server.ToolHandlerFunc) {
	// Create a wrapper that injects the ClickHouse JWT server into context
	wrappedHandler := func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		// Inject JWT token and server into context for testing
		ctx = context.WithValue(ctx, "jwt_token", "")
		ctx = context.WithValue(ctx, "clickhouse_jwt_server", w.chJwtServer)
		
		// Call the original handler from the server package
		return handler(ctx, req)
	}
	w.testServer.AddTool(tool, wrappedHandler)
}

func (w *testServerWrapper) AddPrompt(prompt mcp.Prompt, handler server.PromptHandlerFunc) {
	w.testServer.AddPrompt(prompt, func(ctx context.Context, req mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
		// Inject JWT token and server into context for testing
		ctx = context.WithValue(ctx, "jwt_token", "")
		ctx = context.WithValue(ctx, "clickhouse_jwt_server", w.chJwtServer)
		return handler(ctx, req)
	})
}

func (w *testServerWrapper) AddPrompts(prompts ...server.ServerPrompt) {
	// Convert server.ServerPrompt to mcptest.ServerPrompt
	for _, prompt := range prompts {
		w.testServer.AddPrompt(prompt.Prompt, func(ctx context.Context, req mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
			// Inject JWT token and server into context for testing
			ctx = context.WithValue(ctx, "jwt_token", "")
			ctx = context.WithValue(ctx, "clickhouse_jwt_server", w.chJwtServer)
			return prompt.Handler(ctx, req)
		})
	}
}

func (w *testServerWrapper) AddResource(resource mcp.Resource, handler server.ResourceHandlerFunc) {
	// Wrap the handler to inject JWT context and server
	wrappedHandler := func(ctx context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
		// Inject JWT token and server into context for testing
		ctx = context.WithValue(ctx, "jwt_token", "")
		ctx = context.WithValue(ctx, "clickhouse_jwt_server", w.chJwtServer)
		return handler(ctx, req)
	}
	w.testServer.AddResource(resource, wrappedHandler)
}

func (w *testServerWrapper) AddResources(resources ...server.ServerResource) {
	// Convert server.ServerResource to mcptest.ServerResource
	for _, resource := range resources {
		w.testServer.AddResource(resource.Resource, func(ctx context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
			// Inject JWT token and server into context for testing
			ctx = context.WithValue(ctx, "jwt_token", "")
			ctx = context.WithValue(ctx, "clickhouse_jwt_server", w.chJwtServer)
			return resource.Handler(ctx, req)
		})
	}
}

func (w *testServerWrapper) AddResourceTemplate(template mcp.ResourceTemplate, handler server.ResourceTemplateHandlerFunc) {
	// Wrap the handler to inject JWT context and server
	wrappedHandler := func(ctx context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
		// Inject JWT token and server into context for testing
		ctx = context.WithValue(ctx, "jwt_token", "")
		ctx = context.WithValue(ctx, "clickhouse_jwt_server", w.chJwtServer)
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
	// Update the JWT config in the existing server to avoid re-registration
	s.chJwtServer.JwtConfig = jwtConfig
	return s
}

