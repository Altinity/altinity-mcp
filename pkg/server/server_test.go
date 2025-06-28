package server

import (
	"context"
	"github.com/altinity/altinity-mcp/pkg/clickhouse"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/mcptest"
	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/require"

	"github.com/altinity/altinity-mcp/pkg/config"
)

// AltinityTestServer wraps mcptest functionality to provide additional functionality
// specific to Altinity MCP server testing.
type AltinityTestServer struct {
	testServer       *mcptest.Server
	chJwtServer      *ClickHouseJWTServer
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

	chJwtServer := &ClickHouseJWTServer{
		MCPServer:        srv,
		JwtConfig:        jwtConfig,
		ClickhouseConfig: *chConfig,
	}

	// Register tools, resources, and prompts using the server wrapper (only once)
	wrapper := &testServerWrapper{testServer: testServer, chJwtServer: chJwtServer}
	RegisterTools(wrapper)
	RegisterResources(wrapper)
	RegisterPrompts(wrapper)

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
	chJwtServer *ClickHouseJWTServer
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

		// Call the handler directly with the wrapper as the server parameter
		// since the handler expects an AltinityMCPServer interface
		return callResourceHandlerWithServer(ctx, req, handler, w)
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
			return callResourceHandlerWithServer(ctx, req, resource.Handler, w)
		})
	}
}

func (w *testServerWrapper) AddResourceTemplate(template mcp.ResourceTemplate, handler server.ResourceTemplateHandlerFunc) {
	// Wrap the handler to inject JWT context and server
	wrappedHandler := func(ctx context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
		// Inject JWT token and server into context for testing
		ctx = context.WithValue(ctx, "jwt_token", "")
		ctx = context.WithValue(ctx, "clickhouse_jwt_server", w.chJwtServer)
		return callResourceTemplateHandlerWithServer(ctx, req, handler, w)
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

// callResourceHandlerWithServer is a helper function to call resource handlers with proper server context
func callResourceHandlerWithServer(ctx context.Context, req mcp.ReadResourceRequest, handler server.ResourceHandlerFunc, srv AltinityMCPServer) ([]mcp.ResourceContents, error) {
	// The resource handlers in server.go expect to be called with a server that implements AltinityMCPServer
	// We need to temporarily replace the server casting logic for testing
	return handler(ctx, req)
}

// callResourceTemplateHandlerWithServer is a helper function to call resource template handlers with proper server context
func callResourceTemplateHandlerWithServer(ctx context.Context, req mcp.ReadResourceRequest, handler server.ResourceTemplateHandlerFunc, srv AltinityMCPServer) ([]mcp.ResourceContents, error) {
	// The resource template handlers in server.go expect to be called with a server that implements AltinityMCPServer
	// We need to temporarily replace the server casting logic for testing
	return handler(ctx, req)
}

// WithJWTAuth configures the server to use JWT authentication
func (s *AltinityTestServer) WithJWTAuth(jwtConfig config.JWTConfig) *AltinityTestServer {
	// Update the JWT config in the existing server to avoid re-registration
	s.chJwtServer.JwtConfig = jwtConfig
	return s
}

// TestJWTTokenGeneration tests JWT token generation with TLS configuration
func TestJWTTokenGeneration(t *testing.T) {
	t.Parallel()

	// Test basic JWT token generation
	t.Run("basic_token", func(t *testing.T) {
		claims := map[string]interface{}{
			"host":     "localhost",
			"port":     float64(8123),
			"database": "default",
			"username": "default",
			"protocol": "http",
			"exp":      time.Now().Add(time.Hour).Unix(),
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims(claims))
		tokenString, err := token.SignedString([]byte("test-secret"))
		require.NoError(t, err)
		require.NotEmpty(t, tokenString)

		// Parse and verify the token
		parsedToken, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return []byte("test-secret"), nil
		})
		require.NoError(t, err)
		require.True(t, parsedToken.Valid)

		parsedClaims, ok := parsedToken.Claims.(jwt.MapClaims)
		require.True(t, ok)
		require.Equal(t, "localhost", parsedClaims["host"])
		require.Equal(t, float64(8123), parsedClaims["port"])
	})

	// Test JWT token with TLS configuration
	t.Run("token_with_tls", func(t *testing.T) {
		claims := map[string]interface{}{
			"host":                     "secure.clickhouse.com",
			"port":                     float64(9440),
			"database":                 "secure_db",
			"username":                 "secure_user",
			"protocol":                 "tcp",
			"tls_enabled":              true,
			"tls_ca_cert":              "/path/to/ca.crt",
			"tls_client_cert":          "/path/to/client.crt",
			"tls_client_key":           "/path/to/client.key",
			"tls_insecure_skip_verify": false,
			"exp":                      time.Now().Add(time.Hour).Unix(),
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims(claims))
		tokenString, err := token.SignedString([]byte("test-secret"))
		require.NoError(t, err)
		require.NotEmpty(t, tokenString)

		// Parse and verify the token
		parsedToken, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return []byte("test-secret"), nil
		})
		require.NoError(t, err)
		require.True(t, parsedToken.Valid)

		parsedClaims, ok := parsedToken.Claims.(jwt.MapClaims)
		require.True(t, ok)
		require.Equal(t, true, parsedClaims["tls_enabled"])
		require.Equal(t, "/path/to/ca.crt", parsedClaims["tls_ca_cert"])
		require.Equal(t, "/path/to/client.crt", parsedClaims["tls_client_cert"])
		require.Equal(t, "/path/to/client.key", parsedClaims["tls_client_key"])
		require.Equal(t, false, parsedClaims["tls_insecure_skip_verify"])
	})
}

// setupClickHouseContainer sets up a ClickHouse container for testing.
func setupClickHouseContainer(t *testing.T) *config.ClickHouseConfig {
	t.Helper()
	ctx := context.Background() // Use background context instead of test context to avoid cancellation issues

	req := testcontainers.ContainerRequest{
		Image:        "clickhouse/clickhouse-server:latest",
		ExposedPorts: []string{"8123/tcp", "9000/tcp"},
		Env: map[string]string{
			"CLICKHOUSE_SKIP_USER_SETUP":           "1",
			"CLICKHOUSE_DB":                        "default",
			"CLICKHOUSE_USER":                      "default",
			"CLICKHOUSE_PASSWORD":                  "",
			"CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT": "1",
		},
		WaitingFor: wait.ForHTTP("/").WithPort("8123/tcp").WithStartupTimeout(30 * time.Second).WithPollInterval(2 * time.Second),
	}
	chContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(t, err)

	t.Cleanup(func() {
		// Use a fresh context for cleanup to avoid cancellation issues
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := chContainer.Terminate(cleanupCtx); err != nil {
			t.Logf("Warning: failed to terminate container: %v", err)
		}
	})

	host, err := chContainer.Host(ctx)
	require.NoError(t, err)

	port, err := chContainer.MappedPort(ctx, "9000")
	require.NoError(t, err)

	cfg := &config.ClickHouseConfig{
		Host:             host,
		Port:             port.Int(),
		Database:         "default",
		Username:         "default",
		Password:         "",
		Protocol:         config.TCPProtocol,
		ReadOnly:         false,
		MaxExecutionTime: 60,
		Limit:            1000,
	}

	// Create a client to set up the database
	client, err := clickhouse.NewClient(ctx, *cfg)
	require.NoError(t, err)
	defer func() { require.NoError(t, client.Close()) }()

	_, err = client.ExecuteQuery(ctx, "CREATE TABLE default.test (id UInt64, value String) ENGINE = Memory")
	require.NoError(t, err)
	_, err = client.ExecuteQuery(ctx, "INSERT INTO default.test VALUES (1, 'one'), (2, 'two')")
	require.NoError(t, err)

	return cfg
}

// TestMCPTestingWrapper tests the mcptesting wrapper functionality.
func TestMCPTestingWrapper(t *testing.T) {
	ctx := context.Background()
	chConfig := setupClickHouseContainer(t)

	// Create and configure AltinityTestServer
	testServer := NewAltinityTestServer(t, chConfig)

	// Start the server
	err := testServer.Start(ctx)
	require.NoError(t, err)
	defer testServer.Close()

	// Test our wrapper methods
	t.Run("CallTool_ListTables", func(t *testing.T) {
		// Test list_tables tool - this should succeed since we have a real ClickHouse container
		result, err := testServer.CallTool(ctx, "list_tables", map[string]interface{}{
			"database": "default",
		})
		require.NoError(t, err)
		require.NotNil(t, result)
		require.False(t, result.IsError, "Tool call resulted in error: %v", result)

		// Verify we get some content back
		textContent := testServer.GetTextContent(result)
		require.NotEmpty(t, textContent)
	})

	t.Run("CallTool_ExecuteQuery", func(t *testing.T) {
		// Test execute_query tool with SELECT
		result, err := testServer.CallTool(ctx, "execute_query", map[string]interface{}{
			"query": "SELECT * FROM test",
		})
		require.NoError(t, err)
		require.NotNil(t, result)
		require.False(t, result.IsError, "Tool call resulted in error: %v", result)

		textContent := testServer.GetTextContent(result)
		require.NotEmpty(t, textContent)
	})

	t.Run("CallTool_ExecuteQuery_WithLimit", func(t *testing.T) {
		// Test execute_query tool with custom limit
		result, err := testServer.CallTool(ctx, "execute_query", map[string]interface{}{
			"query": "SELECT * FROM test",
			"limit": float64(5),
		})
		require.NoError(t, err)
		require.NotNil(t, result)
		require.False(t, result.IsError, "Tool call resulted in error: %v", result)
		_ = result // Use the result to avoid unused variable error
	})

	t.Run("CallTool_ExecuteQuery_ExceedsLimit", func(t *testing.T) {
		// Test execute_query tool with limit exceeding default
		result, err := testServer.CallTool(ctx, "execute_query", map[string]interface{}{
			"query": "SELECT * FROM test",
			"limit": float64(2000), // Exceeds default limit of 1000
		})
		require.NoError(t, err)
		require.NotNil(t, result)
		require.True(t, result.IsError, "Expected error for limit exceeding default")
		_ = result // Use the result to avoid unused variable error
	})

	t.Run("CallTool_ExecuteQuery_InvalidQuery", func(t *testing.T) {
		// Test execute_query tool with invalid query
		result, err := testServer.CallTool(ctx, "execute_query", map[string]interface{}{
			"query": "INVALID SQL QUERY",
		})
		require.NoError(t, err)
		require.NotNil(t, result)
		require.True(t, result.IsError, "Expected error for invalid query")
		_ = result // Use the result to avoid unused variable error
	})

	t.Run("CallTool_DescribeTable", func(t *testing.T) {
		// Test describe_table tool
		result, err := testServer.CallTool(ctx, "describe_table", map[string]interface{}{
			"database":   "default",
			"table_name": "test",
		})
		require.NoError(t, err)
		require.NotNil(t, result)
		require.False(t, result.IsError, "Tool call resulted in error: %v", result)

		textContent := testServer.GetTextContent(result)
		require.NotEmpty(t, textContent)
	})

	t.Run("CallTool_DescribeTable_MissingParams", func(t *testing.T) {
		// Test describe_table tool with missing parameters
		result, err := testServer.CallTool(ctx, "describe_table", map[string]interface{}{
			"database": "default",
			// missing table_name
		})
		require.NoError(t, err)
		require.NotNil(t, result)
		require.True(t, result.IsError, "Expected error for missing table_name")
	})

	t.Run("ReadResource_Schema", func(t *testing.T) {
		// Test reading schema resource
		result, err := testServer.ReadResource(ctx, "clickhouse://schema")
		require.NoError(t, err)
		require.NotNil(t, result)
		require.NotEmpty(t, result.Contents)
	})

	t.Run("ReadResource_TableStructure", func(t *testing.T) {
		// Test reading table structure resource
		result, err := testServer.ReadResource(ctx, "clickhouse://table/default/test")
		require.NoError(t, err)
		require.NotNil(t, result)
		require.NotEmpty(t, result.Contents)
	})

	t.Run("ReadResource_InvalidTableURI", func(t *testing.T) {
		// Test reading table structure resource with invalid URI
		_, err := testServer.ReadResource(ctx, "invalid://table/default/invalid")
		require.Error(t, err)
		require.Contains(t, err.Error(), "handler not found for resource URI 'invalid://table/default/invalid': resource not found")

		// Test reading table structure resource with valid URI, but not exists table
		_, err = testServer.ReadResource(ctx, "clickhouse://table/default/not_exists")
		require.Error(t, err)
		require.Contains(t, err.Error(), "`default`.`not_exists` columns not found")
	})

	t.Run("GetPrompt_QueryBuilder", func(t *testing.T) {
		// Test query builder prompt
		result, err := testServer.GetPrompt(ctx, "query_builder", map[string]string{
			"database":   "default",
			"table_name": "test",
			"query_type": "select",
		})
		require.NoError(t, err)
		require.NotNil(t, result)
		require.NotEmpty(t, result.Messages)
	})

	t.Run("GetPrompt_QueryBuilder_MissingDatabase", func(t *testing.T) {
		// Test query builder prompt with missing database
		_, err := testServer.GetPrompt(ctx, "query_builder", map[string]string{
			"table_name": "test",
			"query_type": "select",
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "database parameter is required")
	})

	t.Run("GetPrompt_PerformanceAnalysis", func(t *testing.T) {
		// Test performance analysis prompt
		result, err := testServer.GetPrompt(ctx, "performance_analysis", map[string]string{
			"query": "SELECT * FROM test",
		})
		require.NoError(t, err)
		require.NotNil(t, result)
		require.NotEmpty(t, result.Messages)
	})

	t.Run("GetPrompt_PerformanceAnalysis_MissingQuery", func(t *testing.T) {
		// Test performance analysis prompt with missing query
		_, err := testServer.GetPrompt(ctx, "performance_analysis", map[string]string{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "query parameter is required")
	})

	t.Run("GetTextContent", func(t *testing.T) {
		// Create a simple mock function that simulates the behavior without actually creating a proper CallToolResult
		mockResult := &mcp.CallToolResult{}
		// Let's just verify that empty content returns empty string
		text := testServer.GetTextContent(mockResult)
		require.Equal(t, "", text)
	})
}

// TestNewClickHouseMCPServer tests the server creation
func TestNewClickHouseMCPServer(t *testing.T) {
	chConfig := config.ClickHouseConfig{
		Host:     "localhost",
		Port:     8123,
		Database: "default",
		Username: "default",
		Protocol: config.HTTPProtocol,
		Limit:    1000,
	}

	jwtConfig := config.JWTConfig{
		Enabled: false,
	}

	server := NewClickHouseMCPServer(chConfig, jwtConfig)
	require.NotNil(t, server)
	require.NotNil(t, server.MCPServer)
	require.Equal(t, jwtConfig, server.JwtConfig)
	require.Equal(t, chConfig, server.ClickhouseConfig)
}

// TestGetClickHouseClient tests the JWT client creation
func TestGetClickHouseClient(t *testing.T) {
	ctx := context.Background()

	t.Run("without_jwt", func(t *testing.T) {
		chConfig := config.ClickHouseConfig{
			Host:     "localhost",
			Port:     8123,
			Database: "default",
			Username: "default",
			Protocol: config.HTTPProtocol,
			Limit:    1000,
		}

		jwtConfig := config.JWTConfig{
			Enabled: false,
		}

		server := NewClickHouseMCPServer(chConfig, jwtConfig)

		// This will fail to connect but we're testing the logic, not the connection
		_, err := server.GetClickHouseClient(ctx, "")
		// We expect an error because we're not actually connecting to ClickHouse
		require.Error(t, err)
	})

	t.Run("with_jwt_missing_token", func(t *testing.T) {
		chConfig := config.ClickHouseConfig{
			Host:     "localhost",
			Port:     8123,
			Database: "default",
			Username: "default",
			Protocol: config.HTTPProtocol,
			Limit:    1000,
		}

		jwtConfig := config.JWTConfig{
			Enabled:   true,
			SecretKey: "test-secret",
		}

		server := NewClickHouseMCPServer(chConfig, jwtConfig)

		_, err := server.GetClickHouseClient(ctx, "")
		require.Equal(t, ErrMissingToken, err)
	})

	t.Run("with_jwt_invalid_token", func(t *testing.T) {
		chConfig := config.ClickHouseConfig{
			Host:     "localhost",
			Port:     8123,
			Database: "default",
			Username: "default",
			Protocol: config.HTTPProtocol,
			Limit:    1000,
		}

		jwtConfig := config.JWTConfig{
			Enabled:   true,
			SecretKey: "test-secret",
		}

		server := NewClickHouseMCPServer(chConfig, jwtConfig)

		_, err := server.GetClickHouseClient(ctx, "invalid-token")
		require.Equal(t, ErrInvalidToken, err)
	})

	t.Run("with_jwt_valid_token", func(t *testing.T) {
		chConfig := config.ClickHouseConfig{
			Host:     "localhost",
			Port:     8123,
			Database: "default",
			Username: "default",
			Protocol: config.HTTPProtocol,
			Limit:    1000,
		}

		jwtConfig := config.JWTConfig{
			Enabled:   true,
			SecretKey: "test-secret",
		}

		server := NewClickHouseMCPServer(chConfig, jwtConfig)

		// Create a valid JWT token
		claims := map[string]interface{}{
			"host":     "test-host",
			"port":     float64(9000),
			"database": "test-db",
			"username": "test-user",
			"password": "test-pass",
			"protocol": "tcp",
			"limit":    float64(500),
			"exp":      time.Now().Add(time.Hour).Unix(),
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims(claims))
		tokenString, err := token.SignedString([]byte("test-secret"))
		require.NoError(t, err)

		// This will fail to connect but we're testing the JWT parsing logic
		_, err = server.GetClickHouseClient(ctx, tokenString)
		// We expect a connection error, not a JWT error
		require.Error(t, err)
		require.NotEqual(t, ErrMissingToken, err)
		require.NotEqual(t, ErrInvalidToken, err)
	})

	t.Run("with_jwt_token_with_tls", func(t *testing.T) {
		chConfig := config.ClickHouseConfig{
			Host:     "localhost",
			Port:     8123,
			Database: "default",
			Username: "default",
			Protocol: config.HTTPProtocol,
			Limit:    1000,
		}

		jwtConfig := config.JWTConfig{
			Enabled:   true,
			SecretKey: "test-secret",
		}

		server := NewClickHouseMCPServer(chConfig, jwtConfig)

		// Create a valid JWT token with TLS configuration
		claims := map[string]interface{}{
			"host":                     "secure-host",
			"port":                     float64(9440),
			"database":                 "secure-db",
			"username":                 "secure-user",
			"password":                 "secure-pass",
			"protocol":                 "tcp",
			"limit":                    float64(2000),
			"tls_enabled":              true,
			"tls_ca_cert":              "/path/to/ca.crt",
			"tls_client_cert":          "/path/to/client.crt",
			"tls_client_key":           "/path/to/client.key",
			"tls_insecure_skip_verify": true,
			"exp":                      time.Now().Add(time.Hour).Unix(),
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims(claims))
		tokenString, err := token.SignedString([]byte("test-secret"))
		require.NoError(t, err)

		// This will fail to connect but we're testing the JWT parsing logic
		_, err = server.GetClickHouseClient(ctx, tokenString)
		// We expect a connection error, not a JWT error
		require.Error(t, err)
		require.NotEqual(t, ErrMissingToken, err)
		require.NotEqual(t, ErrInvalidToken, err)
	})

	t.Run("with_jwt_wrong_signing_method", func(t *testing.T) {
		chConfig := config.ClickHouseConfig{
			Host:     "localhost",
			Port:     8123,
			Database: "default",
			Username: "default",
			Protocol: config.HTTPProtocol,
			Limit:    1000,
		}

		jwtConfig := config.JWTConfig{
			Enabled:   true,
			SecretKey: "test-secret",
		}

		server := NewClickHouseMCPServer(chConfig, jwtConfig)

		// Create a token with wrong signing method (use none algorithm which doesn't require special keys)
		claims := map[string]interface{}{
			"host": "test-host",
			"exp":  time.Now().Add(time.Hour).Unix(),
		}

		token := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims(claims))
		tokenString, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
		require.NoError(t, err)

		// This will fail because we're using 'none' but the server expects HS256
		_, err = server.GetClickHouseClient(ctx, tokenString)
		require.Equal(t, ErrInvalidToken, err)
	})

	t.Run("with_jwt_invalid_claims", func(t *testing.T) {
		chConfig := config.ClickHouseConfig{
			Host:     "localhost",
			Port:     8123,
			Database: "default",
			Username: "default",
			Protocol: config.HTTPProtocol,
			Limit:    1000,
		}

		jwtSecret := "test-secret"
		jwtConfig := config.JWTConfig{
			Enabled:   true,
			SecretKey: jwtSecret,
		}

		server := NewClickHouseMCPServer(chConfig, jwtConfig)

		// Create a custom claims struct that is not jwt.MapClaims
		type CustomClaims struct {
			Host string `json:"host"`
			jwt.RegisteredClaims
		}

		customClaims := CustomClaims{
			Host: "test-host",
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			},
		}

		// Create a token with custom claims structure that cannot be cast to jwt.MapClaims
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, customClaims)
		tokenString, err := token.SignedString([]byte(jwtSecret))
		require.NoError(t, err)

		// This should fail because claims are not MapClaims - test the parseAndValidateJWT method directly
		_, err = server.parseAndValidateJWT(tokenString)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid token claims format")
	})
}

// TestExtractTokenFromCtx tests token extraction from context
func TestExtractTokenFromCtx(t *testing.T) {
	server := &ClickHouseJWTServer{}

	t.Run("no_token", func(t *testing.T) {
		ctx := context.Background()
		token := server.ExtractTokenFromCtx(ctx)
		require.Empty(t, token)
		_ = token // Use the token to avoid unused variable error
	})

	t.Run("with_token", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), "jwt_token", "test-token")
		token := server.ExtractTokenFromCtx(ctx)
		require.Equal(t, "test-token", token)
	})

	t.Run("wrong_type", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), "jwt_token", 123)
		token := server.ExtractTokenFromCtx(ctx)
		require.Empty(t, token)
	})
}

// TestJWTWithRealClickHouse tests JWT authentication with a real ClickHouse container
func TestJWTWithRealClickHouse(t *testing.T) {
	ctx := context.Background()
	chConfig := setupClickHouseContainer(t)

	// Create JWT config
	jwtConfig := config.JWTConfig{
		Enabled:   true,
		SecretKey: "test-secret-key",
	}

	// Create test server with JWT enabled
	testServer := NewAltinityTestServer(t, chConfig).WithJWTAuth(jwtConfig)

	// Start the server
	err := testServer.Start(ctx)
	require.NoError(t, err)
	defer testServer.Close()

	t.Run("jwt_enabled_with_valid_token", func(t *testing.T) {
		// Create a valid JWT token with ClickHouse config
		claims := map[string]interface{}{
			"host":     chConfig.Host,
			"port":     float64(chConfig.Port),
			"database": chConfig.Database,
			"username": chConfig.Username,
			"password": chConfig.Password,
			"protocol": string(chConfig.Protocol),
			"limit":    float64(chConfig.Limit),
			"exp":      time.Now().Add(time.Hour).Unix(),
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims(claims))
		tokenString, err := token.SignedString([]byte("test-secret-key"))
		require.NoError(t, err)

		// Inject token into context
		ctxWithToken := context.WithValue(ctx, "jwt_token", tokenString)

		// Test list_tables tool with JWT
		result, err := testServer.CallTool(ctxWithToken, "list_tables", map[string]interface{}{
			"database": "default",
		})
		require.NoError(t, err)
		require.NotNil(t, result)
		require.False(t, result.IsError, "Tool call resulted in error: %v", result)
	})

	t.Run("jwt_enabled_without_token", func(t *testing.T) {
		// Test without token - should fail
		result, err := testServer.CallTool(ctx, "list_tables", map[string]interface{}{
			"database": "default",
		})
		require.NoError(t, err)
		require.NotNil(t, result)
		require.True(t, result.IsError, "Expected error when JWT is enabled but no token provided")
	})
}

// TestHelperFunctions tests utility functions
func TestHelperFunctions(t *testing.T) {
	t.Run("isSelectQuery", func(t *testing.T) {
		require.True(t, isSelectQuery("SELECT * FROM table"))
		require.True(t, isSelectQuery("  select * from table  "))
		require.True(t, isSelectQuery("WITH cte AS (SELECT 1) SELECT * FROM cte"))
		require.False(t, isSelectQuery("INSERT INTO table VALUES (1)"))
		require.False(t, isSelectQuery("CREATE TABLE test (id INT)"))
	})

	t.Run("hasLimitClause", func(t *testing.T) {
		require.True(t, hasLimitClause("SELECT * FROM table LIMIT 100"))
		require.True(t, hasLimitClause("select * from table limit 50"))
		require.False(t, hasLimitClause("SELECT * FROM table"))
		require.False(t, hasLimitClause("SELECT * FROM table ORDER BY id"))
	})
}

// TestGetClickHouseJWTServerFromContext tests context extraction
func TestGetClickHouseJWTServerFromContext(t *testing.T) {
	t.Run("no_server", func(t *testing.T) {
		ctx := context.Background()
		server := GetClickHouseJWTServerFromContext(ctx)
		require.Nil(t, server)
	})

	t.Run("with_server", func(t *testing.T) {
		expectedServer := &ClickHouseJWTServer{}
		ctx := context.WithValue(context.Background(), "clickhouse_jwt_server", expectedServer)
		server := GetClickHouseJWTServerFromContext(ctx)
		require.Equal(t, expectedServer, server)
	})

	t.Run("wrong_type", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), "clickhouse_jwt_server", "not-a-server")
		server := GetClickHouseJWTServerFromContext(ctx)
		require.Nil(t, server)
	})
}

// TestParseAndValidateJWT tests JWT parsing and validation
func TestParseAndValidateJWT(t *testing.T) {
	chConfig := config.ClickHouseConfig{
		Host:     "localhost",
		Port:     8123,
		Database: "default",
		Username: "default",
		Protocol: config.HTTPProtocol,
		Limit:    1000,
	}

	jwtConfig := config.JWTConfig{
		Enabled:   true,
		SecretKey: "test-secret",
	}

	server := NewClickHouseMCPServer(chConfig, jwtConfig)

	t.Run("valid_token", func(t *testing.T) {
		claims := map[string]interface{}{
			"host":     "test-host",
			"port":     float64(9000),
			"database": "test-db",
			"exp":      time.Now().Add(time.Hour).Unix(),
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims(claims))
		tokenString, err := token.SignedString([]byte("test-secret"))
		require.NoError(t, err)

		parsedClaims, err := server.parseAndValidateJWT(tokenString)
		require.NoError(t, err)
		require.Equal(t, "test-host", parsedClaims["host"])
		require.Equal(t, float64(9000), parsedClaims["port"])
		require.Equal(t, "test-db", parsedClaims["database"])
	})

	t.Run("invalid_token", func(t *testing.T) {
		_, err := server.parseAndValidateJWT("invalid-token")
		require.Equal(t, ErrInvalidToken, err)
	})

	t.Run("expired_token", func(t *testing.T) {
		claims := map[string]interface{}{
			"host": "test-host",
			"exp":  time.Now().Add(-time.Hour).Unix(), // Expired
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims(claims))
		tokenString, err := token.SignedString([]byte("test-secret"))
		require.NoError(t, err)

		_, err = server.parseAndValidateJWT(tokenString)
		require.Equal(t, ErrInvalidToken, err)
	})
}

// TestBuildConfigFromClaims tests building ClickHouse config from JWT claims
func TestBuildConfigFromClaims(t *testing.T) {
	chConfig := config.ClickHouseConfig{
		Host:     "default-host",
		Port:     8123,
		Database: "default",
		Username: "default",
		Protocol: config.HTTPProtocol,
		Limit:    1000,
	}

	jwtConfig := config.JWTConfig{
		Enabled:   true,
		SecretKey: "test-secret",
	}

	server := NewClickHouseMCPServer(chConfig, jwtConfig)

	t.Run("basic_claims", func(t *testing.T) {
		claims := jwt.MapClaims{
			"host":     "jwt-host",
			"port":     float64(9000),
			"database": "jwt-db",
			"username": "jwt-user",
			"password": "jwt-pass",
			"protocol": "tcp",
			"limit":    float64(500),
		}

		config, err := server.buildConfigFromClaims(claims)
		require.NoError(t, err)
		require.Equal(t, "jwt-host", config.Host)
		require.Equal(t, 9000, config.Port)
		require.Equal(t, "jwt-db", config.Database)
		require.Equal(t, "jwt-user", config.Username)
		require.Equal(t, "jwt-pass", config.Password)
		require.Equal(t, "tcp", string(config.Protocol))
		require.Equal(t, 500, config.Limit)
	})

	t.Run("tls_claims", func(t *testing.T) {
		claims := jwt.MapClaims{
			"tls_enabled":              true,
			"tls_ca_cert":              "/path/to/ca.crt",
			"tls_client_cert":          "/path/to/client.crt",
			"tls_client_key":           "/path/to/client.key",
			"tls_insecure_skip_verify": true,
		}

		config, err := server.buildConfigFromClaims(claims)
		require.NoError(t, err)
		require.True(t, config.TLS.Enabled)
		require.Equal(t, "/path/to/ca.crt", config.TLS.CaCert)
		require.Equal(t, "/path/to/client.crt", config.TLS.ClientCert)
		require.Equal(t, "/path/to/client.key", config.TLS.ClientKey)
		require.True(t, config.TLS.InsecureSkipVerify)
	})

	t.Run("empty_claims", func(t *testing.T) {
		claims := jwt.MapClaims{}

		config, err := server.buildConfigFromClaims(claims)
		require.NoError(t, err)
		// Should use default values
		require.Equal(t, "default-host", config.Host)
		require.Equal(t, 8123, config.Port)
		require.Equal(t, "default", config.Database)
	})

	t.Run("invalid_types", func(t *testing.T) {
		claims := jwt.MapClaims{
			"host": 123,       // Should be string
			"port": "invalid", // Should be number
		}

		config, err := server.buildConfigFromClaims(claims)
		require.NoError(t, err)
		// Should use default values for invalid types
		require.Equal(t, "default-host", config.Host)
		require.Equal(t, 8123, config.Port)
	})
}
