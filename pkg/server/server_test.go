package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/altinity/altinity-mcp/pkg/clickhouse"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"io"
	"net/http"
	"net/http/httptest"
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
	jweConfig := config.JWEConfig{
		Enabled: false,
	}

	// Create an mcptest server first
	testServer := mcptest.NewUnstartedServer(t)

	// Create a ClickHouse JWT server but don't use NewClickHouseMCPServer to avoid double registration
	// Instead, create the server manually and register tools only once
	srv := server.NewMCPServer(
		"Altinity ClickHouse MCP Test Server",
		"test",
		server.WithToolCapabilities(true),
		server.WithResourceCapabilities(true, true),
		server.WithPromptCapabilities(true),
		server.WithRecovery(),
	)

	chJweServer := &ClickHouseJWEServer{
		MCPServer: srv,
		Config:    config.Config{Server: config.ServerConfig{JWE: jweConfig}, ClickHouse: *chConfig},
	}

	// Create wrapper that will register tools/resources/prompts with the test server
	wrapper := &testServerWrapper{testServer: testServer, chJwtServer: chJwtServer}

	// Register tools, resources, and prompts directly with the wrapper
	RegisterTools(wrapper)
	RegisterResources(wrapper)
	RegisterPrompts(wrapper)

	return &AltinityTestServer{
		testServer:  testServer,
		chJweServer: chJweServer,
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
	for _, tool := range tools {
		w.testServer.AddTool(tool.Tool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			ctx = context.WithValue(ctx, "clickhouse_jwt_server", w.chJwtServer)
			return tool.Handler(ctx, req)
		})
	}
}

func (w *testServerWrapper) AddTool(tool mcp.Tool, handler server.ToolHandlerFunc) {
	w.testServer.AddTool(tool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		ctx = context.WithValue(ctx, "clickhouse_jwt_server", w.chJwtServer)
		return handler(ctx, req)
	})
}

func (w *testServerWrapper) AddPrompt(prompt mcp.Prompt, handler server.PromptHandlerFunc) {
	w.testServer.AddPrompt(prompt, func(ctx context.Context, req mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
		ctx = context.WithValue(ctx, "clickhouse_jwt_server", w.chJwtServer)
		return handler(ctx, req)
	})
}

func (w *testServerWrapper) AddPrompts(prompts ...server.ServerPrompt) {
	for _, prompt := range prompts {
		w.testServer.AddPrompt(prompt.Prompt, func(ctx context.Context, req mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
			ctx = context.WithValue(ctx, "clickhouse_jwt_server", w.chJwtServer)
			return prompt.Handler(ctx, req)
		})
	}
}

func (w *testServerWrapper) AddResource(resource mcp.Resource, handler server.ResourceHandlerFunc) {
	w.testServer.AddResource(resource, func(ctx context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
		ctx = context.WithValue(ctx, "clickhouse_jwt_server", w.chJwtServer)
		return handler(ctx, req)
	})
}

func (w *testServerWrapper) AddResources(resources ...server.ServerResource) {
	for _, resource := range resources {
		w.testServer.AddResource(resource.Resource, func(ctx context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
			ctx = context.WithValue(ctx, "clickhouse_jwt_server", w.chJwtServer)
			return resource.Handler(ctx, req)
		})
	}
}

func (w *testServerWrapper) AddResourceTemplate(template mcp.ResourceTemplate, handler server.ResourceTemplateHandlerFunc) {
	w.testServer.AddResourceTemplate(template, func(ctx context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
		ctx = context.WithValue(ctx, "clickhouse_jwt_server", w.chJwtServer)
		return handler(ctx, req)
	})
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
	// Ensure JWT token is properly set in context
	if s.chJwtServer != nil {
		if tokenFromCtx := ctx.Value("jwt_token"); tokenFromCtx != nil {
			if tokenStr, ok := tokenFromCtx.(string); ok && tokenStr != "" {
				// Token exists and is not empty, preserve it
				ctx = context.WithValue(ctx, "jwt_token", tokenStr)
			} else {
				// Token exists but is empty or wrong type, set empty
				ctx = context.WithValue(ctx, "jwt_token", "")
			}
		} else {
			// No token in context, set empty
			ctx = context.WithValue(ctx, "jwt_token", "")
		}
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
	s.chJwtServer.Config.Server.JWT = jwtConfig
	return s
}

// TestJWETokenGeneration tests JWE token generation with TLS configuration
func TestJWETokenGeneration(t *testing.T) {
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

// TestOpenAPIHandlers tests the OpenAPI handler functions
func TestOpenAPIHandlers(t *testing.T) {
	chConfig := setupClickHouseContainer(t)
	jwtSecret := "test-secret-key"
	// Create valid JWT token
	validClaims := map[string]interface{}{
		"host":     chConfig.Host,
		"port":     float64(chConfig.Port),
		"database": chConfig.Database,
		"username": chConfig.Username,
		"password": chConfig.Password,
		"protocol": string(chConfig.Protocol),
		"exp":      time.Now().Add(time.Hour).Unix(),
	}
	validToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims(validClaims))
	validTokenString, _ := validToken.SignedString([]byte(jwtSecret))

	// Test cases with different configurations
	testCases := []struct {
		name        string
		jwtEnabled  bool
		tokenParam  string
		expectError bool
	}{
		{"without_jwt", false, "", false},
		{"with_jwt_invalid", true, "invalid-token", true},
		{"with_jwt_valid", true, validTokenString, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			jwtConfig := config.JWTConfig{
				Enabled:   tc.jwtEnabled,
				SecretKey: jwtSecret,
			}

			// Set up chJwtServer with ClickHouse config and JWT
			chJwtServer := &ClickHouseJWTServer{
				Config: config.Config{Server: config.ServerConfig{JWT: jwtConfig}, ClickHouse: *chConfig},
			}

			// Create test server
			testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Always inject the server into context
				ctx := context.WithValue(r.Context(), "clickhouse_jwe_server", chJweServer)
				r = r.WithContext(ctx)
				chJwtServer.OpenAPIHandler(w, r)
			}))
			defer testServer.Close()

			// Helper function to make requests
			makeRequest := func(path string, token string) *http.Response {
				req := httptest.NewRequest("GET", path, nil)
				// Inject the appropriate token into context
				if token != "" {
					t.Logf("SUKA!!! %s GET %s jwt_token!!!=%s", t.Name(), path, token)
					req = req.WithContext(context.WithValue(req.Context(), "jwt_token", token))
				}
				w := httptest.NewRecorder()
				testServer.Config.Handler.ServeHTTP(w, req)
				return w.Result()
			}

			t.Run("OpenAPI_schema", func(t *testing.T) {
				// Add token through path for some cases
				path := testServer.URL + "/openapi"
				if tc.jwtEnabled {
					path = fmt.Sprintf("%s/%s/openapi", testServer.URL, tc.tokenParam)
				}

				resp := makeRequest(path, tc.tokenParam)
				if tc.expectError {
					require.Equal(t, http.StatusInternalServerError, resp.StatusCode)
				} else {
					require.Equal(t, http.StatusOK, resp.StatusCode)
					require.Equal(t, "application/json", resp.Header.Get("Content-Type"))

					var schema map[string]interface{}
					err := json.NewDecoder(resp.Body).Decode(&schema)
					require.NoError(t, err)
					require.Contains(t, schema, "openapi")
				}
			})

			t.Run("ListTables_OpenAPI", func(t *testing.T) {
				path := fmt.Sprintf("%s/openapi/list_tables", testServer.URL)
				if tc.jwtEnabled {
					path = fmt.Sprintf("%s/%s/openapi/list_tables", testServer.URL, tc.tokenParam)
				}

				resp := makeRequest(path, tc.tokenParam)
				if tc.expectError {
					require.Equal(t, http.StatusInternalServerError, resp.StatusCode)
				} else {
					bodyBytes, err := io.ReadAll(resp.Body)
					require.NoError(t, err)
					require.NoError(t, resp.Body.Close())
					resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
					require.Equal(t, http.StatusOK, resp.StatusCode, "unexpected status: %d, response body %s", resp.StatusCode, bodyBytes)
					require.Equal(t, "application/json", resp.Header.Get("Content-Type"), "unexpected Content-Type: %s, response body %s", resp.Header.Get("Content-Type"), bodyBytes)

					var result struct {
						ResponseData struct {
							Tables []clickhouse.TableInfo `json:"tables"`
							Count  int                    `json:"count"`
						} `json:"response_data"`
					}
					err = json.NewDecoder(resp.Body).Decode(&result)
					require.NoError(t, err)
					require.Greater(t, result.ResponseData.Count, 0)
					// Verify test table exists in results
					found := false
					for _, table := range result.ResponseData.Tables {
						if table.Name == "test" {
							found = true
							break
						}
					}
					require.True(t, found, "Could not find 'test' table in results")
				}
			})

			t.Run("DescribeTable_OpenAPI", func(t *testing.T) {
				path := fmt.Sprintf("%s/openapi/describe_table?database=default&table_name=test", testServer.URL)
				if tc.jwtEnabled {
					path = fmt.Sprintf("%s/%s/openapi/describe_table?database=default&table_name=test", testServer.URL, tc.tokenParam)
				}

				resp := makeRequest(path, tc.tokenParam)
				if tc.expectError {
					require.Equal(t, http.StatusInternalServerError, resp.StatusCode)
				} else {
					require.Equal(t, http.StatusOK, resp.StatusCode)
					require.Equal(t, "application/json", resp.Header.Get("Content-Type"))

					var columns []clickhouse.ColumnInfo
					err := json.NewDecoder(resp.Body).Decode(&columns)
					require.NoError(t, err)
					require.Greater(t, len(columns), 0)
					require.Equal(t, "id", columns[0].Name)
				}
			})

			t.Run("ExecuteQuery_OpenAPI", func(t *testing.T) {
				path := fmt.Sprintf("%s/openapi/execute_query?query=SELECT+*+FROM+test", testServer.URL)
				if tc.jwtEnabled {
					path = fmt.Sprintf("%s/%s/openapi/execute_query?query=SELECT+*+FROM+test", testServer.URL, tc.tokenParam)
				}

				resp := makeRequest(path, tc.tokenParam)
				if tc.expectError {
					require.Equal(t, http.StatusInternalServerError, resp.StatusCode)
				} else {
					require.Equal(t, http.StatusOK, resp.StatusCode)
					require.Equal(t, "application/json", resp.Header.Get("Content-Type"))

					var result clickhouse.QueryResult
					err := json.NewDecoder(resp.Body).Decode(&result)
					require.NoError(t, err)
					require.Equal(t, 2, result.Count)
					require.Equal(t, []string{"id", "value"}, result.Columns)
					require.Equal(t, 2, len(result.Rows))
				}
			})
		})
	}

	// Additional error case tests
	t.Run("ErrorConditions", func(t *testing.T) {
		jwtConfig := config.JWTConfig{Enabled: false}
		chJwtServer := &ClickHouseJWTServer{
			Config: config.Config{Server: config.ServerConfig{JWT: jwtConfig}, ClickHouse: *chConfig},
		}

		testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), "clickhouse_jwt_server", chJwtServer)
			r = r.WithContext(ctx)
			chJwtServer.OpenAPIHandler(w, r)
		}))
		defer testServer.Close()

		t.Run("MissingParams_DescribeTable", func(t *testing.T) {
			resp, _ := http.Get(fmt.Sprintf("%s/openapi/describe_table", testServer.URL))
			require.Equal(t, http.StatusBadRequest, resp.StatusCode)
		})

		t.Run("InvalidExecuteQuery", func(t *testing.T) {
			resp, _ := http.Get(fmt.Sprintf("%s/openapi/execute_query", testServer.URL))
			require.Equal(t, http.StatusBadRequest, resp.StatusCode)
		})

		t.Run("ExecuteQueryInvalidLimit", func(t *testing.T) {
			resp, _ := http.Get(fmt.Sprintf("%s/openapi/execute_query?query=SELECT+*+FROM+test&limit=abc", testServer.URL))
			require.Equal(t, http.StatusBadRequest, resp.StatusCode)
		})

		t.Run("MethodNotAllowed_ListTables", func(t *testing.T) {
			req, _ := http.NewRequest("POST", fmt.Sprintf("%s/openapi/list_tables", testServer.URL), nil)
			resp, err := http.DefaultClient.Do(req)
			require.NoError(t, err)
			require.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
		})

		t.Run("MethodNotAllowed_DescribeTable", func(t *testing.T) {
			req, _ := http.NewRequest("POST", fmt.Sprintf("%s/openapi/describe_table", testServer.URL), nil)
			resp, err := http.DefaultClient.Do(req)
			require.NoError(t, err)
			require.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
		})

		t.Run("MethodNotAllowed_ExecuteQuery", func(t *testing.T) {
			req, _ := http.NewRequest("POST", fmt.Sprintf("%s/openapi/execute_query", testServer.URL), nil)
			resp, err := http.DefaultClient.Do(req)
			require.NoError(t, err)
			require.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
		})

		t.Run("ExecuteQuery_MissingQuery", func(t *testing.T) {
			resp, _ := http.Get(fmt.Sprintf("%s/openapi/execute_query", testServer.URL))
			require.Equal(t, http.StatusBadRequest, resp.StatusCode)
		})

		t.Run("ExecuteQuery_InvalidQuery", func(t *testing.T) {
			resp, _ := http.Get(fmt.Sprintf("%s/openapi/execute_query?query=%s", testServer.URL, "INVALID%20SQL%20QUERY"))
			require.Equal(t, http.StatusInternalServerError, resp.StatusCode)
		})

		t.Run("ExecuteQuery_InsertQuery", func(t *testing.T) {
			resp, _ := http.Get(fmt.Sprintf("%s/openapi/execute_query?query=INSERT+INTO+test+VALUES+(3,+'three')", testServer.URL))
			require.Equal(t, http.StatusOK, resp.StatusCode)
		})

		t.Run("ExecuteQuery_ContextTimeout", func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			req, _ := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/openapi/execute_query?query=SELECT+sleepEachRow(1)+FROM+system.numbers+LIMIT+10+SETTINGS+function_sleep_max_microseconds_per_block=0,max_execution_time=1", testServer.URL), nil)
			resp, err := http.DefaultClient.Do(req)
			require.NoError(t, err)
			require.Equal(t, http.StatusInternalServerError, resp.StatusCode)
			respBytes, readErr := io.ReadAll(resp.Body)
			require.NoError(t, readErr)
			require.Contains(t, string(respBytes), "Timeout exceeded")
		})
	})

	// Test token extraction from multiple sources
	t.Run("TokenExtraction", func(t *testing.T) {
		jwtConfig := config.JWTConfig{Enabled: true, SecretKey: jwtSecret}
		chJwtServer := &ClickHouseJWTServer{
			Config: config.Config{Server: config.ServerConfig{JWT: jwtConfig}, ClickHouse: *chConfig},
		}

		testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), "clickhouse_jwt_server", chJwtServer)
			r = r.WithContext(ctx)
			chJwtServer.OpenAPIHandler(w, r)
		}))
		defer testServer.Close()

		t.Run("BearerHeader", func(t *testing.T) {
			req, _ := http.NewRequest("GET", testServer.URL+"/openapi", nil)
			req.Header.Set("Authorization", "Bearer "+validTokenString)
			resp, err := http.DefaultClient.Do(req)
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, resp.StatusCode)
		})

		t.Run("AltinityHeader", func(t *testing.T) {
			req, _ := http.NewRequest("GET", testServer.URL+"/openapi", nil)
			req.Header.Set("x-altinity-mcp-key", validTokenString)
			resp, err := http.DefaultClient.Do(req)
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, resp.StatusCode)
		})

		t.Run("BasicAuth", func(t *testing.T) {
			req, _ := http.NewRequest("GET", testServer.URL+"/openapi", nil)
			req.Header.Set("Authorization", "Basic "+validTokenString)
			resp, err := http.DefaultClient.Do(req)
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, resp.StatusCode)
		})

		t.Run("PathToken", func(t *testing.T) {
			req, _ := http.NewRequest("GET", testServer.URL+"/"+validTokenString+"/openapi", nil)
			resp, err := http.DefaultClient.Do(req)
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, resp.StatusCode)
		})

		t.Run("InvalidToken", func(t *testing.T) {
			req, _ := http.NewRequest("GET", testServer.URL+"/openapi", nil)
			req.Header.Set("Authorization", "Bearer invalid-token")
			resp, err := http.DefaultClient.Do(req)
			require.NoError(t, err)
			require.Equal(t, http.StatusInternalServerError, resp.StatusCode)
		})
	})
}

// TestMCPTestingWrapper tests the AltinityTestServer wrapper functionality.
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

	t.Run("CallTool_DescribeTable_InvalidDatabase", func(t *testing.T) {
		// Test describe_table with invalid database
		result, err := testServer.CallTool(ctx, "describe_table", map[string]interface{}{
			"database":   "invalid_db",
			"table_name": "test",
		})
		require.NoError(t, err)
		require.NotNil(t, result)
		require.True(t, result.IsError, "Expected error for invalid database")
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

	srv := NewClickHouseMCPServer(config.Config{Server: config.ServerConfig{JWT: jwtConfig}, ClickHouse: chConfig})
	require.NotNil(t, srv)
	require.NotNil(t, srv.MCPServer)
	require.Equal(t, jwtConfig, srv.Config.Server.JWT)
	require.Equal(t, chConfig, srv.Config.ClickHouse)
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

		srv := NewClickHouseMCPServer(config.Config{Server: config.ServerConfig{JWT: jwtConfig}, ClickHouse: chConfig})

		// This will fail to connect, but we're testing the logic, not the connection
		_, err := srv.GetClickHouseClient(ctx, "")
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

		srv := NewClickHouseMCPServer(config.Config{Server: config.ServerConfig{JWT: jwtConfig}, ClickHouse: chConfig})

		_, err := srv.GetClickHouseClient(ctx, "")
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

		srv := NewClickHouseMCPServer(config.Config{Server: config.ServerConfig{JWT: jwtConfig}, ClickHouse: chConfig})

		_, err := srv.GetClickHouseClient(ctx, "invalid-token")
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

		srv := NewClickHouseMCPServer(config.Config{Server: config.ServerConfig{JWT: jwtConfig}, ClickHouse: chConfig})

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

		// This will fail to connect, but we're testing the JWT parsing logic
		_, err = srv.GetClickHouseClient(ctx, tokenString)
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

		srv := NewClickHouseMCPServer(config.Config{Server: config.ServerConfig{JWT: jwtConfig}, ClickHouse: chConfig})

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

		// This will fail to connect, but we're testing the JWT parsing logic
		_, err = srv.GetClickHouseClient(ctx, tokenString)
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

		srv := NewClickHouseMCPServer(config.Config{Server: config.ServerConfig{JWT: jwtConfig}, ClickHouse: chConfig})

		// Create a token with wrong signing method (use none algorithm which doesn't require special keys)
		claims := map[string]interface{}{
			"host": "test-host",
			"exp":  time.Now().Add(time.Hour).Unix(),
		}

		token := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims(claims))
		tokenString, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
		require.NoError(t, err)

		// This will fail because we're using 'none' but the server expects HS256
		_, err = srv.GetClickHouseClient(ctx, tokenString)
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

		srv := NewClickHouseMCPServer(config.Config{Server: config.ServerConfig{JWT: jwtConfig}, ClickHouse: chConfig})

		// Create a token with a disallowed claim key
		claims := map[string]interface{}{
			"host":          "test-host",
			"port":          float64(9000),
			"database":      "test-db",
			"invalid_claim": "this should not be allowed", // This key is not in whitelist
			"exp":           time.Now().Add(time.Hour).Unix(),
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims(claims))
		tokenString, err := token.SignedString([]byte(jwtSecret))
		require.NoError(t, err)

		// This should fail because the token contains a disallowed claim key
		_, err = srv.parseAndValidateJWT(tokenString)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid token claims format")
		require.Contains(t, err.Error(), "disallowed claim key 'invalid_claim'")
	})
}

// TestExtractTokenFromCtx tests token extraction from context
func TestExtractTokenFromCtx(t *testing.T) {
	srv := &ClickHouseJWTServer{}

	t.Run("no_token", func(t *testing.T) {
		ctx := context.Background()
		token := srv.ExtractTokenFromCtx(ctx)
		require.Empty(t, token)
		_ = token // Use the token to avoid unused variable error
	})

	t.Run("with_token", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), "jwt_token", "test-token")
		token := srv.ExtractTokenFromCtx(ctx)
		require.Equal(t, "test-token", token)
	})

	t.Run("wrong_type", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), "jwt_token", 123)
		token := srv.ExtractTokenFromCtx(ctx)
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

	t.Run("jwt_enabled_with_valid_token", func(t *testing.T) {
		// Create a valid JWT token with ClickHouse config
		claims := map[string]interface{}{
			"host":     chConfig.Host,
			"port":     chConfig.Port,
			"database": chConfig.Database,
			"username": chConfig.Username,
			"password": chConfig.Password,
			"protocol": string(chConfig.Protocol),
			"limit":    chConfig.Limit,
			"exp":      time.Now().Add(time.Hour).Unix(),
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims(claims))
		tokenString, err := token.SignedString([]byte("test-secret-key"))
		require.NoError(t, err)

		// Inject token into context
		contextWithToken := context.WithValue(ctx, "jwt_token", tokenString)

		// Create test server with JWT enabled
		// Start the server
		testServer := NewAltinityTestServer(t, chConfig).WithJWTAuth(jwtConfig)
		err = testServer.Start(contextWithToken)
		require.NoError(t, err)
		defer testServer.Close()

		// Test list_tables tool with JWT
		result, err := testServer.CallTool(ctx, "list_tables", map[string]interface{}{
			"database": "default",
		})
		require.NoError(t, err)
		require.NotNil(t, result)
		require.False(t, result.IsError, "Tool call resulted in error: %v", result)
	})

	t.Run("jwt_enabled_without_token", func(t *testing.T) {
		// Create test server with JWT enabled
		// Start the server
		testServer := NewAltinityTestServer(t, chConfig).WithJWTAuth(jwtConfig)
		err := testServer.Start(ctx)
		require.NoError(t, err)
		defer testServer.Close()
		// Test without token - should fail
		result, err := testServer.CallTool(ctx, "list_tables", map[string]interface{}{
			"database": "default",
		})
		require.NoError(t, err)
		require.NotNil(t, result)
		require.True(t, result.IsError, "Expected error when JWT is enabled but no token provided, result=%#v", result)
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
		srv := GetClickHouseJWTServerFromContext(ctx)
		require.Nil(t, srv)
	})

	t.Run("with_server", func(t *testing.T) {
		expectedServer := &ClickHouseJWTServer{}
		ctx := context.WithValue(context.Background(), "clickhouse_jwt_server", expectedServer)
		srv := GetClickHouseJWTServerFromContext(ctx)
		require.Equal(t, expectedServer, srv)
	})

	t.Run("wrong_type", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), "clickhouse_jwt_server", "not-a-server")
		srv := GetClickHouseJWTServerFromContext(ctx)
		require.Nil(t, srv)
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

	srv := NewClickHouseMCPServer(config.Config{Server: config.ServerConfig{JWT: jwtConfig}, ClickHouse: chConfig})

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

		parsedClaims, err := srv.parseAndValidateJWT(tokenString)
		require.NoError(t, err)
		require.Equal(t, "test-host", parsedClaims["host"])
		require.Equal(t, float64(9000), parsedClaims["port"])
		require.Equal(t, "test-db", parsedClaims["database"])
	})

	t.Run("invalid_token", func(t *testing.T) {
		_, err := srv.parseAndValidateJWT("invalid-token")
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

		_, err = srv.parseAndValidateJWT(tokenString)
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

	srv := NewClickHouseMCPServer(config.Config{Server: config.ServerConfig{JWT: jwtConfig}, ClickHouse: chConfig})

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

		cfg, err := srv.buildConfigFromClaims(claims)
		require.NoError(t, err)
		require.Equal(t, "jwt-host", cfg.Host)
		require.Equal(t, 9000, cfg.Port)
		require.Equal(t, "jwt-db", cfg.Database)
		require.Equal(t, "jwt-user", cfg.Username)
		require.Equal(t, "jwt-pass", cfg.Password)
		require.Equal(t, "tcp", string(cfg.Protocol))
		require.Equal(t, 500, cfg.Limit)
	})

	t.Run("tls_claims", func(t *testing.T) {
		claims := jwt.MapClaims{
			"tls_enabled":              true,
			"tls_ca_cert":              "/path/to/ca.crt",
			"tls_client_cert":          "/path/to/client.crt",
			"tls_client_key":           "/path/to/client.key",
			"tls_insecure_skip_verify": true,
		}

		cfg, err := srv.buildConfigFromClaims(claims)
		require.NoError(t, err)
		require.True(t, cfg.TLS.Enabled)
		require.Equal(t, "/path/to/ca.crt", cfg.TLS.CaCert)
		require.Equal(t, "/path/to/client.crt", cfg.TLS.ClientCert)
		require.Equal(t, "/path/to/client.key", cfg.TLS.ClientKey)
		require.True(t, cfg.TLS.InsecureSkipVerify)
	})

	t.Run("empty_claims", func(t *testing.T) {
		claims := jwt.MapClaims{}

		cfg, err := srv.buildConfigFromClaims(claims)
		require.NoError(t, err)
		// Should use default values
		require.Equal(t, "default-host", cfg.Host)
		require.Equal(t, 8123, cfg.Port)
		require.Equal(t, "default", cfg.Database)
	})

	t.Run("invalid_types", func(t *testing.T) {
		claims := jwt.MapClaims{
			"host": 123,       // Should be string
			"port": "invalid", // Should be number
		}

		cfg, err := srv.buildConfigFromClaims(claims)
		require.NoError(t, err)
		// Should use default values for invalid types
		require.Equal(t, "default-host", cfg.Host)
		require.Equal(t, 8123, cfg.Port)
	})
}
