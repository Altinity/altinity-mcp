package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/altinity/altinity-mcp/pkg/clickhouse"
	"github.com/altinity/altinity-mcp/pkg/config"
	"github.com/altinity/altinity-mcp/pkg/jwe_auth"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/mcptest"
	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// generateJWEToken is a helper to create JWE tokens for testing.
func generateJWEToken(t *testing.T, claims map[string]interface{}, jweSecretKey []byte, jwtSecretKey []byte) string {
	token, err := jwe_auth.GenerateJWEToken(claims, jweSecretKey, jwtSecretKey)
	require.NoError(t, err)
	return token
}

// AltinityTestServer wraps mcptest functionality to provide additional functionality
// specific to Altinity MCP server testing.
type AltinityTestServer struct {
	testServer       *mcptest.Server
	chJweServer      *ClickHouseJWEServer
	t                *testing.T
	clickhouseClient *clickhouse.Client
	chConfig         *config.ClickHouseConfig
}

// NewAltinityTestServer creates a new AltinityTestServer with a preconfigured mcptest.Server.
// It automatically registers all Altinity MCP tools, resources, and prompts.
func NewAltinityTestServer(t *testing.T, chConfig *config.ClickHouseConfig) *AltinityTestServer {
	t.Helper()

	// Create JWE config for testing (disabled by default)
	jweConfig := config.JWEConfig{
		Enabled: false,
	}

	// Create an mcptest server first
	testServer := mcptest.NewUnstartedServer(t)

	// Create a ClickHouse JWE server but don't use NewClickHouseMCPServer to avoid double registration
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
		Version:   "test-version",
	}

	// Create wrapper that will register tools/resources/prompts with the test server
	wrapper := &testServerWrapper{testServer: testServer, chJweServer: chJweServer}

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
// while delegating JWE functionality to the ClickHouseJWEServer
type testServerWrapper struct {
	testServer  *mcptest.Server
	chJweServer *ClickHouseJWEServer
}

func (w *testServerWrapper) AddTools(tools ...server.ServerTool) {
	for _, tool := range tools {
		w.testServer.AddTool(tool.Tool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			ctx = context.WithValue(ctx, "clickhouse_jwe_server", w.chJweServer)
			return tool.Handler(ctx, req)
		})
	}
}

func (w *testServerWrapper) AddTool(tool mcp.Tool, handler server.ToolHandlerFunc) {
	w.testServer.AddTool(tool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		ctx = context.WithValue(ctx, "clickhouse_jwe_server", w.chJweServer)
		return handler(ctx, req)
	})
}

func (w *testServerWrapper) AddPrompt(prompt mcp.Prompt, handler server.PromptHandlerFunc) {
	w.testServer.AddPrompt(prompt, func(ctx context.Context, req mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
		ctx = context.WithValue(ctx, "clickhouse_jwe_server", w.chJweServer)
		return handler(ctx, req)
	})
}

func (w *testServerWrapper) AddPrompts(prompts ...server.ServerPrompt) {
	for _, prompt := range prompts {
		w.testServer.AddPrompt(prompt.Prompt, func(ctx context.Context, req mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
			ctx = context.WithValue(ctx, "clickhouse_jwe_server", w.chJweServer)
			return prompt.Handler(ctx, req)
		})
	}
}

func (w *testServerWrapper) AddResource(resource mcp.Resource, handler server.ResourceHandlerFunc) {
	w.testServer.AddResource(resource, func(ctx context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
		ctx = context.WithValue(ctx, "clickhouse_jwe_server", w.chJweServer)
		return handler(ctx, req)
	})
}

func (w *testServerWrapper) AddResources(resources ...server.ServerResource) {
	for _, resource := range resources {
		w.testServer.AddResource(resource.Resource, func(ctx context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
			ctx = context.WithValue(ctx, "clickhouse_jwe_server", w.chJweServer)
			return resource.Handler(ctx, req)
		})
	}
}

func (w *testServerWrapper) AddResourceTemplate(template mcp.ResourceTemplate, handler server.ResourceTemplateHandlerFunc) {
	w.testServer.AddResourceTemplate(template, func(ctx context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
		ctx = context.WithValue(ctx, "clickhouse_jwe_server", w.chJweServer)
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
	// Ensure JWE token is properly set in context
	if s.chJweServer != nil {
		if tokenFromCtx := ctx.Value("jwe_token"); tokenFromCtx != nil {
			if tokenStr, ok := tokenFromCtx.(string); ok && tokenStr != "" {
				// Token exists and is not empty, preserve it
				ctx = context.WithValue(ctx, "jwe_token", tokenStr)
			} else {
				// Token exists but is empty or wrong type, set empty
				ctx = context.WithValue(ctx, "jwe_token", "")
			}
		} else {
			// No token in context, set empty
			ctx = context.WithValue(ctx, "jwe_token", "")
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

// WithJWEAuth configures the server to use JWE authentication
func (s *AltinityTestServer) WithJWEAuth(jweConfig config.JWEConfig) *AltinityTestServer {
	// Update the JWE config in the existing server to avoid re-registration
	s.chJweServer.Config.Server.JWE = jweConfig
	return s
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
	jweSecretKey := "this-is-a-32-byte-secret-key!!"
	jwtSecretKey := "test-jwt-super-secret"
	// Create valid JWE token
	validClaims := map[string]interface{}{
		"host":     chConfig.Host,
		"port":     float64(chConfig.Port),
		"database": chConfig.Database,
		"username": chConfig.Username,
		"password": chConfig.Password,
		"protocol": string(chConfig.Protocol),
		"exp":      time.Now().Add(time.Hour).Unix(),
	}
	validTokenString := generateJWEToken(t, validClaims, []byte(jweSecretKey), []byte(jwtSecretKey))

	// Test cases with different configurations
	testCases := []struct {
		name        string
		jweEnabled  bool
		tokenParam  string
		expectError bool
	}{
		{"without_jwe", false, "", false},
		{"with_jwe_invalid", true, "invalid-token", true},
		{"with_jwe_valid", true, validTokenString, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			jweConfig := config.JWEConfig{
				Enabled:      tc.jweEnabled,
				JWESecretKey: jweSecretKey,
				JWTSecretKey: jwtSecretKey,
			}

			// Set up chJweServer with ClickHouse config and JWE
			chJweServer := &ClickHouseJWEServer{
				Config:  config.Config{Server: config.ServerConfig{JWE: jweConfig}, ClickHouse: *chConfig},
				Version: "test-version",
			}

			// Create test server
			testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Always inject the server into context
				ctx := context.WithValue(r.Context(), "clickhouse_jwe_server", chJweServer)
				r = r.WithContext(ctx)
				chJweServer.OpenAPIHandler(w, r)
			}))
			defer testServer.Close()

			// Helper function to make requests
			makeRequest := func(path string, token string) *http.Response {
				req := httptest.NewRequest("GET", path, nil)
				// Inject the appropriate token into context
				if token != "" {
					req = req.WithContext(context.WithValue(req.Context(), "jwe_token", token))
				}
				w := httptest.NewRecorder()
				testServer.Config.Handler.ServeHTTP(w, req)
				return w.Result()
			}

			t.Run("OpenAPI_schema", func(t *testing.T) {
				// Add token through path for some cases
				path := testServer.URL + "/openapi"
				if tc.jweEnabled {
					path = fmt.Sprintf("%s/%s/openapi", testServer.URL, tc.tokenParam)
				}

				resp := makeRequest(path, tc.tokenParam)
				if tc.expectError {
					require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
				} else {
					require.Equal(t, http.StatusOK, resp.StatusCode)
					require.Equal(t, "application/json", resp.Header.Get("Content-Type"))

					var schema map[string]interface{}
					err := json.NewDecoder(resp.Body).Decode(&schema)
					require.NoError(t, err)
					require.Contains(t, schema, "openapi")
					// Check version in OpenAPI schema
					require.Contains(t, schema, "info")
					info, ok := schema["info"].(map[string]interface{})
					require.True(t, ok)
					require.Contains(t, info, "version")
					require.Equal(t, "test-version", info["version"])
				}
			})

			t.Run("ListTables_OpenAPI", func(t *testing.T) {
				path := fmt.Sprintf("%s/openapi/list_tables", testServer.URL)
				if tc.jweEnabled {
					path = fmt.Sprintf("%s/%s/openapi/list_tables", testServer.URL, tc.tokenParam)
				}

				resp := makeRequest(path, tc.tokenParam)
				if tc.expectError {
					require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
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
				if tc.jweEnabled {
					path = fmt.Sprintf("%s/%s/openapi/describe_table?database=default&table_name=test", testServer.URL, tc.tokenParam)
				}

				resp := makeRequest(path, tc.tokenParam)
				if tc.expectError {
					require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
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
				if tc.jweEnabled {
					path = fmt.Sprintf("%s/%s/openapi/execute_query?query=SELECT+*+FROM+test", testServer.URL, tc.tokenParam)
				}

				resp := makeRequest(path, tc.tokenParam)
				if tc.expectError {
					require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
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
		jweConfig := config.JWEConfig{Enabled: false}
		chJweServer := &ClickHouseJWEServer{
			Config:  config.Config{Server: config.ServerConfig{JWE: jweConfig}, ClickHouse: *chConfig},
			Version: "test-version",
		}

		testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), "clickhouse_jwe_server", chJweServer)
			r = r.WithContext(ctx)
			chJweServer.OpenAPIHandler(w, r)
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
		jweConfig := config.JWEConfig{
			Enabled:      true,
			JWESecretKey: jweSecretKey,
			JWTSecretKey: jwtSecretKey,
		}
		chJweServer := &ClickHouseJWEServer{
			Config:  config.Config{Server: config.ServerConfig{JWE: jweConfig}, ClickHouse: *chConfig},
			Version: "test-version",
		}

		testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), "clickhouse_jwe_server", chJweServer)
			r = r.WithContext(ctx)
			chJweServer.OpenAPIHandler(w, r)
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
			require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		})
	})
}

// TestExtractTokenFromRequest tests token extraction from HTTP requests
func TestExtractTokenFromRequest(t *testing.T) {
	srv := &ClickHouseJWEServer{}

	t.Run("bearer_authorization_header", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "Bearer test-token-123")

		token := srv.ExtractTokenFromRequest(req)
		require.Equal(t, "test-token-123", token)
	})

	t.Run("basic_authorization_header", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "Basic test-token-456")

		token := srv.ExtractTokenFromRequest(req)
		require.Equal(t, "test-token-456", token)
	})

	t.Run("altinity_mcp_header", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("x-altinity-mcp-key", "test-token-789")

		token := srv.ExtractTokenFromRequest(req)
		require.Equal(t, "test-token-789", token)
	})

	t.Run("openapi_path_token", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/some-token/openapi/list_tables", nil)

		token := srv.ExtractTokenFromRequest(req)
		require.Equal(t, "some-token", token)
	})

	t.Run("bearer_priority", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "Bearer bearer-token")
		req.Header.Set("x-altinity-mcp-key", "header-token")

		token := srv.ExtractTokenFromRequest(req)
		require.Equal(t, "bearer-token", token)
	})

	t.Run("header_priority", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("x-altinity-mcp-key", "header-token")
		req.SetPathValue("token", "path-token")

		token := srv.ExtractTokenFromRequest(req)
		require.Equal(t, "header-token", token)
	})

	t.Run("no_token", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)

		token := srv.ExtractTokenFromRequest(req)
		require.Equal(t, "", token)
	})

	t.Run("invalid_authorization_header", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "Invalid test-token")

		token := srv.ExtractTokenFromRequest(req)
		require.Equal(t, "", token)
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

	// Test MCP server version in initialize response
	t.Run("MCP_Initialize_Version", func(t *testing.T) {
		// The mcptest.Server should handle initialize automatically, but we can check the server's version
		require.Equal(t, "test-version", testServer.chJweServer.Version)
	})

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

	jweConfig := config.JWEConfig{
		Enabled: false,
	}

	version := "test-version"
	srv := NewClickHouseMCPServer(config.Config{Server: config.ServerConfig{JWE: jweConfig}, ClickHouse: chConfig}, version)
	require.NotNil(t, srv)
	require.NotNil(t, srv.MCPServer)
	require.Equal(t, jweConfig, srv.Config.Server.JWE)
	require.Equal(t, chConfig, srv.Config.ClickHouse)
	require.Equal(t, version, srv.Version)
}

// TestGetClickHouseClientWithJWE tests the JWE client creation
func TestGetClickHouseClientWithJWE(t *testing.T) {
	ctx := context.Background()
	jweSecretKey := "this-is-a-32-byte-secret-key!!"
	jwtSecretKey := "test-jwt-secret"

	t.Run("without_jwe", func(t *testing.T) {
		chConfig := config.ClickHouseConfig{
			Host:     "localhost",
			Port:     8123,
			Database: "default",
			Username: "default",
			Protocol: config.HTTPProtocol,
			Limit:    1000,
		}

		jweConfig := config.JWEConfig{
			Enabled: false,
		}

		srv := NewClickHouseMCPServer(config.Config{Server: config.ServerConfig{JWE: jweConfig}, ClickHouse: chConfig}, "test-version")

		// This will fail to connect, but we're testing the logic, not the connection
		_, err := srv.GetClickHouseClient(ctx, "")
		// We expect an error because we're not actually connecting to ClickHouse
		require.Error(t, err)
	})

	t.Run("with_jwe_missing_token", func(t *testing.T) {
		chConfig := config.ClickHouseConfig{
			Host:     "localhost",
			Port:     8123,
			Database: "default",
			Username: "default",
			Protocol: config.HTTPProtocol,
			Limit:    1000,
		}

		jweConfig := config.JWEConfig{
			Enabled:      true,
			JWESecretKey: jweSecretKey,
			JWTSecretKey: jwtSecretKey,
		}

		srv := NewClickHouseMCPServer(config.Config{Server: config.ServerConfig{JWE: jweConfig}, ClickHouse: chConfig}, "test-version")

		_, err := srv.GetClickHouseClient(ctx, "")
		require.Equal(t, jwe_auth.ErrMissingToken, err)
	})

	t.Run("with_jwe_invalid_token", func(t *testing.T) {
		chConfig := config.ClickHouseConfig{
			Host:     "localhost",
			Port:     8123,
			Database: "default",
			Username: "default",
			Protocol: config.HTTPProtocol,
			Limit:    1000,
		}

		jweConfig := config.JWEConfig{
			Enabled:      true,
			JWESecretKey: jweSecretKey,
			JWTSecretKey: jwtSecretKey,
		}

		srv := NewClickHouseMCPServer(config.Config{Server: config.ServerConfig{JWE: jweConfig}, ClickHouse: chConfig}, "test-version")

		_, err := srv.GetClickHouseClient(ctx, "invalid-token")
		require.Equal(t, jwe_auth.ErrInvalidToken, err)
	})

	t.Run("with_jwe_valid_token", func(t *testing.T) {
		chConfig := config.ClickHouseConfig{
			Host:     "localhost",
			Port:     8123,
			Database: "default",
			Username: "default",
			Protocol: config.HTTPProtocol,
			Limit:    1000,
		}

		jweConfig := config.JWEConfig{
			Enabled:      true,
			JWESecretKey: jweSecretKey,
			JWTSecretKey: jwtSecretKey,
		}

		srv := NewClickHouseMCPServer(config.Config{Server: config.ServerConfig{JWE: jweConfig}, ClickHouse: chConfig}, "test-version")

		// Create a valid JWE token
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
		tokenString := generateJWEToken(t, claims, []byte(jweSecretKey), []byte(jwtSecretKey))

		// This will fail to connect, but we're testing the JWE parsing logic
		_, err := srv.GetClickHouseClient(ctx, tokenString)
		// We expect a connection error, not a JWE error
		require.Error(t, err)
		require.NotEqual(t, jwe_auth.ErrMissingToken, err)
		require.NotEqual(t, jwe_auth.ErrInvalidToken, err)
	})

	t.Run("with_jwe_token_with_tls", func(t *testing.T) {
		chConfig := config.ClickHouseConfig{
			Host:     "localhost",
			Port:     8123,
			Database: "default",
			Username: "default",
			Protocol: config.HTTPProtocol,
			Limit:    1000,
		}

		jweConfig := config.JWEConfig{
			Enabled:      true,
			JWESecretKey: jweSecretKey,
			JWTSecretKey: jwtSecretKey,
		}

		srv := NewClickHouseMCPServer(config.Config{Server: config.ServerConfig{JWE: jweConfig}, ClickHouse: chConfig}, "test-version")

		// Create a valid JWE token with TLS configuration
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
		tokenString := generateJWEToken(t, claims, []byte(jweSecretKey), []byte(jwtSecretKey))

		// This will fail to connect, but we're testing the JWE parsing logic
		_, err := srv.GetClickHouseClient(ctx, tokenString)
		// We expect a connection error, not a JWE error
		require.Error(t, err)
		require.NotEqual(t, jwe_auth.ErrMissingToken, err)
		require.NotEqual(t, jwe_auth.ErrInvalidToken, err)
	})

	t.Run("with_jwe_invalid_encryption_key", func(t *testing.T) {
		chConfig := config.ClickHouseConfig{
			Host:     "localhost",
			Port:     8123,
			Database: "default",
			Username: "default",
			Protocol: config.HTTPProtocol,
			Limit:    1000,
		}

		correctJweSecretKey := "this-is-a-different-32-byte-key!"
		jweConfig := config.JWEConfig{
			Enabled:      true,
			JWESecretKey: correctJweSecretKey,
			JWTSecretKey: jwtSecretKey,
		}

		srv := NewClickHouseMCPServer(config.Config{Server: config.ServerConfig{JWE: jweConfig}, ClickHouse: chConfig}, "test-version")

		claims := map[string]interface{}{
			"host": "test-host",
			"exp":  time.Now().Add(time.Hour).Unix(),
		}
		tokenString := generateJWEToken(t, claims, []byte(jweSecretKey), []byte(jwtSecretKey))

		// This will fail because the token was encrypted with a different key
		_, err := srv.GetClickHouseClient(ctx, tokenString)
		require.Equal(t, jwe_auth.ErrInvalidToken, err)
	})

	t.Run("with_jwe_invalid_claims", func(t *testing.T) {
		chConfig := config.ClickHouseConfig{
			Host:     "localhost",
			Port:     8123,
			Database: "default",
			Username: "default",
			Protocol: config.HTTPProtocol,
			Limit:    1000,
		}

		jweConfig := config.JWEConfig{
			Enabled:      true,
			JWESecretKey: jweSecretKey,
			JWTSecretKey: jwtSecretKey,
		}

		srv := NewClickHouseMCPServer(config.Config{Server: config.ServerConfig{JWE: jweConfig}, ClickHouse: chConfig}, "test-version")

		// Create a token with a disallowed claim key
		claims := map[string]interface{}{
			"host":          "test-host",
			"port":          float64(9000),
			"database":      "test-db",
			"invalid_claim": "this should not be allowed", // This key is not in whitelist
			"exp":           time.Now().Add(time.Hour).Unix(),
		}
		tokenString := generateJWEToken(t, claims, []byte(jweSecretKey), []byte(jwtSecretKey))

		// This should fail because the token contains a disallowed claim key
		_, err := srv.GetClickHouseClient(ctx, tokenString)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid token claims format")
		require.Contains(t, err.Error(), "disallowed claim key 'invalid_claim'")
	})
}

// TestExtractTokenFromCtx tests token extraction from context
func TestExtractTokenFromCtx(t *testing.T) {
	srv := &ClickHouseJWEServer{}

	t.Run("no_token", func(t *testing.T) {
		ctx := context.Background()
		token := srv.ExtractTokenFromCtx(ctx)
		require.Empty(t, token)
		_ = token // Use the token to avoid unused variable error
	})

	t.Run("with_token", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), "jwe_token", "test-token")
		token := srv.ExtractTokenFromCtx(ctx)
		require.Equal(t, "test-token", token)
	})

	t.Run("wrong_type", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), "jwe_token", 123)
		token := srv.ExtractTokenFromCtx(ctx)
		require.Empty(t, token)
	})
}

// TestJWEWithRealClickHouse tests JWE authentication with a real ClickHouse container
func TestJWEWithRealClickHouse(t *testing.T) {
	ctx := context.Background()
	chConfig := setupClickHouseContainer(t)

	jweSecretKey := "this-is-a-32-byte-secret-key!!"
	jwtSecretKey := "test-jwt-secret"

	// Create JWE config
	jweConfig := config.JWEConfig{
		Enabled:      true,
		JWESecretKey: jweSecretKey,
		JWTSecretKey: jwtSecretKey,
	}

	t.Run("jwe_enabled_with_valid_token", func(t *testing.T) {
		// Create a valid JWE token with ClickHouse config
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

		tokenString := generateJWEToken(t, claims, []byte(jweSecretKey), []byte(jwtSecretKey))

		// Inject token into context
		contextWithToken := context.WithValue(ctx, "jwe_token", tokenString)

		// Create test server with JWE enabled
		// Start the server
		testServer := NewAltinityTestServer(t, chConfig).WithJWEAuth(jweConfig)
		err := testServer.Start(contextWithToken)
		require.NoError(t, err)
		defer testServer.Close()

		// Test execute_query tool with JWE
		result, err := testServer.CallTool(contextWithToken, "execute_query", map[string]interface{}{
			"query": "SELECT 1",
		})
		require.NoError(t, err)
		require.NotNil(t, result)
		require.False(t, result.IsError, "Tool call resulted in error: %v", result)
	})

	t.Run("jwe_enabled_without_token", func(t *testing.T) {
		// Create test server with JWE enabled
		// Start the server
		testServer := NewAltinityTestServer(t, chConfig).WithJWEAuth(jweConfig)
		err := testServer.Start(ctx)
		require.NoError(t, err)
		defer testServer.Close()
		// Test without token - should fail
		result, err := testServer.CallTool(ctx, "execute_query", map[string]interface{}{
			"query": "SELECT 1",
		})
		require.NoError(t, err)
		require.NotNil(t, result)
		require.True(t, result.IsError, "Expected error when JWE is enabled but no token provided, result=%#v", result)
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

// TestGetClickHouseJWEServerFromContext tests context extraction
func TestGetClickHouseJWEServerFromContext(t *testing.T) {
	t.Run("no_server", func(t *testing.T) {
		ctx := context.Background()
		srv := GetClickHouseJWEServerFromContext(ctx)
		require.Nil(t, srv)
	})

	t.Run("with_server", func(t *testing.T) {
		expectedServer := &ClickHouseJWEServer{}
		ctx := context.WithValue(context.Background(), "clickhouse_jwe_server", expectedServer)
		srv := GetClickHouseJWEServerFromContext(ctx)
		require.Equal(t, expectedServer, srv)
	})

	t.Run("wrong_type", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), "clickhouse_jwe_server", "not-a-server")
		srv := GetClickHouseJWEServerFromContext(ctx)
		require.Nil(t, srv)
	})
}

// TestBuildConfigFromClaims tests building ClickHouse config from JWE claims
func TestBuildConfigFromClaims(t *testing.T) {
	chConfig := config.ClickHouseConfig{
		Host:     "default-host",
		Port:     8123,
		Database: "default",
		Username: "default",
		Protocol: config.HTTPProtocol,
		Limit:    1000,
	}

	jweConfig := config.JWEConfig{
		Enabled:      true,
		JWESecretKey: "test-secret",
	}

	srv := NewClickHouseMCPServer(config.Config{Server: config.ServerConfig{JWE: jweConfig}, ClickHouse: chConfig}, "test-version")

	t.Run("basic_claims", func(t *testing.T) {
		claims := map[string]interface{}{
			"host":     "jwe-host",
			"port":     float64(9000),
			"database": "jwe-db",
			"username": "jwe-user",
			"password": "jwe-pass",
			"protocol": "tcp",
			"limit":    float64(500),
		}

		cfg, err := srv.buildConfigFromClaims(claims)
		require.NoError(t, err)
		require.Equal(t, "jwe-host", cfg.Host)
		require.Equal(t, 9000, cfg.Port)
		require.Equal(t, "jwe-db", cfg.Database)
		require.Equal(t, "jwe-user", cfg.Username)
		require.Equal(t, "jwe-pass", cfg.Password)
		require.Equal(t, "tcp", string(cfg.Protocol))
		require.Equal(t, 500, cfg.Limit)
	})

	t.Run("tls_claims", func(t *testing.T) {
		claims := map[string]interface{}{
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
		claims := map[string]interface{}{}

		cfg, err := srv.buildConfigFromClaims(claims)
		require.NoError(t, err)
		// Should use default values
		require.Equal(t, "default-host", cfg.Host)
		require.Equal(t, 8123, cfg.Port)
		require.Equal(t, "default", cfg.Database)
	})

	t.Run("invalid_types", func(t *testing.T) {
		claims := map[string]interface{}{
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
