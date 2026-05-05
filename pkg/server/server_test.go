package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/altinity/altinity-mcp/pkg/clickhouse"
	"github.com/altinity/altinity-mcp/pkg/config"
	"github.com/altinity/altinity-mcp/pkg/jwe_auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"
)

type captureServer struct {
	tools []*mcp.Tool
}

func (c *captureServer) AddTool(tool *mcp.Tool, _ ToolHandlerFunc) {
	c.tools = append(c.tools, tool)
}

func (c *captureServer) AddResource(_ *mcp.Resource, _ ResourceHandlerFunc) {}

func (c *captureServer) AddResourceTemplate(_ *mcp.ResourceTemplate, _ ResourceHandlerFunc) {}

func (c *captureServer) AddPrompt(_ *mcp.Prompt, _ PromptHandlerFunc) {}

type mockMCPServer struct {
	addToolFn func(tool *mcp.Tool, handler ToolHandlerFunc)
}

func (m *mockMCPServer) AddTool(tool *mcp.Tool, handler ToolHandlerFunc) {
	if m.addToolFn != nil {
		m.addToolFn(tool, handler)
	}
}
func (m *mockMCPServer) AddResource(_ *mcp.Resource, _ ResourceHandlerFunc)                 {}
func (m *mockMCPServer) AddResourceTemplate(_ *mcp.ResourceTemplate, _ ResourceHandlerFunc) {}
func (m *mockMCPServer) AddPrompt(_ *mcp.Prompt, _ PromptHandlerFunc)                       {}

// generateJWEToken is a helper to create JWE tokens for testing.
func generateJWEToken(t *testing.T, claims map[string]interface{}, jweSecretKey []byte, jwtSecretKey []byte) string {
	token, err := jwe_auth.GenerateJWEToken(claims, jweSecretKey, jwtSecretKey)
	require.NoError(t, err)
	return token
}

// TestOpenAPIHandlers tests the OpenAPI handlers
func TestOpenAPIHandlers(t *testing.T) {
	t.Parallel()
	chConfig := setupEmbeddedClickHouse(t)

	t.Run("serves_openapi_schema", func(t *testing.T) {
		t.Parallel()
		srv := NewClickHouseMCPServer(config.Config{
			ClickHouse: *chConfig,
			Server:     config.ServerConfig{JWE: config.JWEConfig{Enabled: false}},
		}, "test")

		req := httptest.NewRequest(http.MethodGet, "/openapi", nil)
		req = req.WithContext(context.WithValue(req.Context(), CHJWEServerKey, srv))

		rr := httptest.NewRecorder()
		srv.ServeOpenAPISchema(rr, req)

		require.Equal(t, http.StatusOK, rr.Code)
		require.Contains(t, rr.Header().Get("Content-Type"), "application/json")

		var schema map[string]interface{}
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &schema))
		require.Equal(t, "3.1.0", schema["openapi"])
	})

	t.Run("execute_query_via_openapi", func(t *testing.T) {
		t.Parallel()
		srv := NewClickHouseMCPServer(config.Config{
			ClickHouse: *chConfig,
			Server:     config.ServerConfig{JWE: config.JWEConfig{Enabled: false}},
		}, "test")

		req := httptest.NewRequest(http.MethodGet, "/openapi/execute_query?query=SELECT%201", nil)
		req = req.WithContext(context.WithValue(req.Context(), CHJWEServerKey, srv))

		rr := httptest.NewRecorder()
		srv.OpenAPIHandler(rr, req)

		require.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("execute_query_with_limit", func(t *testing.T) {
		t.Parallel()
		srv := NewClickHouseMCPServer(config.Config{
			ClickHouse: *chConfig,
			Server:     config.ServerConfig{JWE: config.JWEConfig{Enabled: false}},
		}, "test")

		req := httptest.NewRequest(http.MethodGet, "/openapi/execute_query?query=SELECT%20*%20FROM%20default.test&limit=1", nil)
		req = req.WithContext(context.WithValue(req.Context(), CHJWEServerKey, srv))

		rr := httptest.NewRecorder()
		srv.OpenAPIHandler(rr, req)

		require.Equal(t, http.StatusOK, rr.Code)
		var qr clickhouse.QueryResult
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &qr))
		require.Equal(t, 1, qr.Count)
	})

	t.Run("execute_query_missing_param", func(t *testing.T) {
		t.Parallel()
		srv := NewClickHouseMCPServer(config.Config{
			ClickHouse: *chConfig,
			Server:     config.ServerConfig{JWE: config.JWEConfig{Enabled: false}},
		}, "test")

		req := httptest.NewRequest(http.MethodGet, "/openapi/execute_query", nil)
		req = req.WithContext(context.WithValue(req.Context(), CHJWEServerKey, srv))

		rr := httptest.NewRecorder()
		srv.OpenAPIHandler(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("jwe_required_but_missing", func(t *testing.T) {
		t.Parallel()
		srv := NewClickHouseMCPServer(config.Config{
			ClickHouse: *chConfig,
			Server: config.ServerConfig{
				JWE: config.JWEConfig{
					Enabled:      true,
					JWESecretKey: "test-key",
					JWTSecretKey: "test-jwt",
				},
			},
		}, "test")

		req := httptest.NewRequest(http.MethodGet, "/openapi/execute_query?query=SELECT%201", nil)
		req = req.WithContext(context.WithValue(req.Context(), CHJWEServerKey, srv))

		rr := httptest.NewRecorder()
		srv.OpenAPIHandler(rr, req)

		require.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("combined_auth_oauth_only_via_openapi", func(t *testing.T) {
		t.Parallel()
		const gatingSecret = "test-gating-secret-32-byte-key!!"
		srv := NewClickHouseMCPServer(config.Config{
			ClickHouse: *chConfig,
			Server: config.ServerConfig{
				JWE: config.JWEConfig{
					Enabled:      true,
					JWESecretKey: "this-is-a-32-byte-secret-key!!",
					JWTSecretKey: "jwt-secret",
				},
				OAuth: config.OAuthConfig{
					Enabled:         true,
					Mode:            "gating",
					GatingSecretKey: gatingSecret,
				},
			},
		}, "test")

		oauthToken := mintSelfIssuedToken(t, gatingSecret, map[string]interface{}{
			"sub": "user123",
			"exp": time.Now().Add(time.Hour).Unix(),
		})

		req := httptest.NewRequest(http.MethodGet, "/openapi/execute_query?query=SELECT%201", nil)
		req.Header.Set("Authorization", "Bearer "+oauthToken)
		req = req.WithContext(context.WithValue(req.Context(), CHJWEServerKey, srv))

		rr := httptest.NewRecorder()
		srv.OpenAPIHandler(rr, req)

		require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	})

	t.Run("dynamic_tool_execution", func(t *testing.T) {
		t.Parallel()
		// Create view
		ctx := context.Background()
		client, err := clickhouse.NewClient(ctx, *chConfig)
		require.NoError(t, err)
		defer func() {
			if closeErr := client.Close(); closeErr != nil {
				t.Fatalf("can't close client, %v", closeErr)
			}
		}()

		_, _ = client.ExecuteQuery(ctx, "DROP VIEW IF EXISTS default.v_api")
		_, err = client.ExecuteQuery(ctx, "CREATE VIEW default.v_api AS SELECT * FROM default.test WHERE id={id:UInt64}")
		require.NoError(t, err)

		srv := &ClickHouseJWEServer{
			Config: config.Config{
				ClickHouse: *chConfig,
				Server:     config.ServerConfig{JWE: config.JWEConfig{Enabled: false}},
			},
			Version: "test",
			dynamicTools: map[string]dynamicToolMeta{
				"custom_default_v_api": {
					ToolName:    "custom_default_v_api",
					Database:    "default",
					Table:       "v_api",
					Description: "desc",
					Params:      []dynamicToolParam{{Name: "id", CHType: "UInt64", JSONType: "integer", JSONFormat: "int64", Required: true}},
				},
			},
		}

		body := strings.NewReader(`{"id":1}`)
		req := httptest.NewRequest(http.MethodPost, "/openapi/custom_default_v_api", body)
		req.Header.Set("Content-Type", "application/json")
		req = req.WithContext(context.WithValue(req.Context(), CHJWEServerKey, srv))

		rr := httptest.NewRecorder()
		srv.OpenAPIHandler(rr, req)

		require.Equal(t, http.StatusOK, rr.Code)
		var qr clickhouse.QueryResult
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &qr))
		require.GreaterOrEqual(t, qr.Count, 1)
	})

	t.Run("dynamic_tool_not_found", func(t *testing.T) {
		t.Parallel()
		srv := &ClickHouseJWEServer{
			Config: config.Config{
				ClickHouse: *chConfig,
				Server:     config.ServerConfig{JWE: config.JWEConfig{Enabled: false}},
			},
			Version:      "test",
			dynamicTools: map[string]dynamicToolMeta{},
		}

		body := strings.NewReader(`{"id":1}`)
		req := httptest.NewRequest(http.MethodPost, "/openapi/unknown_tool", body)
		req.Header.Set("Content-Type", "application/json")
		req = req.WithContext(context.WithValue(req.Context(), CHJWEServerKey, srv))

		rr := httptest.NewRecorder()
		srv.OpenAPIHandler(rr, req)

		require.Equal(t, http.StatusNotFound, rr.Code)
	})

	t.Run("dynamic_tool_invalid_json", func(t *testing.T) {
		t.Parallel()
		srv := &ClickHouseJWEServer{
			Config: config.Config{
				ClickHouse: *chConfig,
				Server:     config.ServerConfig{JWE: config.JWEConfig{Enabled: false}},
			},
			Version: "test",
			dynamicTools: map[string]dynamicToolMeta{
				"tool": {
					ToolName: "tool",
					Params:   []dynamicToolParam{},
				},
			},
		}

		body := strings.NewReader(`not json`)
		req := httptest.NewRequest(http.MethodPost, "/openapi/tool", body)
		req = req.WithContext(context.WithValue(req.Context(), CHJWEServerKey, srv))

		rr := httptest.NewRecorder()
		srv.OpenAPIHandler(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
	})
}

// TestNewClickHouseMCPServer tests that the server can be created with various configs
func TestNewClickHouseMCPServer(t *testing.T) {
	t.Parallel()
	t.Run("creates_server_with_defaults", func(t *testing.T) {
		t.Parallel()
		cfg := config.Config{
			ClickHouse: config.ClickHouseConfig{
				Host: "localhost",
				Port: 8123,
			},
			Server: config.ServerConfig{
				JWE: config.JWEConfig{Enabled: false},
			},
		}
		srv := NewClickHouseMCPServer(cfg, "test-version")
		require.NotNil(t, srv)
		require.NotNil(t, srv.MCPServer)
		require.Equal(t, "test-version", srv.Version)
	})

	t.Run("creates_server_with_jwe_enabled", func(t *testing.T) {
		t.Parallel()
		cfg := config.Config{
			ClickHouse: config.ClickHouseConfig{
				Host: "localhost",
				Port: 8123,
			},
			Server: config.ServerConfig{
				JWE: config.JWEConfig{
					Enabled:      true,
					JWESecretKey: "test-jwe-key",
					JWTSecretKey: "test-jwt-key",
				},
			},
		}
		srv := NewClickHouseMCPServer(cfg, "test-version")
		require.NotNil(t, srv)
		require.True(t, srv.Config.Server.JWE.Enabled)
	})
}

func TestRegisterTools_Annotations(t *testing.T) {
	t.Parallel()
	t.Run("read_only_server_skips_write_query_and_marks_execute_query_safe", func(t *testing.T) {
		t.Parallel()
		srv := &captureServer{}

		cfg := config.Config{
			ClickHouse: config.ClickHouseConfig{ReadOnly: true},
		}
		RegisterTools(srv, &cfg)

		// In read-only mode write_query is skipped entirely; only execute_query remains.
		require.Len(t, srv.tools, 1)
		tool := srv.tools[0]
		require.Equal(t, "execute_query", tool.Name)
		require.Equal(t, "Execute SQL Query", tool.Title)
		require.NotNil(t, tool.Annotations)
		require.True(t, tool.Annotations.ReadOnlyHint)
		require.NotNil(t, tool.Annotations.DestructiveHint)
		require.False(t, *tool.Annotations.DestructiveHint)
		require.NotNil(t, tool.Annotations.OpenWorldHint)
		require.False(t, *tool.Annotations.OpenWorldHint)
	})

	t.Run("read_write_server_registers_both_and_execute_query_still_read_only", func(t *testing.T) {
		t.Parallel()
		srv := &captureServer{}

		cfg := config.Config{
			ClickHouse: config.ClickHouseConfig{ReadOnly: false},
		}
		RegisterTools(srv, &cfg)

		// Defaults register both execute_query and write_query.
		require.Len(t, srv.tools, 2)

		var eq, wq *mcp.Tool
		for _, t := range srv.tools {
			switch t.Name {
			case "execute_query":
				eq = t
			case "write_query":
				wq = t
			}
		}
		require.NotNil(t, eq, "execute_query tool should be registered")
		require.NotNil(t, wq, "write_query tool should be registered")

		// execute_query is always read-only, regardless of the server's read-only flag.
		require.True(t, eq.Annotations.ReadOnlyHint)
		require.False(t, *eq.Annotations.DestructiveHint)
		require.False(t, *eq.Annotations.OpenWorldHint)

		// write_query is destructive.
		require.False(t, wq.Annotations.ReadOnlyHint)
		require.True(t, *wq.Annotations.DestructiveHint)
		require.False(t, *wq.Annotations.OpenWorldHint)
	})
}

func TestOpenAPI_DynamicPathsIncluded(t *testing.T) {
	t.Parallel()
	s := &ClickHouseJWEServer{
		Config:  config.Config{},
		Version: "test",
		dynamicTools: map[string]dynamicToolMeta{
			"custom_db_view": {
				ToolName:    "custom_db_view",
				Title:       "Custom Db View",
				Database:    "db",
				Table:       "view",
				Description: "desc",
				Annotations: buildDynamicToolAnnotations(nil),
				Params:      []dynamicToolParam{{Name: "id", CHType: "UInt64", JSONType: "integer", JSONFormat: "int64", Required: true}},
			},
		},
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/openapi", nil)
	ctx := context.WithValue(req.Context(), CHJWEServerKey, s)
	req = req.WithContext(ctx)
	s.ServeOpenAPISchema(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)

	var schema map[string]interface{}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &schema))
	paths := schema["paths"].(map[string]interface{})
	_, ok := paths["/openapi/custom_db_view"]
	require.True(t, ok)
}

func TestOpenAPI_SchemaIncludesCombinedAuthPaths(t *testing.T) {
	t.Parallel()
	s := &ClickHouseJWEServer{
		Version: "test-version",
		Config: config.Config{
			Server: config.ServerConfig{
				JWE: config.JWEConfig{
					Enabled:      true,
					JWESecretKey: "this-is-a-32-byte-secret-key!!",
					JWTSecretKey: "jwt-secret",
				},
				OAuth: config.OAuthConfig{
					Enabled: true,
					Mode:    "forward",
				},
			},
		},
		dynamicTools: map[string]dynamicToolMeta{
			"custom_db_view": {
				ToolName:    "custom_db_view",
				Description: "desc",
				Annotations: buildDynamicToolAnnotations(nil),
				Params:      []dynamicToolParam{{Name: "id", CHType: "UInt64", JSONType: "integer", JSONFormat: "int64", Required: true}},
			},
		},
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/openapi", nil)
	ctx := context.WithValue(req.Context(), CHJWEServerKey, s)
	req = req.WithContext(ctx)
	s.ServeOpenAPISchema(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)

	var schema map[string]interface{}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &schema))
	paths := schema["paths"].(map[string]interface{})
	_, hasOAuthFallbackExecute := paths["/openapi/execute_query"]
	_, hasTokenizedExecute := paths["/{jwe_token}/openapi/execute_query"]
	_, hasOAuthFallbackTool := paths["/openapi/custom_db_view"]
	_, hasTokenizedTool := paths["/{jwe_token}/openapi/custom_db_view"]
	require.True(t, hasOAuthFallbackExecute)
	require.True(t, hasTokenizedExecute)
	require.True(t, hasOAuthFallbackTool)
	require.True(t, hasTokenizedTool)
}

func TestHandleDynamicToolOpenAPI_PostExecutes(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	chConfig := setupEmbeddedClickHouse(t)
	client, err := clickhouse.NewClient(ctx, *chConfig)
	require.NoError(t, err)
	defer func() { require.NoError(t, client.Close()) }()

	_, _ = client.ExecuteQuery(ctx, "DROP VIEW IF EXISTS default.v_api")
	_, err = client.ExecuteQuery(ctx, "CREATE VIEW default.v_api AS SELECT * FROM default.test WHERE id={id:UInt64}")
	require.NoError(t, err)

	s := &ClickHouseJWEServer{
		Config: config.Config{
			ClickHouse: *chConfig,
			Server:     config.ServerConfig{JWE: config.JWEConfig{Enabled: false}},
		},
		Version: "test",
		dynamicTools: map[string]dynamicToolMeta{
			"custom_default_v_api": {
				ToolName:    "custom_default_v_api",
				Database:    "default",
				Table:       "v_api",
				Description: "desc",
				Params:      []dynamicToolParam{{Name: "id", CHType: "UInt64", JSONType: "integer", JSONFormat: "int64", Required: true}},
			},
		},
	}

	// Build POST request to dynamic tool endpoint
	body := strings.NewReader(`{"id":1}`)
	req := httptest.NewRequest(http.MethodPost, "/openapi/custom_default_v_api", body)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	// Inject server into context and call OpenAPIHandler
	req = req.WithContext(context.WithValue(req.Context(), CHJWEServerKey, s))
	s.OpenAPIHandler(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	var qr clickhouse.QueryResult
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &qr))
	require.GreaterOrEqual(t, qr.Count, 1)
}

// TestHandleDynamicToolOpenAPI_Errors tests error cases for dynamic tool OpenAPI
func TestHandleDynamicToolOpenAPI_Errors(t *testing.T) {
	t.Parallel()
	// Build a minimal server with one dynamic tool meta
	s := &ClickHouseJWEServer{
		Config: config.Config{
			Server: config.ServerConfig{
				JWE: config.JWEConfig{Enabled: true, JWESecretKey: "x", JWTSecretKey: "y"},
			},
		},
		Version: "test",
		dynamicTools: map[string]dynamicToolMeta{
			"tool": {
				ToolName:    "tool",
				Database:    "db",
				Table:       "t",
				Description: "d",
				Params:      []dynamicToolParam{{Name: "id", CHType: "UInt64", JSONType: "integer", JSONFormat: "int64", Required: true}},
			},
		},
	}

	// With JWE enabled and invalid token, the token validation occurs before method check → 401
	req := httptest.NewRequest(http.MethodGet, "/token/openapi/tool", nil)
	req = req.WithContext(context.WithValue(req.Context(), CHJWEServerKey, s))
	rr := httptest.NewRecorder()
	s.OpenAPIHandler(rr, req)
	require.Equal(t, http.StatusUnauthorized, rr.Code)

	// Use disabled JWE to test JSON decode and required params
	s.Config.Server.JWE.Enabled = false

	// invalid JSON body
	req = httptest.NewRequest(http.MethodPost, "/openapi/tool", strings.NewReader("not-json"))
	req = req.WithContext(context.WithValue(req.Context(), CHJWEServerKey, s))
	rr = httptest.NewRecorder()
	s.OpenAPIHandler(rr, req)
	require.Equal(t, http.StatusBadRequest, rr.Code)

	// Unknown tool -> 404
	req = httptest.NewRequest(http.MethodPost, "/openapi/unknown_tool", strings.NewReader(`{"id":1}`))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), CHJWEServerKey, s))
	rr = httptest.NewRecorder()
	s.OpenAPIHandler(rr, req)
	require.Equal(t, http.StatusNotFound, rr.Code)
}

// TestLazyLoading_OpenAPISchema tests lazy loading of dynamic tools via OpenAPI
func TestLazyLoading_OpenAPISchema(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	chConfig := setupEmbeddedClickHouse(t)

	// Create view
	client, err := clickhouse.NewClient(ctx, *chConfig)
	require.NoError(t, err)
	defer func() { require.NoError(t, client.Close()) }()

	_, _ = client.ExecuteQuery(ctx, "DROP VIEW IF EXISTS default.v_lazy")
	_, err = client.ExecuteQuery(ctx, "CREATE VIEW default.v_lazy AS SELECT * FROM default.test WHERE id={id:UInt64}")
	require.NoError(t, err)

	// Server config
	cfg := config.Config{
		ClickHouse: *chConfig,
		Server: config.ServerConfig{
			JWE: config.JWEConfig{Enabled: false},
			DynamicTools: []config.DynamicToolRule{
				{Regexp: "default\\.v_lazy", Prefix: "lazy_"},
			},
		},
	}

	// Initialize server (dynamic tools not loaded yet)
	s := NewClickHouseMCPServer(cfg, "test")

	// Verify dynamic tools map is empty initially
	s.dynamicToolsMu.RLock()
	require.Empty(t, s.dynamicTools)
	s.dynamicToolsMu.RUnlock()

	// Call ServeOpenAPISchema
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/openapi", nil)

	s.ServeOpenAPISchema(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)

	// Verify dynamic tools map is populated
	s.dynamicToolsMu.RLock()
	require.Len(t, s.dynamicTools, 1)
	_, ok := s.dynamicTools["lazy_default_v_lazy"]
	require.True(t, ok)
	s.dynamicToolsMu.RUnlock()

	// Verify schema contains the path
	var schema map[string]interface{}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &schema))
	paths := schema["paths"].(map[string]interface{})
	_, ok = paths["/openapi/lazy_default_v_lazy"]
	require.True(t, ok)
}

// TestLazyLoading_MCPTools tests lazy loading of dynamic tools via MCP
func TestLazyLoading_MCPTools(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	chConfig := setupEmbeddedClickHouse(t)

	// Create view
	client, err := clickhouse.NewClient(ctx, *chConfig)
	require.NoError(t, err)
	defer func() { require.NoError(t, client.Close()) }()

	_, _ = client.ExecuteQuery(ctx, "DROP VIEW IF EXISTS default.v_mcp_lazy")
	_, err = client.ExecuteQuery(ctx, "CREATE VIEW default.v_mcp_lazy AS SELECT * FROM default.test WHERE id={id:UInt64}")
	require.NoError(t, err)

	// Server config
	cfg := config.Config{
		ClickHouse: *chConfig,
		Server: config.ServerConfig{
			JWE: config.JWEConfig{Enabled: false},
			DynamicTools: []config.DynamicToolRule{
				{Regexp: "default\\.v_mcp_lazy", Prefix: "mcp_"},
			},
		},
	}

	// Initialize server
	s := NewClickHouseMCPServer(cfg, "test")

	// Verify dynamic tools map is empty initially
	s.dynamicToolsMu.RLock()
	require.Empty(t, s.dynamicTools)
	s.dynamicToolsMu.RUnlock()

	// Simulate middleware calling EnsureDynamicTools
	err = s.EnsureDynamicTools(ctx)
	require.NoError(t, err)

	// Verify tool is registered in dynamic tools map
	s.dynamicToolsMu.RLock()
	require.Len(t, s.dynamicTools, 1)
	_, ok := s.dynamicTools["mcp_default_v_mcp_lazy"]
	require.True(t, ok)
	s.dynamicToolsMu.RUnlock()
}

// TestNewToolResultText tests the NewToolResultText helper
func TestNewToolResultText(t *testing.T) {
	t.Parallel()
	result := NewToolResultText("test content")
	require.NotNil(t, result)
	require.Len(t, result.Content, 1)
	require.False(t, result.IsError)

	textContent, ok := result.Content[0].(*mcp.TextContent)
	require.True(t, ok)
	require.Equal(t, "test content", textContent.Text)
}

// TestNewToolResultError tests the NewToolResultError helper
func TestNewToolResultError(t *testing.T) {
	t.Parallel()
	result := NewToolResultError("error message")
	require.NotNil(t, result)
	require.Len(t, result.Content, 1)
	require.True(t, result.IsError)

	textContent, ok := result.Content[0].(*mcp.TextContent)
	require.True(t, ok)
	require.Equal(t, "error message", textContent.Text)
}

// TestAddPrompt tests the AddPrompt method
func TestAddPrompt(t *testing.T) {
	t.Parallel()
	srv := NewClickHouseMCPServer(config.Config{
		ClickHouse: config.ClickHouseConfig{Host: "localhost", Port: 8123},
		Server:     config.ServerConfig{JWE: config.JWEConfig{Enabled: false}},
	}, "test")

	prompt := &mcp.Prompt{
		Name:        "test_prompt",
		Description: "A test prompt",
	}

	// Test that AddPrompt doesn't panic and registers the prompt
	srv.AddPrompt(prompt, func(ctx context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
		return &mcp.GetPromptResult{
			Messages: []*mcp.PromptMessage{
				{
					Role: "user",
					Content: &mcp.TextContent{
						Text: "test",
					},
				},
			},
		}, nil
	})
	// If we got here without panic, the test passes
}

func TestHandleExecuteQueryOpenAPI_MethodNotAllowed(t *testing.T) {
	t.Parallel()
	chConfig := setupEmbeddedClickHouse(t)

	srv := NewClickHouseMCPServer(config.Config{
		ClickHouse: *chConfig,
		Server:     config.ServerConfig{JWE: config.JWEConfig{Enabled: false}},
	}, "test")

	req := httptest.NewRequest(http.MethodPost, "/openapi/execute_query?query=SELECT%201", nil)
	req = req.WithContext(context.WithValue(req.Context(), CHJWEServerKey, srv))

	rr := httptest.NewRecorder()
	srv.handleExecuteQueryOpenAPI(rr, req)

	require.Equal(t, http.StatusMethodNotAllowed, rr.Code)
}

// TestHandleExecuteQueryOpenAPI_InvalidLimit tests invalid limit parameter
func TestHandleExecuteQueryOpenAPI_InvalidLimit(t *testing.T) {
	t.Parallel()
	chConfig := setupEmbeddedClickHouse(t)

	srv := NewClickHouseMCPServer(config.Config{
		ClickHouse: *chConfig,
		Server:     config.ServerConfig{JWE: config.JWEConfig{Enabled: false}},
	}, "test")

	t.Run("non_numeric_limit", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/openapi/execute_query?query=SELECT%201&limit=abc", nil)
		req = req.WithContext(context.WithValue(req.Context(), CHJWEServerKey, srv))

		rr := httptest.NewRecorder()
		srv.handleExecuteQueryOpenAPI(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("zero_limit", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/openapi/execute_query?query=SELECT%201&limit=0", nil)
		req = req.WithContext(context.WithValue(req.Context(), CHJWEServerKey, srv))

		rr := httptest.NewRecorder()
		srv.handleExecuteQueryOpenAPI(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("negative_limit", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/openapi/execute_query?query=SELECT%201&limit=-1", nil)
		req = req.WithContext(context.WithValue(req.Context(), CHJWEServerKey, srv))

		rr := httptest.NewRecorder()
		srv.handleExecuteQueryOpenAPI(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
	})
}

// TestHandleExecuteQueryOpenAPI_ExceedsMaxLimit tests limit exceeding max
func TestHandleExecuteQueryOpenAPI_ExceedsMaxLimit(t *testing.T) {
	t.Parallel()
	chConfig := setupEmbeddedClickHouse(t)

	srv := NewClickHouseMCPServer(config.Config{
		ClickHouse: config.ClickHouseConfig{
			Host:     chConfig.Host,
			Port:     chConfig.Port,
			Database: chConfig.Database,
			Username: chConfig.Username,
			Protocol: chConfig.Protocol,
			Limit:    10,
		},
		Server: config.ServerConfig{JWE: config.JWEConfig{Enabled: false}},
	}, "test")

	req := httptest.NewRequest(http.MethodGet, "/openapi/execute_query?query=SELECT%201&limit=100", nil)
	req = req.WithContext(context.WithValue(req.Context(), CHJWEServerKey, srv))

	rr := httptest.NewRecorder()
	srv.handleExecuteQueryOpenAPI(rr, req)

	require.Equal(t, http.StatusBadRequest, rr.Code)
	require.Contains(t, rr.Body.String(), "Limit cannot exceed 10")
}

// TestHandleDynamicToolOpenAPI_MethodNotAllowed tests method validation
func TestHandleDynamicToolOpenAPI_MethodNotAllowed(t *testing.T) {
	t.Parallel()
	srv := &ClickHouseJWEServer{
		Config:       config.Config{Server: config.ServerConfig{JWE: config.JWEConfig{Enabled: false}}},
		Version:      "test",
		dynamicTools: map[string]dynamicToolMeta{},
	}

	meta := dynamicToolMeta{ToolName: "tool", Database: "db", Table: "t"}

	req := httptest.NewRequest(http.MethodGet, "/openapi/tool", nil)
	rr := httptest.NewRecorder()

	srv.handleDynamicToolOpenAPI(rr, req, meta)

	require.Equal(t, http.StatusMethodNotAllowed, rr.Code)
}

// TestHandleDynamicToolOpenAPI_MissingRequiredParam tests missing required parameter
func TestHandleDynamicToolOpenAPI_MissingRequiredParam(t *testing.T) {
	t.Parallel()
	chConfig := setupEmbeddedClickHouse(t)

	srv := &ClickHouseJWEServer{
		Config: config.Config{
			ClickHouse: *chConfig,
			Server:     config.ServerConfig{JWE: config.JWEConfig{Enabled: false}},
		},
		Version:      "test",
		dynamicTools: map[string]dynamicToolMeta{},
	}

	meta := dynamicToolMeta{
		ToolName: "tool",
		Database: "default",
		Table:    "test",
		Params:   []dynamicToolParam{{Name: "required_param", JSONType: "string", Required: true}},
	}

	body := strings.NewReader(`{}`)
	req := httptest.NewRequest(http.MethodPost, "/openapi/tool", body)
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), CHJWEServerKey, srv))

	rr := httptest.NewRecorder()
	srv.handleDynamicToolOpenAPI(rr, req, meta)

	require.Equal(t, http.StatusBadRequest, rr.Code)
	require.Contains(t, rr.Body.String(), "Missing required parameter")
}

// TestServeOpenAPISchema_WithTLS tests OpenAPI schema with TLS enabled
func TestServeOpenAPISchema_WithTLS(t *testing.T) {
	t.Parallel()
	srv := &ClickHouseJWEServer{
		Config: config.Config{
			Server: config.ServerConfig{
				JWE:     config.JWEConfig{Enabled: false},
				OpenAPI: config.OpenAPIConfig{TLS: true},
			},
		},
		Version:      "test",
		dynamicTools: map[string]dynamicToolMeta{},
	}

	req := httptest.NewRequest(http.MethodGet, "/openapi", nil)
	req = req.WithContext(context.WithValue(req.Context(), CHJWEServerKey, srv))
	req.Host = "example.com"

	rr := httptest.NewRecorder()
	srv.ServeOpenAPISchema(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)

	var schema map[string]interface{}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &schema))

	servers := schema["servers"].([]interface{})
	serverInfo := servers[0].(map[string]interface{})
	require.Equal(t, "https://example.com", serverInfo["url"])
}

func TestOpenAPIHandler_MissingServerInContext(t *testing.T) {
	t.Parallel()
	srv := &ClickHouseJWEServer{
		Config:       config.Config{Server: config.ServerConfig{JWE: config.JWEConfig{Enabled: false}}},
		Version:      "test",
		dynamicTools: map[string]dynamicToolMeta{},
	}

	req := httptest.NewRequest(http.MethodGet, "/openapi", nil)
	// Intentionally NOT adding server to context

	rr := httptest.NewRecorder()
	srv.OpenAPIHandler(rr, req)

	require.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestOpenAPIHandler_InvalidJWEToken(t *testing.T) {
	t.Parallel()
	srv := &ClickHouseJWEServer{
		Config: config.Config{
			Server: config.ServerConfig{
				JWE: config.JWEConfig{
					Enabled:      true,
					JWESecretKey: "this-is-a-32-byte-secret-key!!",
					JWTSecretKey: "test-jwt-key",
				},
				OAuth: config.OAuthConfig{Enabled: false}, // Only JWE enabled
			},
		},
		Version:      "test",
		dynamicTools: map[string]dynamicToolMeta{},
	}

	req := httptest.NewRequest(http.MethodGet, "/openapi", nil)
	req.Header.Set("x-altinity-mcp-key", "invalid-token") // Use JWE-specific header
	req = req.WithContext(context.WithValue(req.Context(), CHJWEServerKey, srv))

	rr := httptest.NewRecorder()
	srv.OpenAPIHandler(rr, req)

	require.Equal(t, http.StatusUnauthorized, rr.Code)
	require.Contains(t, rr.Body.String(), "Invalid authentication token")
}

// TestHandleDynamicToolOpenAPI_QueryError tests query execution failure
func TestHandleDynamicToolOpenAPI_QueryError(t *testing.T) {
	t.Parallel()
	chConfig := setupEmbeddedClickHouse(t)

	srv := &ClickHouseJWEServer{
		Config: config.Config{
			ClickHouse: *chConfig,
			Server:     config.ServerConfig{JWE: config.JWEConfig{Enabled: false}},
		},
		Version:      "test",
		dynamicTools: map[string]dynamicToolMeta{},
	}

	meta := dynamicToolMeta{
		ToolName: "tool",
		Database: "default",
		Table:    "nonexistent_view_that_does_not_exist",
		Params:   nil,
	}

	body := strings.NewReader(`{}`)
	req := httptest.NewRequest(http.MethodPost, "/openapi/tool", body)
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), CHJWEServerKey, srv))

	rr := httptest.NewRecorder()
	srv.handleDynamicToolOpenAPI(rr, req, meta)

	require.Equal(t, http.StatusInternalServerError, rr.Code)
	require.Contains(t, rr.Body.String(), "Query execution failed")
}

// TestHandleExecuteQueryOpenAPI_QueryError tests query execution failure
func TestHandleExecuteQueryOpenAPI_QueryError(t *testing.T) {
	t.Parallel()
	chConfig := setupEmbeddedClickHouse(t)

	srv := NewClickHouseMCPServer(config.Config{
		ClickHouse: *chConfig,
		Server:     config.ServerConfig{JWE: config.JWEConfig{Enabled: false}},
	}, "test")

	req := httptest.NewRequest(http.MethodGet, "/openapi/execute_query?query=INVALID%20SYNTAX%20HERE", nil)
	req = req.WithContext(context.WithValue(req.Context(), CHJWEServerKey, srv))

	rr := httptest.NewRecorder()
	srv.handleExecuteQueryOpenAPI(rr, req)

	require.Equal(t, http.StatusInternalServerError, rr.Code)
	require.Contains(t, rr.Body.String(), "Query execution failed")
}

// TestHandleExecuteQueryOpenAPI_NonSelectWithLimit tests limit on non-select query
func TestHandleExecuteQueryOpenAPI_NonSelectWithLimit(t *testing.T) {
	t.Parallel()
	chConfig := setupEmbeddedClickHouse(t)

	srv := NewClickHouseMCPServer(config.Config{
		ClickHouse: *chConfig,
		Server:     config.ServerConfig{JWE: config.JWEConfig{Enabled: false}},
	}, "test")

	// SHOW TABLES is not a SELECT query, limit should not be appended
	req := httptest.NewRequest(http.MethodGet, "/openapi/execute_query?query=SHOW%20TABLES&limit=10", nil)
	req = req.WithContext(context.WithValue(req.Context(), CHJWEServerKey, srv))

	rr := httptest.NewRecorder()
	srv.handleExecuteQueryOpenAPI(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
}

// TestHandleDynamicToolOpenAPI_WithOptionalParams tests with optional params
func TestHandleDynamicToolOpenAPI_WithOptionalParams(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	chConfig := setupEmbeddedClickHouse(t)

	// Create a simple view
	client, err := clickhouse.NewClient(ctx, *chConfig)
	require.NoError(t, err)
	defer func() { require.NoError(t, client.Close()) }()

	_, _ = client.ExecuteQuery(ctx, "DROP VIEW IF EXISTS default.v_optional_params")
	_, err = client.ExecuteQuery(ctx, "CREATE VIEW default.v_optional_params AS SELECT * FROM default.test")
	require.NoError(t, err)

	srv := &ClickHouseJWEServer{
		Config: config.Config{
			ClickHouse: *chConfig,
			Server:     config.ServerConfig{JWE: config.JWEConfig{Enabled: false}},
		},
		Version:      "test",
		dynamicTools: map[string]dynamicToolMeta{},
	}

	meta := dynamicToolMeta{
		ToolName: "tool",
		Database: "default",
		Table:    "v_optional_params",
		Params: []dynamicToolParam{
			{Name: "optional_id", CHType: "UInt64", JSONType: "integer", Required: false},
		},
	}

	// Send request without the optional param
	body := strings.NewReader(`{}`)
	req := httptest.NewRequest(http.MethodPost, "/openapi/tool", body)
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), CHJWEServerKey, srv))

	rr := httptest.NewRecorder()
	srv.handleDynamicToolOpenAPI(rr, req, meta)

	require.Equal(t, http.StatusOK, rr.Code)
}

func TestOpenAPIHandlerE2E(t *testing.T) {
	t.Parallel()
	chConfig := setupEmbeddedClickHouse(t)

	srv := NewClickHouseMCPServer(config.Config{
		ClickHouse: *chConfig,
		Server:     config.ServerConfig{JWE: config.JWEConfig{Enabled: false}},
	}, "test")

	t.Run("no_context_server", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/openapi", nil)
		rr := httptest.NewRecorder()
		srv.OpenAPIHandler(rr, req)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
	})

	t.Run("schema_endpoint", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/openapi", nil)
		req = req.WithContext(context.WithValue(req.Context(), CHJWEServerKey, srv))
		rr := httptest.NewRecorder()
		srv.OpenAPIHandler(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("get_method_serves_schema", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/openapi", nil)
		req = req.WithContext(context.WithValue(req.Context(), CHJWEServerKey, srv))
		rr := httptest.NewRecorder()
		srv.ServeOpenAPISchema(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)
		require.Contains(t, rr.Body.String(), "execute_query")
	})
}

func TestGetClickHouseClientWithOAuthE2E(t *testing.T) {
	t.Parallel()
	chConfig := setupEmbeddedClickHouse(t)

	t.Run("default_config_no_oauth", func(t *testing.T) {
		t.Parallel()
		srv := NewClickHouseMCPServer(config.Config{
			ClickHouse: *chConfig,
			Server:     config.ServerConfig{JWE: config.JWEConfig{Enabled: false}},
		}, "test")
		client, err := srv.GetClickHouseClientWithOAuth(context.Background(), "", "", nil)
		require.NoError(t, err)
		require.NotNil(t, client)
		require.NoError(t, client.Close())
	})

	t.Run("jwe_enabled_invalid_token", func(t *testing.T) {
		t.Parallel()
		srv := &ClickHouseJWEServer{Config: config.Config{
			ClickHouse: *chConfig,
			Server:     config.ServerConfig{JWE: config.JWEConfig{Enabled: true, JWESecretKey: "secret"}},
		}}
		_, err := srv.GetClickHouseClientWithOAuth(context.Background(), "bad-token", "", nil)
		require.Error(t, err)
	})
}

func TestNewClickHouseMCPServerVersionField(t *testing.T) {
	t.Parallel()
	srv := NewClickHouseMCPServer(config.Config{
		ClickHouse: config.ClickHouseConfig{Host: "localhost", Port: 9000},
		Server:     config.ServerConfig{JWE: config.JWEConfig{Enabled: false}},
	}, "1.0.0")
	require.NotNil(t, srv)
	require.NotNil(t, srv.MCPServer)
	require.Equal(t, "1.0.0", srv.Version)
	require.NotNil(t, srv.dynamicTools)
}

func TestRegisterToolsAndResources(t *testing.T) {
	t.Parallel()
	capture := &captureServer{}
	cfg := config.Config{}
	RegisterTools(capture, &cfg)
	// Defaults register both execute_query and write_query.
	require.Len(t, capture.tools, 2)
	names := []string{capture.tools[0].Name, capture.tools[1].Name}
	require.ElementsMatch(t, []string{"execute_query", "write_query"}, names)

	// These just verify no panic
	RegisterResources(capture)
	RegisterPrompts(capture)
}

func textOf(res *mcp.CallToolResult) string {
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			return tc.Text
		}
	}
	return ""
}

func TestRegisterTools_UnifiedConfig(t *testing.T) {
	t.Parallel()

	t.Run("only_static_read_tool_registered", func(t *testing.T) {
		t.Parallel()
		srv := &captureServer{}
		cfg := config.Config{
			Server: config.ServerConfig{
				Tools: []config.ToolDefinition{
					{Type: "read", Name: "execute_query"},
				},
			},
		}
		RegisterTools(srv, &cfg)
		require.Len(t, srv.tools, 1)
		require.Equal(t, "execute_query", srv.tools[0].Name)
		// No dynamic rules survived.
		require.Empty(t, cfg.Server.DynamicTools)
	})

	t.Run("dynamic_rules_preserved_in_DynamicTools", func(t *testing.T) {
		t.Parallel()
		srv := &captureServer{}
		cfg := config.Config{
			Server: config.ServerConfig{
				Tools: []config.ToolDefinition{
					{Type: "read", Name: "execute_query"},
					{Type: "read", Regexp: `^analytics\..*_view$`, Prefix: "ro_"},
					{Type: "write", Regexp: `^events\..*$`, Prefix: "log_", Mode: "insert"},
				},
			},
		}
		RegisterTools(srv, &cfg)
		// Only execute_query is static (dynamic tools get registered lazily).
		require.Len(t, srv.tools, 1)
		// Dynamic rules were converted into DynamicTools for EnsureDynamicTools.
		require.Len(t, cfg.Server.DynamicTools, 2)
		// Ordering is preserved, so rule 0 is the read rule, rule 1 is the write rule.
		require.Equal(t, "read", cfg.Server.DynamicTools[0].Type)
		require.Equal(t, "write", cfg.Server.DynamicTools[1].Type)
		require.Equal(t, "insert", cfg.Server.DynamicTools[1].Mode)
	})

	t.Run("invalid_mode_rejected_at_registration", func(t *testing.T) {
		t.Parallel()
		srv := &captureServer{}
		cfg := config.Config{
			Server: config.ServerConfig{
				Tools: []config.ToolDefinition{
					{Type: "read", Name: "execute_query"},
					// Should survive — insert is supported.
					{Type: "write", Regexp: `^ok\..*$`, Prefix: "ok_", Mode: "insert"},
					// Should be rejected — update/upsert not implemented.
					{Type: "write", Regexp: `^bad1\..*$`, Prefix: "x_", Mode: "update"},
					{Type: "write", Regexp: `^bad2\..*$`, Prefix: "x_", Mode: "upsert"},
					// Should be rejected — mode required for write.
					{Type: "write", Regexp: `^bad3\..*$`, Prefix: "x_"},
				},
			},
		}
		RegisterTools(srv, &cfg)
		require.Len(t, cfg.Server.DynamicTools, 1)
		require.Equal(t, "insert", cfg.Server.DynamicTools[0].Mode)
	})

	t.Run("legacy_dynamic_tools_still_works_with_warning", func(t *testing.T) {
		t.Parallel()
		srv := &captureServer{}
		cfg := config.Config{
			Server: config.ServerConfig{
				// Legacy rule: no Type → defaults to "read".
				DynamicTools: []config.DynamicToolRule{
					{Regexp: `^mydb\..*$`, Prefix: "get_"},
				},
			},
		}
		RegisterTools(srv, &cfg)
		require.Len(t, cfg.Server.DynamicTools, 1)
		require.Equal(t, "read", cfg.Server.DynamicTools[0].Type)
	})

	t.Run("static_tool_with_unknown_name_ignored", func(t *testing.T) {
		t.Parallel()
		srv := &captureServer{}
		cfg := config.Config{
			Server: config.ServerConfig{
				Tools: []config.ToolDefinition{
					{Type: "read", Name: "execute_query"},
					{Type: "read", Name: "query_something_unknown"},
				},
			},
		}
		RegisterTools(srv, &cfg)
		require.Len(t, srv.tools, 1)
		require.Equal(t, "execute_query", srv.tools[0].Name)
	})
}
