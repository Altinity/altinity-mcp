package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/altinity/altinity-mcp/pkg/clickhouse"
	"github.com/altinity/altinity-mcp/pkg/config"
	"github.com/altinity/altinity-mcp/pkg/jwe_auth"
	"github.com/go-jose/go-jose/v4"
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
		defer client.Close()

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

// TestHandleExecuteQuery tests the execute_query tool handler
func TestHandleExecuteQuery(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	chConfig := setupEmbeddedClickHouse(t)

	srv := NewClickHouseMCPServer(config.Config{
		ClickHouse: *chConfig,
		Server:     config.ServerConfig{JWE: config.JWEConfig{Enabled: false}},
	}, "test")

	// Add server to context
	ctx = context.WithValue(ctx, CHJWEServerKey, srv)

	t.Run("successful_select", func(t *testing.T) {
		t.Parallel()
		req := &mcp.CallToolRequest{
			Params: &mcp.CallToolParamsRaw{
				Name:      "execute_query",
				Arguments: json.RawMessage(`{"query": "SELECT 1 as num"}`),
			},
		}

		result, err := HandleExecuteQuery(ctx, req)
		require.NoError(t, err)
		require.NotNil(t, result)
		require.False(t, result.IsError)
		require.Len(t, result.Content, 1)

		// Extract text content
		textContent, ok := result.Content[0].(*mcp.TextContent)
		require.True(t, ok)
		require.NotEmpty(t, textContent.Text)

		// Parse result
		var qr clickhouse.QueryResult
		require.NoError(t, json.Unmarshal([]byte(textContent.Text), &qr))
		require.Equal(t, 1, qr.Count)
	})

	t.Run("select_from_test_table", func(t *testing.T) {
		t.Parallel()
		req := &mcp.CallToolRequest{
			Params: &mcp.CallToolParamsRaw{
				Name:      "execute_query",
				Arguments: json.RawMessage(`{"query": "SELECT * FROM default.test ORDER BY id"}`),
			},
		}

		result, err := HandleExecuteQuery(ctx, req)
		require.NoError(t, err)
		require.NotNil(t, result)
		require.False(t, result.IsError)

		textContent, ok := result.Content[0].(*mcp.TextContent)
		require.True(t, ok)

		var qr clickhouse.QueryResult
		require.NoError(t, json.Unmarshal([]byte(textContent.Text), &qr))
		require.GreaterOrEqual(t, qr.Count, 2)
	})

	t.Run("with_limit_parameter", func(t *testing.T) {
		t.Parallel()
		req := &mcp.CallToolRequest{
			Params: &mcp.CallToolParamsRaw{
				Name:      "execute_query",
				Arguments: json.RawMessage(`{"query": "SELECT * FROM default.test", "limit": 1}`),
			},
		}

		result, err := HandleExecuteQuery(ctx, req)
		require.NoError(t, err)
		require.NotNil(t, result)
		require.False(t, result.IsError)

		textContent, ok := result.Content[0].(*mcp.TextContent)
		require.True(t, ok)

		var qr clickhouse.QueryResult
		require.NoError(t, json.Unmarshal([]byte(textContent.Text), &qr))
		require.Equal(t, 1, qr.Count)
	})

	t.Run("missing_query_parameter", func(t *testing.T) {
		t.Parallel()
		req := &mcp.CallToolRequest{
			Params: &mcp.CallToolParamsRaw{
				Name:      "execute_query",
				Arguments: json.RawMessage(`{}`),
			},
		}

		result, err := HandleExecuteQuery(ctx, req)
		require.NoError(t, err)
		require.NotNil(t, result)
		require.True(t, result.IsError)
	})

	t.Run("invalid_query", func(t *testing.T) {
		t.Parallel()
		req := &mcp.CallToolRequest{
			Params: &mcp.CallToolParamsRaw{
				Name:      "execute_query",
				Arguments: json.RawMessage(`{"query": "INVALID SQL"}`),
			},
		}

		result, err := HandleExecuteQuery(ctx, req)
		require.NoError(t, err)
		require.NotNil(t, result)
		require.True(t, result.IsError)
	})
}

// TestHandleSchemaResource tests the schema resource handler
func TestHandleSchemaResource(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	chConfig := setupEmbeddedClickHouse(t)

	srv := NewClickHouseMCPServer(config.Config{
		ClickHouse: *chConfig,
		Server:     config.ServerConfig{JWE: config.JWEConfig{Enabled: false}},
	}, "test")

	ctx = context.WithValue(ctx, CHJWEServerKey, srv)

	t.Run("returns_schema", func(t *testing.T) {
		t.Parallel()
		result, err := HandleSchemaResource(ctx, &mcp.ReadResourceRequest{Params: &mcp.ReadResourceParams{}})
		require.NoError(t, err)
		require.NotNil(t, result)
		require.Len(t, result.Contents, 1)
		require.Equal(t, "clickhouse://schema", result.Contents[0].URI)
		require.Equal(t, "application/json", result.Contents[0].MIMEType)
		require.NotEmpty(t, result.Contents[0].Text)
	})

	t.Run("no_server_in_context", func(t *testing.T) {
		t.Parallel()
		_, err := HandleSchemaResource(context.Background(), &mcp.ReadResourceRequest{Params: &mcp.ReadResourceParams{}})
		require.Error(t, err)
	})
}

// TestHandleTableResource tests the table resource handler
func TestHandleTableResource(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	chConfig := setupEmbeddedClickHouse(t)

	srv := NewClickHouseMCPServer(config.Config{
		ClickHouse: *chConfig,
		Server:     config.ServerConfig{JWE: config.JWEConfig{Enabled: false}},
	}, "test")

	ctx = context.WithValue(ctx, CHJWEServerKey, srv)

	t.Run("returns_table_structure", func(t *testing.T) {
		t.Parallel()
		req := &mcp.ReadResourceRequest{
			Params: &mcp.ReadResourceParams{URI: "clickhouse://table/default/test"},
		}

		result, err := HandleTableResource(ctx, req)
		require.NoError(t, err)
		require.NotNil(t, result)
		require.Len(t, result.Contents, 1)
		require.Equal(t, "clickhouse://table/default/test", result.Contents[0].URI)
		require.NotEmpty(t, result.Contents[0].Text)
	})

	t.Run("invalid_uri_format", func(t *testing.T) {
		t.Parallel()
		req := &mcp.ReadResourceRequest{
			Params: &mcp.ReadResourceParams{URI: "invalid://uri"},
		}

		_, err := HandleTableResource(ctx, req)
		require.Error(t, err)
	})

	t.Run("no_server_in_context", func(t *testing.T) {
		t.Parallel()
		req := &mcp.ReadResourceRequest{
			Params: &mcp.ReadResourceParams{URI: "clickhouse://table/default/test"},
		}

		_, err := HandleTableResource(context.Background(), req)
		require.Error(t, err)
	})
}

// TestJWEAuthentication tests JWE authentication flow
func TestJWEAuthentication(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	chConfig := setupEmbeddedClickHouse(t)

	jweSecretKey := "this-is-a-32-byte-secret-key!!"
	jwtSecretKey := "test-jwt-secret-key-123"

	t.Run("valid_jwe_token", func(t *testing.T) {
		t.Parallel()
		claims := map[string]interface{}{
			"host":     chConfig.Host,
			"port":     float64(chConfig.Port),
			"database": chConfig.Database,
			"username": chConfig.Username,
			"password": chConfig.Password,
			"protocol": string(chConfig.Protocol),
			"exp":      time.Now().Add(time.Hour).Unix(),
		}

		token := generateJWEToken(t, claims, []byte(jweSecretKey), []byte(jwtSecretKey))

		srv := NewClickHouseMCPServer(config.Config{
			ClickHouse: *chConfig,
			Server: config.ServerConfig{
				JWE: config.JWEConfig{
					Enabled:      true,
					JWESecretKey: jweSecretKey,
					JWTSecretKey: jwtSecretKey,
				},
			},
		}, "test")

		ctx = context.WithValue(ctx, CHJWEServerKey, srv)
		ctx = context.WithValue(ctx, JWETokenKey, token)

		client, err := srv.GetClickHouseClient(ctx, token)
		require.NoError(t, err)
		require.NotNil(t, client)
		require.NoError(t, client.Close())
	})

	t.Run("missing_token_when_jwe_enabled", func(t *testing.T) {
		t.Parallel()
		srv := NewClickHouseMCPServer(config.Config{
			ClickHouse: *chConfig,
			Server: config.ServerConfig{
				JWE: config.JWEConfig{
					Enabled:      true,
					JWESecretKey: jweSecretKey,
					JWTSecretKey: jwtSecretKey,
				},
			},
		}, "test")

		_, err := srv.GetClickHouseClient(ctx, "")
		require.Error(t, err)
		require.ErrorIs(t, err, jwe_auth.ErrMissingToken)
	})

	t.Run("invalid_token", func(t *testing.T) {
		t.Parallel()
		srv := NewClickHouseMCPServer(config.Config{
			ClickHouse: *chConfig,
			Server: config.ServerConfig{
				JWE: config.JWEConfig{
					Enabled:      true,
					JWESecretKey: jweSecretKey,
					JWTSecretKey: jwtSecretKey,
				},
			},
		}, "test")

		_, err := srv.GetClickHouseClient(ctx, "invalid-token")
		require.Error(t, err)
	})
}

// TestExtractTokenFromRequest tests token extraction from HTTP requests
func TestExtractTokenFromRequest(t *testing.T) {
	t.Parallel()
	srv := &ClickHouseJWEServer{}

	t.Run("bearer_token", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer test-token")

		token := srv.ExtractTokenFromRequest(req)
		require.Equal(t, "test-token", token)
	})

	t.Run("basic_token", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Basic test-token")

		token := srv.ExtractTokenFromRequest(req)
		require.Equal(t, "test-token", token)
	})

	t.Run("x_altinity_mcp_key_header", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("x-altinity-mcp-key", "header-token")

		token := srv.ExtractTokenFromRequest(req)
		require.Equal(t, "header-token", token)
	})

	t.Run("from_url_path", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/my-token/openapi", nil)

		token := srv.ExtractTokenFromRequest(req)
		require.Equal(t, "my-token", token)
	})

	t.Run("no_token", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/", nil)

		token := srv.ExtractTokenFromRequest(req)
		require.Empty(t, token)
	})
}

// TestExtractTokenFromCtx tests token extraction from context
func TestExtractTokenFromCtx(t *testing.T) {
	t.Parallel()
	srv := &ClickHouseJWEServer{}

	t.Run("with_token", func(t *testing.T) {
		t.Parallel()
		ctx := context.WithValue(context.Background(), JWETokenKey, "test-token")
		token := srv.ExtractTokenFromCtx(ctx)
		require.Equal(t, "test-token", token)
	})

	t.Run("no_token", func(t *testing.T) {
		t.Parallel()
		token := srv.ExtractTokenFromCtx(context.Background())
		require.Empty(t, token)
	})

	t.Run("wrong_type", func(t *testing.T) {
		t.Parallel()
		ctx := context.WithValue(context.Background(), JWETokenKey, 123)
		token := srv.ExtractTokenFromCtx(ctx)
		require.Empty(t, token)
	})
}

// TestHelperFunctions tests various helper functions
func TestHelperFunctions(t *testing.T) {
	t.Parallel()
	t.Run("isSelectQuery", func(t *testing.T) {
		t.Parallel()
		require.True(t, isSelectQuery("SELECT * FROM table"))
		require.True(t, isSelectQuery("select * from table"))
		require.True(t, isSelectQuery("WITH cte AS (SELECT 1) SELECT * FROM cte"))
		require.False(t, isSelectQuery("INSERT INTO table VALUES (1)"))
		require.False(t, isSelectQuery("CREATE TABLE test (id Int)"))
	})

	t.Run("hasLimitClause", func(t *testing.T) {
		t.Parallel()
		require.True(t, hasLimitClause("SELECT * FROM table LIMIT 100"))
		require.True(t, hasLimitClause("select * from table limit 50"))
		require.False(t, hasLimitClause("SELECT * FROM table"))
		require.False(t, hasLimitClause("SELECT * FROM table ORDER BY id"))
	})

	t.Run("snakeCase", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, "db_view", snakeCase("DB.View"))
		require.Equal(t, "custom_db_view", snakeCase("custom DB-View"))
		require.Equal(t, "a_b_c", snakeCase("A B  C"))
	})

	t.Run("sqlLiteral", func(t *testing.T) {
		t.Parallel()
		// integer
		require.Equal(t, "42", sqlLiteral("integer", float64(42)))
		require.Equal(t, "0", sqlLiteral("integer", "oops"))
		// number
		require.Equal(t, "3.14", sqlLiteral("number", float64(3.14)))
		// boolean
		require.Equal(t, "1", sqlLiteral("boolean", true))
		require.Equal(t, "0", sqlLiteral("boolean", false))
		// string: spaces preserved, quotes escaped
		require.Equal(t, "'hello world'", sqlLiteral("string", "hello world"))
		require.Equal(t, `'O\'Brien'`, sqlLiteral("string", "O'Brien"))
		require.Equal(t, `'a\\b'`, sqlLiteral("string", `a\b`))
		require.Equal(t, `'plain'`, sqlLiteral("string", "plain"))
		// string: injection attempts produce escaped literals, not SQL syntax
		require.Equal(t, `'\') OR 1=1 --'`, sqlLiteral("string", "') OR 1=1 --"))
	})

	t.Run("buildDescription", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, "My desc", buildDescription("My desc", "db", "view"))
		require.Equal(t, "Read-only tool to query data from db.view", buildDescription("", "db", "view"))
	})

	t.Run("buildTitle", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, "Github Search", buildTitle("github_search", ""))
		require.Equal(t, "Explicit Title", buildTitle("github_search", " Explicit Title "))
	})
}

func TestDynamicToolCommentMetadata(t *testing.T) {
	t.Parallel()
	t.Run("valid_json_comment", func(t *testing.T) {
		t.Parallel()
		comment := `{"title":"GitHub Search","description":"Returns matching issues.","annotations":{"openWorldHint":true}}`

		meta := buildDynamicToolMeta("github_search", "mcp", "search", comment, nil)

		require.Equal(t, "GitHub Search", meta.Title)
		require.Equal(t, "Returns matching issues.", meta.Description)
		require.NotNil(t, meta.Annotations)
		require.True(t, meta.Annotations.ReadOnlyHint)
		require.NotNil(t, meta.Annotations.DestructiveHint)
		require.False(t, *meta.Annotations.DestructiveHint)
		require.NotNil(t, meta.Annotations.OpenWorldHint)
		require.True(t, *meta.Annotations.OpenWorldHint)
	})

	t.Run("invalid_json_falls_back_to_plain_description", func(t *testing.T) {
		t.Parallel()
		comment := `{"title":"GitHub Search"`

		meta := buildDynamicToolMeta("github_search", "mcp", "search", comment, nil)

		require.Equal(t, "Github Search", meta.Title)
		require.Equal(t, comment, meta.Description)
		require.True(t, meta.Annotations.ReadOnlyHint)
	})

	t.Run("empty_comment_uses_defaults", func(t *testing.T) {
		t.Parallel()
		meta := buildDynamicToolMeta("github_search", "mcp", "search", "", nil)

		require.Equal(t, "Github Search", meta.Title)
		require.Equal(t, "Read-only tool to query data from mcp.search", meta.Description)
		require.True(t, meta.Annotations.ReadOnlyHint)
		require.NotNil(t, meta.Annotations.DestructiveHint)
		require.False(t, *meta.Annotations.DestructiveHint)
		require.NotNil(t, meta.Annotations.OpenWorldHint)
		require.False(t, *meta.Annotations.OpenWorldHint)
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

// TestDynamicTools_ParamParsingAndTypeMapping tests dynamic tool parameter parsing
func TestDynamicTools_ParamParsingAndTypeMapping(t *testing.T) {
	t.Parallel()
	// simple create view text containing params
	create := "CREATE VIEW v AS SELECT * FROM t WHERE id={id:UInt64} AND name={name:String} AND at>={at:DateTime} AND f={f:Float64} AND ok={ok:Bool}"
	params := parseViewParams(create)
	require.Len(t, params, 5)

	// find by name
	byName := func(n string) dynamicToolParam {
		for _, p := range params {
			if p.Name == n {
				return p
			}
		}
		return dynamicToolParam{}
	}

	require.Equal(t, "integer", byName("id").JSONType)
	require.Equal(t, "string", byName("name").JSONType)
	require.Equal(t, "date-time", byName("at").JSONFormat)
	require.Equal(t, "number", byName("f").JSONType)
	require.Equal(t, "boolean", byName("ok").JSONType)
}

// TestOpenAPI_DynamicPathsIncluded tests that dynamic tool paths are included in OpenAPI schema
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

// TestResourceHandlers_NoServerInContext tests error handling when server is missing from context
func TestResourceHandlers_NoServerInContext(t *testing.T) {
	t.Parallel()
	// Directly call handlers with empty context to cover error paths
	_, err := HandleSchemaResource(context.Background(), &mcp.ReadResourceRequest{Params: &mcp.ReadResourceParams{}})
	require.Error(t, err)

	req := &mcp.ReadResourceRequest{
		Params: &mcp.ReadResourceParams{URI: "clickhouse://table/db/t"},
	}
	_, err = HandleTableResource(context.Background(), req)
	require.Error(t, err)
}

// TestMakeDynamicToolHandler_NoServerInContext tests dynamic tool handler without server in context
func TestMakeDynamicToolHandler_NoServerInContext(t *testing.T) {
	t.Parallel()
	meta := dynamicToolMeta{ToolName: "t", Database: "d", Table: "v", Params: nil}
	handler := makeDynamicToolHandler(meta)

	req := &mcp.CallToolRequest{
		Params: &mcp.CallToolParamsRaw{Name: "t"},
	}
	res, err := handler(context.Background(), req)
	require.Error(t, err)
	require.Nil(t, res)
}

// TestGetClickHouseJWEServerFromContext tests context extraction
func TestGetClickHouseJWEServerFromContext(t *testing.T) {
	t.Parallel()
	t.Run("no_server", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		srv := GetClickHouseJWEServerFromContext(ctx)
		require.Nil(t, srv)
	})

	t.Run("with_server", func(t *testing.T) {
		t.Parallel()
		expectedServer := &ClickHouseJWEServer{}
		ctx := context.WithValue(context.Background(), CHJWEServerKey, expectedServer)
		srv := GetClickHouseJWEServerFromContext(ctx)
		require.Equal(t, expectedServer, srv)
	})

	t.Run("wrong_type", func(t *testing.T) {
		t.Parallel()
		ctx := context.WithValue(context.Background(), CHJWEServerKey, "not-a-server")
		srv := GetClickHouseJWEServerFromContext(ctx)
		require.Nil(t, srv)
	})
}

// TestBuildConfigFromClaims tests building ClickHouse config from JWE claims
func TestBuildConfigFromClaims(t *testing.T) {
	t.Parallel()
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
		t.Parallel()
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
		t.Parallel()
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
		t.Parallel()
		claims := map[string]interface{}{}

		cfg, err := srv.buildConfigFromClaims(claims)
		require.NoError(t, err)
		// Should use default values
		require.Equal(t, "default-host", cfg.Host)
		require.Equal(t, 8123, cfg.Port)
		require.Equal(t, "default", cfg.Database)
	})

	t.Run("invalid_types", func(t *testing.T) {
		t.Parallel()
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

// TestMakeDynamicToolHandler_WithClickHouse tests dynamic tool handler with actual ClickHouse
func TestMakeDynamicToolHandler_WithClickHouse(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	chConfig := setupEmbeddedClickHouse(t)

	// prepare parameterized view
	client, err := clickhouse.NewClient(ctx, *chConfig)
	require.NoError(t, err)
	defer func() { require.NoError(t, client.Close()) }()

	_, _ = client.ExecuteQuery(ctx, "DROP VIEW IF EXISTS default.v_dyn")
	_, err = client.ExecuteQuery(ctx, "CREATE VIEW default.v_dyn AS SELECT * FROM default.test WHERE id={id:UInt64}")
	require.NoError(t, err)

	// server with JWE disabled
	s := &ClickHouseJWEServer{
		Config: config.Config{
			ClickHouse: *chConfig,
			Server:     config.ServerConfig{JWE: config.JWEConfig{Enabled: false}},
		},
	}

	meta := dynamicToolMeta{
		ToolName:    "default_v_dyn",
		Database:    "default",
		Table:       "v_dyn",
		Description: "desc",
		Params:      []dynamicToolParam{{Name: "id", CHType: "UInt64", JSONType: "integer", JSONFormat: "int64", Required: true}},
	}

	handler := makeDynamicToolHandler(meta)

	req := &mcp.CallToolRequest{
		Params: &mcp.CallToolParamsRaw{
			Name:      meta.ToolName,
			Arguments: json.RawMessage(`{"id": 1}`),
		},
	}

	// context with server
	ctx = context.WithValue(ctx, CHJWEServerKey, s)
	result, err := handler(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.False(t, result.IsError)

	text := ""
	if len(result.Content) > 0 {
		if tc, ok := result.Content[0].(*mcp.TextContent); ok {
			text = tc.Text
		}
	}
	require.NotEmpty(t, text)

	var qr clickhouse.QueryResult
	require.NoError(t, json.Unmarshal([]byte(text), &qr))
	require.GreaterOrEqual(t, qr.Count, 1)
}

// TestRegisterDynamicTools_SuccessAndOverlap tests dynamic tools registration with overlapping rules
func TestRegisterDynamicTools_SuccessAndOverlap(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	chConfig := setupEmbeddedClickHouse(t)
	client, err := clickhouse.NewClient(ctx, *chConfig)
	require.NoError(t, err)
	defer func() { require.NoError(t, client.Close()) }()

	// Ensure base table exists (created in setup), create views
	_, _ = client.ExecuteQuery(ctx, "DROP VIEW IF EXISTS default.v_a")
	_, _ = client.ExecuteQuery(ctx, "DROP VIEW IF EXISTS default.v_b")
	// v_a has comment and will overlap two rules
	_, err = client.ExecuteQuery(ctx, "CREATE VIEW default.v_a AS SELECT * FROM default.test WHERE id={id:UInt64} COMMENT 'desc a'")
	require.NoError(t, err)
	_, err = client.ExecuteQuery(ctx, "CREATE VIEW default.v_b AS SELECT * FROM default.test WHERE id={id:UInt64}")
	require.NoError(t, err)

	// initialize server
	s := NewClickHouseMCPServer(config.Config{
		ClickHouse: *chConfig,
		Server: config.ServerConfig{
			JWE: config.JWEConfig{Enabled: false},
			DynamicTools: []config.DynamicToolRule{
				{Regexp: "default\\.v_.*", Prefix: "custom_"},
				{Regexp: "default\\.v_a", Prefix: "other_"},
			},
		},
	}, "test")

	err = s.EnsureDynamicTools(ctx)
	require.NoError(t, err)

	// v_a matches two rules -> should be skipped
	_, existsA1 := s.dynamicTools["custom_default_v_a"]
	_, existsA2 := s.dynamicTools["other_default_v_a"]
	require.False(t, existsA1)
	require.False(t, existsA2)

	// v_b matches only first rule -> should be registered
	metaB, existsB := s.dynamicTools["custom_default_v_b"]
	require.True(t, existsB)
	require.Equal(t, "default", metaB.Database)
	require.Equal(t, "v_b", metaB.Table)
	require.NotEmpty(t, metaB.Params)
}

// TestHandleDynamicToolOpenAPI_PostExecutes tests dynamic tool execution via OpenAPI
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

// TestGetArgumentsMap_ErrorPath tests error handling in getArgumentsMap
func TestGetArgumentsMap_ErrorPath(t *testing.T) {
	t.Parallel()
	t.Run("nil_arguments", func(t *testing.T) {
		t.Parallel()
		req := &mcp.CallToolRequest{
			Params: &mcp.CallToolParamsRaw{
				Name:      "test",
				Arguments: nil,
			},
		}
		args, err := getArgumentsMap(req)
		require.NoError(t, err)
		require.NotNil(t, args)
		require.Empty(t, args)
	})

	t.Run("invalid_json_returns_error", func(t *testing.T) {
		t.Parallel()
		req := &mcp.CallToolRequest{
			Params: &mcp.CallToolParamsRaw{
				Name:      "test",
				Arguments: json.RawMessage(`invalid json`),
			},
		}
		args, err := getArgumentsMap(req)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to parse tool arguments")
		require.Nil(t, args)
	})

	t.Run("valid_json_object", func(t *testing.T) {
		t.Parallel()
		req := &mcp.CallToolRequest{
			Params: &mcp.CallToolParamsRaw{
				Name:      "test",
				Arguments: json.RawMessage(`{"foo": "bar", "n": 42}`),
			},
		}
		args, err := getArgumentsMap(req)
		require.NoError(t, err)
		require.Equal(t, "bar", args["foo"])
		require.Equal(t, float64(42), args["n"])
	})

	t.Run("json_null_is_empty_map", func(t *testing.T) {
		t.Parallel()
		req := &mcp.CallToolRequest{
			Params: &mcp.CallToolParamsRaw{
				Name:      "test",
				Arguments: json.RawMessage(`null`),
			},
		}
		args, err := getArgumentsMap(req)
		require.NoError(t, err)
		require.NotNil(t, args)
		require.Empty(t, args)
	})
}

// TestMapCHType_AllTypes tests all type mappings
func TestMapCHType_AllTypes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		chType     string
		wantType   string
		wantFormat string
	}{
		{"UInt64", "integer", "int64"},
		{"UInt32", "integer", "int64"},
		{"Int64", "integer", "int64"},
		{"Int32", "integer", "int64"},
		{"Float64", "number", "double"},
		{"Float32", "number", "double"},
		{"Decimal(10,2)", "number", "double"},
		{"Bool", "boolean", ""},
		{"Date", "string", "date"},
		{"Date32", "string", "date"},
		{"DateTime", "string", "date-time"},
		{"DateTime64", "string", "date-time"},
		{"UUID", "string", "uuid"},
		{"String", "string", ""},
		{"FixedString(10)", "string", ""},
		{"Array(String)", "string", ""},
	}

	for _, tt := range tests {
		t.Run(tt.chType, func(t *testing.T) {
			t.Parallel()
			jsonType, jsonFormat := mapCHType(tt.chType)
			require.Equal(t, tt.wantType, jsonType)
			require.Equal(t, tt.wantFormat, jsonFormat)
		})
	}
}

// TestSqlLiteral_AllTypes tests all SQL literal conversions
func TestSqlLiteral_AllTypes(t *testing.T) {
	t.Parallel()
	t.Run("integer_int64", func(t *testing.T) {
		t.Parallel()
		result := sqlLiteral("integer", int64(42))
		require.Equal(t, "42", result)
	})

	t.Run("integer_int", func(t *testing.T) {
		t.Parallel()
		result := sqlLiteral("integer", int(42))
		require.Equal(t, "42", result)
	})

	t.Run("number_default", func(t *testing.T) {
		t.Parallel()
		result := sqlLiteral("number", "not a number")
		require.Equal(t, "0", result)
	})

	t.Run("boolean_not_bool", func(t *testing.T) {
		t.Parallel()
		result := sqlLiteral("boolean", "not a bool")
		require.Equal(t, "0", result)
	})

	t.Run("string_non_string", func(t *testing.T) {
		t.Parallel()
		result := sqlLiteral("string", 123)
		require.Contains(t, result, "123")
	})
}

// TestHandleExecuteQueryOpenAPI_MethodNotAllowed tests method validation
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

// TestValidateJWEToken_InvalidToken tests token validation with invalid token
func TestValidateJWEToken_InvalidToken(t *testing.T) {
	t.Parallel()
	srv := &ClickHouseJWEServer{
		Config: config.Config{
			Server: config.ServerConfig{
				JWE: config.JWEConfig{
					Enabled:      true,
					JWESecretKey: "this-is-a-32-byte-secret-key!!",
					JWTSecretKey: "test-jwt-key",
				},
			},
		},
	}

	err := srv.ValidateJWEToken("invalid-token")
	require.Error(t, err)
}

// TestOpenAPIHandler_MissingServerInContext tests error when server missing from context
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

// TestHandleExecuteQuery_NoServerInContext tests error when server missing
func TestHandleExecuteQuery_NoServerInContext(t *testing.T) {
	t.Parallel()
	req := &mcp.CallToolRequest{
		Params: &mcp.CallToolParamsRaw{
			Name:      "execute_query",
			Arguments: json.RawMessage(`{"query": "SELECT 1"}`),
		},
	}

	result, err := HandleExecuteQuery(context.Background(), req)
	require.Error(t, err)
	require.Nil(t, result)
}

// TestHandleExecuteQuery_EmptyQuery tests empty query parameter
func TestHandleExecuteQuery_EmptyQuery(t *testing.T) {
	t.Parallel()
	srv := &ClickHouseJWEServer{
		Config:       config.Config{Server: config.ServerConfig{JWE: config.JWEConfig{Enabled: false}}},
		dynamicTools: map[string]dynamicToolMeta{},
	}

	ctx := context.WithValue(context.Background(), CHJWEServerKey, srv)

	req := &mcp.CallToolRequest{
		Params: &mcp.CallToolParamsRaw{
			Name:      "execute_query",
			Arguments: json.RawMessage(`{"query": ""}`),
		},
	}

	result, err := HandleExecuteQuery(ctx, req)
	require.NoError(t, err)
	require.True(t, result.IsError)
}

// TestHandleExecuteQuery_ExceedsMaxLimit tests limit exceeding config max
func TestHandleExecuteQuery_ExceedsMaxLimit(t *testing.T) {
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

	ctx := context.WithValue(context.Background(), CHJWEServerKey, srv)

	req := &mcp.CallToolRequest{
		Params: &mcp.CallToolParamsRaw{
			Name:      "execute_query",
			Arguments: json.RawMessage(`{"query": "SELECT * FROM default.test", "limit": 100}`),
		},
	}

	result, err := HandleExecuteQuery(ctx, req)
	require.NoError(t, err)
	require.True(t, result.IsError)
	textContent, ok := result.Content[0].(*mcp.TextContent)
	require.True(t, ok)
	require.Contains(t, textContent.Text, "Limit cannot exceed 10")
}

// TestHandleExecuteQuery_WithQueryWithExistingLimit tests query already having limit
func TestHandleExecuteQuery_WithQueryWithExistingLimit(t *testing.T) {
	t.Parallel()
	chConfig := setupEmbeddedClickHouse(t)

	srv := NewClickHouseMCPServer(config.Config{
		ClickHouse: *chConfig,
		Server:     config.ServerConfig{JWE: config.JWEConfig{Enabled: false}},
	}, "test")

	ctx := context.WithValue(context.Background(), CHJWEServerKey, srv)

	req := &mcp.CallToolRequest{
		Params: &mcp.CallToolParamsRaw{
			Name:      "execute_query",
			Arguments: json.RawMessage(`{"query": "SELECT * FROM default.test LIMIT 5", "limit": 10}`),
		},
	}

	result, err := HandleExecuteQuery(ctx, req)
	require.NoError(t, err)
	require.False(t, result.IsError)
}

// TestEnsureDynamicTools_NoRules tests when no dynamic tool rules configured
func TestEnsureDynamicTools_NoRules(t *testing.T) {
	t.Parallel()
	srv := &ClickHouseJWEServer{
		Config: config.Config{
			Server: config.ServerConfig{
				JWE:          config.JWEConfig{Enabled: false},
				DynamicTools: nil,
			},
		},
		dynamicTools: make(map[string]dynamicToolMeta),
	}

	err := srv.EnsureDynamicTools(context.Background())
	require.NoError(t, err)
	require.True(t, srv.dynamicToolsInit)
}

// TestEnsureDynamicTools_InvalidRegexp tests invalid regexp in rules
func TestEnsureDynamicTools_InvalidRegexp(t *testing.T) {
	t.Parallel()
	chConfig := setupEmbeddedClickHouse(t)

	srv := NewClickHouseMCPServer(config.Config{
		ClickHouse: *chConfig,
		Server: config.ServerConfig{
			JWE: config.JWEConfig{Enabled: false},
			DynamicTools: []config.DynamicToolRule{
				{Regexp: "[invalid", Prefix: "test_"},
			},
		},
	}, "test")

	ctx := context.Background()
	err := srv.EnsureDynamicTools(ctx)
	require.NoError(t, err) // Should not error, just skip invalid regexp
}

// TestEnsureDynamicTools_NamedRuleNoMatch tests named rule that matches no views
func TestEnsureDynamicTools_NamedRuleNoMatch(t *testing.T) {
	t.Parallel()
	chConfig := setupEmbeddedClickHouse(t)

	srv := NewClickHouseMCPServer(config.Config{
		ClickHouse: *chConfig,
		Server: config.ServerConfig{
			JWE: config.JWEConfig{Enabled: false},
			DynamicTools: []config.DynamicToolRule{
				{Regexp: "nonexistent\\.view", Prefix: "test_", Name: "my_tool"},
			},
		},
	}, "test")

	ctx := context.Background()
	err := srv.EnsureDynamicTools(ctx)
	require.NoError(t, err)
	// Named rule that matched nothing - should log error but not fail
}

// TestEnsureDynamicTools_NamedRuleMultipleMatches tests named rule matching multiple views
func TestEnsureDynamicTools_NamedRuleMultipleMatches(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	chConfig := setupEmbeddedClickHouse(t)

	client, err := clickhouse.NewClient(ctx, *chConfig)
	require.NoError(t, err)
	defer func() { require.NoError(t, client.Close()) }()

	// Create two views that will match the same named rule
	_, _ = client.ExecuteQuery(ctx, "DROP VIEW IF EXISTS default.v_named1")
	_, _ = client.ExecuteQuery(ctx, "DROP VIEW IF EXISTS default.v_named2")
	_, err = client.ExecuteQuery(ctx, "CREATE VIEW default.v_named1 AS SELECT * FROM default.test")
	require.NoError(t, err)
	_, err = client.ExecuteQuery(ctx, "CREATE VIEW default.v_named2 AS SELECT * FROM default.test")
	require.NoError(t, err)

	srv := NewClickHouseMCPServer(config.Config{
		ClickHouse: *chConfig,
		Server: config.ServerConfig{
			JWE: config.JWEConfig{Enabled: false},
			DynamicTools: []config.DynamicToolRule{
				{Regexp: "default\\.v_named.*", Prefix: "test_", Name: "single_tool"},
			},
		},
	}, "test")

	err = srv.EnsureDynamicTools(ctx)
	require.NoError(t, err)
	// Named rule that matched multiple views - should log error
}

// TestMakeDynamicToolHandler_QueryError tests handler when query fails
func TestMakeDynamicToolHandler_QueryError(t *testing.T) {
	t.Parallel()
	chConfig := setupEmbeddedClickHouse(t)

	srv := &ClickHouseJWEServer{
		Config: config.Config{
			ClickHouse: *chConfig,
			Server:     config.ServerConfig{JWE: config.JWEConfig{Enabled: false}},
		},
	}

	// Create handler for non-existent view
	meta := dynamicToolMeta{
		ToolName:    "nonexistent",
		Database:    "default",
		Table:       "nonexistent_view",
		Description: "desc",
		Params:      nil,
	}

	handler := makeDynamicToolHandler(meta)

	req := &mcp.CallToolRequest{
		Params: &mcp.CallToolParamsRaw{
			Name:      meta.ToolName,
			Arguments: json.RawMessage(`{}`),
		},
	}

	ctx := context.WithValue(context.Background(), CHJWEServerKey, srv)
	result, err := handler(ctx, req)
	require.NoError(t, err)
	require.True(t, result.IsError)
}

// TestHandleTableResource_EmptyDatabaseOrTable tests invalid URI with empty parts
func TestHandleTableResource_EmptyDatabaseOrTable(t *testing.T) {
	t.Parallel()
	srv := &ClickHouseJWEServer{
		Config:       config.Config{Server: config.ServerConfig{JWE: config.JWEConfig{Enabled: false}}},
		dynamicTools: map[string]dynamicToolMeta{},
	}

	ctx := context.WithValue(context.Background(), CHJWEServerKey, srv)

	t.Run("empty_database", func(t *testing.T) {
		t.Parallel()
		req := &mcp.ReadResourceRequest{
			Params: &mcp.ReadResourceParams{URI: "clickhouse://table//test"},
		}
		_, err := HandleTableResource(ctx, req)
		require.Error(t, err)
	})

	t.Run("empty_table", func(t *testing.T) {
		t.Parallel()
		req := &mcp.ReadResourceRequest{
			Params: &mcp.ReadResourceParams{URI: "clickhouse://table/default/"},
		}
		_, err := HandleTableResource(ctx, req)
		require.Error(t, err)
	})
}

// TestParseViewParams_NoMatches tests parsing view with no params
func TestParseViewParams_NoMatches(t *testing.T) {
	t.Parallel()
	create := "CREATE VIEW v AS SELECT * FROM t"
	params := parseViewParams(create)
	require.Empty(t, params)
}

// TestParseViewParams_PartialMatch tests parsing with incomplete match
func TestParseViewParams_PartialMatch(t *testing.T) {
	t.Parallel()
	// This has only 2 elements in match, needs 3
	create := "CREATE VIEW v AS SELECT * FROM t WHERE id={invalid"
	params := parseViewParams(create)
	require.Empty(t, params)
}

// TestOpenAPIHandler_InvalidJWEToken tests invalid JWE token response
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

// TestMakeDynamicToolHandler_GetClientError tests handler when GetClickHouseClient fails
func TestMakeDynamicToolHandler_GetClientError(t *testing.T) {
	t.Parallel()
	srv := &ClickHouseJWEServer{
		Config: config.Config{
			ClickHouse: config.ClickHouseConfig{
				Host: "nonexistent-host",
				Port: 9999,
			},
			Server: config.ServerConfig{JWE: config.JWEConfig{Enabled: false}},
		},
	}

	meta := dynamicToolMeta{
		ToolName:    "tool",
		Database:    "default",
		Table:       "test",
		Description: "desc",
		Params:      nil,
	}

	handler := makeDynamicToolHandler(meta)

	req := &mcp.CallToolRequest{
		Params: &mcp.CallToolParamsRaw{
			Name:      meta.ToolName,
			Arguments: json.RawMessage(`{}`),
		},
	}

	ctx := context.WithValue(context.Background(), CHJWEServerKey, srv)
	result, err := handler(ctx, req)
	require.NoError(t, err)
	require.True(t, result.IsError)
	textContent, ok := result.Content[0].(*mcp.TextContent)
	require.True(t, ok)
	require.Contains(t, textContent.Text, "Failed to get ClickHouse client")
}

// TestMakeDynamicToolHandler_WithParams tests handler with various param types
func TestMakeDynamicToolHandler_WithParams(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	chConfig := setupEmbeddedClickHouse(t)

	// Create a view with multiple param types
	client, err := clickhouse.NewClient(ctx, *chConfig)
	require.NoError(t, err)
	defer func() { require.NoError(t, client.Close()) }()

	_, _ = client.ExecuteQuery(ctx, "DROP VIEW IF EXISTS default.v_multi_param")
	_, err = client.ExecuteQuery(ctx, "CREATE VIEW default.v_multi_param AS SELECT * FROM default.test WHERE id >= {min_id:UInt64}")
	require.NoError(t, err)

	srv := &ClickHouseJWEServer{
		Config: config.Config{
			ClickHouse: *chConfig,
			Server:     config.ServerConfig{JWE: config.JWEConfig{Enabled: false}},
		},
	}

	meta := dynamicToolMeta{
		ToolName:    "multi_param",
		Database:    "default",
		Table:       "v_multi_param",
		Description: "desc",
		Params: []dynamicToolParam{
			{Name: "min_id", CHType: "UInt64", JSONType: "integer", Required: false},
		},
	}

	handler := makeDynamicToolHandler(meta)

	// Test with param provided
	req := &mcp.CallToolRequest{
		Params: &mcp.CallToolParamsRaw{
			Name:      meta.ToolName,
			Arguments: json.RawMessage(`{"min_id": 1}`),
		},
	}

	ctx = context.WithValue(ctx, CHJWEServerKey, srv)
	result, err := handler(ctx, req)
	require.NoError(t, err)
	require.False(t, result.IsError)
}

func TestMergeExtraSettings(t *testing.T) {
	t.Parallel()
	base := config.ClickHouseConfig{
		ExtraSettings: map[string]string{"custom_existing": "old"},
	}
	extra := map[string]string{"custom_tenant_id": "tenant_a", "custom_existing": "new"}

	result := mergeExtraSettings(base, extra)

	require.Equal(t, "tenant_a", result.ExtraSettings["custom_tenant_id"])
	require.Equal(t, "new", result.ExtraSettings["custom_existing"])
	require.Equal(t, "old", base.ExtraSettings["custom_existing"], "base must not be mutated")
}

func TestMergeExtraSettings_NilBase(t *testing.T) {
	t.Parallel()
	base := config.ClickHouseConfig{}
	extra := map[string]string{"custom_tenant_id": "tenant_a"}

	result := mergeExtraSettings(base, extra)

	require.Equal(t, "tenant_a", result.ExtraSettings["custom_tenant_id"])
	require.Len(t, result.ExtraSettings, 1)
}

// Unused import suppressors (remove if unused)
var _ = io.EOF
var _ = fmt.Sprintf

// generateOAuthToken creates a mock OAuth JWT token for testing
func generateOAuthToken(t *testing.T, claims map[string]interface{}) string {
	// Create a simple JWT token (header.payload.signature)
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))

	payload, err := json.Marshal(claims)
	require.NoError(t, err)
	payloadEncoded := base64.RawURLEncoding.EncodeToString(payload)

	// For testing, we use a dummy signature
	signature := base64.RawURLEncoding.EncodeToString([]byte("test-signature"))

	return header + "." + payloadEncoded + "." + signature
}

// mintSelfIssuedToken creates a properly signed HS256 JWT using the gating secret
func mintSelfIssuedToken(t *testing.T, gatingSecret string, claims map[string]interface{}) string {
	t.Helper()
	hashedSecret := jwe_auth.HashSHA256([]byte(gatingSecret))
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.HS256, Key: hashedSecret},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	require.NoError(t, err)
	payload, err := json.Marshal(claims)
	require.NoError(t, err)
	object, err := signer.Sign(payload)
	require.NoError(t, err)
	token, err := object.CompactSerialize()
	require.NoError(t, err)
	return token
}

type testOAuthProvider struct {
	server              *httptest.Server
	privateKey          *rsa.PrivateKey
	keyID               string
	lastAuthorization   string
	lastAuthorizationMu sync.Mutex
	userInfoClaims      map[string]interface{}
}

func newTestOAuthProvider(t *testing.T, userInfoClaims map[string]interface{}) *testOAuthProvider {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	provider := &testOAuthProvider{
		privateKey:     privateKey,
		keyID:          "test-signing-key",
		userInfoClaims: userInfoClaims,
	}

	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	provider.server = server
	t.Cleanup(server.Close)

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode(map[string]interface{}{
			"issuer":            server.URL,
			"jwks_uri":          server.URL + "/jwks",
			"userinfo_endpoint": server.URL + "/userinfo",
		}))
	})

	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		keySet := jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{{
				Key:       &privateKey.PublicKey,
				KeyID:     provider.keyID,
				Use:       "sig",
				Algorithm: string(jose.RS256),
			}},
		}
		require.NoError(t, json.NewEncoder(w).Encode(keySet))
	})

	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		provider.lastAuthorizationMu.Lock()
		provider.lastAuthorization = r.Header.Get("Authorization")
		provider.lastAuthorizationMu.Unlock()

		if provider.userInfoClaims == nil {
			http.Error(w, "userinfo not configured", http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode(provider.userInfoClaims))
	})

	return provider
}

func (p *testOAuthProvider) issueJWT(t *testing.T, claims map[string]interface{}) string {
	t.Helper()

	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.RS256,
		Key: jose.JSONWebKey{
			Key:       p.privateKey,
			KeyID:     p.keyID,
			Use:       "sig",
			Algorithm: string(jose.RS256),
		},
	}, (&jose.SignerOptions{}).WithType("JWT"))
	require.NoError(t, err)

	payload, err := json.Marshal(claims)
	require.NoError(t, err)

	object, err := signer.Sign(payload)
	require.NoError(t, err)

	token, err := object.CompactSerialize()
	require.NoError(t, err)

	return token
}

func (p *testOAuthProvider) authorizationHeader() string {
	p.lastAuthorizationMu.Lock()
	defer p.lastAuthorizationMu.Unlock()
	return p.lastAuthorization
}

// TestOAuthConfig tests OAuth configuration
func TestOAuthConfig(t *testing.T) {
	t.Parallel()
	t.Run("oauth_config_defaults", func(t *testing.T) {
		t.Parallel()
		cfg := config.OAuthConfig{}
		require.False(t, cfg.Enabled)
		require.Empty(t, cfg.Issuer)
		require.Empty(t, cfg.Audience)
	})

	t.Run("oauth_config_with_values", func(t *testing.T) {
		t.Parallel()
		cfg := config.OAuthConfig{
			Enabled:              true,
			Issuer:               "https://auth.example.com",
			Audience:             "my-api",
			ClientID:             "client-123",
			ClientSecret:         "secret-456",
			TokenURL:             "https://auth.example.com/oauth/token",
			AuthURL:              "https://auth.example.com/oauth/authorize",
			Scopes:               []string{"read", "write"},
			RequiredScopes:       []string{"read"},
			ClickHouseHeaderName: "X-Custom-Token",
			ClaimsToHeaders: map[string]string{
				"sub":   "X-ClickHouse-User",
				"email": "X-ClickHouse-Email",
			},
		}

		require.True(t, cfg.Enabled)
		require.Equal(t, "https://auth.example.com", cfg.Issuer)
		require.Equal(t, "my-api", cfg.Audience)
		require.Equal(t, "client-123", cfg.ClientID)
		require.Equal(t, "secret-456", cfg.ClientSecret)
		require.Equal(t, []string{"read", "write"}, cfg.Scopes)
		require.Equal(t, []string{"read"}, cfg.RequiredScopes)
		require.Equal(t, "X-Custom-Token", cfg.ClickHouseHeaderName)
		require.Len(t, cfg.ClaimsToHeaders, 2)
	})
}

// TestOAuthExtractToken tests OAuth token extraction from requests
func TestOAuthExtractToken(t *testing.T) {
	t.Parallel()
	srv := &ClickHouseJWEServer{}

	t.Run("bearer_token", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer oauth-test-token")

		token := srv.ExtractOAuthTokenFromRequest(req)
		require.Equal(t, "oauth-test-token", token)
	})

	t.Run("x_oauth_token_header", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("x-oauth-token", "header-oauth-token")

		token := srv.ExtractOAuthTokenFromRequest(req)
		require.Equal(t, "header-oauth-token", token)
	})

	t.Run("x_altinity_oauth_token_header", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("x-altinity-oauth-token", "altinity-oauth-token")

		token := srv.ExtractOAuthTokenFromRequest(req)
		require.Equal(t, "altinity-oauth-token", token)
	})

	t.Run("no_token", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/", nil)

		token := srv.ExtractOAuthTokenFromRequest(req)
		require.Empty(t, token)
	})

	t.Run("bearer_takes_precedence", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer bearer-token")
		req.Header.Set("x-oauth-token", "header-token")

		token := srv.ExtractOAuthTokenFromRequest(req)
		require.Equal(t, "bearer-token", token)
	})
}

// TestOAuthExtractTokenFromCtx tests OAuth token extraction from context
func TestOAuthExtractTokenFromCtx(t *testing.T) {
	t.Parallel()
	srv := &ClickHouseJWEServer{}

	t.Run("with_token", func(t *testing.T) {
		t.Parallel()
		ctx := context.WithValue(context.Background(), OAuthTokenKey, "ctx-oauth-token")
		token := srv.ExtractOAuthTokenFromCtx(ctx)
		require.Equal(t, "ctx-oauth-token", token)
	})

	t.Run("no_token", func(t *testing.T) {
		t.Parallel()
		token := srv.ExtractOAuthTokenFromCtx(context.Background())
		require.Empty(t, token)
	})

	t.Run("wrong_type", func(t *testing.T) {
		t.Parallel()
		ctx := context.WithValue(context.Background(), OAuthTokenKey, 123)
		token := srv.ExtractOAuthTokenFromCtx(ctx)
		require.Empty(t, token)
	})
}

// TestOAuthValidateToken tests OAuth token validation
func TestOAuthValidateToken(t *testing.T) {
	t.Parallel()
	t.Run("oauth_disabled", func(t *testing.T) {
		t.Parallel()
		srv := &ClickHouseJWEServer{
			Config: config.Config{
				Server: config.ServerConfig{
					OAuth: config.OAuthConfig{Enabled: false},
				},
			},
		}

		claims, err := srv.ValidateOAuthToken("any-token")
		require.NoError(t, err)
		require.Nil(t, claims)
	})

	t.Run("missing_token", func(t *testing.T) {
		t.Parallel()
		srv := &ClickHouseJWEServer{
			Config: config.Config{
				Server: config.ServerConfig{
					OAuth: config.OAuthConfig{Enabled: true},
				},
			},
		}

		_, err := srv.ValidateOAuthToken("")
		require.ErrorIs(t, err, ErrMissingOAuthToken)
	})

	t.Run("forward_mode_verifies_signed_jwt_via_jwks", func(t *testing.T) {
		t.Parallel()
		provider := newTestOAuthProvider(t, nil)
		srv := &ClickHouseJWEServer{
			Config: config.Config{
				Server: config.ServerConfig{
					OAuth: config.OAuthConfig{
						Enabled:              true,
						Mode:                 "forward",
						Issuer:               provider.server.URL,
						JWKSURL:              provider.server.URL + "/jwks",
						Audience:             "clickhouse-api",
						RequiredScopes:       []string{"query:execute"},
						AllowedEmailDomains:  []string{"gmail.com"},
						RequireEmailVerified: true,
					},
				},
			},
		}

		token := provider.issueJWT(t, map[string]interface{}{
			"sub":            "user123",
			"iss":            provider.server.URL,
			"aud":            []string{"clickhouse-api", "other-audience"},
			"exp":            time.Now().Add(time.Hour).Unix(),
			"iat":            time.Now().Unix(),
			"email":          "user@gmail.com",
			"name":           "Test User",
			"email_verified": true,
			"scope":          "query:execute query:read",
		})

		claims, err := srv.ValidateOAuthToken(token)
		require.NoError(t, err)
		require.Equal(t, "user123", claims.Subject)
		require.Equal(t, provider.server.URL, claims.Issuer)
		require.Equal(t, "user@gmail.com", claims.Email)
		require.True(t, claims.EmailVerified)
		require.ElementsMatch(t, []string{"clickhouse-api", "other-audience"}, claims.Audience)
		require.ElementsMatch(t, []string{"query:execute", "query:read"}, claims.Scopes)
	})

	t.Run("forward_mode_rejects_unverified_email", func(t *testing.T) {
		t.Parallel()
		provider := newTestOAuthProvider(t, nil)
		srv := &ClickHouseJWEServer{
			Config: config.Config{
				Server: config.ServerConfig{
					OAuth: config.OAuthConfig{
						Enabled:              true,
						Mode:                 "forward",
						Issuer:               provider.server.URL,
						JWKSURL:              provider.server.URL + "/jwks",
						Audience:             "clickhouse-api",
						RequireEmailVerified: true,
					},
				},
			},
		}

		token := provider.issueJWT(t, map[string]interface{}{
			"sub":            "user123",
			"iss":            provider.server.URL,
			"aud":            "clickhouse-api",
			"exp":            time.Now().Add(time.Hour).Unix(),
			"email":          "user@gmail.com",
			"email_verified": false,
		})

		_, err := srv.ValidateOAuthToken(token)
		require.ErrorIs(t, err, ErrOAuthEmailNotVerified)
	})

	t.Run("forward_mode_rejects_disallowed_email_domain", func(t *testing.T) {
		t.Parallel()
		provider := newTestOAuthProvider(t, nil)
		srv := &ClickHouseJWEServer{
			Config: config.Config{
				Server: config.ServerConfig{
					OAuth: config.OAuthConfig{
						Enabled:             true,
						Mode:                "forward",
						Issuer:              provider.server.URL,
						JWKSURL:             provider.server.URL + "/jwks",
						Audience:            "clickhouse-api",
						AllowedEmailDomains: []string{"gmail.com"},
					},
				},
			},
		}

		token := provider.issueJWT(t, map[string]interface{}{
			"sub":            "user123",
			"iss":            provider.server.URL,
			"aud":            "clickhouse-api",
			"exp":            time.Now().Add(time.Hour).Unix(),
			"email":          "user@altinity.com",
			"email_verified": true,
		})

		_, err := srv.ValidateOAuthToken(token)
		require.ErrorIs(t, err, ErrOAuthUnauthorizedDomain)
	})

	t.Run("forward_mode_rejects_disallowed_hosted_domain", func(t *testing.T) {
		t.Parallel()
		provider := newTestOAuthProvider(t, nil)
		srv := &ClickHouseJWEServer{
			Config: config.Config{
				Server: config.ServerConfig{
					OAuth: config.OAuthConfig{
						Enabled:              true,
						Mode:                 "forward",
						Issuer:               provider.server.URL,
						JWKSURL:              provider.server.URL + "/jwks",
						Audience:             "clickhouse-api",
						AllowedHostedDomains: []string{"altinity.com"},
					},
				},
			},
		}

		token := provider.issueJWT(t, map[string]interface{}{
			"sub":            "user123",
			"iss":            provider.server.URL,
			"aud":            "clickhouse-api",
			"exp":            time.Now().Add(time.Hour).Unix(),
			"email":          "user@gmail.com",
			"email_verified": true,
			"hd":             "gmail.com",
		})

		_, err := srv.ValidateOAuthToken(token)
		require.ErrorIs(t, err, ErrOAuthUnauthorizedDomain)
	})

	t.Run("forward_mode_rejects_jwt_missing_configured_audience", func(t *testing.T) {
		t.Parallel()
		provider := newTestOAuthProvider(t, nil)
		srv := &ClickHouseJWEServer{
			Config: config.Config{
				Server: config.ServerConfig{
					OAuth: config.OAuthConfig{
						Enabled:  true,
						Mode:     "forward",
						Issuer:   provider.server.URL,
						JWKSURL:  provider.server.URL + "/jwks",
						Audience: "clickhouse-api",
					},
				},
			},
		}

		token := provider.issueJWT(t, map[string]interface{}{
			"sub": "user123",
			"iss": provider.server.URL,
			"exp": time.Now().Add(time.Hour).Unix(),
		})

		_, err := srv.ValidateOAuthToken(token)
		require.ErrorIs(t, err, ErrInvalidOAuthToken)
	})

	t.Run("forward_mode_rejects_jwt_missing_required_scope_claim", func(t *testing.T) {
		t.Parallel()
		provider := newTestOAuthProvider(t, nil)
		srv := &ClickHouseJWEServer{
			Config: config.Config{
				Server: config.ServerConfig{
					OAuth: config.OAuthConfig{
						Enabled:        true,
						Mode:           "forward",
						Issuer:         provider.server.URL,
						JWKSURL:        provider.server.URL + "/jwks",
						Audience:       "clickhouse-api",
						RequiredScopes: []string{"query:execute"},
					},
				},
			},
		}

		token := provider.issueJWT(t, map[string]interface{}{
			"sub": "user123",
			"iss": provider.server.URL,
			"aud": "clickhouse-api",
			"exp": time.Now().Add(time.Hour).Unix(),
		})

		_, err := srv.ValidateOAuthToken(token)
		require.ErrorIs(t, err, ErrOAuthInsufficientScopes)
	})
}

// TestOAuthBuildClickHouseHeaders tests building ClickHouse headers from OAuth
func TestOAuthBuildClickHouseHeaders(t *testing.T) {
	t.Parallel()
	t.Run("forwarding_disabled", func(t *testing.T) {
		t.Parallel()
		srv := &ClickHouseJWEServer{
			Config: config.Config{
				Server: config.ServerConfig{
					OAuth: config.OAuthConfig{Mode: "gating"},
				},
			},
		}

		headers := srv.BuildClickHouseHeadersFromOAuth("token", nil)
		require.Nil(t, headers)
	})

	t.Run("forward_access_token", func(t *testing.T) {
		t.Parallel()
		srv := &ClickHouseJWEServer{
			Config: config.Config{
				Server: config.ServerConfig{
					OAuth: config.OAuthConfig{
						Mode: "forward",
					},
				},
			},
		}

		headers := srv.BuildClickHouseHeadersFromOAuth("my-access-token", nil)
		require.NotNil(t, headers)
		require.Equal(t, "Bearer my-access-token", headers["Authorization"])
	})

	t.Run("forward_access_token_explicit_authorization_header", func(t *testing.T) {
		t.Parallel()
		srv := &ClickHouseJWEServer{
			Config: config.Config{
				Server: config.ServerConfig{
					OAuth: config.OAuthConfig{
						Mode:                 "forward",
						ClickHouseHeaderName: "Authorization",
					},
				},
			},
		}

		headers := srv.BuildClickHouseHeadersFromOAuth("my-access-token", nil)
		require.NotNil(t, headers)
		require.Equal(t, "Bearer my-access-token", headers["Authorization"])
	})

	t.Run("forward_access_token_custom_header", func(t *testing.T) {
		t.Parallel()
		srv := &ClickHouseJWEServer{
			Config: config.Config{
				Server: config.ServerConfig{
					OAuth: config.OAuthConfig{
						Mode:                 "forward",
						ClickHouseHeaderName: "X-Custom-Token-Header",
					},
				},
			},
		}

		headers := srv.BuildClickHouseHeadersFromOAuth("my-access-token", nil)
		require.NotNil(t, headers)
		require.Equal(t, "my-access-token", headers["X-Custom-Token-Header"])
	})

	t.Run("forward_claims_to_headers", func(t *testing.T) {
		t.Parallel()
		srv := &ClickHouseJWEServer{
			Config: config.Config{
				Server: config.ServerConfig{
					OAuth: config.OAuthConfig{
						Mode: "forward",
						ClaimsToHeaders: map[string]string{
							"sub":   "X-ClickHouse-User",
							"email": "X-ClickHouse-Email",
							"name":  "X-ClickHouse-Name",
						},
					},
				},
			},
		}

		claims := &OAuthClaims{
			Subject: "user123",
			Email:   "user@example.com",
			Name:    "Test User",
		}

		headers := srv.BuildClickHouseHeadersFromOAuth("token", claims)
		require.NotNil(t, headers)
		require.Equal(t, "user123", headers["X-ClickHouse-User"])
		require.Equal(t, "user@example.com", headers["X-ClickHouse-Email"])
		require.Equal(t, "Test User", headers["X-ClickHouse-Name"])
	})

	t.Run("forward_extra_claims", func(t *testing.T) {
		t.Parallel()
		srv := &ClickHouseJWEServer{
			Config: config.Config{
				Server: config.ServerConfig{
					OAuth: config.OAuthConfig{
						Mode: "forward",
						ClaimsToHeaders: map[string]string{
							"custom_claim": "X-Custom-Claim",
						},
					},
				},
			},
		}

		claims := &OAuthClaims{
			Extra: map[string]interface{}{
				"custom_claim": "custom_value",
			},
		}

		headers := srv.BuildClickHouseHeadersFromOAuth("token", claims)
		require.NotNil(t, headers)
		require.Equal(t, "custom_value", headers["X-Custom-Claim"])
	})
}

// TestOAuthClearClickHouseCredentials tests credential clearing when forwarding OAuth token in forward mode
func TestOAuthClearClickHouseCredentials(t *testing.T) {
	t.Parallel()
	t.Run("credentials_cleared_in_forward_mode", func(t *testing.T) {
		t.Parallel()
		srv := &ClickHouseJWEServer{
			Config: config.Config{
				ClickHouse: config.ClickHouseConfig{
					Host:     "localhost",
					Port:     8123,
					Username: "default",
					Password: "secret",
					Protocol: config.HTTPProtocol,
				},
				Server: config.ServerConfig{
					OAuth: config.OAuthConfig{
						Mode: "forward",
					},
				},
			},
		}

		// In forward mode, BuildClickHouseHeadersFromOAuth should return headers
		headers := srv.BuildClickHouseHeadersFromOAuth("test-token", nil)
		require.NotNil(t, headers)
		require.Equal(t, "Bearer test-token", headers["Authorization"])
	})
}

// TestOAuthAndJWECombined tests OAuth and JWE working together
func TestOAuthAndJWECombined(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	chConfig := setupEmbeddedClickHouse(t)
	provider := newTestOAuthProvider(t, nil)

	jweSecretKey := "this-is-a-32-byte-secret-key!!"
	jwtSecretKey := "test-jwt-secret-key-123"

	t.Run("both_enabled_jwe_only", func(t *testing.T) {
		t.Parallel()
		claims := map[string]interface{}{
			"host":     chConfig.Host,
			"port":     float64(chConfig.Port),
			"database": chConfig.Database,
			"username": chConfig.Username,
			"password": chConfig.Password,
			"protocol": string(chConfig.Protocol),
			"exp":      time.Now().Add(time.Hour).Unix(),
		}

		jweToken := generateJWEToken(t, claims, []byte(jweSecretKey), []byte(jwtSecretKey))

		srv := NewClickHouseMCPServer(config.Config{
			ClickHouse: *chConfig,
			Server: config.ServerConfig{
				JWE: config.JWEConfig{
					Enabled:      true,
					JWESecretKey: jweSecretKey,
					JWTSecretKey: jwtSecretKey,
				},
				OAuth: config.OAuthConfig{
					Enabled: true,
					Mode:    "forward",
					Issuer:  provider.server.URL,
					JWKSURL: provider.server.URL + "/jwks",
				},
			},
		}, "test")

		// Create request with only JWE token (no OAuth) — JWE has username, so it's self-sufficient
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("x-altinity-mcp-key", jweToken)
		req = req.WithContext(context.WithValue(req.Context(), CHJWEServerKey, srv))

		jweTokenOut, jweClaims, oauthToken, oauthClaims, err := srv.ValidateAuth(req)
		require.NoError(t, err, "JWE with credentials should succeed without OAuth")
		require.NotEmpty(t, jweTokenOut)
		require.NotNil(t, jweClaims)
		require.Empty(t, oauthToken)
		require.Nil(t, oauthClaims)

		// Should be able to get ClickHouse client via JWE credentials without reparsing JWE.
		ctxWithClaims := context.WithValue(ctx, JWEClaimsKey, jweClaims)
		client, err := srv.GetClickHouseClientWithOAuth(ctxWithClaims, jweTokenOut, "", nil)
		require.NoError(t, err)
		require.NotNil(t, client)
		require.NoError(t, client.Close())
	})

	t.Run("both_enabled_oauth_only", func(t *testing.T) {
		t.Parallel()
		srv := NewClickHouseMCPServer(config.Config{
			ClickHouse: *chConfig,
			Server: config.ServerConfig{
				JWE: config.JWEConfig{
					Enabled:      true,
					JWESecretKey: jweSecretKey,
					JWTSecretKey: jwtSecretKey,
				},
				OAuth: config.OAuthConfig{
					Enabled: true,
					Mode:    "forward",
					Issuer:  provider.server.URL,
					JWKSURL: provider.server.URL + "/jwks",
				},
			},
		}, "test")

		oauthToken := "opaque-access-token"

		// Create request with only OAuth token (no JWE) → falls through to OAuth
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("x-oauth-token", oauthToken)
		req = req.WithContext(context.WithValue(req.Context(), CHJWEServerKey, srv))

		jweTokenOut, jweClaims, oauthTokenOut, oauthClaims, err := srv.ValidateAuth(req)
		require.NoError(t, err, "should succeed with OAuth when JWE token is absent")
		require.Empty(t, jweTokenOut)
		require.Nil(t, jweClaims)
		require.Equal(t, oauthToken, oauthTokenOut)
		require.Nil(t, oauthClaims)
	})

	t.Run("both_enabled_both_provided", func(t *testing.T) {
		t.Parallel()
		claims := map[string]interface{}{
			"host":     chConfig.Host,
			"port":     float64(chConfig.Port),
			"database": chConfig.Database,
			"username": chConfig.Username,
			"password": chConfig.Password,
			"protocol": string(chConfig.Protocol),
			"exp":      time.Now().Add(time.Hour).Unix(),
		}

		jweToken := generateJWEToken(t, claims, []byte(jweSecretKey), []byte(jwtSecretKey))

		srv := NewClickHouseMCPServer(config.Config{
			ClickHouse: *chConfig,
			Server: config.ServerConfig{
				JWE: config.JWEConfig{
					Enabled:      true,
					JWESecretKey: jweSecretKey,
					JWTSecretKey: jwtSecretKey,
				},
				OAuth: config.OAuthConfig{
					Enabled:              true,
					Mode:                 "forward",
					Issuer:               provider.server.URL,
					JWKSURL:              provider.server.URL + "/jwks",
					ClickHouseHeaderName: "X-ClickHouse-OAuth-Token",
				},
			},
		}, "test")

		oauthToken := "opaque-access-token"

		// Create request with both tokens — JWE has credentials, takes priority
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("x-altinity-mcp-key", jweToken)
		req.Header.Set("x-oauth-token", oauthToken)
		req = req.WithContext(context.WithValue(req.Context(), CHJWEServerKey, srv))

		jweTokenOut, jweClaims, oauthTokenOut, oauthClaims, err := srv.ValidateAuth(req)
		require.NoError(t, err)
		require.NotEmpty(t, jweTokenOut)
		require.NotNil(t, jweClaims)
		require.Empty(t, oauthTokenOut, "OAuth should be skipped when JWE has credentials")
		require.Nil(t, oauthClaims)

		// Get client via JWE credentials without reparsing JWE.
		ctxWithClaims := context.WithValue(ctx, JWEClaimsKey, jweClaims)
		client, err := srv.GetClickHouseClientWithOAuth(ctxWithClaims, jweTokenOut, "", nil)
		require.NoError(t, err)
		require.NotNil(t, client)
		require.NoError(t, client.Close())
	})

	t.Run("both_enabled_neither_provided", func(t *testing.T) {
		t.Parallel()
		srv := NewClickHouseMCPServer(config.Config{
			ClickHouse: *chConfig,
			Server: config.ServerConfig{
				JWE: config.JWEConfig{
					Enabled:      true,
					JWESecretKey: jweSecretKey,
					JWTSecretKey: jwtSecretKey,
				},
				OAuth: config.OAuthConfig{
					Enabled: true,
				},
			},
		}, "test")

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req = req.WithContext(context.WithValue(req.Context(), CHJWEServerKey, srv))

		_, _, _, _, err := srv.ValidateAuth(req)
		require.Error(t, err)
	})

	t.Run("both_enabled_jwe_valid_oauth_invalid", func(t *testing.T) {
		t.Parallel()
		claims := map[string]interface{}{
			"host":     chConfig.Host,
			"port":     float64(chConfig.Port),
			"database": chConfig.Database,
			"username": chConfig.Username,
			"password": chConfig.Password,
			"protocol": string(chConfig.Protocol),
			"exp":      time.Now().Add(time.Hour).Unix(),
		}

		jweToken := generateJWEToken(t, claims, []byte(jweSecretKey), []byte(jwtSecretKey))

		srv := NewClickHouseMCPServer(config.Config{
			ClickHouse: *chConfig,
			Server: config.ServerConfig{
				JWE: config.JWEConfig{
					Enabled:      true,
					JWESecretKey: jweSecretKey,
					JWTSecretKey: jwtSecretKey,
				},
				OAuth: config.OAuthConfig{
					Enabled:         true,
					Mode:            "gating",
					Issuer:          provider.server.URL,
					JWKSURL:         provider.server.URL + "/jwks",
					Audience:        "https://mcp.example.com",
					GatingSecretKey: "test-gating-secret-32-byte-key!!",
				},
			},
		}, "test")

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("x-altinity-mcp-key", jweToken)
		req.Header.Set("x-oauth-token", "not-a-valid-oauth-token")
		req = req.WithContext(context.WithValue(req.Context(), CHJWEServerKey, srv))

		// JWE has credentials (username) → takes priority, OAuth skipped entirely.
		jweTokenOut, jweClaims, oauthTokenOut, _, err := srv.ValidateAuth(req)
		require.NoError(t, err)
		require.NotEmpty(t, jweTokenOut)
		require.NotNil(t, jweClaims)
		require.Empty(t, oauthTokenOut, "OAuth should be skipped when JWE has credentials")
	})

	t.Run("both_enabled_jwe_invalid_oauth_valid", func(t *testing.T) {
		t.Parallel()
		oauthToken := "opaque-access-token"

		srv := NewClickHouseMCPServer(config.Config{
			ClickHouse: *chConfig,
			Server: config.ServerConfig{
				JWE: config.JWEConfig{
					Enabled:      true,
					JWESecretKey: jweSecretKey,
					JWTSecretKey: jwtSecretKey,
				},
				OAuth: config.OAuthConfig{
					Enabled: true,
					Mode:    "forward",
					Issuer:  provider.server.URL,
					JWKSURL: provider.server.URL + "/jwks",
				},
			},
		}, "test")

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("x-altinity-mcp-key", "invalid-jwe-token")
		req.Header.Set("x-oauth-token", oauthToken)
		req = req.WithContext(context.WithValue(req.Context(), CHJWEServerKey, srv))

		// AND semantics: JWE token is invalid, so request should fail
		_, _, _, _, err := srv.ValidateAuth(req)
		require.Error(t, err, "should reject when JWE token is invalid")
	})
}

// TestOAuthOpenAPIHandler tests OpenAPI handler with OAuth authentication
func TestOAuthOpenAPIHandler(t *testing.T) {
	t.Parallel()
	chConfig := setupEmbeddedClickHouse(t)
	provider := newTestOAuthProvider(t, nil)

	t.Run("oauth_only_valid", func(t *testing.T) {
		t.Parallel()
		const gatingSecret = "test-gating-secret-32-byte-key!!"
		srv := NewClickHouseMCPServer(config.Config{
			ClickHouse: *chConfig,
			Server: config.ServerConfig{
				JWE: config.JWEConfig{Enabled: false},
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

		require.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("oauth_only_missing", func(t *testing.T) {
		t.Parallel()
		srv := NewClickHouseMCPServer(config.Config{
			ClickHouse: *chConfig,
			Server: config.ServerConfig{
				JWE: config.JWEConfig{Enabled: false},
				OAuth: config.OAuthConfig{
					Enabled: true,
					Mode:    "forward",
					Issuer:  provider.server.URL,
					JWKSURL: provider.server.URL + "/jwks",
				},
			},
		}, "test")

		req := httptest.NewRequest(http.MethodGet, "/openapi/execute_query?query=SELECT%201", nil)
		req = req.WithContext(context.WithValue(req.Context(), CHJWEServerKey, srv))

		rr := httptest.NewRecorder()
		srv.OpenAPIHandler(rr, req)

		require.Equal(t, http.StatusUnauthorized, rr.Code)
		require.Contains(t, rr.Body.String(), "Missing authentication token")
	})

	t.Run("oauth_only_expired", func(t *testing.T) {
		t.Parallel()
		srv := NewClickHouseMCPServer(config.Config{
			ClickHouse: *chConfig,
			Server: config.ServerConfig{
				JWE: config.JWEConfig{Enabled: false},
				OAuth: config.OAuthConfig{
					Enabled: true,
					Mode:    "forward",
					Issuer:  provider.server.URL,
					JWKSURL: provider.server.URL + "/jwks",
				},
			},
		}, "test")

		// Forward mode passes token through without MCP-layer validation.
		// CH may reject with 500/403 — that's expected. We assert MCP didn't return 401.
		req := httptest.NewRequest(http.MethodGet, "/openapi/execute_query?query=SELECT%201", nil)
		req.Header.Set("Authorization", "Bearer opaque-access-token")
		req = req.WithContext(context.WithValue(req.Context(), CHJWEServerKey, srv))

		rr := httptest.NewRecorder()
		srv.OpenAPIHandler(rr, req)

		require.Equal(t, http.StatusInternalServerError, rr.Code,
			"forward mode should pass token to CH; standard CH rejects Bearer auth")
		require.Contains(t, rr.Body.String(), "Failed to get ClickHouse client",
			"response should indicate CH connection failure, not MCP rejection")
	})

	t.Run("oauth_only_insufficient_scopes", func(t *testing.T) {
		t.Parallel()
		srv := NewClickHouseMCPServer(config.Config{
			ClickHouse: *chConfig,
			Server: config.ServerConfig{
				JWE: config.JWEConfig{Enabled: false},
				OAuth: config.OAuthConfig{
					Enabled:        true,
					Mode:           "forward",
					Issuer:         provider.server.URL,
					JWKSURL:        provider.server.URL + "/jwks",
					Audience:       "clickhouse-api",
					RequiredScopes: []string{"admin"},
				},
			},
		}, "test")

		// Forward mode passes token through without MCP-layer validation.
		// CH may reject with 500/403 — that's expected.
		req := httptest.NewRequest(http.MethodGet, "/openapi/execute_query?query=SELECT%201", nil)
		req.Header.Set("Authorization", "Bearer opaque-access-token")
		req = req.WithContext(context.WithValue(req.Context(), CHJWEServerKey, srv))

		rr := httptest.NewRecorder()
		srv.OpenAPIHandler(rr, req)

		require.Equal(t, http.StatusInternalServerError, rr.Code,
			"forward mode should pass token to CH; standard CH rejects Bearer auth")
		require.Contains(t, rr.Body.String(), "Failed to get ClickHouse client",
			"response should indicate CH connection failure, not MCP rejection")
	})

	t.Run("oauth_only_invalid", func(t *testing.T) {
		t.Parallel()
		srv := NewClickHouseMCPServer(config.Config{
			ClickHouse: *chConfig,
			Server: config.ServerConfig{
				JWE: config.JWEConfig{Enabled: false},
				OAuth: config.OAuthConfig{
					Enabled: true,
					Mode:    "forward",
					Issuer:  provider.server.URL,
					JWKSURL: provider.server.URL + "/jwks",
				},
			},
		}, "test")

		// Forward mode passes token through without MCP-layer validation.
		// CH may reject with 500/403 — that's expected.
		req := httptest.NewRequest(http.MethodGet, "/openapi/execute_query?query=SELECT%201", nil)
		req.Header.Set("Authorization", "Bearer opaque-access-token")
		req = req.WithContext(context.WithValue(req.Context(), CHJWEServerKey, srv))

		rr := httptest.NewRecorder()
		srv.OpenAPIHandler(rr, req)

		require.Equal(t, http.StatusInternalServerError, rr.Code,
			"forward mode should pass token to CH; standard CH rejects Bearer auth")
		require.Contains(t, rr.Body.String(), "Failed to get ClickHouse client",
			"response should indicate CH connection failure, not MCP rejection")
	})
}

// TestGetOAuthClaimsFromCtx tests OAuth claims extraction from context
func TestGetOAuthClaimsFromCtx(t *testing.T) {
	t.Parallel()
	srv := &ClickHouseJWEServer{}

	t.Run("with_claims", func(t *testing.T) {
		t.Parallel()
		expectedClaims := &OAuthClaims{
			Subject: "user123",
			Email:   "user@example.com",
		}
		ctx := context.WithValue(context.Background(), OAuthClaimsKey, expectedClaims)
		claims := srv.GetOAuthClaimsFromCtx(ctx)
		require.NotNil(t, claims)
		require.Equal(t, "user123", claims.Subject)
		require.Equal(t, "user@example.com", claims.Email)
	})

	t.Run("no_claims", func(t *testing.T) {
		t.Parallel()
		claims := srv.GetOAuthClaimsFromCtx(context.Background())
		require.Nil(t, claims)
	})

	t.Run("wrong_type", func(t *testing.T) {
		t.Parallel()
		ctx := context.WithValue(context.Background(), OAuthClaimsKey, "not-claims")
		claims := srv.GetOAuthClaimsFromCtx(ctx)
		require.Nil(t, claims)
	})
}

// TestGetClickHouseClientWithOAuth tests client creation with OAuth headers
func TestGetClickHouseClientWithOAuth(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	chConfig := setupEmbeddedClickHouse(t)

	t.Run("no_oauth_forwarding", func(t *testing.T) {
		t.Parallel()
		srv := NewClickHouseMCPServer(config.Config{
			ClickHouse: *chConfig,
			Server: config.ServerConfig{
				JWE: config.JWEConfig{Enabled: false},
				OAuth: config.OAuthConfig{
					Enabled: true,
					Mode:    "gating",
				},
			},
		}, "test")

		client, err := srv.GetClickHouseClientWithOAuth(ctx, "", "oauth-token", nil)
		require.NoError(t, err)
		require.NotNil(t, client)
		require.NoError(t, client.Close())
	})

	t.Run("with_oauth_forwarding", func(t *testing.T) {
		t.Parallel()
		srv := NewClickHouseMCPServer(config.Config{
			ClickHouse: *chConfig,
			Server: config.ServerConfig{
				OAuth: config.OAuthConfig{
					Enabled:         true,
					Mode:            "forward",
					ClaimsToHeaders: map[string]string{"sub": "X-ClickHouse-Quota-Key"},
				},
			},
		}, "test")
		claims := &OAuthClaims{Subject: "user123"}
		headers := srv.BuildClickHouseHeadersFromOAuth("oauth-token", claims)
		require.NotNil(t, headers)
		require.Equal(t, "Bearer oauth-token", headers["Authorization"])
		require.Equal(t, "user123", headers["X-ClickHouse-Quota-Key"])
	})

	t.Run("with_jwe_and_oauth", func(t *testing.T) {
		t.Parallel()
		jweSecretKey := "this-is-a-32-byte-secret-key!!"
		jwtSecretKey := "test-jwt-secret-key-123"

		jweClaims := map[string]interface{}{
			"host":     chConfig.Host,
			"port":     float64(chConfig.Port),
			"database": chConfig.Database,
			"username": chConfig.Username,
			"password": chConfig.Password,
			"protocol": string(chConfig.Protocol),
			"exp":      time.Now().Add(time.Hour).Unix(),
		}
		jweToken := generateJWEToken(t, jweClaims, []byte(jweSecretKey), []byte(jwtSecretKey))

		srv := NewClickHouseMCPServer(config.Config{
			ClickHouse: *chConfig,
			Server: config.ServerConfig{
				JWE: config.JWEConfig{
					Enabled:      true,
					JWESecretKey: jweSecretKey,
					JWTSecretKey: jwtSecretKey,
				},
				OAuth: config.OAuthConfig{
					Enabled:              true,
					ClickHouseHeaderName: "X-ClickHouse-OAuth-Token",
				},
			},
		}, "test")

		client, err := srv.GetClickHouseClientWithOAuth(ctx, jweToken, "oauth-token", nil)
		require.NoError(t, err)
		require.NotNil(t, client)
		require.NoError(t, client.Close())
	})
}

// TestValidateAuth tests the combined validation function
func TestValidateAuth(t *testing.T) {
	t.Parallel()
	t.Run("neither_enabled", func(t *testing.T) {
		t.Parallel()
		srv := &ClickHouseJWEServer{
			Config: config.Config{
				Server: config.ServerConfig{
					JWE:   config.JWEConfig{Enabled: false},
					OAuth: config.OAuthConfig{Enabled: false},
				},
			},
		}

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		jwe, jweClaims, oauth, claims, err := srv.ValidateAuth(req)
		require.NoError(t, err)
		require.Empty(t, jwe)
		require.Nil(t, jweClaims)
		require.Empty(t, oauth)
		require.Nil(t, claims)
	})

	t.Run("both_enabled_jwe_with_credentials_skips_oauth", func(t *testing.T) {
		t.Parallel()
		jweSecret := "this-is-a-32-byte-secret-key!!"
		jwtSecret := "jwt-secret"
		jweToken := generateJWEToken(t, map[string]interface{}{
			"host": "localhost", "port": float64(8123), "username": "default",
			"exp": time.Now().Add(time.Hour).Unix(),
		}, []byte(jweSecret), []byte(jwtSecret))

		srv := &ClickHouseJWEServer{
			Config: config.Config{
				Server: config.ServerConfig{
					JWE:   config.JWEConfig{Enabled: true, JWESecretKey: jweSecret, JWTSecretKey: jwtSecret},
					OAuth: config.OAuthConfig{Enabled: true, Mode: "forward"},
				},
			},
		}

		// Request with JWE token (has credentials) but no OAuth token → should succeed
		req := httptest.NewRequest(http.MethodGet, "/openapi/execute_query", nil)
		req.Header.Set("x-altinity-mcp-key", jweToken)
		jwe, jweClaims, oauth, claims, err := srv.ValidateAuth(req)
		require.NoError(t, err, "JWE with credentials should succeed without OAuth")
		require.NotEmpty(t, jwe)
		require.NotNil(t, jweClaims)
		require.Empty(t, oauth)
		require.Nil(t, claims)
	})

	t.Run("both_enabled_jwe_no_credentials_oauth_fallback", func(t *testing.T) {
		t.Parallel()
		jweSecret := "this-is-a-32-byte-secret-key!!"
		jwtSecret := "jwt-secret"
		// JWE token without username → no credentials
		jweToken := generateJWEToken(t, map[string]interface{}{
			"host": "localhost", "port": float64(8123),
			"exp": time.Now().Add(time.Hour).Unix(),
		}, []byte(jweSecret), []byte(jwtSecret))

		srv := &ClickHouseJWEServer{
			Config: config.Config{
				Server: config.ServerConfig{
					JWE:   config.JWEConfig{Enabled: true, JWESecretKey: jweSecret, JWTSecretKey: jwtSecret},
					OAuth: config.OAuthConfig{Enabled: true, Mode: "forward"},
				},
			},
		}

		// JWE without credentials + OAuth token → falls through to OAuth
		req := httptest.NewRequest(http.MethodGet, "/openapi/execute_query", nil)
		req.Header.Set("x-altinity-mcp-key", jweToken)
		req.Header.Set("Authorization", "Bearer some-oauth-token")
		jwe, jweClaims, oauth, _, err := srv.ValidateAuth(req)
		require.NoError(t, err)
		require.NotEmpty(t, jwe)
		require.NotNil(t, jweClaims)
		require.Equal(t, "some-oauth-token", oauth)
	})

	t.Run("both_enabled_jwe_no_credentials_no_oauth_rejected", func(t *testing.T) {
		t.Parallel()
		jweSecret := "this-is-a-32-byte-secret-key!!"
		jwtSecret := "jwt-secret"
		jweToken := generateJWEToken(t, map[string]interface{}{
			"host": "localhost", "port": float64(8123),
			"exp": time.Now().Add(time.Hour).Unix(),
		}, []byte(jweSecret), []byte(jwtSecret))

		srv := &ClickHouseJWEServer{
			Config: config.Config{
				Server: config.ServerConfig{
					JWE:   config.JWEConfig{Enabled: true, JWESecretKey: jweSecret, JWTSecretKey: jwtSecret},
					OAuth: config.OAuthConfig{Enabled: true, Mode: "forward"},
				},
			},
		}

		// JWE without credentials + no OAuth token → should fail
		req := httptest.NewRequest(http.MethodGet, "/openapi/execute_query", nil)
		req.Header.Set("x-altinity-mcp-key", jweToken)
		_, _, _, _, err := srv.ValidateAuth(req)
		require.Error(t, err, "should reject when JWE has no credentials and OAuth is missing")
	})

	t.Run("both_enabled_oauth_only_succeeds", func(t *testing.T) {
		t.Parallel()
		srv := &ClickHouseJWEServer{
			Config: config.Config{
				Server: config.ServerConfig{
					JWE:   config.JWEConfig{Enabled: true, JWESecretKey: "this-is-a-32-byte-secret-key!!", JWTSecretKey: "jwt"},
					OAuth: config.OAuthConfig{Enabled: true, Mode: "forward"},
				},
			},
		}

		// No JWE token, only OAuth → falls through to OAuth
		req := httptest.NewRequest(http.MethodGet, "/openapi/execute_query", nil)
		req.Header.Set("Authorization", "Bearer some-oauth-token")
		jwe, jweClaims, oauth, _, err := srv.ValidateAuth(req)
		require.NoError(t, err, "should succeed with OAuth when JWE token is absent")
		require.Empty(t, jwe)
		require.Nil(t, jweClaims)
		require.Equal(t, "some-oauth-token", oauth)
	})

	t.Run("both_enabled_jwe_invalid_oauth_valid_rejected", func(t *testing.T) {
		t.Parallel()
		srv := &ClickHouseJWEServer{
			Config: config.Config{
				Server: config.ServerConfig{
					JWE:   config.JWEConfig{Enabled: true, JWESecretKey: "this-is-a-32-byte-secret-key!!", JWTSecretKey: "jwt"},
					OAuth: config.OAuthConfig{Enabled: true, Mode: "forward"},
				},
			},
		}

		// Invalid JWE + valid OAuth → hard error (invalid JWE is always a failure)
		req := httptest.NewRequest(http.MethodGet, "/openapi/execute_query", nil)
		req.Header.Set("x-altinity-mcp-key", "invalid-jwe-token")
		req.Header.Set("Authorization", "Bearer some-oauth-token")
		_, _, _, _, err := srv.ValidateAuth(req)
		require.Error(t, err, "invalid JWE should be a hard error even with valid OAuth")
	})

	t.Run("both_enabled_both_provided_jwe_priority", func(t *testing.T) {
		t.Parallel()
		jweSecret := "this-is-a-32-byte-secret-key!!"
		jwtSecret := "jwt-secret"
		jweToken := generateJWEToken(t, map[string]interface{}{
			"host": "localhost", "port": float64(8123), "username": "default",
			"exp": time.Now().Add(time.Hour).Unix(),
		}, []byte(jweSecret), []byte(jwtSecret))

		srv := &ClickHouseJWEServer{
			Config: config.Config{
				Server: config.ServerConfig{
					JWE:   config.JWEConfig{Enabled: true, JWESecretKey: jweSecret, JWTSecretKey: jwtSecret},
					OAuth: config.OAuthConfig{Enabled: true, Mode: "forward"},
				},
			},
		}

		// Both tokens provided, JWE has credentials → JWE takes priority, OAuth skipped
		req := httptest.NewRequest(http.MethodGet, "/openapi/execute_query", nil)
		req.Header.Set("x-altinity-mcp-key", jweToken)
		req.Header.Set("Authorization", "Bearer some-oauth-token")
		jwe, jweClaims, oauth, claims, err := srv.ValidateAuth(req)
		require.NoError(t, err)
		require.NotEmpty(t, jwe)
		require.NotNil(t, jweClaims)
		require.Empty(t, oauth, "OAuth should be skipped when JWE has credentials")
		require.Nil(t, claims)
	})
}

// TestOAuthMCPToolExecution tests that OAuth works with MCP tool execution
func TestOAuthMCPToolExecution(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	chConfig := setupEmbeddedClickHouse(t)
	provider := newTestOAuthProvider(t, nil)

	t.Run("execute_query_with_oauth", func(t *testing.T) {
		t.Parallel()
		// Create server with OAuth gating mode (validates token at MCP layer, uses static CH credentials)
		const gatingSecret = "test-gating-secret-32-byte-key!!"
		srv := NewClickHouseMCPServer(config.Config{
			ClickHouse: *chConfig,
			Server: config.ServerConfig{
				JWE: config.JWEConfig{Enabled: false},
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

		// Create context with server and OAuth claims (simulating MCP middleware)
		ctx = context.WithValue(ctx, CHJWEServerKey, srv)
		ctx = context.WithValue(ctx, OAuthTokenKey, oauthToken)
		ctx = context.WithValue(ctx, OAuthClaimsKey, (*OAuthClaims)(nil))

		// Execute MCP tool request
		req := &mcp.CallToolRequest{
			Params: &mcp.CallToolParamsRaw{
				Name:      "execute_query",
				Arguments: json.RawMessage(`{"query": "SELECT 1 as result"}`),
			},
		}

		result, err := HandleExecuteQuery(ctx, req)
		require.NoError(t, err)
		require.NotNil(t, result)
		require.False(t, result.IsError)

		// Verify result
		textContent, ok := result.Content[0].(*mcp.TextContent)
		require.True(t, ok)
		require.NotEmpty(t, textContent.Text)

		var qr clickhouse.QueryResult
		require.NoError(t, json.Unmarshal([]byte(textContent.Text), &qr))
		require.Equal(t, 1, qr.Count)
	})

	t.Run("execute_query_with_oauth_and_header_forwarding", func(t *testing.T) {
		t.Parallel()
		srv := NewClickHouseMCPServer(config.Config{
			ClickHouse: *chConfig,
			Server: config.ServerConfig{
				JWE: config.JWEConfig{Enabled: false},
				OAuth: config.OAuthConfig{
					Enabled: true,
					Mode:    "forward",
				},
			},
		}, "test")

		oauthToken := "opaque-access-token"
		headers := srv.BuildClickHouseHeadersFromOAuth(oauthToken, nil)
		require.Equal(t, "Bearer "+oauthToken, headers["Authorization"])
	})

	t.Run("oauth_and_jwe_together_mcp", func(t *testing.T) {
		t.Parallel()
		jweSecretKey := "this-is-a-32-byte-secret-key!!"
		jwtSecretKey := "test-jwt-secret-key-123"

		// Create JWE token with ClickHouse credentials
		jweClaims := map[string]interface{}{
			"host":     chConfig.Host,
			"port":     float64(chConfig.Port),
			"database": chConfig.Database,
			"username": chConfig.Username,
			"password": chConfig.Password,
			"protocol": string(chConfig.Protocol),
			"exp":      time.Now().Add(time.Hour).Unix(),
		}
		jweToken := generateJWEToken(t, jweClaims, []byte(jweSecretKey), []byte(jwtSecretKey))

		oauthToken := "opaque-access-token"

		// Create server with both enabled
		srv := NewClickHouseMCPServer(config.Config{
			ClickHouse: *chConfig,
			Server: config.ServerConfig{
				JWE: config.JWEConfig{
					Enabled:      true,
					JWESecretKey: jweSecretKey,
					JWTSecretKey: jwtSecretKey,
				},
				OAuth: config.OAuthConfig{
					Enabled: true,
					Mode:    "forward",
					Issuer:  provider.server.URL,
					JWKSURL: provider.server.URL + "/jwks",
				},
			},
		}, "test")

		// Simulate HTTP request with both tokens
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("x-altinity-mcp-key", jweToken)
		req.Header.Set("x-oauth-token", oauthToken)
		req = req.WithContext(context.WithValue(req.Context(), CHJWEServerKey, srv))

		// JWE has credentials (username) → takes priority, OAuth is skipped
		jweOut, jweClaims, oauthOut, oauthClaims, err := srv.ValidateAuth(req)
		require.NoError(t, err)
		require.NotEmpty(t, jweOut)
		require.NotNil(t, jweClaims)
		require.Empty(t, oauthOut, "OAuth should be skipped when JWE has credentials")
		require.Nil(t, oauthClaims)
	})
}

// TestOAuthOpenAPIFullFlow tests complete OAuth flow for OpenAPI endpoint
func TestOAuthOpenAPIFullFlow(t *testing.T) {
	t.Parallel()
	chConfig := setupEmbeddedClickHouse(t)
	provider := newTestOAuthProvider(t, nil)

	t.Run("complete_oauth_openapi_flow", func(t *testing.T) {
		t.Parallel()
		// Antalya is required for token_processors-driven OIDC validation in CH.
		// Use newAntalyaOIDCProvider (full discovery doc) — Antalya rejects
		// the shorter doc returned by newTestOAuthProvider.
		// setupEmbeddedAntalyaWithOIDC auto-skips on non-Linux hosts.
		oidcProvider := newAntalyaOIDCProvider(t, nil)
		antalyaCH := setupEmbeddedAntalyaWithOIDC(t, oidcProvider.server.URL)
		srv := NewClickHouseMCPServer(config.Config{
			ClickHouse: antalyaCH,
			Server:     config.ServerConfig{OAuth: config.OAuthConfig{Enabled: true, Mode: "forward"}},
		}, "test")
		oauthToken := oidcProvider.issueJWT(t, map[string]interface{}{
			"sub": "service-account-123",
			"iss": oidcProvider.server.URL,
			"exp": time.Now().Add(time.Hour).Unix(),
		})
		req := httptest.NewRequest(http.MethodGet, "/openapi/execute_query?query=SELECT%20version()%20as%20version", nil)
		req.Header.Set("Authorization", "Bearer "+oauthToken)
		req = req.WithContext(context.WithValue(req.Context(), CHJWEServerKey, srv))
		rr := httptest.NewRecorder()
		srv.OpenAPIHandler(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)
		var qr clickhouse.QueryResult
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &qr))
		require.Equal(t, 1, qr.Count)
		require.Contains(t, qr.Columns, "version")
	})

	t.Run("forward_mode_passthrough_wrong_audience", func(t *testing.T) {
		t.Parallel()
		srv := NewClickHouseMCPServer(config.Config{
			ClickHouse: *chConfig,
			Server: config.ServerConfig{
				JWE: config.JWEConfig{Enabled: false},
				OAuth: config.OAuthConfig{
					Enabled:  true,
					Mode:     "forward",
					Issuer:   provider.server.URL,
					JWKSURL:  provider.server.URL + "/jwks",
					Audience: "expected-audience",
				},
			},
		}, "test")

		// Forward mode passes token through without MCP-layer validation.
		// CH may reject with 500/403 — that's expected.
		req := httptest.NewRequest(http.MethodGet, "/openapi/execute_query?query=SELECT%201", nil)
		req.Header.Set("Authorization", "Bearer opaque-access-token")
		req = req.WithContext(context.WithValue(req.Context(), CHJWEServerKey, srv))

		rr := httptest.NewRecorder()
		srv.OpenAPIHandler(rr, req)

		require.Equal(t, http.StatusInternalServerError, rr.Code,
			"forward mode should pass token to CH; standard CH rejects Bearer auth")
		require.Contains(t, rr.Body.String(), "Failed to get ClickHouse client",
			"response should indicate CH connection failure, not MCP rejection")
	})

	t.Run("forward_mode_passthrough_missing_scope", func(t *testing.T) {
		t.Parallel()
		srv := NewClickHouseMCPServer(config.Config{
			ClickHouse: *chConfig,
			Server: config.ServerConfig{
				JWE: config.JWEConfig{Enabled: false},
				OAuth: config.OAuthConfig{
					Enabled:        true,
					Mode:           "forward",
					Issuer:         provider.server.URL,
					JWKSURL:        provider.server.URL + "/jwks",
					Audience:       "clickhouse-api",
					RequiredScopes: []string{"admin"},
				},
			},
		}, "test")

		// Forward mode passes token through without MCP-layer validation.
		// CH may reject with 500/403 — that's expected.
		req := httptest.NewRequest(http.MethodGet, "/openapi/execute_query?query=SELECT%201", nil)
		req.Header.Set("Authorization", "Bearer opaque-access-token")
		req = req.WithContext(context.WithValue(req.Context(), CHJWEServerKey, srv))

		rr := httptest.NewRecorder()
		srv.OpenAPIHandler(rr, req)

		require.Equal(t, http.StatusInternalServerError, rr.Code,
			"forward mode should pass token to CH; standard CH rejects Bearer auth")
		require.Contains(t, rr.Body.String(), "Failed to get ClickHouse client",
			"response should indicate CH connection failure, not MCP rejection")
	})
}

func TestResolveOAuthJWKSURL(t *testing.T) {
	t.Parallel()
	t.Run("direct_jwks_url_configured", func(t *testing.T) {
		t.Parallel()
		srv := &ClickHouseJWEServer{
			Config: config.Config{
				Server: config.ServerConfig{
					OAuth: config.OAuthConfig{
						JWKSURL: "https://auth.example.com/jwks",
					},
				},
			},
		}
		url, err := srv.resolveOAuthJWKSURL()
		require.NoError(t, err)
		require.Equal(t, "https://auth.example.com/jwks", url)
	})

	t.Run("openid_configuration_discovery", func(t *testing.T) {
		t.Parallel()
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/.well-known/openid-configuration" {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]string{
					"issuer":   "https://auth.example.com",
					"jwks_uri": "https://auth.example.com/keys",
				})
				return
			}
			http.NotFound(w, r)
		}))
		defer mockServer.Close()

		srv := &ClickHouseJWEServer{
			Config: config.Config{
				Server: config.ServerConfig{
					OAuth: config.OAuthConfig{
						Issuer: mockServer.URL,
					},
				},
			},
		}
		url, err := srv.resolveOAuthJWKSURL()
		require.NoError(t, err)
		require.Equal(t, "https://auth.example.com/keys", url)
	})

	t.Run("fallback_to_oauth_authorization_server", func(t *testing.T) {
		t.Parallel()
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/.well-known/openid-configuration" {
				http.NotFound(w, r)
				return
			}
			if r.URL.Path == "/.well-known/oauth-authorization-server" {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]string{
					"issuer":   "https://auth.example.com",
					"jwks_uri": "https://auth.example.com/fallback-keys",
				})
				return
			}
			http.NotFound(w, r)
		}))
		defer mockServer.Close()

		srv := &ClickHouseJWEServer{
			Config: config.Config{
				Server: config.ServerConfig{
					OAuth: config.OAuthConfig{
						Issuer: mockServer.URL,
					},
				},
			},
		}
		url, err := srv.resolveOAuthJWKSURL()
		require.NoError(t, err)
		require.Equal(t, "https://auth.example.com/fallback-keys", url)
	})

	t.Run("both_discovery_endpoints_fail", func(t *testing.T) {
		t.Parallel()
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.NotFound(w, r)
		}))
		defer mockServer.Close()

		srv := &ClickHouseJWEServer{
			Config: config.Config{
				Server: config.ServerConfig{
					OAuth: config.OAuthConfig{
						Issuer: mockServer.URL,
					},
				},
			},
		}
		_, err := srv.resolveOAuthJWKSURL()
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to discover")
	})

	t.Run("discovery_missing_jwks_uri", func(t *testing.T) {
		t.Parallel()
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"issuer": "https://auth.example.com",
			})
		}))
		defer mockServer.Close()

		srv := &ClickHouseJWEServer{
			Config: config.Config{
				Server: config.ServerConfig{
					OAuth: config.OAuthConfig{
						Issuer: mockServer.URL,
					},
				},
			},
		}
		_, err := srv.resolveOAuthJWKSURL()
		require.Error(t, err)
		require.Contains(t, err.Error(), "jwks_uri")
	})
}

func TestOIDCConfigCaching(t *testing.T) {
	t.Parallel()
	var requestCount int
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":   "https://auth.example.com",
			"jwks_uri": "https://auth.example.com/keys",
		})
	}))
	defer mockServer.Close()

	srv := &ClickHouseJWEServer{
		Config: config.Config{
			Server: config.ServerConfig{
				OAuth: config.OAuthConfig{
					Issuer: mockServer.URL,
				},
			},
		},
	}

	// NOTE: subtests are NOT parallel — they share requestCount and srv cache state
	t.Run("cache_hit_within_ttl", func(t *testing.T) {
		requestCount = 0
		_, err := srv.FetchOpenIDConfiguration(mockServer.URL)
		require.NoError(t, err)
		_, err = srv.FetchOpenIDConfiguration(mockServer.URL)
		require.NoError(t, err)
		require.Equal(t, 1, requestCount, "second call should hit cache")
	})

	t.Run("cache_miss_after_ttl_expires", func(t *testing.T) {
		// Ensure cache is populated
		_, err := srv.FetchOpenIDConfiguration(mockServer.URL)
		require.NoError(t, err)

		// Manipulate cache time to simulate TTL expiry
		srv.oidcConfigMu.Lock()
		srv.oidcConfigTime = time.Now().Add(-oauthJWKSCacheTTL - time.Second)
		srv.oidcConfigMu.Unlock()

		countBefore := requestCount
		_, err = srv.FetchOpenIDConfiguration(mockServer.URL)
		require.NoError(t, err)
		require.Equal(t, countBefore+1, requestCount, "should re-fetch after TTL expiry")
	})
}

func TestParseAndVerifyExternalJWTUnknownKid(t *testing.T) {
	t.Parallel()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create JWKS with kid "known"
	knownJWK := jose.JSONWebKey{Key: &privateKey.PublicKey, KeyID: "known", Algorithm: "RS256", Use: "sig"}
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"issuer":   r.Host,
				"jwks_uri": "http://" + r.Host + "/jwks",
			})
		case "/jwks":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{knownJWK}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer mockServer.Close()

	srv := &ClickHouseJWEServer{
		Config: config.Config{
			Server: config.ServerConfig{
				OAuth: config.OAuthConfig{
					Issuer:  mockServer.URL,
					JWKSURL: mockServer.URL + "/jwks",
				},
			},
		},
	}

	// Sign token with kid "unknown"
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: privateKey},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "unknown"),
	)
	require.NoError(t, err)

	payload, err := json.Marshal(map[string]interface{}{
		"sub": "user-1",
		"iss": mockServer.URL,
		"aud": "test-audience",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	})
	require.NoError(t, err)

	object, err := signer.Sign(payload)
	require.NoError(t, err)
	token, err := object.CompactSerialize()
	require.NoError(t, err)

	_, err = srv.parseAndVerifyExternalJWT(token, "test-audience")
	require.Error(t, err)
	require.Contains(t, err.Error(), "no JWK found for kid")
}

func TestValidateOAuthClaimsTemporalEdgeCases(t *testing.T) {
	t.Parallel()
	const gatingSecret = "test-gating-secret-32-byte-key!!"
	now := time.Now().Unix()

	baseClaims := func() map[string]interface{} {
		return map[string]interface{}{
			"sub":   "user-1",
			"iss":   "https://mcp.example.com",
			"aud":   "https://mcp.example.com",
			"email": "user@example.com",
		}
	}

	newSrv := func() *ClickHouseJWEServer {
		return NewClickHouseMCPServer(config.Config{
			Server: config.ServerConfig{
				OAuth: config.OAuthConfig{
					Enabled:         true,
					Mode:            "gating",
					GatingSecretKey: gatingSecret,
				},
			},
		}, "test")
	}

	// NOTE: subtests are NOT parallel — they share a `now` timestamp and are timing-sensitive
	t.Run("expired_token", func(t *testing.T) {
		c := baseClaims()
		c["exp"] = now - 120
		c["iat"] = now - 300
		token := mintSelfIssuedToken(t, gatingSecret, c)
		srv := newSrv()
		_, err := srv.ValidateOAuthToken(token)
		require.ErrorIs(t, err, ErrOAuthTokenExpired)
	})

	t.Run("expired_within_clock_skew", func(t *testing.T) {
		c := baseClaims()
		c["exp"] = now - 30
		c["iat"] = now - 300
		token := mintSelfIssuedToken(t, gatingSecret, c)
		srv := newSrv()
		_, err := srv.ValidateOAuthToken(token)
		require.NoError(t, err)
	})

	t.Run("expired_beyond_clock_skew", func(t *testing.T) {
		c := baseClaims()
		c["exp"] = now - 61
		c["iat"] = now - 300
		token := mintSelfIssuedToken(t, gatingSecret, c)
		srv := newSrv()
		_, err := srv.ValidateOAuthToken(token)
		require.ErrorIs(t, err, ErrOAuthTokenExpired)
	})

	t.Run("future_nbf_within_skew", func(t *testing.T) {
		c := baseClaims()
		c["exp"] = now + 3600
		c["iat"] = now
		c["nbf"] = now + 30
		token := mintSelfIssuedToken(t, gatingSecret, c)
		srv := newSrv()
		_, err := srv.ValidateOAuthToken(token)
		require.NoError(t, err)
	})

	t.Run("future_nbf_beyond_skew", func(t *testing.T) {
		c := baseClaims()
		c["exp"] = now + 3600
		c["iat"] = now
		c["nbf"] = now + 120
		token := mintSelfIssuedToken(t, gatingSecret, c)
		srv := newSrv()
		_, err := srv.ValidateOAuthToken(token)
		require.ErrorIs(t, err, ErrInvalidOAuthToken)
	})

	t.Run("future_iat_within_skew", func(t *testing.T) {
		c := baseClaims()
		c["exp"] = now + 3600
		c["iat"] = now + 30
		token := mintSelfIssuedToken(t, gatingSecret, c)
		srv := newSrv()
		_, err := srv.ValidateOAuthToken(token)
		require.NoError(t, err)
	})

	t.Run("future_iat_beyond_skew", func(t *testing.T) {
		c := baseClaims()
		c["exp"] = now + 3600
		c["iat"] = now + 120
		token := mintSelfIssuedToken(t, gatingSecret, c)
		srv := newSrv()
		_, err := srv.ValidateOAuthToken(token)
		require.ErrorIs(t, err, ErrInvalidOAuthToken)
	})
}

func TestGatingModeIdentityPolicy(t *testing.T) {
	t.Parallel()
	const gatingSecret = "test-gating-secret-32-byte-key!!"

	newSrv := func(oauthCfg config.OAuthConfig) *ClickHouseJWEServer {
		oauthCfg.Enabled = true
		oauthCfg.Mode = "gating"
		oauthCfg.GatingSecretKey = gatingSecret
		return NewClickHouseMCPServer(config.Config{
			Server: config.ServerConfig{
				OAuth: oauthCfg,
			},
		}, "test")
	}

	t.Run("allowed_email_domain_match", func(t *testing.T) {
		t.Parallel()
		srv := newSrv(config.OAuthConfig{AllowedEmailDomains: []string{"corp.com"}})
		claims := &OAuthClaims{Email: "user@corp.com", EmailVerified: true}
		err := srv.ValidateOAuthIdentityPolicyClaims(claims)
		require.NoError(t, err)
	})

	t.Run("allowed_email_domain_reject", func(t *testing.T) {
		t.Parallel()
		srv := newSrv(config.OAuthConfig{AllowedEmailDomains: []string{"corp.com"}})
		claims := &OAuthClaims{Email: "user@other.com", EmailVerified: true}
		err := srv.ValidateOAuthIdentityPolicyClaims(claims)
		require.ErrorIs(t, err, ErrOAuthUnauthorizedDomain)
	})

	t.Run("require_email_verified_pass", func(t *testing.T) {
		t.Parallel()
		srv := newSrv(config.OAuthConfig{RequireEmailVerified: true})
		claims := &OAuthClaims{Email: "user@example.com", EmailVerified: true}
		err := srv.ValidateOAuthIdentityPolicyClaims(claims)
		require.NoError(t, err)
	})

	t.Run("require_email_verified_fail", func(t *testing.T) {
		t.Parallel()
		srv := newSrv(config.OAuthConfig{RequireEmailVerified: true})
		claims := &OAuthClaims{Email: "user@example.com", EmailVerified: false}
		err := srv.ValidateOAuthIdentityPolicyClaims(claims)
		require.ErrorIs(t, err, ErrOAuthEmailNotVerified)
	})

	t.Run("allowed_hosted_domain_reject", func(t *testing.T) {
		t.Parallel()
		srv := newSrv(config.OAuthConfig{AllowedHostedDomains: []string{"corp.com"}})
		claims := &OAuthClaims{HostedDomain: "other.com"}
		err := srv.ValidateOAuthIdentityPolicyClaims(claims)
		require.ErrorIs(t, err, ErrOAuthUnauthorizedDomain)
	})
}

// ---------- coverage gap tests ----------

func TestEmailDomain(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		email string
		want  string
	}{
		{"normal", "user@example.com", "example.com"},
		{"uppercase", "User@EXAMPLE.COM", "example.com"},
		{"whitespace", "  user@example.com  ", "example.com"},
		{"no_at", "noatsign", ""},
		{"empty", "", ""},
		{"multiple_at", "a@b@c", ""},
		{"just_at", "@", ""},
		{"domain_only", "@domain.com", "domain.com"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tt.want, emailDomain(tt.email))
		})
	}
}

func TestCapitalize(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, in, want string
	}{
		{"empty", "", ""},
		{"single_char", "a", "A"},
		{"already_upper", "A", "A"},
		{"word", "hello", "Hello"},
		{"all_caps", "HELLO", "Hello"},
		{"unicode", "ñoño", "Ñoño"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tt.want, capitalize(tt.in))
		})
	}
}

func TestOAuthClaimsFromRawClaims(t *testing.T) {
	t.Parallel()

	t.Run("all_standard_fields", func(t *testing.T) {
		t.Parallel()
		raw := map[string]interface{}{
			"sub":            "user123",
			"iss":            "https://auth.example.com",
			"exp":            float64(1700000000),
			"iat":            float64(1699999000),
			"nbf":            float64(1699998000),
			"email":          "user@example.com",
			"name":           "Test User",
			"hd":             "example.com",
			"email_verified": true,
			"aud":            "my-api",
			"scope":          "read write",
		}
		claims := oauthClaimsFromRawClaims(raw)
		require.Equal(t, "user123", claims.Subject)
		require.Equal(t, "https://auth.example.com", claims.Issuer)
		require.Equal(t, int64(1700000000), claims.ExpiresAt)
		require.Equal(t, int64(1699999000), claims.IssuedAt)
		require.Equal(t, int64(1699998000), claims.NotBefore)
		require.Equal(t, "user@example.com", claims.Email)
		require.Equal(t, "Test User", claims.Name)
		require.Equal(t, "example.com", claims.HostedDomain)
		require.True(t, claims.EmailVerified)
		require.Equal(t, []string{"my-api"}, claims.Audience)
		require.Equal(t, []string{"read", "write"}, claims.Scopes)
	})

	t.Run("json_number_fields", func(t *testing.T) {
		t.Parallel()
		raw := map[string]interface{}{
			"sub": "user",
			"exp": json.Number("1700000000"),
			"iat": json.Number("1699999000"),
			"nbf": json.Number("1699998000"),
		}
		claims := oauthClaimsFromRawClaims(raw)
		require.Equal(t, int64(1700000000), claims.ExpiresAt)
		require.Equal(t, int64(1699999000), claims.IssuedAt)
		require.Equal(t, int64(1699998000), claims.NotBefore)
	})

	t.Run("audience_array", func(t *testing.T) {
		t.Parallel()
		raw := map[string]interface{}{
			"aud": []interface{}{"api1", "api2"},
		}
		claims := oauthClaimsFromRawClaims(raw)
		require.Equal(t, []string{"api1", "api2"}, claims.Audience)
	})

	t.Run("scope_array", func(t *testing.T) {
		t.Parallel()
		raw := map[string]interface{}{
			"scope": []interface{}{"read", "write", "admin"},
		}
		claims := oauthClaimsFromRawClaims(raw)
		require.Equal(t, []string{"read", "write", "admin"}, claims.Scopes)
	})

	t.Run("email_verified_string", func(t *testing.T) {
		t.Parallel()
		raw := map[string]interface{}{
			"email_verified": "true",
		}
		claims := oauthClaimsFromRawClaims(raw)
		require.True(t, claims.EmailVerified)

		raw2 := map[string]interface{}{
			"email_verified": "false",
		}
		claims2 := oauthClaimsFromRawClaims(raw2)
		require.False(t, claims2.EmailVerified)
	})

	t.Run("extra_claims_preserved", func(t *testing.T) {
		t.Parallel()
		raw := map[string]interface{}{
			"sub":        "user",
			"custom1":    "value1",
			"custom_num": float64(42),
		}
		claims := oauthClaimsFromRawClaims(raw)
		require.Equal(t, "value1", claims.Extra["custom1"])
		require.Equal(t, float64(42), claims.Extra["custom_num"])
		_, hasSub := claims.Extra["sub"]
		require.False(t, hasSub)
	})

	t.Run("empty_claims", func(t *testing.T) {
		t.Parallel()
		claims := oauthClaimsFromRawClaims(map[string]interface{}{})
		require.NotNil(t, claims)
		require.Empty(t, claims.Subject)
		require.NotNil(t, claims.Extra)
	})
}

func TestJWETokenHasCredentials(t *testing.T) {
	t.Parallel()
	jweKey := "test-jwe-secret-key-for-test!!"
	jwtKey := "test-jwt-secret-key-for-test!!"

	srv := NewClickHouseMCPServer(config.Config{
		Server: config.ServerConfig{
			JWE: config.JWEConfig{
				Enabled:      true,
				JWESecretKey: jweKey,
				JWTSecretKey: jwtKey,
			},
		},
	}, "test")

	t.Run("has_credentials", func(t *testing.T) {
		t.Parallel()
		token := generateJWEToken(t, map[string]interface{}{
			"username": "admin",
			"password": "secret",
		}, []byte(jweKey), []byte(jwtKey))
		require.True(t, srv.JWETokenHasCredentials(token))
	})

	t.Run("no_credentials", func(t *testing.T) {
		t.Parallel()
		token := generateJWEToken(t, map[string]interface{}{
			"host": "localhost",
		}, []byte(jweKey), []byte(jwtKey))
		require.False(t, srv.JWETokenHasCredentials(token))
	})

	t.Run("invalid_token", func(t *testing.T) {
		t.Parallel()
		require.False(t, srv.JWETokenHasCredentials("not-a-valid-token"))
	})

	t.Run("jwe_disabled", func(t *testing.T) {
		t.Parallel()
		srvDisabled := NewClickHouseMCPServer(config.Config{
			Server: config.ServerConfig{
				JWE: config.JWEConfig{Enabled: false},
			},
		}, "test")
		require.False(t, srvDisabled.JWETokenHasCredentials("any-token"))
	})
}

func TestBuildClickHouseHeadersFromOAuth(t *testing.T) {
	t.Parallel()

	t.Run("gating_mode_returns_nil", func(t *testing.T) {
		t.Parallel()
		srv := NewClickHouseMCPServer(config.Config{
			Server: config.ServerConfig{
				OAuth: config.OAuthConfig{Enabled: true, Mode: "gating"},
			},
		}, "test")
		headers := srv.BuildClickHouseHeadersFromOAuth("token123", &OAuthClaims{Subject: "user"})
		require.Nil(t, headers)
	})

	t.Run("forward_mode_default_header", func(t *testing.T) {
		t.Parallel()
		srv := NewClickHouseMCPServer(config.Config{
			Server: config.ServerConfig{
				OAuth: config.OAuthConfig{Enabled: true, Mode: "forward"},
			},
		}, "test")
		headers := srv.BuildClickHouseHeadersFromOAuth("token123", nil)
		require.Equal(t, "Bearer token123", headers["Authorization"])
	})

	t.Run("forward_mode_custom_header", func(t *testing.T) {
		t.Parallel()
		srv := NewClickHouseMCPServer(config.Config{
			Server: config.ServerConfig{
				OAuth: config.OAuthConfig{
					Enabled:              true,
					Mode:                 "forward",
					ClickHouseHeaderName: "X-Token",
				},
			},
		}, "test")
		headers := srv.BuildClickHouseHeadersFromOAuth("token123", nil)
		require.Equal(t, "token123", headers["X-Token"])
	})

	t.Run("forward_with_claims_to_headers", func(t *testing.T) {
		t.Parallel()
		srv := NewClickHouseMCPServer(config.Config{
			Server: config.ServerConfig{
				OAuth: config.OAuthConfig{
					Enabled: true,
					Mode:    "forward",
					ClaimsToHeaders: map[string]string{
						"sub":            "X-User-ID",
						"email":          "X-Email",
						"name":           "X-Name",
						"email_verified": "X-Verified",
						"hd":             "X-Domain",
						"iss":            "X-Issuer",
						"custom_claim":   "X-Custom",
					},
				},
			},
		}, "test")
		claims := &OAuthClaims{
			Subject:       "user123",
			Issuer:        "https://auth.example.com",
			Email:         "user@example.com",
			Name:          "Test User",
			EmailVerified: true,
			HostedDomain:  "example.com",
			Extra:         map[string]interface{}{"custom_claim": "custom_value"},
		}
		headers := srv.BuildClickHouseHeadersFromOAuth("tok", claims)
		require.Equal(t, "user123", headers["X-User-ID"])
		require.Equal(t, "user@example.com", headers["X-Email"])
		require.Equal(t, "Test User", headers["X-Name"])
		require.Equal(t, "true", headers["X-Verified"])
		require.Equal(t, "example.com", headers["X-Domain"])
		require.Equal(t, "https://auth.example.com", headers["X-Issuer"])
		require.Equal(t, "custom_value", headers["X-Custom"])
	})

	t.Run("forward_with_non_string_extra_claim", func(t *testing.T) {
		t.Parallel()
		srv := NewClickHouseMCPServer(config.Config{
			Server: config.ServerConfig{
				OAuth: config.OAuthConfig{
					Enabled:         true,
					Mode:            "forward",
					ClaimsToHeaders: map[string]string{"roles": "X-Roles"},
				},
			},
		}, "test")
		claims := &OAuthClaims{
			Extra: map[string]interface{}{"roles": []string{"admin", "user"}},
		}
		headers := srv.BuildClickHouseHeadersFromOAuth("tok", claims)
		require.Contains(t, headers["X-Roles"], "admin")
	})

	t.Run("forward_email_verified_false", func(t *testing.T) {
		t.Parallel()
		srv := NewClickHouseMCPServer(config.Config{
			Server: config.ServerConfig{
				OAuth: config.OAuthConfig{
					Enabled:         true,
					Mode:            "forward",
					ClaimsToHeaders: map[string]string{"email_verified": "X-V"},
				},
			},
		}, "test")
		claims := &OAuthClaims{EmailVerified: false}
		headers := srv.BuildClickHouseHeadersFromOAuth("tok", claims)
		require.Equal(t, "false", headers["X-V"])
	})
}

func TestParseJWEClaims(t *testing.T) {
	t.Parallel()

	t.Run("jwe_disabled", func(t *testing.T) {
		t.Parallel()
		srv := NewClickHouseMCPServer(config.Config{
			Server: config.ServerConfig{JWE: config.JWEConfig{Enabled: false}},
		}, "test")
		claims, err := srv.ParseJWEClaims("some-token")
		require.NoError(t, err)
		require.Nil(t, claims)
	})

	t.Run("empty_token", func(t *testing.T) {
		t.Parallel()
		srv := NewClickHouseMCPServer(config.Config{
			Server: config.ServerConfig{JWE: config.JWEConfig{
				Enabled:      true,
				JWESecretKey: "test-key",
			}},
		}, "test")
		_, err := srv.ParseJWEClaims("")
		require.Error(t, err)
	})
}

func TestLooksLikeJWT(t *testing.T) {
	t.Parallel()
	require.True(t, looksLikeJWT("a.b.c"))
	require.False(t, looksLikeJWT("not-a-jwt"))
	require.False(t, looksLikeJWT("a.b"))
	require.False(t, looksLikeJWT("a.b.c.d"))
}

func TestParseDynamicToolComment(t *testing.T) {
	t.Parallel()
	t.Run("empty_string", func(t *testing.T) {
		t.Parallel()
		_, ok := parseDynamicToolComment("")
		require.False(t, ok)
	})
	t.Run("whitespace_only", func(t *testing.T) {
		t.Parallel()
		_, ok := parseDynamicToolComment("   ")
		require.False(t, ok)
	})
	t.Run("non_json_text", func(t *testing.T) {
		t.Parallel()
		_, ok := parseDynamicToolComment("just a plain comment")
		require.False(t, ok)
	})
	t.Run("valid_json_metadata", func(t *testing.T) {
		t.Parallel()
		meta, ok := parseDynamicToolComment(`{"title":"My Tool","description":"Does stuff"}`)
		require.True(t, ok)
		require.Equal(t, "My Tool", meta.Title)
		require.Equal(t, "Does stuff", meta.Description)
	})
	t.Run("invalid_json", func(t *testing.T) {
		t.Parallel()
		_, ok := parseDynamicToolComment(`{invalid json}`)
		require.False(t, ok)
	})
	t.Run("json_with_annotations", func(t *testing.T) {
		t.Parallel()
		meta, ok := parseDynamicToolComment(`{"title":"T","annotations":{"openWorldHint":true}}`)
		require.True(t, ok)
		require.Equal(t, "T", meta.Title)
		require.NotNil(t, meta.Annotations)
		require.True(t, *meta.Annotations.OpenWorldHint)
	})
	t.Run("json_with_params", func(t *testing.T) {
		t.Parallel()
		meta, ok := parseDynamicToolComment(`{"params":{"user_id":"The user ID","ts":"Event timestamp"}}`)
		require.True(t, ok)
		require.Equal(t, "The user ID", meta.Params["user_id"])
		require.Equal(t, "Event timestamp", meta.Params["ts"])
	})
}

func TestApplyCommentParamOverrides(t *testing.T) {
	t.Parallel()

	t.Run("empty_params_is_noop", func(t *testing.T) {
		t.Parallel()
		params := []dynamicToolParam{{Name: "a", Description: "col-level"}}
		applyCommentParamOverrides(params, dynamicToolCommentMetadata{})
		require.Equal(t, "col-level", params[0].Description)
	})
	t.Run("json_overrides_existing_description", func(t *testing.T) {
		t.Parallel()
		params := []dynamicToolParam{{Name: "a", Description: "col-level"}}
		meta := dynamicToolCommentMetadata{Params: map[string]string{"a": "json-override"}}
		applyCommentParamOverrides(params, meta)
		require.Equal(t, "json-override", params[0].Description)
	})
	t.Run("json_fills_missing_description", func(t *testing.T) {
		t.Parallel()
		params := []dynamicToolParam{{Name: "a"}}
		meta := dynamicToolCommentMetadata{Params: map[string]string{"a": "from-json"}}
		applyCommentParamOverrides(params, meta)
		require.Equal(t, "from-json", params[0].Description)
	})
	t.Run("whitespace_only_override_ignored", func(t *testing.T) {
		t.Parallel()
		params := []dynamicToolParam{{Name: "a", Description: "col-level"}}
		meta := dynamicToolCommentMetadata{Params: map[string]string{"a": "   "}}
		applyCommentParamOverrides(params, meta)
		require.Equal(t, "col-level", params[0].Description)
	})
	t.Run("unmatched_params_preserved", func(t *testing.T) {
		t.Parallel()
		params := []dynamicToolParam{{Name: "a", Description: "A"}, {Name: "b"}}
		meta := dynamicToolCommentMetadata{Params: map[string]string{"c": "nope"}}
		applyCommentParamOverrides(params, meta)
		require.Equal(t, "A", params[0].Description)
		require.Equal(t, "", params[1].Description)
	})
}

func TestBuildParamSchema(t *testing.T) {
	t.Parallel()

	t.Run("description_used_when_set", func(t *testing.T) {
		t.Parallel()
		p := dynamicToolParam{Name: "uid", CHType: "UInt64", JSONType: "integer", Description: "user id"}
		schema := buildParamSchema(p)
		require.Equal(t, "integer", schema["type"])
		require.Equal(t, "user id", schema["description"])
	})
	t.Run("fallback_to_chtype_when_empty", func(t *testing.T) {
		t.Parallel()
		p := dynamicToolParam{Name: "uid", CHType: "UInt64", JSONType: "integer"}
		schema := buildParamSchema(p)
		require.Equal(t, "UInt64", schema["description"])
	})
	t.Run("json_format_included_when_set", func(t *testing.T) {
		t.Parallel()
		p := dynamicToolParam{Name: "ts", CHType: "DateTime", JSONType: "string", JSONFormat: "date-time", Description: "event time"}
		schema := buildParamSchema(p)
		require.Equal(t, "string", schema["type"])
		require.Equal(t, "date-time", schema["format"])
		require.Equal(t, "event time", schema["description"])
	})
	t.Run("json_format_omitted_when_empty", func(t *testing.T) {
		t.Parallel()
		p := dynamicToolParam{Name: "n", CHType: "UInt64", JSONType: "integer"}
		schema := buildParamSchema(p)
		_, hasFormat := schema["format"]
		require.False(t, hasFormat)
	})
}

func TestBuildDynamicToolDescription(t *testing.T) {
	t.Parallel()
	t.Run("metadata_description_takes_priority", func(t *testing.T) {
		t.Parallel()
		desc := buildDynamicToolDescription("comment", "db", "tbl", "Meta desc", false)
		require.Equal(t, "Meta desc", desc)
	})
	t.Run("comment_used_when_no_metadata", func(t *testing.T) {
		t.Parallel()
		desc := buildDynamicToolDescription("my comment", "db", "tbl", "", false)
		require.Equal(t, "my comment", desc)
	})
	t.Run("structured_metadata_overrides_comment", func(t *testing.T) {
		t.Parallel()
		desc := buildDynamicToolDescription("my comment", "db", "tbl", "", true)
		require.Equal(t, "Read-only tool to query data from db.tbl", desc)
	})
	t.Run("fallback_when_all_empty", func(t *testing.T) {
		t.Parallel()
		desc := buildDynamicToolDescription("", "db", "tbl", "", false)
		require.Equal(t, "Read-only tool to query data from db.tbl", desc)
	})
	t.Run("whitespace_metadata_description_ignored", func(t *testing.T) {
		t.Parallel()
		desc := buildDynamicToolDescription("comment", "db", "tbl", "   ", false)
		require.Equal(t, "comment", desc)
	})
}

func TestValidateOAuthClaims(t *testing.T) {
	t.Parallel()

	t.Run("issuer_mismatch", func(t *testing.T) {
		t.Parallel()
		s := &ClickHouseJWEServer{Config: config.Config{Server: config.ServerConfig{OAuth: config.OAuthConfig{
			Issuer: "https://expected.example.com",
		}}}}
		_, err := s.validateOAuthClaims(&OAuthClaims{Issuer: "https://wrong.example.com"})
		require.ErrorIs(t, err, ErrInvalidOAuthToken)
	})

	t.Run("audience_missing_when_required", func(t *testing.T) {
		t.Parallel()
		s := &ClickHouseJWEServer{Config: config.Config{Server: config.ServerConfig{OAuth: config.OAuthConfig{
			Audience: "my-audience",
		}}}}
		_, err := s.validateOAuthClaims(&OAuthClaims{})
		require.ErrorIs(t, err, ErrInvalidOAuthToken)
	})

	t.Run("audience_mismatch", func(t *testing.T) {
		t.Parallel()
		s := &ClickHouseJWEServer{Config: config.Config{Server: config.ServerConfig{OAuth: config.OAuthConfig{
			Audience: "my-audience",
		}}}}
		_, err := s.validateOAuthClaims(&OAuthClaims{Audience: []string{"wrong-audience"}})
		require.ErrorIs(t, err, ErrInvalidOAuthToken)
	})

	t.Run("token_expired", func(t *testing.T) {
		t.Parallel()
		s := &ClickHouseJWEServer{Config: config.Config{Server: config.ServerConfig{OAuth: config.OAuthConfig{}}}}
		_, err := s.validateOAuthClaims(&OAuthClaims{ExpiresAt: time.Now().Unix() - 300})
		require.ErrorIs(t, err, ErrOAuthTokenExpired)
	})

	t.Run("not_yet_valid", func(t *testing.T) {
		t.Parallel()
		s := &ClickHouseJWEServer{Config: config.Config{Server: config.ServerConfig{OAuth: config.OAuthConfig{}}}}
		_, err := s.validateOAuthClaims(&OAuthClaims{NotBefore: time.Now().Unix() + 300})
		require.ErrorIs(t, err, ErrInvalidOAuthToken)
	})

	t.Run("issued_in_future", func(t *testing.T) {
		t.Parallel()
		s := &ClickHouseJWEServer{Config: config.Config{Server: config.ServerConfig{OAuth: config.OAuthConfig{}}}}
		_, err := s.validateOAuthClaims(&OAuthClaims{IssuedAt: time.Now().Unix() + 300})
		require.ErrorIs(t, err, ErrInvalidOAuthToken)
	})

	t.Run("missing_required_scopes", func(t *testing.T) {
		t.Parallel()
		s := &ClickHouseJWEServer{Config: config.Config{Server: config.ServerConfig{OAuth: config.OAuthConfig{
			RequiredScopes: []string{"admin"},
		}}}}
		_, err := s.validateOAuthClaims(&OAuthClaims{Scopes: []string{"read"}})
		require.ErrorIs(t, err, ErrOAuthInsufficientScopes)
	})

	t.Run("valid_claims", func(t *testing.T) {
		t.Parallel()
		s := &ClickHouseJWEServer{Config: config.Config{Server: config.ServerConfig{OAuth: config.OAuthConfig{
			Issuer:         "https://issuer.example.com",
			Audience:       "my-aud",
			RequiredScopes: []string{"read"},
		}}}}
		claims, err := s.validateOAuthClaims(&OAuthClaims{
			Issuer:    "https://issuer.example.com",
			Audience:  []string{"my-aud"},
			ExpiresAt: time.Now().Unix() + 300,
			Scopes:    []string{"read", "write"},
		})
		require.NoError(t, err)
		require.Equal(t, "https://issuer.example.com", claims.Issuer)
	})

	t.Run("gating_mode_uses_public_auth_server_url_as_issuer", func(t *testing.T) {
		t.Parallel()
		s := &ClickHouseJWEServer{Config: config.Config{Server: config.ServerConfig{OAuth: config.OAuthConfig{
			Mode:                "gating",
			Issuer:              "https://original-issuer.com",
			PublicAuthServerURL: "https://public-auth.com",
		}}}}
		_, err := s.validateOAuthClaims(&OAuthClaims{Issuer: "https://public-auth.com"})
		require.NoError(t, err)
	})
}

func TestParseAndVerifySelfIssuedOAuthToken(t *testing.T) {
	t.Parallel()

	t.Run("missing_secret", func(t *testing.T) {
		t.Parallel()
		s := &ClickHouseJWEServer{Config: config.Config{Server: config.ServerConfig{OAuth: config.OAuthConfig{
			GatingSecretKey: "",
		}}}}
		_, err := s.parseAndVerifySelfIssuedOAuthToken("some.jwt.token")
		require.Error(t, err)
		require.Contains(t, err.Error(), "gating_secret_key is required")
	})

	t.Run("invalid_jwt_format", func(t *testing.T) {
		t.Parallel()
		s := &ClickHouseJWEServer{Config: config.Config{Server: config.ServerConfig{OAuth: config.OAuthConfig{
			GatingSecretKey: "my-secret",
		}}}}
		_, err := s.parseAndVerifySelfIssuedOAuthToken("not-a-jwt")
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to parse self-issued JWT")
	})
}

func TestHasRequiredScopes(t *testing.T) {
	t.Parallel()
	require.True(t, hasRequiredScopes([]string{"read", "write", "admin"}, []string{"read", "write"}))
	require.False(t, hasRequiredScopes([]string{"read"}, []string{"read", "admin"}))
	require.True(t, hasRequiredScopes([]string{"read"}, []string{}))
	require.True(t, hasRequiredScopes([]string{}, []string{}))
	require.False(t, hasRequiredScopes([]string{}, []string{"read"}))
}

// --- Pure function unit tests ---

func TestMapCHType(t *testing.T) {
	t.Parallel()
	tests := []struct {
		chType     string
		wantType   string
		wantFormat string
	}{
		{"UInt64", "integer", "int64"},
		{"UInt8", "integer", "int64"},
		{"Int32", "integer", "int64"},
		{"Float64", "number", "double"},
		{"Float32", "number", "double"},
		{"Decimal(18,2)", "number", "double"},
		{"Bool", "boolean", ""},
		{"Date", "string", "date"},
		{"Date32", "string", "date"},
		{"DateTime", "string", "date-time"},
		{"DateTime64(3)", "string", "date-time"},
		{"UUID", "string", "uuid"},
		{"String", "string", ""},
		{"FixedString(10)", "string", ""},
		{"Enum8('a'=1)", "string", ""},
		{"Array(UInt64)", "string", ""},
	}
	for _, tt := range tests {
		t.Run(tt.chType, func(t *testing.T) {
			t.Parallel()
			gotType, gotFormat := mapCHType(tt.chType)
			require.Equal(t, tt.wantType, gotType)
			require.Equal(t, tt.wantFormat, gotFormat)
		})
	}
}

func TestSqlLiteral(t *testing.T) {
	t.Parallel()
	t.Run("integer_float64", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, "42", sqlLiteral("integer", float64(42)))
	})
	t.Run("integer_int64", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, "99", sqlLiteral("integer", int64(99)))
	})
	t.Run("integer_int", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, "7", sqlLiteral("integer", int(7)))
	})
	t.Run("integer_unsupported_type", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, "0", sqlLiteral("integer", "not-a-number"))
	})
	t.Run("number_float64", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, "3.14", sqlLiteral("number", float64(3.14)))
	})
	t.Run("number_unsupported_type", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, "0", sqlLiteral("number", "not-a-number"))
	})
	t.Run("boolean_true", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, "1", sqlLiteral("boolean", true))
	})
	t.Run("boolean_false", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, "0", sqlLiteral("boolean", false))
	})
	t.Run("boolean_non_bool", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, "0", sqlLiteral("boolean", "yes"))
	})
	t.Run("string_value", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, "'hello'", sqlLiteral("string", "hello"))
	})
	t.Run("string_with_single_quote", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, "'it\\'s'", sqlLiteral("string", "it's"))
	})
	t.Run("string_with_backslash", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, "'a\\\\b'", sqlLiteral("string", "a\\b"))
	})
	t.Run("string_non_string_value", func(t *testing.T) {
		t.Parallel()
		result := sqlLiteral("string", 42)
		require.Equal(t, "'42'", result)
	})
}

func TestSqlLiteralChecked(t *testing.T) {
	t.Parallel()

	t.Run("integer_rejects_string", func(t *testing.T) {
		t.Parallel()
		_, err := sqlLiteralChecked("integer", "not-a-number")
		require.ErrorContains(t, err, "expected integer")
	})

	t.Run("integer_rejects_fractional_float", func(t *testing.T) {
		t.Parallel()
		_, err := sqlLiteralChecked("integer", 3.14)
		require.ErrorContains(t, err, "non-integer number")
	})

	t.Run("boolean_rejects_string", func(t *testing.T) {
		t.Parallel()
		_, err := sqlLiteralChecked("boolean", "yes")
		require.ErrorContains(t, err, "expected boolean")
	})

	t.Run("string_accepts_marshaled_non_string", func(t *testing.T) {
		t.Parallel()
		result, err := sqlLiteralChecked("string", 42)
		require.NoError(t, err)
		require.Equal(t, "'42'", result)
	})
}

func TestSnakeCase(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"simple", "hello", "hello"},
		{"camel_case", "helloWorld", "helloworld"},
		{"with_spaces", "hello world", "hello_world"},
		{"with_hyphens", "hello-world", "hello_world"},
		{"consecutive_special", "hello--world", "hello_world"},
		{"leading_trailing_special", "--hello--", "hello"},
		{"empty", "", ""},
		{"numbers", "test123value", "test123value"},
		{"mixed", "my View-Name 123", "my_view_name_123"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tt.want, snakeCase(tt.input))
		})
	}
}

func TestParseViewParams(t *testing.T) {
	t.Parallel()
	t.Run("single_param", func(t *testing.T) {
		t.Parallel()
		params := parseViewParams("SELECT * FROM t WHERE id = {id: UInt64}")
		require.Len(t, params, 1)
		require.Equal(t, "id", params[0].Name)
		require.Equal(t, "UInt64", params[0].CHType)
		require.Equal(t, "integer", params[0].JSONType)
		require.Equal(t, "int64", params[0].JSONFormat)
		require.True(t, params[0].Required)
	})
	t.Run("multiple_params", func(t *testing.T) {
		t.Parallel()
		params := parseViewParams("SELECT * FROM t WHERE id = {id: UInt64} AND name = {name: String}")
		require.Len(t, params, 2)
		require.Equal(t, "id", params[0].Name)
		require.Equal(t, "name", params[1].Name)
	})
	t.Run("no_params", func(t *testing.T) {
		t.Parallel()
		params := parseViewParams("SELECT * FROM t")
		require.Empty(t, params)
	})
	t.Run("no_spaces", func(t *testing.T) {
		t.Parallel()
		params := parseViewParams("SELECT * FROM t WHERE id={id:UInt64}")
		require.Len(t, params, 1)
		require.Equal(t, "id", params[0].Name)
		require.Equal(t, "UInt64", params[0].CHType)
	})
	t.Run("date_type", func(t *testing.T) {
		t.Parallel()
		params := parseViewParams("WHERE dt = {dt: DateTime}")
		require.Len(t, params, 1)
		require.Equal(t, "string", params[0].JSONType)
		require.Equal(t, "date-time", params[0].JSONFormat)
	})
}

func TestHumanizeToolName(t *testing.T) {
	t.Parallel()
	require.Equal(t, "My Tool", humanizeToolName("my_tool"))
	require.Equal(t, "Abc Def", humanizeToolName("abc-def"))
	require.Equal(t, "Hello World", humanizeToolName("hello.world"))
	require.Equal(t, "Single", humanizeToolName("single"))
	require.Equal(t, "", humanizeToolName(""))
}

func TestBuildTitle(t *testing.T) {
	t.Parallel()
	require.Equal(t, "Custom Title", buildTitle("my_tool", "Custom Title"))
	require.Equal(t, "My Tool", buildTitle("my_tool", ""))
	require.Equal(t, "My Tool", buildTitle("my_tool", "  "))
}

func TestBuildDescription_Wrapper(t *testing.T) {
	t.Parallel()
	desc := buildDescription("some comment", "db", "tbl")
	require.Equal(t, "some comment", desc)
	desc = buildDescription("", "db", "tbl")
	require.Equal(t, "Read-only tool to query data from db.tbl", desc)
}

func TestBuildDynamicToolAnnotations(t *testing.T) {
	t.Parallel()
	t.Run("nil_annotations", func(t *testing.T) {
		t.Parallel()
		annotations := buildDynamicToolAnnotations(nil)
		require.True(t, annotations.ReadOnlyHint)
		require.False(t, *annotations.DestructiveHint)
		require.False(t, *annotations.OpenWorldHint)
	})
	t.Run("open_world_true", func(t *testing.T) {
		t.Parallel()
		owTrue := true
		annotations := buildDynamicToolAnnotations(&dynamicToolCommentAnnotations{OpenWorldHint: &owTrue})
		require.True(t, *annotations.OpenWorldHint)
	})
}

func TestGetClickHouseJWEServerFromContext_WrongType(t *testing.T) {
	t.Parallel()
	ctx := context.WithValue(context.Background(), CHJWEServerKey, "not-a-server")
	require.Nil(t, GetClickHouseJWEServerFromContext(ctx))
}

func TestExtractTokenFromRequest_AllSources(t *testing.T) {
	t.Parallel()
	s := &ClickHouseJWEServer{}

	t.Run("basic_auth", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Basic abc123")
		require.Equal(t, "abc123", s.ExtractTokenFromRequest(req))
	})
	t.Run("custom_header", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("x-altinity-mcp-key", "custom-key")
		require.Equal(t, "custom-key", s.ExtractTokenFromRequest(req))
	})
	t.Run("openapi_path", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/my-token/openapi/execute_query", nil)
		require.Equal(t, "my-token", s.ExtractTokenFromRequest(req))
	})
	t.Run("no_token", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		require.Equal(t, "", s.ExtractTokenFromRequest(req))
	})
}

func TestValidateJWEToken(t *testing.T) {
	t.Parallel()
	jweKey := "test-jwe-key-12345"
	jwtKey := "test-jwt-key-12345"

	s := &ClickHouseJWEServer{Config: config.Config{Server: config.ServerConfig{JWE: config.JWEConfig{
		Enabled:      true,
		JWESecretKey: jweKey,
		JWTSecretKey: jwtKey,
	}}}}

	t.Run("valid_token", func(t *testing.T) {
		t.Parallel()
		token := generateJWEToken(t, map[string]interface{}{
			"host": "localhost",
			"exp":  float64(time.Now().Add(time.Hour).Unix()),
		}, []byte(jweKey), []byte(jwtKey))
		require.NoError(t, s.ValidateJWEToken(token))
	})

	t.Run("invalid_token", func(t *testing.T) {
		t.Parallel()
		require.Error(t, s.ValidateJWEToken("invalid-token"))
	})

	t.Run("expired_token", func(t *testing.T) {
		t.Parallel()
		token := generateJWEToken(t, map[string]interface{}{
			"host": "localhost",
			"exp":  float64(time.Now().Add(-time.Hour).Unix()),
		}, []byte(jweKey), []byte(jwtKey))
		require.Error(t, s.ValidateJWEToken(token))
	})

	t.Run("jwe_disabled", func(t *testing.T) {
		t.Parallel()
		s2 := &ClickHouseJWEServer{Config: config.Config{Server: config.ServerConfig{JWE: config.JWEConfig{Enabled: false}}}}
		require.NoError(t, s2.ValidateJWEToken("anything"))
	})
}

// --- E2E tests with ClickHouse container ---

func TestHandleSchemaResourceE2E(t *testing.T) {
	t.Parallel()
	chConfig := setupEmbeddedClickHouse(t)

	srv := NewClickHouseMCPServer(config.Config{
		ClickHouse: *chConfig,
		Server:     config.ServerConfig{JWE: config.JWEConfig{Enabled: false}},
	}, "test")

	ctx := context.WithValue(context.Background(), CHJWEServerKey, srv)

	result, err := HandleSchemaResource(ctx, nil)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Len(t, result.Contents, 1)
	require.Contains(t, result.Contents[0].Text, "test")
	require.Equal(t, "application/json", result.Contents[0].MIMEType)
}

func TestHandleSchemaResourceE2E_NoServer(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	_, err := HandleSchemaResource(ctx, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "can't get JWEServer from context")
}

func TestHandleTableResourceE2E(t *testing.T) {
	t.Parallel()
	chConfig := setupEmbeddedClickHouse(t)

	srv := NewClickHouseMCPServer(config.Config{
		ClickHouse: *chConfig,
		Server:     config.ServerConfig{JWE: config.JWEConfig{Enabled: false}},
	}, "test")

	ctx := context.WithValue(context.Background(), CHJWEServerKey, srv)

	t.Run("valid_table", func(t *testing.T) {
		req := &mcp.ReadResourceRequest{Params: &mcp.ReadResourceParams{URI: "clickhouse://table/default/test"}}
		result, err := HandleTableResource(ctx, req)
		require.NoError(t, err)
		require.NotNil(t, result)
		require.Len(t, result.Contents, 1)
		require.Contains(t, result.Contents[0].Text, "id")
	})

	t.Run("invalid_uri_format", func(t *testing.T) {
		req := &mcp.ReadResourceRequest{Params: &mcp.ReadResourceParams{URI: "invalid-uri"}}
		_, err := HandleTableResource(ctx, req)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid table URI format")
	})

	t.Run("empty_database", func(t *testing.T) {
		req := &mcp.ReadResourceRequest{Params: &mcp.ReadResourceParams{URI: "clickhouse://table//test"}}
		_, err := HandleTableResource(ctx, req)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid table URI format")
	})

	t.Run("nonexistent_table", func(t *testing.T) {
		req := &mcp.ReadResourceRequest{Params: &mcp.ReadResourceParams{URI: "clickhouse://table/default/nonexistent_table_xyz"}}
		_, err := HandleTableResource(ctx, req)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get table structure")
	})

	t.Run("no_server_in_context", func(t *testing.T) {
		req := &mcp.ReadResourceRequest{Params: &mcp.ReadResourceParams{URI: "clickhouse://table/default/test"}}
		_, err := HandleTableResource(context.Background(), req)
		require.Error(t, err)
		require.Contains(t, err.Error(), "can't get JWEServer from context")
	})
}

func TestHandleExecuteQueryE2E(t *testing.T) {
	t.Parallel()
	chConfig := setupEmbeddedClickHouse(t)

	srv := NewClickHouseMCPServer(config.Config{
		ClickHouse: *chConfig,
		Server:     config.ServerConfig{JWE: config.JWEConfig{Enabled: false}},
	}, "test")

	ctx := context.WithValue(context.Background(), CHJWEServerKey, srv)

	t.Run("select_query", func(t *testing.T) {
		req := &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: "execute_query", Arguments: json.RawMessage(`{"query":"SELECT * FROM default.test"}`)}}
		result, err := HandleExecuteQuery(ctx, req)
		require.NoError(t, err)
		require.NotNil(t, result)
		require.False(t, result.IsError)
	})

	t.Run("missing_query_param", func(t *testing.T) {
		req := &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: "execute_query", Arguments: json.RawMessage(`{}`)}}
		result, err := HandleExecuteQuery(ctx, req)
		require.NoError(t, err)
		require.True(t, result.IsError)
	})

	t.Run("empty_query", func(t *testing.T) {
		req := &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: "execute_query", Arguments: json.RawMessage(`{"query":""}`)}}
		result, err := HandleExecuteQuery(ctx, req)
		require.NoError(t, err)
		require.True(t, result.IsError)
	})

	t.Run("invalid_query", func(t *testing.T) {
		req := &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: "execute_query", Arguments: json.RawMessage(`{"query":"INVALID SQL SYNTAX HERE 123"}`)}}
		result, err := HandleExecuteQuery(ctx, req)
		require.NoError(t, err)
		require.True(t, result.IsError)
	})

	t.Run("with_limit", func(t *testing.T) {
		req := &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: "execute_query", Arguments: json.RawMessage(`{"query":"SELECT * FROM default.test","limit":1}`)}}
		result, err := HandleExecuteQuery(ctx, req)
		require.NoError(t, err)
		require.False(t, result.IsError)
	})

	t.Run("limit_exceeds_max", func(t *testing.T) {
		srvLimited := NewClickHouseMCPServer(config.Config{
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
		ctxLimited := context.WithValue(context.Background(), CHJWEServerKey, srvLimited)
		req := &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: "execute_query", Arguments: json.RawMessage(`{"query":"SELECT * FROM default.test","limit":100}`)}}
		result, err := HandleExecuteQuery(ctxLimited, req)
		require.NoError(t, err)
		require.True(t, result.IsError)
	})

	t.Run("no_server_in_context", func(t *testing.T) {
		req := &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: "execute_query", Arguments: json.RawMessage(`{"query":"SELECT 1"}`)}}
		_, err := HandleExecuteQuery(context.Background(), req)
		require.Error(t, err)
		require.Contains(t, err.Error(), "can't get JWEServer from context")
	})
}

func TestEnsureDynamicToolsE2E(t *testing.T) {
	t.Parallel()
	chConfig := setupEmbeddedClickHouse(t)

	t.Run("no_dynamic_tools_config", func(t *testing.T) {
		t.Parallel()
		srv := NewClickHouseMCPServer(config.Config{
			ClickHouse: *chConfig,
			Server:     config.ServerConfig{JWE: config.JWEConfig{Enabled: false}},
		}, "test")
		err := srv.EnsureDynamicTools(context.Background())
		require.NoError(t, err)
	})

	t.Run("with_dynamic_tools_pattern", func(t *testing.T) {
		t.Parallel()
		// Create a view first
		ctx := context.Background()
		client, err := clickhouse.NewClient(ctx, *chConfig)
		require.NoError(t, err)
		_, err = client.ExecuteQuery(ctx, "CREATE OR REPLACE VIEW default.mcp_test_view AS SELECT 1 AS value")
		require.NoError(t, err)
		require.NoError(t, client.Close())

		srv := NewClickHouseMCPServer(config.Config{
			ClickHouse: *chConfig,
			Server: config.ServerConfig{
				JWE: config.JWEConfig{Enabled: false},
				DynamicTools: []config.DynamicToolRule{
					{Regexp: "^mcp_"},
				},
			},
		}, "test")
		err = srv.EnsureDynamicTools(ctx)
		require.NoError(t, err)
	})
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

// --- tool_input_settings tests ---

func TestValidateToolInputSettings(t *testing.T) {
	cases := []struct {
		name         string
		settings     []string
		wantErr      string
		wantWarnings int
		warnContains string
	}{
		{"valid_custom_prefix", []string{"custom_tenant_id", "custom_user_id"}, "", 0, ""},
		{"nil_settings", nil, "", 0, ""},
		{"empty_settings", []string{}, "", 0, ""},
		{"blocked_readonly", []string{"readonly"}, "blocked", 0, ""},
		{"blocked_READONLY_case", []string{"READONLY"}, "blocked", 0, ""},
		{"blocked_max_execution_time", []string{"max_execution_time"}, "blocked", 0, ""},
		{"blocked_password", []string{"password"}, "blocked", 0, ""},
		{"blocked_database", []string{"database"}, "blocked", 0, ""},
		{"blocked_user", []string{"user"}, "blocked", 0, ""},
		{"duplicate_setting", []string{"custom_a", "custom_a"}, "duplicate", 0, ""},
		{"duplicate_case_insensitive", []string{"Custom_A", "custom_a"}, "duplicate", 0, ""},
		{"warn_non_custom_prefix", []string{"my_setting"}, "", 1, "does not start with 'custom_'"},
		{"warn_mixed", []string{"custom_ok", "not_custom"}, "", 1, "not_custom"},
		{"warn_multiple_non_custom", []string{"env_name", "region_code"}, "", 2, ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			warnings, err := validateToolInputSettings(tc.settings)
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			require.Len(t, warnings, tc.wantWarnings)
			if tc.warnContains != "" && len(warnings) > 0 {
				require.Contains(t, warnings[0], tc.warnContains)
			}
		})
	}

	t.Run("public_api_delegates_correctly", func(t *testing.T) {
		require.NoError(t, ValidateToolInputSettings([]string{"custom_tenant_id"}))
		require.Error(t, ValidateToolInputSettings([]string{"readonly"}))
	})
}

func TestBuildToolInputSettingsSchema(t *testing.T) {
	t.Run("nil_for_empty", func(t *testing.T) {
		require.Nil(t, buildToolInputSettingsSchema(nil))
		require.Nil(t, buildToolInputSettingsSchema([]string{}))
	})

	t.Run("builds_schema_with_properties", func(t *testing.T) {
		schema := buildToolInputSettingsSchema([]string{"custom_tenant_id", "custom_org_id"})
		require.NotNil(t, schema)
		require.Equal(t, "object", schema["type"])
		require.False(t, schema["additionalProperties"].(bool))

		props := schema["properties"].(map[string]any)
		require.Len(t, props, 2)
		require.Equal(t, map[string]any{"type": "string"}, props["custom_tenant_id"])
		require.Equal(t, map[string]any{"type": "string"}, props["custom_org_id"])
	})

	t.Run("description_lists_settings", func(t *testing.T) {
		schema := buildToolInputSettingsSchema([]string{"custom_a"})
		desc := schema["description"].(string)
		require.Contains(t, desc, "custom_a")
	})
}

func TestExtractToolInputSettings(t *testing.T) {
	allowlist := []string{"custom_tenant_id", "custom_org_id"}

	t.Run("extracts_valid_settings", func(t *testing.T) {
		args := map[string]any{
			"query": "SELECT 1",
			"settings": map[string]any{
				"custom_tenant_id": "123",
				"custom_org_id":    "abc",
			},
		}
		settings, err := extractToolInputSettings(args, allowlist)
		require.NoError(t, err)
		require.Len(t, settings, 2)
		require.Equal(t, "123", settings["custom_tenant_id"])
		require.Equal(t, "abc", settings["custom_org_id"])
	})

	t.Run("nil_when_no_settings_key", func(t *testing.T) {
		args := map[string]any{"query": "SELECT 1"}
		settings, err := extractToolInputSettings(args, allowlist)
		require.NoError(t, err)
		require.Nil(t, settings)
	})

	t.Run("nil_for_empty_settings_object", func(t *testing.T) {
		args := map[string]any{"settings": map[string]any{}}
		settings, err := extractToolInputSettings(args, allowlist)
		require.NoError(t, err)
		require.Nil(t, settings)
	})

	t.Run("error_on_non_object_settings", func(t *testing.T) {
		args := map[string]any{"settings": "not_an_object"}
		_, err := extractToolInputSettings(args, allowlist)
		require.ErrorContains(t, err, "settings must be an object")
	})

	t.Run("error_on_disallowed_setting", func(t *testing.T) {
		args := map[string]any{
			"settings": map[string]any{"custom_unknown": "val"},
		}
		_, err := extractToolInputSettings(args, allowlist)
		require.ErrorContains(t, err, "not allowed")
		require.ErrorContains(t, err, "custom_unknown")
	})

	t.Run("error_on_blocked_setting", func(t *testing.T) {
		args := map[string]any{
			"settings": map[string]any{"readonly": "1"},
		}
		_, err := extractToolInputSettings(args, []string{"readonly"})
		require.ErrorContains(t, err, "blocked")
	})

	t.Run("error_on_non_string_value", func(t *testing.T) {
		args := map[string]any{
			"settings": map[string]any{"custom_tenant_id": 123},
		}
		_, err := extractToolInputSettings(args, allowlist)
		require.ErrorContains(t, err, "must be a string")
	})

	t.Run("partial_settings_ok", func(t *testing.T) {
		args := map[string]any{
			"settings": map[string]any{"custom_tenant_id": "only_one"},
		}
		settings, err := extractToolInputSettings(args, allowlist)
		require.NoError(t, err)
		require.Len(t, settings, 1)
		require.Equal(t, "only_one", settings["custom_tenant_id"])
	})
}

func TestContextToolInputSettings_RoundTrip(t *testing.T) {
	t.Run("stores_and_retrieves", func(t *testing.T) {
		settings := map[string]string{"custom_tenant_id": "t1"}
		ctx := ContextWithToolInputSettings(context.Background(), settings)
		got := ToolInputSettingsFromContext(ctx)
		require.Equal(t, "t1", got["custom_tenant_id"])
	})

	t.Run("nil_from_empty_context", func(t *testing.T) {
		require.Nil(t, ToolInputSettingsFromContext(context.Background()))
	})
}

func TestToolInputSettingsPriority(t *testing.T) {
	base := config.ClickHouseConfig{
		ExtraSettings: map[string]string{"custom_tenant_id": "from_config"},
	}

	// Simulate header-to-settings layer
	afterHeaders := mergeExtraSettings(base, map[string]string{"custom_tenant_id": "from_header"})
	require.Equal(t, "from_header", afterHeaders.ExtraSettings["custom_tenant_id"])

	// Simulate tool-input layer (highest priority)
	afterTool := mergeExtraSettings(afterHeaders, map[string]string{"custom_tenant_id": "from_tool"})
	require.Equal(t, "from_tool", afterTool.ExtraSettings["custom_tenant_id"])

	// Ensure base was never mutated
	require.Equal(t, "from_config", base.ExtraSettings["custom_tenant_id"])
}

func TestRegisterToolsWithSettings(t *testing.T) {
	t.Run("no_settings_property_when_empty", func(t *testing.T) {
		var registeredTools []*mcp.Tool
		mock := &mockMCPServer{
			addToolFn: func(tool *mcp.Tool, handler ToolHandlerFunc) {
				registeredTools = append(registeredTools, tool)
			},
		}
		cfg := config.Config{}
		RegisterTools(mock, &cfg)
		// Defaults register both execute_query and write_query.
		require.Len(t, registeredTools, 2)
		for _, tool := range registeredTools {
			schema := tool.InputSchema.(map[string]any)
			props := schema["properties"].(map[string]any)
			_, hasSettings := props["settings"]
			require.Falsef(t, hasSettings, "tool %q should not have settings property", tool.Name)
		}
	})

	t.Run("settings_property_added_when_configured", func(t *testing.T) {
		var registeredTools []*mcp.Tool
		mock := &mockMCPServer{
			addToolFn: func(tool *mcp.Tool, handler ToolHandlerFunc) {
				registeredTools = append(registeredTools, tool)
			},
		}
		cfg := config.Config{
			Server: config.ServerConfig{
				ToolInputSettings: []string{"custom_tenant_id", "custom_org_id"},
			},
		}
		RegisterTools(mock, &cfg)
		// Defaults register both execute_query and write_query; each should
		// have the settings property wired in.
		require.Len(t, registeredTools, 2)

		for _, tool := range registeredTools {
			schema := tool.InputSchema.(map[string]any)
			props := schema["properties"].(map[string]any)
			settingsSchema, ok := props["settings"].(map[string]any)
			require.Truef(t, ok, "tool %q missing settings property", tool.Name)
			require.Equal(t, "object", settingsSchema["type"])
			require.False(t, settingsSchema["additionalProperties"].(bool))

			innerProps := settingsSchema["properties"].(map[string]any)
			require.Len(t, innerProps, 2)
			require.Contains(t, innerProps, "custom_tenant_id")
			require.Contains(t, innerProps, "custom_org_id")
		}
	})
}

func TestNormalizeBlockedClauses(t *testing.T) {
	t.Run("nil_for_empty", func(t *testing.T) {
		require.Nil(t, NormalizeBlockedClauses(nil))
		require.Nil(t, NormalizeBlockedClauses([]string{}))
	})

	t.Run("normalizes_clauses", func(t *testing.T) {
		set := NormalizeBlockedClauses([]string{"SETTINGS", "FORMAT", "SET", "INTO OUTFILE", "EXPLAIN"})
		require.Len(t, set, 5)
		require.True(t, set["SETTINGS"])
		require.True(t, set["FORMAT"])
		require.True(t, set["SET"])
		require.True(t, set["INTO OUTFILE"])
		require.True(t, set["EXPLAIN"])
	})

	t.Run("uppercases_names", func(t *testing.T) {
		set := NormalizeBlockedClauses([]string{"settings", "Format"})
		require.Len(t, set, 2)
		require.True(t, set["SETTINGS"])
		require.True(t, set["FORMAT"])
	})

	t.Run("skips_empty_entries", func(t *testing.T) {
		set := NormalizeBlockedClauses([]string{"SETTINGS", "", "  "})
		require.Len(t, set, 1)
		require.True(t, set["SETTINGS"])
	})
}

func TestCheckBlockedClauses(t *testing.T) {
	allBlocked := NormalizeBlockedClauses([]string{"SETTINGS", "FORMAT", "SET", "INTO OUTFILE", "EXPLAIN"})

	cases := []struct {
		name         string
		query        string
		wantBlocked  string
		wantParseErr bool
	}{
		// Clean queries — should pass
		{"plain_select", "SELECT * FROM events", "", false},
		{"select_with_limit", "SELECT * FROM events LIMIT 10", "", false},
		{"select_with_where", "SELECT * FROM events WHERE tenant_id = 'a'", "", false},
		{"show_tables", "SHOW TABLES", "", false},
		{"describe_table", "DESCRIBE events", "", false},
		{"table_named_settings_compound", "SELECT * FROM settings_table", "", false},
		{"table_named_nosettings", "SELECT * FROM nosettings", "", false},
		{"offset_not_set", "SELECT * FROM t LIMIT 10 OFFSET 5", "", false},

		// Column/function names that match clause keywords — should NOT be blocked
		{"column_named_format", "SELECT format FROM t", "", false},
		{"function_format", "SELECT format('hello {0}', name) FROM t", "", false},
		{"column_named_settings", "SELECT settings FROM t", "", false},
		{"select_explain_column", "SELECT explain_col FROM t", "", false},

		// SETTINGS injection — detected by AST
		{"settings_override", "SELECT * FROM events SETTINGS custom_tenant_id='evil'", "SETTINGS", false},
		{"settings_lowercase", "select * from events settings custom_tenant_id = 'x'", "SETTINGS", false},
		{"settings_mixed_case", "SELECT 1 Settings max_threads=2", "SETTINGS", false},

		// FORMAT — detected by AST
		{"format_json", "SELECT * FROM events FORMAT JSON", "FORMAT", false},
		{"format_csv", "SELECT * FROM events FORMAT CSV", "FORMAT", false},
		{"format_lowercase", "select 1 format tabseparated", "FORMAT", false},

		// SET — detected by AST
		{"set_statement", "SET custom_tenant_id = 'evil'", "SET", false},
		{"set_lowercase", "set max_threads = 1", "SET", false},

		// INTO OUTFILE on SELECT — parser does not support this syntax; query is rejected (parse error)
		{"into_outfile_parse_error", "SELECT * FROM events INTO OUTFILE '/tmp/data.csv'", "", true},
		{"into_outfile_lowercase_parse_error", "select 1 into outfile '/tmp/x'", "", true},

		// EXPLAIN — forms the parser understands
		{"explain_ast_select", "EXPLAIN AST SELECT * FROM events", "EXPLAIN", false},
		{"explain_syntax", "EXPLAIN SYNTAX SELECT 1", "EXPLAIN", false},

		// Plain EXPLAIN / EXPLAIN PLAN — parser error; reject without substring heuristics
		{"explain_plan_parse_error", "EXPLAIN PLAN SELECT 1", "", true},
		{"explain_select_parse_error", "EXPLAIN SELECT * FROM events", "", true},
		{"explain_lowercase_parse_error", "explain select 1", "", true},

		// Multi-statement — SET after semicolon (detected by AST)
		{"multi_stmt_set", "SELECT 1; SET max_threads=1", "SET", false},

		// SHOW with INTO OUTFILE — detected by AST
		{"show_outfile", "SHOW DATABASES INTO OUTFILE '/tmp/databases.txt'", "INTO OUTFILE", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := checkBlockedClauses(tc.query, allBlocked)
			if tc.wantParseErr {
				require.Error(t, err, "query: %s", tc.query)
				require.Empty(t, got)
				return
			}
			require.NoError(t, err, "query: %s", tc.query)
			require.Equal(t, tc.wantBlocked, got, "query: %s", tc.query)
		})
	}
}

func TestCheckBlockedClauses_Empty(t *testing.T) {
	clause, err := checkBlockedClauses("SELECT 1 SETTINGS x=1", nil)
	require.NoError(t, err)
	require.Empty(t, clause)
	clause, err = checkBlockedClauses("SET x=1", map[string]bool{})
	require.NoError(t, err)
	require.Empty(t, clause)
}

// TestCheckBlockedClauses_ASTTypeMapping checks that blocking uses parser type
// stems (not a fixed hand-maintained list), so new clause kinds work from config alone.
func TestCheckBlockedClauses_ASTTypeMapping(t *testing.T) {
	t.Parallel()

	t.Run("where_clause", func(t *testing.T) {
		blocked := NormalizeBlockedClauses([]string{"WHERE"})
		clause, err := checkBlockedClauses("SELECT 1 WHERE 1", blocked)
		require.NoError(t, err)
		require.Equal(t, "WHERE", clause)
	})

	t.Run("whereclause_full_type_name", func(t *testing.T) {
		blocked := NormalizeBlockedClauses([]string{"WHERECLAUSE"})
		clause, err := checkBlockedClauses("SELECT 1 WHERE 1", blocked)
		require.NoError(t, err)
		require.Equal(t, "WHERECLAUSE", clause)
	})

	t.Run("having_clause", func(t *testing.T) {
		blocked := NormalizeBlockedClauses([]string{"HAVING"})
		clause, err := checkBlockedClauses("SELECT count() FROM t GROUP BY x HAVING count() > 0", blocked)
		require.NoError(t, err)
		require.Equal(t, "HAVING", clause)
	})

	t.Run("prewhere_not_where", func(t *testing.T) {
		blocked := NormalizeBlockedClauses([]string{"PREWHERE"})
		clause, err := checkBlockedClauses("SELECT * FROM t PREWHERE x = 1", blocked)
		require.NoError(t, err)
		require.Equal(t, "PREWHERE", clause)
	})
}

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

// --- PR 1: unified tools config + dynamic write tool discovery ---

// TestRegisterTools_UnifiedConfig covers the new Tools config path.
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

// TestFilterRulesByType covers the read/write rule splitter.
func TestFilterRulesByType(t *testing.T) {
	t.Parallel()
	rules := []config.DynamicToolRule{
		{Regexp: `^a\..*$`, Type: "read"},
		{Regexp: `^b\..*$`, Type: "write", Mode: "insert"},
		{Regexp: `^c\..*$`}, // no type — defaults to "read"
		{Regexp: `^d\..*$`, Type: "write", Mode: "insert"},
	}
	reads := filterRulesByType(rules, "read")
	writes := filterRulesByType(rules, "write")
	require.Len(t, reads, 2)
	require.Len(t, writes, 2)
}

// TestHasDiscoveryCredentials covers the credential-presence check.
func TestHasDiscoveryCredentials(t *testing.T) {
	t.Parallel()

	t.Run("none_present", func(t *testing.T) {
		t.Parallel()
		s := &ClickHouseJWEServer{}
		require.False(t, s.hasDiscoveryCredentials(context.Background()))
	})

	t.Run("jwe_token_present", func(t *testing.T) {
		t.Parallel()
		s := &ClickHouseJWEServer{}
		ctx := context.WithValue(context.Background(), JWETokenKey, "jwe-abc")
		require.True(t, s.hasDiscoveryCredentials(ctx))
	})

	t.Run("oauth_token_present", func(t *testing.T) {
		t.Parallel()
		s := &ClickHouseJWEServer{}
		ctx := context.WithValue(context.Background(), OAuthTokenKey, "oauth-xyz")
		require.True(t, s.hasDiscoveryCredentials(ctx))
	})

	t.Run("static_username_present", func(t *testing.T) {
		t.Parallel()
		s := &ClickHouseJWEServer{
			Config: config.Config{ClickHouse: config.ClickHouseConfig{Username: "alice"}},
		}
		require.True(t, s.hasDiscoveryCredentials(context.Background()))
	})
}

// TestBuildInsertQuery covers the pure-function INSERT SQL generation —
// quote escaping, validation, unicode, null bytes.
func TestBuildInsertQuery(t *testing.T) {
	t.Parallel()

	mkMeta := func(params ...dynamicToolParam) dynamicToolMeta {
		return dynamicToolMeta{Database: "mydb", Table: "users", Params: params}
	}

	t.Run("basic_string_and_int", func(t *testing.T) {
		t.Parallel()
		meta := mkMeta(
			dynamicToolParam{Name: "id", JSONType: "integer", Required: true},
			dynamicToolParam{Name: "name", JSONType: "string", Required: true},
		)
		q, err := buildInsertQuery(meta, map[string]any{"id": float64(42), "name": "Alice"})
		require.NoError(t, err)
		require.Contains(t, q, "INSERT INTO mydb.users")
		require.Contains(t, q, "id, name")
		require.Contains(t, q, "42")
		require.Contains(t, q, "'Alice'")
	})

	t.Run("required_param_missing", func(t *testing.T) {
		t.Parallel()
		meta := mkMeta(
			dynamicToolParam{Name: "id", JSONType: "integer", Required: true},
			dynamicToolParam{Name: "name", JSONType: "string", Required: true},
		)
		_, err := buildInsertQuery(meta, map[string]any{"id": float64(42)})
		require.Error(t, err)
		require.Contains(t, err.Error(), "name")
	})

	t.Run("optional_param_omitted", func(t *testing.T) {
		t.Parallel()
		meta := mkMeta(
			dynamicToolParam{Name: "id", JSONType: "integer", Required: true},
			dynamicToolParam{Name: "note", JSONType: "string", Required: false},
		)
		q, err := buildInsertQuery(meta, map[string]any{"id": float64(42)})
		require.NoError(t, err)
		require.Contains(t, q, "INSERT INTO mydb.users (id) VALUES (42)")
		require.NotContains(t, q, "note")
	})

	t.Run("no_columns_provided", func(t *testing.T) {
		t.Parallel()
		meta := mkMeta(
			dynamicToolParam{Name: "note", JSONType: "string", Required: false},
		)
		_, err := buildInsertQuery(meta, map[string]any{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "no columns")
	})

	t.Run("quote_escaping_keeps_literal_well_formed", func(t *testing.T) {
		t.Parallel()
		// ClickHouse doesn't support multi-statement queries, so classic
		// stacked-query injection isn't applicable. What we verify: a user
		// quote must be escaped so the whole payload stays inside ONE string
		// literal (balanced outer quotes after escape).
		meta := mkMeta(
			dynamicToolParam{Name: "name", JSONType: "string", Required: true},
		)
		q, err := buildInsertQuery(meta, map[string]any{"name": "it's \"fine\""})
		require.NoError(t, err)
		stripped := strings.ReplaceAll(q, `\\`, "")
		stripped = strings.ReplaceAll(stripped, `\'`, "")
		require.Equal(t, 2, strings.Count(stripped, "'"),
			"expected exactly 2 unescaped single quotes (literal boundaries), got: %s", q)
	})

	t.Run("backslash_escaping", func(t *testing.T) {
		t.Parallel()
		meta := mkMeta(
			dynamicToolParam{Name: "path", JSONType: "string", Required: true},
		)
		q, err := buildInsertQuery(meta, map[string]any{"path": `C:\Users\x`})
		require.NoError(t, err)
		require.Contains(t, q, "INSERT INTO mydb.users")
	})

	t.Run("unicode_values", func(t *testing.T) {
		t.Parallel()
		meta := mkMeta(
			dynamicToolParam{Name: "name", JSONType: "string", Required: true},
		)
		q, err := buildInsertQuery(meta, map[string]any{"name": "日本語 — €"})
		require.NoError(t, err)
		require.Contains(t, q, "日本語 — €")
	})

	t.Run("null_byte_in_string_keeps_literal_well_formed", func(t *testing.T) {
		t.Parallel()
		meta := mkMeta(
			dynamicToolParam{Name: "blob", JSONType: "string", Required: true},
		)
		q, err := buildInsertQuery(meta, map[string]any{"blob": "before\x00after"})
		require.NoError(t, err)
		require.True(t, strings.Count(q, "'")%2 == 0, "unbalanced quotes in: %s", q)
	})

	t.Run("invalid_integer_rejected", func(t *testing.T) {
		t.Parallel()
		meta := mkMeta(
			dynamicToolParam{Name: "id", JSONType: "integer", Required: false},
		)
		_, err := buildInsertQuery(meta, map[string]any{"id": "abc"})
		require.ErrorContains(t, err, "invalid parameter id")
		require.ErrorContains(t, err, "expected integer")
	})

	t.Run("fractional_integer_rejected", func(t *testing.T) {
		t.Parallel()
		meta := mkMeta(
			dynamicToolParam{Name: "id", JSONType: "integer", Required: false},
		)
		_, err := buildInsertQuery(meta, map[string]any{"id": 1.5})
		require.ErrorContains(t, err, "non-integer number")
	})
}

// TestBuildDynamicWriteQuery covers the mode dispatcher.
func TestBuildDynamicWriteQuery(t *testing.T) {
	t.Parallel()
	base := dynamicToolMeta{
		Database: "mydb", Table: "t",
		Params: []dynamicToolParam{{Name: "id", JSONType: "integer", Required: true}},
	}

	t.Run("insert_mode", func(t *testing.T) {
		t.Parallel()
		m := base
		m.WriteMode = "insert"
		q, err := buildDynamicWriteQuery(m, map[string]any{"id": float64(1)})
		require.NoError(t, err)
		require.Contains(t, q, "INSERT INTO mydb.t")
	})

	t.Run("unsupported_mode_rejected", func(t *testing.T) {
		t.Parallel()
		for _, mode := range []string{"update", "upsert", "delete", ""} {
			m := base
			m.WriteMode = mode
			_, err := buildDynamicWriteQuery(m, map[string]any{"id": float64(1)})
			require.Errorf(t, err, "mode=%q should error", mode)
		}
	})
}

// TestBuildWriteToolDescription covers description fallbacks.
func TestBuildWriteToolDescription(t *testing.T) {
	t.Parallel()
	require.Equal(t, "table comment", buildWriteToolDescription("table comment", "db", "t", "insert"))
	require.Equal(t, "Insert data in db.t", buildWriteToolDescription("", "db", "t", "insert"))
	require.Equal(t, "Update data in db.t", buildWriteToolDescription("", "db", "t", "update"))
	require.Equal(t, "Insert or update data in db.t", buildWriteToolDescription("", "db", "t", "upsert"))
}
