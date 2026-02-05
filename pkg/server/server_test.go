package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
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
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// generateJWEToken is a helper to create JWE tokens for testing.
func generateJWEToken(t *testing.T, claims map[string]interface{}, jweSecretKey []byte, jwtSecretKey []byte) string {
	token, err := jwe_auth.GenerateJWEToken(claims, jweSecretKey, jwtSecretKey)
	require.NoError(t, err)
	return token
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
		if err := chContainer.Terminate(context.Background()); err != nil {
			t.Logf("Failed to terminate container: %v", err)
		}
	})

	host, err := chContainer.Host(ctx)
	require.NoError(t, err)

	port, err := chContainer.MappedPort(ctx, "8123")
	require.NoError(t, err)

	chConfig := &config.ClickHouseConfig{
		Host:     host,
		Port:     port.Int(),
		Database: "default",
		Username: "default",
		Protocol: config.HTTPProtocol,
	}

	// Create a client to test the connection and create test tables
	client, err := clickhouse.NewClient(ctx, *chConfig)
	require.NoError(t, err)

	// Create a test table
	_, err = client.ExecuteQuery(ctx, `CREATE TABLE IF NOT EXISTS default.test (
		id UInt64,
		name String,
		created_at DateTime
	) ENGINE = MergeTree() ORDER BY id`)
	require.NoError(t, err)

	// Insert some test data
	_, err = client.ExecuteQuery(ctx, `INSERT INTO default.test VALUES (1, 'test1', now()), (2, 'test2', now())`)
	require.NoError(t, err)

	// Close the client after setup
	err = client.Close()
	require.NoError(t, err)

	return chConfig
}

// TestOpenAPIHandlers tests the OpenAPI handlers
func TestOpenAPIHandlers(t *testing.T) {
	chConfig := setupClickHouseContainer(t)

	t.Run("serves_openapi_schema", func(t *testing.T) {
		srv := NewClickHouseMCPServer(config.Config{
			ClickHouse: *chConfig,
			Server:     config.ServerConfig{JWE: config.JWEConfig{Enabled: false}},
		}, "test")

		req := httptest.NewRequest(http.MethodGet, "/openapi", nil)
		req = req.WithContext(context.WithValue(req.Context(), "clickhouse_jwe_server", srv))

		rr := httptest.NewRecorder()
		srv.ServeOpenAPISchema(rr, req)

		require.Equal(t, http.StatusOK, rr.Code)
		require.Contains(t, rr.Header().Get("Content-Type"), "application/json")

		var schema map[string]interface{}
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &schema))
		require.Equal(t, "3.1.0", schema["openapi"])
	})

	t.Run("execute_query_via_openapi", func(t *testing.T) {
		srv := NewClickHouseMCPServer(config.Config{
			ClickHouse: *chConfig,
			Server:     config.ServerConfig{JWE: config.JWEConfig{Enabled: false}},
		}, "test")

		req := httptest.NewRequest(http.MethodGet, "/openapi/execute_query?query=SELECT%201", nil)
		req = req.WithContext(context.WithValue(req.Context(), "clickhouse_jwe_server", srv))

		rr := httptest.NewRecorder()
		srv.OpenAPIHandler(rr, req)

		require.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("execute_query_with_limit", func(t *testing.T) {
		srv := NewClickHouseMCPServer(config.Config{
			ClickHouse: *chConfig,
			Server:     config.ServerConfig{JWE: config.JWEConfig{Enabled: false}},
		}, "test")

		req := httptest.NewRequest(http.MethodGet, "/openapi/execute_query?query=SELECT%20*%20FROM%20default.test&limit=1", nil)
		req = req.WithContext(context.WithValue(req.Context(), "clickhouse_jwe_server", srv))

		rr := httptest.NewRecorder()
		srv.OpenAPIHandler(rr, req)

		require.Equal(t, http.StatusOK, rr.Code)
		var qr clickhouse.QueryResult
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &qr))
		require.Equal(t, 1, qr.Count)
	})

	t.Run("execute_query_missing_param", func(t *testing.T) {
		srv := NewClickHouseMCPServer(config.Config{
			ClickHouse: *chConfig,
			Server:     config.ServerConfig{JWE: config.JWEConfig{Enabled: false}},
		}, "test")

		req := httptest.NewRequest(http.MethodGet, "/openapi/execute_query", nil)
		req = req.WithContext(context.WithValue(req.Context(), "clickhouse_jwe_server", srv))

		rr := httptest.NewRecorder()
		srv.OpenAPIHandler(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("jwe_required_but_missing", func(t *testing.T) {
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
		req = req.WithContext(context.WithValue(req.Context(), "clickhouse_jwe_server", srv))

		rr := httptest.NewRecorder()
		srv.OpenAPIHandler(rr, req)

		require.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("dynamic_tool_execution", func(t *testing.T) {
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
		req = req.WithContext(context.WithValue(req.Context(), "clickhouse_jwe_server", srv))

		rr := httptest.NewRecorder()
		srv.OpenAPIHandler(rr, req)

		require.Equal(t, http.StatusOK, rr.Code)
		var qr clickhouse.QueryResult
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &qr))
		require.GreaterOrEqual(t, qr.Count, 1)
	})

	t.Run("dynamic_tool_not_found", func(t *testing.T) {
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
		req = req.WithContext(context.WithValue(req.Context(), "clickhouse_jwe_server", srv))

		rr := httptest.NewRecorder()
		srv.OpenAPIHandler(rr, req)

		require.Equal(t, http.StatusNotFound, rr.Code)
	})

	t.Run("dynamic_tool_invalid_json", func(t *testing.T) {
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
		req = req.WithContext(context.WithValue(req.Context(), "clickhouse_jwe_server", srv))

		rr := httptest.NewRecorder()
		srv.OpenAPIHandler(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
	})
}

// TestNewClickHouseMCPServer tests that the server can be created with various configs
func TestNewClickHouseMCPServer(t *testing.T) {
	t.Run("creates_server_with_defaults", func(t *testing.T) {
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
	ctx := context.Background()
	chConfig := setupClickHouseContainer(t)

	srv := NewClickHouseMCPServer(config.Config{
		ClickHouse: *chConfig,
		Server:     config.ServerConfig{JWE: config.JWEConfig{Enabled: false}},
	}, "test")

	// Add server to context
	ctx = context.WithValue(ctx, "clickhouse_jwe_server", srv)

	t.Run("successful_select", func(t *testing.T) {
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
	ctx := context.Background()
	chConfig := setupClickHouseContainer(t)

	srv := NewClickHouseMCPServer(config.Config{
		ClickHouse: *chConfig,
		Server:     config.ServerConfig{JWE: config.JWEConfig{Enabled: false}},
	}, "test")

	ctx = context.WithValue(ctx, "clickhouse_jwe_server", srv)

	t.Run("returns_schema", func(t *testing.T) {
		result, err := HandleSchemaResource(ctx, &mcp.ReadResourceRequest{Params: &mcp.ReadResourceParams{}})
		require.NoError(t, err)
		require.NotNil(t, result)
		require.Len(t, result.Contents, 1)
		require.Equal(t, "clickhouse://schema", result.Contents[0].URI)
		require.Equal(t, "application/json", result.Contents[0].MIMEType)
		require.NotEmpty(t, result.Contents[0].Text)
	})

	t.Run("no_server_in_context", func(t *testing.T) {
		_, err := HandleSchemaResource(context.Background(), &mcp.ReadResourceRequest{Params: &mcp.ReadResourceParams{}})
		require.Error(t, err)
	})
}

// TestHandleTableResource tests the table resource handler
func TestHandleTableResource(t *testing.T) {
	ctx := context.Background()
	chConfig := setupClickHouseContainer(t)

	srv := NewClickHouseMCPServer(config.Config{
		ClickHouse: *chConfig,
		Server:     config.ServerConfig{JWE: config.JWEConfig{Enabled: false}},
	}, "test")

	ctx = context.WithValue(ctx, "clickhouse_jwe_server", srv)

	t.Run("returns_table_structure", func(t *testing.T) {
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
		req := &mcp.ReadResourceRequest{
			Params: &mcp.ReadResourceParams{URI: "invalid://uri"},
		}

		_, err := HandleTableResource(ctx, req)
		require.Error(t, err)
	})

	t.Run("no_server_in_context", func(t *testing.T) {
		req := &mcp.ReadResourceRequest{
			Params: &mcp.ReadResourceParams{URI: "clickhouse://table/default/test"},
		}

		_, err := HandleTableResource(context.Background(), req)
		require.Error(t, err)
	})
}

// TestJWEAuthentication tests JWE authentication flow
func TestJWEAuthentication(t *testing.T) {
	ctx := context.Background()
	chConfig := setupClickHouseContainer(t)

	jweSecretKey := "this-is-a-32-byte-secret-key!!"
	jwtSecretKey := "test-jwt-secret-key-123"

	t.Run("valid_jwe_token", func(t *testing.T) {
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

		ctx = context.WithValue(ctx, "clickhouse_jwe_server", srv)
		ctx = context.WithValue(ctx, "jwe_token", token)

		client, err := srv.GetClickHouseClient(ctx, token)
		require.NoError(t, err)
		require.NotNil(t, client)
		require.NoError(t, client.Close())
	})

	t.Run("missing_token_when_jwe_enabled", func(t *testing.T) {
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
	srv := &ClickHouseJWEServer{}

	t.Run("bearer_token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer test-token")

		token := srv.ExtractTokenFromRequest(req)
		require.Equal(t, "test-token", token)
	})

	t.Run("basic_token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Basic test-token")

		token := srv.ExtractTokenFromRequest(req)
		require.Equal(t, "test-token", token)
	})

	t.Run("x_altinity_mcp_key_header", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("x-altinity-mcp-key", "header-token")

		token := srv.ExtractTokenFromRequest(req)
		require.Equal(t, "header-token", token)
	})

	t.Run("from_url_path", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/my-token/openapi", nil)

		token := srv.ExtractTokenFromRequest(req)
		require.Equal(t, "my-token", token)
	})

	t.Run("no_token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)

		token := srv.ExtractTokenFromRequest(req)
		require.Empty(t, token)
	})
}

// TestExtractTokenFromCtx tests token extraction from context
func TestExtractTokenFromCtx(t *testing.T) {
	srv := &ClickHouseJWEServer{}

	t.Run("with_token", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), "jwe_token", "test-token")
		token := srv.ExtractTokenFromCtx(ctx)
		require.Equal(t, "test-token", token)
	})

	t.Run("no_token", func(t *testing.T) {
		token := srv.ExtractTokenFromCtx(context.Background())
		require.Empty(t, token)
	})

	t.Run("wrong_type", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), "jwe_token", 123)
		token := srv.ExtractTokenFromCtx(ctx)
		require.Empty(t, token)
	})
}

// TestHelperFunctions tests various helper functions
func TestHelperFunctions(t *testing.T) {
	t.Run("isSelectQuery", func(t *testing.T) {
		require.True(t, isSelectQuery("SELECT * FROM table"))
		require.True(t, isSelectQuery("select * from table"))
		require.True(t, isSelectQuery("WITH cte AS (SELECT 1) SELECT * FROM cte"))
		require.False(t, isSelectQuery("INSERT INTO table VALUES (1)"))
		require.False(t, isSelectQuery("CREATE TABLE test (id Int)"))
	})

	t.Run("hasLimitClause", func(t *testing.T) {
		require.True(t, hasLimitClause("SELECT * FROM table LIMIT 100"))
		require.True(t, hasLimitClause("select * from table limit 50"))
		require.False(t, hasLimitClause("SELECT * FROM table"))
		require.False(t, hasLimitClause("SELECT * FROM table ORDER BY id"))
	})

	t.Run("snakeCase", func(t *testing.T) {
		require.Equal(t, "db_view", snakeCase("DB.View"))
		require.Equal(t, "custom_db_view", snakeCase("custom DB-View"))
		require.Equal(t, "a_b_c", snakeCase("A B  C"))
	})

	t.Run("sqlLiteral", func(t *testing.T) {
		// integer
		require.Equal(t, "42", sqlLiteral("integer", float64(42)))
		require.Equal(t, "0", sqlLiteral("integer", "oops"))
		// number
		require.Equal(t, "3.14", sqlLiteral("number", float64(3.14)))
		// boolean
		require.Equal(t, "1", sqlLiteral("boolean", true))
		require.Equal(t, "0", sqlLiteral("boolean", false))
		// string
		out := sqlLiteral("string", "a'b c")
		require.Contains(t, out, "'")
	})

	t.Run("buildDescription", func(t *testing.T) {
		require.Equal(t, "My desc", buildDescription("My desc", "db", "view"))
		require.Equal(t, "Tool to load data from db.view", buildDescription("", "db", "view"))
	})
}

// TestDynamicTools_ParamParsingAndTypeMapping tests dynamic tool parameter parsing
func TestDynamicTools_ParamParsingAndTypeMapping(t *testing.T) {
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
	s := &ClickHouseJWEServer{
		Config:  config.Config{},
		Version: "test",
		dynamicTools: map[string]dynamicToolMeta{
			"custom_db_view": {
				ToolName:    "custom_db_view",
				Database:    "db",
				Table:       "view",
				Description: "desc",
				Params:      []dynamicToolParam{{Name: "id", CHType: "UInt64", JSONType: "integer", JSONFormat: "int64", Required: true}},
			},
		},
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/openapi", nil)
	ctx := context.WithValue(req.Context(), "clickhouse_jwe_server", s)
	req = req.WithContext(ctx)
	s.ServeOpenAPISchema(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)

	var schema map[string]interface{}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &schema))
	paths := schema["paths"].(map[string]interface{})
	_, ok := paths["/{jwe_token}/openapi/custom_db_view"]
	require.True(t, ok)
}

// TestResourceHandlers_NoServerInContext tests error handling when server is missing from context
func TestResourceHandlers_NoServerInContext(t *testing.T) {
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

// TestMakeDynamicToolHandler_WithClickHouse tests dynamic tool handler with actual ClickHouse
func TestMakeDynamicToolHandler_WithClickHouse(t *testing.T) {
	ctx := context.Background()
	chConfig := setupClickHouseContainer(t)

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
	ctx = context.WithValue(ctx, "clickhouse_jwe_server", s)
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
	ctx := context.Background()
	chConfig := setupClickHouseContainer(t)
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
	ctx := context.Background()
	chConfig := setupClickHouseContainer(t)
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
	req = req.WithContext(context.WithValue(req.Context(), "clickhouse_jwe_server", s))
	s.OpenAPIHandler(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	var qr clickhouse.QueryResult
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &qr))
	require.GreaterOrEqual(t, qr.Count, 1)
}

// TestHandleDynamicToolOpenAPI_Errors tests error cases for dynamic tool OpenAPI
func TestHandleDynamicToolOpenAPI_Errors(t *testing.T) {
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
	req = req.WithContext(context.WithValue(req.Context(), "clickhouse_jwe_server", s))
	rr := httptest.NewRecorder()
	s.OpenAPIHandler(rr, req)
	require.Equal(t, http.StatusUnauthorized, rr.Code)

	// Use disabled JWE to test JSON decode and required params
	s.Config.Server.JWE.Enabled = false

	// invalid JSON body
	req = httptest.NewRequest(http.MethodPost, "/openapi/tool", strings.NewReader("not-json"))
	req = req.WithContext(context.WithValue(req.Context(), "clickhouse_jwe_server", s))
	rr = httptest.NewRecorder()
	s.OpenAPIHandler(rr, req)
	require.Equal(t, http.StatusBadRequest, rr.Code)

	// Unknown tool -> 404
	req = httptest.NewRequest(http.MethodPost, "/openapi/unknown_tool", strings.NewReader(`{"id":1}`))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), "clickhouse_jwe_server", s))
	rr = httptest.NewRecorder()
	s.OpenAPIHandler(rr, req)
	require.Equal(t, http.StatusNotFound, rr.Code)
}

// TestLazyLoading_OpenAPISchema tests lazy loading of dynamic tools via OpenAPI
func TestLazyLoading_OpenAPISchema(t *testing.T) {
	ctx := context.Background()
	chConfig := setupClickHouseContainer(t)

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
	_, ok = paths["/{jwe_token}/openapi/lazy_default_v_lazy"]
	require.True(t, ok)
}

// TestLazyLoading_MCPTools tests lazy loading of dynamic tools via MCP
func TestLazyLoading_MCPTools(t *testing.T) {
	ctx := context.Background()
	chConfig := setupClickHouseContainer(t)

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
	result := NewToolResultError("error message")
	require.NotNil(t, result)
	require.Len(t, result.Content, 1)
	require.True(t, result.IsError)

	textContent, ok := result.Content[0].(*mcp.TextContent)
	require.True(t, ok)
	require.Equal(t, "error message", textContent.Text)
}

// Unused import suppressors (remove if unused)
var _ = io.EOF
var _ = fmt.Sprintf
