package server

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/altinity/altinity-mcp/pkg/clickhouse"
	"github.com/altinity/altinity-mcp/pkg/config"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"
)

// TestHandleExecuteQuery tests the execute_query tool handler
func TestHandleExecuteQuery(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	chConfig := setupClickHouseContainer(t)

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

// TestHelperFunctions tests various helper functions
func TestHelperFunctions(t *testing.T) {
	t.Parallel()
	t.Run("isSelectQuery", func(t *testing.T) {
		t.Parallel()
		require.True(t, clickhouse.IsSelectQuery("SELECT * FROM table"))
		require.True(t, clickhouse.IsSelectQuery("select * from table"))
		require.True(t, clickhouse.IsSelectQuery("WITH cte AS (SELECT 1) SELECT * FROM cte"))
		require.False(t, clickhouse.IsSelectQuery("INSERT INTO table VALUES (1)"))
		require.False(t, clickhouse.IsSelectQuery("CREATE TABLE test (id Int)"))
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
	chConfig := setupClickHouseContainer(t)

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
	chConfig := setupClickHouseContainer(t)

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

// TestTruncateErrForClient covers the error-truncation helper.
func TestTruncateErrForClient(t *testing.T) {
	t.Parallel()

	t.Run("nil_returns_empty", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, "", truncateErrForClient(nil))
	})

	t.Run("short_error_unchanged", func(t *testing.T) {
		t.Parallel()
		err := errors.New("boom")
		require.Equal(t, "boom", truncateErrForClient(err))
	})

	t.Run("long_error_truncated", func(t *testing.T) {
		t.Parallel()
		big := strings.Repeat("x", maxClientErrorLen+500)
		err := errors.New(big)
		out := truncateErrForClient(err)
		require.Less(t, len(out), len(big))
		require.Greater(t, len(out), maxClientErrorLen)
		require.Contains(t, out, "(truncated)")
	})

	t.Run("passes_through_existing_escaper", func(t *testing.T) {
		t.Parallel()
		err := errors.New("quoted 'x'")
		out := truncateErrForClient(err)
		// The function applies ErrJSONEscaper (pre-existing behavior) — we just
		// verify the message is preserved without adding new artifacts.
		require.Equal(t, ErrJSONEscaper.Replace("quoted 'x'"), out)
	})
}

// TestHandleExecuteQuery_MaxQueryLength covers query-size limiting.
func TestHandleExecuteQuery_MaxQueryLength(t *testing.T) {
	t.Parallel()

	callExec := func(t *testing.T, cfg config.Config, query string) *mcp.CallToolResult {
		srv := &ClickHouseJWEServer{Config: cfg}
		ctx := context.WithValue(context.Background(), CHJWEServerKey, srv)
		args, _ := json.Marshal(map[string]any{"query": query})
		req := &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: "execute_query", Arguments: args}}
		res, err := HandleExecuteQuery(ctx, req)
		require.NoError(t, err)
		require.NotNil(t, res)
		return res
	}

	t.Run("within_default_limit_passes_size_check", func(t *testing.T) {
		t.Parallel()
		// With no ClickHouse reachable, the query will fail later — but we only care
		// that it doesn't fail with the length error.
		cfg := config.Config{ClickHouse: config.ClickHouseConfig{Host: "127.0.0.1", Port: 1}}
		res := callExec(t, cfg, "SELECT 1")
		require.True(t, res.IsError)
		require.NotContains(t, textOf(res), "exceeds max length")
	})

	t.Run("oversize_query_rejected_with_default_limit", func(t *testing.T) {
		t.Parallel()
		cfg := config.Config{ClickHouse: config.ClickHouseConfig{}} // default 10MB
		big := "SELECT '" + strings.Repeat("x", 11*1024*1024) + "'"
		res := callExec(t, cfg, big)
		require.True(t, res.IsError)
		require.Contains(t, textOf(res), "exceeds max length")
	})

	t.Run("custom_limit_enforced", func(t *testing.T) {
		t.Parallel()
		cfg := config.Config{ClickHouse: config.ClickHouseConfig{MaxQueryLength: 100}}
		big := strings.Repeat("X", 150)
		res := callExec(t, cfg, "SELECT '"+big+"'")
		require.True(t, res.IsError)
		require.Contains(t, textOf(res), "exceeds max length")
		require.Contains(t, textOf(res), "limit 100")
	})

	t.Run("limit_disabled_with_negative", func(t *testing.T) {
		t.Parallel()
		cfg := config.Config{ClickHouse: config.ClickHouseConfig{
			MaxQueryLength: -1,
			Limit:          0,
			Host:           "127.0.0.1",
			Port:           1,
		}}
		big := strings.Repeat("x", 1024)
		res := callExec(t, cfg, "SELECT '"+big+"'")
		require.True(t, res.IsError)
		require.NotContains(t, textOf(res), "exceeds max length")
		require.Contains(t, textOf(res), "failed to connect to ClickHouse")
	})
}

// TestEffectiveMaxQueryLength covers the config helper.
func TestEffectiveMaxQueryLength(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		set  int
		want int
	}{
		{"zero_uses_default", 0, 10 * 1024 * 1024},
		{"positive_used_as_is", 1024, 1024},
		{"negative_disables", -1, 0},
		{"negative_large", -1000, 0},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := config.ClickHouseConfig{MaxQueryLength: tc.set}
			require.Equal(t, tc.want, c.EffectiveMaxQueryLength())
		})
	}
}

func TestHandleExecuteQueryE2E(t *testing.T) {
	t.Parallel()
	chConfig := setupClickHouseContainer(t)

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
