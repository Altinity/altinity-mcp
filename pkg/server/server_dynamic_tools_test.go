package server

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/altinity/altinity-mcp/pkg/clickhouse"
	"github.com/altinity/altinity-mcp/pkg/config"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"
)

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

func TestIsNullableCHType(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want bool
	}{
		{"Nullable(String)", true},
		{"Nullable(UInt64)", true},
		{"  nullable(DateTime)  ", true},
		{"NULLABLE(Int64)", true},
		{"String", false},
		{"UInt64", false},
		{"LowCardinality(Nullable(String))", false}, // outer wrapper isn't Nullable
		{"", false},
	}
	for _, c := range cases {
		require.Equalf(t, c.want, isNullableCHType(c.in), "input=%q", c.in)
	}
}

func TestDynamicToolInputSchema(t *testing.T) {
	t.Parallel()
	t.Run("strict_mode_fields_always_emitted", func(t *testing.T) {
		t.Parallel()
		schema := dynamicToolInputSchema(map[string]any{"x": map[string]any{"type": "string"}}, []string{"x"})
		require.Equal(t, "object", schema["type"])
		require.Equal(t, false, schema["additionalProperties"], "schema must pin the property set")
		require.Equal(t, []string{"x"}, schema["required"])
	})
	t.Run("empty_required_is_explicit", func(t *testing.T) {
		t.Parallel()
		// Anthropic's strict-mode validator accepts an empty `required`
		// array but not a missing key for some tool-discovery code paths;
		// emit it explicitly.
		schema := dynamicToolInputSchema(map[string]any{}, []string{})
		require.Contains(t, schema, "required")
		require.Equal(t, []string{}, schema["required"])
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
	t.Run("fallback_to_name_and_chtype_when_empty", func(t *testing.T) {
		t.Parallel()
		// Bare CH type (e.g. "String") read as garbage in claude.ai's tool
		// browser; fall back to "<name> (<type>)" so the param has at least
		// a self-describing label.
		p := dynamicToolParam{Name: "uid", CHType: "UInt64", JSONType: "integer"}
		schema := buildParamSchema(p)
		require.Equal(t, "uid (UInt64)", schema["description"])
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
