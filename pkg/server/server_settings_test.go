package server

import (
	"context"
	"testing"

	"github.com/altinity/altinity-mcp/pkg/config"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"
)

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
