package server

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/altinity/altinity-mcp/pkg/config"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/rs/zerolog/log"
)

// blockedSettings contains ClickHouse settings that must never be overridden
// via tool_input_settings to prevent privilege escalation or DoS.
var blockedSettings = map[string]bool{
	"readonly":                      true,
	"allow_ddl":                     true,
	"allow_introspection_functions": true,
	"max_execution_time":            true,
	"max_memory_usage":              true,
	"max_result_rows":               true,
	"max_result_bytes":              true,
	"max_rows_to_read":              true,
	"max_bytes_to_read":             true,
	"password":                      true,
	"user":                          true,
	"database":                      true,
}

// mergeExtraSettings copies per-request settings into a ClickHouseConfig,
// returning a shallow copy with ExtraSettings populated. Neither input is mutated.
func mergeExtraSettings(cfg config.ClickHouseConfig, settings map[string]string) config.ClickHouseConfig {
	merged := make(map[string]string, len(cfg.ExtraSettings)+len(settings))
	for k, v := range cfg.ExtraSettings {
		merged[k] = v
	}
	for k, v := range settings {
		merged[k] = v
	}
	cfg.ExtraSettings = merged
	return cfg
}

// --- tool_input_settings: allow tool callers to pass ClickHouse settings via arguments ---

const toolInputSettingsKey contextKey = "tool_input_settings"

// ValidateToolInputSettings checks the allowlist at startup and returns an error
// if any entry targets a blocked ClickHouse setting. Logs a warning when a
// setting does not start with "custom_".
func ValidateToolInputSettings(settings []string) error {
	warnings, err := validateToolInputSettings(settings)
	for _, w := range warnings {
		log.Warn().Msg(w)
	}
	return err
}

// validateToolInputSettings is the testable core: returns (warnings, error).
func validateToolInputSettings(settings []string) (warnings []string, err error) {
	seen := make(map[string]bool, len(settings))
	for _, setting := range settings {
		lower := strings.ToLower(setting)
		if blockedSettings[lower] {
			return nil, fmt.Errorf("tool_input_settings: setting %q is blocked", setting)
		}
		if seen[lower] {
			return nil, fmt.Errorf("tool_input_settings: duplicate setting %q", setting)
		}
		seen[lower] = true
		if !strings.HasPrefix(lower, "custom_") {
			warnings = append(warnings, fmt.Sprintf(
				"tool_input_settings: setting %q does not start with 'custom_'; ensure custom_settings_prefixes is configured on ClickHouse",
				setting,
			))
		}
	}
	return warnings, nil
}

// buildToolInputSettingsSchema returns the JSON Schema fragment for the
// "settings" tool parameter, or nil when no settings are configured.
func buildToolInputSettingsSchema(settings []string) map[string]any {
	if len(settings) == 0 {
		return nil
	}
	props := make(map[string]any, len(settings))
	for _, s := range settings {
		props[s] = map[string]any{"type": "string"}
	}
	return map[string]any{
		"type":                 "object",
		"description":          fmt.Sprintf("Optional ClickHouse settings to apply to this query. Allowed: %s", strings.Join(settings, ", ")),
		"properties":           props,
		"additionalProperties": false,
	}
}

// ContextWithToolInputSettings stores per-request ClickHouse settings
// extracted from MCP tool arguments into context.
func ContextWithToolInputSettings(ctx context.Context, settings map[string]string) context.Context {
	return context.WithValue(ctx, toolInputSettingsKey, settings)
}

// ToolInputSettingsFromContext retrieves per-request ClickHouse settings
// previously stored by ContextWithToolInputSettings. Returns nil when none.
func ToolInputSettingsFromContext(ctx context.Context) map[string]string {
	if settings, ok := ctx.Value(toolInputSettingsKey).(map[string]string); ok {
		return settings
	}
	return nil
}

// applyToolInputSettings extracts and validates tool-input settings from MCP
// tool arguments and stores them in context. Returns an error tool result
// if validation fails.
func applyToolInputSettings(ctx context.Context, arguments map[string]any, allowlist []string) (context.Context, *mcp.CallToolResult) {
	settings, err := extractToolInputSettings(arguments, allowlist)
	if err != nil {
		return ctx, NewToolResultError(fmt.Sprintf("Invalid settings: %v", err))
	}
	if settings != nil {
		ctx = ContextWithToolInputSettings(ctx, settings)
	}
	return ctx, nil
}

// extractToolInputSettings parses the "settings" key from tool arguments,
// validates each entry against the admin-configured allowlist and the
// blockedSettings denylist, and returns the resulting map.
func extractToolInputSettings(arguments map[string]any, allowlist []string) (map[string]string, error) {
	settingsRaw, ok := arguments["settings"]
	if !ok {
		return nil, nil
	}
	settingsMap, ok := settingsRaw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("settings must be an object")
	}
	if len(settingsMap) == 0 {
		return nil, nil
	}
	allowSet := make(map[string]bool, len(allowlist))
	for _, s := range allowlist {
		allowSet[s] = true
	}
	settings := make(map[string]string, len(settingsMap))
	for k, v := range settingsMap {
		if !allowSet[k] {
			return nil, fmt.Errorf("setting %q is not allowed; allowed settings: %s", k, strings.Join(allowlist, ", "))
		}
		if blockedSettings[strings.ToLower(k)] {
			return nil, fmt.Errorf("setting %q is blocked", k)
		}
		strVal, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("setting %q value must be a string", k)
		}
		settings[k] = strVal
	}
	names := make([]string, 0, len(settings))
	for k := range settings {
		names = append(names, k)
	}
	sort.Strings(names)
	log.Debug().Int("count", len(settings)).Strs("setting_names", names).Msg("tool input settings extracted from arguments")
	return settings, nil
}
