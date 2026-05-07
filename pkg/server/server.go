package server

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/altinity/altinity-mcp/pkg/clickhouse"
	"github.com/altinity/altinity-mcp/pkg/config"
	"github.com/altinity/altinity-mcp/pkg/oauth_state"
	"github.com/go-jose/go-jose/v4"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/rs/zerolog/log"
)

// ClickHouseJWEServer extends MCPServer with JWE auth capabilities
type ClickHouseJWEServer struct {
	MCPServer *mcp.Server
	Config    config.Config
	Version   string
	// dynamic tools metadata for OpenAPI routing and schema
	dynamicTools     map[string]dynamicToolMeta
	dynamicToolsMu   sync.RWMutex
	dynamicToolsInit bool
	// JWKS cache for OAuth token validation
	jwksCache          jose.JSONWebKeySet
	jwksCacheURL       string
	jwksCacheMu        sync.RWMutex
	jwksCacheTime      time.Time
	oidcConfigCache    OpenIDConfiguration
	oidcConfigCacheURL string
	oidcConfigMu       sync.RWMutex
	oidcConfigTime     time.Time
	blockedClauses     map[string]bool

	// refreshStateStore is non-nil only when oauth.refresh_revokes_tracking
	// is enabled (H-2). Constructed in NewClickHouseMCPServer; consumed by
	// the gating-mode refresh handler.
	refreshStateStore oauth_state.Store
}

// ToolHandlerFunc is a function type for tool handlers
type ToolHandlerFunc func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error)

// ResourceHandlerFunc is a function type for resource handlers
type ResourceHandlerFunc func(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error)

// PromptHandlerFunc is a function type for prompt handlers
type PromptHandlerFunc func(ctx context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error)

// AltinityMCPServer interface for registering tools, resources and prompts
type AltinityMCPServer interface {
	AddTool(tool *mcp.Tool, handler ToolHandlerFunc)
	AddResource(resource *mcp.Resource, handler ResourceHandlerFunc)
	AddResourceTemplate(template *mcp.ResourceTemplate, handler ResourceHandlerFunc)
	AddPrompt(prompt *mcp.Prompt, handler PromptHandlerFunc)
}

// NewClickHouseMCPServer creates a new MCP server with ClickHouse integration
func NewClickHouseMCPServer(cfg config.Config, version string) *ClickHouseJWEServer {
	// Create MCP server with comprehensive configuration
	opts := &mcp.ServerOptions{
		Instructions: "Altinity ClickHouse MCP Server - A Model Context Protocol server for interacting with ClickHouse databases",
		HasTools:     true,
		HasResources: true,
		HasPrompts:   true,
	}

	srv := mcp.NewServer(&mcp.Implementation{
		Name:    "Altinity ClickHouse MCP Server",
		Version: version,
	}, opts)

	chJweServer := &ClickHouseJWEServer{
		MCPServer:      srv,
		Config:         cfg,
		Version:        version,
		dynamicTools:   make(map[string]dynamicToolMeta),
		blockedClauses: NormalizeBlockedClauses(cfg.Server.BlockedQueryClauses),
	}

	if cfg.Server.OAuth.IsGatingMode() && cfg.Server.OAuth.RefreshRevokesTracking {
		chJweServer.refreshStateStore = oauth_state.NewClickHouseStore(
			func(ctx context.Context) (oauth_state.CHClient, error) {
				return chJweServer.GetClickHouseSystemClient(ctx)
			},
		)
	}

	// Register tools, resources, and prompts.
	// Pass pointer to the server's Config so RegisterTools can store converted
	// dynamic-tool rules back into Config.Server.DynamicTools for EnsureDynamicTools
	// to consume later.
	RegisterTools(chJweServer, &chJweServer.Config)
	// dynamic tools registered lazily via EnsureDynamicTools
	RegisterResources(chJweServer)
	RegisterPrompts(chJweServer)

	log.Info().
		Bool("jwe_enabled", cfg.Server.JWE.Enabled).
		Bool("read_only", cfg.ClickHouse.ReadOnly).
		Int("default_limit", cfg.ClickHouse.Limit).
		Str("version", version).
		Msg("ClickHouse MCP server initialized with tools, resources, and prompts")

	return chJweServer
}

// RefreshStateStore returns the H-2 reuse-detection store, or nil when
// oauth.refresh_revokes_tracking is disabled.
func (s *ClickHouseJWEServer) RefreshStateStore() oauth_state.Store {
	return s.refreshStateStore
}

// SetRefreshStateStore overrides the H-2 store (test-only). Tests inject a
// fake or in-memory implementation to exercise the refresh handler's
// control flow without standing up a ClickHouse harness.
func (s *ClickHouseJWEServer) SetRefreshStateStore(store oauth_state.Store) {
	s.refreshStateStore = store
}

// AddTool registers a tool with the MCP server
func (s *ClickHouseJWEServer) AddTool(tool *mcp.Tool, handler ToolHandlerFunc) {
	s.MCPServer.AddTool(tool, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return handler(ctx, req)
	})
}

// AddResource registers a resource with the MCP server
func (s *ClickHouseJWEServer) AddResource(resource *mcp.Resource, handler ResourceHandlerFunc) {
	s.MCPServer.AddResource(resource, func(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		return handler(ctx, req)
	})
}

// AddResourceTemplate registers a resource template with the MCP server
func (s *ClickHouseJWEServer) AddResourceTemplate(template *mcp.ResourceTemplate, handler ResourceHandlerFunc) {
	s.MCPServer.AddResourceTemplate(template, func(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		return handler(ctx, req)
	})
}

// AddPrompt registers a prompt with the MCP server
func (s *ClickHouseJWEServer) AddPrompt(prompt *mcp.Prompt, handler PromptHandlerFunc) {
	s.MCPServer.AddPrompt(prompt, func(ctx context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
		return handler(ctx, req)
	})
}

// ErrJSONEscaper replacing for resolve OpenAI MCP wrong handling single quote and backtick characters in error message
// look details in https://github.com/Altinity/altinity-mcp/issues/19
var ErrJSONEscaper = strings.NewReplacer("'", "\u0027", "`", "\u0060")

// maxClientErrorLen caps error messages returned to MCP clients.
// ClickHouse errors can include full SQL + stack traces that exceed tens of KB.
// The full error is always logged server-side; clients only need enough to
// understand what went wrong.
const maxClientErrorLen = 2000

// truncateErrForClient returns a client-safe error message from err, applying
// JSON-safe escaping and truncating to maxClientErrorLen characters.
func truncateErrForClient(err error) string {
	if err == nil {
		return ""
	}
	msg := ErrJSONEscaper.Replace(err.Error())
	if len(msg) > maxClientErrorLen {
		msg = msg[:maxClientErrorLen] + "… (truncated)"
	}
	return msg
}

// RegisterTools adds ClickHouse tools to the MCP server. It accepts either
// the new unified Tools configuration or the legacy DynamicTools form
// (deprecated; converted automatically with a warning). With no config,
// it registers execute_query (read-only) and write_query (destructive)
// as defaults.
//
// cfg is a pointer because converted dynamic-tool rules are stored back
// into cfg.Server.DynamicTools so EnsureDynamicTools can discover them
// later on the first authenticated request.
func RegisterTools(srv AltinityMCPServer, cfg *config.Config) {
	toolsToRegister := resolveToolDefinitions(cfg)

	staticToolCount := 0
	dynamicRules := make([]config.ToolDefinition, 0, len(toolsToRegister))

	for _, td := range toolsToRegister {
		if td.Type != "read" && td.Type != "write" {
			log.Error().Str("type", td.Type).Msg("Invalid tool type, must be 'read' or 'write'")
			continue
		}

		isDynamic := td.ViewRegexp != "" || td.TableRegexp != ""
		switch {
		case td.Name != "" && !isDynamic:
			// Static tool: bound to a known name.
			if registerStaticTool(srv, td, &cfg.Server, cfg.ClickHouse.ReadOnly) {
				staticToolCount++
			}
		case isDynamic:
			// Dynamic tool: discovered from ClickHouse metadata at first use.
			if td.Type == "write" {
				if td.TableRegexp == "" {
					log.Error().Str("view_regexp", td.ViewRegexp).Msg("Write tool must use table_regexp, not view_regexp")
					continue
				}
				if td.Mode == "" {
					log.Error().Str("table_regexp", td.TableRegexp).Msg("Write tool must specify mode (only 'insert' is supported)")
					continue
				}
				if td.Mode != "insert" {
					log.Error().Str("table_regexp", td.TableRegexp).Str("mode", td.Mode).Msg("Write tool mode not supported (only 'insert' is implemented); skipping")
					continue
				}
			}
			if td.Type == "read" && td.TableRegexp != "" {
				log.Error().Str("table_regexp", td.TableRegexp).Msg("Read tool must use view_regexp, not table_regexp")
				continue
			}
			dynamicRules = append(dynamicRules, td)
		default:
			log.Error().Str("name", td.Name).Str("view_regexp", td.ViewRegexp).Str("table_regexp", td.TableRegexp).Msg("Tool definition must have either name (static) or view_regexp/table_regexp (dynamic)")
		}
	}

	// Stash dynamic rules in the legacy slice that EnsureDynamicTools reads.
	cfg.Server.DynamicTools = convertToDynamicToolRules(dynamicRules)

	log.Info().
		Int("static_tool_count", staticToolCount).
		Int("dynamic_tool_rules", len(dynamicRules)).
		Msg("ClickHouse tools registered")
}

// resolveToolDefinitions picks the source of tool definitions from config:
// the new unified Tools array, the legacy DynamicTools slice (with a
// deprecation warning), or a sensible default (execute_query + write_query).
func resolveToolDefinitions(cfg *config.Config) []config.ToolDefinition {
	if len(cfg.Server.Tools) > 0 {
		return cfg.Server.Tools
	}
	if len(cfg.Server.DynamicTools) > 0 {
		log.Warn().Msg("dynamic_tools config is deprecated, use tools instead")
		out := make([]config.ToolDefinition, 0, len(cfg.Server.DynamicTools))
		for _, old := range cfg.Server.DynamicTools {
			td := config.ToolDefinition{
				Type:   old.Type,
				Name:   old.Name,
				Prefix: old.Prefix,
				Mode:   old.Mode,
			}
			// Legacy DynamicToolRule entries had no Type; they described view-based read tools.
			if td.Type == "" && old.Regexp != "" {
				td.Type = "read"
			}
			// Route the legacy regexp to the correct typed field.
			if td.Type == "write" {
				td.TableRegexp = old.Regexp
			} else {
				td.ViewRegexp = old.Regexp
			}
			out = append(out, td)
		}
		return out
	}
	return []config.ToolDefinition{
		{Type: "read", Name: "execute_query"},
		{Type: "write", Name: "write_query"},
	}
}

// registerStaticTool registers one of the supported static tools ("execute_query"
// or "write_query"). Returns true if the tool was actually added to srv.
func registerStaticTool(srv AltinityMCPServer, td config.ToolDefinition, srvCfg *config.ServerConfig, readOnly bool) bool {
	switch td.Type {
	case "read":
		if td.Name == "execute_query" {
			srv.AddTool(buildExecuteQueryTool(srvCfg), HandleReadOnlyQuery)
			log.Info().Str("tool", "execute_query").Msg("Static read tool registered")
			return true
		}
		log.Warn().Str("tool_name", td.Name).Msg("Unknown static read tool name")
		return false

	case "write":
		if td.Name == "write_query" {
			if readOnly {
				log.Info().Str("tool", "write_query").Msg("Write tool skipped (read-only mode)")
				return false
			}
			srv.AddTool(buildWriteQueryTool(srvCfg), HandleExecuteQuery)
			log.Info().Str("tool", "write_query").Msg("Static write tool registered")
			return true
		}
		log.Warn().Str("tool_name", td.Name).Msg("Unknown static write tool name")
		return false

	default:
		log.Error().Str("type", td.Type).Msg("Unknown static tool type")
		return false
	}
}

// buildExecuteQueryTool builds the execute_query tool definition. execute_query
// is ALWAYS read-only (regardless of the server's read-only flag); it rejects
// non-SELECT statements at call time via HandleReadOnlyQuery.
// When cfg.Server.ToolInputSettings is non-empty, a "settings" property is
// added to every query-executing tool's schema.
func buildExecuteQueryTool(srvCfg *config.ServerConfig) *mcp.Tool {
	properties := map[string]any{
		"query": map[string]any{
			"type":        "string",
			"description": "Read-only SQL query (SELECT, WITH, SHOW, DESCRIBE, EXISTS, EXPLAIN).",
		},
		"limit": map[string]any{
			"type":        "number",
			"description": "Maximum number of rows to return (default: 100000)",
		},
	}
	if settingsSchema := buildToolInputSettingsSchema(srvCfg.ToolInputSettings); settingsSchema != nil {
		properties["settings"] = settingsSchema
	}
	return &mcp.Tool{
		Name:        "execute_query",
		Title:       "Execute SQL Query",
		Description: "Executes a read-only SQL query against ClickHouse and returns the results. Only SELECT, WITH, SHOW, DESCRIBE, EXISTS, and EXPLAIN statements are allowed — write operations are rejected; use write_query for those.",
		Annotations: &mcp.ToolAnnotations{
			ReadOnlyHint:    true,
			DestructiveHint: new(false),
			OpenWorldHint:   new(false),
		},
		InputSchema: map[string]any{
			"type":                 "object",
			"properties":           properties,
			"required":             []string{"query"},
			"additionalProperties": false,
		},
	}
}

// buildWriteQueryTool builds the write_query tool definition. write_query
// accepts arbitrary SQL (INSERT, UPDATE, DELETE, ALTER, CREATE, DROP, ...).
// It is not registered at all when the server runs in read-only mode.
func buildWriteQueryTool(srvCfg *config.ServerConfig) *mcp.Tool {
	properties := map[string]any{
		"query": map[string]any{
			"type":        "string",
			"description": "SQL write query (INSERT, UPDATE, DELETE, ALTER, CREATE, DROP, TRUNCATE).",
		},
		"limit": map[string]any{
			"type":        "number",
			"description": "Maximum number of rows to return for queries that produce result sets",
		},
	}
	if settingsSchema := buildToolInputSettingsSchema(srvCfg.ToolInputSettings); settingsSchema != nil {
		properties["settings"] = settingsSchema
	}
	return &mcp.Tool{
		Name:        "write_query",
		Title:       "Execute Write Query",
		Description: "Executes a write query (INSERT, UPDATE, DELETE, ALTER, CREATE, DROP, TRUNCATE) against ClickHouse. Not registered when the server runs in read-only mode.",
		Annotations: &mcp.ToolAnnotations{
			ReadOnlyHint:    false,
			DestructiveHint: new(true),
			OpenWorldHint:   new(false),
		},
		InputSchema: map[string]any{
			"type":                 "object",
			"properties":           properties,
			"required":             []string{"query"},
			"additionalProperties": false,
		},
	}
}

// convertToDynamicToolRules packs unified ToolDefinition entries back into the
// legacy DynamicToolRule shape so EnsureDynamicTools can consume them.
func convertToDynamicToolRules(defs []config.ToolDefinition) []config.DynamicToolRule {
	rules := make([]config.DynamicToolRule, len(defs))
	for i, td := range defs {
		// Pick whichever regexp field is set (only one should be non-empty per rule).
		re := td.ViewRegexp
		if re == "" {
			re = td.TableRegexp
		}
		rules[i] = config.DynamicToolRule{
			Name:   td.Name,
			Regexp: re,
			Prefix: td.Prefix,
			Type:   td.Type,
			Mode:   td.Mode,
		}
	}
	return rules
}

// HandleReadOnlyQuery wraps HandleExecuteQuery with a SELECT-only guard.
// Write-family statements are rejected with a clear error that points the
// client at write_query.
func HandleReadOnlyQuery(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	arguments, err := getArgumentsMap(req)
	if err != nil {
		return NewToolResultError(err.Error()), nil
	}
	queryArg, ok := arguments["query"]
	if !ok {
		return NewToolResultError("query parameter is required"), nil
	}
	query, ok := queryArg.(string)
	if !ok || query == "" {
		return NewToolResultError("query parameter must be a non-empty string"), nil
	}
	if !clickhouse.IsSelectQuery(query) {
		return NewToolResultError("execute_query only accepts read-only statements (SELECT, WITH, SHOW, DESCRIBE, EXISTS, EXPLAIN). Use write_query for write operations."), nil
	}
	return HandleExecuteQuery(ctx, req)
}

// NewToolResultText creates a tool result with text content
func NewToolResultText(text string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{
				Text: text,
			},
		},
	}
}

// NewToolResultError creates a tool result with an error
func NewToolResultError(errMsg string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{
				Text: errMsg,
			},
		},
		IsError: true,
	}
}

// HandleExecuteQuery implements the execute_query tool handler
func HandleExecuteQuery(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	// Get arguments from request
	arguments, err := getArgumentsMap(req)
	if err != nil {
		return NewToolResultError(err.Error()), nil
	}

	queryArg, ok := arguments["query"]
	if !ok {
		return NewToolResultError("query parameter is required"), nil
	}
	query, ok := queryArg.(string)
	if !ok || query == "" {
		return NewToolResultError("query parameter must be a non-empty string"), nil
	}

	// Get the ClickHouse JWE server from context
	chJweServer := GetClickHouseJWEServerFromContext(ctx)
	if chJweServer == nil {
		return nil, fmt.Errorf("can't get JWEServer from context")
	}

	// Reject oversize queries before they reach ClickHouse or the SQL parser.
	if maxQueryLength := chJweServer.Config.ClickHouse.EffectiveMaxQueryLength(); maxQueryLength > 0 && len(query) > maxQueryLength {
		return NewToolResultError(fmt.Sprintf("query exceeds max length (%d bytes, limit %d)", len(query), maxQueryLength)), nil
	}

	if clause, err := checkBlockedClauses(query, chJweServer.blockedClauses); err != nil {
		return NewToolResultError(fmt.Sprintf("Query rejected: %v", err)), nil
	} else if clause != "" {
		return NewToolResultError(fmt.Sprintf("Query rejected: %s clause is not allowed", clause)), nil
	}

	// Get optional limit parameter
	var limit float64
	hasLimit := false
	if limitVal, exists := arguments["limit"]; exists {
		if l, ok := limitVal.(float64); ok && l > 0 {
			limit = l
			hasLimit = true
			// Check against configured max limit if one is set
			if chJweServer.Config.ClickHouse.Limit > 0 && int(l) > chJweServer.Config.ClickHouse.Limit {
				return NewToolResultError(fmt.Sprintf("Limit cannot exceed %d rows", chJweServer.Config.ClickHouse.Limit)), nil
			}
		}
	}

	log.Debug().
		Str("query", query).
		Float64("limit", limit).
		Bool("has_limit", hasLimit).
		Msg("Executing query")

	// Add LIMIT clause for SELECT queries if limit is specified and not already present
	if hasLimit && clickhouse.IsSelectQuery(query) && !hasLimitClause(query) {
		query = fmt.Sprintf("%s LIMIT %.0f", strings.TrimSpace(query), limit)
	}

	if len(chJweServer.Config.Server.ToolInputSettings) > 0 {
		var errResult *mcp.CallToolResult
		ctx, errResult = applyToolInputSettings(ctx, arguments, chJweServer.Config.Server.ToolInputSettings)
		if errResult != nil {
			return errResult, nil
		}
	}

	chClient, err := chJweServer.GetClickHouseClientFromCtx(ctx)
	if err != nil {
		log.Error().Err(err).Msg("Failed to get ClickHouse client")
		return NewToolResultError(fmt.Sprintf("Failed to get ClickHouse client: %v", err)), nil
	}
	defer func() {
		if closeErr := chClient.Close(); closeErr != nil {
			log.Error().
				Stack().
				Err(closeErr).
				Msg("execute_query: can't close clickhouse")
		}
	}()

	result, err := chClient.ExecuteQuery(ctx, query)
	if err != nil {
		log.Error().
			Err(err).
			Str("query", query).
			Float64("limit", limit).
			Str("tool", "execute_query").
			Msg("ClickHouse operation failed: query execution")
		return NewToolResultError(fmt.Sprintf("Query execution failed: %s", truncateErrForClient(err))), nil
	}

	jsonData, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return NewToolResultError(fmt.Sprintf("Failed to marshal result: %v", err)), nil
	}

	return NewToolResultText(string(jsonData)), nil
}

// GetClickHouseJWEServerFromContext extracts the ClickHouseJWEServer from context
func GetClickHouseJWEServerFromContext(ctx context.Context) *ClickHouseJWEServer {
	if srv := ctx.Value(CHJWEServerKey); srv != nil {
		if chJweServer, ok := srv.(*ClickHouseJWEServer); ok {
			return chJweServer
		}
	}
	log.Error().Msg("can't get 'clickhouse_jwe_server' from context")
	return nil
}

// contextKey avoids collisions with other packages using context.WithValue.
type contextKey string

// Auth context keys
const (
	JWETokenKey    contextKey = "jwe_token"
	JWEClaimsKey   contextKey = "jwe_claims"
	OAuthTokenKey  contextKey = "oauth_token"
	OAuthClaimsKey contextKey = "oauth_claims"
	CHJWEServerKey contextKey = "clickhouse_jwe_server"
)
