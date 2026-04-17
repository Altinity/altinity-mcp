package server

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"github.com/altinity/altinity-mcp/pkg/clickhouse"
	"github.com/altinity/altinity-mcp/pkg/config"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/rs/zerolog/log"
)

type dynamicToolParam struct {
	Name        string
	CHType      string
	JSONType    string
	JSONFormat  string
	Required    bool
	Description string // resolved from column COMMENT or JSON COMMENT params; empty → falls back to CHType
}

type dynamicToolMeta struct {
	ToolName    string
	Title       string
	Database    string
	Table       string
	Description string
	Annotations *mcp.ToolAnnotations
	Params      []dynamicToolParam
	ToolType    string // "read" (view) or "write" (table)
	WriteMode   string // "insert" for write tools; empty for read tools
}

type dynamicToolCommentMetadata struct {
	Title       string                         `json:"title"`
	Description string                         `json:"description"`
	Annotations *dynamicToolCommentAnnotations `json:"annotations"`
	Params      map[string]string              `json:"params"`
}

type dynamicToolCommentAnnotations struct {
	OpenWorldHint *bool `json:"openWorldHint"`
}

// EnsureDynamicTools discovers dynamic tools (views for reads, tables for writes)
// from ClickHouse and registers them with the MCP server. It's safe to call on
// every request: the fast path short-circuits once init completes.
//
// Discovery is deferred until the caller has usable credentials. In OAuth
// forward mode the Bearer token only arrives on tools/call, not tools/list —
// so the first tools/list just returns static tools, and the first authenticated
// tools/call triggers discovery. The MCP SDK's AddTool automatically fires
// notifications/tools/list_changed, prompting the client to re-fetch.
//
// Concurrency: discovery does CH round-trips which can be slow. We hold the
// write lock only while discovery is in progress. If another goroutine is
// already discovering we return immediately without blocking — concurrent
// tools/list calls see the current (static-only) tool set and get updated
// when the in-flight discovery notifies.
func (s *ClickHouseJWEServer) EnsureDynamicTools(ctx context.Context) error {
	// Fast path: already initialized.
	s.dynamicToolsMu.RLock()
	if s.dynamicToolsInit {
		s.dynamicToolsMu.RUnlock()
		return nil
	}
	s.dynamicToolsMu.RUnlock()

	// Try the write lock; skip if another goroutine is already discovering.
	if !s.dynamicToolsMu.TryLock() {
		return nil
	}
	defer s.dynamicToolsMu.Unlock()

	// Double-check under the write lock — another goroutine may have finished
	// between our RUnlock and TryLock.
	if s.dynamicToolsInit {
		return nil
	}

	if len(s.Config.Server.DynamicTools) == 0 {
		s.dynamicToolsInit = true
		return nil
	}

	// In forward-OAuth mode with blank static credentials, the OAuth bearer
	// isn't in context on the tools/list handshake. Don't mark dynamicToolsInit
	// true here — let the next request retry with a real token.
	if !s.hasDiscoveryCredentials(ctx) {
		log.Debug().Msg("dynamic_tools: no credentials available yet; deferring discovery")
		return nil
	}

	readTools, err := s.discoverReadTools(ctx)
	if err != nil {
		return err
	}
	writeTools, err := s.discoverWriteTools(ctx)
	if err != nil {
		return err
	}

	s.registerDynamicTools(readTools, writeTools)
	s.dynamicToolsInit = true
	return nil
}

// hasDiscoveryCredentials reports whether the current context has any form
// of credentials that can be used to query ClickHouse for tool discovery.
func (s *ClickHouseJWEServer) hasDiscoveryCredentials(ctx context.Context) bool {
	if s.ExtractTokenFromCtx(ctx) != "" {
		return true
	}
	if s.ExtractOAuthTokenFromCtx(ctx) != "" {
		return true
	}
	if s.Config.ClickHouse.Username != "" {
		return true
	}
	return false
}

// getDiscoveryClient returns a ClickHouse client that honors whichever kind
// of credential is available on ctx (JWE token, OAuth bearer, or static
// fallback). Callers must Close() the returned client.
func (s *ClickHouseJWEServer) getDiscoveryClient(ctx context.Context) (*clickhouse.Client, error) {
	return s.GetClickHouseClientFromCtx(ctx)
}

// filterRulesByType returns only the rules matching the requested "read"
// or "write" type. Legacy rules without an explicit Type default to "read"
// when they carry a Regexp.
func filterRulesByType(rules []config.DynamicToolRule, toolType string) []config.DynamicToolRule {
	filtered := make([]config.DynamicToolRule, 0, len(rules))
	for _, rule := range rules {
		ruleType := rule.Type
		if ruleType == "" && rule.Regexp != "" {
			ruleType = "read"
		}
		if ruleType == toolType {
			filtered = append(filtered, rule)
		}
	}
	return filtered
}

// discoverReadTools scans system.tables for views and produces dynamic read-tool
// metadata for every view that matches a configured read rule.
func (s *ClickHouseJWEServer) discoverReadTools(ctx context.Context) (map[string]dynamicToolMeta, error) {
	readRules := filterRulesByType(s.Config.Server.DynamicTools, "read")
	if len(readRules) == 0 {
		return map[string]dynamicToolMeta{}, nil
	}

	chClient, err := s.getDiscoveryClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("dynamic_tools: failed to get ClickHouse client: %w", err)
	}
	defer func() {
		if closeErr := chClient.Close(); closeErr != nil {
			log.Error().Err(closeErr).Msg("dynamic_tools: can't close clickhouse")
		}
	}()

	result, err := chClient.ExecuteQuery(ctx, "SELECT database, name, create_table_query, comment FROM system.tables WHERE engine='View'")
	if err != nil {
		return nil, fmt.Errorf("dynamic_tools: failed to list views: %w", err)
	}

	type compiledRule struct {
		r      *regexp.Regexp
		prefix string
		name   string
	}
	rules := make([]compiledRule, 0, len(readRules))
	namedMatches := make(map[int][]string)
	for i, rule := range readRules {
		if rule.Regexp == "" {
			continue
		}
		compiled, compErr := regexp.Compile(rule.Regexp)
		if compErr != nil {
			log.Error().Err(compErr).Str("regexp", rule.Regexp).Msg("dynamic_tools: invalid read regexp, skipping rule")
			continue
		}
		rules = append(rules, compiledRule{r: compiled, prefix: rule.Prefix, name: rule.Name})
		if rule.Name != "" {
			namedMatches[i] = nil
		}
	}

	tools := make(map[string]dynamicToolMeta)
	for _, row := range result.Rows {
		if len(row) < 4 {
			continue
		}
		db, _ := row[0].(string)
		name, _ := row[1].(string)
		create, _ := row[2].(string)
		comment, _ := row[3].(string)
		full := db + "." + name

		matched := make([]int, 0)
		for i, rc := range rules {
			if rc.r.MatchString(full) {
				matched = append(matched, i)
				if rc.name != "" {
					namedMatches[i] = append(namedMatches[i], full)
				}
			}
		}
		if len(matched) == 0 {
			continue
		}
		if len(matched) > 1 {
			log.Error().Str("view", full).Msg("dynamic_tools: overlap between read rules, skipping view")
			continue
		}

		rc := rules[matched[0]]
		var toolName string
		if rc.name != "" {
			toolName = snakeCase(rc.prefix + rc.name)
		} else {
			toolName = snakeCase(rc.prefix + full)
		}

		params := parseViewParams(create)
		meta := buildDynamicToolMeta(toolName, db, name, comment, params)
		meta.ToolType = "read"
		tools[toolName] = meta
	}

	// Warn on named rules that matched zero or more than one view.
	for i, matches := range namedMatches {
		rc := rules[i]
		switch {
		case len(matches) == 0:
			log.Error().Str("name", rc.name).Str("regexp", rc.r.String()).Msg("dynamic_tools: named read rule matched no views")
		case len(matches) > 1:
			log.Error().Str("name", rc.name).Str("regexp", rc.r.String()).Strs("matched_views", matches).Msg("dynamic_tools: named read rule matched multiple views, expected exactly one")
		}
	}

	log.Info().Int("tool_count", len(tools)).Msg("Dynamic read tools discovered")
	return tools, nil
}

// discoverWriteTools scans system.tables for writable tables (not Views /
// MaterializedViews / Aliases, and not in system databases) and produces
// dynamic write-tool metadata for every table that matches a configured
// write rule. Skipped entirely when the server is in read-only mode.
func (s *ClickHouseJWEServer) discoverWriteTools(ctx context.Context) (map[string]dynamicToolMeta, error) {
	if s.Config.ClickHouse.ReadOnly {
		log.Info().Msg("dynamic_tools: write tools disabled in read-only mode")
		return map[string]dynamicToolMeta{}, nil
	}

	writeRules := filterRulesByType(s.Config.Server.DynamicTools, "write")
	if len(writeRules) == 0 {
		return map[string]dynamicToolMeta{}, nil
	}

	chClient, err := s.getDiscoveryClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("dynamic_tools: failed to get ClickHouse client: %w", err)
	}
	defer func() {
		if closeErr := chClient.Close(); closeErr != nil {
			log.Error().Err(closeErr).Msg("dynamic_tools: can't close clickhouse")
		}
	}()

	const q = "SELECT database, name, comment FROM system.tables " +
		"WHERE engine NOT IN ('View', 'MaterializedView', 'Alias') " +
		"AND database NOT IN ('system', 'INFORMATION_SCHEMA')"
	result, err := chClient.ExecuteQuery(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("dynamic_tools: failed to list tables: %w", err)
	}

	type compiledRule struct {
		r      *regexp.Regexp
		prefix string
		name   string
		mode   string
	}
	rules := make([]compiledRule, 0, len(writeRules))
	for _, rule := range writeRules {
		if rule.Regexp == "" {
			continue
		}
		compiled, compErr := regexp.Compile(rule.Regexp)
		if compErr != nil {
			log.Error().Err(compErr).Str("regexp", rule.Regexp).Msg("dynamic_tools: invalid write regexp, skipping rule")
			continue
		}
		rules = append(rules, compiledRule{r: compiled, prefix: rule.Prefix, name: rule.Name, mode: rule.Mode})
	}

	tools := make(map[string]dynamicToolMeta)
	for _, row := range result.Rows {
		if len(row) < 3 {
			continue
		}
		db, _ := row[0].(string)
		name, _ := row[1].(string)
		comment, _ := row[2].(string)
		full := db + "." + name

		matched := make([]int, 0)
		for i, rc := range rules {
			if rc.r.MatchString(full) {
				matched = append(matched, i)
			}
		}
		if len(matched) == 0 {
			continue
		}
		if len(matched) > 1 {
			log.Error().Str("table", full).Msg("dynamic_tools: overlap between write rules, skipping table")
			continue
		}

		rc := rules[matched[0]]
		cols, colErr := s.getTableColumnsForMode(ctx, chClient, db, name)
		if colErr != nil {
			log.Warn().Err(colErr).Str("table", full).Msg("dynamic_tools: failed to get columns for write tool, skipping")
			continue
		}
		if metadata, ok := parseDynamicToolComment(comment); ok {
			applyCommentParamOverrides(cols, metadata)
		}

		var toolName string
		if rc.name != "" {
			toolName = snakeCase(rc.prefix + rc.name)
		} else {
			toolName = snakeCase(rc.prefix + full)
		}

		tools[toolName] = dynamicToolMeta{
			ToolName:    toolName,
			Title:       humanizeToolName(toolName),
			Database:    db,
			Table:       name,
			Description: buildWriteToolDescription(comment, db, name, rc.mode),
			Annotations: &mcp.ToolAnnotations{
				ReadOnlyHint:    false,
				DestructiveHint: boolPtr(true),
				OpenWorldHint:   boolPtr(false),
			},
			Params:    cols,
			ToolType:  "write",
			WriteMode: rc.mode,
		}
	}

	log.Info().Int("tool_count", len(tools)).Msg("Dynamic write tools discovered")
	return tools, nil
}

// getTableColumnsForMode loads columns for a given table and filters out those
// that can't be populated by a client (MATERIALIZED and ALIAS).
//
// Note: we intentionally select only fields that exist across all supported
// ClickHouse versions. Some older versions (e.g., 26.1.x Altinity Antalya)
// do not expose a `column_type` column, so we rely on `default_kind` alone
// which carries the same information for our purposes.
func (s *ClickHouseJWEServer) getTableColumnsForMode(ctx context.Context, chClient *clickhouse.Client, db, table string) ([]dynamicToolParam, error) {
	q := fmt.Sprintf(
		"SELECT name, type, default_kind, comment FROM system.columns WHERE database='%s' AND table='%s' ORDER BY position",
		db, table,
	)
	result, err := chClient.ExecuteQuery(ctx, q)
	if err != nil {
		return nil, err
	}

	params := make([]dynamicToolParam, 0, len(result.Rows))
	for _, row := range result.Rows {
		if len(row) < 4 {
			continue
		}
		name, _ := row[0].(string)
		chType, _ := row[1].(string)
		defaultKind, _ := row[2].(string)
		comment, _ := row[3].(string)

		// MATERIALIZED and ALIAS columns are computed server-side; clients must not
		// supply values for them. Everything else is writable (DEFAULT values make
		// the column optional in INSERT).
		if defaultKind == "MATERIALIZED" || defaultKind == "ALIAS" {
			continue
		}

		jsonType, jsonFmt := mapCHType(chType)
		params = append(params, dynamicToolParam{
			Name:        name,
			CHType:      chType,
			JSONType:    jsonType,
			JSONFormat:  jsonFmt,
			Required:    defaultKind == "", // required iff no DEFAULT expression
			Description: strings.TrimSpace(comment),
		})
	}
	return params, nil
}

// buildWriteToolDescription renders a human-readable description for a
// discovered write tool. Falls back to a mode-specific default when the
// table has no COMMENT.
func buildWriteToolDescription(comment, db, table, mode string) string {
	if strings.TrimSpace(comment) != "" {
		return comment
	}
	action := "Insert data"
	switch mode {
	case "update":
		action = "Update data"
	case "upsert":
		action = "Insert or update data"
	}
	return fmt.Sprintf("%s in %s.%s", action, db, table)
}

// registerDynamicTools commits discovered read and write tools to the MCP server.
// AddTool automatically fires notifications/tools/list_changed so clients refresh.
func (s *ClickHouseJWEServer) registerDynamicTools(readTools, writeTools map[string]dynamicToolMeta) {
	for toolName, meta := range readTools {
		s.dynamicTools[toolName] = meta
		props := make(map[string]any, len(meta.Params)+1)
		for _, p := range meta.Params {
			props[p.Name] = buildParamSchema(p)
		}
		if settingsSchema := buildToolInputSettingsSchema(s.Config.Server.ToolInputSettings); settingsSchema != nil {
			props["settings"] = settingsSchema
		}
		s.AddTool(&mcp.Tool{
			Name:        toolName,
			Title:       meta.Title,
			Description: meta.Description,
			Annotations: meta.Annotations,
			InputSchema: map[string]any{
				"type":       "object",
				"properties": props,
			},
		}, makeDynamicToolHandler(meta))
	}

	for toolName, meta := range writeTools {
		s.dynamicTools[toolName] = meta
		props := make(map[string]any, len(meta.Params)+1)
		required := make([]string, 0, len(meta.Params))
		for _, p := range meta.Params {
			props[p.Name] = buildParamSchema(p)
			if p.Required {
				required = append(required, p.Name)
			}
		}
		if settingsSchema := buildToolInputSettingsSchema(s.Config.Server.ToolInputSettings); settingsSchema != nil {
			props["settings"] = settingsSchema
		}
		schema := map[string]any{
			"type":       "object",
			"properties": props,
		}
		if len(required) > 0 {
			schema["required"] = required
		}
		s.AddTool(&mcp.Tool{
			Name:        toolName,
			Title:       meta.Title,
			Description: meta.Description,
			Annotations: meta.Annotations,
			InputSchema: schema,
		}, s.makeDynamicWriteToolHandler(meta))
	}

	log.Info().
		Int("read_tools", len(readTools)).
		Int("write_tools", len(writeTools)).
		Msg("Dynamic tools registered")
}

func makeDynamicToolHandler(meta dynamicToolMeta) ToolHandlerFunc {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		chJweServer := GetClickHouseJWEServerFromContext(ctx)
		if chJweServer == nil {
			return nil, fmt.Errorf("can't get JWEServer from context")
		}

		arguments, err := getArgumentsMap(req)
		if err != nil {
			return NewToolResultError(err.Error()), nil
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
			log.Error().Err(err).Str("tool", meta.ToolName).Msg("dynamic_tools: GetClickHouseClient failed")
			return NewToolResultError(fmt.Sprintf("Failed to get ClickHouse client: %v", err)), nil
		}
		defer func() {
			if closeErr := chClient.Close(); closeErr != nil {
				log.Error().Err(closeErr).Str("tool", meta.ToolName).Msg("dynamic_tools: close client failed")
			}
		}()

		// build param list
		args := make([]string, 0, len(meta.Params))
		for _, p := range meta.Params {
			if v, ok := arguments[p.Name]; ok {
				// encode to SQL literal based on expected type
				literal := sqlLiteral(p.JSONType, v)
				args = append(args, fmt.Sprintf("%s=%s", p.Name, literal))
			}
		}
		fn := meta.Table
		if len(args) > 0 {
			fn = fmt.Sprintf("%s(%s)", meta.Table, strings.Join(args, ", "))
		}
		query := fmt.Sprintf("SELECT * FROM %s.%s", meta.Database, fn)

		result, err := chClient.ExecuteQuery(ctx, query)
		if err != nil {
			log.Error().Err(err).Str("tool", meta.ToolName).Str("query", query).Msg("dynamic_tools: query failed")
			return NewToolResultError(fmt.Sprintf("Query execution failed: %v", ErrJSONEscaper.Replace(err.Error()))), nil
		}
		jsonData, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return NewToolResultError(err.Error()), nil
		}
		return NewToolResultText(string(jsonData)), nil
	}
}

// makeDynamicWriteToolHandler returns a handler for a discovered dynamic write
// tool. The handler enforces read-only mode, respects tool_input_settings and
// blocked_query_clauses, validates required parameters, and dispatches to the
// mode-specific query builder (currently only "insert").
func (s *ClickHouseJWEServer) makeDynamicWriteToolHandler(meta dynamicToolMeta) ToolHandlerFunc {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		chJweServer := GetClickHouseJWEServerFromContext(ctx)
		if chJweServer == nil {
			return nil, fmt.Errorf("can't get JWEServer from context")
		}
		// Belt-and-suspenders: discoverWriteTools already skips registration in
		// read-only mode, but a config reload could toggle the flag at runtime.
		if chJweServer.Config.ClickHouse.ReadOnly {
			return NewToolResultError("write operations disabled in read-only mode"), nil
		}

		arguments, err := getArgumentsMap(req)
		if err != nil {
			log.Error().Err(err).Str("tool", meta.ToolName).Msg("dynamic_tools: invalid arguments")
			return NewToolResultError(err.Error()), nil
		}

		if len(chJweServer.Config.Server.ToolInputSettings) > 0 {
			var errResult *mcp.CallToolResult
			ctx, errResult = applyToolInputSettings(ctx, arguments, chJweServer.Config.Server.ToolInputSettings)
			if errResult != nil {
				return errResult, nil
			}
		}

		query, err := buildDynamicWriteQuery(meta, arguments)
		if err != nil {
			log.Error().Err(err).Str("tool", meta.ToolName).Msg("dynamic_tools: failed to build write query")
			return NewToolResultError(fmt.Sprintf("Failed to build query: %v", err)), nil
		}

		if clause, clauseErr := checkBlockedClauses(query, chJweServer.blockedClauses); clauseErr != nil {
			return NewToolResultError(fmt.Sprintf("Query rejected: %v", clauseErr)), nil
		} else if clause != "" {
			return NewToolResultError(fmt.Sprintf("Query rejected: %s clause is not allowed", clause)), nil
		}

		chClient, err := chJweServer.GetClickHouseClientFromCtx(ctx)
		if err != nil {
			log.Error().Err(err).Str("tool", meta.ToolName).Msg("dynamic_tools: GetClickHouseClient failed")
			return NewToolResultError(fmt.Sprintf("Failed to get ClickHouse client: %v", err)), nil
		}
		defer func() {
			if closeErr := chClient.Close(); closeErr != nil {
				log.Error().Err(closeErr).Str("tool", meta.ToolName).Msg("dynamic_tools: close client failed")
			}
		}()

		log.Debug().Str("tool", meta.ToolName).Str("query", query).Msg("dynamic_tools: executing write query")
		if _, err := chClient.ExecuteQuery(ctx, query); err != nil {
			log.Error().Err(err).Str("tool", meta.ToolName).Str("query", query).Msg("dynamic_tools: write query failed")
			return NewToolResultError(fmt.Sprintf("Query failed: %v", ErrJSONEscaper.Replace(err.Error()))), nil
		}
		return NewToolResultText(fmt.Sprintf("Successfully executed %s", meta.ToolName)), nil
	}
}

// buildDynamicWriteQuery dispatches to the mode-specific SQL builder.
// Unsupported modes are rejected at tool-registration time (see RegisterTools),
// so reaching them here is a bug.
func buildDynamicWriteQuery(meta dynamicToolMeta, args map[string]interface{}) (string, error) {
	switch meta.WriteMode {
	case "insert":
		return buildInsertQuery(meta, args)
	default:
		return "", fmt.Errorf("unsupported write mode %q (only 'insert' is implemented)", meta.WriteMode)
	}
}

// buildInsertQuery renders INSERT INTO db.table (cols...) VALUES (vals...)
// from a dynamic tool's metadata and the client-supplied arguments. Required
// parameters must be present; everything else is optional (columns with DEFAULT
// expressions are simply omitted when not provided).
func buildInsertQuery(meta dynamicToolMeta, args map[string]interface{}) (string, error) {
	cols := make([]string, 0, len(meta.Params))
	vals := make([]string, 0, len(meta.Params))
	for _, p := range meta.Params {
		v, ok := args[p.Name]
		if ok {
			cols = append(cols, p.Name)
			vals = append(vals, sqlLiteral(p.JSONType, v))
			continue
		}
		if p.Required {
			return "", fmt.Errorf("required parameter missing: %s", p.Name)
		}
	}
	if len(cols) == 0 {
		return "", fmt.Errorf("no columns provided")
	}
	return fmt.Sprintf(
		"INSERT INTO %s.%s (%s) VALUES (%s)",
		meta.Database, meta.Table,
		strings.Join(cols, ", "),
		strings.Join(vals, ", "),
	), nil
}

// getArgumentsMap extracts the arguments object from an MCP tool call.
// Returns an error when the arguments are present but cannot be parsed as JSON
// — handlers should propagate that error to the client instead of proceeding
// with empty arguments (which produces confusing downstream errors).
func getArgumentsMap(req *mcp.CallToolRequest) (map[string]any, error) {
	if req.Params.Arguments == nil {
		return make(map[string]any), nil
	}
	var args map[string]any
	if err := json.Unmarshal(req.Params.Arguments, &args); err != nil {
		return nil, fmt.Errorf("failed to parse tool arguments: %w", err)
	}
	if args == nil {
		// Valid JSON "null" — treat as empty.
		return make(map[string]any), nil
	}
	return args, nil
}

func buildDynamicToolMeta(toolName, db, table, comment string, params []dynamicToolParam) dynamicToolMeta {
	title, description, annotations := buildToolPresentation(toolName, db, table, comment)
	if metadata, ok := parseDynamicToolComment(comment); ok {
		applyCommentParamOverrides(params, metadata)
	}

	return dynamicToolMeta{
		ToolName:    toolName,
		Title:       title,
		Database:    db,
		Table:       table,
		Description: description,
		Annotations: annotations,
		Params:      params,
	}
}

func buildToolPresentation(toolName, db, table, comment string) (string, string, *mcp.ToolAnnotations) {
	metadata, hasStructuredMetadata := parseDynamicToolComment(comment)
	title := buildTitle(toolName, metadata.Title)
	description := buildDynamicToolDescription(comment, db, table, metadata.Description, hasStructuredMetadata)
	annotations := buildDynamicToolAnnotations(metadata.Annotations)
	return title, description, annotations
}

func parseDynamicToolComment(comment string) (dynamicToolCommentMetadata, bool) {
	trimmed := strings.TrimSpace(comment)
	if trimmed == "" {
		return dynamicToolCommentMetadata{}, false
	}
	if !strings.HasPrefix(trimmed, "{") {
		return dynamicToolCommentMetadata{}, false
	}

	var metadata dynamicToolCommentMetadata
	if err := json.Unmarshal([]byte(trimmed), &metadata); err != nil {
		return dynamicToolCommentMetadata{}, false
	}
	return metadata, true
}

// applyCommentParamOverrides sets param.Description from the tool-level JSON
// COMMENT's "params" map when present. Called after any column-level comment
// has been applied, so JSON overrides win.
func applyCommentParamOverrides(params []dynamicToolParam, meta dynamicToolCommentMetadata) {
	if len(meta.Params) == 0 {
		return
	}
	for i, p := range params {
		if desc, ok := meta.Params[p.Name]; ok {
			if trimmed := strings.TrimSpace(desc); trimmed != "" {
				params[i].Description = trimmed
			}
		}
	}
}

// buildParamSchema returns the JSON Schema fragment for a single dynamic tool
// parameter. Description resolves to the param's own Description (from a
// column COMMENT or the tool's JSON COMMENT "params" map) and falls back to
// the ClickHouse type string when none was set.
func buildParamSchema(p dynamicToolParam) map[string]any {
	desc := p.Description
	if desc == "" {
		desc = p.CHType
	}
	schema := map[string]any{
		"type":        p.JSONType,
		"description": desc,
	}
	if p.JSONFormat != "" {
		schema["format"] = p.JSONFormat
	}
	return schema
}

func buildTitle(toolName, title string) string {
	if strings.TrimSpace(title) != "" {
		return strings.TrimSpace(title)
	}
	return humanizeToolName(toolName)
}

func buildDescription(comment, db, table string) string {
	return buildDynamicToolDescription(comment, db, table, "", false)
}

func buildDynamicToolDescription(comment, db, table, metadataDescription string, hasStructuredMetadata bool) string {
	if strings.TrimSpace(metadataDescription) != "" {
		return strings.TrimSpace(metadataDescription)
	}
	if strings.TrimSpace(comment) != "" {
		if hasStructuredMetadata {
			return fmt.Sprintf("Read-only tool to query data from %s.%s", db, table)
		}
		return comment
	}
	return fmt.Sprintf("Read-only tool to query data from %s.%s", db, table)
}

func buildDynamicToolAnnotations(commentAnnotations *dynamicToolCommentAnnotations) *mcp.ToolAnnotations {
	annotations := &mcp.ToolAnnotations{
		ReadOnlyHint:    true,
		DestructiveHint: boolPtr(false),
		OpenWorldHint:   boolPtr(false),
	}
	if commentAnnotations != nil {
		if commentAnnotations.OpenWorldHint != nil {
			annotations.OpenWorldHint = boolPtr(*commentAnnotations.OpenWorldHint)
		}
	}
	return annotations
}

func boolPtr(v bool) *bool {
	return &v
}

func humanizeToolName(toolName string) string {
	parts := strings.FieldsFunc(toolName, func(r rune) bool {
		return !(unicode.IsLetter(r) || unicode.IsNumber(r))
	})
	for i, part := range parts {
		parts[i] = capitalize(part)
	}
	return strings.Join(parts, " ")
}

func capitalize(s string) string {
	if s == "" {
		return ""
	}
	runes := []rune(strings.ToLower(s))
	runes[0] = unicode.ToUpper(runes[0])
	return string(runes)
}

var paramRe = regexp.MustCompile(`\{\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*:\s*([^}]+)\}`)

func parseViewParams(createSQL string) []dynamicToolParam {
	matches := paramRe.FindAllStringSubmatch(createSQL, -1)
	params := make([]dynamicToolParam, 0, len(matches))
	for _, m := range matches {
		if len(m) < 3 {
			continue
		}
		name := m[1]
		ch := strings.TrimSpace(m[2])
		jType, jFmt := mapCHType(ch)
		params = append(params, dynamicToolParam{Name: name, CHType: ch, JSONType: jType, JSONFormat: jFmt, Required: true})
	}
	return params
}

func mapCHType(chType string) (jsonType, jsonFormat string) {
	t := strings.ToLower(chType)
	switch {
	case strings.HasPrefix(t, "uint"):
		return "integer", "int64"
	case strings.HasPrefix(t, "int"):
		return "integer", "int64"
	case strings.HasPrefix(t, "float") || strings.HasPrefix(t, "decimal"):
		return "number", "double"
	case strings.HasPrefix(t, "bool") || t == "uint8" && strings.Contains(strings.ToLower(chType), "bool"):
		return "boolean", ""
	case strings.HasPrefix(t, "date32") || t == "date":
		return "string", "date"
	case strings.HasPrefix(t, "datetime"):
		return "string", "date-time"
	case strings.Contains(t, "uuid"):
		return "string", "uuid"
	default:
		return "string", ""
	}
}

func sqlLiteral(jsonType string, v interface{}) string {
	switch jsonType {
	case "integer":
		switch n := v.(type) {
		case float64:
			return strconv.FormatInt(int64(n), 10)
		case int64:
			return strconv.FormatInt(n, 10)
		case int:
			return strconv.Itoa(n)
		default:
			return "0"
		}
	case "number":
		switch n := v.(type) {
		case float64:
			return strconv.FormatFloat(n, 'f', -1, 64)
		default:
			return "0"
		}
	case "boolean":
		if b, ok := v.(bool); ok {
			if b {
				return "1"
			}
			return "0"
		}
		return "0"
	default: // string
		s := ""
		switch x := v.(type) {
		case string:
			s = x
		default:
			b, _ := json.Marshal(v)
			s = string(b)
		}
		// ClickHouse single-quoted string literal escaping: escape backslashes then single quotes
		s = strings.ReplaceAll(s, "\\", "\\\\")
		s = strings.ReplaceAll(s, "'", "\\'")
		return "'" + s + "'"
	}
}

func snakeCase(s string) string {
	s = strings.ToLower(s)
	b := strings.Builder{}
	prevUnderscore := false
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			prevUnderscore = false
		} else {
			if !prevUnderscore {
				b.WriteByte('_')
				prevUnderscore = true
			}
		}
	}
	out := b.String()
	out = strings.Trim(out, "_")
	return out
}
