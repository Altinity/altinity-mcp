package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/altinity/altinity-mcp/pkg/clickhouse"
	"github.com/altinity/altinity-mcp/pkg/config"
	"github.com/altinity/altinity-mcp/pkg/jwe_auth"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/rs/zerolog/log"
)

// ClickHouseJWEServer extends MCPServer with JWE auth capabilities
type ClickHouseJWEServer struct {
	*server.MCPServer
	Config  config.Config
	Version string
	// dynamic tools metadata for OpenAPI routing and schema
	dynamicTools     map[string]dynamicToolMeta
	dynamicToolsMu   sync.RWMutex
	dynamicToolsInit bool
}

type dynamicToolParam struct {
	Name        string
	CHType      string
	JSONType    string
	JSONFormat  string
	Required    bool
	Description string
}

type dynamicToolMeta struct {
	ToolName    string
	Database    string
	Table       string
	Description string
	Params      []dynamicToolParam
}

type AltinityMCPServer interface {
	AddTools(tools ...server.ServerTool)
	AddTool(tool mcp.Tool, handler server.ToolHandlerFunc)
	AddPrompt(prompt mcp.Prompt, handler server.PromptHandlerFunc)
	AddPrompts(prompts ...server.ServerPrompt)
	AddResource(resource mcp.Resource, handler server.ResourceHandlerFunc)
	AddResources(resources ...server.ServerResource)
	AddResourceTemplate(template mcp.ResourceTemplate, handler server.ResourceTemplateHandlerFunc)
}

// NewClickHouseMCPServer creates a new MCP server with ClickHouse integration
func NewClickHouseMCPServer(cfg config.Config, version string) *ClickHouseJWEServer {
	// Create MCP server with comprehensive configuration
	srv := server.NewMCPServer(
		"Altinity ClickHouse MCP Server",
		version,
		server.WithToolCapabilities(true),
		server.WithResourceCapabilities(true, true),
		server.WithPromptCapabilities(true),
		server.WithRecovery(),
	)

	chJweServer := &ClickHouseJWEServer{
		MCPServer:    srv,
		Config:       cfg,
		Version:      version,
		dynamicTools: make(map[string]dynamicToolMeta),
	}

	// Register tools, resources, and prompts
	RegisterTools(chJweServer)
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

// GetClickHouseClient creates a ClickHouse client from JWE token or falls back to default config
func (s *ClickHouseJWEServer) GetClickHouseClient(ctx context.Context, tokenParam string) (*clickhouse.Client, error) {
	if !s.Config.Server.JWE.Enabled {
		// If JWE auth is disabled, use the default config
		client, err := clickhouse.NewClient(ctx, s.Config.ClickHouse)
		if err != nil {
			return nil, fmt.Errorf("failed to create ClickHouse client: %w", err)
		}
		return client, nil
	}

	if tokenParam == "" {
		// JWE auth is enabled but no token provided
		return nil, jwe_auth.ErrMissingToken
	}

	// Parse and validate JWE token
	claims, err := jwe_auth.ParseAndDecryptJWE(tokenParam, []byte(s.Config.Server.JWE.JWESecretKey), []byte(s.Config.Server.JWE.JWTSecretKey))
	if err != nil {
		log.Error().Err(err).Msg("failed to parse/decrypt JWE token")
		return nil, err
	}

	// Create ClickHouse config from JWE claims
	chConfig, err := s.buildConfigFromClaims(claims)
	if err != nil {
		return nil, err
	}

	// Create client with the configured parameters
	client, err := clickhouse.NewClient(ctx, chConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create ClickHouse client from JWE: %w", err)
	}

	return client, nil
}

// buildConfigFromClaims builds a ClickHouse config from JWE claims
func (s *ClickHouseJWEServer) buildConfigFromClaims(claims map[string]interface{}) (config.ClickHouseConfig, error) {
	// Create a new ClickHouse config from the claims
	chConfig := s.Config.ClickHouse // Use default as base

	if host, ok := claims["host"].(string); ok && host != "" {
		chConfig.Host = host
	}
	if port, ok := claims["port"].(float64); ok && port > 0 {
		chConfig.Port = int(port)
	}
	if database, ok := claims["database"].(string); ok && database != "" {
		chConfig.Database = database
	}
	if username, ok := claims["username"].(string); ok && username != "" {
		chConfig.Username = username
	}
	if password, ok := claims["password"].(string); ok && password != "" {
		chConfig.Password = password
	}
	if protocol, ok := claims["protocol"].(string); ok && protocol != "" {
		chConfig.Protocol = config.ClickHouseProtocol(protocol)
	}
	if limit, ok := claims["limit"].(float64); ok && limit > 0 {
		chConfig.Limit = int(limit)
	}

	// Handle TLS configuration from JWE claims
	if tlsEnabled, ok := claims["tls_enabled"].(bool); ok && tlsEnabled {
		chConfig.TLS.Enabled = true

		if caCert, ok := claims["tls_ca_cert"].(string); ok && caCert != "" {
			chConfig.TLS.CaCert = caCert
		}
		if clientCert, ok := claims["tls_client_cert"].(string); ok && clientCert != "" {
			chConfig.TLS.ClientCert = clientCert
		}
		if clientKey, ok := claims["tls_client_key"].(string); ok && clientKey != "" {
			chConfig.TLS.ClientKey = clientKey
		}
		if insecureSkipVerify, ok := claims["tls_insecure_skip_verify"].(bool); ok {
			chConfig.TLS.InsecureSkipVerify = insecureSkipVerify
		}
	}

	return chConfig, nil
}

// ExtractTokenFromCtx extracts a token from context
func (s *ClickHouseJWEServer) ExtractTokenFromCtx(ctx context.Context) string {
	if tokenFromCtx := ctx.Value("jwe_token"); tokenFromCtx != nil {
		if tokenStr, ok := tokenFromCtx.(string); ok {
			return tokenStr
		}
	}
	return ""
}

// ExtractTokenFromRequest extracts a token from an HTTP request
func (s *ClickHouseJWEServer) ExtractTokenFromRequest(r *http.Request) string {
	var token string

	// Try Authorization header (Bearer or Basic)
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		token = strings.TrimPrefix(authHeader, "Bearer ")
	} else if strings.HasPrefix(authHeader, "Basic ") {
		token = strings.TrimPrefix(authHeader, "Basic ")
	}

	// Try x-altinity-mcp-key header
	if token == "" {
		token = r.Header.Get("x-altinity-mcp-key")
	}

	// Try to extract token from URL path (for OpenAPI compatibility)
	if token == "" {
		pathParts := strings.Split(r.URL.Path, "/")
		for i, part := range pathParts {
			if part == "openapi" && i > 0 {
				token = pathParts[i-1]
				break
			}
		}
	}

	return token
}

// ValidateJWEToken validates a JWE token if JWE auth is enabled
func (s *ClickHouseJWEServer) ValidateJWEToken(token string) error {
	if !s.Config.Server.JWE.Enabled {
		return nil
	}

	if token == "" {
		return jwe_auth.ErrMissingToken
	}

	_, err := jwe_auth.ParseAndDecryptJWE(token, []byte(s.Config.Server.JWE.JWESecretKey), []byte(s.Config.Server.JWE.JWTSecretKey))
	if err != nil {
		log.Error().Err(err).Str("token", token).Msg("JWE token validation failed")
		return err
	}

	return nil
}

// ErrJSONEscaper replacing for resolve OpenAI MCP wrong handling single quote and backtick characters in error message
// look details in https://github.com/Altinity/altinity-mcp/issues/19
var ErrJSONEscaper = strings.NewReplacer("'", "\u0027", "`", "\u0060")

// RegisterTools adds the ClickHouse tools to the MCP server
func RegisterTools(srv AltinityMCPServer) {
	// Execute Query Tool
	executeQueryTool := mcp.NewTool(
		"execute_query",
		mcp.WithDescription("Executes a SQL query against ClickHouse and returns the results"),
		mcp.WithString("query",
			mcp.Required(),
			mcp.Description("SQL query to execute (SELECT, INSERT, CREATE, etc.)"),
		),
		mcp.WithNumber("limit",
			mcp.Description("Maximum number of rows to return (default: 100000)"),
		),
	)

	srv.AddTool(executeQueryTool, HandleExecuteQuery)

	log.Info().Int("tool_count", 1).Msg("ClickHouse tools registered")
}

// RegisterResources adds ClickHouse resources to the MCP server
func RegisterResources(srv AltinityMCPServer) {
	// Database Schema Resource
	schemaResource := mcp.NewResource(
		"clickhouse://schema",
		"Database Schema",
		mcp.WithResourceDescription("Complete schema information for the ClickHouse database"),
		mcp.WithMIMEType("application/json"),
	)

	srv.AddResource(schemaResource, HandleSchemaResource)

	// Table Structure Template Resource
	tableTemplate := mcp.NewResourceTemplate(
		"clickhouse://table/{database}/{table_name}",
		"Table Structure",
		mcp.WithTemplateDescription("Detailed structure information for a specific table"),
		mcp.WithTemplateMIMEType("application/json"),
	)

	srv.AddResourceTemplate(tableTemplate, HandleTableResource)

	log.Info().Int("resource_count", 2).Msg("ClickHouse resources registered")
}

// HandleSchemaResource handles the schema resource
func HandleSchemaResource(ctx context.Context, _ mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
	log.Debug().Msg("Reading database schema resource")

	// Get the ClickHouse JWE server from context
	chJweServer := GetClickHouseJWEServerFromContext(ctx)
	if chJweServer == nil {
		return nil, fmt.Errorf("can't get JWEServer from context")
	}

	// Extract token from context
	token := chJweServer.ExtractTokenFromCtx(ctx)

	// Get ClickHouse client
	chClient, err := chJweServer.GetClickHouseClient(ctx, token)
	if err != nil {
		log.Error().Err(err).Msg("Failed to get ClickHouse client")
		return nil, fmt.Errorf("failed to get ClickHouse client: %w", err)
	}
	defer func() {
		if closeErr := chClient.Close(); closeErr != nil {
			log.Error().
				Err(closeErr).
				Msg("clickhouse://schema: can't close clickhouse")
		}
	}()

	// With an empty database string, ListTables will return tables from all databases
	tables, err := chClient.ListTables(ctx, "")
	if err != nil {
		log.Error().
			Err(err).
			Str("resource", "schema").
			Msg("ClickHouse operation failed: get schema")
		return nil, fmt.Errorf("failed to get schema: %w", err)
	}

	schema := map[string]interface{}{
		"tables": tables,
		"count":  len(tables),
	}

	jsonData, err := json.MarshalIndent(schema, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal schema: %w", err)
	}

	return []mcp.ResourceContents{
		mcp.TextResourceContents{
			URI:      "clickhouse://schema",
			MIMEType: "application/json",
			Text:     string(jsonData),
		},
	}, nil
}

// HandleTableResource handles the table resource
func HandleTableResource(ctx context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
	// Extract database and table name from URI
	uri := req.Params.URI
	parts := strings.Split(uri, "/")
	// expected clickhouse://table/{database}/{table_name}
	if len(parts) < 5 || parts[0] != "clickhouse:" || parts[1] != "" || parts[2] != "table" {
		return nil, fmt.Errorf("invalid table URI format: %s", uri)
	}
	database := parts[len(parts)-2]
	tableName := parts[len(parts)-1]

	// Validate that database and table name are not empty
	if database == "" || tableName == "" {
		return nil, fmt.Errorf("invalid table URI format: %s", uri)
	}

	log.Debug().Str("database", database).Str("table", tableName).Msg("Reading table structure resource")

	// Get the ClickHouse JWE server from context
	chJweServer := GetClickHouseJWEServerFromContext(ctx)
	if chJweServer == nil {
		return nil, fmt.Errorf("can't get JWEServer from context")
	}

	// Extract token from context
	token := chJweServer.ExtractTokenFromCtx(ctx)

	// Get ClickHouse client
	chClient, err := chJweServer.GetClickHouseClient(ctx, token)
	if err != nil {
		log.Error().Err(err).Msg("Failed to get ClickHouse client")
		return nil, fmt.Errorf("failed to get ClickHouse client: %w", err)
	}
	defer func() {
		if closeErr := chClient.Close(); closeErr != nil {
			log.Error().
				Err(closeErr).
				Msgf("clickhouse://table/%s/%s: can't close clickhouse", database, tableName)
		}
	}()

	columns, err := chClient.DescribeTable(ctx, database, tableName)
	if err != nil {
		log.Error().
			Err(err).
			Str("database", database).
			Str("table", tableName).
			Str("resource", "table_structure").
			Msg("ClickHouse operation failed: get table structure")
		return nil, fmt.Errorf("failed to get table structure: %s", ErrJSONEscaper.Replace(err.Error()))
	}

	jsonData, err := json.MarshalIndent(columns, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal table structure: %w", err)
	}

	return []mcp.ResourceContents{
		mcp.TextResourceContents{
			URI:      uri,
			MIMEType: "application/json",
			Text:     string(jsonData),
		},
	}, nil
}

// RegisterPrompts adds ClickHouse prompts to the MCP server
func RegisterPrompts(srv AltinityMCPServer) {
	// No prompts registered
	log.Info().Int("prompt_count", 0).Msg("ClickHouse prompts registered")
}

// EnsureDynamicTools discovers ClickHouse views and registers MCP/OpenAPI tools
func (s *ClickHouseJWEServer) EnsureDynamicTools(ctx context.Context) error {
	s.dynamicToolsMu.Lock()
	defer s.dynamicToolsMu.Unlock()

	if s.dynamicToolsInit {
		return nil
	}

	if len(s.Config.Server.DynamicTools) == 0 {
		s.dynamicToolsInit = true
		return nil
	}

	// Check if we have a valid client/token to proceed
	token := s.ExtractTokenFromCtx(ctx)
	// Get ClickHouse client
	chClient, err := s.GetClickHouseClient(ctx, token)
	if err != nil {
		// If we can't get a client (e.g. missing token when JWE enabled), we can't register dynamic tools yet
		// Return error so we retry later
		return fmt.Errorf("dynamic_tools: failed to get ClickHouse client: %w", err)
	}
	defer func() {
		if closeErr := chClient.Close(); closeErr != nil {
			log.Error().Err(closeErr).Msg("dynamic_tools: can't close clickhouse")
		}
	}()

	// fetch views
	q := "SELECT database, name, create_table_query, comment FROM system.tables WHERE engine='View'"
	result, err := chClient.ExecuteQuery(ctx, q)
	if err != nil {
		return fmt.Errorf("dynamic_tools: failed to list views: %w", err)
	}

	// compile regex rules
	type ruleCompiled struct {
		r      *regexp.Regexp
		prefix string
		name   string
	}
	rules := make([]ruleCompiled, 0, len(s.Config.Server.DynamicTools))
	for _, rule := range s.Config.Server.DynamicTools {
		if rule.Regexp == "" {
			continue
		}
		compiled, compErr := regexp.Compile(rule.Regexp)
		if compErr != nil {
			log.Error().Err(compErr).Str("regexp", rule.Regexp).Msg("dynamic_tools: invalid regexp, skipping rule")
			continue
		}
		rules = append(rules, ruleCompiled{r: compiled, prefix: rule.Prefix, name: rule.Name})
	}

	// detect overlaps: map view -> matched rule indexes
	overlaps := false
	dynamicCount := 0

	// Track matches for rules with name field to ensure they match exactly once
	namedRuleMatches := make(map[int][]string) // rule index -> matched views
	for i, rc := range rules {
		if rc.name != "" {
			namedRuleMatches[i] = make([]string, 0)
		}
	}

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
				// Track named rule matches
				if rc.name != "" {
					namedRuleMatches[i] = append(namedRuleMatches[i], full)
				}
			}
		}
		if len(matched) == 0 {
			continue
		}
		if len(matched) > 1 {
			log.Error().Str("view", full).Msg("dynamic_tools: overlap between rules detected for view")
			overlaps = true
			continue
		}

		// single rule match -> register tool
		rc := rules[matched[0]]

		// Determine tool name
		var toolName string
		if rc.name != "" {
			// Use explicit name if provided
			toolName = snakeCase(rc.prefix + rc.name)
		} else {
			// Generate from view name
			toolName = snakeCase(rc.prefix + full)
		}

		params := parseViewParams(create)
		toolDesc, paramDescs := parseComment(comment, db, name)

		for i := range params {
			if d, ok := paramDescs[params[i].Name]; ok {
				params[i].Description = d
			}
		}

		meta := dynamicToolMeta{
			ToolName:    toolName,
			Database:    db,
			Table:       name,
			Description: toolDesc,
			Params:      params,
		}
		s.dynamicTools[toolName] = meta

		// create MCP tool with parameters
		opts := []mcp.ToolOption{mcp.WithDescription(meta.Description)}
		for _, p := range meta.Params {
			desc := p.CHType
			if p.Description != "" {
				desc = fmt.Sprintf("%s, %s", p.CHType, p.Description)
			}
			switch p.JSONType {
			case "boolean":
				opts = append(opts, mcp.WithBoolean(p.Name, mcp.Description(desc)))
			case "number":
				opts = append(opts, mcp.WithNumber(p.Name, mcp.Description(desc)))
			default:
				opts = append(opts, mcp.WithString(p.Name, mcp.Description(desc)))
			}
		}
		tool := mcp.NewTool(toolName, opts...)
		s.AddTool(tool, makeDynamicToolHandler(meta))
		dynamicCount++
	}

	// Validate named rules matched exactly once
	for i, matches := range namedRuleMatches {
		rc := rules[i]
		if len(matches) == 0 {
			log.Error().Str("name", rc.name).Str("regexp", rc.r.String()).Msg("dynamic_tools: named rule matched no views")
		} else if len(matches) > 1 {
			log.Error().Str("name", rc.name).Str("regexp", rc.r.String()).Strs("matched_views", matches).Msg("dynamic_tools: named rule matched multiple views, expected exactly one")
		}
	}

	if overlaps {
		log.Error().Msg("dynamic_tools: overlaps detected; conflicting views were skipped as per policy 'error on overlap'")
	}
	log.Info().Int("tool_count", dynamicCount).Msg("Dynamic ClickHouse view tools registered")

	s.dynamicToolsInit = true
	return nil
}

func makeDynamicToolHandler(meta dynamicToolMeta) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		chJweServer := GetClickHouseJWEServerFromContext(ctx)
		if chJweServer == nil {
			return nil, fmt.Errorf("can't get JWEServer from context")
		}
		// Extract token
		token := chJweServer.ExtractTokenFromCtx(ctx)
		// Client
		chClient, err := chJweServer.GetClickHouseClient(ctx, token)
		if err != nil {
			log.Error().Err(err).Str("tool", meta.ToolName).Msg("dynamic_tools: GetClickHouseClient failed")
			return mcp.NewToolResultError(fmt.Sprintf("Failed to get ClickHouse client: %v", err)), nil
		}
		defer func() {
			if closeErr := chClient.Close(); closeErr != nil {
				log.Error().Err(closeErr).Str("tool", meta.ToolName).Msg("dynamic_tools: close client failed")
			}
		}()

		// build param list
		args := make([]string, 0, len(meta.Params))
		for _, p := range meta.Params {
			if v, ok := req.GetArguments()[p.Name]; ok {
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
			return mcp.NewToolResultError(fmt.Sprintf("Query execution failed: %v", ErrJSONEscaper.Replace(err.Error()))), nil
		}
		jsonData, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{mcp.TextContent{Type: "text", Text: string(jsonData)}}}, nil
	}
}

func parseComment(comment, db, table string) (string, map[string]string) {
	if strings.TrimSpace(comment) == "" {
		return fmt.Sprintf("Tool to load data from %s.%s", db, table), nil
	}

	// Try to parse as new JSON format
	var commentStruct struct {
		Name        string            `json:"name"`
		Description string            `json:"description"`
		Params      map[string]string `json:"params"`
	}
	if err := json.Unmarshal([]byte(comment), &commentStruct); err == nil {
		toolDesc := commentStruct.Description
		if toolDesc == "" {
			toolDesc = fmt.Sprintf("Tool to load data from %s.%s", db, table)
		}
		return toolDesc, commentStruct.Params
	}

	// Not JSON, return as is
	return comment, nil
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
		case string:
			if i, err := strconv.ParseInt(n, 10, 64); err == nil {
				return strconv.FormatInt(i, 10)
			}
			if f, err := strconv.ParseFloat(n, 64); err == nil {
				return strconv.FormatInt(int64(f), 10)
			}
			return "0"
		default:
			return "0"
		}
	case "number":
		switch n := v.(type) {
		case float64:
			return strconv.FormatFloat(n, 'f', -1, 64)
		case string:
			if f, err := strconv.ParseFloat(n, 64); err == nil {
				return strconv.FormatFloat(f, 'f', -1, 64)
			}
			return "0"
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
		if s, ok := v.(string); ok {
			if b, err := strconv.ParseBool(s); err == nil {
				if b {
					return "1"
				}
				return "0"
			}
		}
		return "0"
	default: // string
		// URL-escape then single-quote, minimal safety; ClickHouse expects single-quoted strings
		s := ""
		switch x := v.(type) {
		case string:
			s = x
		default:
			b, _ := json.Marshal(v)
			s = string(b)
		}
		return "'" + strings.ReplaceAll(url.QueryEscape(s), "'", "''") + "'"
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

// HandleListTables implements the list_tables tool handler

// HandleExecuteQuery implements the execute_query tool handler
func HandleExecuteQuery(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	query, err := req.RequireString("query")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	// Get the ClickHouse JWE server from context
	chJweServer := GetClickHouseJWEServerFromContext(ctx)
	if chJweServer == nil {
		return nil, fmt.Errorf("can't get JWEServer from context")
	}

	// Get optional limit parameter
	var limit float64
	hasLimit := false
	if limitVal, exists := req.GetArguments()["limit"]; exists {
		if l, ok := limitVal.(float64); ok && l > 0 {
			limit = l
			hasLimit = true
			// Check against configured max limit if one is set
			if chJweServer.Config.ClickHouse.Limit > 0 && int(l) > chJweServer.Config.ClickHouse.Limit {
				return mcp.NewToolResultError(fmt.Sprintf("Limit cannot exceed %d rows", chJweServer.Config.ClickHouse.Limit)), nil
			}
		}
	}

	log.Debug().
		Str("query", query).
		Float64("limit", limit).
		Bool("has_limit", hasLimit).
		Msg("Executing query")

	// Add LIMIT clause for SELECT queries if limit is specified and not already present
	if hasLimit && isSelectQuery(query) && !hasLimitClause(query) {
		query = fmt.Sprintf("%s LIMIT %.0f", strings.TrimSpace(query), limit)
	}

	// Extract token from context
	token := chJweServer.ExtractTokenFromCtx(ctx)

	// Get ClickHouse client
	chClient, err := chJweServer.GetClickHouseClient(ctx, token)
	if err != nil {
		log.Error().Err(err).Msg("Failed to get ClickHouse client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get ClickHouse client: %v", err)), nil
	}
	defer func() {
		if closeErr := chClient.Close(); closeErr != nil {
			log.Error().
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
		return mcp.NewToolResultError(fmt.Sprintf("Query execution failed: %v", ErrJSONEscaper.Replace(err.Error()))), nil
	}

	jsonData, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to marshal result: %v", err)), nil
	}

	return mcp.NewToolResultText(string(jsonData)), nil
}

// HandleDescribeTable implements the describe_table tool handler

// GetClickHouseJWEServerFromContext extracts the ClickHouseJWEServer from context
func GetClickHouseJWEServerFromContext(ctx context.Context) *ClickHouseJWEServer {
	if srv := ctx.Value("clickhouse_jwe_server"); srv != nil {
		if chJweServer, ok := srv.(*ClickHouseJWEServer); ok {
			return chJweServer
		}
	}
	log.Error().Msg("can't get 'clickhouse_jwe_server' from context")
	return nil
}

// OpenAPIHandler handles OpenAPI schema and REST API endpoints
func (s *ClickHouseJWEServer) OpenAPIHandler(w http.ResponseWriter, r *http.Request) {
	// Get server instance from context
	chJweServer := GetClickHouseJWEServerFromContext(r.Context())
	if chJweServer == nil {
		http.Error(w, "can't get JWEServer from context", http.StatusInternalServerError)
		return
	}

	// Extract token from request
	token := s.ExtractTokenFromRequest(r)

	// Validate JWE token if auth is enabled
	if err := s.ValidateJWEToken(token); err != nil {
		if errors.Is(err, jwe_auth.ErrMissingToken) {
			http.Error(w, "Missing JWE token", http.StatusUnauthorized)
			return
		}
		http.Error(w, "Invalid JWE token", http.StatusUnauthorized)
		return
	}

	// Route to appropriate handler based on path suffix
	switch {
	case strings.HasSuffix(r.URL.Path, "/openapi/execute_query"):
		s.handleExecuteQueryOpenAPI(w, r, token)
	case strings.Contains(r.URL.Path, "/openapi/") && r.Method == http.MethodPost:
		// Ensure dynamic tools are loaded
		if err := s.EnsureDynamicTools(r.Context()); err != nil {
			log.Warn().Err(err).Msg("Failed to ensure dynamic tools in OpenAPI handler")
		}

		// dynamic tool endpoint: /openapi/{tool}
		parts := strings.Split(r.URL.Path, "/openapi/")
		if len(parts) == 2 {
			tool := strings.Trim(parts[1], "/")

			s.dynamicToolsMu.RLock()
			meta, ok := s.dynamicTools[tool]
			s.dynamicToolsMu.RUnlock()

			if ok {
				s.handleDynamicToolOpenAPI(w, r, token, meta)
				return
			}
		}
		http.NotFound(w, r)
	default:
		// Serve OpenAPI schema by default
		s.ServeOpenAPISchema(w, r)
	}
}

func (s *ClickHouseJWEServer) ServeOpenAPISchema(w http.ResponseWriter, r *http.Request) {
	// Ensure dynamic tools are loaded
	if err := s.EnsureDynamicTools(r.Context()); err != nil {
		log.Warn().Err(err).Msg("Failed to ensure dynamic tools in ServeOpenAPISchema")
	}

	// Get host URL based on OpenAPI TLS configuration
	protocol := "http"
	if s.Config.Server.OpenAPI.TLS {
		protocol = "https"
	}
	hostURL := fmt.Sprintf("%s://%s", protocol, r.Host)
	schema := map[string]interface{}{
		"openapi": "3.1.0",
		"info": map[string]interface{}{
			"title":       "ClickHouse SQL Interface",
			"version":     s.Version,
			"description": "Run SQL queries against a ClickHouse instance via GPT-actions.",
		},
		"servers": []map[string]interface{}{
			{
				"url":         hostURL,
				"description": "Base OpenAPI host.",
			},
		},
		"components": map[string]interface{}{
			"schemas": map[string]interface{}{},
		},
		"paths": map[string]interface{}{
			"/{jwe_token}/openapi/execute_query": map[string]interface{}{
				"get": map[string]interface{}{
					"operationId": "execute_query",
					"summary":     "Execute a SQL query",
					"parameters": []map[string]interface{}{
						{
							"name":        "jwe_token",
							"in":          "path",
							"required":    true,
							"description": "JWE token for authentication.",
							"schema": map[string]interface{}{
								"type": "string",
							},
							"x-oai-meta": map[string]interface{}{"securityType": "user_api_key"},
							"default":    "default",
						},
						{
							"name":        "query",
							"in":          "query",
							"required":    true,
							"description": "SQL to execute (SELECT, INSERT, etc.).",
							"schema":      map[string]interface{}{"type": "string"},
						},
						{
							"name":        "limit",
							"in":          "query",
							"required":    false,
							"description": "Optional max rows to return. If not specified, no limit is applied. If configured, cannot exceed server's maximum limit.",
							"schema":      map[string]interface{}{"type": "integer"},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Query result as JSON",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"columns": map[string]interface{}{
												"type":  "array",
												"items": map[string]interface{}{"type": "string"},
											},
											"types": map[string]interface{}{
												"type":  "array",
												"items": map[string]interface{}{"type": "string"},
											},
											"rows": map[string]interface{}{
												"type":  "array",
												"items": map[string]interface{}{"type": "array"},
											},
											"count": map[string]interface{}{"type": "integer"},
											"error": map[string]interface{}{"type": "string"},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	// add dynamic tool paths (POST)
	paths := schema["paths"].(map[string]interface{})

	s.dynamicToolsMu.RLock()
	defer s.dynamicToolsMu.RUnlock()

	for toolName, meta := range s.dynamicTools {
		path := "/{jwe_token}/openapi/" + toolName
		// request body schema
		props := map[string]interface{}{}
		required := []string{}
		for _, p := range meta.Params {
			prop := map[string]interface{}{"type": p.JSONType}
			if p.JSONFormat != "" {
				prop["format"] = p.JSONFormat
			}
			if p.Description != "" {
				prop["description"] = fmt.Sprintf("%s, %s", p.CHType, p.Description)
			} else {
				prop["description"] = p.CHType
			}
			props[p.Name] = prop
			if p.Required {
				required = append(required, p.Name)
			}
		}
		paths[path] = map[string]interface{}{
			"post": map[string]interface{}{
				"summary": meta.Description,
				"requestBody": map[string]interface{}{
					"required": true,
					"content": map[string]interface{}{
						"application/json": map[string]interface{}{
							"schema": map[string]interface{}{
								"type":       "object",
								"properties": props,
								"required":   required,
							},
						},
					},
				},
				"responses": map[string]interface{}{
					"200": map[string]interface{}{
						"description": "Query result",
						"content": map[string]interface{}{
							"application/json": map[string]interface{}{
								"schema": map[string]interface{}{
									"type": "object",
								},
							},
						},
					},
				},
			},
		}
	}

	w.Header().Set("Content-Type", "application/json")
	if encodeErr := json.NewEncoder(w).Encode(schema); encodeErr != nil {
		log.Err(encodeErr).Msg("can't encode /openapi schema")
	}
}

func (s *ClickHouseJWEServer) handleExecuteQueryOpenAPI(w http.ResponseWriter, r *http.Request, token string) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	query := r.URL.Query().Get("query")
	if query == "" {
		http.Error(w, "Query parameter is required", http.StatusBadRequest)
		return
	}

	limitStr := r.URL.Query().Get("limit")
	var limit int
	hasLimit := false
	if limitStr != "" {
		var err error
		limit, err = strconv.Atoi(limitStr)
		if err != nil || limit <= 0 {
			http.Error(w, "Invalid limit parameter", http.StatusBadRequest)
			return
		}
		hasLimit = true
		// Check against configured max limit if one is set
		if s.Config.ClickHouse.Limit > 0 && limit > s.Config.ClickHouse.Limit {
			http.Error(w, fmt.Sprintf("Limit cannot exceed %d", s.Config.ClickHouse.Limit), http.StatusBadRequest)
			return
		}
	}

	// Add LIMIT clause for SELECT queries if limit is specified and not already present
	if hasLimit && isSelectQuery(query) && !hasLimitClause(query) {
		query = fmt.Sprintf("%s LIMIT %d", strings.TrimSpace(query), limit)
	}

	ctx := context.WithValue(r.Context(), "jwe_token", token)

	// Get ClickHouse client
	chClient, err := s.GetClickHouseClient(ctx, token)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get ClickHouse client: %v", err), http.StatusInternalServerError)
		return
	}
	defer func() {
		if closeErr := chClient.Close(); closeErr != nil {
			log.Error().Err(closeErr).Send()
		}
	}()

	result, err := chClient.ExecuteQuery(ctx, query)
	if err != nil {
		http.Error(w, fmt.Sprintf("Query execution failed: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if encodeErr := json.NewEncoder(w).Encode(result); encodeErr != nil {
		log.Err(encodeErr).Msg("can't encode /openapi/execute_query result")
	}
}

func (s *ClickHouseJWEServer) handleDynamicToolOpenAPI(w http.ResponseWriter, r *http.Request, token string, meta dynamicToolMeta) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// validate JWE already done by caller
	// decode JSON body
	var body map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}

	ctx := context.WithValue(r.Context(), "jwe_token", token)
	chClient, err := s.GetClickHouseClient(ctx, token)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get ClickHouse client: %v", err), http.StatusInternalServerError)
		return
	}
	defer func() {
		if closeErr := chClient.Close(); closeErr != nil {
			log.Error().Err(closeErr).Str("tool", meta.ToolName).Msg("dynamic_tools openapi: can't close clickhouse")
		}
	}()

	// build args in stable order of declared params
	argPairs := make([]string, 0, len(meta.Params))
	for _, p := range meta.Params {
		v, ok := body[p.Name]
		if !ok && p.Required {
			http.Error(w, fmt.Sprintf("Missing required parameter: %s", p.Name), http.StatusBadRequest)
			return
		}
		if ok {
			literal := sqlLiteral(p.JSONType, v)
			argPairs = append(argPairs, fmt.Sprintf("%s=%s", p.Name, literal))
		}
	}
	fn := meta.Table
	if len(argPairs) > 0 {
		fn = fmt.Sprintf("%s(%s)", meta.Table, strings.Join(argPairs, ", "))
	}
	query := fmt.Sprintf("SELECT * FROM %s.%s", meta.Database, fn)

	result, err := chClient.ExecuteQuery(ctx, query)
	if err != nil {
		http.Error(w, fmt.Sprintf("Query execution failed: %v", ErrJSONEscaper.Replace(err.Error())), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if encodeErr := json.NewEncoder(w).Encode(result); encodeErr != nil {
		log.Err(encodeErr).Msg("can't encode dynamic tool result")
	}
}

// Helper functions
func isSelectQuery(query string) bool {
	trimmed := strings.TrimSpace(strings.ToUpper(query))
	return strings.HasPrefix(trimmed, "SELECT") || strings.HasPrefix(trimmed, "WITH")
}

func hasLimitClause(query string) bool {
	hasLimit, _ := regexp.MatchString(`(?im)limit\s+\d+`, query)
	return hasLimit
}
