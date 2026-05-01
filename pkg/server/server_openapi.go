package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/altinity/altinity-mcp/pkg/jwe_auth"
	"github.com/rs/zerolog/log"
)

// OpenAPIHandler handles OpenAPI schema and REST API endpoints
func (s *ClickHouseJWEServer) OpenAPIHandler(w http.ResponseWriter, r *http.Request) {
	// Get server instance from context
	chJweServer := GetClickHouseJWEServerFromContext(r.Context())
	if chJweServer == nil {
		http.Error(w, "can't get JWEServer from context", http.StatusInternalServerError)
		return
	}

	// Validate authentication (JWE and/or OAuth)
	jweToken, jweClaims, oauthToken, oauthClaims, err := s.ValidateAuth(r)
	if err != nil {
		if errors.Is(err, jwe_auth.ErrMissingToken) || errors.Is(err, ErrMissingOAuthToken) {
			http.Error(w, "Missing authentication token", http.StatusUnauthorized)
			return
		}
		if errors.Is(err, ErrOAuthTokenExpired) {
			http.Error(w, "OAuth token expired", http.StatusUnauthorized)
			return
		}
		if errors.Is(err, ErrOAuthInsufficientScopes) {
			http.Error(w, "Insufficient OAuth scopes", http.StatusForbidden)
			return
		}
		if errors.Is(err, ErrInvalidOAuthToken) {
			http.Error(w, "Invalid OAuth token", http.StatusUnauthorized)
			return
		}
		http.Error(w, "Invalid authentication token", http.StatusUnauthorized)
		return
	}

	// Store validated auth data in context for downstream handlers.
	ctx := r.Context()
	if jweToken != "" {
		ctx = context.WithValue(ctx, JWETokenKey, jweToken)
		if jweClaims != nil {
			ctx = context.WithValue(ctx, JWEClaimsKey, jweClaims)
		}
	}
	if oauthToken != "" {
		ctx = context.WithValue(ctx, OAuthTokenKey, oauthToken)
	}
	if oauthClaims != nil {
		ctx = context.WithValue(ctx, OAuthClaimsKey, oauthClaims)
	}
	r = r.WithContext(ctx)

	// Route to appropriate handler based on path suffix
	switch {
	case strings.HasSuffix(r.URL.Path, "/openapi/execute_query"):
		s.handleExecuteQueryOpenAPI(w, r)
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
				s.handleDynamicToolOpenAPI(w, r, meta)
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
	executeQueryProperties := map[string]interface{}{
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
	}
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
		"paths": map[string]interface{}{},
	}

	// add dynamic tool paths (POST)
	paths := schema["paths"].(map[string]interface{})
	for _, prefix := range s.openAPIPathPrefixes() {
		parameters := []map[string]interface{}{}
		if prefix != "" {
			parameters = append(parameters, map[string]interface{}{
				"name":        "jwe_token",
				"in":          "path",
				"required":    true,
				"description": "JWE token for authentication.",
				"schema": map[string]interface{}{
					"type": "string",
				},
				"x-oai-meta": map[string]interface{}{"securityType": "user_api_key"},
				"default":    "default",
			})
		}
		parameters = append(parameters,
			map[string]interface{}{
				"name":        "query",
				"in":          "query",
				"required":    true,
				"description": "SQL to execute. In read-only mode, only SELECT/WITH/SHOW/DESC/EXISTS/EXPLAIN are allowed.",
				"schema":      map[string]interface{}{"type": "string"},
			},
			map[string]interface{}{
				"name":        "limit",
				"in":          "query",
				"required":    false,
				"description": "Optional max rows to return. If not specified, no limit is applied. If configured, cannot exceed server's maximum limit.",
				"schema":      map[string]interface{}{"type": "integer"},
			},
		)
		for _, setting := range s.Config.Server.ToolInputSettings {
			parameters = append(parameters, map[string]interface{}{
				"name":        setting,
				"in":          "query",
				"required":    false,
				"description": fmt.Sprintf("ClickHouse setting: %s", setting),
				"schema":      map[string]interface{}{"type": "string"},
			})
		}

		paths[prefix+"/openapi/execute_query"] = map[string]interface{}{
			"get": map[string]interface{}{
				"operationId": "execute_query",
				"summary":     "Execute a SQL query",
				"parameters":  parameters,
				"responses": map[string]interface{}{
					"200": map[string]interface{}{
						"description": "Query result as JSON",
						"content": map[string]interface{}{
							"application/json": map[string]interface{}{
								"schema": map[string]interface{}{
									"type":       "object",
									"properties": executeQueryProperties,
								},
							},
						},
					},
				},
			},
		}
	}

	s.dynamicToolsMu.RLock()
	defer s.dynamicToolsMu.RUnlock()

	for _, prefix := range s.openAPIPathPrefixes() {
		for toolName, meta := range s.dynamicTools {
			path := prefix + "/openapi/" + toolName
			props := map[string]interface{}{}
			required := []string{}
			for _, p := range meta.Params {
				prop := map[string]interface{}{"type": p.JSONType}
				if p.JSONFormat != "" {
					prop["format"] = p.JSONFormat
				}
				props[p.Name] = prop
				if p.Required {
					required = append(required, p.Name)
				}
			}
			if settingsSchema := buildToolInputSettingsSchema(s.Config.Server.ToolInputSettings); settingsSchema != nil {
				props["settings"] = settingsSchema
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
	}

	w.Header().Set("Content-Type", "application/json")
	if encodeErr := json.NewEncoder(w).Encode(schema); encodeErr != nil {
		log.Err(encodeErr).Msg("can't encode /openapi schema")
	}
}

func (s *ClickHouseJWEServer) handleExecuteQueryOpenAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	query := r.URL.Query().Get("query")
	if query == "" {
		http.Error(w, "Query parameter is required", http.StatusBadRequest)
		return
	}

	if clause, err := checkBlockedClauses(query, s.blockedClauses); err != nil {
		http.Error(w, fmt.Sprintf("Query rejected: %v", err), http.StatusBadRequest)
		return
	} else if clause != "" {
		http.Error(w, fmt.Sprintf("Query rejected: %s clause is not allowed", clause), http.StatusBadRequest)
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

	ctx := r.Context()

	// Extract tool input settings from query parameters
	if len(s.Config.Server.ToolInputSettings) > 0 {
		toolSettings := make(map[string]string)
		for _, name := range s.Config.Server.ToolInputSettings {
			if val := r.URL.Query().Get(name); val != "" {
				toolSettings[name] = val
			}
		}
		if len(toolSettings) > 0 {
			ctx = ContextWithToolInputSettings(ctx, toolSettings)
		}
	}

	// Get ClickHouse client (handles both JWE and OAuth from context)
	chClient, err := s.GetClickHouseClientFromCtx(ctx)
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

func (s *ClickHouseJWEServer) handleDynamicToolOpenAPI(w http.ResponseWriter, r *http.Request, meta dynamicToolMeta) {
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

	ctx := r.Context()

	if len(s.Config.Server.ToolInputSettings) > 0 {
		settings, settingsErr := extractToolInputSettings(body, s.Config.Server.ToolInputSettings)
		if settingsErr != nil {
			http.Error(w, fmt.Sprintf("Invalid settings: %v", settingsErr), http.StatusBadRequest)
			return
		}
		if settings != nil {
			ctx = ContextWithToolInputSettings(ctx, settings)
		}
	}

	// Get ClickHouse client (handles both JWE and OAuth from context)
	chClient, err := s.GetClickHouseClientFromCtx(ctx)
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
