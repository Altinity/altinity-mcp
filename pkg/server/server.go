package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/altinity/altinity-mcp/pkg/clickhouse"
	"github.com/altinity/altinity-mcp/pkg/config"
	"github.com/altinity/altinity-mcp/pkg/jwe_auth"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/rs/zerolog/log"
)

var (
	// ErrMissingOAuthToken is returned when OAuth token is missing
	ErrMissingOAuthToken = errors.New("missing OAuth token")
	// ErrInvalidOAuthToken is returned when OAuth token is invalid
	ErrInvalidOAuthToken = errors.New("invalid OAuth token")
	// ErrOAuthTokenExpired is returned when OAuth token has expired
	ErrOAuthTokenExpired = errors.New("OAuth token expired")
	// ErrOAuthInsufficientScopes is returned when token doesn't have required scopes
	ErrOAuthInsufficientScopes = errors.New("insufficient OAuth scopes")
	// ErrOAuthEmailNotVerified is returned when token email is not verified
	ErrOAuthEmailNotVerified = errors.New("OAuth email is not verified")
	// ErrOAuthUnauthorizedDomain is returned when token principal domain is not allowed
	ErrOAuthUnauthorizedDomain = errors.New("OAuth identity domain is not allowed")
)

const (
	oauthJWKSCacheTTL  = 5 * time.Minute
	oauthHTTPTimeout   = 10 * time.Second
	oauthClockSkewSecs = int64(60)
)

type openIDConfiguration struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	UserInfoEndpoint      string `json:"userinfo_endpoint"`
}

// OAuthClaims represents the claims from an OAuth token
type OAuthClaims struct {
	Subject       string   `json:"sub"`
	Issuer        string   `json:"iss"`
	Audience      []string `json:"aud"`
	ExpiresAt     int64    `json:"exp"`
	IssuedAt      int64    `json:"iat"`
	NotBefore     int64    `json:"nbf,omitempty"`
	Scopes        []string `json:"scope"`
	Email         string   `json:"email,omitempty"`
	Name          string   `json:"name,omitempty"`
	HostedDomain  string   `json:"hd,omitempty"`
	EmailVerified bool     `json:"email_verified,omitempty"`
	Extra         map[string]interface{}
}

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
	oidcConfigCache    openIDConfiguration
	oidcConfigCacheURL string
	oidcConfigMu       sync.RWMutex
	oidcConfigTime     time.Time
}

type dynamicToolParam struct {
	Name       string
	CHType     string
	JSONType   string
	JSONFormat string
	Required   bool
}

type dynamicToolMeta struct {
	ToolName    string
	Title       string
	Database    string
	Table       string
	Description string
	Annotations *mcp.ToolAnnotations
	Params      []dynamicToolParam
	ToolType    string // "read" or "write"
	WriteMode   string // "insert", "update", "upsert" (for write tools)
	IsStatic    bool   // true if static tool, false if dynamic
}

type dynamicToolCommentMetadata struct {
	Title       string                         `json:"title"`
	Description string                         `json:"description"`
	Annotations *dynamicToolCommentAnnotations `json:"annotations"`
}

type dynamicToolCommentAnnotations struct {
	OpenWorldHint *bool `json:"openWorldHint"`
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
		MCPServer:    srv,
		Config:       cfg,
		Version:      version,
		dynamicTools: make(map[string]dynamicToolMeta),
	}

	// Register tools, resources, and prompts.
	// Pass pointer to server's Config so dynamic tool rules are stored for EnsureDynamicTools.
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

// GetClickHouseClient creates a ClickHouse client from JWE token or falls back to default config.
// Also forwards any HTTP headers and header-to-settings stored in context by the middleware.
func (s *ClickHouseJWEServer) GetClickHouseClient(ctx context.Context, tokenParam string) (*clickhouse.Client, error) {
	return s.GetClickHouseClientWithHeaders(ctx, tokenParam, ForwardedHeadersFromContext(ctx), HeaderSettingsFromContext(ctx))
}

// GetClickHouseClientWithHeaders creates a ClickHouse client, merging optional per-request
// HTTP headers (e.g. X-Tenant-Id) and ClickHouse settings into the config before connecting.
func (s *ClickHouseJWEServer) GetClickHouseClientWithHeaders(ctx context.Context, tokenParam string, extraHeaders map[string]string, extraSettings map[string]string) (*clickhouse.Client, error) {
	var chConfig config.ClickHouseConfig

	if !s.Config.Server.JWE.Enabled {
		chConfig = s.Config.ClickHouse
	} else {
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

		var buildErr error
		// Create ClickHouse config from JWE claims
		chConfig, buildErr = s.buildConfigFromClaims(claims)
		if buildErr != nil {
			return nil, buildErr
		}
	}

	if len(extraHeaders) > 0 {
		chConfig.HttpHeaders = mergeHTTPHeaders(chConfig.HttpHeaders, extraHeaders)
	}
	if len(extraSettings) > 0 {
		chConfig = mergeExtraSettings(chConfig, extraSettings)
	}

	// Create client with the configured parameters
	client, err := clickhouse.NewClient(ctx, chConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create ClickHouse client: %w", err)
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
	if tokenFromCtx := ctx.Value(JWETokenKey); tokenFromCtx != nil {
		if tokenStr, ok := tokenFromCtx.(string); ok {
			return tokenStr
		}
	}
	return ""
}

// ExtractTokenFromRequest extracts a token from an HTTP request
func (s *ClickHouseJWEServer) ExtractTokenFromRequest(r *http.Request) string {
	var token string

	// Prefer explicit path token when available to avoid conflicting with OAuth bearer auth.
	if pathToken := r.PathValue("token"); pathToken != "" {
		return pathToken
	}

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

func (s *ClickHouseJWEServer) parseJWEClaims(token string) (map[string]interface{}, error) {
	if !s.Config.Server.JWE.Enabled {
		return nil, nil
	}

	if token == "" {
		return nil, jwe_auth.ErrMissingToken
	}

	return jwe_auth.ParseAndDecryptJWE(token, []byte(s.Config.Server.JWE.JWESecretKey), []byte(s.Config.Server.JWE.JWTSecretKey))
}

// ParseJWEClaims parses and decrypts a JWE token into claims.
func (s *ClickHouseJWEServer) ParseJWEClaims(token string) (map[string]interface{}, error) {
	return s.parseJWEClaims(token)
}

// ValidateJWEToken validates a JWE token if JWE auth is enabled
func (s *ClickHouseJWEServer) ValidateJWEToken(token string) error {
	_, err := s.parseJWEClaims(token)
	if err != nil {
		log.Error().Err(err).Msg("JWE token validation failed")
		return err
	}

	return nil
}

// JWEClaimsHaveCredentials returns true if the parsed JWE claims contain a username claim.
func (s *ClickHouseJWEServer) JWEClaimsHaveCredentials(claims map[string]interface{}) bool {
	username, _ := claims["username"].(string)
	return username != ""
}

// JWETokenHasCredentials returns true if the JWE token contains a username claim
func (s *ClickHouseJWEServer) JWETokenHasCredentials(token string) bool {
	claims, err := s.parseJWEClaims(token)
	if err != nil {
		return false
	}
	return s.JWEClaimsHaveCredentials(claims)
}

// ExtractOAuthTokenFromRequest extracts an OAuth token from an HTTP request
func (s *ClickHouseJWEServer) ExtractOAuthTokenFromRequest(r *http.Request) string {
	// Try Authorization header (Bearer token)
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		return strings.TrimPrefix(authHeader, "Bearer ")
	}

	// Try x-oauth-token header
	if token := r.Header.Get("x-oauth-token"); token != "" {
		return token
	}

	// Try x-altinity-oauth-token header
	if token := r.Header.Get("x-altinity-oauth-token"); token != "" {
		return token
	}

	return ""
}

// ExtractOAuthTokenFromCtx extracts an OAuth token from context
func (s *ClickHouseJWEServer) ExtractOAuthTokenFromCtx(ctx context.Context) string {
	if tokenFromCtx := ctx.Value(OAuthTokenKey); tokenFromCtx != nil {
		if tokenStr, ok := tokenFromCtx.(string); ok {
			return tokenStr
		}
	}
	return ""
}

func (s *ClickHouseJWEServer) oauthRequiresLocalValidation() bool {
	return s.Config.Server.OAuth.IsGatingMode()
}

// ValidateOAuthToken validates an OAuth token and returns claims
func (s *ClickHouseJWEServer) ValidateOAuthToken(token string) (*OAuthClaims, error) {
	if !s.Config.Server.OAuth.Enabled {
		return nil, nil
	}

	if token == "" {
		return nil, ErrMissingOAuthToken
	}

	mode := s.Config.Server.OAuth.NormalizedMode()
	var (
		claims *OAuthClaims
		err    error
	)
	if mode == "forward" {
		claims, err = s.parseAndVerifyOAuthToken(token, s.Config.Server.OAuth.Audience)
	} else {
		claims, err = s.parseAndVerifySelfIssuedOAuthToken(token)
	}
	if err != nil {
		log.Error().Err(err).Str("mode", mode).Msg("Failed to validate OAuth token")
		return nil, err
	}

	return s.validateOAuthClaims(claims)
}

func (s *ClickHouseJWEServer) validateOAuthClaims(claims *OAuthClaims) (*OAuthClaims, error) {
	expectedIssuer := strings.TrimSpace(s.Config.Server.OAuth.Issuer)
	if s.Config.Server.OAuth.IsGatingMode() && strings.TrimSpace(s.Config.Server.OAuth.PublicAuthServerURL) != "" {
		expectedIssuer = strings.TrimSpace(s.Config.Server.OAuth.PublicAuthServerURL)
	}
	// Validate issuer if configured
	if expectedIssuer != "" && claims.Issuer != expectedIssuer {
		log.Error().Str("expected", expectedIssuer).Str("got", claims.Issuer).Msg("OAuth token issuer mismatch")
		return nil, ErrInvalidOAuthToken
	}

	// Validate audience if configured
	if s.Config.Server.OAuth.Audience != "" {
		if len(claims.Audience) == 0 {
			log.Error().Str("expected", s.Config.Server.OAuth.Audience).Msg("OAuth token missing audience claim")
			return nil, ErrInvalidOAuthToken
		}
		audienceValid := false
		for _, aud := range claims.Audience {
			if aud == s.Config.Server.OAuth.Audience {
				audienceValid = true
				break
			}
		}
		if !audienceValid {
			log.Error().Str("expected", s.Config.Server.OAuth.Audience).Strs("got", claims.Audience).Msg("OAuth token audience mismatch")
			return nil, ErrInvalidOAuthToken
		}
	}

	now := time.Now().Unix()
	if claims.ExpiresAt > 0 && now > claims.ExpiresAt+oauthClockSkewSecs {
		log.Error().Int64("exp", claims.ExpiresAt).Msg("OAuth token expired")
		return nil, ErrOAuthTokenExpired
	}
	if claims.NotBefore > 0 && now+oauthClockSkewSecs < claims.NotBefore {
		log.Error().Int64("nbf", claims.NotBefore).Msg("OAuth token not yet valid")
		return nil, ErrInvalidOAuthToken
	}
	if claims.IssuedAt > 0 && claims.IssuedAt > now+oauthClockSkewSecs {
		log.Error().Int64("iat", claims.IssuedAt).Msg("OAuth token issued in the future")
		return nil, ErrInvalidOAuthToken
	}

	if len(s.Config.Server.OAuth.RequiredScopes) > 0 {
		if !hasRequiredScopes(claims.Scopes, s.Config.Server.OAuth.RequiredScopes) {
			log.Error().Strs("required", s.Config.Server.OAuth.RequiredScopes).Strs("got", claims.Scopes).Msg("OAuth token missing required scopes")
			return nil, ErrOAuthInsufficientScopes
		}
	}

	if err := s.validateOAuthIdentityPolicy(claims); err != nil {
		return nil, err
	}

	return claims, nil
}

func (s *ClickHouseJWEServer) validateOAuthIdentityPolicy(claims *OAuthClaims) error {
	oauthCfg := s.Config.Server.OAuth
	if oauthCfg.RequireEmailVerified && claims.Email != "" && !claims.EmailVerified {
		log.Error().Str("email", claims.Email).Msg("OAuth identity email is not verified")
		return ErrOAuthEmailNotVerified
	}

	if len(oauthCfg.AllowedEmailDomains) > 0 {
		domain := emailDomain(claims.Email)
		if domain == "" || !containsDomain(oauthCfg.AllowedEmailDomains, domain) {
			log.Error().Str("email", claims.Email).Strs("allowed_domains", oauthCfg.AllowedEmailDomains).Msg("OAuth identity email domain is not allowed")
			return ErrOAuthUnauthorizedDomain
		}
	}

	if len(oauthCfg.AllowedHostedDomains) > 0 {
		if claims.HostedDomain == "" || !containsDomain(oauthCfg.AllowedHostedDomains, claims.HostedDomain) {
			log.Error().Str("hosted_domain", claims.HostedDomain).Strs("allowed_hosted_domains", oauthCfg.AllowedHostedDomains).Msg("OAuth identity hosted domain is not allowed")
			return ErrOAuthUnauthorizedDomain
		}
	}

	return nil
}

// ValidateOAuthIdentityPolicyClaims applies configured post-verification identity policy checks.
func (s *ClickHouseJWEServer) ValidateOAuthIdentityPolicyClaims(claims *OAuthClaims) error {
	return s.validateOAuthIdentityPolicy(claims)
}

func emailDomain(email string) string {
	parts := strings.Split(strings.ToLower(strings.TrimSpace(email)), "@")
	if len(parts) != 2 {
		return ""
	}
	return parts[1]
}

func containsDomain(domains []string, target string) bool {
	for _, domain := range domains {
		if strings.EqualFold(strings.TrimSpace(domain), strings.TrimSpace(target)) {
			return true
		}
	}
	return false
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func looksLikeJWT(token string) bool {
	return strings.Count(token, ".") == 2
}

func (s *ClickHouseJWEServer) parseAndVerifyOAuthToken(token string, expectedAudience string) (*OAuthClaims, error) {
	if looksLikeJWT(token) {
		return s.parseAndVerifyExternalJWT(token, expectedAudience)
	}
	return nil, fmt.Errorf("%w: opaque bearer tokens are not supported without token introspection", ErrInvalidOAuthToken)
}

func (s *ClickHouseJWEServer) parseAndVerifyExternalJWT(token string, expectedAudience string) (*OAuthClaims, error) {
	jwksURI, err := s.resolveOAuthJWKSURL()
	if err != nil {
		return nil, err
	}

	parsed, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{
		jose.RS256, jose.RS384, jose.RS512,
		jose.ES256, jose.ES384, jose.ES512,
		jose.PS256, jose.PS384, jose.PS512,
		jose.EdDSA,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to parse signed JWT: %w", err)
	}
	if len(parsed.Headers) == 0 {
		return nil, fmt.Errorf("missing JWT header")
	}

	keySet, err := s.fetchOAuthJWKSet(jwksURI)
	if err != nil {
		return nil, err
	}

	keys := keySet.Keys
	keyID := parsed.Headers[0].KeyID
	if keyID != "" {
		keys = keySet.Key(keyID)
		if len(keys) == 0 {
			return nil, fmt.Errorf("no JWK found for kid %q", keyID)
		}
	}

	expectedIssuer := strings.TrimSpace(s.Config.Server.OAuth.Issuer)
	var (
		rawClaims         map[string]interface{}
		signatureVerified bool
		issuerRejected    bool
		audienceRejected  bool
	)
	for _, key := range keys {
		rawClaims = make(map[string]interface{})
		if err := parsed.Claims(key.Key, &rawClaims); err != nil {
			continue
		}
		signatureVerified = true
		claims := oauthClaimsFromRawClaims(rawClaims)
		if expectedIssuer != "" && claims.Issuer != expectedIssuer {
			issuerRejected = true
			continue
		}
		if expectedAudience != "" && !containsString(claims.Audience, expectedAudience) {
			audienceRejected = true
			continue
		}
		return claims, nil
	}
	if signatureVerified && (issuerRejected || audienceRejected) {
		return nil, ErrInvalidOAuthToken
	}

	return nil, fmt.Errorf("failed to verify JWT signature with discovered JWKs")
}

func (s *ClickHouseJWEServer) parseAndVerifySelfIssuedOAuthToken(token string) (*OAuthClaims, error) {
	secret := strings.TrimSpace(s.Config.Server.OAuth.GatingSecretKey)
	if secret == "" {
		return nil, fmt.Errorf("oauth gating_secret_key is required in gating mode")
	}
	hashedSecret := jwe_auth.HashSHA256([]byte(secret))

	parsed, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.HS256})
	if err != nil {
		return nil, fmt.Errorf("failed to parse self-issued JWT: %w", err)
	}

	var rawClaims map[string]interface{}
	if err := parsed.Claims(hashedSecret, &rawClaims); err != nil {
		return nil, fmt.Errorf("failed to verify self-issued JWT: %w", err)
	}
	return oauthClaimsFromRawClaims(rawClaims), nil
}

func (s *ClickHouseJWEServer) ValidateUpstreamIdentityToken(token string, expectedAudience string) (*OAuthClaims, error) {
	claims, err := s.parseAndVerifyExternalJWT(token, expectedAudience)
	if err != nil {
		return nil, err
	}
	return claims, s.ValidateOAuthIdentityPolicyClaims(claims)
}

func (s *ClickHouseJWEServer) resolveOAuthJWKSURL() (string, error) {
	if strings.TrimSpace(s.Config.Server.OAuth.JWKSURL) != "" {
		return strings.TrimSpace(s.Config.Server.OAuth.JWKSURL), nil
	}
	if strings.TrimSpace(s.Config.Server.OAuth.Issuer) == "" {
		return "", fmt.Errorf("oauth issuer or jwks_url must be configured")
	}
	discovery, err := s.fetchOpenIDConfiguration(strings.TrimSpace(s.Config.Server.OAuth.Issuer))
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(discovery.JWKSURI) == "" {
		return "", fmt.Errorf("openid discovery did not return jwks_uri")
	}
	return strings.TrimSpace(discovery.JWKSURI), nil
}

func (s *ClickHouseJWEServer) fetchOpenIDConfiguration(issuer string) (*openIDConfiguration, error) {
	issuer = strings.TrimRight(strings.TrimSpace(issuer), "/")
	if issuer == "" {
		return nil, fmt.Errorf("issuer is required")
	}

	s.oidcConfigMu.RLock()
	if s.oidcConfigCacheURL == issuer && !s.oidcConfigTime.IsZero() && s.oidcConfigTime.Add(oauthJWKSCacheTTL).After(time.Now()) && s.oidcConfigCache.Issuer != "" {
		cached := s.oidcConfigCache
		s.oidcConfigMu.RUnlock()
		return &cached, nil
	}
	s.oidcConfigMu.RUnlock()

	urls := []string{
		issuer + "/.well-known/openid-configuration",
	}
	if !strings.Contains(issuer, "/.well-known/") {
		urls = append(urls, issuer+"/.well-known/oauth-authorization-server")
	}

	client := &http.Client{Timeout: oauthHTTPTimeout}
	for _, metadataURL := range urls {
		resp, err := client.Get(metadataURL)
		if err != nil {
			continue
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if resp.StatusCode >= 300 || readErr != nil {
			continue
		}
		var discovery openIDConfiguration
		if err := json.Unmarshal(body, &discovery); err == nil {
			s.oidcConfigMu.Lock()
			s.oidcConfigCache = discovery
			s.oidcConfigCacheURL = issuer
			s.oidcConfigTime = time.Now()
			s.oidcConfigMu.Unlock()
			return &discovery, nil
		}
	}

	return nil, fmt.Errorf("failed to discover openid configuration for issuer %q", issuer)
}

// FetchOpenIDConfiguration returns the discovered OIDC metadata for the configured issuer.
func (s *ClickHouseJWEServer) FetchOpenIDConfiguration(issuer string) (*openIDConfiguration, error) {
	return s.fetchOpenIDConfiguration(issuer)
}

func (s *ClickHouseJWEServer) fetchOAuthJWKSet(jwksURI string) (*jose.JSONWebKeySet, error) {
	now := time.Now()

	s.jwksCacheMu.RLock()
	if len(s.jwksCache.Keys) > 0 && s.jwksCacheURL == jwksURI && s.jwksCacheTime.Add(oauthJWKSCacheTTL).After(now) {
		cached := s.jwksCache
		s.jwksCacheMu.RUnlock()
		return &cached, nil
	}
	s.jwksCacheMu.RUnlock()

	resp, err := (&http.Client{Timeout: oauthHTTPTimeout}).Get(jwksURI)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch jwks: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("failed to read jwks response: %w", err)
	}
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("jwks endpoint returned status %d", resp.StatusCode)
	}

	var keySet jose.JSONWebKeySet
	if err := json.Unmarshal(body, &keySet); err != nil {
		return nil, fmt.Errorf("failed to parse jwks response: %w", err)
	}

	s.jwksCacheMu.Lock()
	s.jwksCache = keySet
	s.jwksCacheURL = jwksURI
	s.jwksCacheTime = now
	s.jwksCacheMu.Unlock()

	return &keySet, nil
}

func oauthClaimsFromRawClaims(rawClaims map[string]interface{}) *OAuthClaims {
	claims := &OAuthClaims{
		Extra: make(map[string]interface{}),
	}

	if sub, ok := rawClaims["sub"].(string); ok {
		claims.Subject = sub
	}
	if iss, ok := rawClaims["iss"].(string); ok {
		claims.Issuer = iss
	}
	if exp, ok := rawClaims["exp"].(float64); ok {
		claims.ExpiresAt = int64(exp)
	}
	if exp, ok := rawClaims["exp"].(json.Number); ok {
		if n, err := exp.Int64(); err == nil {
			claims.ExpiresAt = n
		}
	}
	if iat, ok := rawClaims["iat"].(float64); ok {
		claims.IssuedAt = int64(iat)
	}
	if iat, ok := rawClaims["iat"].(json.Number); ok {
		if n, err := iat.Int64(); err == nil {
			claims.IssuedAt = n
		}
	}
	if nbf, ok := rawClaims["nbf"].(float64); ok {
		claims.NotBefore = int64(nbf)
	}
	if nbf, ok := rawClaims["nbf"].(json.Number); ok {
		if n, err := nbf.Int64(); err == nil {
			claims.NotBefore = n
		}
	}
	if email, ok := rawClaims["email"].(string); ok {
		claims.Email = email
	}
	if name, ok := rawClaims["name"].(string); ok {
		claims.Name = name
	}
	if hd, ok := rawClaims["hd"].(string); ok {
		claims.HostedDomain = hd
	}
	if emailVerified, ok := rawClaims["email_verified"].(bool); ok {
		claims.EmailVerified = emailVerified
	}
	if emailVerified, ok := rawClaims["email_verified"].(string); ok {
		claims.EmailVerified = strings.EqualFold(emailVerified, "true")
	}

	switch aud := rawClaims["aud"].(type) {
	case string:
		claims.Audience = []string{aud}
	case []interface{}:
		for _, a := range aud {
			if audStr, ok := a.(string); ok {
				claims.Audience = append(claims.Audience, audStr)
			}
		}
	}

	switch scope := rawClaims["scope"].(type) {
	case string:
		claims.Scopes = strings.Fields(scope)
	case []interface{}:
		for _, s := range scope {
			if scopeStr, ok := s.(string); ok {
				claims.Scopes = append(claims.Scopes, scopeStr)
			}
		}
	}

	standardClaims := map[string]bool{
		"sub": true, "iss": true, "aud": true, "exp": true, "iat": true, "nbf": true, "jti": true,
		"scope": true, "email": true, "name": true, "hd": true, "email_verified": true,
	}
	for k, v := range rawClaims {
		if !standardClaims[k] {
			claims.Extra[k] = v
			continue
		}
	}

	return claims
}

// hasRequiredScopes checks if all required scopes are present
func hasRequiredScopes(tokenScopes, requiredScopes []string) bool {
	scopeSet := make(map[string]bool)
	for _, s := range tokenScopes {
		scopeSet[s] = true
	}
	for _, required := range requiredScopes {
		if !scopeSet[required] {
			return false
		}
	}
	return true
}

// GetClickHouseClientFromCtx creates a ClickHouse client using JWE and/or OAuth tokens from context
func (s *ClickHouseJWEServer) GetClickHouseClientFromCtx(ctx context.Context) (*clickhouse.Client, error) {
	jweToken := s.ExtractTokenFromCtx(ctx)
	oauthToken := s.ExtractOAuthTokenFromCtx(ctx)
	oauthClaims := s.GetOAuthClaimsFromCtx(ctx)
	return s.GetClickHouseClientWithOAuth(ctx, jweToken, oauthToken, oauthClaims)
}

// GetJWEClaimsFromCtx extracts parsed JWE claims from context.
func (s *ClickHouseJWEServer) GetJWEClaimsFromCtx(ctx context.Context) map[string]interface{} {
	if claims := ctx.Value(JWEClaimsKey); claims != nil {
		if jweClaims, ok := claims.(map[string]interface{}); ok {
			return jweClaims
		}
	}
	return nil
}

// GetOAuthClaimsFromCtx extracts OAuth claims from context
func (s *ClickHouseJWEServer) GetOAuthClaimsFromCtx(ctx context.Context) *OAuthClaims {
	if claims := ctx.Value(OAuthClaimsKey); claims != nil {
		if oauthClaims, ok := claims.(*OAuthClaims); ok {
			return oauthClaims
		}
	}
	return nil
}

// BuildClickHouseHeadersFromOAuth builds HTTP headers to forward to ClickHouse based on OAuth config
func (s *ClickHouseJWEServer) BuildClickHouseHeadersFromOAuth(token string, claims *OAuthClaims) map[string]string {
	if !s.Config.Server.OAuth.IsForwardMode() {
		return nil
	}

	headers := make(map[string]string)

	// Forward the access token (always in forward mode)
	headerName := s.Config.Server.OAuth.ClickHouseHeaderName
	if headerName == "" {
		headerName = "Authorization"
	}
	if headerName == "Authorization" {
		headers[headerName] = "Bearer " + token
	} else {
		headers[headerName] = token
	}

	// Map claims to headers if configured
	if len(s.Config.Server.OAuth.ClaimsToHeaders) > 0 && claims != nil {
		for claimName, headerName := range s.Config.Server.OAuth.ClaimsToHeaders {
			var value string
			switch claimName {
			case "sub":
				value = claims.Subject
			case "iss":
				value = claims.Issuer
			case "email":
				value = claims.Email
			case "name":
				value = claims.Name
			case "email_verified":
				if claims.EmailVerified {
					value = "true"
				} else {
					value = "false"
				}
			case "hd":
				value = claims.HostedDomain
			default:
				// Check extra claims
				if v, ok := claims.Extra[claimName]; ok {
					if strVal, ok := v.(string); ok {
						value = strVal
					} else {
						// Try to JSON encode non-string values
						if jsonBytes, err := json.Marshal(v); err == nil {
							value = string(jsonBytes)
						}
					}
				}
			}
			if value != "" {
				headers[headerName] = value
			}
		}
	}

	return headers
}

// ValidateAuth validates authentication using priority/fallback semantics.
// JWE takes priority: if present and valid with credentials, OAuth is skipped.
// If JWE is absent or has no credentials, falls through to OAuth.
func (s *ClickHouseJWEServer) ValidateAuth(r *http.Request) (jweToken string, jweClaims map[string]interface{}, oauthToken string, oauthClaims *OAuthClaims, err error) {
	jweEnabled := s.Config.Server.JWE.Enabled
	oauthEnabled := s.Config.Server.OAuth.Enabled

	// If neither auth method is enabled, no validation needed
	if !jweEnabled && !oauthEnabled {
		return "", nil, "", nil, nil
	}

	// Try JWE first
	if jweEnabled {
		if oauthEnabled {
			// When OAuth is also enabled, only extract JWE from unambiguous sources
			// (path value / x-altinity-mcp-key) to avoid conflicting with OAuth Bearer.
			jweToken = r.PathValue("token")
			if jweToken == "" {
				jweToken = r.Header.Get("x-altinity-mcp-key")
			}
		} else {
			jweToken = s.ExtractTokenFromRequest(r)
		}
		if jweToken != "" {
			jweClaims, err = s.ParseJWEClaims(jweToken)
			if err != nil {
				return "", nil, "", nil, err // JWE present but invalid → hard error
			}
			if s.JWEClaimsHaveCredentials(jweClaims) {
				return jweToken, jweClaims, "", nil, nil // JWE sufficient, skip OAuth
			}
		}
	}

	// Fall through to OAuth
	if oauthEnabled {
		oauthToken = s.ExtractOAuthTokenFromRequest(r)
		if oauthToken == "" {
			return jweToken, jweClaims, "", nil, ErrMissingOAuthToken
		}
		if s.oauthRequiresLocalValidation() {
			oauthClaims, err = s.ValidateOAuthToken(oauthToken)
			if err != nil {
				return jweToken, jweClaims, "", nil, err
			}
		}
		return jweToken, jweClaims, oauthToken, oauthClaims, nil
	}

	// JWE enabled but no token and no OAuth
	if jweEnabled && jweToken == "" {
		return "", nil, "", nil, jwe_auth.ErrMissingToken
	}

	return jweToken, jweClaims, "", nil, nil
}

func (s *ClickHouseJWEServer) openAPIPathPrefixes() []string {
	if s.Config.Server.JWE.Enabled {
		prefixes := []string{"/{jwe_token}"}
		if s.Config.Server.OAuth.Enabled {
			prefixes = append(prefixes, "")
		}
		return prefixes
	}
	return []string{""}
}

// GetClickHouseClientWithOAuth creates a ClickHouse client, optionally forwarding OAuth headers
func (s *ClickHouseJWEServer) GetClickHouseClientWithOAuth(ctx context.Context, jweToken string, oauthToken string, oauthClaims *OAuthClaims) (*clickhouse.Client, error) {
	// Build base config
	var chConfig config.ClickHouseConfig
	var err error

	// If JWE is enabled and token provided, use JWE config
	if s.Config.Server.JWE.Enabled && jweToken != "" {
		claims := s.GetJWEClaimsFromCtx(ctx)
		if claims == nil {
			claims, err = s.ParseJWEClaims(jweToken)
			if err != nil {
				return nil, fmt.Errorf("failed to parse JWE token: %w", err)
			}
		}
		chConfig, err = s.buildConfigFromClaims(claims)
		if err != nil {
			return nil, err
		}
	} else {
		chConfig = s.Config.ClickHouse
	}

	// Add OAuth headers if forwarding is enabled
	if s.Config.Server.OAuth.IsForwardMode() && oauthToken != "" {
		oauthHeaders := s.BuildClickHouseHeadersFromOAuth(oauthToken, oauthClaims)
		if len(oauthHeaders) > 0 {
			if chConfig.HttpHeaders == nil {
				chConfig.HttpHeaders = make(map[string]string)
			}
			for k, v := range oauthHeaders {
				chConfig.HttpHeaders[k] = v
			}
		}
		// In forward mode, always clear static credentials — ClickHouse authenticates via the token
		chConfig.Username = ""
		chConfig.Password = ""
	}

	// Merge forwarded HTTP headers from context (forward_http_headers)
	if extraHeaders := ForwardedHeadersFromContext(ctx); len(extraHeaders) > 0 {
		chConfig.HttpHeaders = mergeHTTPHeaders(chConfig.HttpHeaders, extraHeaders)
	}

	// Merge header-to-settings from context (header_to_settings)
	if extraSettings := HeaderSettingsFromContext(ctx); len(extraSettings) > 0 {
		chConfig = mergeExtraSettings(chConfig, extraSettings)
	}

	// Create client
	client, err := clickhouse.NewClient(ctx, chConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create ClickHouse client: %w", err)
	}

	return client, nil
}

// ErrJSONEscaper replacing for resolve OpenAI MCP wrong handling single quote and backtick characters in error message
// look details in https://github.com/Altinity/altinity-mcp/issues/19
var ErrJSONEscaper = strings.NewReplacer("'", "\u0027", "`", "\u0060")

// RegisterTools adds the ClickHouse tools to the MCP server.
// cfg is a pointer so that converted dynamic tool rules are stored
// back for EnsureDynamicTools to discover later.
func RegisterTools(srv AltinityMCPServer, cfg *config.Config) {
	var toolsToRegister []config.ToolDefinition

	// Determine which tools to register: new unified config, old config, or defaults
	if len(cfg.Server.Tools) > 0 {
		// New unified tools config
		toolsToRegister = cfg.Server.Tools
	} else if len(cfg.Server.DynamicTools) > 0 {
		// Old format: convert DynamicTools to ToolDefinition for backwards compatibility
		log.Warn().Msg("dynamic_tools config is deprecated, use tools instead")
		for _, oldRule := range cfg.Server.DynamicTools {
			toolDef := config.ToolDefinition{
				Type:   oldRule.Type,
				Name:   oldRule.Name,
				Regexp: oldRule.Regexp,
				Prefix: oldRule.Prefix,
				Mode:   oldRule.Mode,
			}
			// Default type to "read" if not specified (backwards compat)
			if toolDef.Type == "" && toolDef.Regexp != "" {
				toolDef.Type = "read"
			}
			toolsToRegister = append(toolsToRegister, toolDef)
		}
	} else {
		// Default: register static tools only
		toolsToRegister = []config.ToolDefinition{
			{Type: "read", Name: "execute_query"},
			{Type: "write", Name: "write_query"},
		}
	}

	// Process tools: separate static and dynamic
	staticToolCount := 0
	dynamicToolRules := make([]config.ToolDefinition, 0)

	for _, toolDef := range toolsToRegister {
		// Validate tool definition
		if toolDef.Type != "read" && toolDef.Type != "write" {
			log.Error().Str("type", toolDef.Type).Msg("Invalid tool type, must be 'read' or 'write'")
			continue
		}

		// Static tool: has Name, no Regexp
		if toolDef.Name != "" && toolDef.Regexp == "" {
			if registerStaticTool(srv, toolDef, cfg.ClickHouse.ReadOnly) {
				staticToolCount++
			}
		} else if toolDef.Regexp != "" {
			// Dynamic tool: has Regexp (Name is optional)
			// Validate type and mode for write tools
			if toolDef.Type == "write" && toolDef.Mode == "" {
				log.Error().Str("regexp", toolDef.Regexp).Msg("Write tool must specify mode (insert, update, upsert)")
				continue
			}
			dynamicToolRules = append(dynamicToolRules, toolDef)
		} else {
			log.Error().Str("name", toolDef.Name).Str("regexp", toolDef.Regexp).Msg("Tool definition must have either name (static) or regexp (dynamic)")
			continue
		}
	}

	// Store dynamic tool rules for later discovery in EnsureDynamicTools
	// Clear old DynamicTools and populate from new format
	cfg.Server.DynamicTools = convertToOldFormat(dynamicToolRules)

	log.Info().Int("static_tool_count", staticToolCount).Int("dynamic_tool_rules", len(dynamicToolRules)).Msg("ClickHouse tools registered")
}

// registerStaticTool registers a static tool (not discovered, explicitly configured).
// Returns true if the tool was actually registered.
func registerStaticTool(srv AltinityMCPServer, toolDef config.ToolDefinition, readOnly bool) bool {
	switch toolDef.Type {
	case "read":
		if toolDef.Name == "execute_query" {
			executeQueryTool := &mcp.Tool{
				Name:        "execute_query",
				Title:       "Execute SQL Query",
				Description: "Executes a SQL query against ClickHouse and returns the results",
				Annotations: makeExecuteQueryAnnotations(readOnly),
				InputSchema: map[string]any{
					"type": "object",
					"properties": map[string]any{
						"query": map[string]any{
							"type":        "string",
							"description": "SQL query to execute. In read-only mode, only SELECT/WITH/SHOW/DESC/EXISTS/EXPLAIN are allowed.",
						},
						"limit": map[string]any{
							"type":        "number",
							"description": "Maximum number of rows to return (default: 100000)",
						},
					},
					"required": []string{"query"},
				},
			}
			srv.AddTool(executeQueryTool, HandleExecuteQuery)
			log.Info().Str("tool", "execute_query").Msg("Static read tool registered")
			return true
		}
		log.Warn().Str("tool_name", toolDef.Name).Msg("Unknown static read tool name")
		return false

	case "write":
		if toolDef.Name == "write_query" {
			if readOnly {
				log.Info().Str("tool", "write_query").Msg("Write tool skipped (read-only mode)")
				return false
			}
			writeQueryTool := &mcp.Tool{
				Name:        "write_query",
				Title:       "Execute Write Query",
				Description: "Executes a write query (INSERT, UPDATE, DELETE, ALTER) against ClickHouse",
				Annotations: &mcp.ToolAnnotations{
					ReadOnlyHint:    false,
					DestructiveHint: boolPtr(true),
				},
				InputSchema: map[string]any{
					"type": "object",
					"properties": map[string]any{
						"query": map[string]any{
							"type":        "string",
							"description": "SQL write query to execute (INSERT, UPDATE, DELETE, ALTER)",
						},
						"limit": map[string]any{
							"type":        "number",
							"description": "Maximum number of rows to return for queries with result sets",
						},
					},
					"required": []string{"query"},
				},
			}
			srv.AddTool(writeQueryTool, HandleExecuteQuery)
			log.Info().Str("tool", "write_query").Msg("Static write tool registered")
			return true
		}
		log.Warn().Str("tool_name", toolDef.Name).Msg("Unknown static write tool name")
		return false

	default:
		log.Error().Str("type", toolDef.Type).Msg("Unknown tool type")
		return false
	}
}

// convertToOldFormat converts ToolDefinition array back to DynamicToolRule format for EnsureDynamicTools
func convertToOldFormat(toolDefs []config.ToolDefinition) []config.DynamicToolRule {
	rules := make([]config.DynamicToolRule, len(toolDefs))
	for i, toolDef := range toolDefs {
		rules[i] = config.DynamicToolRule{
			Type:   toolDef.Type,
			Name:   toolDef.Name,
			Regexp: toolDef.Regexp,
			Prefix: toolDef.Prefix,
			Mode:   toolDef.Mode,
		}
	}
	return rules
}

// boolPtr returns a pointer to a boolean value
func boolPtr(b bool) *bool {
	return &b
}

// RegisterResources adds ClickHouse resources to the MCP server
func RegisterResources(srv AltinityMCPServer) {
	// Database Schema Resource
	schemaResource := &mcp.Resource{
		URI:         "clickhouse://schema",
		Name:        "Database Schema",
		Description: "Complete schema information for the ClickHouse database",
		MIMEType:    "application/json",
	}

	srv.AddResource(schemaResource, HandleSchemaResource)

	// Table Structure Template Resource
	tableTemplate := &mcp.ResourceTemplate{
		URITemplate: "clickhouse://table/{database}/{table_name}",
		Name:        "Table Structure",
		Description: "Detailed structure information for a specific table",
		MIMEType:    "application/json",
	}

	srv.AddResourceTemplate(tableTemplate, HandleTableResource)

	log.Info().Int("resource_count", 2).Msg("ClickHouse resources registered")
}

// HandleSchemaResource handles the schema resource
func HandleSchemaResource(ctx context.Context, _ *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
	log.Debug().Msg("Reading database schema resource")

	// Get the ClickHouse JWE server from context
	chJweServer := GetClickHouseJWEServerFromContext(ctx)
	if chJweServer == nil {
		return nil, fmt.Errorf("can't get JWEServer from context")
	}

	// Get ClickHouse client (handles both JWE and OAuth from context)
	chClient, err := chJweServer.GetClickHouseClientFromCtx(ctx)
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

	return &mcp.ReadResourceResult{
		Contents: []*mcp.ResourceContents{
			{
				URI:      "clickhouse://schema",
				MIMEType: "application/json",
				Text:     string(jsonData),
			},
		},
	}, nil
}

// HandleTableResource handles the table resource
func HandleTableResource(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
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

	// Get ClickHouse client (handles both JWE and OAuth from context)
	chClient, err := chJweServer.GetClickHouseClientFromCtx(ctx)
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

	return &mcp.ReadResourceResult{
		Contents: []*mcp.ResourceContents{
			{
				URI:      uri,
				MIMEType: "application/json",
				Text:     string(jsonData),
			},
		},
	}, nil
}

// RegisterPrompts adds ClickHouse prompts to the MCP server
func RegisterPrompts(srv AltinityMCPServer) {
	// No prompts registered
	log.Info().Int("prompt_count", 0).Msg("ClickHouse prompts registered")
}

// EnsureDynamicTools discovers ClickHouse views and registers MCP/OpenAPI tools.
// It is called on every request via middleware. Discovery is deferred until
// credentials are available — in forward-OAuth mode, the Bearer token only
// arrives with the first authenticated tool call, not during tools/list.
// The MCP SDK automatically sends notifications/tools/list_changed when
// AddTool is called, so the client re-fetches the tool list after discovery.
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

	// Check if we have any credentials to connect to ClickHouse.
	// In forward-OAuth mode with blank static creds, the OAuth token
	// may not be available yet (e.g., during tools/list handshake).
	// Skip gracefully — we'll retry on the next request when the token arrives.
	if !s.hasDiscoveryCredentials(ctx) {
		log.Debug().Msg("dynamic_tools: no credentials available yet, deferring discovery")
		return nil
	}

	// Discover and register dynamic tools (both read and write)
	readTools, err := s.discoverReadTools(ctx)
	if err != nil {
		return err
	}

	writeTools, err := s.discoverWriteTools(ctx)
	if err != nil {
		return err
	}

	// Register both read and write tools.
	// AddTool sends notifications/tools/list_changed automatically.
	s.registerDynamicTools(readTools, writeTools)
	s.dynamicToolsInit = true
	return nil
}

// hasDiscoveryCredentials checks if the current context has any form of
// credentials that can be used to query ClickHouse for tool discovery.
func (s *ClickHouseJWEServer) hasDiscoveryCredentials(ctx context.Context) bool {
	// JWE token in context
	if s.ExtractTokenFromCtx(ctx) != "" {
		return true
	}
	// OAuth token in context (forward mode)
	if s.ExtractOAuthTokenFromCtx(ctx) != "" {
		return true
	}
	// Static credentials configured
	if s.Config.ClickHouse.Username != "" {
		return true
	}
	return false
}

// getDiscoveryClient returns a ClickHouse client suitable for tool discovery.
// It uses GetClickHouseClientFromCtx which handles JWE, OAuth, and static credentials.
func (s *ClickHouseJWEServer) getDiscoveryClient(ctx context.Context) (*clickhouse.Client, error) {
	return s.GetClickHouseClientFromCtx(ctx)
}

// discoverReadTools discovers read-only tools from views
func (s *ClickHouseJWEServer) discoverReadTools(ctx context.Context) (map[string]dynamicToolMeta, error) {
	readRules := filterRulesByType(s.Config.Server.DynamicTools, "read")
	if len(readRules) == 0 {
		return make(map[string]dynamicToolMeta), nil
	}

	chClient, err := s.getDiscoveryClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("dynamic_tools: failed to get ClickHouse client: %w", err)
	}
	defer chClient.Close()

	q := "SELECT database, name, create_table_query, comment FROM system.tables WHERE engine='View'"
	result, err := chClient.ExecuteQuery(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("dynamic_tools: failed to list views: %w", err)
	}

	tools := make(map[string]dynamicToolMeta)
	type ruleCompiled struct {
		r      *regexp.Regexp
		prefix string
		name   string
	}
	rules := make([]ruleCompiled, 0)
	for _, rule := range readRules {
		if rule.Regexp == "" {
			continue
		}
		compiled, err := regexp.Compile(rule.Regexp)
		if err != nil {
			log.Error().Err(err).Str("regexp", rule.Regexp).Msg("dynamic_tools: invalid regexp")
			continue
		}
		rules = append(rules, ruleCompiled{r: compiled, prefix: rule.Prefix, name: rule.Name})
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
			}
		}
		if len(matched) == 0 {
			continue
		}
		if len(matched) > 1 {
			log.Error().Str("view", full).Msg("dynamic_tools: overlap between rules")
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

	log.Info().Int("tool_count", len(tools)).Msg("Dynamic read tools discovered")
	return tools, nil
}

// discoverWriteTools discovers write tools from tables
func (s *ClickHouseJWEServer) discoverWriteTools(ctx context.Context) (map[string]dynamicToolMeta, error) {
	if s.Config.ClickHouse.ReadOnly {
		log.Info().Msg("Write tools disabled in read-only mode")
		return make(map[string]dynamicToolMeta), nil
	}

	writeRules := filterRulesByType(s.Config.Server.DynamicTools, "write")
	if len(writeRules) == 0 {
		return make(map[string]dynamicToolMeta), nil
	}

	chClient, err := s.getDiscoveryClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("dynamic_tools: failed to get ClickHouse client: %w", err)
	}
	defer chClient.Close()

	// Query tables (excluding system tables)
	q := "SELECT database, name, comment FROM system.tables WHERE engine NOT IN ('View', 'MaterializedView', 'Alias') AND database NOT IN ('system', 'INFORMATION_SCHEMA')"
	result, err := chClient.ExecuteQuery(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("dynamic_tools: failed to list tables: %w", err)
	}

	tools := make(map[string]dynamicToolMeta)
	type ruleCompiled struct {
		r      *regexp.Regexp
		prefix string
		name   string
		mode   string
	}
	rules := make([]ruleCompiled, 0)
	for _, rule := range writeRules {
		if rule.Regexp == "" {
			continue
		}
		compiled, err := regexp.Compile(rule.Regexp)
		if err != nil {
			log.Error().Err(err).Str("regexp", rule.Regexp).Msg("dynamic_tools: invalid regexp for write tool")
			continue
		}
		rules = append(rules, ruleCompiled{r: compiled, prefix: rule.Prefix, name: rule.Name, mode: rule.Mode})
	}

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
			log.Error().Str("table", full).Msg("dynamic_tools: overlap between rules for write tool")
			continue
		}

		rc := rules[matched[0]]

		// Get table columns
		cols, err := s.getTableColumnsForMode(ctx, chClient, db, name, rc.mode)
		if err != nil {
			log.Warn().Str("table", full).Err(err).Msg("dynamic_tools: failed to get columns for write tool")
			continue
		}

		var toolName string
		if rc.name != "" {
			toolName = snakeCase(rc.prefix + rc.name)
		} else {
			toolName = snakeCase(rc.prefix + full)
		}

		// Build metadata for write tool
		meta := dynamicToolMeta{
			ToolName:    toolName,
			Title:       humanizeToolName(toolName),
			Database:    db,
			Table:       name,
			Description: buildWriteToolDescription(comment, db, name, rc.mode),
			Annotations: &mcp.ToolAnnotations{
				ReadOnlyHint:    false,
				DestructiveHint: boolPtr(true),
			},
			Params:    cols,
			ToolType:  "write",
			WriteMode: rc.mode,
		}
		tools[toolName] = meta
	}

	log.Info().Int("tool_count", len(tools)).Msg("Dynamic write tools discovered")
	return tools, nil
}

// getTableColumnsForMode retrieves and filters table columns for a specific write mode
func (s *ClickHouseJWEServer) getTableColumnsForMode(ctx context.Context, chClient *clickhouse.Client, db, table, mode string) ([]dynamicToolParam, error) {
	// Query column information. Avoid column_type which doesn't exist in all
	// ClickHouse versions; default_kind covers the same exclusion cases.
	q := fmt.Sprintf("SELECT name, type, default_kind, comment FROM system.columns WHERE database='%s' AND table='%s' ORDER BY position",
		db, table)
	result, err := chClient.ExecuteQuery(ctx, q)
	if err != nil {
		return nil, err
	}

	params := make([]dynamicToolParam, 0)
	for _, row := range result.Rows {
		if len(row) < 3 {
			continue
		}
		name, _ := row[0].(string)
		chType, _ := row[1].(string)
		defaultKind, _ := row[2].(string)

		// Skip computed columns: MATERIALIZED (auto-computed) and ALIAS (virtual)
		if defaultKind == "MATERIALIZED" || defaultKind == "ALIAS" {
			continue
		}

		// Determine if column is required
		required := defaultKind == ""

		jsonType, jsonFmt := mapCHType(chType)

		params = append(params, dynamicToolParam{
			Name:       name,
			CHType:     chType,
			JSONType:   jsonType,
			JSONFormat: jsonFmt,
			Required:   required,
		})
	}

	return params, nil
}

// buildWriteToolDescription generates description for write tools
func buildWriteToolDescription(comment, db, table, mode string) string {
	if comment == "" {
		modeDesc := "Insert data"
		if mode == "update" {
			modeDesc = "Update data"
		} else if mode == "upsert" {
			modeDesc = "Insert or update data"
		}
		return fmt.Sprintf("%s in %s.%s", modeDesc, db, table)
	}
	return comment
}

// registerDynamicTools registers discovered tools with the MCP server
func (s *ClickHouseJWEServer) registerDynamicTools(readTools, writeTools map[string]dynamicToolMeta) {
	for toolName, meta := range readTools {
		s.dynamicTools[toolName] = meta
		props := make(map[string]any)
		for _, p := range meta.Params {
			props[p.Name] = map[string]any{
				"type":        p.JSONType,
				"description": p.CHType,
			}
		}
		tool := &mcp.Tool{
			Name:        toolName,
			Title:       meta.Title,
			Description: meta.Description,
			Annotations: meta.Annotations,
			InputSchema: map[string]any{
				"type":       "object",
				"properties": props,
			},
		}
		s.AddTool(tool, makeDynamicToolHandler(meta))
	}

	for toolName, meta := range writeTools {
		s.dynamicTools[toolName] = meta
		props := make(map[string]any)
		for _, p := range meta.Params {
			props[p.Name] = map[string]any{
				"type":        p.JSONType,
				"description": p.CHType,
			}
		}
		tool := &mcp.Tool{
			Name:        toolName,
			Title:       meta.Title,
			Description: meta.Description,
			Annotations: meta.Annotations,
			InputSchema: map[string]any{
				"type":       "object",
				"properties": props,
			},
		}
		s.AddTool(tool, makeDynamicWriteToolHandler(meta))
	}

	log.Info().Int("read_tools", len(readTools)).Int("write_tools", len(writeTools)).Msg("Dynamic tools registered")
}

// filterRulesByType filters dynamic tool rules by type (read or write)
func filterRulesByType(rules []config.DynamicToolRule, toolType string) []config.DynamicToolRule {
	filtered := make([]config.DynamicToolRule, 0)
	for _, rule := range rules {
		// Default type to "read" if not specified (backwards compat)
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

// makeDynamicToolHandler creates a handler for read-only dynamic tools
func makeDynamicToolHandler(meta dynamicToolMeta) ToolHandlerFunc {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		chJweServer := GetClickHouseJWEServerFromContext(ctx)
		if chJweServer == nil {
			return nil, fmt.Errorf("can't get JWEServer from context")
		}
		// Get ClickHouse client (handles both JWE and OAuth from context)
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

		// Get arguments from request
		arguments := getArgumentsMap(req)

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

// makeDynamicWriteToolHandler creates a handler for write dynamic tools
func makeDynamicWriteToolHandler(meta dynamicToolMeta) ToolHandlerFunc {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		chJweServer := GetClickHouseJWEServerFromContext(ctx)
		if chJweServer == nil {
			return nil, fmt.Errorf("can't get JWEServer from context")
		}

		// Check read-only mode
		if chJweServer.Config.ClickHouse.ReadOnly {
			return NewToolResultError("Write operations disabled in read-only mode"), nil
		}

		chClient, err := chJweServer.GetClickHouseClientFromCtx(ctx)
		if err != nil {
			log.Error().Err(err).Str("tool", meta.ToolName).Msg("dynamic_tools: GetClickHouseClient failed")
			return NewToolResultError(fmt.Sprintf("Failed to get ClickHouse client: %v", err)), nil
		}
		defer chClient.Close()

		arguments := getArgumentsMap(req)

		// Build query based on write mode
		query, err := buildDynamicWriteQuery(meta, arguments)
		if err != nil {
			log.Error().Err(err).Str("tool", meta.ToolName).Msg("dynamic_tools: failed to build write query")
			return NewToolResultError(fmt.Sprintf("Failed to build query: %v", err)), nil
		}

		log.Debug().Str("tool", meta.ToolName).Str("query", query).Msg("dynamic_tools: executing write query")
		_, err = chClient.ExecuteQuery(ctx, query)
		if err != nil {
			log.Error().Err(err).Str("tool", meta.ToolName).Str("query", query).Msg("dynamic_tools: write query failed")
			return NewToolResultError(fmt.Sprintf("Query failed: %v", ErrJSONEscaper.Replace(err.Error()))), nil
		}

		return NewToolResultText(fmt.Sprintf("Successfully executed %s", meta.ToolName)), nil
	}
}

// buildDynamicWriteQuery builds a SQL write query from tool parameters
func buildDynamicWriteQuery(meta dynamicToolMeta, args map[string]interface{}) (string, error) {
	switch meta.WriteMode {
	case "insert":
		return buildInsertQuery(meta, args)
	case "update":
		// UPDATE not yet implemented
		return "", fmt.Errorf("UPDATE mode not yet implemented; use write_query tool instead")
	case "upsert":
		// UPSERT not yet implemented
		return "", fmt.Errorf("UPSERT mode not yet implemented; use write_query tool instead")
	default:
		return "", fmt.Errorf("unknown write mode: %s", meta.WriteMode)
	}
}

// buildInsertQuery builds an INSERT query from tool parameters
func buildInsertQuery(meta dynamicToolMeta, args map[string]interface{}) (string, error) {
	cols := make([]string, 0)
	vals := make([]string, 0)

	for _, param := range meta.Params {
		val, ok := args[param.Name]
		if ok {
			cols = append(cols, param.Name)
			literal := sqlLiteral(param.JSONType, val)
			vals = append(vals, literal)
		} else if param.Required {
			return "", fmt.Errorf("required parameter missing: %s", param.Name)
		}
	}

	if len(cols) == 0 {
		return "", fmt.Errorf("no columns provided")
	}

	colList := strings.Join(cols, ", ")
	valList := strings.Join(vals, ", ")
	query := fmt.Sprintf("INSERT INTO %s.%s (%s) VALUES (%s)",
		meta.Database, meta.Table, colList, valList)
	return query, nil
}

// getArgumentsMap extracts arguments from a CallToolRequest as a map
func getArgumentsMap(req *mcp.CallToolRequest) map[string]any {
	if req.Params.Arguments == nil {
		return make(map[string]any)
	}

	// Arguments is json.RawMessage, unmarshal it
	var args map[string]any
	if err := json.Unmarshal(req.Params.Arguments, &args); err != nil {
		return make(map[string]any)
	}
	return args
}

func buildDynamicToolMeta(toolName, db, table, comment string, params []dynamicToolParam) dynamicToolMeta {
	title, description, annotations := buildToolPresentation(toolName, db, table, comment)

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

func makeExecuteQueryAnnotations(readOnly bool) *mcp.ToolAnnotations {
	if readOnly {
		return &mcp.ToolAnnotations{
			ReadOnlyHint:    true,
			DestructiveHint: boolPtr(false),
			OpenWorldHint:   boolPtr(false),
		}
	}

	return &mcp.ToolAnnotations{
		ReadOnlyHint:    false,
		DestructiveHint: boolPtr(true),
		OpenWorldHint:   boolPtr(false),
	}
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
	arguments := getArgumentsMap(req)

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
	if hasLimit && isSelectQuery(query) && !hasLimitClause(query) {
		query = fmt.Sprintf("%s LIMIT %.0f", strings.TrimSpace(query), limit)
	}

	// Get ClickHouse client (handles both JWE and OAuth from context)
	chClient, err := chJweServer.GetClickHouseClientFromCtx(ctx)
	if err != nil {
		log.Error().Err(err).Msg("Failed to get ClickHouse client")
		return NewToolResultError(fmt.Sprintf("Failed to get ClickHouse client: %v", err)), nil
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
		return NewToolResultError(fmt.Sprintf("Query execution failed: %v", ErrJSONEscaper.Replace(err.Error()))), nil
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
			// request body schema
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

// Helper functions

var singleLineCommentRE = regexp.MustCompile(`(?m)--.*$`)
var multiLineCommentRE = regexp.MustCompile(`/\*[\s\S]*?\*/`)

func isSelectQuery(query string) bool {
	query = multiLineCommentRE.ReplaceAllString(query, "")
	query = singleLineCommentRE.ReplaceAllString(query, "")
	trimmed := strings.TrimSpace(strings.ToUpper(query))
	return strings.HasPrefix(trimmed, "SELECT") || strings.HasPrefix(trimmed, "WITH") || strings.HasPrefix(trimmed, "SHOW") || strings.HasPrefix(trimmed, "DESC") || strings.HasPrefix(trimmed, "EXISTS") || strings.HasPrefix(trimmed, "EXPLAIN")
}

func hasLimitClause(query string) bool {
	hasLimit, _ := regexp.MatchString(`(?im)limit\s+\d+`, query)
	return hasLimit
}

// contextKey avoids collisions with other packages using context.WithValue.
type contextKey string

const forwardedHeadersKey contextKey = "forwarded_http_headers"

// Auth context keys
const (
	JWETokenKey    contextKey = "jwe_token"
	JWEClaimsKey   contextKey = "jwe_claims"
	OAuthTokenKey  contextKey = "oauth_token"
	OAuthClaimsKey contextKey = "oauth_claims"
	CHJWEServerKey contextKey = "clickhouse_jwe_server"
)

// sensitiveHeaders are excluded from wildcard pattern matching to prevent
// accidental credential leakage. A user can still forward these by naming
// them explicitly (e.g. --forward-http-headers "Authorization").
var sensitiveHeaders = map[string]bool{
	"Authorization":       true,
	"Cookie":              true,
	"Set-Cookie":          true,
	"Host":                true,
	"Proxy-Authorization": true,
}

// WarnOnCatchAllPattern logs a warning if any pattern is a bare "*",
// which would forward all non-sensitive headers to ClickHouse. Call
// once at startup after parsing the config.
func WarnOnCatchAllPattern(patterns []string) {
	for _, p := range patterns {
		if strings.TrimSpace(p) == "*" {
			log.Warn().Msg("forward-http-headers contains \"*\": all headers (except Authorization, Cookie, Host, Set-Cookie, Proxy-Authorization) will be forwarded to ClickHouse; sensitive headers require an explicit pattern")
			return
		}
	}
}

// ContextWithForwardedHeaders extracts headers matching the given patterns
// from the incoming HTTP request and stores them in context. This makes
// forwarded headers available to every handler path (OpenAPI, MCP JSON-RPC,
// dynamic tools) without coupling to *http.Request.
func ContextWithForwardedHeaders(ctx context.Context, r *http.Request, patterns []string) context.Context {
	if headers := extractForwardHeaders(r, patterns); headers != nil {
		return context.WithValue(ctx, forwardedHeadersKey, headers)
	}
	return ctx
}

// ForwardedHeadersFromContext retrieves forwarded HTTP headers previously
// stored by ContextWithForwardedHeaders. Returns nil when no headers are
// available (e.g. STDIO transport).
func ForwardedHeadersFromContext(ctx context.Context) map[string]string {
	if headers, ok := ctx.Value(forwardedHeadersKey).(map[string]string); ok {
		return headers
	}
	return nil
}

// extractForwardHeaders returns headers matching any of the given patterns.
// Patterns support trailing * wildcard (e.g. "X-*" matches all X-prefixed
// headers) and exact matches (e.g. "X-Tenant-Id"). Matching is
// case-insensitive. Sensitive headers (Authorization, Cookie, …) are
// excluded from wildcard matches but can be forwarded via an explicit
// exact-match pattern.
func extractForwardHeaders(r *http.Request, patterns []string) map[string]string {
	if r == nil || len(patterns) == 0 {
		return nil
	}
	headers := make(map[string]string)
	for name := range r.Header {
		canonical := http.CanonicalHeaderKey(name)
		if matchesAnyPattern(canonical, patterns) {
			headers[canonical] = r.Header.Get(name)
		}
	}
	if len(headers) == 0 {
		return nil
	}
	names := make([]string, 0, len(headers))
	for k := range headers {
		names = append(names, k)
	}
	sort.Strings(names)
	log.Debug().Int("count", len(headers)).Strs("header_names", names).Msg("forwarding HTTP headers to ClickHouse")
	return headers
}

// mergeHTTPHeaders merges extra per-request headers into a base header map,
// returning a new map without mutating either input.
func mergeHTTPHeaders(base, extra map[string]string) map[string]string {
	merged := make(map[string]string, len(base)+len(extra))
	for k, v := range base {
		merged[k] = v
	}
	for k, v := range extra {
		merged[k] = v
	}
	return merged
}

// CORSAllowHeaders builds the Access-Control-Allow-Headers value by combining
// a base set of standard headers with the configured forward patterns and
// header_to_settings source headers. Wildcard patterns (e.g. "X-*") are
// expanded to the CORS spec wildcard "*" since browsers don't support prefix
// wildcards in Access-Control-Allow-Headers.
func CORSAllowHeaders(forwardPatterns []string, headerToSettings map[string]string) string {
	base := "Content-Type, Authorization, X-Altinity-MCP-Key, Mcp-Protocol-Version, Referer, User-Agent"
	hasWildcard := false
	for _, p := range forwardPatterns {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if strings.HasSuffix(p, "*") {
			hasWildcard = true
			continue
		}
		base += ", " + p
	}
	for header := range headerToSettings {
		base += ", " + header
	}
	if hasWildcard {
		base += ", *"
	}
	return base
}

// blockedSettings contains ClickHouse settings that must never be overridden
// via header_to_settings to prevent privilege escalation or DoS.
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

const headerSettingsKey contextKey = "header_to_settings"

// ValidateHeaderToSettings checks the mapping at startup and returns an error
// if any entry targets a blocked ClickHouse setting. Logs a warning when a
// target setting does not start with "custom_" (requires custom_settings_prefixes
// on the ClickHouse server).
func ValidateHeaderToSettings(mapping map[string]string) error {
	warnings, err := validateHeaderToSettings(mapping)
	for _, w := range warnings {
		log.Warn().Msg(w)
	}
	return err
}

// validateHeaderToSettings is the testable core: returns (warnings, error).
func validateHeaderToSettings(mapping map[string]string) (warnings []string, err error) {
	for header, setting := range mapping {
		lower := strings.ToLower(setting)
		if blockedSettings[lower] {
			return nil, fmt.Errorf("header_to_settings: header %q maps to blocked ClickHouse setting %q", header, setting)
		}
		canonical := http.CanonicalHeaderKey(header)
		if sensitiveHeaders[canonical] {
			return nil, fmt.Errorf("header_to_settings: sensitive header %q cannot be used as a source", header)
		}
		if !strings.HasPrefix(lower, "custom_") {
			warnings = append(warnings, fmt.Sprintf(
				"header_to_settings: header %q maps to setting %q which does not start with 'custom_'; ensure custom_settings_prefixes is configured on ClickHouse",
				header, setting,
			))
		}
	}
	return warnings, nil
}

// ContextWithHeaderSettings extracts headers listed in the mapping from the
// incoming HTTP request, converts them to ClickHouse settings, and stores the
// result in context.
func ContextWithHeaderSettings(ctx context.Context, r *http.Request, mapping map[string]string) context.Context {
	if settings := extractHeaderSettings(r, mapping); settings != nil {
		return context.WithValue(ctx, headerSettingsKey, settings)
	}
	return ctx
}

// HeaderSettingsFromContext retrieves per-request ClickHouse settings
// previously stored by ContextWithHeaderSettings. Returns nil when no
// settings are available (e.g. STDIO transport or no mapping configured).
func HeaderSettingsFromContext(ctx context.Context) map[string]string {
	if settings, ok := ctx.Value(headerSettingsKey).(map[string]string); ok {
		return settings
	}
	return nil
}

// extractHeaderSettings reads headers according to the mapping and returns
// the corresponding ClickHouse settings. Headers absent from the request are
// silently skipped. Only header names are logged, never values.
func extractHeaderSettings(r *http.Request, mapping map[string]string) map[string]string {
	if r == nil || len(mapping) == 0 {
		return nil
	}
	settings := make(map[string]string)
	for header, setting := range mapping {
		canonical := http.CanonicalHeaderKey(header)
		if val := r.Header.Get(canonical); val != "" {
			settings[setting] = val
		}
	}
	if len(settings) == 0 {
		return nil
	}
	names := make([]string, 0, len(settings))
	for k := range settings {
		names = append(names, k)
	}
	sort.Strings(names)
	log.Debug().Int("count", len(settings)).Strs("setting_names", names).Msg("mapping HTTP headers to ClickHouse settings")
	return settings
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

// matchesAnyPattern returns true if header matches at least one pattern.
// Supports trailing * wildcard (e.g. "X-*", "X-Tenant-*") and exact match.
// Comparison is case-insensitive. Wildcard patterns skip sensitive headers;
// only an explicit exact-match pattern can forward them.
func matchesAnyPattern(header string, patterns []string) bool {
	lower := strings.ToLower(header)
	for _, p := range patterns {
		p = strings.ToLower(strings.TrimSpace(p))
		if p == "" {
			continue
		}
		if strings.HasSuffix(p, "*") {
			if sensitiveHeaders[http.CanonicalHeaderKey(header)] {
				continue
			}
			if strings.HasPrefix(lower, p[:len(p)-1]) {
				return true
			}
		} else if lower == p {
			return true
		}
	}
	return false
}
