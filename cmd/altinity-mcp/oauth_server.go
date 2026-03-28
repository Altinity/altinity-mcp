package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/altinity/altinity-mcp/pkg/config"
	"github.com/altinity/altinity-mcp/pkg/jwe_auth"
	altinitymcp "github.com/altinity/altinity-mcp/pkg/server"
	"github.com/go-jose/go-jose/v4"
	"github.com/rs/zerolog/log"
)

const (
	defaultProtectedResourceMetadataPath   = "/.well-known/oauth-protected-resource"
	defaultAuthorizationServerMetadataPath = "/.well-known/oauth-authorization-server"
	defaultOpenIDConfigurationPath         = "/.well-known/openid-configuration"
	defaultRegistrationPath                = "/oauth/register"
	defaultAuthorizationPath               = "/oauth/authorize"
	defaultCallbackPath                    = "/oauth/callback"
	defaultTokenPath                       = "/oauth/token"
	defaultAuthCodeTTLSeconds              = 5 * 60
	defaultAccessTokenTTLSeconds           = 60 * 60
	defaultRefreshTokenTTLSeconds          = 30 * 24 * 60 * 60
)

type googleIdentityClaims struct {
	Subject string   `json:"sub"`
	Issuer  string   `json:"iss"`
	Email   string   `json:"email"`
	Name    string   `json:"name"`
	Aud     []string `json:"aud"`
}

type oauthRegisteredClient struct {
	ID                    string
	Secret                string
	RedirectURIs          []string
	TokenEndpointAuthMode string
}

type oauthPendingAuth struct {
	ClientID            string
	RedirectURI         string
	Scope               string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
}

type oauthIssuedCode struct {
	ClientID            string
	RedirectURI         string
	Subject             string
	Email               string
	Name                string
	Scope               string
	CodeChallenge       string
	CodeChallengeMethod string
	ExpiresAt           time.Time
}

type oauthRefreshSession struct {
	ClientID  string
	Subject   string
	Email     string
	Name      string
	Scope     string
	ExpiresAt time.Time
}

type statelessRegisteredClient struct {
	RedirectURIs            []string `json:"redirect_uris"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	GrantType               string   `json:"grant_type"`
	ExpiresAt               int64    `json:"exp"`
}

type statelessBrokerState struct {
	ClientID            string `json:"client_id"`
	RedirectURI         string `json:"redirect_uri"`
	Scope               string `json:"scope"`
	ClientState         string `json:"client_state"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
	ExpiresAt           int64  `json:"exp"`
}

type statelessBrokerCode struct {
	ClientID            string `json:"client_id"`
	RedirectURI         string `json:"redirect_uri"`
	Scope               string `json:"scope"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
	UpstreamBearerToken string `json:"upstream_bearer_token"`
	UpstreamTokenType   string `json:"upstream_token_type"`
	Subject             string `json:"sub"`
	Email               string `json:"email"`
	Name                string `json:"name"`
	HostedDomain        string `json:"hd"`
	EmailVerified       bool   `json:"email_verified"`
	ExpiresAt           int64  `json:"exp"`
	AccessTokenExpiry   int64  `json:"access_token_exp"`
}

type oauthStateStore struct {
	mu            sync.Mutex
	clients       map[string]oauthRegisteredClient
	pendingAuth   map[string]oauthPendingAuth
	authCodes     map[string]oauthIssuedCode
	refreshTokens map[string]oauthRefreshSession
}

func newOAuthStateStore() *oauthStateStore {
	return &oauthStateStore{
		clients:       make(map[string]oauthRegisteredClient),
		pendingAuth:   make(map[string]oauthPendingAuth),
		authCodes:     make(map[string]oauthIssuedCode),
		refreshTokens: make(map[string]oauthRefreshSession),
	}
}

func writeOAuthTokenError(w http.ResponseWriter, status int, code, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             code,
		"error_description": description,
	})
}

func (a *application) oauthEnabled() bool {
	return a.GetCurrentConfig().Server.OAuth.Enabled
}

func (a *application) oauthMode() string {
	return a.GetCurrentConfig().Server.OAuth.NormalizedMode()
}

func (a *application) oauthForwardMode() bool {
	return a.oauthMode() == "forward"
}

func (a *application) oauthBrokerSecret() []byte {
	secret := strings.TrimSpace(a.GetCurrentConfig().Server.OAuth.BrokerSecretKey)
	return []byte(secret)
}

func (a *application) mustBrokerSecret() ([]byte, error) {
	secret := a.oauthBrokerSecret()
	if len(secret) == 0 {
		return nil, fmt.Errorf("oauth broker_secret_key is required for the stateless OAuth facade")
	}
	return secret, nil
}

func encodeBrokerArtifact(secret []byte, claims map[string]interface{}) (string, error) {
	return jwe_auth.GenerateJWEToken(claims, secret, secret)
}

func decodeBrokerArtifact(secret []byte, token string) (map[string]interface{}, error) {
	return jwe_auth.ParseAndDecryptJWE(token, secret, secret)
}

func normalizeURL(raw string) string {
	return strings.TrimRight(strings.TrimSpace(raw), "/")
}

func normalizedPath(raw string, fallback string) string {
	path := strings.TrimSpace(raw)
	if path == "" {
		path = fallback
	}
	if path == "" {
		return ""
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	if path == "/" {
		return path
	}
	return strings.TrimRight(path, "/")
}

func joinURLPath(base string, path string) string {
	base = normalizeURL(base)
	path = normalizedPath(path, "")
	if path == "" || path == "/" {
		return base
	}
	return base + path
}

func ttlSeconds(value int, fallback int) int {
	if value > 0 {
		return value
	}
	return fallback
}

func containsAnyString(list []string, target string) bool {
	for _, item := range list {
		if item == target {
			return true
		}
	}
	return false
}

func uniquePaths(paths ...string) []string {
	result := make([]string, 0, len(paths))
	seen := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		path = normalizedPath(path, "")
		if path == "" {
			continue
		}
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}
		result = append(result, path)
	}
	return result
}

func (a *application) schemeAndHost(r *http.Request) string {
	scheme := "http"
	switch {
	case r.TLS != nil:
		scheme = "https"
	case a.GetCurrentConfig().Server.OpenAPI.TLS || a.GetCurrentConfig().Server.TLS.Enabled:
		scheme = "https"
	}
	host := r.Host
	if host == "" {
		cfg := a.GetCurrentConfig()
		host = fmt.Sprintf("%s:%d", cfg.Server.Address, cfg.Server.Port)
	}

	return fmt.Sprintf("%s://%s", strings.ToLower(scheme), host)
}

func suffixPrefix(path string, markers ...string) string {
	for _, marker := range markers {
		if !strings.HasPrefix(path, marker) {
			continue
		}
		suffix := strings.TrimSpace(strings.TrimPrefix(path, marker))
		if suffix == "" {
			continue
		}
		if !strings.HasPrefix(suffix, "/") {
			suffix = "/" + suffix
		}
		return strings.TrimRight(suffix, "/")
	}
	return ""
}

func pathFromConfiguredURL(raw string) string {
	if raw == "" {
		return ""
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.TrimRight(parsed.Path, "/")
}

func (a *application) resourcePrefix(r *http.Request) string {
	cfg := a.GetCurrentConfig().Server.OAuth
	if prefix := suffixPrefix(
		r.URL.Path,
		"/.well-known/oauth-protected-resource",
		"/.well-known/oauth-authorization-server",
		"/.well-known/openid-configuration",
	); prefix != "" {
		return prefix
	}
	if prefix := pathFromConfiguredURL(cfg.PublicResourceURL); prefix != "" {
		return prefix
	}
	return pathFromConfiguredURL(cfg.Audience)
}

func (a *application) oauthPrefix(r *http.Request) string {
	cfg := a.GetCurrentConfig().Server.OAuth
	if prefix := suffixPrefix(
		r.URL.Path,
		"/.well-known/oauth-authorization-server",
		"/.well-known/openid-configuration",
	); prefix != "" {
		return prefix
	}
	if prefix := pathFromConfiguredURL(cfg.PublicAuthServerURL); prefix != "" {
		return prefix
	}
	return pathFromConfiguredURL(cfg.Issuer)
}

func (a *application) resourceBaseURL(r *http.Request) string {
	if configured := normalizeURL(a.GetCurrentConfig().Server.OAuth.PublicResourceURL); configured != "" {
		return configured
	}
	return a.schemeAndHost(r) + a.resourcePrefix(r)
}

func (a *application) publicBaseURL(r *http.Request) string {
	return a.resourceBaseURL(r)
}

func (a *application) oauthAuthorizationServerBaseURL(r *http.Request) string {
	if configured := normalizeURL(a.GetCurrentConfig().Server.OAuth.PublicAuthServerURL); configured != "" {
		return configured
	}
	return a.schemeAndHost(r) + a.oauthPrefix(r)
}

func (a *application) oauthProtectedResourceMetadataPath() string {
	return normalizedPath(a.GetCurrentConfig().Server.OAuth.ProtectedResourceMetadataPath, defaultProtectedResourceMetadataPath)
}

func (a *application) oauthAuthorizationServerMetadataPath() string {
	return normalizedPath(a.GetCurrentConfig().Server.OAuth.AuthorizationServerMetadataPath, defaultAuthorizationServerMetadataPath)
}

func (a *application) oauthOpenIDConfigurationPath() string {
	return normalizedPath(a.GetCurrentConfig().Server.OAuth.OpenIDConfigurationPath, defaultOpenIDConfigurationPath)
}

func (a *application) oauthRegistrationPath() string {
	return normalizedPath(a.GetCurrentConfig().Server.OAuth.RegistrationPath, defaultRegistrationPath)
}

func (a *application) oauthAuthorizationPath() string {
	return normalizedPath(a.GetCurrentConfig().Server.OAuth.AuthorizationPath, defaultAuthorizationPath)
}

func (a *application) oauthCallbackPath() string {
	return normalizedPath(a.GetCurrentConfig().Server.OAuth.CallbackPath, defaultCallbackPath)
}

func (a *application) oauthTokenPath() string {
	return normalizedPath(a.GetCurrentConfig().Server.OAuth.TokenPath, defaultTokenPath)
}

func (a *application) oauthChallengeHeader(r *http.Request) string {
	baseURL := a.resourceBaseURL(r)
	challenge := fmt.Sprintf("Bearer resource_metadata=%q", joinURLPath(baseURL, a.oauthProtectedResourceMetadataPath()))
	scopes := a.GetCurrentConfig().Server.OAuth.Scopes
	if len(scopes) == 0 {
		scopes = a.GetCurrentConfig().Server.OAuth.RequiredScopes
	}
	if len(scopes) > 0 {
		challenge += fmt.Sprintf(", scope=%q", strings.Join(scopes, " "))
	}
	return challenge
}

func (a *application) writeOAuthError(w http.ResponseWriter, r *http.Request, err error) {
	w.Header().Set("WWW-Authenticate", a.oauthChallengeHeader(r))
	switch {
	case err == nil:
		return
	case strings.Contains(err.Error(), "insufficient OAuth scopes"):
		http.Error(w, "Insufficient OAuth scopes", http.StatusForbidden)
	case strings.Contains(err.Error(), "expired"):
		http.Error(w, "OAuth token expired", http.StatusUnauthorized)
	default:
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	}
}

func (a *application) createMCPAuthInjector(cfg config.Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			if cfg.Server.JWE.Enabled {
				token := r.PathValue("token")
				if token == "" {
					token = r.Header.Get("x-altinity-mcp-key")
				}
				if token == "" {
					http.Error(w, "Missing JWE token", http.StatusUnauthorized)
					return
				}
				if err := a.mcpServer.ValidateJWEToken(token); err != nil {
					http.Error(w, "Invalid JWE token", http.StatusUnauthorized)
					return
				}
				ctx = context.WithValue(ctx, "jwe_token", token)
			}

			if cfg.Server.OAuth.Enabled {
				oauthToken := a.mcpServer.ExtractOAuthTokenFromRequest(r)
				var claims *altinitymcp.OAuthClaims
				if oauthToken == "" {
					a.writeOAuthError(w, r, altinitymcp.ErrMissingOAuthToken)
					return
				}
				if cfg.Server.OAuth.NormalizedMode() != "forward" {
					var err error
					claims, err = a.mcpServer.ValidateOAuthToken(oauthToken)
					if err != nil {
						a.writeOAuthError(w, r, err)
						return
					}
				}
				ctx = context.WithValue(ctx, "oauth_token", oauthToken)
				ctx = context.WithValue(ctx, "oauth_claims", claims)
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func randomToken(prefix string) string {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return prefix + base64.RawURLEncoding.EncodeToString(buf)
}

func encodeUnsignedJWT(claims map[string]interface{}) (string, error) {
	headerBytes, err := json.Marshal(map[string]string{"alg": "none", "typ": "JWT"})
	if err != nil {
		return "", err
	}
	payloadBytes, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(headerBytes) + "." +
		base64.RawURLEncoding.EncodeToString(payloadBytes) + "." +
		base64.RawURLEncoding.EncodeToString([]byte("altinity-mcp")), nil
}

func encodeSelfIssuedAccessToken(secret []byte, claims map[string]interface{}) (string, error) {
	hashedSecret := jwe_auth.HashSHA256(secret)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: hashedSecret}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	object, err := signer.Sign(payload)
	if err != nil {
		return "", err
	}
	return object.CompactSerialize()
}

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func containsString(list []string, target string) bool {
	for _, item := range list {
		if item == target {
			return true
		}
	}
	return false
}

func decodeStringSlice(value interface{}) []string {
	switch typed := value.(type) {
	case []string:
		return append([]string{}, typed...)
	case []interface{}:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			if str, ok := item.(string); ok {
				out = append(out, str)
			}
		}
		return out
	default:
		return nil
	}
}

func sanitizeScope(scope string) string {
	return strings.Join(strings.Fields(scope), " ")
}

func parseStatelessRegisteredClient(claims map[string]interface{}) (*statelessRegisteredClient, error) {
	client := &statelessRegisteredClient{
		RedirectURIs: decodeStringSlice(claims["redirect_uris"]),
	}
	if authMethod, ok := claims["token_endpoint_auth_method"].(string); ok {
		client.TokenEndpointAuthMethod = authMethod
	}
	if grantType, ok := claims["grant_type"].(string); ok {
		client.GrantType = grantType
	}
	if exp, ok := claims["exp"].(float64); ok {
		client.ExpiresAt = int64(exp)
	}
	if client.TokenEndpointAuthMethod == "" {
		client.TokenEndpointAuthMethod = "none"
	}
	if len(client.RedirectURIs) == 0 {
		return nil, fmt.Errorf("missing redirect URIs")
	}
	if client.GrantType == "" {
		client.GrantType = "authorization_code"
	}
	return client, nil
}

func parseStatelessBrokerState(claims map[string]interface{}) (*statelessBrokerState, error) {
	state := &statelessBrokerState{}
	if clientID, ok := claims["client_id"].(string); ok {
		state.ClientID = clientID
	}
	if redirectURI, ok := claims["redirect_uri"].(string); ok {
		state.RedirectURI = redirectURI
	}
	if scope, ok := claims["scope"].(string); ok {
		state.Scope = scope
	}
	if clientState, ok := claims["client_state"].(string); ok {
		state.ClientState = clientState
	}
	if codeChallenge, ok := claims["code_challenge"].(string); ok {
		state.CodeChallenge = codeChallenge
	}
	if codeChallengeMethod, ok := claims["code_challenge_method"].(string); ok {
		state.CodeChallengeMethod = codeChallengeMethod
	}
	if exp, ok := claims["exp"].(float64); ok {
		state.ExpiresAt = int64(exp)
	}
	if state.ClientID == "" || state.RedirectURI == "" {
		return nil, fmt.Errorf("missing broker state fields")
	}
	return state, nil
}

func parseStatelessBrokerCode(claims map[string]interface{}) (*statelessBrokerCode, error) {
	code := &statelessBrokerCode{}
	if clientID, ok := claims["client_id"].(string); ok {
		code.ClientID = clientID
	}
	if redirectURI, ok := claims["redirect_uri"].(string); ok {
		code.RedirectURI = redirectURI
	}
	if scope, ok := claims["scope"].(string); ok {
		code.Scope = scope
	}
	if codeChallenge, ok := claims["code_challenge"].(string); ok {
		code.CodeChallenge = codeChallenge
	}
	if codeChallengeMethod, ok := claims["code_challenge_method"].(string); ok {
		code.CodeChallengeMethod = codeChallengeMethod
	}
	if bearerToken, ok := claims["upstream_bearer_token"].(string); ok {
		code.UpstreamBearerToken = bearerToken
	}
	if tokenType, ok := claims["upstream_token_type"].(string); ok {
		code.UpstreamTokenType = tokenType
	}
	if subject, ok := claims["sub"].(string); ok {
		code.Subject = subject
	}
	if email, ok := claims["email"].(string); ok {
		code.Email = email
	}
	if name, ok := claims["name"].(string); ok {
		code.Name = name
	}
	if hostedDomain, ok := claims["hd"].(string); ok {
		code.HostedDomain = hostedDomain
	}
	if verified, ok := claims["email_verified"].(bool); ok {
		code.EmailVerified = verified
	} else if verifiedStr, ok := claims["email_verified"].(string); ok {
		code.EmailVerified = strings.EqualFold(verifiedStr, "true")
	}
	if exp, ok := claims["exp"].(float64); ok {
		code.ExpiresAt = int64(exp)
	}
	if accessTokenExp, ok := claims["access_token_exp"].(float64); ok {
		code.AccessTokenExpiry = int64(accessTokenExp)
	}
	if code.ClientID == "" || code.RedirectURI == "" {
		return nil, fmt.Errorf("missing broker code fields")
	}
	if code.UpstreamTokenType == "" {
		code.UpstreamTokenType = "Bearer"
	}
	return code, nil
}

func oauthClaimsFromUserInfo(raw map[string]interface{}) *altinitymcp.OAuthClaims {
	claims := &altinitymcp.OAuthClaims{Extra: make(map[string]interface{})}
	if sub, ok := raw["sub"].(string); ok {
		claims.Subject = sub
	}
	if iss, ok := raw["iss"].(string); ok {
		claims.Issuer = iss
	}
	if email, ok := raw["email"].(string); ok {
		claims.Email = email
	}
	if name, ok := raw["name"].(string); ok {
		claims.Name = name
	}
	if hd, ok := raw["hd"].(string); ok {
		claims.HostedDomain = hd
	}
	if verified, ok := raw["email_verified"].(bool); ok {
		claims.EmailVerified = verified
	}
	if scope, ok := raw["scope"].(string); ok {
		claims.Scopes = strings.Fields(scope)
	}
	for key, value := range raw {
		switch key {
		case "sub", "iss", "email", "name", "hd", "email_verified", "scope":
		default:
			claims.Extra[key] = value
		}
	}
	return claims
}

func (a *application) fetchUserInfo(accessToken string) (*altinitymcp.OAuthClaims, error) {
	cfg := a.GetCurrentConfig().Server.OAuth
	userInfoURL := strings.TrimSpace(cfg.UserInfoURL)
	if userInfoURL == "" {
		if discovery, err := a.mcpServer.FetchOpenIDConfiguration(strings.TrimSpace(cfg.Issuer)); err == nil && discovery.UserInfoEndpoint != "" {
			userInfoURL = discovery.UserInfoEndpoint
		}
	}
	if userInfoURL == "" {
		return nil, fmt.Errorf("userinfo endpoint is not configured or discoverable")
	}

	req, err := http.NewRequest(http.MethodGet, userInfoURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("userinfo endpoint returned status %d", resp.StatusCode)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}
	claims := oauthClaimsFromUserInfo(raw)
	if claims.Issuer == "" {
		claims.Issuer = cfg.Issuer
	}
	return claims, a.mcpServer.ValidateOAuthIdentityPolicyClaims(claims)
}

func (a *application) resolveUpstreamAuthURL() (string, error) {
	cfg := a.GetCurrentConfig().Server.OAuth
	if authURL := strings.TrimSpace(cfg.AuthURL); authURL != "" {
		return authURL, nil
	}
	discovery, err := a.mcpServer.FetchOpenIDConfiguration(strings.TrimSpace(cfg.Issuer))
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(discovery.AuthorizationEndpoint) == "" {
		return "", fmt.Errorf("authorization endpoint is not configured or discoverable")
	}
	return strings.TrimSpace(discovery.AuthorizationEndpoint), nil
}

func (a *application) resolveUpstreamTokenURL() (string, error) {
	cfg := a.GetCurrentConfig().Server.OAuth
	if tokenURL := strings.TrimSpace(cfg.TokenURL); tokenURL != "" {
		return tokenURL, nil
	}
	discovery, err := a.mcpServer.FetchOpenIDConfiguration(strings.TrimSpace(cfg.Issuer))
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(discovery.TokenEndpoint) == "" {
		return "", fmt.Errorf("token endpoint is not configured or discoverable")
	}
	return strings.TrimSpace(discovery.TokenEndpoint), nil
}

func (a *application) handleOAuthProtectedResource(w http.ResponseWriter, r *http.Request) {
	if !a.oauthEnabled() {
		http.NotFound(w, r)
		return
	}
	baseURL := a.resourceBaseURL(r)
	authServerBaseURL := a.oauthAuthorizationServerBaseURL(r)
	resp := map[string]interface{}{
		"resource":                 baseURL,
		"authorization_servers":    []string{authServerBaseURL},
		"scopes_supported":         a.GetCurrentConfig().Server.OAuth.Scopes,
		"bearer_methods_supported": []string{"header"},
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (a *application) handleOAuthAuthorizationServerMetadata(w http.ResponseWriter, r *http.Request) {
	if !a.oauthEnabled() {
		http.NotFound(w, r)
		return
	}
	baseURL := a.oauthAuthorizationServerBaseURL(r)
	resp := map[string]interface{}{
		"issuer":                                baseURL,
		"authorization_endpoint":                joinURLPath(baseURL, a.oauthAuthorizationPath()),
		"token_endpoint":                        joinURLPath(baseURL, a.oauthTokenPath()),
		"registration_endpoint":                 joinURLPath(baseURL, a.oauthRegistrationPath()),
		"scopes_supported":                      a.GetCurrentConfig().Server.OAuth.Scopes,
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code"},
		"token_endpoint_auth_methods_supported": []string{"none"},
		"code_challenge_methods_supported":      []string{"S256"},
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (a *application) handleOAuthOpenIDConfiguration(w http.ResponseWriter, r *http.Request) {
	if !a.oauthEnabled() {
		http.NotFound(w, r)
		return
	}
	baseURL := a.oauthAuthorizationServerBaseURL(r)
	resp := map[string]interface{}{
		"issuer":                                baseURL,
		"authorization_endpoint":                joinURLPath(baseURL, a.oauthAuthorizationPath()),
		"token_endpoint":                        joinURLPath(baseURL, a.oauthTokenPath()),
		"registration_endpoint":                 joinURLPath(baseURL, a.oauthRegistrationPath()),
		"scopes_supported":                      a.GetCurrentConfig().Server.OAuth.Scopes,
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code"},
		"token_endpoint_auth_methods_supported": []string{"none"},
		"code_challenge_methods_supported":      []string{"S256"},
	}
	if !a.oauthForwardMode() {
		resp["subject_types_supported"] = []string{"public"}
		resp["id_token_signing_alg_values_supported"] = []string{"HS256"}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (a *application) handleOAuthRegister(w http.ResponseWriter, r *http.Request) {
	if !a.oauthEnabled() {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		RedirectURIs            []string `json:"redirect_uris"`
		TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid registration payload", http.StatusBadRequest)
		return
	}
	if len(req.RedirectURIs) == 0 {
		http.Error(w, "redirect_uris is required", http.StatusBadRequest)
		return
	}
	authMethod := req.TokenEndpointAuthMethod
	if authMethod == "" {
		authMethod = "none"
	}
	if authMethod != "none" {
		http.Error(w, "Only public clients with PKCE are supported", http.StatusBadRequest)
		return
	}
	secret, err := a.mustBrokerSecret()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	clientID, err := encodeBrokerArtifact(secret, map[string]interface{}{
		"redirect_uris":              req.RedirectURIs,
		"token_endpoint_auth_method": "none",
		"grant_type":                 "authorization_code",
		"exp":                        time.Now().Add(30 * 24 * time.Hour).Unix(),
	})
	if err != nil {
		http.Error(w, "Failed to create stateless client registration", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"client_id":                  clientID,
		"redirect_uris":              req.RedirectURIs,
		"grant_types":                []string{"authorization_code"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "none",
		"client_id_issued_at":        time.Now().Unix(),
	})
}

func (a *application) handleOAuthAuthorize(w http.ResponseWriter, r *http.Request) {
	if !a.oauthEnabled() {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q := r.URL.Query()
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	if clientID == "" || redirectURI == "" || q.Get("response_type") != "code" {
		http.Error(w, "Invalid authorization request", http.StatusBadRequest)
		return
	}
	secret, err := a.mustBrokerSecret()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	clientClaims, err := decodeBrokerArtifact(secret, clientID)
	if err != nil {
		http.Error(w, "Unknown OAuth client", http.StatusBadRequest)
		return
	}
	client, err := parseStatelessRegisteredClient(clientClaims)
	if err != nil || time.Now().Unix() > client.ExpiresAt || !containsString(client.RedirectURIs, redirectURI) {
		http.Error(w, "Unknown OAuth client", http.StatusBadRequest)
		return
	}
	if q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256" {
		http.Error(w, "PKCE S256 is required", http.StatusBadRequest)
		return
	}
	callbackState, err := encodeBrokerArtifact(secret, map[string]interface{}{
		"client_id":             clientID,
		"redirect_uri":          redirectURI,
		"scope":                 sanitizeScope(q.Get("scope")),
		"client_state":          q.Get("state"),
		"code_challenge":        q.Get("code_challenge"),
		"code_challenge_method": q.Get("code_challenge_method"),
		"exp":                   time.Now().Add(time.Duration(ttlSeconds(a.GetCurrentConfig().Server.OAuth.AuthCodeTTLSeconds, defaultAuthCodeTTLSeconds)) * time.Second).Unix(),
	})
	if err != nil {
		http.Error(w, "Failed to create broker state", http.StatusInternalServerError)
		return
	}

	cfg := a.GetCurrentConfig()
	authURL, err := a.resolveUpstreamAuthURL()
	if err != nil {
		http.Error(w, "Failed to resolve upstream authorization endpoint", http.StatusBadGateway)
		return
	}
	callbackURL := joinURLPath(a.oauthAuthorizationServerBaseURL(r), a.oauthCallbackPath())
	upstream := url.Values{}
	upstream.Set("client_id", cfg.Server.OAuth.ClientID)
	upstream.Set("redirect_uri", callbackURL)
	upstream.Set("response_type", "code")
	scope := strings.Join(cfg.Server.OAuth.Scopes, " ")
	if scope == "" {
		scope = "openid email"
	}
	upstream.Set("scope", scope)
	upstream.Set("state", callbackState)
	http.Redirect(w, r, authURL+"?"+upstream.Encode(), http.StatusFound)
}

func (a *application) handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	if !a.oauthEnabled() {
		http.NotFound(w, r)
		return
	}
	requestID := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	if requestID == "" || code == "" {
		http.Error(w, "Missing callback parameters", http.StatusBadRequest)
		return
	}

	secret, err := a.mustBrokerSecret()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	stateClaims, err := decodeBrokerArtifact(secret, requestID)
	if err != nil {
		http.Error(w, "Unknown OAuth request", http.StatusBadRequest)
		return
	}
	pending, err := parseStatelessBrokerState(stateClaims)
	if err != nil || time.Now().Unix() > pending.ExpiresAt {
		http.Error(w, "Unknown OAuth request", http.StatusBadRequest)
		return
	}

	cfg := a.GetCurrentConfig()
	callbackURL := joinURLPath(a.oauthAuthorizationServerBaseURL(r), a.oauthCallbackPath())
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("client_id", cfg.Server.OAuth.ClientID)
	form.Set("client_secret", cfg.Server.OAuth.ClientSecret)
	form.Set("redirect_uri", callbackURL)

	tokenURL, err := a.resolveUpstreamTokenURL()
	if err != nil {
		http.Error(w, "Failed to resolve upstream token endpoint", http.StatusBadGateway)
		return
	}
	resp, err := http.PostForm(tokenURL, form)
	if err != nil {
		http.Error(w, "Failed to exchange upstream auth code", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		log.Error().Int("status", resp.StatusCode).Bytes("body", body).Msg("Upstream OAuth token exchange failed")
		http.Error(w, "Failed to exchange upstream auth code", http.StatusBadGateway)
		return
	}
	var tokenResp struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int64  `json:"expires_in"`
		Scope       string `json:"scope"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil || (tokenResp.AccessToken == "" && tokenResp.IDToken == "") {
		http.Error(w, "Missing upstream token", http.StatusBadGateway)
		return
	}

	var identityClaims *altinitymcp.OAuthClaims
	if tokenResp.IDToken != "" {
		identityClaims, err = a.mcpServer.ValidateUpstreamIdentityToken(tokenResp.IDToken, cfg.Server.OAuth.ClientID)
		if err != nil {
			http.Error(w, "Failed to validate upstream identity token", http.StatusBadGateway)
			return
		}
	} else if tokenResp.AccessToken != "" {
		identityClaims, err = a.fetchUserInfo(tokenResp.AccessToken)
		if err != nil {
			http.Error(w, "Failed to validate upstream identity", http.StatusBadGateway)
			return
		}
	} else {
		http.Error(w, "Missing upstream token", http.StatusBadGateway)
		return
	}
	if tokenResp.Scope == "" {
		tokenResp.Scope = pending.Scope
	}
	if tokenResp.Scope == "" {
		tokenResp.Scope = strings.Join(cfg.Server.OAuth.Scopes, " ")
	}
	tokenType := tokenResp.TokenType
	if tokenType == "" {
		tokenType = "Bearer"
	}
	accessTokenExpiry := time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second).Unix()
	if tokenResp.ExpiresIn <= 0 {
		accessTokenExpiry = time.Now().Add(time.Hour).Unix()
	}
	bearerToken := tokenResp.IDToken
	if bearerToken == "" {
		bearerToken = tokenResp.AccessToken
	}

	brokerClaims := map[string]interface{}{
		"client_id":             pending.ClientID,
		"redirect_uri":          pending.RedirectURI,
		"scope":                 tokenResp.Scope,
		"code_challenge":        pending.CodeChallenge,
		"code_challenge_method": pending.CodeChallengeMethod,
		"exp":                   time.Now().Add(time.Duration(ttlSeconds(cfg.Server.OAuth.AuthCodeTTLSeconds, defaultAuthCodeTTLSeconds)) * time.Second).Unix(),
	}
	if a.oauthForwardMode() {
		brokerClaims["upstream_bearer_token"] = bearerToken
		brokerClaims["upstream_token_type"] = tokenType
		brokerClaims["access_token_exp"] = accessTokenExpiry
	} else {
		brokerClaims["sub"] = identityClaims.Subject
		brokerClaims["email"] = identityClaims.Email
		brokerClaims["name"] = identityClaims.Name
		brokerClaims["hd"] = identityClaims.HostedDomain
		brokerClaims["email_verified"] = identityClaims.EmailVerified
	}
	brokerCode, err := encodeBrokerArtifact(secret, brokerClaims)
	if err != nil {
		http.Error(w, "Failed to issue authorization code", http.StatusInternalServerError)
		return
	}

	redirect, err := url.Parse(pending.RedirectURI)
	if err != nil {
		http.Error(w, "Invalid redirect URI", http.StatusBadGateway)
		return
	}
	params := redirect.Query()
	params.Set("code", brokerCode)
	if pending.ClientState != "" {
		params.Set("state", pending.ClientState)
	}
	redirect.RawQuery = params.Encode()
	http.Redirect(w, r, redirect.String(), http.StatusFound)
}

func (a *application) handleOAuthToken(w http.ResponseWriter, r *http.Request) {
	if !a.oauthEnabled() {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		writeOAuthTokenError(w, http.StatusMethodNotAllowed, "invalid_request", "method not allowed")
		return
	}
	if err := r.ParseForm(); err != nil {
		writeOAuthTokenError(w, http.StatusBadRequest, "invalid_request", "invalid token request")
		return
	}
	if r.Form.Get("grant_type") != "authorization_code" {
		log.Debug().
			Str("grant_type", r.Form.Get("grant_type")).
			Str("client_id_present", fmt.Sprintf("%t", r.Form.Get("client_id") != "")).
			Msg("OAuth token request rejected: unsupported grant type")
		writeOAuthTokenError(w, http.StatusBadRequest, "unsupported_grant_type", "unsupported grant type")
		return
	}
	secret, err := a.mustBrokerSecret()
	if err != nil {
		writeOAuthTokenError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	clientID := r.Form.Get("client_id")
	clientClaims, err := decodeBrokerArtifact(secret, clientID)
	if err != nil {
		log.Debug().Err(err).Msg("OAuth token request rejected: unknown client artifact")
		writeOAuthTokenError(w, http.StatusUnauthorized, "invalid_client", "unknown OAuth client")
		return
	}
	client, err := parseStatelessRegisteredClient(clientClaims)
	if err != nil || time.Now().Unix() > client.ExpiresAt || client.TokenEndpointAuthMethod != "none" {
		log.Debug().
			Err(err).
			Int64("client_expires_at", client.ExpiresAt).
			Str("token_endpoint_auth_method", client.TokenEndpointAuthMethod).
			Msg("OAuth token request rejected: invalid client metadata")
		writeOAuthTokenError(w, http.StatusUnauthorized, "invalid_client", "unknown OAuth client")
		return
	}
	codeClaims, err := decodeBrokerArtifact(secret, r.Form.Get("code"))
	if err != nil {
		log.Debug().Err(err).Msg("OAuth token request rejected: invalid authorization code artifact")
		writeOAuthTokenError(w, http.StatusBadRequest, "invalid_grant", "invalid authorization code")
		return
	}
	issued, err := parseStatelessBrokerCode(codeClaims)
	if err != nil || time.Now().Unix() > issued.ExpiresAt || issued.ClientID != clientID || issued.RedirectURI != r.Form.Get("redirect_uri") {
		log.Debug().
			Err(err).
			Int64("code_expires_at", issued.ExpiresAt).
			Str("issued_client_id", issued.ClientID).
			Str("request_client_id", clientID).
			Str("issued_redirect_uri", issued.RedirectURI).
			Str("request_redirect_uri", r.Form.Get("redirect_uri")).
			Msg("OAuth token request rejected: authorization code mismatch")
		writeOAuthTokenError(w, http.StatusBadRequest, "invalid_grant", "invalid authorization code")
		return
	}
	if issued.CodeChallenge != "" {
		if pkceChallenge(r.Form.Get("code_verifier")) != issued.CodeChallenge {
			log.Debug().Msg("OAuth token request rejected: invalid PKCE verifier")
			writeOAuthTokenError(w, http.StatusBadRequest, "invalid_grant", "invalid PKCE verifier")
			return
		}
	}

	if a.oauthForwardMode() {
		bearerToken := issued.UpstreamBearerToken
		if bearerToken == "" {
			writeOAuthTokenError(w, http.StatusBadRequest, "invalid_grant", "invalid authorization code")
			return
		}
		expiresIn := issued.AccessTokenExpiry - time.Now().Unix()
		if expiresIn < 0 {
			expiresIn = 0
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": bearerToken,
			"token_type":   issued.UpstreamTokenType,
			"expires_in":   expiresIn,
			"scope":        issued.Scope,
		})
		return
	}

	issuer := strings.TrimSuffix(a.oauthAuthorizationServerBaseURL(r), "/")
	audience := strings.TrimSuffix(a.GetCurrentConfig().Server.OAuth.Audience, "/")
	if audience == "" {
		audience = strings.TrimSuffix(a.resourceBaseURL(r), "/")
	}
	scope := issued.Scope
	if scope == "" {
		scope = strings.Join(a.GetCurrentConfig().Server.OAuth.Scopes, " ")
	}
	accessToken, err := encodeSelfIssuedAccessToken(secret, map[string]interface{}{
		"sub":            issued.Subject,
		"iss":            issuer,
		"aud":            audience,
		"exp":            time.Now().Add(time.Duration(ttlSeconds(a.GetCurrentConfig().Server.OAuth.AccessTokenTTLSeconds, defaultAccessTokenTTLSeconds)) * time.Second).Unix(),
		"iat":            time.Now().Unix(),
		"scope":          scope,
		"email":          issued.Email,
		"name":           issued.Name,
		"hd":             issued.HostedDomain,
		"email_verified": issued.EmailVerified,
	})
	if err != nil {
		log.Error().Err(err).Msg("Failed to mint self-issued access token")
		writeOAuthTokenError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	accessTokenTTL := ttlSeconds(a.GetCurrentConfig().Server.OAuth.AccessTokenTTLSeconds, defaultAccessTokenTTLSeconds)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   accessTokenTTL,
		"scope":        scope,
	})
}

func readClientCredentials(r *http.Request) (string, string) {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Basic ") {
		return "", ""
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Basic "))
	if err != nil {
		return "", ""
	}
	parts := strings.SplitN(string(raw), ":", 2)
	if len(parts) != 2 {
		return "", ""
	}
	return parts[0], parts[1]
}

func parseGoogleIdentityToken(token string) (*googleIdentityClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var raw map[string]interface{}
	if err := json.Unmarshal(payload, &raw); err != nil {
		return nil, err
	}
	claims := &googleIdentityClaims{}
	if sub, ok := raw["sub"].(string); ok {
		claims.Subject = sub
	}
	if iss, ok := raw["iss"].(string); ok {
		claims.Issuer = iss
	}
	if email, ok := raw["email"].(string); ok {
		claims.Email = email
	}
	if name, ok := raw["name"].(string); ok {
		claims.Name = name
	}
	switch aud := raw["aud"].(type) {
	case string:
		claims.Aud = []string{aud}
	case []interface{}:
		for _, item := range aud {
			if s, ok := item.(string); ok {
				claims.Aud = append(claims.Aud, s)
			}
		}
	}
	return claims, nil
}

func (a *application) registerOAuthHTTPRoutes(mux *http.ServeMux) {
	protectedResourceMetadataPath := a.oauthProtectedResourceMetadataPath()
	protectedResourceAliases := uniquePaths(
		protectedResourceMetadataPath,
		defaultProtectedResourceMetadataPath,
		"/.well-known/oauth-protected-resource/http",
		"/http/.well-known/oauth-protected-resource",
	)
	for _, path := range protectedResourceAliases {
		mux.HandleFunc(path, a.handleOAuthProtectedResource)
	}

	authMetadataPath := a.oauthAuthorizationServerMetadataPath()
	authMetadataAliases := uniquePaths(
		authMetadataPath,
		defaultAuthorizationServerMetadataPath,
		"/.well-known/oauth-authorization-server/http",
		"/.well-known/oauth-authorization-server/oauth",
		"/http/.well-known/oauth-authorization-server",
		"/oauth/.well-known/oauth-authorization-server",
	)
	for _, path := range authMetadataAliases {
		mux.HandleFunc(path, a.handleOAuthAuthorizationServerMetadata)
	}

	openIDConfigurationPath := a.oauthOpenIDConfigurationPath()
	openIDAliases := uniquePaths(
		openIDConfigurationPath,
		defaultOpenIDConfigurationPath,
		"/.well-known/openid-configuration/http",
		"/.well-known/openid-configuration/oauth",
		"/http/.well-known/openid-configuration",
		"/oauth/.well-known/openid-configuration",
	)
	for _, path := range openIDAliases {
		mux.HandleFunc(path, a.handleOAuthOpenIDConfiguration)
	}

	for _, path := range uniquePaths(a.oauthRegistrationPath(), defaultRegistrationPath) {
		mux.HandleFunc(path, a.handleOAuthRegister)
	}
	for _, path := range uniquePaths(a.oauthAuthorizationPath(), defaultAuthorizationPath) {
		mux.HandleFunc(path, a.handleOAuthAuthorize)
	}
	for _, path := range uniquePaths(a.oauthCallbackPath(), defaultCallbackPath) {
		mux.HandleFunc(path, a.handleOAuthCallback)
	}
	for _, path := range uniquePaths(a.oauthTokenPath(), defaultTokenPath) {
		mux.HandleFunc(path, a.handleOAuthToken)
	}
}
