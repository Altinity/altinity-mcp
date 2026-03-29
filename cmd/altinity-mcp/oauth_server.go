package main

import (
	"context"
	"crypto/rand"
	"errors"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/altinity/altinity-mcp/pkg/config"
	"github.com/altinity/altinity-mcp/pkg/jwe_auth"
	altinitymcp "github.com/altinity/altinity-mcp/pkg/server"
	"github.com/go-jose/go-jose/v4"
	"github.com/rs/zerolog/log"
)

const maxOAuthResponseBytes = 1 << 20 // 1 MB

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

type statelessRegisteredClient struct {
	RedirectURIs            []string `json:"redirect_uris"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	GrantType               string   `json:"grant_type"`
	ExpiresAt               int64    `json:"exp"`
}

type oauthPendingAuth struct {
	ClientID            string `json:"client_id"`
	RedirectURI         string `json:"redirect_uri"`
	Scope               string `json:"scope"`
	ClientState         string `json:"client_state"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
	ExpiresAt           time.Time
}

type oauthIssuedCode struct {
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
	ExpiresAt           time.Time
	AccessTokenExpiry   time.Time
}

// maxOAuthStateEntries caps each map in the state store to prevent memory
// exhaustion from floods of unauthenticated /oauth/authorize requests.
const maxOAuthStateEntries = 10000

type oauthStateStore struct {
	mu          sync.Mutex
	pendingAuth map[string]oauthPendingAuth
	authCodes   map[string]oauthIssuedCode
}

func newOAuthStateStore() *oauthStateStore {
	return &oauthStateStore{
		pendingAuth: make(map[string]oauthPendingAuth),
		authCodes:   make(map[string]oauthIssuedCode),
	}
}

func (s *oauthStateStore) cleanupExpiredLocked(now time.Time) {
	for key, pending := range s.pendingAuth {
		if !pending.ExpiresAt.IsZero() && now.After(pending.ExpiresAt) {
			delete(s.pendingAuth, key)
		}
	}
	for key, issued := range s.authCodes {
		if !issued.ExpiresAt.IsZero() && now.After(issued.ExpiresAt) {
			delete(s.authCodes, key)
		}
	}
}

// evictOldestPendingLocked removes the entry with the earliest expiry.
func (s *oauthStateStore) evictOldestPendingLocked() {
	var oldestKey string
	var oldestTime time.Time
	for key, pending := range s.pendingAuth {
		if oldestKey == "" || pending.ExpiresAt.Before(oldestTime) {
			oldestKey = key
			oldestTime = pending.ExpiresAt
		}
	}
	if oldestKey != "" {
		delete(s.pendingAuth, oldestKey)
	}
}

// evictOldestCodeLocked removes the entry with the earliest expiry.
func (s *oauthStateStore) evictOldestCodeLocked() {
	var oldestKey string
	var oldestTime time.Time
	for key, issued := range s.authCodes {
		if oldestKey == "" || issued.ExpiresAt.Before(oldestTime) {
			oldestKey = key
			oldestTime = issued.ExpiresAt
		}
	}
	if oldestKey != "" {
		delete(s.authCodes, oldestKey)
	}
}

func (s *oauthStateStore) putPendingAuth(id string, pending oauthPendingAuth) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupExpiredLocked(time.Now())
	if len(s.pendingAuth) >= maxOAuthStateEntries {
		s.evictOldestPendingLocked()
	}
	s.pendingAuth[id] = pending
}

func (s *oauthStateStore) consumePendingAuth(id string) (oauthPendingAuth, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupExpiredLocked(time.Now())
	pending, ok := s.pendingAuth[id]
	if ok {
		delete(s.pendingAuth, id)
	}
	return pending, ok
}

func (s *oauthStateStore) putAuthCode(id string, issued oauthIssuedCode) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupExpiredLocked(time.Now())
	if len(s.authCodes) >= maxOAuthStateEntries {
		s.evictOldestCodeLocked()
	}
	s.authCodes[id] = issued
}

func (s *oauthStateStore) consumeAuthCode(id string) (oauthIssuedCode, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupExpiredLocked(time.Now())
	issued, ok := s.authCodes[id]
	if ok {
		delete(s.authCodes, id)
	}
	return issued, ok
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
		return nil, fmt.Errorf("oauth broker_secret_key is required for OAuth client registration and broker-mode token minting")
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
	if host == "" || strings.ContainsAny(host, "/<>\"'\\") {
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
	case errors.Is(err, altinitymcp.ErrOAuthInsufficientScopes):
		http.Error(w, "Insufficient OAuth scopes", http.StatusForbidden)
	case errors.Is(err, altinitymcp.ErrOAuthTokenExpired):
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
				ctx = context.WithValue(ctx, altinitymcp.JWETokenKey, token)
			}

			if cfg.Server.OAuth.Enabled {
				oauthToken := a.mcpServer.ExtractOAuthTokenFromRequest(r)
				var claims *altinitymcp.OAuthClaims
				if oauthToken == "" {
					a.writeOAuthError(w, r, altinitymcp.ErrMissingOAuthToken)
					return
				}
				if cfg.Server.OAuth.IsBrokerMode() {
					var err error
					claims, err = a.mcpServer.ValidateOAuthToken(oauthToken)
					if err != nil {
						a.writeOAuthError(w, r, err)
						return
					}
				}
				ctx = context.WithValue(ctx, altinitymcp.OAuthTokenKey, oauthToken)
				ctx = context.WithValue(ctx, altinitymcp.OAuthClaimsKey, claims)
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
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxOAuthResponseBytes))
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
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
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
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
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
	for _, uri := range req.RedirectURIs {
		parsed, err := url.Parse(uri)
		if err != nil || parsed.Host == "" {
			http.Error(w, "invalid redirect URI", http.StatusBadRequest)
			return
		}
		switch parsed.Scheme {
		case "https":
			// always allowed
		case "http":
			host := parsed.Hostname()
			if host != "localhost" && host != "127.0.0.1" && host != "::1" {
				http.Error(w, "http redirect URIs are only allowed for localhost", http.StatusBadRequest)
				return
			}
		default:
			http.Error(w, "redirect URI must use https (or http for localhost)", http.StatusBadRequest)
			return
		}
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
	if err != nil || time.Now().Unix() > client.ExpiresAt || !slices.Contains(client.RedirectURIs, redirectURI) {
		http.Error(w, "Unknown OAuth client", http.StatusBadRequest)
		return
	}
	if q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256" {
		http.Error(w, "PKCE S256 is required", http.StatusBadRequest)
		return
	}
	callbackState := randomToken("oas_")
	a.getOAuthStateStore().putPendingAuth(callbackState, oauthPendingAuth{
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		Scope:               sanitizeScope(q.Get("scope")),
		ClientState:         q.Get("state"),
		CodeChallenge:       q.Get("code_challenge"),
		CodeChallengeMethod: q.Get("code_challenge_method"),
		ExpiresAt:           time.Now().Add(time.Duration(ttlSeconds(a.GetCurrentConfig().Server.OAuth.AuthCodeTTLSeconds, defaultAuthCodeTTLSeconds)) * time.Second),
	})

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

	pending, ok := a.getOAuthStateStore().consumePendingAuth(requestID)
	if !ok {
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
		log.Error().Err(err).Str("token_url", tokenURL).Msg("Upstream OAuth token exchange request failed")
		http.Error(w, "Failed to exchange upstream auth code", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxOAuthResponseBytes))
	if err != nil {
		http.Error(w, "Failed to read upstream token response", http.StatusBadGateway)
		return
	}
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
		log.Error().
			Err(err).
			Bool("has_access_token", tokenResp.AccessToken != "").
			Bool("has_id_token", tokenResp.IDToken != "").
			Msg("Upstream token response missing usable token")
		http.Error(w, "Missing upstream token", http.StatusBadGateway)
		return
	}

	var identityClaims *altinitymcp.OAuthClaims
	if tokenResp.IDToken != "" {
		identityClaims, err = a.mcpServer.ValidateUpstreamIdentityToken(tokenResp.IDToken, cfg.Server.OAuth.ClientID)
		if err != nil {
			log.Error().Err(err).Msg("Upstream identity token validation failed")
			http.Error(w, "Failed to validate upstream identity token", http.StatusBadGateway)
			return
		}
	} else if tokenResp.AccessToken != "" {
		identityClaims, err = a.fetchUserInfo(tokenResp.AccessToken)
		if err != nil {
			log.Error().Err(err).Msg("Upstream userinfo validation failed")
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
	brokerCode := randomToken("oac_")
	issuedCode := oauthIssuedCode{
		ClientID:            pending.ClientID,
		RedirectURI:         pending.RedirectURI,
		Scope:               tokenResp.Scope,
		CodeChallenge:       pending.CodeChallenge,
		CodeChallengeMethod: pending.CodeChallengeMethod,
		ExpiresAt:           time.Now().Add(time.Duration(ttlSeconds(cfg.Server.OAuth.AuthCodeTTLSeconds, defaultAuthCodeTTLSeconds)) * time.Second),
	}
	if a.oauthForwardMode() {
		issuedCode.UpstreamBearerToken = bearerToken
		issuedCode.UpstreamTokenType = tokenType
		issuedCode.AccessTokenExpiry = time.Unix(accessTokenExpiry, 0)
	} else {
		issuedCode.Subject = identityClaims.Subject
		issuedCode.Email = identityClaims.Email
		issuedCode.Name = identityClaims.Name
		issuedCode.HostedDomain = identityClaims.HostedDomain
		issuedCode.EmailVerified = identityClaims.EmailVerified
	}
	a.getOAuthStateStore().putAuthCode(brokerCode, issuedCode)

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

// brokerIdentity holds the identity fields needed to mint broker-mode tokens.
type brokerIdentity struct {
	ClientID      string
	Subject       string
	Email         string
	Name          string
	HostedDomain  string
	EmailVerified bool
	Scope         string
}

// mintBrokerTokenResponse mints an access token and a stateless refresh token
// for broker mode, then writes the JSON response.
func (a *application) mintBrokerTokenResponse(w http.ResponseWriter, r *http.Request, secret []byte, id brokerIdentity) {
	cfg := a.GetCurrentConfig()
	issuer := strings.TrimSuffix(a.oauthAuthorizationServerBaseURL(r), "/")
	audience := strings.TrimSuffix(cfg.Server.OAuth.Audience, "/")
	if audience == "" {
		audience = strings.TrimSuffix(a.resourceBaseURL(r), "/")
	}
	scope := id.Scope
	if scope == "" {
		scope = strings.Join(cfg.Server.OAuth.Scopes, " ")
	}

	now := time.Now()
	accessToken, err := encodeSelfIssuedAccessToken(secret, map[string]interface{}{
		"sub":            id.Subject,
		"iss":            issuer,
		"aud":            audience,
		"exp":            now.Add(time.Duration(ttlSeconds(cfg.Server.OAuth.AccessTokenTTLSeconds, defaultAccessTokenTTLSeconds)) * time.Second).Unix(),
		"iat":            now.Unix(),
		"scope":          scope,
		"email":          id.Email,
		"name":           id.Name,
		"hd":             id.HostedDomain,
		"email_verified": id.EmailVerified,
	})
	if err != nil {
		log.Error().Err(err).Msg("Failed to mint self-issued access token")
		writeOAuthTokenError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	refreshToken, err := encodeBrokerArtifact(secret, map[string]interface{}{
		"sub":            id.Subject,
		"iss":            issuer,
		"aud":            audience,
		"exp":            now.Add(time.Duration(ttlSeconds(cfg.Server.OAuth.RefreshTokenTTLSeconds, defaultRefreshTokenTTLSeconds)) * time.Second).Unix(),
		"iat":            now.Unix(),
		"scope":          scope,
		"email":          id.Email,
		"name":           id.Name,
		"hd":             id.HostedDomain,
		"email_verified": id.EmailVerified,
		"client_id":      id.ClientID,
	})
	if err != nil {
		log.Error().Err(err).Msg("Failed to mint refresh token")
		writeOAuthTokenError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	accessTokenTTL := ttlSeconds(cfg.Server.OAuth.AccessTokenTTLSeconds, defaultAccessTokenTTLSeconds)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"token_type":    "Bearer",
		"expires_in":    accessTokenTTL,
		"scope":         scope,
	})
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

	switch r.Form.Get("grant_type") {
	case "authorization_code":
		a.handleOAuthTokenAuthCode(w, r)
	case "refresh_token":
		a.handleOAuthTokenRefresh(w, r)
	default:
		writeOAuthTokenError(w, http.StatusBadRequest, "unsupported_grant_type", "unsupported grant type")
	}
}

func (a *application) handleOAuthTokenAuthCode(w http.ResponseWriter, r *http.Request) {
	secret, err := a.mustBrokerSecret()
	if err != nil {
		writeOAuthTokenError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	clientID := r.Form.Get("client_id")
	clientClaims, err := decodeBrokerArtifact(secret, clientID)
	if err != nil {
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
	issued, ok := a.getOAuthStateStore().consumeAuthCode(r.Form.Get("code"))
	if !ok {
		log.Debug().Msg("OAuth token request rejected: unknown or expired authorization code")
		writeOAuthTokenError(w, http.StatusBadRequest, "invalid_grant", "invalid authorization code")
		return
	}
	if issued.ClientID != clientID || issued.RedirectURI != r.Form.Get("redirect_uri") {
		log.Debug().
			Time("code_expires_at", issued.ExpiresAt).
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
		expiresIn := int64(0)
		if !issued.AccessTokenExpiry.IsZero() {
			expiresIn = int64(time.Until(issued.AccessTokenExpiry).Seconds())
			if expiresIn < 0 {
				expiresIn = 0
			}
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

	a.mintBrokerTokenResponse(w, r, secret, brokerIdentity{
		ClientID:      issued.ClientID,
		Subject:       issued.Subject,
		Email:         issued.Email,
		Name:          issued.Name,
		HostedDomain:  issued.HostedDomain,
		EmailVerified: issued.EmailVerified,
		Scope:         issued.Scope,
	})
}

func (a *application) handleOAuthTokenRefresh(w http.ResponseWriter, r *http.Request) {
	if a.oauthForwardMode() {
		writeOAuthTokenError(w, http.StatusBadRequest, "unsupported_grant_type", "refresh tokens are not supported in forward mode")
		return
	}
	secret, err := a.mustBrokerSecret()
	if err != nil {
		writeOAuthTokenError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	// Validate client_id
	clientID := r.Form.Get("client_id")
	clientClaims, err := decodeBrokerArtifact(secret, clientID)
	if err != nil {
		writeOAuthTokenError(w, http.StatusUnauthorized, "invalid_client", "unknown OAuth client")
		return
	}
	client, err := parseStatelessRegisteredClient(clientClaims)
	if err != nil || time.Now().Unix() > client.ExpiresAt {
		writeOAuthTokenError(w, http.StatusUnauthorized, "invalid_client", "unknown OAuth client")
		return
	}

	// Decrypt and validate refresh token
	refreshTokenStr := r.Form.Get("refresh_token")
	if refreshTokenStr == "" {
		writeOAuthTokenError(w, http.StatusBadRequest, "invalid_grant", "missing refresh token")
		return
	}
	claims, err := decodeBrokerArtifact(secret, refreshTokenStr)
	if err != nil {
		writeOAuthTokenError(w, http.StatusBadRequest, "invalid_grant", "invalid refresh token")
		return
	}

	// Verify client_id in refresh token matches the requesting client
	tokenClientID, _ := claims["client_id"].(string)
	if tokenClientID != clientID {
		log.Debug().
			Str("token_client_id", tokenClientID).
			Str("request_client_id", clientID).
			Msg("OAuth refresh rejected: client_id mismatch")
		writeOAuthTokenError(w, http.StatusBadRequest, "invalid_grant", "refresh token was not issued to this client")
		return
	}

	sub, _ := claims["sub"].(string)
	email, _ := claims["email"].(string)
	name, _ := claims["name"].(string)
	hd, _ := claims["hd"].(string)
	emailVerified, _ := claims["email_verified"].(bool)
	scope, _ := claims["scope"].(string)

	a.mintBrokerTokenResponse(w, r, secret, brokerIdentity{
		ClientID:      clientID,
		Subject:       sub,
		Email:         email,
		Name:          name,
		HostedDomain:  hd,
		EmailVerified: emailVerified,
		Scope:         scope,
	})
}

func truncateForLog(value string, max int) string {
	if max <= 0 || len(value) <= max {
		return value
	}
	return value[:max]
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
