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
	"github.com/rs/zerolog/log"
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

func (a *application) oauthEnabled() bool {
	return a.GetCurrentConfig().Server.OAuth.Enabled
}

func (a *application) schemeAndHost(r *http.Request) string {
	scheme := "http"
	switch {
	case r.Header.Get("X-Forwarded-Proto") != "":
		scheme = strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0])
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

func cleanedPathPrefix(prefix string) string {
	prefix = strings.TrimSpace(strings.Split(prefix, ",")[0])
	if prefix == "" {
		return ""
	}
	if !strings.HasPrefix(prefix, "/") {
		prefix = "/" + prefix
	}
	return strings.TrimRight(prefix, "/")
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
	if prefix := cleanedPathPrefix(r.Header.Get("X-Forwarded-Prefix")); prefix != "" {
		return prefix
	}
	if prefix := suffixPrefix(
		r.URL.Path,
		"/.well-known/oauth-protected-resource",
		"/.well-known/oauth-authorization-server",
		"/.well-known/openid-configuration",
	); prefix != "" {
		return prefix
	}
	return pathFromConfiguredURL(a.GetCurrentConfig().Server.OAuth.Audience)
}

func (a *application) oauthPrefix(r *http.Request) string {
	if prefix := cleanedPathPrefix(r.Header.Get("X-Forwarded-OAuth-Prefix")); prefix != "" {
		return prefix
	}
	if prefix := cleanedPathPrefix(r.Header.Get("X-Forwarded-Prefix")); prefix == "/oauth" {
		return prefix
	}
	if prefix := suffixPrefix(
		r.URL.Path,
		"/.well-known/oauth-authorization-server",
		"/.well-known/openid-configuration",
	); prefix == "/oauth" {
		return prefix
	}
	return pathFromConfiguredURL(a.GetCurrentConfig().Server.OAuth.Issuer)
}

func (a *application) resourceBaseURL(r *http.Request) string {
	return a.schemeAndHost(r) + a.resourcePrefix(r)
}

func (a *application) publicBaseURL(r *http.Request) string {
	return a.resourceBaseURL(r)
}

func (a *application) oauthAuthorizationServerBaseURL(r *http.Request) string {
	return a.schemeAndHost(r) + a.oauthPrefix(r)
}

func (a *application) oauthChallengeHeader(r *http.Request) string {
	baseURL := a.resourceBaseURL(r)
	challenge := fmt.Sprintf("Bearer resource_metadata=%q", baseURL+"/.well-known/oauth-protected-resource")
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
				claims, err := a.mcpServer.ValidateOAuthToken(oauthToken)
				if err != nil {
					a.writeOAuthError(w, r, err)
					return
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
		"authorization_endpoint":                baseURL + "/oauth/authorize",
		"token_endpoint":                        baseURL + "/oauth/token",
		"registration_endpoint":                 baseURL + "/oauth/register",
		"scopes_supported":                      a.GetCurrentConfig().Server.OAuth.Scopes,
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"token_endpoint_auth_methods_supported": []string{"none", "client_secret_post", "client_secret_basic"},
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
		"authorization_endpoint":                baseURL + "/oauth/authorize",
		"token_endpoint":                        baseURL + "/oauth/token",
		"registration_endpoint":                 baseURL + "/oauth/register",
		"scopes_supported":                      a.GetCurrentConfig().Server.OAuth.Scopes,
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"token_endpoint_auth_methods_supported": []string{"none", "client_secret_post", "client_secret_basic"},
		"code_challenge_methods_supported":      []string{"S256"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"none"},
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
	client := oauthRegisteredClient{
		ID:                    randomToken("client_"),
		Secret:                randomToken("secret_"),
		RedirectURIs:          req.RedirectURIs,
		TokenEndpointAuthMode: authMethod,
	}
	a.oauthState.mu.Lock()
	a.oauthState.clients[client.ID] = client
	a.oauthState.mu.Unlock()

	resp := map[string]interface{}{
		"client_id":                  client.ID,
		"redirect_uris":              client.RedirectURIs,
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": client.TokenEndpointAuthMode,
		"client_id_issued_at":        time.Now().Unix(),
	}
	if client.TokenEndpointAuthMode != "none" {
		resp["client_secret"] = client.Secret
		resp["client_secret_expires_at"] = 0
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(resp)
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

	a.oauthState.mu.Lock()
	client, ok := a.oauthState.clients[clientID]
	a.oauthState.mu.Unlock()
	if !ok || !containsString(client.RedirectURIs, redirectURI) {
		http.Error(w, "Unknown OAuth client", http.StatusBadRequest)
		return
	}

	requestID := randomToken("req_")
	a.oauthState.mu.Lock()
	a.oauthState.pendingAuth[requestID] = oauthPendingAuth{
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		Scope:               q.Get("scope"),
		State:               q.Get("state"),
		CodeChallenge:       q.Get("code_challenge"),
		CodeChallengeMethod: q.Get("code_challenge_method"),
	}
	a.oauthState.mu.Unlock()

	cfg := a.GetCurrentConfig()
	callbackURL := a.publicBaseURL(r) + "/oauth/callback"
	upstream := url.Values{}
	upstream.Set("client_id", cfg.Server.OAuth.ClientID)
	upstream.Set("redirect_uri", callbackURL)
	upstream.Set("response_type", "code")
	scope := strings.Join(cfg.Server.OAuth.Scopes, " ")
	if scope == "" {
		scope = "openid email"
	}
	upstream.Set("scope", scope)
	upstream.Set("state", requestID)
	http.Redirect(w, r, cfg.Server.OAuth.AuthURL+"?"+upstream.Encode(), http.StatusFound)
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

	a.oauthState.mu.Lock()
	pending, ok := a.oauthState.pendingAuth[requestID]
	if ok {
		delete(a.oauthState.pendingAuth, requestID)
	}
	a.oauthState.mu.Unlock()
	if !ok {
		http.Error(w, "Unknown OAuth request", http.StatusBadRequest)
		return
	}

	cfg := a.GetCurrentConfig()
	callbackURL := a.publicBaseURL(r) + "/oauth/callback"
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("client_id", cfg.Server.OAuth.ClientID)
	form.Set("client_secret", cfg.Server.OAuth.ClientSecret)
	form.Set("redirect_uri", callbackURL)

	resp, err := http.PostForm(cfg.Server.OAuth.TokenURL, form)
	if err != nil {
		http.Error(w, "Failed to exchange Google auth code", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		log.Error().Int("status", resp.StatusCode).Bytes("body", body).Msg("Google OAuth token exchange failed")
		http.Error(w, "Failed to exchange Google auth code", http.StatusBadGateway)
		return
	}
	var tokenResp struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil || tokenResp.IDToken == "" {
		http.Error(w, "Missing Google ID token", http.StatusBadGateway)
		return
	}
	claims, err := parseGoogleIdentityToken(tokenResp.IDToken)
	if err != nil {
		http.Error(w, "Failed to validate Google identity", http.StatusBadGateway)
		return
	}
	if claims.Issuer != "accounts.google.com" && claims.Issuer != "https://accounts.google.com" {
		http.Error(w, "Unexpected Google issuer", http.StatusBadGateway)
		return
	}

	authCode := randomToken("code_")
	a.oauthState.mu.Lock()
	a.oauthState.authCodes[authCode] = oauthIssuedCode{
		ClientID:            pending.ClientID,
		RedirectURI:         pending.RedirectURI,
		Subject:             claims.Subject,
		Email:               claims.Email,
		Name:                claims.Name,
		Scope:               pending.Scope,
		CodeChallenge:       pending.CodeChallenge,
		CodeChallengeMethod: pending.CodeChallengeMethod,
		ExpiresAt:           time.Now().Add(5 * time.Minute),
	}
	a.oauthState.mu.Unlock()

	redirect, err := url.Parse(pending.RedirectURI)
	if err != nil {
		http.Error(w, "Invalid redirect URI", http.StatusBadGateway)
		return
	}
	params := redirect.Query()
	params.Set("code", authCode)
	if pending.State != "" {
		params.Set("state", pending.State)
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
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid token request", http.StatusBadRequest)
		return
	}

	clientID, clientSecret := readClientCredentials(r)
	if clientID == "" {
		clientID = r.Form.Get("client_id")
	}
	a.oauthState.mu.Lock()
	client, ok := a.oauthState.clients[clientID]
	a.oauthState.mu.Unlock()
	if !ok {
		http.Error(w, "Unknown OAuth client", http.StatusUnauthorized)
		return
	}
	if client.TokenEndpointAuthMode != "none" && client.Secret != clientSecret {
		http.Error(w, "Invalid client credentials", http.StatusUnauthorized)
		return
	}

	var (
		subject string
		email   string
		name    string
		scope   string
	)
	switch r.Form.Get("grant_type") {
	case "authorization_code":
		code := r.Form.Get("code")
		redirectURI := r.Form.Get("redirect_uri")
		a.oauthState.mu.Lock()
		issued, ok := a.oauthState.authCodes[code]
		if ok {
			delete(a.oauthState.authCodes, code)
		}
		a.oauthState.mu.Unlock()
		if !ok || time.Now().After(issued.ExpiresAt) || issued.ClientID != clientID || issued.RedirectURI != redirectURI {
			http.Error(w, "Invalid authorization code", http.StatusBadRequest)
			return
		}
		if issued.CodeChallenge != "" {
			if pkceChallenge(r.Form.Get("code_verifier")) != issued.CodeChallenge {
				http.Error(w, "Invalid PKCE verifier", http.StatusBadRequest)
				return
			}
		}
		subject, email, name, scope = issued.Subject, issued.Email, issued.Name, issued.Scope
	case "refresh_token":
		refresh := r.Form.Get("refresh_token")
		a.oauthState.mu.Lock()
		session, ok := a.oauthState.refreshTokens[refresh]
		a.oauthState.mu.Unlock()
		if !ok || time.Now().After(session.ExpiresAt) || session.ClientID != clientID {
			http.Error(w, "Invalid refresh token", http.StatusBadRequest)
			return
		}
		subject, email, name, scope = session.Subject, session.Email, session.Name, session.Scope
	default:
		http.Error(w, "Unsupported grant type", http.StatusBadRequest)
		return
	}

	issuer := strings.TrimSuffix(a.oauthAuthorizationServerBaseURL(r), "/")
	audience := strings.TrimSuffix(a.GetCurrentConfig().Server.OAuth.Audience, "/")
	if audience == "" {
		audience = strings.TrimSuffix(a.resourceBaseURL(r), "/")
	}
	if scope == "" {
		scope = strings.Join(a.GetCurrentConfig().Server.OAuth.Scopes, " ")
	}
	accessToken, err := encodeUnsignedJWT(map[string]interface{}{
		"sub":   subject,
		"iss":   issuer,
		"aud":   audience,
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iat":   time.Now().Unix(),
		"scope": scope,
		"email": email,
		"name":  name,
	})
	if err != nil {
		http.Error(w, "Failed to mint access token", http.StatusInternalServerError)
		return
	}
	refreshToken := randomToken("refresh_")
	a.oauthState.mu.Lock()
	a.oauthState.refreshTokens[refreshToken] = oauthRefreshSession{
		ClientID:  clientID,
		Subject:   subject,
		Email:     email,
		Name:      name,
		Scope:     scope,
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
	}
	a.oauthState.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"access_token":  accessToken,
		"token_type":    "Bearer",
		"expires_in":    3600,
		"refresh_token": refreshToken,
		"scope":         scope,
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
	protectedResourceAliases := []string{
		"/.well-known/oauth-protected-resource",
		"/.well-known/oauth-protected-resource/http",
		"/http/.well-known/oauth-protected-resource",
	}
	for _, path := range protectedResourceAliases {
		mux.HandleFunc(path, a.handleOAuthProtectedResource)
	}

	authMetadataAliases := []string{
		"/.well-known/oauth-authorization-server",
		"/.well-known/oauth-authorization-server/http",
		"/.well-known/oauth-authorization-server/oauth",
		"/http/.well-known/oauth-authorization-server",
		"/oauth/.well-known/oauth-authorization-server",
	}
	for _, path := range authMetadataAliases {
		mux.HandleFunc(path, a.handleOAuthAuthorizationServerMetadata)
	}

	openIDAliases := []string{
		"/.well-known/openid-configuration",
		"/.well-known/openid-configuration/http",
		"/.well-known/openid-configuration/oauth",
		"/http/.well-known/openid-configuration",
		"/oauth/.well-known/openid-configuration",
	}
	for _, path := range openIDAliases {
		mux.HandleFunc(path, a.handleOAuthOpenIDConfiguration)
	}

	mux.HandleFunc("/oauth/register", a.handleOAuthRegister)
	mux.HandleFunc("/oauth/authorize", a.handleOAuthAuthorize)
	mux.HandleFunc("/oauth/callback", a.handleOAuthCallback)
	mux.HandleFunc("/oauth/token", a.handleOAuthToken)
}
