package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/altinity/altinity-mcp/pkg/jwe_auth"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
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

type OpenIDConfiguration struct {
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

func (s *ClickHouseJWEServer) fetchOpenIDConfiguration(issuer string) (*OpenIDConfiguration, error) {
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
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Warn().Stack().Err(closeErr).Msgf("can't close %s response body", metadataURL)
		}
		if resp.StatusCode >= 300 || readErr != nil {
			continue
		}
		var discovery OpenIDConfiguration
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
func (s *ClickHouseJWEServer) FetchOpenIDConfiguration(issuer string) (*OpenIDConfiguration, error) {
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
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Warn().Stack().Err(err).Msgf("can't close %s response body", jwksURI)
		}
	}()
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
