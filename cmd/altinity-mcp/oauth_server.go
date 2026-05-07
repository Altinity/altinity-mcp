package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
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
	"github.com/altinity/altinity-mcp/pkg/oauth_state"
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
	// defaultPendingAuthTTLSeconds bounds /authorize → /callback (the user has
	// to log in upstream). 10 minutes per RFC 6749 §3.1.2 guidance for the
	// authorization request lifetime.
	defaultPendingAuthTTLSeconds = 10 * 60
	// defaultAuthCodeTTLSeconds bounds /callback → /token (the legitimate
	// client redeems immediately). 60 seconds per OAuth 2.1 §4.1.2 — auth
	// codes "should be redeemed within seconds, never minutes."
	defaultAuthCodeTTLSeconds     = 60
	defaultAccessTokenTTLSeconds  = 60 * 60
	defaultRefreshTokenTTLSeconds = 30 * 24 * 60 * 60
)

type statelessRegisteredClient struct {
	RedirectURIs            []string `json:"redirect_uris"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	GrantType               string   `json:"grant_type"`
	ExpiresAt               int64    `json:"exp"`
	// ClientSecret is the per-registration secret issued during DCR for
	// confidential clients (token_endpoint_auth_method: client_secret_post |
	// client_secret_basic). When empty, the client is public (PKCE-only) —
	// retained for backward compat with previously-issued client_ids.
	ClientSecret string `json:"client_secret,omitempty"`
}

type oauthPendingAuth struct {
	ClientID            string `json:"client_id"`
	RedirectURI         string `json:"redirect_uri"`
	Scope               string `json:"scope"`
	ClientState         string `json:"client_state"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
	// Resource is the RFC 8707 resource indicator the client passed on
	// /authorize. Stored verbatim (trailing-slash form preserved) so that
	// the eventual `aud` claim byte-matches what the client requested —
	// claude.ai's artifact proxy enforces this byte-equality.
	Resource string `json:"resource,omitempty"`
	// UpstreamPKCEVerifier is *our* PKCE verifier for the upstream-IdP leg
	// (RFC 7636 / OAuth 2.1 §7.5.2). The MCP-client→us leg uses its own
	// verifier (CodeChallenge above); this is the second, independent PKCE
	// pair we use as the OAuth client to the upstream IdP. Required by
	// OAuth 2.1 even when we hold the upstream client_secret, because PKCE
	// also defends against auth-code interception between IdP and our /callback.
	UpstreamPKCEVerifier string `json:"upstream_pkce_verifier,omitempty"`
	ExpiresAt            time.Time
}

type oauthIssuedCode struct {
	ClientID             string `json:"client_id"`
	RedirectURI          string `json:"redirect_uri"`
	Scope                string `json:"scope"`
	CodeChallenge        string `json:"code_challenge"`
	CodeChallengeMethod  string `json:"code_challenge_method"`
	Resource             string `json:"resource,omitempty"`
	UpstreamBearerToken  string `json:"upstream_bearer_token"`
	UpstreamRefreshToken string `json:"upstream_refresh_token,omitempty"`
	UpstreamTokenType    string `json:"upstream_token_type"`
	Subject              string `json:"sub"`
	Email                string `json:"email"`
	Name                 string `json:"name"`
	HostedDomain         string `json:"hd"`
	EmailVerified        bool   `json:"email_verified"`
	ExpiresAt            time.Time
	AccessTokenExpiry    time.Time
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

func (a *application) oauthJWESecret() []byte {
	secret := strings.TrimSpace(a.GetCurrentConfig().Server.OAuth.SigningSecret)
	return []byte(secret)
}

func (a *application) mustJWESecret() ([]byte, error) {
	secret := a.oauthJWESecret()
	if len(secret) == 0 {
		return nil, fmt.Errorf("oauth signing_secret is required for OAuth client registration and gating-mode token minting")
	}
	return secret, nil
}

// oauthKidV1 is the kid header set on cmd-minted OAuth JWE artifacts
// (client_id, refresh-token). Its presence selects the HKDF-derived key on
// decryption; absence (kid="") selects the legacy SHA256(secret) key for
// backwards compat with artifacts minted before the rotation cutover. After
// the longest legacy artifact lifetime expires (refresh tokens, default 30
// days), the legacy fallback below can be removed. Self-issued access-token
// JWS artifacts use altinitymcp.SelfIssuedAccessTokenKid instead — pkg/server
// is the verifier and owns that contract.
const oauthKidV1 = "v1"

// HKDF info labels for cmd-internal OAuth key derivation. Each label produces
// an independent 32-byte key from the shared signing_secret (RFC 5869 §3.2).
// Bumping the /vN suffix in any single label rotates that one key without
// disturbing the others. The access-token label lives in pkg/server as
// altinitymcp.SelfIssuedAccessTokenHKDFInfo because the verifier owns it.
const (
	hkdfInfoOAuthClientID = "altinity-mcp/oauth/client-id/v1"
	hkdfInfoOAuthRefresh  = "altinity-mcp/oauth/refresh-token/v1"
)

// encodeOAuthJWE emits a JWE-wrapped JSON document of `claims`, encrypted
// with a key HKDF-derived from `secret` and the per-context `info` label.
// kid="v1" is set in the protected header so decoders pick the same key.
func encodeOAuthJWE(secret []byte, info string, claims map[string]interface{}) (string, error) {
	key := jwe_auth.DeriveKey(secret, info)
	plaintext, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	encrypter, err := jose.NewEncrypter(
		jose.A256GCM,
		jose.Recipient{Algorithm: jose.A256KW, Key: key},
		(&jose.EncrypterOptions{}).
			WithType("JWE").
			WithContentType("JSON").
			WithHeader(jose.HeaderKey("kid"), oauthKidV1),
	)
	if err != nil {
		return "", err
	}
	jweObj, err := encrypter.Encrypt(plaintext)
	if err != nil {
		return "", err
	}
	return jweObj.CompactSerialize()
}

// decodeOAuthJWE decrypts a JWE produced by encodeOAuthJWE OR by the legacy
// jwe_auth.GenerateJWEToken path used before this commit. The kid header
// selects the derivation:
//
//   - kid == oauthKidV1 → key = HKDF(secret, info)
//   - kid == ""         → key = SHA256(secret) (legacy)
//
// The same RFC 7591/JWE-claim whitelist + expiration check applies to both
// paths via the exported jwe_auth.ValidateClaimsWhitelist / ValidateExpiration
// helpers.
func decodeOAuthJWE(secret []byte, info string, token string) (map[string]interface{}, error) {
	jweObj, err := jose.ParseEncrypted(token,
		[]jose.KeyAlgorithm{jose.A256KW},
		[]jose.ContentEncryption{jose.A256GCM})
	if err != nil {
		return nil, jwe_auth.ErrInvalidToken
	}
	if jweObj.Header.KeyID == oauthKidV1 {
		key := jwe_auth.DeriveKey(secret, info)
		decrypted, err := jweObj.Decrypt(key)
		if err != nil {
			return nil, jwe_auth.ErrInvalidToken
		}
		var claims map[string]interface{}
		if err := json.Unmarshal(decrypted, &claims); err != nil {
			return nil, jwe_auth.ErrInvalidToken
		}
		if err := jwe_auth.ValidateClaimsWhitelist(claims); err != nil {
			return nil, err
		}
		if err := jwe_auth.ValidateExpiration(claims); err != nil {
			return nil, err
		}
		return claims, nil
	}
	// Legacy path: jwe_auth.ParseAndDecryptJWE knows the SHA256(secret)
	// derivation AND the legacy JWT-signed-inside-JWE content type. Routing
	// through it keeps a single source of truth for every legacy variant.
	return jwe_auth.ParseAndDecryptJWE(token, secret, secret)
}


func normalizeURL(raw string) string {
	return strings.TrimRight(strings.TrimSpace(raw), "/")
}

// canonicalResourceURL returns the protected-resource identifier in its
// canonical form: trimmed and with exactly one trailing slash. RFC 9728 §3.3
// (the Bearer Token resource_metadata) and RFC 8707 (resource indicators)
// treat the resource URL as an opaque identifier compared by string match,
// so a stable canonical form is what matters; the trailing-slash form is
// what most upstream IdPs (Auth0, Google) emit in `aud` claims and what
// Claude.ai expects to round-trip in metadata. Audience validation uses
// audienceMatchesResource to accept either form on the inbound side.
func canonicalResourceURL(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	return strings.TrimRight(trimmed, "/") + "/"
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

func (a *application) oauthAuthorizationServerBaseURL(r *http.Request) string {
	if configured := normalizeURL(a.GetCurrentConfig().Server.OAuth.PublicAuthServerURL); configured != "" {
		return configured
	}
	return a.schemeAndHost(r) + a.oauthPrefix(r)
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

// oauthChallengeHeader builds the WWW-Authenticate Bearer challenge.
//
//   - error: distinguishes the failure (invalid_token | insufficient_scope) per
//     RFC 6750 §3 / 3.1. error="invalid_token" is what triggers Anthropic's
//     proxy to start the OAuth discovery flow; without it, some clients treat
//     the 401 as a generic auth failure and skip MCP OAuth entirely.
//   - error_description: human-readable detail for logs/UI.
//   - resource_metadata: where to fetch the RFC 9728 protected-resource doc.
//   - scope: the scopes the client should request to access the resource. MCP
//     authorization spec 2025-11-25 §Protected Resource Metadata Discovery
//     Requirements marks this as SHOULD on initial 401, MUST on
//     insufficient_scope (§Runtime Insufficient Scope Errors). Populated from
//     challengeScope() on both paths.
func (a *application) oauthChallengeHeader(r *http.Request, errCode, errDesc, scope string) string {
	baseURL := a.resourceBaseURL(r)
	resourceMetadata := joinURLPath(baseURL, defaultProtectedResourceMetadataPath)
	if errCode == "" {
		errCode = "invalid_token"
	}
	if errDesc == "" {
		errDesc = "Authentication required"
	}
	parts := []string{
		fmt.Sprintf("error=%q", errCode),
		fmt.Sprintf("error_description=%q", errDesc),
		fmt.Sprintf("resource_metadata=%q", resourceMetadata),
	}
	if scope != "" {
		parts = append(parts, fmt.Sprintf("scope=%q", scope))
	}
	return "Bearer " + strings.Join(parts, ", ")
}

// safeUpstreamErrorFields extracts the RFC 6749 §5.2 `error` code from an
// upstream OAuth error response body, if the body parses as JSON, and always
// returns the body byte length. Used in lieu of logging the body verbatim:
// IdPs sometimes echo the failed token, request parameters, or other
// diagnostic data inside `error_description`, which would otherwise land in
// centralized logs. The `error` field is an RFC-defined enum and safe to log.
func safeUpstreamErrorFields(body []byte) (errCode string, length int) {
	var parsed struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(body, &parsed)
	return parsed.Error, len(body)
}

// challengeScope returns the scope string for the WWW-Authenticate header.
// Prefers RequiredScopes (the operator-pinned minimum); falls back to the full
// Scopes catalog so the client at least has something to request from. Empty
// string when neither is configured — caller will then omit the attribute.
func (a *application) challengeScope() string {
	cfg := a.GetCurrentConfig().Server.OAuth
	switch {
	case len(cfg.RequiredScopes) > 0:
		return strings.Join(cfg.RequiredScopes, " ")
	case len(cfg.Scopes) > 0:
		return strings.Join(cfg.Scopes, " ")
	}
	return ""
}

func (a *application) writeOAuthError(w http.ResponseWriter, r *http.Request, err error) {
	var (
		code           int
		oauthErr, desc string
	)
	switch {
	case errors.Is(err, altinitymcp.ErrOAuthInsufficientScopes):
		// MUST per RFC 6750 §3.1 / MCP §Runtime Insufficient Scope Errors.
		code, oauthErr, desc = http.StatusForbidden, "insufficient_scope", "Insufficient OAuth scopes"
	case errors.Is(err, altinitymcp.ErrOAuthTokenExpired):
		code, oauthErr, desc = http.StatusUnauthorized, "invalid_token", "OAuth token expired"
	default:
		code, oauthErr, desc = http.StatusUnauthorized, "invalid_token", "Authentication required"
	}
	// SHOULD per MCP §Protected Resource Metadata Discovery Requirements on the
	// 401 path; same source list as the insufficient_scope case (RequiredScopes
	// preferred, Scopes as fallback).
	w.Header().Set("WWW-Authenticate", a.oauthChallengeHeader(r, oauthErr, desc, a.challengeScope()))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": oauthErr, "error_description": desc})
}

func (a *application) createMCPAuthInjector(cfg config.Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			jweHasCredentials := false

			if cfg.Server.JWE.Enabled {
				token := r.PathValue("token")
				if token == "" {
					token = r.Header.Get("x-altinity-mcp-key")
				}
				if token != "" {
					jweClaims, err := a.mcpServer.ParseJWEClaims(token)
					if err != nil {
						// Route through the OAuth challenge writer when OAuth is also
						// enabled — clients hitting a malformed JWE then need OAuth
						// discovery to recover. With OAuth disabled this path returns
						// the same JSON error shape minus the WWW-Authenticate header.
						a.writeOAuthError(w, r, altinitymcp.ErrInvalidOAuthToken)
						return
					}
					ctx = context.WithValue(ctx, altinitymcp.JWETokenKey, token)
					ctx = context.WithValue(ctx, altinitymcp.JWEClaimsKey, jweClaims)
					jweHasCredentials = a.mcpServer.JWEClaimsHaveCredentials(jweClaims)
				}
			}

			if cfg.Server.OAuth.Enabled && !jweHasCredentials {
				oauthToken := a.mcpServer.ExtractOAuthTokenFromRequest(r)
				if oauthToken == "" {
					a.writeOAuthError(w, r, altinitymcp.ErrMissingOAuthToken)
					return
				}
				// C-1: validate locally in both gating and forward modes per MCP
				// authorization spec §Token Handling. Forward-mode opaque tokens
				// and JWTs without a configured JWKS source soft-pass with nil
				// claims; ValidateOAuthToken decides which is which.
				claims, err := a.mcpServer.ValidateOAuthToken(oauthToken)
				if err != nil {
					a.writeOAuthError(w, r, err)
					return
				}
				ctx = context.WithValue(ctx, altinitymcp.OAuthTokenKey, oauthToken)
				ctx = context.WithValue(ctx, altinitymcp.OAuthClaimsKey, claims)
			}

			// At least one auth method must have succeeded
			if cfg.Server.JWE.Enabled && ctx.Value(altinitymcp.JWETokenKey) == nil &&
				cfg.Server.OAuth.Enabled && ctx.Value(altinitymcp.OAuthTokenKey) == nil {
				http.Error(w, "Missing authentication", http.StatusUnauthorized)
				return
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

// generateOAuthRandomID returns a 16-byte (128-bit) random hex-encoded
// identifier suitable for refresh-token jti and family_id claims (H-2).
// 32 hex characters; collision probability is negligible at our token
// volume but verifiable via the consumed-jtis store regardless.
func generateOAuthRandomID() (string, error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf[:]), nil
}

func encodeSelfIssuedAccessToken(secret []byte, claims map[string]interface{}) (string, error) {
	// Signing key is HKDF-derived per the access-token info label, separate
	// from the JWE-encryption keys used for client_id and refresh_token. The
	// kid header lets parseAndVerifySelfIssuedOAuthToken (pkg/server) select
	// this derivation; legacy tokens (no kid) verify against the old
	// SHA256(secret). Both the kid value and the info label are imported
	// from pkg/server — that package is the verifier and owns the contract.
	signingKey := jwe_auth.DeriveKey(secret, altinitymcp.SelfIssuedAccessTokenHKDFInfo)
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.HS256, Key: signingKey},
		(&jose.SignerOptions{}).
			WithType("JWT").
			WithHeader(jose.HeaderKey("kid"), altinitymcp.SelfIssuedAccessTokenKid),
	)
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

// newPKCEVerifier generates a 32-byte random PKCE verifier per RFC 7636 §4.1
// (43–128 char URL-safe string). Used for the upstream-IdP leg only —
// downstream MCP-client verifiers come from the client itself.
func newPKCEVerifier() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
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

// authenticateClientSecret validates the inbound `client_secret` against the
// one stored in the registered client's metadata. RFC 6749 §2.3.1 allows the
// secret to be presented either via the form body (client_secret_post) or
// the Authorization: Basic header (client_secret_basic); we accept both.
//
// For backward compat with previously-registered public (PKCE-only) clients
// — those whose JWE-encoded client_id has no `client_secret` claim — we
// return nil even when the client supplied no secret. New registrations
// always carry a client_secret, so this fallback only applies to legacy
// client_ids issued before this change.
func authenticateClientSecret(client *statelessRegisteredClient, r *http.Request) error {
	if client.ClientSecret == "" {
		return nil
	}
	got := r.Form.Get("client_secret")
	if got == "" {
		if user, pass, ok := r.BasicAuth(); ok && user != "" {
			got = pass
		}
	}
	if got == "" {
		return fmt.Errorf("client_secret is required")
	}
	if subtle.ConstantTimeCompare([]byte(got), []byte(client.ClientSecret)) != 1 {
		return fmt.Errorf("client_secret mismatch")
	}
	return nil
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
	if cs, ok := claims["client_secret"].(string); ok {
		client.ClientSecret = cs
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
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Error().Err(closeErr).Msgf("can't close %s response body", userInfoURL)
		}
	}()
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
		// `resource` is the canonical RFC 9728 protected-resource identifier
		// (with trailing slash, per canonicalResourceURL); claude.ai's artifact
		// proxy compares the metadata field literally and round-trips it to the
		// `aud` claim. Inbound `aud` validation tolerates either form via
		// audienceMatchesResource. `authorization_servers` follows the RFC 8414
		// issuer convention (no trailing slash) so as[0] == issuer holds byte-
		// for-byte.
		"resource":                 canonicalResourceURL(baseURL),
		"authorization_servers":    []string{strings.TrimRight(authServerBaseURL, "/")},
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
	// `issuer` is published without a trailing slash to match the RFC 8414 §2
	// convention (issuer == authorization_servers[i] in the resource document).
	// mintGatingTokenResponse mints `iss` in the same form, and
	// validateOAuthClaims still normalises slashes defensively.
	issuer := strings.TrimRight(baseURL, "/")
	resp := map[string]interface{}{
		"issuer":                                issuer,
		"authorization_endpoint":                joinURLPath(baseURL, a.oauthAuthorizationPath()),
		"token_endpoint":                        joinURLPath(baseURL, a.oauthTokenPath()),
		"registration_endpoint":                 joinURLPath(baseURL, a.oauthRegistrationPath()),
		"scopes_supported":                      a.GetCurrentConfig().Server.OAuth.Scopes,
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_post", "client_secret_basic", "none"},
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
	issuer := strings.TrimRight(baseURL, "/")
	resp := map[string]interface{}{
		"issuer":                                issuer,
		"authorization_endpoint":                joinURLPath(baseURL, a.oauthAuthorizationPath()),
		"token_endpoint":                        joinURLPath(baseURL, a.oauthTokenPath()),
		"registration_endpoint":                 joinURLPath(baseURL, a.oauthRegistrationPath()),
		"scopes_supported":                      a.GetCurrentConfig().Server.OAuth.Scopes,
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_post", "client_secret_basic", "none"},
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
	// We register every new client as confidential (client_secret_post). The
	// stored secret lives inside the JWE-encoded client_id, so the server
	// remains stateless. Anthropic's `mcp_servers`-via-URL flow requires a
	// confidential AS (it has no browser to perform PKCE on); leaving the
	// "none" path as the only option silently 401s every artifact-side call.
	// Public-client (PKCE-only) registrations from clients that explicitly ask
	// for token_endpoint_auth_method:none are still honoured for back-compat
	// with first-party apps that use only the browser auth-code path.
	authMethod := req.TokenEndpointAuthMethod
	if authMethod == "" {
		authMethod = "client_secret_post"
	}
	switch authMethod {
	case "client_secret_post", "client_secret_basic", "none":
	default:
		http.Error(w, "Unsupported token_endpoint_auth_method", http.StatusBadRequest)
		return
	}

	secret, err := a.mustJWESecret()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var clientSecret string
	if authMethod != "none" {
		var raw [32]byte
		if _, err := rand.Read(raw[:]); err != nil {
			http.Error(w, "Failed to generate client_secret", http.StatusInternalServerError)
			return
		}
		clientSecret = hex.EncodeToString(raw[:])
	}

	clientIDClaims := map[string]interface{}{
		"redirect_uris":              req.RedirectURIs,
		"token_endpoint_auth_method": authMethod,
		"grant_type":                 "authorization_code",
		"exp":                        time.Now().Add(30 * 24 * time.Hour).Unix(),
	}
	if clientSecret != "" {
		// Embed the secret inside the JWE so the token endpoint can compare
		// it against the inbound form parameter without server-side state.
		clientIDClaims["client_secret"] = clientSecret
	}
	clientID, err := encodeOAuthJWE(secret, hkdfInfoOAuthClientID, clientIDClaims)
	if err != nil {
		http.Error(w, "Failed to create stateless client registration", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	expAt := time.Now().Add(30 * 24 * time.Hour).Unix()
	// grant_types must include every grant the server will accept from this
	// client. Per RFC 7591 §3.2.1 clients treat this list as authoritative,
	// so omitting refresh_token here causes strict clients (e.g. Claude.ai)
	// to skip grant_type=refresh_token even though /oauth/token would
	// accept it and /.well-known/oauth-authorization-server advertises it
	// via grant_types_supported.
	scopes := a.GetCurrentConfig().Server.OAuth.Scopes
	if len(scopes) == 0 {
		scopes = a.GetCurrentConfig().Server.OAuth.RequiredScopes
	}
	resp := map[string]interface{}{
		"client_id":                  clientID,
		"client_id_issued_at":        time.Now().Unix(),
		"redirect_uris":              req.RedirectURIs,
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": authMethod,
	}
	if len(scopes) > 0 {
		resp["scope"] = strings.Join(scopes, " ")
	}
	if clientSecret != "" {
		resp["client_secret"] = clientSecret
		// RFC 7591 §3.2.1: client_secret_expires_at is REQUIRED when a secret
		// is issued. The JWE client_id embeds the same exp, so use it here too.
		resp["client_secret_expires_at"] = expAt
	}
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
	secret, err := a.mustJWESecret()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	clientClaims, err := decodeOAuthJWE(secret, hkdfInfoOAuthClientID, clientID)
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
	// RFC 8707 §2 / MCP authorization spec: clients SHOULD include `resource`.
	// Validate it identifies *this* MCP server. Compare slash-normalised so the
	// client can pass either form, but preserve the exact string sent so the
	// eventual `aud` claim byte-matches what the client requested. Anthropic's
	// artifact proxy validates aud byte-equality against the resource it sent.
	resource := q.Get("resource")
	if resource != "" {
		want := strings.TrimRight(a.resourceBaseURL(r), "/")
		got := strings.TrimRight(resource, "/")
		if got != want {
			log.Debug().Str("got", resource).Str("want", a.resourceBaseURL(r)).Msg("OAuth /authorize rejected: resource indicator mismatch")
			http.Error(w, "Invalid resource indicator", http.StatusBadRequest)
			return
		}
	}
	// Upstream-leg PKCE (OAuth 2.1 §7.5.2): we generate a fresh verifier
	// independent of the MCP-client's PKCE, then send code_challenge=SHA256
	// to the upstream IdP. Defends the upstream auth code from interception
	// between IdP and our /oauth/callback even if we hold the upstream
	// client_secret. Verifier stays in pendingAuth and is replayed during
	// the /token exchange in handleOAuthCallback.
	upstreamVerifier, err := newPKCEVerifier()
	if err != nil {
		http.Error(w, "Failed to generate PKCE verifier", http.StatusInternalServerError)
		return
	}

	callbackState := randomToken("oas_")
	a.getOAuthStateStore().putPendingAuth(callbackState, oauthPendingAuth{
		ClientID:             clientID,
		RedirectURI:          redirectURI,
		Scope:                sanitizeScope(q.Get("scope")),
		ClientState:          q.Get("state"),
		CodeChallenge:        q.Get("code_challenge"),
		CodeChallengeMethod:  q.Get("code_challenge_method"),
		Resource:             resource,
		UpstreamPKCEVerifier: upstreamVerifier,
		ExpiresAt:            time.Now().Add(time.Duration(defaultPendingAuthTTLSeconds) * time.Second),
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
	if a.oauthForwardMode() && cfg.Server.OAuth.UpstreamOfflineAccess && !slices.Contains(strings.Fields(scope), "offline_access") {
		scope = strings.TrimSpace(scope + " offline_access")
	}
	upstream.Set("scope", scope)
	upstream.Set("state", callbackState)
	upstream.Set("code_challenge", pkceChallenge(upstreamVerifier))
	upstream.Set("code_challenge_method", "S256")
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
	// Replay our upstream PKCE verifier (set during /authorize) per RFC 7636
	// §4.5. Skipped only for legacy pending entries that predate the PKCE
	// upgrade — those expire within 10 minutes and stop appearing.
	if pending.UpstreamPKCEVerifier != "" {
		form.Set("code_verifier", pending.UpstreamPKCEVerifier)
	}

	tokenURL, err := a.resolveUpstreamTokenURL()
	if err != nil {
		http.Error(w, "Failed to resolve upstream token endpoint", http.StatusBadGateway)
		return
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).PostForm(tokenURL, form)
	if err != nil {
		log.Error().Err(err).Str("token_url", tokenURL).Msg("Upstream OAuth token exchange request failed")
		http.Error(w, "Failed to exchange upstream auth code", http.StatusBadGateway)
		return
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Error().Err(closeErr).Msgf("can't close %s response body", tokenURL)
		}
	}()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxOAuthResponseBytes))
	if err != nil {
		http.Error(w, "Failed to read upstream token response", http.StatusBadGateway)
		return
	}
	if resp.StatusCode >= 300 {
		errCode, bodyLen := safeUpstreamErrorFields(body)
		log.Error().Int("status", resp.StatusCode).Str("error_code", errCode).Int("body_len", bodyLen).Msg("Upstream OAuth token exchange failed")
		http.Error(w, "Failed to exchange upstream auth code", http.StatusBadGateway)
		return
	}
	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		IDToken      string `json:"id_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int64  `json:"expires_in"`
		Scope        string `json:"scope"`
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
	log.Info().
		Bool("has_access_token", tokenResp.AccessToken != "").
		Bool("has_id_token", tokenResp.IDToken != "").
		Bool("has_refresh_token", tokenResp.RefreshToken != "").
		Bool("forward_mode", a.oauthForwardMode()).
		Bool("upstream_offline_access", cfg.Server.OAuth.UpstreamOfflineAccess).
		Str("scope", tokenResp.Scope).
		Int64("expires_in", tokenResp.ExpiresIn).
		Msg("Upstream OAuth token exchange succeeded")

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
	bearerToken := tokenResp.IDToken
	if bearerToken == "" {
		bearerToken = tokenResp.AccessToken
	}
	// The bearer we forward to ClickHouse is the ID token when present, else
	// the access_token. Auth0 (and other IdPs) routinely return different
	// lifetimes for the two — e.g. expires_in=86400 for the access_token while
	// the id_token's own exp is iat+3600. We must report expires_in matching
	// the actual bearer the client receives, otherwise downstream MCP clients
	// (Claude.ai) won't refresh in time and the user-visible session breaks
	// at the bearer's real expiry.
	var accessTokenExpiry int64
	if tokenResp.IDToken != "" && identityClaims != nil && identityClaims.ExpiresAt > 0 {
		accessTokenExpiry = identityClaims.ExpiresAt
	} else if tokenResp.ExpiresIn > 0 {
		accessTokenExpiry = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second).Unix()
	} else {
		accessTokenExpiry = time.Now().Add(time.Hour).Unix()
	}
	gatingCode := randomToken("oac_")
	issuedCode := oauthIssuedCode{
		ClientID:            pending.ClientID,
		RedirectURI:         pending.RedirectURI,
		Scope:               tokenResp.Scope,
		CodeChallenge:       pending.CodeChallenge,
		CodeChallengeMethod: pending.CodeChallengeMethod,
		Resource:            pending.Resource,
		ExpiresAt:           time.Now().Add(time.Duration(defaultAuthCodeTTLSeconds) * time.Second),
	}
	if a.oauthForwardMode() {
		issuedCode.UpstreamBearerToken = bearerToken
		issuedCode.UpstreamTokenType = tokenType
		issuedCode.AccessTokenExpiry = time.Unix(accessTokenExpiry, 0)
		if cfg.Server.OAuth.UpstreamOfflineAccess {
			issuedCode.UpstreamRefreshToken = tokenResp.RefreshToken
			if tokenResp.RefreshToken == "" {
				log.Warn().
					Str("scope", tokenResp.Scope).
					Msg("upstream_offline_access=true but upstream did not return a refresh_token; check IdP application config (offline_access scope, refresh_token grant, audience)")
			}
		}
	} else {
		issuedCode.Subject = identityClaims.Subject
		issuedCode.Email = identityClaims.Email
		issuedCode.Name = identityClaims.Name
		issuedCode.HostedDomain = identityClaims.HostedDomain
		issuedCode.EmailVerified = identityClaims.EmailVerified
	}
	a.getOAuthStateStore().putAuthCode(gatingCode, issuedCode)

	redirect, err := url.Parse(pending.RedirectURI)
	if err != nil {
		http.Error(w, "Invalid redirect URI", http.StatusBadGateway)
		return
	}
	params := redirect.Query()
	params.Set("code", gatingCode)
	if pending.ClientState != "" {
		params.Set("state", pending.ClientState)
	}
	redirect.RawQuery = params.Encode()
	http.Redirect(w, r, redirect.String(), http.StatusFound)
}

// gatingIdentity holds the identity fields needed to mint gating-mode tokens.
type gatingIdentity struct {
	ClientID      string
	Subject       string
	Email         string
	Name          string
	HostedDomain  string
	EmailVerified bool
	Scope         string
	// Resource is the RFC 8707 resource indicator the client requested.
	// Empty when the client did not pass one. When set, it is used verbatim
	// as the `aud` claim — preserving trailing-slash form for byte-equality
	// with what the client sent.
	Resource string
	// FamilyID is the OAuth refresh-token family identifier (H-2 reuse
	// detection). At initial code→token exchange this is empty and
	// mintGatingTokenResponse generates a fresh one. On refresh, the caller
	// extracts the family_id from the old refresh JWE and passes it through
	// so the new pair stays in the same family.
	//
	// Always non-empty in the minted refresh token's claims when
	// oauth.refresh_revokes_tracking is enabled. Ignored otherwise.
	FamilyID string
}

// mintGatingTokenResponse mints an access token and a stateless refresh token
// for gating mode, then writes the JSON response.
func (a *application) mintGatingTokenResponse(w http.ResponseWriter, r *http.Request, secret []byte, id gatingIdentity) {
	cfg := a.GetCurrentConfig()
	// Match the no-trailing-slash form advertised in /.well-known/oauth-authorization-server
	// (RFC 8414 §2 requires byte-identical issuer between metadata and iss claim).
	issuer := strings.TrimRight(a.oauthAuthorizationServerBaseURL(r), "/")
	// RFC 8707 §2.2 / MCP authorization spec: when the client requested a
	// resource indicator, the `aud` claim MUST identify that resource. Echo
	// the requested string verbatim so byte-equality with what the client sent
	// holds — this is what claude.ai's artifact proxy enforces.
	//
	// When the client did NOT send a resource indicator, fall back to the
	// canonical no-trailing-slash form (matches the advertised `resource`
	// field per MCP 2025-11-25 §Canonical Server URI).
	var audience string
	switch {
	case id.Resource != "":
		audience = id.Resource
	case cfg.Server.OAuth.Audience != "":
		audience = strings.TrimSuffix(cfg.Server.OAuth.Audience, "/")
	default:
		audience = strings.TrimRight(a.resourceBaseURL(r), "/")
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

	refreshClaims := map[string]interface{}{
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
	}

	// H-2: when refresh-token reuse detection is enabled, every issued
	// refresh token carries a fresh jti and a stable family_id. The family
	// is established at initial code→token exchange (FamilyID empty →
	// generate) and propagated through every rotation (FamilyID supplied
	// from the previous refresh's claims). When the flag is off we leave
	// the claims unset so existing forward-mode and pre-H-2 deployments
	// keep producing identical token shapes.
	if cfg.Server.OAuth.RefreshRevokesTracking {
		jti, gerr := generateOAuthRandomID()
		if gerr != nil {
			log.Error().Err(gerr).Msg("Failed to generate refresh-token jti")
			writeOAuthTokenError(w, http.StatusInternalServerError, "server_error", gerr.Error())
			return
		}
		family := id.FamilyID
		if family == "" {
			family, gerr = generateOAuthRandomID()
			if gerr != nil {
				log.Error().Err(gerr).Msg("Failed to generate refresh-token family_id")
				writeOAuthTokenError(w, http.StatusInternalServerError, "server_error", gerr.Error())
				return
			}
		}
		refreshClaims["jti"] = jti
		refreshClaims["family_id"] = family
	}

	refreshToken, err := encodeOAuthJWE(secret, hkdfInfoOAuthRefresh, refreshClaims)
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

// mintForwardRefreshToken wraps an upstream IdP refresh token in a stateless JWE.
func (a *application) mintForwardRefreshToken(secret []byte, upstreamRefresh, upstreamTokenType, scope, clientID, issuer string) (string, error) {
	cfg := a.GetCurrentConfig()
	now := time.Now()
	tokenType := upstreamTokenType
	if tokenType == "" {
		tokenType = "Bearer"
	}
	return encodeOAuthJWE(secret, hkdfInfoOAuthRefresh, map[string]interface{}{
		"upstream_refresh_token": upstreamRefresh,
		"upstream_token_type":    tokenType,
		"scope":                  scope,
		"client_id":              clientID,
		"iss":                    strings.TrimSuffix(issuer, "/"),
		"iat":                    now.Unix(),
		"exp":                    now.Add(time.Duration(ttlSeconds(cfg.Server.OAuth.RefreshTokenTTLSeconds, defaultRefreshTokenTTLSeconds)) * time.Second).Unix(),
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

	grantType := r.Form.Get("grant_type")
	log.Info().
		Str("grant_type", grantType).
		Bool("forward_mode", a.oauthForwardMode()).
		Msg("OAuth /oauth/token request received")
	switch grantType {
	case "authorization_code":
		a.handleOAuthTokenAuthCode(w, r)
	case "refresh_token":
		a.handleOAuthTokenRefresh(w, r)
	default:
		writeOAuthTokenError(w, http.StatusBadRequest, "unsupported_grant_type", "unsupported grant type")
	}
}

func (a *application) handleOAuthTokenAuthCode(w http.ResponseWriter, r *http.Request) {
	secret, err := a.mustJWESecret()
	if err != nil {
		writeOAuthTokenError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	clientID := r.Form.Get("client_id")
	clientClaims, err := decodeOAuthJWE(secret, hkdfInfoOAuthClientID, clientID)
	if err != nil {
		writeOAuthTokenError(w, http.StatusUnauthorized, "invalid_client", "unknown OAuth client")
		return
	}
	client, err := parseStatelessRegisteredClient(clientClaims)
	if err != nil || time.Now().Unix() > client.ExpiresAt {
		log.Debug().
			Err(err).
			Int64("client_expires_at", client.ExpiresAt).
			Str("token_endpoint_auth_method", client.TokenEndpointAuthMethod).
			Msg("OAuth token request rejected: invalid client metadata")
		writeOAuthTokenError(w, http.StatusUnauthorized, "invalid_client", "unknown OAuth client")
		return
	}
	if err := authenticateClientSecret(client, r); err != nil {
		log.Debug().Err(err).Msg("OAuth token request rejected: client_secret authentication failed")
		writeOAuthTokenError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
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

	// RFC 8707 §2.2: clients MAY also send `resource` on /token. When the same
	// resource was already pinned at /authorize, both must agree; if /authorize
	// omitted it but /token includes it, accept and use the latter. Enforced in
	// both gating and forward modes — in forward mode the value is only used
	// for the rejection check (the response carries the upstream bearer token
	// which has its own `aud`).
	resource := issued.Resource
	if formResource := r.Form.Get("resource"); formResource != "" {
		if resource == "" {
			resource = formResource
		} else if strings.TrimRight(formResource, "/") != strings.TrimRight(resource, "/") {
			writeOAuthTokenError(w, http.StatusBadRequest, "invalid_target", "resource indicator does not match the one used at /authorize")
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
		response := map[string]interface{}{
			"access_token": bearerToken,
			"token_type":   issued.UpstreamTokenType,
			"expires_in":   expiresIn,
			"scope":        issued.Scope,
		}
		if issued.UpstreamRefreshToken != "" {
			refreshToken, err := a.mintForwardRefreshToken(secret, issued.UpstreamRefreshToken, issued.UpstreamTokenType, issued.Scope, clientID, a.oauthAuthorizationServerBaseURL(r))
			if err != nil {
				log.Error().Err(err).Msg("Failed to mint forward-mode refresh token")
				writeOAuthTokenError(w, http.StatusInternalServerError, "server_error", err.Error())
				return
			}
			response["refresh_token"] = refreshToken
			log.Info().
				Str("client_id", clientID).
				Int("jwe_len", len(refreshToken)).
				Msg("Forward-mode auth-code response includes refresh_token (JWE wrapping upstream refresh)")
		} else {
			log.Info().
				Str("client_id", clientID).
				Msg("Forward-mode auth-code response WITHOUT refresh_token (no upstream refresh captured)")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
		return
	}

	a.mintGatingTokenResponse(w, r, secret, gatingIdentity{
		ClientID:      issued.ClientID,
		Subject:       issued.Subject,
		Email:         issued.Email,
		Name:          issued.Name,
		HostedDomain:  issued.HostedDomain,
		EmailVerified: issued.EmailVerified,
		Scope:         issued.Scope,
		Resource:      resource,
	})
}

// handleOAuthTokenRefresh exchanges a refresh token for a new access + rotated
// refresh token pair. Refresh tokens are stateless JWE-encrypted blobs validated
// by decrypt + expiry check only.
//
// In gating mode the JWE wraps the user's identity claims and a fresh self-issued
// access token is minted from them. In forward mode the JWE wraps the upstream
// IdP's refresh token; this handler decrypts it, calls the upstream token
// endpoint with grant_type=refresh_token, re-validates the new ID token via the
// configured JWKS, and returns a new pair (access_token = upstream ID token,
// refresh_token = new JWE around the rotated upstream refresh).
//
// Limitations of the stateless design (apply to both modes):
//   - No revocation: a stolen MCP refresh token is valid until its JWE exp.
//   - No reuse detection: a rotated-out MCP refresh token remains valid alongside
//     the new one until it naturally expires.
//   - No server-side state: there is no token store to revoke against.
//
// In forward mode, IdP-side refresh-token rotation + reuse detection (e.g. Auth0)
// provides a second line of defense outside MCP.
func (a *application) handleOAuthTokenRefresh(w http.ResponseWriter, r *http.Request) {
	log.Info().
		Bool("forward_mode", a.oauthForwardMode()).
		Msg("OAuth refresh_token grant: handler entered")
	secret, err := a.mustJWESecret()
	if err != nil {
		writeOAuthTokenError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	// Validate client_id
	clientID := r.Form.Get("client_id")
	clientClaims, err := decodeOAuthJWE(secret, hkdfInfoOAuthClientID, clientID)
	if err != nil {
		writeOAuthTokenError(w, http.StatusUnauthorized, "invalid_client", "unknown OAuth client")
		return
	}
	client, err := parseStatelessRegisteredClient(clientClaims)
	if err != nil || time.Now().Unix() > client.ExpiresAt {
		writeOAuthTokenError(w, http.StatusUnauthorized, "invalid_client", "unknown OAuth client")
		return
	}
	if err := authenticateClientSecret(client, r); err != nil {
		log.Debug().Err(err).Msg("OAuth refresh request rejected: client_secret authentication failed")
		writeOAuthTokenError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
		return
	}

	// Decrypt and validate refresh token
	refreshTokenStr := r.Form.Get("refresh_token")
	if refreshTokenStr == "" {
		writeOAuthTokenError(w, http.StatusBadRequest, "invalid_grant", "missing refresh token")
		return
	}
	claims, err := decodeOAuthJWE(secret, hkdfInfoOAuthRefresh, refreshTokenStr)
	if err != nil {
		log.Warn().Err(err).Msg("OAuth refresh_token grant: JWE decode failed")
		writeOAuthTokenError(w, http.StatusBadRequest, "invalid_grant", "invalid refresh token")
		return
	}
	jweUpstreamRefresh, _ := claims["upstream_refresh_token"].(string)
	log.Info().
		Bool("has_upstream_refresh_token", jweUpstreamRefresh != "").
		Msg("OAuth refresh_token grant: JWE decoded successfully")

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

	if a.oauthForwardMode() {
		a.handleOAuthTokenRefreshForward(w, r, secret, clientID, claims)
		return
	}

	sub, _ := claims["sub"].(string)
	email, _ := claims["email"].(string)
	name, _ := claims["name"].(string)
	hd, _ := claims["hd"].(string)
	emailVerified, _ := claims["email_verified"].(bool)
	scope, _ := claims["scope"].(string)
	resource, _ := claims["aud"].(string)

	// RFC 8707 §2.2: a /token refresh request MAY narrow the resource to a
	// subset of those originally granted. We don't track multi-resource grants,
	// so the only supported case is "same as original" — reject any mismatch.
	if formResource := r.Form.Get("resource"); formResource != "" {
		if resource == "" {
			resource = formResource
		} else if strings.TrimRight(formResource, "/") != strings.TrimRight(resource, "/") {
			writeOAuthTokenError(w, http.StatusBadRequest, "invalid_target", "resource indicator does not match the original grant")
			return
		}
	}

	policyClaims := &altinitymcp.OAuthClaims{
		Email:         email,
		EmailVerified: emailVerified,
		HostedDomain:  hd,
	}
	if err := a.mcpServer.ValidateOAuthIdentityPolicyClaims(policyClaims); err != nil {
		writeOAuthTokenError(w, http.StatusForbidden, "access_denied", err.Error())
		return
	}

	// H-2: refresh-token reuse detection. When enabled, the refresh JWE must
	// carry both jti and family_id (added by mintGatingTokenResponse). We
	// look up jti against the consumed-set and family_id against the revoked
	// -set; on a hit we record the family as revoked and reject the request.
	// On a miss we mark the jti consumed and propagate the family_id into
	// the new token pair so the chain stays linkable.
	//
	// Pre-H-2 refresh tokens lack these claims and are rejected with
	// invalid_grant — clients re-authenticate once. This is the documented
	// rollout cost; "auto-promote on first use" was rejected because it
	// would let a captured pre-deploy token be replayed exactly once before
	// the server starts tracking.
	familyID := ""
	if store := a.mcpServer.RefreshStateStore(); store != nil {
		jti, _ := claims["jti"].(string)
		family, _ := claims["family_id"].(string)
		if jti == "" || family == "" {
			log.Error().
				Str("client_id", clientID).
				Str("sub", sub).
				Bool("has_jti", jti != "").
				Bool("has_family_id", family != "").
				Msg("OAuth refresh token rejected: missing jti or family_id (legacy or malformed)")
			writeOAuthTokenError(w, http.StatusBadRequest, "invalid_grant", "refresh token format unsupported, please re-authenticate")
			return
		}

		switch err := store.CheckAndConsume(r.Context(), jti, family, "reuse_detected"); {
		case errors.Is(err, oauth_state.ErrRefreshReused):
			log.Error().
				Str("family_id", family).
				Str("client_id", clientID).
				Str("sub", sub).
				Msg("OAuth refresh token reuse detected — family revoked")
			writeOAuthTokenError(w, http.StatusBadRequest, "invalid_grant", "refresh token reuse detected, please re-authenticate")
			return
		case err != nil:
			log.Error().
				Err(err).
				Str("family_id", family).
				Str("client_id", clientID).
				Msg("OAuth refresh state lookup failed — hard fail")
			writeOAuthTokenError(w, http.StatusInternalServerError, "server_error", "refresh state unavailable")
			return
		}
		familyID = family
	}

	a.mintGatingTokenResponse(w, r, secret, gatingIdentity{
		ClientID:      clientID,
		Subject:       sub,
		Email:         email,
		Name:          name,
		HostedDomain:  hd,
		EmailVerified: emailVerified,
		Scope:         scope,
		Resource:      resource,
		FamilyID:      familyID,
	})
}

// handleOAuthTokenRefreshForward implements the forward-mode refresh flow.
// The decrypted JWE carries the upstream IdP refresh token; we exchange it
// upstream for a fresh ID token + (rotated) refresh token, re-validate the
// new ID token, and mint a new JWE wrapping the rotated upstream refresh.
//
// RFC 8707 §2.2 note: this path does not validate the optional `resource`
// form parameter. The forward refresh JWE (mintForwardRefreshToken) does not
// embed `aud`, so there is nothing to compare against. Audience enforcement
// in forward mode is delegated to the upstream IdP, which re-issues the ID
// token with its own `aud` claim. Closing this gap requires embedding `aud`
// in the forward refresh JWE — deliberately deferred to keep this change
// small; see the "Out of scope" note in the branch's review-fix plan.
func (a *application) handleOAuthTokenRefreshForward(w http.ResponseWriter, r *http.Request, secret []byte, clientID string, claims map[string]interface{}) {
	upstreamRefresh, _ := claims["upstream_refresh_token"].(string)
	if upstreamRefresh == "" {
		writeOAuthTokenError(w, http.StatusBadRequest, "invalid_grant", "refresh token is not valid for forward mode")
		return
	}
	upstreamTokenType, _ := claims["upstream_token_type"].(string)
	scope, _ := claims["scope"].(string)

	cfg := a.GetCurrentConfig()
	tokenURL, err := a.resolveUpstreamTokenURL()
	if err != nil {
		writeOAuthTokenError(w, http.StatusBadGateway, "server_error", "failed to resolve upstream token endpoint")
		return
	}
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", upstreamRefresh)
	form.Set("client_id", cfg.Server.OAuth.ClientID)
	if cfg.Server.OAuth.ClientSecret != "" {
		form.Set("client_secret", cfg.Server.OAuth.ClientSecret)
	}
	if scope != "" {
		form.Set("scope", scope)
	}

	log.Info().Str("token_url", tokenURL).Msg("Forward-mode refresh: calling upstream /oauth/token")
	resp, err := (&http.Client{Timeout: 10 * time.Second}).PostForm(tokenURL, form)
	if err != nil {
		log.Error().Err(err).Str("token_url", tokenURL).Msg("Upstream OAuth refresh request failed")
		writeOAuthTokenError(w, http.StatusBadGateway, "server_error", "upstream refresh failed")
		return
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Error().Err(closeErr).Msgf("can't close %s response body", tokenURL)
		}
	}()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxOAuthResponseBytes))
	if err != nil {
		writeOAuthTokenError(w, http.StatusBadGateway, "server_error", "failed to read upstream refresh response")
		return
	}
	if resp.StatusCode >= 300 {
		errCode, bodyLen := safeUpstreamErrorFields(body)
		log.Error().Int("status", resp.StatusCode).Str("error_code", errCode).Int("body_len", bodyLen).Msg("Upstream OAuth refresh rejected")
		writeOAuthTokenError(w, http.StatusBadRequest, "invalid_grant", "upstream rejected the refresh token")
		return
	}
	log.Info().Int("status", resp.StatusCode).Msg("Forward-mode refresh: upstream /oauth/token returned 2xx")

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		IDToken      string `json:"id_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int64  `json:"expires_in"`
		Scope        string `json:"scope"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil || (tokenResp.AccessToken == "" && tokenResp.IDToken == "") {
		log.Error().Err(err).Msg("Upstream refresh response missing usable token")
		writeOAuthTokenError(w, http.StatusBadGateway, "server_error", "missing upstream token")
		return
	}

	bearerToken := tokenResp.IDToken
	if bearerToken == "" {
		bearerToken = tokenResp.AccessToken
	}
	// Re-run identity policy on the rotated upstream token before issuing it.
	// Mirror handleOAuthCallback's preference: validate id_token via JWKS when
	// present, otherwise fall back to the upstream userinfo endpoint with the
	// access_token (which also runs identity-policy checks).
	var identityClaims *altinitymcp.OAuthClaims
	if tokenResp.IDToken != "" {
		identityClaims, err = a.mcpServer.ValidateUpstreamIdentityToken(tokenResp.IDToken, cfg.Server.OAuth.ClientID)
		if err != nil {
			log.Error().Err(err).Msg("Upstream identity token validation failed on refresh")
			writeOAuthTokenError(w, http.StatusForbidden, "access_denied", err.Error())
			return
		}
	} else if tokenResp.AccessToken != "" {
		if _, err := a.fetchUserInfo(tokenResp.AccessToken); err != nil {
			log.Error().Err(err).Msg("Upstream userinfo validation failed on refresh")
			writeOAuthTokenError(w, http.StatusForbidden, "access_denied", err.Error())
			return
		}
	}

	rotatedUpstream := tokenResp.RefreshToken
	if rotatedUpstream == "" {
		// IdP did not rotate; keep the existing upstream refresh.
		rotatedUpstream = upstreamRefresh
	}
	newTokenType := tokenResp.TokenType
	if newTokenType == "" {
		newTokenType = upstreamTokenType
	}
	if newTokenType == "" {
		newTokenType = "Bearer"
	}
	newScope := tokenResp.Scope
	if newScope == "" {
		newScope = scope
	}
	newRefreshJWE, err := a.mintForwardRefreshToken(secret, rotatedUpstream, newTokenType, newScope, clientID, a.oauthAuthorizationServerBaseURL(r))
	if err != nil {
		log.Error().Err(err).Msg("Failed to mint rotated forward-mode refresh token")
		writeOAuthTokenError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	// Match expires_in to the actual bearer we forward (id_token when present),
	// not tokenResp.ExpiresIn which describes the access_token's lifetime —
	// IdPs often return divergent lifetimes (e.g. Auth0: id_token exp = iat+3600,
	// access_token expires_in = 86400). See handleOAuthCallback for the same fix.
	var expiresIn int64
	if tokenResp.IDToken != "" && identityClaims != nil && identityClaims.ExpiresAt > 0 {
		expiresIn = identityClaims.ExpiresAt - time.Now().Unix()
	} else if tokenResp.ExpiresIn > 0 {
		expiresIn = tokenResp.ExpiresIn
	} else {
		expiresIn = int64(time.Hour.Seconds())
	}
	if expiresIn < 0 {
		expiresIn = 0
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"access_token":  bearerToken,
		"refresh_token": newRefreshJWE,
		"token_type":    newTokenType,
		"expires_in":    expiresIn,
		"scope":         newScope,
	})
}

func truncateForLog(value string, max int) string {
	if max <= 0 || len(value) <= max {
		return value
	}
	return value[:max]
}

func (a *application) registerOAuthHTTPRoutes(mux *http.ServeMux) {
	mux.HandleFunc(defaultProtectedResourceMetadataPath, a.handleOAuthProtectedResource)

	for _, path := range uniquePaths(
		defaultAuthorizationServerMetadataPath,
		"/.well-known/oauth-authorization-server/oauth",
		"/oauth/.well-known/oauth-authorization-server",
	) {
		mux.HandleFunc(path, a.handleOAuthAuthorizationServerMetadata)
	}

	for _, path := range uniquePaths(
		defaultOpenIDConfigurationPath,
		"/.well-known/openid-configuration/oauth",
		"/oauth/.well-known/openid-configuration",
	) {
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
