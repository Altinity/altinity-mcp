package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/altinity/altinity-mcp/pkg/config"
	"github.com/altinity/altinity-mcp/pkg/jwe_auth"
	altinitymcp "github.com/altinity/altinity-mcp/pkg/server"
	"github.com/go-jose/go-jose/v4"
	"github.com/rs/zerolog/log"
)

const (
	maxOAuthResponseBytes = 1 << 20 // 1 MB cap on upstream IdP response bodies.

	// oauthUpstreamHTTPTimeout bounds the broker's outbound HTTP calls to the
	// upstream IdP (`/token` exchange + `/userinfo` fetch). Mirrors
	// pkg/server.oauthHTTPTimeout used for JWKS / OIDC discovery — both call
	// the same set of upstream hosts and should fail-fast together. Not
	// shared as one cross-package constant to keep cmd/altinity-mcp free of
	// pkg/server import-loop risk.
	oauthUpstreamHTTPTimeout = 10 * time.Second
)

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
	defaultAuthCodeTTLSeconds    = 60
	defaultAccessTokenTTLSeconds = 60 * 60
)

// statelessRegisteredClient is the in-memory shape parseCIMDMetadata returns.
// TokenEndpointAuthMethod is "none" (claude.ai) or "private_key_jwt"
// (ChatGPT). When private_key_jwt, JWKSURI points at the client's published
// JWKS used to verify client_assertion JWTs at /oauth/token per RFC 7523.
type statelessRegisteredClient struct {
	RedirectURIs            []string `json:"redirect_uris"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	JWKSURI                 string   `json:"jwks_uri,omitempty"`
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

// oauthIssuedCode is the JWE-encoded downstream authorization code returned
// from /oauth/callback. Under the HA replay model (#115 § HA replay) the
// upstream IdP authorization code is NOT redeemed at /callback — it is
// wrapped here together with the upstream PKCE verifier and only exchanged
// upstream when the client redeems this downstream code at /oauth/token. That
// way the upstream IdP (Google / Auth0) is the sole cross-replica
// "used codes" oracle: replaying this JWE twice results in the second /token
// call seeing upstream `invalid_grant`.
type oauthIssuedCode struct {
	ClientID             string `json:"client_id"`
	RedirectURI          string `json:"redirect_uri"`
	Scope                string `json:"scope"`
	CodeChallenge        string `json:"code_challenge"`
	CodeChallengeMethod  string `json:"code_challenge_method"`
	Resource             string `json:"resource,omitempty"`
	UpstreamAuthCode     string `json:"upstream_auth_code"`
	UpstreamPKCEVerifier string `json:"upstream_pkce_verifier"`
	ExpiresAt            time.Time
}

// OAuth pending-auth and issued-code state are encoded as stateless JWE tokens
// (see encodePendingAuth / encodeAuthCode below) so any replica can decode
// state minted by any other replica. There is no in-memory store, no eviction,
// and no per-pod size cap — expiry is enforced by the `exp` claim inside each
// JWE. Single-use on auth codes is intentionally NOT enforced server-side:
// codes are bound to the client's PKCE verifier (RFC 7636) and live for at
// most defaultAuthCodeTTLSeconds, so replay within the TTL is limited to
// whoever holds the verifier — i.e. the legitimate client. Trading strict
// RFC 6749 §4.1.2 single-use for zero shared state across replicas.

// writeOAuthTokenError writes an RFC 6749 §5.2 JSON error response. When
// status is 401 it also sets a Bearer-scheme WWW-Authenticate per RFC 7235
// §3.1 (which mandates the header on 401) and RFC 6750 §3 (Bearer challenge
// shape). The header value carries the OAuth error code so a client can
// parse it from either the header or the body.
//
// Used uniformly across /oauth/{authorize,callback,token} so every broker-
// mode error response shares one shape — JSON body, optional WWW-Authenticate.
// Resource-server 401s use writeOAuthError instead because they need the
// RFC 9728 `resource_metadata=` hint.
func writeOAuthTokenError(w http.ResponseWriter, status int, code, description string) {
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer error=%q, error_description=%q`, code, description))
	}
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

// oauthBrokerMode reports whether altinity-mcp is acting as the OAuth AS to
// MCP clients (DCR + /authorize + /token + /callback). True for forward mode
// always; true for gating mode iff the operator opts in via
// oauth.broker_upstream. When true, /oauth/* routes are registered and the
// broker-flow handlers fire. The /mcp request path still differs per mode —
// forward forwards the upstream bearer to CH; gating impersonates via
// cluster_secret + Auth.Username.
func (a *application) oauthBrokerMode() bool {
	cfg := a.GetCurrentConfig().Server.OAuth
	if cfg.IsForwardMode() {
		return true
	}
	return cfg.IsGatingMode() && cfg.BrokerUpstream
}

func (a *application) oauthJWESecret() []byte {
	secret := strings.TrimSpace(a.GetCurrentConfig().Server.OAuth.SigningSecret)
	return []byte(secret)
}

func (a *application) mustJWESecret() ([]byte, error) {
	secret := a.oauthJWESecret()
	if len(secret) == 0 {
		return nil, fmt.Errorf("oauth signing_secret is required for JWE-wrapped pending-auth state and downstream auth-code minting")
	}
	return secret, nil
}

// oauthKidV1 is the kid header set on cmd-minted OAuth JWE artifacts
// (pending-auth and auth-code). Its presence selects the HKDF-derived key
// on decryption; absence (kid="") selects the legacy SHA256(secret) key
// for backwards compat with artifacts minted before the HKDF rotation.
// Post-#115 the longest legacy artifact in flight is the 10-minute
// pending-auth JWE — the legacy fallback can be deleted in a follow-up
// after a >10-minute rolling restart window has passed.
const oauthKidV1 = "v1"

// HKDF info labels for cmd-internal OAuth key derivation. Each label produces
// an independent 32-byte key from the shared signing_secret (RFC 5869 §3.2).
// Bumping the /vN suffix in any single label rotates that one key without
// disturbing the others.
const (
	hkdfInfoOAuthPendingAuth = "altinity-mcp/oauth/pending-auth/v1"
	// v2 bumps the auth-code derivation: under #115 the JWE now wraps the
	// upstream auth code + PKCE verifier (not a bearer), so its semantics
	// changed. Any v1 codes minted before the cutover decrypt as garbage
	// here; that's intended, the auth-code TTL is 60s.
	hkdfInfoOAuthAuthCode = "altinity-mcp/oauth/auth-code/v2"
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

// encodePendingAuth wraps an oauthPendingAuth into a stateless JWE used as the
// `state` parameter sent to the upstream IdP at /authorize. Any replica with
// the shared signing_secret can decode it at /callback.
func (a *application) encodePendingAuth(p oauthPendingAuth) (string, error) {
	secret, err := a.mustJWESecret()
	if err != nil {
		return "", err
	}
	claims := map[string]interface{}{
		"client_id":              p.ClientID,
		"redirect_uri":           p.RedirectURI,
		"scope":                  p.Scope,
		"client_state":           p.ClientState,
		"code_challenge":         p.CodeChallenge,
		"code_challenge_method":  p.CodeChallengeMethod,
		"resource":               p.Resource,
		"upstream_pkce_verifier": p.UpstreamPKCEVerifier,
		"exp":                    p.ExpiresAt.Unix(),
	}
	return encodeOAuthJWE(secret, hkdfInfoOAuthPendingAuth, claims)
}

// decodePendingAuth is the inverse of encodePendingAuth. Returns (pending,
// false) when the token is unparseable, tampered, expired, or carries claims
// outside the JWE whitelist.
func (a *application) decodePendingAuth(token string) (oauthPendingAuth, bool) {
	secret := a.oauthJWESecret()
	if len(secret) == 0 {
		return oauthPendingAuth{}, false
	}
	claims, err := decodeOAuthJWE(secret, hkdfInfoOAuthPendingAuth, token)
	if err != nil {
		return oauthPendingAuth{}, false
	}
	p := oauthPendingAuth{
		ClientID:             stringFromClaims(claims, "client_id"),
		RedirectURI:          stringFromClaims(claims, "redirect_uri"),
		Scope:                stringFromClaims(claims, "scope"),
		ClientState:          stringFromClaims(claims, "client_state"),
		CodeChallenge:        stringFromClaims(claims, "code_challenge"),
		CodeChallengeMethod:  stringFromClaims(claims, "code_challenge_method"),
		Resource:             stringFromClaims(claims, "resource"),
		UpstreamPKCEVerifier: stringFromClaims(claims, "upstream_pkce_verifier"),
		ExpiresAt:            unixFromClaims(claims, "exp"),
	}
	return p, true
}

// encodeAuthCode wraps an oauthIssuedCode into a stateless JWE used as the
// `code` parameter returned to the MCP client at /callback. Redeemed at
// /token by decodeAuthCode on any replica.
func (a *application) encodeAuthCode(c oauthIssuedCode) (string, error) {
	secret, err := a.mustJWESecret()
	if err != nil {
		return "", err
	}
	claims := map[string]interface{}{
		"client_id":              c.ClientID,
		"redirect_uri":           c.RedirectURI,
		"scope":                  c.Scope,
		"code_challenge":         c.CodeChallenge,
		"code_challenge_method":  c.CodeChallengeMethod,
		"resource":               c.Resource,
		"upstream_auth_code":     c.UpstreamAuthCode,
		"upstream_pkce_verifier": c.UpstreamPKCEVerifier,
		"exp":                    c.ExpiresAt.Unix(),
	}
	return encodeOAuthJWE(secret, hkdfInfoOAuthAuthCode, claims)
}

// decodeAuthCode is the inverse of encodeAuthCode.
func (a *application) decodeAuthCode(token string) (oauthIssuedCode, bool) {
	secret := a.oauthJWESecret()
	if len(secret) == 0 {
		return oauthIssuedCode{}, false
	}
	claims, err := decodeOAuthJWE(secret, hkdfInfoOAuthAuthCode, token)
	if err != nil {
		return oauthIssuedCode{}, false
	}
	c := oauthIssuedCode{
		ClientID:             stringFromClaims(claims, "client_id"),
		RedirectURI:          stringFromClaims(claims, "redirect_uri"),
		Scope:                stringFromClaims(claims, "scope"),
		CodeChallenge:        stringFromClaims(claims, "code_challenge"),
		CodeChallengeMethod:  stringFromClaims(claims, "code_challenge_method"),
		Resource:             stringFromClaims(claims, "resource"),
		UpstreamAuthCode:     stringFromClaims(claims, "upstream_auth_code"),
		UpstreamPKCEVerifier: stringFromClaims(claims, "upstream_pkce_verifier"),
		ExpiresAt:            unixFromClaims(claims, "exp"),
	}
	return c, true
}

func stringFromClaims(claims map[string]interface{}, key string) string {
	if v, ok := claims[key].(string); ok {
		return v
	}
	return ""
}

func unixFromClaims(claims map[string]interface{}, key string) time.Time {
	v, ok := claims[key]
	if !ok {
		return time.Time{}
	}
	switch t := v.(type) {
	case float64:
		return time.Unix(int64(t), 0)
	case int64:
		return time.Unix(t, 0)
	case int:
		return time.Unix(int64(t), 0)
	}
	return time.Time{}
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
// Scopes catalog so the client at least has something to request from. Both
// candidate lists are passed through oidcScopesForAdvertisement to strip
// upstream URI-form scopes and any non-allowlisted values that would otherwise
// confuse MCP clients (ChatGPT renders a "permissions not granted" warning
// when it compares the scope hint here against what the upstream IdP grants).
// Empty string when no allowed scopes remain — caller then omits the attribute.
func (a *application) challengeScope() string {
	cfg := a.GetCurrentConfig().Server.OAuth
	switch {
	case len(cfg.RequiredScopes) > 0:
		filtered := oidcScopesForAdvertisement(config.OAuthConfig{Scopes: cfg.RequiredScopes})
		if len(filtered) > 0 {
			return strings.Join(filtered, " ")
		}
		fallthrough
	case len(cfg.Scopes) > 0:
		filtered := oidcScopesForAdvertisement(cfg)
		if len(filtered) > 0 {
			return strings.Join(filtered, " ")
		}
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

func sanitizeScope(scope string) string {
	return strings.Join(strings.Fields(scope), " ")
}

// normalizeUpstreamScopeForClient maps upstream-IdP-specific scope URIs back to
// the OIDC standard names the MCP client originally requested. Google's
// /oauth/token response emits id-token-equivalent scopes in URI form (e.g.
// "https://www.googleapis.com/auth/userinfo.email" instead of "email"); when
// altinity-mcp echoes that string verbatim, ChatGPT compares its requested
// scope ("email") against the response ("…/userinfo.email") and surfaces a
// "permissions not granted" warning even though the identity claims are
// present. Mapping the three OIDC-equivalent Google aliases back to standard
// names makes request and response shapes agree.
//
// Unknown values pass through unchanged. Standard names (openid/email/profile/
// offline_access) pass through unchanged. The helper is used only for the
// client-facing `scope` field in /oauth/token responses; upstream-stored scope
// (oauthIssuedCode.Scope, refresh-JWE claims) keeps Google's original form so
// subsequent upstream refresh calls hit Google with the same scope value Google
// itself returned.
func normalizeUpstreamScopeForClient(scope string) string {
	if scope == "" {
		return ""
	}
	parts := strings.Fields(scope)
	out := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, p := range parts {
		var mapped string
		switch p {
		case "https://www.googleapis.com/auth/userinfo.email":
			mapped = "email"
		case "https://www.googleapis.com/auth/userinfo.profile":
			mapped = "profile"
		case "https://www.googleapis.com/auth/openid":
			mapped = "openid"
		default:
			mapped = p
		}
		if _, dup := seen[mapped]; dup {
			continue
		}
		seen[mapped] = struct{}{}
		out = append(out, mapped)
	}
	return strings.Join(out, " ")
}

// oidcScopesForAdvertisement returns the subset of cfg.Scopes that altinity-mcp
// will surface to MCP clients via discovery metadata (protected-resource doc,
// authorization-server metadata, openid-configuration) and the
// WWW-Authenticate challenge. Only an explicit OIDC-identity allowlist plus
// Auth0's offline_access refresh-token gate is passed through; anything else
// (URI-form upstream scopes like Google's https://www.googleapis.com/auth/…,
// resource-server scopes like mcp:read, custom API scopes like calendar) is
// filtered out.
//
// Why explicit allowlist instead of "filter URI / filter offline_access":
// scope-based tool authorization is not exercised anywhere in altinity-mcp
// today (RequiredScopes is empty in every helm values file). Anything beyond
// identity-shaped names is junk from the MCP-client's perspective and tends
// to provoke "permissions not granted" warnings from ChatGPT. When scope-based
// authorization is added in the future, extend this allowlist explicitly.
//
// Why offline_access is on the list (Auth0 vs Google): Auth0 uses the
// offline_access scope as the gate for issuing refresh tokens (RFC 6749 §6 +
// Auth0 docs); production antalya-mcp depends on advertising it. Google does
// NOT use this scope — it uses access_type=offline as a separate auth param —
// so for Google deployments cfg.Scopes simply omits offline_access and the
// helper naturally doesn't advertise it. Behaviour is therefore config-driven
// per deployment without per-mode branching here.
func oidcScopesForAdvertisement(cfg config.OAuthConfig) []string {
	allowed := map[string]struct{}{
		"openid":         {},
		"email":          {},
		"profile":        {},
		"offline_access": {},
	}
	out := make([]string, 0, len(cfg.Scopes))
	seen := make(map[string]struct{})
	for _, s := range cfg.Scopes {
		if _, ok := allowed[s]; !ok {
			continue
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
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

	resp, err := (&http.Client{Timeout: oauthUpstreamHTTPTimeout}).Do(req)
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
	cfg := a.GetCurrentConfig().Server.OAuth
	baseURL := a.resourceBaseURL(r)
	// authorization_servers advertises where the MCP client should go to get
	// a token. Three shapes:
	//   - Pure gating (#109, no broker): MCP is a pure resource server and
	//     the external AS (configured via `oauth.issuer`) is responsible for
	//     DCR / authorize / token. Advertise the upstream issuer byte-equal
	//     to what tokens carry in their `iss` claim.
	//   - Forward mode: MCP fronts the upstream IdP and is itself the AS to
	//     MCP clients. Advertise our own auth-server base URL.
	//   - Gating + broker_upstream: same as forward mode from the
	//     MCP-client's perspective — MCP exposes /oauth/{register,authorize,
	//     callback,token} and brokers the upstream IdP behind the scenes.
	//     Advertise our own auth-server base URL, NOT the upstream issuer.
	//     If we advertised the upstream issuer here, claude.ai/ChatGPT would
	//     try to DCR against it directly (which most upstreams reject) and
	//     never discover our broker endpoints.
	var authorizationServers []string
	if a.oauthBrokerMode() {
		authorizationServers = []string{strings.TrimRight(a.oauthAuthorizationServerBaseURL(r), "/")}
	} else {
		authorizationServers = []string{strings.TrimSpace(cfg.Issuer)}
	}
	resp := map[string]interface{}{
		// `resource` is the canonical RFC 9728 protected-resource identifier
		// (with trailing slash, per canonicalResourceURL); claude.ai's artifact
		// proxy compares the metadata field literally and round-trips it to the
		// `aud` claim. Inbound `aud` validation tolerates either form via
		// audienceMatchesResource.
		"resource":                 canonicalResourceURL(baseURL),
		"authorization_servers":    authorizationServers,
		"scopes_supported":         oidcScopesForAdvertisement(cfg),
		"bearer_methods_supported": []string{"header"},
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// handleOAuthRegisterRemoved is the tombstone handler at /oauth/register.
// DCR was removed under #115 in favour of CIMD; this responds with an
// RFC 7591 §3.2.2-shaped JSON error so DCR clients in the wild see a
// diagnosable response rather than the bare mux 404. Always 410 Gone —
// the route is permanently retired, not "endpoint unavailable".
func handleOAuthRegisterRemoved(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusGone)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             "registration_not_supported",
		"error_description": "Dynamic Client Registration is no longer supported; clients must use OAuth Client ID Metadata Documents (CIMD). See client_id_metadata_document_supported on /.well-known/oauth-authorization-server.",
	})
}

// oauthASMetadata returns the field set shared by RFC 8414 (oauth-authorization-server)
// and OIDC Discovery (openid-configuration). Both endpoints serve the same
// AS-side advertisement; OIDC adds two extra fields under gating mode (see
// handleOAuthOpenIDConfiguration).
//
// `issuer` is published without a trailing slash to match RFC 8414 §2
// (issuer == authorization_servers[i] in the resource document). The /token
// response mints `iss` in the same form and validateOAuthClaims normalises
// slashes defensively.
func (a *application) oauthASMetadata(r *http.Request) map[string]interface{} {
	baseURL := a.oauthAuthorizationServerBaseURL(r)
	return map[string]interface{}{
		"issuer":                                strings.TrimRight(baseURL, "/"),
		"authorization_endpoint":                joinURLPath(baseURL, a.oauthAuthorizationPath()),
		"token_endpoint":                        joinURLPath(baseURL, a.oauthTokenPath()),
		"scopes_supported":                      oidcScopesForAdvertisement(a.GetCurrentConfig().Server.OAuth),
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code"},
		"token_endpoint_auth_methods_supported":          []string{"none", "private_key_jwt"},
		"token_endpoint_auth_signing_alg_values_supported": []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"},
		"code_challenge_methods_supported":      []string{"S256"},
		"client_id_metadata_document_supported": true,
	}
}

func (a *application) handleOAuthAuthorizationServerMetadata(w http.ResponseWriter, r *http.Request) {
	if !a.oauthEnabled() {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(a.oauthASMetadata(r))
}

func (a *application) handleOAuthOpenIDConfiguration(w http.ResponseWriter, r *http.Request) {
	if !a.oauthEnabled() {
		http.NotFound(w, r)
		return
	}
	resp := a.oauthASMetadata(r)
	if !a.oauthForwardMode() {
		resp["subject_types_supported"] = []string{"public"}
		resp["id_token_signing_alg_values_supported"] = []string{"HS256"}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (a *application) handleOAuthAuthorize(w http.ResponseWriter, r *http.Request) {
	if !a.oauthEnabled() {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		writeOAuthTokenError(w, http.StatusMethodNotAllowed, "invalid_request", "method not allowed")
		return
	}
	q := r.URL.Query()
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	if clientID == "" || redirectURI == "" || q.Get("response_type") != "code" {
		writeOAuthTokenError(w, http.StatusBadRequest, "invalid_request", "missing client_id, redirect_uri, or response_type=code")
		return
	}
	// CIMD inbound (#115): client_id is the HTTPS URL of the MCP client's
	// metadata document. The resolver validates the URL, fetches the document
	// under SSRF-safe constraints, and synthesises the registered client. DCR
	// was removed in the same change; non-https client_ids are rejected as
	// invalid URLs by validateCIMDClientIDURL inside the resolver.
	client, err := a.resolveCIMDClient(r.Context(), clientID)
	if err != nil {
		log.Debug().Err(err).Str("client_id", truncateForLog(clientID, 80)).Msg("OAuth /authorize rejected: CIMD resolution failed")
		writeOAuthTokenError(w, http.StatusBadRequest, "invalid_client", "unknown OAuth client")
		return
	}
	if !slices.Contains(client.RedirectURIs, redirectURI) {
		writeOAuthTokenError(w, http.StatusBadRequest, "invalid_request", "redirect_uri not registered for this client")
		return
	}
	if q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256" {
		writeOAuthTokenError(w, http.StatusBadRequest, "invalid_request", "PKCE S256 is required")
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
			writeOAuthTokenError(w, http.StatusBadRequest, "invalid_target", "resource indicator does not identify this MCP server")
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
		writeOAuthTokenError(w, http.StatusInternalServerError, "server_error", "failed to generate PKCE verifier")
		return
	}

	callbackState, err := a.encodePendingAuth(oauthPendingAuth{
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
	if err != nil {
		log.Error().Err(err).Msg("Failed to encode pending-auth JWE")
		writeOAuthTokenError(w, http.StatusInternalServerError, "server_error", "failed to initialize OAuth state")
		return
	}

	cfg := a.GetCurrentConfig()
	authURL, err := a.resolveUpstreamAuthURL()
	if err != nil {
		writeOAuthTokenError(w, http.StatusBadGateway, "server_error", "failed to resolve upstream authorization endpoint")
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
	if a.oauthBrokerMode() && cfg.Server.OAuth.UpstreamOfflineAccess && !slices.Contains(strings.Fields(scope), "offline_access") {
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
		writeOAuthTokenError(w, http.StatusBadRequest, "invalid_request", "missing state or code on callback")
		return
	}

	pending, ok := a.decodePendingAuth(requestID)
	if !ok {
		writeOAuthTokenError(w, http.StatusBadRequest, "invalid_request", "unknown or expired authorization request")
		return
	}

	// HA replay model (#115): the upstream auth code is NOT redeemed here.
	// We wrap it (plus the upstream PKCE verifier captured at /authorize and
	// the pending-auth fields) into a 60s downstream JWE and let /oauth/token
	// perform the upstream exchange. That way the upstream IdP — Google or
	// Auth0 — is the sole cross-replica "used codes" oracle: a replayed
	// downstream code hits upstream `invalid_grant` and fails.
	issuedCode := oauthIssuedCode{
		ClientID:             pending.ClientID,
		RedirectURI:          pending.RedirectURI,
		Scope:                pending.Scope,
		CodeChallenge:        pending.CodeChallenge,
		CodeChallengeMethod:  pending.CodeChallengeMethod,
		Resource:             pending.Resource,
		UpstreamAuthCode:     code,
		UpstreamPKCEVerifier: pending.UpstreamPKCEVerifier,
		ExpiresAt:            time.Now().Add(time.Duration(defaultAuthCodeTTLSeconds) * time.Second),
	}
	authCode, err := a.encodeAuthCode(issuedCode)
	if err != nil {
		log.Error().Err(err).Msg("Failed to encode auth-code JWE")
		writeOAuthTokenError(w, http.StatusInternalServerError, "server_error", "failed to issue authorization code")
		return
	}

	log.Info().
		Str("client_id", truncateForLog(pending.ClientID, 80)).
		Bool("forward_mode", a.oauthForwardMode()).
		Msg("OAuth /callback wrapped upstream auth code in downstream JWE; awaiting /token redemption")

	redirect, err := url.Parse(pending.RedirectURI)
	if err != nil {
		writeOAuthTokenError(w, http.StatusBadGateway, "server_error", "pending-auth carried an unparseable redirect_uri")
		return
	}
	params := redirect.Query()
	params.Set("code", authCode)
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

	grantType := r.Form.Get("grant_type")
	log.Info().
		Str("grant_type", grantType).
		Bool("forward_mode", a.oauthForwardMode()).
		Msg("OAuth /oauth/token request received")
	switch grantType {
	case "authorization_code":
		a.handleOAuthTokenAuthCode(w, r)
	default:
		// refresh_token grant is intentionally not supported in v1 (#115):
		// CIMD clients re-authorize instead of refreshing. This keeps the
		// downstream JWE footprint small and avoids issuing long-lived
		// credentials to public clients without rotation/reuse detection.
		writeOAuthTokenError(w, http.StatusBadRequest, "unsupported_grant_type", "unsupported grant type")
	}
}

func (a *application) handleOAuthTokenAuthCode(w http.ResponseWriter, r *http.Request) {
	clientID := r.Form.Get("client_id")
	// client_secret is never accepted: CIMD public clients have no shared
	// secret. We never publish client_secret_basic / _post / _jwt as
	// supported auth methods.
	if r.Form.Get("client_secret") != "" {
		writeOAuthTokenError(w, http.StatusUnauthorized, "invalid_client", "client_secret authentication not supported")
		return
	}
	client, err := a.resolveCIMDClient(r.Context(), clientID)
	if err != nil {
		log.Debug().Err(err).Str("client_id", truncateForLog(clientID, 80)).Msg("OAuth /token rejected: CIMD resolution failed")
		writeOAuthTokenError(w, http.StatusUnauthorized, "invalid_client", "unknown OAuth client")
		return
	}
	// RFC 7521 §4.2 / RFC 7523 §2.2: dispatch on the auth method the client
	// declared in its CIMD metadata. "none" requires PKCE only; "private_key_jwt"
	// requires a signed JWT assertion verified against the client's JWKS.
	assertion := r.Form.Get("client_assertion")
	assertionType := r.Form.Get("client_assertion_type")
	switch client.TokenEndpointAuthMethod {
	case "none":
		if assertion != "" || assertionType != "" {
			writeOAuthTokenError(w, http.StatusUnauthorized, "invalid_client", "client_assertion not accepted for public clients")
			return
		}
	case "private_key_jwt":
		if assertionType != clientAssertionType {
			writeOAuthTokenError(w, http.StatusUnauthorized, "invalid_client", "client_assertion_type must be jwt-bearer")
			return
		}
		tokenEndpointURL := joinURLPath(a.oauthAuthorizationServerBaseURL(r), a.oauthTokenPath())
		if err := a.verifyClientAssertion(r.Context(), client, clientID, assertion, tokenEndpointURL); err != nil {
			log.Debug().Err(err).Str("client_id", truncateForLog(clientID, 80)).Msg("OAuth /token rejected: client_assertion invalid")
			writeOAuthTokenError(w, http.StatusUnauthorized, "invalid_client", "client_assertion invalid")
			return
		}
	default:
		// Defence-in-depth: parseCIMDMetadata already rejects anything other
		// than none / private_key_jwt; this branch only fires on stale cache
		// entries from a prior buggy build.
		writeOAuthTokenError(w, http.StatusUnauthorized, "invalid_client", "unsupported client auth method")
		return
	}
	requestRedirect := r.Form.Get("redirect_uri")
	if !slices.Contains(client.RedirectURIs, requestRedirect) {
		writeOAuthTokenError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri not registered for this client")
		return
	}
	issued, ok := a.decodeAuthCode(r.Form.Get("code"))
	if !ok {
		log.Debug().Msg("OAuth /token rejected: unknown or expired authorization code")
		writeOAuthTokenError(w, http.StatusBadRequest, "invalid_grant", "invalid authorization code")
		return
	}
	if issued.ClientID != clientID || issued.RedirectURI != requestRedirect {
		log.Debug().
			Time("code_expires_at", issued.ExpiresAt).
			Str("issued_client_id", issued.ClientID).
			Str("request_client_id", clientID).
			Str("issued_redirect_uri", issued.RedirectURI).
			Str("request_redirect_uri", requestRedirect).
			Msg("OAuth /token rejected: authorization code mismatch")
		writeOAuthTokenError(w, http.StatusBadRequest, "invalid_grant", "invalid authorization code")
		return
	}
	if issued.CodeChallenge == "" || pkceChallenge(r.Form.Get("code_verifier")) != issued.CodeChallenge {
		log.Debug().Msg("OAuth /token rejected: invalid PKCE verifier")
		writeOAuthTokenError(w, http.StatusBadRequest, "invalid_grant", "invalid PKCE verifier")
		return
	}

	// RFC 8707 §2.2: when `resource` was pinned at /authorize, /token must
	// match. When /authorize omitted it but /token includes one, accept and
	// use the latter for downstream advisory only.
	// RFC 8707 §2.2 cross-check between the resource pinned at /authorize and
	// the one (optionally) re-sent at /token. Mismatch → invalid_target. v1
	// doesn't otherwise act on the resource value (audience binding is a
	// separate issue).
	if formResource := r.Form.Get("resource"); formResource != "" && issued.Resource != "" {
		if strings.TrimRight(formResource, "/") != strings.TrimRight(issued.Resource, "/") {
			writeOAuthTokenError(w, http.StatusBadRequest, "invalid_target", "resource indicator does not match the one used at /authorize")
			return
		}
	}

	// HA replay model: redeem the upstream auth code with the upstream IdP
	// *now*, not at /callback. The upstream IdP's `invalid_grant` on a second
	// redemption is our cross-replica replay verdict — see #115 § HA replay.
	if issued.UpstreamAuthCode == "" || issued.UpstreamPKCEVerifier == "" {
		writeOAuthTokenError(w, http.StatusBadRequest, "invalid_grant", "invalid authorization code")
		return
	}
	cfg := a.GetCurrentConfig()
	callbackURL := joinURLPath(a.oauthAuthorizationServerBaseURL(r), a.oauthCallbackPath())
	tokenURL, err := a.resolveUpstreamTokenURL()
	if err != nil {
		log.Error().Err(err).Msg("OAuth /token: failed to resolve upstream token endpoint")
		writeOAuthTokenError(w, http.StatusBadGateway, "server_error", "failed to resolve upstream token endpoint")
		return
	}
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", issued.UpstreamAuthCode)
	form.Set("client_id", cfg.Server.OAuth.ClientID)
	if cfg.Server.OAuth.ClientSecret != "" {
		form.Set("client_secret", cfg.Server.OAuth.ClientSecret)
	}
	form.Set("redirect_uri", callbackURL)
	form.Set("code_verifier", issued.UpstreamPKCEVerifier)

	upstreamResp, err := (&http.Client{Timeout: oauthUpstreamHTTPTimeout}).PostForm(tokenURL, form)
	if err != nil {
		log.Error().Err(err).Str("token_url", tokenURL).Msg("OAuth /token: upstream code exchange transport error")
		writeOAuthTokenError(w, http.StatusBadGateway, "server_error", "upstream code exchange failed")
		return
	}
	defer func() {
		if closeErr := upstreamResp.Body.Close(); closeErr != nil {
			log.Error().Err(closeErr).Msgf("can't close %s response body", tokenURL)
		}
	}()
	body, err := io.ReadAll(io.LimitReader(upstreamResp.Body, maxOAuthResponseBytes))
	if err != nil {
		writeOAuthTokenError(w, http.StatusBadGateway, "server_error", "failed to read upstream token response")
		return
	}
	if upstreamResp.StatusCode >= 300 {
		errCode, bodyLen := safeUpstreamErrorFields(body)
		log.Warn().
			Int("status", upstreamResp.StatusCode).
			Str("upstream_error", errCode).
			Int("body_len", bodyLen).
			Str("client_id", truncateForLog(clientID, 80)).
			Msg("OAuth /token: upstream code exchange rejected — likely replay")
		// Map upstream invalid_grant (replay-detected, expired, already used)
		// to a downstream invalid_grant per RFC 6749 §5.2.
		writeOAuthTokenError(w, http.StatusBadRequest, "invalid_grant", "upstream rejected the authorization code")
		return
	}
	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		IDToken      string `json:"id_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int64  `json:"expires_in"`
		Scope        string `json:"scope"`
		// Error is present on non-RFC-compliant IdPs that signal failure
		// via 200 OK + RFC 6749 §5.2 error JSON. Status-only checks miss
		// this; treating a non-empty Error as upstream rejection keeps the
		// HA replay contract intact (downstream sees invalid_grant).
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		log.Error().Err(err).Msg("OAuth /token: upstream response not JSON")
		writeOAuthTokenError(w, http.StatusBadGateway, "server_error", "upstream returned non-JSON response")
		return
	}
	if tokenResp.Error != "" {
		log.Warn().
			Int("status", upstreamResp.StatusCode).
			Str("upstream_error", tokenResp.Error).
			Str("client_id", truncateForLog(clientID, 80)).
			Msg("OAuth /token: upstream 2xx with RFC 6749 error body — treat as invalid_grant")
		writeOAuthTokenError(w, http.StatusBadRequest, "invalid_grant", "upstream rejected the authorization code")
		return
	}
	if tokenResp.AccessToken == "" && tokenResp.IDToken == "" {
		log.Error().
			Bool("has_access_token", tokenResp.AccessToken != "").
			Bool("has_id_token", tokenResp.IDToken != "").
			Msg("OAuth /token: upstream response missing usable token")
		writeOAuthTokenError(w, http.StatusBadGateway, "server_error", "upstream returned no usable token")
		return
	}
	log.Info().
		Bool("has_access_token", tokenResp.AccessToken != "").
		Bool("has_id_token", tokenResp.IDToken != "").
		Bool("forward_mode", a.oauthForwardMode()).
		Str("scope", tokenResp.Scope).
		Int64("expires_in", tokenResp.ExpiresIn).
		Str("client_id", truncateForLog(clientID, 80)).
		Msg("OAuth /token: upstream code exchange succeeded")

	// Validate the upstream identity before handing the bearer to the MCP
	// client. Claims are NOT bound into the downstream token (audience
	// binding deferred per #115 § Non-goals); the validation has three
	// jobs: fail-fast on a malformed upstream response with a proper 502,
	// confirm the upstream id_token signature/audience for forward mode,
	// and surface the id_token `exp` so we report an accurate `expires_in`
	// to the MCP client below (used at the "expiresIn = identityClaims..."
	// line further down).
	var identityClaims *altinitymcp.OAuthClaims
	if tokenResp.IDToken != "" {
		identityClaims, err = a.mcpServer.ValidateUpstreamIdentityToken(tokenResp.IDToken, cfg.Server.OAuth.ClientID)
		if err != nil {
			log.Error().Err(err).Msg("OAuth /token: upstream identity token validation failed")
			writeOAuthTokenError(w, http.StatusBadGateway, "server_error", "failed to validate upstream identity token")
			return
		}
	} else if tokenResp.AccessToken != "" {
		identityClaims, err = a.fetchUserInfo(tokenResp.AccessToken)
		if err != nil {
			log.Error().Err(err).Msg("OAuth /token: upstream userinfo validation failed")
			writeOAuthTokenError(w, http.StatusBadGateway, "server_error", "failed to validate upstream identity")
			return
		}
	}
	if tokenResp.Scope == "" {
		tokenResp.Scope = issued.Scope
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
	var expiresIn int64
	if tokenResp.IDToken != "" && identityClaims != nil && identityClaims.ExpiresAt > 0 {
		expiresIn = identityClaims.ExpiresAt - time.Now().Unix()
	} else if tokenResp.ExpiresIn > 0 {
		expiresIn = tokenResp.ExpiresIn
	} else {
		expiresIn = int64(defaultAccessTokenTTLSeconds)
	}
	if expiresIn < 0 {
		expiresIn = 0
	}
	response := map[string]interface{}{
		"access_token": bearerToken,
		"token_type":   tokenType,
		"expires_in":   expiresIn,
	}
	if s := normalizeUpstreamScopeForClient(tokenResp.Scope); s != "" {
		response["scope"] = s
	}
	// v1 deliberately drops refresh_token from the response. CIMD clients
	// re-authorize. See #115 § Refresh-token policy.
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

func truncateForLog(value string, max int) string {
	if max <= 0 || len(value) <= max {
		return value
	}
	return value[:max]
}

func (a *application) registerOAuthHTTPRoutes(mux *http.ServeMux) {
	// RFC 9728 protected-resource metadata is the only OAuth endpoint MCP
	// itself owns under pure gating mode (#109): MCP is a pure resource
	// server and points clients at the upstream IdP for everything else.
	// Under forward mode — and under gating mode with `broker_upstream=true`
	// — MCP also fronts the upstream IdP as a proxying AS, so
	// /oauth/register, /authorize, /callback, /token, and the AS-discovery
	// metadata endpoints stay registered on that path. The decision is
	// centralised in oauthBrokerMode().
	mux.HandleFunc(defaultProtectedResourceMetadataPath, a.handleOAuthProtectedResource)

	if !a.oauthBrokerMode() {
		return
	}

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

	// DCR was removed in favour of CIMD per #115. Mount /oauth/register
	// with a stub that returns HTTP 410 Gone + an RFC 7591 §3.2.2-shaped
	// JSON error so an in-the-wild DCR client sees a diagnosable response
	// rather than the bare mux 404.
	mux.HandleFunc(defaultRegistrationPath, handleOAuthRegisterRemoved)

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
