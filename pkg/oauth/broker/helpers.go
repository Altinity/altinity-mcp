// Package broker holds altinity-mcp's OAuth broker-mode helpers — pure
// functions and stateless types lifted out of cmd/altinity-mcp/oauth_server.go
// during the pkg/oauth/ extraction. Route handlers and methods coupled to the
// `application` lifecycle remain in cmd/altinity-mcp until the next refactor
// completes the broker move; see docs/oauth_next_refactor.md.
package broker

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/altinity/altinity-mcp/pkg/jwe_auth"
	"github.com/altinity/altinity-mcp/pkg/oauth"
	"github.com/go-jose/go-jose/v4"
)

// MaxOAuthResponseBytes caps every upstream-IdP HTTP response body the broker
// reads (token, userinfo, JWKS).
const MaxOAuthResponseBytes = 1 << 20 // 1 MB

// UpstreamHTTPTimeout bounds outbound HTTP calls to upstream IdPs.
const UpstreamHTTPTimeout = 10 * time.Second

// Well-known endpoint paths. Exported because main wires routes by name.
const (
	DefaultProtectedResourceMetadataPath   = "/.well-known/oauth-protected-resource"
	DefaultAuthorizationServerMetadataPath = "/.well-known/oauth-authorization-server"
	DefaultOpenIDConfigurationPath         = "/.well-known/openid-configuration"
	DefaultRegistrationPath                = "/oauth/register"
	DefaultAuthorizationPath               = "/oauth/authorize"
	DefaultCallbackPath                    = "/oauth/callback"
	DefaultTokenPath                       = "/oauth/token"
)

// Default TTLs for OAuth artifacts. See cmd/altinity-mcp/oauth_server.go
// comments for the RFC §s these derive from.
const (
	DefaultPendingAuthTTLSeconds = 10 * 60
	DefaultAuthCodeTTLSeconds    = 60
	DefaultAccessTokenTTLSeconds = 60 * 60
	// BrokerModeIDTokenRefreshThresholdSeconds: refresh the upstream id_token
	// at /oauth/token when its remaining life is below this threshold.
	BrokerModeIDTokenRefreshThresholdSeconds = 55 * 60
)

// OAuthKidV1 is the kid header on cmd-minted OAuth JWE artifacts. Selects the
// HKDF-derived key on decryption; absence (kid="") falls back to the legacy
// SHA256(secret) derivation for backwards compat.
const OAuthKidV1 = "v1"

// HKDF info labels for cmd-internal OAuth key derivation.
const (
	HKDFInfoOAuthPendingAuth = "altinity-mcp/oauth/pending-auth/v1"
	// v2 reflects the #115 semantics change (auth-code wraps upstream code +
	// PKCE verifier, not a bearer).
	HKDFInfoOAuthAuthCode = "altinity-mcp/oauth/auth-code/v2"
)

// StatelessRegisteredClient is the in-memory shape parsed from a CIMD
// metadata document.
type StatelessRegisteredClient struct {
	RedirectURIs            []string `json:"redirect_uris"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	JWKSURI                 string   `json:"jwks_uri,omitempty"`
}

// OAuthPendingAuth captures the state of an in-flight /authorize → /callback
// dance — stateless, encoded as a JWE for cross-replica decode.
type OAuthPendingAuth struct {
	ClientID             string `json:"client_id"`
	RedirectURI          string `json:"redirect_uri"`
	Scope                string `json:"scope"`
	ClientState          string `json:"client_state"`
	CodeChallenge        string `json:"code_challenge"`
	CodeChallengeMethod  string `json:"code_challenge_method"`
	Resource             string `json:"resource,omitempty"`
	UpstreamPKCEVerifier string `json:"upstream_pkce_verifier,omitempty"`
	ExpiresAt            time.Time
}

// OAuthIssuedCode is the JWE-encoded downstream authorization code returned
// from /oauth/callback. Wraps the upstream auth code + PKCE verifier per the
// #115 HA replay model (upstream IdP is the cross-replica replay oracle).
type OAuthIssuedCode struct {
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

// EncodeOAuthJWE emits a JWE-wrapped JSON document of `claims`, encrypted
// with a key HKDF-derived from `secret` and the per-context `info` label.
// kid="v1" is set in the protected header so decoders pick the same key.
func EncodeOAuthJWE(secret []byte, info string, claims map[string]interface{}) (string, error) {
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
			WithHeader(jose.HeaderKey("kid"), OAuthKidV1),
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

// DecodeOAuthJWE decrypts a JWE produced by EncodeOAuthJWE OR by the legacy
// jwe_auth.GenerateJWEToken path. kid selects the derivation:
//
//   - kid == OAuthKidV1 → key = HKDF(secret, info)
//   - kid == ""         → key = SHA256(secret) (legacy)
func DecodeOAuthJWE(secret []byte, info string, token string) (map[string]interface{}, error) {
	jweObj, err := jose.ParseEncrypted(token,
		[]jose.KeyAlgorithm{jose.A256KW},
		[]jose.ContentEncryption{jose.A256GCM})
	if err != nil {
		return nil, jwe_auth.ErrInvalidToken
	}
	if jweObj.Header.KeyID == OAuthKidV1 {
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
	return jwe_auth.ParseAndDecryptJWE(token, secret, secret)
}

// StringFromClaims returns claims[key] as a string, or "".
func StringFromClaims(claims map[string]interface{}, key string) string {
	if v, ok := claims[key].(string); ok {
		return v
	}
	return ""
}

// UnixFromClaims returns claims[key] as a time.Time, treating the value as a
// Unix timestamp encoded as float64 / int64 / int. Returns the zero time if
// the key is missing or has an unsupported type.
func UnixFromClaims(claims map[string]interface{}, key string) time.Time {
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

// NormalizeURL trims whitespace and any trailing slashes from raw.
func NormalizeURL(raw string) string {
	return strings.TrimRight(strings.TrimSpace(raw), "/")
}

// CanonicalResourceURL returns the protected-resource identifier in its
// canonical form: trimmed and with exactly one trailing slash. RFC 9728 §3.3
// (the Bearer Token resource_metadata) and RFC 8707 (resource indicators)
// treat the resource URL as an opaque identifier compared by string match.
// Audience validation accepts either form via oauth.audienceMatchesResource.
func CanonicalResourceURL(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	return strings.TrimRight(trimmed, "/") + "/"
}

// NormalizedPath ensures `raw` is a leading-slash-prefixed, trailing-slash-trimmed
// path. Empty input falls back to `fallback`.
func NormalizedPath(raw string, fallback string) string {
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

// JoinURLPath concatenates a base URL with a path, normalising each side.
func JoinURLPath(base string, path string) string {
	base = NormalizeURL(base)
	path = NormalizedPath(path, "")
	if path == "" || path == "/" {
		return base
	}
	return base + path
}

// TTLSeconds returns value if positive, else fallback.
func TTLSeconds(value int, fallback int) int {
	if value > 0 {
		return value
	}
	return fallback
}

// UniquePaths normalises each path and returns the de-duplicated subset in
// input order, skipping empties.
func UniquePaths(paths ...string) []string {
	result := make([]string, 0, len(paths))
	seen := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		path = NormalizedPath(path, "")
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

// SuffixPrefix returns the path portion that precedes any of the listed
// well-known markers. Used to recover the per-deployment URL prefix when an
// incoming /.well-known/* request lands on a sub-path mount.
func SuffixPrefix(path string, markers ...string) string {
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

// PathFromConfiguredURL returns the path component of a configured URL or "".
func PathFromConfiguredURL(raw string) string {
	if raw == "" {
		return ""
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.TrimRight(parsed.Path, "/")
}

// PKCEChallenge returns the S256 PKCE challenge for the given verifier.
func PKCEChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// NewPKCEVerifier generates a 32-byte random PKCE verifier per RFC 7636 §4.1.
// Used for the upstream-IdP leg; downstream verifiers come from the client.
func NewPKCEVerifier() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// SanitizeScope collapses internal whitespace into single spaces.
func SanitizeScope(scope string) string {
	return strings.Join(strings.Fields(scope), " ")
}

// NormalizeUpstreamScopeForClient maps upstream-IdP-specific scope URIs back
// to the OIDC standard names the MCP client originally requested. Mainly
// rewrites Google's URI-form OIDC scopes ("https://www.googleapis.com/auth/
// userinfo.email") to standard names ("email"). Unknown values pass through.
func NormalizeUpstreamScopeForClient(scope string) string {
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

// OIDCScopesForAdvertisement returns the subset of cfg.Scopes that
// altinity-mcp surfaces to MCP clients via discovery metadata and the
// WWW-Authenticate challenge. Only the OIDC-identity allowlist plus
// offline_access is admitted.
func OIDCScopesForAdvertisement(cfg oauth.OAuthConfig) []string {
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

// IsGoogleIssuer reports whether the configured issuer is Google's OIDC
// provider. Used to pick between `access_type=offline` (Google) and the
// `offline_access` scope (Auth0 and other RFC 6749 §6 strict providers).
func IsGoogleIssuer(issuer string) bool {
	host := strings.ToLower(strings.TrimSpace(issuer))
	host = strings.TrimPrefix(host, "https://")
	host = strings.TrimPrefix(host, "http://")
	host, _, _ = strings.Cut(host, "/")
	return host == "accounts.google.com" || host == "www.google.com"
}

// SafeUpstreamErrorFields extracts the RFC 6749 §5.2 `error` code from an
// upstream OAuth error response body, if the body parses as JSON, and always
// returns the body byte length. Avoids logging the body verbatim (IdPs
// sometimes echo the failed token or other diagnostic data in
// `error_description`).
func SafeUpstreamErrorFields(body []byte) (errCode string, length int) {
	var parsed struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(body, &parsed)
	return parsed.Error, len(body)
}

// RefreshErrorFields is the variant for the refresh-token grant that also
// returns error_description (sanitised). Google's refresh failures carry
// diagnostic detail in error_description that's worth surfacing.
func RefreshErrorFields(body []byte) (errCode, errDesc string) {
	var parsed struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	_ = json.Unmarshal(body, &parsed)
	return parsed.Error, SanitizeErrorDesc(parsed.ErrorDescription)
}

// SanitizeErrorDesc bounds an OAuth error_description for inclusion in our
// own error messages and logs: strips newlines + control chars, caps at 120
// bytes, returns a leading ": " separator if non-empty.
func SanitizeErrorDesc(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if len(s) > 120 {
		s = s[:120]
	}
	out := make([]rune, 0, len(s))
	for _, r := range s {
		if r == '\r' || r == '\n' || r == '\t' {
			out = append(out, ' ')
			continue
		}
		if r < 0x20 || r == 0x7f {
			continue
		}
		out = append(out, r)
	}
	return ": " + string(out)
}

// WriteOAuthTokenError writes an RFC 6749 §5.2 JSON error response. When
// status is 401 it also sets a Bearer-scheme WWW-Authenticate per RFC 7235
// §3.1 and RFC 6750 §3.
func WriteOAuthTokenError(w http.ResponseWriter, status int, code, description string) {
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

// ClaimsFromUserInfo projects a raw /userinfo JSON document into oauth.Claims.
// Distinct from oauth.claimsFromRawClaims because userinfo responses lack
// aud/exp/iat and the broker fills Issuer from operator config when absent.
func ClaimsFromUserInfo(raw map[string]interface{}) *oauth.Claims {
	claims := &oauth.Claims{Extra: make(map[string]interface{})}
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
