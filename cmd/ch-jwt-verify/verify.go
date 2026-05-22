package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/altinity/altinity-mcp/pkg/oauth"
	"github.com/rs/zerolog/log"
)

// Verifier wraps the oauth.Verifier with the sidecar-specific identity policy
// and a small bounded LRU-by-TTL cache of verification outcomes. The cache is
// the only state the sidecar carries beyond config; per JWT-hash entries
// expire after positiveTTL/negativeTTL so a rotated token can't be replayed
// past its real exp anyway.
type Verifier struct {
	cfg      *Config
	oauthVer *oauth.Verifier

	mu    sync.Mutex
	cache map[string]cacheEntry
}

type cacheEntry struct {
	ok        bool
	settings  map[string]string
	failure   string
	expiresAt time.Time
}

// verifyResponse is the JSON body returned to ClickHouse on success. The
// `settings` field is the only one CH consumes; we include `email` so an
// operator inspecting sidecar access logs (under `kubectl logs`) can correlate
// queries to principals without grepping the JWT.
type verifyResponse struct {
	Settings map[string]string `json:"settings,omitempty"`
	Email    string            `json:"email,omitempty"`
}

// NewVerifier constructs a Verifier. The oauth.Verifier inside it shares the
// JWKS cache implementation with MCP — keeping the JWKS-rotation behaviour
// identical across binaries simplifies operator mental model.
func NewVerifier(cfg *Config) *Verifier {
	return &Verifier{
		cfg: cfg,
		oauthVer: oauth.NewVerifier(oauth.OAuthConfig{
			Enabled:        true,
			Issuer:         cfg.OAuth.Issuer,
			JWKSURL:        cfg.OAuth.JWKSURL,
			Audience:       cfg.OAuth.Audience,
			RequiredScopes: cfg.OAuth.RequiredScopes,
		}),
		cache: make(map[string]cacheEntry),
	}
}

// Handler returns the http.Handler for POST /verify. Any non-200 status tells
// ClickHouse to reject the authenticator response per CH's docs; the body is
// for the sidecar's log only.
func (v *Verifier) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		user, token, ok := parseBasicAuth(r.Header.Get("Authorization"))
		if !ok {
			log.Debug().Msg("verify: missing or malformed Basic Authorization header")
			http.Error(w, "missing or malformed Authorization", http.StatusUnauthorized)
			return
		}

		resp, err := v.verify(r.Context(), user, token)
		if err != nil {
			log.Debug().Err(err).Str("user", user).Msg("verify: rejected")
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
}

// verify performs the actual JWT validation + identity policy + scope→settings
// derivation. It also handles the small verification cache.
func (v *Verifier) verify(ctx context.Context, user, token string) (*verifyResponse, error) {
	cacheKey := sha256HexShort(token)

	v.mu.Lock()
	if entry, found := v.cache[cacheKey]; found && time.Now().Before(entry.expiresAt) {
		v.mu.Unlock()
		if entry.ok {
			return &verifyResponse{Settings: entry.settings}, nil
		}
		return nil, errors.New(entry.failure)
	}
	v.mu.Unlock()

	resp, err := v.verifyUncached(ctx, user, token)
	v.storeCache(cacheKey, resp, err)
	return resp, err
}

func (v *Verifier) verifyUncached(ctx context.Context, user, token string) (*verifyResponse, error) {
	claims, err := v.oauthVer.ValidateToken(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("token validation failed: %w", err)
	}
	if claims == nil {
		// ValidateToken soft-passes opaque tokens and JWTs with no JWKS — both
		// are misconfigurations on the sidecar side (we always have a JWKS).
		return nil, errors.New("token validation produced no claims; sidecar requires a signed JWT")
	}

	principal, err := v.principalFromClaims(claims)
	if err != nil {
		return nil, err
	}

	if !v.matchUser(user, principal) {
		return nil, fmt.Errorf("Basic user %q does not match JWT %s claim %q", user, v.cfg.Identity.UsernameClaim, principal)
	}

	if err := v.applyIdentityPolicy(claims); err != nil {
		return nil, err
	}

	return &verifyResponse{
		Settings: settingsFromScopes(claims.Scopes, v.cfg.SettingsFromScope),
		Email:    claims.Email,
	}, nil
}

// principalFromClaims picks the JWT claim to match against the Basic user
// half. For `email`, we fall back to the namespaced `*/email` claim used by
// Auth0 third-party tokens.
func (v *Verifier) principalFromClaims(claims *oauth.Claims) (string, error) {
	switch v.cfg.Identity.UsernameClaim {
	case "email", "":
		if e := strings.TrimSpace(claims.Email); e != "" {
			return e, nil
		}
		if e := oauth.EmailFromNamespacedExtra(claims.Extra); e != "" {
			return e, nil
		}
		return "", errors.New("JWT carries no email claim")
	case "sub":
		if s := strings.TrimSpace(claims.Subject); s != "" {
			return s, nil
		}
		return "", errors.New("JWT carries no sub claim")
	default:
		if raw, ok := claims.Extra[v.cfg.Identity.UsernameClaim]; ok {
			if s, ok := raw.(string); ok && strings.TrimSpace(s) != "" {
				return strings.TrimSpace(s), nil
			}
		}
		return "", fmt.Errorf("JWT carries no %q claim", v.cfg.Identity.UsernameClaim)
	}
}

func (v *Verifier) matchUser(user, principal string) bool {
	switch v.cfg.Identity.MatchMode {
	case "exact":
		return user == principal
	default:
		return strings.EqualFold(strings.TrimSpace(user), strings.TrimSpace(principal))
	}
}

// applyIdentityPolicy enforces verified-email + domain allow-lists. These were
// previously enforced in pkg/oauth on the MCP side; they live on the sidecar
// alone now because MCP no longer terminates the JWT cryptographically.
func (v *Verifier) applyIdentityPolicy(claims *oauth.Claims) error {
	if v.cfg.Identity.RequireEmailVerified && claims.Email != "" && !claims.EmailVerified {
		return oauth.ErrEmailNotVerified
	}
	if len(v.cfg.Identity.AllowedEmailDomains) > 0 {
		domain := oauth.EmailDomain(claims.Email)
		if domain == "" || !oauth.ContainsDomain(v.cfg.Identity.AllowedEmailDomains, domain) {
			return oauth.ErrUnauthorizedDomain
		}
	}
	if len(v.cfg.Identity.AllowedHostedDomains) > 0 {
		if claims.HostedDomain == "" || !oauth.ContainsDomain(v.cfg.Identity.AllowedHostedDomains, claims.HostedDomain) {
			return oauth.ErrUnauthorizedDomain
		}
	}
	return nil
}

func (v *Verifier) storeCache(key string, resp *verifyResponse, err error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if err != nil {
		v.cache[key] = cacheEntry{
			ok:        false,
			failure:   err.Error(),
			expiresAt: time.Now().Add(v.cfg.Cache.NegativeTTL),
		}
		return
	}
	settings := resp.Settings
	v.cache[key] = cacheEntry{
		ok:        true,
		settings:  settings,
		expiresAt: time.Now().Add(v.cfg.Cache.PositiveTTL),
	}
}

// parseBasicAuth pulls out the user:token pair from `Authorization: Basic …`.
// We don't import net/http's ParseBasicAuth because that lowercases the auth
// scheme; CH sends `Basic` with a fixed casing and we want the strict version.
func parseBasicAuth(header string) (user, token string, ok bool) {
	const prefix = "Basic "
	if !strings.HasPrefix(header, prefix) {
		return "", "", false
	}
	decoded, err := base64.StdEncoding.DecodeString(header[len(prefix):])
	if err != nil {
		return "", "", false
	}
	idx := strings.IndexByte(string(decoded), ':')
	if idx < 0 {
		return "", "", false
	}
	return string(decoded[:idx]), string(decoded[idx+1:]), true
}

// sha256HexShort returns the first 16 hex chars of SHA256(token). 64 bits of
// the digest is enough for cache-key uniqueness across a single sidecar
// process's lifetime; the shorter key also keeps debug logs compact.
func sha256HexShort(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:8])
}
