package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/oauthex"
	"github.com/rs/zerolog/log"
)

const (
	// jwksCacheTTL is the default TTL applied when OAuthConfig.JWKSCacheTTL
	// is zero. The configured value (when non-zero) wins via
	// (*Verifier).jwksCacheTTL.
	jwksCacheTTL = 5 * time.Minute
	// httpTimeout bounds the broker's outbound discovery + JWKS HTTP calls.
	httpTimeout = 10 * time.Second
)

// jwksCacheTTL resolves the effective JWKS / metadata cache TTL: the
// configured value when set, otherwise the package default.
func (v *Verifier) jwksCacheTTL() time.Duration {
	if v.cfg.JWKSCacheTTL > 0 {
		return v.cfg.JWKSCacheTTL
	}
	return jwksCacheTTL
}

// jitteredExpiry returns now+TTL with ±10% uniformly-distributed jitter, so a
// fleet of replicas rolled out together doesn't synchronise its JWKS refetches
// and thunder the IdP every cache-TTL boundary. TTL/10 is enough to spread N
// replicas without ever extending the *effective* cache past 110% of the
// configured TTL — operators tuning against IdP rotation cadence still get a
// predictable upper bound. Zero / negative TTL falls back to `now` (the cache
// entry is already expired by the time the caller reads it back).
func jitteredExpiry(now time.Time, ttl time.Duration) time.Time {
	if ttl <= 0 {
		return now
	}
	span := ttl / 5 // = 2 × (ttl/10), the full ±10% window
	if span <= 0 {
		// TTL is too small for jitter to make a difference (<5 ns); skip.
		return now.Add(ttl)
	}
	jitter := time.Duration(rand.Int64N(int64(span))) - ttl/10
	return now.Add(ttl + jitter)
}

// Verifier validates OAuth tokens against an issuer's JWKS, caching both the
// JWKS document and the authorization-server metadata (RFC 8414 / OIDC
// discovery) it needs to locate the JWKS URI. Safe for concurrent use.
//
// Cache fields store an `expiresAt` timestamp computed at write time with
// ±10% jitter (see jitteredExpiry). Storing the deadline instead of the
// write time + read-time-applied TTL is what makes the jitter stable across
// reads — otherwise every cache check would roll a fresh random number and
// the cache would appear/disappear on every request.
type Verifier struct {
	cfg OAuthConfig

	jwksCache          jose.JSONWebKeySet
	jwksCacheURL       string
	jwksCacheExpiresAt time.Time
	jwksMu             sync.RWMutex

	asMetaCache     oauthex.AuthServerMeta
	asMetaCacheURL  string
	asMetaExpiresAt time.Time
	asMetaMu        sync.RWMutex

	// Health-probe accounting. Updated only on the JWKS-fetch path (the
	// recurring IdP RPC the sidecar's correctness depends on) so /readyz
	// can answer "is this replica reaching its IdP?" without changing any
	// verifier behavior. Cache hits skip the update — they don't tell us
	// anything new about IdP reachability.
	healthMu             sync.RWMutex
	jwksLastFetchAttempt time.Time
	jwksLastFetchSuccess time.Time
	jwksLastFetchError   error
}

// JWKSHealth returns the most recent JWKS-fetch attempt, the most recent
// success, and the most recent error (cleared on the next success). All
// zero values mean the Verifier has not yet attempted a fetch — readiness
// handlers should treat this as a boot-grace "ready" rather than a stale
// failure.
func (v *Verifier) JWKSHealth() (lastAttempt, lastSuccess time.Time, lastErr error) {
	v.healthMu.RLock()
	defer v.healthMu.RUnlock()
	return v.jwksLastFetchAttempt, v.jwksLastFetchSuccess, v.jwksLastFetchError
}

// NewVerifier builds a Verifier for the given OAuth configuration.
func NewVerifier(cfg OAuthConfig) *Verifier {
	return &Verifier{cfg: cfg}
}

// Config returns the OAuthConfig the Verifier was built with.
func (v *Verifier) Config() OAuthConfig {
	return v.cfg
}

// resolveJWKSURL resolves the JWKS URI by configuration override, then by OIDC
// / OAuth 2.0 Authorization Server Metadata discovery from the configured
// issuer. Returns an error if neither path succeeds.
func (v *Verifier) resolveJWKSURL(ctx context.Context) (string, error) {
	if explicit := strings.TrimSpace(v.cfg.JWKSURL); explicit != "" {
		return explicit, nil
	}
	issuer := strings.TrimSpace(v.cfg.Issuer)
	if issuer == "" {
		return "", fmt.Errorf("oauth issuer or jwks_url must be configured")
	}
	asMeta, err := v.fetchAuthServerMeta(ctx, issuer)
	if err != nil {
		return "", err
	}
	jwksURI := strings.TrimSpace(asMeta.JWKSURI)
	if jwksURI == "" {
		return "", fmt.Errorf("openid discovery did not return jwks_uri")
	}
	return jwksURI, nil
}

// fetchAuthServerMeta returns the cached or freshly-discovered authorization
// server metadata for issuer. Uses auth.GetAuthServerMetadata which tries the
// MCP-spec-required well-known endpoints in order (OAuth 2.0 first, then OIDC
// discovery, plus path-aware variants).
func (v *Verifier) fetchAuthServerMeta(ctx context.Context, issuer string) (*oauthex.AuthServerMeta, error) {
	issuer = strings.TrimRight(strings.TrimSpace(issuer), "/")
	if issuer == "" {
		return nil, fmt.Errorf("issuer is required")
	}

	v.asMetaMu.RLock()
	if v.asMetaCacheURL == issuer && v.asMetaExpiresAt.After(time.Now()) && v.asMetaCache.Issuer != "" {
		cached := v.asMetaCache
		v.asMetaMu.RUnlock()
		return &cached, nil
	}
	v.asMetaMu.RUnlock()

	httpClient := &http.Client{Timeout: httpTimeout}
	asMeta, err := auth.GetAuthServerMetadata(ctx, issuer, httpClient)
	if err != nil {
		// Discovery failures are network-y by nature (timeouts, DNS,
		// upstream 5xx); mark transient so the sidecar's negative cache
		// doesn't pin a legit token as bad across a blip.
		return nil, fmt.Errorf("failed to discover authorization server metadata for issuer %q: %w: %w", issuer, ErrTransient, err)
	}
	if asMeta == nil {
		return nil, fmt.Errorf("no authorization server metadata found for issuer %q", issuer)
	}

	v.asMetaMu.Lock()
	v.asMetaCache = *asMeta
	v.asMetaCacheURL = issuer
	v.asMetaExpiresAt = jitteredExpiry(time.Now(), v.jwksCacheTTL())
	v.asMetaMu.Unlock()
	return asMeta, nil
}

// FetchAuthServerMeta exposes the cached/discovered auth-server metadata for
// the given issuer. Used by the broker to resolve upstream /authorize and
// /token endpoints when the operator hasn't pinned them explicitly.
func (v *Verifier) FetchAuthServerMeta(ctx context.Context, issuer string) (*oauthex.AuthServerMeta, error) {
	return v.fetchAuthServerMeta(ctx, issuer)
}

// ResolveUserInfoEndpoint returns the OIDC userinfo_endpoint advertised by
// issuer's /.well-known/openid-configuration document. oauthex.AuthServerMeta
// (RFC 8414) doesn't expose this field — userinfo is OIDC-only — so this is
// the surgical fallback when the operator hasn't pinned UserInfoURL.
//
// Returns "" without error when the document doesn't advertise the field; the
// caller treats that the same as "no userinfo configured".
func (v *Verifier) ResolveUserInfoEndpoint(ctx context.Context, issuer string) (string, error) {
	issuer = strings.TrimRight(strings.TrimSpace(issuer), "/")
	if issuer == "" {
		return "", fmt.Errorf("issuer is required")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, issuer+"/.well-known/openid-configuration", nil)
	if err != nil {
		return "", err
	}
	resp, err := (&http.Client{Timeout: httpTimeout}).Do(req)
	if err != nil {
		return "", err
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Warn().Stack().Err(closeErr).Msgf("can't close openid-configuration response body for %s", issuer)
		}
	}()
	if resp.StatusCode >= 300 {
		return "", nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	var partial struct {
		UserInfoEndpoint string `json:"userinfo_endpoint"`
	}
	if err := json.Unmarshal(body, &partial); err != nil {
		return "", err
	}
	return strings.TrimSpace(partial.UserInfoEndpoint), nil
}

// fetchJWKSet returns the cached or freshly-fetched JWKS for jwksURI.
func (v *Verifier) fetchJWKSet(ctx context.Context, jwksURI string) (result *jose.JSONWebKeySet, retErr error) {
	now := time.Now()

	v.jwksMu.RLock()
	if len(v.jwksCache.Keys) > 0 && v.jwksCacheURL == jwksURI && v.jwksCacheExpiresAt.After(now) {
		cached := v.jwksCache
		v.jwksMu.RUnlock()
		return &cached, nil
	}
	v.jwksMu.RUnlock()

	// Beyond this point we make an actual IdP RPC; record it for /readyz.
	// recordJWKSFetchResult runs in a defer so each early-return error
	// site updates the health snapshot exactly once.
	v.healthMu.Lock()
	v.jwksLastFetchAttempt = now
	v.healthMu.Unlock()
	defer func() {
		v.healthMu.Lock()
		defer v.healthMu.Unlock()
		if retErr == nil {
			v.jwksLastFetchSuccess = time.Now()
			v.jwksLastFetchError = nil
		} else {
			v.jwksLastFetchError = retErr
		}
	}()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURI, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build jwks request: %w", err)
	}
	resp, err := (&http.Client{Timeout: httpTimeout}).Do(req)
	if err != nil {
		// Connection refused / DNS / TLS / timeout — never a permanent
		// reason to reject the *token*. Mark transient.
		return nil, fmt.Errorf("failed to fetch jwks: %w: %w", ErrTransient, err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Warn().Stack().Err(closeErr).Msgf("can't close %s response body", jwksURI)
		}
	}()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		// Body-read aborts are transport-level — same reasoning as Do() error.
		return nil, fmt.Errorf("failed to read jwks response: %w: %w", ErrTransient, err)
	}
	if resp.StatusCode >= 500 {
		// Upstream 5xx is transient; 4xx (incl. 404 on a wrong URL) is
		// operator misconfiguration and stays permanent.
		return nil, fmt.Errorf("jwks endpoint returned status %d: %w", resp.StatusCode, ErrTransient)
	}
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("jwks endpoint returned status %d", resp.StatusCode)
	}

	var keySet jose.JSONWebKeySet
	if err := json.Unmarshal(body, &keySet); err != nil {
		return nil, fmt.Errorf("failed to parse jwks response: %w", err)
	}

	v.jwksMu.Lock()
	v.jwksCache = keySet
	v.jwksCacheURL = jwksURI
	v.jwksCacheExpiresAt = jitteredExpiry(now, v.jwksCacheTTL())
	v.jwksMu.Unlock()
	return &keySet, nil
}

// invalidateJWKSCache forces the next fetchJWKSet call to re-fetch. Used when
// the upstream AS rotates its signing key (kid we just saw is absent from the
// cached set). The zero-value expiresAt is in the distant past, so the next
// read fails the .After(now) check.
func (v *Verifier) invalidateJWKSCache() {
	v.jwksMu.Lock()
	v.jwksCacheExpiresAt = time.Time{}
	v.jwksMu.Unlock()
}
