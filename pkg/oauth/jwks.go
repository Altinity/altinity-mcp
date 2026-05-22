package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
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
	// jwksCacheTTL bounds how long a JWKS or OIDC discovery response stays
	// cached before re-fetch.
	jwksCacheTTL = 5 * time.Minute
	// httpTimeout bounds the broker's outbound discovery + JWKS HTTP calls.
	httpTimeout = 10 * time.Second
)

// Verifier validates OAuth tokens against an issuer's JWKS, caching both the
// JWKS document and the authorization-server metadata (RFC 8414 / OIDC
// discovery) it needs to locate the JWKS URI. Safe for concurrent use.
type Verifier struct {
	cfg OAuthConfig

	jwksCache     jose.JSONWebKeySet
	jwksCacheURL  string
	jwksCacheTime time.Time
	jwksMu        sync.RWMutex

	asMetaCache    oauthex.AuthServerMeta
	asMetaCacheURL string
	asMetaTime     time.Time
	asMetaMu       sync.RWMutex
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
	if v.asMetaCacheURL == issuer && !v.asMetaTime.IsZero() && v.asMetaTime.Add(jwksCacheTTL).After(time.Now()) && v.asMetaCache.Issuer != "" {
		cached := v.asMetaCache
		v.asMetaMu.RUnlock()
		return &cached, nil
	}
	v.asMetaMu.RUnlock()

	httpClient := &http.Client{Timeout: httpTimeout}
	asMeta, err := auth.GetAuthServerMetadata(ctx, issuer, httpClient)
	if err != nil {
		return nil, fmt.Errorf("failed to discover authorization server metadata for issuer %q: %w", issuer, err)
	}
	if asMeta == nil {
		return nil, fmt.Errorf("no authorization server metadata found for issuer %q", issuer)
	}

	v.asMetaMu.Lock()
	v.asMetaCache = *asMeta
	v.asMetaCacheURL = issuer
	v.asMetaTime = time.Now()
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
func (v *Verifier) fetchJWKSet(ctx context.Context, jwksURI string) (*jose.JSONWebKeySet, error) {
	now := time.Now()

	v.jwksMu.RLock()
	if len(v.jwksCache.Keys) > 0 && v.jwksCacheURL == jwksURI && v.jwksCacheTime.Add(jwksCacheTTL).After(now) {
		cached := v.jwksCache
		v.jwksMu.RUnlock()
		return &cached, nil
	}
	v.jwksMu.RUnlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURI, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build jwks request: %w", err)
	}
	resp, err := (&http.Client{Timeout: httpTimeout}).Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch jwks: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Warn().Stack().Err(closeErr).Msgf("can't close %s response body", jwksURI)
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

	v.jwksMu.Lock()
	v.jwksCache = keySet
	v.jwksCacheURL = jwksURI
	v.jwksCacheTime = now
	v.jwksMu.Unlock()
	return &keySet, nil
}

// invalidateJWKSCache forces the next fetchJWKSet call to re-fetch. Used when
// the upstream AS rotates its signing key (kid we just saw is absent from the
// cached set).
func (v *Verifier) invalidateJWKSCache() {
	v.jwksMu.Lock()
	v.jwksCacheTime = time.Time{}
	v.jwksMu.Unlock()
}
