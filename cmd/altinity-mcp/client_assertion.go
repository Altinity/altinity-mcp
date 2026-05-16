package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// RFC 7523 §2.2 + RFC 7521 §4.2 client authentication for CIMD clients that
// publish token_endpoint_auth_method=private_key_jwt. The client posts:
//
//   client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
//   client_assertion=<JWT signed with the client's private key>
//
// We resolve the client's CIMD doc (already cached by cimdResolver), fetch
// its published JWKS, verify the JWT signature, and validate the registered
// claims: iss == sub == client_id, aud = our /oauth/token URL, exp/nbf/iat
// inside their windows.
//
// SECURITY: jti replay protection is intentionally not implemented as a
// pod-local cache. The replay bound today is the downstream JWE auth code's
// single-use guarantee (HA-replay model: upstream IdP `invalid_grant` on
// the 2nd redemption). A stolen client_assertion can only be replayed
// against a still-redeemable downstream code — a strictly narrower window
// than the assertion's own exp.
//
// **If a future change drops the JWE single-use invariant** (e.g. moves to
// long-lived bearer tokens, removes upstream code redemption, or allows
// auth-code reuse across PKCE generations), the replay surface widens to
// the assertion's full exp window. At that point add a pod-local LRU
// keyed by jti+kid+iss, TTL = max(exp - now, 0) + clientAssertionClockSkew,
// and reject duplicates. See [feedback_cimd_lenient_auth_method.md].

const (
	clientAssertionType        = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
	clientAssertionMaxLifetime = 10 * time.Minute // RFC 7523 §3 recommendation: short
	clientAssertionClockSkew   = 60 * time.Second
	jwksMaxBodyBytes           = 64 * 1024
)

var (
	errClientAssertionInvalid = errors.New("client_assertion invalid")
	errJWKSFetch              = errors.New("jwks fetch failed")
)

// jwksCacheEntry mirrors cimdCacheEntry shape: positive (keys) or negative (err).
type jwksCacheEntry struct {
	keys      *jose.JSONWebKeySet
	err       error
	expiresAt time.Time
}

type jwksCache struct {
	mu       sync.Mutex
	entries  map[string]*jwksCacheEntry
	order    []string
	capacity int
}

func newJWKSCache(capacity int) *jwksCache {
	if capacity <= 0 {
		capacity = 1
	}
	return &jwksCache{entries: make(map[string]*jwksCacheEntry, capacity), capacity: capacity}
}

func (c *jwksCache) get(key string, now time.Time) (*jwksCacheEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok {
		return nil, false
	}
	if now.After(e.expiresAt) {
		delete(c.entries, key)
		for i, k := range c.order {
			if k == key {
				c.order = append(c.order[:i], c.order[i+1:]...)
				break
			}
		}
		return nil, false
	}
	return e, true
}

func (c *jwksCache) put(key string, e *jwksCacheEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.entries[key]; !exists {
		if len(c.entries) >= c.capacity {
			oldest := c.order[0]
			c.order = c.order[1:]
			delete(c.entries, oldest)
		}
		c.order = append(c.order, key)
	}
	c.entries[key] = e
}

// invalidate forces the next fetchJWKS to bypass the cache for this URL.
// Used when a kid lookup misses — the client may have rotated keys.
func (c *jwksCache) invalidate(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.entries[key]; !ok {
		return
	}
	delete(c.entries, key)
	for i, k := range c.order {
		if k == key {
			c.order = append(c.order[:i], c.order[i+1:]...)
			return
		}
	}
}

// fetchJWKS retrieves and caches the JWKS at jwksURI using the same SSRF-safe
// transport as CIMD doc fetches. URL is assumed pre-validated by
// validateJWKSURI (called at CIMD-doc parse time).
func (r *cimdResolver) fetchJWKS(ctx context.Context, jwksURI string) (*jose.JSONWebKeySet, error) {
	if e, ok := r.jwksCache.get(jwksURI, r.now()); ok {
		if e.err != nil {
			return nil, e.err
		}
		return e.keys, nil
	}
	keys, ttl, err := r.fetchJWKSUncached(ctx, jwksURI)
	now := r.now()
	if err != nil {
		// JWKS fetch failures are not negative-cached: a transient outage at
		// the client's JWKS host must not lock out every /token call to that
		// client for the cache window. The next request retries.
		return nil, err
	}
	if ttl > 0 {
		r.jwksCache.put(jwksURI, &jwksCacheEntry{keys: keys, expiresAt: now.Add(ttl)})
	}
	return keys, nil
}

func (r *cimdResolver) fetchJWKSUncached(ctx context.Context, jwksURI string) (*jose.JSONWebKeySet, time.Duration, error) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cimdFetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURI, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: build request: %v", errJWKSFetch, err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %v", errJWKSFetch, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 == 3 {
		return nil, 0, fmt.Errorf("%w: unexpected redirect %d", errJWKSFetch, resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("%w: HTTP %d", errJWKSFetch, resp.StatusCode)
	}
	if !isApplicationJSON(resp.Header.Get("Content-Type")) {
		return nil, 0, fmt.Errorf("%w: content-type %q not application/json", errJWKSFetch, resp.Header.Get("Content-Type"))
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, int64(jwksMaxBodyBytes+1)))
	if err != nil {
		return nil, 0, fmt.Errorf("%w: body read: %v", errJWKSFetch, err)
	}
	if len(body) > jwksMaxBodyBytes {
		return nil, 0, fmt.Errorf("%w: body exceeds %d bytes", errJWKSFetch, jwksMaxBodyBytes)
	}
	var keys jose.JSONWebKeySet
	if err := json.Unmarshal(body, &keys); err != nil {
		return nil, 0, fmt.Errorf("%w: decode: %v", errJWKSFetch, err)
	}
	if len(keys.Keys) == 0 {
		return nil, 0, fmt.Errorf("%w: empty key set", errJWKSFetch)
	}
	return &keys, cacheTTLFromHeader(resp.Header.Get("Cache-Control")), nil
}

// signatureAlgs is the set of asymmetric JWS algorithms we accept for
// client_assertion. Mirrors common library defaults; explicitly omits HMAC
// (would require a shared secret we don't have) and "none".
var clientAssertionAlgs = []jose.SignatureAlgorithm{
	jose.RS256, jose.RS384, jose.RS512,
	jose.PS256, jose.PS384, jose.PS512,
	jose.ES256, jose.ES384, jose.ES512,
	jose.EdDSA,
}

// verifyClientAssertion implements RFC 7523 §3 validation for a CIMD client
// whose metadata declared token_endpoint_auth_method=private_key_jwt.
//
// expectedAud is the absolute URL of our /oauth/token endpoint; the assertion's
// `aud` claim must contain that value (per OAuth2 best-current-practice +
// AS metadata `token_endpoint`). Returns nil on success.
func (a *application) verifyClientAssertion(ctx context.Context, client *statelessRegisteredClient, clientID, assertion, expectedAud string) error {
	if client.JWKSURI == "" {
		return fmt.Errorf("%w: client did not publish jwks_uri", errClientAssertionInvalid)
	}
	if assertion == "" {
		return fmt.Errorf("%w: missing client_assertion", errClientAssertionInvalid)
	}
	parsed, err := jwt.ParseSigned(assertion, clientAssertionAlgs)
	if err != nil {
		return fmt.Errorf("%w: parse: %v", errClientAssertionInvalid, err)
	}
	if len(parsed.Headers) != 1 {
		return fmt.Errorf("%w: expected exactly one JWS signature", errClientAssertionInvalid)
	}
	hdr := parsed.Headers[0]

	keys, err := a.cimdResolver.fetchJWKS(ctx, client.JWKSURI)
	if err != nil {
		return fmt.Errorf("%w: jwks unavailable: %v", errClientAssertionInvalid, err)
	}
	jwk := selectJWK(keys, hdr.KeyID, hdr.Algorithm)
	if jwk == nil {
		// kid miss: client may have rotated keys. Bust the cache and retry once.
		a.cimdResolver.jwksCache.invalidate(client.JWKSURI)
		keys, err = a.cimdResolver.fetchJWKS(ctx, client.JWKSURI)
		if err != nil {
			return fmt.Errorf("%w: jwks unavailable: %v", errClientAssertionInvalid, err)
		}
		jwk = selectJWK(keys, hdr.KeyID, hdr.Algorithm)
		if jwk == nil {
			return fmt.Errorf("%w: no matching key for kid=%q alg=%q", errClientAssertionInvalid, hdr.KeyID, hdr.Algorithm)
		}
	}

	var claims jwt.Claims
	if err := parsed.Claims(jwk.Key, &claims); err != nil {
		return fmt.Errorf("%w: signature: %v", errClientAssertionInvalid, err)
	}

	// RFC 7523 §3: iss MUST be client_id; sub MUST be client_id (for client
	// authentication, where the JWT identifies the client itself, not a user).
	if claims.Issuer != clientID {
		return fmt.Errorf("%w: iss %q != client_id", errClientAssertionInvalid, claims.Issuer)
	}
	if claims.Subject != clientID {
		return fmt.Errorf("%w: sub %q != client_id", errClientAssertionInvalid, claims.Subject)
	}
	// aud MUST contain the exact token endpoint URL we advertised in AS
	// metadata. We don't accept the AS base URL or the issuer as a fallback;
	// callers signing the assertion can read `token_endpoint` from our
	// `.well-known/oauth-authorization-server` document, so byte-equal is
	// reasonable. If a real-world client publishes the AS base URL as `aud`
	// we'll see "aud does not match token endpoint" in logs and can relax.
	now := a.cimdResolver.now()
	if err := claims.ValidateWithLeeway(jwt.Expected{Time: now}, clientAssertionClockSkew); err != nil {
		return fmt.Errorf("%w: time claims: %v", errClientAssertionInvalid, err)
	}
	if !audienceMatches(claims.Audience, expectedAud) {
		return fmt.Errorf("%w: aud %v does not match token endpoint %q", errClientAssertionInvalid, []string(claims.Audience), expectedAud)
	}
	// Bound assertion lifetime: per RFC 7523 §3, assertions SHOULD be short.
	// Reject ones with exp > iat + clientAssertionMaxLifetime, even if both
	// are in their windows individually, to limit replay surface area for a
	// pod-local /token call. iat is OPTIONAL in RFC 7523; only enforce when
	// present.
	if claims.IssuedAt != nil && claims.Expiry != nil {
		if claims.Expiry.Time().Sub(claims.IssuedAt.Time()) > clientAssertionMaxLifetime {
			return fmt.Errorf("%w: exp - iat > %s", errClientAssertionInvalid, clientAssertionMaxLifetime)
		}
	}
	return nil
}

// selectJWK picks a key from the set by kid; if kid is empty, falls back to
// the first signing key whose alg matches the JWS header alg. Returns nil
// if no match. Keys marked `use: enc` are filtered out — they may be
// present in mixed-purpose JWKS docs and must never be used to verify a
// client_assertion signature (RFC 7517 §4.2).
func selectJWK(set *jose.JSONWebKeySet, kid, alg string) *jose.JSONWebKey {
	if set == nil {
		return nil
	}
	if kid != "" {
		for i := range set.Keys {
			if set.Keys[i].KeyID == kid && isSigKey(&set.Keys[i]) {
				return &set.Keys[i]
			}
		}
		return nil
	}
	for i := range set.Keys {
		if !isSigKey(&set.Keys[i]) {
			continue
		}
		if set.Keys[i].Algorithm == alg || set.Keys[i].Algorithm == "" {
			return &set.Keys[i]
		}
	}
	return nil
}

// isSigKey reports whether a JWK is usable for signature verification. An
// unset `use` is permitted (the SDK leaves it empty when omitted from the
// JSON), but an explicit `use: enc` is disqualifying.
func isSigKey(k *jose.JSONWebKey) bool {
	return k.Use == "" || k.Use == "sig"
}

// audienceMatches returns true iff aud contains an entry that exactly
// equals expected. Byte-equality per RFC 7523 §3 + OAuth2 best-current-practice.
func audienceMatches(aud jwt.Audience, expected string) bool {
	for _, a := range aud {
		if a == expected {
			return true
		}
	}
	return false
}
