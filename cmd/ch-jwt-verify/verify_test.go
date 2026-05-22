package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/altinity/altinity-mcp/pkg/oauth"
	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"
)

// testIdP is a tiny in-process OIDC test fixture: it generates one RSA signing
// key, serves /jwks, and can mint JWTs with arbitrary claims. We don't depend
// on pkg/server's testOAuthProvider helper because the sidecar is independent
// of pkg/server — the e2e test there is a separate vertical.
type testIdP struct {
	server   *httptest.Server
	signer   jose.Signer
	keyID    string
	privKey  *rsa.PrivateKey
	issuer   string
	audience string
}

func newTestIdP(t *testing.T) *testIdP {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	const kid = "test-key"

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: priv},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid),
	)
	require.NoError(t, err)

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		// The sidecar may resolve JWKS via OIDC discovery when JWKSURL isn't pinned.
		host := "http://" + r.Host
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"issuer":   host,
			"jwks_uri": host + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key:       &priv.PublicKey,
			KeyID:     kid,
			Algorithm: "RS256",
			Use:       "sig",
		}}}
		_ = json.NewEncoder(w).Encode(set)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	return &testIdP{
		server:   srv,
		signer:   signer,
		keyID:    kid,
		privKey:  priv,
		issuer:   srv.URL,
		audience: "ch-jwt-verify.test",
	}
}

func (p *testIdP) mintJWT(t *testing.T, claims map[string]interface{}) string {
	t.Helper()
	if _, ok := claims["iss"]; !ok {
		claims["iss"] = p.issuer
	}
	if _, ok := claims["aud"]; !ok {
		claims["aud"] = p.audience
	}
	if _, ok := claims["exp"]; !ok {
		claims["exp"] = time.Now().Add(time.Hour).Unix()
	}
	if _, ok := claims["iat"]; !ok {
		claims["iat"] = time.Now().Unix()
	}
	token, err := josejwt.Signed(p.signer).Claims(claims).Serialize()
	require.NoError(t, err)
	return token
}

func baseConfig(p *testIdP) *Config {
	return &Config{
		OAuth: OAuthConfig{
			Issuer:   p.issuer,
			JWKSURL:  p.server.URL + "/jwks",
			Audience: p.audience,
		},
		Identity: IdentityConfig{
			UsernameClaim:        "email",
			MatchMode:            "lowercase_equal",
			RequireEmailVerified: true,
		},
		Cache: CacheConfig{
			PositiveTTL: 30 * time.Second,
			NegativeTTL: 5 * time.Minute,
		},
	}
}

func basicHeader(user, token string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+token))
}

func TestVerifierAcceptsValidJWT(t *testing.T) {
	t.Parallel()
	p := newTestIdP(t)
	v := NewVerifier(baseConfig(p))
	tok := p.mintJWT(t, map[string]interface{}{
		"sub":            "u-1",
		"email":          "alice@example.com",
		"email_verified": true,
	})

	req := httptest.NewRequest(http.MethodPost, "/verify", nil)
	req.Header.Set("Authorization", basicHeader("alice@example.com", tok))
	rr := httptest.NewRecorder()
	v.Handler().ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	var resp verifyResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	require.Equal(t, "alice@example.com", resp.Email)
}

func TestVerifierRejectsWrongAudience(t *testing.T) {
	t.Parallel()
	p := newTestIdP(t)
	v := NewVerifier(baseConfig(p))
	tok := p.mintJWT(t, map[string]interface{}{
		"sub":            "u-1",
		"aud":            "some-other-api",
		"email":          "alice@example.com",
		"email_verified": true,
	})

	req := httptest.NewRequest(http.MethodPost, "/verify", nil)
	req.Header.Set("Authorization", basicHeader("alice@example.com", tok))
	rr := httptest.NewRecorder()
	v.Handler().ServeHTTP(rr, req)

	require.NotEqual(t, http.StatusOK, rr.Code)
}

func TestVerifierRejectsExpiredJWT(t *testing.T) {
	t.Parallel()
	p := newTestIdP(t)
	v := NewVerifier(baseConfig(p))
	tok := p.mintJWT(t, map[string]interface{}{
		"sub":            "u-1",
		"email":          "alice@example.com",
		"email_verified": true,
		"exp":            time.Now().Add(-time.Hour).Unix(),
		"iat":            time.Now().Add(-2 * time.Hour).Unix(),
	})

	req := httptest.NewRequest(http.MethodPost, "/verify", nil)
	req.Header.Set("Authorization", basicHeader("alice@example.com", tok))
	rr := httptest.NewRecorder()
	v.Handler().ServeHTTP(rr, req)

	require.NotEqual(t, http.StatusOK, rr.Code)
}

func TestVerifierRejectsUserVsEmailMismatch(t *testing.T) {
	t.Parallel()
	p := newTestIdP(t)
	v := NewVerifier(baseConfig(p))
	tok := p.mintJWT(t, map[string]interface{}{
		"sub":            "u-1",
		"email":          "alice@example.com",
		"email_verified": true,
	})

	// Try to impersonate bob using alice's JWT.
	req := httptest.NewRequest(http.MethodPost, "/verify", nil)
	req.Header.Set("Authorization", basicHeader("bob@example.com", tok))
	rr := httptest.NewRecorder()
	v.Handler().ServeHTTP(rr, req)

	require.Equal(t, http.StatusForbidden, rr.Code)
	require.Contains(t, rr.Body.String(), "does not match")
}

func TestVerifierLowercaseEqualMatching(t *testing.T) {
	t.Parallel()
	p := newTestIdP(t)
	v := NewVerifier(baseConfig(p))
	tok := p.mintJWT(t, map[string]interface{}{
		"sub":            "u-1",
		"email":          "Alice@Example.com",
		"email_verified": true,
	})

	// Lowercase Basic user must match the email claim under lowercase_equal.
	req := httptest.NewRequest(http.MethodPost, "/verify", nil)
	req.Header.Set("Authorization", basicHeader("alice@example.com", tok))
	rr := httptest.NewRecorder()
	v.Handler().ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
}

func TestVerifierRejectsUnverifiedEmail(t *testing.T) {
	t.Parallel()
	p := newTestIdP(t)
	v := NewVerifier(baseConfig(p))
	tok := p.mintJWT(t, map[string]interface{}{
		"sub":            "u-1",
		"email":          "alice@example.com",
		"email_verified": false,
	})

	req := httptest.NewRequest(http.MethodPost, "/verify", nil)
	req.Header.Set("Authorization", basicHeader("alice@example.com", tok))
	rr := httptest.NewRecorder()
	v.Handler().ServeHTTP(rr, req)

	require.Equal(t, http.StatusForbidden, rr.Code)
}

func TestVerifierEnforcesAllowedEmailDomains(t *testing.T) {
	t.Parallel()
	p := newTestIdP(t)
	cfg := baseConfig(p)
	cfg.Identity.AllowedEmailDomains = []string{"altinity.com"}
	v := NewVerifier(cfg)

	tok := p.mintJWT(t, map[string]interface{}{
		"sub":            "u-1",
		"email":          "alice@example.com",
		"email_verified": true,
	})
	req := httptest.NewRequest(http.MethodPost, "/verify", nil)
	req.Header.Set("Authorization", basicHeader("alice@example.com", tok))
	rr := httptest.NewRecorder()
	v.Handler().ServeHTTP(rr, req)
	require.Equal(t, http.StatusForbidden, rr.Code)
}

func TestVerifierEnforcesRequiredScopes(t *testing.T) {
	t.Parallel()
	p := newTestIdP(t)
	cfg := baseConfig(p)
	cfg.OAuth.RequiredScopes = []string{"mcp:read"}
	v := NewVerifier(cfg)

	tok := p.mintJWT(t, map[string]interface{}{
		"sub":            "u-1",
		"email":          "alice@example.com",
		"email_verified": true,
		"scope":          "mcp:write",
	})
	req := httptest.NewRequest(http.MethodPost, "/verify", nil)
	req.Header.Set("Authorization", basicHeader("alice@example.com", tok))
	rr := httptest.NewRecorder()
	v.Handler().ServeHTTP(rr, req)
	require.Equal(t, http.StatusForbidden, rr.Code)
}

func TestVerifierAppliesScopeSettings(t *testing.T) {
	t.Parallel()
	p := newTestIdP(t)
	cfg := baseConfig(p)
	cfg.SettingsFromScope = map[string]map[string]string{
		"mcp:read": {"readonly": "1"},
	}
	v := NewVerifier(cfg)

	tok := p.mintJWT(t, map[string]interface{}{
		"sub":            "u-1",
		"email":          "alice@example.com",
		"email_verified": true,
		"scope":          "mcp:read",
	})
	req := httptest.NewRequest(http.MethodPost, "/verify", nil)
	req.Header.Set("Authorization", basicHeader("alice@example.com", tok))
	rr := httptest.NewRecorder()
	v.Handler().ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	var resp verifyResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	require.Equal(t, "1", resp.Settings["readonly"])
}

func TestVerifierRejectsNonPOST(t *testing.T) {
	t.Parallel()
	p := newTestIdP(t)
	v := NewVerifier(baseConfig(p))

	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		req := httptest.NewRequest(method, "/verify", nil)
		req.Header.Set("Authorization", basicHeader("alice@example.com", "irrelevant"))
		rr := httptest.NewRecorder()
		v.Handler().ServeHTTP(rr, req)
		require.Equal(t, http.StatusMethodNotAllowed, rr.Code, "method %s should be rejected", method)
		require.Equal(t, http.MethodPost, rr.Header().Get("Allow"))
	}
}

func TestVerifierRejectsMissingAuthHeader(t *testing.T) {
	t.Parallel()
	p := newTestIdP(t)
	v := NewVerifier(baseConfig(p))

	req := httptest.NewRequest(http.MethodPost, "/verify", nil)
	rr := httptest.NewRecorder()
	v.Handler().ServeHTTP(rr, req)
	require.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestVerifierNegativeCacheSuppressesRepeatedFailures(t *testing.T) {
	t.Parallel()
	p := newTestIdP(t)
	v := NewVerifier(baseConfig(p))

	tok := p.mintJWT(t, map[string]interface{}{
		"sub":            "u-1",
		"email":          "alice@example.com",
		"email_verified": false, // → fail
	})

	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodPost, "/verify", nil)
		req.Header.Set("Authorization", basicHeader("alice@example.com", tok))
		rr := httptest.NewRecorder()
		v.Handler().ServeHTTP(rr, req)
		require.Equal(t, http.StatusForbidden, rr.Code)
	}
}

func TestCacheCapEvicts(t *testing.T) {
	t.Parallel()
	p := newTestIdP(t)
	v := NewVerifier(baseConfig(p))
	v.cacheCap = 3 // override default for the test

	// Insert four entries via the public storeCache path — synthesize
	// minimal verifyResponse / error values; we're testing eviction
	// mechanics, not validation.
	for i := 0; i < 4; i++ {
		v.storeCache("k"+string(rune('a'+i)), &verifyResponse{Email: "u@x"}, nil)
	}

	v.mu.Lock()
	got := len(v.cache)
	v.mu.Unlock()
	require.LessOrEqual(t, got, 3, "cache must not exceed cap")
}

func TestPruneExpired(t *testing.T) {
	t.Parallel()
	p := newTestIdP(t)
	v := NewVerifier(baseConfig(p))

	v.mu.Lock()
	v.cache["live"] = cacheEntry{ok: true, expiresAt: time.Now().Add(time.Hour)}
	v.cache["dead"] = cacheEntry{ok: true, expiresAt: time.Now().Add(-time.Hour)}
	v.mu.Unlock()

	v.pruneExpired()

	v.mu.Lock()
	_, liveOK := v.cache["live"]
	_, deadOK := v.cache["dead"]
	v.mu.Unlock()
	require.True(t, liveOK, "live entry must survive prune")
	require.False(t, deadOK, "expired entry must be evicted")
}

func TestCacheHitPreservesEmail(t *testing.T) {
	t.Parallel()
	p := newTestIdP(t)
	v := NewVerifier(baseConfig(p))
	tok := p.mintJWT(t, map[string]interface{}{
		"sub":            "u-1",
		"email":          "alice@example.com",
		"email_verified": true,
	})

	// First request populates the cache.
	req := httptest.NewRequest(http.MethodPost, "/verify", nil)
	req.Header.Set("Authorization", basicHeader("alice@example.com", tok))
	rr := httptest.NewRecorder()
	v.Handler().ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)
	var first verifyResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &first))
	require.Equal(t, "alice@example.com", first.Email)

	// Second request is a cache hit. Email must still surface.
	req2 := httptest.NewRequest(http.MethodPost, "/verify", nil)
	req2.Header.Set("Authorization", basicHeader("alice@example.com", tok))
	rr2 := httptest.NewRecorder()
	v.Handler().ServeHTTP(rr2, req2)
	require.Equal(t, http.StatusOK, rr2.Code)
	var second verifyResponse
	require.NoError(t, json.Unmarshal(rr2.Body.Bytes(), &second))
	require.Equal(t, "alice@example.com", second.Email)
}

func TestNegativeCachePreservesErrorIdentity(t *testing.T) {
	t.Parallel()
	p := newTestIdP(t)
	v := NewVerifier(baseConfig(p))
	// require_email_verified=true by default; unverified email -> ErrEmailNotVerified
	tok := p.mintJWT(t, map[string]interface{}{
		"sub":            "u-1",
		"email":          "alice@example.com",
		"email_verified": false,
	})

	// First call populates the negative cache via the real path.
	_, err1 := v.verify(context.Background(), "alice@example.com", tok)
	require.Error(t, err1)
	require.ErrorIs(t, err1, oauth.ErrEmailNotVerified, "first call must return the sentinel")

	// Second call hits the cache and must return the SAME sentinel
	// (i.e. errors.Is still resolves through the cache layer).
	_, err2 := v.verify(context.Background(), "alice@example.com", tok)
	require.Error(t, err2)
	require.ErrorIs(t, err2, oauth.ErrEmailNotVerified, "cached error must keep sentinel identity")
}

func TestParseBasicAuth(t *testing.T) {
	t.Parallel()
	u, tk, ok := parseBasicAuth("Basic " + base64.StdEncoding.EncodeToString([]byte("alice@example.com:jwt-string")))
	require.True(t, ok)
	require.Equal(t, "alice@example.com", u)
	require.Equal(t, "jwt-string", tk)

	_, _, ok = parseBasicAuth("Bearer xyz")
	require.False(t, ok)

	_, _, ok = parseBasicAuth("")
	require.False(t, ok)
}

func TestSettingsFromScopes(t *testing.T) {
	t.Parallel()
	mapping := map[string]map[string]string{
		"mcp:read":  {"readonly": "1"},
		"mcp:write": {"max_memory_usage": "1000000000"},
	}
	got := settingsFromScopes([]string{"mcp:read"}, mapping)
	require.Equal(t, map[string]string{"readonly": "1"}, got)

	got = settingsFromScopes([]string{"unknown"}, mapping)
	require.Nil(t, got)

	got = settingsFromScopes(nil, mapping)
	require.Nil(t, got)
}

func TestLoadConfigDefaults(t *testing.T) {
	t.Parallel()
	cfg := defaultConfig()
	require.Equal(t, "email", cfg.Identity.UsernameClaim)
	require.Equal(t, "lowercase_equal", cfg.Identity.MatchMode)
	require.True(t, cfg.Identity.RequireEmailVerified)
}

func TestValidateConfigRejectsEmpty(t *testing.T) {
	t.Parallel()
	err := validateConfig(&Config{})
	require.Error(t, err)
}

func TestValidateConfigRejectsBothListeners(t *testing.T) {
	t.Parallel()
	err := validateConfig(&Config{
		Listen: ListenConfig{Unix: "/tmp/s", TCP: "127.0.0.1:1"},
		OAuth:  OAuthConfig{Issuer: "https://x", Audience: "a"},
	})
	require.ErrorContains(t, err, "mutually exclusive")
}

func TestValidateConfigRequiresAudience(t *testing.T) {
	t.Parallel()
	err := validateConfig(&Config{
		Listen: ListenConfig{Unix: "/tmp/s"},
		OAuth:  OAuthConfig{Issuer: "https://x"},
	})
	require.ErrorContains(t, err, "audience")
}

// TestTransientErrorSkipsNegativeCache asserts that a JWKS-fetch failure
// (network blip / upstream 5xx) does NOT populate the negative cache, so a
// retry on the next request is allowed to succeed once the upstream recovers.
// Otherwise multi-replica deployments would see asymmetric "one replica
// 403s every request for 5 minutes" failure modes after a single blip.
func TestTransientErrorSkipsNegativeCache(t *testing.T) {
	t.Parallel()
	// Point JWKSURL at a server that returns 503 — the verifier wraps this
	// with oauth.ErrTransient. We don't need to mint a real JWT: the
	// validation fails at the JWKS-fetch step, before signature checks.
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer bad.Close()

	cfg := &Config{
		OAuth: OAuthConfig{
			Issuer:   "https://issuer.example.com",
			JWKSURL:  bad.URL,
			Audience: "ch-jwt-verify.test",
		},
		Identity: IdentityConfig{UsernameClaim: "email", MatchMode: "lowercase_equal"},
		Cache:    CacheConfig{PositiveTTL: 30 * time.Second, NegativeTTL: 5 * time.Minute},
	}
	v := NewVerifier(cfg)

	// Mint a real-shaped JWT against a separate IdP just so the verifier
	// reaches the JWKS-fetch step — sign+aud don't matter because the
	// JWKS endpoint 503s first.
	p := newTestIdP(t)
	tok := p.mintJWT(t, map[string]interface{}{
		"sub":            "u-1",
		"email":          "alice@example.com",
		"email_verified": true,
	})

	_, err := v.verify(context.Background(), "alice@example.com", tok)
	require.Error(t, err)
	require.ErrorIs(t, err, oauth.ErrTransient, "503 from JWKS must surface as transient")

	v.mu.Lock()
	cacheLen := len(v.cache)
	v.mu.Unlock()
	require.Equal(t, 0, cacheLen, "transient errors must not be negative-cached")
}

// TestPermanentErrorIsNegativeCached is the counterpart of the test above:
// permanent rejections (unverified email here) MUST still be cached, since
// the negative cache is what spares the sidecar from re-checking a replayed
// bad token's signature on every request.
func TestPermanentErrorIsNegativeCached(t *testing.T) {
	t.Parallel()
	p := newTestIdP(t)
	v := NewVerifier(baseConfig(p))
	tok := p.mintJWT(t, map[string]interface{}{
		"sub":            "u-1",
		"email":          "alice@example.com",
		"email_verified": false, // → permanent ErrEmailNotVerified
	})

	_, err := v.verify(context.Background(), "alice@example.com", tok)
	require.Error(t, err)
	require.ErrorIs(t, err, oauth.ErrEmailNotVerified)
	require.NotErrorIs(t, err, oauth.ErrTransient)

	v.mu.Lock()
	cacheLen := len(v.cache)
	v.mu.Unlock()
	require.Equal(t, 1, cacheLen, "permanent rejections must populate negative cache")
}

// TestJWKSHealthTracking asserts the underlying pkg/oauth Verifier records
// fetch attempts/successes/errors that the sidecar's /readyz handler
// consumes. We don't HTTP-test /readyz directly because the handler lives in
// main.go and the wiring is trivial — the meaningful contract is the health
// triple's transitions.
func TestJWKSHealthTracking(t *testing.T) {
	t.Parallel()

	t.Run("zero_before_any_fetch", func(t *testing.T) {
		t.Parallel()
		p := newTestIdP(t)
		v := NewVerifier(baseConfig(p))
		lastAttempt, lastSuccess, lastErr := v.JWKSHealth()
		require.True(t, lastAttempt.IsZero())
		require.True(t, lastSuccess.IsZero())
		require.NoError(t, lastErr)
	})

	t.Run("success_marks_both_attempt_and_success", func(t *testing.T) {
		t.Parallel()
		p := newTestIdP(t)
		v := NewVerifier(baseConfig(p))
		tok := p.mintJWT(t, map[string]interface{}{
			"sub":            "u-1",
			"email":          "alice@example.com",
			"email_verified": true,
		})
		_, err := v.verify(context.Background(), "alice@example.com", tok)
		require.NoError(t, err)
		lastAttempt, lastSuccess, lastErr := v.JWKSHealth()
		require.False(t, lastAttempt.IsZero())
		require.False(t, lastSuccess.IsZero())
		require.NoError(t, lastErr)
		require.False(t, lastSuccess.Before(lastAttempt),
			"successful fetch must record success >= attempt")
	})

	t.Run("failure_records_error_with_attempt_after_success", func(t *testing.T) {
		t.Parallel()
		// Point JWKSURL at a server that 503s — the fetch attempt is
		// recorded but lastSuccess stays in the past relative to lastAttempt.
		bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
		}))
		defer bad.Close()
		cfg := &Config{
			OAuth: OAuthConfig{
				Issuer:   "https://issuer.example.com",
				JWKSURL:  bad.URL,
				Audience: "ch-jwt-verify.test",
			},
			Identity: IdentityConfig{UsernameClaim: "email", MatchMode: "lowercase_equal"},
			Cache:    CacheConfig{PositiveTTL: 30 * time.Second, NegativeTTL: 5 * time.Minute},
		}
		v := NewVerifier(cfg)
		p := newTestIdP(t)
		tok := p.mintJWT(t, map[string]interface{}{
			"sub":            "u-1",
			"email":          "alice@example.com",
			"email_verified": true,
		})
		_, err := v.verify(context.Background(), "alice@example.com", tok)
		require.Error(t, err)
		lastAttempt, lastSuccess, lastErr := v.JWKSHealth()
		require.False(t, lastAttempt.IsZero())
		require.True(t, lastSuccess.Before(lastAttempt),
			"after a failed fetch lastSuccess must be older than lastAttempt — that's how /readyz detects unhealthy")
		require.Error(t, lastErr)
	})
}

// noop assertions to keep `context` referenced if the file shrinks.
var _ = context.Background
