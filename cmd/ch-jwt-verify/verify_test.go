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

// noop assertions to keep `context` referenced if the file shrinks.
var _ = context.Background
