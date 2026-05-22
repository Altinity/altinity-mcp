package oauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"
)

// encodeOIDC returns a JSON-encodable discovery document with the PKCE
// methods go-sdk's auth.GetAuthServerMetadata requires.
func encodeOIDC(issuer, jwksURI string) map[string]interface{} {
	return map[string]interface{}{
		"issuer":                                issuer,
		"jwks_uri":                              jwksURI,
		"response_types_supported":              []string{"code"},
		"code_challenge_methods_supported":      []string{"S256"},
		"authorization_endpoint":                issuer + "/authorize",
		"token_endpoint":                        issuer + "/token",
		"id_token_signing_alg_values_supported": []string{"RS256"},
	}
}

func TestResolveJWKSURL(t *testing.T) {
	t.Parallel()
	t.Run("direct_jwks_url_configured", func(t *testing.T) {
		t.Parallel()
		v := NewVerifier(OAuthConfig{
			JWKSURL: "https://auth.example.com/jwks",
		})
		url, err := v.resolveJWKSURL(context.Background())
		require.NoError(t, err)
		require.Equal(t, "https://auth.example.com/jwks", url)
	})

	t.Run("openid_configuration_discovery", func(t *testing.T) {
		t.Parallel()
		var mockURL string
		mux := http.NewServeMux()
		mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(encodeOIDC(mockURL, mockURL+"/keys"))
		})
		mockServer := httptest.NewServer(mux)
		defer mockServer.Close()
		mockURL = mockServer.URL

		v := NewVerifier(OAuthConfig{Issuer: mockURL})
		url, err := v.resolveJWKSURL(context.Background())
		require.NoError(t, err)
		require.Equal(t, mockURL+"/keys", url)
	})

	t.Run("oauth_authorization_server_discovery", func(t *testing.T) {
		t.Parallel()
		// go-sdk tries oauth-authorization-server first, falling through to
		// openid-configuration on 404. Same shape works for both — pick one.
		var mockURL string
		mux := http.NewServeMux()
		mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(encodeOIDC(mockURL, mockURL+"/fallback-keys"))
		})
		mockServer := httptest.NewServer(mux)
		defer mockServer.Close()
		mockURL = mockServer.URL

		v := NewVerifier(OAuthConfig{Issuer: mockURL})
		url, err := v.resolveJWKSURL(context.Background())
		require.NoError(t, err)
		require.Equal(t, mockURL+"/fallback-keys", url)
	})

	t.Run("both_discovery_endpoints_fail", func(t *testing.T) {
		t.Parallel()
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.NotFound(w, r)
		}))
		defer mockServer.Close()

		v := NewVerifier(OAuthConfig{Issuer: mockServer.URL})
		_, err := v.resolveJWKSURL(context.Background())
		require.Error(t, err)
	})

	t.Run("missing_jwks_uri_in_metadata", func(t *testing.T) {
		t.Parallel()
		// auth.GetAuthServerMetadata returns an error if the issuer in the
		// metadata document does not match the issuer URL or if PKCE is
		// missing; emit a document that satisfies discovery but lacks
		// jwks_uri to exercise the Verifier's "missing jwks_uri" branch.
		var mockURL string
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"issuer":                                mockURL,
				"response_types_supported":              []string{"code"},
				"code_challenge_methods_supported":      []string{"S256"},
				"authorization_endpoint":                mockURL + "/authorize",
				"token_endpoint":                        mockURL + "/token",
				"id_token_signing_alg_values_supported": []string{"RS256"},
			})
		}))
		defer mockServer.Close()
		mockURL = mockServer.URL

		v := NewVerifier(OAuthConfig{Issuer: mockURL})
		_, err := v.resolveJWKSURL(context.Background())
		require.Error(t, err)
		require.Contains(t, err.Error(), "jwks_uri")
	})
}

func TestAuthServerMetaCaching(t *testing.T) {
	t.Parallel()
	var requestCount int
	var mockURL string
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(encodeOIDC(mockURL, mockURL+"/keys"))
	})
	// Respond to the other well-known so go-sdk's first-try doesn't error.
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	mockServer := httptest.NewServer(mux)
	defer mockServer.Close()
	mockURL = mockServer.URL

	v := NewVerifier(OAuthConfig{Issuer: mockURL})

	t.Run("cache_hit_within_ttl", func(t *testing.T) {
		requestCount = 0
		_, err := v.FetchAuthServerMeta(context.Background(), mockURL)
		require.NoError(t, err)
		_, err = v.FetchAuthServerMeta(context.Background(), mockURL)
		require.NoError(t, err)
		require.Equal(t, 1, requestCount, "second call should hit cache")
	})

	t.Run("cache_miss_after_ttl_expires", func(t *testing.T) {
		_, err := v.FetchAuthServerMeta(context.Background(), mockURL)
		require.NoError(t, err)

		v.asMetaMu.Lock()
		v.asMetaExpiresAt = time.Now().Add(-time.Second) // already expired
		v.asMetaMu.Unlock()

		countBefore := requestCount
		_, err = v.FetchAuthServerMeta(context.Background(), mockURL)
		require.NoError(t, err)
		require.Equal(t, countBefore+1, requestCount, "should re-fetch after TTL expiry")
	})
}

// TestJWKSCacheTTLConfigured asserts that a non-zero OAuthConfig.JWKSCacheTTL
// is the cache TTL the Verifier actually applies (not the 5-minute default).
// Before this was wired up, the field was parsed from YAML but silently
// ignored — see docs/ch-jwt-verify.md "Multi-replica behavior". The check is
// against the deadline the writer stamps into asMetaExpiresAt because that's
// where the (jittered) configured TTL becomes observable.
func TestJWKSCacheTTLConfigured(t *testing.T) {
	t.Parallel()
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(encodeOIDC("http://"+r.Host, "http://"+r.Host+"/jwks"))
	})
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	mockServer := httptest.NewServer(mux)
	defer mockServer.Close()

	const configuredTTL = time.Minute
	v := NewVerifier(OAuthConfig{
		Issuer:       mockServer.URL,
		JWKSCacheTTL: configuredTTL,
	})
	require.Equal(t, configuredTTL, v.jwksCacheTTL(), "configured TTL must surface via the helper")

	before := time.Now()
	_, err := v.FetchAuthServerMeta(context.Background(), mockServer.URL)
	require.NoError(t, err)

	v.asMetaMu.RLock()
	expiresAt := v.asMetaExpiresAt
	v.asMetaMu.RUnlock()

	// expiresAt should be `before + configuredTTL + jitter` where jitter
	// is in [-TTL/10, +TTL/10]. Crucially, it must be well below the
	// 5-minute default — that's the regression this test guards.
	delta := expiresAt.Sub(before)
	require.Greater(t, delta, configuredTTL-configuredTTL/10-time.Second,
		"expiresAt under-shoots configured TTL minus jitter")
	require.Less(t, delta, configuredTTL+configuredTTL/10+time.Second,
		"expiresAt over-shoots configured TTL plus jitter — looks like the 5m default is still applied")
}

// TestJWKSCacheTTLDefault asserts that a zero OAuthConfig.JWKSCacheTTL falls
// back to the package default (5 minutes), preserving prior behavior for
// callers (pkg/server, broker) that haven't started passing the new field.
func TestJWKSCacheTTLDefault(t *testing.T) {
	t.Parallel()
	v := NewVerifier(OAuthConfig{})
	require.Equal(t, jwksCacheTTL, v.jwksCacheTTL(), "zero TTL must fall back to default")
}

func TestParseAndVerifyExternalJWTUnknownKid(t *testing.T) {
	t.Parallel()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	knownJWK := jose.JSONWebKey{Key: &privateKey.PublicKey, KeyID: "known", Algorithm: "RS256", Use: "sig"}
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/jwks" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{knownJWK}})
			return
		}
		http.NotFound(w, r)
	}))
	defer mockServer.Close()

	v := NewVerifier(OAuthConfig{
		Issuer:  mockServer.URL,
		JWKSURL: mockServer.URL + "/jwks",
	})

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: privateKey},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "unknown"),
	)
	require.NoError(t, err)

	payload, err := json.Marshal(map[string]interface{}{
		"sub": "user-1",
		"iss": mockServer.URL,
		"aud": "test-audience",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	})
	require.NoError(t, err)

	object, err := signer.Sign(payload)
	require.NoError(t, err)
	token, err := object.CompactSerialize()
	require.NoError(t, err)

	_, err = v.parseAndVerifyExternalJWT(context.Background(), token, "test-audience")
	require.Error(t, err)
	require.Contains(t, err.Error(), "no JWK found for kid")
}

// TestJWKSRefetchOnKidMiss verifies that a kid absent from the cached JWKS
// triggers a one-shot cache-bypass re-fetch, allowing tokens issued after a
// key rotation to be accepted without waiting for the TTL to expire.
func TestJWKSRefetchOnKidMiss(t *testing.T) {
	t.Parallel()

	oldKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	newKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	const oldKid = "old-signing-key"
	const newKid = "new-signing-key"

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/jwks":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
				{Key: &newKey.PublicKey, KeyID: newKid, Algorithm: "RS256", Use: "sig"},
			}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer mockServer.Close()

	v := NewVerifier(OAuthConfig{
		Issuer:  mockServer.URL,
		JWKSURL: mockServer.URL + "/jwks",
	})

	// Seed the JWKS cache with the old key and a far-future TTL so that a
	// normal fetch would not re-fetch.
	v.jwksMu.Lock()
	v.jwksCache = jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{Key: &oldKey.PublicKey, KeyID: oldKid, Algorithm: "RS256", Use: "sig"},
	}}
	v.jwksCacheURL = mockServer.URL + "/jwks"
	v.jwksCacheExpiresAt = time.Now().Add(10 * time.Minute)
	v.jwksMu.Unlock()

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: newKey},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", newKid),
	)
	require.NoError(t, err)
	payload, err := json.Marshal(map[string]interface{}{
		"sub": "user-1",
		"iss": mockServer.URL,
		"aud": "test-audience",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	})
	require.NoError(t, err)
	obj, err := signer.Sign(payload)
	require.NoError(t, err)
	token, err := obj.CompactSerialize()
	require.NoError(t, err)

	claims, err := v.parseAndVerifyExternalJWT(context.Background(), token, "test-audience")
	require.NoError(t, err)
	require.Equal(t, "user-1", claims.Subject)
}

func TestEmailDomain(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		email string
		want  string
	}{
		{"normal", "user@example.com", "example.com"},
		{"uppercase", "User@EXAMPLE.COM", "example.com"},
		{"whitespace", "  user@example.com  ", "example.com"},
		{"no_at", "noatsign", ""},
		{"empty", "", ""},
		{"multiple_at", "a@b@c", ""},
		{"just_at", "@", ""},
		{"domain_only", "@domain.com", "domain.com"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tt.want, EmailDomain(tt.email))
		})
	}
}

func TestClaimsFromRawClaims(t *testing.T) {
	t.Parallel()

	t.Run("all_standard_fields", func(t *testing.T) {
		t.Parallel()
		raw := map[string]interface{}{
			"sub":            "user123",
			"iss":            "https://auth.example.com",
			"exp":            float64(1700000000),
			"iat":            float64(1699999000),
			"nbf":            float64(1699998000),
			"email":          "user@example.com",
			"name":           "Test User",
			"hd":             "example.com",
			"email_verified": true,
			"aud":            "my-api",
			"scope":          "read write",
		}
		claims := claimsFromRawClaims(raw)
		require.Equal(t, "user123", claims.Subject)
		require.Equal(t, "https://auth.example.com", claims.Issuer)
		require.Equal(t, int64(1700000000), claims.ExpiresAt)
		require.Equal(t, int64(1699999000), claims.IssuedAt)
		require.Equal(t, int64(1699998000), claims.NotBefore)
		require.Equal(t, "user@example.com", claims.Email)
		require.Equal(t, "Test User", claims.Name)
		require.Equal(t, "example.com", claims.HostedDomain)
		require.True(t, claims.EmailVerified)
		require.Equal(t, []string{"my-api"}, claims.Audience)
		require.Equal(t, []string{"read", "write"}, claims.Scopes)
	})

	t.Run("json_number_fields", func(t *testing.T) {
		t.Parallel()
		raw := map[string]interface{}{
			"sub": "user",
			"exp": json.Number("1700000000"),
			"iat": json.Number("1699999000"),
			"nbf": json.Number("1699998000"),
		}
		claims := claimsFromRawClaims(raw)
		require.Equal(t, int64(1700000000), claims.ExpiresAt)
		require.Equal(t, int64(1699999000), claims.IssuedAt)
		require.Equal(t, int64(1699998000), claims.NotBefore)
	})

	t.Run("audience_array", func(t *testing.T) {
		t.Parallel()
		raw := map[string]interface{}{
			"aud": []interface{}{"api1", "api2"},
		}
		claims := claimsFromRawClaims(raw)
		require.Equal(t, []string{"api1", "api2"}, claims.Audience)
	})

	t.Run("scope_array", func(t *testing.T) {
		t.Parallel()
		raw := map[string]interface{}{
			"scope": []interface{}{"read", "write", "admin"},
		}
		claims := claimsFromRawClaims(raw)
		require.Equal(t, []string{"read", "write", "admin"}, claims.Scopes)
	})

	t.Run("email_verified_string", func(t *testing.T) {
		t.Parallel()
		raw := map[string]interface{}{
			"email_verified": "true",
		}
		claims := claimsFromRawClaims(raw)
		require.True(t, claims.EmailVerified)

		raw2 := map[string]interface{}{
			"email_verified": "false",
		}
		claims2 := claimsFromRawClaims(raw2)
		require.False(t, claims2.EmailVerified)
	})

	t.Run("extra_claims_preserved", func(t *testing.T) {
		t.Parallel()
		raw := map[string]interface{}{
			"sub":        "user",
			"custom1":    "value1",
			"custom_num": float64(42),
		}
		claims := claimsFromRawClaims(raw)
		require.Equal(t, "value1", claims.Extra["custom1"])
		require.Equal(t, float64(42), claims.Extra["custom_num"])
		_, hasSub := claims.Extra["sub"]
		require.False(t, hasSub)
	})

	t.Run("empty_claims", func(t *testing.T) {
		t.Parallel()
		claims := claimsFromRawClaims(map[string]interface{}{})
		require.NotNil(t, claims)
		require.Empty(t, claims.Subject)
		require.NotNil(t, claims.Extra)
	})
}

func TestLooksLikeJWT(t *testing.T) {
	t.Parallel()
	require.True(t, looksLikeJWT("a.b.c"))
	require.False(t, looksLikeJWT("not-a-jwt"))
	require.False(t, looksLikeJWT("a.b"))
	require.False(t, looksLikeJWT("a.b.c.d"))
}

func TestHasRequiredScopes(t *testing.T) {
	t.Parallel()
	require.True(t, HasRequiredScopes([]string{"read", "write", "admin"}, []string{"read", "write"}))
	require.False(t, HasRequiredScopes([]string{"read"}, []string{"read", "admin"}))
	require.True(t, HasRequiredScopes([]string{"read"}, []string{}))
	require.True(t, HasRequiredScopes([]string{}, []string{}))
	require.False(t, HasRequiredScopes([]string{}, []string{"read"}))
}

func TestValidateClaims(t *testing.T) {
	t.Parallel()

	t.Run("audience_missing_when_required", func(t *testing.T) {
		t.Parallel()
		v := NewVerifier(OAuthConfig{Audience: "my-audience"})
		_, err := v.validateClaims(&Claims{})
		require.ErrorIs(t, err, ErrInvalidToken)
	})

	t.Run("audience_mismatch", func(t *testing.T) {
		t.Parallel()
		v := NewVerifier(OAuthConfig{Audience: "my-audience"})
		_, err := v.validateClaims(&Claims{Audience: []string{"wrong-audience"}})
		require.ErrorIs(t, err, ErrInvalidToken)
	})

	t.Run("audience_trailing_slash_tolerant", func(t *testing.T) {
		t.Parallel()
		v := NewVerifier(OAuthConfig{Audience: "https://mcp.example.com"})
		_, err := v.validateClaims(&Claims{
			Audience:  []string{"https://mcp.example.com/"},
			ExpiresAt: time.Now().Unix() + 300,
		})
		require.NoError(t, err)

		v = NewVerifier(OAuthConfig{Audience: "https://mcp.example.com/"})
		_, err = v.validateClaims(&Claims{
			Audience:  []string{"https://mcp.example.com"},
			ExpiresAt: time.Now().Unix() + 300,
		})
		require.NoError(t, err)
	})

	t.Run("token_expired", func(t *testing.T) {
		t.Parallel()
		v := NewVerifier(OAuthConfig{})
		_, err := v.validateClaims(&Claims{ExpiresAt: time.Now().Unix() - 300})
		require.ErrorIs(t, err, ErrTokenExpired)
	})

	t.Run("not_yet_valid", func(t *testing.T) {
		t.Parallel()
		v := NewVerifier(OAuthConfig{})
		_, err := v.validateClaims(&Claims{NotBefore: time.Now().Unix() + 300})
		require.ErrorIs(t, err, ErrInvalidToken)
	})

	t.Run("issued_in_future", func(t *testing.T) {
		t.Parallel()
		v := NewVerifier(OAuthConfig{})
		_, err := v.validateClaims(&Claims{IssuedAt: time.Now().Unix() + 300})
		require.ErrorIs(t, err, ErrInvalidToken)
	})

	t.Run("missing_required_scopes", func(t *testing.T) {
		t.Parallel()
		v := NewVerifier(OAuthConfig{RequiredScopes: []string{"admin"}})
		_, err := v.validateClaims(&Claims{Scopes: []string{"read"}})
		require.ErrorIs(t, err, ErrInsufficientScopes)
	})

	t.Run("valid_claims", func(t *testing.T) {
		t.Parallel()
		v := NewVerifier(OAuthConfig{
			Issuer:         "https://issuer.example.com",
			Audience:       "my-aud",
			RequiredScopes: []string{"read"},
		})
		claims, err := v.validateClaims(&Claims{
			Issuer:    "https://issuer.example.com",
			Audience:  []string{"my-aud"},
			ExpiresAt: time.Now().Unix() + 300,
			Scopes:    []string{"read", "write"},
		})
		require.NoError(t, err)
		require.Equal(t, "https://issuer.example.com", claims.Issuer)
	})
}
