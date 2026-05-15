package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/altinity/altinity-mcp/pkg/config"
	"github.com/altinity/altinity-mcp/pkg/jwe_auth"
	altinitymcp "github.com/altinity/altinity-mcp/pkg/server"
	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"
)

// decodeJWTSegment base64url-decodes a JWT segment (header/payload), padding-tolerant.
func decodeJWTSegment(seg string) ([]byte, error) {
	if pad := len(seg) % 4; pad != 0 {
		seg += strings.Repeat("=", 4-pad)
	}
	return base64.URLEncoding.DecodeString(seg)
}

func TestOAuthMCPAuthInjector(t *testing.T) {
	t.Parallel()

	app := &application{
		config: config.Config{
			Server: config.ServerConfig{
				JWE: config.JWEConfig{
					Enabled:      true,
					JWESecretKey: "this-is-a-32-byte-secret-key!!",
					JWTSecretKey: "jwt-secret",
				},
				OAuth: config.OAuthConfig{
					Enabled:             true,
					Mode:                "gating",
					Issuer:              "https://accounts.example.com",
					PublicAuthServerURL: "https://mcp.example.com",
					Audience:            "https://mcp.example.com",
					SigningSecret:     "test-gating-secret-32-byte-key!!",
				},
			},
		},
		mcpServer: altinitymcp.NewClickHouseMCPServer(config.Config{Server: config.ServerConfig{JWE: config.JWEConfig{Enabled: true, JWESecretKey: "this-is-a-32-byte-secret-key!!", JWTSecretKey: "jwt-secret"}, OAuth: config.OAuthConfig{
			Enabled:             true,
			Mode:                "gating",
			Issuer:              "https://accounts.example.com",
			PublicAuthServerURL: "https://mcp.example.com",
			Audience:            "https://mcp.example.com",
			SigningSecret:     "test-gating-secret-32-byte-key!!",
		}}}, "test"),
	}

	jweToken, err := jwe_auth.GenerateJWEToken(map[string]interface{}{"host": "localhost", "port": 8123, "exp": time.Now().Add(time.Hour).Unix()}, []byte("this-is-a-32-byte-secret-key!!"), []byte("jwt-secret"))
	require.NoError(t, err)
	jweTokenWithCredentials, err := jwe_auth.GenerateJWEToken(map[string]interface{}{
		"host":     "localhost",
		"port":     8123,
		"username": "default",
		"password": "secret",
		"exp":      time.Now().Add(time.Hour).Unix(),
	}, []byte("this-is-a-32-byte-secret-key!!"), []byte("jwt-secret"))
	require.NoError(t, err)

	t.Run("missing_oauth_gets_challenge", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodPost, "https://mcp.example.com/"+jweToken, nil)
		req.SetPathValue("token", jweToken)
		rr := httptest.NewRecorder()
		handler := app.createMCPAuthInjector(app.config)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		handler.ServeHTTP(rr, req)
		require.Equal(t, http.StatusUnauthorized, rr.Code)
		require.Contains(t, rr.Header().Get("WWW-Authenticate"), "resource_metadata=")
		require.Contains(t, rr.Header().Get("WWW-Authenticate"), "error=\"invalid_token\"")
	})

	t.Run("jwe_with_credentials_skips_oauth", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodPost, "https://mcp.example.com/"+jweTokenWithCredentials, nil)
		req.SetPathValue("token", jweTokenWithCredentials)
		rr := httptest.NewRecorder()
		called := false
		handler := app.createMCPAuthInjector(app.config)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
			require.Equal(t, jweTokenWithCredentials, r.Context().Value(altinitymcp.JWETokenKey))
			require.Nil(t, r.Context().Value(altinitymcp.OAuthTokenKey))
			w.WriteHeader(http.StatusOK)
		}))
		handler.ServeHTTP(rr, req)
		require.True(t, called)
		require.Equal(t, http.StatusOK, rr.Code)
	})
}

func TestOAuthMCPAuthInjectorForwardModePassesOpaqueBearerToken(t *testing.T) {
	t.Parallel()
	token := "opaque-access-token"
	app := &application{
		config: config.Config{
			Server: config.ServerConfig{
				OAuth: config.OAuthConfig{
					Enabled: true,
					Mode:    "forward",
				},
			},
		},
		mcpServer: altinitymcp.NewClickHouseMCPServer(config.Config{
			Server: config.ServerConfig{
				OAuth: config.OAuthConfig{
					Enabled: true,
					Mode:    "forward",
				},
			},
		}, "test"),
	}

	req := httptest.NewRequest(http.MethodPost, "https://mcp.example.com/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	called := false

	handler := app.createMCPAuthInjector(app.config)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		require.Equal(t, token, r.Context().Value(altinitymcp.OAuthTokenKey))
		require.Nil(t, r.Context().Value(altinitymcp.OAuthClaimsKey))
		w.WriteHeader(http.StatusOK)
	}))

	handler.ServeHTTP(rr, req)
	require.True(t, called)
	require.Equal(t, http.StatusOK, rr.Code)
}

// TestOAuthMCPAuthInjectorForwardModeValidatesJWT is the integration check
// for the C-1 fix: forward mode used to skip ValidateOAuthToken entirely,
// so any string in `Authorization: Bearer …` reached the inner handler
// and was forwarded to ClickHouse. After C-1 the auth layer validates JWT
// bearers when Issuer/JWKSURL is configured and rejects bad ones at 401.
func exchangeOAuthBrowserCode(t *testing.T, app *application, clientID, code, redirectURI, codeVerifier string) *httptest.ResponseRecorder {
	t.Helper()

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", clientID)
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("code_verifier", codeVerifier)

	req := httptest.NewRequest(http.MethodPost, "https://mcp.example.com/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	app.handleOAuthToken(rr, req)
	return rr
}

// TestOAuthForwardModeTokenResourceMismatch pins the RFC 8707 §2.2 enforcement
// in forward mode: a /token (auth-code grant) request whose `resource` differs
// from the one already pinned at /authorize must be rejected with
// invalid_target, regardless of which mode we're running in.
func generateOAuthTokenForApp(claims map[string]interface{}) (string, error) {
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	hashedSecret := jwe_auth.HashSHA256([]byte("test-gating-secret-32-byte-key!!"))
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: hashedSecret}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		return "", err
	}
	object, err := signer.Sign(payload)
	if err != nil {
		return "", err
	}
	return object.CompactSerialize()
}

func TestCanonicalResourceURL(t *testing.T) {
	t.Parallel()
	cases := []struct{ in, want string }{
		{"", ""},
		{"  ", ""},
		{"https://mcp.example.com", "https://mcp.example.com/"},
		{"https://mcp.example.com/", "https://mcp.example.com/"},
		{"https://mcp.example.com//", "https://mcp.example.com/"},
		{"  https://mcp.example.com  ", "https://mcp.example.com/"},
		{"https://mcp.example.com/path", "https://mcp.example.com/path/"},
		{"https://mcp.example.com/path/", "https://mcp.example.com/path/"},
	}
	for _, c := range cases {
		require.Equal(t, c.want, canonicalResourceURL(c.in), "input=%q", c.in)
	}
}

// newJWEStateTestApp builds a minimal application wired with a SigningSecret
// for exercising the stateless JWE encode/decode helpers in isolation.
func newJWEStateTestApp(secret string) *application {
	cfg := config.Config{
		Server: config.ServerConfig{
			OAuth: config.OAuthConfig{
				Enabled:       true,
				SigningSecret: secret,
			},
		},
	}
	return &application{config: cfg}
}

// newGatingModeTestApp creates an application configured for gating mode OAuth.
// doGatingAuthCodeFlow runs the full authorize→callback→token exchange and
// returns the parsed token response.
func exchangeRefreshToken(t *testing.T, app *application, clientID, refreshToken string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("client_id", clientID)
	form.Set("refresh_token", refreshToken)

	req := httptest.NewRequest(http.MethodPost, "https://mcp.example.com/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	app.handleOAuthToken(rr, req)
	return rr
}

// newForwardModeRefreshTestApp configures a forward-mode app with
// UpstreamOfflineAccess enabled, so the auth-code response carries a JWE
// refresh_token wrapping the upstream IdP's refresh token.
func TestNormalizedPath(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		raw      string
		fallback string
		want     string
	}{
		{"empty_both", "", "", ""},
		{"empty_raw_uses_fallback", "", "/fallback", "/fallback"},
		{"whitespace_raw_uses_fallback", "   ", "/fb", "/fb"},
		{"root_path", "/", "", "/"},
		{"adds_leading_slash", "path", "", "/path"},
		{"trims_trailing_slash", "/path/", "", "/path"},
		{"normal_path", "/api/v1", "", "/api/v1"},
		{"multiple_trailing_slashes", "/path///", "", "/path"},
		{"fallback_without_slash", "", "fallback", "/fallback"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tt.want, normalizedPath(tt.raw, tt.fallback))
		})
	}
}

func TestJoinURLPath(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		base string
		path string
		want string
	}{
		{"empty_path", "https://example.com", "", "https://example.com"},
		{"root_path", "https://example.com", "/", "https://example.com"},
		{"normal_join", "https://example.com", "/api", "https://example.com/api"},
		{"base_with_trailing_slash", "https://example.com/", "/api", "https://example.com/api"},
		{"path_without_leading_slash", "https://example.com", "api", "https://example.com/api"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tt.want, joinURLPath(tt.base, tt.path))
		})
	}
}

func TestUniquePaths(t *testing.T) {
	t.Parallel()
	t.Run("all_unique", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, []string{"/a", "/b", "/c"}, uniquePaths("/a", "/b", "/c"))
	})
	t.Run("duplicates_removed", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, []string{"/a"}, uniquePaths("/a", "/a", "/a"))
	})
	t.Run("empty_paths_skipped", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, []string{"/a"}, uniquePaths("", "/a", ""))
	})
	t.Run("all_empty", func(t *testing.T) {
		t.Parallel()
		require.Empty(t, uniquePaths("", "", ""))
	})
	t.Run("normalized_duplicates", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, []string{"/path"}, uniquePaths("/path/", "/path"))
	})
}

func TestSuffixPrefix(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		path    string
		markers []string
		want    string
	}{
		{"extract_suffix", "/api/.well-known/resource", []string{"/api"}, "/.well-known/resource"},
		{"no_match", "/path/resource", []string{"/nomatch"}, ""},
		{"exact_marker_no_suffix", "/api", []string{"/api"}, ""},
		{"multiple_markers", "/prefix/resource", []string{"/a", "/b", "/prefix"}, "/resource"},
		{"suffix_gets_leading_slash", "/apistuff", []string{"/api"}, "/stuff"},
		{"trailing_slash_removed", "/api/resource/", []string{"/api"}, "/resource"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tt.want, suffixPrefix(tt.path, tt.markers...))
		})
	}
}

func TestPathFromConfiguredURL(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{"empty", "", ""},
		{"no_path", "https://example.com", ""},
		{"with_path", "https://example.com/api", "/api"},
		{"trailing_slash", "https://example.com/api/", "/api"},
		{"just_path", "/api/v1", "/api/v1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tt.want, pathFromConfiguredURL(tt.raw))
		})
	}
}

func TestTruncateForLog(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		value string
		max   int
		want  string
	}{
		{"negative_max", "hello", -1, "hello"},
		{"zero_max", "hello", 0, "hello"},
		{"shorter_than_max", "hello", 10, "hello"},
		{"exact_max", "hello", 5, "hello"},
		{"truncated", "hello world", 5, "hello"},
		{"empty_string", "", 10, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tt.want, truncateForLog(tt.value, tt.max))
		})
	}
}

func TestOAuthClaimsFromUserInfo(t *testing.T) {
	t.Parallel()
	t.Run("all_standard_fields", func(t *testing.T) {
		t.Parallel()
		raw := map[string]interface{}{
			"sub":            "user-123",
			"iss":            "https://issuer.example.com",
			"email":          "user@example.com",
			"name":           "Test User",
			"hd":             "example.com",
			"email_verified": true,
			"scope":          "read write",
		}
		claims := oauthClaimsFromUserInfo(raw)
		require.Equal(t, "user-123", claims.Subject)
		require.Equal(t, "https://issuer.example.com", claims.Issuer)
		require.Equal(t, "user@example.com", claims.Email)
		require.Equal(t, "Test User", claims.Name)
		require.Equal(t, "example.com", claims.HostedDomain)
		require.True(t, claims.EmailVerified)
		require.Equal(t, []string{"read", "write"}, claims.Scopes)
	})

	t.Run("extra_claims_preserved", func(t *testing.T) {
		t.Parallel()
		raw := map[string]interface{}{
			"sub":    "user-123",
			"custom": "value",
			"groups": []string{"admin"},
		}
		claims := oauthClaimsFromUserInfo(raw)
		require.Equal(t, "value", claims.Extra["custom"])
		require.NotNil(t, claims.Extra["groups"])
	})

	t.Run("empty_input", func(t *testing.T) {
		t.Parallel()
		claims := oauthClaimsFromUserInfo(map[string]interface{}{})
		require.Equal(t, "", claims.Subject)
		require.Empty(t, claims.Extra)
	})
}

func TestNormalizeURL(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{"empty", "", ""},
		{"no_trailing_slash", "https://example.com", "https://example.com"},
		{"trailing_slash", "https://example.com/", "https://example.com"},
		{"whitespace", "  https://example.com  ", "https://example.com"},
		{"multiple_trailing_slashes", "https://example.com///", "https://example.com"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tt.want, normalizeURL(tt.raw))
		})
	}
}

func TestSanitizeScope(t *testing.T) {
	t.Parallel()
	require.Equal(t, "read write", sanitizeScope("  read   write  "))
	require.Equal(t, "single", sanitizeScope("single"))
	require.Equal(t, "", sanitizeScope(""))
	require.Equal(t, "", sanitizeScope("   "))
}

func TestNormalizeUpstreamScopeForClient(t *testing.T) {
	t.Parallel()

	t.Run("google_uri_form_collapses_to_oidc_names", func(t *testing.T) {
		t.Parallel()
		got := normalizeUpstreamScopeForClient("openid https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile")
		require.Equal(t, "openid email profile", got)
	})

	t.Run("already_normalised_passthrough", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, "openid email profile", normalizeUpstreamScopeForClient("openid email profile"))
	})

	t.Run("empty_input_empty_output", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, "", normalizeUpstreamScopeForClient(""))
		require.Equal(t, "", normalizeUpstreamScopeForClient("   "))
	})

	t.Run("unknown_scopes_pass_through", func(t *testing.T) {
		t.Parallel()
		// We only collapse the 3 known Google OIDC aliases; everything else
		// passes through verbatim (including non-Google URI scopes that we
		// don't have a mapping for and arbitrary custom scopes).
		got := normalizeUpstreamScopeForClient("openid offline_access https://example.com/auth/custom mcp:read")
		require.Equal(t, "openid offline_access https://example.com/auth/custom mcp:read", got)
	})

	t.Run("dedup_after_mapping", func(t *testing.T) {
		t.Parallel()
		// "email" + ".../userinfo.email" both map to "email" — dedup keeps one.
		got := normalizeUpstreamScopeForClient("email https://www.googleapis.com/auth/userinfo.email")
		require.Equal(t, "email", got)
	})

	t.Run("openid_uri_alias_collapses", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, "openid", normalizeUpstreamScopeForClient("https://www.googleapis.com/auth/openid"))
	})

	t.Run("preserves_order", func(t *testing.T) {
		t.Parallel()
		// First occurrence of each unique mapped name wins, original order kept.
		got := normalizeUpstreamScopeForClient("profile https://www.googleapis.com/auth/userinfo.email openid")
		require.Equal(t, "profile email openid", got)
	})
}

func TestOidcScopesForAdvertisement(t *testing.T) {
	t.Parallel()

	t.Run("google_three_oidc_scopes_pass_through", func(t *testing.T) {
		t.Parallel()
		got := oidcScopesForAdvertisement(config.OAuthConfig{Scopes: []string{"openid", "email", "profile"}})
		require.Equal(t, []string{"openid", "email", "profile"}, got)
	})

	t.Run("auth0_with_offline_access_passes_through", func(t *testing.T) {
		t.Parallel()
		// Auth0 production antalya-mcp depends on advertising offline_access
		// to receive refresh tokens. The allowlist must include it.
		got := oidcScopesForAdvertisement(config.OAuthConfig{Scopes: []string{"openid", "email", "profile", "offline_access"}})
		require.Equal(t, []string{"openid", "email", "profile", "offline_access"}, got)
	})

	t.Run("google_api_uri_filtered_out", func(t *testing.T) {
		t.Parallel()
		got := oidcScopesForAdvertisement(config.OAuthConfig{Scopes: []string{"openid", "https://www.googleapis.com/auth/calendar", "email"}})
		require.Equal(t, []string{"openid", "email"}, got)
	})

	t.Run("custom_mcp_scope_filtered_out", func(t *testing.T) {
		t.Parallel()
		// Custom resource-server scopes (mcp:read, mcp:write, calendar.list)
		// are filtered out because scope-based tool authorization is not
		// exercised anywhere in altinity-mcp today. If/when it lands, extend
		// the allowlist in oidcScopesForAdvertisement.
		got := oidcScopesForAdvertisement(config.OAuthConfig{Scopes: []string{"openid", "mcp:read", "mcp:write", "calendar.list"}})
		require.Equal(t, []string{"openid"}, got)
	})

	t.Run("empty_input_empty_output", func(t *testing.T) {
		t.Parallel()
		got := oidcScopesForAdvertisement(config.OAuthConfig{Scopes: nil})
		require.Empty(t, got)
		got = oidcScopesForAdvertisement(config.OAuthConfig{Scopes: []string{}})
		require.Empty(t, got)
	})

	t.Run("duplicates_collapsed", func(t *testing.T) {
		t.Parallel()
		got := oidcScopesForAdvertisement(config.OAuthConfig{Scopes: []string{"openid", "openid", "email"}})
		require.Equal(t, []string{"openid", "email"}, got)
	})

	t.Run("order_preserved", func(t *testing.T) {
		t.Parallel()
		got := oidcScopesForAdvertisement(config.OAuthConfig{Scopes: []string{"profile", "openid", "email"}})
		require.Equal(t, []string{"profile", "openid", "email"}, got)
	})
}

func TestPkceChallenge(t *testing.T) {
	t.Parallel()
	// Deterministic test: given a known verifier, check output matches SHA256(verifier) base64url
	challenge := pkceChallenge("test-verifier")
	require.NotEmpty(t, challenge)
	// Same input produces same output
	require.Equal(t, challenge, pkceChallenge("test-verifier"))
	// Different input produces different output
	require.NotEqual(t, challenge, pkceChallenge("other-verifier"))
}

func TestSafeUpstreamErrorFields(t *testing.T) {
	t.Parallel()
	t.Run("rfc6749_error_response_extracts_code", func(t *testing.T) {
		t.Parallel()
		body := []byte(`{"error":"invalid_grant","error_description":"refresh_token=secret123 has expired"}`)
		errCode, length := safeUpstreamErrorFields(body)
		require.Equal(t, "invalid_grant", errCode)
		require.Equal(t, len(body), length)
	})
	t.Run("non_json_body_returns_blank_code", func(t *testing.T) {
		t.Parallel()
		body := []byte(`<html>502 Bad Gateway: secret123 was here</html>`)
		errCode, length := safeUpstreamErrorFields(body)
		require.Equal(t, "", errCode, "non-JSON body must not leak content into errCode")
		require.Equal(t, len(body), length)
	})
	t.Run("empty_body", func(t *testing.T) {
		t.Parallel()
		errCode, length := safeUpstreamErrorFields(nil)
		require.Equal(t, "", errCode)
		require.Equal(t, 0, length)
	})
	t.Run("json_without_error_field", func(t *testing.T) {
		t.Parallel()
		body := []byte(`{"other":"thing"}`)
		errCode, length := safeUpstreamErrorFields(body)
		require.Equal(t, "", errCode)
		require.Equal(t, len(body), length)
	})
}

func TestTtlSeconds(t *testing.T) {
	t.Parallel()
	require.Equal(t, 100, ttlSeconds(100, 60))
	require.Equal(t, 60, ttlSeconds(0, 60))
	require.Equal(t, 60, ttlSeconds(-1, 60))
}

func TestWriteOAuthTokenError(t *testing.T) {
	t.Parallel()
	t.Run("400 has no WWW-Authenticate", func(t *testing.T) {
		t.Parallel()
		rr := httptest.NewRecorder()
		writeOAuthTokenError(rr, http.StatusBadRequest, "invalid_request", "bad thing happened")
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Equal(t, "application/json", rr.Header().Get("Content-Type"))
		require.Empty(t, rr.Header().Get("WWW-Authenticate"), "non-401 responses must not advertise an auth challenge")
		var body map[string]string
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
		require.Equal(t, "invalid_request", body["error"])
		require.Equal(t, "bad thing happened", body["error_description"])
	})
	t.Run("401 carries Bearer challenge per RFC 7235 §3.1", func(t *testing.T) {
		t.Parallel()
		rr := httptest.NewRecorder()
		writeOAuthTokenError(rr, http.StatusUnauthorized, "invalid_client", "unknown OAuth client")
		require.Equal(t, http.StatusUnauthorized, rr.Code)
		challenge := rr.Header().Get("WWW-Authenticate")
		require.NotEmpty(t, challenge, "401 responses MUST carry WWW-Authenticate")
		require.Contains(t, challenge, "Bearer ")
		require.Contains(t, challenge, `error="invalid_client"`)
		require.Contains(t, challenge, `error_description="unknown OAuth client"`)
	})
}

// TestOAuthAuthorizeErrorsAreJSON pins F1 from the post-merge review: every
// 4xx/5xx error response from /oauth/authorize and /oauth/callback returns
// the RFC 6749 §5.2 JSON shape (application/json + error/error_description),
// never the bare text/plain Go default that http.Error produces. Regression
// guard for the high-severity finding.
func TestOAuthAuthorizeErrorsAreJSON(t *testing.T) {
	t.Parallel()
	app := &application{
		config: config.Config{Server: config.ServerConfig{OAuth: config.OAuthConfig{
			Enabled:             true,
			Mode:                "forward",
			Issuer:              "https://idp.example.com",
			PublicAuthServerURL: "https://mcp.example.com",
			SigningSecret:       "regression-f1-jsonerr-32bytes!!!!",
		}}},
	}

	t.Run("/authorize missing params → JSON invalid_request", func(t *testing.T) {
		t.Parallel()
		rr := httptest.NewRecorder()
		app.handleOAuthAuthorize(rr, httptest.NewRequest(http.MethodGet, "https://mcp.example.com/oauth/authorize", nil))
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Equal(t, "application/json", rr.Header().Get("Content-Type"))
		var body map[string]string
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
		require.Equal(t, "invalid_request", body["error"])
	})

	t.Run("/authorize wrong method → JSON invalid_request", func(t *testing.T) {
		t.Parallel()
		rr := httptest.NewRecorder()
		app.handleOAuthAuthorize(rr, httptest.NewRequest(http.MethodPost, "https://mcp.example.com/oauth/authorize", nil))
		require.Equal(t, http.StatusMethodNotAllowed, rr.Code)
		require.Equal(t, "application/json", rr.Header().Get("Content-Type"))
		var body map[string]string
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
		require.Equal(t, "invalid_request", body["error"])
	})

	t.Run("/callback missing state+code → JSON invalid_request", func(t *testing.T) {
		t.Parallel()
		rr := httptest.NewRecorder()
		app.handleOAuthCallback(rr, httptest.NewRequest(http.MethodGet, "https://mcp.example.com/oauth/callback", nil))
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Equal(t, "application/json", rr.Header().Get("Content-Type"))
		var body map[string]string
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
		require.Equal(t, "invalid_request", body["error"])
	})

	t.Run("/callback bogus state → JSON invalid_request", func(t *testing.T) {
		t.Parallel()
		rr := httptest.NewRecorder()
		app.handleOAuthCallback(rr, httptest.NewRequest(http.MethodGet, "https://mcp.example.com/oauth/callback?state=bogus&code=x", nil))
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Equal(t, "application/json", rr.Header().Get("Content-Type"))
		var body map[string]string
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
		require.Equal(t, "invalid_request", body["error"])
	})
}

