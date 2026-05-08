package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/altinity/altinity-mcp/pkg/config"
	"github.com/altinity/altinity-mcp/pkg/jwe_auth"
	"github.com/altinity/altinity-mcp/pkg/oauth_state"
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

// TestOAuthJWEHKDFRoundtripAndLegacyFallback covers the v1 (HKDF) ↔ legacy
// (SHA256) compatibility surface introduced in Step 2 of the OAuth review.
// Three invariants:
//
//  1. Newly-issued artifacts emit kid="v1" in the JWE/JWS header.
//  2. v1 artifacts decrypt/verify with the matching HKDF-derived key — and
//     ONLY with that key (a leak in one info-namespace doesn't compromise
//     another).
//  3. Legacy artifacts (no kid, single SHA256(secret) key) still decrypt and
//     verify, so existing refresh tokens / client_ids minted before the
//     cutover keep working through the rotation window.
func TestOAuthJWEHKDFRoundtripAndLegacyFallback(t *testing.T) {
	t.Parallel()

	secret := []byte("test-signing-secret-32-byte-key!!")

	t.Run("v1_artifact_carries_kid_header", func(t *testing.T) {
		t.Parallel()
		token, err := encodeOAuthJWE(secret, hkdfInfoOAuthClientID, map[string]interface{}{
			"sub": "user-1",
			"exp": time.Now().Add(time.Hour).Unix(),
		})
		require.NoError(t, err)
		// JWE compact serialisation: 5 dot-separated parts (header.cek.iv.ct.tag).
		parts := strings.Split(token, ".")
		require.Len(t, parts, 5)
		header, err := decodeJWTSegment(parts[0])
		require.NoError(t, err)
		var hdr map[string]interface{}
		require.NoError(t, json.Unmarshal(header, &hdr))
		require.Equal(t, oauthKidV1, hdr["kid"], "newly-issued JWE must carry kid=v1")
	})

	t.Run("v1_roundtrip", func(t *testing.T) {
		t.Parallel()
		original := map[string]interface{}{
			"sub":      "user-1",
			"exp":      float64(time.Now().Add(time.Hour).Unix()),
			"scope":    "openid email",
			"email":    "u@example.com",
			"client_id": "test-client",
		}
		token, err := encodeOAuthJWE(secret, hkdfInfoOAuthRefresh, original)
		require.NoError(t, err)
		decrypted, err := decodeOAuthJWE(secret, hkdfInfoOAuthRefresh, token)
		require.NoError(t, err)
		require.Equal(t, original["sub"], decrypted["sub"])
		require.Equal(t, original["scope"], decrypted["scope"])
	})

	t.Run("v1_domain_separation_blocks_cross_context_decrypt", func(t *testing.T) {
		// A refresh token's JWE MUST NOT decrypt against the client_id key,
		// even though both are minted from the same shared secret. This is
		// the core HKDF benefit (RFC 5869 §3.2): different info → independent
		// keys.
		t.Parallel()
		token, err := encodeOAuthJWE(secret, hkdfInfoOAuthRefresh, map[string]interface{}{
			"sub": "user-1",
			"exp": time.Now().Add(time.Hour).Unix(),
		})
		require.NoError(t, err)
		_, err = decodeOAuthJWE(secret, hkdfInfoOAuthClientID, token)
		require.Error(t, err, "decryption with the wrong info label MUST fail")
	})

	t.Run("legacy_artifact_decrypts_via_fallback", func(t *testing.T) {
		// Mint a JWE the way the pre-Step-2 server did: jwe_auth.GenerateJWEToken
		// with the raw secret, no kid header, JWT-signed inner content.
		t.Parallel()
		legacy, err := jwe_auth.GenerateJWEToken(map[string]interface{}{
			"sub":   "user-legacy",
			"exp":   time.Now().Add(time.Hour).Unix(),
			"scope": "openid",
		}, secret, secret)
		require.NoError(t, err)
		// Sanity: legacy artifacts have no kid (or empty) in the protected header.
		parts := strings.Split(legacy, ".")
		header, err := decodeJWTSegment(parts[0])
		require.NoError(t, err)
		var hdr map[string]interface{}
		require.NoError(t, json.Unmarshal(header, &hdr))
		_, hasKid := hdr["kid"]
		require.False(t, hasKid, "legacy artifact must not carry kid")

		// Now decode it via the new path — should succeed via the legacy
		// fallback branch, regardless of which info label we ask for (the
		// fallback ignores info because the legacy SHA256(secret) key is
		// shared across contexts).
		decoded, err := decodeOAuthJWE(secret, hkdfInfoOAuthRefresh, legacy)
		require.NoError(t, err, "legacy JWE must remain decryptable during the rotation window")
		require.Equal(t, "user-legacy", decoded["sub"])
	})

	t.Run("self_issued_access_token_v1_carries_kid", func(t *testing.T) {
		t.Parallel()
		token, err := encodeSelfIssuedAccessToken(secret, map[string]interface{}{
			"sub": "user-1",
			"iss": "https://mcp.example.com",
			"aud": "https://mcp.example.com",
			"exp": time.Now().Add(time.Hour).Unix(),
		})
		require.NoError(t, err)
		parts := strings.Split(token, ".")
		require.Len(t, parts, 3)
		header, err := decodeJWTSegment(parts[0])
		require.NoError(t, err)
		var hdr map[string]interface{}
		require.NoError(t, json.Unmarshal(header, &hdr))
		require.Equal(t, oauthKidV1, hdr["kid"], "self-issued access token must carry kid=v1")
	})
}

func TestOAuthHTTPDiscoveryAndRegistration(t *testing.T) {
	t.Parallel()
	app := &application{
		config: config.Config{
			Server: config.ServerConfig{
				OAuth: config.OAuthConfig{
					Enabled:             true,
					Issuer:              "https://mcp.example.com/oauth",
					Audience:            "https://mcp.example.com",
					PublicResourceURL:   "https://mcp.example.com",
					PublicAuthServerURL: "https://mcp.example.com/oauth",
					SigningSecret:     "test-gating-secret-32-byte-key!!",
					Scopes:              []string{"openid", "email"},
					AuthURL:             "https://accounts.google.com/o/oauth2/v2/auth",
					TokenURL:            "https://oauth2.googleapis.com/token",
					ClientID:            "google-client-id",
					ClientSecret:        "google-client-secret",
				},
			},
		},
	}

	// NOTE: subtests are NOT parallel — custom_public_urls_and_paths mutates shared app.config
	t.Run("protected_resource_metadata", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "https://mcp.example.com/.well-known/oauth-protected-resource", nil)
		rr := httptest.NewRecorder()
		app.handleOAuthProtectedResource(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)

		var body map[string]interface{}
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
		require.Equal(t, "https://mcp.example.com/", body["resource"])
		require.Equal(t, []interface{}{"https://mcp.example.com/oauth"}, body["authorization_servers"])
	})

	t.Run("authorization_server_metadata", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "https://mcp.example.com/.well-known/oauth-authorization-server", nil)
		rr := httptest.NewRecorder()
		app.handleOAuthAuthorizationServerMetadata(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)
		require.Contains(t, rr.Body.String(), "\"authorization_endpoint\":\"https://mcp.example.com/oauth/oauth/authorize\"")
		require.Contains(t, rr.Body.String(), "\"registration_endpoint\":\"https://mcp.example.com/oauth/oauth/register\"")
	})

	t.Run("openid_configuration_aliases", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "https://mcp.example.com/.well-known/openid-configuration/oauth", nil)
		rr := httptest.NewRecorder()
		app.handleOAuthOpenIDConfiguration(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)
		require.Contains(t, rr.Body.String(), "\"issuer\":\"https://mcp.example.com/oauth\"")
		require.Contains(t, rr.Body.String(), "\"token_endpoint\":\"https://mcp.example.com/oauth/oauth/token\"")
	})

	t.Run("dynamic_client_registration", func(t *testing.T) {
		body := bytes.NewBufferString(`{"redirect_uris":["http://127.0.0.1:3334/callback"],"token_endpoint_auth_method":"none"}`)
		req := httptest.NewRequest(http.MethodPost, "https://mcp.example.com/oauth/register", body)
		rr := httptest.NewRecorder()
		app.handleOAuthRegister(rr, req)
		require.Equal(t, http.StatusCreated, rr.Code)
		require.Contains(t, rr.Body.String(), "\"client_id\"")
		require.Contains(t, rr.Body.String(), "\"token_endpoint_auth_method\":\"none\"")

		var reg map[string]interface{}
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &reg))
		clientID, ok := reg["client_id"].(string)
		require.True(t, ok)
		require.NotEmpty(t, clientID)

		// Registration response must echo every grant the client is
		// permitted to use. Per RFC 7591 strict clients (Claude.ai) treat
		// an omitted grant as forbidden and never attempt it, which
		// silently disables the refresh flow.
		grants, ok := reg["grant_types"].([]interface{})
		require.True(t, ok, "grant_types missing or wrong type in registration response")
		require.ElementsMatch(t, []interface{}{"authorization_code", "refresh_token"}, grants,
			"registration response must advertise both authorization_code and refresh_token")

		authReq := httptest.NewRequest(http.MethodGet, "https://mcp.example.com/oauth/authorize?response_type=code&client_id="+url.QueryEscape(clientID)+"&redirect_uri="+url.QueryEscape("http://127.0.0.1:3334/callback")+"&scope=openid+email&state=test-state&code_challenge=test-challenge&code_challenge_method=S256", nil)
		authRR := httptest.NewRecorder()
		app.handleOAuthAuthorize(authRR, authReq)
		require.Equal(t, http.StatusFound, authRR.Code)
		require.Contains(t, authRR.Header().Get("Location"), "https://accounts.google.com/o/oauth2/v2/auth")
	})

	t.Run("authorize_resource_indicator_accepted_when_matches_advertised_resource", func(t *testing.T) {
		// RFC 8707 / MCP authorization spec: client passes `resource=<MCP URL>`
		// on /authorize. We accept either trailing-slash form, but the bare-host
		// form is the canonical advertised resource here (PublicResourceURL
		// "https://mcp.example.com" — slashes get appended where needed).
		regBody := bytes.NewBufferString(`{"redirect_uris":["http://127.0.0.1:3334/callback"],"token_endpoint_auth_method":"none"}`)
		regReq := httptest.NewRequest(http.MethodPost, "https://mcp.example.com/oauth/register", regBody)
		regRR := httptest.NewRecorder()
		app.handleOAuthRegister(regRR, regReq)
		var reg map[string]interface{}
		require.NoError(t, json.Unmarshal(regRR.Body.Bytes(), &reg))
		clientID, _ := reg["client_id"].(string)

		base := "https://mcp.example.com/oauth/authorize?response_type=code&client_id=" + url.QueryEscape(clientID) +
			"&redirect_uri=" + url.QueryEscape("http://127.0.0.1:3334/callback") +
			"&scope=openid+email&state=s&code_challenge=c&code_challenge_method=S256"

		// (a) resource present and matches advertised resource (trailing-slash form): 302
		authReq := httptest.NewRequest(http.MethodGet, base+"&resource="+url.QueryEscape("https://mcp.example.com/"), nil)
		authRR := httptest.NewRecorder()
		app.handleOAuthAuthorize(authRR, authReq)
		require.Equal(t, http.StatusFound, authRR.Code, "valid resource indicator must be accepted (slash form)")

		// PKCE on the upstream-IdP leg: the redirect to upstream MUST include
		// code_challenge + code_challenge_method=S256 (OAuth 2.1 §7.5.2).
		// Without this, an attacker who intercepts the upstream auth code
		// (e.g., via referrer or proxy logs between IdP and our /callback)
		// could redeem it even though we hold the upstream client_secret.
		upstreamRedirect, parseErr := url.Parse(authRR.Header().Get("Location"))
		require.NoError(t, parseErr)
		require.NotEmpty(t, upstreamRedirect.Query().Get("code_challenge"),
			"upstream /authorize redirect must carry code_challenge (RFC 7636 / OAuth 2.1)")
		require.Equal(t, "S256", upstreamRedirect.Query().Get("code_challenge_method"),
			"upstream PKCE method must be S256 per OAuth 2.1 §4.1.1")

		// (b) resource present and matches advertised resource (bare host form): 302
		authReq = httptest.NewRequest(http.MethodGet, base+"&resource="+url.QueryEscape("https://mcp.example.com"), nil)
		authRR = httptest.NewRecorder()
		app.handleOAuthAuthorize(authRR, authReq)
		require.Equal(t, http.StatusFound, authRR.Code, "valid resource indicator must be accepted (bare host form)")

		// (c) resource present but identifies a different host: 400
		authReq = httptest.NewRequest(http.MethodGet, base+"&resource="+url.QueryEscape("https://attacker.example/"), nil)
		authRR = httptest.NewRecorder()
		app.handleOAuthAuthorize(authRR, authReq)
		require.Equal(t, http.StatusBadRequest, authRR.Code, "mismatched resource indicator must be rejected")

		// (d) resource absent (legacy clients): 302 (back-compat — RFC 8707 says SHOULD, not MUST)
		authReq = httptest.NewRequest(http.MethodGet, base, nil)
		authRR = httptest.NewRecorder()
		app.handleOAuthAuthorize(authRR, authReq)
		require.Equal(t, http.StatusFound, authRR.Code, "missing resource indicator must still authorize (legacy clients)")
	})

	t.Run("mint_gating_token_aud_mirrors_requested_resource", func(t *testing.T) {
		// `aud` claim must byte-match what the client passed in `resource`.
		// Anthropic's artifact-side proxy enforces this byte-equality; if we
		// strip a trailing slash that the client included, the proxy silently
		// drops the connector — see docs/artifact-mcp-known-issues.md.
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "https://mcp.example.com/oauth/token", nil)
		// Audience field is set on app.config (= "https://mcp.example.com"),
		// but Resource on the gatingIdentity must win.
		app.mintGatingTokenResponse(w, req, []byte(app.config.Server.OAuth.SigningSecret), gatingIdentity{
			ClientID:      "test-client",
			Subject:       "user-123",
			Email:         "u@example.com",
			EmailVerified: true,
			Scope:         "openid email",
			Resource:      "https://mcp.example.com/",
		})
		require.Equal(t, http.StatusOK, w.Code)

		var resp map[string]interface{}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		accessToken, _ := resp["access_token"].(string)
		require.NotEmpty(t, accessToken)

		// Decode the JWS (3 parts) without verification; we only check the
		// audience claim shape.
		parts := strings.Split(accessToken, ".")
		require.Len(t, parts, 3)
		payload, err := decodeJWTSegment(parts[1])
		require.NoError(t, err)
		var claims map[string]interface{}
		require.NoError(t, json.Unmarshal(payload, &claims))
		require.Equal(t, "https://mcp.example.com/", claims["aud"], "aud must be the exact string the client passed in `resource` (trailing slash preserved)")
	})

	t.Run("mint_gating_token_aud_defaults_to_canonical_no_slash", func(t *testing.T) {
		// When the client did NOT send a resource indicator (e.g., legacy
		// codex / older mcp clients) the fallback `aud` matches the
		// canonical advertised `resource` (no trailing slash) per
		// MCP 2025-11-25 §Canonical Server URI.
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "https://mcp.example.com/oauth/token", nil)
		// Clear the operator-configured Audience for this subtest so the
		// fallback path runs (with Audience set, that wins).
		savedAud := app.config.Server.OAuth.Audience
		app.config.Server.OAuth.Audience = ""
		t.Cleanup(func() { app.config.Server.OAuth.Audience = savedAud })

		app.mintGatingTokenResponse(w, req, []byte(app.config.Server.OAuth.SigningSecret), gatingIdentity{
			ClientID:      "test-client",
			Subject:       "user-123",
			Email:         "u@example.com",
			EmailVerified: true,
			Scope:         "openid email",
			// Resource intentionally empty.
		})
		require.Equal(t, http.StatusOK, w.Code)
		var resp map[string]interface{}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		accessToken, _ := resp["access_token"].(string)
		parts := strings.Split(accessToken, ".")
		require.Len(t, parts, 3)
		payload, err := decodeJWTSegment(parts[1])
		require.NoError(t, err)
		var claims map[string]interface{}
		require.NoError(t, json.Unmarshal(payload, &claims))
		require.Equal(t, "https://mcp.example.com", claims["aud"])
	})

	t.Run("dynamic_client_registration_default_is_confidential", func(t *testing.T) {
		// When the client doesn't ask for a specific auth method, we now
		// register it as confidential (client_secret_post). This unblocks
		// Anthropic's mcp_servers-via-URL flow, which has no browser session
		// for PKCE and needs server-to-server token-endpoint auth.
		body := bytes.NewBufferString(`{"redirect_uris":["http://127.0.0.1:3334/callback"]}`)
		req := httptest.NewRequest(http.MethodPost, "https://mcp.example.com/oauth/register", body)
		rr := httptest.NewRecorder()
		app.handleOAuthRegister(rr, req)
		require.Equal(t, http.StatusCreated, rr.Code)

		var reg map[string]interface{}
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &reg))
		require.Equal(t, "client_secret_post", reg["token_endpoint_auth_method"])
		cs, _ := reg["client_secret"].(string)
		require.NotEmpty(t, cs, "confidential registration must include client_secret")
		require.Len(t, cs, 64, "client_secret should be 32 random bytes hex-encoded")
		_, hasExpiry := reg["client_secret_expires_at"]
		require.True(t, hasExpiry, "RFC 7591 §3.2.1: client_secret_expires_at is required when secret is issued")
	})

	t.Run("dynamic_client_registration_explicit_none_still_public", func(t *testing.T) {
		// First-party flows that explicitly ask for the legacy public-client
		// shape keep getting it — no client_secret in the response.
		body := bytes.NewBufferString(`{"redirect_uris":["http://127.0.0.1:3334/callback"],"token_endpoint_auth_method":"none"}`)
		req := httptest.NewRequest(http.MethodPost, "https://mcp.example.com/oauth/register", body)
		rr := httptest.NewRecorder()
		app.handleOAuthRegister(rr, req)
		require.Equal(t, http.StatusCreated, rr.Code)

		var reg map[string]interface{}
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &reg))
		require.Equal(t, "none", reg["token_endpoint_auth_method"])
		_, hasSecret := reg["client_secret"]
		require.False(t, hasSecret, "public registration must not include client_secret")
	})

	t.Run("authentication_methods_advertised", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "https://mcp.example.com/.well-known/oauth-authorization-server", nil)
		rr := httptest.NewRecorder()
		app.handleOAuthAuthorizationServerMetadata(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)

		var meta map[string]interface{}
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &meta))
		methods, ok := meta["token_endpoint_auth_methods_supported"].([]interface{})
		require.True(t, ok)
		require.Contains(t, methods, "client_secret_post")
		require.Contains(t, methods, "client_secret_basic")
		require.Contains(t, methods, "none")
	})

	t.Run("custom_public_urls_and_paths", func(t *testing.T) {
		app.config.Server.OAuth.PublicResourceURL = "https://public.example.com"
		app.config.Server.OAuth.PublicAuthServerURL = "https://public.example.com/oauth"
		app.config.Server.OAuth.RegistrationPath = "/register"
		app.config.Server.OAuth.AuthorizationPath = "/authorize"
		app.config.Server.OAuth.CallbackPath = "/callback"
		app.config.Server.OAuth.TokenPath = "/token"

		req := httptest.NewRequest(http.MethodGet, "https://internal.example.com/.well-known/oauth-authorization-server", nil)
		rr := httptest.NewRecorder()
		app.handleOAuthAuthorizationServerMetadata(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)
		require.Contains(t, rr.Body.String(), "\"issuer\":\"https://public.example.com/oauth\"")
		require.Contains(t, rr.Body.String(), "\"authorization_endpoint\":\"https://public.example.com/oauth/authorize\"")
		require.Contains(t, rr.Body.String(), "\"registration_endpoint\":\"https://public.example.com/oauth/register\"")

		req = httptest.NewRequest(http.MethodGet, "https://internal.example.com/.well-known/oauth-protected-resource", nil)
		rr = httptest.NewRecorder()
		app.handleOAuthProtectedResource(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)
		require.Contains(t, rr.Body.String(), "\"resource\":\"https://public.example.com/\"")
		require.Contains(t, rr.Body.String(), "\"authorization_servers\":[\"https://public.example.com/oauth\"]")
	})
}

func TestOAuthMCPAuthInjector(t *testing.T) {
	t.Parallel()
	token, err := generateOAuthTokenForApp(map[string]interface{}{
		"sub":   "user123",
		"iss":   "https://mcp.example.com",
		"aud":   "https://mcp.example.com",
		"exp":   time.Now().Add(time.Hour).Unix(),
		"scope": "openid email",
		"email": "user@example.com",
	})
	require.NoError(t, err)

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

	t.Run("valid_oauth_sets_context", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodPost, "https://mcp.example.com/"+jweToken, nil)
		req.SetPathValue("token", jweToken)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()
		called := false
		handler := app.createMCPAuthInjector(app.config)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
			require.Equal(t, jweToken, r.Context().Value(altinitymcp.JWETokenKey))
			require.Equal(t, token, r.Context().Value(altinitymcp.OAuthTokenKey))
			w.WriteHeader(http.StatusOK)
		}))
		handler.ServeHTTP(rr, req)
		require.True(t, called)
		require.Equal(t, http.StatusOK, rr.Code)
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
func TestOAuthMCPAuthInjectorForwardModeValidatesJWT(t *testing.T) {
	t.Parallel()

	provider := newTestForwardModeOIDCProvider(t, nil, nil)
	cfg := config.Config{
		Server: config.ServerConfig{
			OAuth: config.OAuthConfig{
				Enabled:  true,
				Mode:     "forward",
				Issuer:   provider.server.URL,
				JWKSURL:  provider.server.URL + "/jwks",
				Audience: "clickhouse-api",
			},
		},
	}
	app := &application{
		config:    cfg,
		mcpServer: altinitymcp.NewClickHouseMCPServer(cfg, "test"),
	}

	t.Run("valid_jwt_reaches_handler_with_claims", func(t *testing.T) {
		t.Parallel()
		token := provider.issueIDToken(t, map[string]interface{}{
			"sub": "user-good",
			"iss": provider.server.URL,
			"aud": "clickhouse-api",
			"exp": time.Now().Add(time.Hour).Unix(),
			"iat": time.Now().Unix(),
		})
		req := httptest.NewRequest(http.MethodPost, "https://mcp.example.com/", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()
		called := false
		handler := app.createMCPAuthInjector(app.config)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
			require.Equal(t, token, r.Context().Value(altinitymcp.OAuthTokenKey))
			claims, ok := r.Context().Value(altinitymcp.OAuthClaimsKey).(*altinitymcp.OAuthClaims)
			require.True(t, ok, "valid forward-mode JWT must populate OAuthClaims in context")
			require.Equal(t, "user-good", claims.Subject)
			w.WriteHeader(http.StatusOK)
		}))
		handler.ServeHTTP(rr, req)
		require.True(t, called)
		require.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("jwt_with_wrong_audience_rejected_with_401", func(t *testing.T) {
		t.Parallel()
		token := provider.issueIDToken(t, map[string]interface{}{
			"sub": "user-bad-aud",
			"iss": provider.server.URL,
			"aud": "some-other-api",
			"exp": time.Now().Add(time.Hour).Unix(),
		})
		req := httptest.NewRequest(http.MethodPost, "https://mcp.example.com/", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()
		called := false
		handler := app.createMCPAuthInjector(app.config)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
			w.WriteHeader(http.StatusOK)
		}))
		handler.ServeHTTP(rr, req)
		require.False(t, called, "wrong-aud forward-mode JWT must NOT reach inner handler")
		require.Equal(t, http.StatusUnauthorized, rr.Code)
		require.Contains(t, rr.Header().Get("WWW-Authenticate"), `error="invalid_token"`)
		require.Contains(t, rr.Header().Get("WWW-Authenticate"), "resource_metadata=")
	})

	t.Run("expired_jwt_rejected_with_401", func(t *testing.T) {
		t.Parallel()
		token := provider.issueIDToken(t, map[string]interface{}{
			"sub": "user-expired",
			"iss": provider.server.URL,
			"aud": "clickhouse-api",
			"exp": time.Now().Add(-2 * time.Hour).Unix(),
			"iat": time.Now().Add(-3 * time.Hour).Unix(),
		})
		req := httptest.NewRequest(http.MethodPost, "https://mcp.example.com/", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()
		called := false
		handler := app.createMCPAuthInjector(app.config)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
			w.WriteHeader(http.StatusOK)
		}))
		handler.ServeHTTP(rr, req)
		require.False(t, called, "expired forward-mode JWT must NOT reach inner handler")
		require.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("opaque_bearer_softpasses_when_jwks_configured", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodPost, "https://mcp.example.com/", nil)
		req.Header.Set("Authorization", "Bearer not-a-jwt-just-an-opaque-string")
		rr := httptest.NewRecorder()
		called := false
		handler := app.createMCPAuthInjector(app.config)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
			require.Equal(t, "not-a-jwt-just-an-opaque-string", r.Context().Value(altinitymcp.OAuthTokenKey))
			require.Nil(t, r.Context().Value(altinitymcp.OAuthClaimsKey))
			w.WriteHeader(http.StatusOK)
		}))
		handler.ServeHTTP(rr, req)
		require.True(t, called, "opaque forward-mode bearer soft-passes (deferred to ClickHouse)")
		require.Equal(t, http.StatusOK, rr.Code)
	})
}

func TestRegisterOAuthHTTPRoutesAliases(t *testing.T) {
	t.Parallel()
	app := &application{
		config: config.Config{
			Server: config.ServerConfig{
				OAuth: config.OAuthConfig{
					Enabled:  true,
					Issuer:   "https://mcp.example.com/oauth",
					Audience: "https://mcp.example.com",
					Scopes:   []string{"openid", "email"},
				},
			},
		},
	}

	mux := http.NewServeMux()
	app.registerOAuthHTTPRoutes(mux)

	for _, path := range []string{
		"/.well-known/oauth-authorization-server/oauth",
		"/oauth/.well-known/oauth-authorization-server",
		"/.well-known/openid-configuration/oauth",
		"/oauth/.well-known/openid-configuration",
	} {
		req := httptest.NewRequest(http.MethodGet, "https://mcp.example.com"+path, nil)
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		require.Equalf(t, http.StatusOK, rr.Code, "expected alias %s to resolve", path)
	}

	app.config.Server.OAuth.RegistrationPath = "/register"
	app.config.Server.OAuth.AuthorizationPath = "/authorize"
	app.config.Server.OAuth.CallbackPath = "/callback"
	app.config.Server.OAuth.TokenPath = "/token"

	mux = http.NewServeMux()
	app.registerOAuthHTTPRoutes(mux)

	for _, path := range []string{
		"/register",
		"/authorize",
		"/callback",
		"/token",
	} {
		method := http.MethodGet
		if path == "/register" || path == "/token" {
			method = http.MethodPost
		}
		req := httptest.NewRequest(method, "https://mcp.example.com"+path, nil)
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		require.NotEqualf(t, http.StatusNotFound, rr.Code, "expected configured path %s to resolve", path)
	}
}

type testForwardModeOIDCProvider struct {
	server *httptest.Server

	privateKey *rsa.PrivateKey
	keyID      string

	tokenResponse    map[string]interface{}
	userInfoClaims   map[string]interface{}
	lastUserInfoAuth string
	userInfoCalls    int
	mu               sync.Mutex

	// refreshHandler, if non-nil, handles POST /token requests with
	// grant_type=refresh_token. It receives the parsed form and returns
	// (status, body). When nil, refresh_token grants fall through to the
	// default static tokenResponse behavior.
	refreshHandler func(form url.Values) (int, map[string]interface{})
}

func newTestForwardModeOIDCProvider(t *testing.T, tokenResponse map[string]interface{}, userInfoClaims map[string]interface{}) *testForwardModeOIDCProvider {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	provider := &testForwardModeOIDCProvider{
		privateKey:     privateKey,
		keyID:          "test-signing-key",
		tokenResponse:  tokenResponse,
		userInfoClaims: userInfoClaims,
	}

	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	provider.server = server
	t.Cleanup(server.Close)

	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.NoError(t, r.ParseForm())
		if provider.refreshHandler != nil && r.Form.Get("grant_type") == "refresh_token" {
			status, body := provider.refreshHandler(r.Form)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			require.NoError(t, json.NewEncoder(w).Encode(body))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode(provider.tokenResponse))
	})

	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		keySet := jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{{
				Key:       &privateKey.PublicKey,
				KeyID:     provider.keyID,
				Use:       "sig",
				Algorithm: string(jose.RS256),
			}},
		}
		require.NoError(t, json.NewEncoder(w).Encode(keySet))
	})

	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		provider.mu.Lock()
		provider.userInfoCalls++
		provider.lastUserInfoAuth = r.Header.Get("Authorization")
		provider.mu.Unlock()

		if provider.userInfoClaims == nil {
			http.Error(w, "userinfo not configured", http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode(provider.userInfoClaims))
	})

	return provider
}

func (p *testForwardModeOIDCProvider) issueIDToken(t *testing.T, claims map[string]interface{}) string {
	t.Helper()

	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.RS256,
		Key: jose.JSONWebKey{
			Key:       p.privateKey,
			KeyID:     p.keyID,
			Use:       "sig",
			Algorithm: string(jose.RS256),
		},
	}, (&jose.SignerOptions{}).WithType("JWT"))
	require.NoError(t, err)

	payload, err := json.Marshal(claims)
	require.NoError(t, err)

	object, err := signer.Sign(payload)
	require.NoError(t, err)

	token, err := object.CompactSerialize()
	require.NoError(t, err)

	return token
}

func (p *testForwardModeOIDCProvider) userInfoRequest() (int, string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.userInfoCalls, p.lastUserInfoAuth
}

func newForwardModeBrowserLoginTestApp(provider *testForwardModeOIDCProvider) *application {
	cfg := config.Config{
		Server: config.ServerConfig{
			OAuth: config.OAuthConfig{
				Enabled:         true,
				Mode:            "forward",
				Issuer:          provider.server.URL,
				JWKSURL:         provider.server.URL + "/jwks",
				AuthURL:         provider.server.URL + "/authorize",
				TokenURL:        provider.server.URL + "/token",
				UserInfoURL:     provider.server.URL + "/userinfo",
				ClientID:        "upstream-client-id",
				ClientSecret:    "upstream-client-secret",
				Scopes:          []string{"openid", "email"},
				SigningSecret: "test-gating-secret-32-byte-key!!",
			},
		},
	}

	return &application{
		config:    cfg,
		mcpServer: altinitymcp.NewClickHouseMCPServer(cfg, "test"),
	}
}

func registerOAuthBrowserClient(t *testing.T, app *application, redirectURI string) string {
	t.Helper()

	body := bytes.NewBufferString(fmt.Sprintf(`{"redirect_uris":["%s"],"token_endpoint_auth_method":"none"}`, redirectURI))
	req := httptest.NewRequest(http.MethodPost, "https://mcp.example.com/oauth/register", body)
	rr := httptest.NewRecorder()
	app.handleOAuthRegister(rr, req)
	require.Equal(t, http.StatusCreated, rr.Code)

	var reg map[string]interface{}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &reg))

	clientID, ok := reg["client_id"].(string)
	require.True(t, ok)
	require.NotEmpty(t, clientID)
	return clientID
}

func startOAuthBrowserLogin(t *testing.T, app *application, clientID, redirectURI, clientState, codeVerifier string) string {
	t.Helper()

	authReq := httptest.NewRequest(
		http.MethodGet,
		"https://mcp.example.com/oauth/authorize?response_type=code&client_id="+url.QueryEscape(clientID)+
			"&redirect_uri="+url.QueryEscape(redirectURI)+
			"&scope=openid+email&state="+url.QueryEscape(clientState)+
			"&code_challenge="+url.QueryEscape(pkceChallenge(codeVerifier))+
			"&code_challenge_method=S256",
		nil,
	)
	authRR := httptest.NewRecorder()
	app.handleOAuthAuthorize(authRR, authReq)
	require.Equal(t, http.StatusFound, authRR.Code)

	location, err := url.Parse(authRR.Header().Get("Location"))
	require.NoError(t, err)

	state := location.Query().Get("state")
	require.NotEmpty(t, state)
	return state
}

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

func TestOAuthForwardModeBrowserLoginUsesUpstreamBearerToken(t *testing.T) {
	t.Parallel()
	const (
		redirectURI  = "http://127.0.0.1:3334/callback"
		codeVerifier = "test-code-verifier"
		clientState  = "client-state"
	)

	t.Run("access_token_and_id_token_prefers_id_token", func(t *testing.T) {
		t.Parallel()
		provider := newTestForwardModeOIDCProvider(t, map[string]interface{}{
			"access_token": "upstream-access-token",
			"token_type":   "Bearer",
			"expires_in":   1800,
			"scope":        "openid email profile",
		}, nil)
		provider.tokenResponse["id_token"] = provider.issueIDToken(t, map[string]interface{}{
			"sub":            "user-1",
			"iss":            provider.server.URL,
			"aud":            "upstream-client-id",
			"exp":            time.Now().Add(time.Hour).Unix(),
			"iat":            time.Now().Unix(),
			"email":          "user@example.com",
			"email_verified": true,
		})

		app := newForwardModeBrowserLoginTestApp(provider)
		clientID := registerOAuthBrowserClient(t, app, redirectURI)
		state := startOAuthBrowserLogin(t, app, clientID, redirectURI, clientState, codeVerifier)

		callbackReq := httptest.NewRequest(http.MethodGet, "https://mcp.example.com/oauth/callback?code=upstream-auth-code&state="+url.QueryEscape(state), nil)
		callbackRR := httptest.NewRecorder()
		app.handleOAuthCallback(callbackRR, callbackReq)
		require.Equal(t, http.StatusFound, callbackRR.Code)

		redirectLocation, err := url.Parse(callbackRR.Header().Get("Location"))
		require.NoError(t, err)
		require.Equal(t, clientState, redirectLocation.Query().Get("state"))

		tokenRR := exchangeOAuthBrowserCode(t, app, clientID, redirectLocation.Query().Get("code"), redirectURI, codeVerifier)
		require.Equal(t, http.StatusOK, tokenRR.Code)

		var tokenResp map[string]interface{}
		require.NoError(t, json.Unmarshal(tokenRR.Body.Bytes(), &tokenResp))
		// In forward mode, the raw upstream token is returned directly
		require.Equal(t, provider.tokenResponse["id_token"], tokenResp["access_token"])
		require.Equal(t, "Bearer", tokenResp["token_type"])
		require.Equal(t, "openid email profile", tokenResp["scope"])
		// The bearer we forward is the id_token, so expires_in must reflect
		// the id_token's exp (1h), NOT the upstream access_token's expires_in
		// (30m). IdPs commonly return divergent lifetimes; using the wrong
		// one means downstream MCP clients (Claude.ai) refresh too late and
		// the bearer expires under them.
		require.Greater(t, tokenResp["expires_in"].(float64), float64(3500))
		require.LessOrEqual(t, tokenResp["expires_in"].(float64), float64(3600))

		userInfoCalls, userInfoAuth := provider.userInfoRequest()
		require.Equal(t, 0, userInfoCalls)
		require.Empty(t, userInfoAuth)
	})

	t.Run("access_token_only_uses_userinfo_and_returns_access_token", func(t *testing.T) {
		t.Parallel()
		provider := newTestForwardModeOIDCProvider(t, map[string]interface{}{
			"access_token": "opaque-access-token",
			"token_type":   "DPoP",
			"expires_in":   900,
			"scope":        "openid email",
		}, map[string]interface{}{
			"sub":            "user-2",
			"iss":            "https://issuer.example.com",
			"email":          "user2@example.com",
			"email_verified": true,
		})

		app := newForwardModeBrowserLoginTestApp(provider)
		clientID := registerOAuthBrowserClient(t, app, redirectURI)
		state := startOAuthBrowserLogin(t, app, clientID, redirectURI, clientState, codeVerifier)

		callbackReq := httptest.NewRequest(http.MethodGet, "https://mcp.example.com/oauth/callback?code=upstream-auth-code&state="+url.QueryEscape(state), nil)
		callbackRR := httptest.NewRecorder()
		app.handleOAuthCallback(callbackRR, callbackReq)
		require.Equal(t, http.StatusFound, callbackRR.Code)

		redirectLocation, err := url.Parse(callbackRR.Header().Get("Location"))
		require.NoError(t, err)

		tokenRR := exchangeOAuthBrowserCode(t, app, clientID, redirectLocation.Query().Get("code"), redirectURI, codeVerifier)
		require.Equal(t, http.StatusOK, tokenRR.Code)

		var tokenResp map[string]interface{}
		require.NoError(t, json.Unmarshal(tokenRR.Body.Bytes(), &tokenResp))
		// In forward mode, the raw upstream access token is returned directly
		require.Equal(t, "opaque-access-token", tokenResp["access_token"])
		require.Equal(t, "DPoP", tokenResp["token_type"])
		require.Equal(t, "openid email", tokenResp["scope"])
		require.Greater(t, tokenResp["expires_in"].(float64), float64(0))
		require.LessOrEqual(t, tokenResp["expires_in"].(float64), float64(900))

		userInfoCalls, userInfoAuth := provider.userInfoRequest()
		require.Equal(t, 1, userInfoCalls)
		require.Equal(t, "Bearer opaque-access-token", userInfoAuth)
	})

	t.Run("id_token_without_access_token_returns_id_token", func(t *testing.T) {
		t.Parallel()
		provider := newTestForwardModeOIDCProvider(t, map[string]interface{}{
			"token_type": "Bearer",
			"expires_in": 900,
			"scope":      "openid email",
		}, nil)
		provider.tokenResponse["id_token"] = provider.issueIDToken(t, map[string]interface{}{
			"sub":            "user-3",
			"iss":            provider.server.URL,
			"aud":            "upstream-client-id",
			"exp":            time.Now().Add(time.Hour).Unix(),
			"iat":            time.Now().Unix(),
			"email":          "user3@example.com",
			"email_verified": true,
		})

		app := newForwardModeBrowserLoginTestApp(provider)
		clientID := registerOAuthBrowserClient(t, app, redirectURI)
		state := startOAuthBrowserLogin(t, app, clientID, redirectURI, clientState, codeVerifier)

		callbackReq := httptest.NewRequest(http.MethodGet, "https://mcp.example.com/oauth/callback?code=upstream-auth-code&state="+url.QueryEscape(state), nil)
		callbackRR := httptest.NewRecorder()
		app.handleOAuthCallback(callbackRR, callbackReq)
		require.Equal(t, http.StatusFound, callbackRR.Code)

		redirectLocation, err := url.Parse(callbackRR.Header().Get("Location"))
		require.NoError(t, err)

		tokenRR := exchangeOAuthBrowserCode(t, app, clientID, redirectLocation.Query().Get("code"), redirectURI, codeVerifier)
		require.Equal(t, http.StatusOK, tokenRR.Code)

		var tokenResp map[string]interface{}
		require.NoError(t, json.Unmarshal(tokenRR.Body.Bytes(), &tokenResp))
		// In forward mode, the raw upstream id_token is returned directly
		require.Equal(t, provider.tokenResponse["id_token"], tokenResp["access_token"])
		require.Equal(t, "Bearer", tokenResp["token_type"])
		require.Equal(t, "openid email", tokenResp["scope"])

		userInfoCalls, userInfoAuth := provider.userInfoRequest()
		require.Equal(t, 0, userInfoCalls)
		require.Empty(t, userInfoAuth)
	})
}

// TestOAuthForwardModeTokenResourceMismatch pins the RFC 8707 §2.2 enforcement
// in forward mode: a /token (auth-code grant) request whose `resource` differs
// from the one already pinned at /authorize must be rejected with
// invalid_target, regardless of which mode we're running in.
func TestOAuthForwardModeTokenResourceMismatch(t *testing.T) {
	t.Parallel()
	const (
		redirectURI    = "http://127.0.0.1:3334/callback"
		codeVerifier   = "test-code-verifier"
		clientState    = "client-state"
		pinnedResource = "https://mcp.example.com"
		otherResource  = "https://attacker.example.com"
	)

	provider := newTestForwardModeOIDCProvider(t, map[string]interface{}{
		"access_token": "upstream-access-token",
		"token_type":   "Bearer",
		"expires_in":   1800,
		"scope":        "openid email",
	}, nil)
	provider.tokenResponse["id_token"] = provider.issueIDToken(t, map[string]interface{}{
		"sub":            "user-1",
		"iss":            provider.server.URL,
		"aud":            "upstream-client-id",
		"exp":            time.Now().Add(time.Hour).Unix(),
		"iat":            time.Now().Unix(),
		"email":          "user@example.com",
		"email_verified": true,
	})

	app := newForwardModeBrowserLoginTestApp(provider)
	clientID := registerOAuthBrowserClient(t, app, redirectURI)

	authReq := httptest.NewRequest(
		http.MethodGet,
		"https://mcp.example.com/oauth/authorize?response_type=code&client_id="+url.QueryEscape(clientID)+
			"&redirect_uri="+url.QueryEscape(redirectURI)+
			"&scope=openid+email&state="+url.QueryEscape(clientState)+
			"&code_challenge="+url.QueryEscape(pkceChallenge(codeVerifier))+
			"&code_challenge_method=S256"+
			"&resource="+url.QueryEscape(pinnedResource),
		nil,
	)
	authRR := httptest.NewRecorder()
	app.handleOAuthAuthorize(authRR, authReq)
	require.Equal(t, http.StatusFound, authRR.Code, "authorize must accept canonical resource")

	location, err := url.Parse(authRR.Header().Get("Location"))
	require.NoError(t, err)
	state := location.Query().Get("state")
	require.NotEmpty(t, state)

	callbackReq := httptest.NewRequest(http.MethodGet, "https://mcp.example.com/oauth/callback?code=upstream-auth-code&state="+url.QueryEscape(state), nil)
	callbackRR := httptest.NewRecorder()
	app.handleOAuthCallback(callbackRR, callbackReq)
	require.Equal(t, http.StatusFound, callbackRR.Code)

	redirectLocation, err := url.Parse(callbackRR.Header().Get("Location"))
	require.NoError(t, err)
	code := redirectLocation.Query().Get("code")
	require.NotEmpty(t, code)

	exchange := func(t *testing.T, formResource string) *httptest.ResponseRecorder {
		t.Helper()
		form := url.Values{}
		form.Set("grant_type", "authorization_code")
		form.Set("client_id", clientID)
		form.Set("code", code)
		form.Set("redirect_uri", redirectURI)
		form.Set("code_verifier", codeVerifier)
		if formResource != "" {
			form.Set("resource", formResource)
		}
		req := httptest.NewRequest(http.MethodPost, "https://mcp.example.com/oauth/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		app.handleOAuthToken(rr, req)
		return rr
	}

	t.Run("mismatched_resource_rejected", func(t *testing.T) {
		rr := exchange(t, otherResource)
		require.Equal(t, http.StatusBadRequest, rr.Code, "forward mode must reject /token resource that differs from /authorize")
		var body map[string]interface{}
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
		require.Equal(t, "invalid_target", body["error"])
	})
}

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

func TestEncodeSelfIssuedAccessTokenShortSecret(t *testing.T) {
	t.Parallel()
	token, err := encodeSelfIssuedAccessToken([]byte("short-secret"), map[string]interface{}{
		"sub": "user-1",
		"iss": "https://issuer.example.com",
		"aud": "https://resource.example.com",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	require.NoError(t, err)
	require.NotEmpty(t, token)
}

func TestOAuthStateStoreSizeCap(t *testing.T) {
	t.Parallel()
	t.Run("pending_auth_evicts_oldest_at_cap", func(t *testing.T) {
		t.Parallel()
		store := newOAuthStateStore()
		// Fill to capacity with entries that expire far in the future
		for i := 0; i < maxOAuthStateEntries; i++ {
			store.putPendingAuth(fmt.Sprintf("p_%d", i), oauthPendingAuth{
				ClientID:  "client",
				ExpiresAt: time.Now().Add(time.Hour),
			})
		}
		require.Equal(t, maxOAuthStateEntries, len(store.pendingAuth))

		// Insert one with the earliest expiry to make it the eviction target
		store.pendingAuth["earliest"] = oauthPendingAuth{
			ClientID:  "early",
			ExpiresAt: time.Now().Add(-time.Minute),
		}

		// Next put should evict "earliest" and stay at cap
		store.putPendingAuth("overflow", oauthPendingAuth{
			ClientID:  "new",
			ExpiresAt: time.Now().Add(time.Hour),
		})
		// expired entries cleaned + oldest evicted, should not exceed cap
		require.LessOrEqual(t, len(store.pendingAuth), maxOAuthStateEntries)
		_, ok := store.pendingAuth["earliest"]
		require.False(t, ok, "earliest entry should have been evicted")
		_, ok = store.pendingAuth["overflow"]
		require.True(t, ok, "new entry should be present")
	})

	t.Run("auth_codes_evicts_oldest_at_cap", func(t *testing.T) {
		t.Parallel()
		store := newOAuthStateStore()
		for i := 0; i < maxOAuthStateEntries; i++ {
			store.putAuthCode(fmt.Sprintf("c_%d", i), oauthIssuedCode{
				ClientID:  "client",
				ExpiresAt: time.Now().Add(time.Hour),
			})
		}
		require.Equal(t, maxOAuthStateEntries, len(store.authCodes))

		store.authCodes["earliest"] = oauthIssuedCode{
			ClientID:  "early",
			ExpiresAt: time.Now().Add(-time.Minute),
		}

		store.putAuthCode("overflow", oauthIssuedCode{
			ClientID:  "new",
			ExpiresAt: time.Now().Add(time.Hour),
		})
		require.LessOrEqual(t, len(store.authCodes), maxOAuthStateEntries)
		_, ok := store.authCodes["earliest"]
		require.False(t, ok, "earliest entry should have been evicted")
		_, ok = store.authCodes["overflow"]
		require.True(t, ok, "new entry should be present")
	})

	t.Run("expired_entries_cleaned_before_cap_check", func(t *testing.T) {
		t.Parallel()
		store := newOAuthStateStore()
		// Fill with already-expired entries
		for i := 0; i < maxOAuthStateEntries; i++ {
			store.pendingAuth[fmt.Sprintf("exp_%d", i)] = oauthPendingAuth{
				ClientID:  "client",
				ExpiresAt: time.Now().Add(-time.Second),
			}
		}
		require.Equal(t, maxOAuthStateEntries, len(store.pendingAuth))

		// putPendingAuth cleans expired first, so this should succeed without eviction
		store.putPendingAuth("fresh", oauthPendingAuth{
			ClientID:  "new",
			ExpiresAt: time.Now().Add(time.Hour),
		})
		require.Equal(t, 1, len(store.pendingAuth))
		_, ok := store.pendingAuth["fresh"]
		require.True(t, ok)
	})
}

// newGatingModeTestApp creates an application configured for gating mode OAuth.
func newGatingModeTestApp(provider *testForwardModeOIDCProvider) *application {
	cfg := config.Config{
		Server: config.ServerConfig{
			OAuth: config.OAuthConfig{
				Enabled:                true,
				Mode:                   "gating",
				Issuer:                 provider.server.URL,
				JWKSURL:                provider.server.URL + "/jwks",
				AuthURL:                provider.server.URL + "/authorize",
				TokenURL:               provider.server.URL + "/token",
				UserInfoURL:            provider.server.URL + "/userinfo",
				ClientID:               "upstream-client-id",
				ClientSecret:           "upstream-client-secret",
				Scopes:                 []string{"openid", "email"},
				SigningSecret:        "test-gating-secret-32-byte-key!!",
				AccessTokenTTLSeconds:  300,
				RefreshTokenTTLSeconds: 86400,
			},
		},
	}
	return &application{
		config:    cfg,
		mcpServer: altinitymcp.NewClickHouseMCPServer(cfg, "test"),
	}
}

// doGatingAuthCodeFlow runs the full authorize→callback→token exchange and
// returns the parsed token response.
func doGatingAuthCodeFlow(t *testing.T, app *application, provider *testForwardModeOIDCProvider, redirectURI, codeVerifier string) map[string]interface{} {
	t.Helper()

	clientID := registerOAuthBrowserClient(t, app, redirectURI)
	state := startOAuthBrowserLogin(t, app, clientID, redirectURI, "s", codeVerifier)

	callbackReq := httptest.NewRequest(http.MethodGet, "https://mcp.example.com/oauth/callback?code=upstream-auth-code&state="+url.QueryEscape(state), nil)
	callbackRR := httptest.NewRecorder()
	app.handleOAuthCallback(callbackRR, callbackReq)
	require.Equal(t, http.StatusFound, callbackRR.Code)

	loc, err := url.Parse(callbackRR.Header().Get("Location"))
	require.NoError(t, err)

	tokenRR := exchangeOAuthBrowserCode(t, app, clientID, loc.Query().Get("code"), redirectURI, codeVerifier)
	require.Equal(t, http.StatusOK, tokenRR.Code)

	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(tokenRR.Body.Bytes(), &resp))
	resp["_client_id"] = clientID // stash for refresh tests
	return resp
}

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

func TestOAuthRefreshTokenGatingMode(t *testing.T) {
	t.Parallel()
	const (
		redirectURI  = "http://127.0.0.1:3334/callback"
		codeVerifier = "test-code-verifier"
	)

	provider := newTestForwardModeOIDCProvider(t, map[string]interface{}{
		"access_token": "upstream-access-token",
		"token_type":   "Bearer",
		"expires_in":   1800,
		"scope":        "openid email",
	}, nil)
	provider.tokenResponse["id_token"] = provider.issueIDToken(t, map[string]interface{}{
		"sub":            "user-1",
		"iss":            provider.server.URL,
		"aud":            "upstream-client-id",
		"exp":            time.Now().Add(time.Hour).Unix(),
		"iat":            time.Now().Unix(),
		"email":          "user@example.com",
		"email_verified": true,
	})

	app := newGatingModeTestApp(provider)
	resp := doGatingAuthCodeFlow(t, app, provider, redirectURI, codeVerifier)
	clientID := resp["_client_id"].(string)

	t.Run("auth_code_response_includes_refresh_token", func(t *testing.T) {
		t.Parallel()
		require.NotEmpty(t, resp["access_token"])
		require.NotEmpty(t, resp["refresh_token"], "gating mode should return a refresh_token")
		require.Equal(t, "Bearer", resp["token_type"])
		require.Greater(t, resp["expires_in"].(float64), float64(0))
	})

	t.Run("refresh_grants_new_tokens", func(t *testing.T) {
		t.Parallel()
		rr := exchangeRefreshToken(t, app, clientID, resp["refresh_token"].(string))
		require.Equal(t, http.StatusOK, rr.Code)

		var refreshResp map[string]interface{}
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &refreshResp))
		require.NotEmpty(t, refreshResp["access_token"])
		require.NotEmpty(t, refreshResp["refresh_token"], "refresh response should include rotated refresh_token")
		require.Equal(t, "Bearer", refreshResp["token_type"])
		require.Greater(t, refreshResp["expires_in"].(float64), float64(0))

		// Refresh token is JWE (random IV) so always differs; access token is
		// deterministic HS256 JWT so may match within the same second — only
		// check the refresh token is rotated.
		require.NotEqual(t, resp["refresh_token"], refreshResp["refresh_token"])
	})

	t.Run("chained_refresh_works", func(t *testing.T) {
		t.Parallel()
		// First refresh
		rr1 := exchangeRefreshToken(t, app, clientID, resp["refresh_token"].(string))
		require.Equal(t, http.StatusOK, rr1.Code)
		var resp1 map[string]interface{}
		require.NoError(t, json.Unmarshal(rr1.Body.Bytes(), &resp1))

		// Second refresh using rotated token
		rr2 := exchangeRefreshToken(t, app, clientID, resp1["refresh_token"].(string))
		require.Equal(t, http.StatusOK, rr2.Code)
		var resp2 map[string]interface{}
		require.NoError(t, json.Unmarshal(rr2.Body.Bytes(), &resp2))
		require.NotEmpty(t, resp2["access_token"])
		require.NotEmpty(t, resp2["refresh_token"])
	})
}

func TestOAuthRefreshTokenInvalidGrant(t *testing.T) {
	t.Parallel()
	const redirectURI = "http://127.0.0.1:3334/callback"

	provider := newTestForwardModeOIDCProvider(t, map[string]interface{}{
		"access_token": "upstream-access-token",
		"token_type":   "Bearer",
		"expires_in":   1800,
		"scope":        "openid email",
	}, nil)
	provider.tokenResponse["id_token"] = provider.issueIDToken(t, map[string]interface{}{
		"sub":            "user-1",
		"iss":            provider.server.URL,
		"aud":            "upstream-client-id",
		"exp":            time.Now().Add(time.Hour).Unix(),
		"iat":            time.Now().Unix(),
		"email":          "user@example.com",
		"email_verified": true,
	})

	app := newGatingModeTestApp(provider)
	resp := doGatingAuthCodeFlow(t, app, provider, redirectURI, "verifier1")
	clientID := resp["_client_id"].(string)

	t.Run("wrong_client_id", func(t *testing.T) {
		t.Parallel()
		otherClientID := registerOAuthBrowserClient(t, app, redirectURI)
		rr := exchangeRefreshToken(t, app, otherClientID, resp["refresh_token"].(string))
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "not issued to this client")
	})

	t.Run("malformed_refresh_token", func(t *testing.T) {
		t.Parallel()
		rr := exchangeRefreshToken(t, app, clientID, "garbage-token")
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "invalid refresh token")
	})

	t.Run("missing_refresh_token", func(t *testing.T) {
		t.Parallel()
		form := url.Values{}
		form.Set("grant_type", "refresh_token")
		form.Set("client_id", clientID)
		req := httptest.NewRequest(http.MethodPost, "https://mcp.example.com/oauth/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		app.handleOAuthToken(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "missing refresh token")
	})

	t.Run("forward_mode_rejects_gating_refresh_token", func(t *testing.T) {
		t.Parallel()
		// Forward mode now supports refresh when UpstreamOfflineAccess is on,
		// but a refresh token minted by gating mode is not transferable: the
		// client_id encoded in the JWE belongs to the gating-mode app, not the
		// forward-mode app's freshly registered client.
		fwdApp := newForwardModeBrowserLoginTestApp(provider)
		fwdClientID := registerOAuthBrowserClient(t, fwdApp, redirectURI)
		rr := exchangeRefreshToken(t, fwdApp, fwdClientID, resp["refresh_token"].(string))
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "not issued to this client")
	})
}

func TestOAuthForwardModeNoRefreshToken(t *testing.T) {
	t.Parallel()
	const (
		redirectURI  = "http://127.0.0.1:3334/callback"
		codeVerifier = "test-code-verifier"
		clientState  = "cs"
	)

	provider := newTestForwardModeOIDCProvider(t, map[string]interface{}{
		"access_token": "upstream-access-token",
		"token_type":   "Bearer",
		"expires_in":   1800,
		"scope":        "openid email",
	}, nil)
	provider.tokenResponse["id_token"] = provider.issueIDToken(t, map[string]interface{}{
		"sub":            "user-1",
		"iss":            provider.server.URL,
		"aud":            "upstream-client-id",
		"exp":            time.Now().Add(time.Hour).Unix(),
		"iat":            time.Now().Unix(),
		"email":          "user@example.com",
		"email_verified": true,
	})

	app := newForwardModeBrowserLoginTestApp(provider)
	clientID := registerOAuthBrowserClient(t, app, redirectURI)
	state := startOAuthBrowserLogin(t, app, clientID, redirectURI, clientState, codeVerifier)

	callbackReq := httptest.NewRequest(http.MethodGet, "https://mcp.example.com/oauth/callback?code=upstream-auth-code&state="+url.QueryEscape(state), nil)
	callbackRR := httptest.NewRecorder()
	app.handleOAuthCallback(callbackRR, callbackReq)
	require.Equal(t, http.StatusFound, callbackRR.Code)

	loc, err := url.Parse(callbackRR.Header().Get("Location"))
	require.NoError(t, err)

	tokenRR := exchangeOAuthBrowserCode(t, app, clientID, loc.Query().Get("code"), redirectURI, codeVerifier)
	require.Equal(t, http.StatusOK, tokenRR.Code)

	var tokenResp map[string]interface{}
	require.NoError(t, json.Unmarshal(tokenRR.Body.Bytes(), &tokenResp))
	_, hasRefresh := tokenResp["refresh_token"]
	require.False(t, hasRefresh, "forward mode should NOT include refresh_token")
}

// newForwardModeRefreshTestApp configures a forward-mode app with
// UpstreamOfflineAccess enabled, so the auth-code response carries a JWE
// refresh_token wrapping the upstream IdP's refresh token.
func newForwardModeRefreshTestApp(provider *testForwardModeOIDCProvider) *application {
	cfg := config.Config{
		Server: config.ServerConfig{
			OAuth: config.OAuthConfig{
				Enabled:                true,
				Mode:                   "forward",
				Issuer:                 provider.server.URL,
				JWKSURL:                provider.server.URL + "/jwks",
				AuthURL:                provider.server.URL + "/authorize",
				TokenURL:               provider.server.URL + "/token",
				UserInfoURL:            provider.server.URL + "/userinfo",
				ClientID:               "upstream-client-id",
				ClientSecret:           "upstream-client-secret",
				Scopes:                 []string{"openid", "email"},
				UpstreamOfflineAccess:  true,
				SigningSecret:        "test-gating-secret-32-byte-key!!",
				RefreshTokenTTLSeconds: 86400,
			},
		},
	}
	return &application{
		config:    cfg,
		mcpServer: altinitymcp.NewClickHouseMCPServer(cfg, "test"),
	}
}

func TestOAuthForwardModeRefresh(t *testing.T) {
	t.Parallel()
	const (
		redirectURI  = "http://127.0.0.1:3334/callback"
		codeVerifier = "test-code-verifier-fwd-refresh"
		clientState  = "cs"
	)

	newProvider := func(t *testing.T) *testForwardModeOIDCProvider {
		provider := newTestForwardModeOIDCProvider(t, map[string]interface{}{
			"access_token":  "upstream-access-token",
			"refresh_token": "upstream-refresh-token-original",
			"token_type":    "Bearer",
			"expires_in":    1800,
			"scope":         "openid email offline_access",
		}, nil)
		provider.tokenResponse["id_token"] = provider.issueIDToken(t, map[string]interface{}{
			"sub":            "user-1",
			"iss":            provider.server.URL,
			"aud":            "upstream-client-id",
			"exp":            time.Now().Add(time.Hour).Unix(),
			"iat":            time.Now().Unix(),
			"email":          "user@example.com",
			"email_verified": true,
		})

		// Stateful refresh handler with strict single-use rotation: each refresh
		// invalidates the inbound token and issues a new one. Models an IdP with
		// refresh-token reuse detection enabled (e.g. Auth0 default).
		validUpstreamRefresh := map[string]bool{"upstream-refresh-token-original": true}
		rotation := 0
		var mu sync.Mutex
		provider.refreshHandler = func(form url.Values) (int, map[string]interface{}) {
			mu.Lock()
			defer mu.Unlock()
			inbound := form.Get("refresh_token")
			if !validUpstreamRefresh[inbound] {
				return http.StatusBadRequest, map[string]interface{}{"error": "invalid_grant"}
			}
			delete(validUpstreamRefresh, inbound)
			rotation++
			next := fmt.Sprintf("upstream-refresh-token-rotated-%d", rotation)
			validUpstreamRefresh[next] = true
			newIDToken := provider.issueIDToken(t, map[string]interface{}{
				"sub":            "user-1",
				"iss":            provider.server.URL,
				"aud":            "upstream-client-id",
				"exp":            time.Now().Add(time.Hour).Unix(),
				"iat":            time.Now().Add(time.Duration(rotation) * time.Second).Unix(),
				"email":          "user@example.com",
				"email_verified": true,
			})
			return http.StatusOK, map[string]interface{}{
				"access_token":  "upstream-access-token-r" + fmt.Sprint(rotation),
				"id_token":      newIDToken,
				"refresh_token": next,
				"token_type":    "Bearer",
				"expires_in":    1800,
				"scope":         "openid email offline_access",
			}
		}
		return provider
	}

	doInitialFlow := func(t *testing.T, app *application) (string, map[string]interface{}) {
		t.Helper()
		clientID := registerOAuthBrowserClient(t, app, redirectURI)
		state := startOAuthBrowserLogin(t, app, clientID, redirectURI, clientState, codeVerifier)
		callbackReq := httptest.NewRequest(http.MethodGet, "https://mcp.example.com/oauth/callback?code=upstream-auth-code&state="+url.QueryEscape(state), nil)
		callbackRR := httptest.NewRecorder()
		app.handleOAuthCallback(callbackRR, callbackReq)
		require.Equal(t, http.StatusFound, callbackRR.Code)
		loc, err := url.Parse(callbackRR.Header().Get("Location"))
		require.NoError(t, err)
		tokenRR := exchangeOAuthBrowserCode(t, app, clientID, loc.Query().Get("code"), redirectURI, codeVerifier)
		require.Equal(t, http.StatusOK, tokenRR.Code)
		var resp map[string]interface{}
		require.NoError(t, json.Unmarshal(tokenRR.Body.Bytes(), &resp))
		return clientID, resp
	}

	t.Run("auth_code_response_includes_refresh_token", func(t *testing.T) {
		t.Parallel()
		provider := newProvider(t)
		app := newForwardModeRefreshTestApp(provider)
		_, resp := doInitialFlow(t, app)

		require.Equal(t, provider.tokenResponse["id_token"], resp["access_token"], "access_token must remain the upstream ID token verbatim")
		require.NotEmpty(t, resp["refresh_token"], "forward mode + UpstreamOfflineAccess must issue a refresh_token")
		// MCP refresh token is the JWE wrapper, not the raw upstream refresh.
		require.NotEqual(t, "upstream-refresh-token-original", resp["refresh_token"])
		// expires_in must reflect the id_token's actual exp (1h here), not the
		// upstream access_token's expires_in (1800). MCP clients schedule
		// proactive refresh from this value; using the access_token TTL when
		// we forward the id_token causes downstream sessions to break at the
		// real bearer expiry.
		require.Greater(t, resp["expires_in"].(float64), float64(3500))
		require.LessOrEqual(t, resp["expires_in"].(float64), float64(3600))
	})

	t.Run("refresh_grants_new_upstream_id_token_and_rotates", func(t *testing.T) {
		t.Parallel()
		provider := newProvider(t)
		app := newForwardModeRefreshTestApp(provider)
		clientID, resp := doInitialFlow(t, app)

		rr := exchangeRefreshToken(t, app, clientID, resp["refresh_token"].(string))
		require.Equal(t, http.StatusOK, rr.Code, "refresh response body: %s", rr.Body.String())

		var refreshed map[string]interface{}
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &refreshed))
		require.NotEmpty(t, refreshed["access_token"])
		// New access_token must be a freshly minted upstream ID token, not the
		// original one returned at auth_code exchange.
		require.NotEqual(t, resp["access_token"], refreshed["access_token"])
		// Refresh token rotates (new JWE wraps the rotated upstream refresh).
		require.NotEmpty(t, refreshed["refresh_token"])
		require.NotEqual(t, resp["refresh_token"], refreshed["refresh_token"])
		require.Equal(t, "Bearer", refreshed["token_type"])
		// expires_in must reflect the rotated id_token's exp (1h), not the
		// upstream access_token's expires_in (1800). Same rationale as the
		// auth-code path above.
		require.Greater(t, refreshed["expires_in"].(float64), float64(3500))
		require.LessOrEqual(t, refreshed["expires_in"].(float64), float64(3600))
	})

	t.Run("idp_rotation_invalidates_rotated_out_mcp_refresh", func(t *testing.T) {
		t.Parallel()
		// MCP-side refresh tokens are stateless JWEs with no server-side
		// reuse detection — the JWE itself stays decryptable until its exp.
		// Security against replay therefore depends on the upstream IdP
		// enforcing rotation. This test verifies that when the upstream IdP
		// does enforce rotation (the production-recommended Auth0/Okta
		// configuration), MCP correctly surfaces upstream's rejection as
		// invalid_grant rather than silently issuing new tokens.
		provider := newProvider(t)
		app := newForwardModeRefreshTestApp(provider)
		clientID, resp := doInitialFlow(t, app)

		// First refresh succeeds; upstream rotates the underlying refresh.
		rr1 := exchangeRefreshToken(t, app, clientID, resp["refresh_token"].(string))
		require.Equal(t, http.StatusOK, rr1.Code, "first refresh should succeed: %s", rr1.Body.String())

		// Second refresh with the original (now rotated-out) MCP refresh token:
		// MCP decrypts the JWE successfully but the upstream IdP rejects the
		// underlying refresh, and MCP must return invalid_grant.
		rr2 := exchangeRefreshToken(t, app, clientID, resp["refresh_token"].(string))
		require.Equal(t, http.StatusBadRequest, rr2.Code)
		require.Contains(t, rr2.Body.String(), "invalid_grant")
		require.Contains(t, rr2.Body.String(), "upstream rejected the refresh token")
	})

	t.Run("malformed_refresh_token_rejected", func(t *testing.T) {
		t.Parallel()
		provider := newProvider(t)
		app := newForwardModeRefreshTestApp(provider)
		clientID, _ := doInitialFlow(t, app)

		rr := exchangeRefreshToken(t, app, clientID, "garbage-refresh-token")
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "invalid refresh token")
	})

	t.Run("rotating_gating_secret_invalidates_outstanding_refresh_tokens", func(t *testing.T) {
		t.Parallel()
		provider := newProvider(t)
		app := newForwardModeRefreshTestApp(provider)
		clientID, resp := doInitialFlow(t, app)

		// Rotate the symmetric secret used to encrypt the JWE.
		app.config.Server.OAuth.SigningSecret = "different-secret-32-bytes-long!!"
		app.mcpServer.Config.Server.OAuth.SigningSecret = "different-secret-32-bytes-long!!"

		// client_id is decrypted first in handleOAuthTokenRefresh, so a
		// client_id JWE keyed by the prior secret fails before the refresh
		// token is even inspected.
		rr := exchangeRefreshToken(t, app, clientID, resp["refresh_token"].(string))
		require.Equal(t, http.StatusUnauthorized, rr.Code)
		require.Contains(t, rr.Body.String(), "unknown OAuth client")
	})
}

func TestOAuthAuthorizeOfflineAccessScope(t *testing.T) {
	t.Parallel()
	const (
		redirectURI  = "http://127.0.0.1:3334/callback"
		codeVerifier = "v"
	)

	scopeFromRedirect := func(t *testing.T, app *application) []string {
		t.Helper()
		clientID := registerOAuthBrowserClient(t, app, redirectURI)
		authReq := httptest.NewRequest(
			http.MethodGet,
			"https://mcp.example.com/oauth/authorize?response_type=code&client_id="+url.QueryEscape(clientID)+
				"&redirect_uri="+url.QueryEscape(redirectURI)+
				"&scope=openid+email&state=cs"+
				"&code_challenge="+url.QueryEscape(pkceChallenge(codeVerifier))+
				"&code_challenge_method=S256",
			nil,
		)
		authRR := httptest.NewRecorder()
		app.handleOAuthAuthorize(authRR, authReq)
		require.Equal(t, http.StatusFound, authRR.Code)
		loc, err := url.Parse(authRR.Header().Get("Location"))
		require.NoError(t, err)
		return strings.Fields(loc.Query().Get("scope"))
	}

	t.Run("forward_mode_with_offline_access_appends_scope", func(t *testing.T) {
		t.Parallel()
		provider := newTestForwardModeOIDCProvider(t, map[string]interface{}{
			"access_token": "irrelevant",
			"token_type":   "Bearer",
		}, nil)
		app := newForwardModeRefreshTestApp(provider)
		scopes := scopeFromRedirect(t, app)
		require.Contains(t, scopes, "offline_access", "forward mode + UpstreamOfflineAccess must request offline_access upstream")
	})

	t.Run("forward_mode_without_offline_access_omits_scope", func(t *testing.T) {
		t.Parallel()
		provider := newTestForwardModeOIDCProvider(t, map[string]interface{}{
			"access_token": "irrelevant",
			"token_type":   "Bearer",
		}, nil)
		app := newForwardModeBrowserLoginTestApp(provider)
		scopes := scopeFromRedirect(t, app)
		require.NotContains(t, scopes, "offline_access", "default forward mode must not request offline_access")
	})

	t.Run("gating_mode_ignores_flag", func(t *testing.T) {
		t.Parallel()
		provider := newTestForwardModeOIDCProvider(t, map[string]interface{}{
			"access_token": "irrelevant",
			"token_type":   "Bearer",
		}, nil)
		app := newGatingModeTestApp(provider)
		// Even if the flag were set in gating mode, offline_access is forward-only.
		app.config.Server.OAuth.UpstreamOfflineAccess = true
		app.mcpServer.Config.Server.OAuth.UpstreamOfflineAccess = true
		scopes := scopeFromRedirect(t, app)
		require.NotContains(t, scopes, "offline_access", "gating mode must not request offline_access regardless of flag")
	})
}

func TestOAuthRefreshTokenPolicyRevalidation(t *testing.T) {
	t.Parallel()
	const (
		redirectURI  = "http://127.0.0.1:3334/callback"
		codeVerifier = "test-code-verifier-policy"
	)

	setupProviderAndApp := func(t *testing.T, email string, emailVerified bool, hd string) (*testForwardModeOIDCProvider, *application, map[string]interface{}) {
		t.Helper()
		idTokenClaims := map[string]interface{}{
			"sub":            "user-1",
			"aud":            "upstream-client-id",
			"exp":            time.Now().Add(time.Hour).Unix(),
			"iat":            time.Now().Unix(),
			"email":          email,
			"email_verified": emailVerified,
		}
		if hd != "" {
			idTokenClaims["hd"] = hd
		}

		provider := newTestForwardModeOIDCProvider(t, map[string]interface{}{
			"access_token": "upstream-access-token",
			"token_type":   "Bearer",
			"expires_in":   1800,
			"scope":        "openid email",
		}, nil)
		idTokenClaims["iss"] = provider.server.URL
		provider.tokenResponse["id_token"] = provider.issueIDToken(t, idTokenClaims)

		app := newGatingModeTestApp(provider)
		resp := doGatingAuthCodeFlow(t, app, provider, redirectURI, codeVerifier)
		return provider, app, resp
	}

	t.Run("refresh_rejected_when_email_domain_removed", func(t *testing.T) {
		t.Parallel()
		_, app, resp := setupProviderAndApp(t, "user@allowed.com", true, "")
		app.config.Server.OAuth.AllowedEmailDomains = []string{"allowed.com"}
		app.mcpServer.Config.Server.OAuth.AllowedEmailDomains = []string{"allowed.com"}

		// Verify refresh works before policy change
		clientID := resp["_client_id"].(string)
		rr := exchangeRefreshToken(t, app, clientID, resp["refresh_token"].(string))
		require.Equal(t, http.StatusOK, rr.Code)

		// Change policy to remove the allowed domain
		app.config.Server.OAuth.AllowedEmailDomains = []string{"other.com"}
		app.mcpServer.Config.Server.OAuth.AllowedEmailDomains = []string{"other.com"}

		rr = exchangeRefreshToken(t, app, clientID, resp["refresh_token"].(string))
		require.Equal(t, http.StatusForbidden, rr.Code)
		require.Contains(t, rr.Body.String(), "access_denied")
	})

	t.Run("refresh_rejected_when_email_verification_required", func(t *testing.T) {
		t.Parallel()
		_, app, resp := setupProviderAndApp(t, "user@example.com", false, "")
		clientID := resp["_client_id"].(string)

		// Works when not required
		rr := exchangeRefreshToken(t, app, clientID, resp["refresh_token"].(string))
		require.Equal(t, http.StatusOK, rr.Code)

		// Now require email verification
		app.config.Server.OAuth.RequireEmailVerified = true
		app.mcpServer.Config.Server.OAuth.RequireEmailVerified = true

		rr = exchangeRefreshToken(t, app, clientID, resp["refresh_token"].(string))
		require.Equal(t, http.StatusForbidden, rr.Code)
		require.Contains(t, rr.Body.String(), "access_denied")
	})

	t.Run("refresh_rejected_when_hosted_domain_removed", func(t *testing.T) {
		t.Parallel()
		_, app, resp := setupProviderAndApp(t, "user@corp.com", true, "corp.com")
		app.config.Server.OAuth.AllowedHostedDomains = []string{"corp.com"}
		app.mcpServer.Config.Server.OAuth.AllowedHostedDomains = []string{"corp.com"}

		clientID := resp["_client_id"].(string)
		rr := exchangeRefreshToken(t, app, clientID, resp["refresh_token"].(string))
		require.Equal(t, http.StatusOK, rr.Code)

		// Change policy
		app.config.Server.OAuth.AllowedHostedDomains = []string{"other.com"}
		app.mcpServer.Config.Server.OAuth.AllowedHostedDomains = []string{"other.com"}

		rr = exchangeRefreshToken(t, app, clientID, resp["refresh_token"].(string))
		require.Equal(t, http.StatusForbidden, rr.Code)
		require.Contains(t, rr.Body.String(), "access_denied")
	})

	t.Run("refresh_succeeds_when_policy_still_satisfied", func(t *testing.T) {
		t.Parallel()
		_, app, resp := setupProviderAndApp(t, "user@allowed.com", true, "")
		app.config.Server.OAuth.AllowedEmailDomains = []string{"allowed.com"}
		app.mcpServer.Config.Server.OAuth.AllowedEmailDomains = []string{"allowed.com"}

		clientID := resp["_client_id"].(string)
		rr := exchangeRefreshToken(t, app, clientID, resp["refresh_token"].(string))
		require.Equal(t, http.StatusOK, rr.Code)

		var refreshResp map[string]interface{}
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &refreshResp))
		require.NotEmpty(t, refreshResp["access_token"])
		require.NotEmpty(t, refreshResp["refresh_token"])
	})
}

func TestOAuthRegistrationNegative(t *testing.T) {
	t.Parallel()
	provider := newTestForwardModeOIDCProvider(t, nil, nil)
	app := newGatingModeTestApp(provider)

	post := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "https://mcp.example.com/oauth/register", strings.NewReader(body))
		rr := httptest.NewRecorder()
		app.handleOAuthRegister(rr, req)
		return rr
	}

	t.Run("invalid_json", func(t *testing.T) {
		t.Parallel()
		rr := post("{broken")
		require.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("empty_redirect_uris", func(t *testing.T) {
		t.Parallel()
		rr := post(`{"redirect_uris":[]}`)
		require.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("http_non_localhost_redirect", func(t *testing.T) {
		t.Parallel()
		rr := post(`{"redirect_uris":["http://evil.com/cb"]}`)
		require.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("invalid_redirect_uri", func(t *testing.T) {
		t.Parallel()
		rr := post(`{"redirect_uris":["not-a-url"]}`)
		require.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("unsupported_auth_method", func(t *testing.T) {
		t.Parallel()
		// client_secret_post / client_secret_basic / none are now supported.
		// Anything else (e.g. private_key_jwt) must still be rejected.
		rr := post(`{"redirect_uris":["https://example.com/cb"],"token_endpoint_auth_method":"private_key_jwt"}`)
		require.Equal(t, http.StatusBadRequest, rr.Code)
	})
}

func TestOAuthAuthorizeNegative(t *testing.T) {
	t.Parallel()
	provider := newTestForwardModeOIDCProvider(t, nil, nil)
	app := newGatingModeTestApp(provider)
	redirectURI := "http://127.0.0.1:3334/callback"
	clientID := registerOAuthBrowserClient(t, app, redirectURI)

	get := func(query string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "https://mcp.example.com/oauth/authorize?"+query, nil)
		rr := httptest.NewRecorder()
		app.handleOAuthAuthorize(rr, req)
		return rr
	}

	t.Run("missing_client_id", func(t *testing.T) {
		t.Parallel()
		rr := get("redirect_uri=" + url.QueryEscape(redirectURI) + "&response_type=code&code_challenge=abc&code_challenge_method=S256")
		require.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("missing_redirect_uri", func(t *testing.T) {
		t.Parallel()
		rr := get("client_id=" + url.QueryEscape(clientID) + "&response_type=code&code_challenge=abc&code_challenge_method=S256")
		require.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("redirect_uri_mismatch", func(t *testing.T) {
		t.Parallel()
		rr := get("client_id=" + url.QueryEscape(clientID) + "&redirect_uri=" + url.QueryEscape("https://evil.com/cb") + "&response_type=code&code_challenge=abc&code_challenge_method=S256")
		require.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("missing_pkce_challenge", func(t *testing.T) {
		t.Parallel()
		rr := get("client_id=" + url.QueryEscape(clientID) + "&redirect_uri=" + url.QueryEscape(redirectURI) + "&response_type=code&code_challenge_method=S256")
		require.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("wrong_pkce_method", func(t *testing.T) {
		t.Parallel()
		rr := get("client_id=" + url.QueryEscape(clientID) + "&redirect_uri=" + url.QueryEscape(redirectURI) + "&response_type=code&code_challenge=abc&code_challenge_method=plain")
		require.Equal(t, http.StatusBadRequest, rr.Code)
	})
}

func TestOAuthCallbackNegative(t *testing.T) {
	t.Parallel()
	provider := newTestForwardModeOIDCProvider(t, map[string]interface{}{
		"access_token": "upstream-access-token",
		"token_type":   "Bearer",
		"expires_in":   1800,
		"scope":        "openid email",
	}, nil)
	provider.tokenResponse["id_token"] = provider.issueIDToken(t, map[string]interface{}{
		"sub":            "user-1",
		"iss":            provider.server.URL,
		"aud":            "upstream-client-id",
		"exp":            time.Now().Add(time.Hour).Unix(),
		"iat":            time.Now().Unix(),
		"email":          "user@example.com",
		"email_verified": true,
	})
	app := newGatingModeTestApp(provider)

	t.Run("missing_state", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "https://mcp.example.com/oauth/callback?code=some-code", nil)
		rr := httptest.NewRecorder()
		app.handleOAuthCallback(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("missing_code", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "https://mcp.example.com/oauth/callback?state=some-state", nil)
		rr := httptest.NewRecorder()
		app.handleOAuthCallback(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("unknown_pending_state", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "https://mcp.example.com/oauth/callback?code=some-code&state=random-unknown-state", nil)
		rr := httptest.NewRecorder()
		app.handleOAuthCallback(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("upstream_token_endpoint_500", func(t *testing.T) {
		t.Parallel()
		// Create a mock server that returns 500 from its token endpoint
		errorServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/token" {
				http.Error(w, "internal server error", http.StatusInternalServerError)
				return
			}
			http.NotFound(w, r)
		}))
		defer errorServer.Close()

		errorApp := &application{
			config: config.Config{
				Server: config.ServerConfig{
					OAuth: config.OAuthConfig{
						Enabled:                true,
						Mode:                   "gating",
						Issuer:                 errorServer.URL,
						TokenURL:               errorServer.URL + "/token",
						AuthURL:                errorServer.URL + "/authorize",
						ClientID:               "upstream-client-id",
						ClientSecret:           "upstream-client-secret",
						Scopes:                 []string{"openid", "email"},
						SigningSecret:        "test-gating-secret-32-byte-key!!",
						AccessTokenTTLSeconds:  300,
						RefreshTokenTTLSeconds: 86400,
					},
				},
			},
		}
		errorApp.mcpServer = altinitymcp.NewClickHouseMCPServer(errorApp.config, "test")

		redirectURI := "http://127.0.0.1:3334/callback"
		clientID := registerOAuthBrowserClient(t, errorApp, redirectURI)
		state := startOAuthBrowserLogin(t, errorApp, clientID, redirectURI, "s", "verifier")

		req := httptest.NewRequest(http.MethodGet, "https://mcp.example.com/oauth/callback?code=upstream-auth-code&state="+url.QueryEscape(state), nil)
		rr := httptest.NewRecorder()
		errorApp.handleOAuthCallback(rr, req)
		require.Equal(t, http.StatusBadGateway, rr.Code)
	})

	t.Run("upstream_returns_empty_tokens", func(t *testing.T) {
		t.Parallel()
		emptyProvider := newTestForwardModeOIDCProvider(t, map[string]interface{}{
			"token_type": "Bearer",
			"expires_in": 1800,
		}, nil)
		emptyApp := newGatingModeTestApp(emptyProvider)

		redirectURI := "http://127.0.0.1:3334/callback"
		clientID := registerOAuthBrowserClient(t, emptyApp, redirectURI)
		state := startOAuthBrowserLogin(t, emptyApp, clientID, redirectURI, "s", "verifier")

		req := httptest.NewRequest(http.MethodGet, "https://mcp.example.com/oauth/callback?code=upstream-auth-code&state="+url.QueryEscape(state), nil)
		rr := httptest.NewRecorder()
		emptyApp.handleOAuthCallback(rr, req)
		require.Equal(t, http.StatusBadGateway, rr.Code)
	})
}

func TestOAuthTokenExchangeNegative(t *testing.T) {
	t.Parallel()
	provider := newTestForwardModeOIDCProvider(t, map[string]interface{}{
		"access_token": "upstream-access-token",
		"token_type":   "Bearer",
		"expires_in":   1800,
		"scope":        "openid email",
	}, nil)
	provider.tokenResponse["id_token"] = provider.issueIDToken(t, map[string]interface{}{
		"sub":            "user-1",
		"iss":            provider.server.URL,
		"aud":            "upstream-client-id",
		"exp":            time.Now().Add(time.Hour).Unix(),
		"iat":            time.Now().Unix(),
		"email":          "user@example.com",
		"email_verified": true,
	})
	app := newGatingModeTestApp(provider)
	redirectURI := "http://127.0.0.1:3334/callback"
	clientID := registerOAuthBrowserClient(t, app, redirectURI)

	postToken := func(form url.Values) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "https://mcp.example.com/oauth/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		app.handleOAuthToken(rr, req)
		return rr
	}

	t.Run("unknown_auth_code", func(t *testing.T) {
		t.Parallel()
		form := url.Values{}
		form.Set("grant_type", "authorization_code")
		form.Set("client_id", clientID)
		form.Set("code", "random-unknown-code")
		form.Set("redirect_uri", redirectURI)
		form.Set("code_verifier", "test-verifier")
		rr := postToken(form)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "invalid_grant")
	})

	t.Run("redirect_uri_mismatch", func(t *testing.T) {
		t.Parallel()
		codeVerifier := "test-code-verifier-neg"
		state := startOAuthBrowserLogin(t, app, clientID, redirectURI, "s", codeVerifier)

		callbackReq := httptest.NewRequest(http.MethodGet, "https://mcp.example.com/oauth/callback?code=upstream-auth-code&state="+url.QueryEscape(state), nil)
		callbackRR := httptest.NewRecorder()
		app.handleOAuthCallback(callbackRR, callbackReq)
		require.Equal(t, http.StatusFound, callbackRR.Code)
		loc, err := url.Parse(callbackRR.Header().Get("Location"))
		require.NoError(t, err)

		form := url.Values{}
		form.Set("grant_type", "authorization_code")
		form.Set("client_id", clientID)
		form.Set("code", loc.Query().Get("code"))
		form.Set("redirect_uri", "https://wrong.example.com/cb")
		form.Set("code_verifier", codeVerifier)
		rr := postToken(form)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "invalid_grant")
	})

	t.Run("wrong_pkce_verifier", func(t *testing.T) {
		t.Parallel()
		codeVerifier := "correct-code-verifier"
		state := startOAuthBrowserLogin(t, app, clientID, redirectURI, "s", codeVerifier)

		callbackReq := httptest.NewRequest(http.MethodGet, "https://mcp.example.com/oauth/callback?code=upstream-auth-code&state="+url.QueryEscape(state), nil)
		callbackRR := httptest.NewRecorder()
		app.handleOAuthCallback(callbackRR, callbackReq)
		require.Equal(t, http.StatusFound, callbackRR.Code)
		loc, err := url.Parse(callbackRR.Header().Get("Location"))
		require.NoError(t, err)

		form := url.Values{}
		form.Set("grant_type", "authorization_code")
		form.Set("client_id", clientID)
		form.Set("code", loc.Query().Get("code"))
		form.Set("redirect_uri", redirectURI)
		form.Set("code_verifier", "wrong-verifier")
		rr := postToken(form)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "invalid_grant")
	})

	t.Run("unsupported_grant_type", func(t *testing.T) {
		t.Parallel()
		form := url.Values{}
		form.Set("grant_type", "client_credentials")
		form.Set("client_id", clientID)
		rr := postToken(form)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "unsupported_grant_type")
	})
}

func TestOAuthGatingFlowE2E(t *testing.T) {
	t.Parallel()
	provider := newTestForwardModeOIDCProvider(t, map[string]interface{}{
		"access_token": "upstream-access-token",
		"token_type":   "Bearer",
		"expires_in":   1800,
		"scope":        "openid email",
	}, nil)
	provider.tokenResponse["id_token"] = provider.issueIDToken(t, map[string]interface{}{
		"sub":            "user-1",
		"iss":            provider.server.URL,
		"aud":            "upstream-client-id",
		"exp":            time.Now().Add(time.Hour).Unix(),
		"iat":            time.Now().Unix(),
		"email":          "user@example.com",
		"email_verified": true,
		"name":           "Test User",
	})

	app := newGatingModeTestApp(provider)
	// Set PublicAuthServerURL so self-issued tokens use a stable issuer
	app.config.Server.OAuth.PublicAuthServerURL = "https://mcp.example.com"
	app.mcpServer.Config.Server.OAuth.PublicAuthServerURL = "https://mcp.example.com"
	const redirectURI = "http://127.0.0.1:3334/callback"
	const codeVerifier = "e2e-code-verifier-for-pkce-test"

	// Step 1: Discovery document
	t.Run("discovery_document", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "https://mcp.example.com/.well-known/oauth-authorization-server", nil)
		rr := httptest.NewRecorder()
		app.handleOAuthAuthorizationServerMetadata(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)

		var meta map[string]interface{}
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &meta))
		require.NotEmpty(t, meta["token_endpoint"])
		require.NotEmpty(t, meta["authorization_endpoint"])
		require.NotEmpty(t, meta["registration_endpoint"])
	})

	// Step 2: Register client
	clientID := registerOAuthBrowserClient(t, app, redirectURI)

	// Step 3: Authorize with PKCE S256
	state := startOAuthBrowserLogin(t, app, clientID, redirectURI, "client-state-123", codeVerifier)

	// Step 4: Callback with upstream code + state
	callbackReq := httptest.NewRequest(http.MethodGet, "https://mcp.example.com/oauth/callback?code=upstream-auth-code&state="+url.QueryEscape(state), nil)
	callbackRR := httptest.NewRecorder()
	app.handleOAuthCallback(callbackRR, callbackReq)
	require.Equal(t, http.StatusFound, callbackRR.Code)

	loc, err := url.Parse(callbackRR.Header().Get("Location"))
	require.NoError(t, err)
	authCode := loc.Query().Get("code")
	require.NotEmpty(t, authCode)
	require.Equal(t, "client-state-123", loc.Query().Get("state"))

	// Step 5: Token exchange with PKCE verifier
	tokenRR := exchangeOAuthBrowserCode(t, app, clientID, authCode, redirectURI, codeVerifier)
	require.Equal(t, http.StatusOK, tokenRR.Code)

	var tokenResp map[string]interface{}
	require.NoError(t, json.Unmarshal(tokenRR.Body.Bytes(), &tokenResp))
	accessToken := tokenResp["access_token"].(string)
	refreshToken := tokenResp["refresh_token"].(string)
	require.NotEmpty(t, accessToken)
	require.NotEmpty(t, refreshToken)
	require.Equal(t, "Bearer", tokenResp["token_type"])

	// Step 6: Verify access token is valid HS256 JWT
	t.Run("access_token_is_valid_jwt", func(t *testing.T) {
		t.Parallel()
		claims, err := app.mcpServer.ValidateOAuthToken(accessToken)
		require.NoError(t, err)
		require.Equal(t, "user-1", claims.Subject)
		require.Equal(t, "user@example.com", claims.Email)
	})

	// Step 7: Refresh token exchange
	t.Run("refresh_token_exchange", func(t *testing.T) {
		t.Parallel()
		rr := exchangeRefreshToken(t, app, clientID, refreshToken)
		require.Equal(t, http.StatusOK, rr.Code)

		var refreshResp map[string]interface{}
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &refreshResp))
		require.NotEmpty(t, refreshResp["access_token"])
		require.NotEmpty(t, refreshResp["refresh_token"])
		require.Equal(t, "Bearer", refreshResp["token_type"])
		require.NotEqual(t, refreshToken, refreshResp["refresh_token"])
	})
}

func TestOAuthMetadataAdvertisesRefreshToken(t *testing.T) {
	t.Parallel()
	provider := newTestForwardModeOIDCProvider(t, nil, nil)
	app := newGatingModeTestApp(provider)

	for _, path := range []string{
		"/.well-known/oauth-authorization-server",
		"/.well-known/openid-configuration",
	} {
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(http.MethodGet, "https://mcp.example.com"+path, nil)
			rr := httptest.NewRecorder()
			if strings.Contains(path, "openid") {
				app.handleOAuthOpenIDConfiguration(rr, req)
			} else {
				app.handleOAuthAuthorizationServerMetadata(rr, req)
			}
			require.Equal(t, http.StatusOK, rr.Code)

			var meta map[string]interface{}
			require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &meta))
			grants, ok := meta["grant_types_supported"].([]interface{})
			require.True(t, ok)
			var grantStrings []string
			for _, g := range grants {
				grantStrings = append(grantStrings, g.(string))
			}
			require.Contains(t, grantStrings, "refresh_token")
		})
	}
}

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

func TestDecodeStringSlice(t *testing.T) {
	t.Parallel()
	t.Run("string_slice", func(t *testing.T) {
		t.Parallel()
		result := decodeStringSlice([]string{"a", "b"})
		require.Equal(t, []string{"a", "b"}, result)
	})
	t.Run("interface_slice", func(t *testing.T) {
		t.Parallel()
		result := decodeStringSlice([]interface{}{"a", "b"})
		require.Equal(t, []string{"a", "b"}, result)
	})
	t.Run("interface_slice_non_strings_skipped", func(t *testing.T) {
		t.Parallel()
		result := decodeStringSlice([]interface{}{"a", 123, "b"})
		require.Equal(t, []string{"a", "b"}, result)
	})
	t.Run("nil_returns_nil", func(t *testing.T) {
		t.Parallel()
		require.Nil(t, decodeStringSlice(nil))
	})
	t.Run("unsupported_type_returns_nil", func(t *testing.T) {
		t.Parallel()
		require.Nil(t, decodeStringSlice("not-a-slice"))
	})
	t.Run("empty_interface_slice", func(t *testing.T) {
		t.Parallel()
		result := decodeStringSlice([]interface{}{})
		require.Empty(t, result)
	})
}

func TestAuthenticateClientSecret(t *testing.T) {
	t.Parallel()

	t.Run("public_client_legacy_no_secret_required", func(t *testing.T) {
		t.Parallel()
		// Backward compat: client_id JWEs issued before this change have no
		// client_secret claim; they continue to work with PKCE only.
		client := &statelessRegisteredClient{}
		req := httptest.NewRequest(http.MethodPost, "/oauth/token", nil)
		require.NoError(t, req.ParseForm())
		require.NoError(t, authenticateClientSecret(client, req))
	})

	t.Run("confidential_client_secret_via_form", func(t *testing.T) {
		t.Parallel()
		client := &statelessRegisteredClient{ClientSecret: "abc123"}
		req := httptest.NewRequest(http.MethodPost, "/oauth/token",
			strings.NewReader("client_secret=abc123"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		require.NoError(t, req.ParseForm())
		require.NoError(t, authenticateClientSecret(client, req))
	})

	t.Run("confidential_client_secret_via_basic_auth", func(t *testing.T) {
		t.Parallel()
		client := &statelessRegisteredClient{ClientSecret: "abc123"}
		req := httptest.NewRequest(http.MethodPost, "/oauth/token", nil)
		req.SetBasicAuth("client-id-doesnt-matter", "abc123")
		require.NoError(t, req.ParseForm())
		require.NoError(t, authenticateClientSecret(client, req))
	})

	t.Run("confidential_client_secret_missing", func(t *testing.T) {
		t.Parallel()
		client := &statelessRegisteredClient{ClientSecret: "abc123"}
		req := httptest.NewRequest(http.MethodPost, "/oauth/token", nil)
		require.NoError(t, req.ParseForm())
		require.Error(t, authenticateClientSecret(client, req))
	})

	t.Run("confidential_client_secret_mismatch", func(t *testing.T) {
		t.Parallel()
		client := &statelessRegisteredClient{ClientSecret: "abc123"}
		req := httptest.NewRequest(http.MethodPost, "/oauth/token",
			strings.NewReader("client_secret=wrong"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		require.NoError(t, req.ParseForm())
		require.Error(t, authenticateClientSecret(client, req))
	})
}

func TestParseStatelessRegisteredClient(t *testing.T) {
	t.Parallel()
	t.Run("all_fields", func(t *testing.T) {
		t.Parallel()
		claims := map[string]interface{}{
			"redirect_uris":              []interface{}{"https://example.com/callback"},
			"token_endpoint_auth_method": "client_secret_post",
			"grant_type":                 "authorization_code",
			"exp":                        float64(time.Now().Add(time.Hour).Unix()),
		}
		client, err := parseStatelessRegisteredClient(claims)
		require.NoError(t, err)
		require.Equal(t, []string{"https://example.com/callback"}, client.RedirectURIs)
		require.Equal(t, "client_secret_post", client.TokenEndpointAuthMethod)
		require.Equal(t, "authorization_code", client.GrantType)
	})

	t.Run("defaults_applied", func(t *testing.T) {
		t.Parallel()
		claims := map[string]interface{}{
			"redirect_uris": []interface{}{"https://example.com/callback"},
		}
		client, err := parseStatelessRegisteredClient(claims)
		require.NoError(t, err)
		require.Equal(t, "none", client.TokenEndpointAuthMethod)
		require.Equal(t, "authorization_code", client.GrantType)
	})

	t.Run("missing_redirect_uris", func(t *testing.T) {
		t.Parallel()
		claims := map[string]interface{}{}
		_, err := parseStatelessRegisteredClient(claims)
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing redirect URIs")
	})

	t.Run("empty_redirect_uris", func(t *testing.T) {
		t.Parallel()
		claims := map[string]interface{}{
			"redirect_uris": []interface{}{},
		}
		_, err := parseStatelessRegisteredClient(claims)
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing redirect URIs")
	})
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

func TestOAuthStateStore(t *testing.T) {
	t.Parallel()

	t.Run("put_and_consume_pending_auth", func(t *testing.T) {
		t.Parallel()
		store := newOAuthStateStore()
		pending := oauthPendingAuth{ExpiresAt: time.Now().Add(time.Hour)}
		store.putPendingAuth("key1", pending)

		got, ok := store.consumePendingAuth("key1")
		require.True(t, ok)
		require.Equal(t, pending.ExpiresAt.Unix(), got.ExpiresAt.Unix())

		_, ok = store.consumePendingAuth("key1")
		require.False(t, ok)
	})

	t.Run("put_and_consume_auth_code", func(t *testing.T) {
		t.Parallel()
		store := newOAuthStateStore()
		issued := oauthIssuedCode{ExpiresAt: time.Now().Add(time.Hour)}
		store.putAuthCode("code1", issued)

		got, ok := store.consumeAuthCode("code1")
		require.True(t, ok)
		require.Equal(t, issued.ExpiresAt.Unix(), got.ExpiresAt.Unix())

		_, ok = store.consumeAuthCode("code1")
		require.False(t, ok)
	})

	t.Run("expired_entries_cleaned_up", func(t *testing.T) {
		t.Parallel()
		store := newOAuthStateStore()
		store.putPendingAuth("expired", oauthPendingAuth{ExpiresAt: time.Now().Add(-time.Hour)})
		store.putAuthCode("expired", oauthIssuedCode{ExpiresAt: time.Now().Add(-time.Hour)})

		// Next put triggers cleanup
		store.putPendingAuth("fresh", oauthPendingAuth{ExpiresAt: time.Now().Add(time.Hour)})
		store.putAuthCode("fresh", oauthIssuedCode{ExpiresAt: time.Now().Add(time.Hour)})

		_, ok := store.consumePendingAuth("expired")
		require.False(t, ok)
		_, ok = store.consumeAuthCode("expired")
		require.False(t, ok)
	})
}

func TestSanitizeScope(t *testing.T) {
	t.Parallel()
	require.Equal(t, "read write", sanitizeScope("  read   write  "))
	require.Equal(t, "single", sanitizeScope("single"))
	require.Equal(t, "", sanitizeScope(""))
	require.Equal(t, "", sanitizeScope("   "))
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
	rr := httptest.NewRecorder()
	writeOAuthTokenError(rr, http.StatusBadRequest, "invalid_request", "bad thing happened")
	require.Equal(t, http.StatusBadRequest, rr.Code)
	require.Equal(t, "application/json", rr.Header().Get("Content-Type"))
	var body map[string]string
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	require.Equal(t, "invalid_request", body["error"])
	require.Equal(t, "bad thing happened", body["error_description"])
}

// ----------------------------------------------------------------------
// H-2: refresh-token reuse detection (gating mode)
// ----------------------------------------------------------------------

// fakeRefreshStateStore is an in-memory oauth_state.Store for testing the
// refresh-handler control flow without standing up a CH harness. The real
// SQL is exercised by the live otel deployment's negative-replay test.
type fakeRefreshStateStore struct {
	mu        sync.Mutex
	consumed  map[string]bool   // jti → true
	revoked   map[string]string // family_id → reason
	failNext  error             // when set, next call returns this error
	calls     []fakeStoreCall
}

type fakeStoreCall struct {
	JTI      string
	FamilyID string
	Reason   string
}

func newFakeRefreshStateStore() *fakeRefreshStateStore {
	return &fakeRefreshStateStore{
		consumed: map[string]bool{},
		revoked:  map[string]string{},
	}
}

func (f *fakeRefreshStateStore) CheckAndConsume(_ context.Context, jti, familyID, reason string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, fakeStoreCall{JTI: jti, FamilyID: familyID, Reason: reason})

	if f.failNext != nil {
		err := f.failNext
		f.failNext = nil
		return err
	}

	if f.consumed[jti] || f.revoked[familyID] != "" {
		f.revoked[familyID] = reason
		return oauth_state.ErrRefreshReused
	}

	f.consumed[jti] = true
	return nil
}

// Cleanup is a no-op for the fake; the real KeeperMap-backed store runs
// `ALTER TABLE altinity.oauth_refresh_consumed_jtis DELETE WHERE
// consumed_at < now() - INTERVAL …` to bound storage. Tests that exercise
// the cleanup loop do so via a separate counter-based runner.
func (f *fakeRefreshStateStore) Cleanup(_ context.Context, _ time.Duration) error {
	return nil
}

// newGatingModeTestAppWithH2 wires a gating-mode app with H-2 enabled and
// a fake oauth_state.Store injected. ClickHouse config is not populated —
// the fake store never touches CH.
func newGatingModeTestAppWithH2(provider *testForwardModeOIDCProvider) (*application, *fakeRefreshStateStore) {
	cfg := config.Config{
		Server: config.ServerConfig{
			OAuth: config.OAuthConfig{
				Enabled:                true,
				Mode:                   "gating",
				Issuer:                 provider.server.URL,
				JWKSURL:                provider.server.URL + "/jwks",
				AuthURL:                provider.server.URL + "/authorize",
				TokenURL:               provider.server.URL + "/token",
				UserInfoURL:            provider.server.URL + "/userinfo",
				ClientID:               "upstream-client-id",
				ClientSecret:           "upstream-client-secret",
				Scopes:                 []string{"openid", "email"},
				SigningSecret:          "test-gating-secret-32-byte-key!!",
				AccessTokenTTLSeconds:  300,
				RefreshTokenTTLSeconds: 86400,
				RefreshRevokesTracking: true,
			},
		},
	}
	srv := altinitymcp.NewClickHouseMCPServer(cfg, "test")
	store := newFakeRefreshStateStore()
	srv.SetRefreshStateStore(store)
	return &application{
		config:    cfg,
		mcpServer: srv,
	}, store
}

// inspectRefreshJWE decrypts a refresh-token JWE with the test secret so
// tests can assert on jti/family_id claims.
func inspectRefreshJWE(t *testing.T, refreshToken string) map[string]interface{} {
	t.Helper()
	secret := []byte("test-gating-secret-32-byte-key!!")
	claims, err := decodeOAuthJWE(secret, hkdfInfoOAuthRefresh, refreshToken)
	require.NoError(t, err, "failed to decode test refresh JWE")
	return claims
}

func TestOAuthRefreshReuseDetection_HappyPath(t *testing.T) {
	t.Parallel()
	const (
		redirectURI  = "http://127.0.0.1:3334/callback"
		codeVerifier = "test-code-verifier"
	)

	provider := newTestForwardModeOIDCProvider(t, map[string]interface{}{
		"access_token": "upstream-access-token",
		"token_type":   "Bearer",
		"expires_in":   1800,
		"scope":        "openid email",
	}, nil)
	provider.tokenResponse["id_token"] = provider.issueIDToken(t, map[string]interface{}{
		"sub":            "user-1",
		"iss":            provider.server.URL,
		"aud":            "upstream-client-id",
		"exp":            time.Now().Add(time.Hour).Unix(),
		"iat":            time.Now().Unix(),
		"email":          "user@example.com",
		"email_verified": true,
	})

	app, store := newGatingModeTestAppWithH2(provider)
	resp := doGatingAuthCodeFlow(t, app, provider, redirectURI, codeVerifier)
	clientID := resp["_client_id"].(string)

	// Initial refresh JWE carries jti + family_id.
	r1 := resp["refresh_token"].(string)
	r1Claims := inspectRefreshJWE(t, r1)
	r1Jti, _ := r1Claims["jti"].(string)
	r1Family, _ := r1Claims["family_id"].(string)
	require.NotEmpty(t, r1Jti, "refresh token must carry jti when H-2 enabled")
	require.NotEmpty(t, r1Family, "refresh token must carry family_id when H-2 enabled")

	// Refresh once.
	rr1 := exchangeRefreshToken(t, app, clientID, r1)
	require.Equal(t, http.StatusOK, rr1.Code)
	var resp1 map[string]interface{}
	require.NoError(t, json.Unmarshal(rr1.Body.Bytes(), &resp1))

	r2 := resp1["refresh_token"].(string)
	r2Claims := inspectRefreshJWE(t, r2)
	r2Jti, _ := r2Claims["jti"].(string)
	r2Family, _ := r2Claims["family_id"].(string)

	require.NotEmpty(t, r2Jti, "rotated refresh token must have a fresh jti")
	require.NotEqual(t, r1Jti, r2Jti, "jti must rotate on every refresh")
	require.Equal(t, r1Family, r2Family, "family_id must be stable across the rotation chain")

	// Refresh again — chain should keep the same family.
	rr2 := exchangeRefreshToken(t, app, clientID, r2)
	require.Equal(t, http.StatusOK, rr2.Code)
	var resp2 map[string]interface{}
	require.NoError(t, json.Unmarshal(rr2.Body.Bytes(), &resp2))

	r3 := resp2["refresh_token"].(string)
	r3Claims := inspectRefreshJWE(t, r3)
	require.Equal(t, r1Family, r3Claims["family_id"].(string), "family_id stays stable across N refreshes")
	require.NotEqual(t, r2Jti, r3Claims["jti"].(string), "jti rotates on every refresh")

	// Two refreshes recorded; nothing revoked.
	store.mu.Lock()
	defer store.mu.Unlock()
	require.Len(t, store.calls, 2, "store should see one CheckAndConsume per refresh (R1+R2 redeemed; R3 not yet redeemed)")
	require.Empty(t, store.revoked, "no family revoked on a clean rotation chain")
	require.True(t, store.consumed[r1Jti], "R1's jti must be marked consumed")
	require.True(t, store.consumed[r2Jti], "R2's jti must be marked consumed")
}

func TestOAuthRefreshReuseDetection_ReplayRevokesFamily(t *testing.T) {
	t.Parallel()
	const (
		redirectURI  = "http://127.0.0.1:3334/callback"
		codeVerifier = "test-code-verifier"
	)

	provider := newTestForwardModeOIDCProvider(t, map[string]interface{}{
		"access_token": "upstream-access-token",
		"token_type":   "Bearer",
		"expires_in":   1800,
		"scope":        "openid email",
	}, nil)
	provider.tokenResponse["id_token"] = provider.issueIDToken(t, map[string]interface{}{
		"sub":            "user-1",
		"iss":            provider.server.URL,
		"aud":            "upstream-client-id",
		"exp":            time.Now().Add(time.Hour).Unix(),
		"iat":            time.Now().Unix(),
		"email":          "user@example.com",
		"email_verified": true,
	})

	app, store := newGatingModeTestAppWithH2(provider)
	resp := doGatingAuthCodeFlow(t, app, provider, redirectURI, codeVerifier)
	clientID := resp["_client_id"].(string)

	r1 := resp["refresh_token"].(string)
	r1Family := inspectRefreshJWE(t, r1)["family_id"].(string)

	// First redemption succeeds.
	rr1 := exchangeRefreshToken(t, app, clientID, r1)
	require.Equal(t, http.StatusOK, rr1.Code)

	var resp1 map[string]interface{}
	require.NoError(t, json.Unmarshal(rr1.Body.Bytes(), &resp1))
	r2 := resp1["refresh_token"].(string)

	// Replay R1 → 400 invalid_grant, family revoked.
	rrReplay := exchangeRefreshToken(t, app, clientID, r1)
	require.Equal(t, http.StatusBadRequest, rrReplay.Code)
	var replayBody map[string]interface{}
	require.NoError(t, json.Unmarshal(rrReplay.Body.Bytes(), &replayBody))
	require.Equal(t, "invalid_grant", replayBody["error"])
	require.Contains(t, replayBody["error_description"], "reuse")

	store.mu.Lock()
	require.Equal(t, "reuse_detected", store.revoked[r1Family], "family must be in revoked set after replay")
	store.mu.Unlock()

	// Subsequent legit redemption of R2 — family is now revoked, so this also fails.
	rrR2 := exchangeRefreshToken(t, app, clientID, r2)
	require.Equal(t, http.StatusBadRequest, rrR2.Code)
	var r2Body map[string]interface{}
	require.NoError(t, json.Unmarshal(rrR2.Body.Bytes(), &r2Body))
	require.Equal(t, "invalid_grant", r2Body["error"])
}

func TestOAuthRefreshReuseDetection_LegacyTokenRejected(t *testing.T) {
	t.Parallel()
	const (
		redirectURI  = "http://127.0.0.1:3334/callback"
		codeVerifier = "test-code-verifier"
	)

	provider := newTestForwardModeOIDCProvider(t, map[string]interface{}{
		"access_token": "upstream-access-token",
		"token_type":   "Bearer",
		"expires_in":   1800,
		"scope":        "openid email",
	}, nil)
	provider.tokenResponse["id_token"] = provider.issueIDToken(t, map[string]interface{}{
		"sub":            "user-1",
		"iss":            provider.server.URL,
		"aud":            "upstream-client-id",
		"exp":            time.Now().Add(time.Hour).Unix(),
		"iat":            time.Now().Unix(),
		"email":          "user@example.com",
		"email_verified": true,
	})

	// Build app WITHOUT H-2 first to obtain a legacy-shaped refresh token
	// (no jti, no family_id), then flip the flag to simulate a deploy that
	// turns reuse-detection on while a legacy token is in flight.
	cfg := config.Config{
		Server: config.ServerConfig{
			OAuth: config.OAuthConfig{
				Enabled:                true,
				Mode:                   "gating",
				Issuer:                 provider.server.URL,
				JWKSURL:                provider.server.URL + "/jwks",
				AuthURL:                provider.server.URL + "/authorize",
				TokenURL:               provider.server.URL + "/token",
				UserInfoURL:            provider.server.URL + "/userinfo",
				ClientID:               "upstream-client-id",
				ClientSecret:           "upstream-client-secret",
				Scopes:                 []string{"openid", "email"},
				SigningSecret:          "test-gating-secret-32-byte-key!!",
				AccessTokenTTLSeconds:  300,
				RefreshTokenTTLSeconds: 86400,
				// RefreshRevokesTracking: false initially
			},
		},
	}
	app := &application{
		config:    cfg,
		mcpServer: altinitymcp.NewClickHouseMCPServer(cfg, "test"),
	}
	resp := doGatingAuthCodeFlow(t, app, provider, redirectURI, codeVerifier)
	clientID := resp["_client_id"].(string)
	legacyRefresh := resp["refresh_token"].(string)

	// Sanity: legacy token has no jti or family_id claims.
	legacyClaims := inspectRefreshJWE(t, legacyRefresh)
	require.Empty(t, legacyClaims["jti"])
	require.Empty(t, legacyClaims["family_id"])

	// Now flip the flag (simulating helm upgrade) and inject a store.
	cfg.Server.OAuth.RefreshRevokesTracking = true
	app.config = cfg
	srv := altinitymcp.NewClickHouseMCPServer(cfg, "test")
	store := newFakeRefreshStateStore()
	srv.SetRefreshStateStore(store)
	app.mcpServer = srv

	rr := exchangeRefreshToken(t, app, clientID, legacyRefresh)
	require.Equal(t, http.StatusBadRequest, rr.Code)
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	require.Equal(t, "invalid_grant", body["error"])
	require.Contains(t, body["error_description"], "re-authenticate")

	// Importantly, the store was never consulted — legacy rejection happens
	// before the lookup. Otherwise we'd silently INSERT garbage families.
	store.mu.Lock()
	require.Empty(t, store.calls, "legacy refresh must be rejected before any store call")
	store.mu.Unlock()
}

func TestOAuthRefreshReuseDetection_StateUnreachable(t *testing.T) {
	t.Parallel()
	const (
		redirectURI  = "http://127.0.0.1:3334/callback"
		codeVerifier = "test-code-verifier"
	)

	provider := newTestForwardModeOIDCProvider(t, map[string]interface{}{
		"access_token": "upstream-access-token",
		"token_type":   "Bearer",
		"expires_in":   1800,
		"scope":        "openid email",
	}, nil)
	provider.tokenResponse["id_token"] = provider.issueIDToken(t, map[string]interface{}{
		"sub":            "user-1",
		"iss":            provider.server.URL,
		"aud":            "upstream-client-id",
		"exp":            time.Now().Add(time.Hour).Unix(),
		"iat":            time.Now().Unix(),
		"email":          "user@example.com",
		"email_verified": true,
	})

	app, store := newGatingModeTestAppWithH2(provider)
	resp := doGatingAuthCodeFlow(t, app, provider, redirectURI, codeVerifier)
	clientID := resp["_client_id"].(string)

	// Arm the store to fail the next call with a generic CH error (simulates
	// CH unreachable / RBAC denied / timeout).
	store.mu.Lock()
	store.failNext = errors.New("clickhouse: connection refused")
	store.mu.Unlock()

	rr := exchangeRefreshToken(t, app, clientID, resp["refresh_token"].(string))
	require.Equal(t, http.StatusInternalServerError, rr.Code)
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	require.Equal(t, "server_error", body["error"])
	require.Contains(t, body["error_description"], "refresh state unavailable")
}

func TestOAuthRefreshReuseDetection_ForwardModeRejectsConfig(t *testing.T) {
	t.Parallel()
	cfg := config.Config{
		Server: config.ServerConfig{
			OAuth: config.OAuthConfig{
				Enabled:                true,
				Mode:                   "forward",
				SigningSecret:          "test-gating-secret-32-byte-key!!",
				RefreshRevokesTracking: true,
			},
		},
		ClickHouse: config.ClickHouseConfig{
			Database: "default",
			Protocol: config.HTTPProtocol,
		},
	}
	err := validateOAuthRuntimeConfig(cfg)
	require.Error(t, err)
	require.Contains(t, err.Error(), "refresh_revokes_tracking is only supported in gating mode")
}

func TestOAuthRefreshReuseDetection_ReadOnlyRejectsConfig(t *testing.T) {
	t.Parallel()
	cfg := config.Config{
		Server: config.ServerConfig{
			OAuth: config.OAuthConfig{
				Enabled:                true,
				Mode:                   "gating",
				SigningSecret:          "test-gating-secret-32-byte-key!!",
				RefreshRevokesTracking: true,
			},
		},
		ClickHouse: config.ClickHouseConfig{
			Database: "default",
			ReadOnly: true,
		},
	}
	err := validateOAuthRuntimeConfig(cfg)
	require.Error(t, err)
	require.Contains(t, err.Error(), "clickhouse.read_only=false")
}

func TestOAuthRefreshReuseDetection_EmptyDatabaseRejectsConfig(t *testing.T) {
	t.Parallel()
	cfg := config.Config{
		Server: config.ServerConfig{
			OAuth: config.OAuthConfig{
				Enabled:                true,
				Mode:                   "gating",
				SigningSecret:          "test-gating-secret-32-byte-key!!",
				RefreshRevokesTracking: true,
			},
		},
		ClickHouse: config.ClickHouseConfig{
			Database: "",
		},
	}
	err := validateOAuthRuntimeConfig(cfg)
	require.Error(t, err)
	require.Contains(t, err.Error(), "non-empty clickhouse.database")
}

// TestOAuthRefreshReuseDetection_AtomicConcurrentClaim hammers the H-2
// refresh handler with N goroutines all redeeming the SAME refresh JWE in
// parallel. Verifies the atomicity property promised by KeeperMap strict
// mode: exactly one redeemer wins, all others see invalid_grant with
// reuse_detected. The fake store synchronises via sync.Mutex (faithful to
// the production semantics — Keeper Raft serialises through a single
// leader); this test exercises the handler's branching, not the wire
// protocol of CH.
//
// This is the regression test for the parallel-replay race that the
// previous SELECT-then-INSERT design left open and that prompted the
// switch to KeeperMap. If a future refactor reintroduces a check-then-act
// pattern, this test catches it.
func TestOAuthRefreshReuseDetection_AtomicConcurrentClaim(t *testing.T) {
	t.Parallel()
	const (
		redirectURI  = "http://127.0.0.1:3334/callback"
		codeVerifier = "test-code-verifier"
		concurrency  = 50
	)

	provider := newTestForwardModeOIDCProvider(t, map[string]interface{}{
		"access_token": "upstream-access-token",
		"token_type":   "Bearer",
		"expires_in":   1800,
		"scope":        "openid email",
	}, nil)
	provider.tokenResponse["id_token"] = provider.issueIDToken(t, map[string]interface{}{
		"sub":            "user-1",
		"iss":            provider.server.URL,
		"aud":            "upstream-client-id",
		"exp":            time.Now().Add(time.Hour).Unix(),
		"iat":            time.Now().Unix(),
		"email":          "user@example.com",
		"email_verified": true,
	})

	app, store := newGatingModeTestAppWithH2(provider)
	resp := doGatingAuthCodeFlow(t, app, provider, redirectURI, codeVerifier)
	clientID := resp["_client_id"].(string)
	r1 := resp["refresh_token"].(string)
	r1Family := inspectRefreshJWE(t, r1)["family_id"].(string)
	r1Jti := inspectRefreshJWE(t, r1)["jti"].(string)

	// Synchronise N goroutines on a barrier so they all release into the
	// refresh handler at once — maximises the chance of overlapping
	// CheckAndConsume calls. Buffered channels cap on the receiver side.
	type result struct {
		status int
		body   map[string]interface{}
	}
	results := make(chan result, concurrency)
	start := make(chan struct{})

	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			rr := exchangeRefreshToken(t, app, clientID, r1)
			var body map[string]interface{}
			_ = json.Unmarshal(rr.Body.Bytes(), &body)
			results <- result{status: rr.Code, body: body}
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	successes := 0
	reuseDetected := 0
	for r := range results {
		switch r.status {
		case http.StatusOK:
			successes++
		case http.StatusBadRequest:
			require.Equal(t, "invalid_grant", r.body["error"], "non-200 must be invalid_grant")
			require.Contains(t, r.body["error_description"], "reuse",
				"non-200 must be reuse-detected variant of invalid_grant")
			reuseDetected++
		default:
			t.Fatalf("unexpected status %d body %v", r.status, r.body)
		}
	}

	require.Equal(t, 1, successes,
		"exactly one redeemer must win — the atomicity property of KeeperMap strict mode")
	require.Equal(t, concurrency-1, reuseDetected,
		"all other redeemers must be rejected with reuse-detected invalid_grant")

	// Inspect store state. The winning JTI is in consumed_jtis exactly once;
	// the family is in revoked_families because at least one loser wrote it.
	store.mu.Lock()
	require.True(t, store.consumed[r1Jti], "winning jti must be marked consumed")
	require.NotEmpty(t, store.revoked[r1Family],
		"family must be marked revoked by at least one losing redeemer")
	require.Equal(t, "reuse_detected", store.revoked[r1Family])
	store.mu.Unlock()

	// Even though one redeemer "won" — could be the legitimate owner OR
	// the attacker — the family is now revoked. Subsequent refresh of the
	// winner's NEW token (which carries the same family_id) is also
	// rejected. RFC 9700 §refresh-token rotation: server can't tell which
	// party is legitimate, so the family dies on detection.
}

func TestEncodeSelfIssuedAccessToken(t *testing.T) {
	t.Parallel()
	secret := []byte("test-secret-key")
	claims := map[string]interface{}{
		"sub": "user-123",
		"iss": "test-issuer",
		"exp": float64(time.Now().Add(time.Hour).Unix()),
	}
	token, err := encodeSelfIssuedAccessToken(secret, claims)
	require.NoError(t, err)
	require.NotEmpty(t, token)
	// Token should have 3 parts separated by dots (JWT compact format)
	parts := strings.Split(token, ".")
	require.Equal(t, 3, len(parts))
}
