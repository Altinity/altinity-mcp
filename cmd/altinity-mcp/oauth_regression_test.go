package main

// Regression coverage for behaviour that survived the DCR cleanup but lost
// its tests in #116. See PR review (commit 6f8bbed → 03b19f6 → dac3961).
//
// Test groups:
//   - HKDF info-label isolation between pending-auth and auth-code JWEs
//   - Field-by-field round-trip of encodePendingAuth / encodeAuthCode
//   - Forward-mode JWT validation in the MCP auth injector
//   - /token RFC 8707 invalid_target check
//   - /.well-known/* alias-path registration
//   - End-to-end /authorize → /callback → /token through the CIMD resolver

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/altinity/altinity-mcp/pkg/config"
	"github.com/altinity/altinity-mcp/pkg/jwe_auth"
	altinitymcp "github.com/altinity/altinity-mcp/pkg/server"
	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"
)

// --- HKDF + JWE round-trip ----------------------------------------------

func TestOAuthJWEHKDFRoundtripAndIsolation(t *testing.T) {
	t.Parallel()
	secret := []byte("regression-hkdf-secret-32-bytes!")

	t.Run("pending-auth roundtrip", func(t *testing.T) {
		t.Parallel()
		in := map[string]interface{}{
			"client_id":    "https://x.example/y.json",
			"redirect_uri": "https://x.example/cb",
			"exp":          time.Now().Add(time.Hour).Unix(),
		}
		token, err := encodeOAuthJWE(secret, hkdfInfoOAuthPendingAuth, in)
		require.NoError(t, err)
		out, err := decodeOAuthJWE(secret, hkdfInfoOAuthPendingAuth, token)
		require.NoError(t, err)
		require.Equal(t, in["client_id"], out["client_id"])
		require.Equal(t, in["redirect_uri"], out["redirect_uri"])
	})

	t.Run("auth-code roundtrip", func(t *testing.T) {
		t.Parallel()
		in := map[string]interface{}{
			"client_id":          "https://x.example/y.json",
			"upstream_auth_code": "abc",
			"exp":                time.Now().Add(60 * time.Second).Unix(),
		}
		token, err := encodeOAuthJWE(secret, hkdfInfoOAuthAuthCode, in)
		require.NoError(t, err)
		out, err := decodeOAuthJWE(secret, hkdfInfoOAuthAuthCode, token)
		require.NoError(t, err)
		require.Equal(t, in["upstream_auth_code"], out["upstream_auth_code"])
	})

	t.Run("HKDF info-label isolation: pending JWE will not decode as auth-code", func(t *testing.T) {
		t.Parallel()
		token, err := encodeOAuthJWE(secret, hkdfInfoOAuthPendingAuth, map[string]interface{}{
			"client_id": "https://x.example/y.json",
			"exp":       time.Now().Add(time.Hour).Unix(),
		})
		require.NoError(t, err)
		_, err = decodeOAuthJWE(secret, hkdfInfoOAuthAuthCode, token)
		require.Error(t, err, "JWE minted under pending-auth/v1 must NOT decrypt under auth-code/v2 — that's the whole point of HKDF info-label separation")
	})

	t.Run("legacy kid=\"\" fallback path is reachable via jwe_auth.ParseAndDecryptJWE", func(t *testing.T) {
		t.Parallel()
		// Mint a legacy JWE the same way pre-HKDF artifacts were minted
		// (SHA256(secret) → A256GCM, no kid).
		legacy, err := jwe_auth.GenerateJWEToken(map[string]interface{}{
			"sub": "legacy-subject",
			"exp": time.Now().Add(time.Hour).Unix(),
		}, secret, nil)
		require.NoError(t, err)
		// decodeOAuthJWE inspects the kid header: kid="" routes to the
		// legacy SHA256 path. Any info label works because the legacy path
		// doesn't HKDF-derive — passing the auth-code label here mirrors
		// what a production token-handler call would do.
		claims, err := decodeOAuthJWE(secret, hkdfInfoOAuthAuthCode, legacy)
		require.NoError(t, err)
		require.Equal(t, "legacy-subject", claims["sub"])
	})
}

// --- pending-auth / auth-code field-by-field round-trip -----------------

func TestOAuthPendingAuthAndAuthCodeRoundTrip(t *testing.T) {
	t.Parallel()
	app := &application{
		config: config.Config{Server: config.ServerConfig{OAuth: config.OAuthConfig{
			SigningSecret: "regression-roundtrip-32-bytes!!",
		}}},
	}

	t.Run("oauthPendingAuth", func(t *testing.T) {
		t.Parallel()
		in := oauthPendingAuth{
			ClientID:             "https://claude.ai/oauth/x",
			RedirectURI:          "https://claude.ai/cb",
			Scope:                "openid email",
			ClientState:          "csrf-state",
			CodeChallenge:        "ZH-pVPpAjHk",
			CodeChallengeMethod:  "S256",
			Resource:             "https://mcp.example.com/",
			UpstreamPKCEVerifier: "upstream-verifier",
			ExpiresAt:            time.Now().Add(time.Hour).Truncate(time.Second),
		}
		token, err := app.encodePendingAuth(in)
		require.NoError(t, err)
		out, ok := app.decodePendingAuth(token)
		require.True(t, ok)
		require.Equal(t, in.ClientID, out.ClientID)
		require.Equal(t, in.RedirectURI, out.RedirectURI)
		require.Equal(t, in.Scope, out.Scope)
		require.Equal(t, in.ClientState, out.ClientState)
		require.Equal(t, in.CodeChallenge, out.CodeChallenge)
		require.Equal(t, in.CodeChallengeMethod, out.CodeChallengeMethod)
		require.Equal(t, in.Resource, out.Resource)
		require.Equal(t, in.UpstreamPKCEVerifier, out.UpstreamPKCEVerifier)
	})

	t.Run("oauthIssuedCode", func(t *testing.T) {
		t.Parallel()
		in := oauthIssuedCode{
			ClientID:             "https://claude.ai/oauth/x",
			RedirectURI:          "https://claude.ai/cb",
			Scope:                "openid email",
			CodeChallenge:        "ZH-pVPpAjHk",
			CodeChallengeMethod:  "S256",
			Resource:             "https://mcp.example.com/",
			UpstreamAuthCode:     "upstream-code-abc",
			UpstreamPKCEVerifier: "upstream-verifier",
			ExpiresAt:            time.Now().Add(60 * time.Second).Truncate(time.Second),
		}
		token, err := app.encodeAuthCode(in)
		require.NoError(t, err)
		out, ok := app.decodeAuthCode(token)
		require.True(t, ok)
		require.Equal(t, in.ClientID, out.ClientID)
		require.Equal(t, in.RedirectURI, out.RedirectURI)
		require.Equal(t, in.Scope, out.Scope)
		require.Equal(t, in.CodeChallenge, out.CodeChallenge)
		require.Equal(t, in.CodeChallengeMethod, out.CodeChallengeMethod)
		require.Equal(t, in.Resource, out.Resource)
		require.Equal(t, in.UpstreamAuthCode, out.UpstreamAuthCode)
		require.Equal(t, in.UpstreamPKCEVerifier, out.UpstreamPKCEVerifier)
	})
}

// --- forward-mode JWT validation in the MCP auth injector ----------------

func TestOAuthMCPAuthInjectorForwardModeValidatesJWT(t *testing.T) {
	t.Parallel()
	provider := newRegressionOIDCProvider(t, nil, nil)
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

	mkReq := func(token string) (*httptest.ResponseRecorder, *http.Request) {
		req := httptest.NewRequest(http.MethodPost, "https://mcp.example.com/", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		return httptest.NewRecorder(), req
	}

	t.Run("valid JWT reaches handler with claims", func(t *testing.T) {
		t.Parallel()
		tok := provider.issueIDToken(t, map[string]interface{}{
			"sub": "u-good",
			"iss": provider.server.URL,
			"aud": "clickhouse-api",
			"exp": time.Now().Add(time.Hour).Unix(),
			"iat": time.Now().Unix(),
		})
		rr, req := mkReq(tok)
		called := false
		app.createMCPAuthInjector(app.config)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
			require.Equal(t, tok, r.Context().Value(altinitymcp.OAuthTokenKey))
			claims, ok := r.Context().Value(altinitymcp.OAuthClaimsKey).(*altinitymcp.OAuthClaims)
			require.True(t, ok)
			require.Equal(t, "u-good", claims.Subject)
			w.WriteHeader(http.StatusOK)
		})).ServeHTTP(rr, req)
		require.True(t, called)
		require.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("wrong-audience JWT rejected with 401", func(t *testing.T) {
		t.Parallel()
		tok := provider.issueIDToken(t, map[string]interface{}{
			"sub": "u-bad-aud",
			"iss": provider.server.URL,
			"aud": "some-other-api",
			"exp": time.Now().Add(time.Hour).Unix(),
		})
		rr, req := mkReq(tok)
		called := false
		app.createMCPAuthInjector(app.config)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
			w.WriteHeader(http.StatusOK)
		})).ServeHTTP(rr, req)
		require.False(t, called, "wrong-aud token must not reach inner handler")
		require.Equal(t, http.StatusUnauthorized, rr.Code)
		require.Contains(t, rr.Header().Get("WWW-Authenticate"), `error="invalid_token"`)
	})

	t.Run("expired JWT rejected with 401", func(t *testing.T) {
		t.Parallel()
		tok := provider.issueIDToken(t, map[string]interface{}{
			"sub": "u-expired",
			"iss": provider.server.URL,
			"aud": "clickhouse-api",
			"exp": time.Now().Add(-2 * time.Hour).Unix(),
			"iat": time.Now().Add(-3 * time.Hour).Unix(),
		})
		rr, req := mkReq(tok)
		called := false
		app.createMCPAuthInjector(app.config)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
			w.WriteHeader(http.StatusOK)
		})).ServeHTTP(rr, req)
		require.False(t, called, "expired token must not reach inner handler")
		require.Equal(t, http.StatusUnauthorized, rr.Code)
	})
}

// --- /token RFC 8707 invalid_target mismatch ---------------------------

func TestOAuthForwardModeTokenResourceMismatch(t *testing.T) {
	t.Parallel()
	const (
		cimdURL        = "https://demo.example.com/cimd.json"
		redirectURI    = "https://demo.example.com/cb"
		boundResource  = "https://mcp.example.com/"
		clashResource  = "https://other.example.com/"
		signingSecret  = "regression-resource-32-bytes!!!!"
	)
	// CIMD doc server so the resolver can satisfy /token.
	cimdServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"client_id":%q,"client_name":"D","redirect_uris":[%q],"token_endpoint_auth_method":"none"}`, cimdURL, redirectURI)
	}))
	defer cimdServer.Close()

	cfg := config.Config{
		Server: config.ServerConfig{
			OAuth: config.OAuthConfig{
				Enabled:             true,
				Mode:                "forward",
				Issuer:              "https://idp.example.com",
				PublicAuthServerURL: "https://mcp.example.com",
				SigningSecret:       signingSecret,
			},
		},
	}
	app := &application{
		config:       cfg,
		mcpServer:    altinitymcp.NewClickHouseMCPServer(cfg, "test"),
		cimdResolver: testResolver(t, cimdServer),
	}

	verifier, err := newPKCEVerifier()
	require.NoError(t, err)
	issued := oauthIssuedCode{
		ClientID:             cimdURL,
		RedirectURI:          redirectURI,
		Scope:                "openid email",
		CodeChallenge:        pkceChallenge(verifier),
		CodeChallengeMethod:  "S256",
		Resource:             boundResource,
		UpstreamAuthCode:     "unused-this-test-rejects-pre-upstream",
		UpstreamPKCEVerifier: "uv",
		ExpiresAt:            time.Now().Add(60 * time.Second),
	}
	code, err := app.encodeAuthCode(issued)
	require.NoError(t, err)

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", cimdURL)
	form.Set("redirect_uri", redirectURI)
	form.Set("code", code)
	form.Set("code_verifier", verifier)
	form.Set("resource", clashResource) // <- mismatch
	req := httptest.NewRequest(http.MethodPost, "https://mcp.example.com/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	require.NoError(t, req.ParseForm())
	rr := httptest.NewRecorder()
	app.handleOAuthTokenAuthCode(rr, req)

	require.Equal(t, http.StatusBadRequest, rr.Code, "body=%s", rr.Body.String())
	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	require.Equal(t, "invalid_target", resp["error"])
}

// --- .well-known alias paths ---------------------------------------------

func TestRegisterOAuthHTTPRoutesAliases(t *testing.T) {
	t.Parallel()
	app := &application{
		config: config.Config{Server: config.ServerConfig{OAuth: config.OAuthConfig{
			Enabled:             true,
			Mode:                "forward",
			Issuer:              "https://idp.example.com",
			PublicAuthServerURL: "https://mcp.example.com",
			SigningSecret:       "regression-aliases-32-bytes!!!!!",
		}}},
	}
	mux := http.NewServeMux()
	app.registerOAuthHTTPRoutes(mux)

	// Each alias path must return the same JSON document (modulo OIDC's
	// id_token_signing_alg_values_supported extra in gating-mode openid
	// configuration — we run forward so neither path adds it).
	for _, path := range []string{
		"/.well-known/oauth-authorization-server",
		"/.well-known/oauth-authorization-server/oauth",
		"/oauth/.well-known/oauth-authorization-server",
		"/.well-known/openid-configuration",
		"/.well-known/openid-configuration/oauth",
		"/oauth/.well-known/openid-configuration",
	} {
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "https://mcp.example.com"+path, nil))
			require.Equal(t, http.StatusOK, rr.Code, "alias %s should serve metadata", path)
			var doc map[string]interface{}
			require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &doc))
			require.Equal(t, true, doc["client_id_metadata_document_supported"], "alias %s must advertise CIMD support", path)
			require.NotContains(t, doc, "registration_endpoint", "alias %s must not advertise DCR endpoint", path)
		})
	}
}

// --- CIMD end-to-end happy path ------------------------------------------

// TestCIMDFullAuthCodeFlow walks /authorize → /callback → /token through a
// resolver that fetches a fake CIMD doc, a fake upstream IdP that mints
// access_tokens, and an in-process userinfo endpoint. Closes the gap left
// by oauth_ha_replay_test.go, which short-circuits to /token from a hand-
// built JWE auth-code.
func TestCIMDFullAuthCodeFlow(t *testing.T) {
	t.Parallel()
	const (
		downstreamClient = "https://demo.example.com/cimd.json"
		downstreamRedir  = "https://demo.example.com/cb"
		upstreamClient   = "broker-client"
		upstreamSecret   = "broker-secret"
		signingSecret    = "regression-fullflow-32-bytes!!!!"
	)

	// Fake upstream IdP.
	tokenRedemptions := int32(0)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/authorize":
			// Bounce straight to the broker's /oauth/callback with the
			// pending state preserved. In a real run the user logs in here.
			cb := r.URL.Query().Get("redirect_uri")
			state := r.URL.Query().Get("state")
			http.Redirect(w, r, cb+"?code=upstream-code&state="+state, http.StatusFound)
		case "/token":
			atomic.AddInt32(&tokenRedemptions, 1)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "upstream-access-token",
				"token_type":   "Bearer",
				"expires_in":   3600,
				"scope":        "openid email",
			})
		case "/userinfo":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"sub": "u-1", "email": "u1@example.com", "email_verified": true,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer upstream.Close()

	// Fake CIMD doc server.
	cimdServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"client_id":%q,"client_name":"Demo","redirect_uris":[%q],"token_endpoint_auth_method":"none"}`, downstreamClient, downstreamRedir)
	}))
	defer cimdServer.Close()

	cfg := config.Config{
		Server: config.ServerConfig{
			OAuth: config.OAuthConfig{
				Enabled:             true,
				Mode:                "forward",
				Issuer:              upstream.URL,
				JWKSURL:             upstream.URL + "/jwks",
				AuthURL:             upstream.URL + "/authorize",
				TokenURL:            upstream.URL + "/token",
				UserInfoURL:         upstream.URL + "/userinfo",
				ClientID:            upstreamClient,
				ClientSecret:        upstreamSecret,
				Audience:            upstreamClient,
				PublicAuthServerURL: "https://mcp.example.com",
				SigningSecret:       signingSecret,
				Scopes:              []string{"openid", "email"},
			},
		},
	}
	app := &application{
		config:       cfg,
		mcpServer:    altinitymcp.NewClickHouseMCPServer(cfg, "test"),
		cimdResolver: testResolver(t, cimdServer),
	}

	verifier, err := newPKCEVerifier()
	require.NoError(t, err)
	challenge := pkceChallenge(verifier)

	// 1. /oauth/authorize — should produce a 302 to upstream /authorize with
	//    a JWE state parameter.
	authReq := httptest.NewRequest(http.MethodGet,
		"https://mcp.example.com/oauth/authorize?"+url.Values{
			"client_id":             {downstreamClient},
			"redirect_uri":          {downstreamRedir},
			"response_type":         {"code"},
			"code_challenge":        {challenge},
			"code_challenge_method": {"S256"},
			"state":                 {"client-state"},
		}.Encode(), nil)
	authRR := httptest.NewRecorder()
	app.handleOAuthAuthorize(authRR, authReq)
	require.Equal(t, http.StatusFound, authRR.Code, "body=%s", authRR.Body.String())
	upstreamRedirect, err := url.Parse(authRR.Header().Get("Location"))
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(upstreamRedirect.String(), upstream.URL+"/authorize"))
	state := upstreamRedirect.Query().Get("state")
	require.NotEmpty(t, state)

	// 2. /oauth/callback — simulating the upstream IdP's redirect back to
	//    us. Our handler wraps the upstream auth code into a downstream
	//    JWE and 302s the user to the downstream redirect_uri.
	cbReq := httptest.NewRequest(http.MethodGet,
		"https://mcp.example.com/oauth/callback?code=upstream-code&state="+url.QueryEscape(state), nil)
	cbRR := httptest.NewRecorder()
	app.handleOAuthCallback(cbRR, cbReq)
	require.Equal(t, http.StatusFound, cbRR.Code, "body=%s", cbRR.Body.String())
	downstreamRedirect, err := url.Parse(cbRR.Header().Get("Location"))
	require.NoError(t, err)
	require.Equal(t, "demo.example.com", downstreamRedirect.Host)
	downstreamCode := downstreamRedirect.Query().Get("code")
	require.NotEmpty(t, downstreamCode)
	require.Equal(t, "client-state", downstreamRedirect.Query().Get("state"))
	require.Equal(t, int32(0), atomic.LoadInt32(&tokenRedemptions), "/callback must NOT redeem upstream (HA replay model)")

	// 3. /oauth/token — the broker now redeems upstream and hands the
	//    bearer to the MCP client.
	tokenForm := url.Values{}
	tokenForm.Set("grant_type", "authorization_code")
	tokenForm.Set("client_id", downstreamClient)
	tokenForm.Set("redirect_uri", downstreamRedir)
	tokenForm.Set("code", downstreamCode)
	tokenForm.Set("code_verifier", verifier)
	tokenReq := httptest.NewRequest(http.MethodPost, "https://mcp.example.com/oauth/token", strings.NewReader(tokenForm.Encode()))
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenRR := httptest.NewRecorder()
	app.handleOAuthToken(tokenRR, tokenReq)
	require.Equal(t, http.StatusOK, tokenRR.Code, "body=%s", tokenRR.Body.String())
	var tokenResp map[string]interface{}
	require.NoError(t, json.Unmarshal(tokenRR.Body.Bytes(), &tokenResp))
	require.Equal(t, "upstream-access-token", tokenResp["access_token"])
	require.NotContains(t, tokenResp, "refresh_token", "v1 issues no refresh tokens to CIMD clients")
	require.Equal(t, int32(1), atomic.LoadInt32(&tokenRedemptions), "exactly one upstream /token call per /oauth/token attempt")
}

// --- /oauth/register 410 Gone --------------------------------------------

// TestOAuthRegisterGone confirms the DCR-tombstone handler returns a
// diagnosable RFC 7591 §3.2.2-shaped JSON error rather than the bare mux
// 404 a DCR client would otherwise see.
func TestOAuthRegisterGone(t *testing.T) {
	t.Parallel()
	app := &application{
		config: config.Config{Server: config.ServerConfig{OAuth: config.OAuthConfig{
			Enabled:             true,
			Mode:                "forward",
			Issuer:              "https://idp.example.com",
			PublicAuthServerURL: "https://mcp.example.com",
			SigningSecret:       "regression-410-32bytes!!!!!!!!!!!",
		}}},
	}
	mux := http.NewServeMux()
	app.registerOAuthHTTPRoutes(mux)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "https://mcp.example.com/oauth/register", strings.NewReader(`{"redirect_uris":["https://x/cb"],"token_endpoint_auth_method":"none"}`)))
	require.Equal(t, http.StatusGone, rr.Code)
	require.Contains(t, rr.Header().Get("Content-Type"), "application/json")
	var body map[string]string
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	require.Equal(t, "registration_not_supported", body["error"])
	require.Contains(t, body["error_description"], "CIMD")
}

// --- /oauth/token refresh grant unsupported -----------------------------

func TestOAuthTokenRefreshGrantUnsupported(t *testing.T) {
	t.Parallel()
	app := &application{
		config: config.Config{Server: config.ServerConfig{OAuth: config.OAuthConfig{
			Enabled:             true,
			Mode:                "forward",
			Issuer:              "https://idp.example.com",
			PublicAuthServerURL: "https://mcp.example.com",
			SigningSecret:       "regression-refresh-32bytes!!!!!!!",
		}}},
	}
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("client_id", "https://x.example.com/cimd.json")
	form.Set("refresh_token", "anything")
	req := httptest.NewRequest(http.MethodPost, "https://mcp.example.com/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	app.handleOAuthToken(rr, req)
	require.Equal(t, http.StatusBadRequest, rr.Code, "body=%s", rr.Body.String())
	var body map[string]string
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	require.Equal(t, "unsupported_grant_type", body["error"])
}

// --- AS metadata shape ---------------------------------------------------

func TestOAuthASMetadataShape(t *testing.T) {
	t.Parallel()
	app := &application{
		config: config.Config{Server: config.ServerConfig{OAuth: config.OAuthConfig{
			Enabled:             true,
			Mode:                "forward",
			Issuer:              "https://idp.example.com",
			PublicAuthServerURL: "https://mcp.example.com",
			SigningSecret:       "regression-shape-32bytes!!!!!!!!!",
		}}},
	}
	rr := httptest.NewRecorder()
	app.handleOAuthAuthorizationServerMetadata(rr, httptest.NewRequest(http.MethodGet, "https://mcp.example.com/.well-known/oauth-authorization-server", nil))
	require.Equal(t, http.StatusOK, rr.Code)
	var doc map[string]interface{}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &doc))

	require.Equal(t, true, doc["client_id_metadata_document_supported"])
	require.NotContains(t, doc, "registration_endpoint")
	require.Equal(t, []interface{}{"none", "private_key_jwt"}, doc["token_endpoint_auth_methods_supported"])
	require.Contains(t, doc, "token_endpoint_auth_signing_alg_values_supported")
	require.Equal(t, []interface{}{"authorization_code"}, doc["grant_types_supported"])
	require.Equal(t, []interface{}{"code"}, doc["response_types_supported"])
	require.Equal(t, []interface{}{"S256"}, doc["code_challenge_methods_supported"])
	require.NotContains(t, doc["grant_types_supported"], "refresh_token")
}

// --- upstream 200 OK with RFC 6749 §5.2 error body ----------------------

// TestOAuthTokenUpstream200WithErrorBody covers the non-RFC-compliant IdP
// case where /token returns HTTP 200 OK + {"error":"invalid_grant"} (no
// access_token / id_token). Status-only checks miss this; we must surface
// it as downstream invalid_grant so the HA replay contract holds.
func TestOAuthTokenUpstream200WithErrorBody(t *testing.T) {
	t.Parallel()
	const (
		cimdURL     = "https://demo.example.com/cimd.json"
		redirectURI = "https://demo.example.com/cb"
	)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/token" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"error":"invalid_grant","error_description":"already used"}`)
	}))
	defer upstream.Close()
	cimdServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"client_id":%q,"client_name":"D","redirect_uris":[%q],"token_endpoint_auth_method":"none"}`, cimdURL, redirectURI)
	}))
	defer cimdServer.Close()

	cfg := config.Config{Server: config.ServerConfig{OAuth: config.OAuthConfig{
		Enabled:             true,
		Mode:                "forward",
		Issuer:              upstream.URL,
		JWKSURL:             upstream.URL + "/jwks",
		AuthURL:             upstream.URL + "/authorize",
		TokenURL:            upstream.URL + "/token",
		ClientID:            "broker",
		ClientSecret:        "s",
		PublicAuthServerURL: "https://mcp.example.com",
		SigningSecret:       "regression-200err-32bytes!!!!!!!",
	}}}
	app := &application{
		config:       cfg,
		mcpServer:    altinitymcp.NewClickHouseMCPServer(cfg, "test"),
		cimdResolver: testResolver(t, cimdServer),
	}
	verifier, _ := newPKCEVerifier()
	issued := oauthIssuedCode{
		ClientID: cimdURL, RedirectURI: redirectURI, Scope: "openid email",
		CodeChallenge: pkceChallenge(verifier), CodeChallengeMethod: "S256",
		UpstreamAuthCode: "abc", UpstreamPKCEVerifier: "uv",
		ExpiresAt: time.Now().Add(60 * time.Second),
	}
	code, err := app.encodeAuthCode(issued)
	require.NoError(t, err)

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", cimdURL)
	form.Set("redirect_uri", redirectURI)
	form.Set("code", code)
	form.Set("code_verifier", verifier)
	req := httptest.NewRequest(http.MethodPost, "https://mcp.example.com/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	require.NoError(t, req.ParseForm())
	rr := httptest.NewRecorder()
	app.handleOAuthTokenAuthCode(rr, req)
	require.Equal(t, http.StatusBadRequest, rr.Code, "200+error body must surface as 400 invalid_grant, got body=%s", rr.Body.String())
	var body map[string]string
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	require.Equal(t, "invalid_grant", body["error"])
}

// --- helpers -------------------------------------------------------------

// regressionOIDCProvider is a small fake OIDC AS used by the forward-mode
// JWT validation tests. It signs id_tokens with RS256 and exposes JWKS at
// /jwks so altinitymcp.ValidateUpstreamIdentityToken can verify them.
type regressionOIDCProvider struct {
	server     *httptest.Server
	privateKey *rsa.PrivateKey
	keyID      string

	tokenResp      map[string]interface{}
	userInfoClaims map[string]interface{}

	mu               sync.Mutex
	userInfoCalls    int
	lastUserInfoAuth string
}

func newRegressionOIDCProvider(t *testing.T, tokenResp, userInfoClaims map[string]interface{}) *regressionOIDCProvider {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	p := &regressionOIDCProvider{
		privateKey:     priv,
		keyID:          "regression-key",
		tokenResp:      tokenResp,
		userInfoClaims: userInfoClaims,
	}
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	p.server = server

	mux.HandleFunc("/authorize", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode(p.tokenResp))
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode(jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{{
				Key:       &priv.PublicKey,
				KeyID:     p.keyID,
				Use:       "sig",
				Algorithm: string(jose.RS256),
			}},
		}))
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		p.userInfoCalls++
		p.lastUserInfoAuth = r.Header.Get("Authorization")
		p.mu.Unlock()
		if p.userInfoClaims == nil {
			http.Error(w, "userinfo not configured", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode(p.userInfoClaims))
	})
	return p
}

func (p *regressionOIDCProvider) issueIDToken(t *testing.T, claims map[string]interface{}) string {
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
	obj, err := signer.Sign(payload)
	require.NoError(t, err)
	tok, err := obj.CompactSerialize()
	require.NoError(t, err)
	return tok
}

// Avoid unused-import errors if some sub-tests get gated off.
var _ = context.Background
var _ = io.Discard
