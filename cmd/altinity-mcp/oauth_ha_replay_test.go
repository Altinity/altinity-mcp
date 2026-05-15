package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/altinity/altinity-mcp/pkg/config"
	altinitymcp "github.com/altinity/altinity-mcp/pkg/server"
	"github.com/stretchr/testify/require"
)

// TestHAReplay_UpstreamInvalidGrantOnReplay verifies the HA replay model from
// #115: redeeming the same downstream auth-code JWE twice results in the
// second /oauth/token call seeing upstream `invalid_grant` and returning a
// downstream `invalid_grant`. The upstream IdP is the cross-replica oracle.
func TestHAReplay_UpstreamInvalidGrantOnReplay(t *testing.T) {
	const (
		upstreamCode     = "upstream-auth-code-abc"
		upstreamClient   = "upstream-client-id"
		upstreamSecret   = "upstream-client-secret"
		downstreamClient = "https://demo.example.com/cimd.json"
		downstreamRedir  = "https://demo.example.com/cb"
		signingSecret    = "test-ha-signing-secret-32-bytes!"
	)

	// Fake upstream IdP: /token redeems the auth code exactly once.
	tokenCalls := int32(0)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			n := atomic.AddInt32(&tokenCalls, 1)
			_ = r.ParseForm()
			if r.Form.Get("code") != upstreamCode {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = io.WriteString(w, `{"error":"invalid_grant"}`)
				return
			}
			if n > 1 {
				// Second redemption: simulate Google/Auth0 invalid_grant.
				w.WriteHeader(http.StatusBadRequest)
				_, _ = io.WriteString(w, `{"error":"invalid_grant","error_description":"code already used"}`)
				return
			}
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
				"sub":            "user-123",
				"email":          "alice@example.com",
				"email_verified": true,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer upstream.Close()

	// Stub CIMD resolver: skip real network and return a client allowing the
	// downstream redirect URI.
	origResolver := resolveCIMDClient
	t.Cleanup(func() { resolveCIMDClient = origResolver })
	resolveCIMDClient = func(_ context.Context, raw string) (*statelessRegisteredClient, error) {
		if raw != downstreamClient {
			return nil, errCIMDInvalidURL
		}
		return &statelessRegisteredClient{
			RedirectURIs:            []string{downstreamRedir},
			TokenEndpointAuthMethod: "none",
			GrantType:               "authorization_code",
		}, nil
	}

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
		config:    cfg,
		mcpServer: altinitymcp.NewClickHouseMCPServer(cfg, "test"),
	}

	// Build a valid downstream auth code JWE by exercising encodeAuthCode.
	verifier, err := newPKCEVerifier()
	require.NoError(t, err)
	challenge := pkceChallenge(verifier)
	issued := oauthIssuedCode{
		ClientID:             downstreamClient,
		RedirectURI:          downstreamRedir,
		Scope:                "openid email",
		CodeChallenge:        challenge,
		CodeChallengeMethod:  "S256",
		UpstreamAuthCode:     upstreamCode,
		UpstreamPKCEVerifier: "upstream-verifier",
		ExpiresAt:            time.Now().Add(60 * time.Second),
	}
	jweAuthCode, err := app.encodeAuthCode(issued)
	require.NoError(t, err)

	mkReq := func() *http.Request {
		form := url.Values{}
		form.Set("grant_type", "authorization_code")
		form.Set("client_id", downstreamClient)
		form.Set("redirect_uri", downstreamRedir)
		form.Set("code", jweAuthCode)
		form.Set("code_verifier", verifier)
		req := httptest.NewRequest(http.MethodPost, "https://mcp.example.com/oauth/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		require.NoError(t, req.ParseForm())
		return req
	}

	// First /token: succeeds, upstream redeems the code once.
	rr1 := httptest.NewRecorder()
	app.handleOAuthTokenAuthCode(rr1, mkReq())
	require.Equal(t, http.StatusOK, rr1.Code, "first /token body: %s", rr1.Body.String())
	var resp1 map[string]interface{}
	require.NoError(t, json.Unmarshal(rr1.Body.Bytes(), &resp1))
	require.Equal(t, "upstream-access-token", resp1["access_token"])
	require.NotContains(t, resp1, "refresh_token", "v1 must not issue refresh tokens to CIMD clients")

	// Second /token: replay → upstream invalid_grant → downstream invalid_grant.
	rr2 := httptest.NewRecorder()
	app.handleOAuthTokenAuthCode(rr2, mkReq())
	require.Equal(t, http.StatusBadRequest, rr2.Code)
	var resp2 map[string]interface{}
	require.NoError(t, json.Unmarshal(rr2.Body.Bytes(), &resp2))
	require.Equal(t, "invalid_grant", resp2["error"])
	require.Equal(t, int32(2), atomic.LoadInt32(&tokenCalls), "upstream /token should be called once per /token attempt — no pod-local cache")
}

