package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	altinitymcp "github.com/altinity/altinity-mcp/pkg/server"
	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"

	"github.com/altinity/altinity-mcp/pkg/config"
)

// Tests for issue #121: forward-mode id_token refresh.
//
// In forward mode the bearer the MCP client receives is the upstream
// id_token itself. Google's silent-SSO can return a cached id_token whose
// `exp` is set from the original mint time, leaving the MCP client with
// only minutes of session even though the access_token says 1h. The fix
// uses the upstream refresh_token at /token to mint a fresh id_token
// before forwarding.

// --- /authorize: access_type=offline added when upstream_offline_access ---

func TestOAuthAuthorize_OfflineAccessParams(t *testing.T) {
	t.Parallel()
	// Provider-detect: Google MUST get access_type=offline+prompt=consent and
	// MUST NOT receive offline_access scope (rejected as invalid_scope by
	// Google's /authorize). Non-Google providers (Auth0 etc.) get the
	// reverse — offline_access scope, no access_type.
	cases := []struct {
		name             string
		issuer           string
		offlineAccess    bool
		wantAccessType   bool
		wantOfflineScope bool
	}{
		{"google_enabled", "https://accounts.google.com", true, true, false},
		{"google_disabled", "https://accounts.google.com", false, false, false},
		{"auth0_enabled", "https://acme.auth0.com/", true, false, true},
		{"auth0_disabled", "https://acme.auth0.com/", false, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := config.Config{Server: config.ServerConfig{OAuth: config.OAuthConfig{
				Enabled:               true,
				Mode:                  "forward",
				Issuer:                tc.issuer,
				AuthURL:               "https://idp.example.com/authorize",
				TokenURL:              "https://idp.example.com/token",
				ClientID:              "broker",
				ClientSecret:          "s",
				PublicAuthServerURL:   "https://mcp.example.com",
				SigningSecret:         "regression-offline-32bytes!!!!!!",
				UpstreamOfflineAccess: tc.offlineAccess,
				Scopes:                []string{"openid", "email"},
			}}}
			cimdURL := "https://demo.example.com/cimd.json"
			cimdServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprintf(w, `{"client_id":%q,"client_name":"D","redirect_uris":["https://demo.example.com/cb"],"token_endpoint_auth_method":"none"}`, cimdURL)
			}))
			defer cimdServer.Close()

			app := &application{
				config:       cfg,
				mcpServer:    altinitymcp.NewClickHouseMCPServer(cfg, "test"),
				cimdResolver: testResolver(t, cimdServer),
			}
			verifier, _ := newPKCEVerifier()
			form := url.Values{}
			form.Set("client_id", cimdURL)
			form.Set("redirect_uri", "https://demo.example.com/cb")
			form.Set("response_type", "code")
			form.Set("code_challenge", pkceChallenge(verifier))
			form.Set("code_challenge_method", "S256")
			req := httptest.NewRequest(http.MethodGet, "https://mcp.example.com/oauth/authorize?"+form.Encode(), nil)
			rr := httptest.NewRecorder()
			app.handleOAuthAuthorize(rr, req)
			require.Equal(t, http.StatusFound, rr.Code, "body=%s", rr.Body.String())
			loc, err := url.Parse(rr.Header().Get("Location"))
			require.NoError(t, err)
			q := loc.Query()
			if tc.wantAccessType {
				require.Equal(t, "offline", q.Get("access_type"))
				require.Equal(t, "consent", q.Get("prompt"))
			} else {
				require.Empty(t, q.Get("access_type"))
				require.Empty(t, q.Get("prompt"))
			}
			if tc.wantOfflineScope {
				require.Contains(t, q.Get("scope"), "offline_access")
			} else {
				require.NotContains(t, q.Get("scope"), "offline_access",
					"offline_access scope MUST NOT be sent to Google (rejected as invalid_scope)")
			}
		})
	}
}

// --- /token: near-expired id_token triggers internal refresh ---------------

type refreshProbeUpstream struct {
	server         *httptest.Server
	priv           *rsa.PrivateKey
	keyID          string
	codeExchangeCt int32 // grant_type=authorization_code calls
	refreshCt      int32 // grant_type=refresh_token calls
}

func newRefreshProbeUpstream(t *testing.T, initialIDTokenExp, refreshedIDTokenExp time.Time, subject string) *refreshProbeUpstream {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	u := &refreshProbeUpstream{priv: priv, keyID: "refresh-probe-key"}
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	u.server = srv

	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key: &priv.PublicKey, KeyID: u.keyID, Use: "sig", Algorithm: string(jose.RS256),
		}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		now := time.Now().Unix()
		w.Header().Set("Content-Type", "application/json")
		switch r.Form.Get("grant_type") {
		case "authorization_code":
			atomic.AddInt32(&u.codeExchangeCt, 1)
			idToken := u.issueIDToken(t, map[string]interface{}{
				"sub":   subject,
				"aud":   "broker",
				"iat":   now,
				"exp":   initialIDTokenExp.Unix(),
				"iss":   srv.URL,
				"email": subject,
				"email_verified": true,
			})
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"id_token":      idToken,
				"access_token":  "ax-1",
				"refresh_token": "rf-1", // crucial: this enables the #121 refresh path
				"token_type":    "Bearer",
				"expires_in":    3600,
				"scope":         "openid email",
			})
		case "refresh_token":
			atomic.AddInt32(&u.refreshCt, 1)
			require.Equal(t, "rf-1", r.Form.Get("refresh_token"))
			idToken := u.issueIDToken(t, map[string]interface{}{
				"sub":   subject,
				"aud":   "broker",
				"iat":   now,
				"exp":   refreshedIDTokenExp.Unix(),
				"iss":   srv.URL,
				"email": subject,
				"email_verified": true,
			})
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"id_token":     idToken,
				"access_token": "ax-2",
				"token_type":   "Bearer",
				"expires_in":   3600,
				"scope":        "openid email",
			})
		default:
			http.Error(w, "unsupported grant_type", http.StatusBadRequest)
		}
	})
	return u
}

func (u *refreshProbeUpstream) issueIDToken(t *testing.T, claims map[string]interface{}) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.RS256,
		Key: jose.JSONWebKey{
			Key:       u.priv,
			KeyID:     u.keyID,
			Use:       "sig",
			Algorithm: string(jose.RS256),
		},
	}, (&jose.SignerOptions{}).WithType("JWT"))
	require.NoError(t, err)
	body, err := json.Marshal(claims)
	require.NoError(t, err)
	obj, err := signer.Sign(body)
	require.NoError(t, err)
	tok, err := obj.CompactSerialize()
	require.NoError(t, err)
	return tok
}

func runTokenExchange(t *testing.T, app *application, cimdURL, redirectURI string) *httptest.ResponseRecorder {
	t.Helper()
	verifier, _ := newPKCEVerifier()
	issued := oauthIssuedCode{
		ClientID: cimdURL, RedirectURI: redirectURI, Scope: "openid email",
		CodeChallenge: pkceChallenge(verifier), CodeChallengeMethod: "S256",
		UpstreamAuthCode: "uac", UpstreamPKCEVerifier: "uv",
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
	return rr
}

func buildForwardModeApp(t *testing.T, upstream *refreshProbeUpstream, cimdURL, redirectURI string) *application {
	t.Helper()
	cimdServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"client_id":%q,"client_name":"D","redirect_uris":[%q],"token_endpoint_auth_method":"none"}`, cimdURL, redirectURI)
	}))
	t.Cleanup(cimdServer.Close)
	cfg := config.Config{Server: config.ServerConfig{OAuth: config.OAuthConfig{
		Enabled:               true,
		Mode:                  "forward",
		Issuer:                upstream.server.URL,
		JWKSURL:               upstream.server.URL + "/jwks",
		AuthURL:               upstream.server.URL + "/authorize",
		TokenURL:              upstream.server.URL + "/token",
		ClientID:              "broker",
		ClientSecret:          "s",
		PublicAuthServerURL:   "https://mcp.example.com",
		SigningSecret:         "regression-refresh-32bytes!!!!!!",
		UpstreamOfflineAccess: true,
	}}}
	return &application{
		config:       cfg,
		mcpServer:    altinitymcp.NewClickHouseMCPServer(cfg, "test"),
		cimdResolver: testResolver(t, cimdServer),
	}
}

func TestOAuthToken_RefreshesNearExpiredIDToken(t *testing.T) {
	t.Parallel()
	// id_token exp 2 minutes from now — well below 55-min threshold.
	nearExp := time.Now().Add(2 * time.Minute)
	freshExp := time.Now().Add(60 * time.Minute)
	upstream := newRefreshProbeUpstream(t, nearExp, freshExp, "alice@example.com")
	app := buildForwardModeApp(t, upstream, "https://demo.example.com/cimd.json", "https://demo.example.com/cb")

	rr := runTokenExchange(t, app, "https://demo.example.com/cimd.json", "https://demo.example.com/cb")
	require.Equal(t, http.StatusOK, rr.Code, "body=%s", rr.Body.String())

	require.Equal(t, int32(1), atomic.LoadInt32(&upstream.codeExchangeCt))
	require.Equal(t, int32(1), atomic.LoadInt32(&upstream.refreshCt), "expected internal refresh_token call")

	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	// expires_in should now reflect the refreshed id_token, not the near-exp original.
	expiresIn, ok := body["expires_in"].(float64)
	require.True(t, ok)
	require.Greater(t, int64(expiresIn), int64(50*60), "expires_in must reflect refreshed id_token, got %v", expiresIn)
}

func TestOAuthToken_SkipsRefreshWhenIDTokenFresh(t *testing.T) {
	t.Parallel()
	// id_token exp ~57 min — above 55-min threshold, no refresh.
	nearExp := time.Now().Add(57 * time.Minute)
	freshExp := time.Now().Add(60 * time.Minute)
	upstream := newRefreshProbeUpstream(t, nearExp, freshExp, "bob@example.com")
	app := buildForwardModeApp(t, upstream, "https://demo.example.com/cimd.json", "https://demo.example.com/cb")

	rr := runTokenExchange(t, app, "https://demo.example.com/cimd.json", "https://demo.example.com/cb")
	require.Equal(t, http.StatusOK, rr.Code, "body=%s", rr.Body.String())

	require.Equal(t, int32(1), atomic.LoadInt32(&upstream.codeExchangeCt))
	require.Equal(t, int32(0), atomic.LoadInt32(&upstream.refreshCt), "refresh_token must NOT be called when id_token is fresh")
}

func TestOAuthToken_RefreshFailureSoftFallsBack(t *testing.T) {
	t.Parallel()
	// id_token exp near; upstream /token refresh_token responds with HTTP 500.
	nearExp := time.Now().Add(3 * time.Minute)
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	keyID := "soft-fallback-key"
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key: &priv.PublicKey, KeyID: keyID, Use: "sig", Algorithm: string(jose.RS256),
		}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		w.Header().Set("Content-Type", "application/json")
		if r.Form.Get("grant_type") == "refresh_token" {
			http.Error(w, "transient upstream outage", http.StatusInternalServerError)
			return
		}
		// initial code exchange returns a near-expired id_token + refresh_token.
		signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: priv, KeyID: keyID, Use: "sig", Algorithm: string(jose.RS256)}}, (&jose.SignerOptions{}).WithType("JWT"))
		payload, _ := json.Marshal(map[string]interface{}{
			"sub": "carol@example.com", "aud": "broker", "iat": time.Now().Unix(),
			"exp": nearExp.Unix(), "iss": srv.URL, "email": "carol@example.com", "email_verified": true,
		})
		obj, _ := signer.Sign(payload)
		idTok, _ := obj.CompactSerialize()
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"id_token": idTok, "access_token": "a", "refresh_token": "r",
			"token_type": "Bearer", "expires_in": 3600,
		})
	})
	cimdURL, redirectURI := "https://demo.example.com/cimd.json", "https://demo.example.com/cb"
	cimdServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"client_id":%q,"client_name":"D","redirect_uris":[%q],"token_endpoint_auth_method":"none"}`, cimdURL, redirectURI)
	}))
	t.Cleanup(cimdServer.Close)
	cfg := config.Config{Server: config.ServerConfig{OAuth: config.OAuthConfig{
		Enabled: true, Mode: "forward", Issuer: srv.URL, JWKSURL: srv.URL + "/jwks",
		AuthURL: srv.URL + "/authorize", TokenURL: srv.URL + "/token",
		ClientID: "broker", ClientSecret: "s", PublicAuthServerURL: "https://mcp.example.com",
		SigningSecret: "regression-softfail-32bytes!!!!!", UpstreamOfflineAccess: true,
	}}}
	app := &application{config: cfg, mcpServer: altinitymcp.NewClickHouseMCPServer(cfg, "test"), cimdResolver: testResolver(t, cimdServer)}

	rr := runTokenExchange(t, app, cimdURL, redirectURI)
	// MUST still return 200 — soft fallback to the original near-expired id_token.
	require.Equal(t, http.StatusOK, rr.Code, "soft-fail must not break /token; body=%s", rr.Body.String())
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	require.NotEmpty(t, body["access_token"], "must still hand back the original id_token as bearer")
}

// Gating-with-broker_upstream deployments (github-mcp, otel-google-gating-mcp)
// also return the upstream id_token as the bearer, so the same refresh logic
// must apply. Guards against regression to the original forward-mode-only
// gate which left gating+broker silently broken.
func TestOAuthToken_RefreshesNearExpiredIDToken_GatingBrokerUpstream(t *testing.T) {
	t.Parallel()
	nearExp := time.Now().Add(2 * time.Minute)
	freshExp := time.Now().Add(60 * time.Minute)
	upstream := newRefreshProbeUpstream(t, nearExp, freshExp, "alice@example.com")
	cimdURL, redirectURI := "https://demo.example.com/cimd.json", "https://demo.example.com/cb"
	cimdServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"client_id":%q,"client_name":"D","redirect_uris":[%q],"token_endpoint_auth_method":"none"}`, cimdURL, redirectURI)
	}))
	t.Cleanup(cimdServer.Close)
	cfg := config.Config{Server: config.ServerConfig{OAuth: config.OAuthConfig{
		Enabled:               true,
		Mode:                  "gating",
		BrokerUpstream:        true,
		Issuer:                upstream.server.URL,
		JWKSURL:               upstream.server.URL + "/jwks",
		AuthURL:               upstream.server.URL + "/authorize",
		TokenURL:              upstream.server.URL + "/token",
		ClientID:              "broker",
		ClientSecret:          "s",
		Audience:              "broker", // matches client_id under broker_upstream
		PublicAuthServerURL:   "https://mcp.example.com",
		SigningSecret:         "regression-refresh-gating-32b!!!!",
		UpstreamOfflineAccess: true,
	}}}
	app := &application{
		config:       cfg,
		mcpServer:    altinitymcp.NewClickHouseMCPServer(cfg, "test"),
		cimdResolver: testResolver(t, cimdServer),
	}
	rr := runTokenExchange(t, app, cimdURL, redirectURI)
	require.Equal(t, http.StatusOK, rr.Code, "body=%s", rr.Body.String())
	require.Equal(t, int32(1), atomic.LoadInt32(&upstream.codeExchangeCt))
	require.Equal(t, int32(1), atomic.LoadInt32(&upstream.refreshCt),
		"gating+broker_upstream MUST trigger refresh on near-expired id_token (#121)")
}

func TestOAuthToken_NoRefreshWhenUpstreamReturnsNoRefreshToken(t *testing.T) {
	t.Parallel()
	// upstream returns near-expired id_token but no refresh_token. We must
	// NOT attempt refresh (would 400 or call with empty token), just forward.
	nearExp := time.Now().Add(3 * time.Minute)
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	keyID := "no-rt-key"
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key: &priv.PublicKey, KeyID: keyID, Use: "sig", Algorithm: string(jose.RS256),
		}}})
	})
	var refreshCalls int32
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		w.Header().Set("Content-Type", "application/json")
		if r.Form.Get("grant_type") == "refresh_token" {
			atomic.AddInt32(&refreshCalls, 1)
			http.Error(w, "should not be called", http.StatusBadRequest)
			return
		}
		signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: priv, KeyID: keyID, Use: "sig", Algorithm: string(jose.RS256)}}, (&jose.SignerOptions{}).WithType("JWT"))
		payload, _ := json.Marshal(map[string]interface{}{
			"sub": "dave@example.com", "aud": "broker", "iat": time.Now().Unix(),
			"exp": nearExp.Unix(), "iss": srv.URL, "email": "dave@example.com", "email_verified": true,
		})
		obj, _ := signer.Sign(payload)
		idTok, _ := obj.CompactSerialize()
		// NO refresh_token in this response.
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"id_token": idTok, "access_token": "a",
			"token_type": "Bearer", "expires_in": 3600,
		})
	})
	cimdURL, redirectURI := "https://demo.example.com/cimd.json", "https://demo.example.com/cb"
	cimdServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"client_id":%q,"client_name":"D","redirect_uris":[%q],"token_endpoint_auth_method":"none"}`, cimdURL, redirectURI)
	}))
	t.Cleanup(cimdServer.Close)
	cfg := config.Config{Server: config.ServerConfig{OAuth: config.OAuthConfig{
		Enabled: true, Mode: "forward", Issuer: srv.URL, JWKSURL: srv.URL + "/jwks",
		AuthURL: srv.URL + "/authorize", TokenURL: srv.URL + "/token",
		ClientID: "broker", ClientSecret: "s", PublicAuthServerURL: "https://mcp.example.com",
		SigningSecret: "regression-no-rt-32bytes!!!!!!!!", UpstreamOfflineAccess: true,
	}}}
	app := &application{config: cfg, mcpServer: altinitymcp.NewClickHouseMCPServer(cfg, "test"), cimdResolver: testResolver(t, cimdServer)}

	rr := runTokenExchange(t, app, cimdURL, redirectURI)
	require.Equal(t, http.StatusOK, rr.Code, "body=%s", rr.Body.String())
	require.Equal(t, int32(0), atomic.LoadInt32(&refreshCalls), "refresh attempted despite no upstream refresh_token")
}

// keep "io" used for some test paths that may grow later
var _ = io.Discard
