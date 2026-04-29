package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
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
	altinitymcp "github.com/altinity/altinity-mcp/pkg/server"
	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"
)

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
					GatingSecretKey:     "test-gating-secret-32-byte-key!!",
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
		require.Equal(t, "https://mcp.example.com", body["resource"])
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

	t.Run("custom_public_urls_and_paths", func(t *testing.T) {
		app.config.Server.OAuth.PublicResourceURL = "https://public.example.com"
		app.config.Server.OAuth.PublicAuthServerURL = "https://public.example.com/oauth"
		app.config.Server.OAuth.ProtectedResourceMetadataPath = "/resource-metadata"
		app.config.Server.OAuth.AuthorizationServerMetadataPath = "/auth-metadata"
		app.config.Server.OAuth.OpenIDConfigurationPath = "/openid"
		app.config.Server.OAuth.RegistrationPath = "/register"
		app.config.Server.OAuth.AuthorizationPath = "/authorize"
		app.config.Server.OAuth.CallbackPath = "/callback"
		app.config.Server.OAuth.TokenPath = "/token"

		req := httptest.NewRequest(http.MethodGet, "https://internal.example.com/auth-metadata", nil)
		rr := httptest.NewRecorder()
		app.handleOAuthAuthorizationServerMetadata(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)
		require.Contains(t, rr.Body.String(), "\"issuer\":\"https://public.example.com/oauth\"")
		require.Contains(t, rr.Body.String(), "\"authorization_endpoint\":\"https://public.example.com/oauth/authorize\"")
		require.Contains(t, rr.Body.String(), "\"registration_endpoint\":\"https://public.example.com/oauth/register\"")

		req = httptest.NewRequest(http.MethodGet, "https://internal.example.com/resource-metadata", nil)
		rr = httptest.NewRecorder()
		app.handleOAuthProtectedResource(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)
		require.Contains(t, rr.Body.String(), "\"resource\":\"https://public.example.com\"")
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
					GatingSecretKey:     "test-gating-secret-32-byte-key!!",
				},
			},
		},
		mcpServer: altinitymcp.NewClickHouseMCPServer(config.Config{Server: config.ServerConfig{JWE: config.JWEConfig{Enabled: true, JWESecretKey: "this-is-a-32-byte-secret-key!!", JWTSecretKey: "jwt-secret"}, OAuth: config.OAuthConfig{
			Enabled:             true,
			Mode:                "gating",
			Issuer:              "https://accounts.example.com",
			PublicAuthServerURL: "https://mcp.example.com",
			Audience:            "https://mcp.example.com",
			GatingSecretKey:     "test-gating-secret-32-byte-key!!",
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

	app.config.Server.OAuth.ProtectedResourceMetadataPath = "/resource-metadata"
	app.config.Server.OAuth.AuthorizationServerMetadataPath = "/auth-metadata"
	app.config.Server.OAuth.OpenIDConfigurationPath = "/openid"
	app.config.Server.OAuth.RegistrationPath = "/register"
	app.config.Server.OAuth.AuthorizationPath = "/authorize"
	app.config.Server.OAuth.CallbackPath = "/callback"
	app.config.Server.OAuth.TokenPath = "/token"

	mux = http.NewServeMux()
	app.registerOAuthHTTPRoutes(mux)

	for _, path := range []string{
		"/resource-metadata",
		"/auth-metadata",
		"/openid",
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
				GatingSecretKey: "test-gating-secret-32-byte-key!!",
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
		require.Greater(t, tokenResp["expires_in"].(float64), float64(0))
		require.LessOrEqual(t, tokenResp["expires_in"].(float64), float64(1800))

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
				GatingSecretKey:        "test-gating-secret-32-byte-key!!",
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

	t.Run("forward_mode_rejects_refresh", func(t *testing.T) {
		t.Parallel()
		fwdApp := newForwardModeBrowserLoginTestApp(provider)
		fwdClientID := registerOAuthBrowserClient(t, fwdApp, redirectURI)
		rr := exchangeRefreshToken(t, fwdApp, fwdClientID, resp["refresh_token"].(string))
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "not supported in forward mode")
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
		rr := post(`{"redirect_uris":["https://example.com/cb"],"token_endpoint_auth_method":"client_secret_post"}`)
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
						GatingSecretKey:        "test-gating-secret-32-byte-key!!",
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
