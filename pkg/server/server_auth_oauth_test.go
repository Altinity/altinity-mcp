package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/altinity/altinity-mcp/pkg/clickhouse"
	"github.com/altinity/altinity-mcp/pkg/config"
	"github.com/altinity/altinity-mcp/pkg/jwe_auth"
	"github.com/go-jose/go-jose/v4"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"
)

func mintSelfIssuedToken(t *testing.T, gatingSecret string, claims map[string]interface{}) string {
	t.Helper()
	hashedSecret := jwe_auth.HashSHA256([]byte(gatingSecret))
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.HS256, Key: hashedSecret},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	require.NoError(t, err)
	payload, err := json.Marshal(claims)
	require.NoError(t, err)
	object, err := signer.Sign(payload)
	require.NoError(t, err)
	token, err := object.CompactSerialize()
	require.NoError(t, err)
	return token
}

type testOAuthProvider struct {
	server              *httptest.Server
	privateKey          *rsa.PrivateKey
	keyID               string
	lastAuthorization   string
	lastAuthorizationMu sync.Mutex
	userInfoClaims      map[string]interface{}
}

func newTestOAuthProvider(t *testing.T, userInfoClaims map[string]interface{}) *testOAuthProvider {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	provider := &testOAuthProvider{
		privateKey:     privateKey,
		keyID:          "test-signing-key",
		userInfoClaims: userInfoClaims,
	}

	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	provider.server = server
	t.Cleanup(server.Close)

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode(map[string]interface{}{
			"issuer":            server.URL,
			"jwks_uri":          server.URL + "/jwks",
			"userinfo_endpoint": server.URL + "/userinfo",
		}))
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
		provider.lastAuthorizationMu.Lock()
		provider.lastAuthorization = r.Header.Get("Authorization")
		provider.lastAuthorizationMu.Unlock()

		if provider.userInfoClaims == nil {
			http.Error(w, "userinfo not configured", http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode(provider.userInfoClaims))
	})

	return provider
}

func (p *testOAuthProvider) issueJWT(t *testing.T, claims map[string]interface{}) string {
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

// TestOAuthConfig tests OAuth configuration
func TestOAuthConfig(t *testing.T) {
	t.Parallel()
	t.Run("oauth_config_defaults", func(t *testing.T) {
		t.Parallel()
		cfg := config.OAuthConfig{}
		require.False(t, cfg.Enabled)
		require.Empty(t, cfg.Issuer)
		require.Empty(t, cfg.Audience)
	})

	t.Run("oauth_config_with_values", func(t *testing.T) {
		t.Parallel()
		cfg := config.OAuthConfig{
			Enabled:              true,
			Issuer:               "https://auth.example.com",
			Audience:             "my-api",
			ClientID:             "client-123",
			ClientSecret:         "secret-456",
			TokenURL:             "https://auth.example.com/oauth/token",
			AuthURL:              "https://auth.example.com/oauth/authorize",
			Scopes:               []string{"read", "write"},
			RequiredScopes:       []string{"read"},
			ClickHouseHeaderName: "X-Custom-Token",
			ClaimsToHeaders: map[string]string{
				"sub":   "X-ClickHouse-User",
				"email": "X-ClickHouse-Email",
			},
		}

		require.True(t, cfg.Enabled)
		require.Equal(t, "https://auth.example.com", cfg.Issuer)
		require.Equal(t, "my-api", cfg.Audience)
		require.Equal(t, "client-123", cfg.ClientID)
		require.Equal(t, "secret-456", cfg.ClientSecret)
		require.Equal(t, []string{"read", "write"}, cfg.Scopes)
		require.Equal(t, []string{"read"}, cfg.RequiredScopes)
		require.Equal(t, "https://auth.example.com/oauth/token", cfg.TokenURL)
		require.Equal(t, "https://auth.example.com/oauth/authorize", cfg.AuthURL)
		require.Equal(t, "X-Custom-Token", cfg.ClickHouseHeaderName)
		require.Len(t, cfg.ClaimsToHeaders, 2)
	})
}

// TestOAuthExtractToken tests OAuth token extraction from requests
func TestOAuthExtractToken(t *testing.T) {
	t.Parallel()
	srv := &ClickHouseJWEServer{}

	t.Run("bearer_token", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer oauth-test-token")

		token := srv.ExtractOAuthTokenFromRequest(req)
		require.Equal(t, "oauth-test-token", token)
	})

	t.Run("x_oauth_token_header", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("x-oauth-token", "header-oauth-token")

		token := srv.ExtractOAuthTokenFromRequest(req)
		require.Equal(t, "header-oauth-token", token)
	})

	t.Run("x_altinity_oauth_token_header", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("x-altinity-oauth-token", "altinity-oauth-token")

		token := srv.ExtractOAuthTokenFromRequest(req)
		require.Equal(t, "altinity-oauth-token", token)
	})

	t.Run("no_token", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/", nil)

		token := srv.ExtractOAuthTokenFromRequest(req)
		require.Empty(t, token)
	})

	t.Run("bearer_takes_precedence", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer bearer-token")
		req.Header.Set("x-oauth-token", "header-token")

		token := srv.ExtractOAuthTokenFromRequest(req)
		require.Equal(t, "bearer-token", token)
	})
}

// TestOAuthExtractTokenFromCtx tests OAuth token extraction from context
func TestOAuthExtractTokenFromCtx(t *testing.T) {
	t.Parallel()
	srv := &ClickHouseJWEServer{}

	t.Run("with_token", func(t *testing.T) {
		t.Parallel()
		ctx := context.WithValue(context.Background(), OAuthTokenKey, "ctx-oauth-token")
		token := srv.ExtractOAuthTokenFromCtx(ctx)
		require.Equal(t, "ctx-oauth-token", token)
	})

	t.Run("no_token", func(t *testing.T) {
		t.Parallel()
		token := srv.ExtractOAuthTokenFromCtx(context.Background())
		require.Empty(t, token)
	})

	t.Run("wrong_type", func(t *testing.T) {
		t.Parallel()
		ctx := context.WithValue(context.Background(), OAuthTokenKey, 123)
		token := srv.ExtractOAuthTokenFromCtx(ctx)
		require.Empty(t, token)
	})
}

// TestOAuthValidateToken tests OAuth token validation
func TestOAuthValidateToken(t *testing.T) {
	t.Parallel()
	t.Run("oauth_disabled", func(t *testing.T) {
		t.Parallel()
		srv := &ClickHouseJWEServer{
			Config: config.Config{
				Server: config.ServerConfig{
					OAuth: config.OAuthConfig{Enabled: false},
				},
			},
		}

		claims, err := srv.ValidateOAuthToken("any-token")
		require.NoError(t, err)
		require.Nil(t, claims)
	})

	t.Run("missing_token", func(t *testing.T) {
		t.Parallel()
		srv := &ClickHouseJWEServer{
			Config: config.Config{
				Server: config.ServerConfig{
					OAuth: config.OAuthConfig{Enabled: true},
				},
			},
		}

		_, err := srv.ValidateOAuthToken("")
		require.ErrorIs(t, err, ErrMissingOAuthToken)
	})

	t.Run("forward_mode_verifies_signed_jwt_via_jwks", func(t *testing.T) {
		t.Parallel()
		provider := newTestOAuthProvider(t, nil)
		srv := &ClickHouseJWEServer{
			Config: config.Config{
				Server: config.ServerConfig{
					OAuth: config.OAuthConfig{
						Enabled:              true,
						Mode:                 "forward",
						Issuer:               provider.server.URL,
						JWKSURL:              provider.server.URL + "/jwks",
						Audience:             "clickhouse-api",
						RequiredScopes:       []string{"query:execute"},
						AllowedEmailDomains:  []string{"gmail.com"},
						RequireEmailVerified: true,
					},
				},
			},
		}

		token := provider.issueJWT(t, map[string]interface{}{
			"sub":            "user123",
			"iss":            provider.server.URL,
			"aud":            []string{"clickhouse-api", "other-audience"},
			"exp":            time.Now().Add(time.Hour).Unix(),
			"iat":            time.Now().Unix(),
			"email":          "user@gmail.com",
			"name":           "Test User",
			"email_verified": true,
			"scope":          "query:execute query:read",
		})

		claims, err := srv.ValidateOAuthToken(token)
		require.NoError(t, err)
		require.Equal(t, "user123", claims.Subject)
		require.Equal(t, provider.server.URL, claims.Issuer)
		require.Equal(t, "user@gmail.com", claims.Email)
		require.True(t, claims.EmailVerified)
		require.ElementsMatch(t, []string{"clickhouse-api", "other-audience"}, claims.Audience)
		require.ElementsMatch(t, []string{"query:execute", "query:read"}, claims.Scopes)
	})

	t.Run("forward_mode_rejects_unverified_email", func(t *testing.T) {
		t.Parallel()
		provider := newTestOAuthProvider(t, nil)
		srv := &ClickHouseJWEServer{
			Config: config.Config{
				Server: config.ServerConfig{
					OAuth: config.OAuthConfig{
						Enabled:              true,
						Mode:                 "forward",
						Issuer:               provider.server.URL,
						JWKSURL:              provider.server.URL + "/jwks",
						Audience:             "clickhouse-api",
						RequireEmailVerified: true,
					},
				},
			},
		}

		token := provider.issueJWT(t, map[string]interface{}{
			"sub":            "user123",
			"iss":            provider.server.URL,
			"aud":            "clickhouse-api",
			"exp":            time.Now().Add(time.Hour).Unix(),
			"email":          "user@gmail.com",
			"email_verified": false,
		})

		_, err := srv.ValidateOAuthToken(token)
		require.ErrorIs(t, err, ErrOAuthEmailNotVerified)
	})

	t.Run("forward_mode_rejects_disallowed_email_domain", func(t *testing.T) {
		t.Parallel()
		provider := newTestOAuthProvider(t, nil)
		srv := &ClickHouseJWEServer{
			Config: config.Config{
				Server: config.ServerConfig{
					OAuth: config.OAuthConfig{
						Enabled:             true,
						Mode:                "forward",
						Issuer:              provider.server.URL,
						JWKSURL:             provider.server.URL + "/jwks",
						Audience:            "clickhouse-api",
						AllowedEmailDomains: []string{"gmail.com"},
					},
				},
			},
		}

		token := provider.issueJWT(t, map[string]interface{}{
			"sub":            "user123",
			"iss":            provider.server.URL,
			"aud":            "clickhouse-api",
			"exp":            time.Now().Add(time.Hour).Unix(),
			"email":          "user@altinity.com",
			"email_verified": true,
		})

		_, err := srv.ValidateOAuthToken(token)
		require.ErrorIs(t, err, ErrOAuthUnauthorizedDomain)
	})

	t.Run("forward_mode_rejects_disallowed_hosted_domain", func(t *testing.T) {
		t.Parallel()
		provider := newTestOAuthProvider(t, nil)
		srv := &ClickHouseJWEServer{
			Config: config.Config{
				Server: config.ServerConfig{
					OAuth: config.OAuthConfig{
						Enabled:              true,
						Mode:                 "forward",
						Issuer:               provider.server.URL,
						JWKSURL:              provider.server.URL + "/jwks",
						Audience:             "clickhouse-api",
						AllowedHostedDomains: []string{"altinity.com"},
					},
				},
			},
		}

		token := provider.issueJWT(t, map[string]interface{}{
			"sub":            "user123",
			"iss":            provider.server.URL,
			"aud":            "clickhouse-api",
			"exp":            time.Now().Add(time.Hour).Unix(),
			"email":          "user@gmail.com",
			"email_verified": true,
			"hd":             "gmail.com",
		})

		_, err := srv.ValidateOAuthToken(token)
		require.ErrorIs(t, err, ErrOAuthUnauthorizedDomain)
	})

	t.Run("forward_mode_rejects_jwt_missing_configured_audience", func(t *testing.T) {
		t.Parallel()
		provider := newTestOAuthProvider(t, nil)
		srv := &ClickHouseJWEServer{
			Config: config.Config{
				Server: config.ServerConfig{
					OAuth: config.OAuthConfig{
						Enabled:  true,
						Mode:     "forward",
						Issuer:   provider.server.URL,
						JWKSURL:  provider.server.URL + "/jwks",
						Audience: "clickhouse-api",
					},
				},
			},
		}

		token := provider.issueJWT(t, map[string]interface{}{
			"sub": "user123",
			"iss": provider.server.URL,
			"exp": time.Now().Add(time.Hour).Unix(),
		})

		_, err := srv.ValidateOAuthToken(token)
		require.ErrorIs(t, err, ErrInvalidOAuthToken)
	})

	t.Run("forward_mode_rejects_jwt_missing_required_scope_claim", func(t *testing.T) {
		t.Parallel()
		provider := newTestOAuthProvider(t, nil)
		srv := &ClickHouseJWEServer{
			Config: config.Config{
				Server: config.ServerConfig{
					OAuth: config.OAuthConfig{
						Enabled:        true,
						Mode:           "forward",
						Issuer:         provider.server.URL,
						JWKSURL:        provider.server.URL + "/jwks",
						Audience:       "clickhouse-api",
						RequiredScopes: []string{"query:execute"},
					},
				},
			},
		}

		token := provider.issueJWT(t, map[string]interface{}{
			"sub": "user123",
			"iss": provider.server.URL,
			"aud": "clickhouse-api",
			"exp": time.Now().Add(time.Hour).Unix(),
		})

		_, err := srv.ValidateOAuthToken(token)
		require.ErrorIs(t, err, ErrOAuthInsufficientScopes)
	})
}

// TestOAuthBuildClickHouseHeaders tests building ClickHouse headers from OAuth
func TestOAuthBuildClickHouseHeaders(t *testing.T) {
	t.Parallel()
	t.Run("forwarding_disabled", func(t *testing.T) {
		t.Parallel()
		srv := &ClickHouseJWEServer{
			Config: config.Config{
				Server: config.ServerConfig{
					OAuth: config.OAuthConfig{Mode: "gating"},
				},
			},
		}

		headers := srv.BuildClickHouseHeadersFromOAuth("token", nil)
		require.Nil(t, headers)
	})

	t.Run("forward_access_token", func(t *testing.T) {
		t.Parallel()
		srv := &ClickHouseJWEServer{
			Config: config.Config{
				Server: config.ServerConfig{
					OAuth: config.OAuthConfig{
						Mode: "forward",
					},
				},
			},
		}

		headers := srv.BuildClickHouseHeadersFromOAuth("my-access-token", nil)
		require.NotNil(t, headers)
		require.Equal(t, "Bearer my-access-token", headers["Authorization"])
	})

	t.Run("forward_access_token_explicit_authorization_header", func(t *testing.T) {
		t.Parallel()
		srv := &ClickHouseJWEServer{
			Config: config.Config{
				Server: config.ServerConfig{
					OAuth: config.OAuthConfig{
						Mode:                 "forward",
						ClickHouseHeaderName: "Authorization",
					},
				},
			},
		}

		headers := srv.BuildClickHouseHeadersFromOAuth("my-access-token", nil)
		require.NotNil(t, headers)
		require.Equal(t, "Bearer my-access-token", headers["Authorization"])
	})

	t.Run("forward_access_token_custom_header", func(t *testing.T) {
		t.Parallel()
		srv := &ClickHouseJWEServer{
			Config: config.Config{
				Server: config.ServerConfig{
					OAuth: config.OAuthConfig{
						Mode:                 "forward",
						ClickHouseHeaderName: "X-Custom-Token-Header",
					},
				},
			},
		}

		headers := srv.BuildClickHouseHeadersFromOAuth("my-access-token", nil)
		require.NotNil(t, headers)
		require.Equal(t, "my-access-token", headers["X-Custom-Token-Header"])
	})

	t.Run("forward_claims_to_headers", func(t *testing.T) {
		t.Parallel()
		srv := &ClickHouseJWEServer{
			Config: config.Config{
				Server: config.ServerConfig{
					OAuth: config.OAuthConfig{
						Mode: "forward",
						ClaimsToHeaders: map[string]string{
							"sub":   "X-ClickHouse-User",
							"email": "X-ClickHouse-Email",
							"name":  "X-ClickHouse-Name",
						},
					},
				},
			},
		}

		claims := &OAuthClaims{
			Subject: "user123",
			Email:   "user@example.com",
			Name:    "Test User",
		}

		headers := srv.BuildClickHouseHeadersFromOAuth("token", claims)
		require.NotNil(t, headers)
		require.Equal(t, "user123", headers["X-ClickHouse-User"])
		require.Equal(t, "user@example.com", headers["X-ClickHouse-Email"])
		require.Equal(t, "Test User", headers["X-ClickHouse-Name"])
	})

	t.Run("forward_extra_claims", func(t *testing.T) {
		t.Parallel()
		srv := &ClickHouseJWEServer{
			Config: config.Config{
				Server: config.ServerConfig{
					OAuth: config.OAuthConfig{
						Mode: "forward",
						ClaimsToHeaders: map[string]string{
							"custom_claim": "X-Custom-Claim",
						},
					},
				},
			},
		}

		claims := &OAuthClaims{
			Extra: map[string]interface{}{
				"custom_claim": "custom_value",
			},
		}

		headers := srv.BuildClickHouseHeadersFromOAuth("token", claims)
		require.NotNil(t, headers)
		require.Equal(t, "custom_value", headers["X-Custom-Claim"])
	})
}

// TestOAuthClearClickHouseCredentials tests credential clearing when forwarding OAuth token in forward mode
func TestOAuthClearClickHouseCredentials(t *testing.T) {
	t.Parallel()
	t.Run("credentials_cleared_in_forward_mode", func(t *testing.T) {
		t.Parallel()
		srv := &ClickHouseJWEServer{
			Config: config.Config{
				ClickHouse: config.ClickHouseConfig{
					Host:     "localhost",
					Port:     8123,
					Username: "default",
					Password: "secret",
					Protocol: config.HTTPProtocol,
				},
				Server: config.ServerConfig{
					OAuth: config.OAuthConfig{
						Mode: "forward",
					},
				},
			},
		}

		// In forward mode, BuildClickHouseHeadersFromOAuth should return headers
		headers := srv.BuildClickHouseHeadersFromOAuth("test-token", nil)
		require.NotNil(t, headers)
		require.Equal(t, "Bearer test-token", headers["Authorization"])
	})
}

// TestOAuthAndJWECombined tests OAuth and JWE working together
func TestOAuthAndJWECombined(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	chConfig := setupEmbeddedClickHouse(t)
	provider := newTestOAuthProvider(t, nil)

	jweSecretKey := "this-is-a-32-byte-secret-key!!"
	jwtSecretKey := "test-jwt-secret-key-123"

	t.Run("both_enabled_jwe_only", func(t *testing.T) {
		t.Parallel()
		claims := map[string]interface{}{
			"host":     chConfig.Host,
			"port":     float64(chConfig.Port),
			"database": chConfig.Database,
			"username": chConfig.Username,
			"password": chConfig.Password,
			"protocol": string(chConfig.Protocol),
			"exp":      time.Now().Add(time.Hour).Unix(),
		}

		jweToken := generateJWEToken(t, claims, []byte(jweSecretKey), []byte(jwtSecretKey))

		srv := NewClickHouseMCPServer(config.Config{
			ClickHouse: *chConfig,
			Server: config.ServerConfig{
				JWE: config.JWEConfig{
					Enabled:      true,
					JWESecretKey: jweSecretKey,
					JWTSecretKey: jwtSecretKey,
				},
				OAuth: config.OAuthConfig{
					Enabled: true,
					Mode:    "forward",
					Issuer:  provider.server.URL,
					JWKSURL: provider.server.URL + "/jwks",
				},
			},
		}, "test")

		// Create request with only JWE token (no OAuth) — JWE has username, so it's self-sufficient
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("x-altinity-mcp-key", jweToken)
		req = req.WithContext(context.WithValue(req.Context(), CHJWEServerKey, srv))

		jweTokenOut, jweClaims, oauthToken, oauthClaims, err := srv.ValidateAuth(req)
		require.NoError(t, err, "JWE with credentials should succeed without OAuth")
		require.NotEmpty(t, jweTokenOut)
		require.NotNil(t, jweClaims)
		require.Empty(t, oauthToken)
		require.Nil(t, oauthClaims)

		// Should be able to get ClickHouse client via JWE credentials without reparsing JWE.
		ctxWithClaims := context.WithValue(ctx, JWEClaimsKey, jweClaims)
		client, err := srv.GetClickHouseClientWithOAuth(ctxWithClaims, jweTokenOut, "", nil)
		require.NoError(t, err)
		require.NotNil(t, client)
		require.NoError(t, client.Close())
	})

	t.Run("both_enabled_oauth_only", func(t *testing.T) {
		t.Parallel()
		srv := NewClickHouseMCPServer(config.Config{
			ClickHouse: *chConfig,
			Server: config.ServerConfig{
				JWE: config.JWEConfig{
					Enabled:      true,
					JWESecretKey: jweSecretKey,
					JWTSecretKey: jwtSecretKey,
				},
				OAuth: config.OAuthConfig{
					Enabled: true,
					Mode:    "forward",
					Issuer:  provider.server.URL,
					JWKSURL: provider.server.URL + "/jwks",
				},
			},
		}, "test")

		oauthToken := "opaque-access-token"

		// Create request with only OAuth token (no JWE) → falls through to OAuth
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("x-oauth-token", oauthToken)
		req = req.WithContext(context.WithValue(req.Context(), CHJWEServerKey, srv))

		jweTokenOut, jweClaims, oauthTokenOut, oauthClaims, err := srv.ValidateAuth(req)
		require.NoError(t, err, "should succeed with OAuth when JWE token is absent")
		require.Empty(t, jweTokenOut)
		require.Nil(t, jweClaims)
		require.Equal(t, oauthToken, oauthTokenOut)
		require.Nil(t, oauthClaims)
	})

	t.Run("both_enabled_both_provided", func(t *testing.T) {
		t.Parallel()
		claims := map[string]interface{}{
			"host":     chConfig.Host,
			"port":     float64(chConfig.Port),
			"database": chConfig.Database,
			"username": chConfig.Username,
			"password": chConfig.Password,
			"protocol": string(chConfig.Protocol),
			"exp":      time.Now().Add(time.Hour).Unix(),
		}

		jweToken := generateJWEToken(t, claims, []byte(jweSecretKey), []byte(jwtSecretKey))

		srv := NewClickHouseMCPServer(config.Config{
			ClickHouse: *chConfig,
			Server: config.ServerConfig{
				JWE: config.JWEConfig{
					Enabled:      true,
					JWESecretKey: jweSecretKey,
					JWTSecretKey: jwtSecretKey,
				},
				OAuth: config.OAuthConfig{
					Enabled:              true,
					Mode:                 "forward",
					Issuer:               provider.server.URL,
					JWKSURL:              provider.server.URL + "/jwks",
					ClickHouseHeaderName: "X-ClickHouse-OAuth-Token",
				},
			},
		}, "test")

		oauthToken := "opaque-access-token"

		// Create request with both tokens — JWE has credentials, takes priority
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("x-altinity-mcp-key", jweToken)
		req.Header.Set("x-oauth-token", oauthToken)
		req = req.WithContext(context.WithValue(req.Context(), CHJWEServerKey, srv))

		jweTokenOut, jweClaims, oauthTokenOut, oauthClaims, err := srv.ValidateAuth(req)
		require.NoError(t, err)
		require.NotEmpty(t, jweTokenOut)
		require.NotNil(t, jweClaims)
		require.Empty(t, oauthTokenOut, "OAuth should be skipped when JWE has credentials")
		require.Nil(t, oauthClaims)

		// Get client via JWE credentials without reparsing JWE.
		ctxWithClaims := context.WithValue(ctx, JWEClaimsKey, jweClaims)
		client, err := srv.GetClickHouseClientWithOAuth(ctxWithClaims, jweTokenOut, "", nil)
		require.NoError(t, err)
		require.NotNil(t, client)
		require.NoError(t, client.Close())
	})

	t.Run("both_enabled_neither_provided", func(t *testing.T) {
		t.Parallel()
		srv := NewClickHouseMCPServer(config.Config{
			ClickHouse: *chConfig,
			Server: config.ServerConfig{
				JWE: config.JWEConfig{
					Enabled:      true,
					JWESecretKey: jweSecretKey,
					JWTSecretKey: jwtSecretKey,
				},
				OAuth: config.OAuthConfig{
					Enabled: true,
				},
			},
		}, "test")

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req = req.WithContext(context.WithValue(req.Context(), CHJWEServerKey, srv))

		_, _, _, _, err := srv.ValidateAuth(req)
		require.Error(t, err)
	})

	t.Run("both_enabled_jwe_valid_oauth_invalid", func(t *testing.T) {
		t.Parallel()
		claims := map[string]interface{}{
			"host":     chConfig.Host,
			"port":     float64(chConfig.Port),
			"database": chConfig.Database,
			"username": chConfig.Username,
			"password": chConfig.Password,
			"protocol": string(chConfig.Protocol),
			"exp":      time.Now().Add(time.Hour).Unix(),
		}

		jweToken := generateJWEToken(t, claims, []byte(jweSecretKey), []byte(jwtSecretKey))

		srv := NewClickHouseMCPServer(config.Config{
			ClickHouse: *chConfig,
			Server: config.ServerConfig{
				JWE: config.JWEConfig{
					Enabled:      true,
					JWESecretKey: jweSecretKey,
					JWTSecretKey: jwtSecretKey,
				},
				OAuth: config.OAuthConfig{
					Enabled:         true,
					Mode:            "gating",
					Issuer:          provider.server.URL,
					JWKSURL:         provider.server.URL + "/jwks",
					Audience:        "https://mcp.example.com",
					GatingSecretKey: "test-gating-secret-32-byte-key!!",
				},
			},
		}, "test")

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("x-altinity-mcp-key", jweToken)
		req.Header.Set("x-oauth-token", "not-a-valid-oauth-token")
		req = req.WithContext(context.WithValue(req.Context(), CHJWEServerKey, srv))

		// JWE has credentials (username) → takes priority, OAuth skipped entirely.
		jweTokenOut, jweClaims, oauthTokenOut, _, err := srv.ValidateAuth(req)
		require.NoError(t, err)
		require.NotEmpty(t, jweTokenOut)
		require.NotNil(t, jweClaims)
		require.Empty(t, oauthTokenOut, "OAuth should be skipped when JWE has credentials")
	})

	t.Run("both_enabled_jwe_invalid_oauth_valid", func(t *testing.T) {
		t.Parallel()
		oauthToken := "opaque-access-token"

		srv := NewClickHouseMCPServer(config.Config{
			ClickHouse: *chConfig,
			Server: config.ServerConfig{
				JWE: config.JWEConfig{
					Enabled:      true,
					JWESecretKey: jweSecretKey,
					JWTSecretKey: jwtSecretKey,
				},
				OAuth: config.OAuthConfig{
					Enabled: true,
					Mode:    "forward",
					Issuer:  provider.server.URL,
					JWKSURL: provider.server.URL + "/jwks",
				},
			},
		}, "test")

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("x-altinity-mcp-key", "invalid-jwe-token")
		req.Header.Set("x-oauth-token", oauthToken)
		req = req.WithContext(context.WithValue(req.Context(), CHJWEServerKey, srv))

		// AND semantics: JWE token is invalid, so request should fail
		_, _, _, _, err := srv.ValidateAuth(req)
		require.Error(t, err, "should reject when JWE token is invalid")
	})
}

// TestOAuthOpenAPIHandler tests OpenAPI handler with OAuth authentication
func TestOAuthOpenAPIHandler(t *testing.T) {
	t.Parallel()
	chConfig := setupEmbeddedClickHouse(t)
	provider := newTestOAuthProvider(t, nil)

	t.Run("oauth_only_valid", func(t *testing.T) {
		t.Parallel()
		const gatingSecret = "test-gating-secret-32-byte-key!!"
		srv := NewClickHouseMCPServer(config.Config{
			ClickHouse: *chConfig,
			Server: config.ServerConfig{
				JWE: config.JWEConfig{Enabled: false},
				OAuth: config.OAuthConfig{
					Enabled:         true,
					Mode:            "gating",
					GatingSecretKey: gatingSecret,
				},
			},
		}, "test")

		oauthToken := mintSelfIssuedToken(t, gatingSecret, map[string]interface{}{
			"sub": "user123",
			"exp": time.Now().Add(time.Hour).Unix(),
		})

		req := httptest.NewRequest(http.MethodGet, "/openapi/execute_query?query=SELECT%201", nil)
		req.Header.Set("Authorization", "Bearer "+oauthToken)
		req = req.WithContext(context.WithValue(req.Context(), CHJWEServerKey, srv))

		rr := httptest.NewRecorder()
		srv.OpenAPIHandler(rr, req)

		require.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("oauth_only_missing", func(t *testing.T) {
		t.Parallel()
		srv := NewClickHouseMCPServer(config.Config{
			ClickHouse: *chConfig,
			Server: config.ServerConfig{
				JWE: config.JWEConfig{Enabled: false},
				OAuth: config.OAuthConfig{
					Enabled: true,
					Mode:    "forward",
					Issuer:  provider.server.URL,
					JWKSURL: provider.server.URL + "/jwks",
				},
			},
		}, "test")

		req := httptest.NewRequest(http.MethodGet, "/openapi/execute_query?query=SELECT%201", nil)
		req = req.WithContext(context.WithValue(req.Context(), CHJWEServerKey, srv))

		rr := httptest.NewRecorder()
		srv.OpenAPIHandler(rr, req)

		require.Equal(t, http.StatusUnauthorized, rr.Code)
		require.Contains(t, rr.Body.String(), "Missing authentication token")
	})

	t.Run("oauth_only_expired", func(t *testing.T) {
		t.Parallel()
		srv := NewClickHouseMCPServer(config.Config{
			ClickHouse: *chConfig,
			Server: config.ServerConfig{
				JWE: config.JWEConfig{Enabled: false},
				OAuth: config.OAuthConfig{
					Enabled: true,
					Mode:    "forward",
					Issuer:  provider.server.URL,
					JWKSURL: provider.server.URL + "/jwks",
				},
			},
		}, "test")

		// Forward mode passes token through without MCP-layer validation.
		// CH may reject with 500/403 — that's expected. We assert MCP didn't return 401.
		req := httptest.NewRequest(http.MethodGet, "/openapi/execute_query?query=SELECT%201", nil)
		req.Header.Set("Authorization", "Bearer opaque-access-token")
		req = req.WithContext(context.WithValue(req.Context(), CHJWEServerKey, srv))

		rr := httptest.NewRecorder()
		srv.OpenAPIHandler(rr, req)

		require.Equal(t, http.StatusInternalServerError, rr.Code,
			"forward mode should pass token to CH; standard CH rejects Bearer auth")
		require.Contains(t, rr.Body.String(), "Failed to get ClickHouse client",
			"response should indicate CH connection failure, not MCP rejection")
	})

	t.Run("oauth_only_insufficient_scopes", func(t *testing.T) {
		t.Parallel()
		srv := NewClickHouseMCPServer(config.Config{
			ClickHouse: *chConfig,
			Server: config.ServerConfig{
				JWE: config.JWEConfig{Enabled: false},
				OAuth: config.OAuthConfig{
					Enabled:        true,
					Mode:           "forward",
					Issuer:         provider.server.URL,
					JWKSURL:        provider.server.URL + "/jwks",
					Audience:       "clickhouse-api",
					RequiredScopes: []string{"admin"},
				},
			},
		}, "test")

		// Forward mode passes token through without MCP-layer validation.
		// CH may reject with 500/403 — that's expected.
		req := httptest.NewRequest(http.MethodGet, "/openapi/execute_query?query=SELECT%201", nil)
		req.Header.Set("Authorization", "Bearer opaque-access-token")
		req = req.WithContext(context.WithValue(req.Context(), CHJWEServerKey, srv))

		rr := httptest.NewRecorder()
		srv.OpenAPIHandler(rr, req)

		require.Equal(t, http.StatusInternalServerError, rr.Code,
			"forward mode should pass token to CH; standard CH rejects Bearer auth")
		require.Contains(t, rr.Body.String(), "Failed to get ClickHouse client",
			"response should indicate CH connection failure, not MCP rejection")
	})

	t.Run("oauth_only_invalid", func(t *testing.T) {
		t.Parallel()
		srv := NewClickHouseMCPServer(config.Config{
			ClickHouse: *chConfig,
			Server: config.ServerConfig{
				JWE: config.JWEConfig{Enabled: false},
				OAuth: config.OAuthConfig{
					Enabled: true,
					Mode:    "forward",
					Issuer:  provider.server.URL,
					JWKSURL: provider.server.URL + "/jwks",
				},
			},
		}, "test")

		// Forward mode passes token through without MCP-layer validation.
		// CH may reject with 500/403 — that's expected.
		req := httptest.NewRequest(http.MethodGet, "/openapi/execute_query?query=SELECT%201", nil)
		req.Header.Set("Authorization", "Bearer opaque-access-token")
		req = req.WithContext(context.WithValue(req.Context(), CHJWEServerKey, srv))

		rr := httptest.NewRecorder()
		srv.OpenAPIHandler(rr, req)

		require.Equal(t, http.StatusInternalServerError, rr.Code,
			"forward mode should pass token to CH; standard CH rejects Bearer auth")
		require.Contains(t, rr.Body.String(), "Failed to get ClickHouse client",
			"response should indicate CH connection failure, not MCP rejection")
	})
}

// TestGetOAuthClaimsFromCtx tests OAuth claims extraction from context
func TestGetOAuthClaimsFromCtx(t *testing.T) {
	t.Parallel()
	srv := &ClickHouseJWEServer{}

	t.Run("with_claims", func(t *testing.T) {
		t.Parallel()
		expectedClaims := &OAuthClaims{
			Subject: "user123",
			Email:   "user@example.com",
		}
		ctx := context.WithValue(context.Background(), OAuthClaimsKey, expectedClaims)
		claims := srv.GetOAuthClaimsFromCtx(ctx)
		require.NotNil(t, claims)
		require.Equal(t, "user123", claims.Subject)
		require.Equal(t, "user@example.com", claims.Email)
	})

	t.Run("no_claims", func(t *testing.T) {
		t.Parallel()
		claims := srv.GetOAuthClaimsFromCtx(context.Background())
		require.Nil(t, claims)
	})

	t.Run("wrong_type", func(t *testing.T) {
		t.Parallel()
		ctx := context.WithValue(context.Background(), OAuthClaimsKey, "not-claims")
		claims := srv.GetOAuthClaimsFromCtx(ctx)
		require.Nil(t, claims)
	})
}

// TestGetClickHouseClientWithOAuth tests client creation with OAuth headers
func TestGetClickHouseClientWithOAuth(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	chConfig := setupEmbeddedClickHouse(t)

	t.Run("no_oauth_forwarding", func(t *testing.T) {
		t.Parallel()
		srv := NewClickHouseMCPServer(config.Config{
			ClickHouse: *chConfig,
			Server: config.ServerConfig{
				JWE: config.JWEConfig{Enabled: false},
				OAuth: config.OAuthConfig{
					Enabled: true,
					Mode:    "gating",
				},
			},
		}, "test")

		client, err := srv.GetClickHouseClientWithOAuth(ctx, "", "oauth-token", nil)
		require.NoError(t, err)
		require.NotNil(t, client)
		require.NoError(t, client.Close())
	})

	t.Run("with_oauth_forwarding", func(t *testing.T) {
		t.Parallel()
		srv := NewClickHouseMCPServer(config.Config{
			ClickHouse: *chConfig,
			Server: config.ServerConfig{
				OAuth: config.OAuthConfig{
					Enabled:         true,
					Mode:            "forward",
					ClaimsToHeaders: map[string]string{"sub": "X-ClickHouse-Quota-Key"},
				},
			},
		}, "test")
		claims := &OAuthClaims{Subject: "user123"}
		headers := srv.BuildClickHouseHeadersFromOAuth("oauth-token", claims)
		require.NotNil(t, headers)
		require.Equal(t, "Bearer oauth-token", headers["Authorization"])
		require.Equal(t, "user123", headers["X-ClickHouse-Quota-Key"])
	})

	t.Run("with_jwe_and_oauth", func(t *testing.T) {
		t.Parallel()
		jweSecretKey := "this-is-a-32-byte-secret-key!!"
		jwtSecretKey := "test-jwt-secret-key-123"

		jweClaims := map[string]interface{}{
			"host":     chConfig.Host,
			"port":     float64(chConfig.Port),
			"database": chConfig.Database,
			"username": chConfig.Username,
			"password": chConfig.Password,
			"protocol": string(chConfig.Protocol),
			"exp":      time.Now().Add(time.Hour).Unix(),
		}
		jweToken := generateJWEToken(t, jweClaims, []byte(jweSecretKey), []byte(jwtSecretKey))

		srv := NewClickHouseMCPServer(config.Config{
			ClickHouse: *chConfig,
			Server: config.ServerConfig{
				JWE: config.JWEConfig{
					Enabled:      true,
					JWESecretKey: jweSecretKey,
					JWTSecretKey: jwtSecretKey,
				},
				OAuth: config.OAuthConfig{
					Enabled:              true,
					ClickHouseHeaderName: "X-ClickHouse-OAuth-Token",
				},
			},
		}, "test")

		client, err := srv.GetClickHouseClientWithOAuth(ctx, jweToken, "oauth-token", nil)
		require.NoError(t, err)
		require.NotNil(t, client)
		require.NoError(t, client.Close())
	})
}

// TestValidateAuth tests the combined validation function
func TestValidateAuth(t *testing.T) {
	t.Parallel()
	t.Run("neither_enabled", func(t *testing.T) {
		t.Parallel()
		srv := &ClickHouseJWEServer{
			Config: config.Config{
				Server: config.ServerConfig{
					JWE:   config.JWEConfig{Enabled: false},
					OAuth: config.OAuthConfig{Enabled: false},
				},
			},
		}

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		jwe, jweClaims, oauth, claims, err := srv.ValidateAuth(req)
		require.NoError(t, err)
		require.Empty(t, jwe)
		require.Nil(t, jweClaims)
		require.Empty(t, oauth)
		require.Nil(t, claims)
	})

	t.Run("both_enabled_jwe_with_credentials_skips_oauth", func(t *testing.T) {
		t.Parallel()
		jweSecret := "this-is-a-32-byte-secret-key!!"
		jwtSecret := "jwt-secret"
		jweToken := generateJWEToken(t, map[string]interface{}{
			"host": "localhost", "port": float64(8123), "username": "default",
			"exp": time.Now().Add(time.Hour).Unix(),
		}, []byte(jweSecret), []byte(jwtSecret))

		srv := &ClickHouseJWEServer{
			Config: config.Config{
				Server: config.ServerConfig{
					JWE:   config.JWEConfig{Enabled: true, JWESecretKey: jweSecret, JWTSecretKey: jwtSecret},
					OAuth: config.OAuthConfig{Enabled: true, Mode: "forward"},
				},
			},
		}

		// Request with JWE token (has credentials) but no OAuth token → should succeed
		req := httptest.NewRequest(http.MethodGet, "/openapi/execute_query", nil)
		req.Header.Set("x-altinity-mcp-key", jweToken)
		jwe, jweClaims, oauth, claims, err := srv.ValidateAuth(req)
		require.NoError(t, err, "JWE with credentials should succeed without OAuth")
		require.NotEmpty(t, jwe)
		require.NotNil(t, jweClaims)
		require.Empty(t, oauth)
		require.Nil(t, claims)
	})

	t.Run("both_enabled_jwe_no_credentials_oauth_fallback", func(t *testing.T) {
		t.Parallel()
		jweSecret := "this-is-a-32-byte-secret-key!!"
		jwtSecret := "jwt-secret"
		// JWE token without username → no credentials
		jweToken := generateJWEToken(t, map[string]interface{}{
			"host": "localhost", "port": float64(8123),
			"exp": time.Now().Add(time.Hour).Unix(),
		}, []byte(jweSecret), []byte(jwtSecret))

		srv := &ClickHouseJWEServer{
			Config: config.Config{
				Server: config.ServerConfig{
					JWE:   config.JWEConfig{Enabled: true, JWESecretKey: jweSecret, JWTSecretKey: jwtSecret},
					OAuth: config.OAuthConfig{Enabled: true, Mode: "forward"},
				},
			},
		}

		// JWE without credentials + OAuth token → falls through to OAuth
		req := httptest.NewRequest(http.MethodGet, "/openapi/execute_query", nil)
		req.Header.Set("x-altinity-mcp-key", jweToken)
		req.Header.Set("Authorization", "Bearer some-oauth-token")
		jwe, jweClaims, oauth, _, err := srv.ValidateAuth(req)
		require.NoError(t, err)
		require.NotEmpty(t, jwe)
		require.NotNil(t, jweClaims)
		require.Equal(t, "some-oauth-token", oauth)
	})

	t.Run("both_enabled_jwe_no_credentials_no_oauth_rejected", func(t *testing.T) {
		t.Parallel()
		jweSecret := "this-is-a-32-byte-secret-key!!"
		jwtSecret := "jwt-secret"
		jweToken := generateJWEToken(t, map[string]interface{}{
			"host": "localhost", "port": float64(8123),
			"exp": time.Now().Add(time.Hour).Unix(),
		}, []byte(jweSecret), []byte(jwtSecret))

		srv := &ClickHouseJWEServer{
			Config: config.Config{
				Server: config.ServerConfig{
					JWE:   config.JWEConfig{Enabled: true, JWESecretKey: jweSecret, JWTSecretKey: jwtSecret},
					OAuth: config.OAuthConfig{Enabled: true, Mode: "forward"},
				},
			},
		}

		// JWE without credentials + no OAuth token → should fail
		req := httptest.NewRequest(http.MethodGet, "/openapi/execute_query", nil)
		req.Header.Set("x-altinity-mcp-key", jweToken)
		_, _, _, _, err := srv.ValidateAuth(req)
		require.Error(t, err, "should reject when JWE has no credentials and OAuth is missing")
	})

	t.Run("both_enabled_oauth_only_succeeds", func(t *testing.T) {
		t.Parallel()
		srv := &ClickHouseJWEServer{
			Config: config.Config{
				Server: config.ServerConfig{
					JWE:   config.JWEConfig{Enabled: true, JWESecretKey: "this-is-a-32-byte-secret-key!!", JWTSecretKey: "jwt"},
					OAuth: config.OAuthConfig{Enabled: true, Mode: "forward"},
				},
			},
		}

		// No JWE token, only OAuth → falls through to OAuth
		req := httptest.NewRequest(http.MethodGet, "/openapi/execute_query", nil)
		req.Header.Set("Authorization", "Bearer some-oauth-token")
		jwe, jweClaims, oauth, _, err := srv.ValidateAuth(req)
		require.NoError(t, err, "should succeed with OAuth when JWE token is absent")
		require.Empty(t, jwe)
		require.Nil(t, jweClaims)
		require.Equal(t, "some-oauth-token", oauth)
	})

	t.Run("both_enabled_jwe_invalid_oauth_valid_rejected", func(t *testing.T) {
		t.Parallel()
		srv := &ClickHouseJWEServer{
			Config: config.Config{
				Server: config.ServerConfig{
					JWE:   config.JWEConfig{Enabled: true, JWESecretKey: "this-is-a-32-byte-secret-key!!", JWTSecretKey: "jwt"},
					OAuth: config.OAuthConfig{Enabled: true, Mode: "forward"},
				},
			},
		}

		// Invalid JWE + valid OAuth → hard error (invalid JWE is always a failure)
		req := httptest.NewRequest(http.MethodGet, "/openapi/execute_query", nil)
		req.Header.Set("x-altinity-mcp-key", "invalid-jwe-token")
		req.Header.Set("Authorization", "Bearer some-oauth-token")
		_, _, _, _, err := srv.ValidateAuth(req)
		require.Error(t, err, "invalid JWE should be a hard error even with valid OAuth")
	})

	t.Run("both_enabled_both_provided_jwe_priority", func(t *testing.T) {
		t.Parallel()
		jweSecret := "this-is-a-32-byte-secret-key!!"
		jwtSecret := "jwt-secret"
		jweToken := generateJWEToken(t, map[string]interface{}{
			"host": "localhost", "port": float64(8123), "username": "default",
			"exp": time.Now().Add(time.Hour).Unix(),
		}, []byte(jweSecret), []byte(jwtSecret))

		srv := &ClickHouseJWEServer{
			Config: config.Config{
				Server: config.ServerConfig{
					JWE:   config.JWEConfig{Enabled: true, JWESecretKey: jweSecret, JWTSecretKey: jwtSecret},
					OAuth: config.OAuthConfig{Enabled: true, Mode: "forward"},
				},
			},
		}

		// Both tokens provided, JWE has credentials → JWE takes priority, OAuth skipped
		req := httptest.NewRequest(http.MethodGet, "/openapi/execute_query", nil)
		req.Header.Set("x-altinity-mcp-key", jweToken)
		req.Header.Set("Authorization", "Bearer some-oauth-token")
		jwe, jweClaims, oauth, claims, err := srv.ValidateAuth(req)
		require.NoError(t, err)
		require.NotEmpty(t, jwe)
		require.NotNil(t, jweClaims)
		require.Empty(t, oauth, "OAuth should be skipped when JWE has credentials")
		require.Nil(t, claims)
	})
}

// TestOAuthMCPToolExecution tests that OAuth works with MCP tool execution
func TestOAuthMCPToolExecution(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	chConfig := setupEmbeddedClickHouse(t)
	provider := newTestOAuthProvider(t, nil)

	t.Run("execute_query_with_oauth", func(t *testing.T) {
		t.Parallel()
		// Create server with OAuth gating mode (validates token at MCP layer, uses static CH credentials)
		const gatingSecret = "test-gating-secret-32-byte-key!!"
		srv := NewClickHouseMCPServer(config.Config{
			ClickHouse: *chConfig,
			Server: config.ServerConfig{
				JWE: config.JWEConfig{Enabled: false},
				OAuth: config.OAuthConfig{
					Enabled:         true,
					Mode:            "gating",
					GatingSecretKey: gatingSecret,
				},
			},
		}, "test")

		oauthToken := mintSelfIssuedToken(t, gatingSecret, map[string]interface{}{
			"sub": "user123",
			"exp": time.Now().Add(time.Hour).Unix(),
		})

		// Create context with server and OAuth claims (simulating MCP middleware)
		ctx = context.WithValue(ctx, CHJWEServerKey, srv)
		ctx = context.WithValue(ctx, OAuthTokenKey, oauthToken)
		ctx = context.WithValue(ctx, OAuthClaimsKey, (*OAuthClaims)(nil))

		// Execute MCP tool request
		req := &mcp.CallToolRequest{
			Params: &mcp.CallToolParamsRaw{
				Name:      "execute_query",
				Arguments: json.RawMessage(`{"query": "SELECT 1 as result"}`),
			},
		}

		result, err := HandleExecuteQuery(ctx, req)
		require.NoError(t, err)
		require.NotNil(t, result)
		require.False(t, result.IsError)

		// Verify result
		textContent, ok := result.Content[0].(*mcp.TextContent)
		require.True(t, ok)
		require.NotEmpty(t, textContent.Text)

		var qr clickhouse.QueryResult
		require.NoError(t, json.Unmarshal([]byte(textContent.Text), &qr))
		require.Equal(t, 1, qr.Count)
	})

	t.Run("execute_query_with_oauth_and_header_forwarding", func(t *testing.T) {
		t.Parallel()
		srv := NewClickHouseMCPServer(config.Config{
			ClickHouse: *chConfig,
			Server: config.ServerConfig{
				JWE: config.JWEConfig{Enabled: false},
				OAuth: config.OAuthConfig{
					Enabled: true,
					Mode:    "forward",
				},
			},
		}, "test")

		oauthToken := "opaque-access-token"
		headers := srv.BuildClickHouseHeadersFromOAuth(oauthToken, nil)
		require.Equal(t, "Bearer "+oauthToken, headers["Authorization"])
	})

	t.Run("oauth_and_jwe_together_mcp", func(t *testing.T) {
		t.Parallel()
		jweSecretKey := "this-is-a-32-byte-secret-key!!"
		jwtSecretKey := "test-jwt-secret-key-123"

		// Create JWE token with ClickHouse credentials
		jweClaims := map[string]interface{}{
			"host":     chConfig.Host,
			"port":     float64(chConfig.Port),
			"database": chConfig.Database,
			"username": chConfig.Username,
			"password": chConfig.Password,
			"protocol": string(chConfig.Protocol),
			"exp":      time.Now().Add(time.Hour).Unix(),
		}
		jweToken := generateJWEToken(t, jweClaims, []byte(jweSecretKey), []byte(jwtSecretKey))

		oauthToken := "opaque-access-token"

		// Create server with both enabled
		srv := NewClickHouseMCPServer(config.Config{
			ClickHouse: *chConfig,
			Server: config.ServerConfig{
				JWE: config.JWEConfig{
					Enabled:      true,
					JWESecretKey: jweSecretKey,
					JWTSecretKey: jwtSecretKey,
				},
				OAuth: config.OAuthConfig{
					Enabled: true,
					Mode:    "forward",
					Issuer:  provider.server.URL,
					JWKSURL: provider.server.URL + "/jwks",
				},
			},
		}, "test")

		// Simulate HTTP request with both tokens
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("x-altinity-mcp-key", jweToken)
		req.Header.Set("x-oauth-token", oauthToken)
		req = req.WithContext(context.WithValue(req.Context(), CHJWEServerKey, srv))

		// JWE has credentials (username) → takes priority, OAuth is skipped
		jweOut, jweClaims, oauthOut, oauthClaims, err := srv.ValidateAuth(req)
		require.NoError(t, err)
		require.NotEmpty(t, jweOut)
		require.NotNil(t, jweClaims)
		require.Empty(t, oauthOut, "OAuth should be skipped when JWE has credentials")
		require.Nil(t, oauthClaims)
	})
}

// TestOAuthOpenAPIFullFlow tests complete OAuth flow for OpenAPI endpoint
func TestOAuthOpenAPIFullFlow(t *testing.T) {
	t.Parallel()
	chConfig := setupEmbeddedClickHouse(t)
	provider := newTestOAuthProvider(t, nil)

	t.Run("complete_oauth_openapi_flow", func(t *testing.T) {
		t.Parallel()
		// Antalya is required for token_processors-driven OIDC validation in CH.
		// Use newAntalyaOIDCProvider (full discovery doc) — Antalya rejects
		// the shorter doc returned by newTestOAuthProvider.
		// setupEmbeddedAntalyaWithOIDC auto-skips on non-Linux hosts.
		oidcProvider := newAntalyaOIDCProvider(t, nil)
		antalyaCH := setupEmbeddedAntalyaWithOIDC(t, oidcProvider.server.URL)
		srv := NewClickHouseMCPServer(config.Config{
			ClickHouse: antalyaCH,
			Server:     config.ServerConfig{OAuth: config.OAuthConfig{Enabled: true, Mode: "forward"}},
		}, "test")
		oauthToken := oidcProvider.issueJWT(t, map[string]interface{}{
			"sub": "service-account-123",
			"iss": oidcProvider.server.URL,
			"exp": time.Now().Add(time.Hour).Unix(),
		})
		req := httptest.NewRequest(http.MethodGet, "/openapi/execute_query?query=SELECT%20version()%20as%20version", nil)
		req.Header.Set("Authorization", "Bearer "+oauthToken)
		req = req.WithContext(context.WithValue(req.Context(), CHJWEServerKey, srv))
		rr := httptest.NewRecorder()
		srv.OpenAPIHandler(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)
		var qr clickhouse.QueryResult
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &qr))
		require.Equal(t, 1, qr.Count)
		require.Contains(t, qr.Columns, "version")
	})

	t.Run("forward_mode_passthrough_wrong_audience", func(t *testing.T) {
		t.Parallel()
		srv := NewClickHouseMCPServer(config.Config{
			ClickHouse: *chConfig,
			Server: config.ServerConfig{
				JWE: config.JWEConfig{Enabled: false},
				OAuth: config.OAuthConfig{
					Enabled:  true,
					Mode:     "forward",
					Issuer:   provider.server.URL,
					JWKSURL:  provider.server.URL + "/jwks",
					Audience: "expected-audience",
				},
			},
		}, "test")

		// Forward mode passes token through without MCP-layer validation.
		// CH may reject with 500/403 — that's expected.
		req := httptest.NewRequest(http.MethodGet, "/openapi/execute_query?query=SELECT%201", nil)
		req.Header.Set("Authorization", "Bearer opaque-access-token")
		req = req.WithContext(context.WithValue(req.Context(), CHJWEServerKey, srv))

		rr := httptest.NewRecorder()
		srv.OpenAPIHandler(rr, req)

		require.Equal(t, http.StatusInternalServerError, rr.Code,
			"forward mode should pass token to CH; standard CH rejects Bearer auth")
		require.Contains(t, rr.Body.String(), "Failed to get ClickHouse client",
			"response should indicate CH connection failure, not MCP rejection")
	})

	t.Run("forward_mode_passthrough_missing_scope", func(t *testing.T) {
		t.Parallel()
		srv := NewClickHouseMCPServer(config.Config{
			ClickHouse: *chConfig,
			Server: config.ServerConfig{
				JWE: config.JWEConfig{Enabled: false},
				OAuth: config.OAuthConfig{
					Enabled:        true,
					Mode:           "forward",
					Issuer:         provider.server.URL,
					JWKSURL:        provider.server.URL + "/jwks",
					Audience:       "clickhouse-api",
					RequiredScopes: []string{"admin"},
				},
			},
		}, "test")

		// Forward mode passes token through without MCP-layer validation.
		// CH may reject with 500/403 — that's expected.
		req := httptest.NewRequest(http.MethodGet, "/openapi/execute_query?query=SELECT%201", nil)
		req.Header.Set("Authorization", "Bearer opaque-access-token")
		req = req.WithContext(context.WithValue(req.Context(), CHJWEServerKey, srv))

		rr := httptest.NewRecorder()
		srv.OpenAPIHandler(rr, req)

		require.Equal(t, http.StatusInternalServerError, rr.Code,
			"forward mode should pass token to CH; standard CH rejects Bearer auth")
		require.Contains(t, rr.Body.String(), "Failed to get ClickHouse client",
			"response should indicate CH connection failure, not MCP rejection")
	})
}

func TestResolveOAuthJWKSURL(t *testing.T) {
	t.Parallel()
	t.Run("direct_jwks_url_configured", func(t *testing.T) {
		t.Parallel()
		srv := &ClickHouseJWEServer{
			Config: config.Config{
				Server: config.ServerConfig{
					OAuth: config.OAuthConfig{
						JWKSURL: "https://auth.example.com/jwks",
					},
				},
			},
		}
		url, err := srv.resolveOAuthJWKSURL()
		require.NoError(t, err)
		require.Equal(t, "https://auth.example.com/jwks", url)
	})

	t.Run("openid_configuration_discovery", func(t *testing.T) {
		t.Parallel()
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/.well-known/openid-configuration" {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]string{
					"issuer":   "https://auth.example.com",
					"jwks_uri": "https://auth.example.com/keys",
				})
				return
			}
			http.NotFound(w, r)
		}))
		defer mockServer.Close()

		srv := &ClickHouseJWEServer{
			Config: config.Config{
				Server: config.ServerConfig{
					OAuth: config.OAuthConfig{
						Issuer: mockServer.URL,
					},
				},
			},
		}
		url, err := srv.resolveOAuthJWKSURL()
		require.NoError(t, err)
		require.Equal(t, "https://auth.example.com/keys", url)
	})

	t.Run("fallback_to_oauth_authorization_server", func(t *testing.T) {
		t.Parallel()
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/.well-known/openid-configuration" {
				http.NotFound(w, r)
				return
			}
			if r.URL.Path == "/.well-known/oauth-authorization-server" {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]string{
					"issuer":   "https://auth.example.com",
					"jwks_uri": "https://auth.example.com/fallback-keys",
				})
				return
			}
			http.NotFound(w, r)
		}))
		defer mockServer.Close()

		srv := &ClickHouseJWEServer{
			Config: config.Config{
				Server: config.ServerConfig{
					OAuth: config.OAuthConfig{
						Issuer: mockServer.URL,
					},
				},
			},
		}
		url, err := srv.resolveOAuthJWKSURL()
		require.NoError(t, err)
		require.Equal(t, "https://auth.example.com/fallback-keys", url)
	})

	t.Run("both_discovery_endpoints_fail", func(t *testing.T) {
		t.Parallel()
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.NotFound(w, r)
		}))
		defer mockServer.Close()

		srv := &ClickHouseJWEServer{
			Config: config.Config{
				Server: config.ServerConfig{
					OAuth: config.OAuthConfig{
						Issuer: mockServer.URL,
					},
				},
			},
		}
		_, err := srv.resolveOAuthJWKSURL()
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to discover")
	})

	t.Run("discovery_missing_jwks_uri", func(t *testing.T) {
		t.Parallel()
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"issuer": "https://auth.example.com",
			})
		}))
		defer mockServer.Close()

		srv := &ClickHouseJWEServer{
			Config: config.Config{
				Server: config.ServerConfig{
					OAuth: config.OAuthConfig{
						Issuer: mockServer.URL,
					},
				},
			},
		}
		_, err := srv.resolveOAuthJWKSURL()
		require.Error(t, err)
		require.Contains(t, err.Error(), "jwks_uri")
	})
}

func TestOIDCConfigCaching(t *testing.T) {
	t.Parallel()
	var requestCount int
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":   "https://auth.example.com",
			"jwks_uri": "https://auth.example.com/keys",
		})
	}))
	defer mockServer.Close()

	srv := &ClickHouseJWEServer{
		Config: config.Config{
			Server: config.ServerConfig{
				OAuth: config.OAuthConfig{
					Issuer: mockServer.URL,
				},
			},
		},
	}

	// NOTE: subtests are NOT parallel — they share requestCount and srv cache state
	t.Run("cache_hit_within_ttl", func(t *testing.T) {
		requestCount = 0
		_, err := srv.FetchOpenIDConfiguration(mockServer.URL)
		require.NoError(t, err)
		_, err = srv.FetchOpenIDConfiguration(mockServer.URL)
		require.NoError(t, err)
		require.Equal(t, 1, requestCount, "second call should hit cache")
	})

	t.Run("cache_miss_after_ttl_expires", func(t *testing.T) {
		// Ensure cache is populated
		_, err := srv.FetchOpenIDConfiguration(mockServer.URL)
		require.NoError(t, err)

		// Manipulate cache time to simulate TTL expiry
		srv.oidcConfigMu.Lock()
		srv.oidcConfigTime = time.Now().Add(-oauthJWKSCacheTTL - time.Second)
		srv.oidcConfigMu.Unlock()

		countBefore := requestCount
		_, err = srv.FetchOpenIDConfiguration(mockServer.URL)
		require.NoError(t, err)
		require.Equal(t, countBefore+1, requestCount, "should re-fetch after TTL expiry")
	})
}

func TestParseAndVerifyExternalJWTUnknownKid(t *testing.T) {
	t.Parallel()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create JWKS with kid "known"
	knownJWK := jose.JSONWebKey{Key: &privateKey.PublicKey, KeyID: "known", Algorithm: "RS256", Use: "sig"}
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"issuer":   r.Host,
				"jwks_uri": "http://" + r.Host + "/jwks",
			})
		case "/jwks":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{knownJWK}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer mockServer.Close()

	srv := &ClickHouseJWEServer{
		Config: config.Config{
			Server: config.ServerConfig{
				OAuth: config.OAuthConfig{
					Issuer:  mockServer.URL,
					JWKSURL: mockServer.URL + "/jwks",
				},
			},
		},
	}

	// Sign token with kid "unknown"
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

	_, err = srv.parseAndVerifyExternalJWT(token, "test-audience")
	require.Error(t, err)
	require.Contains(t, err.Error(), "no JWK found for kid")
}

func TestValidateOAuthClaimsTemporalEdgeCases(t *testing.T) {
	t.Parallel()
	const gatingSecret = "test-gating-secret-32-byte-key!!"
	now := time.Now().Unix()

	baseClaims := func() map[string]interface{} {
		return map[string]interface{}{
			"sub":   "user-1",
			"iss":   "https://mcp.example.com",
			"aud":   "https://mcp.example.com",
			"email": "user@example.com",
		}
	}

	newSrv := func() *ClickHouseJWEServer {
		return NewClickHouseMCPServer(config.Config{
			Server: config.ServerConfig{
				OAuth: config.OAuthConfig{
					Enabled:         true,
					Mode:            "gating",
					GatingSecretKey: gatingSecret,
				},
			},
		}, "test")
	}

	// NOTE: subtests are NOT parallel — they share a `now` timestamp and are timing-sensitive
	t.Run("expired_token", func(t *testing.T) {
		c := baseClaims()
		c["exp"] = now - 120
		c["iat"] = now - 300
		token := mintSelfIssuedToken(t, gatingSecret, c)
		srv := newSrv()
		_, err := srv.ValidateOAuthToken(token)
		require.ErrorIs(t, err, ErrOAuthTokenExpired)
	})

	t.Run("expired_within_clock_skew", func(t *testing.T) {
		c := baseClaims()
		c["exp"] = now - 30
		c["iat"] = now - 300
		token := mintSelfIssuedToken(t, gatingSecret, c)
		srv := newSrv()
		_, err := srv.ValidateOAuthToken(token)
		require.NoError(t, err)
	})

	t.Run("expired_beyond_clock_skew", func(t *testing.T) {
		c := baseClaims()
		c["exp"] = now - 61
		c["iat"] = now - 300
		token := mintSelfIssuedToken(t, gatingSecret, c)
		srv := newSrv()
		_, err := srv.ValidateOAuthToken(token)
		require.ErrorIs(t, err, ErrOAuthTokenExpired)
	})

	t.Run("future_nbf_within_skew", func(t *testing.T) {
		c := baseClaims()
		c["exp"] = now + 3600
		c["iat"] = now
		c["nbf"] = now + 30
		token := mintSelfIssuedToken(t, gatingSecret, c)
		srv := newSrv()
		_, err := srv.ValidateOAuthToken(token)
		require.NoError(t, err)
	})

	t.Run("future_nbf_beyond_skew", func(t *testing.T) {
		c := baseClaims()
		c["exp"] = now + 3600
		c["iat"] = now
		c["nbf"] = now + 120
		token := mintSelfIssuedToken(t, gatingSecret, c)
		srv := newSrv()
		_, err := srv.ValidateOAuthToken(token)
		require.ErrorIs(t, err, ErrInvalidOAuthToken)
	})

	t.Run("future_iat_within_skew", func(t *testing.T) {
		c := baseClaims()
		c["exp"] = now + 3600
		c["iat"] = now + 30
		token := mintSelfIssuedToken(t, gatingSecret, c)
		srv := newSrv()
		_, err := srv.ValidateOAuthToken(token)
		require.NoError(t, err)
	})

	t.Run("future_iat_beyond_skew", func(t *testing.T) {
		c := baseClaims()
		c["exp"] = now + 3600
		c["iat"] = now + 120
		token := mintSelfIssuedToken(t, gatingSecret, c)
		srv := newSrv()
		_, err := srv.ValidateOAuthToken(token)
		require.ErrorIs(t, err, ErrInvalidOAuthToken)
	})
}

func TestGatingModeIdentityPolicy(t *testing.T) {
	t.Parallel()
	const gatingSecret = "test-gating-secret-32-byte-key!!"

	newSrv := func(oauthCfg config.OAuthConfig) *ClickHouseJWEServer {
		oauthCfg.Enabled = true
		oauthCfg.Mode = "gating"
		oauthCfg.GatingSecretKey = gatingSecret
		return NewClickHouseMCPServer(config.Config{
			Server: config.ServerConfig{
				OAuth: oauthCfg,
			},
		}, "test")
	}

	t.Run("allowed_email_domain_match", func(t *testing.T) {
		t.Parallel()
		srv := newSrv(config.OAuthConfig{AllowedEmailDomains: []string{"corp.com"}})
		claims := &OAuthClaims{Email: "user@corp.com", EmailVerified: true}
		err := srv.ValidateOAuthIdentityPolicyClaims(claims)
		require.NoError(t, err)
	})

	t.Run("allowed_email_domain_reject", func(t *testing.T) {
		t.Parallel()
		srv := newSrv(config.OAuthConfig{AllowedEmailDomains: []string{"corp.com"}})
		claims := &OAuthClaims{Email: "user@other.com", EmailVerified: true}
		err := srv.ValidateOAuthIdentityPolicyClaims(claims)
		require.ErrorIs(t, err, ErrOAuthUnauthorizedDomain)
	})

	t.Run("require_email_verified_pass", func(t *testing.T) {
		t.Parallel()
		srv := newSrv(config.OAuthConfig{RequireEmailVerified: true})
		claims := &OAuthClaims{Email: "user@example.com", EmailVerified: true}
		err := srv.ValidateOAuthIdentityPolicyClaims(claims)
		require.NoError(t, err)
	})

	t.Run("require_email_verified_fail", func(t *testing.T) {
		t.Parallel()
		srv := newSrv(config.OAuthConfig{RequireEmailVerified: true})
		claims := &OAuthClaims{Email: "user@example.com", EmailVerified: false}
		err := srv.ValidateOAuthIdentityPolicyClaims(claims)
		require.ErrorIs(t, err, ErrOAuthEmailNotVerified)
	})

	t.Run("allowed_hosted_domain_reject", func(t *testing.T) {
		t.Parallel()
		srv := newSrv(config.OAuthConfig{AllowedHostedDomains: []string{"corp.com"}})
		claims := &OAuthClaims{HostedDomain: "other.com"}
		err := srv.ValidateOAuthIdentityPolicyClaims(claims)
		require.ErrorIs(t, err, ErrOAuthUnauthorizedDomain)
	})
}

// ---------- coverage gap tests ----------

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
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tt.want, emailDomain(tt.email))
		})
	}
}

func TestOAuthClaimsFromRawClaims(t *testing.T) {
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
		claims := oauthClaimsFromRawClaims(raw)
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
		claims := oauthClaimsFromRawClaims(raw)
		require.Equal(t, int64(1700000000), claims.ExpiresAt)
		require.Equal(t, int64(1699999000), claims.IssuedAt)
		require.Equal(t, int64(1699998000), claims.NotBefore)
	})

	t.Run("audience_array", func(t *testing.T) {
		t.Parallel()
		raw := map[string]interface{}{
			"aud": []interface{}{"api1", "api2"},
		}
		claims := oauthClaimsFromRawClaims(raw)
		require.Equal(t, []string{"api1", "api2"}, claims.Audience)
	})

	t.Run("scope_array", func(t *testing.T) {
		t.Parallel()
		raw := map[string]interface{}{
			"scope": []interface{}{"read", "write", "admin"},
		}
		claims := oauthClaimsFromRawClaims(raw)
		require.Equal(t, []string{"read", "write", "admin"}, claims.Scopes)
	})

	t.Run("email_verified_string", func(t *testing.T) {
		t.Parallel()
		raw := map[string]interface{}{
			"email_verified": "true",
		}
		claims := oauthClaimsFromRawClaims(raw)
		require.True(t, claims.EmailVerified)

		raw2 := map[string]interface{}{
			"email_verified": "false",
		}
		claims2 := oauthClaimsFromRawClaims(raw2)
		require.False(t, claims2.EmailVerified)
	})

	t.Run("extra_claims_preserved", func(t *testing.T) {
		t.Parallel()
		raw := map[string]interface{}{
			"sub":        "user",
			"custom1":    "value1",
			"custom_num": float64(42),
		}
		claims := oauthClaimsFromRawClaims(raw)
		require.Equal(t, "value1", claims.Extra["custom1"])
		require.Equal(t, float64(42), claims.Extra["custom_num"])
		_, hasSub := claims.Extra["sub"]
		require.False(t, hasSub)
	})

	t.Run("empty_claims", func(t *testing.T) {
		t.Parallel()
		claims := oauthClaimsFromRawClaims(map[string]interface{}{})
		require.NotNil(t, claims)
		require.Empty(t, claims.Subject)
		require.NotNil(t, claims.Extra)
	})
}

func TestBuildClickHouseHeadersFromOAuth(t *testing.T) {
	t.Parallel()

	t.Run("gating_mode_returns_nil", func(t *testing.T) {
		t.Parallel()
		srv := NewClickHouseMCPServer(config.Config{
			Server: config.ServerConfig{
				OAuth: config.OAuthConfig{Enabled: true, Mode: "gating"},
			},
		}, "test")
		headers := srv.BuildClickHouseHeadersFromOAuth("token123", &OAuthClaims{Subject: "user"})
		require.Nil(t, headers)
	})

	t.Run("forward_mode_default_header", func(t *testing.T) {
		t.Parallel()
		srv := NewClickHouseMCPServer(config.Config{
			Server: config.ServerConfig{
				OAuth: config.OAuthConfig{Enabled: true, Mode: "forward"},
			},
		}, "test")
		headers := srv.BuildClickHouseHeadersFromOAuth("token123", nil)
		require.Equal(t, "Bearer token123", headers["Authorization"])
	})

	t.Run("forward_mode_custom_header", func(t *testing.T) {
		t.Parallel()
		srv := NewClickHouseMCPServer(config.Config{
			Server: config.ServerConfig{
				OAuth: config.OAuthConfig{
					Enabled:              true,
					Mode:                 "forward",
					ClickHouseHeaderName: "X-Token",
				},
			},
		}, "test")
		headers := srv.BuildClickHouseHeadersFromOAuth("token123", nil)
		require.Equal(t, "token123", headers["X-Token"])
	})

	t.Run("forward_with_claims_to_headers", func(t *testing.T) {
		t.Parallel()
		srv := NewClickHouseMCPServer(config.Config{
			Server: config.ServerConfig{
				OAuth: config.OAuthConfig{
					Enabled: true,
					Mode:    "forward",
					ClaimsToHeaders: map[string]string{
						"sub":            "X-User-ID",
						"email":          "X-Email",
						"name":           "X-Name",
						"email_verified": "X-Verified",
						"hd":             "X-Domain",
						"iss":            "X-Issuer",
						"custom_claim":   "X-Custom",
					},
				},
			},
		}, "test")
		claims := &OAuthClaims{
			Subject:       "user123",
			Issuer:        "https://auth.example.com",
			Email:         "user@example.com",
			Name:          "Test User",
			EmailVerified: true,
			HostedDomain:  "example.com",
			Extra:         map[string]interface{}{"custom_claim": "custom_value"},
		}
		headers := srv.BuildClickHouseHeadersFromOAuth("tok", claims)
		require.Equal(t, "user123", headers["X-User-ID"])
		require.Equal(t, "user@example.com", headers["X-Email"])
		require.Equal(t, "Test User", headers["X-Name"])
		require.Equal(t, "true", headers["X-Verified"])
		require.Equal(t, "example.com", headers["X-Domain"])
		require.Equal(t, "https://auth.example.com", headers["X-Issuer"])
		require.Equal(t, "custom_value", headers["X-Custom"])
	})

	t.Run("forward_with_non_string_extra_claim", func(t *testing.T) {
		t.Parallel()
		srv := NewClickHouseMCPServer(config.Config{
			Server: config.ServerConfig{
				OAuth: config.OAuthConfig{
					Enabled:         true,
					Mode:            "forward",
					ClaimsToHeaders: map[string]string{"roles": "X-Roles"},
				},
			},
		}, "test")
		claims := &OAuthClaims{
			Extra: map[string]interface{}{"roles": []string{"admin", "user"}},
		}
		headers := srv.BuildClickHouseHeadersFromOAuth("tok", claims)
		require.Contains(t, headers["X-Roles"], "admin")
	})

	t.Run("forward_email_verified_false", func(t *testing.T) {
		t.Parallel()
		srv := NewClickHouseMCPServer(config.Config{
			Server: config.ServerConfig{
				OAuth: config.OAuthConfig{
					Enabled:         true,
					Mode:            "forward",
					ClaimsToHeaders: map[string]string{"email_verified": "X-V"},
				},
			},
		}, "test")
		claims := &OAuthClaims{EmailVerified: false}
		headers := srv.BuildClickHouseHeadersFromOAuth("tok", claims)
		require.Equal(t, "false", headers["X-V"])
	})
}

func TestLooksLikeJWT(t *testing.T) {
	t.Parallel()
	require.True(t, looksLikeJWT("a.b.c"))
	require.False(t, looksLikeJWT("not-a-jwt"))
	require.False(t, looksLikeJWT("a.b"))
	require.False(t, looksLikeJWT("a.b.c.d"))
}

func TestValidateOAuthClaims(t *testing.T) {
	t.Parallel()

	t.Run("issuer_mismatch", func(t *testing.T) {
		t.Parallel()
		s := &ClickHouseJWEServer{Config: config.Config{Server: config.ServerConfig{OAuth: config.OAuthConfig{
			Issuer: "https://expected.example.com",
		}}}}
		_, err := s.validateOAuthClaims(&OAuthClaims{Issuer: "https://wrong.example.com"})
		require.ErrorIs(t, err, ErrInvalidOAuthToken)
	})

	t.Run("audience_missing_when_required", func(t *testing.T) {
		t.Parallel()
		s := &ClickHouseJWEServer{Config: config.Config{Server: config.ServerConfig{OAuth: config.OAuthConfig{
			Audience: "my-audience",
		}}}}
		_, err := s.validateOAuthClaims(&OAuthClaims{})
		require.ErrorIs(t, err, ErrInvalidOAuthToken)
	})

	t.Run("audience_mismatch", func(t *testing.T) {
		t.Parallel()
		s := &ClickHouseJWEServer{Config: config.Config{Server: config.ServerConfig{OAuth: config.OAuthConfig{
			Audience: "my-audience",
		}}}}
		_, err := s.validateOAuthClaims(&OAuthClaims{Audience: []string{"wrong-audience"}})
		require.ErrorIs(t, err, ErrInvalidOAuthToken)
	})

	t.Run("token_expired", func(t *testing.T) {
		t.Parallel()
		s := &ClickHouseJWEServer{Config: config.Config{Server: config.ServerConfig{OAuth: config.OAuthConfig{}}}}
		_, err := s.validateOAuthClaims(&OAuthClaims{ExpiresAt: time.Now().Unix() - 300})
		require.ErrorIs(t, err, ErrOAuthTokenExpired)
	})

	t.Run("not_yet_valid", func(t *testing.T) {
		t.Parallel()
		s := &ClickHouseJWEServer{Config: config.Config{Server: config.ServerConfig{OAuth: config.OAuthConfig{}}}}
		_, err := s.validateOAuthClaims(&OAuthClaims{NotBefore: time.Now().Unix() + 300})
		require.ErrorIs(t, err, ErrInvalidOAuthToken)
	})

	t.Run("issued_in_future", func(t *testing.T) {
		t.Parallel()
		s := &ClickHouseJWEServer{Config: config.Config{Server: config.ServerConfig{OAuth: config.OAuthConfig{}}}}
		_, err := s.validateOAuthClaims(&OAuthClaims{IssuedAt: time.Now().Unix() + 300})
		require.ErrorIs(t, err, ErrInvalidOAuthToken)
	})

	t.Run("missing_required_scopes", func(t *testing.T) {
		t.Parallel()
		s := &ClickHouseJWEServer{Config: config.Config{Server: config.ServerConfig{OAuth: config.OAuthConfig{
			RequiredScopes: []string{"admin"},
		}}}}
		_, err := s.validateOAuthClaims(&OAuthClaims{Scopes: []string{"read"}})
		require.ErrorIs(t, err, ErrOAuthInsufficientScopes)
	})

	t.Run("valid_claims", func(t *testing.T) {
		t.Parallel()
		s := &ClickHouseJWEServer{Config: config.Config{Server: config.ServerConfig{OAuth: config.OAuthConfig{
			Issuer:         "https://issuer.example.com",
			Audience:       "my-aud",
			RequiredScopes: []string{"read"},
		}}}}
		claims, err := s.validateOAuthClaims(&OAuthClaims{
			Issuer:    "https://issuer.example.com",
			Audience:  []string{"my-aud"},
			ExpiresAt: time.Now().Unix() + 300,
			Scopes:    []string{"read", "write"},
		})
		require.NoError(t, err)
		require.Equal(t, "https://issuer.example.com", claims.Issuer)
	})

	t.Run("gating_mode_uses_public_auth_server_url_as_issuer", func(t *testing.T) {
		t.Parallel()
		s := &ClickHouseJWEServer{Config: config.Config{Server: config.ServerConfig{OAuth: config.OAuthConfig{
			Mode:                "gating",
			Issuer:              "https://original-issuer.com",
			PublicAuthServerURL: "https://public-auth.com",
		}}}}
		_, err := s.validateOAuthClaims(&OAuthClaims{Issuer: "https://public-auth.com"})
		require.NoError(t, err)
	})
}

func TestParseAndVerifySelfIssuedOAuthToken(t *testing.T) {
	t.Parallel()

	t.Run("missing_secret", func(t *testing.T) {
		t.Parallel()
		s := &ClickHouseJWEServer{Config: config.Config{Server: config.ServerConfig{OAuth: config.OAuthConfig{
			GatingSecretKey: "",
		}}}}
		_, err := s.parseAndVerifySelfIssuedOAuthToken("some.jwt.token")
		require.Error(t, err)
		require.Contains(t, err.Error(), "gating_secret_key is required")
	})

	t.Run("invalid_jwt_format", func(t *testing.T) {
		t.Parallel()
		s := &ClickHouseJWEServer{Config: config.Config{Server: config.ServerConfig{OAuth: config.OAuthConfig{
			GatingSecretKey: "my-secret",
		}}}}
		_, err := s.parseAndVerifySelfIssuedOAuthToken("not-a-jwt")
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to parse self-issued JWT")
	})
}

func TestHasRequiredScopes(t *testing.T) {
	t.Parallel()
	require.True(t, hasRequiredScopes([]string{"read", "write", "admin"}, []string{"read", "write"}))
	require.False(t, hasRequiredScopes([]string{"read"}, []string{"read", "admin"}))
	require.True(t, hasRequiredScopes([]string{"read"}, []string{}))
	require.True(t, hasRequiredScopes([]string{}, []string{}))
	require.False(t, hasRequiredScopes([]string{}, []string{"read"}))
}
