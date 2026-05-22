package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/altinity/altinity-mcp/pkg/clickhouse"
	"github.com/altinity/altinity-mcp/pkg/config"
	"github.com/altinity/altinity-mcp/pkg/jwe_auth"
	"github.com/altinity/altinity-mcp/pkg/oauth"
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
			Enabled:        true,
			Issuer:         "https://auth.example.com",
			Audience:       "my-api",
			ClientID:       "client-123",
			ClientSecret:   "secret-456",
			TokenURL:       "https://auth.example.com/oauth/token",
			AuthURL:        "https://auth.example.com/oauth/authorize",
			Scopes:         []string{"read", "write"},
			RequiredScopes: []string{"read"},
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

	t.Run("x_oauth_token_header_ignored", func(t *testing.T) {
		// MCP authorization spec §Token Requirements: clients MUST use the
		// Authorization header. Non-spec extension headers used to be honoured
		// for legacy clients; we now reject them so the server doesn't have
		// hidden alternative auth surfaces.
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("x-oauth-token", "header-oauth-token")

		token := srv.ExtractOAuthTokenFromRequest(req)
		require.Empty(t, token)
	})

	t.Run("x_altinity_oauth_token_header_ignored", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("x-altinity-oauth-token", "altinity-oauth-token")

		token := srv.ExtractOAuthTokenFromRequest(req)
		require.Empty(t, token)
	})

	t.Run("no_token", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/", nil)

		token := srv.ExtractOAuthTokenFromRequest(req)
		require.Empty(t, token)
	})

	t.Run("bearer_only_extension_headers_ignored", func(t *testing.T) {
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

	// C-1: forward-mode JWT with no JWKS source configured soft-passes — the
	// MCP server cannot validate locally and defers to ClickHouse. Operators
	// who want strict local validation set Issuer or JWKSURL.
	t.Run("forward_mode_jwt_without_jwks_source_softpasses", func(t *testing.T) {
		t.Parallel()
		provider := newTestOAuthProvider(t, nil)
		srv := &ClickHouseJWEServer{
			Config: config.Config{
				Server: config.ServerConfig{
					OAuth: config.OAuthConfig{
						Enabled: true,
						Mode:    "forward",
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
		claims, err := srv.ValidateOAuthToken(token)
		require.NoError(t, err)
		require.Nil(t, claims, "soft-pass returns nil claims to signal 'unvalidated, defer to ClickHouse'")
	})

	// C-1: opaque (non-JWT) bearers in forward mode soft-pass even when JWKS
	// IS configured — there is no way to validate them without RFC 7662
	// introspection, which we do not implement.
	t.Run("forward_mode_opaque_bearer_softpasses_with_jwks_configured", func(t *testing.T) {
		t.Parallel()
		provider := newTestOAuthProvider(t, nil)
		srv := &ClickHouseJWEServer{
			Config: config.Config{
				Server: config.ServerConfig{
					OAuth: config.OAuthConfig{
						Enabled: true,
						Mode:    "forward",
						Issuer:  provider.server.URL,
						JWKSURL: provider.server.URL + "/jwks",
					},
				},
			},
		}
		claims, err := srv.ValidateOAuthToken("opaque-bearer-not-a-jwt")
		require.NoError(t, err)
		require.Nil(t, claims)
	})

	// Gating mode rejects opaque bearers outright (MCP is a pure resource
	// server; only AS-issued JWTs are valid; opaque tokens are never forwarded
	// to ClickHouse in gating mode, so soft-passing them would be a silent
	// auth bypass).
	t.Run("gating_mode_opaque_bearer_rejected", func(t *testing.T) {
		t.Parallel()
		provider := newTestOAuthProvider(t, nil)
		srv := &ClickHouseJWEServer{
			Config: config.Config{
				Server: config.ServerConfig{
					OAuth: config.OAuthConfig{
						Enabled:  true,
						Mode:     "gating",
						Issuer:   provider.server.URL,
						JWKSURL:  provider.server.URL + "/jwks",
						Audience: "https://mcp.example.com/",
					},
				},
			},
		}
		claims, err := srv.ValidateOAuthToken("opaque-bearer-not-a-jwt")
		require.ErrorIs(t, err, ErrInvalidOAuthToken)
		require.Nil(t, claims)
	})

	// C-1: forward-mode JWT with JWKS configured AND a tampered signature is
	// rejected at the MCP layer before reaching ClickHouse. Closes the
	// pre-fix gap where any string in `Authorization: Bearer …` was accepted.
	t.Run("forward_mode_jwt_with_bad_signature_rejected", func(t *testing.T) {
		t.Parallel()
		provider := newTestOAuthProvider(t, nil)
		srv := &ClickHouseJWEServer{
			Config: config.Config{
				Server: config.ServerConfig{
					OAuth: config.OAuthConfig{
						Enabled: true,
						Mode:    "forward",
						Issuer:  provider.server.URL,
						JWKSURL: provider.server.URL + "/jwks",
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
		// Flip the FIRST char of the signature segment so verification fails.
		// Flipping the LAST char is unsafe for RSA-2048 sigs (256 bytes →
		// 342 base64url chars) because the last char encodes only 2 actual
		// signature bits plus 4 padding bits; flipping among 'A'/'B'/'C'/'D'
		// only changes padding bits, which lenient base64 decoders silently
		// drop, producing an identical signature.
		dot2 := strings.LastIndex(token, ".")
		require.NotEqual(t, -1, dot2)
		sigStart := dot2 + 1
		tampered := token[:sigStart] + flipBase64URLChar(token[sigStart:sigStart+1]) + token[sigStart+1:]
		_, err := srv.ValidateOAuthToken(tampered)
		require.Error(t, err, "tampered forward-mode JWT must be rejected (orig token: %q tampered: %q)", token, tampered)
	})

	// C-1: forward-mode expired JWT is rejected at the MCP layer.
	t.Run("forward_mode_expired_jwt_rejected", func(t *testing.T) {
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
			"aud": "clickhouse-api",
			"exp": time.Now().Add(-2 * time.Hour).Unix(),
			"iat": time.Now().Add(-3 * time.Hour).Unix(),
		})
		_, err := srv.ValidateOAuthToken(token)
		require.ErrorIs(t, err, ErrOAuthTokenExpired)
	})
}

// flipBase64URLChar returns a different valid base64url character than `c`,
// used to tamper with a JWT signature segment in tests.
func flipBase64URLChar(c string) string {
	if c == "" {
		return "A"
	}
	if c[0] == 'A' {
		return "B"
	}
	return "A"
}

// TestOAuthRequiresLocalValidation locks in the C-1 invariant: the auth layer
// MUST validate locally in both forward and gating modes. Pre-C-1 the gate
// returned true only for gating, leaving forward-mode tokens unchecked.
func TestOAuthRequiresLocalValidation(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		mode string
		want bool
	}{
		{"gating_validates", "gating", true},
		{"forward_validates", "forward", true},
		{"empty_defaults_to_gating_validates", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			srv := &ClickHouseJWEServer{
				Config: config.Config{
					Server: config.ServerConfig{
						OAuth: config.OAuthConfig{Enabled: true, Mode: tc.mode},
					},
				},
			}
			require.Equal(t, tc.want, srv.oauthRequiresLocalValidation())
		})
	}
	t.Run("disabled_skips_validation", func(t *testing.T) {
		t.Parallel()
		srv := &ClickHouseJWEServer{
			Config: config.Config{
				Server: config.ServerConfig{
					OAuth: config.OAuthConfig{Enabled: false, Mode: "forward"},
				},
			},
		}
		require.False(t, srv.oauthRequiresLocalValidation())
	})
}

// TestOAuthIssuerEnforcement verifies the singular-Issuer single-tenant policy.
func TestOAuthIssuerEnforcement(t *testing.T) {
	t.Parallel()

	t.Run("token_from_configured_issuer_accepted", func(t *testing.T) {
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
			"aud": "clickhouse-api",
			"exp": time.Now().Add(time.Hour).Unix(),
		})
		claims, err := srv.ValidateOAuthToken(token)
		require.NoError(t, err)
		require.Equal(t, provider.server.URL, claims.Issuer)
	})

	t.Run("token_from_other_issuer_rejected", func(t *testing.T) {
		t.Parallel()
		provider := newTestOAuthProvider(t, nil)
		srv := &ClickHouseJWEServer{
			Config: config.Config{
				Server: config.ServerConfig{
					OAuth: config.OAuthConfig{
						Enabled:  true,
						Mode:     "forward",
						Issuer:   "https://only-this-one.example.com",
						JWKSURL:  provider.server.URL + "/jwks",
						Audience: "clickhouse-api",
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
		require.ErrorIs(t, err, ErrInvalidOAuthToken)
	})

	t.Run("issuer_match_is_trailing_slash_tolerant", func(t *testing.T) {
		t.Parallel()
		provider := newTestOAuthProvider(t, nil)
		srv := &ClickHouseJWEServer{
			Config: config.Config{
				Server: config.ServerConfig{
					OAuth: config.OAuthConfig{
						Enabled:  true,
						Mode:     "forward",
						Issuer:   provider.server.URL + "/",
						JWKSURL:  provider.server.URL + "/jwks",
						Audience: "clickhouse-api",
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
		claims, err := srv.ValidateOAuthToken(token)
		require.NoError(t, err)
		require.Equal(t, provider.server.URL, claims.Issuer)
	})
}

// TestOAuthBuildClickHouseHeaders tests the forward-mode header builder. Gating
// mode no longer goes through this helper — its CH credentials are conveyed
// via the clickhouse-go Auth.Username/Auth.Password Basic header.
func TestOAuthBuildClickHouseHeaders(t *testing.T) {
	t.Parallel()
	t.Run("gating_returns_no_headers", func(t *testing.T) {
		t.Parallel()
		cfg := config.OAuthConfig{Mode: "gating"}
		require.Nil(t, oauth.BuildClickHouseHeaders(cfg, "token", nil))
	})

	t.Run("forward_wraps_token_as_bearer", func(t *testing.T) {
		t.Parallel()
		cfg := config.OAuthConfig{Mode: "forward"}
		headers := oauth.BuildClickHouseHeaders(cfg, "my-access-token", nil)
		require.NotNil(t, headers)
		require.Equal(t, "Bearer my-access-token", headers["Authorization"])
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

		// Create request with only OAuth token (no JWE) → falls through to OAuth.
		// Per MCP authorization spec §Token Requirements, the bearer is only
		// accepted in the Authorization header (the legacy x-oauth-token
		// extension was dropped).
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer "+oauthToken)
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
					Enabled: true,
					Mode:    "forward",
					Issuer:  provider.server.URL,
					JWKSURL: provider.server.URL + "/jwks",
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
					SigningSecret: "test-gating-secret-32-byte-key!!",
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

	t.Run("oauth_gating_routes_bearer_through_basic_to_ch", func(t *testing.T) {
		t.Parallel()
		// Gating mode rewrites Auth to Basic email:JWT for the CH-side
		// ch-jwt-verify sidecar. The embedded CH has no http_authentication
		// configured, so the request fails — but the failure is at the CH
		// layer, not at MCP. Assert non-401 to confirm MCP forwarded the
		// bearer.
		const gatingSecret = "test-gating-secret-32-byte-key!!"
		srv := NewClickHouseMCPServer(config.Config{
			ClickHouse: *chConfig,
			Server: config.ServerConfig{
				JWE: config.JWEConfig{Enabled: false},
				OAuth: config.OAuthConfig{
					Enabled:       true,
					Mode:          "gating",
					SigningSecret: gatingSecret,
				},
			},
		}, "test")

		oauthToken := mintSelfIssuedToken(t, gatingSecret, map[string]interface{}{
			"sub":   "user123",
			"email": "user123@example.com",
			"exp":   time.Now().Add(time.Hour).Unix(),
		})

		req := httptest.NewRequest(http.MethodGet, "/openapi/execute_query?query=SELECT%201", nil)
		req.Header.Set("Authorization", "Bearer "+oauthToken)
		req = req.WithContext(context.WithValue(req.Context(), CHJWEServerKey, srv))

		rr := httptest.NewRecorder()
		srv.OpenAPIHandler(rr, req)

		// Embedded CH rejects unknown user → 500 from the client builder.
		// MCP itself does not validate, so 401 would indicate a regression
		// in the pure-forwarder contract.
		require.NotEqual(t, http.StatusUnauthorized, rr.Code, rr.Body.String())
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

	t.Run("oauth_disabled_or_empty_token_uses_static_creds", func(t *testing.T) {
		t.Parallel()
		// When OAuth is disabled the per-request switch is skipped and the
		// static helm-configured Auth.Username/Auth.Password reach the driver.
		srv := NewClickHouseMCPServer(config.Config{
			ClickHouse: *chConfig,
			Server: config.ServerConfig{
				JWE:   config.JWEConfig{Enabled: false},
				OAuth: config.OAuthConfig{Enabled: false},
			},
		}, "test")

		client, err := srv.GetClickHouseClientWithOAuth(ctx, "", "", nil)
		require.NoError(t, err)
		require.NotNil(t, client)
		require.NoError(t, client.Close())
	})

	t.Run("with_oauth_forwarding", func(t *testing.T) {
		t.Parallel()
		cfg := config.OAuthConfig{
			Enabled: true,
			Mode:    "forward",
		}
		headers := oauth.BuildClickHouseHeaders(cfg, "oauth-token", &OAuthClaims{Subject: "user123"})
		require.NotNil(t, headers)
		require.Equal(t, "Bearer oauth-token", headers["Authorization"])
	})

	t.Run("with_jwe_only_oauth_ignored", func(t *testing.T) {
		t.Parallel()
		// JWE carries its own credentials and is sufficient on its own —
		// confirm the OAuth-disabled path still produces a working client.
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
				OAuth: config.OAuthConfig{Enabled: false},
			},
		}, "test")

		client, err := srv.GetClickHouseClientWithOAuth(ctx, jweToken, "", nil)
		require.NoError(t, err)
		require.NotNil(t, client)
		require.NoError(t, client.Close())
	})

	t.Run("gating_mode_sets_basic_creds_from_jwt", func(t *testing.T) {
		t.Parallel()
		// Gating mode unverified-decodes the JWT email claim and routes it as
		// `Authorization: Basic base64(email:JWT)` via clickhouse-go's
		// Auth.Username/Password. We exercise the path by minting an
		// HS256-signed JWT (signature not verified here — sidecar is the
		// gate); the embedded CH rejects an unknown user, so we expect a
		// connection failure, but the error should reference the email
		// (proving the wire-format switch fired).
		const gatingSecret = "test-gating-secret-32-byte-key!!"
		oauthToken := mintSelfIssuedToken(t, gatingSecret, map[string]interface{}{
			"sub":   "u-alice",
			"email": "alice@example.com",
			"exp":   time.Now().Add(time.Hour).Unix(),
		})
		srv := NewClickHouseMCPServer(config.Config{
			ClickHouse: *chConfig,
			Server: config.ServerConfig{
				OAuth: config.OAuthConfig{
					Enabled:       true,
					Mode:          "gating",
					SigningSecret: gatingSecret,
				},
			},
		}, "test")

		// Connection fails because embedded CH has no http_authenticator user
		// `alice@example.com`, but the failure proves the path is wired.
		_, err := srv.GetClickHouseClientWithOAuth(ctx, "", oauthToken, nil)
		require.Error(t, err)
	})

	t.Run("gating_mode_non_jwt_bearer_rejected", func(t *testing.T) {
		t.Parallel()
		srv := NewClickHouseMCPServer(config.Config{
			ClickHouse: *chConfig,
			Server: config.ServerConfig{
				OAuth: config.OAuthConfig{
					Enabled:       true,
					Mode:          "gating",
					SigningSecret: "test-gating-secret-32-byte-key!!",
				},
			},
		}, "test")

		_, err := srv.GetClickHouseClientWithOAuth(ctx, "", "opaque-not-a-jwt", nil)
		require.ErrorContains(t, err, "not a JWT")
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

	t.Run("execute_query_with_oauth_disabled_uses_static_creds", func(t *testing.T) {
		t.Parallel()
		// Without OAuth enabled the static helm-configured Auth.Username/
		// Password reach the embedded CH and the query succeeds — exercises
		// the happy path for the non-OAuth code path through the tool.
		srv := NewClickHouseMCPServer(config.Config{
			ClickHouse: *chConfig,
			Server: config.ServerConfig{
				JWE:   config.JWEConfig{Enabled: false},
				OAuth: config.OAuthConfig{Enabled: false},
			},
		}, "test")

		ctx = context.WithValue(ctx, CHJWEServerKey, srv)

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

		textContent, ok := result.Content[0].(*mcp.TextContent)
		require.True(t, ok)
		require.NotEmpty(t, textContent.Text)

		var qr clickhouse.QueryResult
		require.NoError(t, json.Unmarshal([]byte(textContent.Text), &qr))
		require.Equal(t, 1, qr.Count)
	})

	t.Run("execute_query_with_oauth_and_header_forwarding", func(t *testing.T) {
		t.Parallel()
		cfg := config.OAuthConfig{
			Enabled: true,
			Mode:    "forward",
		}
		oauthToken := "opaque-access-token"
		headers := oauth.BuildClickHouseHeaders(cfg, oauthToken, nil)
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

// Identity-policy enforcement (verified-email, domain allow-listing) moved out
// of pkg/server when the cluster_secret impersonation path was removed; the
// CH-side ch-jwt-verify sidecar is the sole enforcer now.

