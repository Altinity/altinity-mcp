package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/altinity/altinity-mcp/pkg/config"
	"github.com/altinity/altinity-mcp/pkg/jwe_auth"
	"github.com/stretchr/testify/require"
)

// TestJWEAuthentication tests JWE authentication flow
func TestJWEAuthentication(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	chConfig := setupClickHouseContainer(t)

	jweSecretKey := "this-is-a-32-byte-secret-key!!"
	jwtSecretKey := "test-jwt-secret-key-123"

	t.Run("valid_jwe_token", func(t *testing.T) {
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

		token := generateJWEToken(t, claims, []byte(jweSecretKey), []byte(jwtSecretKey))

		srv := NewClickHouseMCPServer(config.Config{
			ClickHouse: *chConfig,
			Server: config.ServerConfig{
				JWE: config.JWEConfig{
					Enabled:      true,
					JWESecretKey: jweSecretKey,
					JWTSecretKey: jwtSecretKey,
				},
			},
		}, "test")

		ctx = context.WithValue(ctx, CHJWEServerKey, srv)
		ctx = context.WithValue(ctx, JWETokenKey, token)

		client, err := srv.GetClickHouseClient(ctx, token)
		require.NoError(t, err)
		require.NotNil(t, client)
		require.NoError(t, client.Close())
	})

	t.Run("missing_token_when_jwe_enabled", func(t *testing.T) {
		t.Parallel()
		srv := NewClickHouseMCPServer(config.Config{
			ClickHouse: *chConfig,
			Server: config.ServerConfig{
				JWE: config.JWEConfig{
					Enabled:      true,
					JWESecretKey: jweSecretKey,
					JWTSecretKey: jwtSecretKey,
				},
			},
		}, "test")

		_, err := srv.GetClickHouseClient(ctx, "")
		require.Error(t, err)
		require.ErrorIs(t, err, jwe_auth.ErrMissingToken)
	})

	t.Run("invalid_token", func(t *testing.T) {
		t.Parallel()
		srv := NewClickHouseMCPServer(config.Config{
			ClickHouse: *chConfig,
			Server: config.ServerConfig{
				JWE: config.JWEConfig{
					Enabled:      true,
					JWESecretKey: jweSecretKey,
					JWTSecretKey: jwtSecretKey,
				},
			},
		}, "test")

		_, err := srv.GetClickHouseClient(ctx, "invalid-token")
		require.Error(t, err)
	})
}

// TestExtractTokenFromRequest tests token extraction from HTTP requests
func TestExtractTokenFromRequest(t *testing.T) {
	t.Parallel()
	srv := &ClickHouseJWEServer{}

	t.Run("bearer_token", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer test-token")

		token := srv.ExtractTokenFromRequest(req)
		require.Equal(t, "test-token", token)
	})

	t.Run("basic_token", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Basic test-token")

		token := srv.ExtractTokenFromRequest(req)
		require.Equal(t, "test-token", token)
	})

	t.Run("x_altinity_mcp_key_header", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("x-altinity-mcp-key", "header-token")

		token := srv.ExtractTokenFromRequest(req)
		require.Equal(t, "header-token", token)
	})

	t.Run("from_url_path", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/my-token/openapi", nil)

		token := srv.ExtractTokenFromRequest(req)
		require.Equal(t, "my-token", token)
	})

	t.Run("no_token", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/", nil)

		token := srv.ExtractTokenFromRequest(req)
		require.Empty(t, token)
	})
}

// TestExtractTokenFromCtx tests token extraction from context
func TestExtractTokenFromCtx(t *testing.T) {
	t.Parallel()
	srv := &ClickHouseJWEServer{}

	t.Run("with_token", func(t *testing.T) {
		t.Parallel()
		ctx := context.WithValue(context.Background(), JWETokenKey, "test-token")
		token := srv.ExtractTokenFromCtx(ctx)
		require.Equal(t, "test-token", token)
	})

	t.Run("no_token", func(t *testing.T) {
		t.Parallel()
		token := srv.ExtractTokenFromCtx(context.Background())
		require.Empty(t, token)
	})

	t.Run("wrong_type", func(t *testing.T) {
		t.Parallel()
		ctx := context.WithValue(context.Background(), JWETokenKey, 123)
		token := srv.ExtractTokenFromCtx(ctx)
		require.Empty(t, token)
	})
}

// TestGetClickHouseJWEServerFromContext tests context extraction
func TestGetClickHouseJWEServerFromContext(t *testing.T) {
	t.Parallel()
	t.Run("no_server", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		srv := GetClickHouseJWEServerFromContext(ctx)
		require.Nil(t, srv)
	})

	t.Run("with_server", func(t *testing.T) {
		t.Parallel()
		expectedServer := &ClickHouseJWEServer{}
		ctx := context.WithValue(context.Background(), CHJWEServerKey, expectedServer)
		srv := GetClickHouseJWEServerFromContext(ctx)
		require.Equal(t, expectedServer, srv)
	})

	t.Run("wrong_type", func(t *testing.T) {
		t.Parallel()
		ctx := context.WithValue(context.Background(), CHJWEServerKey, "not-a-server")
		srv := GetClickHouseJWEServerFromContext(ctx)
		require.Nil(t, srv)
	})
}

// TestValidateJWEToken_InvalidToken tests token validation with invalid token
func TestValidateJWEToken_InvalidToken(t *testing.T) {
	t.Parallel()
	srv := &ClickHouseJWEServer{
		Config: config.Config{
			Server: config.ServerConfig{
				JWE: config.JWEConfig{
					Enabled:      true,
					JWESecretKey: "this-is-a-32-byte-secret-key!!",
					JWTSecretKey: "test-jwt-key",
				},
			},
		},
	}

	err := srv.ValidateJWEToken("invalid-token")
	require.Error(t, err)
}

func TestGetClickHouseJWEServerFromContext_WrongType(t *testing.T) {
	t.Parallel()
	ctx := context.WithValue(context.Background(), CHJWEServerKey, "not-a-server")
	require.Nil(t, GetClickHouseJWEServerFromContext(ctx))
}

func TestExtractTokenFromRequest_AllSources(t *testing.T) {
	t.Parallel()
	s := &ClickHouseJWEServer{}

	t.Run("basic_auth", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Basic abc123")
		require.Equal(t, "abc123", s.ExtractTokenFromRequest(req))
	})
	t.Run("custom_header", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("x-altinity-mcp-key", "custom-key")
		require.Equal(t, "custom-key", s.ExtractTokenFromRequest(req))
	})
	t.Run("openapi_path", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/my-token/openapi/execute_query", nil)
		require.Equal(t, "my-token", s.ExtractTokenFromRequest(req))
	})
	t.Run("no_token", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		require.Equal(t, "", s.ExtractTokenFromRequest(req))
	})
}

func TestValidateJWEToken(t *testing.T) {
	t.Parallel()
	jweKey := "test-jwe-key-12345"
	jwtKey := "test-jwt-key-12345"

	s := &ClickHouseJWEServer{Config: config.Config{Server: config.ServerConfig{JWE: config.JWEConfig{
		Enabled:      true,
		JWESecretKey: jweKey,
		JWTSecretKey: jwtKey,
	}}}}

	t.Run("valid_token", func(t *testing.T) {
		t.Parallel()
		token := generateJWEToken(t, map[string]interface{}{
			"host": "localhost",
			"exp":  float64(time.Now().Add(time.Hour).Unix()),
		}, []byte(jweKey), []byte(jwtKey))
		require.NoError(t, s.ValidateJWEToken(token))
	})

	t.Run("invalid_token", func(t *testing.T) {
		t.Parallel()
		require.Error(t, s.ValidateJWEToken("invalid-token"))
	})

	t.Run("expired_token", func(t *testing.T) {
		t.Parallel()
		token := generateJWEToken(t, map[string]interface{}{
			"host": "localhost",
			"exp":  float64(time.Now().Add(-time.Hour).Unix()),
		}, []byte(jweKey), []byte(jwtKey))
		require.Error(t, s.ValidateJWEToken(token))
	})

	t.Run("jwe_disabled", func(t *testing.T) {
		t.Parallel()
		s2 := &ClickHouseJWEServer{Config: config.Config{Server: config.ServerConfig{JWE: config.JWEConfig{Enabled: false}}}}
		require.NoError(t, s2.ValidateJWEToken("anything"))
	})
}

func TestJWETokenHasCredentials(t *testing.T) {
	t.Parallel()
	jweKey := "test-jwe-secret-key-for-test!!"
	jwtKey := "test-jwt-secret-key-for-test!!"

	srv := NewClickHouseMCPServer(config.Config{
		Server: config.ServerConfig{
			JWE: config.JWEConfig{
				Enabled:      true,
				JWESecretKey: jweKey,
				JWTSecretKey: jwtKey,
			},
		},
	}, "test")

	t.Run("has_credentials", func(t *testing.T) {
		t.Parallel()
		token := generateJWEToken(t, map[string]interface{}{
			"username": "admin",
			"password": "secret",
		}, []byte(jweKey), []byte(jwtKey))
		require.True(t, srv.JWETokenHasCredentials(token))
	})

	t.Run("no_credentials", func(t *testing.T) {
		t.Parallel()
		token := generateJWEToken(t, map[string]interface{}{
			"host": "localhost",
		}, []byte(jweKey), []byte(jwtKey))
		require.False(t, srv.JWETokenHasCredentials(token))
	})

	t.Run("invalid_token", func(t *testing.T) {
		t.Parallel()
		require.False(t, srv.JWETokenHasCredentials("not-a-valid-token"))
	})

	t.Run("jwe_disabled", func(t *testing.T) {
		t.Parallel()
		srvDisabled := NewClickHouseMCPServer(config.Config{
			Server: config.ServerConfig{
				JWE: config.JWEConfig{Enabled: false},
			},
		}, "test")
		require.False(t, srvDisabled.JWETokenHasCredentials("any-token"))
	})
}

func TestParseJWEClaims(t *testing.T) {
	t.Parallel()

	t.Run("jwe_disabled", func(t *testing.T) {
		t.Parallel()
		srv := NewClickHouseMCPServer(config.Config{
			Server: config.ServerConfig{JWE: config.JWEConfig{Enabled: false}},
		}, "test")
		claims, err := srv.ParseJWEClaims("some-token")
		require.NoError(t, err)
		require.Nil(t, claims)
	})

	t.Run("empty_token", func(t *testing.T) {
		t.Parallel()
		srv := NewClickHouseMCPServer(config.Config{
			Server: config.ServerConfig{JWE: config.JWEConfig{
				Enabled:      true,
				JWESecretKey: "test-key",
			}},
		}, "test")
		_, err := srv.ParseJWEClaims("")
		require.Error(t, err)
	})
}
