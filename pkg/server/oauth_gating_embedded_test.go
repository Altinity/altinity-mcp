package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/altinity/altinity-mcp/pkg/config"
	"github.com/stretchr/testify/require"
)

// TestOAuthGatingViaOpenAPI_Embedded mirrors the
// TestOpenAPIHandlers/combined_auth_oauth_only_via_openapi subtest in
// server_test.go but uses embedded-clickhouse instead of testcontainers.
//
// Gating mode validates the bearer locally (HS256 over the gating secret) and
// connects to CH with static credentials, so this test exercises the full MCP
// OAuth path without any Antalya-specific CH-side config.
func TestOAuthGatingViaOpenAPI_Embedded(t *testing.T) {
	t.Parallel()

	chConfig := setupEmbeddedClickHouse(t)

	const gatingSecret = "test-gating-secret-32-byte-key!!"
	srv := NewClickHouseMCPServer(config.Config{
		ClickHouse: *chConfig,
		Server: config.ServerConfig{
			JWE: config.JWEConfig{
				Enabled:      true,
				JWESecretKey: "this-is-a-32-byte-secret-key!!",
				JWTSecretKey: "jwt-secret",
			},
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

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	require.True(t, strings.Contains(rr.Body.String(), `"data"`) || strings.Contains(rr.Body.String(), `"rows"`),
		"response missing data/rows: %s", rr.Body.String())
}
