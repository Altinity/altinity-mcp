package server

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/altinity/altinity-mcp/pkg/clickhouse"
	"github.com/altinity/altinity-mcp/pkg/config"
	embeddedclickhouse "github.com/franchb/embedded-clickhouse"
	"github.com/stretchr/testify/require"
)

// setupEmbeddedClickHouse boots a stock ClickHouse 26.1 binary as a host
// subprocess and returns a ClickHouseConfig pointing at it.
//
// This is the no-container fixture used by gating-mode OAuth tests, where the
// MCP server validates the upstream identity itself and connects to CH with
// static credentials. No Antalya-specific config (no token_processors, no
// jwt_validators) is required — CH only needs to accept a static "default"
// user and run SELECT.
func setupEmbeddedClickHouse(t *testing.T) *config.ClickHouseConfig {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping embedded ClickHouse in short mode")
	}

	ch := embeddedclickhouse.NewServer(
		embeddedclickhouse.DefaultConfig().
			Version(embeddedclickhouse.V26_1).
			StartTimeout(60 * time.Second),
	)
	require.NoError(t, ch.Start())
	t.Cleanup(func() { _ = ch.Stop() })

	host, port := splitHostPort(t, ch.HTTPAddr())
	chConfig := &config.ClickHouseConfig{
		Host:     host,
		Port:     port,
		Database: "default",
		Username: "default",
		Protocol: config.HTTPProtocol,
	}

	// Seed the table the test relies on.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client, err := clickhouse.NewClient(ctx, *chConfig)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	_, err = client.ExecuteQuery(ctx, `CREATE TABLE IF NOT EXISTS default.test (
		id UInt64,
		name String,
		created_at DateTime
	) ENGINE = MergeTree() ORDER BY id`)
	require.NoError(t, err)
	_, err = client.ExecuteQuery(ctx, `INSERT INTO default.test VALUES (1, 'test1', now()), (2, 'test2', now())`)
	require.NoError(t, err)

	return chConfig
}

func splitHostPort(t *testing.T, addr string) (string, int) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr)
	require.NoError(t, err)
	port, err := strconv.Atoi(portStr)
	require.NoError(t, err)
	return host, port
}

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
