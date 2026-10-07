package server

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	chproto "github.com/ClickHouse/ch-go/proto"
	chdriver "github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/column"
	"github.com/ClickHouse/clickhouse-go/v2/lib/proto"
	"github.com/altinity/altinity-mcp/pkg/config"
	"github.com/stretchr/testify/require"
)

func isolationBaseConfig() config.ClickHouseConfig {
	return config.ClickHouseConfig{
		HttpHeaders:   map[string]string{"X-Static": "1"},
		ExtraSettings: map[string]string{"custom_scope": "base"},
		Roles:         []string{"reader"},
	}
}

func TestOAuthApplyBearerIsolation(t *testing.T) {
	t.Parallel()
	base := isolationBaseConfig()
	first := oauthApplyBearer(base, "A", config.OAuthConfig{Enabled: true})
	second := oauthApplyBearer(base, "B", config.OAuthConfig{Enabled: true})
	require.Equal(t, map[string]string{"X-Static": "1"}, base.HttpHeaders)
	require.Equal(t, "Bearer A", first.HttpHeaders["Authorization"])
	require.Equal(t, "Bearer B", second.HttpHeaders["Authorization"])
	first.HttpHeaders["X-Static"] = "changed"
	first.ExtraSettings["custom_scope"] = "changed"
	first.Roles[0] = "changed"
	require.Equal(t, "1", second.HttpHeaders["X-Static"])
	require.Equal(t, base.ExtraSettings, second.ExtraSettings)
	require.Equal(t, base.Roles, second.Roles)

	withoutHeaders := config.ClickHouseConfig{}
	applied := oauthApplyBearer(withoutHeaders, "C", config.OAuthConfig{Enabled: true})
	require.Equal(t, "Bearer C", applied.HttpHeaders["Authorization"])
	require.Nil(t, withoutHeaders.HttpHeaders)
}

func TestOAuthApplyBearerConcurrentIsolation(t *testing.T) {
	t.Parallel()
	base := isolationBaseConfig()
	const callers = 100
	results := make([]config.ClickHouseConfig, callers)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range callers {
		wg.Go(func() {
			<-start
			results[i] = oauthApplyBearer(base, fmt.Sprintf("caller-%d", i), config.OAuthConfig{Enabled: true})
			results[i].HttpHeaders["X-Static"] = fmt.Sprint(i)
			results[i].ExtraSettings["custom_scope"] = fmt.Sprint(i)
			results[i].Roles[0] = fmt.Sprint(i)
		})
	}
	close(start)
	wg.Wait()
	for i, result := range results {
		require.Equal(t, fmt.Sprintf("Bearer caller-%d", i), result.HttpHeaders["Authorization"])
		require.Equal(t, fmt.Sprint(i), result.HttpHeaders["X-Static"])
		require.Equal(t, fmt.Sprint(i), result.ExtraSettings["custom_scope"])
		require.Equal(t, []string{fmt.Sprint(i)}, result.Roles)
	}
	require.Equal(t, isolationBaseConfig(), base)
}

func TestRequestConfigIsolation(t *testing.T) {
	t.Parallel()
	base := isolationBaseConfig()
	srv := &ClickHouseJWEServer{}
	tests := map[string]func() config.ClickHouseConfig{
		"jwe_claims": func() config.ClickHouseConfig {
			cfg, err := srv.buildConfigFromClaimsWithBase(base, map[string]interface{}{"host": "jwe-host", "username": "jwe-user"})
			require.NoError(t, err)
			return cfg
		},
		"basic": func() config.ClickHouseConfig { return oauthApplyBasic(base, "alice", "fake-jwt") },
		"settings": func() config.ClickHouseConfig {
			return mergeExtraSettings(base, map[string]string{"custom_other": "request"})
		},
		"context_fallback": func() config.ClickHouseConfig { return CHConfigFromContext(context.Background(), base) },
	}
	for name, derive := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := derive()
			if name == "jwe_claims" {
				require.Nil(t, cfg.HttpHeaders)
				require.Nil(t, cfg.Roles)
			} else {
				cfg.HttpHeaders["X-Static"] = "changed"
				cfg.Roles[0] = "changed"
			}
			cfg.ExtraSettings["custom_scope"] = "changed"
			require.Equal(t, isolationBaseConfig(), base)
		})
	}

	ctx := WithRequestCHConfig(context.Background(), base)
	base.HttpHeaders["X-Static"] = "caller-changed"
	base.ExtraSettings["custom_scope"] = "caller-changed"
	base.Roles[0] = "caller-changed"
	first := CHConfigFromContext(ctx, config.ClickHouseConfig{})
	require.Equal(t, isolationBaseConfig(), first)
	first.HttpHeaders["X-Static"] = "reader-changed"
	first.ExtraSettings["custom_scope"] = "reader-changed"
	first.Roles[0] = "reader-changed"
	require.Equal(t, isolationBaseConfig(), CHConfigFromContext(ctx, config.ClickHouseConfig{}))
}

func TestMulticlusterRouterConfigIsolation(t *testing.T) {
	t.Parallel()
	base := isolationBaseConfig()
	base.Host = "chi-{cluster}.example"
	router, err := NewMulticlusterRouter(config.MulticlusterConfig{Enabled: true, ClusterAllowlist: []string{"a", "b"}}, base)
	require.NoError(t, err)
	first, ok := router.resolveCluster("a")
	require.True(t, ok)
	second, ok := router.resolveCluster("b")
	require.True(t, ok)
	first.HttpHeaders["Authorization"] = "Bearer fake-a"
	first.HttpHeaders["X-Static"] = "changed"
	first.ExtraSettings["custom_scope"] = "changed"
	first.Roles[0] = "changed"
	require.Equal(t, "chi-a.example", first.Host)
	require.Equal(t, "chi-b.example", second.Host)
	require.Equal(t, base.HttpHeaders, second.HttpHeaders)
	require.Equal(t, base.ExtraSettings, second.ExtraSettings)
	require.Equal(t, base.Roles, second.Roles)
	require.NotContains(t, base.HttpHeaders, "Authorization")
	again, ok := router.resolveCluster("a")
	require.True(t, ok)
	require.Equal(t, second.HttpHeaders, again.HttpHeaders)
}

// TestOAuthThenJWEHeaderIsolation exercises authentication, context dispatch,
// client creation (including the OAuth probe), and SQL through the REST handler.
func TestOAuthThenJWEHeaderIsolation(t *testing.T) {
	t.Parallel()
	// Use the driver's Native encoder to serve real hello/ping/query results
	// without requiring a ClickHouse process or mocking client construction.
	encode := func(block *proto.Block) []byte {
		buf := &chproto.Buffer{}
		require.NoError(t, block.Encode(buf, uint64(chdriver.ClientTCPProtocolVersion)))
		return buf.Buf
	}
	hello := proto.NewBlock()
	for _, col := range []struct{ name, typ string }{
		{"displayName()", "String"}, {"version()", "String"}, {"revision()", "UInt32"}, {"timezone()", "String"},
	} {
		require.NoError(t, hello.AddColumn(col.name, column.Type(col.typ)))
	}
	require.NoError(t, hello.Append("fake-clickhouse", "25.8.1", uint32(chdriver.ClientTCPProtocolVersion), "UTC"))
	helloBody := encode(hello)
	result := proto.NewBlock()
	require.NoError(t, result.AddColumn("1", column.Type("UInt8")))
	require.NoError(t, result.Append(uint8(1)))
	resultBody := encode(result)

	headers := make(chan http.Header, 32)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headers <- r.Header.Clone()
		query, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		if strings.Contains(string(query), "displayName()") {
			_, _ = w.Write(helloBody)
		} else {
			_, _ = w.Write(resultBody)
		}
	}))
	defer upstream.Close()
	endpoint, err := url.Parse(upstream.URL)
	require.NoError(t, err)
	host, portText, err := net.SplitHostPort(endpoint.Host)
	require.NoError(t, err)
	port, err := strconv.Atoi(portText)
	require.NoError(t, err)
	base := config.ClickHouseConfig{
		Host: host, Port: port, Database: "default", Protocol: config.HTTPProtocol,
		HttpHeaders: map[string]string{"X-Static": "1"},
	}
	const jweKey = "this-is-a-32-byte-secret-key!!"
	const jwtKey = "fake-jwt-signing-key"
	srv := NewClickHouseMCPServer(config.Config{
		ClickHouse: base,
		Server: config.ServerConfig{
			OAuth: config.OAuthConfig{Enabled: true},
			JWE:   config.JWEConfig{Enabled: true, JWESecretKey: jweKey, JWTSecretKey: jwtKey},
		},
	}, "test")
	request := func(authHeader, jweToken string) {
		req := httptest.NewRequest(http.MethodGet, "/openapi/execute_query?query=SELECT%201", nil)
		req.Header.Set("Authorization", authHeader)
		if jweToken != "" {
			req.Header.Set("x-altinity-mcp-key", jweToken)
		}
		req = req.WithContext(context.WithValue(req.Context(), CHJWEServerKey, srv))
		rr := httptest.NewRecorder()
		srv.OpenAPIHandler(rr, req)
		require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
		require.Contains(t, rr.Body.String(), `"count":1`)
	}
	checkHeaders := func(expectedAuth, expectedStatic string) {
		require.NotEmpty(t, headers, "request must reach fake ClickHouse")
		for len(headers) > 0 {
			h := <-headers
			require.Equal(t, expectedAuth, h.Get("Authorization"))
			require.Equal(t, expectedStatic, h.Get("X-Static"))
		}
	}
	request("Bearer fake-oauth-token", "")
	checkHeaders("Bearer fake-oauth-token", "1")
	// The next caller uses the cached method with its own bearer.
	request("Bearer fake-second-oauth-token", "")
	checkHeaders("Bearer fake-second-oauth-token", "1")
	require.Equal(t, map[string]string{"X-Static": "1"}, srv.Config.ClickHouse.HttpHeaders)
	jweToken := generateJWEToken(t, map[string]interface{}{
		"host": host, "port": port, "database": "default", "protocol": "http",
		"username": "jwe-user", "password": "fake-jwe-password",
		"exp": time.Now().Add(time.Hour).Unix(),
	}, []byte(jweKey), []byte(jwtKey))
	// A complete JWE wins even when an OAuth bearer is also present.
	request("Bearer ignored-oauth-token", jweToken)
	ctx := context.WithValue(context.Background(), JWETokenKey, jweToken)
	ctx = context.WithValue(ctx, OAuthTokenKey, "ignored-context-oauth-token")
	client, err := srv.GetClickHouseClientFromCtx(ctx)
	require.NoError(t, err)
	require.NoError(t, client.Close())
	basic := httptest.NewRequest(http.MethodGet, "/", nil)
	basic.SetBasicAuth("jwe-user", "fake-jwe-password")
	checkHeaders(basic.Header.Get("Authorization"), "")
	// Partial claims cannot redirect OAuth to another endpoint or change its user.
	for _, claims := range []map[string]interface{}{
		{"username": "partial-user", "port": 1},
		{"host": "127.0.0.2", "port": 1, "password": "fake-partial-password"},
		{},
	} {
		claims["exp"] = time.Now().Add(time.Hour).Unix()
		partial := generateJWEToken(t, claims, []byte(jweKey), []byte(jwtKey))
		request("Bearer fallback-oauth-token", partial)
		checkHeaders("Bearer fallback-oauth-token", "1")
		ctx := context.WithValue(context.Background(), JWETokenKey, partial)
		ctx = context.WithValue(ctx, JWEClaimsKey, claims)
		ctx = context.WithValue(ctx, OAuthTokenKey, "context-fallback-oauth-token")
		client, err := srv.GetClickHouseClientFromCtx(ctx)
		require.NoError(t, err)
		require.NoError(t, client.Close())
		checkHeaders("Bearer context-fallback-oauth-token", "1")
	}
	require.Equal(t, map[string]string{"X-Static": "1"}, srv.Config.ClickHouse.HttpHeaders)
}
