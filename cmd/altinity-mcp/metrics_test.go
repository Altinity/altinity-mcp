package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/altinity/altinity-mcp/pkg/config"
	"github.com/altinity/altinity-mcp/pkg/metrics"
	altinitymcp "github.com/altinity/altinity-mcp/pkg/server"
	"github.com/stretchr/testify/require"
)

// metricsTestApp builds an application (without pinging ClickHouse or binding
// a port) whose transport handlers can be exercised through httptest.
func metricsTestApp(t *testing.T, cfg config.Config) *application {
	t.Helper()
	if cfg.Server.Metrics.Enabled {
		metrics.Enable()
	}
	return &application{
		config:    cfg,
		mcpServer: altinitymcp.NewClickHouseMCPServer(cfg, "test-version"),
	}
}

func baseMetricsConfig(transport config.MCPTransport, metricsEnabled bool) config.Config {
	cfg := config.Config{
		ClickHouse: config.ClickHouseConfig{
			Host: "localhost", Port: 8123, Database: "default", Username: "default", Protocol: config.HTTPProtocol,
		},
		Server: config.ServerConfig{
			Transport:  transport,
			Address:    "localhost",
			Port:       0,
			CORSOrigin: "*",
		},
	}
	cfg.Server.Metrics.Enabled = metricsEnabled
	return cfg
}

func get(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
	return rr
}

// TestTransportHandlersExposeMetricsWhenEnabled is the server-level
// regression test for every transport wiring: plain HTTP, JWE HTTP, plain
// SSE, and JWE SSE must all serve /metrics and instrument requests through
// the same finalizeTransportHandler path.
func TestTransportHandlersExposeMetricsWhenEnabled(t *testing.T) {
	cases := []struct {
		name      string
		transport config.MCPTransport
		jwe       bool
	}{
		{"http_plain", config.HTTPTransport, false},
		{"http_jwe", config.HTTPTransport, true},
		{"sse_plain", config.SSETransport, false},
		{"sse_jwe", config.SSETransport, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := baseMetricsConfig(tc.transport, true)
			if tc.jwe {
				cfg.Server.JWE = config.JWEConfig{Enabled: true, JWESecretKey: "jwe-secret", JWTSecretKey: "jwt-secret"}
			}
			app := metricsTestApp(t, cfg)

			var handler http.Handler
			if tc.transport == config.HTTPTransport {
				handler = app.buildHTTPHandler(cfg, app.mcpServer.MCPServer)
			} else {
				handler = app.buildSSEHandler(cfg, app.mcpServer.MCPServer)
			}

			// A liveness probe through the full middleware stack must be
			// counted under its registered route pattern.
			require.Equal(t, http.StatusOK, get(t, handler, "/livez").Code)

			rr := get(t, handler, "/metrics")
			require.Equal(t, http.StatusOK, rr.Code)
			body := rr.Body.String()
			require.Contains(t, body, "altinity_mcp_clickhouse_up")
			require.Contains(t, body, "altinity_mcp_http_requests_total")
			require.Contains(t, body, `method="GET",route="/livez",status="2xx"`)
			// The exposition must never carry a raw token path from the JWE
			// transport -- only registered patterns are allowed as labels.
			require.NotContains(t, body, `route="/some-token`)
		})
	}
}

// TestTransportHandlersDoNotExposeMetricsWhenDisabled proves that
// server.metrics.enabled=false is a true no-op at the routing layer: the
// /metrics path is not registered on any transport, so it falls through to
// whatever the transport's catch-all does (404 for JWE-prefixed routes, 405
// from the MCP handler for the root-mounted transports) and never returns a
// Prometheus exposition.
func TestTransportHandlersDoNotExposeMetricsWhenDisabled(t *testing.T) {
	cases := []struct {
		name      string
		transport config.MCPTransport
		jwe       bool
	}{
		{"http_plain", config.HTTPTransport, false},
		{"http_jwe", config.HTTPTransport, true},
		{"sse_plain", config.SSETransport, false},
		{"sse_jwe", config.SSETransport, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := baseMetricsConfig(tc.transport, false)
			if tc.jwe {
				cfg.Server.JWE = config.JWEConfig{Enabled: true, JWESecretKey: "jwe-secret", JWTSecretKey: "jwt-secret"}
			}
			app := metricsTestApp(t, cfg)

			var handler http.Handler
			if tc.transport == config.HTTPTransport {
				handler = app.buildHTTPHandler(cfg, app.mcpServer.MCPServer)
			} else {
				handler = app.buildSSEHandler(cfg, app.mcpServer.MCPServer)
			}

			rr := get(t, handler, "/metrics")
			require.NotEqual(t, http.StatusOK, rr.Code)
			require.NotContains(t, rr.Body.String(), "altinity_mcp_")
			require.NotContains(t, rr.Header().Get("Content-Type"), "text/plain; version=")
		})
	}
}

func TestMulticlusterHandlerExposesMetricsWhenEnabled(t *testing.T) {
	cfg := baseMetricsConfig(config.HTTPTransport, true)
	cfg.ClickHouse.Host = "chi-{cluster}-{cluster}-0-0.demo"
	cfg.Server.OAuth = config.OAuthConfig{Enabled: true, SigningSecret: "x"}
	cfg.Multicluster = config.MulticlusterConfig{
		Enabled:            true,
		ClusterAllowlist:   []string{"otel"},
		CatalogCacheMax:    1000,
		CatalogTTLFallback: 15 * time.Minute,
		CatalogNegativeTTL: 60 * time.Second,
	}
	app := metricsTestApp(t, cfg)
	router, err := altinitymcp.NewMulticlusterRouter(cfg.Multicluster, cfg.ClickHouse)
	require.NoError(t, err)
	app.mcRouter = router
	app.mcCache = altinitymcp.NewCatalogCache(cfg.Multicluster)
	t.Cleanup(app.mcCache.Close)
	app.mcMetrics = altinitymcp.NewCatalogCacheCollector(app.mcCache)
	require.NoError(t, metrics.Register(app.mcMetrics))
	t.Cleanup(func() { metrics.Unregister(app.mcMetrics) })

	handler := app.buildMulticlusterHandler(cfg)
	require.Equal(t, http.StatusOK, get(t, handler, "/livez").Code)

	// An unauthenticated MCP request against an allowed cluster must be
	// counted under the registered pattern, never under the concrete path.
	unauth := get(t, handler, "/mcp/otel")
	require.NotEqual(t, http.StatusOK, unauth.Code)

	rr := get(t, handler, "/metrics")
	require.Equal(t, http.StatusOK, rr.Code)
	body := rr.Body.String()
	require.Contains(t, body, "altinity_mcp_catalog_cache_entries")
	require.Contains(t, body, `method="GET",route="/livez",status="2xx"`)
	require.Contains(t, body, `route="/mcp/{cluster}"`)
	require.NotContains(t, body, `route="/mcp/otel"`)
}

func TestMulticlusterHandlerHidesMetricsWhenDisabled(t *testing.T) {
	cfg := baseMetricsConfig(config.HTTPTransport, false)
	cfg.ClickHouse.Host = "chi-{cluster}-{cluster}-0-0.demo"
	cfg.Server.OAuth = config.OAuthConfig{Enabled: true, SigningSecret: "x"}
	cfg.Multicluster = config.MulticlusterConfig{
		Enabled:            true,
		ClusterAllowlist:   []string{"otel"},
		CatalogCacheMax:    1000,
		CatalogTTLFallback: 15 * time.Minute,
		CatalogNegativeTTL: 60 * time.Second,
	}
	app := metricsTestApp(t, cfg)
	router, err := altinitymcp.NewMulticlusterRouter(cfg.Multicluster, cfg.ClickHouse)
	require.NoError(t, err)
	app.mcRouter = router
	app.mcCache = altinitymcp.NewCatalogCache(cfg.Multicluster)
	t.Cleanup(app.mcCache.Close)

	rr := get(t, app.buildMulticlusterHandler(cfg), "/metrics")
	require.Equal(t, http.StatusNotFound, rr.Code)
	require.NotContains(t, rr.Body.String(), "altinity_mcp_")
}

// TestReloadConfigMetricsIsRestartOnly covers both directions of the reload
// mismatch: the effective value survives a reload that tries to flip it, and
// the operator gets a warning rather than a config that lies about the
// running server.
func TestReloadConfigMetricsIsRestartOnly(t *testing.T) {
	for _, tc := range []struct {
		name    string
		running bool
		file    string
	}{
		{"enabled_stays_enabled_after_reload_to_false", true, "server:\n  metrics:\n    enabled: false\n"},
		{"disabled_stays_disabled_after_reload_to_true", false, "server:\n  metrics:\n    enabled: true\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			require.NoError(t, os.WriteFile(path, []byte(tc.file), 0o600))

			cfg := baseMetricsConfig(config.HTTPTransport, tc.running)
			app := &application{
				configFile: path,
				config:     cfg,
				mcpServer:  altinitymcp.NewClickHouseMCPServer(cfg, "test-version"),
			}
			err := app.reloadConfig(&mockCommand{flags: map[string]interface{}{}, setFlags: map[string]bool{}, stringMaps: map[string]map[string]string{}})
			require.NoError(t, err)
			require.Equal(t, tc.running, app.GetCurrentConfig().Server.Metrics.Enabled,
				"server.metrics.enabled must keep the value the running mux was built with")
			require.True(t, app.metricsReloadWarned, "first mismatching reload must warn")

			// A second tick with the same mismatch stays quiet; once the file
			// agrees with the running value the warning re-arms.
			require.NoError(t, app.reloadConfig(&mockCommand{flags: map[string]interface{}{}, setFlags: map[string]bool{}, stringMaps: map[string]map[string]string{}}))
			require.True(t, app.metricsReloadWarned)
			agree := "server:\n  metrics:\n    enabled: " + map[bool]string{true: "true", false: "false"}[tc.running] + "\n"
			require.NoError(t, os.WriteFile(path, []byte(agree), 0o600))
			require.NoError(t, app.reloadConfig(&mockCommand{flags: map[string]interface{}{}, setFlags: map[string]bool{}, stringMaps: map[string]map[string]string{}}))
			require.False(t, app.metricsReloadWarned)
			require.Equal(t, tc.running, app.GetCurrentConfig().Server.Metrics.Enabled)
		})
	}
}

// TestReloadConfigMetricsUnchangedIsSilent ensures the restart-only guard
// does not interfere with reloads that leave server.metrics.* alone.
func TestReloadConfigMetricsUnchangedIsSilent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte("server:\n  metrics:\n    enabled: true\nlogging:\n  level: info\n"), 0o600))
	cfg := baseMetricsConfig(config.HTTPTransport, true)
	app := &application{
		configFile: path,
		config:     cfg,
		mcpServer:  altinitymcp.NewClickHouseMCPServer(cfg, "test-version"),
	}
	require.NoError(t, app.reloadConfig(&mockCommand{flags: map[string]interface{}{}, setFlags: map[string]bool{}, stringMaps: map[string]map[string]string{}}))
	require.True(t, app.GetCurrentConfig().Server.Metrics.Enabled)
}
