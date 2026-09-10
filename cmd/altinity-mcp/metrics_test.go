package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/altinity/altinity-mcp/pkg/config"
	"github.com/altinity/altinity-mcp/pkg/metrics"
	"github.com/stretchr/testify/require"
)

func TestRegisterMetricsRouteDisabledByDefault(t *testing.T) {
	mux := http.NewServeMux()
	registerMetricsRoute(mux, config.Config{})
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	require.Equal(t, http.StatusNotFound, rr.Code)
}

func TestRegisterMetricsRouteWhenEnabled(t *testing.T) {
	mux := http.NewServeMux()
	cfg := config.Config{}
	cfg.Server.Metrics.Enabled = true
	registerMetricsRoute(mux, cfg)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	require.Equal(t, http.StatusOK, rr.Code)
	require.True(t, strings.Contains(rr.Body.String(), "altinity_mcp_clickhouse_up"))
}

func TestMulticlusterMetricsHandlerExposesRouteAndInstrumentsRequests(t *testing.T) {
	mux := http.NewServeMux()
	cfg := config.Config{}
	cfg.Server.Metrics.Enabled = true
	registerMetricsRoute(mux, cfg)
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := metrics.HTTPMiddleware(mux)
	health := httptest.NewRecorder()
	handler.ServeHTTP(health, httptest.NewRequest(http.MethodGet, "/health", nil))
	require.Equal(t, http.StatusOK, health.Code)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	require.Equal(t, http.StatusOK, rr.Code)
	require.Contains(t, rr.Body.String(), "altinity_mcp_http_requests_total")
	require.Contains(t, rr.Body.String(), "route=\"/health\"")
}
