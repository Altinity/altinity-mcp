package metrics

import (
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
)

// These tests share the package-global enabled flag, so none of them run in
// parallel. disableForTest flips the flag back off without touching the
// registry; Enable is idempotent and re-enables it.
func disableForTest(t *testing.T) {
	t.Helper()
	enabled.Store(false)
	t.Cleanup(func() { enabled.Store(false) })
}

func TestDisabledIsNoop(t *testing.T) {
	disableForTest(t)
	require.False(t, Enabled())

	beforeQueries := testutil.ToFloat64(ClickHouseQueriesTotal.WithLabelValues("select", "error"))
	beforeRows := testutil.CollectAndCount(ClickHouseQueryRows)
	beforeBlocked := testutil.ToFloat64(BlockedClauseRejectionsTotal.WithLabelValues("WHERE"))
	ClickHouseUp.Set(math.NaN())

	ObserveClickHouseQuery("select", time.Now(), errors.New("boom"))
	ObserveClickHouseResult("select", 10, 100)
	ObserveBlockedClause("WHERE")
	ObserveClickHouseHealth(nil)

	require.Equal(t, beforeQueries, testutil.ToFloat64(ClickHouseQueriesTotal.WithLabelValues("select", "error")))
	require.Equal(t, beforeRows, testutil.CollectAndCount(ClickHouseQueryRows))
	require.Equal(t, beforeBlocked, testutil.ToFloat64(BlockedClauseRejectionsTotal.WithLabelValues("WHERE")))
	require.True(t, math.IsNaN(testutil.ToFloat64(ClickHouseUp)), "disabled health observation must not mutate the gauge")

	// Nothing is registered until Enable is called: the private registry
	// must gather zero metric families.
	if !registered.Load() {
		families, err := registry.Gather()
		require.NoError(t, err)
		require.Empty(t, families)
	}
}

func TestEnabledObservationsAreRecorded(t *testing.T) {
	disableForTest(t)
	Enable()
	require.True(t, Enabled())

	beforeOK := testutil.ToFloat64(ClickHouseQueriesTotal.WithLabelValues("select", "ok"))
	beforeErr := testutil.ToFloat64(ClickHouseQueriesTotal.WithLabelValues("execute", "error"))
	beforeBlocked := testutil.ToFloat64(BlockedClauseRejectionsTotal.WithLabelValues("SETTINGS"))

	ObserveClickHouseQuery("select", time.Now(), nil)
	ObserveClickHouseQuery("execute", time.Now(), errors.New("boom"))
	ObserveClickHouseResult("select", 3, 42)
	ObserveBlockedClause("SETTINGS")
	ObserveClickHouseHealth(nil)
	require.Equal(t, 1.0, testutil.ToFloat64(ClickHouseUp))
	ObserveClickHouseHealth(errors.New("down"))
	require.Equal(t, 0.0, testutil.ToFloat64(ClickHouseUp))

	require.Equal(t, beforeOK+1, testutil.ToFloat64(ClickHouseQueriesTotal.WithLabelValues("select", "ok")))
	require.Equal(t, beforeErr+1, testutil.ToFloat64(ClickHouseQueriesTotal.WithLabelValues("execute", "error")))
	require.Equal(t, beforeBlocked+1, testutil.ToFloat64(BlockedClauseRejectionsTotal.WithLabelValues("SETTINGS")))

	rr := httptest.NewRecorder()
	Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	require.Equal(t, http.StatusOK, rr.Code)
	require.Contains(t, rr.Body.String(), "altinity_mcp_clickhouse_queries_total")
	require.Contains(t, rr.Body.String(), "altinity_mcp_clickhouse_query_bytes")
	require.Contains(t, rr.Body.String(), "go_goroutines")
}

func TestClickHouseHealthUnknownIsNotReportedDown(t *testing.T) {
	disableForTest(t)
	Enable()
	ClickHouseUp.Set(0)
	ObserveClickHouseHealthUnknown()
	require.True(t, math.IsNaN(testutil.ToFloat64(ClickHouseUp)))
}

func TestHTTPMiddlewareRecordsMatchedRouteAndStatusClass(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	before := testutil.ToFloat64(HTTPRequestsTotal.WithLabelValues("GET /health", http.MethodGet, "2xx"))
	rr := httptest.NewRecorder()
	HTTPMiddleware(mux).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/health", nil))

	require.Equal(t, http.StatusNoContent, rr.Code)
	require.Equal(t, before+1, testutil.ToFloat64(HTTPRequestsTotal.WithLabelValues("GET /health", http.MethodGet, "2xx")))
}

func TestHTTPMiddlewareBoundsMethodLabel(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/anything", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := HTTPMiddleware(mux)

	before := testutil.ToFloat64(HTTPRequestsTotal.WithLabelValues("/anything", "other", "2xx"))
	for _, m := range []string{"PROPFIND", "BREW", "XYZZY"} {
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(m, "/anything", nil))
	}
	require.Equal(t, before+3, testutil.ToFloat64(HTTPRequestsTotal.WithLabelValues("/anything", "other", "2xx")))
	for _, m := range []string{"PROPFIND", "BREW", "XYZZY"} {
		require.Equal(t, 0.0, testutil.ToFloat64(HTTPRequestsTotal.WithLabelValues("/anything", m, "2xx")))
	}
}

func TestNormalizeMethod(t *testing.T) {
	for _, m := range []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"} {
		require.Equal(t, m, normalizeMethod(m))
	}
	require.Equal(t, "other", normalizeMethod("TRACE"))
	require.Equal(t, "other", normalizeMethod("get"))
	require.Equal(t, "other", normalizeMethod(""))
}

func TestHTTPMiddlewarePreservesFlush(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/events", func(w http.ResponseWriter, _ *http.Request) {
		flusher, ok := w.(http.Flusher)
		require.True(t, ok)
		flusher.Flush()
	})

	HTTPMiddleware(mux).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/events", nil))
}

func TestStatusClass(t *testing.T) {
	require.Equal(t, "2xx", statusClass(http.StatusOK))
	require.Equal(t, "5xx", statusClass(http.StatusBadGateway))
	require.Equal(t, "unknown", statusClass(42))
}
