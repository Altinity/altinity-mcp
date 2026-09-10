package metrics

import (
	"math"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
)

func TestClickHouseHealthUnknownIsNotReportedDown(t *testing.T) {
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
