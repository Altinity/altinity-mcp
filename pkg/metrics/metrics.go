// Package metrics defines the Prometheus collectors exposed by the MCP server
// on its /metrics endpoint (see MetricsConfig.Enabled in pkg/config) and the
// helpers that instrument the HTTP layer and the ClickHouse client with them.
package metrics

import (
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

func init() {
	// Until a readiness ping has actually run, there is no observation. This
	// remains NaN in OAuth/JWE modes where credentials only exist per request,
	// instead of claiming that a healthy deployment is down.
	ClickHouseUp.Set(math.NaN())
}

var (
	// HTTPRequestsTotal counts every HTTP request the MCP server's own mux
	// handled, labeled by route pattern (not raw path, which for the JWE
	// transport includes a per-request token) and response status class.
	HTTPRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "altinity_mcp_http_requests_total",
			Help: "Total HTTP requests handled by the MCP server, by route and status class.",
		},
		[]string{"route", "method", "status"},
	)

	// HTTPRequestDuration observes end-to-end handler latency, including MCP
	// tool calls served over the streamable HTTP/SSE transports -- this is
	// deliberately the outermost middleware so it reflects what a client
	// actually waited, not just routing overhead.
	HTTPRequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "altinity_mcp_http_request_duration_seconds",
			Help:    "HTTP request duration in seconds, by route.",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"route"},
	)

	// ClickHouseQueriesTotal counts ClickHouse queries executed through
	// pkg/clickhouse.Client, labeled by statement kind (select vs. the
	// non-select/DDL path) and outcome.
	ClickHouseQueriesTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "altinity_mcp_clickhouse_queries_total",
			Help: "Total ClickHouse queries executed, by kind and outcome.",
		},
		[]string{"kind", "outcome"},
	)

	// ClickHouseQueryDuration observes ClickHouse round-trip latency as seen
	// by the MCP server -- network plus server-side execution, not just the
	// driver call, since that is the number an operator tuning timeouts or
	// caps actually needs.
	ClickHouseQueryDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "altinity_mcp_clickhouse_query_duration_seconds",
			Help:    "ClickHouse query duration in seconds, by kind.",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"kind"},
	)

	ClickHouseQueryRows = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "altinity_mcp_clickhouse_query_rows",
			Help:    "Rows returned by successful ClickHouse queries, by kind.",
			Buckets: prometheus.ExponentialBuckets(1, 2, 16),
		},
		[]string{"kind"},
	)

	ClickHouseQueryBytes = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "altinity_mcp_clickhouse_query_bytes",
			Help:    "Approximate bytes returned by successful ClickHouse queries, by kind.",
			Buckets: prometheus.ExponentialBuckets(128, 2, 18),
		},
		[]string{"kind"},
	)

	BlockedClauseRejectionsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "altinity_mcp_blocked_clause_rejections_total",
			Help: "Queries rejected by the blocked-clause guard, by normalized clause.",
		},
		[]string{"clause"},
	)

	ClickHouseUp = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "altinity_mcp_clickhouse_up",
			Help: "Whether the most recent ClickHouse readiness ping succeeded (1) or failed (0).",
		},
	)
)

// statusRecorder wraps a ResponseWriter to capture the status code a handler
// wrote, so middleware can label a metric with it after the handler returns.
// http.ResponseWriter has no getter for this -- WriteHeader is the only
// place the code is ever seen -- so the recorder is the standard shape for
// it (mirrors net/http/httptest.ResponseRecorder, minus the body capture
// this doesn't need).
type statusRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (r *statusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

func (r *statusRecorder) Flush() {
	_ = http.NewResponseController(r.ResponseWriter).Flush()
}

func (r *statusRecorder) WriteHeader(code int) {
	if r.wroteHeader {
		return
	}
	r.wroteHeader = true
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// HTTPMiddleware wraps mux so every request it serves is recorded against
// HTTPRequestsTotal and HTTPRequestDuration, labeled by mux's own matched
// pattern. (*http.ServeMux).Handler resolves that pattern without invoking
// it, so the label is the registered route (e.g. "/health", "/{token}/mcp")
// rather than r.URL.Path -- the JWE transport's path carries a per-request
// token, and a per-token label would make the metric grow without bound.
// Wrap mux with this first, innermost, then layer request-rewriting
// middleware (stripTrailingSlash, CORS) around the result -- the pattern it
// resolves must see the request the way mux itself will see it.
func HTTPMiddleware(mux *http.ServeMux) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, pattern := mux.Handler(r)
		if pattern == "" {
			pattern = "404"
		}
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		start := time.Now()
		mux.ServeHTTP(rec, r)
		HTTPRequestDuration.WithLabelValues(pattern).Observe(time.Since(start).Seconds())
		HTTPRequestsTotal.WithLabelValues(pattern, r.Method, statusClass(rec.status)).Inc()
	})
}

// statusClass reduces a status code to Prometheus's conventional class label
// ("2xx", "4xx", ...) rather than the raw code, which would otherwise be an
// unbounded label value for a server that can return arbitrary upstream
// ClickHouse error codes through the MCP error envelope.
func statusClass(status int) string {
	if status < 100 || status > 599 {
		return "unknown"
	}
	return strconv.Itoa(status/100) + "xx"
}

// ObserveClickHouseQuery records ClickHouseQueriesTotal and
// ClickHouseQueryDuration for one query. kind is "select" or "execute"
// (pkg/clickhouse.IsSelectQuery's two paths); outcome is "ok" or "error".
func ObserveClickHouseQuery(kind string, start time.Time, err error) {
	outcome := "ok"
	if err != nil {
		outcome = "error"
	}
	ClickHouseQueriesTotal.WithLabelValues(kind, outcome).Inc()
	ClickHouseQueryDuration.WithLabelValues(kind).Observe(time.Since(start).Seconds())
}

// ObserveClickHouseResult records result size only when a query returned a
// complete result. Negative values mean the caller could not measure it.
func ObserveClickHouseResult(kind string, rows, bytesApprox int) {
	if rows >= 0 {
		ClickHouseQueryRows.WithLabelValues(kind).Observe(float64(rows))
	}
	if bytesApprox >= 0 {
		ClickHouseQueryBytes.WithLabelValues(kind).Observe(float64(bytesApprox))
	}
}

func ObserveBlockedClause(clause string) {
	if clause != "" {
		BlockedClauseRejectionsTotal.WithLabelValues(clause).Inc()
	}
}

func ObserveClickHouseHealth(err error) {
	if err == nil {
		ClickHouseUp.Set(1)
		return
	}
	ClickHouseUp.Set(0)
}

// ObserveClickHouseHealthUnknown clears any stale process-local readiness
// result when the active mode cannot perform a credentialed readiness ping.
func ObserveClickHouseHealthUnknown() {
	ClickHouseUp.Set(math.NaN())
}
