// Package metrics defines the Prometheus collectors exposed by the MCP server
// on its /metrics endpoint (see MetricsConfig.Enabled in pkg/config) and the
// helpers that instrument the HTTP layer and the ClickHouse client with them.
//
// Metrics are opt-in. Until Enable is called nothing is registered anywhere
// (not even in the default Prometheus registry) and every Observe* helper is
// a cheap no-op, so a deployment with server.metrics.enabled=false pays no
// per-request or per-query instrumentation cost and exposes no scrape data.
package metrics

import (
	"math"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	// enabled gates every Observe* helper. It is process-global because the
	// ClickHouse client and the query guard have no handle on the server's
	// configuration; the operator's choice is applied once at startup by
	// Enable (server.metrics.* is restart-only, see reloadConfig).
	enabled atomic.Bool

	// registry is private rather than prometheus.DefaultRegisterer so that a
	// disabled server has no collectors registered at all, and so tests can
	// gather from it without racing on global state.
	registry     = prometheus.NewRegistry()
	registerOnce sync.Once
	registered   atomic.Bool
)

var (
	// HTTPRequestsTotal counts every HTTP request the MCP server's own mux
	// handled, labeled by route pattern (not raw path, which for the JWE
	// transport includes a per-request token), normalized method, and
	// response status class.
	HTTPRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "altinity_mcp_http_requests_total",
			Help: "Total HTTP requests handled by the MCP server, by route, method and status class.",
		},
		[]string{"route", "method", "status"},
	)

	// HTTPRequestDuration observes end-to-end handler latency, including MCP
	// tool calls served over the streamable HTTP/SSE transports -- this is
	// deliberately the outermost middleware so it reflects what a client
	// actually waited, not just routing overhead.
	HTTPRequestDuration = prometheus.NewHistogramVec(
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
	ClickHouseQueriesTotal = prometheus.NewCounterVec(
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
	ClickHouseQueryDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "altinity_mcp_clickhouse_query_duration_seconds",
			Help:    "ClickHouse query duration in seconds, by kind.",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"kind"},
	)

	ClickHouseQueryRows = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "altinity_mcp_clickhouse_query_rows",
			Help:    "Rows returned by successful ClickHouse queries, by kind.",
			Buckets: prometheus.ExponentialBuckets(1, 2, 16),
		},
		[]string{"kind"},
	)

	ClickHouseQueryBytes = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "altinity_mcp_clickhouse_query_bytes",
			Help:    "Approximate bytes returned by successful ClickHouse queries, by kind.",
			Buckets: prometheus.ExponentialBuckets(128, 2, 18),
		},
		[]string{"kind"},
	)

	BlockedClauseRejectionsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "altinity_mcp_blocked_clause_rejections_total",
			Help: "Queries rejected by the blocked-clause guard, by normalized clause.",
		},
		[]string{"clause"},
	)

	// ClickHouseUp reports the most recent readiness ping. It starts as NaN
	// ("unknown") and stays NaN in OAuth/JWE modes where credentials only
	// exist per request and the health handler cannot ping ClickHouse, so a
	// healthy deployment is never falsely reported as down.
	ClickHouseUp = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "altinity_mcp_clickhouse_up",
			Help: "Whether the most recent ClickHouse readiness ping succeeded (1) or failed (0). NaN when no credentialed ping is possible.",
		},
	)
)

func init() {
	ClickHouseUp.Set(math.NaN())
}

// Enable turns instrumentation on and registers the collectors (plus the
// standard Go runtime and process collectors) in the private registry.
// Safe to call more than once; registration happens only the first time.
func Enable() {
	registerOnce.Do(func() {
		registry.MustRegister(
			collectors.NewGoCollector(),
			collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
			HTTPRequestsTotal,
			HTTPRequestDuration,
			ClickHouseQueriesTotal,
			ClickHouseQueryDuration,
			ClickHouseQueryRows,
			ClickHouseQueryBytes,
			BlockedClauseRejectionsTotal,
			ClickHouseUp,
		)
		registered.Store(true)
	})
	enabled.Store(true)
}

// Enabled reports whether Enable has been called. Instrumentation call sites
// that would otherwise do work just to feed a metric (e.g. sizing a result)
// should check this first.
func Enabled() bool {
	return enabled.Load()
}

// Handler serves the private registry in Prometheus exposition format.
func Handler() http.Handler {
	return promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
}

// Register adds an additional collector (e.g. the multicluster catalog-cache
// collector) to the metrics registry.
func Register(c prometheus.Collector) error {
	return registry.Register(c)
}

// Unregister removes a collector previously added with Register.
func Unregister(c prometheus.Collector) bool {
	return registry.Unregister(c)
}

// Gatherer exposes the private registry for tests and tooling.
func Gatherer() prometheus.Gatherer {
	return registry
}

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
//
// Callers should only install this when metrics are enabled; it does not
// re-check Enabled on every request.
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
		HTTPRequestsTotal.WithLabelValues(pattern, normalizeMethod(r.Method), statusClass(rec.status)).Inc()
	})
}

// normalizeMethod maps the request method onto a fixed set of label values.
// The wire method is client-controlled free text, so labeling with it
// directly would let any caller mint unbounded series.
func normalizeMethod(method string) string {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut,
		http.MethodPatch, http.MethodDelete, http.MethodOptions:
		return method
	default:
		return "other"
	}
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
	if !Enabled() {
		return
	}
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
	if !Enabled() {
		return
	}
	if rows >= 0 {
		ClickHouseQueryRows.WithLabelValues(kind).Observe(float64(rows))
	}
	if bytesApprox >= 0 {
		ClickHouseQueryBytes.WithLabelValues(kind).Observe(float64(bytesApprox))
	}
}

func ObserveBlockedClause(clause string) {
	if !Enabled() || clause == "" {
		return
	}
	BlockedClauseRejectionsTotal.WithLabelValues(clause).Inc()
}

func ObserveClickHouseHealth(err error) {
	if !Enabled() {
		return
	}
	if err == nil {
		ClickHouseUp.Set(1)
		return
	}
	ClickHouseUp.Set(0)
}

// ObserveClickHouseHealthUnknown clears any stale process-local readiness
// result when the active mode cannot perform a credentialed readiness ping.
func ObserveClickHouseHealthUnknown() {
	if !Enabled() {
		return
	}
	ClickHouseUp.Set(math.NaN())
}
