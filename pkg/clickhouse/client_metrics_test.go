package clickhouse

import (
	"context"
	"testing"

	"github.com/altinity/altinity-mcp/pkg/metrics"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"
)

// histogramSum returns the sample sum and count of one labeled histogram
// series from the metrics registry.
func histogramSum(t *testing.T, name, kind string) (float64, uint64) {
	t.Helper()
	families, err := metrics.Gatherer().Gather()
	require.NoError(t, err)
	for _, f := range families {
		if f.GetName() != name {
			continue
		}
		for _, m := range f.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "kind" && l.GetValue() == kind {
					h := m.GetHistogram()
					return h.GetSampleSum(), h.GetSampleCount()
				}
			}
		}
	}
	return 0, 0
}

func labelValue(m *dto.Metric, name string) string {
	for _, l := range m.GetLabel() {
		if l.GetName() == name {
			return l.GetValue()
		}
	}
	return ""
}

// TestExecuteQueryRecordsMetrics runs real queries against embedded
// ClickHouse with metrics enabled and checks that the counters, the
// histograms, and the reused result-size estimate all line up.
func TestExecuteQueryRecordsMetrics(t *testing.T) {
	cfg := setupEmbeddedClickHouse(t)
	metrics.Enable()

	ctx := context.Background()
	client, err := NewClient(ctx, *cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	okBefore := testutil.ToFloat64(metrics.ClickHouseQueriesTotal.WithLabelValues("select", "ok"))
	errBefore := testutil.ToFloat64(metrics.ClickHouseQueriesTotal.WithLabelValues("select", "error"))
	execBefore := testutil.ToFloat64(metrics.ClickHouseQueriesTotal.WithLabelValues("execute", "ok"))
	bytesSumBefore, bytesCountBefore := histogramSum(t, "altinity_mcp_clickhouse_query_bytes", "select")
	rowsSumBefore, _ := histogramSum(t, "altinity_mcp_clickhouse_query_rows", "select")

	result, err := client.ExecuteQuery(ctx, "SELECT number, toString(number) AS s FROM numbers(5)")
	require.NoError(t, err)
	require.Equal(t, 5, result.Count)
	require.Positive(t, result.bytesApprox, "executeSelect must record the byte estimate it already computes")

	// The metrics wrapper must report exactly the estimate executeSelect
	// produced, not a second pass with a different formula.
	expectedBytes := 0
	for _, row := range result.Rows {
		expectedBytes += approxRowBytes(row)
	}
	require.Equal(t, expectedBytes, result.bytesApprox)

	_, err = client.ExecuteQuery(ctx, "SELECT * FROM this_table_does_not_exist_for_metrics")
	require.Error(t, err)

	_, err = client.ExecuteQuery(ctx, "CREATE TABLE IF NOT EXISTS metrics_probe (x UInt8) ENGINE = Memory")
	require.NoError(t, err)

	require.Equal(t, okBefore+1, testutil.ToFloat64(metrics.ClickHouseQueriesTotal.WithLabelValues("select", "ok")))
	require.Equal(t, errBefore+1, testutil.ToFloat64(metrics.ClickHouseQueriesTotal.WithLabelValues("select", "error")))
	require.Equal(t, execBefore+1, testutil.ToFloat64(metrics.ClickHouseQueriesTotal.WithLabelValues("execute", "ok")))

	bytesSumAfter, bytesCountAfter := histogramSum(t, "altinity_mcp_clickhouse_query_bytes", "select")
	require.Equal(t, bytesCountBefore+1, bytesCountAfter, "only the successful SELECT observes a result size")
	require.InDelta(t, float64(result.bytesApprox), bytesSumAfter-bytesSumBefore, 0.0001)

	rowsSumAfter, _ := histogramSum(t, "altinity_mcp_clickhouse_query_rows", "select")
	require.InDelta(t, 5, rowsSumAfter-rowsSumBefore, 0.0001)

	// Sanity-check label bounds: every series on the queries counter uses
	// only the two documented kinds and two documented outcomes.
	families, err := metrics.Gatherer().Gather()
	require.NoError(t, err)
	for _, f := range families {
		if f.GetName() != "altinity_mcp_clickhouse_queries_total" {
			continue
		}
		for _, m := range f.GetMetric() {
			require.Contains(t, []string{"select", "execute"}, labelValue(m, "kind"))
			require.Contains(t, []string{"ok", "error"}, labelValue(m, "outcome"))
		}
	}
}
