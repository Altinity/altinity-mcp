package server

import (
	"strings"
	"testing"

	"github.com/altinity/altinity-mcp/pkg/config"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
)

func TestCatalogCacheCollectorExportsExistingCounters(t *testing.T) {
	cache := NewCatalogCache(config.MulticlusterConfig{CatalogCacheMax: 100})
	t.Cleanup(cache.Close)
	cache.Metrics.HitsOK.Add(3)

	registry := prometheus.NewRegistry()
	require.NoError(t, registry.Register(NewCatalogCacheCollector(cache)))
	require.NoError(t, testutil.GatherAndCompare(
		registry,
		strings.NewReader("# HELP altinity_mcp_catalog_cache_hits_ok_total Catalog cache hits_ok_total.\n# TYPE altinity_mcp_catalog_cache_hits_ok_total counter\naltinity_mcp_catalog_cache_hits_ok_total 3\n"),
		"altinity_mcp_catalog_cache_hits_ok_total",
	))
}
