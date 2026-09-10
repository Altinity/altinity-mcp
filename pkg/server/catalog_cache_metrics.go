package server

import "github.com/prometheus/client_golang/prometheus"

// CatalogCacheCollector exports the cache's existing atomic counters without
// changing the cache's storage or update path.
type CatalogCacheCollector struct {
	cache *CatalogCache
	desc  map[string]*prometheus.Desc
}

func NewCatalogCacheCollector(cache *CatalogCache) *CatalogCacheCollector {
	desc := make(map[string]*prometheus.Desc)
	for _, name := range []string{
		"entries", "denied_entries", "max_entries", "hits_ok_total",
		"hits_denied_total", "misses_total", "full_drops_ok_total",
		"full_drops_denied_total", "discovery_saturated_total",
		"discovery_auth_errors_total", "discovery_transient_errors_total",
	} {
		desc[name] = prometheus.NewDesc("altinity_mcp_catalog_cache_"+name, "Catalog cache "+name+".", nil, nil)
	}
	return &CatalogCacheCollector{cache: cache, desc: desc}
}

func (c *CatalogCacheCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, desc := range c.desc {
		ch <- desc
	}
}

func (c *CatalogCacheCollector) Collect(ch chan<- prometheus.Metric) {
	s := c.cache.Snapshot()
	gauge := func(name string, value float64) {
		ch <- prometheus.MustNewConstMetric(c.desc[name], prometheus.GaugeValue, value)
	}
	counter := func(name string, value uint64) {
		ch <- prometheus.MustNewConstMetric(c.desc[name], prometheus.CounterValue, float64(value))
	}
	gauge("entries", float64(s.Entries))
	gauge("denied_entries", float64(s.DeniedEntries))
	gauge("max_entries", float64(s.Max))
	counter("hits_ok_total", s.HitsOK)
	counter("hits_denied_total", s.HitsDenied)
	counter("misses_total", s.Misses)
	counter("full_drops_ok_total", s.FullDropsOK)
	counter("full_drops_denied_total", s.FullDropsDenied)
	counter("discovery_saturated_total", s.DiscoverySaturate)
	counter("discovery_auth_errors_total", s.DiscoveryAuthErr)
	counter("discovery_transient_errors_total", s.DiscoveryTransErr)
}
