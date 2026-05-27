package server

import (
	"context"
	"errors"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"

	"github.com/altinity/altinity-mcp/pkg/clickhouse"
	"github.com/altinity/altinity-mcp/pkg/config"
	"github.com/rs/zerolog/log"
	"golang.org/x/sync/singleflight"
)

const (
	// negativeEvictionThreshold is the fill ratio above which insertion of a
	// new entry randomly evicts an existing `denied` entry. Positives are
	// never displaced. Keeps the cache from being filled with attack churn.
	negativeEvictionThreshold = 0.7
	// maxConcurrentDiscoveries is the hardcoded ceiling on simultaneous
	// tool-discovery round-trips to ClickHouse. Discoveries are slow (8s+
	// for a cluster with many views); without a ceiling, a connector storm
	// could exhaust the CH pod's connection pool. v1 decision: not
	// configurable — re-evaluate at v2.
	maxConcurrentDiscoveries = 16
	// discoveryTimeout bounds an individual DiscoverTools invocation
	// triggered by GetOrDiscover, separate from any outer ctx timeout.
	discoveryTimeout = 3 * time.Second
)

// ErrDiscoveryDenied signals that the catalog cache memoised an auth-class
// rejection for this (bearer, cluster). Callers should fall back to
// static-only tools without re-attempting discovery until the cached
// entry expires.
var ErrDiscoveryDenied = errors.New("multicluster: catalog discovery denied (cached)")

// ErrDiscoverySaturated signals that all maxConcurrentDiscoveries slots
// are in use and the caller's ctx fired before one freed. Callers should
// fall back to static-only tools and emit a counter.
var ErrDiscoverySaturated = errors.New("multicluster: discovery concurrency saturated")

type catalogOutcome int

const (
	catalogOutcomeOK catalogOutcome = iota
	catalogOutcomeDenied
)

// catalogEntry is one row in the catalog cache. Tools is nil when Outcome
// is catalogOutcomeDenied. ErrClass is informational only.
type catalogEntry struct {
	Outcome   catalogOutcome
	Tools     map[string]dynamicToolMeta
	ExpiresAt time.Time
	ErrClass  DiscoveryErrorClass
}

// CatalogCacheMetrics is the metrics surface for the catalog cache. The
// Prometheus registration is done by the caller; this struct only carries
// atomic counters so the cache implementation has no Prometheus
// dependency at this layer.
type CatalogCacheMetrics struct {
	HitsOK            atomic.Uint64
	HitsDenied        atomic.Uint64
	Misses            atomic.Uint64
	FullDropsOK       atomic.Uint64
	FullDropsDenied   atomic.Uint64
	DiscoverySaturate atomic.Uint64
	DiscoveryAuthErr  atomic.Uint64
	DiscoveryTransErr atomic.Uint64
}

// ClientFactory creates a ClickHouse client from a context + chCfg. The
// catalog cache passes through the request ctx so credential extraction
// (bearer in ctx) works as in single-cluster mode.
type ClientFactory func(ctx context.Context, chCfg config.ClickHouseConfig) (*clickhouse.Client, error)

// CatalogCache memoises (bearer, cluster) → discovered dynamic tools.
// Thread-safe; one instance per MCP process. Stop with Close() during
// shutdown to terminate the janitor goroutine.
type CatalogCache struct {
	mu          sync.Mutex
	entries     map[string]catalogEntry
	deniedKeys  []string // shadow index of denied-only entries for O(1) eviction
	max         int
	fallbackTTL time.Duration
	negativeTTL time.Duration
	sf          singleflight.Group
	sem         chan struct{}
	rng         *rand.Rand
	rngMu       sync.Mutex
	stop        chan struct{}
	stopped     atomic.Bool
	Metrics     CatalogCacheMetrics
}

// NewCatalogCache creates a catalog cache sized per cfg and starts the
// janitor goroutine. cfg must already have had applyMulticlusterDefaults
// run on it (caller responsibility).
func NewCatalogCache(cfg config.MulticlusterConfig) *CatalogCache {
	if cfg.CatalogCacheMax <= 0 {
		cfg.CatalogCacheMax = defaultMulticlusterCacheMax
	}
	if cfg.CatalogTTLFallback <= 0 {
		cfg.CatalogTTLFallback = defaultMulticlusterFallbackTTL
	}
	if cfg.CatalogNegativeTTL <= 0 {
		cfg.CatalogNegativeTTL = defaultMulticlusterNegativeTTL
	}

	c := &CatalogCache{
		entries:     make(map[string]catalogEntry, cfg.CatalogCacheMax),
		max:         cfg.CatalogCacheMax,
		fallbackTTL: cfg.CatalogTTLFallback,
		negativeTTL: cfg.CatalogNegativeTTL,
		sem:         make(chan struct{}, maxConcurrentDiscoveries),
		rng:         rand.New(rand.NewSource(time.Now().UnixNano())),
		stop:        make(chan struct{}),
	}
	go c.janitor()
	return c
}

// Defaults mirrored from config to avoid a circular import: NewCatalogCache
// is robust to a zero-valued MulticlusterConfig even if the operator
// constructs one by hand.
const (
	defaultMulticlusterCacheMax     = 10000
	defaultMulticlusterFallbackTTL  = 15 * time.Minute
	defaultMulticlusterNegativeTTL  = 60 * time.Second
	catalogCacheJanitorIntervalSecs = 60
)

// Close terminates the janitor goroutine. Safe to call multiple times.
func (c *CatalogCache) Close() {
	if c.stopped.CompareAndSwap(false, true) {
		close(c.stop)
	}
}

func (c *CatalogCache) janitor() {
	ticker := time.NewTicker(catalogCacheJanitorIntervalSecs * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-c.stop:
			return
		case now := <-ticker.C:
			c.sweepExpired(now)
		}
	}
}

func (c *CatalogCache) sweepExpired(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, e := range c.entries {
		if !e.ExpiresAt.IsZero() && now.After(e.ExpiresAt) {
			delete(c.entries, k)
		}
	}
	// Rebuild deniedKeys to drop swept-out denied entries.
	if len(c.deniedKeys) > 0 {
		filtered := c.deniedKeys[:0]
		for _, k := range c.deniedKeys {
			if e, ok := c.entries[k]; ok && e.Outcome == catalogOutcomeDenied {
				filtered = append(filtered, k)
			}
		}
		c.deniedKeys = filtered
	}
}

// fullKey assembles the lookup key. Bearer hash + null + cluster: the null
// byte is impossible in a hex string so there is no aliasing risk and the
// concatenation is unambiguous.
func fullKey(cacheKey, cluster string) string {
	return cacheKey + "\x00" + cluster
}

// GetOrDiscover returns the cached catalog for (cacheKey, cluster), or
// runs DiscoverTools under a singleflight + concurrency-limited semaphore
// to populate it. The bearerExp parameter is the JWT exp claim (zero
// if absent); positive entries' TTL is min(bearerExp, now+fallbackTTL).
//
// Returns ErrDiscoveryDenied when the (cacheKey, cluster) is currently
// memoised as a denied entry; callers should fall back to static-only
// without retrying. Returns ErrDiscoverySaturated when discovery slots
// are exhausted and the caller's ctx fires before one frees; same
// fallback behavior.
func (c *CatalogCache) GetOrDiscover(
	ctx context.Context,
	cacheKey, cluster string,
	reqCfg config.ClickHouseConfig,
	factory ClientFactory,
	rules []config.DynamicToolRule,
	readOnly bool,
	bearerExp time.Time,
) (map[string]dynamicToolMeta, error) {
	key := fullKey(cacheKey, cluster)

	// Fast path: existing entry under read-style lock.
	c.mu.Lock()
	if e, ok := c.entries[key]; ok && (e.ExpiresAt.IsZero() || time.Now().Before(e.ExpiresAt)) {
		c.mu.Unlock()
		switch e.Outcome {
		case catalogOutcomeOK:
			c.Metrics.HitsOK.Add(1)
			return e.Tools, nil
		case catalogOutcomeDenied:
			c.Metrics.HitsDenied.Add(1)
			return nil, ErrDiscoveryDenied
		}
	}
	c.mu.Unlock()
	c.Metrics.Misses.Add(1)

	// Coalesce concurrent misses on the same key.
	v, err, _ := c.sf.Do(key, func() (interface{}, error) {
		// Re-check after acquiring the singleflight slot (another inflight
		// caller may have populated the entry).
		c.mu.Lock()
		if e, ok := c.entries[key]; ok && (e.ExpiresAt.IsZero() || time.Now().Before(e.ExpiresAt)) {
			c.mu.Unlock()
			if e.Outcome == catalogOutcomeOK {
				return e.Tools, nil
			}
			return nil, ErrDiscoveryDenied
		}
		c.mu.Unlock()

		// Acquire a discovery slot or fail under ctx.
		select {
		case c.sem <- struct{}{}:
			defer func() { <-c.sem }()
		case <-ctx.Done():
			c.Metrics.DiscoverySaturate.Add(1)
			return nil, ErrDiscoverySaturated
		}

		ctxTimeout, cancel := context.WithTimeout(ctx, discoveryTimeout)
		defer cancel()

		tools, derr := DiscoverTools(ctxTimeout, reqCfg, factory, rules, readOnly)
		if derr != nil {
			auth, class := ClassifyDiscoveryError(derr)
			if auth {
				c.Metrics.DiscoveryAuthErr.Add(1)
				c.insertDenied(key, class)
			} else {
				c.Metrics.DiscoveryTransErr.Add(1)
			}
			return nil, derr
		}
		c.insertOK(key, tools, bearerExp)
		return tools, nil
	})
	if err != nil {
		return nil, err
	}
	if tools, ok := v.(map[string]dynamicToolMeta); ok {
		return tools, nil
	}
	return nil, nil
}

func (c *CatalogCache) insertOK(key string, tools map[string]dynamicToolMeta, bearerExp time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	exp := time.Now().Add(c.fallbackTTL)
	if !bearerExp.IsZero() && bearerExp.Before(exp) {
		exp = bearerExp
	}
	if !c.makeRoomLocked(catalogOutcomeOK) {
		log.Warn().Str("key_suffix", key[len(key)-12:]).Msg("catalog_cache: full; dropping positive entry")
		c.Metrics.FullDropsOK.Add(1)
		return
	}
	c.entries[key] = catalogEntry{
		Outcome:   catalogOutcomeOK,
		Tools:     tools,
		ExpiresAt: exp,
	}
}

func (c *CatalogCache) insertDenied(key string, class DiscoveryErrorClass) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.makeRoomLocked(catalogOutcomeDenied) {
		c.Metrics.FullDropsDenied.Add(1)
		return
	}
	c.entries[key] = catalogEntry{
		Outcome:   catalogOutcomeDenied,
		ExpiresAt: time.Now().Add(c.negativeTTL),
		ErrClass:  class,
	}
	c.deniedKeys = append(c.deniedKeys, key)
}

// makeRoomLocked guarantees space for one new insert. Caller holds c.mu.
//
// At fill ≥ 70% of max, attempts random eviction of a denied entry.
// Positives are never displaced — under churning attack traffic this
// degrades gracefully to "no more denied entries get cached" rather than
// thrashing legitimate-user catalogs.
//
// Returns false only when the cache is at hard cap AND no denied entry is
// available to evict AND outcome is denied (positive inserts are always
// allowed past the threshold by spilling — the hard cap is informational
// because positive entries are bounded by the (bearer, cluster) cardinality
// the OAuth issuer is willing to mint).
func (c *CatalogCache) makeRoomLocked(outcome catalogOutcome) bool {
	cur := len(c.entries)
	if cur < c.max {
		// Even below the threshold we want random eviction once fill ≥ 70%.
		if float64(cur)/float64(c.max) >= negativeEvictionThreshold {
			c.evictOneDeniedLocked()
		}
		return true
	}
	// At/above hard cap: evict a denied entry to make room, or drop on
	// denied insert (positive insert is allowed to exceed cap by 1 —
	// preferable to losing a legitimate user's catalog).
	if c.evictOneDeniedLocked() {
		return true
	}
	if outcome == catalogOutcomeOK {
		return true
	}
	return false
}

func (c *CatalogCache) evictOneDeniedLocked() bool {
	// Walk deniedKeys from the back, dropping stale entries (already
	// expired / no longer denied). The first valid one we hit gets
	// random-evicted by swap-remove.
	for len(c.deniedKeys) > 0 {
		idx := c.rngIntn(len(c.deniedKeys))
		key := c.deniedKeys[idx]
		// Swap-remove from deniedKeys regardless.
		last := len(c.deniedKeys) - 1
		c.deniedKeys[idx] = c.deniedKeys[last]
		c.deniedKeys = c.deniedKeys[:last]

		e, ok := c.entries[key]
		if !ok || e.Outcome != catalogOutcomeDenied {
			continue
		}
		delete(c.entries, key)
		return true
	}
	return false
}

func (c *CatalogCache) rngIntn(n int) int {
	if n <= 1 {
		return 0
	}
	c.rngMu.Lock()
	defer c.rngMu.Unlock()
	return c.rng.Intn(n)
}
