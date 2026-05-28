package server

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/altinity/altinity-mcp/pkg/clickhouse"
	"github.com/altinity/altinity-mcp/pkg/config"
	"github.com/stretchr/testify/require"
)

// noClientFactory is the ClientFactory used by tests that don't actually
// need a CH client — DiscoverTools short-circuits when len(rules)==0 (no
// factory invocation), so we can use this in fast-path tests by pairing
// it with an empty rules slice. Tests that need to drive discovery
// produce a custom factory inline.
var noClientFactory ClientFactory = func(ctx context.Context, chCfg config.ClickHouseConfig) (*clickhouse.Client, error) {
	return nil, errors.New("noClientFactory: should not be called when rules are empty")
}

func TestCatalogCache_HitOK(t *testing.T) {
	t.Parallel()
	c := newTestCache(t, 100, 15*time.Minute, 60*time.Second)
	defer c.Close()

	// First call: miss, runs (no-op) discovery, caches positive entry.
	tools, err := c.GetOrDiscover(context.Background(), "k1", "alpha", config.ClickHouseConfig{}, noClientFactory, nil, true, time.Time{})
	require.NoError(t, err)
	require.NotNil(t, tools)
	require.Equal(t, uint64(1), c.Metrics.Misses.Load())

	// Second call: hit.
	_, err = c.GetOrDiscover(context.Background(), "k1", "alpha", config.ClickHouseConfig{}, noClientFactory, nil, true, time.Time{})
	require.NoError(t, err)
	require.Equal(t, uint64(1), c.Metrics.HitsOK.Load())
}

func TestCatalogCache_BearerExpBoundsTTL(t *testing.T) {
	t.Parallel()
	c := newTestCache(t, 100, time.Hour, 60*time.Second)
	defer c.Close()

	near := time.Now().Add(5 * time.Second)
	_, err := c.GetOrDiscover(context.Background(), "k1", "alpha", config.ClickHouseConfig{}, noClientFactory, nil, true, near)
	require.NoError(t, err)

	// Read the entry directly to inspect TTL.
	c.mu.Lock()
	e, ok := c.entries[fullKey("k1", "alpha")]
	c.mu.Unlock()
	require.True(t, ok)
	require.WithinDuration(t, near, e.ExpiresAt, time.Second, "expiry capped by bearer exp")
}

func TestCatalogCache_DenyCachedAndReturned(t *testing.T) {
	t.Parallel()
	c := newTestCache(t, 100, 15*time.Minute, 60*time.Second)
	defer c.Close()

	rules := []config.DynamicToolRule{{Name: "x", Regexp: ".*", Type: "read"}}
	authErr := errors.New("ClickHouse error: code: 516, message: AUTHENTICATION_FAILED")
	factory := func(ctx context.Context, chCfg config.ClickHouseConfig) (*clickhouse.Client, error) {
		return nil, authErr
	}

	_, err := c.GetOrDiscover(context.Background(), "k1", "alpha", config.ClickHouseConfig{}, factory, rules, true, time.Time{})
	require.Error(t, err)
	require.Equal(t, uint64(1), c.Metrics.DiscoveryAuthErr.Load())

	// Second call: should hit denied cache without ever calling factory.
	called := 0
	loud := func(ctx context.Context, chCfg config.ClickHouseConfig) (*clickhouse.Client, error) {
		called++
		return nil, authErr
	}
	_, err = c.GetOrDiscover(context.Background(), "k1", "alpha", config.ClickHouseConfig{}, loud, rules, true, time.Time{})
	require.ErrorIs(t, err, ErrDiscoveryDenied)
	require.Equal(t, 0, called, "denied entry must short-circuit the factory")
	require.Equal(t, uint64(1), c.Metrics.HitsDenied.Load())
}

func TestCatalogCache_TransientErrorNotCached(t *testing.T) {
	t.Parallel()
	c := newTestCache(t, 100, 15*time.Minute, 60*time.Second)
	defer c.Close()

	rules := []config.DynamicToolRule{{Name: "x", Regexp: ".*", Type: "read"}}
	transient := errors.New("connection refused")
	calls := atomic.Int32{}
	factory := func(ctx context.Context, chCfg config.ClickHouseConfig) (*clickhouse.Client, error) {
		calls.Add(1)
		return nil, transient
	}

	for i := 0; i < 3; i++ {
		_, err := c.GetOrDiscover(context.Background(), "k1", "alpha", config.ClickHouseConfig{}, factory, rules, true, time.Time{})
		require.Error(t, err)
	}
	require.GreaterOrEqual(t, int(calls.Load()), 3, "transient errors must not be cached")
	require.Equal(t, uint64(0), c.Metrics.DiscoveryAuthErr.Load())
}

func TestCatalogCache_PositivesNeverEvictedByThreshold(t *testing.T) {
	t.Parallel()
	c := newTestCache(t, 10, 15*time.Minute, 60*time.Second)
	defer c.Close()

	// Insert 7 positives (70% fill).
	for i := 0; i < 7; i++ {
		_, err := c.GetOrDiscover(context.Background(), fmt.Sprintf("k%d", i), "alpha", config.ClickHouseConfig{}, noClientFactory, nil, true, time.Time{})
		require.NoError(t, err)
	}

	// Insert several denied entries — they should occupy the remaining
	// 3 slots, then start evicting each other.
	rules := []config.DynamicToolRule{{Name: "x", Regexp: ".*", Type: "read"}}
	auth := errors.New("Code: 497 ACCESS_DENIED")
	authFactory := func(ctx context.Context, chCfg config.ClickHouseConfig) (*clickhouse.Client, error) {
		return nil, auth
	}
	for i := 0; i < 20; i++ {
		_, _ = c.GetOrDiscover(context.Background(), fmt.Sprintf("denied%d", i), "alpha", config.ClickHouseConfig{}, authFactory, rules, true, time.Time{})
	}

	// All 7 positives must still be present.
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := 0; i < 7; i++ {
		e, ok := c.entries[fullKey(fmt.Sprintf("k%d", i), "alpha")]
		require.True(t, ok, "positive k%d evicted unexpectedly", i)
		require.Equal(t, catalogOutcomeOK, e.Outcome)
	}
}

func TestCatalogCache_SingleflightCollapsesConcurrentMisses(t *testing.T) {
	t.Parallel()
	c := newTestCache(t, 100, 15*time.Minute, 60*time.Second)
	defer c.Close()

	gate := make(chan struct{})
	calls := atomic.Int32{}
	factory := func(ctx context.Context, chCfg config.ClickHouseConfig) (*clickhouse.Client, error) {
		calls.Add(1)
		<-gate
		return nil, errors.New("ok-but-empty")
	}
	// Empty rules + custom error so we don't depend on producing tools.
	// Use real rule so factory is invoked.
	rules := []config.DynamicToolRule{{Name: "x", Regexp: ".*", Type: "read"}}

	const N = 8
	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func() {
			defer wg.Done()
			_, _ = c.GetOrDiscover(context.Background(), "shared", "alpha", config.ClickHouseConfig{}, factory, rules, true, time.Time{})
		}()
	}
	// Give the goroutines time to all enter singleflight.
	time.Sleep(50 * time.Millisecond)
	close(gate)
	wg.Wait()
	require.Equal(t, int32(1), calls.Load(), "singleflight must collapse N concurrent misses to 1 discovery")
}

func TestCatalogCache_DiscoverySaturation(t *testing.T) {
	t.Parallel()
	c := newTestCache(t, 100, 15*time.Minute, 60*time.Second)
	defer c.Close()

	hold := make(chan struct{})
	rules := []config.DynamicToolRule{{Name: "x", Regexp: ".*", Type: "read"}}
	factory := func(ctx context.Context, chCfg config.ClickHouseConfig) (*clickhouse.Client, error) {
		<-hold
		return nil, errors.New("never")
	}

	// Fill all maxConcurrentDiscoveries slots with distinct keys.
	var wg sync.WaitGroup
	for i := 0; i < maxConcurrentDiscoveries; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, _ = c.GetOrDiscover(context.Background(), fmt.Sprintf("hot%d", i), "alpha", config.ClickHouseConfig{}, factory, rules, true, time.Time{})
		}(i)
	}
	// Wait for all to acquire the semaphore.
	require.Eventually(t, func() bool {
		return len(c.sem) == maxConcurrentDiscoveries
	}, time.Second, 10*time.Millisecond)

	// Next call with a short ctx must fail-fast on the semaphore wait.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := c.GetOrDiscover(ctx, "extra", "alpha", config.ClickHouseConfig{}, factory, rules, true, time.Time{})
	require.ErrorIs(t, err, ErrDiscoverySaturated)
	require.GreaterOrEqual(t, c.Metrics.DiscoverySaturate.Load(), uint64(1))

	// Release the held goroutines and wait for them to finish so the
	// test's resources (and the semaphore) are clean for the next test.
	close(hold)
	wg.Wait()
}

func newTestCache(t *testing.T, max int, fallback, neg time.Duration) *CatalogCache {
	t.Helper()
	return NewCatalogCache(config.MulticlusterConfig{
		Enabled:            true,
		CatalogCacheMax:    max,
		CatalogTTLFallback: fallback,
		CatalogNegativeTTL: neg,
	})
}
