package server

import (
	"testing"
	"time"

	"github.com/altinity/altinity-mcp/pkg/config"
	"github.com/stretchr/testify/require"
)

// TestMulticlusterFactory_PicksUpUnifiedDynamicRules guards a regression:
// dynamic-tool rules declared via the unified `tools:` block are converted
// into Config.Server.DynamicTools by RegisterTools — but on the *parent
// server's* config copy, not on the value handed to the factory. The
// factory must therefore source its discovery rules from the parent, or
// every unified dynamic rule is silently dropped in multi-cluster mode.
func TestMulticlusterFactory_PicksUpUnifiedDynamicRules(t *testing.T) {
	t.Parallel()
	cfg := config.Config{
		ClickHouse: config.ClickHouseConfig{Host: "chi-{cluster}.demo"},
		Server: config.ServerConfig{
			Tools: []config.ToolDefinition{
				{Type: "read", ViewRegexp: "^analytics\\..*"},
			},
		},
	}
	parent := NewClickHouseMCPServer(cfg, "test")

	// Sanity: the unified rule did NOT land on the value-copy cfg...
	require.Empty(t, cfg.Server.DynamicTools, "conversion must not mutate caller's cfg copy")
	// ...but DID land on the parent server's config copy.
	require.Len(t, parent.Config.Server.DynamicTools, 1, "RegisterTools converts unified tools onto the parent")

	cache := NewCatalogCache(config.MulticlusterConfig{
		Enabled:            true,
		CatalogCacheMax:    100,
		CatalogTTLFallback: 15 * time.Minute,
		CatalogNegativeTTL: time.Minute,
	})
	defer cache.Close()

	f := NewMulticlusterServerFactory(cfg, parent, cache, "test")
	require.Len(t, f.dynamicRules, 1, "factory must inherit the resolved dynamic rules from the parent, not the bare cfg")
	require.Equal(t, "^analytics\\..*", f.dynamicRules[0].Regexp)
}
