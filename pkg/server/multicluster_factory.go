package server

import (
	"context"
	"net/http"

	"github.com/altinity/altinity-mcp/pkg/clickhouse"
	"github.com/altinity/altinity-mcp/pkg/config"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/rs/zerolog/log"
)

// MulticlusterServerFactory mints a per-(bearer, cluster) *mcp.Server on
// each incoming request. Single-cluster mode uses one *mcp.Server for the
// process; multi-cluster mode cannot, because per-tenant dynamic tools
// would poison cross-tenant tools/list.
//
// The factory holds the long-lived (cfg, cache, ClickHouseJWEServer)
// triple and exposes a single GetServer(r *http.Request) entry point
// shaped for mcp.NewStreamableHTTPHandler's first argument.
type MulticlusterServerFactory struct {
	cfg          config.Config
	parent       *ClickHouseJWEServer
	cache        *CatalogCache
	clientFn     ClientFactory
	dynamicRules []config.DynamicToolRule
	version      string
	instrName    string
	instrTitle   string
}

// NewMulticlusterServerFactory wires up the factory. parent supplies
// per-request OAuth/JWE extraction helpers and the CH client builder;
// cache is the catalog cache; cfg.Multicluster must be Enabled.
func NewMulticlusterServerFactory(
	cfg config.Config,
	parent *ClickHouseJWEServer,
	cache *CatalogCache,
	version string,
) *MulticlusterServerFactory {
	f := &MulticlusterServerFactory{
		cfg:    cfg,
		parent: parent,
		cache:  cache,
		// Dynamic-tool rules must come off the parent server, not cfg.
		// RegisterTools (run inside NewClickHouseMCPServer) converts the
		// unified `tools:` config into Config.Server.DynamicTools on the
		// parent's own config copy; the cfg value handed to this factory is
		// a separate copy that never saw that conversion. Reading
		// cfg.Server.DynamicTools here would silently miss every dynamic
		// rule declared via the unified `tools:` block (only the deprecated
		// dynamic_tools: key, parsed straight from YAML, would survive).
		dynamicRules: parent.Config.Server.DynamicTools,
		version:      version,
		instrName:    "Altinity ClickHouse MCP Server",
		instrTitle:   "Altinity ClickHouse MCP Server (multi-cluster)",
	}
	f.clientFn = func(ctx context.Context, chCfg config.ClickHouseConfig) (*clickhouse.Client, error) {
		jweToken := parent.ExtractTokenFromCtx(ctx)
		oauthToken := parent.ExtractOAuthTokenFromCtx(ctx)
		oauthClaims := parent.GetOAuthClaimsFromCtx(ctx)
		return parent.GetClickHouseClientWithOAuthForConfig(ctx, chCfg, jweToken, oauthToken, oauthClaims)
	}
	return f
}

// GetServer is the callback handed to mcp.NewStreamableHTTPHandler. It
// runs after the multi-cluster router middleware (which has injected
// cluster name + per-request chCfg on ctx) and after the OAuth injector
// (which has placed the bearer on ctx). Looks up the catalog cache and
// mints a fresh *mcp.Server populated with the right tool set.
func (f *MulticlusterServerFactory) GetServer(r *http.Request) *mcp.Server {
	ctx := r.Context()
	cluster, hasCluster := ClusterFromContext(ctx)
	if !hasCluster {
		// Defensive — the router should have 404'd. Return a static-only
		// server so the SDK can still respond with method-not-found rather
		// than nil-panic.
		return f.newServer(nil)
	}
	bearer := f.parent.ExtractOAuthTokenFromCtx(ctx)
	if bearer == "" {
		return f.newServer(nil)
	}
	reqCfg := CHConfigFromContext(ctx, f.cfg.ClickHouse)
	key := CacheKey(bearer)
	exp, _ := BearerExp(bearer)

	tools, err := f.cache.GetOrDiscover(ctx, key, cluster, reqCfg, f.clientFn,
		f.dynamicRules, f.cfg.ClickHouse.ReadOnly, exp)
	if err != nil {
		log.Warn().Err(err).Str("cluster", cluster).Msg("multicluster: discovery failed; static-only")
		return f.newServer(nil)
	}
	return f.newServer(tools)
}

// newServer builds a fresh *mcp.Server with resources, prompts, static
// tools, and (optionally) the per-tenant discovered dynamic tools.
func (f *MulticlusterServerFactory) newServer(dynamicTools map[string]dynamicToolMeta) *mcp.Server {
	opts := &mcp.ServerOptions{
		Instructions: f.instrTitle + " - A Model Context Protocol server for interacting with ClickHouse databases",
		HasTools:     true,
		HasResources: true,
		HasPrompts:   true,
	}
	srv := mcp.NewServer(&mcp.Implementation{
		Name:    f.instrName,
		Version: f.version,
	}, opts)
	adapter := NewSDKServerAdapter(srv)
	RegisterResources(adapter)
	RegisterPrompts(adapter)
	RegisterStaticToolsOn(adapter, &f.cfg)
	if len(dynamicTools) > 0 {
		registerDynamicToolsOn(adapter, dynamicTools, f.cfg.Server.ToolInputSettings, nil)
	}
	return srv
}

// ValidateClusterAllowed reports whether the cluster name passes the
// validation + allowlist gates. Exported so cmd/altinity-mcp can reject
// /.well-known/.../mcp/{bogus} before delegating to the existing PRM handler.
func (r *MulticlusterRouter) ValidateClusterAllowed(cluster string) (config.ClickHouseConfig, bool) {
	return r.resolveCluster(cluster)
}
