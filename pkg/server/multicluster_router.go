package server

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/altinity/altinity-mcp/pkg/config"
	"github.com/rs/zerolog/log"
)

// clusterNameRegex matches RFC 1123 DNS labels (lowercase a-z, 0-9, and
// '-', not starting or ending with '-', total length 1..63). Excludes
// leading dots — the load-bearing property is that no valid cluster name
// can collide with /.well-known/* prefixes under any future mount that
// might overlap.
var clusterNameRegex = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)

// IsValidClusterName reports whether name passes the RFC 1123 DNS label
// check. Exported for tests and validation paths in cmd/altinity-mcp.
func IsValidClusterName(name string) bool {
	return clusterNameRegex.MatchString(name)
}

// MulticlusterRouter validates the {cluster} URL path value and expands
// the ClickHouseConfig.Host template into a per-request config that
// downstream middleware reads via CHConfigFromContext.
type MulticlusterRouter struct {
	cfg          config.MulticlusterConfig
	ch           config.ClickHouseConfig
	allowlistSet map[string]struct{}
}

// NewMulticlusterRouter builds a router. Returns an error if any
// allowlist entry fails the cluster-name regex.
func NewMulticlusterRouter(mc config.MulticlusterConfig, ch config.ClickHouseConfig) (*MulticlusterRouter, error) {
	allowlist := make(map[string]struct{}, len(mc.ClusterAllowlist))
	for _, name := range mc.ClusterAllowlist {
		trimmed := strings.TrimSpace(name)
		if trimmed == "" {
			continue
		}
		if !IsValidClusterName(trimmed) {
			return nil, fmt.Errorf("multicluster: cluster_allowlist entry %q is not a valid RFC 1123 DNS label", trimmed)
		}
		allowlist[trimmed] = struct{}{}
	}
	return &MulticlusterRouter{
		cfg:          mc,
		ch:           ch,
		allowlistSet: allowlist,
	}, nil
}

// resolveCluster validates the path-extracted cluster name and returns the
// per-request ClickHouseConfig. Returns ok=false on any rejection.
func (r *MulticlusterRouter) resolveCluster(cluster string) (config.ClickHouseConfig, bool) {
	if !IsValidClusterName(cluster) {
		return config.ClickHouseConfig{}, false
	}
	if len(r.allowlistSet) > 0 {
		if _, allowed := r.allowlistSet[cluster]; !allowed {
			return config.ClickHouseConfig{}, false
		}
	}
	reqCfg := r.ch // copy
	reqCfg.Host = strings.ReplaceAll(r.ch.Host, "{cluster}", cluster)
	return reqCfg, true
}

// Middleware extracts {cluster} from r.PathValue, validates it, expands
// the host template, and injects both the cluster name and the per-request
// ClickHouseConfig on the context. Invalid or non-allowlisted clusters get
// a 404 response without leaking which check failed.
func (r *MulticlusterRouter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		cluster := req.PathValue("cluster")
		reqCfg, ok := r.resolveCluster(cluster)
		if !ok {
			log.Debug().Str("cluster", cluster).Msg("multicluster: cluster rejected (invalid name or not in allowlist)")
			http.NotFound(w, req)
			return
		}
		ctx := WithCluster(req.Context(), cluster)
		ctx = WithRequestCHConfig(ctx, reqCfg)
		next.ServeHTTP(w, req.WithContext(ctx))
	})
}
