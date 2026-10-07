package server

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"time"

	"github.com/altinity/altinity-mcp/pkg/clickhouse"
	"github.com/altinity/altinity-mcp/pkg/config"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/rs/zerolog/log"
)

// CredentialCatalogKey selects exactly the credential used for database access.
// Token kind is part of the hashed, unambiguous tuple; raw tokens never leave
// the request context or appear in cache diagnostics.
func (s *ClickHouseJWEServer) CredentialCatalogKey(ctx context.Context) (string, time.Time, error) {
	if s.Config.Server.JWE.Enabled {
		token := s.ExtractTokenFromCtx(ctx)
		if token != "" {
			claims := s.GetJWEClaimsFromCtx(ctx)
			if claims == nil {
				var err error
				claims, err = s.ParseJWEClaims(token)
				if err != nil {
					return "", time.Time{}, fmt.Errorf("invalid JWE credential")
				}
			}
			if s.JWEClaimsHaveCredentials(claims) {
				exp := time.Time{}
				switch v := claims["exp"].(type) {
				case float64:
					exp = time.Unix(int64(v), 0)
				case int64:
					exp = time.Unix(v, 0)
				case json.Number:
					if n, err := v.Int64(); err == nil {
						exp = time.Unix(n, 0)
					}
				}
				return CacheKey("jwe\x00" + token), exp, nil
			}
		}
	}
	if s.Config.Server.OAuth.Enabled {
		if token := s.ExtractOAuthTokenFromCtx(ctx); token != "" {
			exp, _ := BearerExp(token)
			return CacheKey("oauth\x00" + token), exp, nil
		}
	}
	return "", time.Time{}, fmt.Errorf("missing usable authentication token")
}

// Close releases this configuration generation's catalog janitor. Requests
// holding the retired immutable generation can complete safely.
func (s *ClickHouseJWEServer) Close() {
	s.catalogOnce.Do(func() {})
	if s.catalogCache != nil {
		s.catalogCache.Close()
	}
}

func (s *ClickHouseJWEServer) requestCatalog(ctx context.Context) map[string]dynamicToolMeta {
	if !s.Config.Server.JWE.Enabled && !s.Config.Server.OAuth.Enabled {
		if err := s.EnsureDynamicTools(ctx); err != nil {
			log.Warn().Err(err).Msg("dynamic catalog discovery failed")
		}
		s.dynamicToolsMu.RLock()
		defer s.dynamicToolsMu.RUnlock()
		return maps.Clone(s.dynamicTools)
	}
	key, exp, err := s.CredentialCatalogKey(ctx)
	if err != nil {
		return nil
	}
	if len(s.Config.Server.DynamicTools) == 0 {
		return nil
	}
	s.catalogOnce.Do(func() { s.catalogCache = NewCatalogCache(config.MulticlusterConfig{}) })
	factory := func(ctx context.Context, cfg config.ClickHouseConfig) (*clickhouse.Client, error) {
		return s.GetClickHouseClientWithOAuthForConfig(ctx, cfg, s.ExtractTokenFromCtx(ctx), s.ExtractOAuthTokenFromCtx(ctx), s.GetOAuthClaimsFromCtx(ctx))
	}
	var tools map[string]dynamicToolMeta
	if s.catalogCache == nil {
		// Close may retire a generation after a request snapshots it but before
		// lazy cache initialization. Finish that request with its own generation,
		// without creating a janitor for the retired parent.
		boundedCtx, cancel := context.WithTimeout(ctx, discoveryTimeout)
		defer cancel()
		tools, err = DiscoverTools(boundedCtx, s.Config.ClickHouse, factory, s.Config.Server.DynamicTools, s.Config.ClickHouse.ReadOnly)
	} else {
		tools, err = s.catalogCache.GetOrDiscover(ctx, key, "singlecluster", s.Config.ClickHouse, factory, s.Config.Server.DynamicTools, s.Config.ClickHouse.ReadOnly, exp)
	}
	if err != nil {
		log.Warn().Err(err).Msg("credential catalog discovery failed; static tools remain available")
		return nil
	}
	return tools
}

// GetServer creates a caller's MCP registry without changing the parent registry.
func (s *ClickHouseJWEServer) GetServer(r *http.Request) *mcp.Server {
	if !s.Config.Server.JWE.Enabled && !s.Config.Server.OAuth.Enabled {
		if err := s.EnsureDynamicTools(r.Context()); err != nil {
			log.Warn().Err(err).Msg("Failed to ensure dynamic tools")
		}
		return s.MCPServer
	}
	f := &MulticlusterServerFactory{cfg: s.Config, version: s.Version,
		instrName: "Altinity ClickHouse MCP Server", instrTitle: "Altinity ClickHouse MCP Server"}
	return f.newServer(s.requestCatalog(r.Context()))
}
