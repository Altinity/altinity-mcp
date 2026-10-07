package server

import (
	"context"
	"testing"
	"time"

	"github.com/altinity/altinity-mcp/pkg/config"
	"github.com/stretchr/testify/require"
)

func TestCredentialCatalogKeyEffectiveIdentity(t *testing.T) {
	s := NewClickHouseMCPServer(config.Config{ClickHouse: config.ClickHouseConfig{Username: "server"}, Server: config.ServerConfig{JWE: config.JWEConfig{Enabled: true}, OAuth: config.OAuthConfig{Enabled: true}}}, "test")
	defer s.Close()
	ctx := context.WithValue(context.Background(), JWETokenKey, "same-token")
	ctx = context.WithValue(ctx, JWEClaimsKey, map[string]interface{}{"host": "tenant.example", "username": "alice", "exp": float64(time.Now().Add(time.Hour).Unix())})
	ctx = context.WithValue(ctx, OAuthTokenKey, "ignored-oauth")
	key, exp, err := s.CredentialCatalogKey(ctx)
	require.NoError(t, err)
	require.Equal(t, CacheKey("jwe\x00same-token"), key)
	require.False(t, exp.IsZero())
	ctx = context.WithValue(ctx, OAuthTokenKey, "different-ignored-oauth")
	again, _, err := s.CredentialCatalogKey(ctx)
	require.NoError(t, err)
	require.Equal(t, key, again)
	ctx = context.WithValue(ctx, JWEClaimsKey, map[string]interface{}{"host": "tenant.example"})
	key, _, err = s.CredentialCatalogKey(ctx)
	require.NoError(t, err)
	require.Equal(t, CacheKey("oauth\x00different-ignored-oauth"), key)
	ctx = context.WithValue(ctx, OAuthTokenKey, "same-token")
	oauthKey, _, err := s.CredentialCatalogKey(ctx)
	require.NoError(t, err)
	require.NotEqual(t, again, oauthKey)
	require.False(t, s.hasDiscoveryCredentials(context.Background()), "static username cannot enable auth discovery")
	require.NoError(t, s.EnsureDynamicTools(ctx))
	require.Empty(t, s.dynamicTools)
	require.False(t, s.dynamicToolsInit)
}

func TestCredentialCatalogCacheLifetime(t *testing.T) {
	s := NewClickHouseMCPServer(config.Config{Server: config.ServerConfig{OAuth: config.OAuthConfig{Enabled: true}, Tools: []config.ToolDefinition{{Type: "read", ViewRegexp: ".*"}}}}, "test")
	s.catalogOnce.Do(func() { s.catalogCache = NewCatalogCache(config.MulticlusterConfig{}) })
	ctx := context.WithValue(context.Background(), OAuthTokenKey, "alice")
	key, _, err := s.CredentialCatalogKey(ctx)
	require.NoError(t, err)
	tools := map[string]dynamicToolMeta{"alice": {ToolName: "alice"}}
	s.catalogCache.insertOK(fullKey(key, "singlecluster"), tools, time.Now().Add(time.Minute))
	require.Equal(t, tools, s.requestCatalog(ctx))
	require.Equal(t, uint64(1), s.catalogCache.Metrics.HitsOK.Load())
	s.catalogCache.mu.Lock()
	entry := s.catalogCache.entries[fullKey(key, "singlecluster")]
	entry.ExpiresAt = time.Now().Add(-time.Second)
	s.catalogCache.entries[fullKey(key, "singlecluster")] = entry
	s.catalogCache.mu.Unlock()
	// An expired entry must be rediscovered; the invalid endpoint cannot return
	// the previously cached metadata.
	require.Empty(t, s.requestCatalog(ctx))
	require.Equal(t, uint64(1), s.catalogCache.Metrics.Misses.Load())
	s.Close()
	s.Close()
	require.True(t, s.catalogCache.stopped.Load())
	closed := NewClickHouseMCPServer(s.Config, "test")
	closed.Close()
	require.Empty(t, closed.requestCatalog(ctx))
	require.Nil(t, closed.catalogCache)
}
