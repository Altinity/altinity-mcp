package server

import (
	"context"
	"testing"
	"time"

	"github.com/altinity/altinity-mcp/pkg/config"
	"github.com/altinity/go-mcp-oauth-sdk/jwe_auth"
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

func TestAuthenticatedClientBoundaryNoStaticFallback(t *testing.T) {
	for _, mode := range []string{"jwe", "oauth", "combined"} {
		for _, credentials := range []string{"none", "disabled_token"} {
			t.Run(mode+"/"+credentials, func(t *testing.T) {
				srv, calls := openAPIGuardServer(t, 100)
				srv.Config.Server.JWE.Enabled = mode != "oauth"
				srv.Config.Server.OAuth.Enabled = mode != "jwe"
				ctx := context.Background()
				tokenParam := ""
				if credentials == "disabled_token" {
					if mode == "oauth" {
						ctx = context.WithValue(ctx, JWETokenKey, "disabled-jwe-token")
						tokenParam = "disabled-jwe-token"
					} else if mode == "jwe" {
						ctx = context.WithValue(ctx, OAuthTokenKey, "disabled-oauth-token")
					}
				}
				client, err := srv.GetClickHouseClientFromCtx(ctx)
				if mode == "oauth" {
					require.ErrorIs(t, err, ErrMissingOAuthToken)
				} else {
					require.ErrorIs(t, err, jwe_auth.ErrMissingToken)
				}
				require.Error(t, err)
				require.Nil(t, client)
				require.Zero(t, calls.Load())
				client, err = srv.GetClickHouseClient(ctx, tokenParam)
				require.Error(t, err)
				require.Nil(t, client)
				require.Zero(t, calls.Load())
				client, err = srv.GetClickHouseClientWithOAuthForConfig(ctx, srv.Config.ClickHouse, tokenParam, srv.ExtractOAuthTokenFromCtx(ctx), nil)
				require.Error(t, err)
				require.Nil(t, client)
				require.Zero(t, calls.Load())
			})
		}
	}
}

func TestLegacyClientExplicitJWEArgument(t *testing.T) {
	srv, calls := openAPIGuardServer(t, 100)
	srv.Config.Server.JWE = config.JWEConfig{Enabled: true, JWESecretKey: "this-is-a-32-byte-secret-key!!", JWTSecretKey: "fake-jwt-secret"}
	ctx := context.WithValue(context.Background(), JWETokenKey, "different-token")
	ctx = context.WithValue(ctx, JWEClaimsKey, map[string]interface{}{"host": srv.Config.ClickHouse.Host, "port": float64(srv.Config.ClickHouse.Port), "username": "fake-user"})
	client, err := srv.GetClickHouseClient(ctx, "")
	require.Error(t, err)
	require.Nil(t, client)
	require.Zero(t, calls.Load())
	client, err = srv.GetClickHouseClient(ctx, "invalid-explicit-token")
	require.Error(t, err)
	require.Nil(t, client)
	require.Zero(t, calls.Load())
}

func TestCombinedClientPartialJWEWithoutOAuthNoIO(t *testing.T) {
	srv, calls := openAPIGuardServer(t, 100)
	srv.Config.Server.JWE = config.JWEConfig{Enabled: true, JWESecretKey: "this-is-a-32-byte-secret-key!!", JWTSecretKey: "fake-jwt-secret"}
	srv.Config.Server.OAuth.Enabled = true
	token, err := jwe_auth.GenerateJWEToken(map[string]interface{}{"username": "alice", "exp": time.Now().Add(time.Hour).Unix()}, []byte(srv.Config.Server.JWE.JWESecretKey), []byte(srv.Config.Server.JWE.JWTSecretKey))
	require.NoError(t, err)
	ctx := context.WithValue(context.Background(), JWETokenKey, token)
	client, err := srv.GetClickHouseClientFromCtx(ctx)
	require.ErrorIs(t, err, ErrJWEIncompleteConnection)
	require.Nil(t, client)
	require.Zero(t, calls.Load())
	client, err = srv.GetClickHouseClient(ctx, token)
	require.ErrorIs(t, err, ErrJWEIncompleteConnection)
	require.Nil(t, client)
	require.Zero(t, calls.Load())
}
