package main

import (
	"testing"
	"time"

	"github.com/altinity/altinity-mcp/pkg/config"
	"github.com/stretchr/testify/require"
)

func TestValidateMulticlusterRuntimeConfig(t *testing.T) {
	t.Parallel()

	baseValid := func() config.Config {
		return config.Config{
			ClickHouse: config.ClickHouseConfig{
				Host:     "chi-{cluster}-{cluster}-0-0.demo",
				Port:     8443,
				Protocol: config.HTTPProtocol,
			},
			Server: config.ServerConfig{
				OAuth: config.OAuthConfig{Enabled: true, SigningSecret: "x"},
			},
			Multicluster: config.MulticlusterConfig{
				Enabled:            true,
				ClusterAllowlist:   []string{"otel", "antalya"},
				CatalogCacheMax:    1000,
				CatalogTTLFallback: 15 * time.Minute,
				CatalogNegativeTTL: 60 * time.Second,
			},
		}
	}

	t.Run("disabled_returns_nil", func(t *testing.T) {
		t.Parallel()
		var cfg config.Config
		require.NoError(t, validateMulticlusterRuntimeConfig(cfg))
	})

	t.Run("valid_passes", func(t *testing.T) {
		t.Parallel()
		require.NoError(t, validateMulticlusterRuntimeConfig(baseValid()))
	})

	t.Run("rejects_jwe", func(t *testing.T) {
		t.Parallel()
		cfg := baseValid()
		cfg.Server.JWE.Enabled = true
		err := validateMulticlusterRuntimeConfig(cfg)
		require.Error(t, err)
		require.Contains(t, err.Error(), "JWE is incompatible")
	})

	t.Run("requires_oauth", func(t *testing.T) {
		t.Parallel()
		cfg := baseValid()
		cfg.Server.OAuth.Enabled = false
		err := validateMulticlusterRuntimeConfig(cfg)
		require.Error(t, err)
		require.Contains(t, err.Error(), "requires OAuth")
	})

	t.Run("rejects_openapi", func(t *testing.T) {
		t.Parallel()
		cfg := baseValid()
		cfg.Server.OpenAPI.Enabled = true
		err := validateMulticlusterRuntimeConfig(cfg)
		require.Error(t, err)
		require.Contains(t, err.Error(), "OpenAPI must be disabled")
	})

	t.Run("rejects_tiny_cache", func(t *testing.T) {
		t.Parallel()
		cfg := baseValid()
		cfg.Multicluster.CatalogCacheMax = 50
		err := validateMulticlusterRuntimeConfig(cfg)
		require.Error(t, err)
		require.Contains(t, err.Error(), "catalog_cache_max")
	})

	t.Run("rejects_out_of_range_fallback", func(t *testing.T) {
		t.Parallel()
		cfg := baseValid()
		cfg.Multicluster.CatalogTTLFallback = 30 * time.Second
		err := validateMulticlusterRuntimeConfig(cfg)
		require.Error(t, err)
		require.Contains(t, err.Error(), "catalog_ttl_fallback")
	})

	t.Run("rejects_out_of_range_negative_ttl", func(t *testing.T) {
		t.Parallel()
		cfg := baseValid()
		cfg.Multicluster.CatalogNegativeTTL = 10 * time.Minute
		err := validateMulticlusterRuntimeConfig(cfg)
		require.Error(t, err)
		require.Contains(t, err.Error(), "catalog_negative_ttl")
	})

	t.Run("rejects_bad_allowlist_entry", func(t *testing.T) {
		t.Parallel()
		cfg := baseValid()
		cfg.Multicluster.ClusterAllowlist = []string{"good", "Bad-Caps"}
		err := validateMulticlusterRuntimeConfig(cfg)
		require.Error(t, err)
		require.Contains(t, err.Error(), "Bad-Caps")
	})

	t.Run("warns_on_missing_placeholder", func(t *testing.T) {
		t.Parallel()
		// Warn only — does not error. Existing structured log captures
		// this; we just verify the validator returns nil.
		cfg := baseValid()
		cfg.ClickHouse.Host = "chi-otel-otel-0-0.demo"
		require.NoError(t, validateMulticlusterRuntimeConfig(cfg))
	})
}
