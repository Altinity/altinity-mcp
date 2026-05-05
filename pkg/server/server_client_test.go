package server

import (
	"testing"

	"github.com/altinity/altinity-mcp/pkg/config"
	"github.com/stretchr/testify/require"
)

// TestBuildConfigFromClaims tests building ClickHouse config from JWE claims
func TestBuildConfigFromClaims(t *testing.T) {
	t.Parallel()
	chConfig := config.ClickHouseConfig{
		Host:     "default-host",
		Port:     8123,
		Database: "default",
		Username: "default",
		Protocol: config.HTTPProtocol,
		Limit:    1000,
	}

	jweConfig := config.JWEConfig{
		Enabled:      true,
		JWESecretKey: "test-secret",
	}

	srv := NewClickHouseMCPServer(config.Config{Server: config.ServerConfig{JWE: jweConfig}, ClickHouse: chConfig}, "test-version")

	t.Run("basic_claims", func(t *testing.T) {
		t.Parallel()
		claims := map[string]interface{}{
			"host":     "jwe-host",
			"port":     float64(9000),
			"database": "jwe-db",
			"username": "jwe-user",
			"password": "jwe-pass",
			"protocol": "tcp",
			"limit":    float64(500),
		}

		cfg, err := srv.buildConfigFromClaims(claims)
		require.NoError(t, err)
		require.Equal(t, "jwe-host", cfg.Host)
		require.Equal(t, 9000, cfg.Port)
		require.Equal(t, "jwe-db", cfg.Database)
		require.Equal(t, "jwe-user", cfg.Username)
		require.Equal(t, "jwe-pass", cfg.Password)
		require.Equal(t, "tcp", string(cfg.Protocol))
		require.Equal(t, 500, cfg.Limit)
	})

	t.Run("tls_claims", func(t *testing.T) {
		t.Parallel()
		claims := map[string]interface{}{
			"tls_enabled":              true,
			"tls_ca_cert":              "/path/to/ca.crt",
			"tls_client_cert":          "/path/to/client.crt",
			"tls_client_key":           "/path/to/client.key",
			"tls_insecure_skip_verify": true,
		}

		cfg, err := srv.buildConfigFromClaims(claims)
		require.NoError(t, err)
		require.True(t, cfg.TLS.Enabled)
		require.Equal(t, "/path/to/ca.crt", cfg.TLS.CaCert)
		require.Equal(t, "/path/to/client.crt", cfg.TLS.ClientCert)
		require.Equal(t, "/path/to/client.key", cfg.TLS.ClientKey)
		require.True(t, cfg.TLS.InsecureSkipVerify)
	})

	t.Run("empty_claims", func(t *testing.T) {
		t.Parallel()
		claims := map[string]interface{}{}

		cfg, err := srv.buildConfigFromClaims(claims)
		require.NoError(t, err)
		// Should use default values
		require.Equal(t, "default-host", cfg.Host)
		require.Equal(t, 8123, cfg.Port)
		require.Equal(t, "default", cfg.Database)
	})

	t.Run("invalid_types", func(t *testing.T) {
		t.Parallel()
		claims := map[string]interface{}{
			"host": 123,       // Should be string
			"port": "invalid", // Should be number
		}

		cfg, err := srv.buildConfigFromClaims(claims)
		require.NoError(t, err)
		// Should use default values for invalid types
		require.Equal(t, "default-host", cfg.Host)
		require.Equal(t, 8123, cfg.Port)
	})
}
