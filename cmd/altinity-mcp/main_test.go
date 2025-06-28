package main

import (
	"fmt"
	"os"
	"testing"

	"github.com/altinity/altinity-mcp/pkg/config"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli/v3"
)

// TestMain sets up logging for the test suite.
func TestMain(m *testing.M) {
	if err := setupLogging("debug"); err != nil {
		fmt.Printf("Failed to setup logging: %v\n", err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}

// TestSetupLogging tests the logging setup function
func TestSetupLogging(t *testing.T) {
	t.Run("valid_levels", func(t *testing.T) {
		levels := []string{"debug", "info", "warn", "error"}
		for _, level := range levels {
			err := setupLogging(level)
			require.NoError(t, err)
		}
	})

	t.Run("invalid_level", func(t *testing.T) {
		err := setupLogging("invalid")
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid log level")
	})

	t.Run("case_insensitive", func(t *testing.T) {
		err := setupLogging("DEBUG")
		require.NoError(t, err)
		
		err = setupLogging("Info")
		require.NoError(t, err)
	})
}

// TestBuildConfig tests configuration building
func TestBuildConfig(t *testing.T) {
	t.Run("default_values", func(t *testing.T) {
		cmd := &cli.Command{}
		cmd.Flags = []cli.Flag{
			&cli.StringFlag{Name: "config"},
			&cli.StringFlag{Name: "clickhouse-host", Value: "localhost"},
			&cli.IntFlag{Name: "clickhouse-port", Value: 8123},
			&cli.StringFlag{Name: "clickhouse-database", Value: "default"},
			&cli.StringFlag{Name: "clickhouse-username", Value: "default"},
			&cli.StringFlag{Name: "clickhouse-password", Value: ""},
			&cli.StringFlag{Name: "clickhouse-protocol", Value: "http"},
			&cli.IntFlag{Name: "clickhouse-max-execution-time", Value: 600},
			&cli.BoolFlag{Name: "read-only", Value: false},
			&cli.StringFlag{Name: "transport", Value: "stdio"},
			&cli.StringFlag{Name: "address", Value: "0.0.0.0"},
			&cli.IntFlag{Name: "port", Value: 8080},
			&cli.StringFlag{Name: "log-level", Value: "info"},
			&cli.IntFlag{Name: "clickhouse-limit", Value: 1000},
		}

		cfg, err := buildConfig(cmd)
		require.NoError(t, err)
		require.Equal(t, "localhost", cfg.ClickHouse.Host)
		require.Equal(t, 8123, cfg.ClickHouse.Port)
		require.Equal(t, "default", cfg.ClickHouse.Database)
		require.Equal(t, "default", cfg.ClickHouse.Username)
		require.Equal(t, "", cfg.ClickHouse.Password)
		require.Equal(t, "http", string(cfg.ClickHouse.Protocol))
		require.Equal(t, 600, cfg.ClickHouse.MaxExecutionTime)
		require.False(t, cfg.ClickHouse.ReadOnly)
		require.Equal(t, "stdio", string(cfg.Server.Transport))
		require.Equal(t, "0.0.0.0", cfg.Server.Address)
		require.Equal(t, 8080, cfg.Server.Port)
		require.Equal(t, "info", string(cfg.Logging.Level))
		require.Equal(t, 1000, cfg.ClickHouse.Limit)
	})

	t.Run("nonexistent_config_file", func(t *testing.T) {
		cmd := &cli.Command{}
		cmd.Flags = []cli.Flag{
			&cli.StringFlag{Name: "config", Value: "/nonexistent/config.yaml"},
		}

		_, err := buildConfig(cmd)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to load config file")
	})
}

// TestOverrideWithCLIFlags tests CLI flag override functionality
func TestOverrideWithCLIFlags(t *testing.T) {
	t.Run("protocol_override", func(t *testing.T) {
		// Create a mock command that simulates flag being set
		cmd := &mockCommand{
			flags: map[string]interface{}{
				"clickhouse-protocol": "tcp",
			},
			setFlags: map[string]bool{
				"clickhouse-protocol": true,
			},
		}

		cfg := &config.Config{}
		overrideWithCLIFlags(cfg, cmd)
		require.Equal(t, config.TCPProtocol, cfg.ClickHouse.Protocol)
	})

	t.Run("transport_override", func(t *testing.T) {
		// Create a mock command that simulates flag being set
		cmd := &mockCommand{
			flags: map[string]interface{}{
				"transport": "http",
			},
			setFlags: map[string]bool{
				"transport": true,
			},
		}

		cfg := &config.Config{}
		overrideWithCLIFlags(cfg, cmd)
		require.Equal(t, config.HTTPTransport, cfg.Server.Transport)
	})

	t.Run("log_level_override", func(t *testing.T) {
		// Create a mock command that simulates flag being set
		cmd := &mockCommand{
			flags: map[string]interface{}{
				"log-level": "debug",
			},
			setFlags: map[string]bool{
				"log-level": true,
			},
		}

		cfg := &config.Config{}
		overrideWithCLIFlags(cfg, cmd)
		require.Equal(t, config.DebugLevel, cfg.Logging.Level)
	})
}

// mockCommand implements the interface needed by overrideWithCLIFlags for testing
type mockCommand struct {
	flags    map[string]interface{}
	setFlags map[string]bool
}

func (m *mockCommand) String(name string) string {
	if val, ok := m.flags[name]; ok {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return ""
}

func (m *mockCommand) Int(name string) int {
	if val, ok := m.flags[name]; ok {
		if i, ok := val.(int); ok {
			return i
		}
	}
	return 0
}

func (m *mockCommand) Bool(name string) bool {
	if val, ok := m.flags[name]; ok {
		if b, ok := val.(bool); ok {
			return b
		}
	}
	return false
}

func (m *mockCommand) IsSet(name string) bool {
	return m.setFlags[name]
}

// TestBuildServerTLSConfig tests server TLS configuration building
func TestBuildServerTLSConfig(t *testing.T) {
	t.Run("disabled", func(t *testing.T) {
		cfg := &config.ServerTLSConfig{Enabled: false}
		tlsConfig, err := buildServerTLSConfig(cfg)
		require.NoError(t, err)
		require.Nil(t, tlsConfig)
	})

	t.Run("enabled_without_ca", func(t *testing.T) {
		cfg := &config.ServerTLSConfig{Enabled: true}
		tlsConfig, err := buildServerTLSConfig(cfg)
		require.NoError(t, err)
		require.NotNil(t, tlsConfig)
	})

	t.Run("enabled_with_invalid_ca", func(t *testing.T) {
		cfg := &config.ServerTLSConfig{
			Enabled: true,
			CaCert:  "/nonexistent/ca.crt",
		}
		tlsConfig, err := buildServerTLSConfig(cfg)
		require.Error(t, err)
		require.Nil(t, tlsConfig)
	})
}
