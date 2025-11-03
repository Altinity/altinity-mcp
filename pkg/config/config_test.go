package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoadConfigWithDynamicTools(t *testing.T) {
	yaml := []byte(`
clickhouse:
  host: localhost
  port: 8123
  database: default
  username: default
  protocol: http
server:
  transport: http
  address: 0.0.0.0
  port: 8080
  openapi:
    enabled: true
  dynamic_tools:
    - regexp: "db\\..*"
      prefix: "custom_"
logging:
  level: info
`)

	// Write to temp file
	f := t.TempDir() + "/config.yaml"
	require.NoError(t, os.WriteFile(f, yaml, 0o600))

	cfg, err := LoadConfigFromFile(f)
	require.NoError(t, err)
	require.NotNil(t, cfg)
	require.Len(t, cfg.Server.DynamicTools, 1)
	require.Equal(t, "db\\..*", cfg.Server.DynamicTools[0].Regexp)
	require.Equal(t, "custom_", cfg.Server.DynamicTools[0].Prefix)
}

// TestLoadConfigFromFile tests configuration loading from files
func TestLoadConfigFromFile(t *testing.T) {
	t.Run("yaml_config", func(t *testing.T) {
		yamlContent := `
clickhouse:
  host: "test-host"
  port: 9000
  database: "test-db"
  username: "test-user"
  password: "test-pass"
  protocol: "tcp"
  limit: 500
  http_headers:
    X-Custom-Header: "custom-value"
    Authorization: "Bearer token123"
server:
  openapi:
    enabled: true
  transport: "http"
  address: "127.0.0.1"
  port: 8080
logging:
  level: "debug"
`
		tmpFile := filepath.Join(t.TempDir(), "config.yaml")
		err := os.WriteFile(tmpFile, []byte(yamlContent), 0644)
		require.NoError(t, err)

		cfg, err := LoadConfigFromFile(tmpFile)
		require.NoError(t, err)
		require.NotNil(t, cfg)
		require.Equal(t, "test-host", cfg.ClickHouse.Host)
		require.Equal(t, 9000, cfg.ClickHouse.Port)
		require.Equal(t, "test-db", cfg.ClickHouse.Database)
		require.Equal(t, "test-user", cfg.ClickHouse.Username)
		require.Equal(t, "test-pass", cfg.ClickHouse.Password)
		require.Equal(t, TCPProtocol, cfg.ClickHouse.Protocol)
		require.Equal(t, 500, cfg.ClickHouse.Limit)
		require.Equal(t, HTTPTransport, cfg.Server.Transport)
		require.Equal(t, "127.0.0.1", cfg.Server.Address)
		require.Equal(t, 8080, cfg.Server.Port)
		require.Equal(t, DebugLevel, cfg.Logging.Level)
		require.True(t, cfg.Server.OpenAPI.Enabled)
		require.NotNil(t, cfg.ClickHouse.HttpHeaders)
		require.Len(t, cfg.ClickHouse.HttpHeaders, 2)
		require.Equal(t, "custom-value", cfg.ClickHouse.HttpHeaders["X-Custom-Header"])
		require.Equal(t, "Bearer token123", cfg.ClickHouse.HttpHeaders["Authorization"])
	})

	t.Run("json_config", func(t *testing.T) {
		jsonContent := `{
  "clickhouse": {
    "host": "json-host",
    "port": 8123,
    "database": "json-db",
    "username": "json-user",
    "protocol": "http",
    "limit": 2000,
    "http_headers": {
      "X-JSON-Header": "json-value",
      "User-Agent": "test-agent"
    }
  },
  "server": {
    "transport": "sse",
    "address": "0.0.0.0",
    "port": 9090
  },
  "logging": {
    "level": "info"
  },
  "server": {
    "openapi": { "enabled": false }
  }
}`
		tmpFile := filepath.Join(t.TempDir(), "config.json")
		err := os.WriteFile(tmpFile, []byte(jsonContent), 0644)
		require.NoError(t, err)

		cfg, err := LoadConfigFromFile(tmpFile)
		require.NoError(t, err)
		require.NotNil(t, cfg)
		require.Equal(t, "json-host", cfg.ClickHouse.Host)
		require.Equal(t, 8123, cfg.ClickHouse.Port)
		require.Equal(t, "json-db", cfg.ClickHouse.Database)
		require.Equal(t, "json-user", cfg.ClickHouse.Username)
		require.Equal(t, HTTPProtocol, cfg.ClickHouse.Protocol)
		require.Equal(t, 2000, cfg.ClickHouse.Limit)
		require.Equal(t, SSETransport, cfg.Server.Transport)
		require.Equal(t, "0.0.0.0", cfg.Server.Address)
		require.Equal(t, 9090, cfg.Server.Port)
		require.Equal(t, InfoLevel, cfg.Logging.Level)
		require.False(t, cfg.Server.OpenAPI.Enabled)
		require.NotNil(t, cfg.ClickHouse.HttpHeaders)
		require.Len(t, cfg.ClickHouse.HttpHeaders, 2)
		require.Equal(t, "json-value", cfg.ClickHouse.HttpHeaders["X-JSON-Header"])
		require.Equal(t, "test-agent", cfg.ClickHouse.HttpHeaders["User-Agent"])
	})

	t.Run("nonexistent_file", func(t *testing.T) {
		cfg, err := LoadConfigFromFile("/nonexistent/file.yaml")
		require.Error(t, err)
		require.Nil(t, cfg)
	})

	t.Run("invalid_yaml", func(t *testing.T) {
		invalidYaml := `
clickhouse:
  host: "test-host"
  port: invalid-port
  database: "test-db"
`
		tmpFile := filepath.Join(t.TempDir(), "invalid.yaml")
		err := os.WriteFile(tmpFile, []byte(invalidYaml), 0644)
		require.NoError(t, err)

		cfg, err := LoadConfigFromFile(tmpFile)
		require.Error(t, err)
		require.Nil(t, cfg)
	})

	t.Run("invalid_json", func(t *testing.T) {
		invalidJson := `{
  "clickhouse": {
    "host": "test-host",
    "port": "invalid-port"
  }
}`
		tmpFile := filepath.Join(t.TempDir(), "invalid.json")
		err := os.WriteFile(tmpFile, []byte(invalidJson), 0644)
		require.NoError(t, err)

		cfg, err := LoadConfigFromFile(tmpFile)
		require.Error(t, err)
		require.Nil(t, cfg)
	})

	t.Run("unsupported_extension", func(t *testing.T) {
		tmpFile := filepath.Join(t.TempDir(), "config.txt")
		err := os.WriteFile(tmpFile, []byte("some content"), 0644)
		require.NoError(t, err)

		cfg, err := LoadConfigFromFile(tmpFile)
		require.Error(t, err)
		require.Nil(t, cfg)
	})
}

// TestConfigConstants tests configuration constants
func TestConfigConstants(t *testing.T) {
	t.Run("clickhouse_protocols", func(t *testing.T) {
		require.Equal(t, ClickHouseProtocol("http"), HTTPProtocol)
		require.Equal(t, ClickHouseProtocol("tcp"), TCPProtocol)
	})

	t.Run("mcp_transports", func(t *testing.T) {
		require.Equal(t, MCPTransport("stdio"), StdioTransport)
		require.Equal(t, MCPTransport("http"), HTTPTransport)
		require.Equal(t, MCPTransport("sse"), SSETransport)
	})

	t.Run("log_levels", func(t *testing.T) {
		require.Equal(t, LogLevel("debug"), DebugLevel)
		require.Equal(t, LogLevel("info"), InfoLevel)
		require.Equal(t, LogLevel("warn"), WarnLevel)
		require.Equal(t, LogLevel("error"), ErrorLevel)
	})
}

// TestConfigStructs tests configuration struct initialization
func TestConfigStructs(t *testing.T) {
	t.Run("clickhouse_config", func(t *testing.T) {
		cfg := ClickHouseConfig{
			Host:             "localhost",
			Port:             8123,
			Database:         "default",
			Username:         "default",
			Password:         "password",
			Protocol:         HTTPProtocol,
			ReadOnly:         true,
			MaxExecutionTime: 300,
			Limit:            1000,
			HttpHeaders:      map[string]string{"X-Custom-Header": "custom-value"},
		}

		require.Equal(t, "localhost", cfg.Host)
		require.Equal(t, 8123, cfg.Port)
		require.Equal(t, "default", cfg.Database)
		require.Equal(t, "default", cfg.Username)
		require.Equal(t, "password", cfg.Password)
		require.Equal(t, HTTPProtocol, cfg.Protocol)
		require.True(t, cfg.ReadOnly)
		require.Equal(t, 300, cfg.MaxExecutionTime)
		require.Equal(t, 1000, cfg.Limit)
		require.NotNil(t, cfg.HttpHeaders)
		require.Equal(t, "custom-value", cfg.HttpHeaders["X-Custom-Header"])
	})

	t.Run("tls_config", func(t *testing.T) {
		cfg := TLSConfig{
			Enabled:            true,
			CaCert:             "/path/to/ca.crt",
			ClientCert:         "/path/to/client.crt",
			ClientKey:          "/path/to/client.key",
			InsecureSkipVerify: false,
		}

		require.True(t, cfg.Enabled)
		require.Equal(t, "/path/to/ca.crt", cfg.CaCert)
		require.Equal(t, "/path/to/client.crt", cfg.ClientCert)
		require.Equal(t, "/path/to/client.key", cfg.ClientKey)
		require.False(t, cfg.InsecureSkipVerify)
	})

	t.Run("server_config", func(t *testing.T) {
		cfg := ServerConfig{
			Transport: HTTPTransport,
			Address:   "0.0.0.0",
			Port:      8080,
		}

		require.Equal(t, HTTPTransport, cfg.Transport)
		require.Equal(t, "0.0.0.0", cfg.Address)
		require.Equal(t, 8080, cfg.Port)
	})

	t.Run("jwe_config", func(t *testing.T) {
		cfg := JWEConfig{
			Enabled:      true,
			JWESecretKey: "jwe-private-key",
			JWTSecretKey: "jwt-private-key",
		}

		require.True(t, cfg.Enabled)
		require.Equal(t, "jwe-private-key", cfg.JWESecretKey)
		require.Equal(t, "jwt-private-key", cfg.JWTSecretKey)
	})

	t.Run("logging_config", func(t *testing.T) {
		cfg := LoggingConfig{
			Level: DebugLevel,
		}

		require.Equal(t, DebugLevel, cfg.Level)
	})
}
