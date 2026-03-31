package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoadConfigWithDynamicTools(t *testing.T) {
	t.Parallel()
	t.Run("basic_dynamic_tools", func(t *testing.T) {
		t.Parallel()
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
		require.Equal(t, "", cfg.Server.DynamicTools[0].Name)
	})

	t.Run("dynamic_tools_with_name", func(t *testing.T) {
		t.Parallel()
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
    - name: "my_specific_tool"
      regexp: "mydb\\.my_view"
      prefix: "tool_"
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
		require.Equal(t, "mydb\\.my_view", cfg.Server.DynamicTools[0].Regexp)
		require.Equal(t, "tool_", cfg.Server.DynamicTools[0].Prefix)
		require.Equal(t, "my_specific_tool", cfg.Server.DynamicTools[0].Name)
	})

	t.Run("multiple_dynamic_tools_mixed", func(t *testing.T) {
		t.Parallel()
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
    - name: "specific_tool"
      regexp: "testdb\\.test_view"
    - name: "another_tool"
      regexp: "proddb\\.prod_view"
      prefix: "prod_"
logging:
  level: info
`)

		// Write to temp file
		f := t.TempDir() + "/config.yaml"
		require.NoError(t, os.WriteFile(f, yaml, 0o600))

		cfg, err := LoadConfigFromFile(f)
		require.NoError(t, err)
		require.NotNil(t, cfg)
		require.Len(t, cfg.Server.DynamicTools, 3)

		// First rule: no name
		require.Equal(t, "db\\..*", cfg.Server.DynamicTools[0].Regexp)
		require.Equal(t, "custom_", cfg.Server.DynamicTools[0].Prefix)
		require.Equal(t, "", cfg.Server.DynamicTools[0].Name)

		// Second rule: with name, no prefix
		require.Equal(t, "testdb\\.test_view", cfg.Server.DynamicTools[1].Regexp)
		require.Equal(t, "", cfg.Server.DynamicTools[1].Prefix)
		require.Equal(t, "specific_tool", cfg.Server.DynamicTools[1].Name)

		// Third rule: with name and prefix
		require.Equal(t, "proddb\\.prod_view", cfg.Server.DynamicTools[2].Regexp)
		require.Equal(t, "prod_", cfg.Server.DynamicTools[2].Prefix)
		require.Equal(t, "another_tool", cfg.Server.DynamicTools[2].Name)
	})

	t.Run("dynamic_tools_with_name_json", func(t *testing.T) {
		t.Parallel()
		jsonContent := []byte(`{
  "clickhouse": {
    "host": "localhost",
    "port": 8123,
    "database": "default",
    "username": "default",
    "protocol": "http"
  },
  "server": {
    "transport": "http",
    "address": "0.0.0.0",
    "port": 8080,
    "openapi": {
      "enabled": true
    },
    "dynamic_tools": [
      {
        "name": "json_tool",
        "regexp": "testdb\\..*",
        "prefix": "json_"
      }
    ]
  },
  "logging": {
    "level": "info"
  }
}`)

		// Write to temp file
		f := t.TempDir() + "/config.json"
		require.NoError(t, os.WriteFile(f, jsonContent, 0o600))

		cfg, err := LoadConfigFromFile(f)
		require.NoError(t, err)
		require.NotNil(t, cfg)
		require.Len(t, cfg.Server.DynamicTools, 1)
		require.Equal(t, "testdb\\..*", cfg.Server.DynamicTools[0].Regexp)
		require.Equal(t, "json_", cfg.Server.DynamicTools[0].Prefix)
		require.Equal(t, "json_tool", cfg.Server.DynamicTools[0].Name)
	})
}

// TestLoadConfigFromFile tests configuration loading from files
func TestLoadConfigFromFile(t *testing.T) {
	t.Parallel()
	t.Run("yaml_config", func(t *testing.T) {
		t.Parallel()
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
		t.Parallel()
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
		t.Parallel()
		cfg, err := LoadConfigFromFile("/nonexistent/file.yaml")
		require.Error(t, err)
		require.Nil(t, cfg)
	})

	t.Run("invalid_yaml", func(t *testing.T) {
		t.Parallel()
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
		t.Parallel()
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
		t.Parallel()
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
	t.Parallel()
	t.Run("clickhouse_protocols", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, ClickHouseProtocol("http"), HTTPProtocol)
		require.Equal(t, ClickHouseProtocol("tcp"), TCPProtocol)
	})

	t.Run("mcp_transports", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, MCPTransport("stdio"), StdioTransport)
		require.Equal(t, MCPTransport("http"), HTTPTransport)
		require.Equal(t, MCPTransport("sse"), SSETransport)
	})

	t.Run("log_levels", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, LogLevel("debug"), DebugLevel)
		require.Equal(t, LogLevel("info"), InfoLevel)
		require.Equal(t, LogLevel("warn"), WarnLevel)
		require.Equal(t, LogLevel("error"), ErrorLevel)
	})
}

// TestConfigStructs tests configuration struct initialization
func TestConfigStructs(t *testing.T) {
	t.Parallel()
	t.Run("clickhouse_config", func(t *testing.T) {
		t.Parallel()
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
		t.Parallel()
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
		t.Parallel()
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
		t.Parallel()
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
		t.Parallel()
		cfg := LoggingConfig{
			Level: DebugLevel,
		}

		require.Equal(t, DebugLevel, cfg.Level)
	})

	t.Run("oauth_config", func(t *testing.T) {
		t.Parallel()
		cfg := OAuthConfig{
			Enabled:                         true,
			Issuer:                          "https://auth.example.com",
			JWKSURL:                         "https://auth.example.com/.well-known/jwks.json",
			Audience:                        "my-api",
			PublicResourceURL:               "https://public.example.com/http",
			PublicAuthServerURL:             "https://public.example.com/oauth",
			ClientID:                        "client-123",
			ClientSecret:                    "secret-456",
			TokenURL:                        "https://auth.example.com/oauth/token",
			AuthURL:                         "https://auth.example.com/oauth/authorize",
			Scopes:                          []string{"read", "write"},
			RequiredScopes:                  []string{"read"},
			ClickHouseHeaderName:            "X-Custom-Token",
			ClaimsToHeaders:                 map[string]string{"sub": "X-User", "email": "X-Email"},
			ProtectedResourceMetadataPath:   "/resource-metadata",
			AuthorizationServerMetadataPath: "/auth-metadata",
			OpenIDConfigurationPath:         "/openid",
			RegistrationPath:                "/register",
			AuthorizationPath:               "/authorize",
			CallbackPath:                    "/callback",
			TokenPath:                       "/token",
			UpstreamIssuerAllowlist:         []string{"https://accounts.google.com"},
			AuthCodeTTLSeconds:              120,
			AccessTokenTTLSeconds:           600,
			RefreshTokenTTLSeconds:          86400,
		}

		require.True(t, cfg.Enabled)
		require.Equal(t, "https://auth.example.com", cfg.Issuer)
		require.Equal(t, "https://auth.example.com/.well-known/jwks.json", cfg.JWKSURL)
		require.Equal(t, "my-api", cfg.Audience)
		require.Equal(t, "https://public.example.com/http", cfg.PublicResourceURL)
		require.Equal(t, "https://public.example.com/oauth", cfg.PublicAuthServerURL)
		require.Equal(t, "client-123", cfg.ClientID)
		require.Equal(t, "secret-456", cfg.ClientSecret)
		require.Equal(t, "https://auth.example.com/oauth/token", cfg.TokenURL)
		require.Equal(t, "https://auth.example.com/oauth/authorize", cfg.AuthURL)
		require.Equal(t, []string{"read", "write"}, cfg.Scopes)
		require.Equal(t, []string{"read"}, cfg.RequiredScopes)
		require.Equal(t, "X-Custom-Token", cfg.ClickHouseHeaderName)
		require.Equal(t, "X-User", cfg.ClaimsToHeaders["sub"])
		require.Equal(t, "X-Email", cfg.ClaimsToHeaders["email"])
		require.Equal(t, "/resource-metadata", cfg.ProtectedResourceMetadataPath)
		require.Equal(t, "/auth-metadata", cfg.AuthorizationServerMetadataPath)
		require.Equal(t, "/openid", cfg.OpenIDConfigurationPath)
		require.Equal(t, "/register", cfg.RegistrationPath)
		require.Equal(t, "/authorize", cfg.AuthorizationPath)
		require.Equal(t, "/callback", cfg.CallbackPath)
		require.Equal(t, "/token", cfg.TokenPath)
		require.Equal(t, []string{"https://accounts.google.com"}, cfg.UpstreamIssuerAllowlist)
		require.Equal(t, 120, cfg.AuthCodeTTLSeconds)
		require.Equal(t, 600, cfg.AccessTokenTTLSeconds)
		require.Equal(t, 86400, cfg.RefreshTokenTTLSeconds)
	})
}

// TestLoadConfigWithOAuth tests OAuth configuration loading from files
func TestLoadConfigWithOAuth(t *testing.T) {
	t.Parallel()
	t.Run("oauth_yaml_config", func(t *testing.T) {
		t.Parallel()
		yamlContent := `
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
  jwe:
    enabled: true
    jwe_secret_key: "jwe-secret"
    jwt_secret_key: "jwt-secret"
  oauth:
    enabled: true
    issuer: "https://auth.example.com"
    jwks_url: "https://auth.example.com/.well-known/jwks.json"
    audience: "my-api"
    public_resource_url: "https://public.example.com/http"
    public_auth_server_url: "https://public.example.com/oauth"
    client_id: "client-123"
    client_secret: "secret-456"
    token_url: "https://auth.example.com/oauth/token"
    auth_url: "https://auth.example.com/oauth/authorize"
    protected_resource_metadata_path: "/resource-metadata"
    authorization_server_metadata_path: "/auth-metadata"
    openid_configuration_path: "/openid"
    registration_path: "/register"
    authorization_path: "/authorize"
    callback_path: "/callback"
    token_path: "/token"
    upstream_issuer_allowlist:
      - "https://accounts.google.com"
    auth_code_ttl_seconds: 120
    access_token_ttl_seconds: 600
    refresh_token_ttl_seconds: 86400
    scopes:
      - read
      - write
    required_scopes:
      - read
    clickhouse_header_name: "X-Custom-Token"
    claims_to_headers:
      sub: "X-ClickHouse-User"
      email: "X-ClickHouse-Email"
logging:
  level: info
`
		tmpFile := filepath.Join(t.TempDir(), "config.yaml")
		err := os.WriteFile(tmpFile, []byte(yamlContent), 0644)
		require.NoError(t, err)

		cfg, err := LoadConfigFromFile(tmpFile)
		require.NoError(t, err)
		require.NotNil(t, cfg)

		// Verify JWE config
		require.True(t, cfg.Server.JWE.Enabled)
		require.Equal(t, "jwe-secret", cfg.Server.JWE.JWESecretKey)
		require.Equal(t, "jwt-secret", cfg.Server.JWE.JWTSecretKey)

		// Verify OAuth config
		require.True(t, cfg.Server.OAuth.Enabled)
		require.Equal(t, "https://auth.example.com", cfg.Server.OAuth.Issuer)
		require.Equal(t, "https://auth.example.com/.well-known/jwks.json", cfg.Server.OAuth.JWKSURL)
		require.Equal(t, "my-api", cfg.Server.OAuth.Audience)
		require.Equal(t, "https://public.example.com/http", cfg.Server.OAuth.PublicResourceURL)
		require.Equal(t, "https://public.example.com/oauth", cfg.Server.OAuth.PublicAuthServerURL)
		require.Equal(t, "client-123", cfg.Server.OAuth.ClientID)
		require.Equal(t, "secret-456", cfg.Server.OAuth.ClientSecret)
		require.Equal(t, "https://auth.example.com/oauth/token", cfg.Server.OAuth.TokenURL)
		require.Equal(t, "https://auth.example.com/oauth/authorize", cfg.Server.OAuth.AuthURL)
		require.Equal(t, []string{"read", "write"}, cfg.Server.OAuth.Scopes)
		require.Equal(t, []string{"read"}, cfg.Server.OAuth.RequiredScopes)
		require.Equal(t, "X-Custom-Token", cfg.Server.OAuth.ClickHouseHeaderName)
		require.Equal(t, "X-ClickHouse-User", cfg.Server.OAuth.ClaimsToHeaders["sub"])
		require.Equal(t, "X-ClickHouse-Email", cfg.Server.OAuth.ClaimsToHeaders["email"])
		require.Equal(t, "/resource-metadata", cfg.Server.OAuth.ProtectedResourceMetadataPath)
		require.Equal(t, "/auth-metadata", cfg.Server.OAuth.AuthorizationServerMetadataPath)
		require.Equal(t, "/openid", cfg.Server.OAuth.OpenIDConfigurationPath)
		require.Equal(t, "/register", cfg.Server.OAuth.RegistrationPath)
		require.Equal(t, "/authorize", cfg.Server.OAuth.AuthorizationPath)
		require.Equal(t, "/callback", cfg.Server.OAuth.CallbackPath)
		require.Equal(t, "/token", cfg.Server.OAuth.TokenPath)
		require.Equal(t, []string{"https://accounts.google.com"}, cfg.Server.OAuth.UpstreamIssuerAllowlist)
		require.Equal(t, 120, cfg.Server.OAuth.AuthCodeTTLSeconds)
		require.Equal(t, 600, cfg.Server.OAuth.AccessTokenTTLSeconds)
		require.Equal(t, 86400, cfg.Server.OAuth.RefreshTokenTTLSeconds)
	})

	t.Run("oauth_json_config", func(t *testing.T) {
		t.Parallel()
		jsonContent := `{
  "clickhouse": {
    "host": "localhost",
    "port": 8123,
    "database": "default",
    "username": "default",
    "protocol": "http"
  },
  "server": {
    "transport": "http",
    "address": "0.0.0.0",
    "port": 8080,
    "jwe": {
      "enabled": true,
      "jwe_secret_key": "jwe-secret",
      "jwt_secret_key": "jwt-secret"
    },
    "oauth": {
      "enabled": true,
      "issuer": "https://auth.example.com",
      "audience": "my-api",
      "required_scopes": ["read", "write"],
      "claims_to_headers": {
        "sub": "X-User-ID",
        "name": "X-User-Name"
      }
    }
  },
  "logging": {
    "level": "info"
  }
}`
		tmpFile := filepath.Join(t.TempDir(), "config.json")
		err := os.WriteFile(tmpFile, []byte(jsonContent), 0644)
		require.NoError(t, err)

		cfg, err := LoadConfigFromFile(tmpFile)
		require.NoError(t, err)
		require.NotNil(t, cfg)

		// Verify both JWE and OAuth are configured
		require.True(t, cfg.Server.JWE.Enabled)
		require.True(t, cfg.Server.OAuth.Enabled)
		require.Equal(t, "https://auth.example.com", cfg.Server.OAuth.Issuer)
		require.Equal(t, "my-api", cfg.Server.OAuth.Audience)
		require.Equal(t, []string{"read", "write"}, cfg.Server.OAuth.RequiredScopes)
		require.Equal(t, "X-User-ID", cfg.Server.OAuth.ClaimsToHeaders["sub"])
		require.Equal(t, "X-User-Name", cfg.Server.OAuth.ClaimsToHeaders["name"])
	})

	t.Run("jwe_and_oauth_both_enabled", func(t *testing.T) {
		t.Parallel()
		yamlContent := `
clickhouse:
  host: localhost
  port: 8123
  database: default
server:
  jwe:
    enabled: true
    jwe_secret_key: "test-jwe-key"
  oauth:
    enabled: true
    issuer: "https://auth.example.com"
`
		tmpFile := filepath.Join(t.TempDir(), "config.yaml")
		err := os.WriteFile(tmpFile, []byte(yamlContent), 0644)
		require.NoError(t, err)

		cfg, err := LoadConfigFromFile(tmpFile)
		require.NoError(t, err)
		require.NotNil(t, cfg)

		// Both should be enabled
		require.True(t, cfg.Server.JWE.Enabled)
		require.True(t, cfg.Server.OAuth.Enabled)
	})
}
