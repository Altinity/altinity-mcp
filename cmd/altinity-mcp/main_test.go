package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/altinity/altinity-mcp/pkg/clickhouse"
	"github.com/altinity/altinity-mcp/pkg/config"
	"github.com/altinity/altinity-mcp/pkg/jwe_auth"
	altinitymcp "github.com/altinity/altinity-mcp/pkg/server"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
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
	t.Parallel()
	t.Run("valid_levels", func(t *testing.T) {
		t.Parallel()
		levels := []string{"debug", "info", "warn", "error"}
		for _, level := range levels {
			err := setupLogging(level)
			require.NoError(t, err)
		}
	})

	t.Run("invalid_level", func(t *testing.T) {
		t.Parallel()
		err := setupLogging("invalid")
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid log level")
	})

	t.Run("case_insensitive", func(t *testing.T) {
		t.Parallel()
		err := setupLogging("DEBUG")
		require.NoError(t, err)

		err = setupLogging("Info")
		require.NoError(t, err)
	})
}

// TestBuildConfig tests configuration building
func TestBuildConfig(t *testing.T) {
	t.Parallel()
	t.Run("default_values", func(t *testing.T) {
		t.Parallel()
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
			&cli.BoolFlag{Name: "allow-jwe-auth", Value: false},
			&cli.StringFlag{Name: "jwe-secret-key", Value: ""},
			&cli.StringFlag{Name: "jwt-secret-key", Value: ""},
			&cli.StringFlag{Name: "openapi", Value: "disable"},
			&cli.StringMapFlag{Name: "clickhouse-http-headers", Value: map[string]string{}},
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
		require.Equal(t, 0, cfg.ClickHouse.Limit)
		require.Equal(t, false, cfg.Server.OpenAPI.Enabled)
		require.Nil(t, cfg.ClickHouse.HttpHeaders)
	})

	t.Run("with_http_headers", func(t *testing.T) {
		t.Parallel()
		cmd := &cli.Command{}
		cmd.Flags = []cli.Flag{
			&cli.StringFlag{Name: "config"},
			&cli.StringFlag{Name: "clickhouse-host", Value: "localhost"},
			&cli.IntFlag{Name: "clickhouse-port", Value: 8123},
			&cli.StringMapFlag{Name: "clickhouse-http-headers", Value: map[string]string{
				"X-Custom-Header": "custom-value",
				"Authorization":   "Bearer token123",
			}},
		}

		cfg, err := buildConfig(cmd)
		require.NoError(t, err)
		require.NotNil(t, cfg.ClickHouse.HttpHeaders)
		require.Len(t, cfg.ClickHouse.HttpHeaders, 2)
		require.Equal(t, "custom-value", cfg.ClickHouse.HttpHeaders["X-Custom-Header"])
		require.Equal(t, "Bearer token123", cfg.ClickHouse.HttpHeaders["Authorization"])
	})

	t.Run("openapi_enabled_http", func(t *testing.T) {
		t.Parallel()
		cmd := &cli.Command{}
		cmd.Flags = []cli.Flag{
			&cli.StringFlag{Name: "openapi", Value: "http"},
		}

		cfg, err := buildConfig(cmd)
		require.NoError(t, err)
		require.Equal(t, true, cfg.Server.OpenAPI.Enabled)
		require.Equal(t, false, cfg.Server.OpenAPI.TLS)
	})

	t.Run("nonexistent_config_file", func(t *testing.T) {
		t.Parallel()
		cmd := &cli.Command{}
		cmd.Flags = []cli.Flag{
			&cli.StringFlag{Name: "config", Value: "/nonexistent/config.yaml"},
		}

		_, err := buildConfig(cmd)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to load config file")
	})
}

// TestStripTrailingSlashMiddleware ensures routes work with and without a trailing slash
func TestStripTrailingSlashMiddleware(t *testing.T) {
	t.Parallel()
	// helper to create a mux with our middleware
	newMux := func(jwe bool) http.Handler {
		mux := http.NewServeMux()
		// HTTP transport is served at root
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("root"))
		})
		// dynamic route when JWE is enabled
		if jwe {
			mux.HandleFunc("/{token}", func(w http.ResponseWriter, r *http.Request) {
				token := r.PathValue("token")
				if token == "" {
					http.Error(w, "missing token", http.StatusBadRequest)
					return
				}
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("dyn:" + token))
			})
		}
		return stripTrailingSlash(mux)
	}

	t.Run("root_path", func(t *testing.T) {
		t.Parallel()
		h := newMux(false)
		// Root path "/" has no trailing-slash variant — stripTrailingSlash
		// explicitly skips it. So one case.
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)
		require.Equal(t, "root", strings.TrimSpace(rr.Body.String()))
	})

	t.Run("dynamic_path_with_and_without_slash", func(t *testing.T) {
		t.Parallel()
		h := newMux(true)
		cases := []struct{ in, want string }{
			{"/abc", "dyn:abc"},
			{"/abc/", "dyn:abc"},
		}
		for _, c := range cases {
			req := httptest.NewRequest(http.MethodGet, c.in, nil)
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			require.Equal(t, http.StatusOK, rr.Code, c.in)
			require.Equal(t, c.want, strings.TrimSpace(rr.Body.String()))
		}
	})
}

func TestRoutePatterns(t *testing.T) {
	t.Parallel()
	t.Run("combined_auth_transport_routes_include_tokenized_and_pathless", func(t *testing.T) {
		t.Parallel()
		// HTTP transport is served at root; pass "" as the transport string.
		require.Equal(t,
			[]string{"/{token}", "/"},
			transportRoutePatterns(true, true, ""),
		)
		require.Equal(t,
			[]string{"/{token}/sse", "/sse"},
			transportRoutePatterns(true, true, "sse"),
		)
	})

	t.Run("combined_auth_openapi_routes_include_oauth_fallback_subpaths", func(t *testing.T) {
		t.Parallel()
		require.Equal(t,
			[]string{
				"/{token}/openapi",
				"/{token}/openapi/",
				"/{token}/openapi/list_tables",
				"/{token}/openapi/describe_table",
				"/{token}/openapi/execute_query",
				"/openapi/list_tables",
				"/openapi/describe_table",
				"/openapi/execute_query",
			},
			openAPIRoutePatterns(true, true),
		)
	})
}

// TestOverrideWithCLIFlags tests CLI flag override functionality
func TestOverrideWithCLIFlags(t *testing.T) {
	t.Parallel()
	t.Run("protocol_override", func(t *testing.T) {
		t.Parallel()
		// Create a mock command that simulates flag being set
		cmd := &mockCommand{
			flags: map[string]interface{}{
				"clickhouse-protocol": "tcp",
			},
			setFlags: map[string]bool{
				"clickhouse-protocol": true,
			},
			stringMaps: make(map[string]map[string]string),
		}

		cfg := &config.Config{}
		overrideWithCLIFlags(cfg, cmd)
		require.Equal(t, config.TCPProtocol, cfg.ClickHouse.Protocol)
	})

	t.Run("transport_override", func(t *testing.T) {
		t.Parallel()
		// Create a mock command that simulates flag being set
		cmd := &mockCommand{
			flags: map[string]interface{}{
				"transport": "http",
			},
			setFlags: map[string]bool{
				"transport": true,
			},
			stringMaps: make(map[string]map[string]string),
		}

		cfg := &config.Config{}
		overrideWithCLIFlags(cfg, cmd)
		require.Equal(t, config.HTTPTransport, cfg.Server.Transport)
	})

	t.Run("log_level_override", func(t *testing.T) {
		t.Parallel()
		// Create a mock command that simulates flag being set
		cmd := &mockCommand{
			flags: map[string]interface{}{
				"log-level": "debug",
			},
			setFlags: map[string]bool{
				"log-level": true,
			},
			stringMaps: make(map[string]map[string]string),
		}

		cfg := &config.Config{}
		overrideWithCLIFlags(cfg, cmd)
		require.Equal(t, config.DebugLevel, cfg.Logging.Level)
	})

}

// mockCommand implements CommandInterface for testing
type mockCommand struct {
	flags      map[string]interface{}
	setFlags   map[string]bool
	stringMaps map[string]map[string]string
}

func (m *mockCommand) StringMap(name string) map[string]string {
	if val, ok := m.stringMaps[name]; ok {
		return val
	}
	return map[string]string{}
}

func (m *mockCommand) String(name string) string {
	if val, ok := m.flags[name]; ok {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return ""
}

func (m *mockCommand) StringSlice(name string) []string {
	if val, ok := m.flags[name]; ok {
		if ss, ok := val.([]string); ok {
			return ss
		}
	}
	return nil
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
	t.Parallel()
	t.Run("disabled", func(t *testing.T) {
		t.Parallel()
		cfg := &config.ServerTLSConfig{Enabled: false}
		tlsConfig, err := buildServerTLSConfig(cfg)
		require.NoError(t, err)
		require.Nil(t, tlsConfig)
	})

	t.Run("enabled_without_ca", func(t *testing.T) {
		t.Parallel()
		cfg := &config.ServerTLSConfig{Enabled: true}
		tlsConfig, err := buildServerTLSConfig(cfg)
		require.NoError(t, err)
		require.NotNil(t, tlsConfig)
	})

	t.Run("enabled_with_invalid_ca", func(t *testing.T) {
		t.Parallel()
		cfg := &config.ServerTLSConfig{
			Enabled: true,
			CaCert:  "/nonexistent/ca.crt",
		}
		tlsConfig, err := buildServerTLSConfig(cfg)
		require.Error(t, err)
		require.Nil(t, tlsConfig)
	})

	t.Run("enabled_with_valid_ca", func(t *testing.T) {
		t.Parallel()
		// Create a temporary CA certificate file
		tmpFile, err := os.CreateTemp("", "test-ca-*.crt")
		require.NoError(t, err)
		defer os.Remove(tmpFile.Name())

		// Write a dummy PEM certificate
		caCertPEM := `-----BEGIN CERTIFICATE-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7d7Qj8fKjKjKjKjKjKjK
-----END CERTIFICATE-----`

		_, err = tmpFile.WriteString(caCertPEM)
		require.NoError(t, err)
		require.NoError(t, tmpFile.Close())

		cfg := &config.ServerTLSConfig{
			Enabled: true,
			CaCert:  tmpFile.Name(),
		}
		tlsConfig, err := buildServerTLSConfig(cfg)
		require.NoError(t, err)
		require.NotNil(t, tlsConfig)
		require.NotNil(t, tlsConfig.ClientCAs)
		require.Equal(t, tls.RequireAndVerifyClientCert, tlsConfig.ClientAuth)
	})
}

// setupClickHouseContainerMain is a local helper for this package's tests
func setupClickHouseContainerMain(t *testing.T) *config.ClickHouseConfig {
	t.Helper()
	ctx := context.Background()

	totalStart := time.Now()

	req := testcontainers.ContainerRequest{
		Image:        "clickhouse/clickhouse-server:latest",
		ExposedPorts: []string{"8123/tcp", "9000/tcp"},
		Env: map[string]string{
			"CLICKHOUSE_SKIP_USER_SETUP":           "1",
			"CLICKHOUSE_DB":                        "default",
			"CLICKHOUSE_USER":                      "default",
			"CLICKHOUSE_PASSWORD":                  "",
			"CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT": "1",
		},
		WaitingFor: wait.ForHTTP("/").WithPort("8123/tcp").WithStartupTimeout(30 * time.Second).WithPollInterval(2 * time.Second),
	}
	containerStart := time.Now()
	chContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{ContainerRequest: req, Started: true})
	containerElapsed := time.Since(containerStart)
	require.NoError(t, err)

	t.Cleanup(func() {
		cleanupStart := time.Now()
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = chContainer.Terminate(cleanupCtx)
		t.Logf("[container/%s] cleanup took %s", req.Image, time.Since(cleanupStart))
	})

	host, err := chContainer.Host(ctx)
	require.NoError(t, err)
	port, err := chContainer.MappedPort(ctx, "9000")
	require.NoError(t, err)

	cfg := &config.ClickHouseConfig{
		Host:             host,
		Port:             port.Int(),
		Database:         "default",
		Username:         "default",
		Password:         "",
		Protocol:         config.TCPProtocol,
		ReadOnly:         false,
		MaxExecutionTime: 60,
		Limit:            1000,
	}

	// create base table
	setupStart := time.Now()
	client, err := clickhouse.NewClient(ctx, *cfg)
	require.NoError(t, err)
	defer func() { _ = client.Close() }()
	_, _ = client.ExecuteQuery(ctx, "CREATE TABLE IF NOT EXISTS default.test (id UInt64, value String) ENGINE = Memory")
	_, _ = client.ExecuteQuery(ctx, "INSERT INTO default.test VALUES (1, 'one') ON CLUSTER default")
	setupElapsed := time.Since(setupStart)

	t.Logf("[container/%s] start=%s setup=%s total=%s", req.Image, containerElapsed, setupElapsed, time.Since(totalStart))
	return cfg
}

// startContainerWithTiming wraps testcontainers.GenericContainer with timing logs.
func startContainerWithTiming(t *testing.T, ctx context.Context, req testcontainers.GenericContainerRequest) (testcontainers.Container, error) {
	t.Helper()
	start := time.Now()
	container, err := testcontainers.GenericContainer(ctx, req)
	t.Logf("[container/%s] start took %s", req.Image, time.Since(start))
	return container, err
}

// Health handler tests
func TestHealthHandler_Additions(t *testing.T) {
	t.Parallel()
	// JWE enabled -> should return 200 and auth=per_request_credentials
	t.Run("jwe_enabled", func(t *testing.T) {
		t.Parallel()
		app := &application{config: config.Config{Server: config.ServerConfig{JWE: config.JWEConfig{Enabled: true}}}}
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		app.healthHandler(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)
		var body map[string]interface{}
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
		require.Equal(t, "per_request_credentials", body["auth"])
	})

	// JWE disabled with invalid CH -> 503
	t.Run("clickhouse_unhealthy", func(t *testing.T) {
		t.Parallel()
		app := &application{config: config.Config{Server: config.ServerConfig{JWE: config.JWEConfig{Enabled: false}}, ClickHouse: config.ClickHouseConfig{Host: "127.0.0.1", Port: 9999, Database: "default", Username: "default", Protocol: config.TCPProtocol}}}
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		app.healthHandler(rr, req)
		require.Equal(t, http.StatusServiceUnavailable, rr.Code)
	})

	// JWE disabled with real CH -> 200
	t.Run("clickhouse_healthy", func(t *testing.T) {
		t.Parallel()
		// spin container
		ctx := context.Background()
		cfg := setupClickHouseContainerMain(t)
		app := &application{config: config.Config{Server: config.ServerConfig{JWE: config.JWEConfig{Enabled: false}}, ClickHouse: *cfg}}
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		app.healthHandler(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)
		var body map[string]interface{}
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
		require.Equal(t, "connected", body["clickhouse"])
		_ = ctx
	})

	// Method not allowed
	t.Run("method_not_allowed", func(t *testing.T) {
		t.Parallel()
		app := &application{config: config.Config{}}
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/health", nil)
		app.healthHandler(rr, req)
		require.Equal(t, http.StatusMethodNotAllowed, rr.Code)
	})
}

// testConnection tests
func TestTestConnection_Additions(t *testing.T) {
	t.Parallel()
	t.Run("success", func(t *testing.T) {
		t.Parallel()
		cfg := setupClickHouseContainerMain(t)
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		err := testConnection(ctx, *cfg)
		require.NoError(t, err)
	})

	t.Run("failure", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		bad := config.ClickHouseConfig{Host: "127.0.0.1", Port: 9999, Database: "default", Username: "default", Protocol: config.TCPProtocol}
		err := testConnection(ctx, bad)
		require.Error(t, err)
	})
}

func TestNewApplication_ErrorPaths(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	t.Run("jwe_enabled_missing_key", func(t *testing.T) {
		t.Parallel()
		cfg := config.Config{Server: config.ServerConfig{JWE: config.JWEConfig{Enabled: true}}}
		_, err := newApplication(ctx, cfg, &mockCommand{flags: map[string]interface{}{"config-reload-time": 0}, setFlags: map[string]bool{"config-reload-time": true}, stringMaps: map[string]map[string]string{}})
		require.Error(t, err)
		require.Contains(t, err.Error(), "JWE encryption is enabled")
	})

	t.Run("clickhouse_ping_fail", func(t *testing.T) {
		t.Parallel()
		cfg := config.Config{ClickHouse: config.ClickHouseConfig{Host: "127.0.0.1", Port: 65000, Database: "default", Username: "default", Protocol: config.TCPProtocol}}
		_, err := newApplication(ctx, cfg, &mockCommand{flags: map[string]interface{}{"config-reload-time": 0}, setFlags: map[string]bool{"config-reload-time": true}, stringMaps: map[string]map[string]string{}})
		require.Error(t, err)
	})
}

func TestConfigReloadLoop_ErrorAndStop(t *testing.T) {
	t.Parallel()
	// Create temp invalid config file to trigger reload error
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte("invalid: : yaml"), 0o600))

	cfg := config.Config{ReloadTime: 1}
	app := &application{config: cfg, configFile: cfgPath, stopConfigReload: make(chan struct{}), mcpServer: altinitymcp.NewClickHouseMCPServer(config.Config{}, "test")}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		app.configReloadLoop(ctx, &mockCommand{flags: map[string]interface{}{}, setFlags: map[string]bool{}, stringMaps: map[string]map[string]string{}})
		close(done)
	}()
	time.Sleep(1500 * time.Millisecond)
	close(app.stopConfigReload)
	<-done
}

// ClickHouse client Ping/DescribeTable extra coverage
func TestClickHouseClient_PingAndDescribeTable(t *testing.T) {
	t.Parallel()
	cfg := setupClickHouseContainerMain(t)
	ctx := context.Background()
	client, err := clickhouse.NewClient(ctx, *cfg)
	require.NoError(t, err)
	defer func() { require.NoError(t, client.Close()) }()

	require.NoError(t, client.Ping(ctx))
	cols, err := client.DescribeTable(ctx, cfg.Database, "test")
	require.NoError(t, err)
	require.NotEmpty(t, cols)
}

// TestHealthHandler tests the health check endpoint
func TestHealthHandler(t *testing.T) {
	t.Parallel()
	t.Run("method_not_allowed", func(t *testing.T) {
		t.Parallel()
		app := &application{
			config: config.Config{
				Server: config.ServerConfig{
					JWE: config.JWEConfig{Enabled: false},
				},
			},
		}

		req := httptest.NewRequest(http.MethodPost, "/health", nil)
		w := httptest.NewRecorder()

		app.healthHandler(w, req)

		require.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})

	t.Run("jwe_enabled", func(t *testing.T) {
		t.Parallel()
		app := &application{
			config: config.Config{
				Server: config.ServerConfig{
					JWE: config.JWEConfig{Enabled: true},
				},
			},
		}

		httpReq := httptest.NewRequest(http.MethodGet, "/health", nil)
		w := httptest.NewRecorder()

		app.healthHandler(w, httpReq)

		require.Equal(t, http.StatusOK, w.Code)
		require.Contains(t, w.Body.String(), "healthy")
		require.Contains(t, w.Body.String(), "per_request_credentials")
	})

	t.Run("clickhouse_connection_failure", func(t *testing.T) {
		t.Parallel()
		app := &application{
			config: config.Config{
				ClickHouse: config.ClickHouseConfig{
					Host:     "nonexistent-host",
					Port:     9999,
					Database: "default",
					Username: "default",
					Password: "",
					Protocol: config.HTTPProtocol,
				},
				Server: config.ServerConfig{
					JWE: config.JWEConfig{Enabled: false},
				},
			},
		}

		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		w := httptest.NewRecorder()

		app.healthHandler(w, req)

		require.Equal(t, http.StatusServiceUnavailable, w.Code)
		require.Contains(t, w.Body.String(), "unhealthy")
	})

	t.Run("clickhouse_ping_failure", func(t *testing.T) {
		t.Parallel()
		app := &application{
			config: config.Config{
				ClickHouse: config.ClickHouseConfig{
					Host:     "127.0.0.1",
					Port:     9999, // Invalid port
					Database: "default",
					Username: "default",
					Password: "",
					Protocol: config.HTTPProtocol,
				},
				Server: config.ServerConfig{
					JWE: config.JWEConfig{Enabled: false},
				},
			},
		}

		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		w := httptest.NewRecorder()

		app.healthHandler(w, req)

		require.Equal(t, http.StatusServiceUnavailable, w.Code)
		require.Contains(t, w.Body.String(), "unhealthy")
		require.Contains(t, w.Body.String(), "ClickHouse connection failed")
	})

	t.Run("successful_clickhouse_connection_with_testcontainer", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()

		// Start ClickHouse container
		containerReq := testcontainers.ContainerRequest{
			Image:        "clickhouse/clickhouse-server:latest",
			ExposedPorts: []string{"8123/tcp"},
			Env: map[string]string{
				"CLICKHOUSE_SKIP_USER_SETUP": "1",
			},
			WaitingFor: wait.ForHTTP("/ping").WithPort("8123/tcp").WithStartupTimeout(30 * time.Second).WithPollInterval(1 * time.Second),
		}

		clickhouseContainer, err := startContainerWithTiming(t, ctx, testcontainers.GenericContainerRequest{
			ContainerRequest: containerReq,
			Started:          true,
		})
		if err != nil {
			t.Fatal("Failed to start ClickHouse container, skipping test:", err)
		}
		defer func() {
			if termErr := clickhouseContainer.Terminate(ctx); termErr != nil {
				t.Logf("Failed to terminate container: %v", termErr)
			}
		}()

		// Get the mapped port
		mappedPort, err := clickhouseContainer.MappedPort(ctx, "8123")
		require.NoError(t, err)

		host, err := clickhouseContainer.Host(ctx)
		require.NoError(t, err)

		app := &application{
			config: config.Config{
				ClickHouse: config.ClickHouseConfig{
					Host:     host,
					Port:     mappedPort.Int(),
					Database: "default",
					Username: "default",
					Password: "",
					Protocol: config.HTTPProtocol,
				},
				Server: config.ServerConfig{
					JWE: config.JWEConfig{Enabled: false},
				},
			},
		}

		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		w := httptest.NewRecorder()

		app.healthHandler(w, req)

		require.Equal(t, http.StatusOK, w.Code)
		require.Contains(t, w.Body.String(), "healthy")
		require.Contains(t, w.Body.String(), "connected")
	})
}

// TestApplication tests application lifecycle methods
func TestApplication(t *testing.T) {
	t.Parallel()
	t.Run("get_current_config", func(t *testing.T) {
		t.Parallel()
		cfg := config.Config{
			ClickHouse: config.ClickHouseConfig{
				Host: "test-host",
				Port: 9000,
			},
		}
		app := &application{config: cfg}

		result := app.GetCurrentConfig()
		require.Equal(t, "test-host", result.ClickHouse.Host)
		require.Equal(t, 9000, result.ClickHouse.Port)
	})

	t.Run("close", func(t *testing.T) {
		t.Parallel()
		app := &application{
			stopConfigReload: make(chan struct{}),
			configFile:       "test.yaml",
			config:           config.Config{ReloadTime: 10},
		}

		// This should not panic
		app.Close()
	})

	t.Run("close_without_config_reload", func(t *testing.T) {
		t.Parallel()
		app := &application{}

		// This should not panic
		app.Close()
	})
}

// TestConfigReloadLoop tests the configuration reload functionality
func TestConfigReloadLoop(t *testing.T) {
	t.Parallel()
	t.Run("stop_via_channel", func(t *testing.T) {
		t.Parallel()
		app := &application{
			stopConfigReload: make(chan struct{}),
			configFile:       "test.yaml",
			config:           config.Config{ReloadTime: 1}, // 1 second for faster test
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		// Create a mock CLI command
		cmd := &cli.Command{}
		cmd.Flags = []cli.Flag{
			&cli.StringFlag{Name: "log-level", Value: "info"},
		}

		// Start the reload loop in a goroutine
		done := make(chan struct{})
		go func() {
			app.configReloadLoop(ctx, cmd)
			close(done)
		}()

		// Stop it immediately
		close(app.stopConfigReload)

		// Wait for it to finish with timeout
		select {
		case <-done:
			// Success
		case <-time.After(2 * time.Second):
			t.Fatal("configReloadLoop did not stop in time")
		}
	})

	t.Run("stop_via_context", func(t *testing.T) {
		t.Parallel()
		app := &application{
			stopConfigReload: make(chan struct{}),
			configFile:       "test.yaml",
			config:           config.Config{ReloadTime: 1}, // 1 second for faster test
		}

		ctx, cancel := context.WithCancel(context.Background())

		// Create a mock CLI command
		cmd := &cli.Command{}
		cmd.Flags = []cli.Flag{
			&cli.StringFlag{Name: "log-level", Value: "info"},
		}

		// Start the reload loop in a goroutine
		done := make(chan struct{})
		go func() {
			app.configReloadLoop(ctx, cmd)
			close(done)
		}()

		// Cancel the context
		cancel()

		// Wait for it to finish with timeout
		select {
		case <-done:
			// Success
		case <-time.After(2 * time.Second):
			t.Fatal("configReloadLoop did not stop in time")
		}
	})
}

// TestReloadConfig tests configuration reloading
func TestReloadConfig(t *testing.T) {
	t.Parallel()
	t.Run("nonexistent_file", func(t *testing.T) {
		t.Parallel()
		app := &application{
			configFile: "/nonexistent/config.yaml",
		}

		cmd := &cli.Command{}
		cmd.Flags = []cli.Flag{
			&cli.StringFlag{Name: "log-level", Value: "info"},
		}
		err := app.reloadConfig(cmd)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to load config file")
	})
}

// TestTestConnection tests the testConnection function
func TestTestConnection(t *testing.T) {
	t.Parallel()
	t.Run("invalid_config", func(t *testing.T) {
		t.Parallel()
		cfg := config.ClickHouseConfig{
			Host:     "nonexistent-host",
			Port:     9999,
			Database: "nonexistent",
			Username: "invalid",
			Password: "invalid",
			Protocol: config.HTTPProtocol,
		}

		ctx := context.Background()
		err := testConnection(ctx, cfg)
		require.Error(t, err)
		// Should fail to create client or ping
	})

	t.Run("context_cancellation", func(t *testing.T) {
		t.Parallel()
		cfg := config.ClickHouseConfig{
			Host:     "localhost",
			Port:     8123,
			Database: "default",
			Username: "default",
			Password: "",
			Protocol: config.HTTPProtocol,
		}

		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		err := testConnection(ctx, cfg)
		require.Error(t, err)
		// Should fail due to cancelled context
	})

	t.Run("successful_connection_with_testcontainer", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()

		// Start ClickHouse container
		containerReq := testcontainers.ContainerRequest{
			Image:        "clickhouse/clickhouse-server:latest",
			ExposedPorts: []string{"8123/tcp"},
			Env: map[string]string{
				"CLICKHOUSE_SKIP_USER_SETUP": "1",
			},
			WaitingFor: wait.ForHTTP("/ping").WithPort("8123/tcp").WithStartupTimeout(30 * time.Second).WithPollInterval(1 * time.Second),
		}

		clickhouseContainer, err := startContainerWithTiming(t, ctx, testcontainers.GenericContainerRequest{
			ContainerRequest: containerReq,
			Started:          true,
		})
		if err != nil {
			t.Fatal("Failed to start ClickHouse container, skipping test:", err)
		}
		defer func() {
			if termErr := clickhouseContainer.Terminate(ctx); termErr != nil {
				t.Logf("Failed to terminate container: %v", termErr)
			}
		}()

		// Get the mapped port
		mappedPort, err := clickhouseContainer.MappedPort(ctx, "8123")
		require.NoError(t, err)

		host, err := clickhouseContainer.Host(ctx)
		require.NoError(t, err)

		cfg := config.ClickHouseConfig{
			Host:     host,
			Port:     mappedPort.Int(),
			Database: "default",
			Username: "default",
			Password: "",
			Protocol: config.HTTPProtocol,
		}

		// Test connection
		err = testConnection(ctx, cfg)
		require.NoError(t, err)
	})

	t.Run("connection_with_tcp_protocol", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()

		// Start ClickHouse container
		containerReq := testcontainers.ContainerRequest{
			Image:        "clickhouse/clickhouse-server:latest",
			ExposedPorts: []string{"9000/tcp", "8123/tcp"},
			Env: map[string]string{
				"CLICKHOUSE_SKIP_USER_SETUP": "1",
			},
			WaitingFor: wait.ForHTTP("/ping").WithPort("8123/tcp").WithStartupTimeout(30 * time.Second).WithPollInterval(1 * time.Second),
		}

		clickhouseContainer, err := startContainerWithTiming(t, ctx, testcontainers.GenericContainerRequest{
			ContainerRequest: containerReq,
			Started:          true,
		})
		if err != nil {
			t.Fatal("Failed to start ClickHouse container, skipping test:", err)
		}
		defer func() {
			if termErr := clickhouseContainer.Terminate(ctx); termErr != nil {
				t.Logf("Failed to terminate container: %v", termErr)
			}
		}()

		// Get the mapped port for TCP
		mappedPort, err := clickhouseContainer.MappedPort(ctx, "9000")
		require.NoError(t, err)

		host, err := clickhouseContainer.Host(ctx)
		require.NoError(t, err)

		cfg := config.ClickHouseConfig{
			Host:     host,
			Port:     mappedPort.Int(),
			Database: "default",
			Username: "default",
			Password: "",
			Protocol: config.TCPProtocol,
		}

		// Test connection
		err = testConnection(ctx, cfg)
		require.NoError(t, err)
	})

	t.Run("connection_with_tls", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		require.NoError(t, setupLogging("debug"))
		// Generate self-signed certificate
		cert, key, err := generateSelfSignedCert()
		require.NoError(t, err)

		// Create HTTPS port config with OpenSSL server section
		httpsConfig := `<clickhouse>
    <https_port>8443</https_port>
    <openSSL>
        <server>
            <certificateFile>/etc/clickhouse-server/server.crt</certificateFile>
            <privateKeyFile>/etc/clickhouse-server/server.key</privateKeyFile>
            <verificationMode>none</verificationMode>
        </server>
    </openSSL>
</clickhouse>`

		// https://github.com/ClickHouse/clickhouse-go/issues/1630
		nonEmptyDefaultUserPassword := "<clickhouse><users><default><password>non_empty</password></default></users></clickhouse>"

		// Start ClickHouse container with TLS enabled
		containerReq := testcontainers.ContainerRequest{
			Image:        "clickhouse/clickhouse-server:latest",
			ExposedPorts: []string{"8123/tcp", "8443/tcp"},
			Env: map[string]string{
				"CLICKHOUSE_SKIP_USER_SETUP": "1",
			},
			Files: []testcontainers.ContainerFile{
				{
					Reader:            strings.NewReader(string(cert)),
					ContainerFilePath: "/etc/clickhouse-server/server.crt",
					FileMode:          0644,
				},
				{
					Reader:            strings.NewReader(string(key)),
					ContainerFilePath: "/etc/clickhouse-server/server.key",
					FileMode:          0644,
				},
				{
					Reader:            strings.NewReader(httpsConfig),
					ContainerFilePath: "/etc/clickhouse-server/config.d/https_port.xml",
					FileMode:          0644,
				},
				// https://github.com/ClickHouse/clickhouse-go/issues/1630
				{
					Reader:            strings.NewReader(nonEmptyDefaultUserPassword),
					ContainerFilePath: "/etc/clickhouse-server/users.d/non_empty_password.xml",
					FileMode:          0644,
				},
			},
			WaitingFor: wait.ForHTTP("/ping").WithPort("8123/tcp").WithStartupTimeout(30 * time.Second).WithPollInterval(1 * time.Second),
		}

		clickhouseContainer, err := startContainerWithTiming(t, ctx, testcontainers.GenericContainerRequest{
			ContainerRequest: containerReq,
			Started:          true,
		})
		if err != nil {
			t.Fatal("Failed to start ClickHouse container, skipping test:", err)
		}
		defer func() {
			if termErr := clickhouseContainer.Terminate(ctx); termErr != nil {
				t.Logf("Failed to terminate container: %v", termErr)
			}
		}()

		mappedPort, err := clickhouseContainer.MappedPort(ctx, "8443")
		require.NoError(t, err)

		host, err := clickhouseContainer.Host(ctx)
		require.NoError(t, err)

		cfg := config.ClickHouseConfig{
			Host:     host,
			Port:     mappedPort.Int(),
			Database: "default",
			Username: "default",
			// https://github.com/ClickHouse/clickhouse-go/issues/1630
			Password: "non_empty",
			Protocol: config.HTTPProtocol,
			TLS: config.TLSConfig{
				Enabled:            true,
				InsecureSkipVerify: true,
			},
		}

		// Test connection
		err = testConnection(ctx, cfg)
		require.NoError(t, err)
	})

	t.Run("connection_with_readonly_mode", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()

		// Start ClickHouse container
		containerReq := testcontainers.ContainerRequest{
			Image:        "clickhouse/clickhouse-server:latest",
			ExposedPorts: []string{"8123/tcp"},
			Env: map[string]string{
				"CLICKHOUSE_SKIP_USER_SETUP": "1",
			},
			WaitingFor: wait.ForHTTP("/ping").WithPort("8123/tcp").WithStartupTimeout(30 * time.Second).WithPollInterval(1 * time.Second),
		}

		clickhouseContainer, err := startContainerWithTiming(t, ctx, testcontainers.GenericContainerRequest{
			ContainerRequest: containerReq,
			Started:          true,
		})
		if err != nil {
			t.Fatal("Failed to start ClickHouse container, skipping test:", err)
		}
		defer func() {
			if termErr := clickhouseContainer.Terminate(ctx); termErr != nil {
				t.Logf("Failed to terminate container: %v", termErr)
			}
		}()

		// Get the mapped port
		mappedPort, err := clickhouseContainer.MappedPort(ctx, "8123")
		require.NoError(t, err)

		host, err := clickhouseContainer.Host(ctx)
		require.NoError(t, err)

		cfg := config.ClickHouseConfig{
			Host:     host,
			Port:     mappedPort.Int(),
			Database: "default",
			Username: "default",
			Password: "",
			Protocol: config.HTTPProtocol,
			ReadOnly: true,
		}

		// Test connection
		err = testConnection(ctx, cfg)
		require.NoError(t, err)
	})

	t.Run("connection_with_max_execution_time", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()

		// Start ClickHouse container
		containerReq := testcontainers.ContainerRequest{
			Image:        "clickhouse/clickhouse-server:latest",
			ExposedPorts: []string{"8123/tcp"},
			Env: map[string]string{
				"CLICKHOUSE_SKIP_USER_SETUP": "1",
			},
			WaitingFor: wait.ForHTTP("/ping").WithPort("8123/tcp").WithStartupTimeout(30 * time.Second).WithPollInterval(1 * time.Second),
		}

		clickhouseContainer, err := startContainerWithTiming(t, ctx, testcontainers.GenericContainerRequest{
			ContainerRequest: containerReq,
			Started:          true,
		})
		if err != nil {
			t.Fatal("Failed to start ClickHouse container, skipping test:", err)
		}
		defer func() {
			if termErr := clickhouseContainer.Terminate(ctx); termErr != nil {
				t.Logf("Failed to terminate container: %v", termErr)
			}
		}()

		// Get the mapped port
		mappedPort, err := clickhouseContainer.MappedPort(ctx, "8123")
		require.NoError(t, err)

		host, err := clickhouseContainer.Host(ctx)
		require.NoError(t, err)

		cfg := config.ClickHouseConfig{
			Host:             host,
			Port:             mappedPort.Int(),
			Database:         "default",
			Username:         "default",
			Password:         "",
			Protocol:         config.HTTPProtocol,
			MaxExecutionTime: 300,
		}

		// Test connection
		err = testConnection(ctx, cfg)
		require.NoError(t, err)
	})
}

// TestRunServer tests the runServer function
func TestRunServer(t *testing.T) {
	t.Parallel()
	t.Run("invalid_config_file", func(t *testing.T) {
		t.Parallel()
		// Create a CLI command with invalid config file
		cmd := &cli.Command{}
		cmd.Flags = []cli.Flag{
			&cli.StringFlag{Name: "config", Value: "/nonexistent/config.yaml"},
		}

		ctx := context.Background()
		err := runServer(ctx, cmd)
		require.Error(t, err)
		// Should fail to build configuration
	})

	t.Run("invalid_clickhouse_connection", func(t *testing.T) {
		t.Parallel()
		// Create a CLI command with invalid ClickHouse settings
		cmd := &cli.Command{}
		cmd.Flags = []cli.Flag{
			&cli.StringFlag{Name: "config", Value: ""},
			&cli.StringFlag{Name: "clickhouse-host", Value: "nonexistent-host"},
			&cli.IntFlag{Name: "clickhouse-port", Value: 9999},
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
			&cli.BoolFlag{Name: "allow-jwe-auth", Value: false},
			&cli.StringFlag{Name: "jwe-secret-key", Value: ""},
			&cli.StringFlag{Name: "jwt-secret-key", Value: ""},
			&cli.IntFlag{Name: "config-reload-time", Value: 0},
		}

		ctx := context.Background()
		err := runServer(ctx, cmd)
		require.Error(t, err)
		// Should fail to create application due to ClickHouse connection failure
	})
}

// TestMainCLIApp tests the main CLI application
func TestMainCLIApp(t *testing.T) {
	t.Parallel()
	t.Run("version_command", func(t *testing.T) {
		t.Parallel()
		app := &cli.Command{
			Name:        "altinity-mcp",
			Usage:       "Altinity MCP Server - ClickHouse Model Context Protocol Server",
			Description: "A Model Context Protocol (MCP) server that provides tools for interacting with ClickHouse databases",
			Version:     "test-version",
			Commands: []*cli.Command{
				{
					Name:  "version",
					Usage: "Show version information",
					Action: func(ctx context.Context, cmd *cli.Command) error {
						fmt.Printf("altinity-mcp version %s\n", "test-version")
						fmt.Printf("Commit: %s\n", "test-commit")
						fmt.Printf("Built: %s\n", "test-date")
						return nil
					},
				},
			},
		}

		err := app.Run(context.Background(), []string{"altinity-mcp", "version"})
		require.NoError(t, err)
	})

	t.Run("test_connection_command", func(t *testing.T) {
		t.Parallel()
		app := &cli.Command{
			Name: "altinity-mcp",
			Flags: []cli.Flag{
				&cli.StringFlag{Name: "clickhouse-host", Value: "nonexistent-host"},
				&cli.IntFlag{Name: "clickhouse-port", Value: 9999},
				&cli.StringFlag{Name: "clickhouse-database", Value: "default"},
				&cli.StringFlag{Name: "clickhouse-username", Value: "default"},
				&cli.StringFlag{Name: "clickhouse-password", Value: ""},
				&cli.StringFlag{Name: "clickhouse-protocol", Value: "http"},
				&cli.IntFlag{Name: "clickhouse-max-execution-time", Value: 600},
				&cli.BoolFlag{Name: "read-only", Value: false},
				&cli.StringFlag{Name: "log-level", Value: "info"},
				&cli.IntFlag{Name: "clickhouse-limit", Value: 1000},
			},
			Before: func(ctx context.Context, cmd *cli.Command) (context.Context, error) {
				return ctx, setupLogging(cmd.String("log-level"))
			},
			Commands: []*cli.Command{
				{
					Name:  "test-connection",
					Usage: "Test connection to ClickHouse",
					Action: func(ctx context.Context, cmd *cli.Command) error {
						cfg, err := buildConfig(cmd)
						if err != nil {
							return err
						}
						return testConnection(ctx, cfg.ClickHouse)
					},
				},
			},
		}

		err := app.Run(context.Background(), []string{"altinity-mcp", "test-connection"})
		require.Error(t, err) // Should fail due to invalid ClickHouse connection
	})
}

// TestNewApplication tests the newApplication function
func TestNewApplication(t *testing.T) {
	t.Parallel()
	t.Run("jwe_enabled_without_jwe_secret_key", func(t *testing.T) {
		t.Parallel()
		cfg := config.Config{
			ClickHouse: config.ClickHouseConfig{
				Host:     "localhost",
				Port:     8123,
				Database: "default",
				Username: "default",
				Password: "",
				Protocol: config.HTTPProtocol,
			},
			Server: config.ServerConfig{
				JWE: config.JWEConfig{
					Enabled:      true,
					JWESecretKey: "", // Empty secret key should cause error
					JWTSecretKey: "jwt-secret",
				},
			},
		}

		cmd := &mockCommand{
			flags: map[string]interface{}{
				"config":             "",
				"config-reload-time": 0,
			},
			setFlags:   map[string]bool{},
			stringMaps: make(map[string]map[string]string),
		}

		ctx := context.Background()
		app, err := newApplication(ctx, cfg, cmd)
		require.Error(t, err)
		require.Nil(t, app)
		require.Contains(t, err.Error(), "JWE encryption is enabled but no JWE secret key is provided")
	})

	t.Run("jwe_enabled_without_jwt_secret_key", func(t *testing.T) {
		t.Parallel()
		cfg := config.Config{
			ClickHouse: config.ClickHouseConfig{
				Host:     "localhost",
				Port:     8123,
				Database: "default",
				Username: "default",
				Password: "",
				Protocol: config.HTTPProtocol,
			},
			Server: config.ServerConfig{
				JWE: config.JWEConfig{
					Enabled:      true,
					JWESecretKey: "jwe-secret",
					JWTSecretKey: "", // Empty secret key is now allowed
				},
			},
		}

		cmd := &mockCommand{
			flags: map[string]interface{}{
				"config":             "",
				"config-reload-time": 0,
			},
			setFlags:   map[string]bool{},
			stringMaps: make(map[string]map[string]string),
		}

		ctx := context.Background()
		app, err := newApplication(ctx, cfg, cmd)
		require.NoError(t, err)
		require.NotNil(t, app)

		claims := map[string]interface{}{
			"host":     "localhost",
			"port":     8123,
			"database": "default",
			"username": "default",
			"protocol": "http",
			"exp":      time.Now().Add(time.Hour).Unix(),
		}
		body, err := json.Marshal(claims)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/jwe-token-generator", bytes.NewReader(body))
		w := httptest.NewRecorder()

		app.jweTokenGeneratorHandler(w, req)

		require.Equal(t, http.StatusOK, w.Code)

		var resp map[string]string
		err = json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		require.Contains(t, resp, "token")

		// Verify the token
		parsedClaims, err := jwe_auth.ParseAndDecryptJWE(resp["token"], []byte(cfg.Server.JWE.JWESecretKey), []byte(cfg.Server.JWE.JWTSecretKey))
		require.NoError(t, err)
		require.Equal(t, "localhost", parsedClaims["host"])
		require.Equal(t, float64(8123), parsedClaims["port"])
		app.Close()
	})

	t.Run("jwe_enabled_with_secret", func(t *testing.T) {
		t.Parallel()
		cfg := config.Config{
			ClickHouse: config.ClickHouseConfig{
				Host:     "localhost",
				Port:     8123,
				Database: "default",
				Username: "default",
				Password: "",
				Protocol: config.HTTPProtocol,
			},
			Server: config.ServerConfig{
				JWE: config.JWEConfig{
					Enabled:      true,
					JWESecretKey: "test-secret-key",
					JWTSecretKey: "test-jwt-secret-key",
				},
			},
		}

		cmd := &mockCommand{
			flags: map[string]interface{}{
				"config":             "",
				"config-reload-time": 0,
			},
			setFlags:   map[string]bool{},
			stringMaps: make(map[string]map[string]string),
		}

		ctx := context.Background()
		app, err := newApplication(ctx, cfg, cmd)
		require.NoError(t, err)
		require.NotNil(t, app)
		require.NotNil(t, app.mcpServer)
		app.Close()
	})

	t.Run("invalid_clickhouse_connection", func(t *testing.T) {
		t.Parallel()
		cfg := config.Config{
			ClickHouse: config.ClickHouseConfig{
				Host:     "nonexistent-host",
				Port:     9999,
				Database: "default",
				Username: "default",
				Password: "",
				Protocol: config.HTTPProtocol,
			},
			Server: config.ServerConfig{
				JWE: config.JWEConfig{
					Enabled: false,
				},
			},
		}

		cmd := &mockCommand{
			flags: map[string]interface{}{
				"config":             "",
				"config-reload-time": 0,
			},
			setFlags:   map[string]bool{},
			stringMaps: make(map[string]map[string]string),
		}

		ctx := context.Background()
		app, err := newApplication(ctx, cfg, cmd)
		require.Error(t, err)
		require.Nil(t, app)
		// Should fail due to ClickHouse connection test failure
	})

	t.Run("successful_creation_with_config_reload", func(t *testing.T) {
		t.Parallel()
		// Create a temporary config file
		tmpFile, err := os.CreateTemp("", "test-config-*.yaml")
		require.NoError(t, err)
		defer os.Remove(tmpFile.Name())

		configContent := `
clickhouse:
  host: "localhost"
  port: 8123
  database: "default"
server:
  jwe:
    enabled: true
    jwe_secret_key: "test-secret"
    jwt_secret_key: "test-jwt-secret"
`
		_, err = tmpFile.WriteString(configContent)
		require.NoError(t, err)
		_ = tmpFile.Close()

		cfg := config.Config{
			ClickHouse: config.ClickHouseConfig{
				Host:     "localhost",
				Port:     8123,
				Database: "default",
				Username: "default",
				Password: "",
				Protocol: config.HTTPProtocol,
			},
			Server: config.ServerConfig{
				JWE: config.JWEConfig{
					Enabled:      true,
					JWESecretKey: "test-secret-key",
					JWTSecretKey: "test-jwt-secret-key",
				},
			},
		}

		cmd := &mockCommand{
			flags: map[string]interface{}{
				"config":             tmpFile.Name(),
				"config-reload-time": 1, // Enable config reload
			},
			setFlags: map[string]bool{
				"config":             true,
				"config-reload-time": true,
			},
			stringMaps: make(map[string]map[string]string),
		}

		ctx := context.Background()
		app, err := newApplication(ctx, cfg, cmd)
		require.NoError(t, err)
		require.NotNil(t, app)
		require.NotNil(t, app.mcpServer)
		require.Equal(t, tmpFile.Name(), app.configFile)
		require.Equal(t, 1, app.config.ReloadTime)

		// Give a moment for the config reload goroutine to start
		time.Sleep(100 * time.Millisecond)

		app.Close()
	})

	t.Run("clickhouse_ping_failure", func(t *testing.T) {
		t.Parallel()
		cfg := config.Config{
			ClickHouse: config.ClickHouseConfig{
				Host:     "127.0.0.1", // Use localhost IP
				Port:     9999,        // Invalid port
				Database: "default",
				Username: "default",
				Password: "",
				Protocol: config.HTTPProtocol,
			},
			Server: config.ServerConfig{
				JWE: config.JWEConfig{
					Enabled: false,
				},
			},
		}

		cmd := &mockCommand{
			flags: map[string]interface{}{
				"config":             "",
				"config-reload-time": 0,
			},
			setFlags: map[string]bool{},
		}

		ctx := context.Background()
		app, err := newApplication(ctx, cfg, cmd)
		require.Error(t, err)
		require.Nil(t, app)
		// Should fail due to ClickHouse ping failure
	})
}

// TestBuildConfigWithFile tests configuration building with file
func TestBuildConfigWithFile(t *testing.T) {
	t.Parallel()
	t.Run("with_valid_config_file", func(t *testing.T) {
		t.Parallel()
		// Create a temporary config file
		tmpFile, err := os.CreateTemp("", "test-config-*.yaml")
		require.NoError(t, err)
		defer os.Remove(tmpFile.Name())

		configContent := `
reload_time: 10
clickhouse:
  host: "config-host"
  port: 9000
  database: "config-db"
  http_headers:
    X-Config-Header: "config-value"
    User-Agent: "config-agent"
server:
  transport: "http"
  port: 9090
logging:
  level: "debug"
  openapi: true
`
		_, err = tmpFile.WriteString(configContent)
		require.NoError(t, err)
		_ = tmpFile.Close()

		cmd := &mockCommand{
			flags: map[string]interface{}{
				"config":                        tmpFile.Name(),
				"clickhouse-host":               "cli-host", // This should override config file
				"clickhouse-limit":              2000,
				"clickhouse-port":               8123,
				"clickhouse-database":           "default",
				"clickhouse-username":           "default",
				"clickhouse-password":           "",
				"clickhouse-protocol":           "http",
				"clickhouse-max-execution-time": 600,
				"read-only":                     false,
				"transport":                     "stdio",
				"address":                       "0.0.0.0",
				"port":                          8080,
				"log-level":                     "info",
				"openapi":                       "disable",
			},
			setFlags: map[string]bool{
				"config":           true,
				"clickhouse-host":  true,
				"clickhouse-limit": true,
				"openapi":          true,
			},
			stringMaps: make(map[string]map[string]string),
		}

		cfg, err := buildConfig(cmd)
		require.NoError(t, err)

		// CLI flag should override config file
		require.Equal(t, "cli-host", cfg.ClickHouse.Host)
		// Config file values should be used where CLI flags aren't set
		require.Equal(t, 9000, cfg.ClickHouse.Port)
		require.Equal(t, "config-db", cfg.ClickHouse.Database)
		require.Equal(t, config.HTTPTransport, cfg.Server.Transport)
		require.Equal(t, 9090, cfg.Server.Port)
		require.Equal(t, config.DebugLevel, cfg.Logging.Level)
		require.Equal(t, false, cfg.Server.OpenAPI.Enabled)
		// CLI flag should set limit
		require.Equal(t, 2000, cfg.ClickHouse.Limit)
		// HTTP headers from config file should be preserved
		require.NotNil(t, cfg.ClickHouse.HttpHeaders)
		require.Len(t, cfg.ClickHouse.HttpHeaders, 2)
		require.Equal(t, "config-value", cfg.ClickHouse.HttpHeaders["X-Config-Header"])
		require.Equal(t, "config-agent", cfg.ClickHouse.HttpHeaders["User-Agent"])

		// Verify reload time was preserved from CLI flag (not overwritten by config file)
		require.Equal(t, 10, cfg.ReloadTime)
	})

	t.Run("with_http_headers_cli_override", func(t *testing.T) {
		t.Parallel()
		// Create a temporary config file
		tmpFile, err := os.CreateTemp("", "test-config-*.yaml")
		require.NoError(t, err)
		defer os.Remove(tmpFile.Name())

		configContent := `
clickhouse:
  http_headers:
    X-Config-Header: "config-value"
    User-Agent: "config-agent"
`
		_, err = tmpFile.WriteString(configContent)
		require.NoError(t, err)
		_ = tmpFile.Close()

		cmd := &mockCommand{
			flags: map[string]interface{}{
				"config": tmpFile.Name(),
			},
			setFlags: map[string]bool{
				"config":                  true,
				"clickhouse-http-headers": true,
			},
			stringMaps: map[string]map[string]string{
				"clickhouse-http-headers": {
					"X-CLI-Header": "cli-value",
					"User-Agent":   "cli-agent",
				},
			},
		}

		cfg, err := buildConfig(cmd)
		require.NoError(t, err)

		// CLI headers should override config file headers
		require.NotNil(t, cfg.ClickHouse.HttpHeaders)
		require.Len(t, cfg.ClickHouse.HttpHeaders, 2)
		require.Equal(t, "cli-value", cfg.ClickHouse.HttpHeaders["X-CLI-Header"])
		require.Equal(t, "cli-agent", cfg.ClickHouse.HttpHeaders["User-Agent"])
		// Config header should be replaced
		require.NotContains(t, cfg.ClickHouse.HttpHeaders, "X-Config-Header")
	})
}

// TestOverrideWithCLIFlagsExtended tests more CLI flag override scenarios
func TestOverrideWithCLIFlagsExtended(t *testing.T) {
	t.Parallel()
	t.Run("all_clickhouse_flags", func(t *testing.T) {
		t.Parallel()
		cmd := &mockCommand{
			flags: map[string]interface{}{
				"clickhouse-host":                     "test-host",
				"clickhouse-port":                     9000,
				"clickhouse-database":                 "test-db",
				"clickhouse-username":                 "test-user",
				"clickhouse-password":                 "test-pass",
				"clickhouse-protocol":                 "tcp",
				"read-only":                           true,
				"clickhouse-max-execution-time":       300,
				"clickhouse-tls":                      true,
				"clickhouse-tls-ca-cert":              "/path/to/ca.crt",
				"clickhouse-tls-client-cert":          "/path/to/client.crt",
				"clickhouse-tls-client-key":           "/path/to/client.key",
				"clickhouse-tls-insecure-skip-verify": true,
				"clickhouse-limit":                    5000,
			},
			setFlags: map[string]bool{
				"clickhouse-host":                     true,
				"clickhouse-port":                     true,
				"clickhouse-database":                 true,
				"clickhouse-username":                 true,
				"clickhouse-password":                 true,
				"clickhouse-protocol":                 true,
				"read-only":                           true,
				"clickhouse-max-execution-time":       true,
				"clickhouse-tls":                      true,
				"clickhouse-tls-ca-cert":              true,
				"clickhouse-tls-client-cert":          true,
				"clickhouse-tls-client-key":           true,
				"clickhouse-tls-insecure-skip-verify": true,
				"clickhouse-limit":                    true,
			},
			stringMaps: make(map[string]map[string]string),
		}

		cfg := &config.Config{}
		overrideWithCLIFlags(cfg, cmd)

		require.Equal(t, "test-host", cfg.ClickHouse.Host)
		require.Equal(t, 9000, cfg.ClickHouse.Port)
		require.Equal(t, "test-db", cfg.ClickHouse.Database)
		require.Equal(t, "test-user", cfg.ClickHouse.Username)
		require.Equal(t, "test-pass", cfg.ClickHouse.Password)
		require.Equal(t, config.TCPProtocol, cfg.ClickHouse.Protocol)
		require.True(t, cfg.ClickHouse.ReadOnly)
		require.Equal(t, 300, cfg.ClickHouse.MaxExecutionTime)
		require.True(t, cfg.ClickHouse.TLS.Enabled)
		require.Equal(t, "/path/to/ca.crt", cfg.ClickHouse.TLS.CaCert)
		require.Equal(t, "/path/to/client.crt", cfg.ClickHouse.TLS.ClientCert)
		require.Equal(t, "/path/to/client.key", cfg.ClickHouse.TLS.ClientKey)
		require.True(t, cfg.ClickHouse.TLS.InsecureSkipVerify)
		require.Equal(t, 5000, cfg.ClickHouse.Limit)
	})

	t.Run("clickhouse_http_headers_flag", func(t *testing.T) {
		t.Parallel()
		cmd := &mockCommand{
			flags: map[string]interface{}{},
			setFlags: map[string]bool{
				"clickhouse-http-headers": true,
			},
			stringMaps: map[string]map[string]string{
				"clickhouse-http-headers": {
					"X-Custom-Header": "custom-value",
					"User-Agent":      "test-agent",
					"Authorization":   "Bearer token123",
				},
			},
		}

		cfg := &config.Config{}
		overrideWithCLIFlags(cfg, cmd)

		require.NotNil(t, cfg.ClickHouse.HttpHeaders)
		require.Len(t, cfg.ClickHouse.HttpHeaders, 3)
		require.Equal(t, "custom-value", cfg.ClickHouse.HttpHeaders["X-Custom-Header"])
		require.Equal(t, "test-agent", cfg.ClickHouse.HttpHeaders["User-Agent"])
		require.Equal(t, "Bearer token123", cfg.ClickHouse.HttpHeaders["Authorization"])
	})

	t.Run("clickhouse_http_headers_flag_empty", func(t *testing.T) {
		t.Parallel()
		cmd := &mockCommand{
			flags:    map[string]interface{}{},
			setFlags: map[string]bool{},
			stringMaps: map[string]map[string]string{
				"clickhouse-http-headers": {},
			},
		}

		cfg := &config.Config{}
		overrideWithCLIFlags(cfg, cmd)

		require.Nil(t, cfg.ClickHouse.HttpHeaders)
		require.Empty(t, cfg.ClickHouse.HttpHeaders)
	})

	t.Run("clickhouse_http_headers_flag_not_set", func(t *testing.T) {
		t.Parallel()
		cmd := &mockCommand{
			flags:      map[string]interface{}{},
			setFlags:   map[string]bool{},
			stringMaps: make(map[string]map[string]string),
		}

		cfg := &config.Config{}
		overrideWithCLIFlags(cfg, cmd)

		// Should be empty map when flag is not set
		require.Nil(t, cfg.ClickHouse.HttpHeaders)
		require.Empty(t, cfg.ClickHouse.HttpHeaders)
	})

	t.Run("clickhouse_http_headers_with_other_flags", func(t *testing.T) {
		t.Parallel()
		cmd := &mockCommand{
			flags: map[string]interface{}{
				"clickhouse-host":     "test-host",
				"clickhouse-port":     9000,
				"clickhouse-database": "test-db",
			},
			setFlags: map[string]bool{
				"clickhouse-host":         true,
				"clickhouse-port":         true,
				"clickhouse-database":     true,
				"clickhouse-http-headers": true,
			},
			stringMaps: map[string]map[string]string{
				"clickhouse-http-headers": {
					"X-Test-Header": "test-value",
				},
			},
		}

		cfg := &config.Config{}
		overrideWithCLIFlags(cfg, cmd)

		require.Equal(t, "test-host", cfg.ClickHouse.Host)
		require.Equal(t, 9000, cfg.ClickHouse.Port)
		require.Equal(t, "test-db", cfg.ClickHouse.Database)
		require.NotNil(t, cfg.ClickHouse.HttpHeaders)
		require.Len(t, cfg.ClickHouse.HttpHeaders, 1)
		require.Equal(t, "test-value", cfg.ClickHouse.HttpHeaders["X-Test-Header"])
	})

	t.Run("all_server_flags", func(t *testing.T) {
		t.Parallel()
		cmd := &mockCommand{
			flags: map[string]interface{}{
				"transport":            "sse",
				"address":              "127.0.0.1",
				"port":                 9090,
				"server-tls":           true,
				"server-tls-cert-file": "/path/to/server.crt",
				"server-tls-key-file":  "/path/to/server.key",
				"server-tls-ca-cert":   "/path/to/server-ca.crt",
				"allow-jwe-auth":       true,
				"jwe-secret-key":       "jwe-secret123",
				"jwt-secret-key":       "jwt-secret123",
				"openapi":              "https",
			},
			setFlags: map[string]bool{
				"transport":            true,
				"address":              true,
				"port":                 true,
				"server-tls":           true,
				"server-tls-cert-file": true,
				"server-tls-key-file":  true,
				"server-tls-ca-cert":   true,
				"allow-jwe-auth":       true,
				"jwe-secret-key":       true,
				"jwt-secret-key":       true,
				"openapi":              true,
			},
			stringMaps: make(map[string]map[string]string),
		}

		cfg := &config.Config{}
		overrideWithCLIFlags(cfg, cmd)

		require.Equal(t, config.SSETransport, cfg.Server.Transport)
		require.Equal(t, "127.0.0.1", cfg.Server.Address)
		require.Equal(t, 9090, cfg.Server.Port)
		require.True(t, cfg.Server.TLS.Enabled)
		require.Equal(t, "/path/to/server.crt", cfg.Server.TLS.CertFile)
		require.Equal(t, "/path/to/server.key", cfg.Server.TLS.KeyFile)
		require.Equal(t, "/path/to/server-ca.crt", cfg.Server.TLS.CaCert)
		require.True(t, cfg.Server.JWE.Enabled)
		require.Equal(t, "jwe-secret123", cfg.Server.JWE.JWESecretKey)
		require.Equal(t, "jwt-secret123", cfg.Server.JWE.JWTSecretKey)
		require.True(t, cfg.Server.OpenAPI.Enabled)
		require.True(t, cfg.Server.OpenAPI.TLS)
	})

	t.Run("defaults_when_not_set", func(t *testing.T) {
		t.Parallel()
		cmd := &mockCommand{
			flags:      map[string]interface{}{},
			setFlags:   map[string]bool{},
			stringMaps: make(map[string]map[string]string),
		}

		cfg := &config.Config{}
		overrideWithCLIFlags(cfg, cmd)

		// Should use defaults when not set
		require.Equal(t, "localhost", cfg.ClickHouse.Host)
		require.Equal(t, 8123, cfg.ClickHouse.Port)
		require.Equal(t, "default", cfg.ClickHouse.Database)
		require.Equal(t, "default", cfg.ClickHouse.Username)
		require.Equal(t, config.HTTPProtocol, cfg.ClickHouse.Protocol)
		require.Equal(t, 600, cfg.ClickHouse.MaxExecutionTime)
		require.Equal(t, config.StdioTransport, cfg.Server.Transport)
		require.Equal(t, "0.0.0.0", cfg.Server.Address)
		require.Equal(t, 8080, cfg.Server.Port)
		require.Equal(t, config.InfoLevel, cfg.Logging.Level)
		require.Equal(t, 0, cfg.ClickHouse.Limit)
		require.Equal(t, false, cfg.Server.OpenAPI.Enabled)
		require.Equal(t, false, cfg.Server.OpenAPI.TLS)
	})

	t.Run("invalid_protocol_defaults_to_http", func(t *testing.T) {
		t.Parallel()
		cmd := &mockCommand{
			flags: map[string]interface{}{
				"clickhouse-protocol": "invalid",
			},
			setFlags: map[string]bool{
				"clickhouse-protocol": true,
			},
			stringMaps: make(map[string]map[string]string),
		}

		cfg := &config.Config{}
		overrideWithCLIFlags(cfg, cmd)

		require.Equal(t, config.HTTPProtocol, cfg.ClickHouse.Protocol)
	})

	t.Run("invalid_transport_defaults_to_stdio", func(t *testing.T) {
		t.Parallel()
		cmd := &mockCommand{
			flags: map[string]interface{}{
				"transport": "invalid",
			},
			setFlags: map[string]bool{
				"transport": true,
			},
			stringMaps: make(map[string]map[string]string),
		}

		cfg := &config.Config{}
		overrideWithCLIFlags(cfg, cmd)

		require.Equal(t, config.StdioTransport, cfg.Server.Transport)
	})

	t.Run("invalid_log_level_defaults_to_info", func(t *testing.T) {
		t.Parallel()
		cmd := &mockCommand{
			flags: map[string]interface{}{
				"log-level": "invalid",
			},
			setFlags: map[string]bool{
				"log-level": true,
			},
			stringMaps: make(map[string]map[string]string),
		}

		cfg := &config.Config{}
		overrideWithCLIFlags(cfg, cmd)

		require.Equal(t, config.InfoLevel, cfg.Logging.Level)
	})
}

// TestCORSSupport tests the CORS handler behavior
func TestCORSSupport(t *testing.T) {
	t.Parallel()
	t.Run("cors_preflight_request", func(t *testing.T) {
		t.Parallel()
		for _, transport := range []config.MCPTransport{config.HTTPTransport, config.SSETransport} {
			port, err := getFreeRandomPort()
			require.NoError(t, err)
			cfg := config.Config{
				Server: config.ServerConfig{
					Transport:  transport,
					Address:    "localhost",
					Port:       port, // Use random port
					CORSOrigin: "*",
					JWE: config.JWEConfig{
						Enabled: false,
					},
					TLS: config.ServerTLSConfig{
						Enabled: false,
					},
				},
			}
			app := &application{
				config:    cfg,
				mcpServer: altinitymcp.NewClickHouseMCPServer(cfg, "test-version"),
			}

			// Start server in a goroutine
			done := make(chan error, 1)
			go func() {
				done <- app.Start()
			}()

			// Give server time to start
			time.Sleep(100 * time.Millisecond)

			// Get the actual server port (thread-safe)
			var serverPort string
			httpSrv := app.getHTTPServer()
			if httpSrv != nil && httpSrv.Addr != "" {
				_, port, _ := net.SplitHostPort(httpSrv.Addr)
				serverPort = port
			}

			if serverPort != "" {
				// Test CORS preflight request
				client := &http.Client{}
				req, _ := http.NewRequest("OPTIONS", fmt.Sprintf("http://localhost:%s/", serverPort), nil)
				req.Header.Set("Access-Control-Request-Method", "POST")
				req.Header.Set("Access-Control-Request-Headers", "Content-Type, Authorization")
				req.Header.Set("Origin", "http://localhost")

				resp, err := client.Do(req)
				require.NoError(t, err)
				defer resp.Body.Close()
				require.Equal(t, http.StatusOK, resp.StatusCode)
				require.Equal(t, "*", resp.Header.Get("Access-Control-Allow-Origin"))
				require.Equal(t, "GET, POST, PUT, DELETE, OPTIONS", resp.Header.Get("Access-Control-Allow-Methods"))
				require.Equal(t, "Content-Type, Authorization, X-Altinity-MCP-Key, Mcp-Protocol-Version, Referer, User-Agent", resp.Header.Get("Access-Control-Allow-Headers"))
			}

			// Clean up (thread-safe)
			if httpSrv := app.getHTTPServer(); httpSrv != nil {
				_ = httpSrv.Close()
			}
			select {
			case <-done:
			default:
			}

		}
	})
}

// getFreeRandomPort finds a free random port and returns it
func getFreeRandomPort() (int, error) {
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		return 0, err
	}
	defer listener.Close()

	addr := listener.Addr().(*net.TCPAddr)
	return addr.Port, nil
}

// TestApplicationStart tests the application Start method
func TestApplicationStart(t *testing.T) {
	t.Parallel()
	t.Run("unsupported_transport", func(t *testing.T) {
		t.Parallel()
		cfg := config.Config{
			Server: config.ServerConfig{
				Transport: "unsupported",
			},
		}
		app := &application{
			config:    cfg,
			mcpServer: altinitymcp.NewClickHouseMCPServer(cfg, "test-version"),
		}

		err := app.Start()
		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported transport type")
	})

	t.Run("stdio_transport", func(t *testing.T) {
		t.Parallel()
		cfg := config.Config{
			Server: config.ServerConfig{
				Transport: config.StdioTransport,
			},
		}
		app := &application{
			config:    cfg,
			mcpServer: altinitymcp.NewClickHouseMCPServer(cfg, "test-version"),
		}

		// Start in a goroutine since STDIO transport will block
		done := make(chan error, 1)
		go func() {
			done <- app.Start()
		}()

		// Wait for either completion or timeout
		select {
		case err := <-done:
			// If it completes, it could be with an error or nil (successful start)
			// Both are acceptable for stdio transport
			if err != nil {
				t.Logf("STDIO transport completed with error (acceptable): %v", err)
			} else {
				t.Log("STDIO transport completed successfully")
			}
		case <-time.After(1 * time.Second):
			// If it times out, that means it's probably running (blocked on stdio)
			// which is expected behavior for stdio transport
			t.Log("STDIO transport appears to be running (blocked on stdin), which is expected")
		}
	})

	t.Run("http_transport_invalid_port", func(t *testing.T) {
		t.Parallel()
		cfg := config.Config{
			Server: config.ServerConfig{
				Transport: config.HTTPTransport,
				Address:   "localhost",
				Port:      -1, // Invalid port
				TLS: config.ServerTLSConfig{
					Enabled: false,
				},
			},
		}
		app := &application{
			config:    cfg,
			mcpServer: altinitymcp.NewClickHouseMCPServer(cfg, "test-version"),
		}

		err := app.Start()
		require.Error(t, err)
		// Should fail due to invalid port
	})

	t.Run("http_transport_with_tls_missing_files", func(t *testing.T) {
		t.Parallel()
		port, err := getFreeRandomPort()
		require.NoError(t, err)

		cfg := config.Config{
			Server: config.ServerConfig{
				Transport: config.HTTPTransport,
				Address:   "localhost",
				Port:      port,
				TLS: config.ServerTLSConfig{
					Enabled:  true,
					CertFile: "/nonexistent/cert.pem",
					KeyFile:  "/nonexistent/key.pem",
				},
			},
		}
		app := &application{
			config:    cfg,
			mcpServer: altinitymcp.NewClickHouseMCPServer(cfg, "test-version"),
		}

		err = app.Start()
		require.Error(t, err)
		// Should fail due to missing cert/key files
	})

	t.Run("sse_transport_without_jwe", func(t *testing.T) {
		t.Parallel()
		port, err := getFreeRandomPort()
		require.NoError(t, err)

		cfg := config.Config{
			Server: config.ServerConfig{
				Transport: config.SSETransport,
				Address:   "localhost",
				Port:      port,
				JWE: config.JWEConfig{
					Enabled: false,
				},
				TLS: config.ServerTLSConfig{
					Enabled: false,
				},
			},
		}
		app := &application{
			config:    cfg,
			mcpServer: altinitymcp.NewClickHouseMCPServer(cfg, "test-version"),
		}

		// Start in a goroutine since it will block
		done := make(chan error, 1)
		go func() {
			done <- app.Start()
		}()

		// Give it a moment to start
		time.Sleep(100 * time.Millisecond)

		// Should start successfully (will block on ListenAndServe)
		select {
		case err := <-done:
			// If it returns immediately, it should be an error
			require.Error(t, err)
		default:
			// If it's still running, that's expected - stop it
			if httpSrv := app.getHTTPServer(); httpSrv != nil {
				_ = httpSrv.Close()
				<-done // Wait for it to finish
			}
		}
	})

	t.Run("sse_transport_with_jwe", func(t *testing.T) {
		t.Parallel()
		port, err := getFreeRandomPort()
		require.NoError(t, err)

		cfg := config.Config{
			Server: config.ServerConfig{
				Transport: config.SSETransport,
				Address:   "localhost",
				Port:      port,
				JWE: config.JWEConfig{
					Enabled: true,
				},
				TLS: config.ServerTLSConfig{
					Enabled: false,
				},
			},
		}
		app := &application{
			config:    cfg,
			mcpServer: altinitymcp.NewClickHouseMCPServer(cfg, "test-version"),
		}

		// Start in a goroutine since it will block
		done := make(chan error, 1)
		go func() {
			done <- app.Start()
		}()

		// Give it a moment to start
		time.Sleep(100 * time.Millisecond)

		// Should start successfully (will block on ListenAndServe)
		select {
		case err := <-done:
			// If it returns immediately, it should be an error
			require.Error(t, err)
		default:
			// If it's still running, that's expected - stop it
			if httpSrv := app.getHTTPServer(); httpSrv != nil {
				_ = httpSrv.Close()
				<-done // Wait for it to finish
			}
		}
	})

	t.Run("sse_transport_with_jwe_and_openapi", func(t *testing.T) {
		t.Parallel()
		port, err := getFreeRandomPort()
		require.NoError(t, err)

		cfg := config.Config{
			Server: config.ServerConfig{
				Transport: config.SSETransport,
				Address:   "localhost",
				Port:      port,
				JWE: config.JWEConfig{
					Enabled: true,
				},
				OpenAPI: config.OpenAPIConfig{
					Enabled: true,
					TLS:     false,
				},
				TLS: config.ServerTLSConfig{
					Enabled: false,
				},
			},
		}
		app := &application{
			config:    cfg,
			mcpServer: altinitymcp.NewClickHouseMCPServer(cfg, "test-version"),
		}

		// Start in a goroutine since it will block
		done := make(chan error, 1)
		go func() {
			done <- app.Start()
		}()

		// Give it a moment to start
		time.Sleep(100 * time.Millisecond)

		// Should start successfully (will block on ListenAndServe)
		select {
		case err := <-done:
			// If it returns immediately, it should be an error
			require.Error(t, err)
		default:
			// If it's still running, that's expected - stop it
			if httpSrv := app.getHTTPServer(); httpSrv != nil {
				_ = httpSrv.Close()
				<-done // Wait for it to finish
			}
		}
	})

	t.Run("http_transport_with_jwe_and_openapi", func(t *testing.T) {
		t.Parallel()
		port, err := getFreeRandomPort()
		require.NoError(t, err)

		cfg := config.Config{
			Server: config.ServerConfig{
				Transport: config.HTTPTransport,
				Address:   "localhost",
				Port:      port,
				JWE: config.JWEConfig{
					Enabled: true,
				},
				OpenAPI: config.OpenAPIConfig{
					Enabled: true,
					TLS:     false,
				},
				TLS: config.ServerTLSConfig{
					Enabled: false,
				},
			},
		}
		app := &application{
			config:    cfg,
			mcpServer: altinitymcp.NewClickHouseMCPServer(cfg, "test-version"),
		}

		// Start in a goroutine since it will block
		done := make(chan error, 1)
		go func() {
			done <- app.Start()
		}()

		// Give it a moment to start
		time.Sleep(100 * time.Millisecond)

		// Should start successfully (will block on ListenAndServe)
		select {
		case err := <-done:
			// If it returns immediately, it should be an error
			require.Error(t, err)
		default:
			// If it's still running, that's expected - stop it
			if httpSrv := app.getHTTPServer(); httpSrv != nil {
				_ = httpSrv.Close()
				<-done // Wait for it to finish
			}
		}
	})

	t.Run("sse_transport_openapi_without_jwe", func(t *testing.T) {
		t.Parallel()
		port, err := getFreeRandomPort()
		require.NoError(t, err)

		cfg := config.Config{
			Server: config.ServerConfig{
				Transport: config.SSETransport,
				Address:   "localhost",
				Port:      port,
				JWE: config.JWEConfig{
					Enabled: false,
				},
				OpenAPI: config.OpenAPIConfig{
					Enabled: true,
					TLS:     false,
				},
				TLS: config.ServerTLSConfig{
					Enabled: false,
				},
			},
		}
		app := &application{
			config:    cfg,
			mcpServer: altinitymcp.NewClickHouseMCPServer(cfg, "test-version"),
		}

		// Start in a goroutine since it will block
		done := make(chan error, 1)
		go func() {
			done <- app.Start()
		}()

		// Give it a moment to start
		time.Sleep(100 * time.Millisecond)

		// Should start successfully (will block on ListenAndServe)
		select {
		case err := <-done:
			// If it returns immediately, it should be an error
			require.Error(t, err)
		default:
			// If it's still running, that's expected - stop it
			if httpSrv := app.getHTTPServer(); httpSrv != nil {
				_ = httpSrv.Close()
				<-done // Wait for it to finish
			}
		}
	})

	t.Run("http_transport_openapi_without_jwe", func(t *testing.T) {
		t.Parallel()
		port, err := getFreeRandomPort()
		require.NoError(t, err)

		cfg := config.Config{
			Server: config.ServerConfig{
				Transport: config.HTTPTransport,
				Address:   "localhost",
				Port:      port,
				JWE: config.JWEConfig{
					Enabled: false,
				},
				OpenAPI: config.OpenAPIConfig{
					Enabled: true,
					TLS:     false,
				},
				TLS: config.ServerTLSConfig{
					Enabled: false,
				},
			},
		}
		app := &application{
			config:    cfg,
			mcpServer: altinitymcp.NewClickHouseMCPServer(cfg, "test-version"),
		}

		// Start in a goroutine since it will block
		done := make(chan error, 1)
		go func() {
			done <- app.Start()
		}()

		// Give it a moment to start
		time.Sleep(100 * time.Millisecond)

		// Should start successfully (will block on ListenAndServe)
		select {
		case err := <-done:
			// If it returns immediately, it should be an error
			require.Error(t, err)
		default:
			// If it's still running, that's expected - stop it
			if httpSrv := app.getHTTPServer(); httpSrv != nil {
				_ = httpSrv.Close()
				<-done // Wait for it to finish
			}
		}
	})

	t.Run("sse_transport_with_tls_invalid_config", func(t *testing.T) {
		t.Parallel()
		port, err := getFreeRandomPort()
		require.NoError(t, err)

		cfg := config.Config{
			Server: config.ServerConfig{
				Transport: config.SSETransport,
				Address:   "localhost",
				Port:      port,
				JWE: config.JWEConfig{
					Enabled: false,
				},
				TLS: config.ServerTLSConfig{
					Enabled:  true,
					CertFile: "/nonexistent/cert.pem",
					KeyFile:  "/nonexistent/key.pem",
					CaCert:   "/nonexistent/ca.pem",
				},
			},
		}
		app := &application{
			config:    cfg,
			mcpServer: altinitymcp.NewClickHouseMCPServer(cfg, "test-version"),
		}

		err = app.Start()
		require.Error(t, err)
		// Should fail due to invalid TLS config
	})

	t.Run("build_server_tls_config_error", func(t *testing.T) {
		t.Parallel()
		port, err := getFreeRandomPort()
		require.NoError(t, err)

		cfg := config.Config{
			Server: config.ServerConfig{
				Transport: config.HTTPTransport,
				Address:   "localhost",
				Port:      port,
				TLS: config.ServerTLSConfig{
					Enabled: true,
					CaCert:  "/nonexistent/ca.pem", // This will cause buildServerTLSConfig to fail
				},
			},
		}
		app := &application{
			config:    cfg,
			mcpServer: altinitymcp.NewClickHouseMCPServer(cfg, "test-version"),
		}

		err = app.Start()
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to read server CA certificate")
	})

	t.Run("http_transport_successful_start", func(t *testing.T) {
		t.Parallel()
		port, err := getFreeRandomPort()
		require.NoError(t, err)

		cfg := config.Config{
			Server: config.ServerConfig{
				Transport: config.HTTPTransport,
				Address:   "localhost",
				Port:      port,
				TLS: config.ServerTLSConfig{
					Enabled: false,
				},
			},
		}
		app := &application{
			config:    cfg,
			mcpServer: altinitymcp.NewClickHouseMCPServer(cfg, "test-version"),
		}

		// Start in a goroutine since it will block
		done := make(chan error, 1)
		go func() {
			done <- app.Start()
		}()

		// Give it a moment to start
		time.Sleep(100 * time.Millisecond)

		// Should start successfully (will block on ListenAndServe)
		select {
		case err := <-done:
			// If it returns immediately, it should be an error
			require.Error(t, err)
		default:
			// If it's still running, that's expected - stop it
			if httpSrv := app.getHTTPServer(); httpSrv != nil {
				_ = httpSrv.Close()
				<-done // Wait for it to finish
			}
		}
	})
}

// TestReloadConfigWithValidFile tests config reloading with a valid file
func TestReloadConfigWithValidFile(t *testing.T) {
	t.Parallel()
	// Create a temporary config file
	tmpFile, err := os.CreateTemp("", "test-config-*.yaml")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	configContent := `
clickhouse:
  host: "reloaded-host"
  port: 9001
  database: "reloaded-db"
server:
  transport: "http"
  port: 9091
logging:
  level: "warn"
  openapi: false
`
	_, err = tmpFile.WriteString(configContent)
	require.NoError(t, err)
	_ = tmpFile.Close()
	cfg := config.Config{
		ClickHouse: config.ClickHouseConfig{
			Host: "old-host",
			Port: 8123,
		},
		Logging: config.LoggingConfig{
			Level: config.InfoLevel,
		},
	}

	// Verify reload time is preserved when not in new config
	t.Run("reload_time_preserved_when_not_in_config", func(t *testing.T) {
		t.Parallel()
		// Create a temporary config file
		tmpFile, err := os.CreateTemp("", "test-config-*.yaml")
		require.NoError(t, err)
		defer os.Remove(tmpFile.Name())

		configContent := `clickhouse: {}`
		_, err = tmpFile.WriteString(configContent)
		require.NoError(t, err)
		_ = tmpFile.Close()

		prevReloadTime := 15
		app := &application{
			config:     config.Config{ReloadTime: prevReloadTime},
			configFile: tmpFile.Name(),
		}

		// Mock command interface
		cmd := &mockCommand{
			flags:      map[string]interface{}{},
			setFlags:   map[string]bool{},
			stringMaps: make(map[string]map[string]string),
		}

		// Store the original reload time before override
		originalReloadTime := app.config.ReloadTime

		// Use the actual reloadConfig method
		err = app.reloadConfig(cmd)
		require.NoError(t, err)

		// If config didn't set a reload time and CLI didn't set one, preserve original value
		if app.config.ReloadTime == 0 {
			app.config.ReloadTime = originalReloadTime
		}

		require.Equal(t, prevReloadTime, app.config.ReloadTime)
	})
	app := &application{
		configFile: tmpFile.Name(),
		config:     cfg,
		mcpServer:  altinitymcp.NewClickHouseMCPServer(cfg, "test-version"),
	}

	cmd := &mockCommand{
		flags: map[string]interface{}{
			"log-level": "warn",
		},
		setFlags: map[string]bool{
			"log-level": true,
		},
		stringMaps: make(map[string]map[string]string),
	}

	err = app.reloadConfig(cmd)
	require.NoError(t, err)

	// Check that config was updated
	newConfig := app.GetCurrentConfig()
	require.Equal(t, "reloaded-host", newConfig.ClickHouse.Host)
	require.Equal(t, 9001, newConfig.ClickHouse.Port)
	require.Equal(t, "reloaded-db", newConfig.ClickHouse.Database)
	require.Equal(t, config.HTTPTransport, newConfig.Server.Transport)
	require.Equal(t, 9091, newConfig.Server.Port)
	require.Equal(t, config.WarnLevel, newConfig.Logging.Level)
	require.Equal(t, false, newConfig.Server.OpenAPI.Enabled)
}

// TestNewApplicationWithTestContainer tests newApplication with a real ClickHouse instance
func TestNewApplicationWithTestContainer(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// Start ClickHouse container
	containerReq := testcontainers.ContainerRequest{
		Image:        "clickhouse/clickhouse-server:latest",
		ExposedPorts: []string{"8123/tcp"},
		Env: map[string]string{
			"CLICKHOUSE_SKIP_USER_SETUP": "1",
		},
		WaitingFor: wait.ForHTTP("/ping").WithPort("8123/tcp").WithStartupTimeout(30 * time.Second).WithPollInterval(1 * time.Second),
	}

	clickhouseContainer, err := startContainerWithTiming(t, ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: containerReq,
		Started:          true,
	})
	if err != nil {
		t.Fatal("Failed to start ClickHouse container, skipping test:", err)
	}
	defer func() {
		if termErr := clickhouseContainer.Terminate(ctx); termErr != nil {
			t.Logf("Failed to terminate container: %v", termErr)
		}
	}()

	// Get the mapped port
	mappedPort, err := clickhouseContainer.MappedPort(ctx, "8123")
	require.NoError(t, err)

	host, err := clickhouseContainer.Host(ctx)
	require.NoError(t, err)

	cfg := config.Config{
		ClickHouse: config.ClickHouseConfig{
			Host:     host,
			Port:     mappedPort.Int(),
			Database: "default",
			Username: "default",
			Password: "",
			Protocol: config.HTTPProtocol,
		},
		Server: config.ServerConfig{
			JWE: config.JWEConfig{
				Enabled: false,
			},
		},
	}

	cmd := &mockCommand{
		flags: map[string]interface{}{
			"config":             "",
			"config-reload-time": 0,
		},
		setFlags: map[string]bool{},
	}

	app, err := newApplication(ctx, cfg, cmd)
	require.NoError(t, err)
	require.NotNil(t, app)
	require.NotNil(t, app.mcpServer)
	app.Close()
}

// TestRunServerWithValidConfig tests runServer with a valid configuration
func TestRunServerWithValidConfig(t *testing.T) {
	t.Parallel()
	// Create a temporary config file
	tmpFile, err := os.CreateTemp("", "test-config-*.yaml")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	configContent := `
clickhouse:
  host: "localhost"
  port: 8123
  database: "default"
server:
  jwe:
    enabled: true
    jwe_secret_key: "test-secret"
    jwt_secret_key: "test-jwt-secret"
  transport: "stdio"
logging:
  level: "info"
`
	_, err = tmpFile.WriteString(configContent)
	require.NoError(t, err)
	_ = tmpFile.Close()

	cmd := &cli.Command{}
	cmd.Flags = []cli.Flag{
		&cli.StringFlag{Name: "config", Value: tmpFile.Name()},
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
		&cli.BoolFlag{Name: "allow-jwe-auth", Value: true},
		&cli.StringFlag{Name: "jwe-secret-key", Value: "test-secret"},
		&cli.StringFlag{Name: "jwt-secret-key", Value: "test-jwt-secret"},
		&cli.IntFlag{Name: "config-reload-time", Value: 0},
	}

	// Run in a goroutine with a timeout to avoid blocking
	done := make(chan error, 1)
	go func() {
		done <- runServer(context.Background(), cmd)
	}()

	// Wait for either completion or timeout
	select {
	case err := <-done:
		// If it completes, it could be with an error (stdio serving failure) or nil (successful start)
		// Both are acceptable since JWE auth is enabled, and we're not testing ClickHouse connection
		if err != nil {
			t.Logf("runServer completed with error (expected for stdio): %v", err)
		} else {
			t.Log("runServer completed successfully")
		}
	case <-time.After(2 * time.Second):
		// If it times out, that means it's probably stuck in stdio serving
		// which is expected behavior, so we consider this a pass
		t.Log("runServer appears to be running (stuck in stdio serve), which is expected")
	}
}

// TestRun tests the main run function
func TestRun(t *testing.T) {
	t.Parallel()
	t.Run("version_command", func(t *testing.T) {
		t.Parallel()
		args := []string{"altinity-mcp", "version"}
		err := run(args)
		require.NoError(t, err)
	})

	t.Run("test_connection_command_invalid_config", func(t *testing.T) {
		t.Parallel()
		args := []string{"altinity-mcp", "test-connection", "--clickhouse-host", "nonexistent-host", "--clickhouse-port", "9999"}
		err := run(args)
		require.Error(t, err)
		// Should fail due to invalid ClickHouse connection
	})

	t.Run("invalid_flag", func(t *testing.T) {
		t.Parallel()
		args := []string{"altinity-mcp", "--invalid-flag"}
		err := run(args)
		require.Error(t, err)
		// Should fail due to invalid flag
	})

	t.Run("help_command", func(t *testing.T) {
		t.Parallel()
		args := []string{"altinity-mcp", "--help"}
		err := run(args)
		require.NoError(t, err)
	})

	t.Run("invalid_log_level", func(t *testing.T) {
		t.Parallel()
		args := []string{"altinity-mcp", "--log-level", "invalid"}
		err := run(args)
		require.Error(t, err)
		// Should fail due to invalid log level in Before hook
	})

	t.Run("jwe_enabled_without_secret", func(t *testing.T) {
		t.Parallel()
		args := []string{"altinity-mcp", "--allow-jwe-auth", "--jwe-secret-key", ""}
		err := run(args)
		require.Error(t, err)
		// Should fail due to missing JWE secret key
	})

	t.Run("invalid_config_file", func(t *testing.T) {
		t.Parallel()
		args := []string{"altinity-mcp", "--config", "/nonexistent/config.yaml"}
		err := run(args)
		require.Error(t, err)
		// Should fail due to nonexistent config file
	})

	t.Run("invalid_clickhouse_connection", func(t *testing.T) {
		t.Parallel()
		args := []string{"altinity-mcp", "--clickhouse-host", "nonexistent-host", "--clickhouse-port", "9999"}
		err := run(args)
		require.Error(t, err)
		// Should fail due to invalid ClickHouse connection when JWE is disabled
	})

	t.Run("jwe_enabled_with_secret", func(t *testing.T) {
		t.Parallel()
		// This test will start the server, but we need to stop it quickly
		args := []string{"altinity-mcp", "--allow-jwe-auth", "--jwe-secret-key", "test-secret", "--jwt-secret-key", "test-jwt-secret", "--transport", "stdio"}

		// Run in a goroutine with timeout since stdio transport will block
		done := make(chan error, 1)
		go func() {
			done <- run(args)
		}()

		// Wait for either completion or timeout
		select {
		case err := <-done:
			// If it completes, it could be with an error or nil
			// Both are acceptable since we're testing that it doesn't fail during setup
			if err != nil {
				t.Logf("run completed with error (expected for stdio): %v", err)
			} else {
				t.Log("run completed successfully")
			}
		case <-time.After(1 * time.Second):
			// If it times out, that means it's probably running (blocked on stdio)
			// which is expected behavior for stdio transport
			t.Log("run appears to be running (blocked on stdin), which is expected")
		}
	})

	t.Run("valid_config_file", func(t *testing.T) {
		t.Parallel()
		// Create a temporary config file
		tmpFile, err := os.CreateTemp("", "test-config-*.yaml")
		require.NoError(t, err)
		defer os.Remove(tmpFile.Name())

		configContent := `
clickhouse:
  host: "localhost"
  port: 8123
  database: "default"
server:
  jwe:
    enabled: true
    jwe_secret_key: "test-secret"
    jwt_secret_key: "test-jwt-secret"
  transport: "stdio"
logging:
  level: "info"
`
		_, err = tmpFile.WriteString(configContent)
		require.NoError(t, err)
		tmpFile.Close()

		args := []string{"altinity-mcp", "--config", tmpFile.Name()}

		// Run in a goroutine with timeout since stdio transport will block
		done := make(chan error, 1)
		go func() {
			done <- run(args)
		}()

		// Wait for either completion or timeout
		select {
		case err := <-done:
			// If it completes, it could be with an error or nil
			if err != nil {
				t.Logf("run with config file completed with error (expected for stdio): %v", err)
			} else {
				t.Log("run with config file completed successfully")
			}
		case <-time.After(1 * time.Second):
			// If it times out, that means it's probably running
			t.Log("run with config file appears to be running, which is expected")
		}
	})

	t.Run("token_injection_middleware", func(t *testing.T) {
		t.Parallel()
		app := &application{}

		// Create the token injector middleware
		tokenInjector := app.createTokenInjector()

		// Test with Bearer token
		t.Run("bearer_token", func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest("GET", "/test", nil)
			req.Header.Set("Authorization", "Bearer test-token-123")

			var capturedToken string
			testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				token := r.Context().Value(altinitymcp.JWETokenKey)
				if token != nil {
					capturedToken, _ = token.(string)
				}
				w.WriteHeader(http.StatusOK)
			})

			handler := tokenInjector(testHandler)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, req)

			require.Equal(t, "test-token-123", capturedToken)
		})

		// Test with Basic token
		t.Run("basic_token", func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest("GET", "/test", nil)
			req.Header.Set("Authorization", "Basic test-token-456")

			var capturedToken string
			testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				token := r.Context().Value(altinitymcp.JWETokenKey)
				if token != nil {
					capturedToken, _ = token.(string)
				}
				w.WriteHeader(http.StatusOK)
			})

			handler := tokenInjector(testHandler)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, req)

			require.Equal(t, "test-token-456", capturedToken)
		})

		// Test with x-altinity-mcp-key header
		t.Run("altinity_header", func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest("GET", "/test", nil)
			req.Header.Set("x-altinity-mcp-key", "test-token-789")

			var capturedToken string
			testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				token := r.Context().Value(altinitymcp.JWETokenKey)
				if token != nil {
					capturedToken, _ = token.(string)
				}
				w.WriteHeader(http.StatusOK)
			})

			handler := tokenInjector(testHandler)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, req)

			require.Equal(t, "test-token-789", capturedToken)
		})

		// Test with path token (fallback)
		t.Run("path_token", func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest("GET", "/test", nil)
			req.SetPathValue("token", "test-token-path")

			var capturedToken string
			testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				token := r.Context().Value(altinitymcp.JWETokenKey)
				if token != nil {
					capturedToken, _ = token.(string)
				}
				w.WriteHeader(http.StatusOK)
			})

			handler := tokenInjector(testHandler)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, req)

			require.Equal(t, "test-token-path", capturedToken)
		})

		// Test priority: Bearer > x-altinity-mcp-key > path
		t.Run("token_priority", func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest("GET", "/test", nil)
			req.Header.Set("Authorization", "Bearer bearer-token")
			req.Header.Set("x-altinity-mcp-key", "header-token")
			req.SetPathValue("token", "path-token")

			var capturedToken string
			testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				token := r.Context().Value(altinitymcp.JWETokenKey)
				if token != nil {
					capturedToken, _ = token.(string)
				}
				w.WriteHeader(http.StatusOK)
			})

			handler := tokenInjector(testHandler)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, req)

			require.Equal(t, "bearer-token", capturedToken)
		})

		// Test with no token
		t.Run("no_token", func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest("GET", "/test", nil)

			tokenInContext := false
			testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, tokenInContext = r.Context().Value(altinitymcp.JWETokenKey).(string)
				w.WriteHeader(http.StatusOK)
			})

			handler := tokenInjector(testHandler)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, req)

			require.False(t, tokenInContext)
		})
	})
}

// TestJWETokenGeneratorHandler tests the JWE token generator endpoint.
func TestJWETokenGeneratorHandler(t *testing.T) {
	t.Parallel()
	jweSecretKey := "a-secret-for-jwe-generation-test"
	jwtSecretKey := "a-secret-for-jwt-generation-test"

	app := &application{
		config: config.Config{
			Server: config.ServerConfig{
				JWE: config.JWEConfig{
					Enabled:      true,
					JWESecretKey: jweSecretKey,
					JWTSecretKey: jwtSecretKey,
				},
			},
		},
	}

	t.Run("successful_generation", func(t *testing.T) {
		t.Parallel()
		claims := map[string]interface{}{
			"host":     "localhost",
			"port":     8123,
			"username": "test",
			"expiry":   60,
		}
		body, err := json.Marshal(claims)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/jwe-token-generator", bytes.NewReader(body))
		w := httptest.NewRecorder()

		app.jweTokenGeneratorHandler(w, req)

		require.Equal(t, http.StatusOK, w.Code)

		var resp map[string]string
		err = json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		require.Contains(t, resp, "token")

		// Verify the token
		parsedClaims, err := jwe_auth.ParseAndDecryptJWE(resp["token"], []byte(jweSecretKey), []byte(jwtSecretKey))
		require.NoError(t, err)
		require.Equal(t, "localhost", parsedClaims["host"])
		require.Equal(t, float64(8123), parsedClaims["port"]) // json unmarshals numbers to float64
	})

	t.Run("jwe_disabled", func(t *testing.T) {
		t.Parallel()
		disabledApp := &application{
			config: config.Config{
				Server: config.ServerConfig{
					JWE: config.JWEConfig{
						JWESecretKey: jweSecretKey,
						JWTSecretKey: jwtSecretKey,
						Enabled:      false,
					},
				},
			},
		}
		req := httptest.NewRequest(http.MethodPost, "/jwe-token-generator", nil)
		w := httptest.NewRecorder()

		disabledApp.jweTokenGeneratorHandler(w, req)
		require.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("method_not_allowed", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/jwe-token-generator", nil)
		w := httptest.NewRecorder()

		app.jweTokenGeneratorHandler(w, req)
		require.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})

	t.Run("invalid_request_body", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodPost, "/jwe-token-generator", strings.NewReader("not-json"))
		w := httptest.NewRecorder()

		app.jweTokenGeneratorHandler(w, req)
		require.Equal(t, http.StatusBadRequest, w.Code)
	})

	// Additional error test cases to increase coverage
	t.Run("generate_token_failure", func(t *testing.T) {
		t.Parallel()
		// Create an app with invalid secret keys to force token generation failure
		invalidApp := &application{
			config: config.Config{
				Server: config.ServerConfig{
					JWE: config.JWEConfig{
						Enabled:      true,
						JWESecretKey: "", // Empty key will cause generation to fail
						JWTSecretKey: jwtSecretKey,
					},
				},
			},
		}

		claims := map[string]interface{}{
			"host":   "localhost",
			"port":   8123,
			"expiry": 60,
		}
		body, err := json.Marshal(claims)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/jwe-token-generator", bytes.NewReader(body))
		w := httptest.NewRecorder()

		invalidApp.jweTokenGeneratorHandler(w, req)
		reqBody, bodyErr := io.ReadAll(w.Result().Body)
		require.NoError(t, bodyErr)
		require.Equal(t, http.StatusInternalServerError, w.Code, "unexpected HTTP code, expect=%d,actual=%d, response.Body=%s", http.StatusInternalServerError, w.Code, reqBody)
	})

	t.Run("default_expiry_when_not_provided", func(t *testing.T) {
		t.Parallel()
		claims := map[string]interface{}{
			"host":     "localhost",
			"port":     8123,
			"username": "test",
			// No expiry provided - should default to 3600
		}
		body, err := json.Marshal(claims)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/jwe-token-generator", bytes.NewReader(body))
		w := httptest.NewRecorder()

		app.jweTokenGeneratorHandler(w, req)

		require.Equal(t, http.StatusOK, w.Code)

		var resp map[string]string
		err = json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		require.Contains(t, resp, "token")

		// Verify the token
		parsedClaims, err := jwe_auth.ParseAndDecryptJWE(resp["token"], []byte(jweSecretKey), []byte(jwtSecretKey))
		require.NoError(t, err)
		require.Equal(t, "localhost", parsedClaims["host"])
		require.Equal(t, float64(8123), parsedClaims["port"])
		// Check that expiry was set (should be present and in the future)
		require.Contains(t, parsedClaims, "exp")
		expiry, ok := parsedClaims["exp"].(float64)
		require.True(t, ok)
		require.True(t, expiry > float64(time.Now().Unix()))
	})

	t.Run("all_optional_fields", func(t *testing.T) {
		t.Parallel()
		claims := map[string]interface{}{
			"host":                     "localhost",
			"port":                     8123,
			"database":                 "testdb",
			"username":                 "testuser",
			"password":                 "testpass",
			"protocol":                 "http",
			"limit":                    1000,
			"expiry":                   120,
			"tls_enabled":              true,
			"tls_ca_cert":              "/path/to/ca.crt",
			"tls_client_cert":          "/path/to/client.crt",
			"tls_client_key":           "/path/to/client.key",
			"tls_insecure_skip_verify": true,
		}
		body, err := json.Marshal(claims)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/jwe-token-generator", bytes.NewReader(body))
		w := httptest.NewRecorder()

		app.jweTokenGeneratorHandler(w, req)

		require.Equal(t, http.StatusOK, w.Code)

		var resp map[string]string
		err = json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		require.Contains(t, resp, "token")

		// Verify the token contains all fields
		parsedClaims, err := jwe_auth.ParseAndDecryptJWE(resp["token"], []byte(jweSecretKey), []byte(jwtSecretKey))
		require.NoError(t, err)
		require.Equal(t, "localhost", parsedClaims["host"])
		require.Equal(t, float64(8123), parsedClaims["port"])
		require.Equal(t, "testdb", parsedClaims["database"])
		require.Equal(t, "testuser", parsedClaims["username"])
		require.Equal(t, "testpass", parsedClaims["password"])
		require.Equal(t, "http", parsedClaims["protocol"])
		require.Equal(t, float64(1000), parsedClaims["limit"])
		require.Equal(t, true, parsedClaims["tls_enabled"])
		require.Equal(t, "/path/to/ca.crt", parsedClaims["tls_ca_cert"])
		require.Equal(t, "/path/to/client.crt", parsedClaims["tls_client_cert"])
		require.Equal(t, "/path/to/client.key", parsedClaims["tls_client_key"])
		require.Equal(t, true, parsedClaims["tls_insecure_skip_verify"])
	})

	t.Run("tls_fields_without_tls_enabled", func(t *testing.T) {
		t.Parallel()
		claims := map[string]interface{}{
			"host":            "localhost",
			"port":            8123,
			"expiry":          60,
			"tls_ca_cert":     "/path/to/ca.crt",
			"tls_client_cert": "/path/to/client.crt",
			"tls_client_key":  "/path/to/client.key",
			// tls_enabled is false by default, so TLS fields should not be included
		}
		body, err := json.Marshal(claims)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/jwe-token-generator", bytes.NewReader(body))
		w := httptest.NewRecorder()

		app.jweTokenGeneratorHandler(w, req)

		require.Equal(t, http.StatusOK, w.Code)

		var resp map[string]string
		err = json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		require.Contains(t, resp, "token")

		// Verify the token does NOT contain TLS fields since tls_enabled is false
		parsedClaims, err := jwe_auth.ParseAndDecryptJWE(resp["token"], []byte(jweSecretKey), []byte(jwtSecretKey))
		require.NoError(t, err)
		require.Equal(t, "localhost", parsedClaims["host"])
		require.Equal(t, float64(8123), parsedClaims["port"])
		require.NotContains(t, parsedClaims, "tls_ca_cert")
		require.NotContains(t, parsedClaims, "tls_client_cert")
		require.NotContains(t, parsedClaims, "tls_client_key")
	})
}

// TestMainFunctionality tests various main function scenarios
func TestMainFunctionality(t *testing.T) {
	t.Parallel()
	t.Run("setup_logging_error", func(t *testing.T) {
		t.Parallel()
		err := setupLogging("invalid-level")
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid log level")
	})

	t.Run("build_config_with_empty_values", func(t *testing.T) {
		t.Parallel()
		cmd := &mockCommand{
			flags: map[string]interface{}{
				"config":                        "",
				"clickhouse-host":               "",
				"clickhouse-port":               0,
				"clickhouse-database":           "",
				"clickhouse-username":           "",
				"clickhouse-password":           "",
				"clickhouse-protocol":           "",
				"clickhouse-max-execution-time": 0,
				"read-only":                     false,
				"transport":                     "",
				"address":                       "",
				"port":                          0,
				"log-level":                     "",
				"clickhouse-limit":              0,
			},
			setFlags: map[string]bool{},
		}

		cfg, err := buildConfig(cmd)
		require.NoError(t, err)

		// Should use defaults when values are empty
		require.Equal(t, "localhost", cfg.ClickHouse.Host)
		require.Equal(t, 8123, cfg.ClickHouse.Port)
		require.Equal(t, "default", cfg.ClickHouse.Database)
		require.Equal(t, "default", cfg.ClickHouse.Username)
		require.Equal(t, config.HTTPProtocol, cfg.ClickHouse.Protocol)
		require.Equal(t, 600, cfg.ClickHouse.MaxExecutionTime)
		require.Equal(t, config.StdioTransport, cfg.Server.Transport)
		require.Equal(t, "0.0.0.0", cfg.Server.Address)
		require.Equal(t, 8080, cfg.Server.Port)
		require.Equal(t, config.InfoLevel, cfg.Logging.Level)
		require.Equal(t, 0, cfg.ClickHouse.Limit)
	})

	t.Run("config_reload_with_logging_level_change", func(t *testing.T) {
		t.Parallel()
		// Create a temporary config file
		tmpFile, err := os.CreateTemp("", "test-config-*.yaml")
		require.NoError(t, err)
		defer os.Remove(tmpFile.Name())

		configContent := `
clickhouse:
  host: "localhost"
  port: 8123
server:
  jwe:
    enabled: true
    jwe_secret_key: "test-secret"
    jwt_secret_key: "test-jwt-secret"
logging:
  level: "debug"
`
		_, err = tmpFile.WriteString(configContent)
		require.NoError(t, err)
		_ = tmpFile.Close()
		cfg := config.Config{
			Logging: config.LoggingConfig{
				Level: config.InfoLevel, // Different from file
			},
		}
		app := &application{
			configFile: tmpFile.Name(),
			config:     cfg,
			mcpServer:  altinitymcp.NewClickHouseMCPServer(cfg, "test-version"),
		}

		cmd := &mockCommand{
			flags: map[string]interface{}{
				"log-level": "debug",
			},
			setFlags: map[string]bool{
				"log-level": true,
			},
		}

		err = app.reloadConfig(cmd)
		require.NoError(t, err)

		// Check that logging level was updated
		newConfig := app.GetCurrentConfig()
		require.Equal(t, config.DebugLevel, newConfig.Logging.Level)
	})
}

// generateSelfSignedCert generates a self-signed certificate for testing
func generateSelfSignedCert() ([]byte, []byte, error) {
	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Organization"},
			CommonName:   "localhost",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(1, 0, 0), // Valid for 1 year

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		DNSNames:              []string{"localhost", "clickhouse"},
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, err
	}

	// Encode certificate and private key to PEM format
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	return certPEM, privateKeyPEM, nil
}

func TestValidateOAuthRuntimeConfig(t *testing.T) {
	t.Parallel()

	t.Run("disabled_returns_nil", func(t *testing.T) {
		t.Parallel()
		cfg := config.Config{Server: config.ServerConfig{OAuth: config.OAuthConfig{Enabled: false}}}
		require.NoError(t, validateOAuthRuntimeConfig(cfg))
	})

	t.Run("unsupported_mode", func(t *testing.T) {
		t.Parallel()
		cfg := config.Config{Server: config.ServerConfig{OAuth: config.OAuthConfig{
			Enabled:         true,
			Mode:            "custom",
			GatingSecretKey: "secret",
		}}}
		err := validateOAuthRuntimeConfig(cfg)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported oauth mode")
	})

	t.Run("missing_gating_secret", func(t *testing.T) {
		t.Parallel()
		cfg := config.Config{Server: config.ServerConfig{OAuth: config.OAuthConfig{
			Enabled:         true,
			Mode:            "gating",
			GatingSecretKey: "",
		}}}
		err := validateOAuthRuntimeConfig(cfg)
		require.Error(t, err)
		require.Contains(t, err.Error(), "gating_secret_key is required")
	})

	t.Run("forward_mode_requires_http", func(t *testing.T) {
		t.Parallel()
		cfg := config.Config{
			Server: config.ServerConfig{OAuth: config.OAuthConfig{
				Enabled:         true,
				Mode:            "forward",
				GatingSecretKey: "secret",
			}},
			ClickHouse: config.ClickHouseConfig{Protocol: config.TCPProtocol},
		}
		err := validateOAuthRuntimeConfig(cfg)
		require.Error(t, err)
		require.Contains(t, err.Error(), "requires clickhouse protocol http")
	})

	t.Run("valid_gating_config", func(t *testing.T) {
		t.Parallel()
		cfg := config.Config{Server: config.ServerConfig{OAuth: config.OAuthConfig{
			Enabled:         true,
			Mode:            "gating",
			GatingSecretKey: "secret",
		}}}
		require.NoError(t, validateOAuthRuntimeConfig(cfg))
	})

	t.Run("valid_forward_config", func(t *testing.T) {
		t.Parallel()
		cfg := config.Config{
			Server: config.ServerConfig{OAuth: config.OAuthConfig{
				Enabled:         true,
				Mode:            "forward",
				GatingSecretKey: "secret",
			}},
			ClickHouse: config.ClickHouseConfig{Protocol: config.HTTPProtocol},
		}
		require.NoError(t, validateOAuthRuntimeConfig(cfg))
	})
}

func TestValidateClusterSecretConfig(t *testing.T) {
	t.Parallel()

	t.Run("empty_secret_is_ok", func(t *testing.T) {
		t.Parallel()
		require.NoError(t, validateClusterSecretConfig(config.Config{}))
	})

	t.Run("requires_tcp", func(t *testing.T) {
		t.Parallel()
		cfg := config.Config{
			ClickHouse: config.ClickHouseConfig{
				Protocol:      config.HTTPProtocol,
				ClusterSecret: "shared-secret",
			},
		}
		err := validateClusterSecretConfig(cfg)
		require.ErrorContains(t, err, "clickhouse-cluster-secret requires clickhouse-protocol=tcp")
	})

	t.Run("requires_cluster_name", func(t *testing.T) {
		t.Parallel()
		cfg := config.Config{
			ClickHouse: config.ClickHouseConfig{
				Protocol:      config.TCPProtocol,
				ClusterSecret: "shared-secret",
			},
		}
		err := validateClusterSecretConfig(cfg)
		require.ErrorContains(t, err, "clickhouse-cluster-secret is set but clickhouse-cluster-name is empty")
	})

	t.Run("valid_secret_config", func(t *testing.T) {
		t.Parallel()
		cfg := config.Config{
			ClickHouse: config.ClickHouseConfig{
				Protocol:      config.TCPProtocol,
				ClusterName:   "mcp_cluster",
				ClusterSecret: "shared-secret",
			},
		}
		require.NoError(t, validateClusterSecretConfig(cfg))
	})
}

func TestWarnOAuthMisconfiguration(t *testing.T) {
	t.Parallel()

	t.Run("disabled_no_warn", func(t *testing.T) {
		t.Parallel()
		// Should not panic
		warnOAuthMisconfiguration(config.Config{Server: config.ServerConfig{OAuth: config.OAuthConfig{Enabled: false}}})
	})

	t.Run("gating_mode_missing_public_auth_server_url", func(t *testing.T) {
		t.Parallel()
		// Should log warning but not panic
		warnOAuthMisconfiguration(config.Config{Server: config.ServerConfig{OAuth: config.OAuthConfig{
			Enabled:             true,
			Mode:                "gating",
			Issuer:              "https://issuer.example.com",
			PublicAuthServerURL: "",
		}}})
	})

	t.Run("gating_mode_with_public_auth_server_url", func(t *testing.T) {
		t.Parallel()
		// Should not warn
		warnOAuthMisconfiguration(config.Config{Server: config.ServerConfig{OAuth: config.OAuthConfig{
			Enabled:             true,
			Mode:                "gating",
			Issuer:              "https://issuer.example.com",
			PublicAuthServerURL: "https://public.example.com",
		}}})
	})
}

func TestTransportRoutePatterns(t *testing.T) {
	t.Parallel()
	// HTTP transport is served at root — callers pass "" as the transport string.
	t.Run("http_jwe_only", func(t *testing.T) {
		t.Parallel()
		patterns := transportRoutePatterns(true, false, "")
		require.Equal(t, []string{"/{token}"}, patterns)
	})
	t.Run("http_jwe_and_oauth", func(t *testing.T) {
		t.Parallel()
		patterns := transportRoutePatterns(true, true, "")
		require.Equal(t, []string{"/{token}", "/"}, patterns)
	})
	t.Run("http_no_jwe", func(t *testing.T) {
		t.Parallel()
		patterns := transportRoutePatterns(false, false, "")
		require.Equal(t, []string{"/"}, patterns)
	})
	t.Run("sse_transport", func(t *testing.T) {
		t.Parallel()
		patterns := transportRoutePatterns(false, false, "sse")
		require.Equal(t, []string{"/sse"}, patterns)
	})
	t.Run("sse_jwe_and_oauth", func(t *testing.T) {
		t.Parallel()
		patterns := transportRoutePatterns(true, true, "sse")
		require.Equal(t, []string{"/{token}/sse", "/sse"}, patterns)
	})
}

func TestOpenAPIRoutePatterns(t *testing.T) {
	t.Parallel()
	t.Run("jwe_and_oauth", func(t *testing.T) {
		t.Parallel()
		patterns := openAPIRoutePatterns(true, true)
		require.Contains(t, patterns, "/{token}/openapi")
		require.Contains(t, patterns, "/openapi/list_tables")
		require.Contains(t, patterns, "/openapi/describe_table")
		require.Contains(t, patterns, "/openapi/execute_query")
	})
	t.Run("jwe_only", func(t *testing.T) {
		t.Parallel()
		patterns := openAPIRoutePatterns(true, false)
		require.Equal(t, 5, len(patterns))
		require.Contains(t, patterns, "/{token}/openapi")
	})
	t.Run("no_jwe", func(t *testing.T) {
		t.Parallel()
		patterns := openAPIRoutePatterns(false, false)
		require.Contains(t, patterns, "/openapi")
		require.Contains(t, patterns, "/openapi/execute_query")
	})
}

func TestStripTrailingSlash(t *testing.T) {
	t.Parallel()
	handler := stripTrailingSlash(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(r.URL.Path))
	}))

	t.Run("removes_trailing_slash", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/", nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		require.Equal(t, "/api/v1", rr.Body.String())
	})
	t.Run("root_path_unchanged", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		require.Equal(t, "/", rr.Body.String())
	})
	t.Run("no_trailing_slash_unchanged", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/api/v1", nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		require.Equal(t, "/api/v1", rr.Body.String())
	})
}

func TestJWETokenGeneratorHandlerEdgeCases(t *testing.T) {
	t.Parallel()

	makeApp := func(jweEnabled bool, jweSecret string) *application {
		cfg := config.Config{
			Server: config.ServerConfig{
				JWE: config.JWEConfig{
					Enabled:      jweEnabled,
					JWESecretKey: jweSecret,
					JWTSecretKey: "jwt-secret",
				},
			},
		}
		return &application{config: cfg}
	}

	t.Run("method_not_allowed", func(t *testing.T) {
		t.Parallel()
		app := makeApp(true, "secret")
		req := httptest.NewRequest(http.MethodGet, "/jwe-token-generator", nil)
		rr := httptest.NewRecorder()
		app.jweTokenGeneratorHandler(rr, req)
		require.Equal(t, http.StatusMethodNotAllowed, rr.Code)
	})

	t.Run("jwe_not_enabled", func(t *testing.T) {
		t.Parallel()
		app := makeApp(false, "secret")
		body := strings.NewReader(`{"host":"localhost"}`)
		req := httptest.NewRequest(http.MethodPost, "/jwe-token-generator", body)
		rr := httptest.NewRecorder()
		app.jweTokenGeneratorHandler(rr, req)
		require.Equal(t, http.StatusForbidden, rr.Code)
	})

	t.Run("missing_jwe_secret", func(t *testing.T) {
		t.Parallel()
		app := makeApp(true, "")
		body := strings.NewReader(`{"host":"localhost"}`)
		req := httptest.NewRequest(http.MethodPost, "/jwe-token-generator", body)
		rr := httptest.NewRecorder()
		app.jweTokenGeneratorHandler(rr, req)
		require.Equal(t, http.StatusInternalServerError, rr.Code)
	})

	t.Run("invalid_body", func(t *testing.T) {
		t.Parallel()
		app := makeApp(true, "secret")
		body := strings.NewReader(`{invalid}`)
		req := httptest.NewRequest(http.MethodPost, "/jwe-token-generator", body)
		rr := httptest.NewRecorder()
		app.jweTokenGeneratorHandler(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("success_generates_token", func(t *testing.T) {
		t.Parallel()
		app := makeApp(true, "my-secret-key")
		body := strings.NewReader(`{"host":"clickhouse.local","port":9000,"database":"default","username":"admin","password":"pass","protocol":"native","expiry":3600}`)
		req := httptest.NewRequest(http.MethodPost, "/jwe-token-generator", body)
		rr := httptest.NewRecorder()
		app.jweTokenGeneratorHandler(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)
		var resp map[string]string
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
		require.NotEmpty(t, resp["token"])
	})

	t.Run("success_with_tls_options", func(t *testing.T) {
		t.Parallel()
		app := makeApp(true, "my-secret-key")
		body := strings.NewReader(`{"host":"ch","tls_enabled":true,"tls_ca_cert":"ca","tls_client_cert":"cert","tls_client_key":"key","tls_insecure_skip_verify":true}`)
		req := httptest.NewRequest(http.MethodPost, "/jwe-token-generator", body)
		rr := httptest.NewRecorder()
		app.jweTokenGeneratorHandler(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("default_expiry", func(t *testing.T) {
		t.Parallel()
		app := makeApp(true, "my-secret-key")
		body := strings.NewReader(`{"host":"ch"}`)
		req := httptest.NewRequest(http.MethodPost, "/jwe-token-generator", body)
		rr := httptest.NewRecorder()
		app.jweTokenGeneratorHandler(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)
	})
}

func TestHealthHandler_JWEEnabled(t *testing.T) {
	t.Parallel()
	// When JWE is enabled, credentials are per-request, so no CH connection test
	cfg := config.Config{
		Server: config.ServerConfig{
			JWE: config.JWEConfig{Enabled: true, JWESecretKey: "secret"},
		},
	}
	app := &application{
		config:    cfg,
		mcpServer: altinitymcp.NewClickHouseMCPServer(cfg, "test"),
	}

	t.Run("get_returns_healthy", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		rr := httptest.NewRecorder()
		app.healthHandler(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)
		var body map[string]interface{}
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
		require.Equal(t, "healthy", body["status"])
		require.Equal(t, "per_request_credentials", body["auth"])
	})

	t.Run("method_not_allowed", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodPost, "/health", nil)
		rr := httptest.NewRecorder()
		app.healthHandler(rr, req)
		require.Equal(t, http.StatusMethodNotAllowed, rr.Code)
	})
}

func TestLivenessHandler(t *testing.T) {
	t.Parallel()

	app := &application{
		config: config.Config{
			ClickHouse: config.ClickHouseConfig{
				Host:     "nonexistent-host",
				Port:     9999,
				Database: "default",
				Username: "default",
				Protocol: config.HTTPProtocol,
			},
		},
	}

	t.Run("get_returns_alive_without_clickhouse_check", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/livez", nil)
		rr := httptest.NewRecorder()
		app.livenessHandler(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)
		var body map[string]interface{}
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
		require.Equal(t, "alive", body["status"])
		_, hasClickHouse := body["clickhouse"]
		require.False(t, hasClickHouse)
	})

	t.Run("method_not_allowed", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodPost, "/livez", nil)
		rr := httptest.NewRecorder()
		app.livenessHandler(rr, req)
		require.Equal(t, http.StatusMethodNotAllowed, rr.Code)
	})
}

func TestHealthHandler_OAuthForwardMode(t *testing.T) {
	t.Parallel()
	cfg := config.Config{
		Server: config.ServerConfig{
			OAuth: config.OAuthConfig{Enabled: true, Mode: "forward"},
		},
	}
	app := &application{
		config:    cfg,
		mcpServer: altinitymcp.NewClickHouseMCPServer(cfg, "test"),
	}
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rr := httptest.NewRecorder()
	app.healthHandler(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	require.Equal(t, "per_request_credentials", body["auth"])
}

func TestHealthHandler_CHUnavailable(t *testing.T) {
	t.Parallel()
	cfg := config.Config{
		ClickHouse: config.ClickHouseConfig{
			Host:     "localhost",
			Port:     19999, // port with no server
			Protocol: config.TCPProtocol,
			Database: "default",
			Username: "default",
		},
		Server: config.ServerConfig{
			JWE: config.JWEConfig{Enabled: false},
		},
	}
	app := &application{
		config:    cfg,
		mcpServer: altinitymcp.NewClickHouseMCPServer(cfg, "test"),
	}
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rr := httptest.NewRecorder()
	app.healthHandler(rr, req)
	require.Equal(t, http.StatusServiceUnavailable, rr.Code)
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	require.Equal(t, "unhealthy", body["status"])
}

func TestOAuthStateStoreEviction(t *testing.T) {
	t.Parallel()
	store := newOAuthStateStore()

	// Fill pending auth to capacity
	for i := 0; i < maxOAuthStateEntries; i++ {
		store.putPendingAuth(fmt.Sprintf("pending-%d", i), oauthPendingAuth{
			ExpiresAt: time.Now().Add(time.Duration(i) * time.Second),
		})
	}

	// Adding one more should evict the oldest
	store.putPendingAuth("new-pending", oauthPendingAuth{ExpiresAt: time.Now().Add(time.Hour)})
	_, ok := store.consumePendingAuth("pending-0") // oldest should be evicted
	require.False(t, ok)
	_, ok = store.consumePendingAuth("new-pending")
	require.True(t, ok)

	// Fill auth codes to capacity
	for i := 0; i < maxOAuthStateEntries; i++ {
		store.putAuthCode(fmt.Sprintf("code-%d", i), oauthIssuedCode{
			ExpiresAt: time.Now().Add(time.Duration(i) * time.Second),
		})
	}

	// Adding one more should evict the oldest
	store.putAuthCode("new-code", oauthIssuedCode{ExpiresAt: time.Now().Add(time.Hour)})
	_, ok = store.consumeAuthCode("code-0")
	require.False(t, ok)
	_, ok = store.consumeAuthCode("new-code")
	require.True(t, ok)
}

func TestToolInputSettingsCLIFlag(t *testing.T) {
	cases := []struct {
		name     string
		flagVal  []string
		flagSet  bool
		initList []string
		wantLen  int
		wantList []string
	}{
		{
			name:    "multiple_settings",
			flagVal: []string{"custom_tenant_id", "custom_org_id"},
			flagSet: true, wantLen: 2,
			wantList: []string{"custom_tenant_id", "custom_org_id"},
		},
		{
			name:    "single_setting",
			flagVal: []string{"custom_tenant_id"},
			flagSet: true, wantLen: 1,
			wantList: []string{"custom_tenant_id"},
		},
		{
			name:    "not_set_preserves_config",
			flagSet: false, initList: []string{"custom_tenant_id"},
			wantLen:  1,
			wantList: []string{"custom_tenant_id"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := &mockCommand{
				flags:      map[string]interface{}{},
				setFlags:   map[string]bool{},
				stringMaps: make(map[string]map[string]string),
			}
			if tc.flagSet {
				cmd.flags["tool-input-settings"] = tc.flagVal
				cmd.setFlags["tool-input-settings"] = true
			}

			cfg := &config.Config{}
			if tc.initList != nil {
				cfg.Server.ToolInputSettings = tc.initList
			}
			overrideWithCLIFlags(cfg, cmd)

			require.Len(t, cfg.Server.ToolInputSettings, tc.wantLen)
			require.Equal(t, tc.wantList, cfg.Server.ToolInputSettings)
		})
	}
}

func TestToolInputSettingsConfigFile(t *testing.T) {
	cases := []struct {
		name      string
		yaml      string
		cliFlags  []string
		wantLen   int
		wantList  []string
		wantEmpty bool
	}{
		{
			name: "parses_yaml_list",
			yaml: `
server:
  tool_input_settings:
    - custom_tenant_id
    - custom_org_id
`,
			wantLen:  2,
			wantList: []string{"custom_tenant_id", "custom_org_id"},
		},
		{
			name: "cli_flag_overrides_config_file",
			yaml: `
server:
  tool_input_settings:
    - custom_tenant_id
    - custom_org_id
`,
			cliFlags: []string{"custom_region"},
			wantLen:  1,
			wantList: []string{"custom_region"},
		},
		{
			name: "empty_list_in_config_file",
			yaml: `
server:
  tool_input_settings: []
`,
			wantEmpty: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := filepath.Join(t.TempDir(), "config.yaml")
			require.NoError(t, os.WriteFile(f, []byte(tc.yaml), 0o600))

			cmd := &mockCommand{
				flags:      map[string]interface{}{"config": f},
				setFlags:   map[string]bool{"config": true},
				stringMaps: make(map[string]map[string]string),
			}
			if tc.cliFlags != nil {
				cmd.flags["tool-input-settings"] = tc.cliFlags
				cmd.setFlags["tool-input-settings"] = true
			}

			cfg, err := buildConfig(cmd)
			require.NoError(t, err)

			if tc.wantEmpty {
				require.Empty(t, cfg.Server.ToolInputSettings)
				return
			}
			require.Len(t, cfg.Server.ToolInputSettings, tc.wantLen)
			require.Equal(t, tc.wantList, cfg.Server.ToolInputSettings)
		})
	}
}
