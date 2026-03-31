package clickhouse

import (
	"context"
	"testing"
	"time"

	"github.com/altinity/altinity-mcp/pkg/config"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// setupClickHouseContainer sets up a ClickHouse container for testing.
func setupClickHouseContainer(t *testing.T) *config.ClickHouseConfig {
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
	chContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	containerElapsed := time.Since(containerStart)
	require.NoError(t, err)

	t.Cleanup(func() {
		cleanupStart := time.Now()
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := chContainer.Terminate(cleanupCtx); err != nil {
			t.Logf("Warning: failed to terminate container: %v", err)
		}
		t.Logf("[container/%s] cleanup took %s", req.Image, time.Since(cleanupStart))
	})

	host, err := chContainer.Host(ctx)
	require.NoError(t, err)

	port, err := chContainer.MappedPort(ctx, "9000")
	require.NoError(t, err)

	t.Logf("[container/%s] start=%s total=%s", req.Image, containerElapsed, time.Since(totalStart))

	return &config.ClickHouseConfig{
		Host:             host,
		Port:             port.Int(),
		Database:         "default",
		Username:         "default",
		Password:         "",
		Protocol:         config.TCPProtocol,
		ReadOnly:         false,
		MaxExecutionTime: 60,
		Limit:            0,
	}
}

// TestNewClient tests client creation
func TestNewClient(t *testing.T) {
	t.Parallel()
	t.Run("invalid_config", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		cfg := config.ClickHouseConfig{
			Host:     "invalid-host-that-does-not-exist",
			Port:     9999,
			Database: "default",
			Username: "default",
			Protocol: config.TCPProtocol,
		}

		client, err := NewClient(ctx, cfg)
		require.Error(t, err)
		require.Nil(t, client)
		require.Contains(t, err.Error(), "failed to connect to ClickHouse")
	})

	t.Run("valid_config_but_no_server", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		cfg := config.ClickHouseConfig{
			Host:     "localhost",
			Port:     19999, // Use a port that's unlikely to be in use
			Database: "default",
			Username: "default",
			Protocol: config.TCPProtocol,
		}

		client, err := NewClient(ctx, cfg)
		require.Error(t, err)
		require.Nil(t, client)
	})
}

// TestClientOperations tests client operations with real ClickHouse
func TestClientOperations(t *testing.T) {
	t.Parallel()
	cfg := setupClickHouseContainer(t)
	ctx := context.Background()

	client, err := NewClient(ctx, *cfg)
	require.NoError(t, err)
	require.NotNil(t, client)
	defer func() { require.NoError(t, client.Close()) }()

	t.Run("ping", func(t *testing.T) {
		err := client.Ping(ctx)
		require.NoError(t, err)
	})

	t.Run("list_tables", func(t *testing.T) {
		tables, err := client.ListTables(ctx, "default")
		require.NoError(t, err)
		require.NotNil(t, tables)
	})

	t.Run("execute_ddl", func(t *testing.T) {
		result, err := client.ExecuteQuery(ctx, "CREATE TABLE test_table (id UInt64, name String) ENGINE = Memory")
		require.NoError(t, err)
		require.NotNil(t, result)
		require.Empty(t, result.Error)
	})

	t.Run("execute_insert", func(t *testing.T) {
		result, err := client.ExecuteQuery(ctx, "INSERT INTO test_table VALUES (1, 'test')")
		require.NoError(t, err)
		require.NotNil(t, result)
		require.Empty(t, result.Error)
	})

	t.Run("execute_select", func(t *testing.T) {
		result, err := client.ExecuteQuery(ctx, "SELECT * FROM test_table")
		require.NoError(t, err)
		require.NotNil(t, result)
		require.Empty(t, result.Error)
		require.NotEmpty(t, result.Columns)
		require.NotEmpty(t, result.Rows)
	})

	t.Run("describe_table", func(t *testing.T) {
		columns, err := client.DescribeTable(ctx, "default", "test_table")
		require.NoError(t, err)
		require.NotEmpty(t, columns)
		require.Equal(t, "id", columns[0].Name)
		require.Equal(t, "name", columns[1].Name)
	})
}

func TestClientErrorPaths(t *testing.T) {
	t.Parallel()
	t.Run("ping_failure", func(t *testing.T) {
		t.Parallel()
		cfg := &config.ClickHouseConfig{Host: "127.0.0.1", Port: 65000, Database: "default", Username: "default", Protocol: config.TCPProtocol}
		ctx := context.Background()
		client, err := NewClient(ctx, *cfg)
		require.Error(t, err)
		require.Nil(t, client)
	})

	t.Run("describe_table_not_exists", func(t *testing.T) {
		t.Parallel()
		cfg := setupClickHouseContainer(t)
		ctx := context.Background()
		client, err := NewClient(ctx, *cfg)
		require.NoError(t, err)
		defer func() { _ = client.Close() }()
		_, err = client.DescribeTable(ctx, cfg.Database, "not_exists")
		require.Error(t, err)
		require.Contains(t, err.Error(), "columns not found")
	})

	t.Run("non_select_error", func(t *testing.T) {
		t.Parallel()
		cfg := setupClickHouseContainer(t)
		ctx := context.Background()
		client, err := NewClient(ctx, *cfg)
		require.NoError(t, err)
		defer func() { _ = client.Close() }()
		_, err = client.ExecuteQuery(ctx, "CREATE TABLE broken ENGINE = Memory")
		require.Error(t, err)
	})

	t.Run("read_only_blocks_non_select", func(t *testing.T) {
		t.Parallel()
		client := &Client{
			config: config.ClickHouseConfig{
				ReadOnly: true,
			},
		}
		_, err := client.ExecuteQuery(context.Background(), "INSERT INTO t VALUES (1)")
		require.Error(t, err)
		require.Contains(t, err.Error(), "read-only mode allows only")
	})
}

// TestUtilityFunctions tests utility functions
func TestUtilityFunctions(t *testing.T) {
	t.Parallel()
	t.Run("isSelectQuery", func(t *testing.T) {
		t.Parallel()
		require.True(t, isSelectQuery("SELECT * FROM table"))
		require.True(t, isSelectQuery("  select * from table  "))
		require.True(t, isSelectQuery("WITH cte AS (SELECT 1) SELECT * FROM cte"))
		require.False(t, isSelectQuery("INSERT INTO table VALUES (1)"))
		require.False(t, isSelectQuery("CREATE TABLE test (id INT)"))
		// Test with -- comments
		require.True(t, isSelectQuery("-- comment\nSELECT * FROM table"))
		require.False(t, isSelectQuery("-- comment\nINSERT INTO table VALUES (1)"))
		require.True(t, isSelectQuery("SELECT * FROM table -- comment"))
		require.True(t, isSelectQuery("-- comment\nWITH cte AS (SELECT 1) SELECT * FROM cte"))
		// Test with /* */ comments
		require.True(t, isSelectQuery("/* comment */ SELECT * FROM table"))
		require.False(t, isSelectQuery("/* comment */ INSERT INTO table VALUES (1)"))
		require.True(t, isSelectQuery("SELECT /* comment */ * FROM table"))
		require.True(t, isSelectQuery("/* multiline\ncomment */ SELECT * FROM table"))
		require.False(t, isSelectQuery("/* comment */ CREATE TABLE test (id INT)"))
		// Test with both comment types
		require.True(t, isSelectQuery("-- line comment\n/* block comment */ SELECT * FROM table"))
		require.False(t, isSelectQuery("-- line comment\n/* block comment */ INSERT INTO table VALUES (1)"))
		// Mid-query single-line comments (multiline input)
		require.True(t, isSelectQuery("SELECT 1\n-- mid comment\nFROM table"))
		require.False(t, isSelectQuery("-- first line\n-- second line\nINSERT INTO table VALUES (1)"))
		require.True(t, isSelectQuery("\n-- leading blank\n\nSELECT 1"))
		// Additional query types
		require.True(t, isSelectQuery("DESC table"))
		require.True(t, isSelectQuery("EXISTS (SELECT 1)"))
		require.True(t, isSelectQuery("EXPLAIN SELECT * FROM table"))
	})

	t.Run("truncateString", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, "hello", truncateString("hello", 10))
		require.Equal(t, "hello...", truncateString("hello world", 5))
	})

	t.Run("convertToSerializable", func(t *testing.T) {
		t.Parallel()
		now := time.Now()
		require.Equal(t, now.Format(time.RFC3339), convertToSerializable(now))
		require.Equal(t, "hello", convertToSerializable([]byte("hello")))
		require.Equal(t, 123, convertToSerializable(123))
	})
}

// TestTLSConfig tests TLS configuration building
func TestTLSConfig(t *testing.T) {
	t.Parallel()
	t.Run("disabled", func(t *testing.T) {
		t.Parallel()
		cfg := &config.TLSConfig{Enabled: false}
		tlsConfig, err := buildTLSConfig(cfg)
		require.NoError(t, err)
		require.Nil(t, tlsConfig)
	})

	t.Run("enabled_insecure", func(t *testing.T) {
		t.Parallel()
		cfg := &config.TLSConfig{
			Enabled:            true,
			InsecureSkipVerify: true,
		}
		tlsConfig, err := buildTLSConfig(cfg)
		require.NoError(t, err)
		require.NotNil(t, tlsConfig)
		require.True(t, tlsConfig.InsecureSkipVerify)
	})

	t.Run("ca_cert_not_found", func(t *testing.T) {
		t.Parallel()
		cfg := &config.TLSConfig{
			Enabled: true,
			CaCert:  "/path/that/does/not/exist/ca.crt",
		}
		tlsConfig, err := buildTLSConfig(cfg)
		require.Error(t, err)
		require.Nil(t, tlsConfig)
		require.Contains(t, err.Error(), "failed to read CA certificate")
	})

	t.Run("client_cert_not_found", func(t *testing.T) {
		t.Parallel()
		cfg := &config.TLSConfig{
			Enabled:    true,
			ClientCert: "/path/that/does/not/exist/client.crt",
			ClientKey:  "/path/that/does/not/exist/client.key",
		}
		tlsConfig, err := buildTLSConfig(cfg)
		require.Error(t, err)
		require.Nil(t, tlsConfig)
		require.Contains(t, err.Error(), "failed to load client key pair")
	})
}

func TestPrepareHTTPAuthForClickHouse(t *testing.T) {
	t.Parallel()
	t.Run("http_tls_bearer_uses_jwt_hook", func(t *testing.T) {
		t.Parallel()
		cfg := config.ClickHouseConfig{
			Protocol: config.HTTPProtocol,
			TLS: config.TLSConfig{
				Enabled: true,
			},
			HttpHeaders: map[string]string{
				"Authorization": "Bearer secret-token",
				"X-Test":        "value",
			},
		}

		headers, getJWT := prepareHTTPAuthForClickHouse(cfg)
		require.NotNil(t, getJWT)
		require.Equal(t, "value", headers["X-Test"])
		_, hasAuth := headers["Authorization"]
		require.False(t, hasAuth)

		token, err := getJWT(context.Background())
		require.NoError(t, err)
		require.Equal(t, "secret-token", token)
	})

	t.Run("non_tls_keeps_authorization_header", func(t *testing.T) {
		t.Parallel()
		cfg := config.ClickHouseConfig{
			Protocol: config.HTTPProtocol,
			HttpHeaders: map[string]string{
				"Authorization": "Bearer secret-token",
			},
		}

		headers, getJWT := prepareHTTPAuthForClickHouse(cfg)
		require.Nil(t, getJWT)
		require.Equal(t, "Bearer secret-token", headers["Authorization"])
	})

	t.Run("custom_auth_scheme_kept_as_header", func(t *testing.T) {
		t.Parallel()
		cfg := config.ClickHouseConfig{
			Protocol: config.HTTPProtocol,
			TLS: config.TLSConfig{
				Enabled: true,
			},
			HttpHeaders: map[string]string{
				"Authorization": "Basic abc",
			},
		}

		headers, getJWT := prepareHTTPAuthForClickHouse(cfg)
		require.Nil(t, getJWT)
		require.Equal(t, "Basic abc", headers["Authorization"])
	})
}
