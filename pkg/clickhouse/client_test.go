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
	chContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(t, err)

	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := chContainer.Terminate(cleanupCtx); err != nil {
			t.Logf("Warning: failed to terminate container: %v", err)
		}
	})

	host, err := chContainer.Host(ctx)
	require.NoError(t, err)

	port, err := chContainer.MappedPort(ctx, "9000")
	require.NoError(t, err)

	return &config.ClickHouseConfig{
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
}

// TestNewClient tests client creation
func TestNewClient(t *testing.T) {
	t.Run("invalid_config", func(t *testing.T) {
		ctx := context.Background()
		cfg := config.ClickHouseConfig{
			Host:     "invalid-host",
			Port:     9999,
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

// TestUtilityFunctions tests utility functions
func TestUtilityFunctions(t *testing.T) {
	t.Run("isSelectQuery", func(t *testing.T) {
		require.True(t, isSelectQuery("SELECT * FROM table"))
		require.True(t, isSelectQuery("  select * from table  "))
		require.True(t, isSelectQuery("WITH cte AS (SELECT 1) SELECT * FROM cte"))
		require.False(t, isSelectQuery("INSERT INTO table VALUES (1)"))
		require.False(t, isSelectQuery("CREATE TABLE test (id INT)"))
	})

	t.Run("truncateString", func(t *testing.T) {
		require.Equal(t, "hello", truncateString("hello", 10))
		require.Equal(t, "hello...", truncateString("hello world", 5))
	})

	t.Run("convertToSerializable", func(t *testing.T) {
		now := time.Now()
		require.Equal(t, now.Format(time.RFC3339), convertToSerializable(now))
		require.Equal(t, "hello", convertToSerializable([]byte("hello")))
		require.Equal(t, 123, convertToSerializable(123))
	})
}

// TestTLSConfig tests TLS configuration building
func TestTLSConfig(t *testing.T) {
	t.Run("disabled", func(t *testing.T) {
		cfg := &config.TLSConfig{Enabled: false}
		tlsConfig, err := buildTLSConfig(cfg)
		require.NoError(t, err)
		require.Nil(t, tlsConfig)
	})

	t.Run("enabled_insecure", func(t *testing.T) {
		cfg := &config.TLSConfig{
			Enabled:            true,
			InsecureSkipVerify: true,
		}
		tlsConfig, err := buildTLSConfig(cfg)
		require.NoError(t, err)
		require.NotNil(t, tlsConfig)
		require.True(t, tlsConfig.InsecureSkipVerify)
	})
}
