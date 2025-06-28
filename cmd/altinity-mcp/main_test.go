package main

import (
	"context"
	"fmt"
	"github.com/altinity/altinity-mcp/pkg/clickhouse"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/require"

	"github.com/altinity/altinity-mcp/pkg/config"
	"github.com/altinity/altinity-mcp/pkg/mcptesting"
)

// TestMain sets up logging for the test suite.
func TestMain(m *testing.M) {
	if err := setupLogging("debug"); err != nil {
		fmt.Printf("Failed to setup logging: %v\n", err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}

// TestJWTTokenGeneration tests JWT token generation with TLS configuration
func TestJWTTokenGeneration(t *testing.T) {
	t.Parallel()

	// Test basic JWT token generation
	t.Run("basic_token", func(t *testing.T) {
		claims := map[string]interface{}{
			"host":     "localhost",
			"port":     float64(8123),
			"database": "default",
			"username": "default",
			"protocol": "http",
			"exp":      time.Now().Add(time.Hour).Unix(),
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims(claims))
		tokenString, err := token.SignedString([]byte("test-secret"))
		require.NoError(t, err)
		require.NotEmpty(t, tokenString)

		// Parse and verify the token
		parsedToken, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return []byte("test-secret"), nil
		})
		require.NoError(t, err)
		require.True(t, parsedToken.Valid)

		parsedClaims, ok := parsedToken.Claims.(jwt.MapClaims)
		require.True(t, ok)
		require.Equal(t, "localhost", parsedClaims["host"])
		require.Equal(t, float64(8123), parsedClaims["port"])
	})

	// Test JWT token with TLS configuration
	t.Run("token_with_tls", func(t *testing.T) {
		claims := map[string]interface{}{
			"host":                     "secure.clickhouse.com",
			"port":                     float64(9440),
			"database":                 "secure_db",
			"username":                 "secure_user",
			"protocol":                 "tcp",
			"tls_enabled":              true,
			"tls_ca_cert":              "/path/to/ca.crt",
			"tls_client_cert":          "/path/to/client.crt",
			"tls_client_key":           "/path/to/client.key",
			"tls_insecure_skip_verify": false,
			"exp":                      time.Now().Add(time.Hour).Unix(),
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims(claims))
		tokenString, err := token.SignedString([]byte("test-secret"))
		require.NoError(t, err)
		require.NotEmpty(t, tokenString)

		// Parse and verify the token
		parsedToken, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return []byte("test-secret"), nil
		})
		require.NoError(t, err)
		require.True(t, parsedToken.Valid)

		parsedClaims, ok := parsedToken.Claims.(jwt.MapClaims)
		require.True(t, ok)
		require.Equal(t, true, parsedClaims["tls_enabled"])
		require.Equal(t, "/path/to/ca.crt", parsedClaims["tls_ca_cert"])
		require.Equal(t, "/path/to/client.crt", parsedClaims["tls_client_cert"])
		require.Equal(t, "/path/to/client.key", parsedClaims["tls_client_key"])
		require.Equal(t, false, parsedClaims["tls_insecure_skip_verify"])
	})
}

// setupClickHouseContainer sets up a ClickHouse container for testing.
func setupClickHouseContainer(t *testing.T) *config.ClickHouseConfig {
	t.Helper()
	ctx := context.Background() // Use background context instead of test context to avoid cancellation issues

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
		// Use a fresh context for cleanup to avoid cancellation issues
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

	// Create a client to set up the database
	client, err := clickhouse.NewClient(ctx, *cfg)
	require.NoError(t, err)
	defer func() { require.NoError(t, client.Close()) }()

	_, err = client.ExecuteQuery(ctx, "CREATE TABLE default.test (id UInt64, value String) ENGINE = Memory")
	require.NoError(t, err)
	_, err = client.ExecuteQuery(ctx, "INSERT INTO default.test VALUES (1, 'one'), (2, 'two')")
	require.NoError(t, err)

	return cfg
}

// TestMCPTestingWrapper tests the mcptesting wrapper functionality.
func TestMCPTestingWrapper(t *testing.T) {

	ctx := context.Background()
	chConfig := setupClickHouseContainer(t)

	// Create and configure AltinityTestServer
	testServer := mcptesting.NewAltinityTestServer(t, chConfig)

	// Start the server
	err := testServer.Start(ctx)
	require.NoError(t, err)
	defer testServer.Close()

	// Test our wrapper methods
	t.Run("CallTool", func(t *testing.T) {
		// Test list_tables tool - this should succeed since we have a real ClickHouse container
		result, err := testServer.CallTool(ctx, "list_tables", map[string]interface{}{
			"database": "default",
		})
		require.NoError(t, err)
		require.NotNil(t, result)
		require.False(t, result.IsError, "Tool call resulted in error: %v", result)
		
		// Verify we get some content back
		textContent := testServer.GetTextContent(result)
		require.NotEmpty(t, textContent)
	})

	t.Run("GetTextContent", func(t *testing.T) {
		// Create a simple mock function that simulates the behavior without actually creating a proper CallToolResult
		mockResult := &mcp.CallToolResult{}
		// Let's just verify that empty content returns empty string
		text := testServer.GetTextContent(mockResult)
		require.Equal(t, "", text)
	})
}
