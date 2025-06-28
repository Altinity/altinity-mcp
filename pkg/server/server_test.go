package server

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

// TestNewClickHouseMCPServer tests the server creation
func TestNewClickHouseMCPServer(t *testing.T) {
	chConfig := config.ClickHouseConfig{
		Host:     "localhost",
		Port:     8123,
		Database: "default",
		Username: "default",
		Protocol: config.HTTPProtocol,
		Limit:    1000,
	}
	
	jwtConfig := config.JWTConfig{
		Enabled: false,
	}
	
	server := NewClickHouseMCPServer(chConfig, jwtConfig)
	require.NotNil(t, server)
	require.NotNil(t, server.MCPServer)
	require.Equal(t, jwtConfig, server.JwtConfig)
	require.Equal(t, chConfig, server.ClickhouseConfig)
}

// TestGetClickHouseClient tests the JWT client creation
func TestGetClickHouseClient(t *testing.T) {
	ctx := context.Background()
	
	t.Run("without_jwt", func(t *testing.T) {
		chConfig := config.ClickHouseConfig{
			Host:     "localhost",
			Port:     8123,
			Database: "default",
			Username: "default",
			Protocol: config.HTTPProtocol,
			Limit:    1000,
		}
		
		jwtConfig := config.JWTConfig{
			Enabled: false,
		}
		
		server := NewClickHouseMCPServer(chConfig, jwtConfig)
		
		// This will fail to connect but we're testing the logic, not the connection
		_, err := server.GetClickHouseClient(ctx, "")
		// We expect an error because we're not actually connecting to ClickHouse
		require.Error(t, err)
	})
	
	t.Run("with_jwt_missing_token", func(t *testing.T) {
		chConfig := config.ClickHouseConfig{
			Host:     "localhost",
			Port:     8123,
			Database: "default",
			Username: "default",
			Protocol: config.HTTPProtocol,
			Limit:    1000,
		}
		
		jwtConfig := config.JWTConfig{
			Enabled: true,
			SecretKey: "test-secret",
		}
		
		server := NewClickHouseMCPServer(chConfig, jwtConfig)
		
		_, err := server.GetClickHouseClient(ctx, "")
		require.Equal(t, ErrMissingToken, err)
	})
	
	t.Run("with_jwt_invalid_token", func(t *testing.T) {
		chConfig := config.ClickHouseConfig{
			Host:     "localhost",
			Port:     8123,
			Database: "default",
			Username: "default",
			Protocol: config.HTTPProtocol,
			Limit:    1000,
		}
		
		jwtConfig := config.JWTConfig{
			Enabled: true,
			SecretKey: "test-secret",
		}
		
		server := NewClickHouseMCPServer(chConfig, jwtConfig)
		
		_, err := server.GetClickHouseClient(ctx, "invalid-token")
		require.Equal(t, ErrInvalidToken, err)
	})
}

// TestExtractTokenFromCtx tests token extraction from context
func TestExtractTokenFromCtx(t *testing.T) {
	server := &ClickHouseJWTServer{}
	
	t.Run("no_token", func(t *testing.T) {
		ctx := context.Background()
		token := server.ExtractTokenFromCtx(ctx)
		require.Empty(t, token)
	})
	
	t.Run("with_token", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), "jwt_token", "test-token")
		token := server.ExtractTokenFromCtx(ctx)
		require.Equal(t, "test-token", token)
	})
	
	t.Run("wrong_type", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), "jwt_token", 123)
		token := server.ExtractTokenFromCtx(ctx)
		require.Empty(t, token)
	})
}

// TestHelperFunctions tests utility functions
func TestHelperFunctions(t *testing.T) {
	t.Run("isSelectQuery", func(t *testing.T) {
		require.True(t, isSelectQuery("SELECT * FROM table"))
		require.True(t, isSelectQuery("  select * from table  "))
		require.True(t, isSelectQuery("WITH cte AS (SELECT 1) SELECT * FROM cte"))
		require.False(t, isSelectQuery("INSERT INTO table VALUES (1)"))
		require.False(t, isSelectQuery("CREATE TABLE test (id INT)"))
	})
	
	t.Run("hasLimitClause", func(t *testing.T) {
		require.True(t, hasLimitClause("SELECT * FROM table LIMIT 100"))
		require.True(t, hasLimitClause("select * from table limit 50"))
		require.False(t, hasLimitClause("SELECT * FROM table"))
		require.False(t, hasLimitClause("SELECT * FROM table ORDER BY id"))
	})
}

// TestGetClickHouseJWTServerFromContext tests context extraction
func TestGetClickHouseJWTServerFromContext(t *testing.T) {
	t.Run("no_server", func(t *testing.T) {
		ctx := context.Background()
		server := GetClickHouseJWTServerFromContext(ctx)
		require.Nil(t, server)
	})
	
	t.Run("with_server", func(t *testing.T) {
		expectedServer := &ClickHouseJWTServer{}
		ctx := context.WithValue(context.Background(), "clickhouse_jwt_server", expectedServer)
		server := GetClickHouseJWTServerFromContext(ctx)
		require.Equal(t, expectedServer, server)
	})
	
	t.Run("wrong_type", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), "clickhouse_jwt_server", "not-a-server")
		server := GetClickHouseJWTServerFromContext(ctx)
		require.Nil(t, server)
	})
}
