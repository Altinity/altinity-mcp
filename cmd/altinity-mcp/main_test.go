package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/altinity/altinity-mcp/pkg/clickhouse"
	"github.com/altinity/altinity-mcp/pkg/config"
	altinityMcp "github.com/altinity/altinity-mcp/pkg/server"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/mcptest"
	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// TestMain sets up logging for the test suite.
func TestMain(m *testing.M) {
	if err := setupLogging("debug"); err != nil {
		fmt.Printf("Failed to setup logging: %v\n", err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}

type AltinityMCPTestServer struct {
	*mcptest.Server
}

// AddResourceTemplate, currently doesn't implements in mcptest https://github.com/mark3labs/mcp-go/issues/436
func (s *AltinityMCPTestServer) AddResourceTemplate(template mcp.ResourceTemplate, handler server.ResourceTemplateHandlerFunc) {

}

// setupClickHouseContainer sets up a ClickHouse container for testing.
func setupClickHouseContainer(t *testing.T, ctx context.Context) *config.ClickHouseConfig {
	t.Helper()
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
		require.NoError(t, chContainer.Terminate(ctx))
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
	}

	// Create a client to set up the database
	client, err := clickhouse.NewClient(*cfg)
	require.NoError(t, err)
	defer func() { require.NoError(t, client.Close()) }()

	_, err = client.ExecuteQuery(ctx, "CREATE TABLE default.test (id UInt64, value String) ENGINE = Memory")
	require.NoError(t, err)
	_, err = client.ExecuteQuery(ctx, "INSERT INTO default.test VALUES (1, 'one'), (2, 'two')")
	require.NoError(t, err)

	return cfg
}

// Extract text content from a tool result
func getTextContent(result *mcp.CallToolResult) string {
	if len(result.Content) == 0 {
		return ""
	}
	if textContent, ok := result.Content[0].(mcp.TextContent); ok {
		return textContent.Text
	}
	return ""
}

// TestMCPServer is the main test suite for the MCP server.
func TestMCPServer(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	chConfig := setupClickHouseContainer(t, ctx)

	// Create a ClickHouse client
	chClient, err := clickhouse.NewClient(*chConfig)
	require.NoError(t, err)
	defer func() { require.NoError(t, chClient.Close()) }()

	// Create a test server
	testServer := mcptest.NewUnstartedServer(t)
	testServerWrapper := &AltinityMCPTestServer{testServer}
	// Add tools
	altinityMcp.RegisterTools(testServerWrapper, chClient)
	altinityMcp.RegisterResources(testServerWrapper, chClient)
	altinityMcp.RegisterPrompts(testServerWrapper)

	// Start the server
	err = testServer.Start(ctx)
	require.NoError(t, err)
	defer testServer.Close()

	client := testServer.Client()
	require.NotNil(t, client)

	// Test Tools
	t.Run("Tools", func(t *testing.T) {
		// Test list_tables tool
		t.Run("list_tables", func(t *testing.T) {
			callReq := mcp.CallToolRequest{}
			callReq.Params.Name = "list_tables"

			result, err := client.CallTool(ctx, callReq)
			require.NoError(t, err)
			require.NotNil(t, result)
			require.False(t, result.IsError)

			text := getTextContent(result)
			require.Contains(t, text, "test")
			require.Contains(t, text, "count")
		})

		// Test describe_table tool
		t.Run("describe_table", func(t *testing.T) {
			callReq := mcp.CallToolRequest{}
			callReq.Params.Name = "describe_table"
			callReq.Params.Arguments = map[string]interface{}{
				"table_name": "test",
			}

			result, err := client.CallTool(ctx, callReq)
			require.NoError(t, err)
			require.NotNil(t, result)
			require.False(t, result.IsError)

			text := getTextContent(result)
			require.Contains(t, text, "id")
			require.Contains(t, text, "value")
		})

		// Test execute_query tool - SELECT
		t.Run("execute_query_select", func(t *testing.T) {
			callReq := mcp.CallToolRequest{}
			callReq.Params.Name = "execute_query"
			callReq.Params.Arguments = map[string]interface{}{
				"query": "SELECT * FROM test",
			}

			result, err := client.CallTool(ctx, callReq)
			require.NoError(t, err)
			require.NotNil(t, result)
			require.False(t, result.IsError)

			text := getTextContent(result)
			require.Contains(t, text, "one")
			require.Contains(t, text, "two")
		})

		// Test execute_query tool with limit parameter
		t.Run("execute_query_with_limit", func(t *testing.T) {
			callReq := mcp.CallToolRequest{}
			callReq.Params.Name = "execute_query"
			callReq.Params.Arguments = map[string]interface{}{
				"query": "SELECT * FROM test",
				"limit": float64(1),
			}

			result, err := client.CallTool(ctx, callReq)
			require.NoError(t, err)
			require.NotNil(t, result)
			require.False(t, result.IsError)

			// Parse the JSON response to check row count
			text := getTextContent(result)
			var queryResult map[string]interface{}
			err = json.Unmarshal([]byte(text), &queryResult)
			require.NoError(t, err)
			rows, ok := queryResult["rows"].([]interface{})
			require.True(t, ok)
			require.Equal(t, 1, len(rows))
		})

		// Test execute_query tool - Non-SELECT (DDL)
		t.Run("execute_query_ddl", func(t *testing.T) {
			callReq := mcp.CallToolRequest{}
			callReq.Params.Name = "execute_query"
			callReq.Params.Arguments = map[string]interface{}{
				"query": "CREATE TABLE IF NOT EXISTS test_new (id UInt64, name String) ENGINE = Memory",
			}

			result, err := client.CallTool(ctx, callReq)
			require.NoError(t, err)
			require.NotNil(t, result)
			require.False(t, result.IsError)

			text := getTextContent(result)
			require.Contains(t, text, "OK")
		})

		// Test execute_query tool - INSERT
		t.Run("execute_query_insert", func(t *testing.T) {
			callReq := mcp.CallToolRequest{}
			callReq.Params.Name = "execute_query"
			callReq.Params.Arguments = map[string]interface{}{
				"query": "INSERT INTO test_new VALUES (1, 'test_name')",
			}

			result, err := client.CallTool(ctx, callReq)
			require.NoError(t, err)
			require.NotNil(t, result)
			require.False(t, result.IsError)

			text := getTextContent(result)
			require.Contains(t, text, "OK")
		})

		// Test execute_query tool error case (invalid query)
		t.Run("execute_query_error", func(t *testing.T) {
			callReq := mcp.CallToolRequest{}
			callReq.Params.Name = "execute_query"
			callReq.Params.Arguments = map[string]interface{}{
				"query": "SELECT * FROM non_existent_table",
			}

			result, err := client.CallTool(ctx, callReq)
			require.NoError(t, err) // The error is in the result, not in the call
			require.NotNil(t, result)
			require.True(t, result.IsError)
		})

		// Test execute_query tool error case (missing required parameter)
		t.Run("execute_query_missing_param", func(t *testing.T) {
			callReq := mcp.CallToolRequest{}
			callReq.Params.Name = "execute_query"
			// Missing required "query" parameter

			result, err := client.CallTool(ctx, callReq)
			require.NoError(t, err) // The error is in the result, not in the call
			require.NotNil(t, result)
			require.True(t, result.IsError)
		})

		// Test execute_query tool with invalid limit
		t.Run("execute_query_invalid_limit", func(t *testing.T) {
			callReq := mcp.CallToolRequest{}
			callReq.Params.Name = "execute_query"
			callReq.Params.Arguments = map[string]interface{}{
				"query": "SELECT * FROM test",
				"limit": float64(20000), // Over 10000 limit
			}

			result, err := client.CallTool(ctx, callReq)
			require.NoError(t, err)
			require.NotNil(t, result)
			require.True(t, result.IsError)

			text := getTextContent(result)
			require.Contains(t, text, "Limit cannot exceed 10,000 rows")
		})
	})

	// Test Resources
	t.Run("Resources", func(t *testing.T) {
		// Test schema resource
		t.Run("schema_resource", func(t *testing.T) {
			readReq := mcp.ReadResourceRequest{}
			readReq.Params.URI = "clickhouse://schema"

			result, err := client.ReadResource(ctx, readReq)
			require.NoError(t, err)
			require.NotNil(t, result)
			require.NotEmpty(t, result.Contents)

			content := result.Contents[0]
			textContent, ok := content.(mcp.TextResourceContents)
			require.True(t, ok)
			require.Equal(t, "application/json", textContent.MIMEType)
			require.Contains(t, textContent.Text, "database")
			require.Contains(t, textContent.Text, "tables")
		})

		// Test table resource
		t.Run("table_resource", func(t *testing.T) {
			readReq := mcp.ReadResourceRequest{}
			readReq.Params.URI = "clickhouse://table/test"

			result, err := client.ReadResource(ctx, readReq)
			require.NoError(t, err)
			require.NotNil(t, result)
			require.NotEmpty(t, result.Contents)

			content := result.Contents[0]
			textContent, ok := content.(mcp.TextResourceContents)
			require.True(t, ok)
			require.Equal(t, "application/json", textContent.MIMEType)
			require.Contains(t, textContent.Text, "id")
			require.Contains(t, textContent.Text, "value")
		})

		// Test invalid resource
		t.Run("invalid_resource", func(t *testing.T) {
			readReq := mcp.ReadResourceRequest{}
			readReq.Params.URI = "clickhouse://invalid"

			_, err := client.ReadResource(ctx, readReq)
			require.Error(t, err)
		})
	})

	// Test Prompts
	t.Run("Prompts", func(t *testing.T) {
		// Test query_builder prompt
		t.Run("query_builder_prompt", func(t *testing.T) {
			promptReq := mcp.GetPromptRequest{}
			promptReq.Params.Name = "query_builder"
			promptReq.Params.Arguments = map[string]string{
				"table_name": "test",
				"query_type": "select",
			}

			result, err := client.GetPrompt(ctx, promptReq)
			require.NoError(t, err)
			require.NotNil(t, result)
			// Prompts don't have a Title field directly accessible
			require.GreaterOrEqual(t, len(result.Messages), 1)

			// The first message should be from the user
			require.Equal(t, mcp.RoleUser, result.Messages[0].Role)

			// Check if there's a second message with the embedded resource
			if len(result.Messages) > 1 {
				require.Equal(t, mcp.RoleUser, result.Messages[1].Role)
				_, ok := result.Messages[1].Content.(mcp.EmbeddedResource)
				require.True(t, ok)
			}
		})

		// Test performance_analysis prompt
		t.Run("performance_analysis_prompt", func(t *testing.T) {
			promptReq := mcp.GetPromptRequest{}
			promptReq.Params.Name = "performance_analysis"
			promptReq.Params.Arguments = map[string]string{
				"query": "SELECT * FROM test WHERE id > 0",
			}

			result, err := client.GetPrompt(ctx, promptReq)
			require.NoError(t, err)
			require.NotNil(t, result)
			// Prompts don't have a Title field directly accessible
			require.GreaterOrEqual(t, len(result.Messages), 1)

			// First message should contain the query
			require.Equal(t, mcp.RoleUser, result.Messages[0].Role)
			text, ok := result.Messages[0].Content.(mcp.TextContent)
			require.True(t, ok)
			require.Contains(t, text.Text, "SELECT * FROM test WHERE id > 0")
		})

		// Test performance_analysis prompt error case (missing required parameter)
		t.Run("performance_analysis_missing_param", func(t *testing.T) {
			promptReq := mcp.GetPromptRequest{}
			promptReq.Params.Name = "performance_analysis"
			// Missing required "query" parameter

			_, err := client.GetPrompt(ctx, promptReq)
			require.Error(t, err)
		})
	})
}

// Helper functions
func isSelectQuery(query string) bool {
	trimmed := strings.TrimSpace(strings.ToUpper(query))
	return strings.HasPrefix(trimmed, "SELECT") || strings.HasPrefix(trimmed, "WITH")
}

func hasLimitClause(query string) bool {
	upper := strings.ToUpper(query)
	return strings.Contains(upper, " LIMIT ")
}
