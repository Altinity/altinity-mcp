package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/altinity/altinity-mcp/pkg/clickhouse"
	"github.com/altinity/altinity-mcp/pkg/config"
	"github.com/google/uuid"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/r3labs/sse/v2"
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

// setupClickHouseContainer sets up a ClickHouse container for testing.
func setupClickHouseContainer(t *testing.T, ctx context.Context) *config.ClickHouseConfig {
	t.Helper()
	req := testcontainers.ContainerRequest{
		Image:        "clickhouse/clickhouse-server:latest",
		ExposedPorts: []string{"9000/tcp"},
		WaitingFor:   wait.ForLog("Ready for connections").WithStartupTimeout(5 * time.Minute),
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

// getFreePort finds and returns an available TCP port.
func getFreePort(t *testing.T) int {
	t.Helper()
	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	require.NoError(t, err)

	l, err := net.ListenTCP("tcp", addr)
	require.NoError(t, err)
	defer func() { require.NoError(t, l.Close()) }()
	return l.Addr().(*net.TCPAddr).Port
}

// TestMCPServer is the main test suite for the MCP server.
func TestMCPServer(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	chConfig := setupClickHouseContainer(t, ctx)

	// Test HTTP Transport
	t.Run("HTTP Transport", func(t *testing.T) {
		t.Parallel()
		testTransport(t, ctx, *chConfig, config.HTTPTransport)
	})

	// Test SSE Transport
	t.Run("SSE Transport", func(t *testing.T) {
		t.Parallel()
		testTransport(t, ctx, *chConfig, config.SSETransport)
	})

	// Test Stdio Transport
	t.Run("Stdio Transport", func(t *testing.T) {
		t.Parallel()
		testTransport(t, ctx, *chConfig, config.StdioTransport)
	})
}

// testTransport runs a suite of tool tests for a given transport.
func testTransport(t *testing.T, ctx context.Context, chConfig config.ClickHouseConfig, transport config.MCPTransport) {
	t.Helper()

	var app *application
	var url string
	var stdioReader *bufio.Reader
	var stdioWriter io.Writer

	if transport == config.StdioTransport {
		oldStdin := os.Stdin
		oldStdout := os.Stdout
		r, w, err := os.Pipe()
		require.NoError(t, err)
		os.Stdin = r
		stdioWriter = w

		rOut, wOut, err := os.Pipe()
		require.NoError(t, err)
		os.Stdout = wOut
		stdioReader = bufio.NewReader(rOut)

		t.Cleanup(func() {
			os.Stdin = oldStdin
			os.Stdout = oldStdout
			_ = r.Close()
			_ = w.Close()
			_ = rOut.Close()
			_ = wOut.Close()
		})
	}

	port := getFreePort(t)
	appConfig := config.Config{
		ClickHouse: chConfig,
		Server: config.ServerConfig{
			Transport: transport,
			Address:   "127.0.0.1",
			Port:      port,
		},
	}
	url = fmt.Sprintf("http://127.0.0.1:%d/mcp/v1/tool", port)

	var err error
	app, err = newApplication(ctx, appConfig)
	require.NoError(t, err)
	t.Cleanup(app.Close)

	errChan := make(chan error, 1)
	go func() {
		err := app.Start(ctx)
		if err != nil && err != http.ErrServerClosed {
			errChan <- err
		}
		close(errChan)
	}()

	if transport != config.StdioTransport {
		// Wait for server to start
		require.Eventually(t, func() bool {
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 1*time.Second)
			if err != nil {
				return false
			}
			_ = conn.Close()
			return true
		}, 5*time.Second, 100*time.Millisecond, "server did not start")

		t.Cleanup(func() {
			if app.httpSrv != nil {
				require.NoError(t, app.httpSrv.Shutdown(context.Background()))
			}
			// Check for server startup errors
			select {
			case err := <-errChan:
				require.NoError(t, err, "server failed during execution")
			default:
			}
		})
	}

	// Run tool tests
	t.Run("list_tables", func(t *testing.T) {
		t.Parallel()
		req := mcp.CallToolRequest{
			Request:   mcp.Request{ProtocolVersion: "1.0", RequestID: uuid.NewString()},
			ToolName:  "list_tables",
			Arguments: map[string]interface{}{},
		}
		result := callTool(t, ctx, transport, req, url, stdioReader, stdioWriter)
		require.Empty(t, result.Error)
		var data map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(result.Content), &data))
		require.Equal(t, float64(1), data["count"])
		tables := data["tables"].([]interface{})
		require.Len(t, tables, 1)
		require.Equal(t, "test", tables[0].(map[string]interface{})["name"])
	})

	t.Run("execute_query", func(t *testing.T) {
		t.Parallel()
		req := mcp.CallToolRequest{
			Request:  mcp.Request{ProtocolVersion: "1.0", RequestID: uuid.NewString()},
			ToolName: "execute_query",
			Arguments: map[string]interface{}{
				"query": "SELECT * FROM test ORDER BY id",
			},
		}
		result := callTool(t, ctx, transport, req, url, stdioReader, stdioWriter)
		require.Empty(t, result.Error)
		var data clickhouse.QueryResult
		require.NoError(t, json.Unmarshal([]byte(result.Content), &data))
		require.Equal(t, 2, data.Count)
		require.Len(t, data.Rows, 2)
		require.Equal(t, []interface{}{float64(1), "one"}, data.Rows[0])
	})

	t.Run("describe_table", func(t *testing.T) {
		t.Parallel()
		req := mcp.CallToolRequest{
			Request:  mcp.Request{ProtocolVersion: "1.0", RequestID: uuid.NewString()},
			ToolName: "describe_table",
			Arguments: map[string]interface{}{
				"table_name": "test",
			},
		}
		result := callTool(t, ctx, transport, req, url, stdioReader, stdioWriter)
		require.Empty(t, result.Error)
		var data []clickhouse.ColumnInfo
		require.NoError(t, json.Unmarshal([]byte(result.Content), &data))
		require.Len(t, data, 2)
		require.Equal(t, "id", data[0].Name)
		require.Equal(t, "UInt64", data[0].Type)
		require.Equal(t, "value", data[1].Name)
		require.Equal(t, "String", data[1].Type)
	})
}

func callTool(t *testing.T, ctx context.Context, transport config.MCPTransport, req mcp.CallToolRequest, url string, stdioReader *bufio.Reader, stdioWriter io.Writer) *mcp.CallToolResult {
	t.Helper()
	body, err := json.Marshal(req)
	require.NoError(t, err)

	var result mcp.CallToolResult

	switch transport {
	case config.HTTPTransport:
		httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
		require.NoError(t, err)
		httpReq.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(httpReq)
		require.NoError(t, err)
		defer func() { require.NoError(t, resp.Body.Close()) }()
		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))

	case config.SSETransport:
		client := sse.NewClient(url)
		var wg sync.WaitGroup
		wg.Add(1)
		err = client.Subscribe(req.RequestID, func(msg *sse.Event) {
			if string(msg.Event) == "tool_result" {
				require.NoError(t, json.Unmarshal(msg.Data, &result))
				wg.Done()
			}
		})
		require.NoError(t, err)
		defer client.Unsubscribe(req.RequestID)

		httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
		require.NoError(t, err)
		httpReq.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(httpReq)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.NoError(t, resp.Body.Close())
		wg.Wait()

	case config.StdioTransport:
		_, err := stdioWriter.Write(append(body, '\n'))
		require.NoError(t, err)
		line, err := stdioReader.ReadBytes('\n')
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(line, &result))
	}

	return &result
}
