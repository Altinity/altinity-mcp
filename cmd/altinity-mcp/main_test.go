package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/altinity/altinity-mcp/pkg/clickhouse"
	"github.com/altinity/altinity-mcp/pkg/config"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
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

	port := getFreePort(t)
	appConfig := config.Config{
		ClickHouse: chConfig,
		Server: config.ServerConfig{
			Transport: transport,
			Address:   "127.0.0.1",
			Port:      port,
		},
	}
	switch transport {
	case config.HTTPTransport:
		url = fmt.Sprintf("http://127.0.0.1:%d/mcp", port)
	case config.SSETransport:
		url = fmt.Sprintf("http://127.0.0.1:%d/sse", port)
	case config.StdioTransport:
		url = "" // Not used for stdio
	}

	var err error
	app, err = newApplication(ctx, appConfig)
	require.NoError(t, err)
	t.Cleanup(app.Close)

	errChan := make(chan error, 1)

	if transport == config.StdioTransport {
		stdinPipeR, stdinPipeW := io.Pipe()
		stdoutPipeR, stdoutPipeW := io.Pipe()
		stdioReader = bufio.NewReader(stdoutPipeR)
		stdioWriter = stdinPipeW

		listenCtx, cancelListen := context.WithCancel(ctx)

		go func() {
			stdioServer := server.NewStdioServer(app.mcpServer)
			err := stdioServer.Listen(listenCtx, stdinPipeR, stdoutPipeW)
			if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, io.EOF) {
				errChan <- err
			}
			close(errChan)
		}()

		t.Cleanup(func() {
			cancelListen()
			// Close pipes to unblock Listen
			_ = stdinPipeW.Close()
			_ = stdoutPipeR.Close()
			// check for server errors
			if err, ok := <-errChan; ok {
				require.NoError(t, err, "stdio server returned an error")
			}
		})

		// Handle initialize call
		initReq := mcp.Request{
			Version: "2.0",
			Method:  "initialize",
			ID:      "1",
		}
		initBody, err := json.Marshal(initReq)
		require.NoError(t, err)
		_, err = stdioWriter.Write(append(initBody, '\n'))
		require.NoError(t, err)

		// Read response
		line, err := stdioReader.ReadBytes('\n')
		require.NoError(t, err)
		var initResp mcp.Response
		require.NoError(t, json.Unmarshal(line, &initResp))
		require.NotNil(t, initResp.Result)
		require.Nil(t, initResp.Error)
	} else {
		go func() {
			startErr := app.Start(ctx)
			if startErr != nil && !errors.Is(startErr, http.ErrServerClosed) {
				errChan <- startErr
			}
			close(errChan)
		}()

		// Wait for server to start
		require.Eventually(t, func() bool {
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 1*time.Second)
			if err != nil {
				return false
			}
			_ = conn.Close()
			return true
		}, 10*time.Second, 500*time.Millisecond, "server did not start")

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
			Request: mcp.Request{
				Method: "tools/call",
			},
		}
		req.Params.Name = "list_tables"
		result := callTool(t, ctx, transport, req, url, stdioReader, stdioWriter)
		require.False(t, result.IsError)
		require.NotEmpty(t, result.Content, "expected non-empty content")
		require.IsType(t, mcp.TextContent{}, result.Content[0])
		textContent := result.Content[0].(mcp.TextContent)
		var data map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(textContent.Text), &data))
		require.Equal(t, float64(1), data["count"])
		tables := data["tables"].([]interface{})
		require.Len(t, tables, 1)
		require.Equal(t, "test", tables[0].(map[string]interface{})["name"])
	})

	t.Run("execute_query", func(t *testing.T) {
		t.Parallel()
		req := mcp.CallToolRequest{
			Request: mcp.Request{
				Method: "tools/call",
			},
			Params: mcp.CallToolParams{
				Name: "execute_query",
				Arguments: map[string]interface{}{
					"query": "SELECT * FROM test ORDER BY id",
				},
			},
		}
		result := callTool(t, ctx, transport, req, url, stdioReader, stdioWriter)
		require.False(t, result.IsError)
		var data clickhouse.QueryResult
		require.NoError(t, json.Unmarshal([]byte(result.Content[0].(mcp.TextContent).Text), &data))
		require.Equal(t, 2, data.Count)
		require.Len(t, data.Rows, 2)
		require.Equal(t, []interface{}{float64(1), "one"}, data.Rows[0])
	})

	t.Run("describe_table", func(t *testing.T) {
		t.Parallel()
		req := mcp.CallToolRequest{
			Request: mcp.Request{
				Method: "tools/call",
			},
			Params: mcp.CallToolParams{
				Name: "describe_table",
				Arguments: map[string]interface{}{
					"table_name": "test",
				},
			},
		}
		result := callTool(t, ctx, transport, req, url, stdioReader, stdioWriter)
		require.False(t, result.IsError)
		require.NotEmpty(t, result.Content)
		var data []clickhouse.ColumnInfo
		require.NoError(t, json.Unmarshal([]byte(result.Content[0].(mcp.TextContent).Text), &data))
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
		httpReq, err := http.NewRequestWithContext(ctx, "POST", url+"/messages", bytes.NewReader(body))
		require.NoError(t, err)
		httpReq.Header.Set("Content-Type", "application/json")
		httpReq.Header.Set("X-Session-ID", "test-session")
		resp, err := http.DefaultClient.Do(httpReq)
		require.NoError(t, err)
		defer func() { require.NoError(t, resp.Body.Close()) }()
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			require.Fail(t, fmt.Sprintf("unexpected status code: %d, body: %s", resp.StatusCode, string(body)))
		}
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))

	case config.SSETransport:
		// First subscribe to SSE events
		client := sse.NewClient(url + "/messages")
		events := make(chan *sse.Event)
		err = client.SubscribeRaw(func(msg *sse.Event) {
			// Only process tool_result events
			if string(msg.Event) == "tool_result" {
				events <- msg
			}
		})
		require.NoError(t, err)
		defer client.Unsubscribe(events)

		// Then send the POST request
		httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
		require.NoError(t, err)
		httpReq.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(httpReq)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.NoError(t, resp.Body.Close())

		// Wait for the tool result event
		select {
		case msg := <-events:
			var toolResult mcp.CallToolResult
			require.NoError(t, json.Unmarshal(msg.Data, &toolResult))
			result = toolResult
		case <-time.After(10 * time.Second):
			require.Fail(t, "timed out waiting for SSE tool result")
		case <-ctx.Done():
			require.Fail(t, "context canceled while waiting for SSE response")
		}

	case config.StdioTransport:
		_, writeErr := stdioWriter.Write(append(body, '\n'))
		require.NoError(t, writeErr)

		// Add timeout for reading response
		ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()

		readChan := make(chan []byte)
		errChan := make(chan error)
		done := make(chan struct{})

		go func() {
			defer close(done)
			line, err := stdioReader.ReadBytes('\n')
			if err != nil {
				if !errors.Is(err, io.EOF) {
					errChan <- err
				}
				return
			}
			readChan <- line
		}()

		select {
		case line := <-readChan:
			require.NoError(t, json.Unmarshal(line, &result))
		case err := <-errChan:
			require.NoError(t, err)
		case <-ctx.Done():
			require.Fail(t, "timed out waiting for stdio response")
		case <-done:
			// Goroutine completed but no data received
			require.Fail(t, "no response received from stdio transport")
		}
	}

	return &result
}
