package server

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	chproto "github.com/ClickHouse/ch-go/proto"
	driver "github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/column"
	"github.com/ClickHouse/clickhouse-go/v2/lib/proto"
	"github.com/altinity/altinity-mcp/pkg/config"
	"github.com/stretchr/testify/require"
)

// A failing upstream proves whether validation ran before any connection,
// including the client's initial ping.
func openAPIGuardServer(t *testing.T, limit int) (*ClickHouseJWEServer, *atomic.Int64) {
	t.Helper()
	calls := &atomic.Int64{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		http.Error(w, "fake upstream unavailable", http.StatusServiceUnavailable)
	}))
	t.Cleanup(upstream.Close)
	u, err := url.Parse(upstream.URL)
	require.NoError(t, err)
	host, portText, err := net.SplitHostPort(u.Host)
	require.NoError(t, err)
	port, err := strconv.Atoi(portText)
	require.NoError(t, err)
	return &ClickHouseJWEServer{Config: config.Config{ClickHouse: config.ClickHouseConfig{
		Host: host, Port: port, Protocol: config.HTTPProtocol, Username: "default", MaxQueryLength: limit,
	}}}, calls
}

func TestOpenAPIExecuteQueryGuards(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, query   string
		limit, status int
		message       string
	}{
		{"write", "DROP TABLE t", 100, http.StatusBadRequest, "execute_query only accepts read-only statements (SELECT, WITH, SHOW, DESCRIBE, EXISTS, EXPLAIN). Use write_query for write operations."},
		{"oversized_select", "SELECT 123", 8, http.StatusRequestEntityTooLarge, "query exceeds max length (10 bytes, limit 8)"},
		{"oversized_write", "DROP TABLE t", 8, http.StatusRequestEntityTooLarge, "query exceeds max length"},
		{"oversized_invalid_sql", "SELECT 'unclosed", 8, http.StatusRequestEntityTooLarge, "query exceeds max length"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			srv, calls := openAPIGuardServer(t, tc.limit)
			req := httptest.NewRequest(http.MethodGet, "/openapi/execute_query?query="+url.QueryEscape(tc.query), nil)
			req = req.WithContext(context.WithValue(req.Context(), CHJWEServerKey, srv))
			rr := httptest.NewRecorder()
			srv.OpenAPIHandler(rr, req)
			require.Equal(t, tc.status, rr.Code, rr.Body.String())
			require.Contains(t, rr.Body.String(), tc.message)
			require.Zero(t, calls.Load(), "rejected input must not contact ClickHouse")
		})
	}
}

func TestOpenAPIDynamicBodyGuards(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, body    string
		limit, status int
		connects      bool
		unknownLength bool
	}{
		{"below_limit", `{}`, 8, http.StatusInternalServerError, true, false},
		{"exact_limit", `{"x":1}`, 7, http.StatusInternalServerError, true, false},
		{"oversized_object", `{"x":12}`, 7, http.StatusRequestEntityTooLarge, false, false},
		{"oversized_unknown_length", `{"x":12}`, 7, http.StatusRequestEntityTooLarge, false, true},
		{"trailing_whitespace", `{}` + strings.Repeat(" ", 20), 8, http.StatusRequestEntityTooLarge, false, true},
		{"second_value", `{} {}`, 8, http.StatusBadRequest, false, false},
		{"malformed", `{`, 8, http.StatusBadRequest, false, false},
		{"disabled_limit", `{"x":12}`, -1, http.StatusInternalServerError, true, false},
		{"default_limit", `{}` + strings.Repeat(" ", 10*1024*1024), 0, http.StatusRequestEntityTooLarge, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			srv, calls := openAPIGuardServer(t, tc.limit)
			req := httptest.NewRequest(http.MethodPost, "/openapi/tool", strings.NewReader(tc.body))
			if tc.unknownLength {
				req.ContentLength = -1
			}
			rr := httptest.NewRecorder()
			srv.handleDynamicToolOpenAPI(rr, req, dynamicToolMeta{ToolName: "tool", Database: "default", Table: "test"})
			require.Equal(t, tc.status, rr.Code, rr.Body.String())
			if tc.connects {
				require.Positive(t, calls.Load(), "accepted body must reach ClickHouse")
			} else {
				require.Zero(t, calls.Load(), "rejected body must not contact ClickHouse")
			}
		})
	}
}

func TestOpenAPIExecuteQuerySelectAllowed(t *testing.T) {
	t.Parallel()
	// Serve the driver's Native format for its hello, ping, and query so the
	// success regression exercises the real HTTP client without a CH fixture.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			http.Error(w, "bad query", 500)
			return
		}
		block := proto.NewBlock()
		if strings.Contains(string(query), "displayName()") {
			for _, c := range []struct{ name, typ string }{{"displayName()", "String"}, {"version()", "String"}, {"revision()", "UInt32"}, {"timezone()", "String"}} {
				if err := block.AddColumn(c.name, column.Type(c.typ)); err != nil {
					t.Error(err)
					return
				}
			}
			err = block.Append("fake", "25.1.1", uint32(driver.ClientTCPProtocolVersion), "UTC")
		} else {
			if !strings.Contains(string(query), "SELECT 1") {
				t.Errorf("unexpected query: %q", query)
				http.Error(w, "unexpected query", 400)
				return
			}
			err = block.AddColumn("1", column.Type("UInt8"))
			if err == nil {
				err = block.Append(uint8(1))
			}
		}
		if err != nil {
			t.Error(err)
			http.Error(w, "encode query", 500)
			return
		}
		buffer := new(chproto.Buffer)
		if err := block.Encode(buffer, uint64(driver.ClientTCPProtocolVersion)); err != nil {
			t.Error(err)
			return
		}
		_, _ = w.Write(buffer.Buf)
	}))
	defer upstream.Close()
	u, err := url.Parse(upstream.URL)
	require.NoError(t, err)
	host, portText, err := net.SplitHostPort(u.Host)
	require.NoError(t, err)
	port, err := strconv.Atoi(portText)
	require.NoError(t, err)
	for _, limit := range []int{len("SELECT 1"), -1} {
		t.Run(strconv.Itoa(limit), func(t *testing.T) {
			cfg := config.ClickHouseConfig{Host: host, Port: port, Protocol: config.HTTPProtocol, Username: "default", MaxQueryLength: limit, ReadOnly: false}
			srv := NewClickHouseMCPServer(config.Config{ClickHouse: cfg}, "test")
			req := httptest.NewRequest(http.MethodGet, "/openapi/execute_query?query=SELECT+1", nil)
			req = req.WithContext(context.WithValue(req.Context(), CHJWEServerKey, srv))
			rr := httptest.NewRecorder()
			srv.OpenAPIHandler(rr, req)
			require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
			require.JSONEq(t, `{"columns":["1"],"types":["UInt8"],"rows":[[1]],"count":1}`, rr.Body.String())
		})
	}
}

func TestOpenAPISchemaExecuteQueryAlwaysReadOnly(t *testing.T) {
	t.Parallel()
	srv := NewClickHouseMCPServer(config.Config{}, "test")
	rr := httptest.NewRecorder()
	srv.ServeOpenAPISchema(rr, httptest.NewRequest(http.MethodGet, "/openapi", nil))
	body, err := io.ReadAll(rr.Result().Body)
	require.NoError(t, err)
	require.Contains(t, string(body), "write statements are always rejected")
	require.NotContains(t, string(body), "In read-only mode")
}
