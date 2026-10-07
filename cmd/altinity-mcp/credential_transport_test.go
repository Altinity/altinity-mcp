package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	chproto "github.com/ClickHouse/ch-go/proto"
	driver "github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/column"
	"github.com/ClickHouse/clickhouse-go/v2/lib/proto"
	"github.com/altinity/altinity-mcp/pkg/config"
	altinitymcp "github.com/altinity/altinity-mcp/pkg/server"
	"github.com/altinity/go-mcp-oauth-sdk/jwe_auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"
)

type catalogUpstream struct {
	server    *httptest.Server
	requests  atomic.Int64
	marker    string
	mu        sync.Mutex
	discovers map[string]int
	queries   map[string]int
}

func newCatalogUpstream(t *testing.T) *catalogUpstream {
	t.Helper()
	u := &catalogUpstream{discovers: make(map[string]int), queries: make(map[string]int)}
	u.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.requests.Add(1)
		query, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		text := string(query)
		identity, _, _ := r.BasicAuth()
		if strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			switch token {
			case "alice":
				identity = "alice"
			case "bob":
				identity = "bob"
			default:
				parts := strings.Split(token, ".")
				if len(parts) == 3 {
					// Tests use the forward path; this fake CH is the credential boundary.
					if strings.Contains(token, "invalid") {
						http.Error(w, "denied", 401)
						return
					}
					identity = "oauth"
				}
			}
		}
		if identity == "" {
			identity = r.Header.Get("X-ClickHouse-User")
		}
		if identity == "" {
			identity = "static"
		}
		identity += u.marker
		block := proto.NewBlock()
		add := func(name, typ string) {
			if err := block.AddColumn(name, column.Type(typ)); err != nil {
				t.Error(err)
			}
		}
		var row []any
		switch {
		case strings.Contains(text, "displayName()"):
			add("displayName()", "String")
			add("version()", "String")
			add("revision()", "UInt32")
			add("timezone()", "String")
			row = []any{"fake", "25.1.1", uint32(driver.ClientTCPProtocolVersion), "UTC"}
		case strings.Contains(text, "system.tables"):
			u.mu.Lock()
			u.discovers[identity]++
			u.mu.Unlock()
			add("database", "String")
			add("name", "String")
			add("create_table_query", "String")
			add("comment", "String")
			row = []any{"tenant", identity, "CREATE VIEW tenant." + identity + " AS SELECT {" + identity + "_id:UInt64}", "catalog for " + identity}
		case strings.Contains(text, "FROM tenant."):
			u.mu.Lock()
			u.queries[identity]++
			u.mu.Unlock()
			if !strings.Contains(text, "tenant."+identity) {
				t.Errorf("identity %s executed foreign query %q", identity, text)
				http.Error(w, "foreign view", 403)
				return
			}
			add("identity", "String")
			row = []any{identity}
		default:
			add("1", "UInt8")
			row = []any{uint8(1)}
		}
		if err := block.Append(row...); err != nil {
			t.Error(err)
			return
		}
		buf := new(chproto.Buffer)
		if err := block.Encode(buf, uint64(driver.ClientTCPProtocolVersion)); err != nil {
			t.Error(err)
			return
		}
		_, _ = w.Write(buf.Buf)
	}))
	t.Cleanup(u.server.Close)
	return u
}
func (u *catalogUpstream) chConfig(t *testing.T) config.ClickHouseConfig {
	t.Helper()
	parsed, err := url.Parse(u.server.URL)
	require.NoError(t, err)
	host, port, err := net.SplitHostPort(parsed.Host)
	require.NoError(t, err)
	n, err := strconv.Atoi(port)
	require.NoError(t, err)
	return config.ClickHouseConfig{Host: host, Port: n, Protocol: config.HTTPProtocol, Username: "static", Password: "fake-server-password", ReadOnly: true}
}
func catalogApp(t *testing.T, cfg config.Config) *application {
	t.Helper()
	parent := altinitymcp.NewClickHouseMCPServer(cfg, "test")
	app := &application{config: cfg, mcpServer: parent}
	t.Cleanup(app.Close)
	return app
}
func catalogConfig(ch config.ClickHouseConfig, jwe, oauth bool) config.Config {
	return config.Config{ClickHouse: ch, Logging: config.LoggingConfig{Level: config.InfoLevel}, Server: config.ServerConfig{
		JWE:   config.JWEConfig{Enabled: jwe, JWESecretKey: "this-is-a-32-byte-secret-key!!", JWTSecretKey: "fake-jwt-secret"},
		OAuth: config.OAuthConfig{Enabled: oauth}, OpenAPI: config.OpenAPIConfig{Enabled: true},
		Tools: []config.ToolDefinition{{Type: "read", Name: "execute_query"}, {Type: "read", ViewRegexp: "^tenant\\..*", Prefix: "dyn_"}},
	}}
}
func catalogJWE(t *testing.T, cfg config.Config, ch config.ClickHouseConfig, user string) string {
	t.Helper()
	token, err := jwe_auth.GenerateJWEToken(map[string]interface{}{
		"host": ch.Host, "port": ch.Port, "protocol": "http", "username": user, "password": "fake-password", "exp": time.Now().Add(time.Hour).Unix(),
	}, []byte(cfg.Server.JWE.JWESecretKey), []byte(cfg.Server.JWE.JWTSecretKey))
	require.NoError(t, err)
	return token
}

type credentialRoundTripper struct {
	token, jwe string
	endpointMu sync.Mutex
	endpoint   string
}

func (tr *credentialRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header = r.Header.Clone()
	if tr.token != "" {
		r.Header.Set("Authorization", "Bearer "+tr.token)
	}
	if tr.jwe != "" {
		r.Header.Set("X-Altinity-MCP-Key", tr.jwe)
	}
	if r.URL.Query().Get("sessionid") != "" {
		tr.endpointMu.Lock()
		tr.endpoint = r.URL.String()
		tr.endpointMu.Unlock()
	}
	return http.DefaultTransport.RoundTrip(r)
}
func catalogSession(t *testing.T, ctx context.Context, endpoint string, tr *credentialRoundTripper, sse bool) *mcp.ClientSession {
	t.Helper()
	client := mcp.NewClient(&mcp.Implementation{Name: "catalog-test", Version: "1"}, nil)
	hc := &http.Client{Transport: tr}
	var transport mcp.Transport = &mcp.StreamableClientTransport{Endpoint: endpoint, HTTPClient: hc}
	if sse {
		transport = &mcp.SSEClientTransport{Endpoint: endpoint, HTTPClient: hc}
	}
	session, err := client.Connect(ctx, transport, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = session.Close() })
	return session
}
func assertCatalogSession(t *testing.T, ctx context.Context, session *mcp.ClientSession, identity, other string) {
	t.Helper()
	list, err := session.ListTools(ctx, nil)
	require.NoError(t, err)
	names := []string{}
	for _, tool := range list.Tools {
		names = append(names, tool.Name)
	}
	require.Contains(t, names, "dyn_tenant_"+identity)
	require.NotContains(t, names, "dyn_tenant_"+other)
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "dyn_tenant_" + identity, Arguments: map[string]any{identity + "_id": 1}})
	require.NoError(t, err)
	require.False(t, result.IsError, fmt.Sprint(result.Content))
	data, err := json.Marshal(result)
	require.NoError(t, err)
	require.Contains(t, string(data), identity)
	_, err = session.CallTool(ctx, &mcp.CallToolParams{Name: "dyn_tenant_" + other, Arguments: map[string]any{other + "_id": 1}})
	require.Error(t, err)
}
func catalogSchema(t *testing.T, endpoint string, tr *credentialRoundTripper, identity, other string) {
	t.Helper()
	hc := &http.Client{Transport: tr}
	response, err := hc.Get(endpoint + "/openapi")
	require.NoError(t, err)
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	require.Equal(t, 200, response.StatusCode, string(body))
	require.Contains(t, string(body), "dyn_tenant_"+identity)
	require.Contains(t, string(body), identity+"_id")
	require.NotContains(t, string(body), "dyn_tenant_"+other)
}
func TestCredentialCatalogAnonymousSchema(t *testing.T) {
	for _, sse := range []bool{false, true} {
		for _, auth := range []string{"jwe", "oauth", "combined"} {
			t.Run(fmt.Sprintf("%s/sse=%t", auth, sse), func(t *testing.T) {
				up := newCatalogUpstream(t)
				cfg := catalogConfig(up.chConfig(t), auth != "oauth", auth != "jwe")
				app := catalogApp(t, cfg)
				var handler http.Handler = app.buildHTTPHandler(cfg, app.mcpServer.MCPServer)
				if sse {
					handler = app.buildSSEHandler(cfg, app.mcpServer.MCPServer)
				}
				web := httptest.NewServer(handler)
				defer web.Close()
				response, err := http.Get(web.URL + "/openapi")
				require.NoError(t, err)
				defer response.Body.Close()
				require.Equal(t, 401, response.StatusCode)
				require.Zero(t, up.requests.Load())
			})
		}
	}
}
func TestCredentialCatalogHTTPIsolation(t *testing.T) {
	for _, auth := range []string{"jwe", "oauth", "combined"} {
		t.Run(auth, func(t *testing.T) {
			up := newCatalogUpstream(t)
			bobUp := up
			if auth == "jwe" {
				bobUp = newCatalogUpstream(t)
			}
			cfg := catalogConfig(up.chConfig(t), auth != "oauth", auth != "jwe")
			app := catalogApp(t, cfg)
			web := httptest.NewServer(app.buildHTTPHandler(cfg, app.mcpServer.MCPServer))
			defer web.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			trs := []*credentialRoundTripper{{token: "alice"}, {token: "bob"}}
			if auth != "oauth" {
				for i, id := range []string{"alice", "bob"} {
					ch := cfg.ClickHouse
					if i == 1 {
						ch = bobUp.chConfig(t)
					}
					trs[i].jwe = catalogJWE(t, cfg, ch, id)
				}
			}
			if auth == "combined" {
				trs[0].token = "bob"
				trs[1].token = "alice"
			}
			endpoints := []string{web.URL, web.URL}
			if auth == "jwe" {
				endpoints[0] += "/" + trs[0].jwe
				endpoints[1] += "/" + trs[1].jwe
				trs[0].token = ""
				trs[1].token = ""
			}
			sessions := []*mcp.ClientSession{catalogSession(t, ctx, endpoints[0], trs[0], false), catalogSession(t, ctx, endpoints[1], trs[1], false)}
			var wg sync.WaitGroup
			for i, id := range []string{"alice", "bob"} {
				wg.Add(1)
				go func(i int, id string) {
					defer wg.Done()
					other := []string{"bob", "alice"}[i]
					for j := 0; j < 3; j++ {
						assertCatalogSession(t, ctx, sessions[i], id, other)
						catalogSchema(t, web.URL, trs[i], id, other)
						catalogREST(t, web.URL, trs[i], id, other)
					}
				}(i, id)
			}
			wg.Wait()
			up.mu.Lock()
			require.Equal(t, 1, up.discovers["alice"])
			require.Equal(t, 6, up.queries["alice"])
			up.mu.Unlock()
			bobUp.mu.Lock()
			require.Equal(t, 1, bobUp.discovers["bob"])
			require.Equal(t, 6, bobUp.queries["bob"])
			bobUp.mu.Unlock()
		})
	}
}
func TestCredentialCatalogSSEOwnership(t *testing.T) {
	for _, auth := range []string{"oauth", "jwe", "combined"} {
		t.Run(auth, func(t *testing.T) {
			up := newCatalogUpstream(t)
			cfg := catalogConfig(up.chConfig(t), auth != "oauth", auth != "jwe")
			app := catalogApp(t, cfg)
			web := httptest.NewServer(app.buildSSEHandler(cfg, app.mcpServer.MCPServer))
			defer web.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			aTr := &credentialRoundTripper{token: "alice"}
			bTr := &credentialRoundTripper{token: "bob"}
			aEndpoint, bEndpoint := web.URL+"/sse", web.URL+"/sse"
			if auth != "oauth" {
				aTr.jwe = catalogJWE(t, cfg, cfg.ClickHouse, "alice")
				bTr.jwe = catalogJWE(t, cfg, cfg.ClickHouse, "bob")
			}
			if auth == "jwe" {
				aEndpoint = web.URL + "/" + aTr.jwe + "/sse"
				bEndpoint = web.URL + "/" + bTr.jwe + "/sse"
				aTr.token = ""
				bTr.token = ""
			}
			if auth == "combined" {
				aTr.token = "bob"
				bTr.token = "alice"
			}
			a := catalogSession(t, ctx, aEndpoint, aTr, true)
			a2 := catalogSession(t, ctx, aEndpoint, aTr, true)
			b := catalogSession(t, ctx, bEndpoint, bTr, true)
			catalogSchema(t, web.URL, aTr, "alice", "bob")
			catalogREST(t, web.URL, aTr, "alice", "bob")
			assertCatalogSession(t, ctx, a, "alice", "bob")
			assertCatalogSession(t, ctx, a2, "alice", "bob")
			assertCatalogSession(t, ctx, b, "bob", "alice")
			aTr.endpointMu.Lock()
			endpoint := aTr.endpoint
			aTr.endpointMu.Unlock()
			require.NotEmpty(t, endpoint)
			if auth == "jwe" {
				endpoint = strings.Replace(endpoint, "/"+aTr.jwe+"/sse", "/"+bTr.jwe+"/sse", 1)
			}
			up.mu.Lock()
			before := up.queries["alice"]
			up.mu.Unlock()
			request, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(`{"jsonrpc":"2.0","id":99,"method":"tools/call","params":{"name":"dyn_tenant_alice","arguments":{"alice_id":1}}}`))
			require.NoError(t, err)
			request.Header.Set("Content-Type", "application/json")
			response, err := (&http.Client{Transport: bTr}).Do(request)
			require.NoError(t, err)
			response.Body.Close()
			require.Equal(t, 404, response.StatusCode)
			up.mu.Lock()
			require.Equal(t, before, up.queries["alice"])
			require.Equal(t, 1, up.discovers["alice"])
			require.Equal(t, 1, up.discovers["bob"])
			up.mu.Unlock()
			pool := app.ssePools[0]
			pool.mu.Lock()
			require.Equal(t, 2, len(pool.buckets))
			require.Equal(t, 3, pool.active)
			pool.mu.Unlock()
			require.NoError(t, a.Close())
			require.NoError(t, a2.Close())
			require.NoError(t, b.Close())
			require.Eventually(t, func() bool { pool.mu.Lock(); defer pool.mu.Unlock(); return len(pool.buckets) == 0 && pool.active == 0 }, 3*time.Second, 10*time.Millisecond)
			if auth == "jwe" {
				request.URL, err = url.Parse(strings.Replace(endpoint, "/"+bTr.jwe+"/sse", "/"+aTr.jwe+"/sse", 1))
				require.NoError(t, err)
			}
			request.Body, err = request.GetBody()
			require.NoError(t, err)
			response, err = (&http.Client{Transport: aTr}).Do(request)
			require.NoError(t, err)
			response.Body.Close()
			require.Equal(t, 404, response.StatusCode)
			pool.mu.Lock()
			require.Empty(t, pool.buckets)
			pool.mu.Unlock()
		})
	}
}
func writeCatalogReload(t *testing.T, app *application, cfg config.Config) {
	t.Helper()
	if app.configFile == "" {
		app.configFile = filepath.Join(t.TempDir(), "config.json")
		app.stopConfigReload = make(chan struct{})
	}
	data, err := json.Marshal(cfg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(app.configFile, data, 0600))
	require.NoError(t, app.reloadConfig(&mockCommand{flags: map[string]interface{}{}, setFlags: map[string]bool{}, stringMaps: map[string]map[string]string{}}))
}
func TestCredentialCatalogReloadGenerations(t *testing.T) {
	for _, sse := range []bool{false, true} {
		t.Run(fmt.Sprintf("sse=%t", sse), func(t *testing.T) {
			oldUp := newCatalogUpstream(t)
			oldUp.marker = "_old"
			newUp := newCatalogUpstream(t)
			newUp.marker = "_new"
			cfg := catalogConfig(oldUp.chConfig(t), false, true)
			app := catalogApp(t, cfg)
			var handler http.Handler = app.buildHTTPHandler(cfg, app.mcpServer.MCPServer)
			endpointSuffix := ""
			if sse {
				handler = app.buildSSEHandler(cfg, app.mcpServer.MCPServer)
				endpointSuffix = "/sse"
			}
			web := httptest.NewServer(handler)
			defer web.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			tr := &credentialRoundTripper{token: "alice"}
			session := catalogSession(t, ctx, web.URL+endpointSuffix, tr, sse)
			catalogSchema(t, web.URL, tr, "alice_old", "alice_new")
			oldParent := app.mcpServer
			tr.endpointMu.Lock()
			oldEndpoint := tr.endpoint
			tr.endpointMu.Unlock()
			next := cfg
			next.ClickHouse = newUp.chConfig(t)
			next.Server.Tools = []config.ToolDefinition{{Type: "read", Name: "execute_query"}, {Type: "read", ViewRegexp: "^tenant\\..*", Prefix: "next_"}}
			writeCatalogReload(t, app, next)
			require.NotSame(t, oldParent, app.mcpServer)
			if sse {
				request, err := http.NewRequest(http.MethodPost, oldEndpoint, strings.NewReader(`{"jsonrpc":"2.0","id":19,"method":"tools/list"}`))
				require.NoError(t, err)
				request.Header.Set("Content-Type", "application/json")
				response, err := (&http.Client{Transport: tr}).Do(request)
				require.NoError(t, err)
				response.Body.Close()
				require.Equal(t, 404, response.StatusCode)
				session = catalogSession(t, ctx, web.URL+"/sse", tr, true)
			}
			list, err := session.ListTools(ctx, nil)
			require.NoError(t, err)
			names := []string{}
			for _, tool := range list.Tools {
				names = append(names, tool.Name)
			}
			require.Contains(t, names, "next_tenant_alice_new")
			require.NotContains(t, names, "dyn_tenant_alice_old")
			response, err := (&http.Client{Transport: tr}).Get(web.URL + "/openapi")
			require.NoError(t, err)
			body, err := io.ReadAll(response.Body)
			response.Body.Close()
			require.NoError(t, err)
			require.Equal(t, 200, response.StatusCode)
			require.Contains(t, string(body), "next_tenant_alice_new")
			require.NotContains(t, string(body), "dyn_tenant_alice_old")
			oldUp.mu.Lock()
			require.Equal(t, 1, oldUp.discovers["alice_old"])
			oldUp.mu.Unlock()
			newUp.mu.Lock()
			require.Equal(t, 1, newUp.discovers["alice_new"])
			newUp.mu.Unlock()
		})
	}
}
func TestCredentialCatalogExpiredSSEBearer(t *testing.T) {
	up := newCatalogUpstream(t)
	cfg := catalogConfig(up.chConfig(t), false, true)
	app := catalogApp(t, cfg)
	web := httptest.NewServer(app.buildSSEHandler(cfg, app.mcpServer.MCPServer))
	defer web.Close()
	tr := &credentialRoundTripper{token: makeUnsignedJWT(t, map[string]interface{}{"exp": time.Now().Add(-time.Hour).Unix(), "email": "alice@example.com"})}
	request, err := http.NewRequest(http.MethodPost, web.URL+"/sse?sessionid=unowned", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	require.NoError(t, err)
	request.Header.Set("Content-Type", "application/json")
	response, err := (&http.Client{Transport: tr}).Do(request)
	require.NoError(t, err)
	response.Body.Close()
	require.Equal(t, 401, response.StatusCode)
	require.Zero(t, up.requests.Load())
	pool := app.ssePools[0]
	pool.mu.Lock()
	require.Empty(t, pool.buckets)
	pool.mu.Unlock()
}

func catalogREST(t *testing.T, endpoint string, tr *credentialRoundTripper, identity, other string) {
	t.Helper()
	// The exact schema supports header auth. JWE-only REST routes retain their
	// existing tokenized path contract.
	prefix := ""
	if tr.jwe != "" && tr.token == "" {
		prefix = "/" + tr.jwe
	}
	client := &http.Client{Transport: tr}
	response, err := client.Post(endpoint+prefix+"/openapi/dyn_tenant_"+identity, "application/json", strings.NewReader(fmt.Sprintf(`{"%s_id":1}`, identity)))
	require.NoError(t, err)
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	require.NoError(t, err)
	require.Equal(t, 200, response.StatusCode, string(body))
	require.Contains(t, string(body), identity)
	response, err = client.Post(endpoint+prefix+"/openapi/dyn_tenant_"+other, "application/json", strings.NewReader(fmt.Sprintf(`{"%s_id":1}`, other)))
	require.NoError(t, err)
	response.Body.Close()
	require.Equal(t, 404, response.StatusCode)
}

// Reload while schema requests are active: an endpoint and its discovery rules
// must always come from the same immutable parent snapshot.
func TestCredentialCatalogConcurrentReloadSnapshots(t *testing.T) {
	oldUp := newCatalogUpstream(t)
	oldUp.marker = "_old"
	newUp := newCatalogUpstream(t)
	newUp.marker = "_new"
	oldCfg := catalogConfig(oldUp.chConfig(t), false, true)
	newCfg := catalogConfig(newUp.chConfig(t), false, true)
	newCfg.Logging.Level = config.DebugLevel
	newCfg.Server.Tools = []config.ToolDefinition{{Type: "read", ViewRegexp: "^tenant\\..*", Prefix: "next_"}}
	app := catalogApp(t, oldCfg)
	web := httptest.NewServer(app.buildHTTPHandler(oldCfg, app.mcpServer.MCPServer))
	defer web.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for j := 0; j < 15; j++ {
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, web.URL+"/openapi", nil)
				if err != nil {
					t.Error(err)
					return
				}
				req.Header.Set("Authorization", "Bearer alice")
				response, err := http.DefaultClient.Do(req)
				if err != nil {
					t.Error(err)
					return
				}
				data, err := io.ReadAll(response.Body)
				response.Body.Close()
				if err != nil {
					t.Error(err)
					return
				}
				if response.StatusCode != 200 {
					t.Errorf("schema status %d", response.StatusCode)
					return
				}
				body := string(data)
				old := strings.Contains(body, "dyn_tenant_alice_old")
				next := strings.Contains(body, "next_tenant_alice_new")
				if strings.Contains(body, "dyn_tenant_alice_new") || strings.Contains(body, "next_tenant_alice_old") || (old == next) {
					t.Errorf("mixed catalog generation: %s", body)
					return
				}
			}
		}()
	}
	close(start)
	for i := 0; i < 4; i++ {
		writeCatalogReload(t, app, newCfg)
		writeCatalogReload(t, app, oldCfg)
	}
	wg.Wait()
	catalogSchema(t, web.URL, &credentialRoundTripper{token: "alice"}, "alice_old", "alice_new")
}

func TestCredentialCatalogReservedOpenAPIToolName(t *testing.T) {
	for _, sse := range []bool{false, true} {
		t.Run(fmt.Sprintf("sse=%t", sse), func(t *testing.T) {
			up := newCatalogUpstream(t)
			cfg := catalogConfig(up.chConfig(t), true, true)
			cfg.Server.Tools = []config.ToolDefinition{{Type: "read", Name: "execute_query"}, {Type: "read", Name: "openapi", ViewRegexp: "^tenant\\.alice$"}}
			app := catalogApp(t, cfg)
			var handler http.Handler = app.buildHTTPHandler(cfg, app.mcpServer.MCPServer)
			if sse {
				handler = app.buildSSEHandler(cfg, app.mcpServer.MCPServer)
			}
			web := httptest.NewServer(handler)
			defer web.Close()
			client := &http.Client{Transport: &credentialRoundTripper{token: "alice"}}
			response, err := client.Post(web.URL+"/openapi/openapi", "application/json", strings.NewReader(`{"alice_id":1}`))
			require.NoError(t, err)
			body, err := io.ReadAll(response.Body)
			response.Body.Close()
			require.NoError(t, err)
			require.Equal(t, 200, response.StatusCode, string(body))
			require.Contains(t, string(body), "alice")
			up.mu.Lock()
			require.Equal(t, 1, up.discovers["alice"])
			require.Equal(t, 1, up.queries["alice"])
			up.mu.Unlock()
		})
	}
}

func TestCredentialCatalogPartialJWEUsesOAuthEndpoint(t *testing.T) {
	for _, sse := range []bool{false, true} {
		t.Run(fmt.Sprintf("sse=%t", sse), func(t *testing.T) {
			operator := newCatalogUpstream(t)
			rejected := newCatalogUpstream(t)
			cfg := catalogConfig(operator.chConfig(t), true, true)
			app := catalogApp(t, cfg)
			var handler http.Handler = app.buildHTTPHandler(cfg, app.mcpServer.MCPServer)
			suffix := ""
			if sse {
				handler = app.buildSSEHandler(cfg, app.mcpServer.MCPServer)
				suffix = "/sse"
			}
			web := httptest.NewServer(handler)
			defer web.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			for _, partial := range []string{"host_only", "username_only"} {
				t.Run(partial, func(t *testing.T) {
					ch := rejected.chConfig(t)
					claims := map[string]interface{}{"port": ch.Port, "protocol": "http", "password": "unused-password", "exp": time.Now().Add(time.Hour).Unix()}
					if partial == "host_only" {
						claims["host"] = ch.Host
					} else {
						claims["username"] = "unused-user"
					}
					token, err := jwe_auth.GenerateJWEToken(claims, []byte(cfg.Server.JWE.JWESecretKey), []byte(cfg.Server.JWE.JWTSecretKey))
					require.NoError(t, err)
					tr := &credentialRoundTripper{token: "alice", jwe: token}
					session := catalogSession(t, ctx, web.URL+suffix, tr, sse)
					assertCatalogSession(t, ctx, session, "alice", "bob")
					catalogSchema(t, web.URL, tr, "alice", "bob")
					catalogREST(t, web.URL, tr, "alice", "bob")
				})
			}
			require.Zero(t, rejected.requests.Load(), "partial JWE routing and credentials must never be used")
			operator.mu.Lock()
			require.Equal(t, 1, operator.discovers["alice"], "partial JWEs share the effective OAuth cache key")
			require.Equal(t, 4, operator.queries["alice"])
			operator.mu.Unlock()
		})
	}
}

func TestLegacyClientEffectiveCredentials(t *testing.T) {
	for _, auth := range []string{"oauth", "jwe", "combined"} {
		t.Run(auth, func(t *testing.T) {
			up := newCatalogUpstream(t)
			cfg := catalogConfig(up.chConfig(t), auth != "oauth", auth != "jwe")
			app := catalogApp(t, cfg)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			tokenParam := ""
			if auth == "oauth" {
				ctx = context.WithValue(ctx, altinitymcp.OAuthTokenKey, "alice")
			} else {
				tokenParam = catalogJWE(t, cfg, cfg.ClickHouse, "alice")
				// The context intentionally contains a different validated JWE. The
				// legacy API's explicit argument must retain its historical precedence.
				other := catalogJWE(t, cfg, cfg.ClickHouse, "bob")
				claims, err := app.mcpServer.ParseJWEClaims(other)
				require.NoError(t, err)
				ctx = context.WithValue(ctx, altinitymcp.JWETokenKey, other)
				ctx = context.WithValue(ctx, altinitymcp.JWEClaimsKey, claims)
				if auth == "combined" {
					ctx = context.WithValue(ctx, altinitymcp.OAuthTokenKey, "bob")
				}
			}
			client, err := app.mcpServer.GetClickHouseClient(ctx, tokenParam)
			require.NoError(t, err)
			defer client.Close()
			result, err := client.ExecuteQuery(ctx, "SELECT * FROM tenant.alice")
			require.NoError(t, err)
			require.Equal(t, [][]interface{}{{"alice"}}, result.Rows)
			up.mu.Lock()
			require.Equal(t, 1, up.queries["alice"])
			require.Zero(t, up.queries["bob"])
			require.Zero(t, up.queries["static"])
			up.mu.Unlock()
		})
	}
}

func TestCredentialCatalogUnchangedPeriodicReload(t *testing.T) {
	up := newCatalogUpstream(t)
	unused := newCatalogUpstream(t)
	path := filepath.Join(t.TempDir(), "config.json")
	cfg := catalogConfig(up.chConfig(t), false, true)
	cfg.ReloadTime = 1
	data, err := json.Marshal(cfg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, data, 0600))
	cmd := &mockCommand{flags: map[string]interface{}{"clickhouse-port": cfg.ClickHouse.Port}, setFlags: map[string]bool{"clickhouse-port": true}, stringMaps: map[string]map[string]string{}}
	initial, err := config.LoadConfigFromFile(path)
	require.NoError(t, err)
	overrideWithCLIFlags(initial, cmd)
	initial.RemovedKeyWarnings = []string{"previous diagnostic only"}
	app := catalogApp(t, *initial)
	app.configFile = path
	app.stopConfigReload = make(chan struct{})
	web := httptest.NewServer(app.buildSSEHandler(*initial, app.mcpServer.MCPServer))
	defer web.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	tr := &credentialRoundTripper{token: "alice"}
	session := catalogSession(t, ctx, web.URL+"/sse", tr, true)
	assertCatalogSession(t, ctx, session, "alice", "bob")
	initialParent := app.mcpServer
	tr.endpointMu.Lock()
	initialEndpoint := tr.endpoint
	tr.endpointMu.Unlock()
	// CLI overrides the on-disk endpoint. Restart-only metrics and multicluster
	// settings also must not replace the effective catalog generation. ReloadTime
	// is bookkeeping; observing it below proves the periodic tick completed.
	next := *initial
	next.ReloadTime = 2
	next.ClickHouse.Port = unused.chConfig(t).Port
	next.Server.Metrics.Enabled = true
	next.Multicluster.CatalogCacheMax = initial.Multicluster.CatalogCacheMax + 1
	data, err = json.Marshal(next)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, data, 0600))
	loopCtx, stopLoop := context.WithCancel(ctx)
	loopDone := make(chan struct{})
	go func() { defer close(loopDone); app.configReloadLoop(loopCtx, cmd) }()
	t.Cleanup(func() { stopLoop(); <-loopDone })
	require.Eventually(t, func() bool { return app.GetCurrentConfig().ReloadTime == 2 }, 5*time.Second, 10*time.Millisecond)
	app.configMutex.RLock()
	parent := app.mcpServer
	app.configMutex.RUnlock()
	require.Same(t, initialParent, parent)
	current := app.GetCurrentConfig()
	require.Equal(t, initial.Multicluster, current.Multicluster)
	require.False(t, current.Server.Metrics.Enabled)
	require.Empty(t, current.RemovedKeyWarnings)
	assertCatalogSession(t, ctx, session, "alice", "bob")
	catalogSchema(t, web.URL, tr, "alice", "bob")
	tr.endpointMu.Lock()
	require.Equal(t, initialEndpoint, tr.endpoint)
	tr.endpointMu.Unlock()
	require.NoError(t, app.reloadConfig(cmd))
	app.configMutex.RLock()
	parent = app.mcpServer
	app.configMutex.RUnlock()
	require.Same(t, initialParent, parent)
	up.mu.Lock()
	require.Equal(t, 1, up.discovers["alice"], "unchanged polls preserve the credential cache")
	up.mu.Unlock()
	require.Zero(t, unused.requests.Load())
}

func TestCredentialCatalogRetiredSnapshotCompletesDiscovery(t *testing.T) {
	oldUp := newCatalogUpstream(t)
	oldUp.marker = "_old"
	newUp := newCatalogUpstream(t)
	newUp.marker = "_new"
	cfg := catalogConfig(oldUp.chConfig(t), false, true)
	app := catalogApp(t, cfg)
	oldParent := app.mcpServer
	request := httptest.NewRequest(http.MethodPost, "/openapi/dyn_tenant_alice_old", strings.NewReader(`{"alice_old_id":1}`))
	request.Header.Set("Authorization", "Bearer alice")
	response := httptest.NewRecorder()
	// Capture through production snapshot middleware, then retire the captured
	// generation before it has ever created a catalog cache.
	app.withServerSnapshot(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next := cfg
		next.ClickHouse = newUp.chConfig(t)
		writeCatalogReload(t, app, next)
		captured := altinitymcp.GetClickHouseJWEServerFromContext(r.Context())
		require.Same(t, oldParent, captured)
		captured.OpenAPIHandler(w, r)
	})).ServeHTTP(response, request)
	require.Equal(t, 200, response.Code, response.Body.String())
	require.Contains(t, response.Body.String(), "alice_old")
	oldUp.mu.Lock()
	require.Equal(t, 1, oldUp.discovers["alice_old"])
	require.Equal(t, 1, oldUp.queries["alice_old"])
	oldUp.mu.Unlock()
	require.Zero(t, newUp.requests.Load())
}

func TestCredentialCatalogJWEIncompleteTransportMessage(t *testing.T) {
	for _, sse := range []bool{false, true} {
		for _, partial := range []string{"host_only", "username_only"} {
			t.Run(fmt.Sprintf("%s/sse=%t", partial, sse), func(t *testing.T) {
				up := newCatalogUpstream(t)
				cfg := catalogConfig(up.chConfig(t), true, false)
				app := catalogApp(t, cfg)
				claims := map[string]interface{}{"exp": time.Now().Add(time.Hour).Unix()}
				if partial == "host_only" {
					claims["host"] = cfg.ClickHouse.Host
				} else {
					claims["username"] = "alice"
				}
				token, err := jwe_auth.GenerateJWEToken(claims, []byte(cfg.Server.JWE.JWESecretKey), []byte(cfg.Server.JWE.JWTSecretKey))
				require.NoError(t, err)
				var handler http.Handler = app.buildHTTPHandler(cfg, app.mcpServer.MCPServer)
				suffix := ""
				method := http.MethodPost
				if sse {
					handler = app.buildSSEHandler(cfg, app.mcpServer.MCPServer)
					suffix = "/sse"
					method = http.MethodGet
				}
				web := httptest.NewServer(handler)
				defer web.Close()
				request, err := http.NewRequest(method, web.URL+"/"+token+suffix, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
				require.NoError(t, err)
				request.Header.Set("Content-Type", "application/json")
				response, err := http.DefaultClient.Do(request)
				require.NoError(t, err)
				body, err := io.ReadAll(response.Body)
				response.Body.Close()
				require.NoError(t, err)
				require.Equal(t, 401, response.StatusCode)
				require.Equal(t, altinitymcp.ErrJWEIncompleteConnection.Error(), strings.TrimSpace(string(body)))
				require.Zero(t, up.requests.Load())
			})
		}
	}
}

func TestCredentialCatalogNoAuthUnifiedTransports(t *testing.T) {
	for _, sse := range []bool{false, true} {
		t.Run(fmt.Sprintf("sse=%t", sse), func(t *testing.T) {
			up := newCatalogUpstream(t)
			cfg := catalogConfig(up.chConfig(t), false, false)
			app := catalogApp(t, cfg)
			var handler http.Handler = app.buildHTTPHandler(cfg, app.mcpServer.MCPServer)
			suffix := ""
			if sse {
				handler = app.buildSSEHandler(cfg, app.mcpServer.MCPServer)
				suffix = "/sse"
			}
			web := httptest.NewServer(handler)
			defer web.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			tr := &credentialRoundTripper{}
			session := catalogSession(t, ctx, web.URL+suffix, tr, sse)
			assertCatalogSession(t, ctx, session, "static", "foreign")
			catalogSchema(t, web.URL, tr, "static", "foreign")
			up.mu.Lock()
			require.Equal(t, 1, up.discovers["static"])
			require.Equal(t, 1, up.queries["static"])
			up.mu.Unlock()
		})
	}
}
