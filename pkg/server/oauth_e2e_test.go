package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/altinity/altinity-mcp/pkg/config"
	"github.com/docker/docker/api/types/container"
	"github.com/go-jose/go-jose/v4"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// TestOAuthE2EWithMockOIDC is an end-to-end test that validates the full OAuth2 flow
// through real MCP client and OpenAPI endpoints:
// 1. A lightweight mock OIDC provider (in-process Go HTTP server)
// 2. ClickHouse (Antalya build) with token_processors for JWT auth
// 3. MCP server forwarding Bearer tokens to ClickHouse
func TestOAuthE2EWithMockOIDC(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	ctx := context.Background()

	// ---------- Step 1: Start mock OIDC provider ----------
	provider, dockerOIDCURL := newTestOAuthProviderReachableFromDocker(t, nil)
	t.Logf("Mock OIDC provider URL (Docker): %s", dockerOIDCURL)

	// ---------- Step 2: Start ClickHouse with token_processors ----------
	chConfig := setupAntalyaClickHouseWithOIDC(t, ctx, dockerOIDCURL)

	// ---------- Step 3: Issue a signed JWT ----------
	const tokenSubject = "test-oauth-user"
	token := provider.issueJWT(t, map[string]interface{}{
		"sub": tokenSubject,
		"iss": dockerOIDCURL,
		"aud": "test-audience",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	})
	require.NotEmpty(t, token, "OAuth token should not be empty")

	// Verify it looks like a JWT
	parts := strings.Split(token, ".")
	require.Equal(t, 3, len(parts), "Token should be a JWT with 3 parts")

	// ---------- Step 4: Test via MCP Client (InMemoryTransports) ----------
	t.Run("MCP_Client", func(t *testing.T) {
		srv := NewClickHouseMCPServer(config.Config{
			ClickHouse: chConfig,
			Server: config.ServerConfig{
				OAuth: config.OAuthConfig{
					Enabled: true,
					Mode:    "forward",
				},
			},
		}, "test-e2e")

		// Create in-memory transports
		clientTransport, serverTransport := mcp.NewInMemoryTransports()

		// Connect server with context containing the server instance and OAuth token
		srvCtx := context.WithValue(ctx, CHJWEServerKey, srv)
		srvCtx = context.WithValue(srvCtx, OAuthTokenKey, token)
		serverSession, err := srv.MCPServer.Connect(srvCtx, serverTransport, nil)
		require.NoError(t, err, "Server connect should succeed")
		defer serverSession.Close()

		// Connect MCP client
		mcpClient := mcp.NewClient(
			&mcp.Implementation{Name: "test-oauth-client", Version: "v0.0.1"}, nil,
		)
		clientSession, err := mcpClient.Connect(ctx, clientTransport, nil)
		require.NoError(t, err, "Client connect should succeed")
		defer clientSession.Close()

		// 4a. ListTools — verify execute_query is registered
		t.Run("ListTools", func(t *testing.T) {
			toolsResult, err := clientSession.ListTools(ctx, nil)
			require.NoError(t, err)
			require.NotNil(t, toolsResult)

			var toolNames []string
			for _, tool := range toolsResult.Tools {
				toolNames = append(toolNames, tool.Name)
			}
			require.Contains(t, toolNames, "execute_query", "execute_query tool should be registered")
			t.Logf("Listed tools: %v", toolNames)
		})

		// 4b. CallTool(execute_query) — query should reach ClickHouse via OAuth Bearer token
		t.Run("CallTool_ExecuteQuery", func(t *testing.T) {
			res, err := clientSession.CallTool(ctx, &mcp.CallToolParams{
				Name:      "execute_query",
				Arguments: map[string]any{"query": "SELECT currentUser() AS user, 1 AS ok"},
			})
			require.NoError(t, err, "CallTool should succeed")
			require.NotNil(t, res)
			require.False(t, res.IsError, "Tool result should not be an error")
			require.Greater(t, len(res.Content), 0, "Result should have content")

			textContent, ok := res.Content[0].(*mcp.TextContent)
			require.True(t, ok, "Content should be TextContent")
			require.NotEmpty(t, textContent.Text)
			t.Logf("execute_query result: %s", textContent.Text)

			// Parse the JSON result and verify it has rows
			var queryResult map[string]interface{}
			require.NoError(t, json.Unmarshal([]byte(textContent.Text), &queryResult))
			rows, ok := queryResult["rows"].([]interface{})
			require.True(t, ok, "Result should have Rows")
			require.Greater(t, len(rows), 0, "Should have at least one row")
			require.Equal(t, tokenSubject, firstStringCell(t, rows))
		})

		// 4c. ListResources — verify clickhouse://schema is registered
		t.Run("ListResources", func(t *testing.T) {
			resourcesResult, err := clientSession.ListResources(ctx, nil)
			require.NoError(t, err)
			require.NotNil(t, resourcesResult)

			var resourceURIs []string
			for _, r := range resourcesResult.Resources {
				resourceURIs = append(resourceURIs, r.URI)
			}
			require.Contains(t, resourceURIs, "clickhouse://schema", "Schema resource should be registered")
			t.Logf("Listed resources: %v", resourceURIs)
		})

		// 4d. ReadResource(clickhouse://schema) — should return schema via OAuth
		t.Run("ReadResource_Schema", func(t *testing.T) {
			res, err := clientSession.ReadResource(ctx, &mcp.ReadResourceParams{
				URI: "clickhouse://schema",
			})
			require.NoError(t, err, "ReadResource should succeed")
			require.NotNil(t, res)
			require.Greater(t, len(res.Contents), 0, "Should have contents")
			require.NotEmpty(t, res.Contents[0].Text, "Schema should not be empty")
			t.Logf("Schema resource (first 200 chars): %.200s...", res.Contents[0].Text)
		})
	})

	// ---------- Step 5: Test via OpenAPI Client (httptest) ----------
	t.Run("OpenAPI_Client", func(t *testing.T) {
		srv := NewClickHouseMCPServer(config.Config{
			ClickHouse: chConfig,
			Server: config.ServerConfig{
				OAuth: config.OAuthConfig{
					Enabled: true,
					Mode:    "forward",
				},
			},
		}, "test-e2e")

		// 5a. Execute query via OpenAPI with Bearer token
		t.Run("ExecuteQuery", func(t *testing.T) {
			query := url.QueryEscape("SELECT currentUser() AS user, 1 AS ok")
			req := httptest.NewRequest(http.MethodGet, "/openapi/execute_query?query="+query, nil)
			req.Header.Set("Authorization", "Bearer "+token)
			reqCtx := context.WithValue(req.Context(), CHJWEServerKey, srv)
			req = req.WithContext(reqCtx)

			rr := httptest.NewRecorder()
			srv.OpenAPIHandler(rr, req)

			require.Equal(t, http.StatusOK, rr.Code, "OpenAPI should return 200, body: %s", rr.Body.String())

			var result map[string]interface{}
			require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &result))
			rows, ok := result["rows"].([]interface{})
			require.True(t, ok, "Result should have Rows")
			require.Greater(t, len(rows), 0, "Should have at least one row")
			require.Equal(t, tokenSubject, firstStringCell(t, rows))
			t.Logf("OpenAPI result: %s", rr.Body.String())
		})

		// 5b. OpenAPI schema endpoint should work
		t.Run("OpenAPISchema", func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/openapi", nil)
			req.Header.Set("Authorization", "Bearer "+token)
			reqCtx := context.WithValue(req.Context(), CHJWEServerKey, srv)
			req = req.WithContext(reqCtx)

			rr := httptest.NewRecorder()
			srv.OpenAPIHandler(rr, req)

			require.Equal(t, http.StatusOK, rr.Code, "OpenAPI schema should return 200")
			require.Contains(t, rr.Body.String(), "execute_query", "Schema should contain execute_query")
			t.Logf("OpenAPI schema (first 200 chars): %.200s...", rr.Body.String())
		})

		t.Run("ExecuteQuery_MissingBearerToken", func(t *testing.T) {
			query := url.QueryEscape("SELECT currentUser() AS user")
			req := httptest.NewRequest(http.MethodGet, "/openapi/execute_query?query="+query, nil)
			reqCtx := context.WithValue(req.Context(), CHJWEServerKey, srv)
			req = req.WithContext(reqCtx)

			rr := httptest.NewRecorder()
			srv.OpenAPIHandler(rr, req)

			require.Equal(t, http.StatusUnauthorized, rr.Code, "missing token should be rejected before ClickHouse query execution")
			require.Contains(t, rr.Body.String(), "Missing authentication token")
		})

		t.Run("ExecuteQuery_InvalidBearerTokenRejectedByClickHouse", func(t *testing.T) {
			query := url.QueryEscape("SELECT currentUser() AS user")
			req := httptest.NewRequest(http.MethodGet, "/openapi/execute_query?query="+query, nil)
			req.Header.Set("Authorization", "Bearer "+generateUnsignedJWT(t, map[string]any{
				"sub":   "forged-user",
				"iss":   "http://forged-issuer.invalid",
				"aud":   []string{"forged-client"},
				"exp":   time.Now().Add(10 * time.Minute).Unix(),
				"scope": "openid",
			}))
			reqCtx := context.WithValue(req.Context(), CHJWEServerKey, srv)
			req = req.WithContext(reqCtx)

			rr := httptest.NewRecorder()
			srv.OpenAPIHandler(rr, req)

			require.Equal(t, http.StatusInternalServerError, rr.Code, "forged token should fail during ClickHouse authentication")
			require.Contains(t, rr.Body.String(), "Failed to get ClickHouse client")
			require.Contains(t, rr.Body.String(), "AUTHENTICATION_FAILED")
		})
	})
}

// ---------- Helper functions ----------

func generateClickHouseStartupScriptsConfig() string {
	return `<?xml version="1.0"?>
<clickhouse>
    <startup_scripts>
        <scripts>
            <query>CREATE ROLE OR REPLACE 'default_role'</query>
        </scripts>
        <scripts>
            <query>GRANT SELECT ON *.* TO 'default_role'</query>
        </scripts>
    </startup_scripts>
</clickhouse>
`
}

func extractJWTStringClaim(t *testing.T, token, claim string) string {
	t.Helper()

	parts := strings.Split(token, ".")
	require.Len(t, parts, 3, "token should have three JWT parts")

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)

	var claims map[string]any
	require.NoError(t, json.Unmarshal(payload, &claims))

	value, ok := claims[claim].(string)
	require.True(t, ok, "token should include string %q claim", claim)

	return value
}

func firstStringCell(t *testing.T, rows []interface{}) string {
	t.Helper()

	require.NotEmpty(t, rows, "expected at least one row")

	row, ok := rows[0].([]interface{})
	require.True(t, ok, "expected row to be an array")
	require.NotEmpty(t, row, "expected row to have at least one column")

	value, ok := row[0].(string)
	require.True(t, ok, "expected first column to be a string")

	return value
}

func generateUnsignedJWT(t *testing.T, claims map[string]any) string {
	t.Helper()

	headerJSON, err := json.Marshal(map[string]string{
		"alg": "none",
		"typ": "JWT",
	})
	require.NoError(t, err)

	payloadJSON, err := json.Marshal(claims)
	require.NoError(t, err)

	return fmt.Sprintf(
		"%s.%s.",
		base64.RawURLEncoding.EncodeToString(headerJSON),
		base64.RawURLEncoding.EncodeToString(payloadJSON),
	)
}

// getDockerHostIP returns the hostname reachable from Docker containers.
// We always return "host.docker.internal" and rely on the ExtraHosts container setting
// (host.docker.internal:host-gateway) so it resolves correctly on both macOS and Linux.
func getDockerHostIP() string {
	return "host.docker.internal"
}

// newTestOAuthProviderReachableFromDocker creates an OIDC provider bound to 0.0.0.0
// so Docker containers can reach it. Returns (provider, dockerAccessURL).
//
// The discovery document, JWKS, and userinfo endpoints all use dockerURL directly,
// so ClickHouse containers can reach all endpoints without any forwarding.
func newTestOAuthProviderReachableFromDocker(t *testing.T, userInfoClaims map[string]interface{}) (*testOAuthProvider, string) {
	t.Helper()

	// Bind to all interfaces so Docker containers can reach us.
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	require.NoError(t, err)
	port := ln.Addr().(*net.TCPAddr).Port
	dockerURL := fmt.Sprintf("http://%s:%d", getDockerHostIP(), port)
	localURL := fmt.Sprintf("http://127.0.0.1:%d", port) // for host-side access in tests

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	provider := &testOAuthProvider{
		privateKey:     privateKey,
		keyID:          "test-signing-key",
		userInfoClaims: userInfoClaims,
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		// Antalya CH requires a complete OIDC discovery document with introspection_endpoint
		// (or userinfo_endpoint) plus the standard required OIDC fields. Without them CH
		// silently ignores the document and logs "Cannot extract userinfo_endpoint or
		// introspection_endpoint from OIDC configuration". Content-Length must be set
		// explicitly so CH's HTTP client receives the full body over the OrbStack NAT.
		doc := map[string]interface{}{
			"issuer":                                dockerURL,
			"authorization_endpoint":                dockerURL + "/auth",
			"token_endpoint":                        dockerURL + "/token",
			"jwks_uri":                              dockerURL + "/jwks",
			"userinfo_endpoint":                     dockerURL + "/userinfo",
			"introspection_endpoint":                dockerURL + "/introspect",
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		}
		body, _ := json.Marshal(doc)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
		w.WriteHeader(200)
		_, _ = w.Write(body)
	})

	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		keySet := jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{{
				Key:       &privateKey.PublicKey,
				KeyID:     provider.keyID,
				Use:       "sig",
				Algorithm: string(jose.RS256),
			}},
		}
		body, _ := json.Marshal(keySet)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
		w.WriteHeader(200)
		_, _ = w.Write(body)
	})

	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		provider.lastAuthorizationMu.Lock()
		provider.lastAuthorization = r.Header.Get("Authorization")
		provider.lastAuthorizationMu.Unlock()
		if provider.userInfoClaims == nil {
			http.Error(w, "userinfo not configured", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(provider.userInfoClaims)
	})

	// Use plain http.Serve (not httptest) — httptest replaces the listener
	// in a way that breaks 0.0.0.0 binding needed for Docker-to-host connectivity.
	httpSrv := &http.Server{Handler: mux}
	go func() { _ = httpSrv.Serve(ln) }()
	time.Sleep(50 * time.Millisecond) // ensure goroutine is scheduled before container starts
	t.Cleanup(func() {
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutCtx)
	})

	// Set a stub server so provider.server.URL works in test verification code.
	stub := httptest.NewUnstartedServer(nil)
	stub.Listener.Close() // free the auto-created listener immediately
	stub.URL = localURL
	provider.server = stub

	return provider, dockerURL
}

// setupAntalyaClickHouseWithOIDC starts an Antalya ClickHouse container with token_processors
// pointing at the given OIDC discovery URL.
// On Linux, host.docker.internal is resolved via ExtraHosts (host-gateway).
// On macOS/Docker Desktop/OrbStack it resolves automatically.
func setupAntalyaClickHouseWithOIDC(t *testing.T, ctx context.Context, oidcDiscoveryURL string) config.ClickHouseConfig {
	t.Helper()

	tokenProcessorXML := fmt.Sprintf(`<?xml version="1.0"?>
<clickhouse>
    <token_processors>
        <test_oidc>
            <type>openid</type>
            <configuration_endpoint>%s/.well-known/openid-configuration</configuration_endpoint>
            <token_cache_lifetime>60</token_cache_lifetime>
        </test_oidc>
    </token_processors>
    <user_directories replace="replace">
        <users_xml>
            <path>users.xml</path>
        </users_xml>
        <local_directory>
            <path>/var/lib/clickhouse/access/</path>
        </local_directory>
        <token>
            <processor>test_oidc</processor>
            <common_roles>
                <default_role />
            </common_roles>
        </token>
    </user_directories>
</clickhouse>
`, oidcDiscoveryURL)
	startupScriptsXML := generateClickHouseStartupScriptsConfig()

	tmpDir := t.TempDir()
	tokenProcessorFile := tmpDir + "/token_processor.xml"
	require.NoError(t, os.WriteFile(tokenProcessorFile, []byte(tokenProcessorXML), 0644))
	startupScriptsFile := tmpDir + "/startup_scripts.xml"
	require.NoError(t, os.WriteFile(startupScriptsFile, []byte(startupScriptsXML), 0644))

	req := testcontainers.ContainerRequest{
		Image:        "altinity/clickhouse-server:25.8.16.20001.altinityantalya",
		ExposedPorts: []string{"8123/tcp", "9000/tcp"},
		Files: []testcontainers.ContainerFile{
			{HostFilePath: tokenProcessorFile, ContainerFilePath: "/etc/clickhouse-server/config.d/token_processor.xml", FileMode: 0644},
			{HostFilePath: startupScriptsFile, ContainerFilePath: "/etc/clickhouse-server/config.d/startup_scripts.xml", FileMode: 0644},
		},
		Env: map[string]string{
			"CLICKHOUSE_SKIP_USER_SETUP":           "1",
			"CLICKHOUSE_DB":                        "default",
			"CLICKHOUSE_USER":                      "default",
			"CLICKHOUSE_PASSWORD":                  "",
			"CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT": "1",
		},
		HostConfigModifier: func(hc *container.HostConfig) {
			hc.ExtraHosts = append(hc.ExtraHosts, "host.docker.internal:host-gateway")
		},
		WaitingFor: wait.ForHTTP("/").WithPort("8123/tcp").
			WithStartupTimeout(120 * time.Second).WithPollInterval(2 * time.Second),
	}

	ctr, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = ctr.Terminate(cleanupCtx)
	})

	host, err := ctr.Host(ctx)
	require.NoError(t, err)
	httpPort, err := ctr.MappedPort(ctx, "8123")
	require.NoError(t, err)

	t.Logf("Antalya ClickHouse HTTP at %s:%s", host, httpPort.Port())

	return config.ClickHouseConfig{
		Host:             host,
		Port:             httpPort.Int(),
		Database:         "default",
		Username:         "default",
		Password:         "",
		Protocol:         config.HTTPProtocol,
		ReadOnly:         false,
		MaxExecutionTime: 60,
	}
}
