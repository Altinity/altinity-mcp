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
	"strings"
	"testing"
	"time"

	"github.com/altinity/altinity-mcp/internal/testutil/embeddedch"
	"github.com/altinity/altinity-mcp/pkg/config"
	"github.com/go-jose/go-jose/v4"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"
)

// TestOAuthE2EWithMockOIDC is an end-to-end test that validates the full OAuth2 flow
// through real MCP client and OpenAPI endpoints:
//
//  1. A lightweight mock OIDC provider (in-process Go HTTP server bound to 127.0.0.1)
//  2. Altinity Antalya ClickHouse with token_processors for JWT auth, run as a host
//     subprocess via embedded-clickhouse + an extracted Antalya binary
//  3. MCP server forwarding Bearer tokens to ClickHouse
//
// On Linux the Antalya binary is auto-extracted from the published Docker
// image on first run. On macOS/other hosts there is no published binary,
// so the test requires a pre-cached binary at ~/.cache/embedded-clickhouse/
// — see docs/build_antalya_macos.md and docs/development_and_testing.md.
// The test fails (not skips) if the binary is missing.
func TestOAuthE2EWithMockOIDC(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	ctx := context.Background()

	// Step 1: mock OIDC provider on 127.0.0.1. Use the full-discovery variant
	// because Antalya's token_processors parser requires introspection_endpoint
	// (or userinfo_endpoint) plus the standard required OIDC fields — without
	// them it logs "Cannot extract userinfo_endpoint or introspection_endpoint
	// from OIDC configuration" and silently disables the processor.
	provider := newAntalyaOIDCProvider(t, nil)
	oidcURL := provider.server.URL
	t.Logf("Mock OIDC provider URL: %s", oidcURL)

	// Step 2: Antalya ClickHouse via embedded-clickhouse, configured for OIDC.
	chConfig := setupEmbeddedAntalyaWithOIDC(t, oidcURL)

	// Step 3: issue a signed JWT to use as the Bearer.
	const tokenSubject = "test-oauth-user"
	token := provider.issueJWT(t, map[string]interface{}{
		"sub": tokenSubject,
		"iss": oidcURL,
		"aud": "test-audience",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	})
	require.NotEmpty(t, token, "OAuth token should not be empty")

	parts := strings.Split(token, ".")
	require.Equal(t, 3, len(parts), "Token should be a JWT with 3 parts")

	t.Run("MCP_Client", func(t *testing.T) {
		t.Parallel()
		srv := NewClickHouseMCPServer(config.Config{
			ClickHouse: chConfig,
			Server: config.ServerConfig{
				OAuth: config.OAuthConfig{
					Enabled: true,
					Mode:    "forward",
				},
			},
		}, "test-e2e")

		clientTransport, serverTransport := mcp.NewInMemoryTransports()

		srvCtx := context.WithValue(ctx, CHJWEServerKey, srv)
		srvCtx = context.WithValue(srvCtx, OAuthTokenKey, token)
		serverSession, err := srv.MCPServer.Connect(srvCtx, serverTransport, nil)
		require.NoError(t, err, "Server connect should succeed")
		defer func() {
			require.NoError(t, serverSession.Close())
		}()

		mcpClient := mcp.NewClient(
			&mcp.Implementation{Name: "test-oauth-client", Version: "v0.0.1"}, nil,
		)
		clientSession, err := mcpClient.Connect(ctx, clientTransport, nil)
		require.NoError(t, err, "Client connect should succeed")
		defer func() {
			require.NoError(t, clientSession.Close())
		}()

		t.Run("ListTools", func(t *testing.T) {
			toolsResult, err := clientSession.ListTools(ctx, nil)
			require.NoError(t, err)
			require.NotNil(t, toolsResult)

			var toolNames []string
			for _, tool := range toolsResult.Tools {
				toolNames = append(toolNames, tool.Name)
			}
			require.Contains(t, toolNames, "execute_query", "execute_query tool should be registered")
		})

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

			var queryResult map[string]interface{}
			require.NoError(t, json.Unmarshal([]byte(textContent.Text), &queryResult))
			rows, ok := queryResult["rows"].([]interface{})
			require.True(t, ok, "Result should have Rows")
			require.Greater(t, len(rows), 0, "Should have at least one row")
			require.Equal(t, tokenSubject, firstStringCell(t, rows))
		})

		t.Run("ListResources", func(t *testing.T) {
			resourcesResult, err := clientSession.ListResources(ctx, nil)
			require.NoError(t, err)
			require.NotNil(t, resourcesResult)

			var resourceURIs []string
			for _, r := range resourcesResult.Resources {
				resourceURIs = append(resourceURIs, r.URI)
			}
			require.Contains(t, resourceURIs, "clickhouse://schema", "Schema resource should be registered")
		})

		t.Run("ReadResource_Schema", func(t *testing.T) {
			res, err := clientSession.ReadResource(ctx, &mcp.ReadResourceParams{
				URI: "clickhouse://schema",
			})
			require.NoError(t, err, "ReadResource should succeed")
			require.NotNil(t, res)
			require.Greater(t, len(res.Contents), 0, "Should have contents")
			require.NotEmpty(t, res.Contents[0].Text, "Schema should not be empty")
		})
	})

	t.Run("OpenAPI_Client", func(t *testing.T) {
		t.Parallel()
		srv := NewClickHouseMCPServer(config.Config{
			ClickHouse: chConfig,
			Server: config.ServerConfig{
				OAuth: config.OAuthConfig{
					Enabled: true,
					Mode:    "forward",
				},
			},
		}, "test-e2e")

		t.Run("ExecuteQuery", func(t *testing.T) {
			t.Parallel()
			query := url.QueryEscape("SELECT currentUser() AS user, 1 AS ok")
			req := httptest.NewRequest(http.MethodGet, "/openapi/execute_query?query="+query, nil)
			req.Header.Set("Authorization", "Bearer "+token)
			req = req.WithContext(context.WithValue(req.Context(), CHJWEServerKey, srv))

			rr := httptest.NewRecorder()
			srv.OpenAPIHandler(rr, req)

			require.Equal(t, http.StatusOK, rr.Code, "OpenAPI should return 200, body: %s", rr.Body.String())

			var result map[string]interface{}
			require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &result))
			rows, ok := result["rows"].([]interface{})
			require.True(t, ok, "Result should have Rows")
			require.Greater(t, len(rows), 0, "Should have at least one row")
			require.Equal(t, tokenSubject, firstStringCell(t, rows))
		})

		t.Run("OpenAPISchema", func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(http.MethodGet, "/openapi", nil)
			req.Header.Set("Authorization", "Bearer "+token)
			req = req.WithContext(context.WithValue(req.Context(), CHJWEServerKey, srv))

			rr := httptest.NewRecorder()
			srv.OpenAPIHandler(rr, req)

			require.Equal(t, http.StatusOK, rr.Code, "OpenAPI schema should return 200")
			require.Contains(t, rr.Body.String(), "execute_query", "Schema should contain execute_query")
		})

		t.Run("ExecuteQuery_MissingBearerToken", func(t *testing.T) {
			t.Parallel()
			query := url.QueryEscape("SELECT currentUser() AS user")
			req := httptest.NewRequest(http.MethodGet, "/openapi/execute_query?query="+query, nil)
			req = req.WithContext(context.WithValue(req.Context(), CHJWEServerKey, srv))

			rr := httptest.NewRecorder()
			srv.OpenAPIHandler(rr, req)

			require.Equal(t, http.StatusUnauthorized, rr.Code, "missing token should be rejected before ClickHouse query execution")
			require.Contains(t, rr.Body.String(), "Missing authentication token")
		})

		t.Run("ExecuteQuery_InvalidBearerTokenRejectedByClickHouse", func(t *testing.T) {
			t.Parallel()
			query := url.QueryEscape("SELECT currentUser() AS user")
			req := httptest.NewRequest(http.MethodGet, "/openapi/execute_query?query="+query, nil)
			req.Header.Set("Authorization", "Bearer "+generateUnsignedJWT(t, map[string]any{
				"sub":   "forged-user",
				"iss":   "http://forged-issuer.invalid",
				"aud":   []string{"forged-client"},
				"exp":   time.Now().Add(10 * time.Minute).Unix(),
				"scope": "openid",
			}))
			req = req.WithContext(context.WithValue(req.Context(), CHJWEServerKey, srv))

			rr := httptest.NewRecorder()
			srv.OpenAPIHandler(rr, req)

			require.Equal(t, http.StatusInternalServerError, rr.Code, "forged token should fail during ClickHouse authentication")
			require.Contains(t, rr.Body.String(), "Failed to get ClickHouse client")
			require.Contains(t, rr.Body.String(), "AUTHENTICATION_FAILED")
		})
	})
}

// setupEmbeddedAntalyaWithOIDC boots an Antalya ClickHouse server as a host
// subprocess via embedded-clickhouse, configured with a token_processors
// drop-in pointing at the supplied OIDC discovery URL plus a startup_scripts
// drop-in that creates the default_role used by the token user_directory.
//
// Auto-skips on non-Linux hosts because Antalya only ships Linux binaries.
func setupEmbeddedAntalyaWithOIDC(t *testing.T, oidcDiscoveryURL string) config.ClickHouseConfig {
	t.Helper()

	// Antalya's <user_directories> needs a writable <local_directory> for
	// runtime user storage. The Antalya container shipped with
	// /var/lib/clickhouse/access/, but the host process running as the CI
	// user can't create that path. Use a host-writable temp dir.
	accessDir := t.TempDir()

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
            <path>%s</path>
        </local_directory>
        <token>
            <processor>test_oidc</processor>
            <common_roles>
                <default_role />
            </common_roles>
        </token>
    </user_directories>
</clickhouse>
`, oidcDiscoveryURL, accessDir)

	startupScriptsXML := generateClickHouseStartupScriptsConfig()

	// The token_processor.xml above declares <user_directories> with a
	// <users_xml> element pointing at users.xml. The Antalya Docker image
	// ships /etc/clickhouse-server/users.xml; embedded-clickhouse does not.
	// Without it, ClickHouse fails startup with CANNOT_LOAD_CONFIG. Provide
	// a minimal users.xml so the path resolves; the actual users we care
	// about come from the OIDC token user_directory at runtime.
	const usersXML = `<?xml version="1.0"?>
<clickhouse>
    <users>
        <default>
            <password></password>
            <networks><ip>::/0</ip></networks>
            <profile>default</profile>
            <quota>default</quota>
            <access_management>1</access_management>
        </default>
    </users>
    <profiles><default/></profiles>
    <quotas><default/></quotas>
</clickhouse>
`

	cfg := setupEmbeddedClickHouseUnseeded(t,
		withFlavor(flavorAntalya),
		withConfigDropIn(tokenProcessorXML),
		withConfigDropIn(startupScriptsXML),
		embeddedch.WithUsersXML(usersXML),
	)
	return *cfg
}

// newAntalyaOIDCProvider serves the full OIDC discovery document Antalya's
// token_processors parser requires (issuer + auth/token/jwks/userinfo/
// introspection endpoints + response_types + subject_types + id_token_signing
// algs). The shorter doc returned by newTestOAuthProvider is enough for
// forward-mode bearer-passthrough tests that never look at it — Antalya
// rejects it with "Cannot extract userinfo_endpoint or introspection_endpoint".
//
// Uses an explicit net.Listen + http.Server.Serve loop instead of
// httptest.NewServer so we control Content-Length / chunked-vs-fixed framing
// exactly as the original docker-reachable variant did. Antalya's HTTP
// client occasionally drops the trailing bytes when chunked encoding kicks
// in mid-response on small bodies.
func newAntalyaOIDCProvider(t *testing.T, userInfoClaims map[string]interface{}) *testOAuthProvider {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := ln.Addr().(*net.TCPAddr).Port
	oidcProviderURL := fmt.Sprintf("http://127.0.0.1:%d", port)

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	provider := &testOAuthProvider{
		privateKey:     privateKey,
		keyID:          "test-signing-key",
		userInfoClaims: userInfoClaims,
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		body, _ := json.Marshal(map[string]interface{}{
			"issuer":                                oidcProviderURL,
			"authorization_endpoint":                oidcProviderURL + "/auth",
			"token_endpoint":                        oidcProviderURL + "/token",
			"jwks_uri":                              oidcProviderURL + "/jwks",
			"userinfo_endpoint":                     oidcProviderURL + "/userinfo",
			"introspection_endpoint":                oidcProviderURL + "/introspect",
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
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

	httpSrv := &http.Server{Handler: mux}
	go func() { _ = httpSrv.Serve(ln) }()
	time.Sleep(50 * time.Millisecond)
	t.Cleanup(func() {
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutCtx)
	})

	stub := httptest.NewUnstartedServer(nil)
	_ = stub.Listener.Close()
	stub.URL = oidcProviderURL
	provider.server = stub

	return provider
}

// generateClickHouseStartupScriptsConfig returns the XML drop-in that
// pre-creates the default_role granted to OIDC-authenticated users.
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
