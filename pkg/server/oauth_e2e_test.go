package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/altinity/altinity-mcp/pkg/config"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	tcnetwork "github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"
)

// TestOAuthE2EWithKeycloak is an end-to-end test that validates the full OAuth2 flow
// through real MCP client and OpenAPI endpoints:
// 1. Keycloak as the OAuth2/OIDC provider (RS256 keys compatible with ClickHouse)
// 2. ClickHouse (Antalya build) with token_processors for JWT auth
// 3. MCP server forwarding Bearer tokens to ClickHouse
//
// Reference setup: https://github.com/zvonand/grafana-oauth/tree/main/keycloak
func TestOAuthE2EWithKeycloak(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}
	if os.Getenv("RUN_OAUTH_E2E") == "" {
		t.Skip("set RUN_OAUTH_E2E=1 to run Docker-based OAuth E2E test")
	}

	ctx := context.Background()
	const (
		keycloakHostname   = "keycloak"
		clickhouseHostname = "clickhouse"
		realmName          = "mcp"
		clientID           = "clickhouse-mcp"
		testUserName       = "testuser"
		testUserPassword   = "testpass123"
	)

	// Create a shared Docker network for container-to-container communication
	net, err := tcnetwork.New(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = net.Remove(ctx) })

	// ---------- Step 1: Start Keycloak with realm import ----------
	realmJSON := generateKeycloakRealmJSON(realmName, clientID, testUserName, testUserPassword)
	keycloakInternalURL, keycloakExternalURL := startKeycloakContainer(
		t, ctx, net.Name, keycloakHostname, realmJSON,
	)
	t.Logf("Keycloak internal URL: %s", keycloakInternalURL)
	t.Logf("Keycloak external URL: %s", keycloakExternalURL)

	// ---------- Step 2: Start ClickHouse with token_processors ----------
	tokenProcessorXML := generateClickHouseTokenProcessorConfig(keycloakInternalURL, realmName)
	startupScriptsXML := generateClickHouseStartupScriptsConfig()
	chConfig := startClickHouseContainer(t, ctx, net.Name, clickhouseHostname, tokenProcessorXML, startupScriptsXML)

	// ---------- Step 3: Obtain OAuth2 token from Keycloak via password grant ----------
	token := getKeycloakToken(t, keycloakExternalURL, realmName, clientID, testUserName, testUserPassword)
	require.NotEmpty(t, token, "OAuth token should not be empty")
	t.Logf("Obtained OAuth token (first 50 chars): %.50s...", token)

	// Verify it looks like a JWT
	parts := strings.Split(token, ".")
	require.Equal(t, 3, len(parts), "Token should be a JWT with 3 parts")
	tokenSubject := extractJWTStringClaim(t, token, "sub")
	require.NotEmpty(t, tokenSubject, "access token should include a subject claim")

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

func generateKeycloakRealmJSON(realmName, clientID, userName, userPassword string) string {
	realm := map[string]interface{}{
		"realm":                      realmName,
		"enabled":                    true,
		"sslRequired":                "none",
		"registrationAllowed":        false,
		"verifyEmail":                false,
		"requiredActions":            []interface{}{},
		"defaultDefaultClientScopes": []string{"web-origins", "acr", "profile", "roles", "email", "basic"},
		"clients": []map[string]interface{}{
			{
				"clientId":                  clientID,
				"name":                      "ClickHouse MCP",
				"protocol":                  "openid-connect",
				"publicClient":              true,
				"directAccessGrantsEnabled": true,
				"standardFlowEnabled":       true,
				"redirectUris":              []string{"*"},
			},
		},
		"users": []map[string]interface{}{
			{
				"username":        userName,
				"enabled":         true,
				"email":           userName + "@test.local",
				"emailVerified":   true,
				"firstName":       "Test",
				"lastName":        "User",
				"requiredActions": []string{},
				"credentials": []map[string]interface{}{
					{
						"type":      "password",
						"value":     userPassword,
						"temporary": false,
					},
				},
			},
		},
		"roles": map[string]interface{}{
			"realm": []map[string]interface{}{
				{"name": "default_role", "description": "Default role for token-authenticated users"},
			},
		},
	}
	data, _ := json.MarshalIndent(realm, "", "  ")
	return string(data)
}

func startKeycloakContainer(
	t *testing.T, ctx context.Context, networkName, hostname, realmJSON string,
) (internalURL, externalURL string) {
	t.Helper()

	realmFile := t.TempDir() + "/realm-export.json"
	require.NoError(t, os.WriteFile(realmFile, []byte(realmJSON), 0644))

	req := testcontainers.ContainerRequest{
		Image:        "keycloak/keycloak:26.3",
		ExposedPorts: []string{"8080/tcp"},
		Cmd:          []string{"start-dev", "--import-realm", "--hostname-strict=false"},
		Env: map[string]string{
			"KC_BOOTSTRAP_ADMIN_USERNAME": "admin",
			"KC_BOOTSTRAP_ADMIN_PASSWORD": "admin",
		},
		Networks: []string{networkName},
		NetworkAliases: map[string][]string{
			networkName: {hostname},
		},
		Files: []testcontainers.ContainerFile{
			{HostFilePath: realmFile, ContainerFilePath: "/opt/keycloak/data/import/realm-export.json", FileMode: 0644},
		},
		WaitingFor: wait.ForLog("Listening on:").WithStartupTimeout(180 * time.Second),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = container.Terminate(cleanupCtx)
	})

	host, err := container.Host(ctx)
	require.NoError(t, err)
	port, err := container.MappedPort(ctx, "8080")
	require.NoError(t, err)

	internalURL = fmt.Sprintf("http://%s:8080", hostname)
	externalURL = fmt.Sprintf("http://%s:%s", host, port.Port())
	return internalURL, externalURL
}

func generateClickHouseTokenProcessorConfig(keycloakURL, realmName string) string {
	return fmt.Sprintf(`<?xml version="1.0"?>
<clickhouse>
    <token_processors>
        <keycloak>
            <type>openid</type>
            <configuration_endpoint>%[1]s/realms/%[2]s/.well-known/openid-configuration</configuration_endpoint>
            <token_cache_lifetime>60</token_cache_lifetime>
        </keycloak>
    </token_processors>
    <!-- replace="replace" is needed because ClickHouse does not merge new children into user_directories from config.d -->
    <user_directories replace="replace">
        <users_xml>
            <path>users.xml</path>
        </users_xml>
        <local_directory>
            <path>/var/lib/clickhouse/access/</path>
        </local_directory>
        <token>
            <processor>keycloak</processor>
            <common_roles>
                <default_role />
            </common_roles>
        </token>
    </user_directories>
</clickhouse>
`, keycloakURL, realmName)
}

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

func startClickHouseContainer(
	t *testing.T, ctx context.Context, networkName, hostname, tokenProcessorXML, startupScriptsXML string,
) config.ClickHouseConfig {
	t.Helper()

	tmpDir := t.TempDir()
	tokenProcessorFile := tmpDir + "/token_processor.xml"
	require.NoError(t, os.WriteFile(tokenProcessorFile, []byte(tokenProcessorXML), 0644))
	startupScriptsFile := tmpDir + "/startup_scripts.xml"
	require.NoError(t, os.WriteFile(startupScriptsFile, []byte(startupScriptsXML), 0644))

	req := testcontainers.ContainerRequest{
		Image:        "altinity/clickhouse-server:25.8.16.20001.altinityantalya",
		ExposedPorts: []string{"8123/tcp", "9000/tcp"},
		Networks:     []string{networkName},
		NetworkAliases: map[string][]string{
			networkName: {hostname},
		},
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
		WaitingFor: wait.ForHTTP("/").WithPort("8123/tcp").
			WithStartupTimeout(120 * time.Second).WithPollInterval(2 * time.Second),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = container.Terminate(cleanupCtx)
	})

	host, err := container.Host(ctx)
	require.NoError(t, err)
	httpPort, err := container.MappedPort(ctx, "8123")
	require.NoError(t, err)

	t.Logf("ClickHouse HTTP at %s:%s", host, httpPort.Port())

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

func getKeycloakToken(
	t *testing.T, keycloakURL, realmName, clientID, username, password string,
) string {
	t.Helper()

	tokenURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", keycloakURL, realmName)
	data := url.Values{
		"grant_type": {"password"},
		"client_id":  {clientID},
		"username":   {username},
		"password":   {password},
		"scope":      {"openid"},
	}

	resp, err := http.PostForm(tokenURL, data)
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	t.Logf("Token exchange (status=%d): %s", resp.StatusCode, string(body))
	require.Equal(t, http.StatusOK, resp.StatusCode, "Token request should succeed: %s", string(body))

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
		TokenType   string `json:"token_type"`
	}
	require.NoError(t, json.Unmarshal(body, &tokenResp))
	require.NotEmpty(t, tokenResp.AccessToken, "Access token should not be empty")

	return tokenResp.AccessToken
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
