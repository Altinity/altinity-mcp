package server

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/altinity/altinity-mcp/pkg/config"
	"github.com/altinity/go-mcp-oauth-sdk/jwe_auth"
	"github.com/stretchr/testify/require"
)

func TestJWESelfContainedConfig(t *testing.T) {
	t.Parallel()
	base := config.ClickHouseConfig{
		Host: "operator-host", ConnectHost: "operator-dial-host", Port: 8443,
		Database: "operator-db", Username: "operator-user", Password: "fake-operator-password",
		HttpHeaders: map[string]string{"Authorization": "fake-operator-token"},
		TLS:         config.TLSConfig{Enabled: true, CaCert: "/operator-ca", ClientCert: "/operator-cert", ClientKey: "/operator-key", InsecureSkipVerify: true},
		Roles:       []string{"operator-role"}, Protocol: config.TCPProtocol, ReadOnly: true,
		MaxExecutionTime: 17, Limit: 999, MaxResultRows: 23, MaxResultBytes: 31, MaxQueryLength: 47,
		ExtraSettings: map[string]string{"custom_scope": "operator-setting"},
	}
	srv := &ClickHouseJWEServer{}
	for _, password := range []interface{}{nil, "", "fake-token-password"} {
		claims := map[string]interface{}{"host": "token-host", "username": "token-user"}
		if password != nil {
			claims["password"] = password
		}
		cfg, err := srv.buildConfigFromClaimsWithBase(base, claims)
		require.NoError(t, err)
		expected := config.ClickHouseConfig{
			Host: "token-host", Username: "token-user", Port: 9000, Protocol: config.TCPProtocol,
			ReadOnly: true, MaxExecutionTime: 17, MaxResultRows: 23, MaxResultBytes: 31, MaxQueryLength: 47,
			ExtraSettings: map[string]string{"custom_scope": "operator-setting"},
		}
		if password != nil {
			expected.Password = password.(string)
		}
		require.Equal(t, expected, cfg)
		cfg.ExtraSettings["custom_scope"] = "request-setting"
		require.Equal(t, "operator-setting", base.ExtraSettings["custom_scope"])
	}
	for _, tc := range []struct {
		base, claim config.ClickHouseProtocol
		port        int
	}{
		{"", "", 8123}, {config.TCPProtocol, "", 9000},
		{config.TCPProtocol, config.HTTPProtocol, 8123}, {config.HTTPProtocol, config.TCPProtocol, 9000},
	} {
		cfg, err := srv.buildConfigFromClaimsWithBase(config.ClickHouseConfig{Protocol: tc.base, Port: 8443}, map[string]interface{}{
			"host": "token-host", "username": "token-user", "protocol": string(tc.claim),
		})
		require.NoError(t, err)
		require.Equal(t, tc.port, cfg.Port)
	}
}

func TestJWERejectedBeforeConnection(t *testing.T) {
	t.Parallel()
	var requests atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		http.Error(w, "unexpected upstream connection", http.StatusForbidden)
	}))
	defer upstream.Close()
	endpoint, err := url.Parse(upstream.URL)
	require.NoError(t, err)
	host, portText, err := net.SplitHostPort(endpoint.Host)
	require.NoError(t, err)
	port, err := strconv.Atoi(portText)
	require.NoError(t, err)
	const key = "fake-jwe-key"
	srv := NewClickHouseMCPServer(config.Config{
		ClickHouse: config.ClickHouseConfig{Host: host, Port: port, Username: "operator", Password: "fake-password", Protocol: config.HTTPProtocol},
		Server:     config.ServerConfig{JWE: config.JWEConfig{Enabled: true, JWESecretKey: key}},
	}, "test")
	for name, claims := range map[string]map[string]interface{}{
		"empty": {}, "host_only": {"host": host, "port": port}, "username_only": {"username": "u"},
		"tls_disabled_outside": {"host": host, "username": "u", "port": port, "tls_enabled": false, "tls_ca_cert": "/etc/passwd"},
		"tls_enabled_outside":  {"host": host, "username": "u", "port": port, "tls_enabled": true, "tls_client_key": "/etc/passwd"},
	} {
		t.Run(name, func(t *testing.T) {
			claims["exp"] = time.Now().Add(time.Hour).Unix()
			claims["password"] = "fake-token-secret"
			token := generateJWEToken(t, claims, []byte(key), nil)
			_, err := srv.GetClickHouseClient(context.Background(), token)
			require.Error(t, err)
			ctx := context.WithValue(context.Background(), JWETokenKey, token)
			_, err = srv.GetClickHouseClientFromCtx(ctx)
			require.Error(t, err)
			req := httptest.NewRequest(http.MethodGet, "/openapi/execute_query?query=SELECT%201", nil)
			req.Header.Set("x-altinity-mcp-key", token)
			req = req.WithContext(context.WithValue(req.Context(), CHJWEServerKey, srv))
			rr := httptest.NewRecorder()
			srv.OpenAPIHandler(rr, req)
			if name == "empty" || name == "host_only" || name == "username_only" {
				require.ErrorIs(t, err, ErrJWEIncompleteConnection)
				require.Equal(t, http.StatusUnauthorized, rr.Code)
				require.Equal(t, "jwe: token must carry host and username claims\n", rr.Body.String())
			} else {
				require.NotEqual(t, http.StatusOK, rr.Code)
			}
			require.NotContains(t, rr.Body.String(), "fake-token-secret")
			require.NotContains(t, rr.Body.String(), "fake-password")
			require.NotContains(t, rr.Body.String(), "/etc/passwd")
			require.Zero(t, requests.Load())
		})
	}
}

func TestJWETLSClaims(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cert := filepath.Join(dir, "cert.pem")
	key := filepath.Join(dir, "key.pem")
	require.NoError(t, os.WriteFile(cert, []byte("private-invalid-certificate"), 0600))
	require.NoError(t, os.WriteFile(key, []byte("private-invalid-key"), 0600))
	srv := &ClickHouseJWEServer{Config: config.Config{Server: config.ServerConfig{JWE: config.JWEConfig{Enabled: true, JWESecretKey: "fake-key", TLSMaterialDir: dir}}}}
	claims := map[string]interface{}{"host": "localhost", "username": "u", "tls_enabled": true, "tls_client_cert": cert, "tls_client_key": key}
	cfg, err := srv.buildConfigFromClaims(claims)
	require.NoError(t, err)
	require.True(t, cfg.TLS.Enabled)
	resolvedCert, err := filepath.EvalSymlinks(cert)
	require.NoError(t, err)
	resolvedKey, err := filepath.EvalSymlinks(key)
	require.NoError(t, err)
	require.Equal(t, resolvedCert, cfg.TLS.ClientCert)
	require.Equal(t, resolvedKey, cfg.TLS.ClientKey)
	claims["exp"] = time.Now().Add(time.Hour).Unix()
	token := generateJWEToken(t, claims, []byte("fake-key"), nil)
	_, err = srv.GetClickHouseClient(context.Background(), token)
	require.EqualError(t, err, "jwe: failed to create ClickHouse client with TLS material")
	_, err = srv.GetClickHouseClientWithOAuth(context.Background(), token, "", nil)
	require.EqualError(t, err, "jwe: failed to create ClickHouse client with TLS material")
	for _, claim := range []string{"tls_ca_cert", "tls_client_cert", "tls_client_key"} {
		for _, enabled := range []bool{false, true} {
			_, err := srv.buildConfigFromClaims(map[string]interface{}{"host": "x", "username": "u", "tls_enabled": enabled, claim: "/etc/passwd"})
			require.EqualError(t, err, "jwe: invalid TLS material path")
		}
	}
}

func TestValidateAuthUsernameWithoutHost(t *testing.T) {
	t.Parallel()
	const key = "fake-jwe-key"
	token := generateJWEToken(t, map[string]interface{}{"username": "u", "exp": time.Now().Add(time.Hour).Unix()}, []byte(key), nil)
	for _, oauthEnabled := range []bool{false, true} {
		srv := &ClickHouseJWEServer{Config: config.Config{Server: config.ServerConfig{
			JWE: config.JWEConfig{Enabled: true, JWESecretKey: key}, OAuth: config.OAuthConfig{Enabled: oauthEnabled},
		}}}
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("x-altinity-mcp-key", token)
		_, _, _, _, err := srv.ValidateAuth(req)
		require.Error(t, err)
		req.Header.Set("Authorization", "Bearer fake-oauth-token")
		_, _, oauth, _, err := srv.ValidateAuth(req)
		if oauthEnabled {
			require.NoError(t, err)
			require.Equal(t, "fake-oauth-token", oauth)
		} else {
			require.Error(t, err)
		}
	}
}

// Missing request credentials must fail before static operator credentials can
// be used, including discovery's context-based client path.
func TestJWEAbsentTokensDoNotUseStaticCredentials(t *testing.T) {
	t.Parallel()
	var requests atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		http.Error(w, "unexpected static credential use", http.StatusForbidden)
	}))
	defer upstream.Close()
	endpoint, err := url.Parse(upstream.URL)
	require.NoError(t, err)
	host, portText, err := net.SplitHostPort(endpoint.Host)
	require.NoError(t, err)
	port, err := strconv.Atoi(portText)
	require.NoError(t, err)
	for _, oauthEnabled := range []bool{false, true} {
		name := "jwe_only"
		if oauthEnabled {
			name = "jwe_and_oauth"
		}
		t.Run(name, func(t *testing.T) {
			srv := NewClickHouseMCPServer(config.Config{
				ClickHouse: config.ClickHouseConfig{Host: host, Port: port, Protocol: config.HTTPProtocol, Username: "operator", Password: "fake-static-password"},
				Server:     config.ServerConfig{JWE: config.JWEConfig{Enabled: true, JWESecretKey: "fake-key"}, OAuth: config.OAuthConfig{Enabled: oauthEnabled}},
			}, "test")
			ctx := context.Background()
			_, err := srv.GetClickHouseClientWithOAuth(ctx, "", "", nil)
			require.ErrorIs(t, err, jwe_auth.ErrMissingToken)
			_, err = srv.GetClickHouseClientFromCtx(ctx)
			require.ErrorIs(t, err, jwe_auth.ErrMissingToken)
			_, err = srv.GetClickHouseClientWithOAuthForConfig(ctx, srv.Config.ClickHouse, "", "", nil)
			require.ErrorIs(t, err, jwe_auth.ErrMissingToken)
			_, err = srv.getDiscoveryClient(ctx)
			require.ErrorIs(t, err, jwe_auth.ErrMissingToken)
			require.Zero(t, requests.Load(), "missing tokens must never reach the operator endpoint")
		})
	}
}
