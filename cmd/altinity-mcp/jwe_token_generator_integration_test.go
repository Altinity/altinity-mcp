package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/altinity/altinity-mcp/pkg/config"
	altinitymcp "github.com/altinity/altinity-mcp/pkg/server"
	"github.com/stretchr/testify/require"
)

// These tests exercise production wiring as well as the hardened issuance helper.
func TestJWETokenGeneratorProductionRoutes(t *testing.T) {
	for _, transport := range []string{"http", "sse"} {
		for _, mode := range []string{"static", "JWE", "OAuth", "combined"} {
			for _, enabled := range []bool{false, true} {
				if enabled && (mode == "static" || mode == "OAuth") {
					continue
				}
				t.Run(fmt.Sprintf("%s/%s/enabled=%t", transport, mode, enabled), func(t *testing.T) {
					cfg := config.Config{Server: config.ServerConfig{JWE: protectedGeneratorConfig()}}
					cfg.Server.JWE.Enabled = mode == "JWE" || mode == "combined"
					cfg.Server.JWE.TokenGenerator.Enabled = enabled
					cfg.Server.OAuth.Enabled = mode == "OAuth" || mode == "combined"
					app := &application{config: cfg, mcpServer: altinitymcp.NewClickHouseMCPServer(cfg, "test")}
					var handler http.Handler
					if transport == "http" {
						handler = app.buildHTTPHandler(cfg, app.mcpServer.MCPServer)
					} else {
						handler = app.buildSSEHandler(cfg, app.mcpServer.MCPServer)
					}
					t.Cleanup(app.Close)
					for _, authorization := range []string{"", "Bearer wrong", "Bearer " + fakeGeneratorAdmin} {
						request := httptest.NewRequest(http.MethodPost, "/jwe-token-generator", strings.NewReader(`{"host":"ch.example","username":"alice"}`))
						request.Header.Set("Authorization", authorization)
						rr := httptest.NewRecorder()
						handler.ServeHTTP(rr, request)
						want := http.StatusNotFound
						if enabled {
							want = http.StatusUnauthorized
							if authorization == "Bearer "+fakeGeneratorAdmin {
								want = http.StatusOK
							}
						}
						require.Equal(t, want, rr.Code, rr.Body.String())
						if want == http.StatusOK {
							decodeGeneratedClaims(t, cfg.Server.JWE, rr)
						}
					}
				})
			}
		}
	}
}

func TestJWETokenGeneratorProductionStartupValidation(t *testing.T) {
	for _, admin := range []string{"", strings.Repeat("x", 31)} {
		cfg := config.Config{Server: config.ServerConfig{JWE: protectedGeneratorConfig()}}
		cfg.Server.JWE.TokenGenerator.AdminToken = admin
		app, err := newApplication(context.Background(), cfg, &mockCommand{})
		if app != nil {
			app.Close()
		}
		require.ErrorContains(t, err, "admin_token must be at least 32 bytes")
		require.Nil(t, app)
	}
	cfg := config.Config{Server: config.ServerConfig{JWE: protectedGeneratorConfig()}}
	app, err := newApplication(context.Background(), cfg, &mockCommand{})
	require.NoError(t, err)
	t.Cleanup(app.Close)
}

func TestJWETokenGeneratorProductionReloadValidation(t *testing.T) {
	cfg := config.Config{Server: config.ServerConfig{JWE: protectedGeneratorConfig()}, Logging: config.LoggingConfig{Level: config.InfoLevel}}
	app := &application{config: cfg, mcpServer: altinitymcp.NewClickHouseMCPServer(cfg, "test"), configFile: filepath.Join(t.TempDir(), "config.yaml"), stopConfigReload: make(chan struct{})}
	t.Cleanup(app.Close)
	for _, admin := range []string{"", strings.Repeat("x", 31)} {
		body := fmt.Sprintf("logging:\n  level: info\nserver:\n  jwe:\n    enabled: true\n    jwe_secret_key: fake-jwe-key\n    token_generator:\n      enabled: true\n      admin_token: %q\n", admin)
		require.NoError(t, os.WriteFile(app.configFile, []byte(body), 0600))
		err := app.reloadConfig(&mockCommand{})
		require.ErrorContains(t, err, "admin_token must be at least 32 bytes")
		require.Equal(t, fakeGeneratorAdmin, app.GetCurrentConfig().Server.JWE.TokenGenerator.AdminToken)
	}
	body := fmt.Sprintf("logging:\n  level: info\nserver:\n  jwe:\n    enabled: true\n    jwe_secret_key: fake-jwe-key\n    token_generator:\n      enabled: true\n      admin_token: %q\n      max_expiry_seconds: 1234\n", fakeGeneratorAdmin+"-rotated")
	require.NoError(t, os.WriteFile(app.configFile, []byte(body), 0600))
	require.NoError(t, app.reloadConfig(&mockCommand{}))
	require.Equal(t, fakeGeneratorAdmin+"-rotated", app.GetCurrentConfig().Server.JWE.TokenGenerator.AdminToken)
	require.Equal(t, 1234, app.GetCurrentConfig().Server.JWE.TokenGenerator.MaxExpirySeconds)
}
