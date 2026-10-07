package server

import (
	"context"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/altinity/altinity-mcp/pkg/config"
	"github.com/stretchr/testify/require"
)

// Isolate logger output in a subprocess instead of replacing the package's
// global logger while unrelated concurrent tests may still be logging.
func TestRequestRegistryKeepsStartupSignalsQuiet(t *testing.T) {
	if os.Getenv("ALTINITY_MCP_TEST_REGISTRY_LOGS") == "1" {
		for _, legacy := range []bool{false, true} {
			cfg := config.Config{Server: config.ServerConfig{OAuth: config.OAuthConfig{Enabled: true}}}
			if legacy {
				cfg.Server.DynamicTools = []config.DynamicToolRule{{Regexp: ".*"}}
			}
			parent := NewClickHouseMCPServer(cfg, "test")
			if legacy {
				parent.catalogOnce.Do(func() { parent.catalogCache = NewCatalogCache(config.MulticlusterConfig{}) })
				parent.catalogCache.insertOK(fullKey(CacheKey("oauth\x00alice"), "singlecluster"), map[string]dynamicToolMeta{}, time.Time{})
			}
			_, _ = os.Stderr.WriteString("BEGIN REQUEST REGISTRIES\n")
			request := httptest.NewRequest("POST", "/", nil)
			request = request.WithContext(context.WithValue(request.Context(), OAuthTokenKey, "alice"))
			for i := 0; i < 3; i++ {
				parent.GetServer(request)
			}
			_, _ = os.Stderr.WriteString("END REQUEST REGISTRIES\n")
			parent.Close()
		}
		// Failed no-auth discovery still emits an operator warning.
		parent := NewClickHouseMCPServer(config.Config{ClickHouse: config.ClickHouseConfig{Username: "fake-user", Protocol: "invalid"}, Server: config.ServerConfig{DynamicTools: []config.DynamicToolRule{{Regexp: ".*"}}}}, "test")
		parent.GetServer(httptest.NewRequest("POST", "/", nil))
		parent.Close()
		return
	}
	child := exec.Command(os.Args[0], "-test.run=^TestRequestRegistryKeepsStartupSignalsQuiet$")
	child.Env = append(os.Environ(), "ALTINITY_MCP_TEST_REGISTRY_LOGS=1")
	output, err := child.CombinedOutput()
	require.NoError(t, err, string(output))
	text := string(output)
	require.Contains(t, text, "Static read tool registered")
	require.Contains(t, text, "ClickHouse resources registered")
	require.Contains(t, text, "dynamic_tools config is deprecated")
	parts := strings.Split(text, "BEGIN REQUEST REGISTRIES\n")
	require.Len(t, parts, 3)
	for _, part := range parts[1:] {
		requestLogs := strings.SplitN(part, "END REQUEST REGISTRIES\n", 2)
		require.Len(t, requestLogs, 2)
		require.Empty(t, requestLogs[0], "request registry creation must preserve startup-only logging")
	}
	require.Contains(t, text, `"level":"warn"`)
	require.Contains(t, text, "Failed to ensure dynamic tools")
}
