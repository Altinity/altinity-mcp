package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/altinity/altinity-mcp/pkg/config"
	"github.com/stretchr/testify/require"
)

func TestIsValidClusterName(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"basic", "otel", true},
		{"with-dash", "my-cluster", true},
		{"digits", "cluster1", true},
		{"single-char", "a", true},
		{"empty", "", false},
		{"uppercase", "Otel", false},
		{"leading-dot", ".well-known", false},
		{"with-dot", "evil.example", false},
		{"trailing-dash", "cluster-", false},
		{"leading-dash", "-cluster", false},
		{"ipv4-literal", "10.0.0.1", false},
		{"slash", "a/b", false},
		{"too-long", "a-very-long-name-that-exceeds-the-rfc-1123-dns-label-limit-of-63-characters-and-then-some", false},
		{"underscore", "my_cluster", false},
		{"space", "my cluster", false},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, c.want, IsValidClusterName(c.in), "case %q (%q)", c.name, c.in)
		})
	}
}

func TestMulticlusterRouter_AllowlistRejection(t *testing.T) {
	t.Parallel()
	mc := config.MulticlusterConfig{
		Enabled:          true,
		ClusterAllowlist: []string{"otel", "antalya"},
	}
	ch := config.ClickHouseConfig{Host: "chi-{cluster}-{cluster}-0-0.demo", Port: 8443}
	router, err := NewMulticlusterRouter(mc, ch)
	require.NoError(t, err)

	tests := []struct {
		cluster string
		want    int
	}{
		{"otel", 200},
		{"antalya", 200},
		{"bogus", 404},
		{"evil.example", 404},
		{"", 404},
		{".well-known", 404},
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cluster, ok := ClusterFromContext(r.Context())
		require.True(t, ok, "expected cluster on ctx")
		require.NotEmpty(t, cluster)
		cfg := CHConfigFromContext(r.Context(), config.ClickHouseConfig{})
		require.Contains(t, cfg.Host, cluster)
		require.NotContains(t, cfg.Host, "{cluster}")
		w.WriteHeader(200)
	})
	handler := router.Middleware(next)

	for _, tc := range tests {
		tc := tc
		t.Run(tc.cluster, func(t *testing.T) {
			rr := httptest.NewRecorder()
			// Use mux pattern so r.PathValue works.
			mux := http.NewServeMux()
			mux.Handle("/mcp/{cluster}", handler)
			req := httptest.NewRequest("GET", "/mcp/"+tc.cluster, nil)
			mux.ServeHTTP(rr, req)
			require.Equal(t, tc.want, rr.Code, "cluster=%q", tc.cluster)
		})
	}
}

func TestMulticlusterRouter_HostExpansion(t *testing.T) {
	t.Parallel()
	mc := config.MulticlusterConfig{
		Enabled:          true,
		ClusterAllowlist: []string{"alpha"},
	}
	ch := config.ClickHouseConfig{Host: "chi-{cluster}-{cluster}-0-0.demo", Port: 8443}
	router, err := NewMulticlusterRouter(mc, ch)
	require.NoError(t, err)

	cfg, ok := router.ValidateClusterAllowed("alpha")
	require.True(t, ok)
	require.Equal(t, "chi-alpha-alpha-0-0.demo", cfg.Host)
	// Other fields preserved.
	require.Equal(t, 8443, cfg.Port)
}

func TestMulticlusterRouter_EmptyAllowlistAllowsAny(t *testing.T) {
	t.Parallel()
	// When allowlist is empty, *any* valid RFC 1123 name is allowed.
	// This is deliberate: operators sometimes want to admit all clusters
	// in a namespace; the strict check is still the DNS-label regex.
	mc := config.MulticlusterConfig{Enabled: true}
	ch := config.ClickHouseConfig{Host: "chi-{cluster}.demo"}
	router, err := NewMulticlusterRouter(mc, ch)
	require.NoError(t, err)

	cfg, ok := router.ValidateClusterAllowed("anything")
	require.True(t, ok)
	require.Equal(t, "chi-anything.demo", cfg.Host)

	_, ok = router.ValidateClusterAllowed("evil.example")
	require.False(t, ok)
}

func TestNewMulticlusterRouter_RejectsBadAllowlist(t *testing.T) {
	t.Parallel()
	mc := config.MulticlusterConfig{
		Enabled:          true,
		ClusterAllowlist: []string{"good", "Bad-Caps"},
	}
	ch := config.ClickHouseConfig{Host: "chi-{cluster}.demo"}
	_, err := NewMulticlusterRouter(mc, ch)
	require.Error(t, err)
	require.Contains(t, err.Error(), "Bad-Caps")
}
