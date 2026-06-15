package server

import (
	"context"
	"testing"

	"github.com/altinity/altinity-mcp/pkg/config"
	"github.com/stretchr/testify/require"
)

// roleServer builds a struct-literal server with OAuth + per-request role
// filtering configured. roleFilter() lazily compiles the pattern.
func roleServer(claim, filter string) *ClickHouseJWEServer {
	s := &ClickHouseJWEServer{}
	s.Config.Server.OAuth.Enabled = true
	s.Config.Server.OAuth.RoleClaim = claim
	s.Config.Server.OAuth.RoleFilter = filter
	return s
}

const rolesClaimKey = "https://clickhouse/roles"

// TestOAuthRoleFilterFailClosed verifies that when role_claim is set but no
// role in the claim matches role_filter, the request is rejected before any
// ClickHouse client is built — never falling back to the user's full grant.
func TestOAuthRoleFilterFailClosed(t *testing.T) {
	t.Parallel()
	s := roleServer(rolesClaimKey, "_mcp$")
	chCfg := config.ClickHouseConfig{Host: "ch.invalid", Port: 8123, Protocol: config.HTTPProtocol}
	claims := &OAuthClaims{Extra: map[string]interface{}{
		rolesClaimKey: []interface{}{"admin", "analyst"}, // none end in _mcp
	}}

	client, err := s.GetClickHouseClientWithOAuthForConfig(context.Background(), chCfg, "", "fake-bearer", claims)
	require.Error(t, err)
	require.Nil(t, client)
	require.Contains(t, err.Error(), "access denied")
}

// TestOAuthRoleFilterRejectsNonHTTP verifies the fail-closed guard for the
// native TCP protocol: role= activation is HTTP-only, so silently running on
// TCP (with the full grant) is refused.
func TestOAuthRoleFilterRejectsNonHTTP(t *testing.T) {
	t.Parallel()
	s := roleServer(rolesClaimKey, "_mcp$")
	chCfg := config.ClickHouseConfig{Host: "ch.invalid", Port: 9000, Protocol: config.TCPProtocol}
	claims := &OAuthClaims{Extra: map[string]interface{}{
		rolesClaimKey: []interface{}{"sandbox_mcp"}, // a match exists
	}}

	client, err := s.GetClickHouseClientWithOAuthForConfig(context.Background(), chCfg, "", "fake-bearer", claims)
	require.Error(t, err)
	require.Nil(t, client)
	require.Contains(t, err.Error(), "protocol http")
}

// TestOAuthRoleFilterPassesGate verifies that with a matching role over HTTP
// the role checks pass and the code proceeds to client construction — the
// resulting error is a connection failure, not a role/access-denied error.
func TestOAuthRoleFilterPassesGate(t *testing.T) {
	t.Parallel()
	s := roleServer(rolesClaimKey, "_mcp$")
	// Port 1 refuses immediately, so we exercise the role gate without a 10s dial.
	chCfg := config.ClickHouseConfig{Host: "127.0.0.1", Port: 1, Protocol: config.HTTPProtocol}
	claims := &OAuthClaims{Extra: map[string]interface{}{
		rolesClaimKey: []interface{}{"sandbox_mcp", "admin"},
	}}

	client, err := s.GetClickHouseClientWithOAuthForConfig(context.Background(), chCfg, "", "fake-bearer", claims)
	require.Error(t, err)
	require.Nil(t, client)
	require.NotContains(t, err.Error(), "access denied")
	require.NotContains(t, err.Error(), "protocol http")
}
