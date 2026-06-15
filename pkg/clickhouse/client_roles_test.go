package clickhouse

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/altinity/altinity-mcp/internal/testutil/embeddedch"
	"github.com/stretchr/testify/require"
)

// captureRT records the RawQuery of the request it receives and returns an
// empty 200 response. It stands in for the driver's real transport.
type captureRT struct{ gotQuery string }

func (c *captureRT) RoundTrip(req *http.Request) (*http.Response, error) {
	c.gotQuery = req.URL.RawQuery
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader("")),
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

// TestRoleRoundTripper pins the multi-role wire encoding: each configured role
// is appended as its own repeated `role=` query param, existing params are
// preserved, and the caller's request is not mutated (so retries are safe).
func TestRoleRoundTripper(t *testing.T) {
	t.Parallel()
	cap := &captureRT{}
	rt := &roleRoundTripper{wrapped: cap, roles: []string{"sandbox_mcp", "readonly_mcp"}}

	req, err := http.NewRequest(http.MethodPost, "http://ch:8123/?database=default", strings.NewReader("SELECT 1"))
	require.NoError(t, err)
	origQuery := req.URL.RawQuery

	resp, err := rt.RoundTrip(req)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())

	// The shared request object must be untouched.
	require.Equal(t, origQuery, req.URL.RawQuery)

	vals, err := url.ParseQuery(cap.gotQuery)
	require.NoError(t, err)
	require.Equal(t, []string{"sandbox_mcp", "readonly_mcp"}, vals["role"], "both roles sent as repeated params")
	require.Equal(t, "default", vals.Get("database"), "pre-existing query params preserved")
}

// roleTestUsersXML enables SQL access management on the default user so the
// test can CREATE ROLE / CREATE USER / GRANT. embedded-clickhouse ships no
// users.xml of its own, so we provide a minimal one.
const roleTestUsersXML = `<?xml version="1.0"?>
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

// TestClientRoleActivation proves end-to-end that config.Roles activates only
// the named roles for a request: currentRoles() returns exactly the activated
// set, and a query needing a non-activated role's privilege is denied.
func TestClientRoleActivation(t *testing.T) {
	t.Parallel()
	// SQL CREATE ROLE/USER needs a writeable access storage; point
	// access_control_path at a temp dir (users.xml alone is read-only).
	accessDropIn := fmt.Sprintf(
		"<clickhouse><access_control_path>%s/</access_control_path></clickhouse>",
		t.TempDir(),
	)
	cfg := embeddedch.Setup(t,
		embeddedch.WithUsersXML(roleTestUsersXML),
		embeddedch.WithConfigDropIn(accessDropIn),
	) // HTTP protocol by default
	ctx := context.Background()

	admin, err := NewClient(ctx, *cfg)
	require.NoError(t, err)
	defer func() { require.NoError(t, admin.Close()) }()

	exec := func(q string) {
		t.Helper()
		res, err := admin.ExecuteQuery(ctx, q)
		require.NoError(t, err, q)
		require.Empty(t, res.Error, q)
	}
	exec("CREATE DATABASE IF NOT EXISTS roletest")
	exec("CREATE TABLE IF NOT EXISTS roletest.public (x UInt64) ENGINE = Memory")
	exec("CREATE TABLE IF NOT EXISTS roletest.secret (x UInt64) ENGINE = Memory")
	exec("CREATE ROLE IF NOT EXISTS r_public_mcp")
	exec("CREATE ROLE IF NOT EXISTS r_secret_real")
	exec("GRANT SELECT ON roletest.public TO r_public_mcp")
	exec("GRANT SELECT ON roletest.secret TO r_secret_real")
	exec("CREATE USER IF NOT EXISTS ruser IDENTIFIED WITH no_password HOST ANY")
	exec("GRANT r_public_mcp, r_secret_real TO ruser")

	// Base config for the restricted user, activating only the sandbox role.
	userCfg := *cfg
	userCfg.Username = "ruser"
	userCfg.Password = ""
	userCfg.Roles = []string{"r_public_mcp"}

	cl, err := NewClient(ctx, userCfg)
	require.NoError(t, err)
	defer func() { require.NoError(t, cl.Close()) }()

	t.Run("narrows_active_roles", func(t *testing.T) {
		res, err := cl.ExecuteQuery(ctx, "SELECT arrayStringConcat(arraySort(currentRoles()), ',') AS roles")
		require.NoError(t, err)
		require.Empty(t, res.Error)
		require.Len(t, res.Rows, 1)
		require.Equal(t, "r_public_mcp", fmt.Sprint(res.Rows[0][0]),
			"only the activated role is current, not the full granted set")
	})

	t.Run("activated_role_privilege_allowed", func(t *testing.T) {
		res, err := cl.ExecuteQuery(ctx, "SELECT count() FROM roletest.public")
		require.NoError(t, err)
		require.Empty(t, res.Error)
	})

	t.Run("non_activated_role_privilege_denied", func(t *testing.T) {
		_, err := cl.ExecuteQuery(ctx, "SELECT count() FROM roletest.secret")
		require.Error(t, err, "secret table needs r_secret_real, which was not activated")
		require.Contains(t, strings.ToLower(err.Error()), "privileg",
			"expected an ACCESS_DENIED / not-enough-privileges error")
	})
}
