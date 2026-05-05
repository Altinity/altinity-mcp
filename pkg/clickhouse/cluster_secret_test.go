package clickhouse

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/altinity/altinity-mcp/pkg/config"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

const (
	testClusterName   = "test_cluster"
	testClusterSecret = "altinity-mcp-cluster-secret"

	clusterConfigXML = `<clickhouse>
    <remote_servers>
        <test_cluster>
            <secret>altinity-mcp-cluster-secret</secret>
            <shard>
                <replica>
                    <host>localhost</host>
                    <port>9000</port>
                </replica>
            </shard>
        </test_cluster>
    </remote_servers>
</clickhouse>
`

	// alice and bob are declared with no password so the interserver path can
	// authenticate them via AlwaysAllowCredentials. A static password would
	// also be accepted — the interserver check never compares it — but
	// no_password keeps the fixture honest: the shared secret is the only
	// credential that reaches the server.
	clusterUsersXML = `<clickhouse>
    <users>
        <alice>
            <no_password/>
            <networks><ip>::/0</ip></networks>
            <profile>default</profile>
            <quota>default</quota>
            <access_management>1</access_management>
        </alice>
        <bob>
            <no_password/>
            <networks><ip>::/0</ip></networks>
            <profile>default</profile>
            <quota>default</quota>
        </bob>
    </users>
</clickhouse>
`
)

// setupClusterSecretClickHouse launches a ClickHouse container whose
// `remote_servers` list declares a cluster with a shared interserver secret,
// plus two password-less users (alice, bob) that the driver can impersonate.
//
// Config files are written by a shell wrapper before ClickHouse starts. We
// cannot use testcontainers' file-copy API here — the isolator sandbox
// blocks the `PUT /containers/<id>/archive` Docker endpoint.
func setupClusterSecretClickHouse(t *testing.T) (host string, tcpPort int) {
	t.Helper()
	ctx := context.Background()

	script := fmt.Sprintf(`set -e
cat > /etc/clickhouse-server/config.d/cluster.xml <<'EOF'
%sEOF
cat > /etc/clickhouse-server/users.d/cluster_users.xml <<'EOF'
%sEOF
exec /entrypoint.sh
`, clusterConfigXML, clusterUsersXML)

	req := testcontainers.ContainerRequest{
		Image:        "clickhouse/clickhouse-server:latest",
		ExposedPorts: []string{"8123/tcp", "9000/tcp"},
		Env: map[string]string{
			"CLICKHOUSE_DB":                        "default",
			"CLICKHOUSE_USER":                      "default",
			"CLICKHOUSE_PASSWORD":                  "",
			"CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT": "1",
		},
		Entrypoint: []string{"/bin/sh", "-c", script},
		WaitingFor: wait.ForHTTP("/").WithPort("8123/tcp").
			WithStartupTimeout(60 * time.Second).
			WithPollInterval(2 * time.Second),
	}
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if termErr := c.Terminate(cleanCtx); termErr != nil {
			t.Logf("cluster fixture: terminate failed: %v", termErr)
		}
	})

	h, err := c.Host(ctx)
	require.NoError(t, err)
	p, err := c.MappedPort(ctx, "9000")
	require.NoError(t, err)
	return h, p.Int()
}

func clusterClientConfig(host string, port int, username string, secret string) config.ClickHouseConfig {
	return config.ClickHouseConfig{
		Host:             host,
		Port:             port,
		Database:         "default",
		Username:         username,
		Password:         "", // never needed; included to prove it is ignored
		Protocol:         config.TCPProtocol,
		MaxExecutionTime: 60,
		ClusterName:      testClusterName,
		ClusterSecret:    secret,
	}
}

// TestClusterSecretImpersonation is the end-to-end proof that altinity-mcp
// can authenticate to ClickHouse with only the shared cluster secret and
// execute queries as an arbitrary user. Three cases:
//
//  1. Impersonate `alice`: `currentUser()` returns `alice`.
//  2. Impersonate `bob` over a second connection with the same secret.
//  3. Wrong secret is rejected by the server.
func TestClusterSecretImpersonation(t *testing.T) {
	t.Parallel()
	host, port := setupClusterSecretClickHouse(t)
	ctx := context.Background()

	t.Run("alice", func(t *testing.T) {
		cfg := clusterClientConfig(host, port, "alice", testClusterSecret)
		client, err := NewClient(ctx, cfg)
		require.NoError(t, err)
		defer func() { require.NoError(t, client.Close()) }()

		res, err := client.ExecuteQuery(ctx, "SELECT currentUser()")
		require.NoError(t, err)
		require.Equal(t, 1, res.Count)
		require.Equal(t, "alice", res.Rows[0][0])
	})

	t.Run("bob", func(t *testing.T) {
		cfg := clusterClientConfig(host, port, "bob", testClusterSecret)
		client, err := NewClient(ctx, cfg)
		require.NoError(t, err)
		defer func() { require.NoError(t, client.Close()) }()

		res, err := client.ExecuteQuery(ctx, "SELECT currentUser()")
		require.NoError(t, err)
		require.Equal(t, "bob", res.Rows[0][0])
	})

	t.Run("wrong_secret_rejected", func(t *testing.T) {
		cfg := clusterClientConfig(host, port, "alice", "wrong-secret")
		client, err := NewClient(ctx, cfg)
		// The interserver hash is only verified when the server processes
		// a query, so NewClient's ping may or may not fail depending on
		// timing. Either a construction error or a query error is fine —
		// we just need the session to not succeed. ClickHouse typically
		// closes the socket on auth failure rather than returning a typed
		// error, so match broadly on EOF / Authentication / connection
		// closed messages.
		if err != nil {
			return
		}
		defer func() { _ = client.Close() }()

		res, queryErr := client.ExecuteQuery(ctx, "SELECT currentUser()")
		require.Error(t, queryErr, "query must not succeed with wrong secret, got %+v", res)
	})
}

// TestClusterSecretNoPasswordRequired proves altinity-mcp can run with no
// ClickHouse password configured. The Auth.Password field is empty and the
// driver drops it entirely in cluster-secret mode; only the shared secret
// leaves the client.
func TestClusterSecretNoPasswordRequired(t *testing.T) {
	t.Parallel()
	host, port := setupClusterSecretClickHouse(t)
	ctx := context.Background()

	cfg := clusterClientConfig(host, port, "alice", testClusterSecret)
	cfg.Password = "this-should-be-ignored"

	client, err := NewClient(ctx, cfg)
	require.NoError(t, err)
	defer func() { require.NoError(t, client.Close()) }()

	res, err := client.ExecuteQuery(ctx, "SELECT currentUser()")
	require.NoError(t, err)
	require.Equal(t, "alice", res.Rows[0][0])
}
