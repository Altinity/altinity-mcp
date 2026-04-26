package server

import (
	"context"
	"database/sql"
	"testing"
	"time"

	_ "github.com/Altinity/clickhouse-go/v2"
	"github.com/stretchr/testify/require"
)

// TestEmbeddedClickHouseXMLDropIn verifies that ClickHouse's standard
// auto-merge of config.d/*.xml works under embedded-clickhouse: we drop a
// custom user, profile, and a server-level setting into config.d/, then assert
// at runtime that all three took effect.
//
// embedded-clickhouse generates a single config.xml with <users> defined
// inline (no separate users.xml), so users.d/ is ignored. Drop-ins go in
// config.d/, where ClickHouse merges them into the main config — including
// <users> and <profiles> elements.
func TestEmbeddedClickHouseXMLDropIn(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("skipping CH XML drop-in test in short mode")
	}

	const customXML = `<?xml version="1.0"?>
<clickhouse>
    <max_connections>4242</max_connections>
    <users>
        <tester>
            <password>secret123</password>
            <networks>
                <ip>::/0</ip>
            </networks>
            <profile>tester_profile</profile>
            <quota>default</quota>
        </tester>
    </users>
    <profiles>
        <tester_profile>
            <max_memory_usage>123456789</max_memory_usage>
        </tester_profile>
    </profiles>
</clickhouse>
`
	chConfig := setupEmbeddedClickHouseUnseeded(t,
		withConfigDropIn(customXML),
	)

	dsn := "http://tester:secret123@" + chConfig.Host + ":" + portString(chConfig.Port) + "/default"
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	db, err := sql.Open("clickhouse", dsn)
	require.NoError(t, err, "DSN: %s", dsn)
	t.Cleanup(func() { _ = db.Close() })

	t.Run("custom_user_authenticates", func(t *testing.T) {
		var who string
		require.NoError(t, db.QueryRowContext(ctx, "SELECT currentUser()").Scan(&who),
			"the users.d drop-in must have created the user; auth must succeed")
		require.Equal(t, "tester", who)
	})

	t.Run("custom_profile_setting_applied", func(t *testing.T) {
		var maxMem string
		require.NoError(t, db.QueryRowContext(ctx, "SELECT getSetting('max_memory_usage')").Scan(&maxMem),
			"the profile we attached to the custom user via config.d must apply")
		require.Equal(t, "123456789", maxMem,
			"max_memory_usage from tester_profile in config.d must be honored")
	})

	t.Run("config_d_server_setting_applied", func(t *testing.T) {
		var rows int
		require.NoError(t, db.QueryRowContext(ctx,
			"SELECT count() FROM system.server_settings WHERE name = 'max_connections' AND value = '4242'",
		).Scan(&rows),
			"the config.d drop-in must have set max_connections=4242 server-wide")
		require.Equal(t, 1, rows,
			"system.server_settings should report max_connections=4242 from our drop-in")
	})
}
