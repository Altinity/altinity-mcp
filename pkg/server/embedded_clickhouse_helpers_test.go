package server

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/altinity/altinity-mcp/internal/testutil/embeddedch"
	"github.com/altinity/altinity-mcp/pkg/clickhouse"
	"github.com/altinity/altinity-mcp/pkg/config"
	"github.com/stretchr/testify/require"
)

// setupEmbeddedClickHouse boots a ClickHouse server via embedded-clickhouse
// and seeds the default.test table the broader pkg/server suite relies on.
// Use setupEmbeddedClickHouseUnseeded when the test needs a clean server.
func setupEmbeddedClickHouse(t *testing.T, opts ...embeddedch.Option) *config.ClickHouseConfig {
	t.Helper()
	chConfig := embeddedch.Setup(t, opts...)
	seedDefaultTable(t, chConfig)
	return chConfig
}

// setupEmbeddedClickHouseUnseeded boots a server without seeding default.test.
// Use this for tests that need a clean schema or define their own users via
// config.d drop-ins (where the default user may not have access yet).
func setupEmbeddedClickHouseUnseeded(t *testing.T, opts ...embeddedch.Option) *config.ClickHouseConfig {
	t.Helper()
	return embeddedch.Setup(t, opts...)
}

func seedDefaultTable(t *testing.T, chConfig *config.ClickHouseConfig) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client, err := clickhouse.NewClient(ctx, *chConfig)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	_, err = client.ExecuteQuery(ctx, `CREATE TABLE IF NOT EXISTS default.test (
		id UInt64,
		name String,
		created_at DateTime
	) ENGINE = MergeTree() ORDER BY id`)
	require.NoError(t, err)
	_, err = client.ExecuteQuery(ctx, `INSERT INTO default.test VALUES (1, 'test1', now()), (2, 'test2', now())`)
	require.NoError(t, err)
}

// Local re-exports so call sites in pkg/server don't need to import the
// shared package by its full path.
func withFlavor(f embeddedch.Flavor) embeddedch.Option { return embeddedch.WithFlavor(f) }
func withConfigDropIn(xml string) embeddedch.Option    { return embeddedch.WithConfigDropIn(xml) }

const (
	flavorStock   = embeddedch.FlavorStock
	flavorAntalya = embeddedch.FlavorAntalya
)

// portString stringifies an integer port for callers building DSNs by hand.
func portString(p int) string { return strconv.Itoa(p) }
