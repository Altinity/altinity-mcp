// Package oauth_state implements server-side state for OAuth refresh-token
// reuse detection (H-2 in the OAuth security review).
//
// On every gating-mode `grant_type=refresh_token` request, the handler:
//
//  1. Calls Store.CheckAndConsume with the presented refresh token's jti
//     and family_id.
//  2. If the jti was already in the consumed-jti table OR the family_id was
//     already in the revoked-families table, the entire family is revoked
//     and ErrRefreshReused is returned. The handler must reject the request.
//  3. Otherwise, the jti is recorded as consumed and the handler mints a
//     fresh access+refresh pair sharing the same family_id with a new jti.
//
// The implementation is intentionally minimal: two ClickHouse tables in the
// `altinity` database, each Replicated|MergeTree with TTL 35 days. Operators
// pre-create the schema (see docs/sql/oauth-state.sql) — the binary never
// issues DDL.
package oauth_state

import (
	"context"
	"errors"
	"fmt"
	"math/big"

	"github.com/altinity/altinity-mcp/pkg/clickhouse"
)

// ErrRefreshReused signals that the presented refresh token's jti was
// already consumed or its family was already revoked. The store has
// recorded the family in oauth_refresh_revoked_families before returning
// this error. Callers must reject the refresh with `invalid_grant`.
var ErrRefreshReused = errors.New("oauth_state: refresh token reuse detected, family revoked")

// Store handles OAuth refresh-token reuse detection.
type Store interface {
	// CheckAndConsume looks up the jti + family_id, marks the family
	// revoked on a hit, or marks the jti consumed on a miss.
	//
	// `reason` is recorded in oauth_refresh_revoked_families for audit;
	// suggested values: "reuse_detected", "manual_revoke".
	//
	// Returns ErrRefreshReused on reuse, nil on a fresh redemption,
	// or a wrapped CH error on infrastructure failure (caller hard-fails).
	CheckAndConsume(ctx context.Context, jti, familyID, reason string) error
}

// CHClient is the subset of *clickhouse.Client used by chStore. It exists
// so tests can inject fakes without depending on the real driver.
type CHClient interface {
	ExecuteQuery(ctx context.Context, query string, args ...interface{}) (*clickhouse.QueryResult, error)
	Close() error
}

// ClientFactory returns a fresh ClickHouse client per call. The store
// closes the client after each CheckAndConsume.
//
// In production this is wired to ClickHouseJWEServer.GetClickHouseSystemClient
// so state queries authorize as the pool user (mcp_service) and bypass the
// cluster-secret + initial_user impersonation used for end-user-bound queries.
type ClientFactory func(ctx context.Context) (CHClient, error)

type chStore struct {
	newClient ClientFactory
}

// NewClickHouseStore wires a Store to a ClickHouse connection factory.
func NewClickHouseStore(newClient ClientFactory) Store {
	return &chStore{newClient: newClient}
}

// Table names are hardcoded — operators created them via the documented DDL.
const (
	consumedJtisTable    = "altinity.oauth_refresh_consumed_jtis"
	revokedFamiliesTable = "altinity.oauth_refresh_revoked_families"
)

// Combined existence check: one round trip yields both consumed-jti and
// revoked-family counts. Subqueries each use the table's primary-key
// index (ORDER BY jti / ORDER BY family_id), so each is a sparse-index
// lookup, not a scan.
const checkQuery = `
SELECT
    (SELECT count() FROM ` + consumedJtisTable + ` WHERE jti = ?) AS consumed,
    (SELECT count() FROM ` + revokedFamiliesTable + ` WHERE family_id = ?) AS revoked
`

const insertConsumedQuery = `INSERT INTO ` + consumedJtisTable + ` (jti, family_id) VALUES (?, ?)`

const insertRevokedQuery = `INSERT INTO ` + revokedFamiliesTable + ` (family_id, reason) VALUES (?, ?)`

func (s *chStore) CheckAndConsume(ctx context.Context, jti, familyID, reason string) error {
	if jti == "" || familyID == "" {
		return fmt.Errorf("oauth_state: jti and family_id must both be non-empty")
	}

	cli, err := s.newClient(ctx)
	if err != nil {
		return fmt.Errorf("oauth_state: open CH client: %w", err)
	}
	defer func() { _ = cli.Close() }()

	res, err := cli.ExecuteQuery(ctx, checkQuery, jti, familyID)
	if err != nil {
		return fmt.Errorf("oauth_state: select consumed/revoked: %w", err)
	}
	if res == nil || res.Count != 1 || len(res.Rows) != 1 || len(res.Rows[0]) < 2 {
		return fmt.Errorf("oauth_state: unexpected select shape (count=%d rows=%d cols=%d)",
			func() int {
				if res == nil {
					return 0
				}
				return res.Count
			}(),
			func() int {
				if res == nil {
					return 0
				}
				return len(res.Rows)
			}(),
			func() int {
				if res == nil || len(res.Rows) == 0 {
					return 0
				}
				return len(res.Rows[0])
			}())
	}

	consumed, err := readUInt64(res.Rows[0][0])
	if err != nil {
		return fmt.Errorf("oauth_state: parse consumed count: %w", err)
	}
	revoked, err := readUInt64(res.Rows[0][1])
	if err != nil {
		return fmt.Errorf("oauth_state: parse revoked count: %w", err)
	}

	if consumed > 0 || revoked > 0 {
		if _, ierr := cli.ExecuteQuery(ctx, insertRevokedQuery, familyID, reason); ierr != nil {
			return fmt.Errorf("oauth_state: insert revoked family: %w", ierr)
		}
		return ErrRefreshReused
	}

	if _, ierr := cli.ExecuteQuery(ctx, insertConsumedQuery, jti, familyID); ierr != nil {
		return fmt.Errorf("oauth_state: insert consumed jti: %w", ierr)
	}
	return nil
}

// readUInt64 normalizes count() return values across driver paths
// (uint64/int64/*big.Int depending on protocol + version).
func readUInt64(v interface{}) (uint64, error) {
	switch t := v.(type) {
	case uint64:
		return t, nil
	case int64:
		if t < 0 {
			return 0, fmt.Errorf("negative count %d", t)
		}
		return uint64(t), nil
	case uint32:
		return uint64(t), nil
	case int:
		if t < 0 {
			return 0, fmt.Errorf("negative count %d", t)
		}
		return uint64(t), nil
	case *big.Int:
		if t == nil {
			return 0, fmt.Errorf("nil *big.Int count")
		}
		if t.Sign() < 0 {
			return 0, fmt.Errorf("negative count %s", t.String())
		}
		return t.Uint64(), nil
	default:
		return 0, fmt.Errorf("unexpected count type %T", v)
	}
}
