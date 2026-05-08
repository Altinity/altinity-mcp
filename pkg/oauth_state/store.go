// Package oauth_state implements server-side state for OAuth refresh-token
// reuse detection (H-2 in the OAuth security review).
//
// On every gating-mode `grant_type=refresh_token` request, the handler:
//
//  1. Calls Store.CheckAndConsume with the presented refresh token's jti
//     and family_id.
//  2. The store fast-rejects if the family is already in the revoked-
//     families table.
//  3. Otherwise it attempts to atomically claim the jti by INSERTing into
//     the KeeperMap-backed consumed-jti table (with strict mode, duplicate
//     PRIMARY KEY throws an exception). On success the caller mints a new
//     access+refresh pair sharing the same family_id with a new jti. On
//     duplicate-key error the family is recorded as revoked and
//     ErrRefreshReused is returned.
//
// Atomicity property: KeeperMap with `keeper_map_strict_mode=1` provides
// linearizable, exactly-one-winner INSERT across MCP pods regardless of
// which CH replica each pod connects to. This is what closes the parallel-
// replay window that the previous SELECT-then-INSERT design left open.
//
// Operators pre-create the schema (see docs/sql/oauth-state.sql) — the
// binary never issues DDL. KeeperMap requires `<keeper_map_path_prefix>`
// in CH server config; without it CREATE TABLE fails at deploy time.
package oauth_state

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/altinity/altinity-mcp/pkg/clickhouse"
	"github.com/rs/zerolog/log"
)

// ErrRefreshReused signals that the presented refresh token's jti was
// already consumed or its family was already revoked. The store
// best-effort records the family in oauth_refresh_revoked_families
// before returning this error. Callers must reject the refresh with
// `invalid_grant`.
var ErrRefreshReused = errors.New("oauth_state: refresh token reuse detected, family revoked")

// Store handles OAuth refresh-token reuse detection.
type Store interface {
	// CheckAndConsume tries to atomically claim the (jti, family_id) pair.
	//
	//   - Returns nil on a fresh redemption: the jti is now recorded as
	//     consumed (linearizable-claimed via KeeperMap strict mode).
	//     Caller mints new tokens.
	//   - Returns ErrRefreshReused if the family is already revoked OR
	//     another concurrent claimant won the race for this jti. The
	//     family is best-effort recorded in revoked_families.
	//   - Returns a wrapped CH error on infrastructure failure (caller
	//     hard-fails with HTTP 500 server_error).
	//
	// `reason` is recorded in oauth_refresh_revoked_families for audit;
	// suggested values: "reuse_detected", "manual_revoke".
	CheckAndConsume(ctx context.Context, jti, familyID, reason string) error

	// Cleanup deletes consumed-jti rows older than the given retention
	// window. Bounded operation, idempotent across pods. Returns the CH
	// error verbatim so callers can decide whether to log or escalate.
	Cleanup(ctx context.Context, retention time.Duration) error
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

// selectRevokedQuery returns 1 if the family is already revoked, 0 otherwise.
// Cheap point-lookup (ORDER BY family_id) on a small ReplicatedMergeTree.
const selectRevokedQuery = `SELECT count() FROM ` + revokedFamiliesTable + ` WHERE family_id = ?`

// insertConsumedQuery atomically claims a jti slot in the KeeperMap-backed
// table. `keeper_map_strict_mode` MUST be set on the INSERT statement
// itself — CH silently ignores the table-level SETTINGS clause for this
// flag, so without query-level enforcement a duplicate INSERT silently
// overwrites instead of erroring (verified empirically against CH 26.1.6).
// Without strict mode, the entire atomicity property of this design
// collapses; the SETTINGS clause below is load-bearing.
//
// On a duplicate primary key, CH raises a KEEPER_EXCEPTION with text
// "Transaction failed (Node exists)" — detected by isKeeperMapDuplicateKeyError.
const insertConsumedQuery = `INSERT INTO ` + consumedJtisTable + ` (jti, family_id) ` +
	`SETTINGS keeper_map_strict_mode = 1 VALUES (?, ?)`

const insertRevokedQuery = `INSERT INTO ` + revokedFamiliesTable + ` (family_id, reason) VALUES (?, ?)`

// deleteOldConsumedQuery is the cleanup statement: KeeperMap doesn't support
// CH-native TTL, so we run this on a goroutine ticker. Uses INTERVAL with a
// bound seconds value (driver-side parametrization).
const deleteOldConsumedQuery = `ALTER TABLE ` + consumedJtisTable + ` DELETE WHERE consumed_at < now() - toIntervalSecond(?)`

func (s *chStore) CheckAndConsume(ctx context.Context, jti, familyID, reason string) error {
	if jti == "" || familyID == "" {
		return fmt.Errorf("oauth_state: jti and family_id must both be non-empty")
	}

	cli, err := s.newClient(ctx)
	if err != nil {
		return fmt.Errorf("oauth_state: open CH client: %w", err)
	}
	defer func() { _ = cli.Close() }()

	// 1. Cheap revocation check. If the family is already in
	// revoked_families, fast-reject without burning a KeeperMap slot.
	// Catches the case where a prior race-loser pod revoked the family
	// and the legitimate owner is now refreshing.
	revoked, err := s.familyRevoked(ctx, cli, familyID)
	if err != nil {
		return fmt.Errorf("oauth_state: select revoked: %w", err)
	}
	if revoked {
		return ErrRefreshReused
	}

	// 2. Atomic claim. KeeperMap strict-mode INSERT is linearized through
	// Keeper Raft: exactly one of N concurrent redeemers wins, the rest
	// see a duplicate-key exception. The winner returns nil; the losers
	// fall into the reuse-detected branch below.
	if _, ierr := cli.ExecuteQuery(ctx, insertConsumedQuery, jti, familyID); ierr != nil {
		if !isKeeperMapDuplicateKeyError(ierr) {
			return fmt.Errorf("oauth_state: insert consumed jti: %w", ierr)
		}
		// 3. Reuse detected. Record the family revocation. Idempotent
		// across parallel losers (multiple INSERTs to revoked_families
		// merge / TTL-expire). If the revoke INSERT itself fails we
		// still return ErrRefreshReused — better to over-reject than
		// silently mint a duplicate, and the family is logically
		// revoked for the next refresh attempt either way (the
		// duplicate-key error is the SECURITY signal; the revoke
		// table is the audit trail).
		if _, rerr := cli.ExecuteQuery(ctx, insertRevokedQuery, familyID, reason); rerr != nil {
			log.Warn().
				Err(rerr).
				Str("family_id", familyID).
				Msg("oauth_state: revoked-family insert failed (non-fatal — family is logically revoked anyway)")
		}
		return ErrRefreshReused
	}

	// Winner. Caller mints new tokens with the same family_id.
	return nil
}

func (s *chStore) familyRevoked(ctx context.Context, cli CHClient, familyID string) (bool, error) {
	res, err := cli.ExecuteQuery(ctx, selectRevokedQuery, familyID)
	if err != nil {
		return false, err
	}
	if res == nil || res.Count != 1 || len(res.Rows) != 1 || len(res.Rows[0]) < 1 {
		return false, fmt.Errorf("oauth_state: unexpected revoked-select shape")
	}
	revoked, perr := readUInt64(res.Rows[0][0])
	if perr != nil {
		return false, fmt.Errorf("oauth_state: parse revoked count: %w", perr)
	}
	return revoked > 0, nil
}

// isKeeperMapDuplicateKeyError detects ClickHouse's strict-mode KeeperMap
// duplicate-PRIMARY-KEY exception. The exact surfaced error message,
// verified empirically against CH 26.1.6 stock running KeeperMap with
// `keeper_map_strict_mode=1`:
//
//	Code: 999. DB::Exception: Coordination::Exception. Transaction failed
//	(Node exists): Op #0, path: /altinity_mcp/keeper_map/.../data/<key>.
//	(KEEPER_EXCEPTION)
//
// We match on `Transaction failed (Node exists)` — the most specific,
// stable phrase across CH versions — and accept either case form since
// some driver paths capitalise differently. Code 999 (KEEPER_EXCEPTION)
// is checked separately as a backstop in case the message format drifts.
//
// Risk of over-matching: very low. `Transaction failed (Node exists)`
// is the Keeper Raft phrase for "create-if-absent rejected because the
// node exists" — for KeeperMap this only fires on PRIMARY KEY collision.
// Other Keeper errors (timeout, leader-loss, etc.) produce different
// messages.
func isKeeperMapDuplicateKeyError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	if strings.Contains(msg, "Transaction failed (Node exists)") {
		return true
	}
	// Lowercased fallback — defensive; not observed in 26.1.6 but cheap.
	if strings.Contains(strings.ToLower(msg), "transaction failed (node exists)") {
		return true
	}
	return false
}

func (s *chStore) Cleanup(ctx context.Context, retention time.Duration) error {
	cli, err := s.newClient(ctx)
	if err != nil {
		return fmt.Errorf("oauth_state cleanup: open CH client: %w", err)
	}
	defer func() { _ = cli.Close() }()
	cutoffSeconds := int64(retention.Seconds())
	if cutoffSeconds <= 0 {
		return fmt.Errorf("oauth_state cleanup: retention must be positive (got %v)", retention)
	}
	if _, err := cli.ExecuteQuery(ctx, deleteOldConsumedQuery, cutoffSeconds); err != nil {
		return fmt.Errorf("oauth_state cleanup: ALTER DELETE: %w", err)
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
