# QA scripts — H-2 refresh-token reuse detection

Regression coverage for the OAuth refresh-token atomicity property
([#103](https://github.com/altinity/altinity-mcp/issues/103),
[#106](https://github.com/altinity/altinity-mcp/pull/106)). These run
against a **live deployment** (gating mode + `oauth.refresh_revokes_tracking: true`)
and complement the unit test
`TestOAuthRefreshReuseDetection_AtomicConcurrentClaim` in
`cmd/altinity-mcp/oauth_server_test.go`.

The unit test proves the handler's branching is correct against a
synchronised in-memory fake. These scripts prove the property holds end
-to-end through the live HTTP/JWE/Keeper stack — the surface where the
SELECT-then-INSERT race the original H-2 design left open would actually
manifest.

## Prerequisites

- `jq`, `openssl`, `python3`, `curl` (all on a stock macOS or any Linux)
- A browser to complete the Auth0 login interactively (one click per run)
- Network access to the target MCP `/oauth/{register,authorize,token}`
  endpoints
- Local port 8910 free (override with `PORT=…`)

## When to run

Run before merging any change that touches:

- `pkg/oauth_state/store.go` — claim/revoke logic
- `pkg/oauth_state/cleanup.go` — TTL replacement
- `pkg/server/server_client.go:GetClickHouseSystemClient` — pool-user CH connection used by the store
- `pkg/jwe_auth/jwe_auth.go` claims whitelist (specifically `family_id`/`jti`)
- `cmd/altinity-mcp/oauth_server.go:mintGatingTokenResponse` — refresh-token claims
- `cmd/altinity-mcp/oauth_server.go:handleOAuthTokenRefresh` — caller of CheckAndConsume
- `docs/sql/oauth-state.sql` schema — KeeperMap table shape
- CHI `<keeper_map_path_prefix>` config — operator-side enabling

…against any environment running gating mode with H-2 enabled.

## Scripts

### `h2-replay-test.sh` — sequential reuse + family revocation

Drives:

1. DCR registration → ephemeral client_id
2. `/oauth/authorize` → browser → Auth0 → `/oauth/callback` (captured by an
   inline Python `http.server` on `localhost:8910`)
3. `/oauth/token` `grant_type=authorization_code` → R0
4. `/oauth/token` `grant_type=refresh_token` (R0) → expect **200 OK** → R1
5. `/oauth/token` `grant_type=refresh_token` (**same R0**) → expect **400
   `invalid_grant` "refresh token reuse detected"**
6. (bonus) `/oauth/token` `grant_type=refresh_token` (R1) → expect **400
   `invalid_grant`** even though R1 is a legitimate child of R0; family
   revocation is family-wide per RFC 9700

Override env: `MCP=https://otel-mcp.demo.altinity.cloud` (default), `PORT=8910`.

State-table verification afterwards:

```sql
SELECT consumed_at, jti, family_id
FROM   altinity.oauth_refresh_consumed_jtis
ORDER BY consumed_at DESC LIMIT 3;
-- expect: a row for R0's jti (claimed) + a row for R1's jti (claimed
-- before the family was revoked)

SELECT revoked_at, family_id, reason
FROM   altinity.oauth_refresh_revoked_families
ORDER BY revoked_at DESC LIMIT 3;
-- expect: row with reason='reuse_detected', family_id matching the
-- family from the consumed-jtis rows
```

### `h2-parallel-test.sh` — atomicity under concurrent replay

The property the KeeperMap migration adds. Drives the same DCR + Auth0
dance to obtain R0, then fires **N parallel redemptions** (default 50)
of the same R0 via backgrounded `curl &` + `wait`. Asserts:

- exactly **1 × 200 OK**
- exactly **N − 1 × 400 `invalid_grant` "refresh token reuse detected"**
- zero anomalies

Non-zero exit on any deviation. Tweak concurrency via `N=…`.

This is the test that the SELECT-then-INSERT design (PR #106 commit
`0f3318d` before the atomicity fix) would FAIL — multiple redeemers
racing through `count() = 0` would all win, family forks, no reuse
detected. With KeeperMap strict mode, Keeper Raft serialises the
concurrent INSERTs through the cluster leader; only one transaction
wins, the rest receive `KEEPER_EXCEPTION: Transaction failed (Node
exists)` (Code 999) and the handler maps that to the reuse-detected
error response.

State-table verification afterwards:

```sql
SELECT count() FROM altinity.oauth_refresh_consumed_jtis
WHERE consumed_at > now() - 60;
-- expect: 1 (only the winner's INSERT landed; the other 49 were rejected
-- by KeeperMap before any row was created)

SELECT family_id, reason FROM altinity.oauth_refresh_revoked_families
WHERE revoked_at > now() - 60;
-- expect: ≥1 row with reason='reuse_detected' (multiple losers may have
-- written the same family_id; revoke is idempotent)
```

## Cleanup

Both scripts use ephemeral DCR client_ids (one per run, JWE-stateless,
expire on the OAuth signing-secret rotation). Nothing to clean up.

The `consumed_jtis` rows from test runs decay automatically via the
35-day cleanup goroutine in `pkg/oauth_state/cleanup.go`. The
`revoked_families` rows decay via CH-native TTL.

## Failure modes

| Symptom                                          | Likely cause                                                                 |
| ------------------------------------------------ | ---------------------------------------------------------------------------- |
| `localhost refused to connect` in browser        | python3 listener didn't bind — port 8910 in use; rerun with `PORT=…`          |
| `no callback received within 5 min`              | browser tab was closed before submitting Auth0; rerun                         |
| `token exchange failed: { … invalid_grant … }`   | auth code expired (60 s TTL); rerun the full flow                             |
| `HTTP 500` `server_error` `refresh state unavailable` | CH unreachable, RBAC denied, or `keeper_map_path_prefix` missing on CHI — see [`docs/oauth-refresh-reuse-detection.md`](../../docs/oauth-refresh-reuse-detection.md) §Operator prerequisites |
| Replay test sees 200 instead of 400              | The atomicity fix regressed; check `pkg/oauth_state/store.go:CheckAndConsume` for re-introduced check-then-act pattern; check `INSERT` statement still has `SETTINGS keeper_map_strict_mode = 1` |
| Parallel test sees `success > 1`                 | Same as above, more dramatic. The KeeperMap claim is no longer atomic.       |
