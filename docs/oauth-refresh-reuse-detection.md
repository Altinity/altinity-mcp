# OAuth refresh-token reuse detection (H-2)

This page documents the H-2 mitigation from the internal OAuth security
review: how it works, what operators must do before turning it on, and how
it fails. It is opt-in — set `oauth.refresh_revokes_tracking: true` only
after running the operator prerequisites below.

## Why this exists

Without H-2, gating-mode refresh tokens are stateless JWE blobs. A captured
refresh token can be redeemed many times — each redemption mints a fresh
`access_token` + rotated `refresh_token` pair until the original JWE expires
(default 30 days). An attacker who briefly captures a refresh JWE (leaked
log, intermediate proxy, browser-extension compromise) gets a silent 30-day
window of access against the legitimate user's identity.

OAuth 2.1 §4.13.2 and the MCP authorization spec (2025-11-25) require
*refresh-token rotation with reuse detection*: when a previously-redeemed
token is presented again, the entire token *family* must be invalidated and
the user forced to re-authenticate. RFC 6749 §10.4 frames the same
requirement at SHOULD level for OAuth 2.0.

H-2 closes the gap: the moment the legitimate client refreshes after the
attacker (or vice-versa), the redeemed jti is in the consumed-set, the
family is revoked, both parties are rejected on subsequent attempts, and
the user re-authenticates once. The auth event is a clear signal.

## How it works

Every gating-mode refresh JWE carries two new claims:

| Claim       | Lifecycle                                                       |
| ----------- | --------------------------------------------------------------- |
| `jti`       | Fresh 16-byte random hex per issuance. **Different every refresh.** |
| `family_id` | Fresh 16-byte random hex at code→token exchange. **Stable across the entire rotation chain.** |

```
client → POST /oauth/token grant_type=authorization_code
server → mint R1 { jti: A, family_id: F, ... }              [F is new]

client → POST /oauth/token grant_type=refresh_token, R1
server → check: A not in consumed, F not in revoked
       → INSERT (jti=A, family_id=F) into consumed
       → mint R2 { jti: B, family_id: F, ... }              [same F, new jti]

client → POST /oauth/token grant_type=refresh_token, R2
server → check: B not in consumed, F not in revoked
       → INSERT (jti=B, family_id=F) into consumed
       → mint R3 { jti: C, family_id: F, ... }
```

Reuse detection:

```
attacker steals R1 before client uses it.
client legitimately refreshes R1 → R2 (A consumed, F still healthy)
client refreshes R2 → R3 (B consumed)
attacker now presents R1: server sees A already in consumed
                        → INSERT (family_id=F, reason="reuse_detected") into revoked_families
                        → reject this request with invalid_grant
                        → next legit refresh of R3 sees F in revoked → also rejected
                        → user re-auths from scratch
```

State lives in two ClickHouse tables in the `altinity` database. Both are
append-only with `TTL ... + INTERVAL 35 DAY` so storage is bounded.

| Table                                        | Purpose                                       | Lookup key  |
| -------------------------------------------- | --------------------------------------------- | ----------- |
| `altinity.oauth_refresh_consumed_jtis`       | Every redeemed refresh-token jti              | `jti`       |
| `altinity.oauth_refresh_revoked_families`    | Families flagged after reuse detection        | `family_id` |

Each refresh = 1 combined `SELECT count()` (two subqueries) + 1 `INSERT`.
At realistic load (~hundreds of clients refreshing ~once per hour) that's
on the order of 0.5 qps cluster-wide. Negligible.

## Operator prerequisites

Run [`docs/sql/oauth-state.sql`](sql/oauth-state.sql) against your
ClickHouse cluster as an admin user **before** flipping the flag in helm
values. The SQL file contains both the clustered (ReplicatedMergeTree) and
single-node (MergeTree) flavors — uncomment the one you need.

Pick clustered when:
- Your CH is replicated (operator-managed CHI, multiple replicas).
- You want the state to survive any single replica being down.

Pick single-node when:
- You're running a single CH server (e.g., a dev sandbox).
- You only have one MCP pod.

The Go code is engine-agnostic: SELECT and INSERT work the same on both.

### Cluster name: `all-replicated` and why

The DDL uses `ON CLUSTER 'all-replicated'` rather than the operator-default
`{cluster}` macro. Reason: the primary cluster may be sharded across
multiple physical clusters. OAuth state must live in a single logical shard
so every MCP pod sees a consistent view of consumed jtis. By convention,
`all-replicated` names a single shard spanning all replicas — operators
configure this in the CHI's `<remote_servers>` block.

If your CHI uses a different name for the all-replicas-single-shard
cluster, edit `docs/sql/oauth-state.sql` to match. The Go code does not
care about the cluster name; it only ever issues SELECT and INSERT.

### `mcp_service` user and the `read_only` constraint

The pool user (typically `mcp_service`) needs `INSERT, SELECT ON
altinity.*`. The DDL adds the grant.

**Important**: when `oauth.refresh_revokes_tracking: true`, the pool user
**cannot** be read-only. Two checkpoints:

1. **MCP-side**: `cfg.ClickHouse.read_only` must be `false`. Startup
   validation refuses to boot if it's `true` while the flag is on.
2. **CH-side**: the user's settings profile cannot include `readonly = 1`
   (or `2`). The operator is responsible for this — there is no way for
   MCP to inspect a profile from the client side without trying a write.
   Verify:

   ```sql
   SELECT name, profile FROM system.users WHERE name = 'mcp_service';
   SELECT name, value FROM system.settings_profiles
   WHERE name IN (SELECT profile FROM system.users WHERE name = 'mcp_service');
   ```

   No row should set `readonly` to a non-zero value.

If the pool user *is* read-only, the first refresh after enabling the flag
will hard-fail with `server_error` and an ERR-level zerolog line. Roll
back by flipping the flag to `false`; the refresh path returns to its
stateless behavior.

## Failure modes — hard fail with ERR

Every CH-state failure path returns HTTP 500 `server_error` and emits an
ERR-level zerolog line. We never silently fall through to "mint a new
pair anyway" — that would defeat the security control.

| Failure                                        | Response                  | Log                              |
| ---------------------------------------------- | ------------------------- | -------------------------------- |
| `mode: forward` + flag on                      | startup refuses to boot   | fatal startup error              |
| `clickhouse.read_only: true` + flag on         | startup refuses to boot   | fatal startup error              |
| Refresh JWE missing `jti` or `family_id` (legacy or malformed) | 400 `invalid_grant` "refresh token format unsupported, please re-authenticate" | ERR `OAuth refresh token rejected: missing jti or family_id` |
| jti in `consumed_jtis` OR family in `revoked_families` (reuse) | 400 `invalid_grant` "refresh token reuse detected, please re-authenticate" | ERR `OAuth refresh token reuse detected — family revoked` |
| CH unreachable / RBAC denied / timeout         | 500 `server_error` "refresh state unavailable" | ERR `OAuth refresh state lookup failed — hard fail` |

## Legacy-token policy

Refresh tokens issued before the flag flips lack the `jti` and `family_id`
claims. They are rejected with `invalid_grant` on first redemption after
deploy. Clients re-authenticate once.

The alternative — auto-promote legacy tokens on first use — would let a
captured pre-deploy token be replayed exactly once before the server
starts tracking the family. We rejected that approach: a brief re-login
is cheaper than a silent bypass window.

## Rollback

Set `oauth.refresh_revokes_tracking: false` in helm values, helm-upgrade.
The refresh path returns to its current stateless behavior — no DB hit, no
family-id propagation. In-flight refresh tokens that already carry the
`jti`/`family_id` claims continue to work; the JWE whitelist accepts them
even when the flag is off.

The state tables can stay populated; TTL drops them in 35 days. There's
no harm in leaving them — re-enabling the flag later picks up a clean
table state plus whatever consumed jtis from the last 35 days are still
relevant (most aren't, since each token's lifetime is 30 days).

## Where the code lives

| File                                                      | Role                                                     |
| --------------------------------------------------------- | -------------------------------------------------------- |
| `pkg/config/config.go`                                    | `OAuthConfig.RefreshRevokesTracking` field               |
| `pkg/jwe_auth/jwe_auth.go`                                | `family_id` added to claims whitelist                    |
| `pkg/oauth_state/store.go`                                | `Store` interface + ClickHouse implementation            |
| `pkg/server/server_client.go`                             | `GetClickHouseSystemClient` (no oauth impersonation)     |
| `pkg/server/server.go`                                    | Store wired onto `ClickHouseJWEServer` at construction   |
| `cmd/altinity-mcp/main.go`                                | Startup validation + warnings                            |
| `cmd/altinity-mcp/oauth_server.go`                        | Mint embeds `jti`/`family_id`; refresh handler enforces  |
| `cmd/altinity-mcp/oauth_server_test.go`                   | Reuse-detection unit/integration tests                   |
| `docs/sql/oauth-state.sql`                                | DDL + grant for operators                                |
| `docs/oauth-refresh-reuse-detection.md`                   | This page                                                |

## See also

- `/Users/Workspaces/acm/mcp/.wiki/mcp-oauth-debugging.md` — operator wiki:
  rollout checklist for each demo deployment + the original H-1/H-2
  context.
- [RFC 6749 §10.4 — Refresh Tokens](https://datatracker.ietf.org/doc/html/rfc6749#section-10.4)
- [OAuth 2.1 (draft) §4.13.2 — Refresh Token Protection](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1)
- [MCP authorization spec 2025-11-25](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization)
