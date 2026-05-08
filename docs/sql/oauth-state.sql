-- Altinity MCP — OAuth refresh-token reuse-detection state (H-2).
--
-- Two tables: KeeperMap-backed consumed-jti store (atomic insert-or-error,
-- exactly-one-winner across MCP pods via ClickHouse Keeper Raft consensus)
-- and a ReplicatedMergeTree revoked-families log. Run this on the cluster
-- BEFORE flipping `oauth.refresh_revokes_tracking: true` in helm values.
-- Run as an admin user (the pool user `mcp_service` intentionally lacks
-- CREATE privileges).
--
-- See docs/oauth-refresh-reuse-detection.md for the full design rationale,
-- threat model, and operator-side knobs.
--
-- The cluster name `all-replicated` is conventional for a single logical
-- shard spanning all replicas. OAuth state belongs in a single shard so
-- KeeperMap entries (one per consumed jti) are visible to every MCP pod
-- without cross-shard hops.

----------------------------------------------------------------------
-- Operator prerequisite (BLOCKING):
--
-- KeeperMap requires <keeper_map_path_prefix> in CH server config. Add a
-- config.d drop-in:
--
--     <clickhouse>
--         <keeper_map_path_prefix>/altinity_mcp/keeper_map</keeper_map_path_prefix>
--     </clickhouse>
--
-- (For ACM-managed clusters: setting name `config.d/keeper_map.xml`.)
-- Without this, CREATE TABLE … ENGINE = KeeperMap fails with
-- "KeeperMap is disabled because 'keeper_map_path_prefix' config is not
-- defined" (BAD_ARGUMENTS, code 36).
----------------------------------------------------------------------

----------------------------------------------------------------------
-- Flavor 1: Clustered (KeeperMap + ReplicatedMergeTree)
----------------------------------------------------------------------

CREATE DATABASE IF NOT EXISTS altinity ON CLUSTER 'all-replicated';

-- Atomic claim store. The MCP binary issues every INSERT with
-- `SETTINGS keeper_map_strict_mode = 1`, which makes Keeper reject
-- duplicate primary-key transactions with a KEEPER_EXCEPTION. The
-- table-level SETTINGS clause below is COSMETIC — CH silently ignores
-- `keeper_map_strict_mode` at table-create time; only the per-query
-- setting is honoured. The DDL keeps it for documentation.
CREATE TABLE IF NOT EXISTS altinity.oauth_refresh_consumed_jtis ON CLUSTER 'all-replicated'
(
    jti         String,
    family_id   String,
    consumed_at DateTime DEFAULT now()
)
ENGINE = KeeperMap('/altinity_mcp/oauth_refresh_consumed_jtis')
PRIMARY KEY jti
SETTINGS keeper_map_strict_mode = 1;  -- documentation only; query-level is what enforces

-- Revoked-families audit log. Plain ReplicatedMergeTree — INSERTs are
-- idempotent (multiple parallel revokes of the same family collapse via
-- TTL), and CH-native TTL handles cleanup automatically.
CREATE TABLE IF NOT EXISTS altinity.oauth_refresh_revoked_families ON CLUSTER 'all-replicated'
(
    family_id  String,
    revoked_at DateTime DEFAULT now(),
    reason     LowCardinality(String)
)
ENGINE = ReplicatedMergeTree
ORDER BY family_id
TTL revoked_at + INTERVAL 35 DAY;

-- Grants needed by the MCP pool user.
--   INSERT — both tables (claim a jti, log a revoke).
--   SELECT — revoked_families lookup before claiming.
--   ALTER DELETE — the in-process cleanup loop runs ALTER TABLE … DELETE
--                  WHERE consumed_at < now() - INTERVAL 35 DAY against
--                  the KeeperMap consumed_jtis table (KeeperMap doesn't
--                  support TTL natively).
GRANT INSERT, SELECT, ALTER DELETE ON altinity.* TO mcp_service ON CLUSTER 'all-replicated';

----------------------------------------------------------------------
-- Flavor 2: Single-node (KeeperMap + MergeTree)
----------------------------------------------------------------------
-- KeeperMap requires Keeper. If you have a Keeper service available
-- (even a single-node embedded keeper), this flavor still applies. If
-- you have NO Keeper at all, H-2 cannot run as designed — the security
-- property requires linearizable claim semantics that no single-node
-- engine provides. In that case keep `oauth.refresh_revokes_tracking`
-- disabled and accept the residual risk documented in the H-2 doc.

-- CREATE DATABASE IF NOT EXISTS altinity;
--
-- CREATE TABLE IF NOT EXISTS altinity.oauth_refresh_consumed_jtis
-- (
--     jti         String,
--     family_id   String,
--     consumed_at DateTime DEFAULT now()
-- )
-- ENGINE = KeeperMap('/altinity_mcp/oauth_refresh_consumed_jtis')
-- PRIMARY KEY jti
-- SETTINGS keeper_map_strict_mode = 1;
--
-- CREATE TABLE IF NOT EXISTS altinity.oauth_refresh_revoked_families
-- (
--     family_id  String,
--     revoked_at DateTime DEFAULT now(),
--     reason     LowCardinality(String)
-- )
-- ENGINE = MergeTree
-- ORDER BY family_id
-- TTL revoked_at + INTERVAL 35 DAY;
--
-- GRANT INSERT, SELECT, ALTER DELETE ON altinity.* TO mcp_service;

----------------------------------------------------------------------
-- Verification (run as the same admin user)
----------------------------------------------------------------------
--
--   SHOW GRANTS FOR mcp_service;
--   -- expect: GRANT INSERT, SELECT, ALTER DELETE ON altinity.* TO mcp_service
--
--   -- Confirm KeeperMap is enabled (path_prefix configured):
--   CREATE TABLE default.kmap_smoke (k String) ENGINE = KeeperMap('/altinity_mcp/smoke')
--       PRIMARY KEY k SETTINGS keeper_map_strict_mode=1;
--   DROP TABLE default.kmap_smoke;
--   -- both should succeed; the first throws BAD_ARGUMENTS (code 36)
--   -- "KeeperMap is disabled" if the operator prerequisite is unmet.
--
--   -- Confirm strict-mode rejects duplicate INSERTs (must be set per-query
--   -- — table-level SETTINGS is silently ignored for keeper_map_strict_mode):
--   CREATE TABLE default.kmap_strict_smoke (k String, v String)
--       ENGINE = KeeperMap('/altinity_mcp/strict_smoke') PRIMARY KEY k;
--   INSERT INTO default.kmap_strict_smoke VALUES ('a', '1');  -- ok
--   INSERT INTO default.kmap_strict_smoke
--       SETTINGS keeper_map_strict_mode = 1
--       VALUES ('a', '2');
--   -- expect: Code 999 KEEPER_EXCEPTION "Transaction failed (Node exists)"
--   DROP TABLE default.kmap_strict_smoke;
--
--   -- Confirm mcp_service is NOT readonly (H-2 requires write access):
--   SELECT name, default_roles_list FROM system.users WHERE name = 'mcp_service';
--   -- and check that no inherited settings profile sets readonly >= 1.
