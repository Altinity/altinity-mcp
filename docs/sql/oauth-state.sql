-- Altinity MCP — OAuth refresh-token reuse-detection state (H-2).
--
-- One database, two append-only tables, one role grant. Run this on the
-- ClickHouse cluster BEFORE flipping `oauth.refresh_revokes_tracking: true`
-- in the MCP helm values. Run as an admin user (the pool user `mcp_service`
-- intentionally lacks CREATE privileges).
--
-- See docs/oauth-refresh-reuse-detection.md for the full design rationale,
-- threat model, and operator-side knobs.
--
-- Two flavors below:
--   1. Clustered (ON CLUSTER 'all-replicated' + ReplicatedMergeTree)
--   2. Single-node (plain MergeTree)
-- Pick exactly one block and run it; the binary doesn't care which engine,
-- only that the schema matches.
--
-- The cluster name `all-replicated` is conventional for a single logical
-- shard spanning all replicas. We deliberately avoid the `{cluster}` macro
-- because the primary cluster may be sharded; OAuth state belongs in a
-- single shard so SELECT count() / INSERT see a consistent view across
-- all MCP pods.

----------------------------------------------------------------------
-- Flavor 1: Clustered (ReplicatedMergeTree, multi-replica)
----------------------------------------------------------------------

CREATE DATABASE IF NOT EXISTS altinity ON CLUSTER 'all-replicated';

CREATE TABLE IF NOT EXISTS altinity.oauth_refresh_consumed_jtis ON CLUSTER 'all-replicated'
(
    jti         String,
    family_id   String,
    consumed_at DateTime DEFAULT now()
)
ENGINE = ReplicatedMergeTree
ORDER BY jti
TTL consumed_at + INTERVAL 35 DAY;

CREATE TABLE IF NOT EXISTS altinity.oauth_refresh_revoked_families ON CLUSTER 'all-replicated'
(
    family_id  String,
    revoked_at DateTime DEFAULT now(),
    reason     LowCardinality(String)
)
ENGINE = ReplicatedMergeTree
ORDER BY family_id
TTL revoked_at + INTERVAL 35 DAY;

GRANT INSERT, SELECT ON altinity.* TO mcp_service ON CLUSTER 'all-replicated';

----------------------------------------------------------------------
-- Flavor 2: Single-node (MergeTree, no replication)
----------------------------------------------------------------------

-- CREATE DATABASE IF NOT EXISTS altinity;
--
-- CREATE TABLE IF NOT EXISTS altinity.oauth_refresh_consumed_jtis
-- (
--     jti         String,
--     family_id   String,
--     consumed_at DateTime DEFAULT now()
-- )
-- ENGINE = MergeTree
-- ORDER BY jti
-- TTL consumed_at + INTERVAL 35 DAY;
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
-- GRANT INSERT, SELECT ON altinity.* TO mcp_service;

----------------------------------------------------------------------
-- Verification (run as the same admin user)
----------------------------------------------------------------------
--
--   SHOW GRANTS FOR mcp_service;
--   -- expect: GRANT INSERT, SELECT ON altinity.* TO mcp_service
--
--   -- Confirm mcp_service is NOT readonly (H-2 requires write access):
--   SELECT name, profile FROM system.users WHERE name = 'mcp_service';
--   SELECT * FROM system.settings_profiles WHERE name IN
--       (SELECT profile FROM system.users WHERE name = 'mcp_service');
--   -- expect: no `readonly` setting >= 1 in any inherited profile.
