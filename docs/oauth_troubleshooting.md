# OAuth Troubleshooting Guide

This document covers common issues encountered when deploying OAuth forward mode with ClickHouse `token_processors`, based on real-world debugging experience.

> **claude.ai JSX artifact users:** if your connector works in the main chat
> but not from a JSX artifact (`✗ No tools attached — proxy didn't expose this
> connector`), see [`artifact-mcp-known-issues.md`](./artifact-mcp-known-issues.md).
> That failure mode tracks to known unfixed Anthropic-side proxy bugs
> ([claude-code#16848](https://github.com/anthropics/claude-code/issues/16848),
> [claude-ai-mcp#123](https://github.com/anthropics/claude-ai-mcp/issues/123))
> and is not something the MCP server can fix.

## ClickHouse returns "Authentication failed" but token_processors are configured

**Symptom:** ClickHouse extracts the username from the token (e.g., `btyshkevich@altinity.com: Authentication failed`) but rejects the request with `AUTHENTICATION_FAILED` (Code 516).

**Root cause:** A user with the same name as the token's `username_claim` value exists in `local_directory` or `users.xml`. ClickHouse evaluates `user_directories` in order:

1. `users_xml` (position 1)
2. `local_directory` (position 2)
3. `token` (position 3)

If a matching user is found in an earlier directory, ClickHouse attempts password authentication instead of token authentication — even when a valid bearer token is present.

**Diagnosis:**

```sql
SELECT name, storage FROM system.users WHERE name LIKE '%example%';
```

```sql
SELECT * FROM system.user_directories;
```

**Fix:** Drop or rename the conflicting user:

```sql
DROP USER `user@example.com`;
```

## ClickHouse returns "SSL certificate authentication requires nonempty certificate's Common Name"

**Symptom:** The error `Invalid authentication: SSL certificate authentication requires nonempty certificate's Common Name or Subject Alternative Name` appears in the MCP server logs.

**Root cause:** ClickHouse received **no bearer token** in the request. The empty authentication falls through to SSL certificate-based authentication, which fails because the MCP server's TLS connection has no client certificate.

**Checklist:**

- The server is running in `mode: forward` (token forwarding to ClickHouse is automatic in this mode)
- The MCP client completed the OAuth flow — check MCP server logs for register, authorize, callback, and token exchange activity
- The MCP client is not reusing a stale token from a previous session

## Forward mode does not require static ClickHouse credentials

In forward mode, each request forwards the OAuth bearer token to ClickHouse instead of using static credentials. The MCP server health check skips the ClickHouse ping in this mode (it reports `"auth": "per_request_credentials"` in the health response).

Any `username`/`password` in the ClickHouse config section is ignored for query execution in forward mode. If you see startup authentication errors, verify that the MCP server is not attempting a ClickHouse connection with empty or default credentials.

## `username_claim` in token_processors defaults to `sub`

**Symptom:** ClickHouse shows numeric user IDs (e.g., `104832759283...`) in `system.query_log`, `currentUser()`, and process lists instead of readable names.

**Root cause:** The default `username_claim` for ClickHouse `token_processors` is `sub`. For Google tokens, the `sub` claim is a numeric Google account ID.

**Fix:** Set `<username_claim>email</username_claim>` in the ClickHouse `token_processors` configuration:

```xml
<token_processors>
    <google>
        <type>openid</type>
        <configuration_endpoint>https://accounts.google.com/.well-known/openid-configuration</configuration_endpoint>
        <token_cache_lifetime>60</token_cache_lifetime>
        <username_claim>email</username_claim>
    </google>
</token_processors>
```

## Sporadic "invalid token supplied" errors in MCP server logs

**Symptom:** The MCP server logs show occasional `ClickHouse ping failed during connection` errors with `invalid token supplied` from ClickHouse, even though queries succeed for authenticated users.

**Root cause:** An MCP client (e.g., Claude Desktop, Claude.ai) is retrying with a cached or stale token from a previous session. In forward mode, the MCP server does not validate tokens locally — it passes them through to ClickHouse, which rejects invalid tokens.

**Resolution:** These errors are transient and resolve once the client re-authenticates through the OAuth flow. They do not indicate a server-side configuration issue. If errors persist, ask the client to clear cached credentials for the MCP server and re-authenticate.

## ClickHouse returns HTTP 403 with "Bearer HTTP Authorization scheme is not supported"

The ClickHouse build does not support `token_processors`. Forward mode requires the Altinity Antalya build 25.8+ or a compatible ClickHouse version that supports `token_processors` and `user_directories` token authentication.

## Useful diagnostic queries

Check configured user directories and their priority:

```sql
SELECT * FROM system.user_directories;
```

Check if a specific user exists and where it's stored:

```sql
SELECT name, storage FROM system.users WHERE name LIKE '%pattern%';
```

Check recent authentication failures:

```sql
SELECT event_time, user, type, exception
FROM system.query_log
WHERE type = 'ExceptionBeforeStart'
  AND event_time > now() - INTERVAL 10 MINUTE
ORDER BY event_time DESC
LIMIT 20;
```

Check grants for the OAuth role:

```sql
SHOW GRANTS FOR oauth_google_demo_role;
```
