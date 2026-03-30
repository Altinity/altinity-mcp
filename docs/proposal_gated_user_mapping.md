# Gating Mode with Real ClickHouse Authentication

## Motivation

Current gating mode validates OAuth tokens at the MCP proxy layer but connects
to ClickHouse with a single static set of credentials. This means:

- No per-user audit trail in `system.query_log` — every query shows the same
  ClickHouse user.
- No per-group access control — the MCP server decides what's allowed, not
  ClickHouse grants.

Using ClickHouse's [HTTP external authenticator](https://clickhouse.com/docs/operations/external-authenticators/http)
we can get real ClickHouse authentication in gating mode, with standard
(non-Antalya) ClickHouse builds.

## Design

### IdP group → ClickHouse user mapping

Pre-create a ClickHouse user per IdP group. No ClickHouse roles are needed —
each user already has the appropriate grants. MCP maps the first matching IdP
group from the OAuth token to a ClickHouse user.

Groups in the mapping are domain-qualified (`group.domain`) to support a
single IdP serving multiple organisations. MCP constructs the FQDN at runtime
by combining the group name from the token with a domain resolved from the
user's identity.

```yaml
oauth:
  group_claim: "groups"              # JWT claim containing group list
  group_domain_claim: "hd"           # claim to use as domain (e.g. Google hd)
  group_user_mapping:
    engineering.altinity.com: "ch_engineering"
    analytics.partner.com:   "ch_analytics"
    admin.altinity.com:      "ch_admin"
  default_user: ""                   # empty = reject if no group matches
```

**Domain resolution order:**
1. `group_domain_claim` — value of the configured claim (e.g. `hd: "altinity.com"`)
2. Email domain — extracted from `email` claim (`alice@altinity.com` → `altinity.com`)
3. If neither available — reject (cannot construct qualified group name)

**Example:** Token contains `groups: ["engineering", "admin"]` and
`hd: "altinity.com"`. MCP constructs `["engineering.altinity.com",
"admin.altinity.com"]` and matches against `group_user_mapping` keys.

A user from `partner.com` with `groups: ["analytics"]` and
`hd: "partner.com"` constructs `analytics.partner.com` → maps to
`ch_analytics`. Same IdP, different domain, different ClickHouse user.

**Multi-group priority**: first match in config order wins.

**No matching group**: returns 403 to the MCP client unless `default_user` is
set.

### ClickHouse configuration

Define the HTTP auth server and the users that delegate to it:

```xml
<clickhouse>
    <http_authentication_servers>
        <mcp_auth>
            <uri>http://altinity-mcp:8080/auth/callback</uri>
            <connection_timeout_ms>1000</connection_timeout_ms>
            <receive_timeout_ms>1000</receive_timeout_ms>
            <send_timeout_ms>1000</send_timeout_ms>
            <max_tries>1</max_tries>
        </mcp_auth>
    </http_authentication_servers>

    <users>
        <ch_engineering>
            <http_authentication>
                <server>mcp_auth</server>
                <scheme>basic</scheme>
            </http_authentication>
            <!-- grants configured separately via GRANT statements -->
        </ch_engineering>

        <ch_analytics>
            <http_authentication>
                <server>mcp_auth</server>
                <scheme>basic</scheme>
            </http_authentication>
        </ch_analytics>

        <ch_admin>
            <http_authentication>
                <server>mcp_auth</server>
                <scheme>basic</scheme>
            </http_authentication>
        </ch_admin>
    </users>
</clickhouse>
```

`max_tries` is set to 1 — see [Replay and retries](#replay-and-retries) below.

### Request flow

```
  MCP Client                MCP Server                  ClickHouse
  ==========                ==========                  ==========
      │                          │                           │
      │  (1) MCP request         │                           │
      │      + OAuth token       │                           │
      │─────────────────────────▶│                           │
      │                          │                           │
      │                    ┌─────┴─────┐                     │
      │                    │ (2) Verify │                     │
      │                    │   token    │                     │
      │                    │ (3) Check  │                     │
      │                    │   policy   │                     │
      │                    │ (4) Extract│                     │
      │                    │   groups   │                     │
      │                    │ (5) Map to │                     │
      │                    │   CH user  │                     │
      │                    │ (6) Gen    │                     │
      │                    │   nonce    │                     │
      │                    └─────┬─────┘                     │
      │                          │                           │
      │                          │  (7) SQL query            │
      │                          │      Authorization: Basic │
      │                          │        user=ch_engineering │
      │                          │        pass=<nonce>       │
      │                          │      + log_comment header │
      │                          │──────────────────────────▶│
      │                          │                           │
      │                          │   (8) HTTP callback       │
      │                          │       POST /auth/callback │
      │                          │       Authorization: Basic│
      │                          │         (same creds)      │
      │                          │◀──────────────────────────│
      │                          │                           │
      │                    ┌─────┴─────┐                     │
      │                    │ (9) Lookup │                     │
      │                    │   nonce,   │                     │
      │                    │   consume, │                     │
      │                    │   200/401  │                     │
      │                    └─────┬─────┘                     │
      │                          │                           │
      │                          │  200 OK or 401            │
      │                          │──────────────────────────▶│
      │                          │                           │
      │                          │  (10) Query result        │
      │                          │◀──────────────────────────│
      │                          │                           │
      │  (11) Response           │                           │
      │◀─────────────────────────│                           │
      │                          │                           │

  Nonce lifecycle:
  ┌──────────────────────────────────────────────────────┐
  │  Created at step 6    map[nonce] → {user, email, exp}│
  │  Consumed at step 9   deleted on first callback hit  │
  │  TTL safety net       expired nonces swept if unused │
  └──────────────────────────────────────────────────────┘
```

**Step details:**

1. MCP client sends request with OAuth access token.
2. MCP validates token (signature, expiry, issuer, audience).
3. MCP applies identity policy (domain allowlist, email verification).
4. MCP extracts groups from token via configured `group_claim`.
5. MCP resolves domain (`group_domain_claim` → email domain fallback),
   constructs `group.domain` FQDNs, maps first match to a ClickHouse user
   via `group_user_mapping`. If no match and no `default_user`, return 403.
6. MCP generates a single-use nonce, stores `nonce → {ch_user, email, expires_at}`
   in an in-memory map with a short TTL (e.g. 10 seconds).
7. MCP sends the query to ClickHouse as HTTP basic auth:
   `user=ch_engineering`, `password=<nonce>`.
   Also sets `X-ClickHouse-Setting-log_comment` to the real identity — see
   [Audit trail](#audit-trail-in-systemquery_log).
8. ClickHouse calls back to `http://altinity-mcp:8080/auth/callback` with the
   same basic auth credentials.
9. MCP looks up the nonce in the map. If found and not expired, consumes it
   (delete from map) and returns 200. Otherwise returns 401.
10. ClickHouse executes or rejects the query based on the callback response.
11. MCP returns the query result to the client.

### Replay and retries

The nonce is consumed on first callback hit (delete from map). This makes
replay impossible — a second request with the same nonce gets 401.

This conflicts with ClickHouse's `max_tries` retry behaviour: if the first
callback succeeds but the connection drops before ClickHouse reads the
response, CH retries — and the nonce is already consumed.

Setting `max_tries=1` avoids this. The CH→MCP call is in-cluster (same k8s
namespace, no TLS needed), so transient failures are rare. If the callback
does fail, the query fails, and the MCP client retries the whole flow at the
application level.

The nonce TTL (10 seconds) is a safety net for callbacks that never arrive
(ClickHouse crash, network partition). Expired nonces are lazily evicted or
swept periodically.

### Audit trail in `system.query_log`

Since multiple real users share the same ClickHouse user (e.g. all engineers
connect as `ch_engineering`), the `user` column alone doesn't identify who
ran a query. Two approaches to inject real identity:

**Option A: `log_comment` (recommended)**

MCP sets the `X-ClickHouse-Setting-log_comment` HTTP header on every query:

```
X-ClickHouse-Setting-log_comment: alice@corp.com
```

This populates the dedicated `system.query_log.log_comment` column:

```sql
SELECT event_time, user, log_comment AS real_user, query
FROM system.query_log
WHERE type = 'QueryFinish'
ORDER BY event_time DESC
```

**Option B: custom setting**

Use `X-ClickHouse-Setting-custom_oauth_email` instead, which populates
`system.query_log.Settings['custom_oauth_email']`. This keeps `log_comment`
free for other uses but requires querying the `Settings` map column.

Both approaches use the existing ClickHouse HTTP settings header mechanism —
no ClickHouse-side configuration needed.

## MCP server changes

1. **New config fields**: `group_claim`, `group_user_mapping`, `default_user`,
   `auth_callback_path`.
2. **New HTTP endpoint**: `/auth/callback` — accepts basic auth, looks up nonce,
   returns 200 or 401.
3. **Nonce store**: in-memory map with TTL-based expiry. Stateless — if MCP
   restarts, in-flight queries fail (clients retry). Acceptable tradeoff for
   no persistent storage.
4. **Query dispatch**: in gating mode with `group_user_mapping` configured,
   override ClickHouse username/password with the mapped user and nonce. Set
   `log_comment` header with real identity.
5. **Existing gating mode**: unchanged when `group_user_mapping` is not
   configured. This is an opt-in enhancement.

## Comparison with forward mode (Antalya)

| | Gating + HTTP auth callback | Forward mode (Antalya) |
|---|---|---|
| ClickHouse build | Standard | Antalya (token_processors) |
| User creation | Pre-created per group | Automatic via user_directories |
| Role mapping | Via CH grants on pre-created users | roles_filter + roles_transform |
| Identity in query_log | log_comment header | user column (username_claim) |
| Token lifecycle | MCP-controlled (nonce per query) | IdP-controlled (token passthrough) |

## Group claims across Identity Providers

The design above assumes groups are available in the OAuth token. There is
**no standard OIDC claim for groups** — each IdP handles this differently,
and some don't support it at all.

### Summary

| IdP | Claim name | Type | In token by default? | Config required |
|-----|-----------|------|---------------------|-----------------|
| Google Workspace | N/A | N/A | **No — not in tokens** | Groups require Directory API |
| Auth0 | custom namespaced | `[]string` | No | Action required |
| Okta | `groups` | `[]string` (names) | No | Custom claim in auth server |
| Keycloak | `groups` | `[]string` (names/paths) | No | Group Membership mapper |
| Microsoft Entra ID | `groups` | `[]string` (GUIDs) | No | Manifest setting |

### Google Workspace

Google **does not include group membership in OIDC tokens or the userinfo
endpoint**. The ID token provides `sub`, `email`, `name`, `hd` (hosted
domain), `email_verified` — but no groups.

**To get groups** you must call the Google Directory API:
- Endpoint: `admin.googleapis.com/admin/directory/v1/groups`
- Requires a GCP service account with domain-wide delegation
- Requires `https://www.googleapis.com/auth/admin.directory.group.readonly` scope
- Requires an admin email to impersonate in the API call

This is a significant integration: service account JSON key in config, an
extra API call after every authentication, and Google-specific code.

**Workarounds without groups:**
- `AllowedHostedDomains: ["corp.com"]` — restricts to the Google Workspace org
- `AllowedEmailDomains: ["corp.com"]` — same effect via email domain
- These cover "only our org" but not finer-grained access like "only engineering"

**Options for full group support with Google:**

1. **Google Directory API integration** — new config fields for service account
   key and admin email. After token validation, call the Directory API to
   resolve groups, inject into claims. Adds Google-specific dependency.

2. **Generic group resolver webhook** — after auth, POST the user's
   email/claims to a configurable URL, get back a list of groups. The URL
   points to a sidecar/lambda that calls the Google Directory API. More
   flexible, works for any IdP, but adds latency and an external dependency.

3. **Accept the limitation** — for Google deployments, use domain-based
   allowlists. For group-level granularity, use an IdP that puts groups
   in tokens (Okta, Keycloak, Auth0).

### Auth0

Auth0 uses "Roles" (not directory groups). Roles are **not in tokens by
default**.

**To add roles to tokens**, create a post-login Action:

```javascript
exports.onExecutePostLogin = async (event, api) => {
  api.idToken.setCustomClaim(
    'https://myapp.example.com/groups',
    event.authorization.roles
  );
};
```

The claim **must** use a namespaced URI — non-namespaced custom claims are
silently dropped from ID tokens.

**MCP config:**
```yaml
oauth:
  group_claim: "https://myapp.example.com/groups"
```

The namespaced claim lands in the `Extra` map of `OAuthClaims`. The
`group_claim` config tells the policy validator which key to look up.

### Okta

- **Claim**: `groups` — not included by default
- **Config**: Security > API > Authorization Server > Claims > Add Claim.
  Name: `groups`, Value type: `Groups`, Filter: `Matches regex .*`
- **Type**: `[]string` of group names, e.g. `["Everyone", "Engineering"]`
- **Limit**: >100 groups may be omitted from the token. Fallback to
  `/userinfo` or Okta Groups API.

### Keycloak

- **Claim**: `groups` — requires a "Group Membership" protocol mapper
- **Type**: `[]string` — either flat names (`["admin"]`) or full paths
  (`["/org/admin"]`) depending on mapper config
- **Alternative**: `realm_access.roles` — included by default, contains
  realm-level role names

### Microsoft Entra ID (Azure AD)

- **Claim**: `groups` — contains **Object IDs (GUIDs)**, not names
- **Config**: Set `"groupMembershipClaims"` in the app manifest
- **Overage**: Azure AD limits tokens to 200 groups. When exceeded, the
  `groups` claim is omitted and replaced with a Graph API endpoint reference.
  The application must call Microsoft Graph to get the full list.
- **Alternative**: `roles` claim — contains App Role value names (strings,
  not GUIDs), no overage problem. Configure via app registration. For MCP,
  `group_claim: "roles"` may be simpler than directory groups.

### Design implications

1. **`group_claim` must be configurable** — default `"groups"`, but Auth0
   needs a namespaced URI, Azure AD might prefer `"roles"`.

2. **Expect `[]string`** — all IdPs use string arrays. Also handle
   space-separated strings as fallback.

3. **Google requires special handling** — Directory API integration,
   webhook, or accept that group-level control needs a different IdP.

4. **Case sensitivity** — compare group names case-insensitively to avoid
   `"Admin"` vs `"admin"` misconfiguration.

5. **Overage (Azure AD, Okta)** — when the group list is too large, the
   claim may be omitted. A fallback to userinfo could help but adds
   complexity and an extra HTTP call per request.

## Ops notes

- MCP's `/auth/callback` must be reachable from ClickHouse. In k8s, both run
  in the same namespace — use the service DNS name.
- If MCP restarts, all in-flight nonces are lost. Queries in progress fail;
  clients retry normally.
- Monitor the nonce map size. Under normal load it stays small (one entry per
  concurrent query, consumed in milliseconds). A leak would indicate callbacks
  not arriving — check CH→MCP connectivity.
