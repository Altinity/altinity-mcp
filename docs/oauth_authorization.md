# OAuth 2.0 Authorization for Altinity MCP Server

> **Updated 2026-05-15 (#115 landing):** Dynamic Client Registration (DCR) has
> been removed. Inbound MCP OAuth clients must use the spec-track replacement,
> OAuth Client ID Metadata Documents ([draft-ietf-oauth-client-id-metadata-document](https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/)).
> claude.ai and ChatGPT both publish CIMD documents today. The
> `/.well-known/oauth-authorization-server` document advertises
> `client_id_metadata_document_supported: true`, drops `registration_endpoint`,
> and lists `token_endpoint_auth_methods_supported: ["none"]` plus
> `grant_types_supported: ["authorization_code"]`. `/oauth/register` returns
> HTTP 410 Gone with an RFC 7591 §3.2.2-shaped JSON error.
>
> v1 issues **no downstream refresh tokens**. CIMD clients re-authorize via
> `/oauth/authorize` when the access token expires. The
> `upstream_offline_access` flag only controls whether `offline_access` is
> appended to the upstream scope (to influence the IdP's consent screen); any
> upstream refresh token returned is discarded.
>
> The HA replay model (#115 § HA replay) defers upstream authorization-code
> redemption from `/oauth/callback` to `/oauth/token` so the upstream IdP
> becomes the cross-replica replay oracle via `invalid_grant`.
>
> The rest of this document still describes the gating / forward / broker
> dichotomy and the trust model. Mentions of DCR below predate #115 and
> apply only to the upstream IdP side (Auth0 / Hydra / Keycloak), never to
> altinity-mcp itself.

This document explains how to configure OAuth 2.0 / OpenID Connect (OIDC) authentication with the Altinity MCP Server.

## Overview

OAuth 2.0 authorization supports two modes:

- **`mode: gating`** *(default for v1+, redefined in #109)* — MCP is a pure OAuth resource server. The upstream IdP (Auth0 Enterprise, Authentik, Keycloak, Okta) handles DCR, `/authorize`, `/token`, and refresh-token rotation natively. MCP validates AS-issued JWTs and authorizes per-tool scopes. Use when the IdP supports DCR + RFC 8707 resource indicators.
- **`mode: forward`** *(unchanged)* — MCP proxies DCR + `/authorize` + `/token` to upstream and relays upstream tokens to clients. Use when the IdP does NOT support DCR (Google direct, basic-tier Auth0).

Detailed flows are in [Forward mode](#forward-mode) and [Gating mode](#gating-mode). The decision-rationale and trust-model differences are in [Choosing a mode](#choosing-a-mode) below.

## Mode taxonomy

| Mode | What MCP does | When to use |
|---|---|---|
| **`gating`** *(redefined in #109)* | Validates AS-issued JWTs via JWKS (RS256/ES256/EdDSA); enforces `aud` byte-equality (RFC 8707); enforces per-tool scopes (`mcp:read` / `mcp:write`); impersonates the user to ClickHouse via `cluster_secret` + `Auth.Username`. Does **not** run `/register`, `/authorize`, `/token`, `/callback`, `/consent`. | Default for v1+. Use when the upstream IdP supports DCR (Auth0 Enterprise, Authentik, Keycloak ≥ 18, Okta). |
| **`forward`** *(unchanged)* | Proxies DCR + `/authorize` + `/token` to upstream; relays upstream tokens to clients. MCP appears to be the AS to clients but isn't really. JWE-wraps the upstream refresh token for stateless rotation. | Use when the upstream IdP does NOT support DCR (Google direct, basic-tier Auth0). IdP-agnostic. |

### Required helm values per mode

**Gating mode** (live example: `$MCP_DEPLOY_DIR/otel/mcp-values.yaml`):

```yaml
config:
  server:
    oauth:
      enabled: true
      mode: gating
      issuer: "https://altinity.auth0.com/"
      jwks_url: "https://altinity.auth0.com/.well-known/jwks.json"
      audience: "https://otel-mcp.demo.altinity.cloud"   # RFC 8707 byte-equal with Auth0 API identifier
      required_scopes:
        - mcp:read
        - mcp:write
      public_urls:
        - "https://otel-mcp.demo.altinity.cloud"
      # signing_secret injected via MCP_OAUTH_SIGNING_SECRET env var
```

Fields that **must not be present** under gating (startup refuses with a clear error naming the field): `client_id`, `client_secret` / `MCP_OAUTH_CLIENT_SECRET`, `token_url`, `auth_url`, `userinfo_url`, `public_auth_server_url`, `callback_path`.

**Forward mode** (live example: `$MCP_DEPLOY_DIR/antalya/mcp-values.yaml`):

```yaml
config:
  server:
    oauth:
      enabled: true
      mode: forward
      issuer: "https://altinity.auth0.com/"
      auth_url: "https://altinity.auth0.com/authorize"
      token_url: "https://altinity.auth0.com/oauth/token"
      callback_path: "/callback"
      client_id: "<per-cluster-client-id>"
      # client_secret injected via MCP_OAUTH_CLIENT_SECRET env var
      public_auth_server_url: "https://antalya-mcp.demo.altinity.cloud"
      public_resource_url: "https://antalya-mcp.demo.altinity.cloud"
      scopes: [openid, email, profile, offline_access]
      upstream_offline_access: true
```

### Auth0 setup checklist for gating mode

1. **Tenant-level DCR enabled** — already done at `altinity.auth0.com`.
2. **RFC 8707 resource indicators configured** — already done at tenant level.
3. **Per-cluster Auth0 API resource** (create one per cluster, otel example already exists):
   - Identifier (audience) = MCP public URL byte-equal (e.g. `https://otel-mcp.demo.altinity.cloud`)
   - Signing algorithm: `RS256`
   - RBAC enabled; "Add Permissions in the Access Token" enabled; token dialect: `access_token_authz`
   - Scopes: `mcp:read`, `mcp:write`
   - Token Expiration: 600 s (10 min — revocation-latency mitigation)
   - Allow Offline Access: on
   - Refresh Token Rotation: Rotating; Reuse Interval: 0 s; Absolute expiry: 30 d; Inactivity: 7 d
4. **`otel` cluster** — API resource already created (W2): resource-server id `69ff99639b974225b2bab5cd`, identifier `https://otel-mcp.demo.altinity.cloud`.

> **Known security gap (action required before relying on gating-mode security posture):** Refresh-token rotation policy is set per-Application in Auth0. The existing per-cluster Application (`altinity-mcp-otel`, client_id `fAkf9qpOo0HBI2lA8Nc2R1fOqXdJEshx`) is currently non-rotating and non-expiring. DCR-registered clients (claude.ai, ChatGPT) inherit tenant-level DCR-template defaults at registration time, not the per-cluster Application's settings. Tenant-level DCR-template defaults must be set to enable rotation before OAuth 2.1 §4.13.2 reuse detection will actually take effect for dynamically registered clients.

### Migration from old gating (pre-#109)

An operator moving from the old gating (MCP-as-AS) to new gating (pure resource server) must **remove** the following helm values fields; if any are present at startup the server exits with an error naming the offending field:

- `client_id`
- `client_secret` env injection (`MCP_OAUTH_CLIENT_SECRET`)
- `token_url`
- `auth_url`
- `userinfo_url`
- `public_auth_server_url`
- `callback_path`

The canonical diff pattern is the `otel` values change committed on `feature/dcr-via-auth0` (`$MCP_DEPLOY_DIR/otel/mcp-values.yaml`).

Fields that must be **added**:
- `audience` (RFC 8707 byte-equal with the Auth0 API identifier)
- `jwks_url` (or rely on OIDC discovery from `issuer`)
- `required_scopes: [mcp:read, mcp:write]`

## Choosing a mode

Use **gating** when the IdP supports DCR + RFC 8707 (Auth0 Enterprise, Authentik, Keycloak ≥ 18, Okta) and you don't need ClickHouse to independently validate the JWT. Use **forward** when the IdP lacks DCR support (Google direct, basic-tier Auth0) or when you specifically need ClickHouse to do per-request identity validation for stronger trust isolation.

### What's actually different

| | Gating (#109+) | Forward |
|---|---|---|
| Who runs DCR / authorize / token | Upstream IdP | MCP (proxied to upstream) |
| Bearer the MCP client receives | AS-issued JWT (RS256, 10-min TTL) | Upstream IdP id_token (raw passthrough) |
| MCP→ClickHouse credential | `cluster_secret` + `Auth.Username` = email | `Authorization: Bearer <id_token>` over HTTP |
| Who validates the bearer on every query | MCP (JWKS + RFC 8707 aud + scopes) | **ClickHouse** via `token_processors` (MCP also validates locally — see [C-1](#c-1-defense-in-depth-validation-in-forward-mode)) |
| User provisioning in ClickHouse | Pre-create users (`CREATE USER alice@example.com …`) | Dynamic — `token_processors` materialises ephemeral users from JWT claims |
| ClickHouse build requirement | Any | Altinity Antalya 25.8+ (or any CH with native JWT auth) |
| ClickHouse protocol | TCP (cluster_secret) or HTTP (static creds) | HTTP only |
| Identity in `system.query_log` | The cluster-secret-impersonated user | The JWT subject directly |
| Refresh-token rotation + reuse detection | Auth0 native (when DCR-template defaults are set — see security gap above) | Upstream IdP (when `upstream_offline_access: true`) |

### The trust-boundary argument for forward mode

In **gating + cluster_secret**, the MCP pod holds the cluster-shared secret and tells ClickHouse "this query is by user `alice@example.com`". ClickHouse trusts that claim because MCP knows the secret. Compromise the MCP pod, impersonate any provisioned user.

In **forward mode**, ClickHouse re-validates the upstream JWT signature on every query. A compromised MCP server cannot forge identity to ClickHouse — it can only forward whatever bearer it received from the user. The MCP-side bearer validation (per [C-1 below](#c-1-defense-in-depth-validation-in-forward-mode)) is defense-in-depth on top of CH's authoritative check.

The honest summary: **forward mode is a stronger trust-isolation story when ClickHouse can independently validate the JWT.** Without that capability on the CH side, forward mode's bearer is just an opaque blob to CH (it 403s), and you fall back to gating.

### Dynamic user provisioning

Antalya's `token_processors` reads JWT claims (`email`, `roles`, custom claims) and materialises an ephemeral CH user with the right grants on the fly. This is forward-mode-exclusive — gating mode never hands the JWT to ClickHouse, so ClickHouse can't react to its claims.

For a multi-tenant or per-customer deployment where you don't want to manually `CREATE USER` for every new identity, this is a real operational gain. For a fixed roster of internal users, it doesn't matter.

### Token lifecycle

In gating mode the AS-issued access token has a 10-minute TTL (operator-controlled via `access_token_ttl_seconds`). The IdP revokes a session → tokens expire within 10 min. Refresh-token rotation and reuse detection are handled by Auth0, not MCP.

In forward mode every query carries the upstream id_token, so revocation lands at the next query (subject to JWKS cache TTL and ClickHouse's own caching). This is a stronger "log the user out and they're out" guarantee.

### When forward mode is the wrong choice

- ClickHouse build is anything other than Altinity Antalya 25.8+ or another build with native JWT auth. Forward sends the bearer; CH 403s every query.
- You need TCP protocol to ClickHouse (forward only supports HTTP).
- The IdP supports DCR and RFC 8707 — gating is simpler in that case.
- You don't want CH fetching the upstream JWKS on every cold cache.

### When gating mode is the wrong choice

- You specifically want CH to do per-request identity validation (the trust-isolation argument above).
- You want ephemeral user provisioning from JWT claims.
- You want CH `system.query_log` to show the JWT subject without a `cluster_secret` setup.
- You want IdP-immediate revocation semantics on every query.

### C-1: defense-in-depth validation in forward mode

The MCP server validates JWT bearers locally before forwarding to CH (signature + iss + aud + exp) when `issuer` or `jwks_url` is configured — full defense-in-depth. With neither configured, it soft-passes with a startup warning, preserving "trust ClickHouse entirely" semantics for deployments that explicitly want that.

So in current code:

- **Forward + `issuer` set** → defense-in-depth: MCP validates, CH validates again.
- **Forward + nothing set** → pure passthrough: only CH validates. Startup logs a warning.
- **Forward + opaque (non-JWT) bearer** → soft-pass to CH. RFC 7662 introspection isn't implemented.

For new deployments, set `issuer` to the upstream IdP. The cost is one local JWKS fetch (cached) per token; the benefit is malformed/expired/wrong-aud tokens get rejected at the MCP edge instead of consuming a CH connection.

## Forward mode

Use this when ClickHouse has native OAuth support (Altinity Antalya 25.8+). The MCP server validates the bearer locally (when `issuer` is configured) and forwards it to ClickHouse, which re-validates via `token_processors`.

1. An MCP client authenticates with an Identity Provider (IdP) and obtains a token (via the MCP server brokering DCR + auth-code).
2. The MCP client sends the token to the MCP server in the `Authorization: Bearer {token}` header.
3. The MCP server validates the JWT locally (signature + iss + aud + exp) when `issuer`/`jwks_url` is configured; rejects bad tokens at 401. With neither configured, soft-passes the bearer to CH.
4. The MCP server forwards the token to ClickHouse via HTTP headers.
5. ClickHouse re-validates the token using `token_processors` and authenticates the user.

> **Spec deviation (deliberate).** MCP authorization spec 2025-11-25 §Access
> Token Privilege Restriction says *"the MCP server **MUST NOT** pass through
> the token it received from the MCP client"*. Forward mode does pass it
> through — by design. The architectural justification: ClickHouse re-validates
> the same JWT against the upstream JWKS, extracts the same identity, and runs
> its own RBAC. The MCP server is a transparent gateway, not a trust anchor.
> Defense-in-depth is provided by C-1's local validation, but the *forwarded*
> bearer is still the upstream token. Gating mode is the spec-clean
> alternative when you don't have ClickHouse-side token validation set up.

```
┌────────┐      ┌──────────┐      ┌──────────┐      ┌────────────┐
│  MCP   │─────>│   IdP    │      │   MCP    │      │ ClickHouse │
│ Client │<─────│(Keycloak,│      │  Server  │      │  (Antalya) │
│        │      │ Azure AD,│      │          │      │            │
│        │      │ Google)  │      │          │      │            │
│        │      └──────────┘      │          │      │            │
│        │                        │          │      │            │
│        │──Bearer token─────────>│          │      │            │
│        │                        │─Bearer──>│      │            │
│        │                        │  token   │─────>│ Validates  │
│        │                        │          │      │ via OIDC/  │
│        │<───────────────────────│<─────────│<─────│ JWKS       │
│        │      query results     │          │      │            │
└────────┘                        └──────────┘      └────────────┘
```

```yaml
clickhouse:
  host: "clickhouse.example.com"
  port: 8123
  protocol: http
server:
  oauth:
    enabled: true
    mode: "forward"
    signing_secret: "CHANGE_ME_TO_A_RANDOM_SECRET"
    issuer: "https://accounts.google.com"
    client_id: "<YOUR_CLIENT_ID>"
    client_secret: "<YOUR_CLIENT_SECRET>"
    scopes: ["openid", "email"]
```

In forward mode, the bearer token is automatically forwarded to ClickHouse and static credentials are cleared. No additional flags needed.


## Gating mode

Use this when ClickHouse has no native OAuth support and the upstream IdP supports DCR + RFC 8707 resource indicators (Auth0 Enterprise, Authentik, Keycloak ≥ 18, Okta).

Under #109, MCP is a **pure OAuth resource server** in gating mode. The upstream IdP owns the entire OAuth AS surface (DCR, `/authorize`, `/token`, refresh-token rotation, reuse detection). MCP only validates and authorizes:

1. An MCP client (claude.ai, ChatGPT, Codex) discovers the IdP via `/.well-known/oauth-protected-resource` and completes the auth-code-with-PKCE flow directly against the IdP. MCP plays no role in that dance.
2. The client presents the AS-issued access token (RS256 JWT) on every MCP request.
3. MCP validates: JWKS signature, `iss` match, `aud` byte-equality (RFC 8707), `exp`, and per-tool required scopes (`mcp:read` / `mcp:write`). Rejects invalid tokens at 401.
4. MCP connects to ClickHouse via `cluster_secret` + `Auth.Username = email` (per-user attribution) or static credentials. ClickHouse never sees the JWT.

```
┌────────┐      ┌────────────┐      ┌──────────┐      ┌────────────┐
│  MCP   │─────>│  Auth0 /   │      │   MCP    │      │ ClickHouse │
│ Client │<─────│  Keycloak  │      │  Server  │      │            │
│        │      │  (IdP/AS)  │      │          │      │            │
│        │      └────────────┘      │          │      │            │
│        │                          │          │      │            │
│        │──AS-issued JWT──────────>│          │      │            │
│        │                          │ validate │      │            │
│        │                          │ JWKS+aud │      │            │
│        │                          │ +scopes  │      │            │
│        │                          │─cluster─>│      │  verifies  │
│        │                          │ secret + │─────>│  HMAC, runs│
│        │                          │ initial  │      │  as email  │
│        │                          │ _user    │      │            │
│        │<─────────────────────────│<─────────│<─────│            │
│        │         query results    │          │      │            │
└────────┘                          └──────────┘      └────────────┘
```

```yaml
config:
  clickhouse:
    host: "clickhouse.example.com"
    port: 9000
    protocol: tcp
    cluster_name: "mcp_cluster"
    cluster_secret: "CHANGE_ME_SHARED_SECRET"
    username: default   # fallback; real queries run as OAuth email
  server:
    oauth:
      enabled: true
      mode: gating
      issuer: "https://altinity.auth0.com/"
      jwks_url: "https://altinity.auth0.com/.well-known/jwks.json"
      audience: "https://mcp.example.com"   # RFC 8707 byte-equal with Auth0 API identifier
      required_scopes: [mcp:read, mcp:write]
      public_urls:
        - "https://mcp.example.com"
      # signing_secret via MCP_OAUTH_SIGNING_SECRET env var
      # DO NOT set: client_id, client_secret, token_url, auth_url,
      #             userinfo_url, public_auth_server_url
```

### Cluster-secret authentication (optional)

Gating mode's default connects to ClickHouse with a **single static username/password** shared across all MCP users. Queries land in `system.query_log` under that service account, so you lose per-user attribution.

The **cluster-secret path** removes both limitations. altinity-mcp handshakes with ClickHouse as a trusted cluster peer using a shared `<secret>` instead of a password, and executes each query as the OAuth-authenticated user. ClickHouse records the real identity in `system.query_log`, applies that user's grants, and the MCP process never touches a shared password.

```
┌────────┐      ┌──────────┐      ┌──────────┐      ┌────────────┐
│  MCP   │      │  IdP/AS  │      │   MCP    │      │ ClickHouse │
│ Client │      │  (Auth0) │      │  Server  │      │            │
│        │──DCR+login──────>│      │          │      │            │
│        │<─AS JWT──────────│      │          │      │            │
│        │                        │          │      │            │
│        │──query + AS JWT────────>│          │      │            │
│        │                        │─cluster─>│      │  verifies  │
│        │                        │ secret + │      │  HMAC, runs│
│        │                        │ initial  │─────>│  as email  │
│        │                        │ _user =  │      │  claim     │
│        │                        │ email    │      │            │
│        │<───────────────────────│<─────────│<─────│            │
└────────┘                        └──────────┘      └────────────┘
```

**altinity-mcp config** (abbreviated — see [Required helm values per mode](#required-helm-values-per-mode) for the full gating snippet):

```yaml
clickhouse:
  host: "clickhouse.example.com"
  port: 9000               # TCP only — interserver auth has no HTTP equivalent
  protocol: tcp
  database: default
  cluster_name: mcp_cluster        # must match <remote_servers> on ClickHouse
  cluster_secret: "CHANGE_ME_SHARED_SECRET"
  username: default                # fallback when no OAuth identity is present
  # password: intentionally omitted — the shared secret is the only credential

server:
  oauth:
    enabled: true
    mode: gating
    issuer: "https://altinity.auth0.com/"
    jwks_url: "https://altinity.auth0.com/.well-known/jwks.json"
    audience: "https://mcp.example.com"
    required_scopes: [mcp:read, mcp:write]
    # signing_secret via MCP_OAUTH_SIGNING_SECRET env var
```

Or via env: `CLICKHOUSE_CLUSTER_NAME`, `CLICKHOUSE_CLUSTER_SECRET`, `CLICKHOUSE_PROTOCOL=tcp`.

**ClickHouse config** (`/etc/clickhouse-server/config.d/mcp_cluster.xml`):

```xml
<clickhouse>
  <remote_servers>
    <mcp_cluster>
      <secret>CHANGE_ME_SHARED_SECRET</secret>
      <shard>
        <replica>
          <host>clickhouse.example.com</host>
          <port>9000</port>
        </replica>
      </shard>
    </mcp_cluster>
  </remote_servers>
</clickhouse>
```

**User and role provisioning (required).** The impersonated user must already exist on ClickHouse. ClickHouse skips the password check for cluster peers, but **not** the user lookup or grant resolution — an unknown `initial_user` fails with `Unknown user`. altinity-mcp does **not** auto-provision users; you precreate them with the grants they need.

Map OAuth claims to ClickHouse users however suits your IdP. Typical setup using the user's email as the ClickHouse username:

```sql
-- One role per entitlement level
CREATE ROLE IF NOT EXISTS mcp_reader;
GRANT SELECT ON analytics.* TO mcp_reader;

CREATE ROLE IF NOT EXISTS mcp_admin;
GRANT ALL ON analytics.* TO mcp_admin;

-- One user per identity; password-less because the cluster secret is the credential
CREATE USER IF NOT EXISTS "alice@example.com" IDENTIFIED WITH no_password;
GRANT mcp_reader TO "alice@example.com";

CREATE USER IF NOT EXISTS "bob@example.com" IDENTIFIED WITH no_password;
GRANT mcp_admin TO "bob@example.com";
```

The literal value used for the ClickHouse username is the OAuth `email` claim when present, falling back to `sub` otherwise. Most IdPs (Google, Azure AD, Keycloak with the email scope) emit `email`, so `system.query_log` attributes queries to addresses like `alice@example.com`. `sub` is reserved for IdPs that deliberately omit email (e.g., machine-to-machine tokens). This matches the convention used by forward mode's `username_claim: email` setups, so operators can share a single pool of pre-provisioned CH users across both modes.

**Limitations:**

- **TCP only**: Startup fails with `clickhouse-cluster-secret requires clickhouse-protocol=tcp` if `protocol: http` is set.
- **No role forwarding from the IdP**: altinity-mcp does not send ClickHouse `external_roles` on the wire; permissions come entirely from what's `GRANT`ed to the user on the ClickHouse side. This is a deliberate limit of the current driver protocol revision (54460); revisit if the IdP becomes the source of truth for ClickHouse entitlements.
- **Secret hygiene**: Treat `cluster_secret` like a root credential. Anyone holding it can authenticate to ClickHouse as any existing user — including `default` and any admin account. Put it in a secret manager, rotate it by updating both sides simultaneously (ClickHouse accepts live reloads of `remote_servers` config).


## Requirements

- **ClickHouse protocol**: Forward mode requires `http`. Gating mode with static credentials works with both `http` and native `tcp`. Gating mode with cluster-secret authentication requires `tcp`.
- **ClickHouse version**: Forward mode requires Altinity Antalya build 25.8+ (or any build that supports `token_processors`). Gating mode works with any ClickHouse version.
- **Identity Provider**: Any OAuth 2.0 / OIDC-compliant provider (Keycloak, Azure AD, Google, AWS Cognito, etc.)
- **`signing_secret`**: Required in both modes. Protects stateless OAuth artifacts: DCR client-id JWE, forward-mode refresh-token JWE, and HKDF-derived key material.
- **Frontend / reverse proxy**: If published behind a proxy, configure `public_resource_url` (both modes) and `public_auth_server_url` (forward mode only). See [Frontend / Reverse Proxy Requirements](#frontend--reverse-proxy-requirements).

## MCP Client Discovery Flow

OAuth-capable MCP clients (e.g., Claude Desktop, Codex) discover authentication automatically:

1. Client fetches `/.well-known/oauth-protected-resource` from the MCP endpoint.
2. **Gating**: response `authorization_servers` points to the upstream IdP (e.g. `https://altinity.auth0.com/`). Client fetches `/.well-known/oauth-authorization-server` **from the IdP**. MCP's `/.well-known/oauth-authorization-server` returns 404 (route removed under #109). **Forward**: response points to MCP itself; client fetches MCP's `/.well-known/oauth-authorization-server`.
3. Client dynamically registers (DCR) with the authorization server — the IdP in gating mode, MCP in forward mode.
4. Client initiates authorization code flow with S256 PKCE.
5. After login, client exchanges the code for access + refresh tokens.
6. Client presents the access token on every MCP request and refreshes silently via the AS when it expires.

## Refresh Tokens

Both modes can issue refresh tokens. The MCP refresh token is always a stateless JWE keyed by `signing_secret`; what it *wraps* differs by mode.

### Gating mode

Refresh tokens are issued and rotated entirely by the upstream IdP (Auth0, Keycloak, etc.). MCP does not issue, rotate, or validate gating-mode refresh tokens — it never sees them. The client exchanges refresh tokens directly against the IdP's `/token` endpoint.

- **TTL**: Set on the Auth0 API resource (absolute: 30 d; inactivity: 7 d per the otel setup).
- **Rotation**: Rotating with reuse interval = 0 s (when the Auth0 DCR-template defaults are configured — see the security gap in the Auth0 setup checklist above).
- **Reuse detection**: RFC 6749 §10.4 / OAuth 2.1 §4.13.2 — handled by Auth0, not MCP.

### Forward mode (opt-in)

By default, forward mode does not issue refresh tokens — MCP-client sessions die when the upstream ID token expires. Set `upstream_offline_access: true` to opt into a refresh path that preserves the forward-mode invariant (the bearer reaching ClickHouse remains the upstream-IdP-signed JWT, validated end-to-end by CH's `token_processor`).

When enabled:

1. MCP appends `offline_access` to the upstream authorize redirect.
2. MCP captures the upstream IdP's `refresh_token` from the token-exchange response and wraps it in a JWE keyed by `signing_secret`. The MCP client sees only the opaque JWE.
3. On `grant_type=refresh_token`, MCP decrypts the JWE, calls the upstream `/oauth/token` with `grant_type=refresh_token`, re-validates the new ID token (signature via JWKS, identity policy), mints a new JWE around the rotated upstream refresh, and returns the new pair. The new `access_token` is the fresh upstream ID token verbatim.

Operator setup:

- Enable the `offline_access` scope on your IdP (Auth0: tenant API; Okta: app grant types; Azure AD: scope exposure). Without IdP-side support, the authorize redirect may hard-fail or silently strip the scope.
- Configure refresh-token rotation + reuse detection at the IdP if available. This provides revocation outside MCP, since the JWE itself is stateless.
- The default is `false` so existing forward-mode deployments are unaffected unless an operator opts in. Three reasons for the default: (1) turning on refresh widens the stolen-token blast radius from the upstream ID-token TTL (~1 h) to `refresh_token_ttl_seconds` (default 30 d) — operators must consciously accept that envelope; (2) `offline_access` requires upstream IdP configuration that may not yet be in place; (3) refresh-rotation policy is a separate operator decision (often owned by the identity team).

Limitations:

- **Gating**: no MCP-side revocation; token validity is bounded by Auth0's access-token TTL (600 s). Grant revocations take effect within one TTL window.
- **Forward**: no server-side revocation of the JWE-wrapped refresh token. Rotate `signing_secret` to invalidate all outstanding JWEs. The upstream IdP's reuse detection (if enabled) provides defense-in-depth when `upstream_offline_access: true`.

## Identity Policy

MCP can restrict access based on identity claims extracted from the validated JWT on every request. These checks apply to both modes; in gating mode they are MCP's primary admission gate (the IdP is still the authority for authentication, but MCP enforces the domain/email policy at authorization time).

| Option | Description |
|--------|-------------|
| `allowed_email_domains` | Only allow principals with an `email` claim in these domains (e.g., `["example.com"]`) |
| `allowed_hosted_domains` | Only allow principals with an `hd` (hosted/workspace domain) claim in this set — Google Workspace / Auth0 organization |
| `allow_unverified_email` | Opt out of the default `email_verified=true` requirement. Default `false` (verified required) — set `true` only when the IdP omits the claim or the operator trusts upstream verification. **Forbidden** combined with `cluster_secret` (H-1: would let any token impersonate any CH user) or with `allowed_email_domains` / `allowed_hosted_domains` (M3: a forged unverified email would defeat the domain policy). Startup refuses in either combination. |

Claims come from the AS-issued JWT (gating) or the upstream id_token (forward) and cannot be forged by the client.

```yaml
server:
  oauth:
    allowed_email_domains: ["altinity.com", "example.com"]
    allowed_hosted_domains: ["altinity.com"]
    # allow_unverified_email defaults to false (verified required). Setting
    # true here would be a startup error because of the domain allow-list.
```

## Full Configuration Reference

```yaml
server:
  oauth:
    # Enable OAuth 2.0 authentication
    enabled: false

    # OAuth operating mode:
    # - "gating": pure resource server — validate AS-issued JWTs (JWKS + RFC 8707 aud + scopes).
    #             Upstream IdP handles DCR/authorize/token. Requires issuer + audience.
    #             Forbidden fields: client_id, client_secret, token_url, auth_url,
    #             userinfo_url, public_auth_server_url.
    # - "forward": MCP proxies DCR + authorize + token to upstream; relays upstream tokens.
    #              Requires client_id, client_secret, auth_url, token_url.
    mode: "gating"

    # Symmetric secret for stateless OAuth artifacts (client registration,
    # authorization codes, refresh tokens). Required whenever OAuth is enabled.
    signing_secret: ""

    # Upstream OAuth/OIDC issuer URL (used for discovery and validation)
    issuer: ""

    # URL to fetch JWKS for token validation (discovered from issuer if empty)
    jwks_url: ""

    # Expected audience claim in incoming tokens
    audience: ""

    # Forward mode only: upstream OAuth client credentials and endpoint URLs.
    # FORBIDDEN in gating mode — startup refuses if any of these are set.
    client_id: ""
    client_secret: ""
    token_url: ""
    auth_url: ""
    userinfo_url: ""
    public_auth_server_url: ""

    # Forward mode only: OAuth scopes to request from upstream IdP
    scopes: ["openid", "profile", "email"]

    # Forward mode: opt into requesting offline_access upstream and issuing
    # JWE-wrapped refresh tokens to MCP clients. Default false. See "Refresh
    # Tokens / Forward mode (opt-in)" for trust model and operator setup.
    upstream_offline_access: false

    # Gating mode: scopes required in every incoming AS-issued JWT
    required_scopes: []

    # Forward mode: allowed upstream IdP issuers for identity tokens
    upstream_issuer_allowlist: []

    # Identity policy — applies to both modes (claims from JWT)
    allowed_email_domains: []
    allowed_hosted_domains: []

    # Accept tokens with email_verified=false. Default false (verified required).
    # Forbidden together with cluster_secret or allowed_*_domains — startup errors.
    allow_unverified_email: false

    # Token lifetimes
    access_token_ttl_seconds: 3600    # 1 hour (gating: reduce to 600 for revocation latency)
    refresh_token_ttl_seconds: 2592000 # 30 days (forward mode only — gating refresh tokens are IdP-managed)

    # Header name for forwarding (forward mode). Default "Authorization" sends "Bearer {token}".
    # Set to a custom name to send the raw token without "Bearer " prefix.
    clickhouse_header_name: ""

    # Map token claims to ClickHouse HTTP headers (forward mode with claims)
    claims_to_headers:
      sub: "X-ClickHouse-User"
      email: "X-ClickHouse-Email"

    # Externally visible MCP endpoint URL. Required behind a reverse proxy (both modes).
    public_resource_url: ""

    # Forward mode only: endpoint paths (defaults shown; override for custom proxy layouts).
    # The .well-known metadata paths are spec-fixed and not configurable.
    registration_path: "/register"
    authorization_path: "/authorize"
    callback_path: "/callback"
    token_path: "/token"
```

### Key Options Explained

| Option | Description |
|--------|-------------|
| `mode` | `gating` validates AS-issued JWTs (JWKS + RFC 8707 aud + scopes); `forward` proxies DCR/authorize/token to upstream and relays tokens to ClickHouse |
| `signing_secret` | Symmetric secret for all stateless OAuth artifacts. **Required** whenever OAuth is enabled |
| `issuer` | Upstream IdP issuer URL for OIDC discovery and token validation |
| `public_resource_url` | Externally visible MCP endpoint URL. **Required** behind a reverse proxy |
| `public_auth_server_url` | Externally visible OAuth authorization server URL. **Forward mode only** — required behind a reverse proxy. Forbidden in gating mode. |
| `refresh_token_ttl_seconds` | Lifetime of JWE-wrapped refresh tokens (default 30 days). Applies to forward mode when `upstream_offline_access` is on. Not applicable to gating mode (refresh tokens are IdP-managed). |
| `upstream_offline_access` | Forward mode only: request `offline_access` upstream and issue JWE-wrapped refresh tokens to MCP clients. Default `false` |

## Frontend / Reverse Proxy Requirements

For direct bearer-token use, a plain reverse proxy is usually enough.

For browser-based MCP login in **forward mode**, the frontend must expose two public URL spaces:

- the protected resource, for example `https://PUBLIC_HOST.example.com/`
- the OAuth authorization server, for example `https://PUBLIC_HOST.example.com/oauth`

In **gating mode**, only the protected resource URL needs to be proxied. The authorization server is the upstream IdP and is not proxied through MCP.

The proxy must:

- Forward `Host` and `Authorization` headers unchanged
- Disable response buffering for MCP streaming
- Disable request buffering for long-lived POSTs
- Keep long read/send timeouts
- Not normalize or rewrite the configured callback or metadata paths
- Not rely on forwarded-prefix headers; configure the public OAuth URLs explicitly in `altinity-mcp`

Example nginx configuration:

```nginx
location / {
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header Authorization $http_authorization;
    proxy_buffering off;
    proxy_request_buffering off;
    proxy_read_timeout 3600;
    proxy_send_timeout 3600;
    proxy_pass http://ALTINITY_MCP_UPSTREAM;
}
```

Notes:

- Set both `public_resource_url` and `public_auth_server_url` whenever OAuth is published behind a proxy.
- If an IdP reports `redirect_uri_mismatch`, verify the public callback URL seen by the browser exactly matches the URI registered at the IdP.

### Browser-login config behind a proxy (Google + forward mode)

```yaml
server:
  oauth:
    enabled: true
    mode: "forward"
    signing_secret: "CHANGE_ME_TO_A_RANDOM_SECRET"
    issuer: "https://accounts.google.com"
    audience: "https://PUBLIC_HOST.example.com/"
    public_resource_url: "https://PUBLIC_HOST.example.com/"
    public_auth_server_url: "https://PUBLIC_HOST.example.com/oauth"
    client_id: "YOUR_GOOGLE_WEB_CLIENT.apps.googleusercontent.com"
    client_secret: "YOUR_GOOGLE_CLIENT_SECRET"
    scopes: ["openid", "email"]
```

In forward mode, the bearer token is automatically forwarded to ClickHouse and static credentials are cleared. No additional flags needed.

## ClickHouse Configuration

ClickHouse must be configured with `token_processors` and a `user_directories` section that maps tokens to user identities and roles.

### OpenID Connect (Keycloak, Google, generic OIDC providers)

```xml
<clickhouse>
    <token_processors>
        <my_oidc_provider>
            <type>openid</type>
            <configuration_endpoint>https://your-idp.example.com/.well-known/openid-configuration</configuration_endpoint>
            <token_cache_lifetime>60</token_cache_lifetime>
        </my_oidc_provider>
    </token_processors>
    <user_directories>
        <token>
            <processor>my_oidc_provider</processor>
            <common_roles>
                <default_role />
            </common_roles>
        </token>
    </user_directories>
</clickhouse>
```

Alternatively, you can specify the OIDC endpoints explicitly:

```xml
<clickhouse>
    <token_processors>
        <my_oidc_provider>
            <type>OpenID</type>
            <userinfo_endpoint>https://your-idp.example.com/userinfo</userinfo_endpoint>
            <jwks_uri>https://your-idp.example.com/certs</jwks_uri>
            <token_introspection_endpoint>https://your-idp.example.com/token/introspect</token_introspection_endpoint>
            <token_cache_lifetime>60</token_cache_lifetime>
        </my_oidc_provider>
    </token_processors>
    <user_directories>
        <token>
            <processor>my_oidc_provider</processor>
            <common_roles>
                <default_role />
            </common_roles>
        </token>
    </user_directories>
</clickhouse>
```

### Azure AD (Microsoft Entra ID)

Azure AD has a dedicated `azure` type that requires no explicit endpoint configuration:

```xml
<clickhouse>
    <token_processors>
        <azure_ad>
            <type>azure</type>
            <token_cache_lifetime>60</token_cache_lifetime>
        </azure_ad>
    </token_processors>
    <user_directories>
        <token>
            <processor>azure_ad</processor>
            <common_roles>
                <default_role />
            </common_roles>
        </token>
    </user_directories>
</clickhouse>
```

### ClickHouse Roles Setup

You must create the roles referenced in `common_roles` before users can authenticate:

```sql
CREATE ROLE OR REPLACE default_role;
GRANT SELECT ON default.* TO default_role;
```

## Provider-Specific Setup

### Keycloak

#### 1. Create a Realm and Client

In the Keycloak admin console:
- Create a realm (e.g., `mcp`)
- Create a client with:
  - **Client ID**: `clickhouse-mcp`
  - **Client Protocol**: `openid-connect`
  - **Access Type**: `confidential` (or `public` for PKCE)
  - **Valid Redirect URIs**: your MCP server URL
- Enable "Standard Flow Enabled" and "Direct Access Grants Enabled"

#### 2. Create Groups and Users

- Create groups for role mapping (e.g., `clickhouse-users`)
- Create users and assign them to groups
- Configure group membership mapper in the client to include groups in tokens

#### 3. MCP Server Configuration

```yaml
server:
  oauth:
    enabled: true
    mode: "forward"
    signing_secret: "CHANGE_ME_TO_A_RANDOM_SECRET"
    issuer: "http://keycloak:8080/realms/mcp"
    audience: "clickhouse-mcp"
    client_id: "clickhouse-mcp"
    client_secret: "<KEYCLOAK_CLIENT_SECRET>"
    scopes: ["openid", "email"]
```

#### 4. ClickHouse Configuration

```xml
<token_processors>
    <keycloak>
        <type>OpenID</type>
        <userinfo_endpoint>http://keycloak:8080/realms/mcp/protocol/openid-connect/userinfo</userinfo_endpoint>
        <jwks_uri>http://keycloak:8080/realms/mcp/protocol/openid-connect/certs</jwks_uri>
        <token_cache_lifetime>60</token_cache_lifetime>
    </keycloak>
</token_processors>
```

See also: [zvonand/grafana-oauth](https://github.com/zvonand/grafana-oauth) for a complete working example with Keycloak and ClickHouse.

### Azure AD (Microsoft Entra ID)

#### 1. Register an Application

In the [Azure Portal](https://portal.azure.com):
- Go to **Microsoft Entra ID** > **App registrations** > **New registration**
- Set a name (e.g., "ClickHouse MCP")
- Select the appropriate supported account types
- Add a redirect URI if using authorization code flow

#### 2. Create Client Secret

- Go to **Certificates & secrets** > **New client secret**
- Copy the secret value (shown only once)

#### 3. Configure API Permissions

- Add the `openid`, `profile`, and `email` permissions under **API permissions**

#### 4. Note the Endpoints

- **Tenant ID**: found in the **Overview** tab
- **Application (Client) ID**: found in the **Overview** tab
- **Token URL**: `https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token`
- **Auth URL**: `https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/authorize`
- **OIDC Discovery**: `https://login.microsoftonline.com/{TENANT_ID}/v2.0/.well-known/openid-configuration`

#### 5. MCP Server Configuration

```yaml
server:
  oauth:
    enabled: true
    mode: "forward"
    signing_secret: "CHANGE_ME_TO_A_RANDOM_SECRET"
    issuer: "https://login.microsoftonline.com/<TENANT_ID>/v2.0"
    audience: "<APPLICATION_CLIENT_ID>"
    client_id: "<APPLICATION_CLIENT_ID>"
    client_secret: "<APPLICATION_CLIENT_SECRET>"
    token_url: "https://login.microsoftonline.com/<TENANT_ID>/oauth2/v2.0/token"
    auth_url: "https://login.microsoftonline.com/<TENANT_ID>/oauth2/v2.0/authorize"
    scopes: ["openid", "profile", "email"]
```

#### 6. ClickHouse Configuration

Azure AD uses the dedicated `azure` token processor type:

```xml
<token_processors>
    <azure_ad>
        <type>azure</type>
        <token_cache_lifetime>60</token_cache_lifetime>
    </azure_ad>
</token_processors>
```

See also: [zvonand/grafana-oauth/azure](https://github.com/zvonand/grafana-oauth/tree/main/azure) for a complete working example with Azure AD and ClickHouse.

**References:**
- [Microsoft Entra ID - OAuth 2.0 and OpenID Connect protocols](https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols)
- [Microsoft Entra ID - OpenID Connect](https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc)

### Google Cloud Identity

#### 1. Create OAuth 2.0 Credentials

In the [Google Cloud Console](https://console.cloud.google.com):
- Go to **APIs & Services** > **Credentials** > **Create Credentials** > **OAuth client ID**
- Select **Web application** as the application type
- Set authorized redirect URIs
- Copy the **Client ID** and **Client Secret**

#### 2. MCP Server Configuration

```yaml
server:
  oauth:
    enabled: true
    mode: "forward"
    signing_secret: "CHANGE_ME_TO_A_RANDOM_SECRET"
    issuer: "https://accounts.google.com"
    audience: "<GOOGLE_CLIENT_ID>.apps.googleusercontent.com"
    client_id: "<GOOGLE_CLIENT_ID>.apps.googleusercontent.com"
    client_secret: "<GOOGLE_CLIENT_SECRET>"
    token_url: "https://oauth2.googleapis.com/token"
    auth_url: "https://accounts.google.com/o/oauth2/v2/auth"
    scopes: ["openid", "profile", "email"]
```

#### 3. ClickHouse Configuration

Google uses the standard `openid` token processor type:

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

Default for `username_claim` is `sub`, that means IdP users will be shown in clickhouse (processlist, query_log, etc) as numerical ids.  To see emails, set `<username_claim>email</username_claim>`

**References:**
- [Google - OpenID Connect](https://developers.google.com/identity/openid-connect/openid-connect)
- [Google - Using OAuth 2.0 to Access Google APIs](https://developers.google.com/identity/protocols/oauth2)
- [Setting up OAuth 2.0 in Google Cloud Console](https://support.google.com/googleapi/answer/6158849)

### AWS Cognito

#### 1. Create a User Pool

In the [AWS Console](https://console.aws.amazon.com/cognito):
- Create a new user pool
- Configure sign-in options (email, username)
- Set password policies
- Add an app client with OAuth 2.0 settings enabled

#### 2. Configure App Client

- Under **App integration** > **App clients**, create a new app client
- Enable the OAuth 2.0 grant types you need (Authorization Code)
- Set the allowed callback URLs
- Select the OAuth scopes: `openid`, `profile`, `email`

#### 3. Note the Endpoints

- **User Pool ID**: found in the **General settings** tab
- **Region**: the AWS region where the user pool is created
- **Issuer URL**: `https://cognito-idp.{REGION}.amazonaws.com/{USER_POOL_ID}`
- **Token URL**: `https://{DOMAIN}.auth.{REGION}.amazoncognito.com/oauth2/token`
- **Auth URL**: `https://{DOMAIN}.auth.{REGION}.amazoncognito.com/oauth2/authorize`
- **OIDC Discovery**: `https://cognito-idp.{REGION}.amazonaws.com/{USER_POOL_ID}/.well-known/openid-configuration`

#### 4. MCP Server Configuration

```yaml
server:
  oauth:
    enabled: true
    mode: "forward"
    signing_secret: "CHANGE_ME_TO_A_RANDOM_SECRET"
    issuer: "https://cognito-idp.<REGION>.amazonaws.com/<USER_POOL_ID>"
    audience: "<APP_CLIENT_ID>"
    client_id: "<APP_CLIENT_ID>"
    client_secret: "<APP_CLIENT_SECRET>"
    token_url: "https://<DOMAIN>.auth.<REGION>.amazoncognito.com/oauth2/token"
    auth_url: "https://<DOMAIN>.auth.<REGION>.amazoncognito.com/oauth2/authorize"
    scopes: ["openid", "profile", "email"]
```

#### 5. ClickHouse Configuration

AWS Cognito uses the standard `openid` token processor type:

```xml
<token_processors>
    <cognito>
        <type>openid</type>
        <configuration_endpoint>https://cognito-idp.<REGION>.amazonaws.com/<USER_POOL_ID>/.well-known/openid-configuration</configuration_endpoint>
        <token_cache_lifetime>60</token_cache_lifetime>
    </cognito>
</token_processors>
```

**References:**
- [Amazon Cognito - Using OIDC identity providers](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-oidc-idp.html)
- [Amazon Cognito - How to use OAuth 2.0](https://aws.amazon.com/blogs/security/how-to-use-oauth-2-0-in-amazon-cognito-learn-about-the-different-oauth-2-0-grants/)
- [Amazon Cognito - Identity provider endpoints](https://docs.aws.amazon.com/cognito/latest/developerguide/federation-endpoints.html)

## Helm Chart Deployment

The Helm chart supports all OAuth configuration options under `config.server.oauth`:

```bash
helm install altinity-mcp ./helm/altinity-mcp \
  -f helm/altinity-mcp/values_examples/mcp-oauth-keycloak.yaml
```

Example values files are provided for each provider:
- `values_examples/mcp-oauth-keycloak.yaml` - Keycloak / generic OIDC
- `values_examples/mcp-oauth-azure.yaml` - Azure AD (Microsoft Entra ID)
- `values_examples/mcp-oauth-google.yaml` - Google Cloud Identity

## Security Considerations

- **`signing_secret`** protects all stateless OAuth artifacts (client registrations, authorization codes, refresh tokens). Treat it like a signing key. Rotate it to invalidate all outstanding registrations and tokens.
- **Forward mode does not validate tokens locally.** It checks only that a bearer token is present, then forwards it to ClickHouse. Token validation is ClickHouse's responsibility via `token_processors`.
- **Gating-mode tokens are AS-issued JWTs.** MCP does not mint or revoke them. Revocation propagates to MCP within one access-token TTL window (default 600 s). Refresh-token revocation is handled entirely by the upstream IdP.
- **Opaque bearer tokens are not supported.** Inbound OAuth validation on MCP/OpenAPI endpoints requires a signed JWT that can be validated via JWKS. The `userinfo` endpoint is used only during browser-login identity lookup, not for runtime token validation.
- **Token preference during browser login.** When both `id_token` and `access_token` are returned by the upstream provider, `altinity-mcp` prefers `id_token` as the MCP bearer token and falls back to `access_token` only when no `id_token` is available.

## Troubleshooting

### ClickHouse returns HTTP 403 with "Bearer HTTP Authorization scheme is not supported"

Your ClickHouse build does not support `token_processors`. You need the Altinity Antalya build 25.8+ or a compatible ClickHouse version.

### Token validation fails with "issuer mismatch"

Ensure the `issuer` in your MCP config matches exactly what your IdP puts in the `iss` claim. Common issues:
- Trailing slash mismatch (`https://accounts.google.com` vs `https://accounts.google.com/`)
- Missing `/v2.0` suffix for Azure AD

In gating mode, `issuer` must exactly match the `iss` claim in the AS-issued JWT. `public_auth_server_url` is a **forward-mode-only** field and must not be set under gating (startup refuses).

### ClickHouse authenticates but user has no permissions

Create the roles referenced in `common_roles` and grant them the necessary permissions:

```sql
CREATE ROLE OR REPLACE default_role;
GRANT SELECT ON *.* TO default_role;
```
