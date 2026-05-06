# OAuth 2.0 Authorization for Altinity MCP Server

This document explains how to configure OAuth 2.0 / OpenID Connect (OIDC) authentication with the Altinity MCP Server.

## Overview

OAuth 2.0 authorization supports two modes.

### Forward mode

Use this when ClickHouse has native OAuth support (Altinity Antalya 25.8+). The MCP server passes the bearer token through; ClickHouse validates it.

1. An MCP client authenticates with an Identity Provider (IdP) and obtains a token
2. The MCP client sends the token to the MCP server in the `Authorization: Bearer {token}` header
3. The MCP server requires only that a bearer token is present (it does **not** validate the token locally)
4. The MCP server forwards the token to ClickHouse via HTTP headers
5. ClickHouse validates the token using `token_processors` and authenticates the user

### Per-DCR-client consent (and how to disable it)

Both modes route through `/oauth/callback` after upstream IdP authentication.
By default, the user is then shown a brief HTML consent screen listing the
client name, the redirect URI hostname, the resource being authorized, and
the identity from upstream. This satisfies MCP §Confused Deputy Problem:

> "MCP proxy servers using static client IDs MUST obtain user consent for each
> dynamically registered client before forwarding to third-party authorization
> servers."

Configure with:

| Field | Env var | Default | Effect |
|---|---|---|---|
| `disable_dcr_consent` | `MCP_OAUTH_DISABLE_DCR_CONSENT` | `false` | Skip the consent screen; `/callback` 302's the gating code straight to the client redirect. **Spec deviation.** |
| `consent_path` | `MCP_OAUTH_CONSENT_PATH` | `/oauth/consent` | Override the consent endpoint path. |

Disabling consent is reasonable for deployments where another trust gate (one
of `allowed_email_domains` / `allowed_hosted_domains`) restricts who can
authenticate through your IdP at all — the confused-deputy attack relies on
phishing a logged-in upstream user, and an identity-domain allowlist removes
that attack surface. The startup banner refuses silently if you disable
consent without setting one of those gates.

**Default-on / opt-out** is intentional: spec compliance is the secure default.
Operators who explicitly opt out get a startup log line stating the
identity-policy fallback they're relying on.

> **Spec deviation (deliberate).** MCP authorization spec 2025-11-25 §Access
> Token Privilege Restriction says *"the MCP server **MUST NOT** pass through
> the token it received from the MCP client"*. Forward mode does pass it
> through — by design. The architectural justification is that ClickHouse
> validates the token against the same upstream JWKS the MCP server would;
> both extract the same identity; there is no privilege boundary between them
> to abuse. The deviation is recorded in
> `docs/oauth_compatibility_hypotheses.md` (H-2). Gating mode is the
> spec-clean alternative — use that when you don't have ClickHouse-side
> token validation set up.

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


### Gating mode

Use this when ClickHouse has no OAuth support. The MCP server itself authenticates users via the upstream IdP, mints its own tokens, and connects to ClickHouse with static credentials.

1. An MCP client authenticates with an Identity Provider (IdP) via browser login
2. The MCP server validates the upstream identity (email domain, hosted domain, email verification)
3. The MCP server mints its own signed access and refresh tokens
4. The MCP server connects to ClickHouse with its statically configured credentials

This mode works even when ClickHouse has no native OAuth support.

```
┌────────┐      ┌──────────┐      ┌──────────┐      ┌────────────┐
│  MCP   │─────>│   IdP    │      │   MCP    │      │ ClickHouse │
│ Client │<─────│(Keycloak,│      │  Server  │      │            │
│        │      │ Azure AD,│      │          │      │            │
│        │      │ Google)  │      │          │      │            │
│        │      └──────────┘      │          │      │            │
│        │                        │          │      │            │
│        │──Browser login────────>│──Verify──>│     │            │
│        │<─────────MCP token─────│  identity │     │            │
│        │                        │          │      │            │
│        │──MCP token────────────>│          │      │            │
│        │                        │─Static──>│      │            │
│        │                        │  creds   │─────>│ Authn via  │
│        │<───────────────────────│<─────────│<─────│ config user│
│        │      query results     │          │      │            │
└────────┘                        └──────────┘      └────────────┘
```

```yaml
clickhouse:
  host: "clickhouse.example.com"
  port: 9000
  protocol: tcp
  username: "default"
  password: "<CLICKHOUSE_PASSWORD>"
server:
  oauth:
    enabled: true
    mode: "gating"
    signing_secret: "CHANGE_ME_TO_A_RANDOM_SECRET"
    issuer: "https://accounts.google.com"
    public_auth_server_url: "https://mcp.example.com"
    client_id: "<YOUR_CLIENT_ID>"
    client_secret: "<YOUR_CLIENT_SECRET>"
    scopes: ["openid", "email"]
    allowed_email_domains: ["example.com"]
```

#### Cluster-secret authentication (optional)

Gating mode's default connects to ClickHouse with a **single static username/password** shared across all MCP users. Queries land in `system.query_log` under that service account, so you lose per-user attribution.

The **cluster-secret path** removes both limitations. altinity-mcp handshakes with ClickHouse as a trusted cluster peer using a shared `<secret>` instead of a password, and executes each query as the OAuth-authenticated user. ClickHouse records the real identity in `system.query_log`, applies that user's grants, and the MCP process never touches a shared password.

```
┌────────┐      ┌──────────┐      ┌──────────┐      ┌────────────┐
│  MCP   │      │   IdP    │      │   MCP    │      │ ClickHouse │
│ Client │      │          │      │  Server  │      │            │
│        │──login──>│     │      │          │      │            │
│        │<─MCP tok─│     │      │          │      │            │
│        │                        │          │      │            │
│        │──query + MCP token────>│          │      │            │
│        │                        │─cluster─>│      │  verifies  │
│        │                        │ secret + │      │  HMAC, runs│
│        │                        │ initial  │─────>│  as claim. │
│        │                        │ _user =  │      │  subject   │
│        │                        │ claim.sub│      │            │
│        │<───────────────────────│<─────────│<─────│            │
└────────┘                        └──────────┘      └────────────┘
```

**altinity-mcp config:**

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
    issuer: https://accounts.google.com
    signing_secret: "CHANGE_ME_TO_A_RANDOM_SECRET"
    # ... standard gating config ...
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
- **`signing_secret`**: Required in both modes. Protects stateless client registration, authorization codes, and (in gating mode) refresh tokens.
- **Frontend / reverse proxy**: If published behind a proxy, configure explicit `public_resource_url` and `public_auth_server_url`. See [Frontend / Reverse Proxy Requirements](#frontend--reverse-proxy-requirements).

## MCP Client Discovery Flow

OAuth-capable MCP clients (e.g., Claude Desktop, Codex) discover authentication automatically:

1. Client fetches `/.well-known/oauth-protected-resource` from the MCP endpoint
2. Response points to the authorization server URL
3. Client fetches `/.well-known/oauth-authorization-server` for endpoint metadata
4. Client dynamically registers via the registration endpoint (PKCE, public client)
5. Client initiates authorization code flow with S256 PKCE
6. After login, client exchanges the code for access + refresh tokens
7. Client uses the access token for MCP requests and refreshes silently when it expires

## Refresh Tokens

Both modes can issue refresh tokens. The MCP refresh token is always a stateless JWE keyed by `signing_secret`; what it *wraps* differs by mode.

### Gating mode

The token endpoint returns a `refresh_token` alongside the `access_token`. Clients exchange it via `grant_type=refresh_token` to get a new access token without re-authorizing through the browser.

- **TTL**: Controlled by `refresh_token_ttl_seconds` (default: 30 days)
- **Rotation**: Each refresh returns a new refresh token (the old one remains valid until expiry)
- **Stateless**: Refresh tokens are encrypted JWE blobs with no server-side state. There is no revocation or reuse detection.

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

Limitations (apply to both modes):

- No server-side revocation of individual MCP tokens. Rotate `signing_secret` to invalidate all outstanding JWEs.
- No reuse detection for the MCP-side refresh token: a rotated-out JWE remains valid until its `exp`. In forward mode, the upstream IdP's reuse detection (if enabled) provides defense-in-depth.

## Identity Policy (Gating Mode)

Gating mode can restrict access based on verified identity claims from the upstream IdP:

| Option | Description |
|--------|-------------|
| `allowed_email_domains` | Only allow users with email addresses in these domains (e.g., `["example.com"]`) |
| `allowed_hosted_domains` | Only allow users from these Google Workspace / hosted domains (checks the `hd` claim) |
| `require_email_verified` | Reject users whose `email_verified` claim is false |

These checks run on every token mint and refresh. Identity claims come from the upstream IdP's signed id_token or userinfo response and cannot be forged by the client.

```yaml
server:
  oauth:
    allowed_email_domains: ["altinity.com", "example.com"]
    allowed_hosted_domains: ["altinity.com"]
    require_email_verified: true
```

## Full Configuration Reference

```yaml
server:
  oauth:
    # Enable OAuth 2.0 authentication
    enabled: false

    # OAuth operating mode:
    # - "forward": pass bearer tokens through to ClickHouse for validation
    # - "gating": validate upstream identity and mint local MCP tokens
    mode: "forward"

    # Symmetric secret for stateless OAuth artifacts (client registration,
    # authorization codes, refresh tokens). Required whenever OAuth is enabled.
    signing_secret: ""

    # Upstream OAuth/OIDC issuer URL (used for discovery and validation)
    issuer: ""

    # URL to fetch JWKS for token validation (discovered from issuer if empty)
    jwks_url: ""

    # Expected audience claim in incoming tokens
    audience: ""

    # Upstream OAuth client credentials (for browser-login facade)
    client_id: ""
    client_secret: ""

    # Upstream OAuth endpoint URLs (discovered from issuer if empty)
    token_url: ""
    auth_url: ""
    userinfo_url: ""

    # OAuth scopes to request from upstream IdP
    scopes: ["openid", "profile", "email"]

    # Forward mode: opt into requesting offline_access upstream and issuing
    # JWE-wrapped refresh tokens to MCP clients. Default false. See "Refresh
    # Tokens / Forward mode (opt-in)" for trust model and operator setup.
    upstream_offline_access: false

    # Scopes required in incoming tokens (gating mode only)
    required_scopes: []

    # Allowed upstream IdP issuers for identity tokens during callback exchange
    upstream_issuer_allowlist: []

    # Identity policy (gating mode)
    allowed_email_domains: []
    allowed_hosted_domains: []
    require_email_verified: false

    # Token lifetimes (auth code TTL is hardcoded to 300s per RFC 6749)
    access_token_ttl_seconds: 3600    # 1 hour
    refresh_token_ttl_seconds: 2592000 # 30 days (gating mode only)

    # Header name for forwarding. Default "Authorization" sends "Bearer {token}".
    # Set to a custom name to send the raw token without "Bearer " prefix.
    clickhouse_header_name: ""

    # Map token claims to ClickHouse HTTP headers (gating mode with claims)
    claims_to_headers:
      sub: "X-ClickHouse-User"
      email: "X-ClickHouse-Email"

    # Externally visible URLs (required behind a reverse proxy)
    public_resource_url: ""
    public_auth_server_url: ""

    # Endpoint paths (defaults shown; override for custom proxy layouts).
    # The .well-known metadata paths are spec-fixed and not configurable.
    registration_path: "/register"
    authorization_path: "/authorize"
    callback_path: "/callback"
    token_path: "/token"
```

### Key Options Explained

| Option | Description |
|--------|-------------|
| `mode` | `forward` passes tokens to ClickHouse for validation; `gating` validates upstream identity and mints local tokens |
| `signing_secret` | Symmetric secret for all stateless OAuth artifacts. **Required** whenever OAuth is enabled |
| `issuer` | Upstream IdP issuer URL for OIDC discovery and token validation |
| `public_resource_url` | Externally visible MCP endpoint URL. **Required** behind a reverse proxy |
| `public_auth_server_url` | Externally visible OAuth authorization server URL. **Required** behind a reverse proxy |
| `refresh_token_ttl_seconds` | Lifetime of stateless refresh tokens (default 30 days). Applies to gating mode and to forward mode when `upstream_offline_access` is on |
| `upstream_offline_access` | Forward mode only: request `offline_access` upstream and issue JWE-wrapped refresh tokens to MCP clients. Default `false` |

## Frontend / Reverse Proxy Requirements

For direct bearer-token use, a plain reverse proxy is usually enough.

For browser-based MCP login, the frontend must expose two public URL spaces:

- the protected resource, for example `https://PUBLIC_HOST.example.com/`
- the OAuth authorization server, for example `https://PUBLIC_HOST.example.com/oauth`

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
- **Gating-mode refresh tokens are stateless.** There is no server-side state, so individual tokens cannot be revoked. The only way to invalidate all tokens is to rotate `signing_secret`. Use `refresh_token_ttl_seconds` to limit exposure.
- **Opaque bearer tokens are not supported.** Inbound OAuth validation on MCP/OpenAPI endpoints requires a signed JWT that can be validated via JWKS. The `userinfo` endpoint is used only during browser-login identity lookup, not for runtime token validation.
- **Token preference during browser login.** When both `id_token` and `access_token` are returned by the upstream provider, `altinity-mcp` prefers `id_token` as the MCP bearer token and falls back to `access_token` only when no `id_token` is available.

## Troubleshooting

### ClickHouse returns HTTP 403 with "Bearer HTTP Authorization scheme is not supported"

Your ClickHouse build does not support `token_processors`. You need the Altinity Antalya build 25.8+ or a compatible ClickHouse version.

### Token validation fails with "issuer mismatch"

Ensure the `issuer` in your MCP config matches exactly what your IdP puts in the `iss` claim. Common issues:
- Trailing slash mismatch (`https://accounts.google.com` vs `https://accounts.google.com/`)
- Missing `/v2.0` suffix for Azure AD

In gating mode, also ensure `public_auth_server_url` is set when `issuer` is configured. The server mints tokens with `public_auth_server_url` as the issuer but validates against `issuer` if `public_auth_server_url` is empty.

### ClickHouse authenticates but user has no permissions

Create the roles referenced in `common_roles` and grant them the necessary permissions:

```sql
CREATE ROLE OR REPLACE default_role;
GRANT SELECT ON *.* TO default_role;
```
