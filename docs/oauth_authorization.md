# OAuth 2.0 Authorization for Altinity MCP Server

How OAuth 2.0 / OpenID Connect (OIDC) authentication works in
`altinity-mcp` and how to wire it up against common identity providers.

Companion: the ClickHouse-side JWT verifier sidecar lives in
[`altinity-oauth-helper`](https://github.com/altinity/altinity-oauth-helper) —
that repo carries the spec, source, helm chart, and Dockerfile.

## Overview

Set `oauth.broker: true`. That single flag makes altinity-mcp:

1. Act as the **OAuth Authorization Server** to MCP clients (claude.ai,
   ChatGPT, Codex) — hosts CIMD resolution, `/oauth/authorize`,
   `/oauth/callback`, `/oauth/token`.
2. **Broker the upstream IdP** (Google, Azure AD, Keycloak, etc.) using a
   static OAuth application credential you register there.
3. **Auto-detect the ClickHouse wire format** on the first authenticated
   request to each endpoint and cache it — no `mode:` config needed.

```yaml
config:
  clickhouse:
    host: clickhouse.example.com
    port: 8123
    protocol: http
  server:
    oauth:
      enabled: true
      broker: true
      signing_secret: "<32-byte-random>"        # openssl rand -base64 32
      issuer: "https://mcp.example.com"
      audience: "https://mcp.example.com"
      client_id: "<UPSTREAM_OAUTH_CLIENT_ID>"
      client_secret: "<UPSTREAM_OAUTH_CLIENT_SECRET>"
      auth_url: "<UPSTREAM_AUTH_URL>"
      token_url: "<UPSTREAM_TOKEN_URL>"
      public_resource_url: "https://mcp.example.com"
      public_auth_server_url: "https://mcp.example.com"
      scopes: [openid, email, profile]
```

## ClickHouse authentication (auto-detected)

altinity-mcp supports two CH-side auth methods. With `broker: true` it
probes the endpoint on first use and caches the result — operators do not
need to configure which one is in use.

### Bearer (`Authorization: Bearer <token>`)

Requires a ClickHouse build with `token_processors` (Altinity Antalya
25.8+). MCP forwards the upstream JWT directly; ClickHouse re-validates
against the upstream JWKS and materializes ephemeral users from claims.

- No sidecar needed.
- Users are provisioned dynamically from JWT claims — no `CREATE USER`
  per identity.
- Identity in `system.query_log` is the JWT subject (set
  `<username_claim>email</username_claim>` to get readable names).

### Basic (`Authorization: Basic base64(email:JWT)`)

Works on any ClickHouse build. MCP unverified-decodes the JWT's `email`
claim and rewrites the credential to Basic form. ClickHouse's
[`<http_authentication>`](https://clickhouse.com/docs/operations/external-authenticators/http)
posts the Basic header to the colocated `ch-jwt-verify` sidecar, which
cryptographically validates signature, `iss`, `aud` (RFC 8707 byte-equal),
`exp`/`nbf`/`iat`, required scopes, identity policy, and the
user-vs-claim match.

- Sidecar must be deployed next to ClickHouse (see
  [`altinity-oauth-helper`](https://github.com/altinity/altinity-oauth-helper)).
- Users are pre-provisioned: `CREATE USER "alice@example.com" IDENTIFIED
  WITH http SERVER 'ch_jwt_verify' SCHEME 'BASIC'`.
- Forces HTTP protocol on the driver.

### Detection logic

On the first authenticated request to `host:port`, MCP tries Bearer. If
CH returns an auth error (HTTP 401/403, CH exception codes 497/516/519),
it falls back to Basic. The result is stored in an in-memory cache keyed
by `host:port` and reused for all subsequent requests. The cache is
cleared on config reload.

## MCP client discovery flow

OAuth-capable MCP clients discover authentication automatically per
[RFC 9728](https://www.rfc-editor.org/rfc/rfc9728):

1. Client `GET`s `/.well-known/oauth-protected-resource` from the MCP endpoint.
2. Response `authorization_servers` points to **MCP itself**.
3. Client fetches MCP's `/.well-known/oauth-authorization-server`, which
   advertises CIMD support (no DCR `registration_endpoint`), lists
   `grant_types_supported: ["authorization_code"]` and
   `token_endpoint_auth_methods_supported: ["none", "private_key_jwt"]`.
4. Client publishes a CIMD document at a URL it controls and uses that
   URL as its `client_id` at `/authorize`.
5. Client initiates the authorization-code flow with S256 PKCE.
6. After login, client exchanges the code for an access token.
7. Client presents the access token on every MCP request.

## Requirements

- **ClickHouse protocol**: HTTP (port 8123 typically). Both Bearer and
  Basic routes use CH's HTTP interface; TCP/native has no equivalent.
- **ClickHouse build**:
  - Bearer: Altinity Antalya 25.8+ or any CH build with `token_processors`.
  - Basic: any build with `<http_authentication>` and `IDENTIFIED WITH http`
    (CH 24.x+ for OSS). Requires the `ch-jwt-verify` sidecar.
- **Identity Provider**: any OAuth 2.0 / OIDC-compliant IdP that supports
  the authorization-code flow.
- **`signing_secret`**: required when `broker: true`. Symmetric secret
  (≥ 32 bytes) for all stateless OAuth artifacts. Generate with
  `openssl rand -base64 32`.
- **Reverse proxy**: if published behind a proxy, set `public_resource_url`
  and `public_auth_server_url`. See
  [Frontend / Reverse Proxy](#frontend--reverse-proxy-requirements).

## Sidecar + ClickHouse-side config (Basic auth path)

If your ClickHouse uses the `ch-jwt-verify` sidecar, altinity-mcp will
detect and use Basic auth automatically. No MCP-side config change needed.

The sidecar deploys as a colocated container in the CH pod. See
[`altinity-oauth-helper`](https://github.com/altinity/altinity-oauth-helper)
for the full spec, helm chart, and wiring example.

ClickHouse registers the sidecar via a `config.d/` XML drop-in:

```xml
<clickhouse>
  <http_authentication_servers>
    <ch_jwt_verify>
      <uri>http://127.0.0.1:9999/verify</uri>
      <forward_headers>
        <header>Authorization</header>
      </forward_headers>
    </ch_jwt_verify>
  </http_authentication_servers>
</clickhouse>
```

Per-user provisioning:

```sql
CREATE ROLE IF NOT EXISTS mcp_reader;
GRANT SELECT ON analytics.* TO mcp_reader;

CREATE USER `alice@example.com`
  IDENTIFIED WITH http SERVER 'ch_jwt_verify' SCHEME 'BASIC'
  DEFAULT ROLE mcp_reader;
```

The grammar token is `http`, not `http_authenticator` — ClickHouse
rejects the latter with `SYNTAX_ERROR`. `SERVER 'ch_jwt_verify'` must
match the `<http_authentication_servers><ch_jwt_verify>` block name.

Identity policy (verified-email, domain allow-listing, user-vs-claim
match) lives in the sidecar's config:

```yaml
identity:
  username_claim: email
  match_mode: lowercase_equal
  require_email_verified: true
  allowed_email_domains: ["example.com"]
```

## ClickHouse `token_processors` (Bearer auth path)

If your ClickHouse uses `token_processors`, altinity-mcp will detect
Bearer auth automatically. No MCP-side config change needed.

### Generic OIDC (Keycloak, etc.)

```xml
<clickhouse>
    <token_processors>
        <my_oidc_provider>
            <type>openid</type>
            <configuration_endpoint>https://idp.example.com/.well-known/openid-configuration</configuration_endpoint>
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

Roles must exist before users can authenticate:

```sql
CREATE ROLE OR REPLACE default_role;
GRANT SELECT ON default.* TO default_role;
```

The default `<username_claim>` is `sub` — IdP users appear in
`system.processes` as numeric IDs. Set
`<username_claim>email</username_claim>` to attribute queries by email.

## Full configuration reference

```yaml
server:
  oauth:
    # Enable OAuth 2.0 authentication
    enabled: false

    # Canonical broker flag: MCP acts as AS to MCP clients (CIMD + /authorize
    # + /callback + /token) and brokers the upstream IdP. CH auth format
    # (Bearer vs Basic) is auto-detected on first request per endpoint.
    broker: true

    # Symmetric secret for stateless OAuth artifacts (authorization codes,
    # JWE-wrapped state, HKDF-derived signing material). Required when
    # broker: true. Minimum 32 bytes — generate with `openssl rand -base64 32`.
    signing_secret: ""

    # Upstream OAuth/OIDC issuer URL (used for discovery and token validation)
    issuer: ""

    # URL to fetch JWKS for token validation (discovered from issuer if omitted)
    jwks_url: ""

    # Expected audience claim in incoming tokens
    # (RFC 8707 byte-equality; trailing slash matters)
    audience: ""

    # Upstream OAuth client credentials. Required when broker: true.
    client_id: ""
    client_secret: ""
    token_url: ""
    auth_url: ""
    userinfo_url: ""

    # OAuth scopes to request from the upstream IdP
    scopes: ["openid", "profile", "email"]

    # Append offline_access to the upstream authorize scope so the IdP
    # consent screen offers long-lived sessions. v1 does NOT issue downstream
    # refresh tokens — clients re-authorize via /oauth/authorize on expiry.
    upstream_offline_access: false

    # Scopes required in every incoming bearer JWT
    required_scopes: []

    # Token lifetimes (broker mode)
    access_token_ttl_seconds: 3600
    refresh_token_ttl_seconds: 2592000   # 30 d

    # Externally visible MCP endpoint URL. Required behind a reverse proxy.
    public_resource_url: ""

    # Externally visible OAuth authorization server URL. Required behind
    # a reverse proxy when broker: true.
    public_auth_server_url: ""

    # Endpoint paths (defaults shown)
    authorization_path: "/authorize"
    callback_path: "/callback"
    token_path: "/token"
```

### Key options

| Option | Description |
|---|---|
| `broker` | `true`: MCP acts as the OAuth AS, brokers upstream IdP, auto-detects CH auth format. |
| `signing_secret` | Symmetric HKDF master secret for OAuth JWE artifacts. **Required** when `broker: true`. ≥ 32 bytes. |
| `issuer` | Upstream IdP issuer URL for OIDC discovery and token validation. |
| `audience` | RFC 8707 byte-equal target. Must match the JWT's `aud` claim byte-for-byte (trailing slashes count). |
| `public_resource_url` | Externally visible MCP endpoint URL. **Required** behind a reverse proxy. |
| `public_auth_server_url` | Externally visible OAuth AS URL. **Required** behind a reverse proxy when `broker: true`. |
| `upstream_offline_access` | Request `offline_access` upstream so the IdP consent screen offers long-lived sessions. Default `false`. |

## Provider-specific setup

### Keycloak

1. Create a realm and client in the Keycloak admin console:
   - Client Protocol: `openid-connect`
   - Access Type: `confidential`
   - Valid Redirect URIs: your MCP server's `<public>/oauth/callback`
   - Enable "Standard Flow"

2. MCP config:

   ```yaml
   server:
     oauth:
       enabled: true
       broker: true
       signing_secret: "<32-byte-random>"
       issuer:    "http://keycloak:8080/realms/mcp"
       audience:  "clickhouse-mcp"
       client_id: "clickhouse-mcp"
       client_secret: "<KEYCLOAK_CLIENT_SECRET>"
       auth_url:  "http://keycloak:8080/realms/mcp/protocol/openid-connect/auth"
       token_url: "http://keycloak:8080/realms/mcp/protocol/openid-connect/token"
       scopes: ["openid", "email"]
   ```

3. ClickHouse `token_processors` (if using Bearer):

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

See [zvonand/grafana-oauth](https://github.com/zvonand/grafana-oauth) for
a complete working example with Keycloak and ClickHouse.

### Azure AD (Microsoft Entra ID)

1. Register an application in the [Azure Portal](https://portal.azure.com):
   - Microsoft Entra ID → App registrations → New registration
   - Add a redirect URI: your MCP `<public>/oauth/callback`
   - Create a client secret under Certificates & secrets.
   - Configure API permissions: `openid`, `profile`, `email`.

2. MCP config:

   ```yaml
   server:
     oauth:
       enabled: true
       broker: true
       signing_secret: "<32-byte-random>"
       issuer:    "https://login.microsoftonline.com/<TENANT_ID>/v2.0"
       audience:  "<APP_CLIENT_ID>"
       client_id: "<APP_CLIENT_ID>"
       client_secret: "<APP_CLIENT_SECRET>"
       token_url: "https://login.microsoftonline.com/<TENANT_ID>/oauth2/v2.0/token"
       auth_url:  "https://login.microsoftonline.com/<TENANT_ID>/oauth2/v2.0/authorize"
       scopes: ["openid", "profile", "email"]
   ```

See [zvonand/grafana-oauth/azure](https://github.com/zvonand/grafana-oauth/tree/main/azure)
for a complete working example.

### Google Cloud Identity

1. Create OAuth 2.0 credentials in the [Google Cloud Console](https://console.cloud.google.com)
   under APIs & Services → Credentials → OAuth client ID → Web application.
   Set the authorized redirect URI to `<public>/oauth/callback`.

2. MCP config:

   ```yaml
   server:
     oauth:
       enabled: true
       broker: true
       signing_secret: "<32-byte-random>"
       issuer:    "https://accounts.google.com"
       audience:  "<GOOGLE_CLIENT_ID>.apps.googleusercontent.com"
       client_id: "<GOOGLE_CLIENT_ID>.apps.googleusercontent.com"
       client_secret: "<GOOGLE_CLIENT_SECRET>"
       token_url: "https://oauth2.googleapis.com/token"
       auth_url:  "https://accounts.google.com/o/oauth2/v2/auth"
       scopes: ["openid", "profile", "email"]
   ```

3. ClickHouse `token_processors` (if using Bearer):

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

References: [Google OpenID Connect](https://developers.google.com/identity/openid-connect/openid-connect),
[Using OAuth 2.0 to Access Google APIs](https://developers.google.com/identity/protocols/oauth2).

### AWS Cognito

1. Create a user pool in the [AWS Console](https://console.aws.amazon.com/cognito)
   with Authorization Code grant, scopes `openid profile email`, callback
   URL `<public>/oauth/callback`.

2. MCP config:

   ```yaml
   server:
     oauth:
       enabled: true
       broker: true
       signing_secret: "<32-byte-random>"
       issuer:    "https://cognito-idp.<REGION>.amazonaws.com/<USER_POOL_ID>"
       audience:  "<APP_CLIENT_ID>"
       client_id: "<APP_CLIENT_ID>"
       client_secret: "<APP_CLIENT_SECRET>"
       token_url: "https://<DOMAIN>.auth.<REGION>.amazoncognito.com/oauth2/token"
       auth_url:  "https://<DOMAIN>.auth.<REGION>.amazoncognito.com/oauth2/authorize"
       scopes: ["openid", "profile", "email"]
   ```

3. ClickHouse `token_processors` (if using Bearer):

   ```xml
   <token_processors>
       <cognito>
           <type>openid</type>
           <configuration_endpoint>https://cognito-idp.<REGION>.amazonaws.com/<USER_POOL_ID>/.well-known/openid-configuration</configuration_endpoint>
           <token_cache_lifetime>60</token_cache_lifetime>
       </cognito>
   </token_processors>
   ```

References: [Amazon Cognito - OIDC IdPs](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-oidc-idp.html).

## Helm chart deployment

```bash
helm install altinity-mcp ./helm/altinity-mcp \
  -f helm/altinity-mcp/values_examples/mcp-oauth-keycloak.yaml
```

- `values_examples/mcp-oauth-keycloak.yaml` — Keycloak / generic OIDC
- `values_examples/mcp-oauth-azure.yaml` — Azure AD
- `values_examples/mcp-oauth-google.yaml` — Google Cloud Identity

For the `ch-jwt-verify` sidecar path, also deploy from
[`altinity-oauth-helper`](https://github.com/altinity/altinity-oauth-helper)
into the ClickHouse pod.

## Frontend / Reverse Proxy Requirements

The proxy must expose two public URL spaces:

- the protected resource, e.g. `https://mcp.example.com/`
- the OAuth authorization server, e.g. `https://mcp.example.com/oauth`

The proxy must:

- Forward `Host` and `Authorization` headers unchanged
- Disable response buffering for MCP streaming
- Disable request buffering for long-lived POSTs
- Keep long read/send timeouts
- Not normalize or rewrite the configured callback or metadata paths

Example nginx fragment:

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

If the IdP reports `redirect_uri_mismatch`, verify the public callback
URL the browser sees exactly matches the URI registered at the IdP.

## Security considerations

- **`signing_secret`** protects all stateless OAuth artifacts. Treat it
  like a signing key. Rotate it to invalidate all outstanding tokens.
- **MCP holds no per-tenant ClickHouse credential.** The bearer is the
  upstream IdP's JWT; validation happens at ClickHouse (either
  `token_processors` or the `ch-jwt-verify` sidecar).
- **Opaque bearer tokens are not supported.** Inbound OAuth requires a
  signed JWT validatable via JWKS. RFC 7662 introspection is not
  implemented.
- **CIMD is the only inbound registration model.** Dynamic Client
  Registration (DCR, RFC 7591) is intentionally not exposed —
  `/oauth/register` returns HTTP 410 Gone.
- **Token preference.** When both `id_token` and `access_token` come back
  from the upstream, altinity-mcp prefers `id_token` and falls back to
  `access_token` only when no `id_token` is available.

## Troubleshooting

### ClickHouse returns HTTP 403 with `Bearer HTTP Authorization scheme is not supported`

The CH build does not support `token_processors`. altinity-mcp will
automatically fall back to Basic auth if the `ch-jwt-verify` sidecar is
running. If neither is configured, upgrade to Altinity Antalya 25.8+ or
deploy [`altinity-oauth-helper`](https://github.com/altinity/altinity-oauth-helper).

### Token validation fails with `issuer mismatch`

`oauth.issuer` doesn't exactly match the `iss` claim. Common causes:

- Trailing slash mismatch (`https://idp.example.com` vs
  `https://idp.example.com/`).
- Missing `/v2.0` suffix for Azure AD.
- Wrong realm path for Keycloak.

### `oauth: bearer is not a JWT with an email claim`

The JWT's top-level `email` claim is missing. Some IdPs strip standard
OIDC claims for third-party clients. Configure a post-login action that
injects `https://<your-namespace>/email` into the access token —
altinity-mcp reads any claim with a `/email` suffix as a fallback.

### ClickHouse authenticates but the user has no permissions

Create the roles and grant them the necessary permissions:

```sql
CREATE ROLE OR REPLACE default_role;
GRANT SELECT ON *.* TO default_role;
```

For the sidecar path, also verify the user exists:
`CREATE USER "alice@example.com" IDENTIFIED WITH http SERVER 'ch_jwt_verify' SCHEME 'BASIC'`.

### `block decode for exception: unexpected value 10 for boolean`

A `FORMAT JSON` (or similar) suffix in the SQL — the driver speaks native
binary over HTTP and the format override makes ClickHouse return text.
Drop the `FORMAT` clause.

### More troubleshooting

For sidecar-specific errors (JWKS rotation, audience byte-equality,
sidecar binding gotchas) see the
[`altinity-oauth-helper`](https://github.com/altinity/altinity-oauth-helper)
repo's troubleshooting section.

## Deprecated fields

The following config fields still work but log a deprecation warning at
startup. Migrate by replacing them with `broker: true`.

| Deprecated | Replacement |
|---|---|
| `mode: forward` | `broker: true` |
| `mode: gating` + `broker_upstream: true` | `broker: true` |
| `mode: gating` (no broker) | `broker: false` (default) — MCP is a pure resource server; the upstream IdP must support CIMD natively |

When `mode: forward` or `broker_upstream: true` is set, the startup log
will contain:
```
oauth.mode=forward and oauth.broker_upstream are deprecated; use oauth.broker: true instead
```
