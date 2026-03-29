# OAuth 2.0 Authorization for Altinity MCP Server

This document explains how to configure OAuth 2.0 / OpenID Connect (OIDC) authentication with the Altinity MCP Server.

## Quick Start

### Forward mode: ClickHouse validates tokens via token_processors

Use this when ClickHouse has native OAuth support (Altinity Antalya 25.8+). The MCP server passes the bearer token through; ClickHouse validates it.

```yaml
server:
  oauth:
    enabled: true
    mode: "forward"
    gating_secret_key: "CHANGE_ME_TO_A_RANDOM_SECRET"
    issuer: "https://accounts.google.com"
    client_id: "<YOUR_CLIENT_ID>"
    client_secret: "<YOUR_CLIENT_SECRET>"
    scopes: ["openid", "email"]
    forward_to_clickhouse: true
    forward_access_token: true
    clear_clickhouse_credentials: true
```

### Gating mode: MCP server validates tokens locally

Use this when ClickHouse has no OAuth support. The MCP server authenticates users via the upstream IdP, mints its own tokens, and connects to ClickHouse with static credentials.

```yaml
server:
  oauth:
    enabled: true
    mode: "gating"
    gating_secret_key: "CHANGE_ME_TO_A_RANDOM_SECRET"
    issuer: "https://accounts.google.com"
    public_auth_server_url: "https://mcp.example.com"
    client_id: "<YOUR_CLIENT_ID>"
    client_secret: "<YOUR_CLIENT_SECRET>"
    scopes: ["openid", "email"]
    allowed_email_domains: ["example.com"]
```

## Overview

OAuth 2.0 authorization supports two modes.

### Forward mode

1. An MCP client sends a bearer token to the MCP server
2. The MCP server requires that a bearer token is present (it does **not** validate the token locally)
3. The MCP server forwards the token to ClickHouse via HTTP headers
4. ClickHouse validates the token using `token_processors` and authenticates the user

```
MCP Client ──Bearer token──> MCP Server ──Bearer token──> ClickHouse
                                                          (validates via
                                                           OIDC/JWKS)
```

### Gating mode

1. An MCP client authenticates with an Identity Provider (IdP) via browser login
2. The MCP server validates the upstream identity, then mints its own signed access and refresh tokens
3. The MCP server connects to ClickHouse with its statically configured credentials

This mode works even when ClickHouse has no native OAuth support.

## Requirements

- **ClickHouse protocol**: Forward mode requires `http`. Gating mode works with both `http` and native `tcp`.
- **ClickHouse version**: Forward mode requires Altinity Antalya build 25.8+ (or any build that supports `token_processors`). Gating mode works with any ClickHouse version.
- **Identity Provider**: Any OAuth 2.0 / OIDC-compliant provider (Keycloak, Azure AD, Google, AWS Cognito, etc.)
- **`gating_secret_key`**: Required in both modes. Protects stateless client registration, authorization codes, and (in gating mode) refresh tokens.
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

## Refresh Tokens (Gating Mode)

In gating mode, the token endpoint returns a `refresh_token` alongside the `access_token`. Clients can exchange it via `grant_type=refresh_token` to get a new access token without re-authorizing through the browser.

- **TTL**: Controlled by `refresh_token_ttl_seconds` (default: 30 days)
- **Rotation**: Each refresh returns a new refresh token (the old one remains valid until expiry)
- **Stateless**: Refresh tokens are encrypted JWE blobs with no server-side state. There is no revocation or reuse detection.
- **Forward mode**: Does not issue refresh tokens. The upstream IdP controls token lifecycle.

Deployments that require token revocation should use forward mode with an IdP that supports it.

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
    gating_secret_key: ""

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

    # Scopes required in incoming tokens (gating mode only)
    required_scopes: []

    # Allowed upstream IdP issuers for identity tokens during callback exchange
    upstream_issuer_allowlist: []

    # Identity policy (gating mode)
    allowed_email_domains: []
    allowed_hosted_domains: []
    require_email_verified: false

    # Token/code lifetimes
    auth_code_ttl_seconds: 300        # 5 minutes
    access_token_ttl_seconds: 3600    # 1 hour
    refresh_token_ttl_seconds: 2592000 # 30 days (gating mode only)

    # Forward bearer token to ClickHouse via HTTP headers (forward mode)
    forward_to_clickhouse: true
    forward_access_token: true
    clear_clickhouse_credentials: true

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

    # Endpoint paths (defaults shown; override for custom proxy layouts)
    protected_resource_metadata_path: "/.well-known/oauth-protected-resource"
    authorization_server_metadata_path: "/.well-known/oauth-authorization-server"
    openid_configuration_path: "/.well-known/openid-configuration"
    registration_path: "/register"
    authorization_path: "/authorize"
    callback_path: "/callback"
    token_path: "/token"
```

### Key Options Explained

| Option | Description |
|--------|-------------|
| `mode` | `forward` passes tokens to ClickHouse for validation; `gating` validates upstream identity and mints local tokens |
| `gating_secret_key` | Symmetric secret for all stateless OAuth artifacts. **Required** whenever OAuth is enabled |
| `issuer` | Upstream IdP issuer URL for OIDC discovery and token validation |
| `forward_to_clickhouse` | Forward the bearer token to ClickHouse via HTTP headers |
| `forward_access_token` | Send the raw access token (required for ClickHouse `token_processors`) |
| `clear_clickhouse_credentials` | Remove static username/password when forwarding. **Required** for `token_processors` |
| `public_resource_url` | Externally visible MCP endpoint URL. **Required** behind a reverse proxy |
| `public_auth_server_url` | Externally visible OAuth authorization server URL. **Required** behind a reverse proxy |
| `refresh_token_ttl_seconds` | Lifetime of stateless refresh tokens in gating mode (default 30 days) |

## Command Line Options

```
--oauth-clear-clickhouse-credentials    Clear ClickHouse credentials when forwarding OAuth token
```

Environment variable: `OAUTH_CLEAR_CLICKHOUSE_CREDENTIALS=true`

All other OAuth options are configured via the YAML config file.

## Frontend / Reverse Proxy Requirements

For direct bearer-token use, a plain reverse proxy is usually enough.

For browser-based MCP login, the frontend must expose two public URL spaces:

- the protected resource, for example `https://PUBLIC_HOST.example.com/http-t`
- the OAuth authorization server, for example `https://PUBLIC_HOST.example.com/oauth-t`

The proxy must:

- Forward `Host` and `Authorization` headers unchanged
- Disable response buffering for MCP streaming
- Disable request buffering for long-lived POSTs
- Keep long read/send timeouts
- Not normalize or rewrite the configured callback or metadata paths
- Not rely on forwarded-prefix headers; configure the public OAuth URLs explicitly in `altinity-mcp`

Example nginx configuration:

```nginx
location ^~ /http-t {
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header Authorization $http_authorization;
    proxy_buffering off;
    proxy_request_buffering off;
    proxy_read_timeout 3600;
    proxy_send_timeout 3600;
    proxy_pass http://ALTINITY_MCP_UPSTREAM;
}

location ^~ /oauth-t/ {
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header Authorization $http_authorization;
    proxy_buffering off;
    proxy_request_buffering off;
    proxy_read_timeout 3600;
    proxy_send_timeout 3600;
    rewrite ^/oauth-t/(.*)$ /$1 break;
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
    gating_secret_key: "CHANGE_ME_TO_A_RANDOM_SECRET"
    issuer: "https://accounts.google.com"
    audience: "https://PUBLIC_HOST.example.com/http-t"
    public_resource_url: "https://PUBLIC_HOST.example.com/http-t"
    public_auth_server_url: "https://PUBLIC_HOST.example.com/oauth-t"
    client_id: "YOUR_GOOGLE_WEB_CLIENT.apps.googleusercontent.com"
    client_secret: "YOUR_GOOGLE_CLIENT_SECRET"
    scopes: ["openid", "email"]
    forward_to_clickhouse: true
    forward_access_token: true
    clear_clickhouse_credentials: true
```

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
    gating_secret_key: "CHANGE_ME_TO_A_RANDOM_SECRET"
    issuer: "http://keycloak:8080/realms/mcp"
    audience: "clickhouse-mcp"
    client_id: "clickhouse-mcp"
    client_secret: "<KEYCLOAK_CLIENT_SECRET>"
    scopes: ["openid", "email"]
    forward_to_clickhouse: true
    forward_access_token: true
    clear_clickhouse_credentials: true
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
    gating_secret_key: "CHANGE_ME_TO_A_RANDOM_SECRET"
    issuer: "https://login.microsoftonline.com/<TENANT_ID>/v2.0"
    audience: "<APPLICATION_CLIENT_ID>"
    client_id: "<APPLICATION_CLIENT_ID>"
    client_secret: "<APPLICATION_CLIENT_SECRET>"
    token_url: "https://login.microsoftonline.com/<TENANT_ID>/oauth2/v2.0/token"
    auth_url: "https://login.microsoftonline.com/<TENANT_ID>/oauth2/v2.0/authorize"
    scopes: ["openid", "profile", "email"]
    forward_to_clickhouse: true
    forward_access_token: true
    clear_clickhouse_credentials: true
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
    gating_secret_key: "CHANGE_ME_TO_A_RANDOM_SECRET"
    issuer: "https://accounts.google.com"
    audience: "<GOOGLE_CLIENT_ID>.apps.googleusercontent.com"
    client_id: "<GOOGLE_CLIENT_ID>.apps.googleusercontent.com"
    client_secret: "<GOOGLE_CLIENT_SECRET>"
    token_url: "https://oauth2.googleapis.com/token"
    auth_url: "https://accounts.google.com/o/oauth2/v2/auth"
    scopes: ["openid", "profile", "email"]
    forward_to_clickhouse: true
    forward_access_token: true
    clear_clickhouse_credentials: true
```

#### 3. ClickHouse Configuration

Google uses the standard `openid` token processor type:

```xml
<token_processors>
    <google>
        <type>openid</type>
        <configuration_endpoint>https://accounts.google.com/.well-known/openid-configuration</configuration_endpoint>
        <token_cache_lifetime>60</token_cache_lifetime>
    </google>
</token_processors>
```

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
    gating_secret_key: "CHANGE_ME_TO_A_RANDOM_SECRET"
    issuer: "https://cognito-idp.<REGION>.amazonaws.com/<USER_POOL_ID>"
    audience: "<APP_CLIENT_ID>"
    client_id: "<APP_CLIENT_ID>"
    client_secret: "<APP_CLIENT_SECRET>"
    token_url: "https://<DOMAIN>.auth.<REGION>.amazoncognito.com/oauth2/token"
    auth_url: "https://<DOMAIN>.auth.<REGION>.amazoncognito.com/oauth2/authorize"
    scopes: ["openid", "profile", "email"]
    forward_to_clickhouse: true
    forward_access_token: true
    clear_clickhouse_credentials: true
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

- **`gating_secret_key`** protects all stateless OAuth artifacts (client registrations, authorization codes, refresh tokens). Treat it like a signing key. Rotate it to invalidate all outstanding registrations and tokens.
- **Forward mode does not validate tokens locally.** It checks only that a bearer token is present, then forwards it to ClickHouse. Token validation is ClickHouse's responsibility via `token_processors`.
- **Gating-mode refresh tokens are stateless.** There is no server-side state, so individual tokens cannot be revoked. The only way to invalidate all tokens is to rotate `gating_secret_key`. Use `refresh_token_ttl_seconds` to limit exposure.
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

### Token forwarding works but ClickHouse rejects the user

Ensure `clear_clickhouse_credentials: true` is set. When ClickHouse receives both a username/password (basic auth) and a Bearer token, the basic auth may take precedence and fail.

### Startup warning: "forward mode is enabled but forward_to_clickhouse is false"

Forward mode without token forwarding means tokens are accepted by presence only but not sent to ClickHouse. Requests run as the statically configured ClickHouse user. This is almost certainly a misconfiguration. Either enable `forward_to_clickhouse: true` or switch to gating mode.

## Automated ClickHouse OAuth E2E Test

The automated ClickHouse OAuth test suite uses:

- Keycloak as the OIDC provider
- `altinity/clickhouse-server:25.8.16.20001.altinityantalya`
- real ClickHouse `token_processors` plus `user_directories` token auth
- `altinity-mcp` with bearer-token forwarding enabled

Run the E2E test explicitly:

```bash
RUN_OAUTH_E2E=1 go test ./pkg/server -run TestOAuthE2EWithKeycloak -count=1 -v
```

The test is skipped by default unless `RUN_OAUTH_E2E=1` is set, and it is also skipped in `go test -short`.

The Antalya image is required because standard upstream ClickHouse images do not provide the `token_processors` support needed for bearer-token authentication.
