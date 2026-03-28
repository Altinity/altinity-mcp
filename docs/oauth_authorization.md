# OAuth 2.0 Authorization for Altinity MCP Server

This document explains how to configure OAuth 2.0 / OpenID Connect (OIDC) authentication with the Altinity MCP Server. It covers both:

- bearer-token validation at the MCP layer
- optional forwarding of bearer tokens to ClickHouse for `token_processors`-based authentication

## Overview

OAuth 2.0 authorization supports two related workflows.

### 1. MCP-only OAuth gating

1. An MCP client authenticates with an Identity Provider (IdP) and obtains a token
2. The MCP client sends the token to the MCP server in the `Authorization: Bearer {token}` header
3. The MCP server validates the token claims
4. The MCP server connects to ClickHouse with its configured credentials

This mode works even when ClickHouse has no native OAuth support.

### 2. OAuth plus ClickHouse token forwarding

1. An MCP client authenticates with an Identity Provider (IdP) and obtains a token
2. The MCP client sends the token to the MCP server in the `Authorization: Bearer {token}` header
3. The MCP server validates the token claims
4. The MCP server forwards the token to ClickHouse via HTTP headers
5. ClickHouse validates the token using `token_processors` and authenticates the user

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

## Requirements

- **ClickHouse**: Altinity Antalya build 25.8+ (or any Altinity stable build that supports `token_processors`)
- **ClickHouse protocol**:
  - MCP-only OAuth gating works with both `http` and native `tcp`
  - OAuth token forwarding to ClickHouse requires `http`
- **Identity Provider**: Any OAuth 2.0 / OIDC-compliant provider (Keycloak, Azure AD, Google, AWS Cognito, etc.)
- **Frontend / reverse proxy**: If `altinity-mcp` is published behind nginx, ingress, xray, or another frontend, the proxy must preserve the public OAuth URLs and required forwarded headers. Browser-based MCP login will fail if the proxy rewrites callback or discovery URLs incorrectly.

## Frontend / Reverse Proxy Requirements

For direct bearer-token use, a plain reverse proxy is usually enough.

For browser-based MCP login, the frontend must expose two public URL spaces:

- the protected resource, for example `https://welcome.ru/http`
- the OAuth authorization server, for example `https://welcome.ru/oauth`

The proxy must preserve these semantics:

- `https://PUBLIC_HOST/http` must reach the MCP streamable HTTP endpoint
- `https://PUBLIC_HOST/http/.well-known/oauth-protected-resource` must return protected-resource metadata
- `https://PUBLIC_HOST/oauth/.well-known/oauth-authorization-server` and `https://PUBLIC_HOST/oauth/.well-known/openid-configuration` must return authorization-server metadata
- `https://PUBLIC_HOST/oauth/callback` must round-trip exactly to the upstream IdP redirect URI you register

Required forwarded headers for the split-path setup implemented in this repo:

- `Host`
- `Authorization`
- `X-Forwarded-Proto`
- `X-Forwarded-Prefix`
- `X-Forwarded-OAuth-Prefix`

Recommended proxy behavior:

- disable response buffering for MCP streaming
- disable request buffering for long-lived POSTs
- keep long read/send timeouts
- do not normalize or rewrite the configured callback or metadata paths

Example nginx shape:

```nginx
location ^~ /http {
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header X-Forwarded-Prefix /http;
    proxy_set_header X-Forwarded-OAuth-Prefix /oauth;
    proxy_set_header Authorization $http_authorization;
    proxy_buffering off;
    proxy_request_buffering off;
    proxy_read_timeout 3600;
    proxy_send_timeout 3600;
    proxy_pass http://ALTINITY_MCP_UPSTREAM;
}

location ^~ /oauth/ {
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header X-Forwarded-Prefix /oauth;
    proxy_set_header Authorization $http_authorization;
    proxy_buffering off;
    proxy_request_buffering off;
    proxy_read_timeout 3600;
    proxy_send_timeout 3600;
    rewrite ^/oauth/(.*)$ /$1 break;
    proxy_pass http://ALTINITY_MCP_UPSTREAM;
}
```

Notes:

- The server can now use explicit public URLs and endpoint paths from config instead of inferring everything from forwarded headers.
- If `public_resource_url` and `public_auth_server_url` are omitted, the implementation still falls back to request host plus forwarded-prefix headers.
- If Google or another IdP reports `redirect_uri_mismatch`, verify the public callback URL seen by the browser exactly matches the URI registered at the IdP.

## Command Line Options

```
--oauth-clear-clickhouse-credentials    Clear ClickHouse credentials when forwarding OAuth token
```

Environment variable:

```
OAUTH_CLEAR_CLICKHOUSE_CREDENTIALS=true
```

All other OAuth options are configured via the YAML config file.

## altinity-mcp Configuration File example

Add the `oauth` section under `server` in your config file:

```yaml
server:
  oauth:
    enabled: true
    issuer: "https://welcome.ru/oauth"
    audience: "https://welcome.ru/http"
    public_resource_url: "https://welcome.ru/http"
    public_auth_server_url: "https://welcome.ru/oauth"
    authorization_path: "/authorize"
    callback_path: "/callback"
    token_path: "/token"
    forward_to_clickhouse: false
    forward_access_token: false
    clear_clickhouse_credentials: false
```

### Full OAuth Configuration Reference

```yaml
server:
  oauth:
    # Enable OAuth 2.0 authentication
    enabled: false

    # OAuth token issuer URL for validation
    # Used to verify the "iss" claim in incoming tokens
    issuer: ""

    # URL to fetch JWKS for token signature validation
    # If empty, discovered from issuer's .well-known/openid-configuration
    jwks_url: ""

    # Expected audience claim in the token
    audience: ""

    # Optional externally visible protected-resource base URL
    # Used for protected-resource metadata and bearer challenges
    public_resource_url: ""

    # Optional externally visible authorization-server base URL
    # Used for OAuth/OpenID metadata and browser-based login
    public_auth_server_url: ""

    # OAuth client ID (for client credentials flow or validation)
    client_id: ""

    # OAuth client secret (for client credentials flow)
    client_secret: ""

    # OAuth token endpoint URL
    token_url: ""

    # OAuth authorization endpoint URL
    auth_url: ""

    # Relative path under public_resource_url for OAuth protected-resource metadata
    protected_resource_metadata_path: "/.well-known/oauth-protected-resource"

    # Relative path under public_auth_server_url for OAuth authorization-server metadata
    authorization_server_metadata_path: "/.well-known/oauth-authorization-server"

    # Relative path under public_auth_server_url for OpenID configuration
    openid_configuration_path: "/.well-known/openid-configuration"

    # Relative path under public_auth_server_url for dynamic client registration
    registration_path: "/oauth/register"

    # Relative path under public_auth_server_url for authorization
    authorization_path: "/oauth/authorize"

    # Relative path under public_auth_server_url for upstream IdP callback
    callback_path: "/oauth/callback"

    # Relative path under public_auth_server_url for token exchange
    token_path: "/oauth/token"

    # OAuth scopes to request
    scopes:
      - "openid"
      - "profile"
      - "email"

    # Required scopes - token must have ALL of these to be accepted
    required_scopes: []

    # Allowed upstream IdP issuers for the identity token returned by the upstream provider
    # Defaults to Google issuers when empty
    upstream_issuer_allowlist: []

    # Internal token/code TTLs used by the built-in browser-login facade
    auth_code_ttl_seconds: 300
    access_token_ttl_seconds: 3600
    refresh_token_ttl_seconds: 2592000

    # Forward the OAuth token to ClickHouse via HTTP headers
    forward_to_clickhouse: true

    # Header name for forwarding the token
    # Default: "Authorization" (sends as "Bearer {token}")
    # Set to a custom name (e.g. "X-ClickHouse-Token") to send raw token
    clickhouse_header_name: ""

    # Forward the raw access token (required for ClickHouse token_processors)
    forward_access_token: true

    # Clear ClickHouse username/password when forwarding OAuth token
    # Required when ClickHouse authenticates via token_processors,
    # where user identity comes from the token's "sub" claim
    clear_clickhouse_credentials: true

    # Map specific token claims to ClickHouse HTTP headers
    claims_to_headers:
      sub: "X-ClickHouse-User"
      email: "X-ClickHouse-Email"
```

### Key Options Explained

| Option | Description |
|--------|-------------|
| `forward_to_clickhouse` | Enables token forwarding to ClickHouse |
| `forward_access_token` | Sends the raw access token (not just claims) |
| `clear_clickhouse_credentials` | Removes username/password from requests to ClickHouse. **Required** when ClickHouse uses `token_processors` because it must authenticate the user from the token, not from basic auth |
| `clickhouse_header_name` | Controls the HTTP header used for forwarding. Default is `Authorization` which sends `Bearer {token}`. Set to any custom header to send the raw token |
| `public_resource_url` | Externally visible MCP protected-resource base URL |
| `public_auth_server_url` | Externally visible OAuth authorization-server base URL |
| `protected_resource_metadata_path` | Relative path for protected-resource metadata |
| `authorization_server_metadata_path` | Relative path for OAuth authorization-server metadata |
| `openid_configuration_path` | Relative path for OpenID configuration |
| `registration_path` | Relative path for dynamic client registration |
| `authorization_path` | Relative path for the authorization endpoint |
| `callback_path` | Relative path for the upstream IdP callback handler |
| `token_path` | Relative path for the token endpoint |
| `upstream_issuer_allowlist` | Allowed issuers for upstream identity tokens returned during callback exchange |
| `auth_code_ttl_seconds` | Lifetime of internal authorization codes minted by `altinity-mcp` |
| `access_token_ttl_seconds` | Lifetime of internal MCP access tokens minted by `altinity-mcp` |
| `refresh_token_ttl_seconds` | Lifetime of internal MCP refresh tokens minted by `altinity-mcp` |

## Browser-Based MCP Login

When the server is published over HTTP/S behind a public frontend, `altinity-mcp` can expose:

- protected-resource metadata for the MCP endpoint
- authorization-server metadata for OAuth-capable MCP clients
- a small authorization facade that redirects to an upstream IdP and mints MCP access tokens after login

For the current `welcome.ru` layout, the typical public URLs are:

- protected resource: `https://welcome.ru/http`
- protected-resource metadata: `https://welcome.ru/http/.well-known/oauth-protected-resource`
- authorization server: `https://welcome.ru/oauth`
- authorization-server metadata: `https://welcome.ru/oauth/.well-known/oauth-authorization-server`
- OpenID configuration: `https://welcome.ru/oauth/.well-known/openid-configuration`
- callback registered at Google: `https://welcome.ru/oauth/callback`

Minimal config for that shape:

```yaml
server:
  oauth:
    enabled: true
    issuer: "https://welcome.ru/oauth"
    audience: "https://welcome.ru/http"
    public_resource_url: "https://welcome.ru/http"
    public_auth_server_url: "https://welcome.ru/oauth"
    protected_resource_metadata_path: "/.well-known/oauth-protected-resource"
    authorization_server_metadata_path: "/.well-known/oauth-authorization-server"
    openid_configuration_path: "/.well-known/openid-configuration"
    registration_path: "/register"
    authorization_path: "/authorize"
    callback_path: "/callback"
    token_path: "/token"
    upstream_issuer_allowlist:
      - "accounts.google.com"
      - "https://accounts.google.com"
    client_id: "YOUR_GOOGLE_WEB_CLIENT.apps.googleusercontent.com"
    client_secret: "YOUR_GOOGLE_CLIENT_SECRET"
    auth_url: "https://accounts.google.com/o/oauth2/v2/auth"
    token_url: "https://oauth2.googleapis.com/token"
    scopes: ["openid", "email"]
    required_scopes: ["openid"]
    auth_code_ttl_seconds: 300
    access_token_ttl_seconds: 3600
    refresh_token_ttl_seconds: 2592000
    forward_to_clickhouse: false
    forward_access_token: false
    clear_clickhouse_credentials: false
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
            <!-- Optional: transform group names to ClickHouse role names -->
            <roles_transform>s/-/_/g</roles_transform>
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
-- Create a role for token-authenticated users
CREATE ROLE OR REPLACE default_role;

-- Grant permissions
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
    issuer: "http://keycloak:8080/realms/mcp"
    audience: "clickhouse-mcp"
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
- Enable the OAuth 2.0 grant types you need (Authorization Code, Implicit)
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

## MCP Client Integration

Any MCP-compatible client (AI agent, IDE plugin, CLI tool, etc.) can use OAuth token forwarding:

1. Configure the MCP client to authenticate with your OAuth provider
2. The MCP client sends the access token in the `Authorization: Bearer {token}` header
3. The MCP server validates the token and forwards it to ClickHouse
4. ClickHouse authenticates the user via `token_processors`


## Troubleshooting

### ClickHouse returns HTTP 403 with "Bearer HTTP Authorization scheme is not supported"

Your ClickHouse build does not support `token_processors`. You need the Altinity Antalya build 25.8+ or a compatible ClickHouse version.

### Token validation fails with "issuer mismatch"

Ensure the `issuer` in your MCP config matches exactly what your IdP puts in the `iss` claim. Common issues:
- Trailing slash mismatch (`https://accounts.google.com` vs `https://accounts.google.com/`)
- Missing `/v2.0` suffix for Azure AD

### ClickHouse authenticates but user has no permissions

Create the roles referenced in `common_roles` and grant them the necessary permissions:

```sql
CREATE ROLE OR REPLACE default_role;
GRANT SELECT ON *.* TO default_role;
```

### Token forwarding works but ClickHouse rejects the user

Ensure `clear_clickhouse_credentials: true` is set. When ClickHouse receives both a username/password (basic auth) and a Bearer token, the basic auth may take precedence and fail.
