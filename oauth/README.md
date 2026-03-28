# OAuth MCP Development via `welcome.ru`

This harness is for local-first development of `altinity-mcp` OAuth support with Codex browser login.

## What This Setup Does

- Runs a freshly built `altinity-mcp` locally on `0.0.0.0:18080`
- Exposes it publicly through nginx on `https://welcome.ru`
- Serves the MCP endpoint under `https://welcome.ru/http`
- Serves OAuth discovery and auth endpoints under `https://welcome.ru/oauth/`
- Uses the local `demo` ClickHouse connection without JWE
- Uses Codex as the OAuth client via `codex mcp login`
- Uses Google only as the upstream identity provider
- Issues MCP access tokens from `altinity-mcp` itself so Codex can complete MCP OAuth

## Important URLs

- Public MCP base: `https://welcome.ru/http`
- Public OAuth base: `https://welcome.ru/oauth/`
- OAuth callback for Google app: `https://welcome.ru/oauth/callback`
- Protected resource metadata: `https://welcome.ru/http/.well-known/oauth-protected-resource`
- Authorization server metadata: `https://welcome.ru/oauth/.well-known/oauth-authorization-server`

## Google Project

Create or reuse a long-lived project under folder `246059149080`.

Recommended project:

```bash
gcloud projects create altinity-mcp-oauth-test \
  --name="altinity-mcp-oauth-test" \
  --folder=246059149080
gcloud config set project altinity-mcp-oauth-test
```

Create a Google Auth Platform web client with redirect URI:

```bash
https://welcome.ru/oauth/callback
```

Keep these values available:

- `GOOGLE_OAUTH_CLIENT_ID`
- `GOOGLE_OAUTH_CLIENT_SECRET`

In Google Auth Platform console:

1. Configure Branding
2. Set Audience to `External`
3. Add test users from both `@altinity.com` and Gmail
4. Keep scopes minimal: `openid`, `email`

## Local Files

Required environment variables for scripts:

```bash
export GOOGLE_OAUTH_CLIENT_ID='...'
export GOOGLE_OAUTH_CLIENT_SECRET='...'
export CLICKHOUSE_HOST='...'
export CLICKHOUSE_PORT='9440'
export CLICKHOUSE_DATABASE='default'
export CLICKHOUSE_USERNAME='...'
export CLICKHOUSE_PASSWORD='...'
export CLICKHOUSE_PROTOCOL='tcp'
export MCP_TARGET_HOST='welcome.ru'
export MCP_PUBLIC_MCP_PREFIX='/http'
export MCP_PUBLIC_OAUTH_PREFIX='/oauth'
```

Optional:

```bash
export CLICKHOUSE_READ_ONLY='true'
export JWT_SECRET_KEY=''
export MCP_NAME='altinity_mcp_oauth'
```

## nginx Requirements

`welcome.ru` must reverse-proxy both `/http` and `/oauth/` to your local machine.

Minimum requirements:

- preserve `Host`
- set `X-Forwarded-Proto https`
- set `X-Forwarded-Prefix`
- set `X-Forwarded-OAuth-Prefix`
- forward `Authorization`
- support long-lived HTTP streaming
- disable buffering for both request and response bodies

For the current implementation, these public URLs must work exactly:

- `https://welcome.ru/http`
- `https://welcome.ru/http/.well-known/oauth-protected-resource`
- `https://welcome.ru/oauth/.well-known/oauth-authorization-server`
- `https://welcome.ru/oauth/.well-known/openid-configuration`
- `https://welcome.ru/oauth/callback`

If any frontend rewrites or normalizes these paths, Codex browser login will fail.

Example:

```nginx
server {
    server_name welcome.ru;

    location ^~ /http {
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-Prefix /http;
        proxy_set_header X-Forwarded-OAuth-Prefix /oauth;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Authorization $http_authorization;
        proxy_buffering off;
        proxy_request_buffering off;
        proxy_read_timeout 3600;
        proxy_send_timeout 3600;
        proxy_pass http://YOUR_LOCAL_IP:18080;
    }

    location ^~ /oauth/ {
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-Prefix /oauth;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Authorization $http_authorization;
        proxy_buffering off;
        proxy_request_buffering off;
        proxy_read_timeout 3600;
        proxy_send_timeout 3600;
        rewrite ^/oauth/(.*)$ /$1 break;
        proxy_pass http://YOUR_LOCAL_IP:18080;
    }
}
```

Also add exact-location routes for the well-known aliases if your frontend does not naturally pass them through:

- `/.well-known/oauth-protected-resource/http`
- `/.well-known/oauth-authorization-server/http`
- `/.well-known/openid-configuration/http`
- `/.well-known/oauth-authorization-server/oauth`
- `/.well-known/openid-configuration/oauth`

The working nginx example for this repo is in [nginx-welcome.ru-split-paths.conf](/Users/bvt/work/altinity-mcp/oauth/nginx-welcome.ru-split-paths.conf).

## Local Development Workflow

1. Start local MCP:

```bash
oauth/start-local.sh
```

2. Register the MCP server with Codex:

```bash
oauth/register-codex.sh
```

3. Login through the browser:

```bash
oauth/test-codex.sh
```

This runs:

- `codex mcp login <name>`
- `codex exec "select version()"`

## Helm Validation Later

After the local public-host flow works, validate the same config on Kubernetes:

```bash
oauth/start-k8s.sh
```

This uses:

- `KUBECONFIG=$HOME/.kube/aw-demo.config`
- namespace `demo`

## OAuth Config

The harness now uses explicit public URL and path settings instead of inferring everything from `issuer` and `audience`.

Key fields:

- `issuer`
  The issuer claim to validate on inbound OAuth tokens. For the local Codex flow this should match the public auth server base, for example `https://welcome.ru/oauth`.
- `audience`
  The audience claim to validate on inbound OAuth tokens and the default audience for minted MCP access tokens. For the local Codex flow this should match `https://welcome.ru/http`.
- `public_resource_url`
  The externally visible protected resource base URL advertised in `/.well-known/oauth-protected-resource`.
- `public_auth_server_url`
  The externally visible OAuth authorization server base URL advertised in metadata responses.
- `protected_resource_metadata_path`
  Relative path under `public_resource_url` for resource metadata.
- `authorization_server_metadata_path`
  Relative path under `public_auth_server_url` for authorization server metadata.
- `openid_configuration_path`
  Relative path under `public_auth_server_url` for OpenID configuration.
- `registration_path`
  Relative path under `public_auth_server_url` for dynamic client registration.
- `authorization_path`
  Relative path under `public_auth_server_url` for the authorization endpoint.
- `callback_path`
  Relative path under `public_auth_server_url` for the upstream Google callback handler.
- `token_path`
  Relative path under `public_auth_server_url` for the token endpoint.
- `upstream_issuer_allowlist`
  Accepted upstream identity token issuers during Google callback exchange.
- `auth_code_ttl_seconds`
  Lifetime of internal authorization codes minted by `altinity-mcp`.
- `access_token_ttl_seconds`
  Lifetime of MCP access tokens minted by `altinity-mcp`.
- `refresh_token_ttl_seconds`
  Lifetime of MCP refresh tokens minted by `altinity-mcp`.

Minimal config for the current `welcome.ru` split-path setup:

```yaml
server:
  transport: http
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
    client_id: "YOUR_WEB_CLIENT.apps.googleusercontent.com"
    client_secret: "YOUR_CLIENT_SECRET"
    auth_url: "https://accounts.google.com/o/oauth2/v2/auth"
    token_url: "https://oauth2.googleapis.com/token"
    scopes: ["openid", "email"]
    required_scopes: ["openid"]
    auth_code_ttl_seconds: 300
    access_token_ttl_seconds: 3600
    refresh_token_ttl_seconds: 2592000
```

## Notes

- This repo now exposes MCP OAuth discovery and a test-oriented auth server facade.
- Google is only the upstream login provider.
- MCP access tokens are minted by `altinity-mcp` for Codex after Google login.
- This is for development/testing, not production security hardening.
