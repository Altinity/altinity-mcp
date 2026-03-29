# OAuth MCP Development via `PUBLIC_HOST.example.com`

This harness is for local-first development of `altinity-mcp` OAuth support with Codex browser login in both runtime modes.

## What This Setup Does

- Runs `altinity-mcp` locally on separate ports so both modes can stay up together:
  - forward on `0.0.0.0:18080`
  - gating on `0.0.0.0:18081`
- Exposes it publicly through nginx on `https://PUBLIC_HOST.example.com`
- Serves the gating MCP endpoint under `https://PUBLIC_HOST.example.com/http-t`
- Serves the gating OAuth endpoints under `https://PUBLIC_HOST.example.com/oauth-t/`
- Serves the forward MCP endpoint under `https://PUBLIC_HOST.example.com/http-f`
- Serves the forward OAuth endpoints under `https://PUBLIC_HOST.example.com/oauth-f/`
- Supports two manual Google-provider flows:
  - `forward`: local `altinity-mcp` plus `github.demo.altinity.cloud:8443` with token forwarding into ClickHouse
  - `gating`: local `altinity-mcp` plus normal ClickHouse auth against `github.demo.altinity.cloud:9440`
- Uses Codex as the OAuth client via `codex mcp login`
- Uses Google only as the upstream identity provider
- In `forward` mode, returns the upstream Google access token to Codex and validates it on inbound requests
- In `gating` mode, mints self-issued MCP access tokens after Google login

## Important URLs

- Gating MCP base: `https://PUBLIC_HOST.example.com/http-t`
- Gating OAuth base: `https://PUBLIC_HOST.example.com/oauth-t/`
- Forward MCP base: `https://PUBLIC_HOST.example.com/http-f`
- Forward OAuth base: `https://PUBLIC_HOST.example.com/oauth-f/`
- OAuth callback for gating Google app: `https://PUBLIC_HOST.example.com/oauth-t/callback`
- OAuth callback for forward Google app: `https://PUBLIC_HOST.example.com/oauth-f/callback`

## Google Project

Create or reuse a long-lived project under folder `246059149080`.

Recommended project:

```bash
gcloud projects create altinity-mcp-oauth-test \
  --name="altinity-mcp-oauth-test" \
  --folder=246059149080
gcloud config set project altinity-mcp-oauth-test
```

Create a Google Auth Platform web client with redirect URIs:

```bash
https://PUBLIC_HOST.example.com/oauth-t/callback
https://PUBLIC_HOST.example.com/oauth-f/callback
```

Keep these values available:

- `GOOGLE_OAUTH_CLIENT_ID`
- `GOOGLE_OAUTH_CLIENT_SECRET`

Do not store a single shared `GOOGLE_OAUTH_REDIRECT_URI` in the local env file for this split-path setup. The harness derives the callback URL from the active mode's `public_auth_server_url` plus `callback_path`, so one static redirect URI is misleading for dual-mode testing.

In Google Auth Platform console:

1. Configure Branding
2. Set Audience to `External`
3. Add test users from both `@altinity.com` and Gmail
4. Keep scopes minimal: `openid`, `email`

## Local Files

Required environment variables for scripts:

```bash
export MCP_TARGET_HOST='PUBLIC_HOST.example.com'
export MCP_PUBLIC_MCP_PREFIX='/http-t'
export MCP_PUBLIC_OAUTH_PREFIX='/oauth-t'
export MCP_LOCAL_PORT='18081'
```

The scripts load Google credentials from:

- `~/.mcp/$MCP_TARGET_HOST/google-oauth.env`
- `~/.mcp/$MCP_TARGET_HOST/oauth-gating-secret`

`google-oauth.env` should contain only the Google client ID and secret for this harness.

So the minimal local setup is usually just:

```bash
export MCP_TARGET_HOST='PUBLIC_HOST.example.com'
```

Optional:

```bash
export CLICKHOUSE_HOST='...'
export CLICKHOUSE_PORT='9440'
export CLICKHOUSE_DATABASE='default'
export CLICKHOUSE_USERNAME='...'
export CLICKHOUSE_PASSWORD='...'
export CLICKHOUSE_PROTOCOL='tcp'
export CLICKHOUSE_READ_ONLY='true'
export CLICKHOUSE_TLS_ENABLED='true'
```

## nginx Requirements

`PUBLIC_HOST.example.com` must reverse-proxy both mode pairs to different local ports:

- gating: `/http-t` and `/oauth-t/` to `192.168.1.155:18081`
- forward: `/http-f` and `/oauth-f/` to `192.168.1.155:18080`

Minimum requirements:

- preserve `Host`
- set `X-Forwarded-Proto https`
- set `X-Forwarded-Prefix`
- set `X-Forwarded-OAuth-Prefix`
- forward `Authorization`
- support long-lived HTTP streaming
- disable buffering for both request and response bodies

For the current implementation, these public URLs must work exactly:

- `https://PUBLIC_HOST.example.com/http-t`
- `https://PUBLIC_HOST.example.com/http-t/.well-known/oauth-protected-resource`
- `https://PUBLIC_HOST.example.com/oauth-t/.well-known/oauth-authorization-server`
- `https://PUBLIC_HOST.example.com/oauth-t/.well-known/openid-configuration`
- `https://PUBLIC_HOST.example.com/oauth-t/callback`
- `https://PUBLIC_HOST.example.com/http-f`
- `https://PUBLIC_HOST.example.com/http-f/.well-known/oauth-protected-resource`
- `https://PUBLIC_HOST.example.com/oauth-f/.well-known/oauth-authorization-server`
- `https://PUBLIC_HOST.example.com/oauth-f/.well-known/openid-configuration`
- `https://PUBLIC_HOST.example.com/oauth-f/callback`

If any frontend rewrites or normalizes these paths, Codex browser login will fail.

Example:

```nginx
server {
    server_name PUBLIC_HOST.example.com;

    location ^~ /http-t {
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-Prefix /http-t;
        proxy_set_header X-Forwarded-OAuth-Prefix /oauth-t;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Authorization $http_authorization;
        proxy_buffering off;
        proxy_request_buffering off;
        proxy_read_timeout 3600;
        proxy_send_timeout 3600;
        rewrite ^/http-t(.*)$ /http$1 break;
        proxy_pass http://YOUR_LOCAL_IP:18081;
    }

    location ^~ /oauth-t/ {
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-Prefix /oauth-t;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Authorization $http_authorization;
        proxy_buffering off;
        proxy_request_buffering off;
        proxy_read_timeout 3600;
        proxy_send_timeout 3600;
        rewrite ^/oauth-t/(.*)$ /$1 break;
        proxy_pass http://YOUR_LOCAL_IP:18081;
    }
}
```

Also add exact-location routes for the well-known aliases if your frontend does not naturally pass them through:

- `/.well-known/oauth-protected-resource/http-t`
- `/.well-known/oauth-authorization-server/http-t`
- `/.well-known/openid-configuration/http-t`
- `/.well-known/oauth-authorization-server/oauth-t`
- `/.well-known/openid-configuration/oauth-t`
- `/.well-known/oauth-protected-resource/http-f`
- `/.well-known/oauth-authorization-server/http-f`
- `/.well-known/openid-configuration/http-f`
- `/.well-known/oauth-authorization-server/oauth-f`
- `/.well-known/openid-configuration/oauth-f`

The working nginx example for this repo is in [nginx-PUBLIC_HOST.example.com-split-paths.conf](/Users/bvt/work/altinity-mcp/oauth/nginx-PUBLIC_HOST.example.com-split-paths.conf).

## Manual Google Test Flows

### Forward Mode

This mode forwards the Google bearer token that ClickHouse expects to `github.demo.altinity.cloud:8443` over HTTPS.
When the upstream provider returns both `id_token` and `access_token`, the browser-login callback returns `id_token` as the MCP bearer token and keeps `access_token` only for fallback or provider-specific use. If no `id_token` is available, the callback falls back to the upstream `access_token`.
In forward mode, `altinity-mcp` only requires that a bearer token is present on incoming requests and forwards it unchanged to ClickHouse. Real token validation and user identity mapping are delegated to ClickHouse `token_processors`.

```bash
oauth/test-google-forward.sh
```

Manual Codex flow:

```bash
export MCP_TARGET_HOST='PUBLIC_HOST.example.com'
codex mcp remove altinity_mcp_oauth_forward >/dev/null 2>&1 || true
codex mcp add altinity_mcp_oauth_forward --url "https://${MCP_TARGET_HOST}/http-f"
codex mcp login altinity_mcp_oauth_forward
codex exec "Use the configured MCP server named altinity_mcp_oauth_forward. Execute SELECT currentUser(), version() and return only the SQL result."
```

What it does:

- starts local `altinity-mcp` in `mode: forward`
- connects to `github.demo.altinity.cloud:8443` with `demo/demo`
- probes the public MCP and OAuth metadata URLs
- registers the MCP server in Codex
- runs `codex mcp login`
- runs `SELECT currentUser(), version()`

For a deterministic non-Codex validation path, use:

```bash
oauth/test-google-forward-direct.sh
```

What it verifies:

- `gcloud auth print-identity-token` returns a Google-signed ID token for the active account
- direct auth to `github.demo.altinity.cloud:8443` works with that token
- local `altinity-mcp` forward mode passes that token through to ClickHouse
- the public `https://PUBLIC_HOST.example.com/http-f/openapi/execute_query` path is probed separately so proxy issues are visible without blocking the core server validation

### Gating Mode

This mode verifies the Google identity at `altinity-mcp`, limits access to verified `@altinity.com` emails, and then uses normal ClickHouse credentials.

Default ClickHouse target:

- `github.demo.altinity.cloud:9440`
- username `demo`
- password `demo`

```bash
oauth/test-google-gating.sh
```

Manual Codex flow:

```bash
export MCP_TARGET_HOST='PUBLIC_HOST.example.com'
codex mcp remove altinity_mcp_oauth_gating >/dev/null 2>&1 || true
codex mcp add altinity_mcp_oauth_gating --url "https://${MCP_TARGET_HOST}/http-t"
codex mcp login altinity_mcp_oauth_gating
codex exec "Use the configured MCP server named altinity_mcp_oauth_gating. Execute SELECT version() and return only the SQL result."
```

What it does:

- starts local `altinity-mcp` in `mode: gating`
- connects to `github.demo.altinity.cloud:9440` with `demo/demo`
- enforces `allowed_email_domains: [altinity.com]`
- enforces `require_email_verified: true`
- probes the public MCP and OAuth metadata URLs
- registers the MCP server in Codex
- runs `codex mcp login`
- runs `SELECT version()`

For gating mode, sign in with a verified `@altinity.com` Google account.

Gating mode default local bind:

- `0.0.0.0:18081`

## Helm Validation Later

After the local public-host flow works, validate the same config on Kubernetes:

```bash
oauth/start-k8s.sh
```

This uses:

- `KUBECONFIG=$HOME/.kube/aw-demo.config`
- namespace `demo`

## OAuth Config

The harness uses explicit public URL and path settings for both modes. `issuer` is the upstream OIDC issuer, not the public MCP OAuth base URL.

Key fields:

- `issuer`
  The upstream OIDC issuer claim to validate on inbound OAuth tokens. For Google use `https://accounts.google.com`.
- `audience`
  The audience claim to validate on inbound OAuth tokens when the upstream provider emits JWT access or identity tokens. For the public MCP resource this is typically `https://PUBLIC_HOST.example.com/http-t`.
- `gating_secret_key`
  Shared secret for stateless client registration, gating state, and gating codes used by the browser-login facade. This is required for `codex mcp login` in both modes.
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
  Lifetime of stateless gating authorization codes.
- `access_token_ttl_seconds`
  Lifetime of self-issued access tokens in `gating` mode only.
- `refresh_token_ttl_seconds`
  Reserved for `gating` mode only. `forward` mode does not mint refresh tokens.

Minimal `forward` mode config for the current `PUBLIC_HOST.example.com` split-path setup:

```yaml
server:
  transport: http
  oauth:
    enabled: true
    mode: "forward"
    issuer: "https://accounts.google.com"
    audience: ""
    gating_secret_key: "CHANGE_ME_TO_A_RANDOM_SECRET"
    public_resource_url: "https://PUBLIC_HOST.example.com/http-f"
    public_auth_server_url: "https://PUBLIC_HOST.example.com/oauth-f"
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
```

Minimal `gating` mode differences:

```yaml
server:
  oauth:
    mode: "gating"
    issuer: "https://accounts.google.com"
    audience: "https://PUBLIC_HOST.example.com/http-t"
    allowed_email_domains: ["altinity.com"]
    require_email_verified: true
```

## Notes

- This repo exposes MCP OAuth discovery and a test-oriented auth server facade.
- Google is only the upstream login provider.
- In `forward` mode, Codex receives the upstream Google access token and `altinity-mcp` forwards it to ClickHouse.
- In `gating` mode, `altinity-mcp` mints and validates its own MCP access tokens after Google login.
- This is for development/testing, not production security hardening.
