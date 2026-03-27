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
- OAuth callback for Google app: `https://welcome.ru/oauth/oauth/callback`
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

Create the Google OAuth client and credential:

```bash
gcloud iam oauth-clients create altinity-mcp \
  --location=global \
  --client-type=confidential-client \
  --display-name="Altinity MCP" \
  --allowed-grant-types=authorization-code-grant,refresh-token-grant \
  --allowed-scopes=openid,email \
  --allowed-redirect-uris=https://welcome.ru/oauth/oauth/callback

gcloud iam oauth-clients credentials create altinity-mcp-cred \
  --location=global \
  --oauth-client=altinity-mcp \
  --display-name="Altinity MCP credential"
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
- forward `Authorization`
- support long-lived HTTP streaming

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
        proxy_read_timeout 3600;
        proxy_send_timeout 3600;
        rewrite ^/oauth/(.*)$ /$1 break;
        proxy_pass http://YOUR_LOCAL_IP:18080;
    }
}
```

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

## Notes

- This repo now exposes MCP OAuth discovery and a test-oriented auth server facade.
- Google is only the upstream login provider.
- MCP access tokens are minted by `altinity-mcp` for Codex after Google login.
- This is for development/testing, not production security hardening.
