# OAuth 2.0 Authorization for Altinity MCP Server

How OAuth 2.0 / OpenID Connect (OIDC) authentication works in
`altinity-mcp`, when to pick each mode, and how to wire it up against
common identity providers.

Companion: the ClickHouse-side JWT verifier sidecar used by gating mode
lives in [`altinity-oauth-helper`](https://github.com/altinity/altinity-oauth-helper) —
that repo carries the spec, source, helm chart, and Dockerfile.

## Overview

Two modes, picked per deployment via `oauth.mode`:

- **`mode: gating`** — MCP is a pure forwarder. Each query carries
  `Authorization: Basic base64(email:JWT)` to ClickHouse; ClickHouse's
  [`<http_authentication>`](https://clickhouse.com/docs/operations/external-authenticators/http)
  delegates the password check to the `ch-jwt-verify` sidecar, which
  validates the JWT against the upstream IdP's JWKS and applies identity
  policy. Works on any ClickHouse build; the sidecar must be deployed
  next to ClickHouse.

- **`mode: forward`** — MCP is the OAuth Authorization Server to its
  clients (terminates Client ID Metadata Documents (CIMD) registration,
  `/authorize`, `/token`, `/callback`) and relays the upstream IdP's
  token to ClickHouse via `Authorization: Bearer <jwt>`. ClickHouse
  re-validates with its `token_processors` and materializes ephemeral
  users from the JWT's claims. Requires a ClickHouse build that supports
  `token_processors` (Altinity Antalya 25.8+ or an equivalent JWT-aware
  build).

Detailed flows: [Gating mode](#gating-mode), [Forward mode](#forward-mode).
Decision rationale: [Choosing a mode](#choosing-a-mode).

## Mode taxonomy

| Mode | What MCP does | What ClickHouse does | When to use |
|---|---|---|---|
| **`gating`** | Unverified-decodes the JWT's `email` claim. Rewrites `Authorization: Bearer <jwt>` to `Authorization: Basic base64(email:JWT)`. Forces HTTP protocol. No cryptographic check per request — the sidecar is the gate. | `<http_authentication>` calls the `ch-jwt-verify` sidecar. Sidecar validates signature, `iss`, `aud` (RFC 8707 byte-equal), `exp`/`nbf`/`iat`, required scopes, identity policy, user-vs-claim match. | Works on any ClickHouse build, including OSS. Sidecar must be reachable from the CH pod (loopback for the production trust model). |
| **`forward`** | Acts as the OAuth Authorization Server to the MCP client: accepts CIMD-registered clients, runs `/authorize` + `/token` + `/callback`, brokers the upstream IdP. Relays the upstream JWT to ClickHouse as `Bearer`. | `token_processors` cryptographically validates the bearer (JWKS, `aud`, `exp`) and materializes ephemeral users from claims via the `<token>` `user_directory`. | When the IdP doesn't expose CIMD-compatible endpoints (Google direct, basic-tier Auth0) and ClickHouse supports `token_processors`. |

Both modes require ClickHouse over HTTP (port 8123 typically). TCP/native
is incompatible with both `<http_authentication>` and `token_processors`.

## Choosing a mode

Use **gating** when:

- Your ClickHouse build doesn't support `token_processors` (OSS builds).
- You can deploy a sidecar container next to ClickHouse.
- You prefer pre-provisioned ClickHouse users over per-claim ephemeral
  ones.
- You want the cryptographic gate next to the data plane (sidecar) with
  MCP holding no secrets at all.

Use **forward** when:

- Your ClickHouse build supports `token_processors` (Altinity Antalya
  25.8+).
- You want **ephemeral CH users materialized from JWT claims** — no
  pre-`CREATE USER` step per identity.
- You can't or don't want to deploy a sidecar.

### What's actually different

| | Gating | Forward |
|---|---|---|
| OAuth Authorization Server | Upstream IdP | MCP (brokering the upstream IdP) |
| Bearer the MCP client receives | Upstream IdP's JWT (TTL set per the IdP's access-token policy) | Upstream IdP id_token (raw passthrough) |
| MCP → ClickHouse credential | `Authorization: Basic base64(email:JWT)` over HTTP | `Authorization: Bearer <id_token>` over HTTP |
| Who validates the bearer on every query | The `ch-jwt-verify` sidecar | ClickHouse via `token_processors` |
| CH user provisioning | Pre-create with `IDENTIFIED WITH http SERVER 'ch_jwt_verify' SCHEME 'BASIC'` | Dynamic — `token_processors` materializes ephemeral users from JWT claims |
| ClickHouse build requirement | Any (OSS too); needs the sidecar | Antalya 25.8+ |
| ClickHouse protocol | HTTP only | HTTP only |
| Identity in `system.query_log` | The matched CH user (= JWT email) | The JWT subject directly |
| Refresh-token rotation + reuse detection | Upstream IdP | Upstream IdP (when `upstream_offline_access: true`) |

### The trust-boundary argument

In **gating** mode, MCP holds no shared secret with ClickHouse and has
no authority to impersonate users. Every query is gated by a
cryptographic check performed by the sidecar against the upstream IdP's
JWKS. Compromise of the MCP pod buys an attacker nothing the inbound
bearer doesn't already grant. When the sidecar runs colocated in the CH
pod, the CH↔sidecar channel is loopback-only — not network-reachable
from anywhere outside the pod.

In **forward** mode, ClickHouse re-validates the upstream JWT on every
query via `token_processors`. Same trust property: the cryptographic
gate sits next to the data plane.

Both modes keep the cryptographic identity check at ClickHouse, not at
MCP.

### Dynamic user provisioning

Forward mode's `token_processors` reads JWT claims (`email`, `roles`,
custom claims) and materializes an ephemeral CH user with the right
grants on the fly — no manual `CREATE USER` per identity. Useful for
multi-tenant deployments where the user roster comes from the IdP.

Gating mode requires `CREATE USER <email> IDENTIFIED WITH http
SERVER 'ch_jwt_verify' SCHEME 'BASIC'` for each OAuth identity. For a
fixed roster of internal users this is straightforward; for a large
churning user base it's a maintenance burden.

### Token lifecycle

Gating mode tokens are managed by the upstream IdP. The IdP's
access-token TTL is what bounds revocation latency — pick it on the
IdP side to match your security/availability trade-off (shorter TTL =
faster revocation, more refresh load). Refresh-token rotation and reuse
detection are also the IdP's responsibility.

Forward mode tokens are also the upstream IdP's. With
`upstream_offline_access: true`, MCP wraps the upstream refresh token in
a JWE keyed by `signing_secret` and returns it to the MCP client; on
refresh, MCP unwraps, calls the upstream `/token` with the upstream
refresh, and returns the rotated pair. Revocation lands at the next
query (subject to JWKS cache TTL + ClickHouse's own caching).

### When forward mode is the wrong choice

- ClickHouse build doesn't support `token_processors`. Forward sends the
  bearer; CH 403s every query.
- The IdP supports CIMD + RFC 8707 and you don't need ephemeral CH
  users from JWT claims — gating + the sidecar is simpler.

### When gating mode is the wrong choice

- You want ephemeral user provisioning from JWT claims.
- You can't deploy a sidecar into (or next to) the CH pod — e.g. a
  managed CH offering that doesn't expose pod-template editing.

## Requirements

- **ClickHouse protocol**: HTTP (port 8123 typically). Both modes route
  credentials through CH's HTTP interface; TCP/native has no equivalent.
- **ClickHouse build**:
  - Forward: Altinity Antalya 25.8+ or any CH build with
    `token_processors`.
  - Gating: any build that supports `<http_authentication>` and
    `IDENTIFIED WITH http` (CH 24.x+ for OSS).
- **Identity Provider**: any OAuth 2.0 / OIDC-compliant IdP. Inbound
  client registration uses [Client ID Metadata Documents (CIMD)](https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/);
  Dynamic Client Registration (DCR, RFC 7591) is not exposed by MCP.
- **`signing_secret`**: required whenever OAuth is enabled. Symmetric
  secret (≥ 32 bytes) that HKDF-derives keys for all stateless OAuth
  artifacts (forward-mode authorization codes, refresh-token JWEs,
  HKDF-derived signing material). Generate with `openssl rand -base64 32`.
- **Reverse proxy**: if published behind a proxy, set `public_resource_url`
  (both modes) and `public_auth_server_url` (forward only). See
  [Frontend / Reverse Proxy](#frontend--reverse-proxy-requirements).

## MCP client discovery flow

OAuth-capable MCP clients (Claude, Codex, etc.) discover authentication
automatically per [RFC 9728 (OAuth 2.0 Protected Resource Metadata)](https://www.rfc-editor.org/rfc/rfc9728):

1. Client `GET`s `/.well-known/oauth-protected-resource` from the MCP
   endpoint.
2. **Gating**: response `authorization_servers` points to the **upstream
   IdP**. Client fetches `/.well-known/oauth-authorization-server` from
   the IdP. MCP's `/.well-known/oauth-authorization-server` returns 404
   (MCP isn't the AS in gating mode).
3. **Forward**: response `authorization_servers` points to **MCP
   itself**. Client fetches MCP's
   `/.well-known/oauth-authorization-server`, which advertises CIMD
   support, omits the DCR `registration_endpoint`, and lists
   `grant_types_supported: ["authorization_code"]` plus
   `token_endpoint_auth_methods_supported: ["none", "private_key_jwt"]`.
4. Client publishes a CIMD document at a URL it controls and uses that
   URL as its `client_id` at `/authorize`.
5. Client initiates the authorization-code flow with S256 PKCE.
6. After login, client exchanges the code for an access token (and,
   in forward mode with `upstream_offline_access: true`, a JWE-wrapped
   refresh token).
7. Client presents the access token on every MCP request.

## Forward mode

ClickHouse with `token_processors` (Antalya 25.8+) validates the
upstream JWT directly; MCP brokers the OAuth dance and forwards the
bearer.

```
+--------+      +---------+      +----------+      +-------------+
|  MCP   |----->|   IdP   |      |   MCP    |      |  ClickHouse |
| Client |<-----|         |      |  Server  |      |  (Antalya)  |
|        |      +---------+      |          |      |             |
|        |                       |          |      |             |
|        |---Bearer token------->|          |      |             |
|        |                       |--Bearer->|      |             |
|        |                       |  token   |----->| token_proc  |
|        |                       |          |      | validates   |
|        |<----------------------|<---------|<-----| via JWKS    |
|        |    query results      |          |      |             |
+--------+                       +----------+      +-------------+
```

Flow:

1. MCP client discovers MCP-as-AS via RFC 9728 → fetches MCP's AS
   metadata → publishes a CIMD document → starts the auth-code flow
   against MCP.
2. MCP brokers the upstream IdP using its configured `client_id` /
   `client_secret` (operator-issued OAuth application).
3. The upstream's id_token comes back; MCP wraps any refresh token in a
   JWE (when `upstream_offline_access: true`) and returns the
   id_token unchanged to the MCP client as the access token.
4. The MCP client presents the bearer on each MCP request. MCP forwards
   it to ClickHouse as `Authorization: Bearer <jwt>`.
5. ClickHouse's `token_processors` re-validates against the upstream
   JWKS, materializes an ephemeral user, and runs RBAC.

> **Spec deviation (deliberate).** MCP authorization spec §Access Token
> Privilege Restriction says *"the MCP server MUST NOT pass through the
> token it received from the MCP client"*. Forward mode does pass it
> through — by design. Justification: ClickHouse re-validates the same
> JWT against the upstream JWKS, extracts the same identity, and runs
> its own RBAC. The MCP server is a transparent gateway, not a trust
> anchor. Gating mode is the spec-clean alternative when you don't have
> ClickHouse-side JWT validation set up.

### Minimum config

```yaml
config:
  clickhouse:
    host: clickhouse.example.com
    port: 8123
    protocol: http
  server:
    oauth:
      enabled: true
      mode: forward
      signing_secret: "<32-byte-random>"     # via env in production
      issuer:    "https://idp.example.com/"
      auth_url:  "https://idp.example.com/authorize"
      token_url: "https://idp.example.com/oauth/token"
      client_id: "<UPSTREAM_OAUTH_CLIENT_ID>"
      # client_secret via MCP_OAUTH_CLIENT_SECRET env var
      callback_path: "/oauth/callback"
      public_auth_server_url: "https://mcp.example.com"
      public_resource_url:    "https://mcp.example.com"
      scopes: [openid, email, profile, offline_access]
      upstream_offline_access: true
```

## Gating mode

ClickHouse delegates the per-query password check to a colocated
`ch-jwt-verify` sidecar that cryptographically validates the JWT.

```
+--------+      +-----------+      +----------+      +------------------+
|  MCP   |----->|    IdP    |      |   MCP    |      | ClickHouse pod   |
| Client |<-----|           |      | (forward)|      | +--------------+ |
|        |      +-----------+      |          |      | | ClickHouse   | |
|        |--Bearer JWT------------>|          |      | |  + http_     | |
|        |                         | rewrite  |      | |  auth        | |
|        |                         | to Basic |----->| |              | |
|        |                         | email:JWT|      | |  loopback    | |
|        |                         |          |      | |  v           | |
|        |                         |          |      | | ch-jwt-      | |
|        |                         |          |      | | verify       | |
|        |                         |          |      | | (signature   | |
|        |                         |          |      | |  + policy)   | |
|        |<------------------------|<---------|<-----| +--------------+ |
|        |       query results     |          |      +------------------+
+--------+                         +----------+
```

Flow:

1. MCP client discovers the upstream IdP via RFC 9728 (MCP's
   protected-resource doc points at the IdP, not MCP itself).
2. Client publishes a CIMD document and runs the auth-code flow against
   the upstream IdP — MCP is invisible to that exchange.
3. Client presents the IdP-issued JWT on every MCP request.
4. MCP unverified-decodes the JWT's `email` claim (or a namespaced
   `*/email` fallback for IdPs that strip top-level OIDC claims for
   third-party clients), builds `Authorization: Basic base64(email:JWT)`,
   and forwards the query to ClickHouse over HTTP.
5. ClickHouse's `<http_authentication>` looks up the matching user
   (provisioned as `IDENTIFIED WITH http SERVER 'ch_jwt_verify' SCHEME
   'BASIC'`) and POSTs the Basic header to the sidecar.
6. The sidecar validates signature (against the upstream JWKS), `iss`
   (exact match), `aud` (RFC 8707 byte-equal), `exp`/`nbf`/`iat` (with
   clock skew), required scopes, identity policy (verified email,
   domain allow-lists), and **user-vs-claim match** (Basic user half
   must match the JWT's `email` claim). On success it returns 200 with
   optional session settings; any non-200 rejects the query.

### Minimum config

```yaml
config:
  clickhouse:
    host: clickhouse.example.com
    port: 8123
    protocol: http
    # Static username/password are unused for OAuth requests — the
    # per-request switch sets Auth.Username = email, Password = JWT.
    # They remain as fallbacks for the (skipped) startup ping path.
    username: default
  server:
    oauth:
      enabled: true
      mode: gating
      signing_secret: "<32-byte-random>"     # via env in production
      issuer:   "https://idp.example.com/"
      jwks_url: "https://idp.example.com/.well-known/jwks.json"
      audience: "https://mcp.example.com/"   # RFC 8707 byte-equal target
      required_scopes: []                    # optional; empty disables the check
      public_resource_url: "https://mcp.example.com"
      # Forbidden under gating mode (startup refuses if any are set):
      # client_id, client_secret, token_url, auth_url, userinfo_url,
      # public_auth_server_url
```

### Sidecar + ClickHouse-side config

The sidecar deploys as a colocated container in the CH pod (loopback
trust model). See
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
-- One role per entitlement level
CREATE ROLE IF NOT EXISTS mcp_reader;
GRANT SELECT ON analytics.* TO mcp_reader;

-- One user per identity, delegating auth to the sidecar
CREATE USER `alice@example.com`
  IDENTIFIED WITH http SERVER 'ch_jwt_verify' SCHEME 'BASIC'
  DEFAULT ROLE mcp_reader;
GRANT mcp_reader TO `alice@example.com`;
```

The grammar token is `http`, not `http_authenticator` — ClickHouse
rejects the latter with `SYNTAX_ERROR`. `SERVER 'ch_jwt_verify'` must
match the `<http_authentication_servers><ch_jwt_verify>` block name.

### Identity policy

All identity policy (verified-email, email-domain allow-listing,
hosted-domain allow-listing, user-vs-claim match) lives in the sidecar's
config:

```yaml
identity:
  username_claim: email
  match_mode: lowercase_equal      # or "exact"
  require_email_verified: true
  allowed_email_domains:  ["example.com"]
  allowed_hosted_domains: []
```

Full schema in the [`altinity-oauth-helper`](https://github.com/altinity/altinity-oauth-helper) repo.

MCP itself applies no identity policy in gating mode — the sidecar is
the only enforcer.

### Limitations

- **HTTP only** on the CH side: `<http_authentication>` has no TCP
  equivalent.
- **Sidecar must be reachable from the CH pod.** Colocated container is
  the loopback-only production shape. Standalone Deployment + Service in
  the same namespace works for shadow / smoke-test but expands the trust
  boundary to the cluster network — lock down with a `NetworkPolicy` if
  the namespace is multi-tenant.
- **No role forwarding from the IdP**: ClickHouse permissions come from
  what's `GRANT`ed to the matched CH user. The sidecar can return
  per-scope ClickHouse **session settings** via `settings_from_scope`,
  but those are session settings only, not roles.

## Refresh tokens

Both modes can issue refresh tokens; the lifecycle is different.

### Gating mode

Refresh tokens are issued and rotated entirely by the upstream IdP —
MCP never sees them. The client exchanges refresh tokens directly
against the IdP's `/token` endpoint.

Configure refresh-token rotation and reuse detection at the IdP itself
(RFC 6749 §10.4, OAuth 2.1 §4.13.2). MCP plays no role in this.

### Forward mode (opt-in)

By default, forward mode does not issue refresh tokens; MCP-client
sessions die when the upstream id_token expires. Set
`upstream_offline_access: true` to opt in:

1. MCP appends `offline_access` (or the IdP-specific equivalent like
   Google's `access_type=offline`) to the upstream authorize redirect.
2. MCP captures the upstream IdP's `refresh_token` from the
   token-exchange response and wraps it in a JWE keyed by
   `signing_secret`. The MCP client sees only the opaque JWE.
3. On `grant_type=refresh_token` from the MCP client, MCP decrypts the
   JWE, calls the upstream `/oauth/token` with the upstream refresh,
   re-validates the new id_token (signature via JWKS), and returns the
   rotated pair. The new `access_token` is the fresh upstream id_token
   verbatim.

Operator setup:

- Enable the `offline_access` scope on the IdP (Auth0: tenant API; Okta:
  app grant types; Azure AD: scope exposure). Without IdP-side support,
  the authorize redirect may hard-fail or silently strip the scope.
- Configure refresh-token rotation + reuse detection at the IdP. This
  provides revocation outside MCP, since the JWE itself is stateless.
- Default is `false` so existing deployments are unaffected unless an
  operator opts in. Turning on refresh widens the stolen-token blast
  radius from the upstream id_token TTL (~1 h) to
  `refresh_token_ttl_seconds` (default 30 d).

### Revocation limitations

- **Gating**: no MCP-side revocation; token validity is bounded by the
  IdP's access-token TTL. Grant revocations take effect within one TTL
  window. The sidecar's `cache.positive_ttl` (default 30 s) adds a
  small additional window per validated token.
- **Forward**: no server-side revocation of the JWE-wrapped refresh
  token. Rotate `signing_secret` to invalidate all outstanding JWEs.
  The upstream IdP's reuse detection (if enabled) provides
  defense-in-depth.

## Full configuration reference

```yaml
server:
  oauth:
    # Enable OAuth 2.0 authentication
    enabled: false

    # OAuth operating mode:
    # - "gating":  pure resource server. Upstream IdP handles
    #              /authorize, /token, and refresh-token rotation.
    #              MCP forwards Authorization: Basic base64(email:JWT)
    #              to ClickHouse; the ch-jwt-verify sidecar gates.
    # - "forward": MCP brokers DCR/CIMD + authorize + token against
    #              the upstream IdP; relays the upstream JWT to
    #              ClickHouse as Bearer for token_processors to
    #              validate.
    mode: "gating"

    # Symmetric secret for stateless OAuth artifacts (authorization
    # codes, refresh-token JWEs, HKDF-derived signing material).
    # Required whenever OAuth is enabled. Minimum 32 bytes — generate
    # with `openssl rand -base64 32`.
    signing_secret: ""

    # Upstream OAuth/OIDC issuer URL (used for discovery + validation)
    issuer: ""

    # URL to fetch JWKS for token validation (discovered from issuer
    # if omitted)
    jwks_url: ""

    # Expected audience claim in incoming tokens
    # (RFC 8707 byte-equality; trailing slash matters)
    audience: ""

    # Forward mode only — upstream OAuth client credentials and
    # endpoint URLs. FORBIDDEN in gating mode (startup refuses).
    client_id: ""
    client_secret: ""
    token_url: ""
    auth_url: ""
    userinfo_url: ""
    public_auth_server_url: ""

    # Forward mode only — OAuth scopes to request from the upstream IdP
    scopes: ["openid", "profile", "email"]

    # Forward mode only — opt into requesting offline_access upstream
    # and issuing JWE-wrapped refresh tokens to MCP clients.
    upstream_offline_access: false

    # Scopes required in every incoming bearer JWT. Enforced by the
    # ch-jwt-verify sidecar (gating) or token_processors (forward);
    # MCP itself does not validate per-request.
    required_scopes: []

    # Token lifetimes
    access_token_ttl_seconds: 3600     # forward-mode only; gating is IdP-managed
    refresh_token_ttl_seconds: 2592000 # forward-mode only; 30 d default

    # Externally visible MCP endpoint URL. Required behind a reverse
    # proxy (both modes).
    public_resource_url: ""

    # Forward mode only — endpoint paths (defaults shown).
    registration_path: "/register"
    authorization_path: "/authorize"
    callback_path: "/callback"
    token_path: "/token"
```

### Key options

| Option | Description |
|---|---|
| `mode` | `gating` (MCP as pure forwarder, sidecar gates) or `forward` (MCP as AS broker, `token_processors` gates) |
| `signing_secret` | Symmetric secret for stateless OAuth artifacts. **Required** whenever OAuth is enabled. ≥ 32 bytes. |
| `issuer` | Upstream IdP issuer URL for OIDC discovery and token validation |
| `audience` | RFC 8707 byte-equal target. Must match the JWT's `aud` claim byte-for-byte (trailing slashes count). |
| `public_resource_url` | Externally visible MCP endpoint URL. **Required** behind a reverse proxy |
| `public_auth_server_url` | Externally visible OAuth authorization server URL. **Forward only** — required behind a reverse proxy. Forbidden in gating. |
| `upstream_offline_access` | Forward only: request `offline_access` upstream and issue JWE-wrapped refresh tokens to MCP clients. Default `false` |

## Frontend / Reverse Proxy Requirements

For direct bearer-token use, a plain reverse proxy is usually enough.

For browser-based MCP login in **forward mode**, the frontend must
expose two public URL spaces:

- the protected resource, e.g. `https://mcp.example.com/`
- the OAuth authorization server, e.g. `https://mcp.example.com/oauth`

In **gating mode**, only the protected resource needs to be proxied —
the authorization server is the upstream IdP.

The proxy must:

- Forward `Host` and `Authorization` headers unchanged
- Disable response buffering for MCP streaming
- Disable request buffering for long-lived POSTs
- Keep long read/send timeouts
- Not normalize or rewrite the configured callback or metadata paths
- Not rely on forwarded-prefix headers — configure the public OAuth
  URLs explicitly in `altinity-mcp`

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

## ClickHouse `token_processors` (forward mode)

Forward mode requires ClickHouse to be configured with `token_processors`
plus a `<token>` entry in `<user_directories>` that maps validated
tokens to ClickHouse users.

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

You can also specify endpoints explicitly:

```xml
<clickhouse>
    <token_processors>
        <my_oidc_provider>
            <type>OpenID</type>
            <userinfo_endpoint>https://idp.example.com/userinfo</userinfo_endpoint>
            <jwks_uri>https://idp.example.com/certs</jwks_uri>
            <token_introspection_endpoint>https://idp.example.com/token/introspect</token_introspection_endpoint>
            <token_cache_lifetime>60</token_cache_lifetime>
        </my_oidc_provider>
    </token_processors>
</clickhouse>
```

### Azure AD (Microsoft Entra ID)

Azure has a dedicated `azure` type that requires no explicit endpoints:

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

### Roles setup

You must create the roles referenced in `common_roles` before users can
authenticate:

```sql
CREATE ROLE OR REPLACE default_role;
GRANT SELECT ON default.* TO default_role;
```

The default `<username_claim>` is `sub` — IdP users show up in
`system.processes` / `system.query_log` as numeric IDs. To attribute
queries by email, set `<username_claim>email</username_claim>` on the
processor.

## Provider-specific setup

The OAuth setup for the IdP itself is provider-specific. The examples
below cover the common providers. Substitute the relevant URLs into the
[forward-mode config](#forward-mode) or
[gating-mode config](#gating-mode) above.

### Keycloak

1. **Create a realm and client** in the Keycloak admin console:
   - Realm: e.g. `mcp`
   - Client ID: `clickhouse-mcp`
   - Client Protocol: `openid-connect`
   - Access Type: `confidential` (or `public` for PKCE)
   - Valid Redirect URIs: your MCP server's `<public>/oauth/callback`
   - Enable "Standard Flow" and "Direct Access Grants"

2. **Create groups + users** for role mapping (configure a group
   membership mapper on the client so groups land in the token).

3. **Forward-mode MCP config:**

   ```yaml
   server:
     oauth:
       enabled: true
       mode: forward
       signing_secret: "<32-byte-random>"
       issuer:    "http://keycloak:8080/realms/mcp"
       auth_url:  "http://keycloak:8080/realms/mcp/protocol/openid-connect/auth"
       token_url: "http://keycloak:8080/realms/mcp/protocol/openid-connect/token"
       audience:  "clickhouse-mcp"
       client_id: "clickhouse-mcp"
       client_secret: "<KEYCLOAK_CLIENT_SECRET>"   # via env in prod
       scopes: ["openid", "email"]
   ```

4. **ClickHouse `token_processors`** (forward mode):

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

See [zvonand/grafana-oauth](https://github.com/zvonand/grafana-oauth)
for a complete working example with Keycloak and ClickHouse.

### Azure AD (Microsoft Entra ID)

1. **Register an application** in the [Azure Portal](https://portal.azure.com):
   - Microsoft Entra ID → App registrations → New registration
   - Add a redirect URI: your MCP `<public>/oauth/callback`

2. **Create a client secret** under Certificates & secrets.

3. **Configure API permissions**: `openid`, `profile`, `email`.

4. **Note endpoints** (from app overview):
   - Tenant ID, Application (Client) ID
   - Token URL:    `https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token`
   - Auth URL:     `https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/authorize`
   - OIDC discovery: `https://login.microsoftonline.com/{TENANT_ID}/v2.0/.well-known/openid-configuration`

5. **Forward-mode MCP config:**

   ```yaml
   server:
     oauth:
       enabled: true
       mode: forward
       signing_secret: "<32-byte-random>"
       issuer:    "https://login.microsoftonline.com/<TENANT_ID>/v2.0"
       audience:  "<APP_CLIENT_ID>"
       client_id: "<APP_CLIENT_ID>"
       client_secret: "<APP_CLIENT_SECRET>"   # via env
       token_url: "https://login.microsoftonline.com/<TENANT_ID>/oauth2/v2.0/token"
       auth_url:  "https://login.microsoftonline.com/<TENANT_ID>/oauth2/v2.0/authorize"
       scopes: ["openid", "profile", "email"]
   ```

See [zvonand/grafana-oauth/azure](https://github.com/zvonand/grafana-oauth/tree/main/azure)
for a complete working example with Azure AD and ClickHouse.

### Google Cloud Identity

1. **Create OAuth 2.0 credentials** in the [Google Cloud Console](https://console.cloud.google.com)
   under APIs & Services → Credentials → OAuth client ID → Web
   application. Set the authorized redirect URI to
   `<public>/oauth/callback`.

2. **Forward-mode MCP config:**

   ```yaml
   server:
     oauth:
       enabled: true
       mode: forward
       signing_secret: "<32-byte-random>"
       issuer:    "https://accounts.google.com"
       audience:  "<GOOGLE_CLIENT_ID>.apps.googleusercontent.com"
       client_id: "<GOOGLE_CLIENT_ID>.apps.googleusercontent.com"
       client_secret: "<GOOGLE_CLIENT_SECRET>"   # via env
       token_url: "https://oauth2.googleapis.com/token"
       auth_url:  "https://accounts.google.com/o/oauth2/v2/auth"
       scopes: ["openid", "profile", "email"]
   ```

3. **ClickHouse `token_processors`** (forward mode):

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
[Using OAuth 2.0 to Access Google APIs](https://developers.google.com/identity/protocols/oauth2),
[Setting up OAuth 2.0 in Google Cloud Console](https://support.google.com/googleapi/answer/6158849).

### AWS Cognito

1. **Create a user pool** in the [AWS Console](https://console.aws.amazon.com/cognito).
   Configure sign-in (email/username), password policies, and add an
   App Client with OAuth 2.0 enabled (Authorization Code grant, scopes
   `openid` `profile` `email`, callback URL `<public>/oauth/callback`).

2. **Note endpoints:**
   - Issuer URL: `https://cognito-idp.{REGION}.amazonaws.com/{USER_POOL_ID}`
   - Token URL:  `https://{DOMAIN}.auth.{REGION}.amazoncognito.com/oauth2/token`
   - Auth URL:   `https://{DOMAIN}.auth.{REGION}.amazoncognito.com/oauth2/authorize`
   - OIDC discovery: `https://cognito-idp.{REGION}.amazonaws.com/{USER_POOL_ID}/.well-known/openid-configuration`

3. **Forward-mode MCP config:**

   ```yaml
   server:
     oauth:
       enabled: true
       mode: forward
       signing_secret: "<32-byte-random>"
       issuer:    "https://cognito-idp.<REGION>.amazonaws.com/<USER_POOL_ID>"
       audience:  "<APP_CLIENT_ID>"
       client_id: "<APP_CLIENT_ID>"
       client_secret: "<APP_CLIENT_SECRET>"   # via env
       token_url: "https://<DOMAIN>.auth.<REGION>.amazoncognito.com/oauth2/token"
       auth_url:  "https://<DOMAIN>.auth.<REGION>.amazoncognito.com/oauth2/authorize"
       scopes: ["openid", "profile", "email"]
   ```

4. **ClickHouse `token_processors`** (forward mode):

   ```xml
   <token_processors>
       <cognito>
           <type>openid</type>
           <configuration_endpoint>https://cognito-idp.<REGION>.amazonaws.com/<USER_POOL_ID>/.well-known/openid-configuration</configuration_endpoint>
           <token_cache_lifetime>60</token_cache_lifetime>
       </cognito>
   </token_processors>
   ```

References: [Amazon Cognito - OIDC IdPs](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-oidc-idp.html),
[How to use OAuth 2.0 in Amazon Cognito](https://aws.amazon.com/blogs/security/how-to-use-oauth-2-0-in-amazon-cognito-learn-about-the-different-oauth-2-0-grants/),
[Cognito IdP endpoints](https://docs.aws.amazon.com/cognito/latest/developerguide/federation-endpoints.html).

## Helm chart deployment

The chart at [`helm/altinity-mcp/`](../helm/altinity-mcp/) supports all
OAuth options under `config.server.oauth`. Example values files:

```bash
helm install altinity-mcp ./helm/altinity-mcp \
  -f helm/altinity-mcp/values_examples/mcp-oauth-keycloak.yaml
```

- `values_examples/mcp-oauth-keycloak.yaml` — Keycloak / generic OIDC
- `values_examples/mcp-oauth-azure.yaml` — Azure AD
- `values_examples/mcp-oauth-google.yaml` — Google Cloud Identity

For gating mode, also deploy the sidecar from
[`altinity-oauth-helper`](https://github.com/altinity/altinity-oauth-helper)
into the ClickHouse pod.

## Security considerations

- **`signing_secret`** protects all stateless OAuth artifacts (forward-
  mode authorization codes, refresh-token JWEs, HKDF-derived signing
  material). Treat it like a signing key. Rotate it to invalidate all
  outstanding tokens.
- **MCP no longer holds a per-tenant ClickHouse credential.** In gating
  mode there is no shared cluster secret. In forward mode the bearer is
  the upstream IdP's JWT, validated end-to-end by `token_processors`.
- **Gating-mode tokens are upstream-IdP-issued.** MCP does not mint or
  revoke them. Revocation propagates within the IdP's access-token TTL
  window + the sidecar's positive-cache TTL (default 30 s).
- **Opaque bearer tokens are not supported.** Inbound OAuth requires a
  signed JWT validatable via JWKS. RFC 7662 introspection is not
  implemented.
- **Token preference during browser login.** When both `id_token` and
  `access_token` come back from the upstream, `altinity-mcp` prefers
  `id_token` as the MCP bearer and falls back to `access_token` only
  when no `id_token` is available.
- **CIMD is the only inbound registration model.** Dynamic Client
  Registration (DCR, RFC 7591) is intentionally not exposed —
  `/oauth/register` returns HTTP 410 Gone with an RFC 7591 §3.2.2 JSON
  error pointing at the CIMD spec.

## Troubleshooting

### ClickHouse returns HTTP 403 with `Bearer HTTP Authorization scheme is not supported`

Forward mode without `token_processors`. The build is OSS-only or
otherwise lacks JWT auth. Either switch to gating mode (deploy the
sidecar; see [`altinity-oauth-helper`](https://github.com/altinity/altinity-oauth-helper)) or upgrade to a
ClickHouse build with `token_processors` (Altinity Antalya 25.8+).

### Token validation fails with `issuer mismatch`

`oauth.issuer` doesn't exactly match the `iss` claim. Common causes:

- Trailing slash mismatch (`https://idp.example.com` vs
  `https://idp.example.com/`).
- Missing `/v2.0` suffix for Azure AD.
- Wrong realm path for Keycloak.

In gating mode, `issuer` must exactly match the `iss` claim in the
AS-issued JWT. `public_auth_server_url` is forward-mode-only — startup
refuses it under gating.

### ClickHouse authenticates but the user has no permissions

Create the roles referenced in `common_roles` (forward) or
`DEFAULT ROLE` (gating) and grant them the necessary permissions:

```sql
CREATE ROLE OR REPLACE default_role;
GRANT SELECT ON *.* TO default_role;
```

### Gating-mode error `oauth gating: bearer is not a JWT with an email claim`

The IdP stripped the top-level `email` claim from the access token.
Some IdPs (Auth0 enhanced-security DCR is one) strip standard OIDC
claims for third-party clients unless they're set under a namespaced
URL claim. Configure a post-login action that injects
`https://<your-namespace>/email` (or similar) into the access token;
`altinity-mcp` reads any claim with a `/email` suffix as a fallback for
the top-level `email`.

### `block decode for exception: unexpected value 10 for boolean`

The clickhouse-go driver received text where it expected native binary
blocks. Common cause: a `FORMAT JSON` (or `FORMAT TSV`, etc.) suffix in
the SQL — the driver speaks native binary over HTTP and the format
override makes ClickHouse return text. Drop the `FORMAT` clause; MCP
serializes results to JSON for the LLM itself.

### More troubleshooting

For sidecar-specific errors (JWKS rotation, audience byte-equality,
sidecar binding gotchas) see the
[`altinity-oauth-helper`](https://github.com/altinity/altinity-oauth-helper)
repo's troubleshooting section.
