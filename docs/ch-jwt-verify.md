# ch-jwt-verify — ClickHouse-side JWT verifier sidecar

Companion to gating-mode `altinity-mcp`. Validates per-query OAuth bearers
against an upstream IdP's JWKS so that ClickHouse can authenticate users
cryptographically without `altinity-mcp` ever holding a shared secret.

For the protocol-level "how MCP talks to CH" picture see
[`oauth_authorization.md`](oauth_authorization.md). This document is the
canonical spec for the sidecar itself: rationale, wire contract, config
schema, identity policy, scope→settings mapping, deployment topology,
troubleshooting.

## Why this exists

Pre-sidecar, `altinity-mcp` in gating mode held a shared `cluster_secret`
that let it impersonate any provisioned ClickHouse user as a trusted
interserver-cluster peer. ClickHouse trusted the impersonation because
the peer presented the secret. Trust radius: compromise the MCP pod,
forge identity to ClickHouse as any user, including `default`/admin
accounts.

The sidecar removes that path. Each query carries
`Authorization: Basic base64(email:JWT)` end-to-end; ClickHouse's
[`<http_authentication>`](https://clickhouse.com/docs/operations/external-authenticators/http)
delegates the password check to the sidecar, which:

1. Decodes the Basic header into `(user, jwt)`.
2. Fetches the upstream IdP's JWKS (cached) and **verifies the JWT
   signature**.
3. Checks `iss` (exact match), `aud` (RFC 8707 byte-equality), `exp`/`nbf`
   (with clock-skew tolerance).
4. Enforces the configured required scopes.
5. Applies identity policy: `email_verified`, email-domain allow-list,
   hosted-domain allow-list.
6. **Matches the Basic user half against a JWT claim** (default: `email`,
   `lowercase_equal`) — preventing a compromised MCP pod from sending a
   valid JWT for user A while claiming to be user B in the Basic header.

A compromised MCP pod now buys an attacker nothing they don't already
have via a stolen bearer — the cryptographic gate sits next to the data
plane and the MCP pod is just a forwarder.

## Wire contract

```
Request:
    GET or POST  /verify
    Authorization: Basic base64(<user>:<jwt>)

Response (success):
    HTTP 200
    Content-Type: application/json
    Body:
      {
        "settings": { "<setting_name>": "<setting_value>", ... },
        "email":    "<claim>"
      }

Response (failure):
    HTTP 401 (missing/malformed Authorization)
    HTTP 403 (validation failed for any reason)
    Body: plain-text human-readable error (sidecar log only;
          ClickHouse ignores the body and reads the status code)
```

ClickHouse's HTTP authentication response parser
([`SettingsAuthResponseParser.cpp`](https://github.com/ClickHouse/ClickHouse/blob/master/src/Access/SettingsAuthResponseParser.cpp))
treats the JSON `settings` field as **session-scoped** settings applied
for the duration of the authenticating query only. They cannot persist
or escape the request scope — useful for per-scope row caps, read-only
flags, memory limits, etc.

`/healthz` returns 200 + `"ok"` unconditionally for liveness/readiness
probes. There is no `/metrics` endpoint in v1.

### Why a JWT in the Basic password slot?

`<http_authentication>` is the only ClickHouse external-authenticator
that runs per query and works on OSS ClickHouse builds. It only carries
forwarded HTTP headers to the auth server, not the request body. The
Basic auth header is the natural carrier because:

- HTTP RFCs and middleware handle it transparently.
- The CH go-driver assembles it from the standard `Auth.Username` /
  `Auth.Password` fields with no special-case code.
- The Basic `user` slot is the perfect place for the **claimed** identity
  the sidecar will check against the JWT's signed `email` claim, making
  the user-vs-claim binding an explicit part of the wire format.

The JWT does not exceed the typical Basic-auth header-size budget
(64–128 KiB on most HTTP stacks) for tokens up to a few KB.

## Architecture

```
   claude.ai / ChatGPT
         │  Bearer <JWT>
         ▼
   altinity-mcp           (pure forwarder; no per-request crypto)
         │  rewrite to
         │  Basic base64(email:JWT)
         │  protocol: HTTP only
         ▼
   ┌──────────────────────────────┐
   │ ClickHouse pod               │
   │                              │
   │  clickhouse-server (8123)    │
   │    ↓ <http_authentication>   │
   │  ch-jwt-verify (127.0.0.1)   │  ← signature, iss, aud, exp,
   │    ↑ signature + iss         │    scope, identity policy,
   │    ↑ aud + scope + policy    │    user-vs-claim match
   │    ↑ user-vs-email match     │
   └──────────────────────────────┘
                ↓
            (cached JWKS from upstream IdP)
```

Per-user provisioning on ClickHouse:

```sql
CREATE USER `alice@example.com`
  IDENTIFIED WITH http SERVER 'ch_jwt_verify' SCHEME 'BASIC'
  DEFAULT ROLE mcp_reader;
GRANT mcp_reader TO `alice@example.com`;
```

The grammar token is `http`, not `http_authenticator` — ClickHouse rejects
the latter with `SYNTAX_ERROR`. `SERVER 'ch_jwt_verify'` must match the
`<http_authentication_servers><ch_jwt_verify>` block name from CH config.

## Deployment topology

Two supported shapes, each with a different trust boundary.

### Colocated (production)

The sidecar runs as an additional container in the **same pod** as
ClickHouse. ClickHouse reaches the sidecar via `127.0.0.1`, and the
sidecar's port is never exposed beyond the pod's network namespace. A
sibling pod in the same namespace cannot reach the sidecar — only the
ClickHouse process in the same netns can.

This is the strongest trust boundary the sidecar supports. **Use this
in production.**

Requires:
- A way to inject a second container into the ClickHouse pod's spec.
  With clickhouse-operator this is a `podTemplate` edit on the
  `ClickHouseInstallation` CR (or a `ClickHouseInstallationTemplate`
  that the operator preserves on reconcile).
- `listen.tcp: 0.0.0.0:<port>` in sidecar config (not `127.0.0.1`) —
  see [Sidecar binding gotcha](#sidecar-binding-gotcha) below.

### Standalone (testing / validation)

The sidecar runs as its own `Deployment` + `Service` in the same
namespace as ClickHouse. ClickHouse reaches it via cluster DNS
(`http://ch-jwt-verify.<ns>.svc.cluster.local:<port>/verify`).

Trust boundary expands to **anything in the same Kubernetes namespace** —
a sibling pod could in principle hit the sidecar's port. Without a JWT
the sidecar 401s; with a stolen JWT the worst it can do is return the
session-settings response, which is useless without separately reaching
ClickHouse with the same JWT.

Acceptable for shadow / smoke-test deployments. Lock down further with a
`NetworkPolicy` restricting ingress to the ClickHouse pod selector if
the namespace is multi-tenant.

### Sidecar binding gotcha

Kubernetes liveness/readiness probes target the **pod IP** (the pod
netns's `eth0`), not loopback. A server bound to `127.0.0.1` is reachable
from the ClickHouse process in the same netns (loopback works) but
**not** from the kubelet probe — the kubelet would CrashLoop the
container.

Bind `0.0.0.0:<port>` even in the colocated case. ClickHouse-on-loopback
in the same pod still reaches it. In the colocated case, no `Service`
exposes the port — so the bind address has no external effect.

## Config schema

Top-level YAML structure:

```yaml
listen:
  unix: <path>          # mutually exclusive with tcp; one or the other
  tcp:   <host:port>    # bind 0.0.0.0:9999 for colocated; see note above

oauth:
  issuer:              <https URL>
  jwks_url:            <https URL>   # optional; discovered from issuer if omitted
  audience:            <string>      # RFC 8707 byte-equal target (mandatory)
  required_scopes:     [<scope>, ...]
  jwks_cache_ttl:      <duration>    # default 5m
  jwks_refresh_ahead:  <duration>    # default 1m (reserved; see Caching)

identity:
  username_claim:        email | sub | <custom>   # default: email
  match_mode:            lowercase_equal | exact  # default: lowercase_equal
  require_email_verified: true | false             # default: true
  allowed_email_domains:  [<domain>, ...]          # empty = no allow-list
  allowed_hosted_domains: [<domain>, ...]          # empty = no allow-list

settings_from_scope:
  <scope-name>:
    <ch-setting>: <value>
  ...

cache:
  positive_ttl: <duration>   # default 30s
  negative_ttl: <duration>   # default 5m
```

### `listen`

Exactly one of `unix` or `tcp` must be set. Startup fails otherwise.

- `unix`: e.g. `/run/ch-jwt-verify/sock`. Preferred when ClickHouse and
  the sidecar can share a volume — zero port surface, fs permissions
  gate access.
- `tcp`: e.g. `0.0.0.0:9999`. Required when a shared-volume Unix socket
  isn't practical, or when running standalone.

### `oauth`

- **`issuer`** — the upstream IdP's issuer URL. Used to discover the
  authorization-server metadata (and the JWKS URL via standard OIDC
  discovery) when `jwks_url` is omitted. Also enforced as the JWT's
  expected `iss` claim (slash-normalized).
- **`jwks_url`** — explicit JWKS endpoint. Set this to avoid a discovery
  hop on cold start.
- **`audience`** — must byte-equal the JWT's `aud` claim (RFC 8707
  resource-indicator). Trailing slash matters; whitespace matters. If
  the upstream IdP emits the audience with a trailing `/`, configure it
  with the trailing `/`.
- **`required_scopes`** — token's `scope` claim must be a superset.
  Empty list disables the check.
- **`jwks_cache_ttl`** — how long a JWKS document stays cached. Shared
  with `pkg/oauth`'s validator.
- **`jwks_refresh_ahead`** — reserved; behavior is to refresh JIT on
  `kid` miss (key rotation). Cache TTL alone bounds staleness.

### `identity`

- **`username_claim`** — which JWT claim to match against the Basic
  user half. `email` (OIDC standard) is the common case; for opaque
  principals use `sub`; for any other claim, the sidecar reads it from
  the JWT's `Extra` (non-standard) map as a string.
- **`match_mode`** — `lowercase_equal` (default) tolerates case
  differences common when operators provision ClickHouse users in
  lowercase. `exact` requires byte-equal.
- **`require_email_verified`** — if `true` (default), the sidecar
  rejects tokens with `email_verified=false` (only when the JWT carries
  an `email` claim at all; tokens without an `email` claim are unaffected
  by this check).
- **`allowed_email_domains`** — case-insensitive allow-list applied to
  the lowercased domain portion of the JWT's `email` claim. Empty list
  disables the check.
- **`allowed_hosted_domains`** — case-insensitive allow-list applied to
  the JWT's `hd` claim (Google Workspace / similar). Empty list disables
  the check.

#### Why the user-vs-claim match matters

ClickHouse uses the Basic header's `user` half for **user lookup** —
which `CREATE USER` definition to consult. Without the user-vs-claim
check, a compromised middleware could send a valid JWT for `alice` while
claiming `Basic admin:<alice's JWT>` and ClickHouse would resolve as
`admin`. The check binds the two.

### `settings_from_scope`

Maps an OAuth scope name to a set of ClickHouse session settings
returned in the `/verify` response. ClickHouse applies these for the
duration of the authenticating query.

```yaml
settings_from_scope:
  mcp:read:
    readonly: "1"
    max_result_rows: "10000"
  mcp:write: {}     # explicit empty map means "no settings derived from this scope"
```

Token scopes not in the map are silently ignored — a token with one
known + one unknown scope still gets the known one's settings.
First-writer-wins on conflicts between two scopes' settings.

### `cache`

- **`positive_ttl`** — successful validations are cached by
  `SHA256(JWT)` for this long. Bounds the cost of repeated queries by
  the same JWT.
- **`negative_ttl`** — failed validations are cached too, with the
  failure reason, for this long. Suppresses repeated cryptographic
  checks when an upstream replays a bad token.

Cache is in-process and bounded by JWT lifetime — an entry can't outlive
the JWT's real `exp` because the next validation after `positive_ttl`
expiry will reject an expired JWT.

### Environment-variable overrides

For deployment-time fields the Helm chart sets, these env vars override
the YAML at startup. Naming: `CH_JWT_VERIFY_<UPPER_SNAKE>`.

| Env var | YAML field |
|---|---|
| `CH_JWT_VERIFY_LISTEN_UNIX` | `listen.unix` |
| `CH_JWT_VERIFY_LISTEN_TCP`  | `listen.tcp` |
| `CH_JWT_VERIFY_OAUTH_ISSUER`   | `oauth.issuer` |
| `CH_JWT_VERIFY_OAUTH_JWKS_URL` | `oauth.jwks_url` |
| `CH_JWT_VERIFY_OAUTH_AUDIENCE` | `oauth.audience` |
| `CH_JWT_VERIFY_LOG_LEVEL` | log level (debug / info / warn / error) |
| `CH_JWT_VERIFY_CONFIG` | path to config file (default `/etc/ch-jwt-verify/config.yaml`) |

## Config example

Production-shape config for a colocated deployment validating Auth0
tokens for a single MCP audience:

```yaml
listen:
  tcp: "0.0.0.0:9999"

oauth:
  issuer:   "https://example.auth0.com/"
  jwks_url: "https://example.auth0.com/.well-known/jwks.json"
  audience: "https://mcp.example.com/"
  required_scopes: []
  jwks_cache_ttl: 5m
  jwks_refresh_ahead: 1m

identity:
  username_claim: email
  match_mode: lowercase_equal
  require_email_verified: true
  allowed_email_domains:
    - example.com
  allowed_hosted_domains: []

settings_from_scope:
  mcp:read:
    readonly: "1"
  mcp:write: {}

cache:
  positive_ttl: 30s
  negative_ttl: 5m
```

## CH-side config

The ClickHouse `<http_authentication_servers>` block, dropped into
`config.d/`:

```xml
<?xml version="1.0"?>
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

- **`<uri>`** — `http://127.0.0.1:<port>/verify` for colocated; the
  Kubernetes service DNS for standalone.
- **`<forward_headers>`** — must include `Authorization`. ClickHouse
  default-drops Authorization for safety; without this, the sidecar
  receives no auth header and 401s.
- **The server name (`<ch_jwt_verify>` here)** is referenced from
  `CREATE USER` definitions and must match `SERVER 'ch_jwt_verify'`
  exactly.

Per-user provisioning:

```sql
-- Create the role with the permissions the OAuth identity should have.
CREATE ROLE IF NOT EXISTS mcp_reader;
GRANT SELECT ON analytics.* TO mcp_reader;

-- Bind one user per identity; no password, delegated to the sidecar.
CREATE USER `alice@example.com`
  IDENTIFIED WITH http SERVER 'ch_jwt_verify' SCHEME 'BASIC'
  DEFAULT ROLE mcp_reader;
GRANT mcp_reader TO `alice@example.com`;
```

The user's `IDENTIFIED WITH http` clause replaces the previous
`IDENTIFIED WITH no_password` (under `cluster_secret` impersonation).
ClickHouse calls the `ch_jwt_verify` HTTP authentication server for the
password check; password is the JWT, validated end-to-end by the
sidecar.

### `<token>` user_directory interaction

If your ClickHouse has a `<token>` entry in `<user_directories>` (e.g.
for native JWT auth via Antalya `token_processors` or an OIDC token
provider), the lookup precedence is `users_xml > replicated > token`.
A user `CREATE`d in `replicated` shadows any ephemeral version in the
`<token>` directory.

If both code paths need to work for the same email (e.g. one user
querying ClickHouse both via `ch-jwt-verify` and via a separate
JWT-forwarding path), you cannot serve both via the same `replicated`
user — the `<http>` authenticator and the `<token>` directory expect
incompatible authorization headers. Pick one path per user.

## Caching behavior

The sidecar's in-process cache is keyed by `SHA256(token)` (truncated to
16 hex chars for cache-key uniqueness within a single process lifetime).

- **Positive cache (`cache.positive_ttl`, default 30s)** — successful
  validations skip JWKS lookup + signature check + identity policy.
  Bounded by the JWT's real `exp` — after `positive_ttl` expiry, the
  next validation rejects expired tokens.
- **Negative cache (`cache.negative_ttl`, default 5m)** — failed
  validations cache the failure reason and short-circuit repeated bad
  requests for the same token.

**JWKS cache** (separate from validation cache): the sidecar fetches the
upstream JWKS once per `oauth.jwks_cache_ttl` (default 5m) and stores
the JSON Web Key Set in memory. When a JWT references a `kid` not in the
cached set (key rotation), the cache is invalidated once and re-fetched
JIT — the validation succeeds on the same request as long as the new
`kid` is in the refreshed set.

There is no Redis / external cache and no warming on startup. The first
request after a cold start (or after the JWKS TTL expires) pays one
JWKS HTTP round trip.

## Build + run

### Build the binary

```bash
go build -o ch-jwt-verify ./cmd/ch-jwt-verify
```

### Build the container image

The image is cross-compiled and pushed via
`scripts/build-ch-jwt-verify-image.sh`:

```bash
ARCHES=arm64 scripts/build-ch-jwt-verify-image.sh sidecar
# → ghcr.io/altinity/ch-jwt-verify:sidecar-<short-sha>-arm64
```

`REGISTRY=`, `IMAGE=`, `ARCHES=`, and the tag prefix are overridable.
The script uses legacy `docker build` (sandbox-friendly) and assembles
a multi-arch manifest when given multiple `ARCHES`.

### Run directly

```bash
./ch-jwt-verify --config=/path/to/config.yaml --log-level=info
```

The binary supports `--config` (env: `CH_JWT_VERIFY_CONFIG`) and
`--log-level` (env: `CH_JWT_VERIFY_LOG_LEVEL`). SIGINT/SIGTERM trigger
a 5-second graceful shutdown.

## Helm chart

The chart at `helm/ch-jwt-verify/` is intentionally not a Deployment.
It renders two ConfigMaps and a reusable container fragment template:

- `<release>-ch-jwt-verify-config` — the sidecar's `config.yaml`,
  mounted at `/etc/ch-jwt-verify/`.
- `<release>-ch-jwt-verify-ch-config` — the CH-side
  `<http_authentication_servers>` XML, mounted into the ClickHouse
  container at `/etc/clickhouse-server/config.d/`.
- `ch-jwt-verify.container` — a helper template emitting the
  container spec to splice into your CH pod.

See `helm/ch-jwt-verify/README.md` for the wiring example.

## Troubleshooting

### `oauth gating: bearer is not a JWT with an email claim`

Reported by `altinity-mcp` (not the sidecar) when the inbound bearer
has no top-level `email` claim and no namespaced `*/email` fallback.
Common causes:

- The upstream IdP's policy strips top-level OIDC claims for
  third-party DCR clients (Auth0 enhanced-security DCR does this).
  Solution: add a post-login action that injects a **namespaced** email
  claim (e.g. `https://mcp.example.com/email`). `pkg/oauth`'s
  `EmailFromNamespacedExtra` reads any `*/email` suffix.
- The upstream IdP's audience-conditional logic isn't applying. Some
  IdPs let you scope post-login actions per audience — your audience
  must be in the action's allowlist.

### `Token authentication is not configured` from ClickHouse

`<http_authentication>` is wired but ClickHouse doesn't recognize the
`<http>` user identifier. Check that the CH version supports the
`IDENTIFIED WITH http SERVER ...` syntax (24.x+ for OSS; older Altinity
Antalya builds have it via the `<token>` directive instead). Confirm
the config file is loaded:

```bash
kubectl exec <ch-pod> -- ls /etc/clickhouse-server/config.d/
kubectl exec <ch-pod> -- grep -r http_authentication_servers /etc/clickhouse-server/
```

### `Code: 516. AUTHENTICATION_FAILED` from ClickHouse

The CH-side authenticator rejected the request. Three sub-cases:

1. **User doesn't exist** — check the user is provisioned in
   `replicated` (or `users_xml`) storage:

   ```sql
   SELECT name, auth_type, storage FROM system.users WHERE name = '<email>';
   ```

2. **User has `VALID UNTIL` past** — some flows
   (ACM `temp_creds`-style provisioning) create users with a 1-hour
   expiry. Re-`CREATE USER OR REPLACE` without `VALID UNTIL`.

3. **Sidecar rejected the JWT** — check sidecar logs:

   ```bash
   kubectl logs <ch-pod> -c ch-jwt-verify --tail=50
   ```

   The sidecar logs every reject with the reason
   (`token expired`, `aud mismatch`, `user does not match JWT email
   claim`, etc.).

### Sidecar CrashLoopBackOff on liveness probe

If the sidecar's `listen.tcp` is `127.0.0.1:<port>`, the kubelet
liveness probe (which targets the pod IP, not loopback) can't reach it.
Switch to `0.0.0.0:<port>` — see
[Sidecar binding gotcha](#sidecar-binding-gotcha).

### `block decode for exception: unexpected value 10 for boolean`

The clickhouse-go driver received text where it expected native binary
blocks. Common cause: a `FORMAT JSON` (or `FORMAT TSV`, etc.) suffix in
the SQL — the driver speaks native binary over HTTP and the format
override makes ClickHouse return text. Drop the `FORMAT` clause; MCP
serializes results to JSON for the LLM itself.

### Sidecar logs `failed to validate JWT: invalid claims` followed by aud mismatch

The token's `aud` differs from the sidecar's configured `audience`,
byte for byte. RFC 8707 byte-equality is strict — trailing slashes,
case, and any whitespace count. Decode a real token and compare:

```bash
echo "<JWT>" | cut -d. -f2 | base64 -d 2>/dev/null | jq '.aud'
```

The `aud` claim is sometimes a string and sometimes an array; the
sidecar accepts both shapes but matches each element strictly.

### `no JWK found for kid "..."` even after JWKS refresh

The token references a signing key not in the upstream IdP's published
JWKS. Possible causes:

- The token was minted by a different IdP (audience misconfiguration —
  the sidecar's `oauth.issuer` doesn't match the IdP that minted the
  token).
- The IdP rotated keys and the new `kid` isn't published yet (very
  rare; mostly affects multi-region IdP deployments).
- A forged token.

Verify the IdP and key set:

```bash
curl -s <jwks_url> | jq '.keys[] | .kid'
```

## Security considerations

- **JWT in Basic password slot** — the JWT travels over HTTP as a Basic
  password (base64 in the `Authorization` header). The CH↔sidecar
  channel must be loopback or otherwise non-network for this to be
  acceptable. Standalone deployments require either a NetworkPolicy
  scoping the sidecar to the CH pod selector, or accepting that any
  pod in the same namespace can attempt validation (the attempt fails
  without a stolen JWT).

- **Signing-secret separation** — the sidecar holds no secrets of its
  own; it only holds the upstream IdP's public JWKS. Compromising the
  sidecar reveals no signing material — at worst an attacker disrupts
  validation (DoS).

- **Cache as oracle** — the verification cache is keyed by
  `SHA256(JWT)`, not by user/email. A negative-cache hit reveals
  "this exact JWT was tried before and failed", but not what user or
  scope was claimed. Acceptable.

- **`require_email_verified` is on by default** for new configs. The
  sidecar's identity policy is the only enforcement; `altinity-mcp` no
  longer applies any identity policy after the sidecar refactor.

- **No introspection (RFC 7662)** — only JWTs are validated. Opaque
  tokens would require an introspection endpoint, which `pkg/oauth`
  doesn't implement.

- **No revocation list** — token revocation lands at the next request
  after the validation cache expires (`cache.positive_ttl`, default
  30s). The IdP's token TTL bounds revocation latency.

## See also

- [`oauth_authorization.md`](oauth_authorization.md) — protocol-level
  "how it works" for altinity-mcp's OAuth modes.
- [`helm/ch-jwt-verify/README.md`](../helm/ch-jwt-verify/README.md) —
  chart usage, wiring example.
- `cmd/ch-jwt-verify/` — source.
- ClickHouse docs:
  [HTTP external authenticator](https://clickhouse.com/docs/operations/external-authenticators/http),
  [`<http_authentication_servers>` config](https://clickhouse.com/docs/operations/external-authenticators/http#http-authentication-servers-config).
