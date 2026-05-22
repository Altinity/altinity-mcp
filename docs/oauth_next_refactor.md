# OAuth refactor — follow-up: adopting `auth.RequireBearerToken`

## Status

Captured during the `pkg/oauth/` extraction (PR oauth/refactor-go-sdk-adoption).
This document records:
1. Why `auth.RequireBearerToken` from `modelcontextprotocol/go-sdk` was deferred.
2. The follow-up work that completes the broker extraction begun in this PR.

## What landed in this PR

- `pkg/oauth/` package: `OAuthConfig`, `Claims`, errors, context keys, `Verifier`
  (owns JWKS + OIDC discovery cache), `ValidateToken`, identity policy, forward
  header builder, namespaced-email extra-claim helper. All public APIs.
- `pkg/server/server_auth_oauth.go` is now a thin alias-and-delegate shim over
  `pkg/oauth.Verifier`. `ClickHouseJWEServer` no longer owns OAuth cache state.
- `pkg/config.OAuthConfig` is a type alias to `pkg/oauth.OAuthConfig`.
- `UpstreamIssuerAllowlist` field, `issuerAllowed` helper, and matching tests
  removed (YAGNI — single-AS deployments only).
- go-sdk `auth.GetAuthServerMetadata` adopted for OIDC/AS discovery (with
  fallback into `oauthex.AuthServerMeta` struct).
- `pkg/oauth/broker/` package created with exported pure helpers (URL/path
  normalisation, PKCE, scope advertising, JWE codec for pending-auth and
  auth-code state, error-body sanitisation, userinfo claim projection,
  `IsGoogleIssuer`). Not yet wired into cmd/altinity-mcp — see "Deferred work".

## Deferred work — to land in follow-up PRs

1. **Wire cmd/altinity-mcp/oauth_server.go to use `pkg/oauth/broker/`**. The
   helpers exist in the package; the cmd file still carries its own copies.
   Switching the call sites is mechanical (rename `normalizeURL` →
   `broker.NormalizeURL` etc.); the bigger task is migrating method receivers
   (`(a *application).encodePendingAuth` etc.) into a `Broker` type that owns
   the JWE-secret accessor and CIMD resolver.
2. **Move oauth_server.go's route handlers into `pkg/oauth/broker/`**. Requires
   the `Broker` type above plus a `JWEAuthenticator` interface for the parts
   the middleware needs from `*server.ClickHouseJWEServer`.
3. **Move cimd.go and client_assertion.go** into `pkg/oauth/broker/`.
4. **Move OAuth test files** (`cmd/altinity-mcp/oauth_*_test.go`,
   `pkg/server/oauth_e2e_test.go`, `pkg/server/oauth_gating_embedded_test.go`)
   alongside their production code in `pkg/oauth/broker/`.
5. **Adopt `auth.ProtectedResourceMetadataHandler`** for the
   `/.well-known/oauth-protected-resource` endpoint. Blocked on either making
   `PublicResourceURL` mandatory (breaks dynamic-host derivation) or by
   wrapping the static handler with a per-request metadata builder.

## Context

The current `cmd/altinity-mcp` OAuth code (now extracted into `pkg/oauth/`) wires
a hand-rolled bearer-token middleware (`AuthInjector`) that:

1. Extracts the `Authorization: Bearer …` header.
2. Calls `Verifier.ValidateOAuthToken(token)`.
3. Soft-passes on two cases (returns `(nil, nil)`):
   - Opaque (non-JWT) bearer in forward mode — local validation impossible
     without RFC 7662 introspection.
   - JWT bearer without configured JWKS/issuer — operator hasn't told the
     server where to fetch verification keys.
4. Hard-fails on every other validation error with a WWW-Authenticate
   challenge + JSON error envelope (RFC 6750 + the broker error shape).

`auth.RequireBearerToken` from go-sdk would replace ~all of this with a single
middleware constructor + a `TokenVerifier` callback. It does NOT fit cleanly today.
This doc explains why and what would change that.

## Why deferred

### 1. Forward-mode opaque-token soft-pass cannot be expressed via `RequireBearerToken`

`RequireBearerToken` expects the verifier to return `(*TokenInfo, error)`. Both
arms are required:

- `(nil, nil)` produces HTTP 500 — the contract is "claim or reject".
- `TokenInfo.Expiration.IsZero()` is rejected at `auth.go:133-135`.

To preserve the soft-pass we'd have to **synthesize a fake `TokenInfo`** with a
far-future `Expiration` and empty everything else. That is dishonest data
flowing through the auth layer; the downstream `BuildClickHouseHeadersFromOAuth`
would have to learn to treat a synthetic TokenInfo as "no validation happened".
A custom bypass middleware deletes less code than it adds.

### 2. Forward-mode JWT validation is load-bearing

Even if the soft-pass were removed, forward-mode validation is not a no-op:

- `ClaimsToHeaders` security — operators map JWT claims to ClickHouse headers
  (e.g. `sub` → `X-ClickHouse-User`). Skipping local validation would allow a
  client to set arbitrary headers via a forged JWT signature.
- Identity policy — `allowed_email_domains`, `allowed_hosted_domains`,
  `email_verified` are enforced post-validation. Soft-pass disables them.
- ClusterSecret impersonation — `server_client.go` derives the impersonated
  user from `claims.Email`. Without claims we cannot impersonate.

Adopting `RequireBearerToken` blindly would silently disable these features in
the soft-pass paths.

### 3. The realistic deletion is small

Once you account for restoring our richer error envelope and per-tool scope
checks, `RequireBearerToken` deletes ~10–30 lines net. The custom
`AuthInjector` is small and well-tested; the cost/benefit doesn't justify the
risk in this refactor.

## Deployment audit checklist (the next refactor needs this)

For each live deployment, answer:

| Env       | mode             | uses `ClaimsToHeaders`? | identity policy?           | ClusterSecret? |
|-----------|------------------|-------------------------|----------------------------|----------------|
| otel      | gating+broker    | ?                       | ?                          | ?              |
| antalya   | forward          | ?                       | ?                          | ?              |
| github    | ?                | ?                       | ?                          | ?              |
| billing   | ?                | ?                       | ?                          | ?              |

Fill the table by reading `$MCP_DEPLOY_DIR/<env>/mcp-values.yaml`. Any "yes"
in columns 3–5 means soft-pass is **not** safe to drop for that env.

## Three viable adoption strategies

### Strategy A — Synthetic `TokenInfo`

Make the verifier return a `TokenInfo` with sentinel values for the soft-pass
cases. Downstream code learns to detect the sentinel.

- **Pro:** Drops in cleanly under `RequireBearerToken`.
- **Con:** Synthetic data poisons every downstream consumer. Easy to break by
  refactor — a future change that uses `TokenInfo.Subject` would silently
  start using `""` for soft-passed requests.
- **Verdict:** Don't.

### Strategy B — Conditional bypass middleware

Keep a thin altinity-mcp middleware that:
1. Checks if the inbound bearer would soft-pass (opaque or unconfigured JWKS).
2. If yes, sets a context marker and skips `RequireBearerToken`.
3. If no, delegates to `RequireBearerToken`.

- **Pro:** Honest — soft-pass is a labeled context state, not synthetic claims.
- **Con:** Two middlewares to maintain. The detection logic for "would
  soft-pass" duplicates `ValidateOAuthToken`'s early-return logic.
- **Verdict:** Workable; tests stay tractable.

### Strategy C — Drop soft-pass entirely

Require `Issuer` or `JWKSURL` to be configured under forward mode. Require
opaque-token deployments to configure introspection (RFC 7662, see below) or
fail closed.

- **Pro:** No special cases. `RequireBearerToken` fits perfectly.
- **Con:** Breaking change for deployments that pre-date issuer/JWKS being
  load-bearing. Requires the audit table above to be filled before deciding.
- **Verdict:** Preferred long-term; needs the audit.

## The missing third leg — RFC 7662 token introspection

The opaque-token soft-pass exists because we have no way to validate an opaque
bearer locally. RFC 7662 (OAuth 2.0 Token Introspection) closes that gap: the
resource server POSTs the token to the AS's `/introspect` endpoint and
receives a JSON document with `active`, `exp`, `scope`, `sub`, etc.

What this would look like:

```yaml
oauth:
  introspection_endpoint: https://idp.example/oauth/introspect
  introspection_client_id: altinity-mcp
  introspection_client_secret_env: MCP_OAUTH_INTROSPECTION_SECRET
  introspection_cache_ttl: 60s
```

Per-request cost: one HTTPS round-trip to the AS, cacheable for `introspection_cache_ttl`
seconds keyed by token hash. With this implemented, the opaque-token soft-pass
becomes unnecessary — every bearer is locally validatable, either via JWKS
(JWT) or via `/introspect` (opaque).

Once introspection lands, **Strategy C** becomes the obvious choice.

## Decision criteria — when to revisit

Revisit this refactor when **all** of the following are true:

1. Upstream go-sdk PRs land (filed alongside this refactor):
   - `ClockSkew time.Duration` on `RequireBearerTokenOptions` (PR-1).
   - `oauthex.MatchesResource` helper (PR-2) — RFC 9728/RFC 8707
     trailing-slash tolerance, currently `audienceMatchesResource` in
     `pkg/oauth/jwt.go`.
   - `AllowMissingExpiration bool` on `RequireBearerTokenOptions` (PR-3) —
     so session-bound bearers without standalone `exp` can opt in.
2. The deployment audit table above is fully filled, and every "yes" cell is
   either no longer in production or has been migrated to a non-soft-pass
   configuration.
3. RFC 7662 introspection is implemented (closes the opaque-token soft-pass)
   OR a written decision is recorded that opaque-token deployments are no
   longer supported.

Until all three hold, the custom `AuthInjector` stays. The cost of holding
it (a hundred lines of well-tested middleware) is lower than the risk of a
silent ClaimsToHeaders / identity-policy / impersonation regression.

## Related references

- RFC 6750 — Bearer token usage.
- RFC 7662 — OAuth 2.0 Token Introspection.
- RFC 8707 — Resource Indicators for OAuth 2.0.
- RFC 9728 — OAuth 2.0 Protected Resource Metadata.
- `pkg/oauth/middleware.go` — current `AuthInjector` implementation.
- `pkg/oauth/validator.go` — `ValidateOAuthToken` and the soft-pass cases.
- `vendor/.../modelcontextprotocol/go-sdk/auth/auth.go` — `RequireBearerToken`
  contract this doc references.
