# OAuth compatibility hypotheses — to discuss before implementing

This document captures changes that the OAuth review (in commit history) flagged
as legitimate spec gaps but that we have **not** implemented yet because the
fix risks breaking real clients in non-obvious ways. Each section states the
hypothesis, what would change, and the specific compatibility question the
team needs to answer (or test against the live deployment) before merging.

The fixes already shipped are listed at the bottom for context.

---

## Resolved (with caveats): H-1 — Per-DCR-client consent screen

### What shipped

A real interactive HTML consent screen now renders in the user's browser
between `/oauth/callback` (after upstream IdP auth) and the gating-code
issuance to the DCR'd client. Per MCP authorization spec 2025-11-25
§Confused Deputy Problem.

The consent page surfaces:

- **Client** (the `client_name` the DCR client claimed — display only,
  never trusted)
- **Will redirect to** (the host portion of the registered redirect URI —
  the only field that materially helps the user spot a malicious DCR client)
- **Full redirect URI** (so the user can see the path too)
- **Resource** (the MCP server URI being authorized)
- **You are signed in as** (the user's email from upstream)
- **Scopes** (if the client requested any)

The page lives at `/oauth/consent` (configurable via `MCP_OAUTH_CONSENT_PATH`),
renders with strict CSP (`default-src 'self'; script-src 'none'`,
`frame-ancestors 'none'`, `Cache-Control: no-store`), and uses
`html/template` for safe interpolation. Approve issues a one-time gating
code and 302's to the registered redirect URI; Deny 302's with
`error=access_denied` per RFC 6749 §4.1.2.1. Consent state is single-use
and replays/tampering hit 400.

### Why this doesn't break JSX artifacts

The consent page only renders during `/callback`, which only runs during
**initial connector setup or re-authorization in the user's browser**.
The artifact path (cached bearer + token refresh via `/oauth/token`) never
goes through `/callback`. So once the user has set the connector up,
their JSX artifacts keep working with cached bearers and refresh tokens
— consent is a one-time interaction at connector-add time, not a recurring
gate per tool call.

### Caveat: the user has to actually click Approve in their browser

When adding a new connector via claude.ai Settings, the OAuth flow opens
the user's browser for upstream auth. Our consent page is one extra page
in that flow — the user sees it, reviews the redirect URI, clicks Approve.

If a different MCP client (e.g., a CLI-based one that uses a headless OAuth
flow without a real browser) tries to register, it'll dead-end at the
consent page. That's the trade-off: we're satisfying the spec by demanding
real user attention. Headless clients can pre-register out of band (the
spec calls this "Pre-registration" path) instead of going through DCR.

### What was *not* implemented

We didn't add per-`(user_sub, client_id)` consent caching. Every fresh
authorization (the user re-adding the connector, or after `/authorize`
has been called for any reason) re-renders the consent page. Two reasons:

1. `/authorize` is rare in practice — connector setup is usually once
   per browser per connector.
2. Cached consent introduces its own state-management problem (where do
   you store it, how do you revoke it, what happens on key rotation).
   Out of scope for the initial fix.

If the rate of re-consent prompts becomes a UX issue, add a JWE-encoded
"consent_token" cookie scoped to the user's browser session.

### Hypotheses 1A, 1B, 1C status

- **1A** (proxy is headless, can't render): not in play. claude.ai's
  custom-connector setup uses the user's browser, not the proxy's
  internal flow. Live test confirmed Approve+302 lets JSX artifacts work.
- **1B** (auto-submit consent for headless): not needed; we picked the
  real-consent path because the user-visible browser is available.
- **1C** (PKCE + redirect-URI binding is enough): rejected. The spec
  strictly requires user consent, and the residual risk (attacker DCRs a
  client, tricks user into authorizing it) is real enough to warrant a
  user-visible review step.

---

## H-2 — Forward-mode token passthrough

### What the spec says

MCP spec §Access Token Privilege Restriction:

> "If the MCP server makes requests to upstream APIs ... The MCP server **MUST
> NOT** pass through the token it received from the MCP client."

Our forward mode forwards the bearer to ClickHouse via Authorization header.
ClickHouse re-validates via JWKS using `token_processors`. Spec-strict reading:
this is non-compliant.

### Hypothesis-2A: ClickHouse-side validation counts as "the MCP server validated"

The intent of the spec rule is to prevent confused-deputy across the
MCP-server boundary. In forward mode the MCP server doesn't have privileged
access ClickHouse doesn't — both validate against the same upstream JWKS, both
extract the same identity. Architecturally there's no privilege escalation to
exploit.

A stricter reading: the spec doesn't care about architecture; it says MUST
NOT pass-through. Period.

### Hypothesis-2B: RFC 8693 token exchange would be the spec-clean path

We could mint a fresh ClickHouse-scoped token in the MCP server using token
exchange (or just by re-signing identity claims under a key ClickHouse trusts).
Compatibility cost: requires a new key-distribution arrangement between MCP
and ClickHouse, breaks the existing `token_processors` config, and adds a
network round-trip per request.

### What we'd need to test

This isn't really a compatibility question — it's a "should we redesign
forward mode" question. Recommended: **document the deviation explicitly in
`docs/oauth_authorization.md`, accept it as a deliberate architectural
choice**, and revisit when MCP spec adds explicit guidance for transparent
gateways.

---

## Resolved: H-4 — HKDF-derived per-context keys + kid migration (Step 2)

### What shipped

Each cryptographic use of the shared `SigningSecret` now derives an
independent 32-byte key via HKDF-SHA256 (RFC 5869 §3.2 domain separation):

| Use | HKDF info label | kid |
|---|---|---|
| client_id JWE wrap | `altinity-mcp/oauth/client-id/v1` | `v1` |
| refresh-token JWE wrap (gating + forward) | `altinity-mcp/oauth/refresh-token/v1` | `v1` |
| self-issued access token HS256 | `altinity-mcp/oauth/access-token/v1` | `v1` |

Newly-issued artifacts carry `kid="v1"` in the protected JWE/JWS header.
Decoders pick the derivation by inspecting `kid`:

- `kid == "v1"` → use HKDF-derived key for the matching info label.
- `kid` absent → fall back to the legacy `SHA256(SigningSecret)` derivation
  used before the cutover, so refresh tokens and client_ids minted before
  this commit keep working.

The fallback runs through `jwe_auth.ParseAndDecryptJWE` (legacy SHA256
path) and the gating-mode access-token verifier path, both of which know
the historical formats.

### When the legacy fallback can be removed

After every legacy refresh token (default TTL 30 days) and legacy stateless
client_id (also 30 days) has expired naturally — i.e. ~30 days after the
deploy that introduced HKDF. After that:

1. Drop the `kid == ""` branch in `decodeOAuthJWE` and the matching branch
   in `parseAndVerifySelfIssuedOAuthToken`.
2. Drop the `encodeJWEArtifact` legacy emit helper if anything still uses
   it (currently nothing does after Step 2).
3. Drop the SHA256-fallback test cases.

### Future rotation

To rotate any single key without disturbing the others, bump the `/vN`
suffix in that one info label and the `kid` value, while temporarily
accepting both the old and the new label during a rotation window. The
labels are namespaced so `client-id/v2` doesn't affect `access-token/v1`.

### Hypothesis-4A (caches refresh token, breaks at first use): expected to be mitigated

The dual-key acceptance branch covers it in code; live JSX-artifact testing
on the deployed branch verifies it. Update this section to "confirmed" once
verified.

### Hypothesis-4B (claude.ai rejects unknown kid): expected not to apply

claude.ai's proxy treats our self-issued access tokens as opaque — it
forwards them to us in `Authorization: Bearer` without inspecting the
`kid` header. To be confirmed by JSX-artifact testing after deploy.

---

## CONFIRMED: `scope=` on generic `invalid_token` 401 breaks claude.ai's proxy

### What we did

Re-added `scope=<configured scopes>` to the `WWW-Authenticate` header on
generic 401 responses (M-2 in the original review), per MCP authorization
spec 2025-11-25 §Protected Resource Metadata Discovery Requirements:

> "MCP servers **SHOULD** include a `scope` parameter in the
> `WWW-Authenticate` header as defined in RFC 6750 §3 to indicate the scopes
> required for accessing the resource."

### What broke

After deploy of commit `7da21f2`, `mcp__claude_ai_otel__*` tool calls (and
JSX artifacts using the same connector) started failing with:

```
Anthropic Proxy: Invalid content from server
```

…with **zero requests reaching our origin server** (verified via pod logs).
The proxy was failing somewhere in its own internal handling of our metadata
or 401 challenge, before forwarding tools/call to us.

The earlier RFC 8707 fix (`a3226b2`) had the proxy working. The only
client-visible change between the two deploys was the addition of `scope=`
on the generic invalid_token 401.

### What we ship instead

We honour the **MUST** case (RFC 6750 §3.1 / MCP §Runtime Insufficient Scope
Errors) — `scope=` is included when the failure is `insufficient_scope` and
the client genuinely needs to know which scopes to request to step up. We
stay quiet on the **SHOULD** case (initial generic 401) to keep claude.ai's
proxy working.

### Status

The override is intentional and documented inline at
`oauthChallengeHeader` (`cmd/altinity-mcp/oauth_server.go`). When Anthropic
fixes the proxy to tolerate `scope=` on generic 401s, we should reinstate
the SHOULD path — clients other than claude.ai (Codex, MCP Inspector,
manual Claude Desktop configs) all want it for spec-compliance and because
the proxy/Anthropic backend won't be the only consumer forever.

---

## Resolved: canonical resource URI is no-trailing-slash (Step 1 of incremental hardening)

MCP spec 2025-11-25 §Canonical Server URI:

> implementations **SHOULD** consistently use the form without the trailing
> slash for better interoperability unless the trailing slash is semantically
> significant for the specific resource

We now ship the no-slash form on the advertised `resource` field and on the
default-fallback `aud` claim. Byte-equality with whatever the client sent in
`resource=` on /authorize is preserved on the `aud` claim itself, so a client
that registered the connector URL with a slash still gets `aud` byte-matching
what it sent. `validateOAuthClaims` continues to compare slash-normalised
forms against the operator-configured `Audience`, so operator config remains
flexible.

The ripple-effect concern (claude.ai cached the with-slash form, would
mismatch after switch) was tested live: artifact path continued to work
because the proxy passes the user-registered URL form, and we echo it back
verbatim on the aud claim.

---

## Already-shipped (no compatibility risk discovered)

Recording these here so we don't re-debate them:

- **C-1** — Wired up `UpstreamIssuerAllowlist`. Operators were getting zero
  enforcement; now the allowlist actually constrains accepted upstream issuers.
- **H-3** — PKCE on upstream IdP leg (OAuth 2.1 §7.5.2). Verifier kept in
  `oauthPendingAuth`, replayed on `/token`. Defends the upstream auth-code
  channel against interception even when we hold the upstream client_secret.
- **M-2/M-3** — `scope=` attribute in `WWW-Authenticate` for both 401
  (`invalid_token`) and 403 (`insufficient_scope`).
- **L-2** — Malformed-JWE 401 now routes through `writeOAuthError`, returning
  JSON + `WWW-Authenticate` instead of plain text.
- **M-6** — Split pending-auth-TTL (10 min) from auth-code-TTL (60 s). The old
  shared 5-min window was too short for the user-login phase and too long for
  code redemption.
- **H-4 (cheap)** — Reject `signing_secret` shorter than 32 bytes at startup.
- **M-5** — Dropped `x-oauth-token` and `x-altinity-oauth-token` fallback
  headers. MCP spec mandates `Authorization: Bearer` only.
- **M-4** — Startup warnings when `public_resource_url` is unset (host-spoof
  surface) or when neither `oauth_issuer` nor `upstream_issuer_allowlist` is
  set in forward mode.
