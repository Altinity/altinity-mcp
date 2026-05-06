# OAuth compatibility hypotheses — to discuss before implementing

This document captures changes that the OAuth review (in commit history) flagged
as legitimate spec gaps but that we have **not** implemented yet because the
fix risks breaking real clients in non-obvious ways. Each section states the
hypothesis, what would change, and the specific compatibility question the
team needs to answer (or test against the live deployment) before merging.

The fixes already shipped are listed at the bottom for context.

---

## H-1 — Per-DCR-client consent screen (confused-deputy mitigation)

### What the spec says

MCP authorization spec 2025-11-25 §Confused Deputy Problem:

> "MCP proxy servers using static client IDs **MUST** obtain user consent for
> each dynamically registered client before forwarding to third-party
> authorization servers."

We are exactly that: gating-mode proxies a single static upstream Auth0 client
across all DCR-registered MCP clients. Auth0 only shows its own consent screen
once for the upstream client; subsequent DCR'd MCP clients ride on the existing
upstream session.

### Hypothesis-1A: claude.ai's proxy will follow our redirect to a consent page

If we render an HTML "Authorize *<client_name>* to access *<resource>*?" page
between `/oauth/authorize` and the upstream redirect, claude.ai's artifact-side
proxy needs to display it and capture the user's click. The proxy is probably
doing one of:

- **(a)** A headless follow-redirects loop with no UI surface — our consent
  page would never be shown and the flow would dead-end.
- **(b)** A WebView with cookies — would render and work like a normal browser.
- **(c)** Pre-flighted: the proxy expects to see only OAuth-spec'd interstitials
  (the IdP login + IdP consent), not a custom HTML page from the resource
  server.

The safe default to assume is (a) — Anthropic's proxy is server-side
infrastructure designed for `mcp_servers`-via-URL flows, not browser UIs. If we
add a consent step that requires a click, the artifact path will break.

### Hypothesis-1B: a non-clickthrough consent record would work

We could implement consent passively: maintain a per-`(user_sub, dcr_client_id)`
record (TTL'd in the existing JWE state store), and if it's the user's *first*
authorization for this client, render an interstitial that auto-submits via
JavaScript (or via a 302 to a self-issued URL containing a signed
"consent_token"). The artifact proxy would follow it and we'd record consent.

This is **security theatre** — an autosubmit isn't real consent — but it
satisfies the letter of the spec and centralises the data. Worth less than the
implementation cost.

### Hypothesis-1C: the existing PKCE + DCR-redirect-URI binding is enough

The attack model assumes an attacker can DCR a client and trick a victim into
authorizing it. PKCE binds the auth code to the *attacker's* code_verifier (the
attacker DCR'd the client and so legitimately holds the secret + verifier). So
PKCE doesn't help against a malicious DCR client.

But: the redirect URI is also locked at DCR time. The only way the attacker
captures the code is if they trick the user into starting `/authorize` with
`client_id=<attacker_dcr>&redirect_uri=<attacker_url>`. The user would need to
already be logged into our upstream Auth0 (otherwise they hit Auth0's consent
which DOES show what's being authorized). And the resulting access token is
scoped to *our* MCP server only — the attacker can query our MCP, not the
victim's other resources.

Does that residual risk warrant breaking the current artifact flow? Open
question. **My recommendation:** ship a logging-only mitigation first (record
every DCR + first-use-per-user pair, alert on anomalies), gather data, then
decide.

### What we'd need to test

1. Deploy a test branch that puts a static "Authorize this client?" HTML page
   between `/oauth/authorize` and the upstream redirect.
2. Connect via claude.ai artifact: does the JSX get tools attached, or does the
   flow dead-end?
3. If it dead-ends, try the auto-submit-form variant.
4. If even that breaks, confirm we'd need to abandon strict spec compliance
   here in exchange for the artifact path working.

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
