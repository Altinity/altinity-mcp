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

## H-4 (full) — HKDF-derived per-context keys + key rotation

### What the report flagged

`SigningSecret` is currently used as the input to a single `SHA256(secret)`
that doubles as:
- HS256 signing key for self-issued access tokens
- A256KW key-wrap key for JWE'd client_ids
- A256KW key-wrap key for JWE'd refresh tokens

Single-key compromise = total compromise. There's no `kid` in either header,
so multi-key rotation isn't possible without breaking all outstanding tokens.

### Hypothesis-4A: claude.ai caches the refresh token; rotating any key invalidates it and forces re-auth

If we change the derivation to HKDF(secret, info=<context>), all outstanding
refresh tokens decrypt to garbage on first use after deploy. Every connected
artifact has to reauthorize. For a small population this is annoying but
recoverable; for a deployed feature with many users it's an operational
incident.

The mitigation is **dual-key acceptance**:

1. New tokens emit a `kid="v2"` header (in JWE protected headers + in JWT
   header).
2. Decryption tries `v2` first (with HKDF-derived keys), falls back to no-kid
   path (with current `SHA256(secret)` keys).
3. After 30 days (one refresh-token lifetime), remove the fallback.

### Hypothesis-4B: claude.ai validates the JWS signature shape and rejects unknown `kid`

Some JWT validators reject any token whose `kid` doesn't appear in the JWKS
they fetched. Our access token isn't validated by claude.ai — claude.ai just
passes it back to us. So adding `kid` should be transparent to them. Worth
verifying with a probe: emit a token with `kid` set, ensure claude.ai still
sends it back in `Authorization: Bearer`.

### What we'd need to do

1. Implement HKDF derivation (`info` = "altinity-mcp/oauth/jwe-keywrap-v2",
   "altinity-mcp/oauth/access-token-hs256-v2").
2. Add `kid` header support to both JWE artifact creation and self-issued JWT
   signing.
3. Decryption + signature verification accept either `kid="v2"` (new) or no
   `kid` (legacy).
4. Add a config knob `signing_secret_v1` that retains the old derivation for
   the rotation window.
5. After 30 days, drop legacy support.

This is a real change; ~100 lines + tests + docs. Not trivial. But it's the
right thing if we expect the deployment to last and we want incident response
to be possible without forcing every user to re-auth.

---

## Open question: should we re-add `scope=` to WWW-Authenticate?

We already shipped this fix (M-2). Recording the hypothesis here in case it
turns out to break artifacts:

### The earlier hypothesis (now disproved)

When we first compared kapa to otel-mcp, kapa's WWW-Authenticate did NOT
include `scope=`. We hypothesised that Anthropic's proxy disliked it and
removed it from our challenge. After the RFC 8707 fix unblocked artifacts, we
re-added `scope=` per MCP spec §Protected Resource Metadata Discovery
Requirements. If artifact tests start failing after this deploy, the
hypothesis is back in play and we should drop `scope=` again.

### Quick test

Probe `WWW-Authenticate` after the deploy:

```sh
curl -si "https://otel-mcp.demo.altinity.cloud/" | grep WWW-Authenticate
```

Expected:

```
Bearer error="invalid_token", error_description="...", resource_metadata="...", scope="openid email profile"
```

Then verify a fresh JSX artifact still attaches tools. If yes, ship. If no,
revert the `scope=` addition and reopen this hypothesis.

---

## Open question: trailing slash on canonical resource URI

MCP spec 2025-11-25 §Canonical Server URI explicitly recommends the
**no-trailing-slash** form for interoperability. Our advertised `resource` and
the default-fallback `aud` use the **trailing-slash** form because that's what
unblocked claude.ai's JSX artifact (commit `2ebf51d`).

### Hypothesis: claude.ai sends the URL the user pasted; our deployment is registered with the trailing slash

Our public URL `https://otel-mcp.demo.altinity.cloud/` was registered in the
claude.ai connector settings with the trailing slash. claude.ai's proxy uses
that exact form when sending `resource=` on `/authorize` and validating `aud`
in returned tokens.

If a user registered the connector *without* a trailing slash, the byte-equal
comparison would fail and the artifact wouldn't attach. This means the spec's
"no trailing slash for interop" advice is actually correct, *and* we should
both:

- Strip trailing slash from `resource` and the default `aud` (spec compliance)
- Pass through whatever the client sent in `resource` for the `aud` claim
  byte-for-byte (already implemented)

### Why we haven't done it yet

Switching from trailing-slash to no-slash would, for the duration of any
in-flight refresh tokens, mint tokens with `aud` not matching whatever
claude.ai cached for our connector. If they validate cross-request, it'd
break. Tested-but-not-confirmed.

### What to test

1. Probe a fresh artifact registration with `resource=https://otel-mcp.demo.altinity.cloud`
   (no slash): does claude.ai accept the corresponding token?
2. If yes, switch our default to no-slash and reaffirm via the artifact test.
3. If no — keep current behaviour and document that some clients are slash-sensitive.

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
