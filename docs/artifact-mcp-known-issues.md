# MCP from claude.ai JSX artifacts: known proxy bug

> **TL;DR.** OAuth-protected MCP servers like altinity-mcp work fine when used
> from the main claude.ai chat (and from Claude Code, MCP Inspector, the
> Messages API directly, etc.) but **silently fail to attach** when called from
> a JSX/HTML artifact's `mcp_servers: [...]` parameter. The artifact-side proxy
> drops the connector before any request reaches the MCP server. We have not
> found a server-side workaround, and the issue tracks to known unfixed bugs in
> Anthropic's artifact proxy: [claude-code#16848][i16848] and
> [claude-ai-mcp#123][i123].

## Symptoms

- Connector registered at `https://otel-mcp.demo.altinity.cloud/`
- OAuth 2.1 + RFC 9728 + PKCE + DCR all spec-compliant per [MCP authorization spec][mcp-spec]
- MCP works from main chat — `select 1` round-trips fine, tools list available
- MCP works from Claude Code, MCP Inspector, Anthropic Messages API directly
- In a JSX artifact: `mcp_servers: [{type:"url", url:"https://otel-mcp.demo.altinity.cloud/", name:"otel"}]`
  → sub-Claude responds "I don't have access to … tools" and/or claude.ai shows
  `✗ No tools attached — proxy didn't expose this connector`
- **Zero requests reach the MCP server during the artifact attempt** — the
  access log is silent. The proxy never even initiates the OAuth flow.

## Reverse-engineering the artifact path

When a JSX/HTML artifact's JavaScript calls:

```js
fetch("https://api.anthropic.com/v1/messages", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    model: "claude-sonnet-4-20250514",
    max_tokens: 800,
    mcp_servers: [
      { type: "url", url: "https://your-mcp.example.com/", name: "yourmcp" }
    ],
    messages: [{ role: "user", content: "..." }],
  })
});
```

…claude.ai's frontend monkey-patches `window.fetch` to redirect this to:

```
POST https://claude.ai/api/organizations/<org-uuid>/proxy/v1/messages
```

The proxy is supposed to look up `yourmcp` in the user's connector store,
prompt the user with an "Allow access to connectors" dialog on first use, and
attach the connector to the sub-Claude as a tool. In practice, for our
OAuth-protected servers, the attach step silently fails.

## Likely root cause: RFC 8707 resource indicator + `aud` byte-equality

After several rounds of tuning surface-level discovery shapes with no effect,
the actual gap turned out to be RFC 8707 / MCP-spec resource-indicator
handling. Found via [openai/codex#11292][codex11292] — the codex CLI
client was failing OAuth with kapa-hosted MCP because codex didn't pass the
`resource` query parameter on `/authorize`, and **kapa's authorization
server requires it**. That's how we know Anthropic's claude.ai client *does*
send it: kapa wouldn't have mounted in artifacts otherwise.

What altinity-mcp was doing wrong:

- `handleOAuthAuthorize` ignored the `resource` query parameter entirely.
- `mintGatingTokenResponse` minted `aud` from a stripped-trailing-slash
  form of the resource URL: `aud="https://otel-mcp.demo.altinity.cloud"`
  while the `resource` field in `/.well-known/oauth-protected-resource`
  was `"https://otel-mcp.demo.altinity.cloud/"` (with slash).
- `validateOAuthClaims` audience comparison was strict byte-equality.

If the artifact proxy follows the spec — sends `resource=<URL>` on
`/authorize` and validates that the issued token's `aud` byte-matches the
URL it asked for — our mismatch causes silent rejection at the proxy. No
log on our side because the proxy never sends a tool call against our
server with the rejected token.

What we now ship:

- `/authorize` reads `resource`, validates it identifies *this* MCP server
  (slash-normalised compare), stores it verbatim in the pending-auth state.
- The auth code carries the resource through to `/token`.
- `/token` (both `authorization_code` and `refresh_token` grants) accepts a
  `resource` form param per RFC 8707 §2.2, with consistency checking against
  what was pinned at `/authorize`.
- `mintGatingTokenResponse` uses the requested resource as `aud`
  byte-identically — the slash form the client sent is preserved.
- The default fallback (no resource indicator from the client) now mints
  `aud` matching the trailing-slash `resource` field we advertise, so
  byte-equality holds for legacy clients too.
- `validateOAuthClaims` audience check normalises trailing slash on both
  sides so operator-configured `Audience` keeps working in either form.

Whether this actually unblocks JSX artifacts remains to be confirmed in a
production deploy; the mechanism is well-grounded but Anthropic's proxy
implementation is opaque, so the upstream bug references below still stand.

[codex11292]: https://github.com/openai/codex/issues/11292

## What else we tried first (no effect)

We compared `/.well-known/oauth-protected-resource`, `/.well-known/oauth-authorization-server`,
401 responses, CORS preflights, DCR responses, and the MCP-protocol handshake
side-by-side between our deployment and `https://kapa-docs.mcp.kapa.ai/` (which
*does* attach in artifacts). Surface differences we found and tried fixing:

| Difference | Action taken | Result |
|---|---|---|
| `WWW-Authenticate` missing `error="invalid_token"` | Added (commit `2ebf51d`) | No effect on artifacts |
| 401 body was `text/plain` not `application/json` | Switched to JSON OAuth-error body (`2ebf51d`) | No effect |
| `resource` field missing trailing slash | Added (`2ebf51d`) — also matches RFC 9728 §2 | No effect |
| DCR response missing `scope` and `client_secret_expires_at` | Added per RFC 7591 (`cf5f30d`) | No effect |
| Tools didn't emit `additionalProperties:false` + `required` | Added (`ba5f7cd`) — required for strict-schema clients | No effect on artifacts |
| `authorization_servers` / `issuer` consistency | First added trailing slash, then reverted to match kapa | No effect either direction |

All of those tweaks are correct per spec — keep them — but none of them moved
the needle on JSX artifacts. The actual gap was further along the OAuth
flow (resource indicator → `aud` claim), described in the section above.

## Why we believe it's an Anthropic proxy bug

Two open issues in Anthropic repos describe the same shape of failure:

- **[anthropics/claude-code#16848][i16848]** — *Artifact API proxy strips
  mcp_servers parameter despite documentation support.* Reporter shows the
  same connector working in main chat, then being silently dropped on the
  artifact path. Filed Jan 2026, auto-closed after 30 days of inactivity
  with no fix.
- **[anthropics/claude-ai-mcp#123][i123]** — *Tool Discovery Succeeds but
  CallToolRequest Never Sent.* Tailscale Funnel MCP server with 80+ tools:
  discovery from main chat works, tool execution from the artifact-equivalent
  path produces zero server hits.

Our case matches both: discovery and tool calls work in the main chat, the
same connector silently produces zero hits on the artifact path.

## What altinity-mcp ships today

In `cmd/altinity-mcp/oauth_server.go`:

- `/.well-known/oauth-protected-resource` returns `resource` with trailing
  slash (RFC 9728 §2 canonical form), `authorization_servers[0]` without
  trailing slash (RFC 8414 issuer convention; matches the working reference).
- `/.well-known/oauth-authorization-server` returns `issuer` without trailing
  slash. `mintGatingTokenResponse` mints `iss` in the same form so RFC 8414 §2
  byte-equality holds. `validateOAuthClaims` normalises trailing slashes on
  both sides defensively, so operator config with-or-without the slash works.
- 401 responses on protected endpoints carry
  `WWW-Authenticate: Bearer error="invalid_token", error_description="...", resource_metadata="..."`
  with a JSON `application/json` body.
- DCR (`/oauth/register`) registers clients as confidential by default
  (`client_secret_post`), echoes `scope` and `client_secret_expires_at` per
  RFC 7591 §3.2.1.

These are correct per spec and match working third-party MCP servers. They are
**not** sufficient to make JSX-artifact `mcp_servers` work.

## What to tell users hitting this

If a user reports "no tools attached" / "proxy didn't expose this connector"
from a JSX artifact:

1. Confirm the connector works in the main chat first. If it doesn't, the
   bug is on our side; debug normally.
2. If it works in main chat but not in artifacts, route them to one of the
   workarounds rather than the artifact path:
    - Use the connector directly from the main claude.ai chat.
    - Use the Anthropic Messages API directly (`anthropic-beta: mcp-client-2025-04-04`)
      from outside the artifact sandbox — the API path itself works; only the
      claude.ai artifact proxy strips the parameter.
    - Use Claude Code, MCP Inspector, or Claude Desktop, which do not go
      through the artifact proxy.
3. Reference [#16848][i16848] when explaining — it's the public bug record.

## Open question

We don't have a reliable repro of kapa-docs *not* working in artifacts, so
we don't know what makes some OAuth-protected MCPs attach successfully via
the artifact path. The proxy may be allow-listing specific connector domains,
specific OAuth flow shapes, or specific MCP transport configurations. Without
visibility into the proxy code, we can't isolate further. If the underlying
proxy bug gets fixed (#16848 reopened, or a successor issue resolved), this
page should be updated to reflect any newly-required server-side knobs.

## Related references

- [`anthropics/claude-code#16848`][i16848] — Artifact API proxy strips
  `mcp_servers` parameter despite documentation support
- [`anthropics/claude-ai-mcp#123`][i123] — Tool Discovery Succeeds but
  CallToolRequest Never Sent
- [Claude support: Artifacts and MCP integrations][artifacts-doc]
- [RFC 9728: OAuth 2.0 Protected Resource Metadata][rfc9728]
- [RFC 8414: OAuth 2.0 Authorization Server Metadata][rfc8414]
- [RFC 7591: OAuth 2.0 Dynamic Client Registration][rfc7591]
- [MCP Authorization spec][mcp-spec]

[i16848]: https://github.com/anthropics/claude-code/issues/16848
[i123]: https://github.com/anthropics/claude-ai-mcp/issues/123
[rfc9728]: https://datatracker.ietf.org/doc/rfc9728/
[rfc8414]: https://datatracker.ietf.org/doc/rfc8414/
[rfc7591]: https://datatracker.ietf.org/doc/rfc7591/
[mcp-spec]: https://modelcontextprotocol.io/specification/draft/basic/authorization
[artifacts-doc]: https://support.claude.com/en/articles/9487310-what-are-artifacts-and-how-do-i-use-them
