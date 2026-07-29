# Plan: Stateless MCP Protocol (2026-07-28) Support

## Context

The MCP specification revision **2026-07-28** ([announcement](https://claude.com/blog/bringing-mcp-2026-07-28-to-claude)) moves the
protocol from a bidirectional stateful model to a request/response model:

- The `initialize` / `notifications/initialized` handshake and the
  `Mcp-Session-Id` session are removed. Each request is self-describing:
  client info, capabilities, and protocol version travel in the request's
  `_meta` field (`io.modelcontextprotocol/protocolVersion`, etc.).
- A new `server/discover` RPC lets clients learn server capabilities up
  front; clients fall back to legacy `initialize` when it is unavailable.
- Requests carry routable HTTP headers (`Mcp-Method`, `Mcp-Protocol-Version`,
  `Mcp-Param-*`) so intermediaries can route MCP traffic without body
  inspection. Header/body mismatch is rejected with error code `-32020`.
- In stateless mode GET/DELETE return `405 Method Not Allowed`;
  resumability (Last-Event-ID) and server-initiated requests are gone.
- `roots`, `sampling`, and `logging` are deprecated.

The official Go SDK ships 2026-07-28 support in **v1.7.0**
(`github.com/modelcontextprotocol/go-sdk`). With the upgraded SDK, a
`StreamableHTTPHandler` created with `StreamableHTTPOptions.Stateless = true`
serves the new protocol natively and transparently negotiates down to
2025-11-25 (and older) for legacy clients.

altinity-mcp already ran the streamable HTTP transport with
`Stateless: true` (required for `replicas>=2` behind a non-sticky LB), so
the upgrade is the main enabler. Supporting work is still needed around
CORS and request-lifecycle handling.

## Steps

1. **Upgrade the SDK**: `go get github.com/modelcontextprotocol/go-sdk@v1.7.0`
   then `go mod tidy`. Verify `go build ./...` and `go vet ./...` pass —
   v1.7.0 keeps backward compatibility with the v1.6.x server API.

2. **Centralize streamable options** in `cmd/altinity-mcp/main.go`:
   replace the three inline `&mcp.StreamableHTTPOptions{Stateless: true}`
   literals (JWE HTTP path, plain HTTP path, multicluster path) with a
   shared `statelessStreamableOptions()` helper that sets:
   - `Stateless: true` — serves the 2026-07-28 stateless protocol,
   - `PropagateRequestCancellation: true` — ties tool-handler contexts to
     the originating HTTP request so abandoned 2026-07-28 requests cancel
     the underlying ClickHouse queries.

3. **Update CORS for the new routable headers**: browser-based clients now
   send `Mcp-Method` and dynamic `Mcp-Param-*` headers. `Mcp-Param-*` names
   derive from tool arguments and cannot be enumerated statically, so the
   shared `corsMiddleware()`:
   - echoes `Access-Control-Request-Headers` back on preflight when present,
   - otherwise falls back to a static allowlist that now includes
     `Mcp-Method`.
   Replace the three duplicated inline CORS closures (HTTP, SSE,
   multicluster) with this middleware.

4. **Tests**:
   - Update the CORS preflight expectations in `main_test.go`
     (echo behavior + new static fallback list).
   - Add `TestStatelessHTTPProtocol`: start the app with the HTTP
     transport, connect with the SDK's `StreamableClientTransport`, and
     assert the negotiated protocol version is `2026-07-28` and
     `tools/list` succeeds without an initialize handshake.

## Nuances

- The legacy SSE transport (`mcp.NewSSEHandler`) is untouched — it predates
  the streamable transport and has no stateless variant.
- stdio transport still uses the classic handshake; the SDK negotiates
  per-connection, no changes needed.
- Old streamable clients (Claude Desktop et al. on 2025-11-25/2025-06-18)
  keep working: the SDK's stateless handler accepts legacy `initialize`
  POSTs with per-request temporary sessions, exactly as before the upgrade.
- `MCPGODEBUG=allowsessionsinstateless=1` is available as an escape hatch
  if a client misbehaves against the strict sessionless behavior (removed
  in SDK v1.9.0).
