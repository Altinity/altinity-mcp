# Checklist: Stateless MCP Protocol (2026-07-28) Support

## What was implemented

- `github.com/modelcontextprotocol/go-sdk` upgraded v1.6.1 → v1.7.0 (first
  release with MCP 2026-07-28 stateless protocol support).
- `cmd/altinity-mcp/main.go`:
  - `statelessStreamableOptions()` — shared `StreamableHTTPOptions` with
    `Stateless: true` + `PropagateRequestCancellation: true`, used by the
    JWE HTTP, plain HTTP, and multicluster streamable handlers.
  - `corsMiddleware()` + `defaultCORSAllowHeaders` — shared CORS handler
    that echoes `Access-Control-Request-Headers` on preflight (covers
    dynamic `Mcp-Param-*`) and adds `Mcp-Method` to the static fallback
    list; replaces three duplicated inline closures. Preflight-only headers
    (`Allow-Methods`, `Allow-Headers`, `Max-Age`) are set only in the
    OPTIONS branch, with `Vary: Access-Control-Request-Headers` since the
    Allow-Headers value is request-dependent and cacheable. Call sites use
    `stripTrailingSlash(corsMiddleware(cfg.Server.CORSOrigin, mux))`
    directly — no local wrapper closures.
- `cmd/altinity-mcp/main_test.go`:
  - CORS preflight test updated for echo + fallback behavior.
  - New `TestStatelessHTTPProtocol` verifies an SDK client negotiates
    protocol version `2026-07-28` against the HTTP transport and can list
    tools without an initialize handshake.

## Verification steps

- [x] `go build ./...` and `go vet ./...` pass.
- [x] `go.mod` requires `github.com/modelcontextprotocol/go-sdk v1.7.0`.
- [x] No remaining inline `&mcp.StreamableHTTPOptions{...}` literals in
      `cmd/altinity-mcp/main.go` (`grep StreamableHTTPOptions`): all three
      handler sites call `statelessStreamableOptions()`.
- [x] No remaining inline CORS closures: `grep corsHandler` in
      `cmd/altinity-mcp/main.go` returns nothing; all five wrap points call
      `corsMiddleware` directly.
- [x] `go test ./cmd/altinity-mcp/ -run 'TestCORSSupport' -count=1` passes.
- [x] `go test ./cmd/altinity-mcp/ -run 'TestStatelessHTTPProtocol' -count=1`
      passes and asserts `InitializeResult().ProtocolVersion == "2026-07-28"`.
- [x] Legacy client compatibility: full test suite (which connects with
      pre-2026 clients over streamable HTTP/SSE) passes, confirming
      downgrade negotiation to 2025-11-25 and older still works.
- [x] SSE and stdio transports unchanged (no stateless flags applied there).
