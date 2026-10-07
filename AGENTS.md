# Agent guide — altinity-mcp

This repository provides a Go MCP server for ClickHouse and a JWE token
generator. Start with `README.md`, `docs/tools.md`, and the documentation for
the feature you are changing. Treat live implementation and tests as
authoritative when documentation disagrees.

## Working loop

1. Inspect the relevant implementation, tests, issue, and configuration before
   changing code. Keep the scope focused and preserve unrelated changes.
2. Add or update meaningful tests for changed behavior. Use focused package
   tests while iterating. Documentation and developer-instruction changes
   need only relevant content checks.
3. For production changes, format changed Go files, run `go vet ./...`,
   `go test ./...`, and `make build`. Match the current CI test command in
   `.github/workflows/build-altinity-mcp.yml` before declaring delivery ready.
   Run race tests for changes to concurrency or shared state. Report failures,
   skipped tests, and unavailable checks accurately.
4. Update affected README, tool, authentication, deployment, and configuration
   documentation in the same change. Add user-visible changes to
   `CHANGELOG.md`, following its existing release format. Trivial edits are
   exempt.

The repository has one Go module. Use the version in `go.mod` and CI.
There is no `build/gate.sh` or enforced per-package coverage floor.
Tests use `internal/testutil/embeddedch` to run ClickHouse as a host subprocess.
Stock binaries download automatically. Antalya fixtures use the image and
cache rules in that helper; first use on Linux can require Docker to extract
the binary. Other hosts need a prepared binary. Read the helper and relevant
tests for current requirements; some Docker guidance and image versions in
`docs/development_and_testing.md` are stale. A short test run does not prove
the full suite passes.

## Architecture and compatibility

- `cmd/altinity-mcp` contains startup, CLI wiring, and OAuth HTTP handlers.
  `cmd/jwe_auth` builds the token generator.
- `pkg/config` owns configuration and reflected CLI flags. `pkg/clickhouse`
  owns database access. `pkg/server` owns MCP, OpenAPI, authentication hooks,
  tools, resources, and cluster routing. `pkg/metrics` owns metrics.
- Keep policy with its caller. Extract shared primitives when a second
  consumer needs them. Avoid broad restyling during focused fixes.
- Before adding a dependency, check the standard library and existing
  modules. Explain the need and leave `go.mod` and `go.sum` consistent.
- Preserve CLI flags, environment variables, YAML/JSON keys, tool schemas,
  transport behavior, and token formats unless the requested change covers
  a compatibility break. Document migrations and update Helm values and
  examples when their contracts change.
- Trace authentication changes through the current OAuth broker/resource
  server behavior, ClickHouse authentication, and cluster routing. Do not
  assume old `forward`/`gating` configuration modes still exist.

## Security and product invariants

- Never commit or expose real credentials, signing keys, bearer tokens,
  decrypted JWE payloads, or secret-bearing configuration. Use fake secrets
  in tests and verify sensitive output paths redact them.
- Treat SQL, tool arguments, token claims, upstream responses, and remote
  metadata as untrusted. Validate at the relevant trust boundary.
- Preserve configured read-only enforcement and tool safety annotations.
  This server supports writes when enabled; do not impose the Expert
  application's unconditional read-only or loopback-only rules.
- Preserve request identity, roles, and cluster scope through dispatch,
  database access, and caches. Authentication and authorization failures
  must not silently grant access.
- Preserve cancellation, resource cleanup, and synchronization when changing
  request handlers, shared caches, or background work.

## Repository discipline

- Write clear, concise prose. Preserve exact identifiers, commands, and
  established error text unless changing them is part of the task.
- Surface meaningful out-of-scope defects with file and line evidence.
  Create external issues only when authorized by the task or workflow.
- Keep generated binaries, coverage files, local credentials, and review
  artifacts out of commits. Use imperative commit messages.
- Use an isolated worktree for delivery when the shared checkout contains
  unrelated work. Deployments and service restarts need separate authorization.
- Local developer skills live under `.codex/`. The borrowed deliver workflow
  is `.codex/deliver/SKILL.md`; apply its issue and review mechanics when
  invoked, using this repository's checks.
- When delegating, state each worker's scope and mutation boundary. Reviewers
  are read-only unless explicitly assigned a report artifact. Inspect actual
  diffs, commits, and check results before accepting worker claims.
