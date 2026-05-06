# v1.5.0

BREAKING CHANGES
- **`server.tools[].regexp` split into `view_regexp` / `table_regexp`**: In the new unified `server.tools` config, the old `regexp` field is replaced by `view_regexp` (for `type: read` rules) and `table_regexp` (for `type: write` rules). Cross-type validation rejects `view_regexp` on write rules and vice versa. The legacy `server.dynamic_tools` block with `regexp` still works but is now **deprecated** — migrate to `server.tools` ([PR #84](https://github.com/Altinity/altinity-mcp/pull/84))
- **`server.dynamic_tools` deprecated**: Replaced by the unified `server.tools` array that covers both static tools (by `name`) and dynamic tools (by `view_regexp`/`table_regexp`). Old config is preserved for backwards compatibility but will be removed in a future release ([PR #84](https://github.com/Altinity/altinity-mcp/pull/84))
- **OAuth gating mode: ClickHouse username now derived from `email` claim first, `subject` as fallback**: Previously the opaque `subject` (numeric Google ID / UUID) was used as the ClickHouse username. If you pre-provisioned ClickHouse users by subject, they need to be re-provisioned by email address
- **MCP HTTP transport moved from `/http` to `/` (root path)**: Nginx reverse-proxy configs and client integrations pointing to `/http` must be updated. SSE stays at `/sse`, OAuth paths stay under `/oauth/*` ([PR #83](https://github.com/Altinity/altinity-mcp/pull/83))
- **`github.com/ClickHouse/clickhouse-go/v2` replaced by Altinity fork**: `go.mod` now uses `github.com/Altinity/clickhouse-go/v2` which adds the cluster interserver-secret protocol extension. No application-level API changes, but the import path in any downstream forks must be updated ([PR #86](https://github.com/Altinity/altinity-mcp/pull/86))

FEATURES
- add unified `server.tools` configuration replacing `server.dynamic_tools`, fix [#35](https://github.com/Altinity/altinity-mcp/issues/35), [#36](https://github.com/Altinity/altinity-mcp/issues/36), [#58](https://github.com/Altinity/altinity-mcp/issues/58) ([PR #84](https://github.com/Altinity/altinity-mcp/pull/84)):
  - single array covers static tools (`type` + `name`), dynamic read tools (`type: read` + `view_regexp`), and dynamic write tools (`type: write` + `table_regexp` + `mode: insert`)
  - static tool names: `execute_query` (read) and `write_query` (write)
  - lazy discovery: views/tables are resolved at connection time, not at startup
- add write tools (insert mode): dynamic tools can now target ClickHouse tables and expose parameterized INSERT operations as MCP tools (`mode: insert`) ([PR #84](https://github.com/Altinity/altinity-mcp/pull/84))
- add ClickHouse cluster interserver-secret authentication ([PR #86](https://github.com/Altinity/altinity-mcp/pull/86)):
  - new config fields `clickhouse.cluster_name` / `clickhouse.cluster_secret` (CLI: `--clickhouse-cluster-name`, `--clickhouse-cluster-secret`; env: `CLICKHOUSE_CLUSTER_NAME`, `CLICKHOUSE_CLUSTER_SECRET`)
  - altinity-mcp authenticates as a trusted cluster peer without a password; each query runs as the MCP-authenticated user (`system.query_log` shows the real user)
  - requires `clickhouse-protocol=tcp`; invalid combinations (HTTP + secret, missing cluster name) are rejected at startup
- add forward-mode refresh tokens via stateless JWE ([PR #88](https://github.com/Altinity/altinity-mcp/pull/88)):
  - new config flag `server.oauth.upstream_offline_access` (CLI: `--oauth-upstream-offline-access`); defaults to `false` so existing deployments are unaffected
  - when enabled, `offline_access` is appended to the upstream authorize redirect; the upstream refresh token is wrapped in a JWE and returned to the MCP client; the cleartext upstream refresh token never leaves the MCP server
  - on `grant_type=refresh_token`, MCP decrypts the JWE, refreshes upstream, re-validates the new ID token, and returns a new pair
- add `clickhouse.max_query_length` to cap SQL query size accepted from clients (CLI: `--clickhouse-max-query-length`; default 10 MiB, negative value disables the check) ([PR #82](https://github.com/Altinity/altinity-mcp/pull/82))
- add dynamic tool parameter descriptions from column `COMMENT`: JSON Schema `description` for each parameter is now resolved from (1) tool-level JSON `COMMENT` `params` map, (2) `system.columns.comment`, (3) ClickHouse type string as fallback ([PR #84](https://github.com/Altinity/altinity-mcp/pull/84))

IMPROVEMENTS
- prefer `email` claim over `subject` as ClickHouse username in OAuth gating mode; fall back to `subject` for machine-to-machine flows that omit email ([PR #86](https://github.com/Altinity/altinity-mcp/pull/86))
- fix `expires_in` in OAuth forward mode to match the actual JWT expiry instead of a fixed offset ([PR #88](https://github.com/Altinity/altinity-mcp/pull/88))
- advertise `refresh_token` grant in OAuth dynamic client registration response ([PR #88](https://github.com/Altinity/altinity-mcp/pull/88))
- split `pkg/server/server.go` into domain-specific files (`server_auth_oauth.go`, `server_dynamic_tools.go`, etc.) for maintainability ([PR #85](https://github.com/Altinity/altinity-mcp/pull/85))
- migrate all tests from testcontainers-go to `embedded-clickhouse` — faster local test runs with no Docker dependency for unit/integration tests ([PR #92](https://github.com/Altinity/altinity-mcp/pull/92))
- split `server_test.go` into domain-specific test files (`server_auth_oauth_test.go`, etc.) ([PR #85](https://github.com/Altinity/altinity-mcp/pull/85))
- helm: make liveness/readiness probe paths, `initialDelaySeconds`, and `periodSeconds` configurable via `probes.liveness.*` / `probes.readiness.*` values ([PR #95](https://github.com/Altinity/altinity-mcp/pull/95))
- add `go install` instructions to README
- document cluster-secret authentication in OAuth gating mode docs ([PR #86](https://github.com/Altinity/altinity-mcp/pull/86))
- upgrade Go toolchain to 1.26

BUG FIXES
- fix `isSelectQuery` duplicated in `server.go` and `client.go` — deduplicated to single implementation
- fix dynamic tool input validation: optional parameters (columns with DEFAULT) are no longer incorrectly required in JSON Schema ([PR #84](https://github.com/Altinity/altinity-mcp/pull/84))
- fix off-by-one in `getTableColumnsForMode`: short-row guard now correctly checks for `< 4` fields ([PR #84](https://github.com/Altinity/altinity-mcp/pull/84))
- skip unsupported ClickHouse column types (Dynamic, Array, Tuple, JSON) in write tool discovery with a warning log instead of panicking ([PR #84](https://github.com/Altinity/altinity-mcp/pull/84))
- truncate verbose internal error strings returned to MCP clients to avoid leaking stack traces ([PR #82](https://github.com/Altinity/altinity-mcp/pull/82))

DEPENDENCY UPDATES
- replace `github.com/ClickHouse/clickhouse-go/v2` with `github.com/Altinity/clickhouse-go/v2 v2.45.1` (adds cluster interserver-secret protocol extension) ([PR #86](https://github.com/Altinity/altinity-mcp/pull/86))
- replace `github.com/testcontainers/testcontainers-go` with `github.com/franchb/embedded-clickhouse v0.4.0` ([PR #92](https://github.com/Altinity/altinity-mcp/pull/92))
- add `github.com/moby/moby/api v1.54.2`
- bump `github.com/modelcontextprotocol/go-sdk` from 1.5.0 to 1.6.0 ([PR #97](https://github.com/Altinity/altinity-mcp/pull/97))
- bump `github.com/AfterShip/clickhouse-sql-parser` from 0.5.0 to 0.5.1 ([PR #93](https://github.com/Altinity/altinity-mcp/pull/93))
- bump `github.com/rs/zerolog` from 1.35.0 to 1.35.1 ([PR #94](https://github.com/Altinity/altinity-mcp/pull/94))
- bump `github.com/urfave/cli/v3` from 3.7.0 to 3.8.0
- bump `github.com/stretchr/testify` to 1.11.1
- remove many transitive deps shed by dropping testcontainers-go (docker, containerd, otel, grpc, and ~30 others)

# v1.4.2

IMPROVEMENTS
- helm: add `sessionAffinity` and `sessionAffinityConfig` support to service template for sticky sessions (PR #78)
- helm: add liveness probe handler
- fix description of resources

DEPENDENCY UPDATES
- bump `github.com/ClickHouse/clickhouse-go/v2` from 2.44.0 to 2.45.0
- bump `github.com/modelcontextprotocol/go-sdk` from 1.4.1 to 1.5.0

# v1.4.1

IMPROVEMENTS
- helm: add `env` support for container secrets (e.g. `CLICKHOUSE_PASSWORD`) (PR #77)

# v1.4.0

FEATURES
- add OAuth 2.0 authentication with two modes (PR #68):
  - **forward mode** — MCP server acts as OAuth broker, forwards access tokens to ClickHouse via HTTP (port 8123)
  - **gating mode** — MCP server validates tokens and connects to ClickHouse with its own credentials via native protocol (port 9000)
  - browser-based OAuth flow with configurable URLs and paths
  - refresh token support with stateless token limitations documented
  - combined JWE + OAuth authentication: JWE with credentials skips OAuth, otherwise falls through
  - in-memory OAuth state store capped to prevent memory exhaustion
  - 10s timeout on upstream OAuth token exchange
  - misconfiguration warnings for forward mode
  - comprehensive E2E tests with Keycloak + ClickHouse Antalya containers
- add `tool_input_settings` for per-request ClickHouse settings via tool arguments (PR #67), fix https://github.com/Altinity/altinity-mcp/issues/48
  - allows clients to pass ClickHouse settings (e.g. `max_threads`, `max_execution_time`) as tool input parameters
- add `blocked_query_clauses` to prevent SQL clause injection (PR #67)
  - configurable list of SQL clauses that are blocked from query execution
- add MCP safety hints for tools — `readOnlyHint`, `destructiveHint`, `openWorldHint` (PR #66), fix https://github.com/Altinity/altinity-mcp/issues/48
  - `openWorldHint` computed from effective ClickHouse grants
  - safety hints applied to both static and dynamic tools
- enforce read-only mode by blocking write SQL in `execute_query` (PR #57), fix https://github.com/Altinity/altinity-mcp/issues/56

IMPROVEMENTS
- replace regex-based SQL clause detection with AST parser for more reliable query analysis (PR #67)
- refactor: remove `forward_http_headers` and `header_to_settings` features (PRs #63/#65 superseded by #67)
- remove `forward_to_clickhouse`, `forward_access_token`, `clear_clickhouse_credentials` flags — replaced by OAuth modes
- skip startup ClickHouse ping in OAuth forward mode when credentials are per-request
- move development and testing docs out of README
- rewrite OAuth documentation with ASCII diagrams for both modes
- improve test coverage from 84.6% to 87.6% with unit and E2E tests
- add `t.Parallel()` to all tests and container startup timing logs
- refactor server tests to use official MCP Go SDK
- increase server test coverage to 91% and fix race conditions
- fix GitHub Actions CI to avoid deprecated Node 20 runners

BUG FIXES
- fix `sqlLiteral` string escaping and `isSelectQuery` comment stripping
- fix nil pointer panic, route conflict, and test assertions in OAuth flow
- fix dynamic tool discovery when JWE is enabled
- fix refresh token policy bypass
- avoid `max_execution_time` during ClickHouse HTTP handshake
- fix JWE validation running unconditionally when startup ping is skipped
- fix OpenAPI OAuth token forwarding in forward mode

DEPENDENCY UPDATES
- bump `github.com/go-jose/go-jose/v4` from 4.1.3 to 4.1.4
- bump `google.golang.org/grpc` from 1.78.0 to 1.79.3
- bump `github.com/modelcontextprotocol/go-sdk` to 1.4.1
- bump `github.com/testcontainers/testcontainers-go` from 0.40.0 to 0.41.0
- bump `github.com/urfave/cli/v3` from 3.6.1 to 3.7.0
- bump `github.com/ClickHouse/clickhouse-go/v2` from 2.41.0 to 2.42.0
- bump `github.com/mark3labs/mcp-go` from 0.43.1 to 0.43.2

# v1.3.4
IMPROVEMENTS
- refresh dynamic tools per-connection on every MCP `tools/list` request
- update dynamic tools when view signature changes (DDL + comment) instead of skipping
- use `create_table_query` + `comment` as dynamic tool signature for reliable change detection
- refactor: remove `registeredMCPTools`, use `dynamicTools` map for tracking MCP tool changes
- handle tool deletion on refresh when views are dropped

BUG FIXES
- fix nil pointer panic when `MCPServer` is nil during dynamic tools refresh
- fix `registeredMCPTools` map initialization to avoid duplicate registration panics
- fix HTTP response writer conflict by refreshing dynamic tools at startup instead of middleware
- fix pointer to `Hooks` struct in `server.WithHooks` call

# v1.3.3
IMPROVEMENTS
- refactor dynamic tools JSON comment format structure
- bump `github.com/ClickHouse/clickhouse-go/v2` from 2.40.3 to 2.41.0
- bump `github.com/mark3labs/mcp-go` from 0.43.0 to 0.43.1

# v1.3.2
FEATURES
- support JSON comments in ClickHouse view definitions for rich dynamic tool descriptions
- append custom description to ClickHouse type in parameter details

# v1.3.1
FEATURES
- switch dynamic tools to lazy loading — tools are discovered on first request instead of at startup

BUG FIXES
- fix: handle string inputs for numeric and boolean parameters in dynamic tools

DEPENDENCY UPDATES
- bump `golang.org/x/crypto` from 0.43.0 to 0.45.0
- bump `github.com/urfave/cli/v3` from 3.5.0 to 3.6.1
- bump `github.com/testcontainers/testcontainers-go` from 0.39.0 to 0.40.0

# v1.3.0
FEATURES
- add dynamic tools support - automatically generate MCP tools from ClickHouse views, fix https://github.com/Altinity/altinity-mcp/issues/27
  - configure rules to match views using regexp patterns against `system.tables`
  - optionally specify explicit tool names with `name` field (requires regexp to match exactly one view)
  - automatic parameter detection from view definitions `{param: Type}`
  - support for both MCP and OpenAPI endpoints
  - comprehensive documentation in `docs/dynamic_tools.md`

IMPROVEMENTS
- add Microsoft Copilot Studio compatibility by handling trailing slashes in HTTP paths (contribution by @derFunk)
- update dependencies:
  - bump `github.com/mark3labs/mcp-go` from 0.41.1 to 0.42.0
  - bump `github.com/urfave/cli/v3` from 3.4.1 to 3.5.0
- update Helm chart values.yaml

# v1.2.1
IMPROVEMENTS
- remove default limit behavior - LIMIT clause is now only added when explicitly specified by the user
- change `--clickhouse-limit` default from 1000 to 0 (no limit)
- `--clickhouse-limit` now acts as a maximum cap rather than a default value
- update OpenAPI documentation to clarify optional limit parameter behavior

BUG FIXES
- fix test expectations to match new limit behavior (expect 0 instead of 1000)

# v1.2.0
IMPROVEMENTS
- remove `list_tables` and `describe_table` tools and resources
- remove all prompt capabilities

BUG FIXES
- fix OpenAPI schema generation to exclude removed endpoints
- remove references to deleted tools in documentation and tests
- extend isSelectQuery to support DESC, EXISTS, and EXPLAIN queries, fix https://github.com/Altinity/altinity-mcp/issues/26

# v1.1.3
BUG FIXES
- replace `single quote` and `backtick` chars to \uXXXX unicode representations in error message to avoid wrong MCP tool response handling in OpenAI, fix https://github.com/Altinity/altinity-mcp/issues/19
- properly show version in OpenAPI spec and MCP protocol

# v1.1.2
BUG FIXES
- add /openapi for SSE transport, even without JWE token, when JWE enabled, fix wrong config override from CLI to allow `/openapi` endpoint, even without JWE token, fix https://github.com/Altinity/altinity-mcp/issues/15

# v1.1.1
IMPROVEMENTS
- make `--jwt-secret-key` optional to use JSON serialization+JWE encryption instead of JWT signing+JWE encryption, fix https://github.com/Altinity/altinity-mcp/issues/25

# v1.1.0
IMPROVEMENTS
- switch to go 1.25, update go.mod
- add `--clickhouse-http-headers` and `CLICKHOUSE_HTTP_HEADERS` to configuration, fix https://github.com/Altinity/altinity-mcp/issues/18

BUG FIXES
- generate OpenAPI schema with `/openapi` endpoint, even without JWE token, fix https://github.com/Altinity/altinity-mcp/issues/15
- fix `stdio` transport failures after implementations JWE, fix https://github.com/Altinity/altinity-mcp/issues/17
- fix `isSelectQuery` corner cases, fix https://github.com/Altinity/altinity-mcp/issues/22

# v1.0.7
IMPROVEMENTS
- Update and enhance integration documentation for AI tools like Claude, Cursor, Windsurf, and OpenAI GPTs.
- Improve Helm chart documentation and resolve issues in the publishing workflow.
- Update project dependencies.

# v1.0.6
IMPROVEMENTS
- allow empty `--jwt-secret-key` parameter in CLI and inside `/jwe_token_generator`
- when jwt secret empty then instead of use JWT inside JWE just use json serialization and encrypt it with JWE 
- during check JWE token first of all try to validate encrypted token as JWT if this is not JWT token try try parse descryted JWE as json and try to check expire without JWT

# v1.0.5
IMPROVEMENTS
- add `--cors-origin` CLI parameter and `MCP_CORS_ORIGIN` config parameter, to allow custom origin in CORS policy

BUG FIXES
- minor fixes for CORS to pass https://playground.ai.cloudflare.com/

# v1.0.4
FEATURES
- add `/jwe-token-generator` endpoint to generate JWE tokens, fix https://github.com/Altinity/altinity-mcp/issues/8

# v1.0.3
BUG FIXES
- fix `/health` behavior for `read_only=true` corner case, fix https://github.com/Altinity/altinity-mcp/issues/7

# v1.0.2
IMPROVEMENTS
- add support `Authorization: Bearer`, `Authorization: Basic` and `x-altinity-mcp-key` headers for MCP servers
- add push helm chart into oci://ghcr.io/altinity/altinity-mcp/helm/altinity-mcp

# v1.0.1
BUG FIXES
- fix `/messages` handler for MCP SSE transport when JWE disabled

# v1.0.0
Initial release of Altinity MCP Server

## Features
- Using encrypted JWE Token to dynamically pass ClickHouse connection parameters
- MCP with STDIO, SSE and Streaming HTTP protocol - https://modelcontextprotocol.io
- OpenAPI for OpenAI GPTs actions - https://help.openai.com/en/articles/8554397-creating-a-gpt

vibe coded with https://github.com/hotovo/aider-desk
