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
