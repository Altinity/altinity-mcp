# v1.1.3
BUG FIXES
- replace `single quote` and `backtick` chars to \uXXXX unicode representations in error message to avoid wrong MCP tool response handling in OpenAI, fix https://github.com/Altinity/altinity-mcp/issues/19 

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
