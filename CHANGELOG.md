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
