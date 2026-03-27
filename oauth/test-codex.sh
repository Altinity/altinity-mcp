#!/usr/bin/env bash
set -euo pipefail

NAME="${MCP_NAME:-altinity_mcp_oauth}"
CALLBACK_PORT="${MCP_CALLBACK_PORT:-3334}"

echo "Logging into MCP server ${NAME}..."
codex -c "mcp_oauth_callback_port=${CALLBACK_PORT}" mcp login "${NAME}"

echo "Running non-interactive query through Codex..."
codex exec "Use the configured MCP server named ${NAME}. Execute SELECT version() and return only the SQL result."
