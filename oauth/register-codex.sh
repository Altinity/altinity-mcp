#!/usr/bin/env bash
set -euo pipefail

NAME="${MCP_NAME:-altinity_mcp_oauth}"
HOST="${MCP_TARGET_HOST:-welcome.ru}"
MCP_PREFIX="${MCP_PUBLIC_MCP_PREFIX:-/http}"
URL="https://${HOST}${MCP_PREFIX}"

codex mcp remove "${NAME}" >/dev/null 2>&1 || true
codex mcp add "${NAME}" --url "${URL}"
codex mcp get "${NAME}" --json
