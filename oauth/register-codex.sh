#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"
require_target_host

NAME="${MCP_NAME:-altinity_mcp_oauth}"
HOST="${MCP_TARGET_HOST}"
MCP_PREFIX="${MCP_PUBLIC_MCP_PREFIX:-/http-t}"
URL="https://${HOST}${MCP_PREFIX}"

codex mcp remove "${NAME}" >/dev/null 2>&1 || true
codex mcp add "${NAME}" --url "${URL}"
codex mcp get "${NAME}" --json
