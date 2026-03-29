#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"
load_oauth_local_config

TARGET_HOST="${MCP_TARGET_HOST}"
MCP_PREFIX="${MCP_PUBLIC_MCP_PREFIX:-/http-t}"
OAUTH_PREFIX="${MCP_PUBLIC_OAUTH_PREFIX:-/oauth-t}"
MCP_NAME="${MCP_NAME:-altinity_mcp_oauth_gating}"
CALLBACK_PORT="${MCP_CALLBACK_PORT:-3334}"
LOCAL_PORT="${MCP_LOCAL_PORT:-18081}"
LOG_DIR="${BIN_DIR:-$PWD/.tmp}"
LOCAL_LOG="${LOG_DIR}/test-google-gating.local.log"

require_env GOOGLE_OAUTH_CLIENT_ID
require_env GOOGLE_OAUTH_CLIENT_SECRET
require_env MCP_OAUTH_GATING_SECRET

mkdir -p "${LOG_DIR}"

cleanup() {
  cleanup_pid "${LOCAL_PID:-}"
}
trap cleanup EXIT

LOCAL_PID="$(start_local_mcp "${SCRIPT_DIR}/start-local-gating.sh" "${LOCAL_LOG}")"

wait_for_url "http://127.0.0.1:${LOCAL_PORT}/.well-known/oauth-protected-resource" 60
wait_for_url "https://${TARGET_HOST}${MCP_PREFIX}/.well-known/oauth-protected-resource" 60
wait_for_url "https://${TARGET_HOST}${OAUTH_PREFIX}/.well-known/oauth-authorization-server" 60
wait_for_url "https://${TARGET_HOST}${OAUTH_PREFIX}/.well-known/openid-configuration" 60

probe_json_endpoint "https://${TARGET_HOST}${MCP_PREFIX}/.well-known/oauth-protected-resource"
probe_json_endpoint "https://${TARGET_HOST}${OAUTH_PREFIX}/.well-known/oauth-authorization-server"
probe_json_endpoint "https://${TARGET_HOST}${OAUTH_PREFIX}/.well-known/openid-configuration"

register_codex_server "${MCP_NAME}" "${TARGET_HOST}" "${MCP_PREFIX}"

echo "Login with a verified @altinity.com Google account."
codex_login "${MCP_NAME}" "${CALLBACK_PORT}"

echo "Running gating-mode verification query against github.demo.altinity.cloud..."
codex_query "Use the configured MCP server named ${MCP_NAME}. Execute SELECT version() and return only the SQL result."
