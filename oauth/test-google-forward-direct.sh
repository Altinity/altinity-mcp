#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"
load_oauth_local_config

LOCAL_PORT="${MCP_LOCAL_PORT:-18080}"
CLICKHOUSE_HOST="${CLICKHOUSE_HOST:-github.demo.altinity.cloud}"
CLICKHOUSE_HTTP_PORT="${CLICKHOUSE_PORT:-8443}"
TARGET_HOST="${MCP_TARGET_HOST}"
PUBLIC_PREFIX="${MCP_PUBLIC_MCP_PREFIX:-/http-f}"
LOG_DIR="${BIN_DIR:-$PWD/.tmp}"
LOCAL_LOG="${LOG_DIR}/test-google-forward-direct.local.log"
PUBLIC_QUERY_URL="${FORWARD_PUBLIC_OPENAPI_URL:-https://${TARGET_HOST}${PUBLIC_PREFIX}/openapi/execute_query}"
AUDIENCE="${FORWARD_ID_TOKEN_AUDIENCE:-}"

require_command gcloud

mkdir -p "${LOG_DIR}"

cleanup() {
  cleanup_pid "${LOCAL_PID:-}"
}
trap cleanup EXIT

if [[ -n "${GOOGLE_OAUTH_CLIENT_ID:-}" && -n "${GOOGLE_OAUTH_CLIENT_SECRET:-}" && -n "${MCP_OAUTH_GATING_SECRET:-}" ]]; then
  echo "Starting local altinity-mcp in forward mode..."
  LOCAL_PID="$(start_local_mcp "${SCRIPT_DIR}/start-local-forward.sh" "${LOCAL_LOG}")"
  wait_for_url "http://127.0.0.1:${LOCAL_PORT}/.well-known/oauth-protected-resource" 60
else
  echo "Skipping local altinity-mcp startup because one of GOOGLE_OAUTH_CLIENT_ID, GOOGLE_OAUTH_CLIENT_SECRET, MCP_OAUTH_GATING_SECRET is missing."
fi

TOKEN_CMD=(gcloud auth print-identity-token)
if [[ -n "${AUDIENCE}" ]]; then
  TOKEN_CMD+=(--audiences="${AUDIENCE}")
fi

echo "Obtaining Google identity token for the active gcloud account..."
GOOGLE_ID_TOKEN="$("${TOKEN_CMD[@]}")"
if [[ -z "${GOOGLE_ID_TOKEN}" ]]; then
  echo "Failed to obtain Google identity token" >&2
  exit 1
fi

echo "Validating direct ClickHouse token auth..."
CH_RESPONSE="$(curl -fsS -H "Authorization: Bearer ${GOOGLE_ID_TOKEN}" \
  --get --data-urlencode "query=SELECT currentUser(), version()" \
  "https://${CLICKHOUSE_HOST}:${CLICKHOUSE_HTTP_PORT}/")"
printf '%s\n' "${CH_RESPONSE}"

if [[ -n "${LOCAL_PID:-}" ]]; then
  echo "Validating altinity-mcp local forward mode..."
  MCP_RESPONSE="$(curl -fsS -H "Authorization: Bearer ${GOOGLE_ID_TOKEN}" \
    --get --data-urlencode "query=SELECT currentUser(), version()" \
    "http://127.0.0.1:${LOCAL_PORT}/openapi/execute_query")"
  printf '%s\n' "${MCP_RESPONSE}"
fi

echo "Probing public forward OpenAPI endpoint..."
PUBLIC_HTTP_CODE="$(
  curl -sS -o "${LOG_DIR}/test-google-forward-direct.public.out" \
    -w '%{http_code}' \
    -H "Authorization: Bearer ${GOOGLE_ID_TOKEN}" \
    --get --data-urlencode "query=SELECT currentUser(), version()" \
    "${PUBLIC_QUERY_URL}" || true
)"
echo "public_http_code=${PUBLIC_HTTP_CODE}"
cat "${LOG_DIR}/test-google-forward-direct.public.out"
