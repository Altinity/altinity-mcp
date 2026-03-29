#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"
load_oauth_local_config

TARGET_HOST="${MCP_TARGET_HOST}"
MCP_PREFIX="${MCP_PUBLIC_MCP_PREFIX:-/http-f}"
OAUTH_PREFIX="${MCP_PUBLIC_OAUTH_PREFIX:-/oauth-f}"
BIN_DIR="${BIN_DIR:-$PWD/.tmp}"
BIN_PATH="${BIN_DIR}/altinity-mcp-oauth-forward"
CONFIG_PATH="${BIN_DIR}/oauth-forward.yaml"
PORT="${MCP_LOCAL_PORT:-18080}"
ADDRESS="${MCP_LOCAL_ADDRESS:-0.0.0.0}"

: "${GOOGLE_OAUTH_CLIENT_ID:?set GOOGLE_OAUTH_CLIENT_ID}"
: "${GOOGLE_OAUTH_CLIENT_SECRET:?set GOOGLE_OAUTH_CLIENT_SECRET}"
: "${MCP_OAUTH_GATING_SECRET:?set MCP_OAUTH_GATING_SECRET}"

# ── ClickHouse target ──
# Default: remote demo server
# Pass --local-clickhouse to start Antalya in Docker instead

USE_LOCAL_CH=false
for arg in "$@"; do
  case "${arg}" in
    --local-clickhouse) USE_LOCAL_CH=true ;;
  esac
done

if [[ "${USE_LOCAL_CH}" == "true" ]]; then
  echo "Starting local ClickHouse Antalya container..."
  "${SCRIPT_DIR}/start-clickhouse-antalia-google.sh"
  CLICKHOUSE_HOST="127.0.0.1"
  CLICKHOUSE_PORT="${CLICKHOUSE_FORWARD_HTTP_PORT:-18123}"
  CLICKHOUSE_DATABASE="default"
  CLICKHOUSE_USERNAME="default"
  CLICKHOUSE_PASSWORD=""
  CLICKHOUSE_PROTOCOL="http"
  CLICKHOUSE_TLS_ENABLED="false"
  CLICKHOUSE_TLS_INSECURE_SKIP_VERIFY="false"
  CLICKHOUSE_READ_ONLY="false"
else
  CLICKHOUSE_HOST="${CLICKHOUSE_HOST:-github.demo.altinity.cloud}"
  CLICKHOUSE_PORT="${CLICKHOUSE_PORT:-8443}"
  CLICKHOUSE_DATABASE="${CLICKHOUSE_DATABASE:-default}"
  CLICKHOUSE_PROTOCOL="${CLICKHOUSE_PROTOCOL:-http}"
  CLICKHOUSE_TLS_ENABLED="${CLICKHOUSE_TLS_ENABLED:-true}"
  CLICKHOUSE_TLS_INSECURE_SKIP_VERIFY="${CLICKHOUSE_TLS_INSECURE_SKIP_VERIFY:-false}"
  CLICKHOUSE_READ_ONLY="${CLICKHOUSE_READ_ONLY:-true}"
fi

mkdir -p "${BIN_DIR}"

go build -o "${BIN_PATH}" ./cmd/altinity-mcp

cat > "${CONFIG_PATH}" <<EOF
clickhouse:
  host: "${CLICKHOUSE_HOST}"
  port: ${CLICKHOUSE_PORT}
  database: "${CLICKHOUSE_DATABASE}"
  protocol: "${CLICKHOUSE_PROTOCOL}"
  tls:
    enabled: ${CLICKHOUSE_TLS_ENABLED}
    insecure_skip_verify: ${CLICKHOUSE_TLS_INSECURE_SKIP_VERIFY}
  read_only: ${CLICKHOUSE_READ_ONLY}
  limit: 0
server:
  transport: "http"
  address: "${ADDRESS}"
  port: ${PORT}
  openapi:
    enabled: true
    tls: true
  jwe:
    enabled: false
  oauth:
    enabled: true
    mode: "forward"
    issuer: "https://accounts.google.com"
    audience: "${MCP_OAUTH_FORWARD_AUDIENCE:-}"
    gating_secret_key: "${MCP_OAUTH_GATING_SECRET}"
    public_resource_url: "https://${TARGET_HOST}${MCP_PREFIX}"
    public_auth_server_url: "https://${TARGET_HOST}${OAUTH_PREFIX}"
    protected_resource_metadata_path: "/.well-known/oauth-protected-resource"
    authorization_server_metadata_path: "/.well-known/oauth-authorization-server"
    openid_configuration_path: "/.well-known/openid-configuration"
    registration_path: "/register"
    authorization_path: "/authorize"
    callback_path: "/callback"
    token_path: "/token"
    upstream_issuer_allowlist:
      - "accounts.google.com"
      - "https://accounts.google.com"
    client_id: "${GOOGLE_OAUTH_CLIENT_ID}"
    client_secret: "${GOOGLE_OAUTH_CLIENT_SECRET}"
    token_url: "https://oauth2.googleapis.com/token"
    auth_url: "https://accounts.google.com/o/oauth2/v2/auth"
    scopes:
      - "openid"
      - "email"
    required_scopes:
      - "openid"
    auth_code_ttl_seconds: 300
    access_token_ttl_seconds: 3600
    refresh_token_ttl_seconds: 2592000
logging:
  level: "debug"
EOF

echo "Starting local altinity-mcp forward mode on ${ADDRESS}:${PORT}"
if [[ "${USE_LOCAL_CH}" == "true" ]]; then
  echo "ClickHouse: local Antalya container at ${CLICKHOUSE_HOST}:${CLICKHOUSE_PORT}"
else
  echo "ClickHouse: remote ${CLICKHOUSE_HOST}:${CLICKHOUSE_PORT}/${CLICKHOUSE_DATABASE}"
fi
echo "Public MCP base: https://${TARGET_HOST}${MCP_PREFIX}"
echo "Public OAuth base: https://${TARGET_HOST}${OAUTH_PREFIX}/"
exec "${BIN_PATH}" --config "${CONFIG_PATH}"
