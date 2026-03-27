#!/usr/bin/env bash
set -euo pipefail

TARGET_HOST="${MCP_TARGET_HOST:-welcome.ru}"
MCP_PREFIX="${MCP_PUBLIC_MCP_PREFIX:-/http}"
OAUTH_PREFIX="${MCP_PUBLIC_OAUTH_PREFIX:-/oauth}"
BIN_DIR="${BIN_DIR:-$PWD/.tmp}"
BIN_PATH="${BIN_DIR}/altinity-mcp-oauth"
CONFIG_PATH="${BIN_DIR}/oauth-local.yaml"
PORT="${MCP_LOCAL_PORT:-8080}"
ADDRESS="${MCP_LOCAL_ADDRESS:-0.0.0.0}"
CLICKHOUSE_CLIENT_CONFIG="${CLICKHOUSE_CLIENT_CONFIG:-$HOME/.clickhouse-client/config.xml}"
CLICKHOUSE_CONNECTION_NAME="${CLICKHOUSE_CONNECTION_NAME:-demo}"

: "${GOOGLE_OAUTH_CLIENT_ID:?set GOOGLE_OAUTH_CLIENT_ID}"
: "${GOOGLE_OAUTH_CLIENT_SECRET:?set GOOGLE_OAUTH_CLIENT_SECRET}"

mkdir -p "${BIN_DIR}"

if [[ -z "${CLICKHOUSE_HOST:-}" ]]; then
  if [[ ! -s "${CLICKHOUSE_CLIENT_CONFIG}" ]]; then
    echo "Missing ClickHouse client config: ${CLICKHOUSE_CLIENT_CONFIG}" >&2
    exit 1
  fi
  eval "$(
    python3 - <<'PY'
import shlex
import xml.etree.ElementTree as ET
from pathlib import Path
import os

cfg = Path(os.environ["CLICKHOUSE_CLIENT_CONFIG"])
name = os.environ["CLICKHOUSE_CONNECTION_NAME"]
root = ET.parse(cfg).getroot()
section = root.find("connections_credentials")
if section is None:
    raise SystemExit("missing <connections_credentials>")
target = None
for conn in section.findall("connection"):
    if (conn.findtext("name") or "").strip() == name:
        target = conn
        break
if target is None:
    raise SystemExit(f"missing connection named {name!r}")

def emit(key, value):
    print(f'{key}={shlex.quote((value or "").strip())}')

emit("CLICKHOUSE_HOST", target.findtext("hostname"))
emit("CLICKHOUSE_PORT", target.findtext("port") or "9440")
emit("CLICKHOUSE_DATABASE", target.findtext("database") or "default")
emit("CLICKHOUSE_USERNAME", target.findtext("user"))
emit("CLICKHOUSE_PASSWORD", target.findtext("password") or "")
secure = (target.findtext("secure") or "").strip()
emit("CLICKHOUSE_PROTOCOL", "tcp")
emit("CLICKHOUSE_TLS_ENABLED", "true" if secure in {"1", "true", "True"} else "false")
PY
  )"
fi

go build -o "${BIN_PATH}" ./cmd/altinity-mcp

cat > "${CONFIG_PATH}" <<EOF
clickhouse:
  host: "${CLICKHOUSE_HOST}"
  port: ${CLICKHOUSE_PORT}
  database: "${CLICKHOUSE_DATABASE}"
  username: "${CLICKHOUSE_USERNAME}"
  password: "${CLICKHOUSE_PASSWORD}"
  protocol: "${CLICKHOUSE_PROTOCOL}"
  tls:
    enabled: ${CLICKHOUSE_TLS_ENABLED:-false}
    insecure_skip_verify: ${CLICKHOUSE_TLS_INSECURE_SKIP_VERIFY:-false}
  read_only: ${CLICKHOUSE_READ_ONLY:-true}
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
    issuer: "https://${TARGET_HOST}${OAUTH_PREFIX}"
    audience: "https://${TARGET_HOST}${MCP_PREFIX}"
    client_id: "${GOOGLE_OAUTH_CLIENT_ID}"
    client_secret: "${GOOGLE_OAUTH_CLIENT_SECRET}"
    token_url: "https://oauth2.googleapis.com/token"
    auth_url: "https://accounts.google.com/o/oauth2/v2/auth"
    scopes:
      - "openid"
      - "email"
    required_scopes:
      - "openid"
    forward_to_clickhouse: false
    forward_access_token: false
    clear_clickhouse_credentials: false
logging:
  level: "debug"
EOF

echo "Starting local altinity-mcp on ${ADDRESS}:${PORT}"
echo "ClickHouse connection: ${CLICKHOUSE_CONNECTION_NAME} -> ${CLICKHOUSE_HOST}:${CLICKHOUSE_PORT}/${CLICKHOUSE_DATABASE}"
echo "Public MCP base: https://${TARGET_HOST}${MCP_PREFIX}"
echo "Public OAuth base: https://${TARGET_HOST}${OAUTH_PREFIX}/"
exec "${BIN_PATH}" --config "${CONFIG_PATH}"
