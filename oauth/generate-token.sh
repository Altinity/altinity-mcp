#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "Usage: $0 <clickhouse-host> <mcp-host>" >&2
  exit 1
fi

CLICKHOUSE="${1}"
MCP_HOST="${2}"
KEY_DIR="${HOME}/.mcp/${MCP_HOST}"
JWE_FILE="${KEY_DIR}/jwe.key"
PORT="${PORT:-9440}"
PROTOCOL="${PROTOCOL:-http}"

if [[ ! -s "${JWE_FILE}" ]]; then
  echo "Missing JWE key file: ${JWE_FILE}" >&2
  exit 2
fi

read -rp "Database [default]: " database
database=${database:-default}
read -rp "Username: " username
read -rp "Password: " password
echo
read -rp "Expiry in seconds [86400]: " expiry
expiry=${expiry:-86400}

read -rp "Port [${PORT}]: " port_input
PORT=${port_input:-$PORT}
read -rp "Protocol (tcp/http) [${PROTOCOL}]: " proto_input
PROTOCOL=${proto_input:-$PROTOCOL}

case "${PROTOCOL}" in
  tcp) proto_flag="--protocol tcp" ;;
  http) proto_flag="--protocol http" ;;
  *) echo "Unsupported protocol: ${PROTOCOL}" >&2; exit 3 ;;
esac

JWE_TOKEN="$(tr -d '\n' < "${JWE_FILE}")"

docker run --rm ghcr.io/altinity/altinity-mcp:latest jwe-token-generator \
  --jwe-secret-key "${JWE_TOKEN}" \
  --host "${CLICKHOUSE}" \
  --port "${PORT}" \
  ${proto_flag} \
  --username "${username}" \
  ${password:+--password "${password}"} \
  --database "${database}" \
  --expiry "${expiry}"
