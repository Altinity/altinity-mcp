#!/bin/bash
set -euo pipefail
CLICKHOUSE="${1}"
MCP="${2}"
KEY_DIR="${HOME}/.mcp/${MCP}"
JWE_FILE="${KEY_DIR}/jwe.key"
JWT_FILE="${KEY_DIR}/jwt.key"
PORT="${PORT:-9440}"
PROTOCOL="${PROTOCOL:-tls}"

# Colors
RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
NC="\033[0m" # No color

show_help() {
  echo -e "${GREEN}Usage:${NC} $0 <clickhouse> <mcp>"
  echo
  echo "Arguments:"
  echo "  clickhouse       Target clickhouse host (e.g., github.demo.altinity.cloud)"
  echo "  mcp              mcp server (to get keys from $HOME/.mcp/<mcp>)"
  echo
  echo "The script will then prompt you for:"
  echo "  - Database (default: default)"
  echo "  - Username"
  echo "  - Password"
  echo "  - Expiry in seconds (default: 86400 = 1 day), optional. To disable, enter none/None/NONE"
  echo
  echo "Fixed values:"
  echo "  JWE key:   \$HOME/.mcp/<mcp>/jwe.key"
  echo "  JWT key:   \$HOME/.mcp/<mcp>/jwt.key"
  echo "  Port:      configurable via --port (default: 9440)"
  echo "  Protocol:  configurable via --protocol (tcp/tls/http/https, default: tcp)"
  echo
  echo "Example:"
  echo "  $0 github.demo.altinity.cloud mcp.demo.altinity.cloud"
  exit 1
}

if [ $# -gt 2 ] || [[ "${1:-}" == "--help" ]]; then
  show_help
fi

# --- Validation for key files ---
if [ ! -s "$JWE_FILE" ]; then
  echo -e "${RED}Error:${NC} JWE key file not found or empty: $JWE_FILE"
  exit 2
fi

if [ ! -s "$JWT_FILE" ]; then
  echo -e "${RED}Error:${NC} JWT key file not found or empty: $JWT_FILE"
  exit 3
fi

echo -e "${GREEN}=== JWE/JWT Token Generator ===${NC}"
read -rp "Database [default]: " database
database=${database:-default}
read -rp "Username: " username
read -rp "Password: " password
if [[ -z "$password" ]]; then
  password=""
fi
echo
read -rp "Expiry in seconds [86400]: " expiry

# Validate expiry
if [[ -z "$expiry" ]]; then
  expiry=86400
elif [[ "$expiry" =~ ^([Nn][Oo][Nn][Ee])$ ]]; then
  expiry=""
elif ! [[ "$expiry" =~ ^[0-9]+$ ]]; then
  echo -e "${YELLOW}Warning:${NC} Expiry must be a number. Using default (86400)."
  expiry=86400
fi

read -rp "Port [${PORT}]: " port_input
PORT=${port_input:-$PORT}
read -rp "Protocol (tcp/tls/http/https) [${PROTOCOL}]: " proto_input
PROTOCOL=${proto_input:-$PROTOCOL}

# Normalize protocol and set proto_flag
proto_lc=$(echo "$PROTOCOL" | tr '[:upper:]' '[:lower:]')
case "$proto_lc" in
  tls)
    proto_flag="--protocol tcp --tls"
    ;;
  tcp)
    proto_flag="--protocol tcp"
    ;;
  http)
    proto_flag="--protocol http"
    ;;
  https)
    proto_flag="--protocol http --tls"
    ;;
  *)
    echo -e "${YELLOW}Warning:${NC} Unknown protocol '$PROTOCOL', defaulting to tls."
    proto_flag="--protocol tcp --tls"
    ;;
esac

jwe_token=$(tr -d '\n' < "$JWE_FILE")
jwt_token=$(tr -d '\n' < "$JWT_FILE")

echo -e "${GREEN}Running token generator...${NC}"

output=$(docker run --rm ghcr.io/altinity/altinity-mcp:latest jwe-token-generator \
  --jwe-secret-key "$jwe_token" \
  --jwt-secret-key "$jwt_token" \
  --host "$CLICKHOUSE" \
  --port "$PORT" \
  $proto_flag \
  --username "$username" \
  ${password:+--password "$password"} \
  --database "$database" \
  ${expiry:+--expiry "$expiry"})
echo "$output" | sed -E "s|http://localhost:8080/?|https://${MCP}/|g; s|/sse\"|/http\"|g"

echo -e "${GREEN}Done.${NC}"
