#!/bin/bash
set -e
# This script demonstrates how to use JWE authentication with the Altinity MCP Server
CUR_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"

JWE_SECRET_KEY="$(openssl genrsa 4096)"
echo "Generating RSA private key"
echo "${JWE_SECRET_KEY}"

# First, generate a JWT token
echo "Generating JWE token..."
# Note: Now using separate keys for JWE encryption and JWT signing
TOKEN=$(go run "${CUR_DIR}/jwe_token_generator.go" \
  --jwe-secret-key="test-jwt-secret-key" \
  --jwt-secret-key="${JWE_SECRET_KEY}" \
  --host="${CLICKHOUSE_HOST:-localhost}" \
  --port="${CLICKHOUSE_PORT:-8123}" \
  --database="${CLICKHOUSE_DB:-default}" \
  --username="${CLICKHOUSE_USER:-default}" \
  --password="${CLICKHOUSE_PASSWORD:-}" \
  --tls="${CLICKHOUSE_TLS:-False}" \
  --protocol="${CLICKHOUSE_PROTOCOL:-http}" \
  --expiry="${TOKEN_EXPIRE:-86400}" | grep -A 1 "JWT Token:" | tail -n 1)

echo "Generated token: $TOKEN"

# Start the MCP server with JWT authentication in the background
echo "Starting MCP server with JWE authentication..."
go run "${CUR_DIR}/../../cmd/altinity-mcp/main.go" --allow-jwe-auth --jwe-secret-key="${JWE_SECRET_KEY}" --jwt-secret-key="test-jwt-secret-key" --transport=sse --address=127.0.0.1 --port=8080 &
SERVER_PID=$!

# Wait for server to start
sleep 5

# Now query the server with the JWT token
echo -e "\nQuerying server with JWE token in path..."
curl -vvv "http://127.0.0.1:8080/$TOKEN/sse" -H "Accept: text/event-stream" &
CURL_PATH_PID=$!

# Wait a bit to see events
sleep 5

# Clean up
echo -e "\n\nStopping client and server..."
kill $CURL_PATH_PID
pkill -P $SERVER_PID
echo "Test completed"
