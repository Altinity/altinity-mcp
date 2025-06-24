#!/bin/bash
set -e
# This script demonstrates how to use JWT authentication with the Altinity MCP Server
CUR_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"

# First, generate a JWT token
echo "Generating JWT token..."
TOKEN=$(go run "${CUR_DIR}/jwt_token_generator.go" \
  --secret="test-secret-key" \
  --host="${CLICKHOUSE_HOST:-localhost}" \
  --port="${CLICKHOUSE_PORT:-8123}" \
  --database="${CLICKHOUSE_DB:-default}" \
  --username="${CLICKHOUSE_USER:-default}" \
  --password="${CLICKHOUSE_PASSWORD:-}" \
  --tls="${CLICKHOUSE_TLS:-False}" \
  --protocol="http" \
  --expiry=3600 | grep -A 1 "JWT Token:" | tail -n 1)

echo "Generated token: $TOKEN"

# Start the MCP server with JWT authentication in the background
echo "Starting MCP server with JWT authentication..."
go run "${CUR_DIR}/../../cmd/altinity-mcp/main.go" --allow-jwt-auth --jwt-secret-key="test-secret-key" --transport=sse --address=127.0.0.1 --port=8080 &
GO_RUN_PID=$!

# Get the actual server process PID (child of go run)
sleep 1
SERVER_PID=$(pgrep -P $GO_RUN_PID)
if [ -z "$SERVER_PID" ]; then
    echo "Warning: Could not find server process PID, using go run PID"
    SERVER_PID=$GO_RUN_PID
fi
echo "Server PID: $SERVER_PID"

# Wait for server to start
sleep 2

# Now query the server with the JWT token
echo -e "\nQuerying server with JWT token in path..."
curl -vvv "http://127.0.0.1:8080/$TOKEN/sse" -H "Accept: text/event-stream" &
CURL_PATH_PID=$!

# Wait a bit to see events
sleep 5

# Clean up
echo -e "\n\nStopping client and server... ${SERVER_PID} ${CURL_PATH_PID}"
kill $CURL_PATH_PID 2>/dev/null || true
kill $SERVER_PID 2>/dev/null || true
kill $GO_RUN_PID 2>/dev/null || true

echo "Test completed"
