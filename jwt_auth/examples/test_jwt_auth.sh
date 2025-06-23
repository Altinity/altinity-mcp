#!/bin/bash

# This script demonstrates how to use JWT authentication with the Altinity MCP Server
CUR_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"

# First, generate a JWT token
echo "Generating JWT token..."
TOKEN=$(go run "${CUR_DIR}/jwt_token_generator.go" \
  --secret="test-secret-key" \
  --host="${CLICKHOUSE_HOST:-localhost}" \
  --port=${CLICKHOUSE_PORT:-8123} \
  --database="${CLICKHOUSE_DB:-default}" \
  --username="${CLICKHOUSE_USER:-default}" \
  --password="${CLICKHOUSE_USER:-default}" \
  --protocol="http" \
  --expiry=3600 | grep -A 1 "JWT Token:" | tail -n 1)

echo "Generated token: $TOKEN"

# Start the MCP server with JWT authentication in the background
echo "Starting MCP server with JWT authentication..."
go run ../../cmd/altinity-mcp/ --allow-jwt-auth --jwt-secret-key="test-secret-key" --transport=sse --address=127.0.0.1 --port=8080 &
SERVER_PID=$!

# Wait for server to start
sleep 2

# Now query the server with the JWT token
echo -e "\nQuerying server with JWT token..."
curl -s "http://localhost:8080/sse?token=$TOKEN" -H "Accept: text/event-stream" &
CURL_PID=$!

# Wait a bit to see events
sleep 5

# Clean up
echo -e "\n\nStopping client and server..."
kill $CURL_PID
kill $SERVER_PID

echo "Test completed"