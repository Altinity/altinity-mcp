#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"
load_oauth_local_config

TARGET_HOST="${MCP_TARGET_HOST}"
KUBECONFIG_PATH="${KUBECONFIG_PATH:-$HOME/.kube/aw-demo.config}"
NAMESPACE="${NAMESPACE:-demo}"
RELEASE_NAME="${RELEASE_NAME:-altinity-mcp-oauth}"
JWE_KEY_FILE="${JWE_KEY_FILE:-$HOME/.mcp/$TARGET_HOST/jwe.key}"
MCP_PREFIX="${MCP_PUBLIC_MCP_PREFIX:-/http-t}"
OAUTH_PREFIX="${MCP_PUBLIC_OAUTH_PREFIX:-/oauth-t}"

: "${GOOGLE_OAUTH_CLIENT_ID:?set GOOGLE_OAUTH_CLIENT_ID}"
: "${GOOGLE_OAUTH_CLIENT_SECRET:?set GOOGLE_OAUTH_CLIENT_SECRET}"
: "${MCP_OAUTH_BROKER_SECRET:?set MCP_OAUTH_BROKER_SECRET}"

if [[ ! -s "${JWE_KEY_FILE}" ]]; then
  echo "Missing JWE key: ${JWE_KEY_FILE}" >&2
  exit 1
fi

KUBECONFIG="${KUBECONFIG_PATH}" helm upgrade --install "${RELEASE_NAME}" \
  oci://ghcr.io/altinity/altinity-mcp/helm/altinity-mcp \
  --namespace "${NAMESPACE}" \
  --create-namespace \
  -f oauth/values.yaml \
  --set-string config.server.jwe.jwe_secret_key="$(tr -d '\n' < "${JWE_KEY_FILE}")" \
  --set-string config.server.oauth.mode="forward" \
  --set-string config.server.oauth.issuer="https://accounts.google.com" \
  --set-string config.server.oauth.audience="https://${TARGET_HOST}${MCP_PREFIX}" \
  --set-string config.server.oauth.broker_secret_key="${MCP_OAUTH_BROKER_SECRET}" \
  --set-string config.server.oauth.public_resource_url="https://${TARGET_HOST}${MCP_PREFIX}" \
  --set-string config.server.oauth.public_auth_server_url="https://${TARGET_HOST}${OAUTH_PREFIX}" \
  --set-string config.server.oauth.client_id="${GOOGLE_OAUTH_CLIENT_ID}" \
  --set-string config.server.oauth.client_secret="${GOOGLE_OAUTH_CLIENT_SECRET}"
