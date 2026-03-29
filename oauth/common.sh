#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

require_target_host() {
  require_env MCP_TARGET_HOST
}

oauth_host_config_dir() {
  require_target_host
  printf '%s\n' "${MCP_CONFIG_DIR:-$HOME/.mcp/$MCP_TARGET_HOST}"
}

load_google_oauth_env() {
  local env_file="${MCP_GOOGLE_ENV_FILE:-$(oauth_host_config_dir)/google-oauth.env}"
  if [[ -f "${env_file}" ]]; then
    set -a
    # shellcheck disable=SC1090
    source "${env_file}"
    set +a
  fi
}

load_gating_secret() {
  local config_dir secret_file
  config_dir="$(oauth_host_config_dir)"
  mkdir -p "${config_dir}"
  secret_file="${MCP_GATING_SECRET_FILE:-${config_dir}/oauth-gating-secret}"

  if [[ -z "${MCP_OAUTH_GATING_SECRET:-}" && -s "${secret_file}" ]]; then
    MCP_OAUTH_GATING_SECRET="$(<"${secret_file}")"
    export MCP_OAUTH_GATING_SECRET
  fi

  if [[ -z "${MCP_OAUTH_GATING_SECRET:-}" ]]; then
    MCP_OAUTH_GATING_SECRET="$(openssl rand -base64 32 | tr -d '\n')"
    export MCP_OAUTH_GATING_SECRET
    umask 077
    printf '%s\n' "${MCP_OAUTH_GATING_SECRET}" > "${secret_file}"
  fi
}

load_oauth_local_config() {
  require_target_host
  load_google_oauth_env
  load_gating_secret
}

require_env() {
  local name="$1"
  if [[ -z "${!name:-}" ]]; then
    echo "Missing required environment variable: ${name}" >&2
    exit 1
  fi
}

require_command() {
  local name="$1"
  if ! command -v "${name}" >/dev/null 2>&1; then
    echo "Missing required command: ${name}" >&2
    exit 1
  fi
}

wait_for_url() {
  local url="$1"
  local timeout="${2:-60}"
  local sleep_seconds=2
  local attempt=0
  local max_attempts=$(( timeout / sleep_seconds ))

  while (( attempt < max_attempts )); do
    if curl -fsS "${url}" >/dev/null 2>&1; then
      return 0
    fi
    attempt=$(( attempt + 1 ))
    sleep "${sleep_seconds}"
  done

  echo "Timed out waiting for ${url}" >&2
  return 1
}

probe_json_endpoint() {
  local url="$1"
  echo "Probing ${url}..."
  curl -fsS "${url}" >/dev/null
}

start_local_mcp() {
  local script_path="$1"
  local log_file="$2"

  echo "Starting ${script_path}..."
  "${script_path}" >"${log_file}" 2>&1 &
  echo $!
}

cleanup_pid() {
  local pid="$1"
  if [[ -n "${pid}" ]] && kill -0 "${pid}" >/dev/null 2>&1; then
    kill "${pid}" >/dev/null 2>&1 || true
    wait "${pid}" >/dev/null 2>&1 || true
  fi
}

register_codex_server() {
  local name="$1"
  local host="$2"
  local prefix="$3"
  MCP_NAME="${name}" MCP_TARGET_HOST="${host}" MCP_PUBLIC_MCP_PREFIX="${prefix}" \
    "${SCRIPT_DIR}/register-codex.sh"
}

codex_login() {
  local name="$1"
  local callback_port="$2"
  codex -c "mcp_oauth_callback_port=${callback_port}" mcp login "${name}"
}

codex_query() {
  local prompt="$1"
  codex exec "${prompt}"
}
