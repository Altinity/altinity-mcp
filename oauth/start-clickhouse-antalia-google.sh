#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TMP_DIR="${BIN_DIR:-$PWD/.tmp}/google-antalia"
CONTAINER_NAME="${CLICKHOUSE_CONTAINER_NAME:-altinity-mcp-google-antalia}"
HTTP_PORT="${CLICKHOUSE_FORWARD_HTTP_PORT:-18123}"
IMAGE="${CLICKHOUSE_ANTALIA_IMAGE:-altinity/clickhouse-server:25.8.16.20001.altinityantalya}"
TOKEN_PROCESSOR_FILE="${TMP_DIR}/token_processor.xml"
STARTUP_SCRIPTS_FILE="${TMP_DIR}/startup_scripts.xml"

mkdir -p "${TMP_DIR}"

cat > "${TOKEN_PROCESSOR_FILE}" <<'EOF'
<?xml version="1.0"?>
<clickhouse>
    <token_processors>
        <google>
            <type>jwt_dynamic_jwks</type>
            <userinfo_endpoint>https://openidconnect.googleapis.com/v1/userinfo</userinfo_endpoint>
            <token_introspection_endpoint>https://oauth2.googleapis.com/tokeninfo</token_introspection_endpoint>
            <jwks_uri>https://www.googleapis.com/oauth2/v3/certs</jwks_uri>
            <token_cache_lifetime>60</token_cache_lifetime>
            <username_claim>email</username_claim>
        </google>
    </token_processors>
    <user_directories replace="replace">
        <users_xml>
            <path>users.xml</path>
        </users_xml>
        <local_directory>
            <path>/var/lib/clickhouse/access/</path>
        </local_directory>
        <token>
            <processor>google</processor>
            <common_roles>
                <default_role />
            </common_roles>
        </token>
    </user_directories>
</clickhouse>
EOF

cat > "${STARTUP_SCRIPTS_FILE}" <<'EOF'
<?xml version="1.0"?>
<clickhouse>
    <startup_scripts>
        <scripts>
            <query>CREATE ROLE OR REPLACE default_role</query>
        </scripts>
        <scripts>
            <query>GRANT SELECT ON *.* TO default_role</query>
        </scripts>
    </startup_scripts>
</clickhouse>
EOF

docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true

docker run -d \
  --name "${CONTAINER_NAME}" \
  -p "127.0.0.1:${HTTP_PORT}:8123" \
  -e CLICKHOUSE_SKIP_USER_SETUP=1 \
  -e CLICKHOUSE_DB=default \
  -e CLICKHOUSE_USER=default \
  -e CLICKHOUSE_PASSWORD= \
  -e CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT=1 \
  -v "${TOKEN_PROCESSOR_FILE}:/etc/clickhouse-server/config.d/token_processor.xml:ro" \
  -v "${STARTUP_SCRIPTS_FILE}:/etc/clickhouse-server/config.d/startup_scripts.xml:ro" \
  "${IMAGE}" >/dev/null

echo "Started ${CONTAINER_NAME} on 127.0.0.1:${HTTP_PORT}"

for _ in $(seq 1 60); do
  if curl -fsS "http://127.0.0.1:${HTTP_PORT}/" >/dev/null 2>&1; then
    echo "ClickHouse Antalya is ready"
    exit 0
  fi
  sleep 2
done

echo "ClickHouse Antalya did not become ready in time" >&2
exit 1
