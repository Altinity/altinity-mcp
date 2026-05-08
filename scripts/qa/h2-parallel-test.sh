#!/usr/bin/env bash
# H-2 atomicity test: drive N concurrent /oauth/token grant_type=refresh_token
# requests with the SAME refresh JWE. KeeperMap strict-mode INSERT must
# linearise the claim — exactly one wins, the rest get invalid_grant.
#
# Reuses h2-replay-test.sh's OAuth dance (DCR + Auth0 login + auth-code
# exchange) up to obtaining R0, then fans out parallel redemptions.
set -euo pipefail

MCP="${MCP:-https://otel-mcp.demo.altinity.cloud}"
PORT="${PORT:-8910}"
N="${N:-50}"           # concurrent redeemers
REDIR="http://localhost:${PORT}/cb"

verifier=$(openssl rand -base64 32 | tr -d '=+/' | head -c 43)
challenge=$(printf '%s' "$verifier" | openssl dgst -sha256 -binary | openssl base64 | tr -d '=' | tr '/+' '_-')
state=$(openssl rand -hex 8)

echo "[1/4] DCR + Auth0 dance (same as h2-replay-test.sh)"
reg=$(curl -sS -X POST "$MCP/oauth/register" -H 'Content-Type: application/json' \
  -d "$(printf '{"redirect_uris":["%s"],"token_endpoint_auth_method":"client_secret_post","grant_types":["authorization_code","refresh_token"]}' "$REDIR")")
client_id=$(jq -r .client_id <<<"$reg")
client_secret=$(jq -r .client_secret <<<"$reg")

auth_url="$MCP/oauth/authorize?response_type=code&client_id=$(jq -rn --arg s "$client_id" '$s|@uri')&redirect_uri=$(jq -rn --arg s "$REDIR" '$s|@uri')&state=$state&code_challenge=$challenge&code_challenge_method=S256&scope=openid+email+profile"
echo
echo "    Open in browser: $auth_url"
echo

cb_file="/tmp/h2-cb-${PORT}.txt"
rm -f "$cb_file"
python3 - "$PORT" "$cb_file" <<'PY' &
import http.server, socketserver, sys, urllib.parse, threading
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a, **kw): pass
    def do_GET(self):
        with open(sys.argv[2], 'w') as f: f.write(urllib.parse.urlparse(self.path).query)
        body = b"<html><body><h2>captured. close this tab.</h2></body></html>"
        self.send_response(200); self.send_header('Content-Length', str(len(body))); self.end_headers()
        self.wfile.write(body)
        threading.Thread(target=self.server.shutdown, daemon=True).start()
with socketserver.TCPServer(('127.0.0.1', int(sys.argv[1])), H) as srv:
    srv.serve_forever()
PY
listener_pid=$!
for _ in $(seq 1 300); do [ -s "$cb_file" ] && break; sleep 1; done
wait "$listener_pid" 2>/dev/null || true
[ -s "$cb_file" ] || { echo "no callback"; exit 1; }
code=$(cat "$cb_file" | tr '&' '\n' | grep -E '^code=' | cut -d= -f2-)

tok=$(curl -sS -X POST "$MCP/oauth/token" \
  -d "grant_type=authorization_code" -d "code=$code" \
  --data-urlencode "redirect_uri=$REDIR" \
  -d "client_id=$client_id" -d "client_secret=$client_secret" \
  --data-urlencode "code_verifier=$verifier")
refresh=$(jq -r .refresh_token <<<"$tok")
[ -n "$refresh" ] && [ "$refresh" != null ] || { echo "no refresh token: $tok"; exit 1; }
echo "[2/4] got R0 (${#refresh} chars)"

# Fan out N parallel redeems. Use & + wait, write each result to a numbered
# file to avoid output interleaving. Curl gives us status code via -w.
echo
echo "[3/4] firing $N concurrent /oauth/token redemptions of the SAME R0"
work=$(mktemp -d -t h2-parallel-XXXXX)
trap 'rm -rf "$work"' EXIT

for i in $(seq 1 "$N"); do
    (curl -sS -o "$work/$i.body" -w "%{http_code}" -X POST "$MCP/oauth/token" \
        -d "grant_type=refresh_token" \
        -d "refresh_token=$refresh" \
        -d "client_id=$client_id" \
        -d "client_secret=$client_secret" > "$work/$i.code") &
done
wait

success=0
reuse=0
other=0
for i in $(seq 1 "$N"); do
    code=$(cat "$work/$i.code")
    case "$code" in
        200) success=$((success+1)) ;;
        400)
            err=$(jq -r '.error // "?"' < "$work/$i.body" 2>/dev/null)
            desc=$(jq -r '.error_description // "?"' < "$work/$i.body" 2>/dev/null)
            if [ "$err" = "invalid_grant" ] && [[ "$desc" == *reuse* ]]; then
                reuse=$((reuse+1))
            else
                other=$((other+1))
                echo "    UNEXPECTED 400 from req $i: $err / $desc"
            fi
            ;;
        *) other=$((other+1)); echo "    UNEXPECTED status $code from req $i: $(cat "$work/$i.body" | head -c 200)" ;;
    esac
done

echo
echo "[4/4] results:"
echo "    200 OK (claimed):       $success"
echo "    400 invalid_grant reuse: $reuse"
echo "    other:                  $other"
echo
if [ "$success" -eq 1 ] && [ "$reuse" -eq $((N-1)) ] && [ "$other" -eq 0 ]; then
    echo "✓ ATOMICITY CONFIRMED: exactly 1 winner, $((N-1)) reuse-detected, no anomalies"
else
    echo "✗ ANOMALY: expected exactly 1 winner + $((N-1)) reuse-detected"
    exit 1
fi

echo
echo "Verify state-table side effects:"
echo "  echo \"SELECT count() FROM altinity.oauth_refresh_consumed_jtis WHERE consumed_at > now() - 60\" | ~/bin/cl otel"
echo "  # expect: 1 (winning jti only — other 49 INSERTs were rejected by KeeperMap strict mode)"
echo "  echo \"SELECT family_id, reason FROM altinity.oauth_refresh_revoked_families WHERE revoked_at > now() - 60\" | ~/bin/cl otel"
echo "  # expect: 1 row, reason=reuse_detected (or possibly more rows if multiple losers wrote — that's idempotent)"
