#!/usr/bin/env bash
set -euo pipefail

MCP="${MCP:-https://otel-mcp.demo.altinity.cloud}"
PORT="${PORT:-8910}"
REDIR="http://localhost:${PORT}/cb"

# 1. PKCE verifier + challenge.
verifier=$(openssl rand -base64 32 | tr -d '=+/' | head -c 43)
challenge=$(printf '%s' "$verifier" | openssl dgst -sha256 -binary | openssl base64 | tr -d '=' | tr '/+' '_-')
state=$(openssl rand -hex 8)

# 2. DCR — register a confidential client.
echo "[1/6] registering DCR client at $MCP/oauth/register"
reg=$(curl -sS -X POST "$MCP/oauth/register" -H 'Content-Type: application/json' \
  -d "$(printf '{"redirect_uris":["%s"],"token_endpoint_auth_method":"client_secret_post","grant_types":["authorization_code","refresh_token"]}' "$REDIR")")
client_id=$(jq -r .client_id <<<"$reg")
client_secret=$(jq -r .client_secret <<<"$reg")
[ -n "$client_id" ] && [ "$client_id" != null ] || { echo "DCR failed: $reg"; exit 1; }
echo "    client_id=${client_id:0:24}…"

# 3. Build /oauth/authorize URL.
auth_url="$MCP/oauth/authorize?response_type=code&client_id=$(jq -rn --arg s "$client_id" '$s|@uri')&redirect_uri=$(jq -rn --arg s "$REDIR" '$s|@uri')&state=$state&code_challenge=$challenge&code_challenge_method=S256&scope=openid+email+profile"
echo
echo "[2/6] open this URL in a browser, complete Auth0 login:"
echo
echo "    $auth_url"
echo

# 4. Listen on PORT for the callback. Inline Python — robust on macOS, doesn't
#    depend on which nc flavor is installed. Writes the captured query string
#    to /tmp/h2-cb-${PORT}.txt and exits cleanly with a 200 to the browser.
cb_file="/tmp/h2-cb-${PORT}.txt"
rm -f "$cb_file"
echo "    waiting on http://localhost:$PORT/cb …"
python3 - "$PORT" "$cb_file" <<'PY' &
import http.server, socketserver, sys, urllib.parse, threading
port = int(sys.argv[1])
out  = sys.argv[2]
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a, **kw): pass
    def do_GET(self):
        qs = urllib.parse.urlparse(self.path).query
        with open(out, 'w') as f: f.write(qs)
        body = b"<html><body><h2>code captured. you can close this tab.</h2></body></html>"
        self.send_response(200)
        self.send_header('Content-Type','text/html')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        threading.Thread(target=self.server.shutdown, daemon=True).start()
with socketserver.TCPServer(('127.0.0.1', port), H) as srv:
    srv.serve_forever()
PY
listener_pid=$!

# Poll for the callback file (max 5 min).
for _ in $(seq 1 300); do
    [ -s "$cb_file" ] && break
    sleep 1
done
wait "$listener_pid" 2>/dev/null || true
[ -s "$cb_file" ] || { echo "no callback received within 5 min"; exit 1; }

qs=$(cat "$cb_file")
code=$(printf '%s' "$qs" | tr '&' '\n' | grep -E '^code=' | head -1 | cut -d= -f2-)
[ -n "$code" ] || { echo "no code in callback: $qs"; exit 1; }
echo "[3/6] captured code=${code:0:16}…"

# 5. Exchange code → tokens.
tok=$(curl -sS -X POST "$MCP/oauth/token" \
  -d "grant_type=authorization_code" \
  -d "code=$code" \
  --data-urlencode "redirect_uri=$REDIR" \
  -d "client_id=$client_id" \
  -d "client_secret=$client_secret" \
  --data-urlencode "code_verifier=$verifier")
access=$(jq -r .access_token <<<"$tok")
refresh=$(jq -r .refresh_token <<<"$tok")
[ -n "$refresh" ] && [ "$refresh" != null ] || { echo "token exchange failed: $tok"; exit 1; }
echo "[4/6] got access (${#access} chars) + refresh JWE R0 (${#refresh} chars)"

# 6. First refresh — must succeed, mints R1.
echo
echo "[5/6] first refresh of R0 — expect 200 OK"
r1_resp=$(curl -sS -w '\nHTTP %{http_code}' -X POST "$MCP/oauth/token" \
  -d "grant_type=refresh_token" \
  -d "refresh_token=$refresh" \
  -d "client_id=$client_id" \
  -d "client_secret=$client_secret")
echo "$r1_resp" | sed -e 's/^/    /'

# 7. Replay the SAME R0 — must fail and revoke family.
echo
echo "[6/6] REPLAY R0 — expect 400 invalid_grant 'reuse detected'"
r2_resp=$(curl -sS -w '\nHTTP %{http_code}' -X POST "$MCP/oauth/token" \
  -d "grant_type=refresh_token" \
  -d "refresh_token=$refresh" \
  -d "client_id=$client_id" \
  -d "client_secret=$client_secret")
echo "$r2_resp" | sed -e 's/^/    /'

# 8. Optional: redeem R1 (legit child) — must ALSO fail (family revoked).
r1=$(echo "$r1_resp" | head -1 | jq -r '.refresh_token // empty')
if [ -n "$r1" ]; then
    echo
    echo "[bonus] redeem R1 (legit child) — expect 400 invalid_grant (family revoked)"
    r3_resp=$(curl -sS -w '\nHTTP %{http_code}' -X POST "$MCP/oauth/token" \
      -d "grant_type=refresh_token" \
      -d "refresh_token=$r1" \
      -d "client_id=$client_id" \
      -d "client_secret=$client_secret")
    echo "$r3_resp" | sed -e 's/^/    /'
fi

echo
echo "Now check the state tables:"
echo "  echo \"SELECT consumed_at, jti, family_id FROM altinity.oauth_refresh_consumed_jtis ORDER BY consumed_at DESC LIMIT 3\" | ~/bin/cl otel"
echo "  echo \"SELECT revoked_at, family_id, reason FROM altinity.oauth_refresh_revoked_families ORDER BY revoked_at DESC LIMIT 3\" | ~/bin/cl otel"
