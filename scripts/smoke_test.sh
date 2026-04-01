#!/bin/bash
# ContrastAPI Smoke Test — all endpoints
# Usage: ./smoke_test.sh [base_url]
# Deploy: scp -P 2222 smoke_test.sh root@116.203.191.133:/opt/contrastapi/
# Cron:   */15 * * * * /opt/contrastapi/smoke_test.sh --quiet

BASE="${1:-https://api.contrastcyber.com}"
QUIET=false
[ "$1" = "--quiet" ] && QUIET=true && BASE="http://127.0.0.1:8002"

PASS=0
FAIL=0
TOTAL=0
FAILURES=""

TELEGRAM_TOKEN_FILE="/etc/telegram-bot/token"
TELEGRAM_CHAT_FILE="/etc/telegram-bot/chat_ids"
STATE_FILE="/tmp/contrastapi_smoke_state"

send_telegram() {
  local message="$1"
  [ ! -f "$TELEGRAM_TOKEN_FILE" ] && return
  local token
  token=$(cat "$TELEGRAM_TOKEN_FILE")
  while IFS= read -r cid; do
    [ -z "$cid" ] || [ "${cid:0:1}" = "#" ] && continue
    curl -s -X POST "https://api.telegram.org/bot${token}/sendMessage" \
      -d "chat_id=$cid" -d "parse_mode=HTML" -d "text=$message" \
      --max-time 10 >/dev/null 2>&1
  done < "$TELEGRAM_CHAT_FILE"
}

check() {
  local method="$1" url="$2" expect="$3" body="$4"
  ((TOTAL++))

  if [ "$method" = "POST" ]; then
    status=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$url" \
      -H "Content-Type: application/json" -d "$body" --max-time 15)
  else
    status=$(curl -s -o /dev/null -w "%{http_code}" "$url" --max-time 15)
  fi

  # Strip base URL for cleaner output
  local path="${url#$BASE}"

  if [ "$status" = "$expect" ]; then
    ((PASS++))
    $QUIET || printf "  [OK]   %3s  %-6s %s\n" "$status" "$method" "$path"
  else
    ((FAIL++))
    FAILURES="${FAILURES}❌ ${method} ${path} → ${status} (expected ${expect})\n"
    $QUIET || printf "  [FAIL] %3s  %-6s %s  (expected %s)\n" "$status" "$method" "$path" "$expect"
  fi
}

echo ""
echo "============================================================"
echo "  ContrastAPI Smoke Test"
echo "  $(date -u '+%Y-%m-%d %H:%M UTC')"
echo "  Target: $BASE"
echo "============================================================"

echo ""
echo "  --- Meta ---"
check GET "$BASE/v1/status" 200
check GET "$BASE/v1/usage" 401

echo ""
echo "  --- CVE ---"
check GET "$BASE/v1/cve/CVE-2024-3400" 200
check GET "$BASE/v1/cves?keyword=apache&limit=2" 200
check GET "$BASE/v1/cves/recent?limit=2" 200
check GET "$BASE/v1/cves/kev?limit=2" 200
check GET "$BASE/v1/epss/CVE-2024-3400" 200

echo ""
echo "  --- Domain Intelligence ---"
check GET "$BASE/v1/domain/example.com" 200
check GET "$BASE/v1/dns/example.com" 200
check GET "$BASE/v1/whois/example.com" 200
check GET "$BASE/v1/subdomains/example.com" 200
check GET "$BASE/v1/certs/example.com" 200
check GET "$BASE/v1/threat/example.com" 200
check GET "$BASE/v1/tech/example.com" 200
check GET "$BASE/v1/monitor/example.com" 200
check GET "$BASE/v1/domain/example.com/vulns" 200

echo ""
echo "  --- SSL ---"
check GET "$BASE/v1/ssl/example.com" 200

echo ""
echo "  --- IP ---"
check GET "$BASE/v1/ip/8.8.8.8" 200

echo ""
echo "  --- Threat Intelligence ---"
check GET "$BASE/v1/ioc/8.8.8.8" 200
check GET "$BASE/v1/hash/e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" 200
check GET "$BASE/v1/password/5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8" 200
check GET "$BASE/v1/phishing/https://example.com" 200

echo ""
echo "  --- Bulk ---"
check POST "$BASE/v1/domains/bulk" 200 '{"domains":["example.com","google.com"]}'

echo ""
echo "  --- Code Security ---"
check POST "$BASE/v1/check/secrets" 200 '{"code":"const x = 1;","language":"javascript"}'
check POST "$BASE/v1/check/injection" 200 '{"code":"user_input = request.args[\"id\"]\nquery = \"SELECT * FROM users WHERE id = \" + user_input","language":"python"}'
check GET  "$BASE/v1/scan/headers/example.com" 200
check POST "$BASE/v1/check/headers" 200 '{"headers":{"X-Frame-Options":"DENY"}}'
check POST "$BASE/v1/check/dependencies" 200 '{"packages":[{"name":"lodash","version":"4.17.20"}],"ecosystem":"npm"}'

echo ""
echo "  --- Exploit ---"
check GET "$BASE/v1/exploit/CVE-2024-3400" 200

echo ""
echo "  --- Error Handling ---"
check GET "$BASE/v1/cve/INVALID" 400
check GET "$BASE/v1/ip/not-an-ip" 400
check GET "$BASE/v1/domain/999.999.999.999" 422

$QUIET || echo ""
$QUIET || echo "============================================================"
$QUIET || echo "  Results: $PASS passed, $FAIL failed, $TOTAL total"
$QUIET || echo "============================================================"

# State tracking for recovery alerts
PREV_STATE="ok"
[ -f "$STATE_FILE" ] && PREV_STATE=$(cat "$STATE_FILE")

if [ "$FAIL" -gt 0 ]; then
  echo "fail" > "$STATE_FILE"
  MSG="<b>🚨 API Smoke Test FAILED</b>
${PASS}/${TOTAL} passed, <b>${FAIL} failed</b>
$(date -u '+%Y-%m-%d %H:%M UTC')

$(echo -e "$FAILURES")"
  send_telegram "$MSG"
else
  echo "ok" > "$STATE_FILE"
  if [ "$PREV_STATE" = "fail" ]; then
    send_telegram "<b>✅ API Recovered</b>
All ${TOTAL} endpoints OK
$(date -u '+%Y-%m-%d %H:%M UTC')"
  fi
fi

exit $FAIL
