#!/bin/bash
# ContrastAPI Health Check — test all external APIs, alert on failure
# Cron: 0 8 * * * /opt/contrastapi/scripts/api_healthcheck.sh
# Optional: /etc/telegram-bot/token + chat_ids for Telegram alerts

set -euo pipefail

html_escape() {
  local s="$1"
  s="${s//&/&amp;}"
  s="${s//</&lt;}"
  s="${s//>/&gt;}"
  echo "$s"
}

LOG="/root/daily_logs/healthcheck.log"

# Telegram (optional)
TELEGRAM_ENABLED=false
if [[ -f /etc/telegram-bot/token && -f /etc/telegram-bot/chat_ids ]]; then
  TOKEN=$(cat /etc/telegram-bot/token)
  CHAT_IDS="/etc/telegram-bot/chat_ids"
  TELEGRAM_ENABLED=true
fi

# Load API keys from environment or systemd env file
if [[ -f /opt/contrastapi/.env ]]; then
  source /opt/contrastapi/.env
fi

ABUSEIPDB_KEY="${ABUSEIPDB_API_KEY:-}"
SHODAN_KEY="${SHODAN_API_KEY:-}"
URLHAUS_KEY="${URLHAUS_API_KEY:-}"

TEST_IP="8.8.8.8"
TEST_DOMAIN="example.com"

FAILED=()
RESULTS=()

check_api() {
  local name="$1"
  local url="$2"
  local method="${3:-GET}"
  local headers="${4:-}"
  local data="${5:-}"

  local start end elapsed http_code
  start=$(date +%s%N)

  local curl_args=(-s -o /dev/null -w "%{http_code}" --max-time 15)

  if [[ -n "$headers" ]]; then
    while IFS='|' read -ra HDR; do
      for h in "${HDR[@]}"; do
        curl_args+=(-H "$h")
      done
    done <<< "$headers"
  fi

  if [[ "$method" == "POST" ]]; then
    curl_args+=(-X POST)
    if [[ -n "$data" ]]; then
      curl_args+=(-d "$data")
    fi
  fi

  http_code=$(curl "${curl_args[@]}" "$url" 2>/dev/null || echo "000")
  end=$(date +%s%N)
  elapsed=$(( (end - start) / 1000000 ))

  if [[ "$http_code" =~ ^2 ]]; then
    RESULTS+=("$name: ${http_code} (${elapsed}ms)")
  else
    RESULTS+=("$name: ${http_code} (${elapsed}ms) FAIL")
    FAILED+=("$name (HTTP $http_code)")
  fi
}

echo "=== ContrastAPI Health Check $(date '+%Y-%m-%d %H:%M:%S') ===" | tee "$LOG"

# (GreyNoise removed — 25/week limit too low for production use)

# 2. AbuseIPDB
if [[ -n "$ABUSEIPDB_KEY" ]]; then
  check_api "AbuseIPDB" \
    "https://api.abuseipdb.com/api/v2/check?ipAddress=${TEST_IP}&maxAgeInDays=90" \
    "GET" \
    "Key: ${ABUSEIPDB_KEY}|Accept: application/json"
else
  RESULTS+=("AbuseIPDB: SKIPPED (no key)")
fi

# 3. Shodan Full API
if [[ -n "$SHODAN_KEY" ]]; then
  check_api "Shodan" \
    "https://api.shodan.io/shodan/host/${TEST_IP}?key=${SHODAN_KEY}" \
    "GET" \
    "Accept: application/json"
else
  RESULTS+=("Shodan: SKIPPED (no key)")
fi

# 4. Shodan InternetDB (free, no key)
check_api "InternetDB" \
  "https://internetdb.shodan.io/${TEST_IP}"

# 5. URLhaus
if [[ -n "$URLHAUS_KEY" ]]; then
  check_api "URLhaus" \
    "https://urlhaus-api.abuse.ch/v1/host/" \
    "POST" \
    "Auth-Key: ${URLHAUS_KEY}" \
    "host=${TEST_DOMAIN}"
else
  RESULTS+=("URLhaus: SKIPPED (no key)")
fi

# 6. crt.sh
check_api "crt.sh" \
  "https://crt.sh/?q=${TEST_DOMAIN}&output=json"

# 7. NVD API
check_api "NVD" \
  "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1"

# 8. FIRST EPSS
check_api "EPSS" \
  "https://api.first.org/data/v1/epss?cve=CVE-2024-0001"

# 9. ContrastAPI itself
check_api "ContrastAPI" \
  "http://localhost:8002/v1/status"

# 10. ContrastScan
check_api "ContrastScan" \
  "http://localhost:8001/"

# Print results
echo "" | tee -a "$LOG"
for r in "${RESULTS[@]}"; do
  echo "  $r" | tee -a "$LOG"
done
echo "" | tee -a "$LOG"

# Summary
if [[ ${#FAILED[@]} -gt 0 ]]; then
  echo "FAILED — ${#FAILED[@]} API(s): ${FAILED[*]}" | tee -a "$LOG"

  # Send Telegram alert if configured
  if [[ "$TELEGRAM_ENABLED" == true ]]; then
    DATE=$(date '+%Y-%m-%d %H:%M:%S')
    FAIL_LIST=""
    for f in "${FAILED[@]}"; do
      FAIL_LIST="${FAIL_LIST}
  - $(html_escape "$f")"
    done

    MSG="<b>ContrastAPI Health Check FAILED</b>

Time: ${DATE}
Failed:${FAIL_LIST}

All results:"
    for r in "${RESULTS[@]}"; do
      MSG="${MSG}
  $(html_escape "$r")"
    done

    while IFS= read -r CID; do
      [[ -z "${CID}" || "${CID}" == \#* ]] && continue
      curl -s -X POST "https://api.telegram.org/bot${TOKEN}/sendMessage" \
        --data-urlencode "chat_id=${CID}" \
        --data-urlencode "parse_mode=HTML" \
        --data-urlencode "text=${MSG}" \
        --max-time 10 \
        -o /dev/null &
    done < "${CHAT_IDS}"
    wait
    echo "Telegram alert sent" | tee -a "$LOG"
  fi
else
  echo "ALL OK — ${#RESULTS[@]} APIs checked" | tee -a "$LOG"
fi
