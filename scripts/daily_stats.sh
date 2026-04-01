#!/bin/bash
# ContrastAPI Daily Stats — query api.db + domain_cache.db, send to Telegram
# Cron: 0 8 * * * /opt/contrastapi/scripts/daily_stats.sh

set -euo pipefail

API_DB="/var/lib/contrastapi/api.db"
CACHE_DB="/var/lib/contrastapi/domain_cache.db"
CUTOFF=$(date -u -d '24 hours ago' '+%Y-%m-%dT%H:%M:%S')

# --- Telegram setup ---
TELEGRAM_ENABLED=false
if [[ -f /etc/telegram-bot/token && -f /etc/telegram-bot/chat_ids ]]; then
  TOKEN=$(cat /etc/telegram-bot/token)
  CHAT_IDS="/etc/telegram-bot/chat_ids"
  TELEGRAM_ENABLED=true
fi

# --- Queries against api.db ---
UNIQUE_IPS=$(sqlite3 "$API_DB" \
  "SELECT COUNT(DISTINCT client_ip) FROM api_usage WHERE called_at >= '$CUTOFF';")

TOTAL_REQS=$(sqlite3 "$API_DB" \
  "SELECT COUNT(*) FROM api_usage WHERE called_at >= '$CUTOFF';")

TOP_IPS=$(sqlite3 -separator ' ' "$API_DB" \
  "SELECT client_ip, COUNT(*) AS cnt FROM api_usage
   WHERE called_at >= '$CUTOFF'
   GROUP BY client_ip ORDER BY cnt DESC LIMIT 5;")

TOP_ENDPOINTS=$(sqlite3 -separator ' ' "$API_DB" \
  "SELECT endpoint, COUNT(*) AS cnt FROM api_usage
   WHERE called_at >= '$CUTOFF'
   GROUP BY endpoint ORDER BY cnt DESC LIMIT 10;")

# --- Cache hit/miss from domain_cache.db ---
# Entries written in last 24h = API calls made (cache miss that resulted in a save)
GN_TOTAL=$(sqlite3 "$CACHE_DB" \
  "SELECT COUNT(*) FROM domain_cache WHERE domain LIKE 'greynoise:%';")
GN_NEW=$(sqlite3 "$CACHE_DB" \
  "SELECT COUNT(*) FROM domain_cache
   WHERE domain LIKE 'greynoise:%' AND fetched_at >= '$CUTOFF';")

SH_TOTAL=$(sqlite3 "$CACHE_DB" \
  "SELECT COUNT(*) FROM domain_cache WHERE domain LIKE 'shodan:%';")
SH_NEW=$(sqlite3 "$CACHE_DB" \
  "SELECT COUNT(*) FROM domain_cache
   WHERE domain LIKE 'shodan:%' AND fetched_at >= '$CUTOFF';")

AB_CALLS=$(sqlite3 "$API_DB" \
  "SELECT COUNT(*) FROM api_usage
   WHERE called_at >= '$CUTOFF' AND endpoint LIKE '%ip%';")

# --- Build message ---
MSG="<b>ContrastAPI Daily Stats</b>
<b>Period:</b> $(date -u -d '24 hours ago' '+%Y-%m-%d %H:%M') — $(date -u '+%Y-%m-%d %H:%M') UTC

<b>Users:</b> ${UNIQUE_IPS} unique IPs
<b>Requests:</b> ${TOTAL_REQS} total
"

# Top endpoints
MSG+="
<b>Top Endpoints:</b>"
while IFS=' ' read -r ep cnt; do
  [[ -z "$ep" ]] && continue
  MSG+="
  ${ep} (${cnt})"
done <<< "$TOP_ENDPOINTS"

# Top users
MSG+="

<b>Top Users:</b>"
while IFS=' ' read -r ip cnt; do
  [[ -z "$ip" ]] && continue
  MSG+="
  ${ip} (${cnt})"
done <<< "$TOP_IPS"

# Cache / API quota
MSG+="

<b>API Quota (24h new lookups):</b>
  GreyNoise: ${GN_NEW}/50 (${GN_TOTAL} cached)
  Shodan: ${SH_NEW}/100 (${SH_TOTAL} cached)
  AbuseIPDB: ~${AB_CALLS} (1000/day)"

# --- Send ---
echo "$MSG"

if [[ "$TELEGRAM_ENABLED" == true ]]; then
  while IFS= read -r CID; do
    [[ -z "${CID}" || "${CID}" == \#* ]] && continue
    curl -s -X POST "https://api.telegram.org/bot${TOKEN}/sendMessage" \
      -d chat_id="${CID}" \
      -d parse_mode="HTML" \
      --data-urlencode "text=${MSG}" \
      --max-time 10 \
      -o /dev/null &
  done < "${CHAT_IDS}"
  wait
  echo "Telegram sent."
else
  echo "Telegram not configured, printed to stdout only."
fi
