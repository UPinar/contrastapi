#!/bin/bash
set -u
# CVE/EPSS/KEV sync wrapper with Telegram fail alert
# Cron: 0 */2 * * * /opt/contrastapi/scripts/cve_sync.sh

LOGFILE="/var/log/contrastapi/cve_sync.log"
TELEGRAM_TOKEN_FILE="/etc/telegram-bot/token"
TELEGRAM_CHAT_FILE="/etc/telegram-bot/chat_ids"

html_escape() {
  local s="$1"
  s="${s//&/&amp;}"
  s="${s//</&lt;}"
  s="${s//>/&gt;}"
  echo "$s"
}

send_telegram() {
  local message="$1"
  [ ! -f "$TELEGRAM_TOKEN_FILE" ] || [ ! -f "$TELEGRAM_CHAT_FILE" ] && return
  local token
  token=$(cat "$TELEGRAM_TOKEN_FILE")
  while IFS= read -r cid; do
    [ -z "$cid" ] || [ "${cid:0:1}" = "#" ] && continue
    curl -s -X POST "https://api.telegram.org/bot${token}/sendMessage" \
      --data-urlencode "chat_id=$cid" \
      --data-urlencode "parse_mode=HTML" \
      --data-urlencode "text=$message" \
      --max-time 10 >/dev/null 2>&1
  done < "$TELEGRAM_CHAT_FILE"
}

mkdir -p "$(dirname "$LOGFILE")"
cd /opt/contrastapi/app || exit 1

output=$(timeout 1800 /opt/contrastapi/venv/bin/python -m cve.sync 2>&1)
status=$?

echo "$(date -u '+%Y-%m-%d %H:%M:%S') --- sync run (exit: ${status}) ---" >> "$LOGFILE"
echo "$output" >> "$LOGFILE"

if [ $status -ne 0 ]; then
  escaped_output=$(html_escape "$(echo "$output" | tail -5)")
  send_telegram "<b>🚨 CVE Sync FAILED</b>
Exit code: ${status}
$(date -u '+%Y-%m-%d %H:%M UTC')

<pre>${escaped_output}</pre>"
fi
