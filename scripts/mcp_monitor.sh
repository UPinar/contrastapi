#!/bin/bash
###############################################################################
# mcp_monitor.sh — MCP endpoint health monitor + Telegram alerts
#
# Checks (last 5 min window from nginx access log):
#   1. MCP errors      — 4xx/5xx responses on /mcp (excludes 429)
#   2. Rate limit hits  — 429 responses (users hitting free tier limit)
#   3. Slow responses   — MCP requests taking >10s (upstream_response_time)
#   4. New MCP users    — first-time IPs using /mcp (daily, sends summary)
#   5. MCP health       — POST /mcp/ returns 200 within 5s
#
# Behavior:
#   - Silent when everything is OK (cron-friendly)
#   - Sends Telegram alert only when problems detected
#   - New user summary: appended to daily stats, not a separate alert
#
# Deploy: scp /tmp/mcp_monitor.sh local:/opt/contrastapi/scripts/mcp_monitor.sh
# Cron:   */5 * * * * bash /opt/contrastapi/scripts/mcp_monitor.sh
# Manual: bash /opt/contrastapi/scripts/mcp_monitor.sh --verbose
###############################################################################

set -uo pipefail

# === Config ===
NGINX_LOG="/var/log/nginx/access.log"
MCP_USERS_FILE="/var/lib/contrastapi/mcp_known_ips.txt"
TELEGRAM_TOKEN_FILE="/etc/telegram-bot/token"
TELEGRAM_CHAT_FILE="/etc/telegram-bot/chat_ids"

# === Thresholds ===
MAX_ERRORS=3             # error count in 5 min before alerting
MAX_429=10               # rate limit hits in 5 min before alerting
MAX_RESPONSE_TIME=5      # seconds — MCP health check timeout

# === State ===
VERBOSE=0
[[ "${1:-}" == "--verbose" ]] && VERBOSE=1

ALERTS=()
METRICS=()

alert() { ALERTS+=("$1"); }
metric() { METRICS+=("$1"); }
log() { [[ "$VERBOSE" -eq 1 ]] && echo "$1"; }

###############################################################################
# Get recent MCP log lines (last 5 min)
###############################################################################
get_mcp_lines() {
  [[ ! -f "$NGINX_LOG" ]] && return

  # Build grep pattern matching all minute prefixes in the last 5 min window
  # This handles minute boundaries correctly (e.g., 01:28|01:29|01:30|01:31|01:32)
  local pattern=""
  for i in 0 1 2 3 4 5; do
    local ts
    ts=$(date -u -d "$i minutes ago" '+%d/%b/%Y:%H:%M' 2>/dev/null)
    [[ -z "$ts" ]] && continue
    [[ -n "$pattern" ]] && pattern+="|"
    pattern+="$ts"
  done
  [[ -z "$pattern" ]] && return

  grep -E "($pattern)" "$NGINX_LOG" 2>/dev/null \
    | grep ' /mcp' \
    | tail -5000
}

###############################################################################
# CHECK 1: MCP Errors (4xx except 429, 5xx)
###############################################################################
check_mcp_errors() {
  local lines="$1"
  [[ -z "$lines" ]] && { log "  No MCP requests in window"; return; }

  local total=0 errors=0 error_details=""
  while IFS= read -r line; do
    local status
    status=$(echo "$line" | grep -oP '" \K[0-9]{3}' | head -1)
    [[ -z "$status" ]] && continue
    total=$((total + 1))

    if [[ "$status" =~ ^5 ]]; then
      errors=$((errors + 1))
      error_details+="  ${status} "
    elif [[ "$status" =~ ^4 && "$status" != "429" ]]; then
      errors=$((errors + 1))
      error_details+="  ${status} "
    fi
  done <<< "$lines"

  metric "MCP requests: $total, errors: $errors"

  if [[ "$errors" -ge "$MAX_ERRORS" ]]; then
    # Get unique error codes
    local codes
    codes=$(echo "$error_details" | tr ' ' '\n' | sort | uniq -c | sort -rn | head -5 \
      | awk '{printf "%sx%s ", $1, $2}')
    alert "MCP errors: ${errors}/${total} in 5 min ($codes)"
  fi
  log "  MCP: $total requests, $errors errors"
}

###############################################################################
# CHECK 2: Rate Limit Hits (429)
###############################################################################
check_mcp_ratelimit() {
  local lines="$1"
  [[ -z "$lines" ]] && return

  local count=0
  while IFS= read -r line; do
    local status
    status=$(echo "$line" | grep -oP '" \K[0-9]{3}' | head -1)
    if [[ "$status" == "429" ]]; then
      count=$((count + 1))
    fi
  done <<< "$lines"

  metric "MCP 429s: $count"

  if [[ "$count" -ge "$MAX_429" ]]; then
    alert "MCP rate limit: ${count} hits in 5 min"
  fi
  log "  MCP 429s: $count"
}

###############################################################################
# CHECK 3: Slow MCP Responses (>10s)
# Parses upstream_response_time from nginx log if available
###############################################################################
check_mcp_slow() {
  local lines="$1"
  [[ -z "$lines" ]] && return

  # Look for response times in the log — format varies by nginx config
  # Common: "POST /mcp/ HTTP/1.1" 200 1234 ... 0.058
  local slow=0
  while IFS= read -r line; do
    # Try to extract response time (last numeric field before potential cache status)
    local resp_time
    resp_time=$(echo "$line" | grep -oP '[0-9]+\.[0-9]+$' | head -1)
    [[ -z "$resp_time" ]] && continue
    local int_part=${resp_time%%.*}
    if [[ "$int_part" -ge 10 ]]; then
      slow=$((slow + 1))
    fi
  done <<< "$lines"

  metric "MCP slow (>10s): $slow"

  if [[ "$slow" -gt 0 ]]; then
    alert "MCP slow responses: $slow requests >10s in 5 min"
  fi
  log "  MCP slow: $slow"
}

###############################################################################
# CHECK 4: New MCP Users (first-time IPs)
# Tracks known MCP users in a file. New IPs trigger an info notification.
###############################################################################
check_mcp_new_users() {
  local lines="$1"
  [[ -z "$lines" ]] && return

  # Ensure tracking file exists
  touch "$MCP_USERS_FILE" 2>/dev/null

  local seen_ips
  seen_ips=$(cat "$MCP_USERS_FILE" 2>/dev/null)

  # Get unique IPs from MCP requests
  local current_ips new_count=0
  current_ips=$(echo "$lines" | awk '{print $1}' | sort -u)

  while IFS= read -r ip; do
    [[ -z "$ip" ]] && continue
    if ! echo "$seen_ips" | grep -qF "$ip"; then
      new_count=$((new_count + 1))
      echo "$ip" >> "$MCP_USERS_FILE"
    fi
  done <<< "$current_ips"

  local total_known
  total_known=$(wc -l < "$MCP_USERS_FILE" 2>/dev/null || echo 0)
  metric "MCP users: $total_known total, $new_count new"

  if [[ "$new_count" -gt 0 ]]; then
    alert "New MCP user(s): $new_count (total: $total_known)"
  fi
  log "  MCP users: $total_known total, $new_count new"
}

###############################################################################
# CHECK 5: MCP Health — can we initialize?
###############################################################################
check_mcp_health() {
  local result
  result=$(curl -s -o /dev/null -w "%{http_code} %{time_total}" \
    --max-time "$MAX_RESPONSE_TIME" \
    -X POST http://127.0.0.1:8002/mcp/ \
    -H "Content-Type: application/json" \
    -H "Accept: application/json, text/event-stream" \
    -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"healthcheck","version":"1.0"}}}' \
    2>/dev/null)

  local code time_s
  code=$(echo "$result" | awk '{print $1}')
  time_s=$(echo "$result" | awk '{print $2}')

  metric "MCP health: HTTP $code, ${time_s}s"

  if [[ "$code" != "200" ]]; then
    alert "MCP endpoint DOWN: HTTP $code"
  fi

  local time_int=${time_s%%.*}
  if [[ "$time_int" -ge "$MAX_RESPONSE_TIME" ]]; then
    alert "MCP slow: initialize took ${time_s}s"
  fi

  log "  MCP health: HTTP $code (${time_s}s)"
}

###############################################################################
# Telegram
###############################################################################
send_telegram() {
  local message="$1"
  [[ ! -f "$TELEGRAM_TOKEN_FILE" ]] && return
  [[ ! -f "$TELEGRAM_CHAT_FILE" ]] && return

  local token
  token=$(cat "$TELEGRAM_TOKEN_FILE")

  while IFS= read -r chat_id; do
    [[ -z "$chat_id" || "$chat_id" == \#* ]] && continue
    curl -s -X POST "https://api.telegram.org/bot${token}/sendMessage" \
      -d "chat_id=${chat_id}" \
      -d "parse_mode=HTML" \
      -d "text=${message}" \
      --max-time 10 >/dev/null 2>&1
  done < "$TELEGRAM_CHAT_FILE"
}

###############################################################################
# Main
###############################################################################
main() {
  # Collect MCP lines once, reuse across checks
  local mcp_lines
  mcp_lines=$(get_mcp_lines)

  check_mcp_health
  check_mcp_errors "$mcp_lines"
  check_mcp_ratelimit "$mcp_lines"
  check_mcp_slow "$mcp_lines"
  check_mcp_new_users "$mcp_lines"

  if [[ "$VERBOSE" -eq 1 ]]; then
    echo ""
    echo "=== MCP Metrics ==="
    for m in "${METRICS[@]}"; do
      echo "  $m"
    done
  fi

  if [[ ${#ALERTS[@]} -gt 0 ]]; then
    local msg="<b>MCP Monitor Alert</b>"
    msg+="%0A$(date -u '+%Y-%m-%d %H:%M UTC')"
    for a in "${ALERTS[@]}"; do
      msg+="%0A$a"
    done
    msg+="%0A%0A<b>Metrics:</b>"
    for m in "${METRICS[@]}"; do
      msg+="%0A$m"
    done

    send_telegram "$msg"

    if [[ "$VERBOSE" -eq 1 ]]; then
      echo ""
      echo "=== ALERTS ==="
      for a in "${ALERTS[@]}"; do
        echo "  $a"
      done
    fi
    exit 1
  fi

  log "All MCP checks passed"
  exit 0
}

main
