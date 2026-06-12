#!/bin/bash
###############################################################################
# test_integration.sh — end-to-end scanner validation against live domains
#
# Verifies:
#   1. JSON structure — all 7 modules present
#   2. Score ranges   — each module within [0, max]
#   3. Grade logic    — grade matches total_score
#   4. Known domains  — contrastcyber.com = 100/100 A
#   5. Field types    — booleans, numbers, strings
#
# Usage: bash tests/test_integration.sh
# Deploy: /opt/contrastcyber/scanner/tests/test_integration.sh
###############################################################################

set -uo pipefail

SCANNER="./contrastscan"
PASS=0
FAIL=0
SKIP=0

# colors
GREEN='\033[32m'
RED='\033[31m'
YELLOW='\033[33m'
NC='\033[0m'

pass() { PASS=$((PASS + 1)); echo -e "  ${GREEN}PASS${NC}  $1"; }
fail() { FAIL=$((FAIL + 1)); echo -e "  ${RED}FAIL${NC}  $1 — $2"; }
skip() { SKIP=$((SKIP + 1)); echo -e "  ${YELLOW}SKIP${NC}  $1 — $2"; }

# check dependencies
if [ ! -x "$SCANNER" ]; then
  echo "Error: scanner binary not found at $SCANNER"
  echo "Run from scanner directory: cd /path/to/scanner && bash tests/test_integration.sh"
  exit 1
fi

if ! command -v jq &>/dev/null; then
  echo "Error: jq required — apt install jq"
  exit 1
fi

# run scanner and capture output
scan_domain() {
  local domain="$1"
  local output
  output=$("$SCANNER" "$domain" 2>/dev/null) || { echo ""; return; }
  echo "$output"
}

# === STRUCTURAL TESTS ===
echo ""
echo "=== Integration Tests ==="
echo ""
echo "[structure] — JSON module validation"

RESULT=$(scan_domain "contrastcyber.com")
if [ -z "$RESULT" ]; then
  fail "contrastcyber.com scan" "scanner returned empty output"
  echo -e "\n=== Results: $PASS passed, $FAIL failed, $SKIP skipped ===\n"
  exit 1
fi

# check valid JSON
if echo "$RESULT" | jq . &>/dev/null; then
  pass "valid JSON output"
else
  fail "valid JSON output" "scanner returned invalid JSON"
  exit 1
fi

# check all 7 modules present
for module in headers ssl dns redirect disclosure cookies dnssec; do
  if echo "$RESULT" | jq -e ".$module" &>/dev/null; then
    pass "module '$module' present"
  else
    fail "module '$module' present" "missing from output"
  fi
done

# check top-level fields (findings/findings_count added by Python, not C scanner)
for field in domain grade total_score max_score; do
  if echo "$RESULT" | jq -e ".$field" &>/dev/null; then
    pass "field '$field' present"
  else
    fail "field '$field' present" "missing from output"
  fi
done

# check each module has score, max, details
echo ""
echo "[module_structure] — score/max/details in each module"

for module in headers ssl dns redirect disclosure cookies dnssec; do
  score=$(echo "$RESULT" | jq -r ".$module.score // \"missing\"")
  max=$(echo "$RESULT" | jq -r ".$module.max // \"missing\"")
  has_details=$(echo "$RESULT" | jq ".$module | has(\"details\")")

  if [ "$score" != "missing" ] && [ "$max" != "missing" ] && [ "$has_details" = "true" ]; then
    pass "$module: score=$score max=$max details=ok"
  else
    fail "$module structure" "score=$score max=$max details=$details"
  fi
done

# === SCORE RANGE TESTS ===
echo ""
echo "[score_ranges] — each module score within [0, max]"

for module in headers ssl dns redirect disclosure cookies dnssec; do
  score=$(echo "$RESULT" | jq ".$module.score")
  max=$(echo "$RESULT" | jq ".$module.max")

  if [ "$score" -ge 0 ] && [ "$score" -le "$max" ]; then
    pass "$module: $score in [0, $max]"
  else
    fail "$module score range" "$score not in [0, $max]"
  fi
done

# total score = sum of modules
total=$(echo "$RESULT" | jq ".total_score")
max_score=$(echo "$RESULT" | jq ".max_score")
computed_total=$(echo "$RESULT" | jq '[.headers.score, .ssl.score, .dns.score, .redirect.score, .disclosure.score, .cookies.score, .dnssec.score] | add')

if [ "$total" -eq "$computed_total" ]; then
  pass "total_score ($total) = sum of modules ($computed_total)"
else
  fail "total_score sum" "total=$total but sum=$computed_total"
fi

if [ "$max_score" -eq 100 ]; then
  pass "max_score = 100"
else
  fail "max_score" "expected 100, got $max_score"
fi

# === GRADE LOGIC ===
echo ""
echo "[grade_logic] — grade matches percentage"

grade=$(echo "$RESULT" | jq -r ".grade")
pct=$((total * 100 / max_score))

expected_grade="F"
if [ "$pct" -ge 90 ]; then expected_grade="A"
elif [ "$pct" -ge 75 ]; then expected_grade="B"
elif [ "$pct" -ge 60 ]; then expected_grade="C"
elif [ "$pct" -ge 40 ]; then expected_grade="D"
fi

if [ "$grade" = "$expected_grade" ]; then
  pass "grade '$grade' correct for $pct%"
else
  fail "grade logic" "expected '$expected_grade' for $pct%, got '$grade'"
fi

# === CONTRASTCYBER.COM KNOWN VALUES ===
echo ""
echo "[known_domain] — contrastcyber.com expected results"

# grade A, 100/100
if [ "$grade" = "A" ]; then
  pass "contrastcyber.com grade = A"
else
  fail "contrastcyber.com grade" "expected A, got $grade"
fi

if [ "$total" -eq 100 ]; then
  pass "contrastcyber.com score = 100/100"
else
  fail "contrastcyber.com score" "expected 100, got $total"
fi

# specific module checks
h_score=$(echo "$RESULT" | jq ".headers.score")
if [ "$h_score" -eq 30 ]; then
  pass "headers = 30/30"
else
  fail "headers" "expected 30, got $h_score"
fi

s_score=$(echo "$RESULT" | jq ".ssl.score")
if [ "$s_score" -eq 25 ]; then
  pass "ssl = 25/25"
else
  fail "ssl" "expected 25, got $s_score"
fi

d_score=$(echo "$RESULT" | jq ".dns.score")
if [ "$d_score" -eq 20 ]; then
  pass "dns = 20/20"
else
  fail "dns" "expected 20, got $d_score"
fi

r_score=$(echo "$RESULT" | jq ".redirect.score")
if [ "$r_score" -eq 10 ]; then
  pass "redirect = 10/10"
else
  fail "redirect" "expected 10, got $r_score"
fi

disc_score=$(echo "$RESULT" | jq ".disclosure.score")
if [ "$disc_score" -eq 5 ]; then
  pass "disclosure = 5/5"
else
  fail "disclosure" "expected 5, got $disc_score"
fi

cook_score=$(echo "$RESULT" | jq ".cookies.score")
if [ "$cook_score" -eq 5 ]; then
  pass "cookies = 5/5"
else
  fail "cookies" "expected 5, got $cook_score"
fi

dsec_score=$(echo "$RESULT" | jq ".dnssec.score")
if [ "$dsec_score" -eq 5 ]; then
  pass "dnssec = 5/5"
else
  fail "dnssec" "expected 5, got $dsec_score"
fi

# === DETAIL FIELD VALIDATION ===
echo ""
echo "[detail_fields] — contrastcyber.com expected detail values"

# redirect
redir=$(echo "$RESULT" | jq ".redirect.details.redirects_to_https")
if [ "$redir" = "true" ]; then
  pass "redirects_to_https = true"
else
  fail "redirects_to_https" "expected true, got $redir"
fi

# disclosure
srv_exposed=$(echo "$RESULT" | jq ".disclosure.details.server_exposed")
pb_exposed=$(echo "$RESULT" | jq ".disclosure.details.powered_by_exposed")
if [ "$pb_exposed" = "false" ]; then
  pass "powered_by_exposed = false"
else
  fail "powered_by_exposed" "expected false, got $pb_exposed"
fi

# cookies
cookie_cnt=$(echo "$RESULT" | jq ".cookies.details.cookies_found")
if [ "$cookie_cnt" -eq 0 ]; then
  pass "cookies_found = 0"
else
  fail "cookies_found" "expected 0, got $cookie_cnt"
fi

# dnssec
dnssec_on=$(echo "$RESULT" | jq ".dnssec.details.dnssec_enabled")
if [ "$dnssec_on" = "true" ]; then
  pass "dnssec_enabled = true"
else
  fail "dnssec_enabled" "expected true, got $dnssec_on"
fi

# dns records
spf=$(echo "$RESULT" | jq ".dns.details.spf")
dmarc=$(echo "$RESULT" | jq ".dns.details.dmarc")
dkim=$(echo "$RESULT" | jq ".dns.details.dkim")
if [ "$spf" = "true" ]; then pass "SPF = true"; else fail "SPF" "expected true"; fi
if [ "$dmarc" = "true" ]; then pass "DMARC = true"; else fail "DMARC" "expected true"; fi
if [ "$dkim" = "true" ]; then pass "DKIM = true"; else fail "DKIM" "expected true"; fi

# ssl details
tls_ver=$(echo "$RESULT" | jq -r ".ssl.details.tls_version")
cert_valid=$(echo "$RESULT" | jq ".ssl.details.cert_valid")
chain_valid=$(echo "$RESULT" | jq ".ssl.details.chain_valid")
if [ "$tls_ver" = "TLSv1.3" ]; then pass "TLS version = TLSv1.3"; else fail "TLS version" "expected TLSv1.3, got $tls_ver"; fi
if [ "$cert_valid" = "true" ]; then pass "cert_valid = true"; else fail "cert_valid" "expected true"; fi
if [ "$chain_valid" = "true" ]; then pass "chain_valid = true"; else fail "chain_valid" "expected true"; fi

# === DNSSEC FALSE NEGATIVE CHECK ===
echo ""
echo "[dnssec] — verify DNSSEC detection works"

# cloudflare.com has DNSSEC — test against known DNSSEC domain
DNSSEC_RESULT=$(scan_domain "cloudflare.com")
if [ -n "$DNSSEC_RESULT" ]; then
  cf_dnssec=$(echo "$DNSSEC_RESULT" | jq ".dnssec.details.dnssec_enabled")
  if [ "$cf_dnssec" = "true" ]; then
    pass "cloudflare.com DNSSEC detected"
  else
    fail "cloudflare.com DNSSEC" "expected true — possible false negative (systemd-resolved may block DNSKEY)"
  fi
else
  skip "cloudflare.com DNSSEC" "scan failed"
fi

# contrastcyber.com should also have DNSSEC now
ct_dnssec=$(echo "$RESULT" | jq ".dnssec.details.dnssec_enabled")
if [ "$ct_dnssec" = "true" ]; then
  pass "contrastcyber.com DNSSEC detected"
else
  fail "contrastcyber.com DNSSEC" "expected true — check DNS propagation"
fi

# example.com — may or may not have DNSSEC, just check it doesn't crash
NO_DNSSEC_RESULT=$(scan_domain "example.com")
if [ -n "$NO_DNSSEC_RESULT" ]; then
  ex_dnssec=$(echo "$NO_DNSSEC_RESULT" | jq ".dnssec.details.dnssec_enabled")
  if [ "$ex_dnssec" = "true" ] || [ "$ex_dnssec" = "false" ]; then
    pass "example.com DNSSEC returns valid boolean ($ex_dnssec)"
  else
    fail "example.com DNSSEC" "unexpected value: $ex_dnssec"
  fi
else
  skip "example.com DNSSEC" "scan failed"
fi

# === INVALID INPUT TESTS ===
echo ""
echo "[invalid_input] — scanner rejects bad input"

# empty domain
if ! "$SCANNER" "" 2>/dev/null; then
  pass "rejects empty domain"
else
  fail "empty domain" "should have failed"
fi

# special characters
if ! "$SCANNER" "test;id" 2>/dev/null; then
  pass "rejects special chars (semicolon)"
else
  fail "special chars" "should have rejected test;id"
fi

if ! "$SCANNER" "test'OR'1=1" 2>/dev/null; then
  pass "rejects special chars (quote)"
else
  fail "special chars" "should have rejected quote"
fi

if ! "$SCANNER" 'test$(whoami)' 2>/dev/null; then
  pass "rejects special chars (dollar)"
else
  fail "special chars" "should have rejected dollar"
fi

# too long domain
long_domain=$(python3 -c "print('a' * 254 + '.com')")
if ! "$SCANNER" "$long_domain" 2>/dev/null; then
  pass "rejects domain > 253 chars"
else
  fail "long domain" "should have rejected"
fi

# === SUMMARY ===
echo ""
TOTAL=$((PASS + FAIL + SKIP))
echo -n "=== Results: $PASS/$TOTAL passed"
if [ "$FAIL" -gt 0 ]; then
  echo -ne ", ${RED}$FAIL FAILED${NC}"
fi
if [ "$SKIP" -gt 0 ]; then
  echo -ne ", ${YELLOW}$SKIP skipped${NC}"
fi
echo " ==="
echo ""

exit $FAIL
