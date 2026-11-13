#!/usr/bin/env bash
set -u

if [ -z "${DB_TEST:-}" ] || [ "$DB_TEST" = "contrastapi" ]; then
  echo "test-sql-lock: DB_TEST must name a test database, not contrastapi"
  exit 1
fi

cd "$(dirname "$0")/../../.." || exit 1
lock_db="${DB_TEST}_lock"
work_dir="$(mktemp -d)"
failed_count=0

cleanup() {
  exec 3>&- 2>/dev/null
  jobs -p | xargs -r kill 2>/dev/null
  wait 2>/dev/null
  dropdb --if-exists "$lock_db"
  rm -rf "$work_dir"
}
trap cleanup EXIT

run_sql() {
  psql -X -q -At -v ON_ERROR_STOP=1 -d "$lock_db" "$@"
}

wait_for() {
  local poll_count
  for poll_count in $(seq 1 100); do
    if [ "$(run_sql -c "SELECT count(*) FROM pg_stat_activity AS sa WHERE sa.application_name = '$1' AND ($2)")" = "1" ]; then
      return 0
    fi
    sleep 0.05
  done
  return 1
}

dropdb --if-exists "$lock_db"
createdb "$lock_db" || exit 1
run_sql -f sql/init.sql > /dev/null || exit 1

PURGE_DOMAIN="SELECT api.fn_domain_change_event_purge(100) AS purged_event_count"
PURGE_CVE="SELECT api.fn_cve_change_event_purge(100) AS purged_event_count"
CLEAR_A="SELECT string_agg(DISTINCT x.edit_status, ',') AS edit_status
           FROM api.fn_watchlist_clear(repeat('a', 64)) AS x"
PURGE_EXPIRED="SELECT api.fn_watchlist_purge(100) AS cleared_key_count"
READ_A="SELECT min(x.events_status) || '|' || min(x.next_cursor) || '|' || bool_and(x.has_more) || '|' || count(x.event_type)
                 || '|' || coalesce(string_agg(x.item_domain_name, ','), '')
          FROM api.fn_watchlist_events(repeat('a', 64), NULL, false, 100, 100, 600) AS x"
EXPIRE_A="UPDATE api_keys SET expires_at = now() - interval '31 days' WHERE key_hash = repeat('a', 64)"
END_STATE="SELECT format('events=%s refs=%s items=%s a=%s b=%s',
                         (SELECT count(*) FROM domain_change_event) + (SELECT count(*) FROM cve_change_event),
                         (SELECT count(*) FROM watchlist_event_ref),
                         (SELECT count(*) FROM watchlist_item),
                         (SELECT wks.last_key_event_id || ',' || wks.max_purged_key_event_id
                            FROM watchlist_key_state AS wks JOIN api_keys AS ak ON ak.id = wks.api_key_id
                           WHERE ak.key_hash = repeat('a', 64)),
                         (SELECT wks.last_key_event_id || ',' || wks.max_purged_key_event_id
                            FROM watchlist_key_state AS wks JOIN api_keys AS ak ON ak.id = wks.api_key_id
                           WHERE ak.key_hash = repeat('b', 64)))"

BLOCKER="SELECT wer.event_id FROM watchlist_event_ref AS wer JOIN api_keys AS ak ON ak.id = wer.api_key_id
          WHERE ak.key_hash = repeat('b', 64) FOR UPDATE OF wer;"

ORPHAN_REF_COUNT="SELECT count(*) FROM watchlist_event_ref AS wer
                   WHERE NOT EXISTS (SELECT 1 FROM cve_change_event AS cce WHERE cce.event_id = wer.event_id)
                     AND NOT EXISTS (SELECT 1 FROM domain_change_event AS dce WHERE dce.event_id = wer.event_id)"
UNSCANNED_A="DELETE FROM watchlist_event_ref AS wer USING api_keys AS ak
              WHERE ak.id = wer.api_key_id AND ak.key_hash = repeat('a', 64);
             UPDATE watchlist_key_state AS wks SET last_key_event_id = 0, last_cve_event_id = 1 FROM api_keys AS ak
              WHERE ak.id = wks.api_key_id AND ak.key_hash = repeat('a', 64);
             UPDATE watchlist_event_cursor AS wec SET previous_cursor = 0, delivered_cursor = 0 FROM api_keys AS ak
              WHERE ak.id = wec.api_key_id AND ak.key_hash = repeat('a', 64)"

B_FIRST_CHECK="DO \$\$ BEGIN
                 ASSERT (SELECT ak.key_hash FROM watchlist_event_ref AS wer JOIN api_keys AS ak ON ak.id = wer.api_key_id
                          ORDER BY wer.event_id LIMIT 1) = repeat('b', 64), 'b_first did not reach the fixture';
               END \$\$"
run_scenario() {
  local name="$1" is_cve="$2" setup="$3" first="$4" second="$5"
  local first_answer="$6" second_answer="$7" end_state="$8"
  local out="$work_dir/$name" problem="" first_pid second_pid first_status second_status found

  echo "== $name"
  run_sql -v is_cve="$is_cve" ${FIXTURE_VARS:-} -f "${LOCK_FIXTURE:-sql/tests/lock/fixture.sql}" > "$out.fixture" 2>&1 || problem="$problem fixture failed;"
  if [ -n "$setup" ]; then
    run_sql -c "$setup" >> "$out.fixture" 2>&1 || problem="$problem setup failed;"
  fi

  rm -f "$out.fifo"
  mkfifo "$out.fifo"
  PGAPPNAME=lock_blocker timeout 60 psql -X -q -At -v ON_ERROR_STOP=1 -d "$lock_db" < "$out.fifo" > "$out.blocker" 2>&1 &
  exec 3> "$out.fifo"
  echo "BEGIN;" >&3
  echo "${LOCK_BLOCKER:-$BLOCKER}" >&3
  wait_for lock_blocker "sa.state = 'idle in transaction' AND sa.query NOT LIKE 'BEGIN%'" || problem="$problem the blocker never held its rows;"

  PGAPPNAME=lock_first timeout 60 psql -X -q -At -v ON_ERROR_STOP=1 -d "$lock_db" -c "$first" > "$out.first" 2>&1 &
  first_pid=$!
  wait_for lock_first "cardinality(pg_blocking_pids(sa.pid)) > 0" || problem="$problem the first session never waited;"
  PGAPPNAME=lock_second timeout 60 psql -X -q -At -v ON_ERROR_STOP=1 -d "$lock_db" -c "$second" > "$out.second" 2>&1 &
  second_pid=$!
  wait_for lock_second "cardinality(pg_blocking_pids(sa.pid)) > 0" || problem="$problem the second session never waited;"

  echo "COMMIT;" >&3
  exec 3>&-
  wait "$first_pid"; first_status=$?
  wait "$second_pid"; second_status=$?
  wait

  [ "$first_status" = "0" ] || problem="$problem the first session exited $first_status;"
  [ "$second_status" = "0" ] || problem="$problem the second session exited $second_status;"
  if grep -q "deadlock detected" "$out.blocker" "$out.first" "$out.second"; then
    problem="$problem deadlock detected;"
  fi
  [ "$(cat "$out.first")" = "$first_answer" ] || problem="$problem the first session answered '$(cat "$out.first")', not '$first_answer';"
  [ "$(cat "$out.second")" = "$second_answer" ] || problem="$problem the second session answered '$(cat "$out.second")', not '$second_answer';"
  found="$(run_sql -c "${LOCK_END_STATE:-$END_STATE}" 2>&1)"
  [ "$found" = "$end_state" ] || problem="$problem the end state is '$found', not '$end_state';"

  if [ -n "$problem" ]; then
    failed_count=$((failed_count + 1))
    echo "FAIL $name:$problem"
    for part in first second blocker; do
      echo "-- $part:"
      cat "$out.$part"
    done
  else
    echo "PASS $name"
  fi
}

run_held_scenario() {
  local name="$1" is_cve="$2" setup="$3" holder="$4" waiter="$5"
  local holder_answer="$6" waiter_answer="$7" end_state="$8"
  local out="$work_dir/$name" problem="" waiter_pid waiter_status found orphan_ref_count

  echo "== $name"
  run_sql -v is_cve="$is_cve" ${FIXTURE_VARS:-} -f "${LOCK_FIXTURE:-sql/tests/lock/fixture.sql}" > "$out.fixture" 2>&1 || problem="$problem fixture failed;"
  if [ -n "$setup" ]; then
    run_sql -c "$setup" >> "$out.fixture" 2>&1 || problem="$problem setup failed;"
  fi

  rm -f "$out.fifo"
  mkfifo "$out.fifo"
  PGAPPNAME=lock_holder timeout 60 psql -X -q -At -v ON_ERROR_STOP=1 -d "$lock_db" < "$out.fifo" > "$out.holder" 2>&1 &
  exec 3> "$out.fifo"
  echo "BEGIN;" >&3
  echo "$holder;" >&3
  wait_for lock_holder "sa.state = 'idle in transaction' AND sa.query NOT LIKE 'BEGIN%'" \
    || problem="$problem the holder never answered in its open transaction;"

  PGAPPNAME=lock_waiter timeout 60 psql -X -q -At -v ON_ERROR_STOP=1 -d "$lock_db" -c "$waiter" > "$out.waiter" 2>&1 &
  waiter_pid=$!
  wait_for lock_waiter "cardinality(pg_blocking_pids(sa.pid)) > 0" || problem="$problem the waiter never waited for the holder;"

  echo "COMMIT;" >&3
  exec 3>&-
  wait "$waiter_pid"; waiter_status=$?
  wait

  [ "$waiter_status" = "0" ] || problem="$problem the waiter exited $waiter_status;"
  if grep -q "deadlock detected" "$out.holder" "$out.waiter"; then
    problem="$problem deadlock detected;"
  fi
  [ "$(cat "$out.holder")" = "$holder_answer" ] || problem="$problem the holder answered '$(cat "$out.holder")', not '$holder_answer';"
  [ "$(cat "$out.waiter")" = "$waiter_answer" ] || problem="$problem the waiter answered '$(cat "$out.waiter")', not '$waiter_answer';"
  found="$(run_sql -c "${LOCK_END_STATE:-$END_STATE}" 2>&1)"
  [ "$found" = "$end_state" ] || problem="$problem the end state is '$found', not '$end_state';"
  orphan_ref_count="$(run_sql -c "$ORPHAN_REF_COUNT" 2>&1)"
  [ "$orphan_ref_count" = "0" ] || problem="$problem $orphan_ref_count ref(s) point to an event that is gone;"

  if [ -n "$problem" ]; then
    failed_count=$((failed_count + 1))
    echo "FAIL $name:$problem"
    for part in holder waiter; do
      echo "-- $part:"
      cat "$out.$part"
    done
  else
    echo "PASS $name"
  fi
}

run_unblocked_scenario() {
  local name="$1" holder="$2" other="$3" holder_answer="$4" other_answer="$5" end_state="$6"
  local out="$work_dir/$name" problem="" other_status found

  echo "== $name"
  run_sql -v is_cve=false -f "$LOCK_FIXTURE" > "$out.fixture" 2>&1 || problem="$problem fixture failed;"

  rm -f "$out.fifo"
  mkfifo "$out.fifo"
  PGAPPNAME=lock_holder timeout 60 psql -X -q -At -v ON_ERROR_STOP=1 -d "$lock_db" < "$out.fifo" > "$out.holder" 2>&1 &
  exec 3> "$out.fifo"
  echo "BEGIN;" >&3
  echo "$holder;" >&3
  wait_for lock_holder "sa.state = 'idle in transaction' AND sa.query NOT LIKE 'BEGIN%'" \
    || problem="$problem the holder never answered in its open transaction;"

  PGAPPNAME=lock_other timeout 10 psql -X -q -At -v ON_ERROR_STOP=1 -d "$lock_db" -c "$other" > "$out.other" 2>&1
  other_status=$?
  echo "COMMIT;" >&3
  exec 3>&-
  wait

  [ "$other_status" = "0" ] || problem="$problem the other session exited $other_status, so it waited or failed;"
  [ "$(cat "$out.holder")" = "$holder_answer" ] || problem="$problem the holder answered '$(cat "$out.holder")', not '$holder_answer';"
  [ "$(cat "$out.other")" = "$other_answer" ] || problem="$problem the other session answered '$(cat "$out.other")', not '$other_answer';"
  found="$(run_sql -c "$LOCK_END_STATE" 2>&1)"
  [ "$found" = "$end_state" ] || problem="$problem the end state is '$found', not '$end_state';"

  if [ -n "$problem" ]; then
    failed_count=$((failed_count + 1))
    echo "FAIL $name:$problem"
    for part in holder other; do
      echo "-- $part:"
      cat "$out.$part"
    done
  else
    echo "PASS $name"
  fi
}

run_scenario s1_domain_purge_vs_clear false "" "$PURGE_DOMAIN" "$CLEAR_A" \
  "4" "ok" "events=1 refs=0 items=1 a=3,3 b=1,1"
FIXTURE_VARS="-v a_pending=1" run_scenario s1p_domain_purge_of_waiting_refs_vs_clear false "" "$PURGE_DOMAIN" "$CLEAR_A" \
  "4" "ok" "events=1 refs=0 items=1 a=0,0 b=1,1"
FIXTURE_VARS="-v b_first=1" run_scenario s1b_domain_purge_first_event_of_b_vs_clear false "$B_FIRST_CHECK" "$PURGE_DOMAIN" "$CLEAR_A" \
  "4" "ok" "events=1 refs=0 items=1 a=3,3 b=1,1"
run_scenario s2_cve_purge_vs_clear true "" "$PURGE_CVE" "$CLEAR_A" \
  "4" "ok" "events=1 refs=0 items=1 a=4,4 b=1,1"
FIXTURE_VARS="-v b_first=1" run_scenario s2b_cve_purge_first_event_of_b_vs_clear true "$B_FIRST_CHECK" "$PURGE_CVE" "$CLEAR_A" \
  "4" "ok" "events=1 refs=0 items=1 a=4,4 b=1,1"
FIXTURE_VARS="-v b_last=1" run_scenario s1l_domain_purge_last_event_of_b_vs_clear false "" "$PURGE_DOMAIN" "$CLEAR_A" \
  "4" "ok" "events=1 refs=0 items=1 a=2,2 b=2,2"
FIXTURE_VARS="-v b_last=1" run_scenario s2l_cve_purge_last_event_of_b_vs_clear true "" "$PURGE_CVE" "$CLEAR_A" \
  "4" "ok" "events=1 refs=0 items=1 a=3,3 b=2,2"
run_scenario s3_domain_purge_vs_expired_purge false "$EXPIRE_A" "$PURGE_DOMAIN" "$PURGE_EXPIRED" \
  "4" "1" "events=1 refs=0 items=1 a=3,3 b=1,1"
run_scenario s4_domain_purge_vs_read false "" "$PURGE_DOMAIN" "$READ_A" \
  "4" "ok|4|false|1|x.example.com" "events=1 refs=1 items=3 a=4,3 b=1,1"

run_held_scenario s5a_read_vs_cve_purge true "$UNSCANNED_A" "$READ_A" "$PURGE_CVE" \
  "ok|3|false|3|" "4" "events=1 refs=1 items=3 a=3,2 b=1,1"
run_held_scenario s5b_cve_purge_vs_read true "$UNSCANNED_A" "$PURGE_CVE" "$READ_A" \
  "4" "ok|1|false|1|" "events=1 refs=1 items=3 a=1,0 b=1,1"

ADD_A_P1_P2="SELECT min(x.edit_status) || '|' || min(x.added_count) || ',' || min(x.removed_count) || ',' || min(x.unchanged_count)
               FROM api.fn_watchlist_package_list_edit(repeat('a', 64), 'add', ARRAY['npm', 'npm'], ARRAY['p1', 'p2'],
                                                       ARRAY[NULL, NULL]::text[], 500, 100, 100000, 20) AS x"
ADD_A_P2_P3="SELECT min(x.edit_status) || '|' || min(x.added_count) || ',' || min(x.removed_count) || ',' || min(x.unchanged_count)
               FROM api.fn_watchlist_package_list_edit(repeat('a', 64), 'add', ARRAY['npm', 'npm'], ARRAY['p2', 'p3'],
                                                       ARRAY[NULL, NULL]::text[], 500, 100, 100000, 20) AS x"
PACKAGES_A="SELECT coalesce(string_agg(wip.package_name, ',' ORDER BY wip.package_name), '')
              FROM watchlist_item_package AS wip JOIN api_keys AS ak ON ak.id = wip.api_key_id
             WHERE ak.key_hash = repeat('a', 64)"
LOCK_END_STATE="$PACKAGES_A" run_held_scenario s6_package_add_vs_add false "" "$ADD_A_P1_P2" "$ADD_A_P2_P3" \
  "ok|2,0,0" "ok|1,0,1" "p1,p2,p3"
run_scenario s7_domain_purge_vs_package_add false "" "$PURGE_DOMAIN" "$ADD_A_P1_P2" \
  "4" "ok|2,0,0" "events=1 refs=1 items=5 a=3,3 b=1,1"

BILLING_FIXTURE="sql/tests/lock/billing_fixture.sql"
BILLING_BLOCKER="SELECT ak.id FROM api_keys AS ak WHERE ak.key_hash = repeat('c', 64) FOR UPDATE;"
BILLING_END_STATE="SELECT format('order=%s new_uuid=%s key_active=%s key=%s', bo.status, bo.order_id <> 'c0000000-0000-4000-8000-000000005001',
                                 ak.active, CASE ak.key_hash WHEN repeat('c', 64) THEN 'c' WHEN repeat('d', 64) THEN 'd' ELSE 'random' END)
                     FROM billing_orders AS bo JOIN api_keys AS ak ON ak.id = bo.api_key_id
                    WHERE bo.provider = 'lemonsqueezy' AND bo.provider_order_ref = '5001'"
CLAIM_5001="SELECT api.fn_billing_claim('c0000000-0000-4000-8000-000000005001', repeat('d', 64)) AS billing_claim_status"
REGENERATE_5001="SELECT r.regenerate_status FROM api.fn_billing_regenerate_key('lemonsqueezy', '5001') AS r"
REFUND_5001="SELECT api.fn_billing_lemonsqueezy_revoke('e0000000-0000-4000-8000-000000005001', 'order_refunded', '5001') AS billing_event_status"
LOCK_FIXTURE="$BILLING_FIXTURE" LOCK_BLOCKER="$BILLING_BLOCKER" LOCK_END_STATE="$BILLING_END_STATE" \
  run_scenario b1_claim_vs_regenerate false "" "$CLAIM_5001" "$REGENERATE_5001" \
  "claimed" "regenerating" "order=regenerating new_uuid=t key_active=t key=random"
LOCK_FIXTURE="$BILLING_FIXTURE" LOCK_BLOCKER="$BILLING_BLOCKER" LOCK_END_STATE="$BILLING_END_STATE" \
  run_scenario b2_regenerate_vs_claim false "" "$REGENERATE_5001" "$CLAIM_5001" \
  "regenerating" "unknown" "order=regenerating new_uuid=t key_active=t key=random"
LOCK_FIXTURE="$BILLING_FIXTURE" LOCK_BLOCKER="$BILLING_BLOCKER" LOCK_END_STATE="$BILLING_END_STATE" \
  run_scenario b3_claim_vs_refund false "" "$CLAIM_5001" "$REFUND_5001" \
  "claimed" "applied" "order=revoked new_uuid=f key_active=f key=d"
LOCK_FIXTURE="$BILLING_FIXTURE" LOCK_BLOCKER="$BILLING_BLOCKER" LOCK_END_STATE="$BILLING_END_STATE" \
  run_scenario b4_refund_vs_claim false "" "$REFUND_5001" "$CLAIM_5001" \
  "applied" "revoked" "order=revoked new_uuid=f key_active=f key=c"

BILLING_RACE_END_STATE="SELECT coalesce(string_agg(bo.provider_order_ref || '=' || bo.status, ',' ORDER BY bo.provider_order_ref), 'none')
                          FROM billing_orders AS bo WHERE bo.provider_order_ref <> '5001'"
REFUND_5002="SELECT api.fn_billing_lemonsqueezy_revoke('e0000000-0000-4000-8000-000000005002', 'order_refunded', '5002') AS billing_event_status"
PAID_5002="SELECT api.fn_billing_lemonsqueezy_order_paid('e0000000-0000-4000-8000-000000006002', 'c0000000-0000-4000-8000-000000005002', '5002')
             AS billing_event_status"
PAID_5003="SELECT api.fn_billing_lemonsqueezy_order_paid('e0000000-0000-4000-8000-000000006003', 'c0000000-0000-4000-8000-000000005003', '5003')
             AS billing_event_status"
LOCK_FIXTURE="$BILLING_FIXTURE" LOCK_END_STATE="$BILLING_RACE_END_STATE" \
  run_held_scenario b5_refund_vs_order_paid false "" "$REFUND_5002" "$PAID_5002" "unknown" "applied" "5002=revoked"
LOCK_FIXTURE="$BILLING_FIXTURE" LOCK_END_STATE="$BILLING_RACE_END_STATE" \
  run_held_scenario b6_order_paid_vs_refund false "" "$PAID_5002" "$REFUND_5002" "applied" "applied" "5002=revoked"
LOCK_FIXTURE="$BILLING_FIXTURE" LOCK_END_STATE="$BILLING_RACE_END_STATE" \
  run_unblocked_scenario b7_order_paid_of_another_ref "$PAID_5002" "$PAID_5003" "applied" "applied" "5002=paid,5003=paid"

DELETE_5001="SELECT api.fn_billing_delete_key('lemonsqueezy', '5001') AS billing_delete_status"
BILLING_DELETE_END_STATE="SELECT format('order=%s key=%s keys=%s', bo.status, bo.api_key_id IS NOT NULL, (SELECT count(*) FROM api_keys))
                            FROM billing_orders AS bo WHERE bo.provider = 'lemonsqueezy' AND bo.provider_order_ref = '5001'"
LOCK_FIXTURE="$BILLING_FIXTURE" LOCK_END_STATE="$BILLING_DELETE_END_STATE" \
  run_held_scenario b8_delete_vs_refund false "" "$DELETE_5001" "$REFUND_5001" "deleted" "revoked" "order=revoked key=f keys=0"
LOCK_FIXTURE="$BILLING_FIXTURE" LOCK_END_STATE="$BILLING_DELETE_END_STATE" \
  run_held_scenario b9_refund_vs_delete false "" "$REFUND_5001" "$DELETE_5001" "applied" "deleted" "order=revoked key=f keys=0"
LOCK_FIXTURE="$BILLING_FIXTURE" LOCK_END_STATE="$BILLING_DELETE_END_STATE" \
  run_held_scenario b10_claim_vs_delete false "" "$CLAIM_5001" "$DELETE_5001" "claimed" "deleted" "order=revoked key=f keys=0"
LOCK_FIXTURE="$BILLING_FIXTURE" LOCK_END_STATE="$BILLING_DELETE_END_STATE" \
  run_held_scenario b11_delete_vs_claim false "" "$DELETE_5001" "$CLAIM_5001" "deleted" "revoked" "order=revoked key=f keys=0"
DELETE_5002="SELECT api.fn_billing_delete_key('lemonsqueezy', '5002') AS billing_delete_status"
CLAIM_5002="SELECT api.fn_billing_claim('c0000000-0000-4000-8000-000000005002', repeat('e', 64)) AS billing_claim_status"
BILLING_NEW_KEY_END_STATE="SELECT format('5002=%s keys=%s', bo.status, (SELECT count(*) FROM api_keys))
                             FROM billing_orders AS bo WHERE bo.provider_order_ref = '5002'"
LOCK_FIXTURE="$BILLING_FIXTURE" LOCK_END_STATE="$BILLING_NEW_KEY_END_STATE" \
  run_held_scenario b12_claim_of_paid_vs_delete false "$PAID_5002" "$CLAIM_5002" "$DELETE_5002" "claimed" "deleted" "5002=revoked keys=1"
LOCK_FIXTURE="$BILLING_FIXTURE" LOCK_END_STATE="$BILLING_RACE_END_STATE" \
  run_held_scenario b13_order_paid_vs_delete false "" "$PAID_5002" "$DELETE_5002" "applied" "no_key" "5002=paid"
LOCK_FIXTURE="$BILLING_FIXTURE" LOCK_BLOCKER="$BILLING_BLOCKER" LOCK_END_STATE="$BILLING_DELETE_END_STATE" \
  run_scenario b14_claim_vs_delete_behind_blocker false "" "$CLAIM_5001" "$DELETE_5001" "claimed" "deleted" "order=revoked key=f keys=0"

X402_FIXTURE="sql/tests/lock/x402_fixture.sql"
X402_END_STATE="SELECT coalesce(string_agg(left(xp.message_hash, 1) || '=' || xp.status, ',' ORDER BY xp.message_hash), 'none')
                  FROM x402_payment AS xp"
RESERVE_A_E="SELECT r.reserve_answer FROM api.fn_x402_payment_reserve(repeat('a', 64), repeat('e', 64)) AS r"
RESERVE_B_E="SELECT r.reserve_answer FROM api.fn_x402_payment_reserve(repeat('b', 64), repeat('e', 64)) AS r"
RESERVE_B_F="SELECT r.reserve_answer FROM api.fn_x402_payment_reserve(repeat('b', 64), repeat('f', 64)) AS r"
OLD_RESERVED_A_E="INSERT INTO x402_payment (message_hash, source_hash, status, reserved_at)
                  VALUES (repeat('a', 64), repeat('e', 64), 'reserved', now() - interval '200 seconds')"
RELEASE_A="SELECT api.fn_x402_payment_release(repeat('a', 64))"
LOCK_FIXTURE="$X402_FIXTURE" LOCK_END_STATE="$X402_END_STATE" \
  run_held_scenario x1_reserve_vs_reserve_of_one_message false "" "$RESERVE_A_E" "$RESERVE_A_E" "reserved" "in_flight" "a=reserved"
LOCK_FIXTURE="$X402_FIXTURE" LOCK_END_STATE="$X402_END_STATE" \
  run_held_scenario x2_reserve_vs_reserve_of_one_source false "" "$RESERVE_A_E" "$RESERVE_B_E" "reserved" "source_busy" "a=reserved"
LOCK_FIXTURE="$X402_FIXTURE" LOCK_END_STATE="$X402_END_STATE" \
  run_unblocked_scenario x3_reserve_of_another_source "$RESERVE_A_E" "$RESERVE_B_F" "reserved" "reserved" "a=reserved,b=reserved"
LOCK_FIXTURE="$X402_FIXTURE" LOCK_END_STATE="$X402_END_STATE" \
  run_held_scenario x4_release_vs_reserve_of_one_message false "$OLD_RESERVED_A_E" "$RELEASE_A" "$RESERVE_A_E" "t" "reserved" "a=reserved"


if [ "$failed_count" -gt 0 ]; then
  echo "test-sql-lock: $failed_count scenario(s) failed"
  exit 1
fi
echo "test-sql-lock: every scenario passed"
