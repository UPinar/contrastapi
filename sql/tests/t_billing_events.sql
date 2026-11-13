CREATE OR REPLACE FUNCTION pg_temp.t_billing_hash(p_n integer) RETURNS text LANGUAGE sql AS $$
  SELECT 'b1' || lpad(to_hex(p_n), 62, '0')
$$;

CREATE OR REPLACE FUNCTION pg_temp.t_uuid(p_kind text, p_n integer) RETURNS text LANGUAGE sql AS $$
  SELECT p_kind || '0000000-0000-4000-8000-' || lpad(p_n::text, 12, '0')
$$;

CREATE OR REPLACE FUNCTION pg_temp.t_bo(p_ref text) RETURNS billing_orders LANGUAGE sql AS $$
  SELECT * FROM billing_orders AS bo WHERE bo.provider = 'lemonsqueezy' AND bo.provider_order_ref = p_ref
$$;

CREATE OR REPLACE FUNCTION pg_temp.t_be(p_ref text) RETURNS billing_events LANGUAGE sql AS $$
  SELECT * FROM billing_events AS be WHERE be.provider = 'lemonsqueezy' AND be.provider_event_ref = p_ref
$$;

CREATE OR REPLACE FUNCTION pg_temp.t_ak(p_hash text) RETURNS api_keys LANGUAGE sql AS $$
  SELECT * FROM api_keys AS ak WHERE ak.key_hash = p_hash
$$;

CREATE OR REPLACE FUNCTION pg_temp.t_claimed(p_ref text, p_n integer, p_key_expires_at timestamptz, p_order_expires_at timestamptz)
  RETURNS void LANGUAGE sql AS $$
  INSERT INTO api_keys (key_hash, expires_at) VALUES (pg_temp.t_billing_hash(p_n), p_key_expires_at);
  INSERT INTO billing_orders (provider, provider_order_ref, order_id, status, claimable_until, claimed_at, expires_at, api_key_id)
  SELECT 'lemonsqueezy', p_ref, pg_temp.t_uuid('a', p_n), 'claimed', now() + interval '24 hours', now(), p_order_expires_at, ak.id
    FROM api_keys AS ak WHERE ak.key_hash = pg_temp.t_billing_hash(p_n);
$$;

CREATE OR REPLACE FUNCTION pg_temp.t_violated(p_sql text) RETURNS text LANGUAGE plpgsql AS $$
DECLARE
  constraint_name text;
BEGIN
  BEGIN
    EXECUTE p_sql;
    RAISE EXCEPTION 't_violated_none';
  EXCEPTION
    WHEN check_violation OR unique_violation OR foreign_key_violation THEN
      GET STACKED DIAGNOSTICS constraint_name = CONSTRAINT_NAME;
      RETURN constraint_name;
    WHEN raise_exception THEN
      RETURN 'none';
  END;
END
$$;

SELECT pg_temp.t_claimed('7101', 101, NULL, NULL);
SELECT pg_temp.t_claimed('7201', 201, now() + interval '10 days', now() + interval '10 days');
PREPARE t_billing_paid_query   AS SELECT api.fn_billing_lemonsqueezy_order_paid($1, $2, $3) AS billing_event_status;
PREPARE t_billing_set_query    AS SELECT api.fn_billing_lemonsqueezy_set_expiry($1, $2, $3, $4, $5) AS billing_event_status;
PREPARE t_billing_clear_query  AS SELECT api.fn_billing_lemonsqueezy_clear_expiry($1, $2, $3, $4) AS billing_event_status;
PREPARE t_billing_revoke_query AS SELECT api.fn_billing_lemonsqueezy_revoke($1, $2, $3) AS billing_event_status;
PREPARE t_billing_record_query AS SELECT api.fn_billing_event_record($1, $2, $3, $4, $5) AS billing_event_status;
CREATE TEMP TABLE t_billing_paid_answer AS
  EXECUTE t_billing_paid_query(pg_temp.t_uuid('e', 1), pg_temp.t_uuid('a', 1), '7001');
CREATE TEMP TABLE t_billing_set_answer AS
  EXECUTE t_billing_set_query(pg_temp.t_uuid('e', 101), '7101', '9101', '1793506844', '1796185244');
CREATE TEMP TABLE t_billing_clear_answer AS
  EXECUTE t_billing_clear_query(pg_temp.t_uuid('e', 102), '7101', '9101', '1793506854');
CREATE TEMP TABLE t_billing_revoke_answer AS
  EXECUTE t_billing_revoke_query(pg_temp.t_uuid('e', 201), 'subscription_expired', '7201');
CREATE TEMP TABLE t_billing_record_answer AS
  EXECUTE t_billing_record_query('lemonsqueezy', pg_temp.t_uuid('e', 301), 'subscription_payment_success', '7301', '9301');
DEALLOCATE t_billing_paid_query;
DEALLOCATE t_billing_set_query;
DEALLOCATE t_billing_clear_query;
DEALLOCATE t_billing_revoke_query;
DEALLOCATE t_billing_record_query;

DO $$
DECLARE
  answer_table text;
BEGIN
  FOREACH answer_table IN ARRAY ARRAY['t_billing_paid_answer', 't_billing_set_answer', 't_billing_clear_answer',
                                      't_billing_revoke_answer', 't_billing_record_answer']
  LOOP
    ASSERT (SELECT array_agg(attname::text || ' ' || format_type(atttypid, atttypmod) ORDER BY attnum) FROM pg_attribute
             WHERE attrelid = answer_table::regclass AND attnum > 0)
           = ARRAY['billing_event_status text'],
           answer_table || ': the call db.c sends answers one text column, billing_event_status';
  END LOOP;
  ASSERT (SELECT array_agg(billing_event_status) FROM t_billing_paid_answer)   = ARRAY['applied'], 'the paid call answers applied for a new order';
  ASSERT (SELECT array_agg(billing_event_status) FROM t_billing_set_answer)    = ARRAY['applied'], 'the set call answers applied on a claimed order';
  ASSERT (SELECT array_agg(billing_event_status) FROM t_billing_clear_answer)  = ARRAY['applied'], 'the clear call answers applied on a newer time';
  ASSERT (SELECT array_agg(billing_event_status) FROM t_billing_revoke_answer) = ARRAY['applied'], 'the revoke call answers applied on a claimed order';
  ASSERT (SELECT array_agg(billing_event_status) FROM t_billing_record_answer) = ARRAY['applied'], 'the record call answers applied for a new event';
END
$$;

DO $$
DECLARE
  o billing_orders := pg_temp.t_bo('7001');
  e billing_events := pg_temp.t_be(pg_temp.t_uuid('e', 1));
BEGIN
  ASSERT o.status = 'paid', 'a paid order starts as paid';
  ASSERT o.order_id = pg_temp.t_uuid('a', 1), 'the paid order keeps its claim UUID';
  ASSERT o.claimable_until = now() + interval '24 hours', 'the paid order can be claimed for 24 hours from now()';
  ASSERT o.api_key_id IS NULL AND o.claimed_at IS NULL, 'the paid order has no key yet';
  ASSERT o.expires_at IS NULL AND o.provider_updated_at IS NULL AND o.provider_subscription_ref IS NULL,
         'the paid order has no expiry, no subscription time and no subscription ref';
  ASSERT e.event_name = 'order_created' AND e.provider_order_ref = '7001' AND e.provider_subscription_ref IS NULL,
         'the event row names order_created and the order ref';
  ASSERT e.billing_action = 'order_paid' AND e.provider_updated_at IS NULL AND e.expires_at IS NULL,
         'the event row is an order_paid action with no subscription time and no expiry';
  ASSERT e.received_at = now(), 'the event row is received at now()';

  ASSERT api.fn_billing_lemonsqueezy_order_paid(pg_temp.t_uuid('e', 1), pg_temp.t_uuid('a', 2), '7002') = 'duplicate',
         'a second delivery of an event id is duplicate';
  ASSERT (pg_temp.t_bo('7002')).provider IS NULL, 'a duplicate event writes no order';
  ASSERT (SELECT count(*) FROM billing_events AS be WHERE be.provider_event_ref = pg_temp.t_uuid('e', 1)) = 1,
         'a duplicate event writes no second event row';
  ASSERT (pg_temp.t_be(pg_temp.t_uuid('e', 1))).provider_order_ref = '7001', 'a duplicate event leaves the first event row';

  ASSERT api.fn_billing_lemonsqueezy_order_paid(pg_temp.t_uuid('e', 2), pg_temp.t_uuid('a', 1), '7001') = 'exists',
         'a new event id for the same order is exists';
  ASSERT (pg_temp.t_be(pg_temp.t_uuid('e', 2))).provider IS NOT NULL, 'the event of an exists answer stays';
  ASSERT api.fn_billing_lemonsqueezy_order_paid(pg_temp.t_uuid('e', 3), pg_temp.t_uuid('a', 1), '7003') = 'exists',
         'a known claim UUID under another provider ref is exists';
  ASSERT (pg_temp.t_bo('7003')).provider IS NULL, 'an exists answer by the claim UUID writes no order';
  ASSERT api.fn_billing_lemonsqueezy_order_paid(pg_temp.t_uuid('e', 4), pg_temp.t_uuid('a', 4), '7001') = 'exists',
         'a known provider ref under another claim UUID is exists';
  ASSERT (pg_temp.t_bo('7001')).order_id = pg_temp.t_uuid('a', 1), 'an exists answer keeps the claim UUID of the order';
  ASSERT (SELECT count(*) FROM billing_orders AS bo WHERE bo.order_id = pg_temp.t_uuid('a', 4)) = 0,
         'an exists answer by the provider ref writes no order';
  ASSERT (pg_temp.t_bo('7001')) IS NOT DISTINCT FROM o, 'an exists answer changes nothing in the order';

  ASSERT api.fn_billing_lemonsqueezy_order_paid(NULL, pg_temp.t_uuid('a', 5), '7005') IS NULL, 'a NULL event id answers NULL';
  ASSERT (pg_temp.t_bo('7005')).provider IS NULL, 'a NULL event id writes no order';
END
$$;

DO $$
BEGIN
  BEGIN
    PERFORM api.fn_billing_lemonsqueezy_order_paid(pg_temp.t_uuid('e', 6), upper(pg_temp.t_uuid('a', 6)), '7006');
    RAISE EXCEPTION 'order_paid took an upper-case claim UUID';
  EXCEPTION WHEN check_violation THEN
    NULL;
  END;
  ASSERT (pg_temp.t_be(pg_temp.t_uuid('e', 6))).provider IS NULL AND (pg_temp.t_bo('7006')).provider IS NULL,
         'a refused paid event writes neither row';
  BEGIN
    PERFORM api.fn_billing_lemonsqueezy_order_paid(pg_temp.t_uuid('e', 7), pg_temp.t_uuid('a', 7), '012');
    RAISE EXCEPTION 'order_paid took the provider ref 012';
  EXCEPTION WHEN check_violation THEN
    NULL;
  END;
END
$$;

DO $$
DECLARE
  o billing_orders := pg_temp.t_bo('7101');
  k api_keys       := pg_temp.t_ak(pg_temp.t_billing_hash(101));
  other_key        api_keys := pg_temp.t_ak(pg_temp.t_billing_hash(201));
BEGIN
  ASSERT (pg_temp.t_be(pg_temp.t_uuid('e', 101))).event_name = 'subscription_cancelled', 'the set event is stored as subscription_cancelled';
  ASSERT (pg_temp.t_be(pg_temp.t_uuid('e', 102))).event_name = 'subscription_resumed', 'the clear event is stored as subscription_resumed';
  ASSERT (pg_temp.t_be(pg_temp.t_uuid('e', 101))).provider_subscription_ref = '9101', 'the set event keeps the subscription ref';
  ASSERT (pg_temp.t_be(pg_temp.t_uuid('e', 101))).billing_action = 'set_expiry'
     AND (pg_temp.t_be(pg_temp.t_uuid('e', 101))).provider_updated_at = to_timestamp(1793506844)
     AND (pg_temp.t_be(pg_temp.t_uuid('e', 101))).expires_at = to_timestamp(1796185244), 'the set event keeps its action, time and expiry';
  ASSERT (pg_temp.t_be(pg_temp.t_uuid('e', 102))).billing_action = 'clear_expiry'
     AND (pg_temp.t_be(pg_temp.t_uuid('e', 102))).provider_updated_at = to_timestamp(1793506854)
     AND (pg_temp.t_be(pg_temp.t_uuid('e', 102))).expires_at IS NULL, 'the clear event keeps its action and time, and no expiry';
  ASSERT o.expires_at IS NULL AND k.expires_at IS NULL, 'the clear removed the expiry of the order and of its key';
  ASSERT o.provider_updated_at = to_timestamp(1793506854), 'the clear stored its time';
  ASSERT o.provider_subscription_ref = '9101', 'the first subscription ref is stored';
  ASSERT o.status = 'claimed' AND k.active, 'an expiry change leaves the order claimed and the key active';

  ASSERT api.fn_billing_lemonsqueezy_set_expiry(pg_temp.t_uuid('e', 103), '7101', '9101', 1793506853, 1796185244) = 'stale',
         'a set with a time one second before the stored one is stale';
  ASSERT pg_temp.t_bo('7101') IS NOT DISTINCT FROM o AND pg_temp.t_ak(pg_temp.t_billing_hash(101)) IS NOT DISTINCT FROM k, 'a stale set changes neither row';
  ASSERT (pg_temp.t_be(pg_temp.t_uuid('e', 103))).provider IS NOT NULL, 'the event of a stale set stays';

  ASSERT api.fn_billing_lemonsqueezy_set_expiry(pg_temp.t_uuid('e', 104), '7101', '9102', 1793506854, 1796271644) = 'applied',
         'a set with the stored time applies';
  ASSERT (pg_temp.t_bo('7101')).expires_at = to_timestamp(1796271644), 'the set wrote the expiry of the order';
  ASSERT (pg_temp.t_ak(pg_temp.t_billing_hash(101))).expires_at = to_timestamp(1796271644), 'the set wrote the expiry of the key';
  ASSERT (pg_temp.t_bo('7101')).provider_subscription_ref = '9101', 'a second, other subscription ref leaves the first';
  ASSERT pg_temp.t_ak(pg_temp.t_billing_hash(201)) IS NOT DISTINCT FROM other_key, 'the set leaves the key of another order';

  ASSERT api.fn_billing_lemonsqueezy_clear_expiry(pg_temp.t_uuid('e', 105), '7101', '9101', 1793506853) = 'stale',
         'a clear with a time before the stored one is stale';
  ASSERT (pg_temp.t_bo('7101')).expires_at = to_timestamp(1796271644)
     AND (pg_temp.t_ak(pg_temp.t_billing_hash(101))).expires_at = to_timestamp(1796271644), 'a stale clear leaves both expiries';
  ASSERT api.fn_billing_lemonsqueezy_clear_expiry(pg_temp.t_uuid('e', 106), '7101', '9101', 1793506854) = 'applied',
         'a clear with the stored time applies';
  ASSERT (pg_temp.t_bo('7101')).expires_at IS NULL AND (pg_temp.t_ak(pg_temp.t_billing_hash(101))).expires_at IS NULL,
         'the clear removed both expiries';
  ASSERT api.fn_billing_lemonsqueezy_clear_expiry(pg_temp.t_uuid('e', 108), '7101', '9199', 1793506854) = 'applied',
         'a clear with another subscription ref applies';
  ASSERT (pg_temp.t_bo('7101')).provider_subscription_ref = '9101', 'a clear leaves the first subscription ref';
  ASSERT pg_temp.t_ak(pg_temp.t_billing_hash(201)) IS NOT DISTINCT FROM other_key, 'the clear leaves the key of another order';

  ASSERT api.fn_billing_lemonsqueezy_set_expiry(pg_temp.t_uuid('e', 104), '7101', '9101', 1793600000, 1796300000) = 'duplicate',
         'a set under a used event id is duplicate';
  ASSERT api.fn_billing_lemonsqueezy_clear_expiry(pg_temp.t_uuid('e', 104), '7101', '9101', 1793600000) = 'duplicate',
         'a clear under a used event id is duplicate';
  ASSERT (pg_temp.t_bo('7101')).expires_at IS NULL AND (pg_temp.t_bo('7101')).provider_updated_at = to_timestamp(1793506854),
         'a duplicate event changes nothing, also with newer values';

  ASSERT api.fn_billing_lemonsqueezy_set_expiry(pg_temp.t_uuid('e', 107), '7101', '9101', 1793506900, -1) = 'applied',
         'a set with an expiry before 1970 applies';
  ASSERT (pg_temp.t_bo('7101')).expires_at = to_timestamp(-1), 'a negative epoch is read as seconds before 1970';
END
$$;

SELECT api.fn_billing_lemonsqueezy_order_paid(pg_temp.t_uuid('e', 110), pg_temp.t_uuid('a', 102), '7102');
SELECT pg_temp.t_claimed('7103', 103, now() + interval '5 days', now() + interval '5 days');
UPDATE billing_orders AS bo SET status = 'revoked' WHERE bo.provider_order_ref = '7103';
INSERT INTO billing_orders (provider, provider_order_ref, status) VALUES ('manual', '7105', 'revoked');
DO $$
DECLARE
  revoked_order billing_orders := pg_temp.t_bo('7103');
  revoked_key   api_keys       := pg_temp.t_ak(pg_temp.t_billing_hash(103));
BEGIN
  ASSERT api.fn_billing_lemonsqueezy_set_expiry(pg_temp.t_uuid('e', 111), '7102', '9102', 1793506844, 1796185244) = 'applied',
         'a set on an unclaimed order applies';
  ASSERT (pg_temp.t_bo('7102')).expires_at = to_timestamp(1796185244) AND (pg_temp.t_bo('7102')).status = 'paid',
         'the set wrote the expiry of the unclaimed order, which stays paid';
  ASSERT (pg_temp.t_bo('7102')).provider_updated_at = to_timestamp(1793506844), 'the set stored its time';
  ASSERT api.fn_billing_lemonsqueezy_clear_expiry(pg_temp.t_uuid('e', 123), '7102', '9102', 1793506843) = 'stale',
         'a clear older than the time a set stored is stale';
  ASSERT (pg_temp.t_bo('7102')).expires_at = to_timestamp(1796185244), 'a stale clear leaves the expiry the set wrote';

  ASSERT api.fn_billing_lemonsqueezy_set_expiry(pg_temp.t_uuid('e', 112), '7103', '9103', 1793506844, 1796185244) = 'revoked',
         'a set on a revoked order answers revoked';
  ASSERT api.fn_billing_lemonsqueezy_clear_expiry(pg_temp.t_uuid('e', 113), '7103', '9103', 1793506844) = 'revoked',
         'a clear on a revoked order answers revoked';
  ASSERT pg_temp.t_bo('7103') IS NOT DISTINCT FROM revoked_order AND pg_temp.t_ak(pg_temp.t_billing_hash(103)) IS NOT DISTINCT FROM revoked_key,
         'a set and a clear on a revoked order change neither row';
  ASSERT (pg_temp.t_be(pg_temp.t_uuid('e', 113))).provider IS NOT NULL, 'the event on a revoked order stays';

  ASSERT api.fn_billing_lemonsqueezy_set_expiry(pg_temp.t_uuid('e', 114), '7999', '9999', 1793506844, 1796185244) = 'unknown',
         'a set on a ref with no order answers unknown';
  ASSERT api.fn_billing_lemonsqueezy_clear_expiry(pg_temp.t_uuid('e', 115), '7999', '9999', 1793506844) = 'unknown',
         'a clear on a ref with no order answers unknown';
  ASSERT (pg_temp.t_be(pg_temp.t_uuid('e', 114))).provider_order_ref = '7999'
     AND (pg_temp.t_be(pg_temp.t_uuid('e', 115))).provider_subscription_ref = '9999', 'the event of an unknown order stays with its refs';
  ASSERT (pg_temp.t_be(pg_temp.t_uuid('e', 114))).provider_updated_at = to_timestamp(1793506844)
     AND (pg_temp.t_be(pg_temp.t_uuid('e', 114))).expires_at = to_timestamp(1796185244),
         'the set event of an unknown order keeps its time and expiry, so a later paid order can replay it';
  ASSERT (pg_temp.t_be(pg_temp.t_uuid('e', 115))).billing_action = 'clear_expiry'
     AND (pg_temp.t_be(pg_temp.t_uuid('e', 115))).provider_updated_at = to_timestamp(1793506844),
         'the clear event of an unknown order keeps its action and time';
  ASSERT (pg_temp.t_bo('7999')).provider IS NULL, 'an unknown order is not written';
  ASSERT api.fn_billing_lemonsqueezy_set_expiry(pg_temp.t_uuid('e', 118), '7105', '9105', 1793506844, 1796185244) = 'unknown',
         'a set reads only the orders of Lemon Squeezy';
  ASSERT api.fn_billing_lemonsqueezy_clear_expiry(pg_temp.t_uuid('e', 119), '7105', '9105', 1793506844) = 'unknown',
         'a clear reads only the orders of Lemon Squeezy';
  ASSERT api.fn_billing_lemonsqueezy_revoke(pg_temp.t_uuid('e', 122), 'order_refunded', '7105') = 'unknown',
         'a revoke reads only the orders of Lemon Squeezy';

  ASSERT api.fn_billing_lemonsqueezy_set_expiry(pg_temp.t_uuid('e', 116), '7102', NULL, 1793506844, 1796185244) IS NULL,
         'a NULL subscription ref answers NULL';
  ASSERT api.fn_billing_lemonsqueezy_clear_expiry(pg_temp.t_uuid('e', 117), '7102', '9102', NULL) IS NULL, 'a NULL time answers NULL';
  ASSERT (pg_temp.t_be(pg_temp.t_uuid('e', 116))).provider IS NULL AND (pg_temp.t_be(pg_temp.t_uuid('e', 117))).provider IS NULL,
         'a NULL argument writes no event';
END
$$;

SELECT pg_temp.t_claimed('7104', 104, NULL, NULL);
SELECT api.fn_api_key_revoke(pg_temp.t_billing_hash(104));
DO $$
DECLARE
  revoked_key api_keys := pg_temp.t_ak(pg_temp.t_billing_hash(104));
BEGIN
  ASSERT api.fn_billing_lemonsqueezy_set_expiry(pg_temp.t_uuid('e', 120), '7104', '9104', 1793506844, 1796185244) = 'applied',
         'a set on the order of a key revoked by hand applies to the order';
  ASSERT (pg_temp.t_bo('7104')).expires_at = to_timestamp(1796185244), 'the set wrote the order expiry';
  ASSERT api.fn_billing_lemonsqueezy_clear_expiry(pg_temp.t_uuid('e', 121), '7104', '9104', 1793506845) = 'applied',
         'a clear on the order of a key revoked by hand applies to the order';
  ASSERT (pg_temp.t_bo('7104')).expires_at IS NULL, 'the clear removed the order expiry';
  ASSERT pg_temp.t_ak(pg_temp.t_billing_hash(104)) IS NOT DISTINCT FROM revoked_key, 'neither call wrote the key revoked by hand';
  ASSERT (pg_temp.t_ak(pg_temp.t_billing_hash(104))).expires_at = now() AND NOT (pg_temp.t_ak(pg_temp.t_billing_hash(104))).active,
         'the key revoked by hand still expires at now()';
END
$$;

SELECT pg_temp.t_claimed('7202', 202, now() - interval '3 days', now() - interval '3 days');
SELECT pg_temp.t_claimed('7203', 203, NULL, NULL);
SELECT api.fn_billing_lemonsqueezy_set_expiry(pg_temp.t_uuid('e', 210), '7203', '9203', 4102444800, 4102444800);
SELECT api.fn_billing_lemonsqueezy_clear_expiry(pg_temp.t_uuid('e', 211), '7203', '9203', 4102444800);
SELECT api.fn_billing_lemonsqueezy_order_paid(pg_temp.t_uuid('e', 212), pg_temp.t_uuid('a', 204), '7204');
DO $$
DECLARE
  other_key api_keys := pg_temp.t_ak(pg_temp.t_billing_hash(101));
  revoked   billing_orders;
BEGIN
  ASSERT (pg_temp.t_bo('7201')).status = 'revoked', 'the revoked order is revoked';
  ASSERT (pg_temp.t_bo('7201')).expires_at = now(), 'a later order expiry moves back to now()';
  ASSERT NOT (pg_temp.t_ak(pg_temp.t_billing_hash(201))).active, 'the key of the revoked order is not active';
  ASSERT (pg_temp.t_ak(pg_temp.t_billing_hash(201))).expires_at = now(), 'a later key expiry moves back to now()';
  ASSERT (pg_temp.t_be(pg_temp.t_uuid('e', 201))).event_name = 'subscription_expired', 'the revoke stores its event name';
  ASSERT (pg_temp.t_be(pg_temp.t_uuid('e', 201))).billing_action = 'revoke'
     AND (pg_temp.t_be(pg_temp.t_uuid('e', 201))).provider_updated_at IS NULL
     AND (pg_temp.t_be(pg_temp.t_uuid('e', 201))).expires_at IS NULL, 'the revoke event is a revoke action with no time and no expiry';

  ASSERT api.fn_billing_lemonsqueezy_revoke(pg_temp.t_uuid('e', 213), 'order_refunded', '7202') = 'applied', 'a refund revokes';
  ASSERT (pg_temp.t_be(pg_temp.t_uuid('e', 213))).event_name = 'order_refunded', 'the refund stores order_refunded';
  ASSERT (pg_temp.t_bo('7202')).expires_at = now() - interval '3 days', 'an earlier order expiry stays';
  ASSERT (pg_temp.t_ak(pg_temp.t_billing_hash(202))).expires_at = now() - interval '3 days', 'an earlier key expiry stays';
  ASSERT NOT (pg_temp.t_ak(pg_temp.t_billing_hash(202))).active, 'the refunded key is not active';

  ASSERT api.fn_billing_lemonsqueezy_revoke(pg_temp.t_uuid('e', 214), 'subscription_expired', '7203') = 'applied',
         'a revoke applies whatever time the order stores';
  ASSERT (pg_temp.t_bo('7203')).expires_at = now(), 'an order with no expiry expires at now()';
  ASSERT (pg_temp.t_ak(pg_temp.t_billing_hash(203))).expires_at = now(), 'a key with no expiry expires at now()';

  revoked := pg_temp.t_bo('7201');
  ASSERT api.fn_billing_lemonsqueezy_revoke(pg_temp.t_uuid('e', 215), 'order_refunded', '7201') = 'revoked',
         'a second revoke answers revoked';
  ASSERT pg_temp.t_bo('7201') IS NOT DISTINCT FROM revoked, 'a second revoke changes nothing';
  ASSERT (pg_temp.t_be(pg_temp.t_uuid('e', 215))).provider IS NOT NULL, 'the event of a second revoke stays';

  ASSERT api.fn_billing_lemonsqueezy_revoke(pg_temp.t_uuid('e', 216), 'subscription_expired', '7204') = 'applied',
         'a revoke of an unclaimed order applies';
  ASSERT (pg_temp.t_bo('7204')).status = 'revoked' AND (pg_temp.t_bo('7204')).api_key_id IS NULL,
         'the unclaimed order is revoked and has no key';

  ASSERT api.fn_billing_lemonsqueezy_revoke(pg_temp.t_uuid('e', 216), 'subscription_expired', '7101') = 'duplicate',
         'a revoke under a used event id is duplicate';
  ASSERT (pg_temp.t_bo('7101')).status = 'claimed' AND (pg_temp.t_ak(pg_temp.t_billing_hash(101))).active,
         'a duplicate revoke changes nothing';
  ASSERT api.fn_billing_lemonsqueezy_revoke(pg_temp.t_uuid('e', 217), 'subscription_expired', '7999') = 'unknown',
         'a revoke of a ref with no order answers unknown';
  ASSERT (pg_temp.t_be(pg_temp.t_uuid('e', 217))).billing_action = 'revoke' AND (pg_temp.t_be(pg_temp.t_uuid('e', 217))).provider_order_ref = '7999',
         'the revoke event of an unknown order stays as a revoke action with its order ref';
  ASSERT api.fn_billing_lemonsqueezy_revoke(pg_temp.t_uuid('e', 218), NULL, '7101') IS NULL, 'a NULL event name answers NULL';
  ASSERT pg_temp.t_ak(pg_temp.t_billing_hash(101)) IS NOT DISTINCT FROM other_key, 'no revoke wrote the key of another order';
END
$$;

DO $$
DECLARE
  order_before billing_orders := pg_temp.t_bo('7101');
  order_count  bigint         := (SELECT count(*) FROM billing_orders);
  e            billing_events := pg_temp.t_be(pg_temp.t_uuid('e', 301));
BEGIN
  ASSERT e.event_name = 'subscription_payment_success' AND e.provider_order_ref = '7301' AND e.provider_subscription_ref = '9301',
         'the recorded event keeps its name and both refs';
  ASSERT e.billing_action = 'record' AND e.provider_updated_at IS NULL AND e.expires_at IS NULL,
         'the recorded event is a record action with no time and no expiry';
  ASSERT api.fn_billing_event_record('lemonsqueezy', pg_temp.t_uuid('e', 301), 'order_created', NULL, NULL) = 'duplicate',
         'a second delivery of a recorded id is duplicate';
  ASSERT pg_temp.t_be(pg_temp.t_uuid('e', 301)) IS NOT DISTINCT FROM e, 'a duplicate record leaves the first row';
  ASSERT api.fn_billing_event_record('lemonsqueezy', pg_temp.t_uuid('e', 302), 'subscription_updated', NULL, NULL) = 'applied',
         'an event with no refs is recorded';
  ASSERT (pg_temp.t_be(pg_temp.t_uuid('e', 302))).provider_order_ref IS NULL
     AND (pg_temp.t_be(pg_temp.t_uuid('e', 302))).provider_subscription_ref IS NULL, 'its refs stay NULL';
  ASSERT api.fn_billing_event_record('lemonsqueezy', pg_temp.t_uuid('e', 303), 'subscription_payment_success', '7101', '9101') = 'applied',
         'an event of a known order is recorded';
  ASSERT api.fn_billing_event_record('manual', pg_temp.t_uuid('e', 301), 'order_created', NULL, NULL) = 'applied',
         'the same id under another provider is another event';
  ASSERT api.fn_billing_event_record('nowpayments', 'np-5077', 'payment_finished', 'np-order-1', NULL) = 'applied',
         'another provider takes an id of its own form';
  ASSERT pg_temp.t_bo('7101') IS NOT DISTINCT FROM order_before AND (SELECT count(*) FROM billing_orders) = order_count,
         'a record touches no order';
END
$$;

DO $$
DECLARE
  key_id integer := (pg_temp.t_ak(pg_temp.t_billing_hash(101))).id;
  bo_cols text := 'INSERT INTO billing_orders (provider, provider_order_ref, provider_subscription_ref, order_id, status, claimable_until, claimed_at, api_key_id) VALUES ';
  be_cols text := 'INSERT INTO billing_events (provider, provider_event_ref, event_name, provider_order_ref, provider_subscription_ref, '
                  'billing_action, provider_updated_at, expires_at) VALUES ';
  uuid_ok text := quote_literal(pg_temp.t_uuid('a', 900));
  ev_ok   text := quote_literal(pg_temp.t_uuid('e', 900));
  c record;
BEGIN
  FOR c IN SELECT * FROM (VALUES
      ('lemonsqueezy', '''7900''', 'NULL', uuid_ok, '''paid''', 'now()', 'NULL', 'NULL', 'none'),
      ('lemonsqueezy', '''1234567890123456789''', '''5''', uuid_ok, '''paid''', 'now()', 'NULL', 'NULL', 'none'),
      ('x402',         '''7900''', 'NULL', uuid_ok, '''paid''', 'now()', 'NULL', 'NULL', 'billing_orders_provider_known'),
      ('manual',       '''abc''',  'NULL', uuid_ok, '''paid''', 'now()', 'NULL', 'NULL', 'none'),
      ('nowpayments',  '''abc''',  '''x''', uuid_ok, '''paid''', 'now()', 'NULL', 'NULL', 'none'),
      ('manual',       '''''',     'NULL', uuid_ok, '''paid''', 'now()', 'NULL', 'NULL', 'billing_orders_provider_order_ref_length'),
      ('manual',       quote_literal(repeat('m', 128)), 'NULL', uuid_ok, '''paid''', 'now()', 'NULL', 'NULL', 'none'),
      ('manual',       quote_literal(repeat('m', 129)), 'NULL', uuid_ok, '''paid''', 'now()', 'NULL', 'NULL', 'billing_orders_provider_order_ref_length'),
      ('lemonsqueezy', '''012''',  'NULL', uuid_ok, '''paid''', 'now()', 'NULL', 'NULL', 'billing_orders_lemonsqueezy_ref_format'),
      ('lemonsqueezy', '''0''',    'NULL', uuid_ok, '''paid''', 'now()', 'NULL', 'NULL', 'billing_orders_lemonsqueezy_ref_format'),
      ('lemonsqueezy', '''12345678901234567890''', 'NULL', uuid_ok, '''paid''', 'now()', 'NULL', 'NULL', 'billing_orders_lemonsqueezy_ref_format'),
      ('lemonsqueezy', '''12a''',  'NULL', uuid_ok, '''paid''', 'now()', 'NULL', 'NULL', 'billing_orders_lemonsqueezy_ref_format'),
      ('lemonsqueezy', '''7900''', '''012''', uuid_ok, '''paid''', 'now()', 'NULL', 'NULL', 'billing_orders_lemonsqueezy_ref_format'),
      ('lemonsqueezy', '''7900''', '''12345678901234567890''', uuid_ok, '''paid''', 'now()', 'NULL', 'NULL', 'billing_orders_lemonsqueezy_ref_format'),
      ('lemonsqueezy', '''7900''', 'NULL', upper(uuid_ok), '''paid''', 'now()', 'NULL', 'NULL', 'billing_orders_order_id_format'),
      ('lemonsqueezy', '''7900''', 'NULL', replace(uuid_ok, '-', '0'), '''paid''', 'now()', 'NULL', 'NULL', 'billing_orders_order_id_format'),
      ('lemonsqueezy', '''7900''', 'NULL', '''{' || pg_temp.t_uuid('a', 900) || '}''', '''paid''', 'now()', 'NULL', 'NULL', 'billing_orders_order_id_format'),
      ('lemonsqueezy', '''7900''', 'NULL', quote_literal(pg_temp.t_uuid('a', 900) || '0'), '''paid''', 'now()', 'NULL', 'NULL', 'billing_orders_order_id_format'),
      ('lemonsqueezy', '''7900''', 'NULL', uuid_ok, '''lapsed''', 'now()', 'NULL', 'NULL', 'billing_orders_status_known'),
      ('lemonsqueezy', '''7900''', 'NULL', 'NULL',  '''paid''', 'now()', 'NULL', 'NULL', 'billing_orders_claimable_has_claim'),
      ('lemonsqueezy', '''7900''', 'NULL', uuid_ok, '''paid''', 'NULL',  'NULL', 'NULL', 'billing_orders_claimable_has_claim'),
      ('lemonsqueezy', '''7900''', 'NULL', uuid_ok, '''regenerating''', 'NULL', 'now()', key_id::text, 'billing_orders_claimable_has_claim'),
      ('lemonsqueezy', '''7900''', 'NULL', 'NULL',  '''regenerating''', 'now()', 'now()', key_id::text, 'billing_orders_claimable_has_claim'),
      ('lemonsqueezy', '''7900''', 'NULL', uuid_ok, '''regenerating''', 'now()', 'now()', key_id::text, 'none'),
      ('lemonsqueezy', '''7900''', 'NULL', uuid_ok, '''paid''', 'now()', 'NULL',  key_id::text, 'billing_orders_paid_has_no_key'),
      ('lemonsqueezy', '''7900''', 'NULL', uuid_ok, '''paid''', 'now()', 'now()', 'NULL', 'billing_orders_paid_has_no_key'),
      ('lemonsqueezy', '''7900''', 'NULL', 'NULL',  '''claimed''', 'NULL', 'now()', key_id::text, 'none'),
      ('lemonsqueezy', '''7900''', 'NULL', 'NULL',  '''claimed''', 'NULL', 'NULL',  key_id::text, 'billing_orders_claimed_has_key'),
      ('lemonsqueezy', '''7900''', 'NULL', 'NULL',  '''claimed''', 'NULL', 'now()', 'NULL', 'billing_orders_claimed_has_key'),
      ('lemonsqueezy', '''7900''', 'NULL', uuid_ok, '''regenerating''', 'now()', 'NULL', key_id::text, 'billing_orders_claimed_has_key'),
      ('lemonsqueezy', '''7900''', 'NULL', uuid_ok, '''regenerating''', 'now()', 'now()', 'NULL', 'billing_orders_claimed_has_key'),
      ('lemonsqueezy', '''7900''', 'NULL', 'NULL',  '''revoked''', 'NULL', 'NULL', 'NULL', 'none'),
      ('lemonsqueezy', '''7900''', 'NULL', 'NULL',  '''claimed''', 'NULL', 'now()', '-1', 'billing_orders_api_key_id_fkey'),
      ('lemonsqueezy', '''7101''', 'NULL', 'NULL',  '''revoked''', 'NULL', 'NULL', 'NULL', 'billing_orders_provider_order_ref_unique'),
      ('manual',       '''7101''', 'NULL', 'NULL',  '''revoked''', 'NULL', 'NULL', 'NULL', 'none'),
      ('lemonsqueezy', '''7900''', 'NULL', quote_literal(pg_temp.t_uuid('a', 1)), '''paid''', 'now()', 'NULL', 'NULL', 'billing_orders_order_id_key'))
    AS t (provider, order_ref, subscription_ref, order_id, status, claimable_until, claimed_at, api_key_id, broken) LOOP
    ASSERT pg_temp.t_violated(bo_cols || format('(%L, %s, %s, %s, %s, %s, %s, %s)', c.provider, c.order_ref, c.subscription_ref,
                                                c.order_id, c.status, c.claimable_until, c.claimed_at, c.api_key_id)) = c.broken,
           format('billing_orders %s %s %s %s %s %s breaks %s', c.provider, c.order_ref, c.subscription_ref, c.order_id, c.status,
                  c.api_key_id, c.broken);
  END LOOP;

  FOR c IN SELECT * FROM (VALUES
      ('lemonsqueezy', ev_ok, '''order_created''', '''7900''', '''9900''', '''record''', 'NULL', 'NULL', 'none'),
      ('lemonsqueezy', ev_ok, '''order_created''', 'NULL', 'NULL', '''refund''', 'NULL', 'NULL', 'billing_events_billing_action_known'),
      ('lemonsqueezy', ev_ok, '''order_created''', 'NULL', 'NULL', '''order_paid''', 'NULL', 'NULL', 'none'),
      ('lemonsqueezy', ev_ok, '''order_refunded''', 'NULL', 'NULL', '''revoke''', 'NULL', 'NULL', 'none'),
      ('lemonsqueezy', ev_ok, '''subscription_cancelled''', 'NULL', 'NULL', '''set_expiry''', 'now()', '''2030-01-02 03:04:05+00''', 'none'),
      ('lemonsqueezy', ev_ok, '''subscription_cancelled''', 'NULL', 'NULL', '''set_expiry''', 'NULL', '''2030-01-02 03:04:05+00''', 'billing_events_updated_at_by_action'),
      ('lemonsqueezy', ev_ok, '''subscription_cancelled''', 'NULL', 'NULL', '''set_expiry''', 'now()', 'NULL', 'billing_events_expires_at_by_action'),
      ('lemonsqueezy', ev_ok, '''subscription_resumed''', 'NULL', 'NULL', '''clear_expiry''', 'now()', 'NULL', 'none'),
      ('lemonsqueezy', ev_ok, '''subscription_resumed''', 'NULL', 'NULL', '''clear_expiry''', 'NULL', 'NULL', 'billing_events_updated_at_by_action'),
      ('lemonsqueezy', ev_ok, '''subscription_resumed''', 'NULL', 'NULL', '''clear_expiry''', 'now()', '''2030-01-02 03:04:05+00''', 'billing_events_expires_at_by_action'),
      ('lemonsqueezy', ev_ok, '''order_refunded''', 'NULL', 'NULL', '''revoke''', 'now()', 'NULL', 'billing_events_updated_at_by_action'),
      ('lemonsqueezy', ev_ok, '''order_refunded''', 'NULL', 'NULL', '''record''', 'NULL', '''2030-01-02 03:04:05+00''', 'billing_events_expires_at_by_action'),
      ('x402',         ev_ok, '''order_created''', 'NULL', 'NULL', '''record''', 'NULL', 'NULL', 'billing_events_provider_known'),
      ('lemonsqueezy', ev_ok, '''Order_created''', 'NULL', 'NULL', '''record''', 'NULL', 'NULL', 'billing_events_event_name_format'),
      ('lemonsqueezy', ev_ok, '''order-created''', 'NULL', 'NULL', '''record''', 'NULL', 'NULL', 'billing_events_event_name_format'),
      ('lemonsqueezy', ev_ok, '''''',              'NULL', 'NULL', '''record''', 'NULL', 'NULL', 'billing_events_event_name_format'),
      ('lemonsqueezy', ev_ok, quote_literal(repeat('e', 64)), 'NULL', 'NULL', '''record''', 'NULL', 'NULL', 'none'),
      ('lemonsqueezy', ev_ok, quote_literal(repeat('e', 65)), 'NULL', 'NULL', '''record''', 'NULL', 'NULL', 'billing_events_event_name_format'),
      ('manual',       '''''', '''order_created''', 'NULL', 'NULL', '''record''', 'NULL', 'NULL', 'billing_events_provider_event_ref_length'),
      ('manual',       quote_literal(repeat('m', 128)), '''order_created''', 'NULL', 'NULL', '''record''', 'NULL', 'NULL', 'none'),
      ('manual',       quote_literal(repeat('m', 129)), '''order_created''', 'NULL', 'NULL', '''record''', 'NULL', 'NULL', 'billing_events_provider_event_ref_length'),
      ('manual',       '''np-1''', '''order_created''', '''012''', '''0''', '''record''', 'NULL', 'NULL', 'none'),
      ('lemonsqueezy', '''np-1''', '''order_created''', 'NULL', 'NULL', '''record''', 'NULL', 'NULL', 'billing_events_lemonsqueezy_ref_format'),
      ('lemonsqueezy', upper(ev_ok), '''order_created''', 'NULL', 'NULL', '''record''', 'NULL', 'NULL', 'billing_events_lemonsqueezy_ref_format'),
      ('lemonsqueezy', quote_literal(pg_temp.t_uuid('e', 900) || '0'), '''order_created''', 'NULL', 'NULL', '''record''', 'NULL', 'NULL', 'billing_events_lemonsqueezy_ref_format'),
      ('lemonsqueezy', ev_ok, '''order_created''', 'NULL', '''a12''', '''record''', 'NULL', 'NULL', 'billing_events_lemonsqueezy_ref_format'),
      ('lemonsqueezy', ev_ok, '''order_created''', '''012''', 'NULL', '''record''', 'NULL', 'NULL', 'billing_events_lemonsqueezy_ref_format'),
      ('lemonsqueezy', ev_ok, '''order_created''', '''12345678901234567890''', 'NULL', '''record''', 'NULL', 'NULL', 'billing_events_lemonsqueezy_ref_format'),
      ('lemonsqueezy', ev_ok, '''order_created''', 'NULL', '''0''', '''record''', 'NULL', 'NULL', 'billing_events_lemonsqueezy_ref_format'),
      ('lemonsqueezy', ev_ok, '''order_created''', 'NULL', '''12a''', '''record''', 'NULL', 'NULL', 'billing_events_lemonsqueezy_ref_format'),
      ('lemonsqueezy', quote_literal(pg_temp.t_uuid('e', 1)), '''order_created''', 'NULL', 'NULL', '''record''', 'NULL', 'NULL', 'billing_events_pkey'))
    AS t (provider, event_ref, event_name, order_ref, subscription_ref, billing_action, updated_at, expires_at, broken) LOOP
    ASSERT pg_temp.t_violated(be_cols || format('(%L, %s, %s, %s, %s, %s, %s, %s)', c.provider, c.event_ref, c.event_name, c.order_ref,
                                                c.subscription_ref, c.billing_action, c.updated_at, c.expires_at)) = c.broken,
           format('billing_events %s %s %s %s %s %s %s %s breaks %s', c.provider, c.event_ref, c.event_name, c.order_ref, c.subscription_ref,
                  c.billing_action, c.updated_at, c.expires_at, c.broken);
  END LOOP;
END
$$;

DO $$
DECLARE
  f regprocedure;
BEGIN
  FOR f IN SELECT p.oid::regprocedure FROM pg_proc AS p
            WHERE p.pronamespace = 'api'::regnamespace AND p.proname LIKE 'fn\_billing\_%' LOOP
    ASSERT regexp_replace(pg_get_functiondef(f), '--[^\n]*', '', 'g') !~ '\mactive\s*=',
           f::text || ' writes no active flag';
  END LOOP;
  ASSERT regexp_replace(pg_get_functiondef('api.fn_billing_lemonsqueezy_revoke(text, text, text)'::regprocedure), '--[^\n]*', '', 'g')
         ~ 'api\.fn_api_key_revoke\(',
         'api.fn_billing_lemonsqueezy_revoke revokes the key through api.fn_api_key_revoke';
  ASSERT (SELECT count(*) FROM pg_proc AS p WHERE p.pronamespace = 'api'::regnamespace AND p.proname LIKE 'fn\_billing\_%') = 11,
         'fn_billing.sql builds eleven functions';
  ASSERT (SELECT array_agg(i.indexname::text ORDER BY i.indexname) FROM pg_indexes AS i
           WHERE i.tablename IN ('billing_orders', 'billing_events') AND i.indexname LIKE 'idx\_%')
         = ARRAY['idx_billing_events_received_at', 'idx_billing_orders_api_key_id'],
         'the two tables have their two indexes';
END
$$;

DO $$
DECLARE
  f record;
BEGIN
  FOR f IN SELECT * FROM (VALUES
      ('api.fn_billing_lemonsqueezy_order_paid(text, text, text)'::regprocedure,                 true,  'sql'),
      ('api.fn_billing_lemonsqueezy_set_expiry(text, text, text, bigint, bigint)'::regprocedure, true,  'plpgsql'),
      ('api.fn_billing_lemonsqueezy_clear_expiry(text, text, text, bigint)'::regprocedure,       true,  'plpgsql'),
      ('api.fn_billing_lemonsqueezy_revoke(text, text, text)'::regprocedure,                     true,  'plpgsql'),
      ('api.fn_billing_event_record(text, text, text, text, text)'::regprocedure,                false, 'sql')) AS t (oid, is_strict, language) LOOP
    ASSERT (SELECT p.prosecdef FROM pg_proc AS p WHERE p.oid = f.oid), f.oid::text || ' is SECURITY DEFINER';
    ASSERT (SELECT p.proconfig FROM pg_proc AS p WHERE p.oid = f.oid) = ARRAY['search_path=pg_catalog'],
           f.oid::text || ' sets search_path to pg_catalog';
    ASSERT (SELECT p.provolatile FROM pg_proc AS p WHERE p.oid = f.oid) = 'v', f.oid::text || ' is VOLATILE';
    ASSERT (SELECT p.proisstrict FROM pg_proc AS p WHERE p.oid = f.oid) = f.is_strict, f.oid::text || ' has its STRICT flag';
    ASSERT (SELECT l.lanname::text FROM pg_proc AS p JOIN pg_language AS l ON l.oid = p.prolang WHERE p.oid = f.oid) = f.language,
           f.oid::text || ' is ' || f.language;
    ASSERT (SELECT p.prorettype FROM pg_proc AS p WHERE p.oid = f.oid) = 'text'::regtype, f.oid::text || ' answers text';
  END LOOP;
END
$$;

CREATE OR REPLACE FUNCTION pg_temp.t_order_lock_count() RETURNS bigint LANGUAGE sql AS $$
  SELECT count(*) FROM pg_locks AS l WHERE l.locktype = 'advisory' AND l.objsubid = 2 AND l.pid = pg_backend_pid()
$$;
CREATE OR REPLACE FUNCTION pg_temp.t_holds_order_lock(p_ref text) RETURNS boolean LANGUAGE sql AS $$
  SELECT EXISTS (SELECT FROM pg_locks AS l
                  WHERE l.locktype = 'advisory' AND l.objsubid = 2 AND l.pid = pg_backend_pid()
                    AND l.classid = oid(hashtext('lemonsqueezy')::bigint & 4294967295)
                    AND l.objid = oid(hashtext(p_ref)::bigint & 4294967295))
$$;
DO $$
DECLARE
  lock_count bigint := pg_temp.t_order_lock_count();
BEGIN
  ASSERT NOT pg_temp.t_holds_order_lock('7804') AND NOT pg_temp.t_holds_order_lock('7805')
     AND NOT pg_temp.t_holds_order_lock('7806') AND NOT pg_temp.t_holds_order_lock('7807'), 'no lock of the four refs is held yet';
  ASSERT api.fn_billing_lemonsqueezy_order_paid(pg_temp.t_uuid('e', 801), pg_temp.t_uuid('a', 801), '7804') = 'applied', 'the paid call applies';
  ASSERT pg_temp.t_holds_order_lock('7804') AND pg_temp.t_order_lock_count() = lock_count + 1,
         'the paid order takes the lock of its ref, and no other';
  ASSERT api.fn_billing_lemonsqueezy_revoke(pg_temp.t_uuid('e', 802), 'order_refunded', '7804') = 'applied', 'the revoke applies';
  ASSERT pg_temp.t_order_lock_count() = lock_count + 1, 'a revoke takes the same lock as the paid order of its ref';
  ASSERT api.fn_billing_lemonsqueezy_revoke(pg_temp.t_uuid('e', 803), 'subscription_expired', '7805') = 'unknown', 'the revoke of 7805 is unknown';
  ASSERT pg_temp.t_holds_order_lock('7805') AND pg_temp.t_order_lock_count() = lock_count + 2, 'a revoke takes the lock of its ref';
  ASSERT api.fn_billing_lemonsqueezy_set_expiry(pg_temp.t_uuid('e', 804), '7806', '9806', 1793506880, 1796185280) = 'unknown',
         'the set of 7806 is unknown';
  ASSERT pg_temp.t_holds_order_lock('7806') AND pg_temp.t_order_lock_count() = lock_count + 3, 'a set takes the lock of its ref';
  ASSERT api.fn_billing_lemonsqueezy_clear_expiry(pg_temp.t_uuid('e', 805), '7807', '9807', 1793506881) = 'unknown',
         'the clear of 7807 is unknown';
  ASSERT pg_temp.t_holds_order_lock('7807') AND pg_temp.t_order_lock_count() = lock_count + 4, 'a clear takes the lock of its ref';
  ASSERT api.fn_billing_event_record('lemonsqueezy', pg_temp.t_uuid('e', 806), 'order_refunded', '7808', NULL) = 'applied',
         'the record of 7808 applies';
  ASSERT NOT pg_temp.t_holds_order_lock('7808') AND pg_temp.t_order_lock_count() = lock_count + 4, 'a record takes no lock';
END
$$;

INSERT INTO billing_orders (provider, provider_order_ref, status) VALUES ('manual', '7106', 'revoked');
SELECT pg_temp.t_claimed('7106', 106, NULL, NULL);
DO $$
BEGIN
  ASSERT api.fn_billing_lemonsqueezy_set_expiry(pg_temp.t_uuid('e', 130), '7106', '9106', 1793506844, 1796185244) = 'applied',
         'a set locks the Lemon Squeezy order, not the manual order of the same ref';
  ASSERT (pg_temp.t_ak(pg_temp.t_billing_hash(106))).expires_at = to_timestamp(1796185244), 'the set wrote the key of the Lemon Squeezy order';
  ASSERT api.fn_billing_lemonsqueezy_clear_expiry(pg_temp.t_uuid('e', 131), '7106', '9106', 1793506845) = 'applied',
         'a clear locks the Lemon Squeezy order';
  ASSERT (pg_temp.t_ak(pg_temp.t_billing_hash(106))).expires_at IS NULL, 'the clear wrote the key of the Lemon Squeezy order';
  ASSERT api.fn_billing_lemonsqueezy_revoke(pg_temp.t_uuid('e', 132), 'order_refunded', '7106') = 'applied',
         'a revoke locks the Lemon Squeezy order';
  ASSERT (pg_temp.t_bo('7106')).status = 'revoked' AND NOT (pg_temp.t_ak(pg_temp.t_billing_hash(106))).active,
         'the revoke revoked the Lemon Squeezy order and its key';
  ASSERT pg_temp.t_violated('DELETE FROM api_keys WHERE key_hash = ' || quote_literal(pg_temp.t_billing_hash(101)))
         = 'billing_orders_api_key_id_fkey', 'a key row with an order cannot be deleted';
END
$$;

INSERT INTO billing_orders (provider, provider_order_ref, status) VALUES ('manual', '7951', 'revoked');
INSERT INTO billing_orders (provider, provider_order_ref, status) VALUES ('lemonsqueezy', '7952', 'revoked');
INSERT INTO billing_orders (provider, provider_order_ref, status, provider_updated_at)
  VALUES ('lemonsqueezy', '7953', 'revoked', now() - interval '500 days');
INSERT INTO billing_events (provider, provider_event_ref, event_name, provider_order_ref, received_at, billing_action,
                            provider_updated_at, expires_at) VALUES
  ('lemonsqueezy', pg_temp.t_uuid('e', 910), 'subscription_cancelled', '7953', now() - interval '400 days', 'set_expiry',
   now() - interval '500 days', now() - interval '470 days'),
  ('lemonsqueezy', pg_temp.t_uuid('e', 911), 'subscription_resumed', '7953', now() - interval '400 days', 'clear_expiry',
   now() - interval '500 days', NULL),
  ('lemonsqueezy', pg_temp.t_uuid('e', 912), 'subscription_resumed', '7953', now() - interval '400 days', 'clear_expiry',
   now() - interval '500 days 1 second', NULL);
INSERT INTO billing_events (provider, provider_event_ref, event_name, provider_order_ref, received_at, billing_action) VALUES
  ('lemonsqueezy', pg_temp.t_uuid('e', 901), 'order_created',        '7001', now() - interval '366 days',          'order_paid'),
  ('lemonsqueezy', pg_temp.t_uuid('e', 902), 'order_refunded',       '7001', now() - interval '364 days',          'record'),
  ('lemonsqueezy', pg_temp.t_uuid('e', 903), 'order_refunded',       '7001', now() - interval '365 days',          'record'),
  ('lemonsqueezy', pg_temp.t_uuid('e', 904), 'order_refunded',       '7001', now() - interval '365 days 1 second', 'record'),
  ('lemonsqueezy', pg_temp.t_uuid('e', 905), 'order_refunded',       '7950', now() - interval '400 days',          'record'),
  ('lemonsqueezy', pg_temp.t_uuid('e', 906), 'subscription_updated', NULL,   now() - interval '400 days',          'record'),
  ('lemonsqueezy', pg_temp.t_uuid('e', 907), 'order_refunded',       '7951', now() - interval '400 days',          'record'),
  ('lemonsqueezy', pg_temp.t_uuid('e', 908), 'order_refunded',       '7952', now() - interval '400 days',          'record'),
  ('manual',       'm-909',                  'order_refunded',       '7001', now() - interval '400 days',          'record'),
  ('manual',       pg_temp.t_uuid('e', 901), 'order_refunded',       NULL,   now(),                                'record');

PREPARE t_billing_purge_query AS SELECT api.fn_billing_event_purge($1) AS purged_event_count;
CREATE TEMP TABLE t_billing_purge_answer AS EXECUTE t_billing_purge_query('0');
DEALLOCATE t_billing_purge_query;

DO $$
DECLARE
  event_count bigint := (SELECT count(*) FROM billing_events);
BEGIN
  ASSERT (SELECT array_agg(a.attname::text || ' ' || format_type(a.atttypid, a.atttypmod) ORDER BY a.attnum)
            FROM pg_attribute AS a WHERE a.attrelid = 'pg_temp.t_billing_purge_answer'::regclass AND a.attnum > 0)
         = ARRAY['purged_event_count integer'], 'the call db.c sends answers one integer column, purged_event_count';
  ASSERT (SELECT t.purged_event_count FROM t_billing_purge_answer AS t) = 0, 'a limit of 0 deletes nothing';
  ASSERT api.fn_billing_event_purge(NULL) IS NULL, 'a NULL limit answers NULL';
  ASSERT (SELECT count(*) FROM billing_events) = event_count, 'neither call deleted an event';
  ASSERT api.fn_billing_event_purge(1) = 1, 'a limit of 1 deletes one of the five old events';
  ASSERT api.fn_billing_event_purge(10) = 4, 'the next call deletes the other four';
  ASSERT api.fn_billing_event_purge(10) = 0, 'a call with no old event left deletes none';
  ASSERT (SELECT count(*) FROM billing_events) = event_count - 5, 'the purge deleted five events in all';
  ASSERT (SELECT array_agg(right(be.provider_event_ref, 3) ORDER BY be.provider_event_ref) FROM billing_events AS be
           WHERE be.provider = 'lemonsqueezy'
             AND be.provider_event_ref IN (SELECT pg_temp.t_uuid('e', n) FROM generate_series(901, 912) AS n))
         = ARRAY['902', '903', '905', '907', '910', '911'], 'the events 902, 903, 905, 907, 910 and 911 stay';
  ASSERT (SELECT array_agg(be.provider_event_ref ORDER BY be.provider_event_ref) FROM billing_events AS be
           WHERE be.provider = 'manual' AND be.provider_event_ref IN ('m-909', pg_temp.t_uuid('e', 901)))
         = ARRAY[pg_temp.t_uuid('e', 901), 'm-909'], 'the manual events of the ref 7001 and of the event id of 901 stay';
END
$$;

DO $$
DECLARE
  f regprocedure := 'api.fn_billing_event_purge(integer)'::regprocedure;
BEGIN
  ASSERT (SELECT p.prosecdef FROM pg_proc AS p WHERE p.oid = f), 'the purge is SECURITY DEFINER';
  ASSERT (SELECT p.proconfig FROM pg_proc AS p WHERE p.oid = f) = ARRAY['search_path=pg_catalog'],
         'the purge sets search_path to pg_catalog';
  ASSERT (SELECT p.provolatile FROM pg_proc AS p WHERE p.oid = f) = 'v', 'the purge is VOLATILE';
  ASSERT (SELECT p.proisstrict FROM pg_proc AS p WHERE p.oid = f), 'the purge is STRICT';
  ASSERT (SELECT l.lanname::text FROM pg_proc AS p JOIN pg_language AS l ON l.oid = p.prolang WHERE p.oid = f) = 'sql',
         'the purge is sql';
  ASSERT (SELECT p.prorettype FROM pg_proc AS p WHERE p.oid = f) = 'integer'::regtype, 'the purge answers an integer';
END
$$;
