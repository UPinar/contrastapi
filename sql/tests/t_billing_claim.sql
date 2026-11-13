CREATE OR REPLACE FUNCTION pg_temp.t_billing_hash(p_n integer) RETURNS text LANGUAGE sql AS $$
  SELECT 'b1' || lpad(to_hex(p_n), 62, '0')
$$;
CREATE OR REPLACE FUNCTION pg_temp.t_uuid(p_kind text, p_n integer) RETURNS text LANGUAGE sql AS $$
  SELECT p_kind || '0000000-0000-4000-8000-' || lpad(p_n::text, 12, '0')
$$;
CREATE OR REPLACE FUNCTION pg_temp.t_bo(p_ref text) RETURNS billing_orders LANGUAGE sql AS $$
  SELECT * FROM billing_orders AS bo WHERE bo.provider = 'lemonsqueezy' AND bo.provider_order_ref = p_ref
$$;
CREATE OR REPLACE FUNCTION pg_temp.t_ak(p_hash text) RETURNS api_keys LANGUAGE sql AS $$
  SELECT * FROM api_keys AS ak WHERE ak.key_hash = p_hash
$$;

CREATE FUNCTION pg_temp.t_paid(p_ref text, p_n integer) RETURNS text LANGUAGE sql AS $$
  SELECT api.fn_billing_lemonsqueezy_order_paid(pg_temp.t_uuid('e', p_n), pg_temp.t_uuid('a', p_n), p_ref)
$$;

CREATE FUNCTION pg_temp.t_regenerate_key(p_provider text, p_ref text) RETURNS text LANGUAGE sql AS $$
  SELECT coalesce(string_agg(r.regenerate_status || '|' || coalesce(r.claim_order_id, 'null'), ','), '')
    FROM api.fn_billing_regenerate_key(p_provider, p_ref) AS r
$$;

SELECT pg_temp.t_paid('8001', 1001);
SELECT pg_temp.t_paid('8002', 1002);
SELECT pg_temp.t_paid('8003', 1003);
SELECT pg_temp.t_paid('8004', 1004);
SELECT pg_temp.t_paid('8005', 1005);
SELECT pg_temp.t_paid('8006', 1006);

PREPARE t_billing_claim_query AS SELECT api.fn_billing_claim($1, $2) AS billing_claim_status;
CREATE TEMP TABLE t_billing_claim_answer AS
  EXECUTE t_billing_claim_query(pg_temp.t_uuid('a', 1001), pg_temp.t_billing_hash(1001));
DEALLOCATE t_billing_claim_query;

DO $$
DECLARE
  o billing_orders := pg_temp.t_bo('8001');
  k api_keys       := pg_temp.t_ak(pg_temp.t_billing_hash(1001));
BEGIN
  ASSERT (SELECT array_agg(attname::text || ' ' || format_type(atttypid, atttypmod) ORDER BY attnum) FROM pg_attribute
           WHERE attrelid = 't_billing_claim_answer'::regclass AND attnum > 0)
         = ARRAY['billing_claim_status text'],
         'the call db.c sends answers one text column, billing_claim_status';
  ASSERT (SELECT array_agg(billing_claim_status) FROM t_billing_claim_answer) = ARRAY['claimed'], 'the call claims a paid order';
  ASSERT k.id IS NOT NULL AND k.active AND k.expires_at IS NULL, 'the claim wrote an active key that never expires';
  ASSERT o.status = 'claimed' AND o.api_key_id = k.id AND o.claimed_at = now(), 'the order is claimed by the new key at now()';
  ASSERT (SELECT s.api_key_state FROM api.fn_api_key_state(pg_temp.t_billing_hash(1001)) AS s) = 'active', 'the claimed hash is an active key';

  ASSERT api.fn_billing_claim(pg_temp.t_uuid('a', 1001), pg_temp.t_billing_hash(1101)) = 'already_claimed',
         'a second claim answers already_claimed';
  ASSERT (pg_temp.t_ak(pg_temp.t_billing_hash(1101))).id IS NULL, 'a second claim writes no key';
  ASSERT (pg_temp.t_bo('8001')).api_key_id = k.id, 'a second claim keeps the key of the order';
  UPDATE billing_orders AS bo SET claimable_until = now() - interval '1 day' WHERE bo.provider_order_ref = '8001';
  ASSERT api.fn_billing_claim(pg_temp.t_uuid('a', 1001), pg_temp.t_billing_hash(1102)) = 'already_claimed',
         'a claimed order whose claim time passed still answers already_claimed';

  ASSERT api.fn_billing_claim(pg_temp.t_uuid('a', 1999), pg_temp.t_billing_hash(1103)) = 'unknown', 'a UUID of no order answers unknown';
  ASSERT (pg_temp.t_ak(pg_temp.t_billing_hash(1103))).id IS NULL, 'an unknown claim writes no key';
  ASSERT api.fn_billing_claim(NULL, pg_temp.t_billing_hash(1104)) IS NULL, 'a NULL UUID answers NULL';

  UPDATE billing_orders AS bo SET claimable_until = now() WHERE bo.provider_order_ref = '8002';
  ASSERT api.fn_billing_claim(pg_temp.t_uuid('a', 1002), pg_temp.t_billing_hash(1002)) = 'lapsed',
         'an order whose claim time is now() has lapsed';
  ASSERT (pg_temp.t_ak(pg_temp.t_billing_hash(1002))).id IS NULL AND (pg_temp.t_bo('8002')).status = 'paid',
         'a lapsed claim writes no key and leaves the order paid';
  UPDATE billing_orders AS bo SET claimable_until = now() - interval '1 day' WHERE bo.provider_order_ref = '8002';
  ASSERT api.fn_billing_claim(pg_temp.t_uuid('a', 1002), pg_temp.t_billing_hash(1002)) = 'lapsed',
         'an order whose claim time passed a day ago has lapsed';
  UPDATE billing_orders AS bo SET claimable_until = now() + interval '1 second' WHERE bo.provider_order_ref = '8002';
  ASSERT api.fn_billing_claim(pg_temp.t_uuid('a', 1002), pg_temp.t_billing_hash(1002)) = 'claimed',
         'an order with one second left is claimed';
END
$$;

SELECT api.fn_billing_lemonsqueezy_revoke(pg_temp.t_uuid('e', 1203), 'order_refunded', '8003');
SELECT api.fn_billing_lemonsqueezy_revoke(pg_temp.t_uuid('e', 1201), 'order_refunded', '8001');
SELECT api.fn_billing_lemonsqueezy_set_expiry(pg_temp.t_uuid('e', 1204), '8004', '9004', 1793506844, 1796185244);
DO $$
BEGIN
  ASSERT api.fn_billing_claim(pg_temp.t_uuid('a', 1003), pg_temp.t_billing_hash(1003)) = 'revoked',
         'a revoked unclaimed order answers revoked';
  ASSERT (pg_temp.t_ak(pg_temp.t_billing_hash(1003))).id IS NULL, 'a revoked claim writes no key';
  ASSERT api.fn_billing_claim(pg_temp.t_uuid('a', 1001), pg_temp.t_billing_hash(1105)) = 'revoked',
         'a revoked claimed order answers revoked';

  ASSERT api.fn_billing_claim(pg_temp.t_uuid('a', 1004), pg_temp.t_billing_hash(1004)) = 'claimed', 'an order with an expiry is claimed';
  ASSERT (pg_temp.t_ak(pg_temp.t_billing_hash(1004))).expires_at = to_timestamp(1796185244), 'the claim copies the expiry of the order';

  BEGIN
    PERFORM api.fn_billing_claim(pg_temp.t_uuid('a', 1006), upper(pg_temp.t_billing_hash(1006)));
    RAISE EXCEPTION 'the claim took an upper-case hash';
  EXCEPTION WHEN check_violation THEN
    NULL;
  END;
  ASSERT (pg_temp.t_bo('8006')).status = 'paid' AND (pg_temp.t_bo('8006')).api_key_id IS NULL, 'a refused hash leaves the order paid';
END
$$;

INSERT INTO watchlist_item (api_key_id, endpoint_name)
  SELECT ak.id, 'cve_lookup' FROM api_keys AS ak WHERE ak.key_hash = pg_temp.t_billing_hash(1004);
DO $$
DECLARE
  key_before   api_keys := pg_temp.t_ak(pg_temp.t_billing_hash(1004));
  key_count    bigint   := (SELECT count(*) FROM api_keys);
  answer       text     := pg_temp.t_regenerate_key('lemonsqueezy', '8004');
  new_order_id text     := split_part(answer, '|', 2);
  o            billing_orders := pg_temp.t_bo('8004');
  k            api_keys;
  second_id    text;
BEGIN
  ASSERT split_part(answer, '|', 1) = 'regenerating', 'regenerating the key of a claimed order with an active key answers regenerating';
  ASSERT new_order_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', 'the new claim UUID is lowercase';
  ASSERT new_order_id <> pg_temp.t_uuid('a', 1004), 'the new claim UUID is not the old one';
  ASSERT o.status = 'regenerating' AND o.order_id = new_order_id, 'the order is regenerating under the new claim UUID';
  ASSERT o.claimable_until = now() + interval '24 hours', 'the regenerating order can be claimed for 24 hours';
  ASSERT o.api_key_id = key_before.id, 'the regenerating order keeps its key row';
  SELECT * INTO k FROM api_keys AS ak WHERE ak.id = key_before.id;
  ASSERT k.key_hash <> key_before.key_hash AND k.key_hash ~ '^[0-9a-f]{64}$', 'the key hash changes to another valid hash';
  ASSERT k.active AND k.expires_at = key_before.expires_at, 'the key stays active with its expiry';
  ASSERT (SELECT s.api_key_state FROM api.fn_api_key_state(pg_temp.t_billing_hash(1004)) AS s) = 'unknown', 'the old hash stops at once';
  ASSERT (SELECT count(*) FROM api_keys) = key_count, 'regenerating the key writes no key row';

  ASSERT api.fn_billing_claim(pg_temp.t_uuid('a', 1004), pg_temp.t_billing_hash(1204)) = 'unknown', 'the old claim UUID claims nothing';
  UPDATE billing_orders AS bo SET claimed_at = now() - interval '1 day' WHERE bo.provider_order_ref = '8004';
  ASSERT api.fn_billing_claim(new_order_id, pg_temp.t_billing_hash(1304)) = 'claimed', 'the new claim UUID claims the order';
  k := pg_temp.t_ak(pg_temp.t_billing_hash(1304));
  ASSERT k.id = key_before.id, 'the claim of a regenerating order writes the new hash on the same key row';
  ASSERT (SELECT count(*) FROM api_keys) = key_count, 'the claim of a regenerating order writes no key row';
  ASSERT (SELECT count(*) FROM watchlist_item AS wi WHERE wi.api_key_id = key_before.id) = 1, 'the watch list item of the key stays';
  ASSERT (pg_temp.t_bo('8004')).status = 'claimed' AND (pg_temp.t_bo('8004')).claimed_at = now(), 'the order is claimed again';
  ASSERT api.fn_billing_claim(new_order_id, pg_temp.t_billing_hash(1404)) = 'already_claimed', 'the new UUID claims once';

  second_id := split_part(pg_temp.t_regenerate_key('lemonsqueezy', '8004'), '|', 2);
  ASSERT second_id <> new_order_id, 'regenerating the key again gives another claim UUID';
  UPDATE billing_orders AS bo SET claimable_until = now() WHERE bo.provider_order_ref = '8004';
  ASSERT api.fn_billing_claim(second_id, pg_temp.t_billing_hash(1504)) = 'lapsed', 'a regenerating order lapses too';
  ASSERT (SELECT ak.key_hash FROM api_keys AS ak WHERE ak.id = key_before.id) <> pg_temp.t_billing_hash(1504),
         'a lapsed claim of a regenerating order writes no hash';
END
$$;
DELETE FROM watchlist_item AS wi WHERE wi.api_key_id = (SELECT bo.api_key_id FROM billing_orders AS bo WHERE bo.provider_order_ref = '8004');

INSERT INTO api_keys (key_hash) VALUES (pg_temp.t_billing_hash(1010));
INSERT INTO billing_orders (provider, provider_order_ref, order_id, status, claimable_until, claimed_at, api_key_id)
  SELECT 'lemonsqueezy', '8010', NULL, 'claimed', NULL, now() - interval '30 days', ak.id
    FROM api_keys AS ak WHERE ak.key_hash = pg_temp.t_billing_hash(1010);
DO $$
DECLARE
  key_before   api_keys := pg_temp.t_ak(pg_temp.t_billing_hash(1010));
  answer       text     := pg_temp.t_regenerate_key('lemonsqueezy', '8010');
  new_order_id text     := split_part(answer, '|', 2);
  o            billing_orders := pg_temp.t_bo('8010');
BEGIN
  ASSERT split_part(answer, '|', 1) = 'regenerating', 'regenerating the key of a claimed order with no claim UUID answers regenerating';
  ASSERT new_order_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', 'the order with no claim UUID gets a lowercase one';
  ASSERT o.status = 'regenerating' AND o.order_id = new_order_id AND o.claimable_until = now() + interval '24 hours',
         'the order with no claim UUID is regenerating under the new one for 24 hours';
  ASSERT (SELECT s.api_key_state FROM api.fn_api_key_state(pg_temp.t_billing_hash(1010)) AS s) = 'unknown', 'the old hash of the linked key stops at once';
  ASSERT api.fn_billing_claim(new_order_id, pg_temp.t_billing_hash(1110)) = 'claimed', 'the new claim UUID claims the linked order';
  ASSERT (pg_temp.t_ak(pg_temp.t_billing_hash(1110))).id = key_before.id, 'the claim writes the new hash on the linked key row';
END
$$;

SELECT pg_temp.t_paid('8007', 1007);
SELECT api.fn_billing_claim(pg_temp.t_uuid('a', 1007), pg_temp.t_billing_hash(1007));
SELECT api.fn_api_key_revoke(pg_temp.t_billing_hash(1007));
SELECT pg_temp.t_paid('8008', 1008);
SELECT api.fn_billing_claim(pg_temp.t_uuid('a', 1008), pg_temp.t_billing_hash(1008));
UPDATE api_keys AS ak SET expires_at = now() WHERE ak.key_hash = pg_temp.t_billing_hash(1008);
SELECT pg_temp.t_paid('8009', 1009);
SELECT api.fn_billing_claim(pg_temp.t_uuid('a', 1009), pg_temp.t_billing_hash(1009));
UPDATE api_keys AS ak SET active = false WHERE ak.key_hash = pg_temp.t_billing_hash(1009);
DO $$
DECLARE
  orders_before text := (SELECT string_agg(bo::text, ',' ORDER BY bo.billing_order_id) FROM billing_orders AS bo);
  keys_before   text := (SELECT string_agg(ak::text, ',' ORDER BY ak.id) FROM api_keys AS ak);
BEGIN
  ASSERT pg_temp.t_regenerate_key('lemonsqueezy', '8003') = 'revoked|null', 'regenerating the key of a revoked order answers revoked';
  ASSERT pg_temp.t_regenerate_key('lemonsqueezy', '8001') = 'revoked|null', 'regenerating the key of a revoked claimed order answers revoked';
  ASSERT pg_temp.t_regenerate_key('lemonsqueezy', '8007') = 'inactive|null', 'regenerating a key revoked by hand answers inactive';
  ASSERT pg_temp.t_regenerate_key('lemonsqueezy', '8008') = 'inactive|null', 'regenerating a key that expires at now() answers inactive';
  ASSERT pg_temp.t_regenerate_key('lemonsqueezy', '8009') = 'inactive|null', 'regenerating a key that is not active and never expires answers inactive';
  ASSERT pg_temp.t_regenerate_key('lemonsqueezy', '8999') = 'unknown|null', 'regenerating the key of a ref with no order answers unknown';
  ASSERT pg_temp.t_regenerate_key('manual', '8005') = 'unknown|null', 'regenerating a key reads only the orders of its provider';
  ASSERT pg_temp.t_regenerate_key(NULL, '8005') = '', 'a NULL provider answers no row';
  ASSERT (SELECT string_agg(bo::text, ',' ORDER BY bo.billing_order_id) FROM billing_orders AS bo) = orders_before
     AND (SELECT string_agg(ak::text, ',' ORDER BY ak.id) FROM api_keys AS ak) = keys_before, 'no refused call writes a row';
END
$$;

SELECT pg_temp.t_paid('8012', 1012);
UPDATE billing_orders AS bo SET claimable_until = now() - interval '1 day' WHERE bo.provider_order_ref = '8012';
DO $$
DECLARE
  lapsed_answer text := pg_temp.t_regenerate_key('lemonsqueezy', '8012');
  lapsed_id     text := split_part(lapsed_answer, '|', 2);
  open_answer   text := pg_temp.t_regenerate_key('lemonsqueezy', '8005');
  open_id       text := split_part(open_answer, '|', 2);
BEGIN
  ASSERT split_part(lapsed_answer, '|', 1) = 'reopened', 'regenerating a lapsed paid order answers reopened';
  ASSERT split_part(open_answer, '|', 1) = 'reopened', 'regenerating a paid order within its claim time answers reopened';
  ASSERT (pg_temp.t_bo('8012')).order_id = lapsed_id AND lapsed_id <> pg_temp.t_uuid('a', 1012),
         'the lapsed order holds the new claim UUID it answered';
  ASSERT (pg_temp.t_bo('8005')).order_id = open_id AND open_id <> pg_temp.t_uuid('a', 1005),
         'the open order holds the new claim UUID it answered';
  ASSERT (pg_temp.t_bo('8012')).status = 'paid' AND (pg_temp.t_bo('8012')).api_key_id IS NULL
     AND (pg_temp.t_bo('8012')).claimable_until = now() + interval '24 hours',
         'the order stays paid with no key, and can be claimed for 24 hours again';
  ASSERT api.fn_billing_claim(pg_temp.t_uuid('a', 1012), pg_temp.t_billing_hash(1012)) = 'unknown', 'the old claim UUID claims nothing';
  ASSERT api.fn_billing_claim(lapsed_id, pg_temp.t_billing_hash(1012)) = 'claimed', 'the new claim UUID claims the order';
  ASSERT (SELECT s.api_key_state FROM api.fn_api_key_state(pg_temp.t_billing_hash(1012)) AS s) = 'active',
         'the claim writes a working key';
END
$$;

DO $$
DECLARE
  f record;
BEGIN
  FOR f IN SELECT * FROM (VALUES
      ('api.fn_billing_claim(text, text)'::regprocedure,          'plpgsql', true),
      ('api.fn_billing_regenerate_key(text, text)'::regprocedure, 'plpgsql', false)) AS t (oid, language, is_definer) LOOP
    ASSERT (SELECT p.prosecdef FROM pg_proc AS p WHERE p.oid = f.oid) = f.is_definer,
           f.oid::text || CASE WHEN f.is_definer THEN ' is SECURITY DEFINER' ELSE ' is SECURITY INVOKER' END;
    ASSERT (SELECT p.proconfig FROM pg_proc AS p WHERE p.oid = f.oid) = ARRAY['search_path=pg_catalog'],
           f.oid::text || ' sets search_path to pg_catalog';
    ASSERT (SELECT p.provolatile FROM pg_proc AS p WHERE p.oid = f.oid) = 'v', f.oid::text || ' is VOLATILE';
    ASSERT (SELECT p.proisstrict FROM pg_proc AS p WHERE p.oid = f.oid), f.oid::text || ' is STRICT';
    ASSERT (SELECT l.lanname::text FROM pg_proc AS p JOIN pg_language AS l ON l.oid = p.prolang WHERE p.oid = f.oid) = f.language,
           f.oid::text || ' is ' || f.language;
  END LOOP;
  ASSERT (SELECT array_agg(a.name || ' ' || format_type(a.type, NULL) ORDER BY a.n)
            FROM pg_proc AS p
           CROSS JOIN LATERAL unnest(p.proargnames, p.proallargtypes::oid[], p.proargmodes::text[]) WITH ORDINALITY AS a (name, type, mode, n)
           WHERE p.oid = 'api.fn_billing_regenerate_key(text, text)'::regprocedure AND a.mode = 't')
         = ARRAY['regenerate_status text', 'claim_order_id text'],
         'api.fn_billing_regenerate_key answers regenerate_status, then claim_order_id';
END
$$;

INSERT INTO billing_orders (provider, provider_order_ref, status) VALUES ('manual', '8011', 'revoked');
SELECT pg_temp.t_paid('8011', 1011);
SELECT api.fn_billing_claim(pg_temp.t_uuid('a', 1011), pg_temp.t_billing_hash(1011));
DO $$
BEGIN
  ASSERT split_part(pg_temp.t_regenerate_key('lemonsqueezy', '8011'), '|', 1) = 'regenerating',
         'a regenerate locks the order of its provider, not the manual order of the same ref';
  ASSERT (pg_temp.t_bo('8011')).status = 'regenerating', 'the Lemon Squeezy order is regenerating';
END
$$;

DO $$
DECLARE
  o billing_orders;
BEGIN
  ASSERT api.fn_billing_lemonsqueezy_revoke(pg_temp.t_uuid('e', 1651), 'order_refunded', '8101') = 'unknown',
         'a refund before its order answers unknown';
  ASSERT api.fn_billing_lemonsqueezy_set_expiry(pg_temp.t_uuid('e', 1652), '8102', '9102', 1793506851, 4102444800) = 'unknown',
         'a cancel before its order answers unknown';
  ASSERT api.fn_billing_lemonsqueezy_revoke(pg_temp.t_uuid('e', 1653), 'subscription_expired', '8102') = 'unknown',
         'an expiry before its order answers unknown';
  ASSERT api.fn_billing_lemonsqueezy_set_expiry(pg_temp.t_uuid('e', 1654), '8103', '9103', 1793506853, 1796185253) = 'unknown',
         'the cancel of 8103 answers unknown';
  ASSERT api.fn_billing_lemonsqueezy_set_expiry(pg_temp.t_uuid('e', 1655), '8104', '9104', 1793506854, 1796185254) = 'unknown',
         'the cancel of 8104 answers unknown';
  ASSERT api.fn_billing_lemonsqueezy_clear_expiry(pg_temp.t_uuid('e', 1656), '8104', '9114', 1793506855) = 'unknown',
         'a resume before its order answers unknown';
  ASSERT api.fn_billing_lemonsqueezy_set_expiry(pg_temp.t_uuid('e', 1657), '8105', '9105', 1793506857, 1796185257) = 'unknown',
         'the newer cancel of 8105 comes first and answers unknown';
  ASSERT api.fn_billing_lemonsqueezy_set_expiry(pg_temp.t_uuid('e', 1658), '8105', '9115', 1793506856, 1796185256) = 'unknown',
         'the older cancel of 8105 comes second and answers unknown';
  INSERT INTO billing_events (provider, provider_event_ref, event_name, provider_order_ref, provider_subscription_ref, received_at,
                              billing_action, provider_updated_at, expires_at)
  VALUES ('lemonsqueezy', pg_temp.t_uuid('e', 1660), 'subscription_cancelled', '8106', '9106', now() - interval '2 minutes',
          'set_expiry', to_timestamp(1793506860), to_timestamp(1796185260)),
         ('lemonsqueezy', pg_temp.t_uuid('e', 1659), 'subscription_cancelled', '8106', '9116', now() - interval '1 minute',
          'set_expiry', to_timestamp(1793506860), to_timestamp(1796185259)),
         ('manual', 'np-8107-refund', 'order_refunded', '8107', NULL, now(), 'revoke', NULL, NULL),
         ('manual', 'np-8107-cancel', 'subscription_cancelled', '8107', 'np-9107', now(),
          'set_expiry', to_timestamp(1793506870), to_timestamp(1796185270));
  ASSERT api.fn_billing_lemonsqueezy_revoke(pg_temp.t_uuid('e', 1661), 'order_refunded', '8109') = 'unknown',
         'the refund of the ref 8109 answers unknown';
  ASSERT api.fn_billing_lemonsqueezy_set_expiry(pg_temp.t_uuid('e', 1662), '8109', '9109', 1793506869, 1796185269) = 'unknown',
         'the cancel of the ref 8109 answers unknown';
  ASSERT api.fn_billing_event_record('lemonsqueezy', pg_temp.t_uuid('e', 1663), 'order_refunded', '8110', NULL) = 'applied',
         'a partial refund before its order is recorded';
  ASSERT api.fn_billing_lemonsqueezy_clear_expiry(pg_temp.t_uuid('e', 1671), '8111', '9111', 1793506871) = 'unknown',
         'the lone resume of 8111 answers unknown';
  ASSERT api.fn_billing_lemonsqueezy_set_expiry(pg_temp.t_uuid('e', 1672), '8112', '9112', 1793506872, 1796185272) = 'unknown',
         'the cancel of 8112 with the lower event id answers unknown';
  ASSERT api.fn_billing_lemonsqueezy_set_expiry(pg_temp.t_uuid('e', 1673), '8112', '9112', 1793506872, 1796185273) = 'unknown',
         'the cancel of 8112 with the higher event id answers unknown';

  ASSERT pg_temp.t_paid('8101', 1601) = 'applied', 'the paid event of a refunded order answers applied';
  o := pg_temp.t_bo('8101');
  ASSERT o.status = 'revoked' AND o.api_key_id IS NULL, 'an order refunded before its paid event is revoked and has no key';
  ASSERT o.expires_at = now(), 'the revoked order with no expiry expires at now(), as a revoke writes it';
  ASSERT api.fn_billing_claim(pg_temp.t_uuid('a', 1601), pg_temp.t_billing_hash(1601)) = 'revoked',
         'the claim of an order refunded before its paid event answers revoked';
  ASSERT (pg_temp.t_ak(pg_temp.t_billing_hash(1601))).id IS NULL, 'that claim writes no key';

  ASSERT pg_temp.t_paid('8102', 1602) = 'applied', 'the paid event of an expired order answers applied';
  o := pg_temp.t_bo('8102');
  ASSERT o.status = 'revoked', 'an order expired before its paid event is revoked';
  ASSERT o.expires_at = now(), 'the revoked order expires at the earlier of its cancel expiry and now()';
  ASSERT api.fn_billing_claim(pg_temp.t_uuid('a', 1602), pg_temp.t_billing_hash(1602)) = 'revoked',
         'the claim of an order expired before its paid event answers revoked';

  ASSERT pg_temp.t_paid('8103', 1603) = 'applied', 'the paid event of a cancelled order answers applied';
  o := pg_temp.t_bo('8103');
  ASSERT o.status = 'paid' AND o.expires_at = to_timestamp(1796185253), 'the paid order carries the expiry of the earlier cancel';
  ASSERT o.provider_updated_at = to_timestamp(1793506853) AND o.provider_subscription_ref = '9103',
         'the paid order carries the time and the subscription ref of the earlier cancel';
  ASSERT api.fn_billing_claim(pg_temp.t_uuid('a', 1603), pg_temp.t_billing_hash(1603)) = 'claimed', 'a cancelled order is claimed';
  ASSERT (pg_temp.t_ak(pg_temp.t_billing_hash(1603))).expires_at = to_timestamp(1796185253), 'the claim copies the expiry of the cancel to the key';
  ASSERT api.fn_billing_lemonsqueezy_set_expiry(pg_temp.t_uuid('e', 1664), '8103', '9103', 1793506852, 1796185252) = 'stale',
         'a cancel older than the replayed one is stale';

  ASSERT pg_temp.t_paid('8104', 1604) = 'applied', 'the paid event of a resumed order answers applied';
  o := pg_temp.t_bo('8104');
  ASSERT o.expires_at IS NULL AND o.provider_updated_at = to_timestamp(1793506855), 'the newer resume clears the expiry of the cancel';
  ASSERT o.provider_subscription_ref = '9104', 'the subscription ref of the first event stays';
  ASSERT api.fn_billing_claim(pg_temp.t_uuid('a', 1604), pg_temp.t_billing_hash(1604)) = 'claimed', 'a resumed order is claimed';
  ASSERT (pg_temp.t_ak(pg_temp.t_billing_hash(1604))).expires_at IS NULL, 'the key of a resumed order has no expiry';

  ASSERT pg_temp.t_paid('8105', 1605) = 'applied', 'the paid event of an order with two cancels answers applied';
  ASSERT api.fn_billing_claim(pg_temp.t_uuid('a', 1605), pg_temp.t_billing_hash(1605)) = 'claimed', 'that order is claimed';
  ASSERT (pg_temp.t_ak(pg_temp.t_billing_hash(1605))).expires_at = to_timestamp(1796185257),
         'the cancel with the newer time wins, though it came first';

  ASSERT pg_temp.t_paid('8106', 1606) = 'applied', 'the paid event of an order with two cancels of one time answers applied';
  o := pg_temp.t_bo('8106');
  ASSERT o.expires_at = to_timestamp(1796185259), 'of two cancels of one time, the later one wins';
  ASSERT o.provider_subscription_ref = '9106', 'the subscription ref of the earlier event stays';

  ASSERT pg_temp.t_paid('8107', 1607) = 'applied', 'the paid event of an order with events of another provider answers applied';
  o := pg_temp.t_bo('8107');
  ASSERT o.status = 'paid' AND o.expires_at IS NULL AND o.provider_updated_at IS NULL AND o.provider_subscription_ref IS NULL,
         'the events of another provider do not count';
  ASSERT pg_temp.t_paid('8108', 1608) = 'applied', 'the paid event of an order with no event of its own answers applied';
  o := pg_temp.t_bo('8108');
  ASSERT o.status = 'paid' AND o.expires_at IS NULL AND o.provider_updated_at IS NULL AND o.provider_subscription_ref IS NULL,
         'the events of another ref do not count';
  ASSERT o.claimable_until = now() + interval '24 hours', 'an order with no earlier event can be claimed for 24 hours';
  ASSERT api.fn_billing_claim(pg_temp.t_uuid('a', 1608), pg_temp.t_billing_hash(1608)) = 'claimed', 'an order with no earlier event is claimed';
  ASSERT (pg_temp.t_ak(pg_temp.t_billing_hash(1608))).expires_at IS NULL, 'its key has no expiry';
  ASSERT pg_temp.t_paid('8110', 1610) = 'applied', 'the paid event of a partly refunded order answers applied';
  ASSERT api.fn_billing_claim(pg_temp.t_uuid('a', 1610), pg_temp.t_billing_hash(1610)) = 'claimed',
         'a partial refund before the paid event does not revoke the order';

  ASSERT pg_temp.t_paid('8111', 1611) = 'applied', 'the paid event of an order with a lone resume answers applied';
  o := pg_temp.t_bo('8111');
  ASSERT o.status = 'paid' AND o.expires_at IS NULL AND o.provider_updated_at = to_timestamp(1793506871),
         'the paid order carries the time of the lone resume';
  ASSERT o.provider_subscription_ref = '9111', 'the paid order carries the subscription ref of the lone resume';

  ASSERT pg_temp.t_paid('8112', 1612) = 'applied', 'the paid event of an order with two cancels of one time and one arrival answers applied';
  o := pg_temp.t_bo('8112');
  ASSERT o.expires_at = to_timestamp(1796185273), 'of two cancels of one time and one arrival, the higher event id wins';
END
$$;

DO $$
DECLARE
  o billing_orders;
BEGIN
  ASSERT api.fn_billing_lemonsqueezy_set_expiry(pg_temp.t_uuid('e', 1691), '8113', '9113', 1577836800, 1580515200) = 'unknown',
         'the past cancel of 8113 answers unknown';
  ASSERT api.fn_billing_lemonsqueezy_revoke(pg_temp.t_uuid('e', 1692), 'subscription_expired', '8113') = 'unknown',
         'the expiry of 8113 answers unknown';
  ASSERT pg_temp.t_paid('8113', 1613) = 'applied', 'the paid event of an order expired with a past cancel expiry answers applied';
  o := pg_temp.t_bo('8113');
  ASSERT o.status = 'revoked' AND o.expires_at = to_timestamp(1580515200) AND o.provider_updated_at = to_timestamp(1577836800),
         'a revoked order keeps the past expiry and the time of its cancel';
END
$$;
