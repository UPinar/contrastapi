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

SELECT api.fn_billing_lemonsqueezy_order_paid(pg_temp.t_uuid('e', 2501), pg_temp.t_uuid('a', 2501), '8501');
SELECT api.fn_billing_lemonsqueezy_order_paid(pg_temp.t_uuid('e', 2502), pg_temp.t_uuid('a', 2502), '8502');
SELECT api.fn_billing_claim(pg_temp.t_uuid('a', 2502), pg_temp.t_billing_hash(2502));
INSERT INTO watchlist_item (api_key_id, endpoint_name)
  SELECT ak.id, 'cve_lookup' FROM api_keys AS ak WHERE ak.key_hash = pg_temp.t_billing_hash(2502);
INSERT INTO watchlist_event_ref (api_key_id, item_id, event_id)
  SELECT wi.api_key_id, wi.item_id, 1
    FROM watchlist_item AS wi JOIN api_keys AS ak ON ak.id = wi.api_key_id
   WHERE ak.key_hash = pg_temp.t_billing_hash(2502);
INSERT INTO vendor_key (api_key_id, vendor_name, sealed_hex)
  SELECT ak.id, 'shodan', repeat('25', 40) FROM api_keys AS ak WHERE ak.key_hash = pg_temp.t_billing_hash(2502);
INSERT INTO vendor_key_link (link_hash, api_key_id, key_fingerprint, expires_at)
  SELECT pg_temp.t_billing_hash(2602), ak.id, repeat('a', 32), now() + interval '1 hour'
    FROM api_keys AS ak WHERE ak.key_hash = pg_temp.t_billing_hash(2502);

INSERT INTO api_keys (key_hash) VALUES (pg_temp.t_billing_hash(2503));
INSERT INTO billing_orders (provider, provider_order_ref, status, claimed_at, api_key_id)
  SELECT 'manual', '8502', 'claimed', now(), ak.id FROM api_keys AS ak WHERE ak.key_hash = pg_temp.t_billing_hash(2503);

DO $$
DECLARE
  paid_before billing_orders := pg_temp.t_bo('8501');
  key_count   bigint         := (SELECT count(*) FROM api_keys);
BEGIN
  ASSERT api.fn_billing_delete_key('lemonsqueezy', '8599') = 'unknown', 'a ref of no order answers unknown';
  ASSERT api.fn_billing_delete_key('nowpayments', '8501') = 'unknown', 'a ref of another provider answers unknown';
  ASSERT api.fn_billing_delete_key('lemonsqueezy', '8501') = 'no_key', 'a paid order answers no_key';
  ASSERT pg_temp.t_bo('8501') IS NOT DISTINCT FROM paid_before, 'a paid order stays as it was after no_key';
  ASSERT (SELECT count(*) FROM api_keys) = key_count, 'unknown and no_key delete no key row';
  ASSERT api.fn_billing_delete_key(NULL, '8501') IS NULL, 'a NULL provider answers NULL';
  ASSERT api.fn_billing_delete_key('lemonsqueezy', NULL) IS NULL, 'a NULL ref answers NULL';
END
$$;

DO $$
DECLARE
  order_before billing_orders := pg_temp.t_bo('8502');
  key_before   api_keys       := pg_temp.t_ak(pg_temp.t_billing_hash(2502));
  order_after  billing_orders;
BEGIN
  ASSERT key_before.id IS NOT NULL AND order_before.api_key_id = key_before.id AND order_before.status = 'claimed',
         'the fixture: the order 8502 is claimed by the key of the hash 2502';
  ASSERT (SELECT count(*) FROM watchlist_item AS wi WHERE wi.api_key_id = key_before.id) = 1
         AND (SELECT count(*) FROM vendor_key AS vk WHERE vk.api_key_id = key_before.id) = 1
         AND (SELECT count(*) FROM vendor_key_link AS vl WHERE vl.api_key_id = key_before.id) = 1,
         'the fixture: the key holds a watch list item, a vendor key and a manage link';

  ASSERT api.fn_billing_delete_key('lemonsqueezy', '8502') = 'deleted', 'a claimed order answers deleted';
  order_after := pg_temp.t_bo('8502');
  ASSERT NOT EXISTS (SELECT FROM api_keys AS ak WHERE ak.id = key_before.id), 'the key row of the order is deleted';
  ASSERT NOT EXISTS (SELECT FROM watchlist_item AS wi WHERE wi.api_key_id = key_before.id), 'the watch list item of the key is deleted';
  ASSERT NOT EXISTS (SELECT FROM watchlist_event_ref AS er WHERE er.api_key_id = key_before.id), 'the event ref of the key is deleted';
  ASSERT NOT EXISTS (SELECT FROM vendor_key AS vk WHERE vk.api_key_id = key_before.id), 'the vendor key of the key is deleted';
  ASSERT NOT EXISTS (SELECT FROM vendor_key_link AS vl WHERE vl.api_key_id = key_before.id), 'the manage link of the key is deleted';
  ASSERT order_after.billing_order_id IS NOT NULL, 'the order row stays after its key is deleted';
  ASSERT order_after.status = 'revoked', 'the order row is revoked';
  ASSERT order_after.api_key_id IS NULL, 'the order row holds no key';
  ASSERT order_after.claimed_at IS NULL, 'the order row has no claim time';
  ASSERT order_after.order_id = order_before.order_id AND order_after.order_id = pg_temp.t_uuid('a', 2502),
         'the order row keeps its claim UUID';
  ASSERT order_after.provider_order_ref = '8502' AND order_after.billing_order_id = order_before.billing_order_id,
         'the order row keeps its ref and its id';
  ASSERT order_after.provider_subscription_ref IS NOT DISTINCT FROM order_before.provider_subscription_ref,
         'the order row keeps its subscription ref';
  ASSERT order_after.expires_at = now(), 'an order with no expiry expires at now()';

  ASSERT api.fn_billing_delete_key('lemonsqueezy', '8502') = 'no_key', 'a second delete of the same order answers no_key';
  ASSERT pg_temp.t_bo('8502') IS NOT DISTINCT FROM order_after, 'a second delete leaves the order row as it was';
END
$$;

DO $$
DECLARE
  key_count   bigint         := (SELECT count(*) FROM api_keys);
  order_count bigint         := (SELECT count(*) FROM billing_orders);
  order_after billing_orders := pg_temp.t_bo('8502');
BEGIN
  ASSERT api.fn_billing_lemonsqueezy_order_paid(pg_temp.t_uuid('e', 2652), pg_temp.t_uuid('a', 2502), '8502') = 'exists',
         'a replayed paid event of a deleted key answers exists';
  DELETE FROM billing_events AS be WHERE be.provider = 'lemonsqueezy' AND be.provider_event_ref = pg_temp.t_uuid('e', 2502);
  ASSERT api.fn_billing_lemonsqueezy_order_paid(pg_temp.t_uuid('e', 2502), pg_temp.t_uuid('a', 2502), '8502') = 'exists',
         'a replayed paid event whose event row was purged answers exists';
  ASSERT (SELECT count(*) FROM billing_orders) = order_count, 'a replayed paid event writes no order';
  ASSERT pg_temp.t_bo('8502') IS NOT DISTINCT FROM order_after, 'a replayed paid event leaves the order row as it was';
  ASSERT api.fn_billing_claim(pg_temp.t_uuid('a', 2502), pg_temp.t_billing_hash(2552)) = 'revoked',
         'a claim of the claim UUID of a deleted key answers revoked';
  ASSERT (pg_temp.t_ak(pg_temp.t_billing_hash(2552))).id IS NULL, 'a claim of a deleted key writes no key';
  ASSERT (SELECT count(*) FROM api_keys) = key_count, 'a replay and a claim write no key row';
END
$$;

DO $$
DECLARE
  past_expiry timestamptz := now() - interval '3 days';
BEGIN
  PERFORM api.fn_billing_lemonsqueezy_order_paid(pg_temp.t_uuid('e', 2510), pg_temp.t_uuid('a', 2510), '8510');
  PERFORM api.fn_billing_claim(pg_temp.t_uuid('a', 2510), pg_temp.t_billing_hash(2510));
  UPDATE billing_orders SET expires_at = past_expiry, provider_subscription_ref = '25100' WHERE provider_order_ref = '8510';
  ASSERT api.fn_billing_delete_key('lemonsqueezy', '8510') = 'deleted', 'the expired order 8510 answers deleted';
  ASSERT (pg_temp.t_bo('8510')).expires_at = past_expiry, 'an expiry in the past stays';
  ASSERT (pg_temp.t_bo('8510')).provider_subscription_ref = '25100', 'the subscription ref stays';
  ASSERT api.fn_billing_lemonsqueezy_revoke(pg_temp.t_uuid('e', 2610), 'order_refunded', '8510') = 'revoked',
         'a refund of a deleted key answers revoked';
  ASSERT (pg_temp.t_bo('8510')).status = 'revoked' AND (pg_temp.t_bo('8510')).api_key_id IS NULL,
         'a refund of a deleted key leaves the order revoked with no key';
END
$$;

DO $$
DECLARE
  decoy_key api_keys := pg_temp.t_ak(pg_temp.t_billing_hash(2503));
BEGIN
  ASSERT decoy_key.id IS NOT NULL, 'the key of the manual order 8502 stays';
  ASSERT (SELECT bo.status = 'claimed' AND bo.api_key_id = decoy_key.id FROM billing_orders AS bo
           WHERE bo.provider = 'manual' AND bo.provider_order_ref = '8502'),
         'the manual order 8502 stays claimed by its key';
  ASSERT api.fn_billing_delete_key('manual', '8502') = 'deleted', 'the manual order answers deleted for its own provider';
  ASSERT (pg_temp.t_ak(pg_temp.t_billing_hash(2503))).id IS NULL, 'a delete for the provider manual deletes the manual key';
END
$$;

DO $$
DECLARE
  f   regprocedure := 'api.fn_billing_delete_key(text, text)'::regprocedure;
  r   text;
BEGIN
  ASSERT (SELECT NOT p.prosecdef FROM pg_proc AS p WHERE p.oid = f), f::text || ' is SECURITY INVOKER';
  ASSERT (SELECT p.proconfig FROM pg_proc AS p WHERE p.oid = f) = ARRAY['search_path=pg_catalog'],
         f::text || ' sets search_path to pg_catalog';
  ASSERT (SELECT p.provolatile FROM pg_proc AS p WHERE p.oid = f) = 'v', f::text || ' is VOLATILE';
  ASSERT (SELECT p.proisstrict FROM pg_proc AS p WHERE p.oid = f), f::text || ' is STRICT';
  ASSERT (SELECT l.lanname::text FROM pg_proc AS p JOIN pg_language AS l ON l.oid = p.prolang WHERE p.oid = f) = 'plpgsql',
         f::text || ' is plpgsql';
  ASSERT (SELECT p.prorettype FROM pg_proc AS p WHERE p.oid = f) = 'text'::regtype, f::text || ' answers text';
  ASSERT NOT has_function_privilege('public', f, 'EXECUTE'), 'PUBLIC may not call ' || f::text;
  FOREACH r IN ARRAY ARRAY['contrastapi-api', 'contrastapi-web', 'contrastapi-sync'] LOOP
    ASSERT NOT has_function_privilege(r, f, 'EXECUTE'), r || ' may not call ' || f::text;
  END LOOP;
END
$$;
