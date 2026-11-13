CREATE OR REPLACE FUNCTION pg_temp.t_billing_hash(p_n integer) RETURNS text LANGUAGE sql AS $$
  SELECT 'b1' || lpad(to_hex(p_n), 62, '0')
$$;
CREATE OR REPLACE FUNCTION pg_temp.t_uuid(p_kind text, p_n integer) RETURNS text LANGUAGE sql AS $$
  SELECT p_kind || '0000000-0000-4000-8000-' || lpad(p_n::text, 12, '0')
$$;
CREATE OR REPLACE FUNCTION pg_temp.t_ak(p_hash text) RETURNS api_keys LANGUAGE sql AS $$
  SELECT * FROM api_keys AS ak WHERE ak.key_hash = p_hash
$$;
CREATE OR REPLACE FUNCTION pg_temp.t_manual_bo(p_ref text) RETURNS billing_orders LANGUAGE sql AS $$
  SELECT * FROM billing_orders AS bo WHERE bo.provider = 'manual' AND bo.provider_order_ref = p_ref
$$;

SELECT api.fn_billing_lemonsqueezy_order_paid(pg_temp.t_uuid('e', 4002), pg_temp.t_uuid('a', 4002), '8702');
SELECT api.fn_billing_claim(pg_temp.t_uuid('a', 4002), pg_temp.t_billing_hash(4002));

DO $$
DECLARE
  key_count     bigint := (SELECT count(*) FROM api_keys);
  order_count   bigint := (SELECT count(*) FROM billing_orders);
  granted_key   api_keys;
  granted_order billing_orders;
BEGIN
  ASSERT api.fn_billing_manual_key_grant('8701', pg_temp.t_billing_hash(4001)) = 'granted', 'a new ref answers granted';
  granted_key   := pg_temp.t_ak(pg_temp.t_billing_hash(4001));
  granted_order := pg_temp.t_manual_bo('8701');
  ASSERT (SELECT count(*) FROM api_keys) = key_count + 1, 'a grant writes one key row';
  ASSERT (SELECT count(*) FROM billing_orders) = order_count + 1, 'a grant writes one order row';
  ASSERT granted_key.active AND granted_key.expires_at IS NULL, 'the granted key is active and never expires';
  ASSERT granted_order.status = 'claimed' AND granted_order.api_key_id = granted_key.id,
         'the manual order 8701 is claimed by the granted key';
  ASSERT granted_order.claimed_at = now(), 'the order is claimed now';
  ASSERT granted_order.order_id IS NULL AND granted_order.claimable_until IS NULL,
         'the order has no claim UUID and no claim window';
  ASSERT granted_order.expires_at IS NULL AND granted_order.provider_subscription_ref IS NULL
         AND granted_order.provider_updated_at IS NULL,
         'the order has no expiry and no subscription';
  ASSERT (SELECT s.api_key_state = 'active' AND s.key_expires_at IS NULL
            FROM api.fn_api_key_state(pg_temp.t_billing_hash(4001)) AS s),
         'api.fn_api_key_state reads the granted key as active with no expiry';
END
$$;

DO $$
DECLARE
  order_before billing_orders := pg_temp.t_manual_bo('8701');
  key_count    bigint         := (SELECT count(*) FROM api_keys);
BEGIN
  ASSERT api.fn_billing_manual_key_grant('8701', pg_temp.t_billing_hash(4004)) = 'exists',
         'a ref of a manual order answers exists';
  ASSERT (pg_temp.t_ak(pg_temp.t_billing_hash(4004))).id IS NULL, 'exists writes no key with the new hash';
  ASSERT (SELECT count(*) FROM api_keys) = key_count, 'exists writes no key row';
  ASSERT pg_temp.t_manual_bo('8701') IS NOT DISTINCT FROM order_before, 'exists leaves the order as it was';
END
$$;

DO $$
DECLARE
  decoy_before billing_orders;
  decoy_after  billing_orders;
BEGIN
  SELECT * INTO decoy_before FROM billing_orders AS bo WHERE bo.provider = 'lemonsqueezy' AND bo.provider_order_ref = '8702';
  ASSERT decoy_before.status = 'claimed' AND decoy_before.api_key_id = (pg_temp.t_ak(pg_temp.t_billing_hash(4002))).id,
         'the fixture: the Lemon Squeezy order 8702 is claimed by the key of the hash 4002';
  ASSERT api.fn_billing_manual_key_grant('8702', pg_temp.t_billing_hash(4003)) = 'granted',
         'a Lemon Squeezy order with the same ref is another order';
  ASSERT (pg_temp.t_manual_bo('8702')).api_key_id = (pg_temp.t_ak(pg_temp.t_billing_hash(4003))).id,
         'the manual order 8702 is tied to the key of the hash 4003';
  SELECT * INTO decoy_after FROM billing_orders AS bo WHERE bo.provider = 'lemonsqueezy' AND bo.provider_order_ref = '8702';
  ASSERT decoy_after IS NOT DISTINCT FROM decoy_before, 'the Lemon Squeezy order 8702 stays as it was';
END
$$;

SELECT api.fn_billing_nowpayments_order_paid('paid:8703', 'finished', pg_temp.t_uuid('a', 4010)::uuid, '8703');
DO $$
DECLARE
  decoy_before billing_orders;
  decoy_after  billing_orders;
BEGIN
  SELECT * INTO decoy_before FROM billing_orders AS bo WHERE bo.provider = 'nowpayments' AND bo.provider_order_ref = '8703';
  ASSERT decoy_before.status = 'paid', 'the fixture: the NOWPayments order 8703 is paid';
  ASSERT api.fn_billing_manual_key_grant('8703', pg_temp.t_billing_hash(4010)) = 'granted',
         'a NOWPayments order with the same ref is another order';
  ASSERT (pg_temp.t_manual_bo('8703')).api_key_id = (pg_temp.t_ak(pg_temp.t_billing_hash(4010))).id,
         'the manual order 8703 is tied to the key of the hash 4010';
  SELECT * INTO decoy_after FROM billing_orders AS bo WHERE bo.provider = 'nowpayments' AND bo.provider_order_ref = '8703';
  ASSERT decoy_after IS NOT DISTINCT FROM decoy_before, 'the NOWPayments order 8703 stays as it was';
END
$$;

DO $$
DECLARE
  is_refused boolean := false;
BEGIN
  ASSERT api.fn_billing_manual_key_grant(NULL, pg_temp.t_billing_hash(4005)) IS NULL, 'a NULL ref answers NULL';
  ASSERT api.fn_billing_manual_key_grant('8705', NULL) IS NULL, 'a NULL hash answers NULL';
  ASSERT (pg_temp.t_ak(pg_temp.t_billing_hash(4005))).id IS NULL
         AND (pg_temp.t_manual_bo('8705')).billing_order_id IS NULL,
         'a NULL argument writes nothing';
  BEGIN
    PERFORM api.fn_billing_manual_key_grant('8706', upper(pg_temp.t_billing_hash(4006)));
  EXCEPTION WHEN check_violation THEN
    is_refused := true;
  END;
  ASSERT is_refused, 'an uppercase hash fails the CHECK of api_keys';
  ASSERT (pg_temp.t_manual_bo('8706')).billing_order_id IS NULL, 'a refused hash writes no order';
END
$$;

CREATE OR REPLACE FUNCTION pg_temp.t_manual_lock_held(p_provider text, p_ref text) RETURNS boolean LANGUAGE sql AS $$
  SELECT EXISTS (SELECT FROM pg_locks AS l
                  WHERE l.locktype = 'advisory' AND l.objsubid = 2 AND l.pid = pg_backend_pid()
                    AND l.classid::bigint = (hashtext(p_provider)::bigint & 4294967295) AND l.objid::bigint = (hashtext(p_ref)::bigint & 4294967295))
$$;
DO $$
BEGIN
  ASSERT NOT pg_temp.t_manual_lock_held('manual', '8709'), 'no lock before';
  ASSERT api.fn_billing_manual_key_grant('8709', pg_temp.t_billing_hash(4009)) = 'granted', 'the grant of 8709 answers granted';
  ASSERT pg_temp.t_manual_lock_held('manual', '8709'), 'the grant takes the order ref lock of the provider manual and its ref';
  ASSERT NOT pg_temp.t_manual_lock_held('lemonsqueezy', '8709'), 'the lock names the provider manual';
  ASSERT NOT pg_advisory_unlock(hashtext('manual'), hashtext('8709')), 'the order ref lock is a transaction lock';
END
$$;

INSERT INTO vendor_key (api_key_id, vendor_name, sealed_hex)
  SELECT ak.id, 'shodan', repeat('40', 40) FROM api_keys AS ak WHERE ak.key_hash = pg_temp.t_billing_hash(4001);
DO $$
DECLARE
  key_before  api_keys := pg_temp.t_ak(pg_temp.t_billing_hash(4001));
  regenerated record;
BEGIN
  SELECT * INTO regenerated FROM api.fn_billing_regenerate_key('manual', '8701');
  ASSERT regenerated.regenerate_status = 'regenerating' AND regenerated.claim_order_id IS NOT NULL,
         'a regenerate of a granted key answers regenerating with a claim UUID';
  ASSERT (pg_temp.t_ak(pg_temp.t_billing_hash(4001))).id IS NULL, 'the old hash stops at once';
  ASSERT api.fn_billing_claim(regenerated.claim_order_id, pg_temp.t_billing_hash(4007)) = 'claimed',
         'the claim of the new UUID answers claimed';
  ASSERT (pg_temp.t_ak(pg_temp.t_billing_hash(4007))).id = key_before.id, 'the new hash is on the same key row';
  ASSERT (pg_temp.t_manual_bo('8701')).status = 'claimed', 'the order is claimed again';
  ASSERT (SELECT count(*) FROM vendor_key AS vk WHERE vk.api_key_id = key_before.id) = 1,
         'the vendor key stays with the key row';
END
$$;

DO $$
DECLARE
  key_id integer := (pg_temp.t_ak(pg_temp.t_billing_hash(4007))).id;
BEGIN
  ASSERT api.fn_billing_delete_key('manual', '8701') = 'deleted', 'a delete of a granted key answers deleted';
  ASSERT NOT EXISTS (SELECT FROM api_keys AS ak WHERE ak.id = key_id), 'the key row is deleted';
  ASSERT NOT EXISTS (SELECT FROM vendor_key AS vk WHERE vk.api_key_id = key_id), 'its vendor key is deleted with it';
  ASSERT (pg_temp.t_manual_bo('8701')).status = 'revoked' AND (pg_temp.t_manual_bo('8701')).api_key_id IS NULL,
         'the order stays revoked with no key';
  ASSERT api.fn_billing_manual_key_grant('8701', pg_temp.t_billing_hash(4008)) = 'exists',
         'a grant of the ref of a revoked order answers exists';
  ASSERT (pg_temp.t_ak(pg_temp.t_billing_hash(4008))).id IS NULL, 'that grant writes no key';
END
$$;

DO $$
DECLARE
  f   regprocedure := 'api.fn_billing_manual_key_grant(text, text)'::regprocedure;
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
