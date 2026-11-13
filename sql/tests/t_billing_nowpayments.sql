CREATE OR REPLACE FUNCTION pg_temp.t_billing_hash(p_n integer) RETURNS text LANGUAGE sql AS $$
  SELECT 'b1' || lpad(to_hex(p_n), 62, '0')
$$;
CREATE OR REPLACE FUNCTION pg_temp.t_uuid(p_kind text, p_n integer) RETURNS text LANGUAGE sql AS $$
  SELECT p_kind || '0000000-0000-4000-8000-' || lpad(p_n::text, 12, '0')
$$;
CREATE OR REPLACE FUNCTION pg_temp.t_bo(p_provider text, p_ref text) RETURNS billing_orders LANGUAGE sql AS $$
  SELECT * FROM billing_orders AS bo WHERE bo.provider = p_provider AND bo.provider_order_ref = p_ref
$$;
CREATE OR REPLACE FUNCTION pg_temp.t_be(p_ref text) RETURNS billing_events LANGUAGE sql AS $$
  SELECT * FROM billing_events AS be WHERE be.provider = 'nowpayments' AND be.provider_event_ref = p_ref
$$;
CREATE OR REPLACE FUNCTION pg_temp.t_ak(p_hash text) RETURNS api_keys LANGUAGE sql AS $$
  SELECT * FROM api_keys AS ak WHERE ak.key_hash = p_hash
$$;
CREATE OR REPLACE FUNCTION pg_temp.t_paid(p_ref text, p_name text, p_n integer) RETURNS text LANGUAGE sql AS $$
  SELECT api.fn_billing_nowpayments_order_paid('paid:' || p_ref, p_name, pg_temp.t_uuid('a', p_n)::uuid, p_ref)
$$;

PREPARE t_np_query AS SELECT api.fn_billing_nowpayments_order_paid($1, $2, $3, $4) AS billing_event_status;
CREATE TEMP TABLE t_np_answer AS
  EXECUTE t_np_query('paid:9000', 'finished', pg_temp.t_uuid('a', 3000)::uuid, '9000');
DEALLOCATE t_np_query;
DO $$
BEGIN
  ASSERT (SELECT array_agg(attname::text || ' ' || format_type(atttypid, atttypmod) ORDER BY attnum) FROM pg_attribute
           WHERE attrelid = 't_np_answer'::regclass AND attnum > 0)
         = ARRAY['billing_event_status text'], 'the call db.c sends answers one text column';
  ASSERT (SELECT array_agg(billing_event_status) FROM t_np_answer) = ARRAY['applied'], 'a new order answers applied';
END
$$;

DO $$
DECLARE
  o billing_orders;
  e billing_events;
BEGIN
  ASSERT pg_temp.t_paid('9001', 'finished', 3001) = 'applied', 'a new invoice answers applied';
  o := pg_temp.t_bo('nowpayments', '9001');
  e := pg_temp.t_be('paid:9001');
  ASSERT o.provider = 'nowpayments' AND o.provider_order_ref = '9001' AND o.order_id = pg_temp.t_uuid('a', 3001),
         'the order holds the provider, the ref and the claim UUID';
  ASSERT o.status = 'paid' AND o.api_key_id IS NULL AND o.claimed_at IS NULL, 'the order is paid, with no key yet';
  ASSERT o.claimable_until = now() + interval '24 hours', 'the order can be claimed for 24 hours';
  ASSERT o.expires_at = now() + interval '30 days', 'the order expires after 30 days';
  ASSERT o.provider_subscription_ref IS NULL AND o.provider_updated_at IS NULL, 'an IPN stores no subscription';
  ASSERT e.provider_event_ref = 'paid:9001' AND e.event_name = 'finished' AND e.provider_order_ref = '9001'
         AND e.billing_action = 'order_paid' AND e.provider_updated_at IS NULL AND e.expires_at IS NULL,
         'the event holds the ref, the name, the order ref and its action';

  ASSERT pg_temp.t_paid('9002', 'partially_paid', 3002) = 'applied', 'a tolerated partial payment answers applied';
  ASSERT (pg_temp.t_be('paid:9002')).event_name = 'partially_paid', 'the event keeps the name it came with';
END
$$;

DO $$
DECLARE
  o billing_orders := pg_temp.t_bo('nowpayments', '9001');
  order_count bigint := (SELECT count(*) FROM billing_orders);
BEGIN
  ASSERT pg_temp.t_paid('9001', 'partially_paid', 3099) = 'duplicate', 'one invoice is one event, whatever its name';
  ASSERT pg_temp.t_bo('nowpayments', '9001') IS NOT DISTINCT FROM o, 'a duplicate leaves the order';
  ASSERT (pg_temp.t_be('paid:9001')).event_name = 'finished', 'a duplicate leaves the event';
  ASSERT (SELECT count(*) FROM billing_orders) = order_count, 'a duplicate adds no order';
  ASSERT (SELECT count(*) FROM billing_orders AS bo WHERE bo.order_id = pg_temp.t_uuid('a', 3099)) = 0, 'a duplicate stores no claim UUID';
END
$$;

DO $$
BEGIN
  ASSERT api.fn_billing_nowpayments_order_paid('paid:other-3003', 'finished', pg_temp.t_uuid('a', 3001)::uuid, 'other-3003') = 'exists',
         'a claim UUID in use answers exists';
  ASSERT pg_temp.t_bo('nowpayments', 'other-3003') IS NULL, 'exists writes no order';
  ASSERT (pg_temp.t_be('paid:other-3003')).provider_order_ref = 'other-3003', 'exists keeps the event';

  ASSERT api.fn_billing_nowpayments_order_paid('paid:other-3004', 'finished', pg_temp.t_uuid('a', 3004)::uuid, '9001') = 'exists',
         'a ref in use answers exists';
  ASSERT (pg_temp.t_bo('nowpayments', '9001')).order_id = pg_temp.t_uuid('a', 3001), 'exists leaves the first claim UUID';
  ASSERT (SELECT count(*) FROM billing_orders AS bo WHERE bo.order_id = pg_temp.t_uuid('a', 3004)) = 0, 'a ref in use stores no claim UUID';
END
$$;

DO $$
DECLARE
  ak api_keys;
BEGIN
  ASSERT api.fn_billing_claim(pg_temp.t_uuid('a', 3001), pg_temp.t_billing_hash(3001)) = 'claimed', 'a paid order is claimed';
  ak := pg_temp.t_ak(pg_temp.t_billing_hash(3001));
  ASSERT ak.expires_at = now() + interval '30 days', 'the claim copies the 30-day expiry to the key';
  ASSERT (pg_temp.t_bo('nowpayments', '9001')).status = 'claimed' AND (pg_temp.t_bo('nowpayments', '9001')).api_key_id = ak.id,
         'the order holds the key';

  PERFORM pg_temp.t_paid('9005', 'finished', 3005);
  UPDATE billing_orders AS bo SET claimable_until = now() WHERE bo.provider = 'nowpayments' AND bo.provider_order_ref = '9005';
  ASSERT api.fn_billing_claim(pg_temp.t_uuid('a', 3005), pg_temp.t_billing_hash(3005)) = 'lapsed', 'the window has ended at now()';
END
$$;

DO $$
DECLARE
  ls_before billing_orders;
BEGIN
  PERFORM api.fn_billing_lemonsqueezy_order_paid(pg_temp.t_uuid('e', 3010), pg_temp.t_uuid('a', 3010), '9010');
  ls_before := pg_temp.t_bo('lemonsqueezy', '9010');
  ASSERT pg_temp.t_paid('9010', 'finished', 3011) = 'applied', 'a NOWPayments ref does not meet a Lemon Squeezy order of that ref';
  ASSERT pg_temp.t_bo('lemonsqueezy', '9010') IS NOT DISTINCT FROM ls_before, 'the Lemon Squeezy order stays';
  ASSERT (pg_temp.t_bo('nowpayments', '9010')).order_id = pg_temp.t_uuid('a', 3011), 'the NOWPayments order is its own row';
  ASSERT pg_temp.t_paid('9010', 'finished', 3012) = 'duplicate', 'the event belongs to the provider';
  ASSERT (SELECT count(*) FROM billing_events AS be WHERE be.provider = 'lemonsqueezy' AND be.provider_order_ref = '9010') = 1,
         'the IPN event is not the Lemon Squeezy event';
END
$$;

DO $$
DECLARE
  answer text;
BEGIN
  PERFORM pg_temp.t_paid('9020', 'finished', 3020);
  PERFORM api.fn_billing_claim(pg_temp.t_uuid('a', 3020), pg_temp.t_billing_hash(3020));
  SELECT r.regenerate_status INTO answer FROM api.fn_billing_regenerate_key('nowpayments', '9020') AS r;
  ASSERT answer = 'regenerating', 'a claimed order of the provider nowpayments regenerates';
  ASSERT (pg_temp.t_bo('nowpayments', '9020')).status = 'regenerating', 'the order is regenerating';
END
$$;

CREATE OR REPLACE FUNCTION pg_temp.t_np_lock_held(p_provider text, p_ref text) RETURNS boolean LANGUAGE sql AS $$
  SELECT EXISTS (SELECT FROM pg_locks AS l
                  WHERE l.locktype = 'advisory' AND l.objsubid = 2 AND l.pid = pg_backend_pid()
                    AND l.classid::bigint = (hashtext(p_provider)::bigint & 4294967295) AND l.objid::bigint = (hashtext(p_ref)::bigint & 4294967295))
$$;
DO $$
BEGIN
  ASSERT NOT pg_temp.t_np_lock_held('nowpayments', '9030'), 'no lock before';
  PERFORM pg_temp.t_paid('9030', 'finished', 3030);
  ASSERT pg_temp.t_np_lock_held('nowpayments', '9030'), 'the writer takes the order ref lock of its provider and ref';
  ASSERT NOT pg_temp.t_np_lock_held('lemonsqueezy', '9030'), 'the lock names the provider nowpayments';
END
$$;

DO $$
BEGIN
  ASSERT NOT pg_advisory_unlock(hashtext('nowpayments'), hashtext('9030')), 'the order ref lock is a transaction lock, a session lock would outlive the call';
END
$$;

DO $$
BEGIN
  ASSERT pg_temp.t_paid('9031', 'finished', 3031) = 'applied', 'first';
  DELETE FROM billing_orders AS bo WHERE bo.provider = 'nowpayments' AND bo.provider_order_ref = '9031';
  ASSERT pg_temp.t_paid('9031', 'finished', 3032) = 'duplicate', 'a repeated IPN of a removed order is a duplicate';
  ASSERT pg_temp.t_bo('nowpayments', '9031') IS NULL, 'a duplicate event writes no order';
END
$$;

DO $$
BEGIN
  ASSERT api.fn_billing_nowpayments_order_paid('paid:9033', 'finished', pg_temp.t_uuid('a', 3001)::uuid, '9033') = 'exists', 'uuid in use';
  ASSERT api.fn_billing_nowpayments_order_paid('paid:9033', 'finished', pg_temp.t_uuid('a', 3033)::uuid, '9033') = 'duplicate', 'the retry is a duplicate';
  ASSERT pg_temp.t_bo('nowpayments', '9033') IS NULL, 'a duplicate event writes no order';
END
$$;

DO $$
DECLARE
  f regprocedure := 'api.fn_billing_nowpayments_order_paid(text, text, uuid, text)'::regprocedure;
BEGIN
  ASSERT (SELECT p.prosecdef FROM pg_proc AS p WHERE p.oid = f), 'it is SECURITY DEFINER';
  ASSERT (SELECT p.proconfig FROM pg_proc AS p WHERE p.oid = f) = ARRAY['search_path=pg_catalog'], 'it sets search_path to pg_catalog';
  ASSERT (SELECT p.proisstrict FROM pg_proc AS p WHERE p.oid = f), 'a NULL argument answers NULL';
  ASSERT (SELECT p.provolatile FROM pg_proc AS p WHERE p.oid = f) = 'v', 'it is VOLATILE';
  ASSERT (SELECT p.prorettype FROM pg_proc AS p WHERE p.oid = f) = 'text'::regtype, 'it answers text';
  ASSERT (SELECT l.lanname::text FROM pg_proc AS p JOIN pg_language AS l ON l.oid = p.prolang WHERE p.oid = f) = 'sql', 'it is SQL-standard';
  ASSERT has_function_privilege('contrastapi-api', f, 'EXECUTE'), 'the API role may call it';
  ASSERT NOT has_function_privilege('public', f, 'EXECUTE'), 'PUBLIC may not call it';
  ASSERT api.fn_billing_nowpayments_order_paid(NULL, 'finished', pg_temp.t_uuid('a', 3040)::uuid, '9040') IS NULL, 'a NULL ref writes nothing';
  ASSERT pg_temp.t_bo('nowpayments', '9040') IS NULL, 'a NULL event ref wrote no order';
END
$$;
