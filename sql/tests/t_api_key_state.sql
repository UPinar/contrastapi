INSERT INTO api_keys (key_hash, active, expires_at) VALUES
  (repeat('a', 64), true,  NULL),
  (repeat('b', 64), false, NULL),
  (repeat('c', 64), true,  now() - interval '1 second'),
  (repeat('d', 64), true,  now() + interval '1 day'),
  (repeat('e', 64), true,  now()),
  (repeat('f', 64), false, now() + interval '1 day'),
  (repeat('1', 64), true,  '2100-01-01 00:00:00.75+00'),
  (repeat('2', 64), false, '1969-12-31 23:59:59.25+00');

CREATE FUNCTION pg_temp.t_api_key_answer(p_key_hash text) RETURNS text LANGUAGE sql AS $$
  SELECT coalesce(string_agg(s.api_key_state || '|' || coalesce(s.key_expires_at::text, 'null'), ','), '')
    FROM api.fn_api_key_state(p_key_hash) AS s
$$;

CREATE FUNCTION pg_temp.t_epoch(p_moment timestamptz) RETURNS text LANGUAGE sql AS $$
  SELECT floor(extract(epoch FROM p_moment))::bigint::text
$$;

CREATE TEMP VIEW t_api_key_state_call AS
  SELECT * FROM api.fn_api_key_state(repeat('a', 64));

DO $$
BEGIN
  ASSERT api.fn_api_key_is_active(true, NULL),                         'an active key with no expiry is active';
  ASSERT NOT api.fn_api_key_is_active(false, NULL),                    'a revoked key with no expiry is not active';
  ASSERT api.fn_api_key_is_active(true, now() + interval '1 second'),  'an active key that expires in a second is active';
  ASSERT NOT api.fn_api_key_is_active(true, now()),                    'an active key that expires at now() is not active';
  ASSERT NOT api.fn_api_key_is_active(true, now() - interval '1 second'), 'an active key that expired a second ago is not active';
  ASSERT NOT api.fn_api_key_is_active(false, now() + interval '1 day'), 'a revoked key is not active before it expires';
END
$$;

DO $$
BEGIN
  ASSERT pg_temp.t_api_key_answer(repeat('a', 64)) = 'active|null',   'an active key that never expires is active, with no expiry';
  ASSERT pg_temp.t_api_key_answer(repeat('b', 64)) = 'inactive|null', 'a revoked key with no expiry is inactive, with no expiry';
  ASSERT pg_temp.t_api_key_answer(repeat('c', 64)) = 'inactive|' || pg_temp.t_epoch(now() - interval '1 second'),
         'an expired key is inactive, with its expiry';
  ASSERT pg_temp.t_api_key_answer(repeat('d', 64)) = 'active|' || pg_temp.t_epoch(now() + interval '1 day'),
         'a key that expires tomorrow is active, with its expiry';
  ASSERT pg_temp.t_api_key_answer(repeat('e', 64)) = 'inactive|' || pg_temp.t_epoch(now()),
         'a key that expires now is inactive, with its expiry';
  ASSERT pg_temp.t_api_key_answer(repeat('f', 64)) = 'inactive|' || pg_temp.t_epoch(now() + interval '1 day'),
         'a revoked key is inactive before it expires, with its expiry';
  ASSERT pg_temp.t_api_key_answer(repeat('1', 64)) = 'active|4102444800',
         'an expiry three quarters of a second after a whole second is cut down to that second';
  ASSERT pg_temp.t_api_key_answer(repeat('2', 64)) = 'inactive|-1',
         'an expiry three quarters of a second before 1970 is cut down to -1, not toward 0';
  ASSERT pg_temp.t_api_key_answer(repeat('0', 64)) = 'unknown|null', 'a hash with no row is unknown, with no expiry, on one row';
  ASSERT pg_temp.t_api_key_answer(NULL) = 'unknown|null', 'a NULL hash is unknown, on one row';
  ASSERT (SELECT array_agg(attname::text || ' ' || format_type(atttypid, atttypmod) ORDER BY attnum)
            FROM pg_attribute
           WHERE attrelid = 't_api_key_state_call'::regclass AND attnum > 0)
         = ARRAY['api_key_state text', 'key_expires_at bigint'],
         'the call db.c sends answers two columns: api_key_state text, then key_expires_at bigint';
  ASSERT regexp_replace(pg_get_functiondef('api.fn_api_key_state(text)'::regprocedure), '--[^\n]*', '', 'g')
         ~ 'api\.fn_api_key_is_active\(ak\.active, ak\.expires_at\)',
         'api.fn_api_key_state takes the state from api.fn_api_key_is_active';
  ASSERT regexp_replace(pg_get_functiondef('api.fn_api_key_state(text)'::regprocedure), '--[^\n]*', '', 'g')
         !~ 'now\(\)',
         'api.fn_api_key_state keeps no copy of the rule of an active key';
END
$$;

INSERT INTO api_keys (key_hash, active, expires_at) VALUES
  (repeat('3', 64), true,  NULL),
  (repeat('4', 64), true,  now() + interval '1 day'),
  (repeat('5', 64), true,  now() - interval '10 days'),
  (repeat('6', 64), false, now() - interval '5 days');

CREATE FUNCTION pg_temp.t_key_row(p_key_hash text) RETURNS text LANGUAGE sql AS $$
  SELECT coalesce((SELECT ak.active::text || '|' || coalesce((now() - ak.expires_at)::text, 'null')
                     FROM api_keys AS ak WHERE ak.key_hash = p_key_hash), 'none')
$$;

DO $$
DECLARE
  others_before text := pg_temp.t_key_row(repeat('a', 64)) || ' ' || pg_temp.t_key_row(repeat('d', 64));
BEGIN
  ASSERT api.fn_api_key_revoke(repeat('3', 64)), 'a revoke of a key with a row answers true';
  ASSERT pg_temp.t_key_row(repeat('3', 64)) = 'false|00:00:00', 'a key with no expiry is revoked and expires at now()';
  ASSERT pg_temp.t_api_key_answer(repeat('3', 64)) = 'inactive|' || pg_temp.t_epoch(now()),
         'the revoked key is inactive, and its expiry is now()';
  ASSERT api.fn_api_key_revoke(repeat('4', 64)), 'a revoke of a key that expires tomorrow answers true';
  ASSERT pg_temp.t_key_row(repeat('4', 64)) = 'false|00:00:00', 'a later expiry is moved back to now()';
  ASSERT api.fn_api_key_revoke(repeat('5', 64)), 'a revoke of an expired key answers true';
  ASSERT pg_temp.t_key_row(repeat('5', 64)) = 'false|10 days', 'an earlier expiry is kept, so the 30 days do not start again';
  ASSERT api.fn_api_key_revoke(repeat('6', 64)), 'a revoke of a key revoked before answers true';
  ASSERT pg_temp.t_key_row(repeat('6', 64)) = 'false|5 days', 'a second revoke keeps the expiry of the first';
  ASSERT NOT api.fn_api_key_revoke(repeat('7', 64)), 'a revoke of a hash with no row answers false';
  ASSERT pg_temp.t_key_row(repeat('7', 64)) = 'none', 'a revoke of a hash with no row writes no row';
  ASSERT api.fn_api_key_revoke(NULL) IS NULL, 'a NULL hash answers NULL';
  ASSERT pg_temp.t_key_row(repeat('a', 64)) || ' ' || pg_temp.t_key_row(repeat('d', 64)) = others_before,
         'a revoke changes only the row of its hash';
END
$$;

DO $$
DECLARE
  f record;
BEGIN
  FOR f IN SELECT * FROM (VALUES
      ('api.fn_api_key_is_active(boolean, timestamptz)'::regprocedure, 's'::"char", false, false),
      ('api.fn_api_key_state(text)'::regprocedure,                     's'::"char", false, true),
      ('api.fn_api_key_revoke(text)'::regprocedure,                    'v'::"char", true, false)) AS t (oid, volatility, is_strict, is_definer) LOOP
    ASSERT (SELECT p.prosecdef FROM pg_proc AS p WHERE p.oid = f.oid) = f.is_definer,
           f.oid::text || CASE WHEN f.is_definer THEN ' is SECURITY DEFINER' ELSE ' is SECURITY INVOKER' END;
    ASSERT (SELECT p.proconfig FROM pg_proc AS p WHERE p.oid = f.oid) = ARRAY['search_path=pg_catalog'],
           f.oid::text || ' sets search_path to pg_catalog';
    ASSERT (SELECT p.provolatile FROM pg_proc AS p WHERE p.oid = f.oid) = f.volatility, f.oid::text || ' has its volatility';
    ASSERT (SELECT p.proisstrict FROM pg_proc AS p WHERE p.oid = f.oid) = f.is_strict, f.oid::text || ' is STRICT only when it writes';
  END LOOP;
END
$$;

DO $$
DECLARE
  bad_hash text;
BEGIN
  FOREACH bad_hash IN ARRAY ARRAY[repeat('A', 64), repeat('a', 63), repeat('a', 65), repeat('g', 64)]
  LOOP
    BEGIN
      INSERT INTO api_keys (key_hash) VALUES (bad_hash);
      RAISE EXCEPTION 'api_keys took the key_hash %', bad_hash;
    EXCEPTION WHEN check_violation THEN
      NULL;
    END;
  END LOOP;
END
$$;
