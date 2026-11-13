INSERT INTO upstream_cache (cache_key, body, is_error, fetched_at, expires_at) VALUES
  ('t-cache-live',    '{"live":1}',    false, '2026-10-17 21:00:00+03', now() + interval '1 second'),
  ('t-cache-error',   '{"error":"x"}', true,  now() - interval '1 hour',  now() + interval '1 hour'),
  ('t-cache-expired', '{"old":1}',     false, now() - interval '1 hour',  now()),
  ('t-cache-stale',   '{"old":2}',     false, now() - interval '2 hours', now() - interval '1 second');

PREPARE t_upstream_cache_get_query AS SELECT * FROM api.fn_upstream_cache_get($1);
PREPARE t_upstream_cache_put_query AS SELECT api.fn_upstream_cache_put($1, $2, $3, $4) AS is_written;
PREPARE t_upstream_cache_purge_query AS SELECT api.fn_upstream_cache_purge($1) AS purged_row_count;
CREATE TEMP TABLE t_upstream_cache_put_answer AS EXECUTE t_upstream_cache_put_query('t-cache-text', '{"text":1}', 'true', '60');
CREATE TEMP TABLE t_upstream_cache_get_answer AS EXECUTE t_upstream_cache_get_query('t-cache-text');
CREATE TEMP TABLE t_upstream_cache_purge_answer AS EXECUTE t_upstream_cache_purge_query('0');
DEALLOCATE t_upstream_cache_get_query;
DEALLOCATE t_upstream_cache_put_query;
DEALLOCATE t_upstream_cache_purge_query;

DO $$
BEGIN
  ASSERT (SELECT array_agg(attname::text || ' ' || format_type(atttypid, atttypmod) ORDER BY attnum) FROM pg_attribute
          WHERE attrelid = 't_upstream_cache_put_answer'::regclass AND attnum > 0)
         = ARRAY['is_written boolean'],
         'the put query cache.c sends answers one boolean column, is_written';
  ASSERT (SELECT array_agg(is_written) FROM t_upstream_cache_put_answer) = ARRAY[true],
         'the put query writes its key';
  ASSERT (SELECT array_agg(attname::text || ' ' || format_type(atttypid, atttypmod) ORDER BY attnum) FROM pg_attribute
          WHERE attrelid = 't_upstream_cache_get_answer'::regclass AND attnum > 0)
         = ARRAY['body text', 'is_error boolean', 'fetched_at text'],
         'the get query cache.c sends answers body, is_error and fetched_at, in that order';
  ASSERT (SELECT array_agg(row(body, is_error)::text) FROM t_upstream_cache_get_answer)
         = ARRAY[row('{"text":1}', true)::text],
         'the get query answers the body and the flag the put query wrote';
  ASSERT (SELECT array_agg(attname::text || ' ' || format_type(atttypid, atttypmod) ORDER BY attnum) FROM pg_attribute
          WHERE attrelid = 't_upstream_cache_purge_answer'::regclass AND attnum > 0)
         = ARRAY['purged_row_count integer'],
         'the purge query cache.c sends answers one integer column, purged_row_count';
END
$$;

DO $$
DECLARE
  saved_time_zone text := current_setting('TimeZone');
BEGIN
  PERFORM set_config('TimeZone', 'Asia/Kolkata', true);
  ASSERT (SELECT array_agg(row(body, is_error, fetched_at)::text) FROM api.fn_upstream_cache_get('t-cache-live'))
         = ARRAY[row('{"live":1}', false, '2026-10-17T18:00:00Z')::text],
         'a row that expires one second after now() answers its body, its flag and fetched_at in UTC';
  ASSERT (SELECT array_agg(row(body, is_error)::text) FROM api.fn_upstream_cache_get('t-cache-error'))
         = ARRAY[row('{"error":"x"}', true)::text],
         'a row whose body is an error answer has is_error true';
  ASSERT (SELECT count(*) FROM api.fn_upstream_cache_get('t-cache-expired')) = 0,
         'a row that expires at now() answers no row';
  ASSERT (SELECT count(*) FROM api.fn_upstream_cache_get('t-cache-stale')) = 0,
         'a row that expired one second ago answers no row';
  ASSERT (SELECT count(*) FROM api.fn_upstream_cache_get('t-cache-none')) = 0,
         'a key with no row answers no row';
  PERFORM set_config('TimeZone', saved_time_zone, true);
END
$$;

DO $$
BEGIN
  ASSERT api.fn_upstream_cache_put('t-cache-error', '{"fixed":1}', false, 120), 'a put over a stored key answers true';
  ASSERT (SELECT row(body, is_error, fetched_at = now(), expires_at = now() + interval '2 minutes')::text
            FROM upstream_cache WHERE cache_key = 't-cache-error')
         = row('{"fixed":1}', false, true, true)::text,
         'the put writes the new body and flag, fetched_at now() and expires_at p_expires_after_seconds later';
  ASSERT api.fn_upstream_cache_put('t-cache-stale', '{"new":2}', true, 1), 'a put over an expired key answers true';
  ASSERT (SELECT array_agg(row(body, is_error)::text) FROM api.fn_upstream_cache_get('t-cache-stale'))
         = ARRAY[row('{"new":2}', true)::text],
         'a put that expires after 1 second is answered in the same transaction';
  ASSERT api.fn_upstream_cache_put(NULL, '{}', false, 60) IS NULL
     AND api.fn_upstream_cache_put('t-cache-null', NULL, false, 60) IS NULL
     AND api.fn_upstream_cache_put('t-cache-null', '{}', NULL, 60) IS NULL
     AND api.fn_upstream_cache_put('t-cache-null', '{}', false, NULL) IS NULL,
         'a NULL argument answers NULL';
  ASSERT (SELECT count(*) FROM upstream_cache WHERE cache_key = 't-cache-null') = 0,
         'a NULL argument writes nothing';
  ASSERT api.fn_upstream_cache_put(repeat('k', 512), '{}', false, 60), 'a key of 512 bytes is written';
  ASSERT api.fn_upstream_cache_put('t-cache-big', repeat('b', 1048576), false, 60), 'a body of 1 MiB is written';
END
$$;

DO $$
DECLARE
  refused_by text;
BEGIN
  BEGIN
    PERFORM api.fn_upstream_cache_put('t-cache-expiry', '{}', false, 0);
    ASSERT false, 'an expiry of 0 seconds is refused';
  EXCEPTION WHEN check_violation THEN
    GET STACKED DIAGNOSTICS refused_by = CONSTRAINT_NAME;
    ASSERT refused_by = 'upstream_cache_expires_after_fetch', 'upstream_cache_expires_after_fetch refuses an expiry of 0 seconds';
  END;
  BEGIN
    PERFORM api.fn_upstream_cache_put('', '{}', false, 60);
    ASSERT false, 'an empty key is refused';
  EXCEPTION WHEN check_violation THEN
    GET STACKED DIAGNOSTICS refused_by = CONSTRAINT_NAME;
    ASSERT refused_by = 'upstream_cache_key_length', 'upstream_cache_key_length refuses an empty key';
  END;
  BEGIN
    PERFORM api.fn_upstream_cache_put(repeat('k', 513), '{}', false, 60);
    ASSERT false, 'a key of 513 bytes is refused';
  EXCEPTION WHEN check_violation THEN
    GET STACKED DIAGNOSTICS refused_by = CONSTRAINT_NAME;
    ASSERT refused_by = 'upstream_cache_key_length', 'upstream_cache_key_length refuses a key of 513 bytes';
  END;
  BEGIN
    PERFORM api.fn_upstream_cache_put('t-cache-huge', repeat('b', 1048577), false, 60);
    ASSERT false, 'a body of 1 MiB and one byte is refused';
  EXCEPTION WHEN check_violation THEN
    GET STACKED DIAGNOSTICS refused_by = CONSTRAINT_NAME;
    ASSERT refused_by = 'upstream_cache_body_length', 'upstream_cache_body_length refuses a body one byte past 1 MiB';
  END;
  ASSERT (SELECT count(*) FROM upstream_cache WHERE cache_key IN ('t-cache-expiry', 't-cache-huge')) = 0,
         'a refused put writes nothing';
END
$$;

INSERT INTO upstream_cache (cache_key, body, is_error, fetched_at, expires_at) VALUES
  ('t-cache-gone', '{}', false, now() - interval '3 hours', now() - interval '2 hours');

DO $$
BEGIN
  ASSERT api.fn_upstream_cache_purge(NULL) IS NULL, 'a NULL limit answers NULL';
  ASSERT (SELECT count(*) FROM upstream_cache WHERE cache_key IN ('t-cache-expired', 't-cache-gone')) = 2,
         'a NULL limit deletes nothing';
  ASSERT api.fn_upstream_cache_purge(1) = 1, 'a limit of 1 deletes one of the two expired rows';
  ASSERT api.fn_upstream_cache_purge(10) = 1, 'the next call deletes the other expired row';
  ASSERT api.fn_upstream_cache_purge(10) = 0, 'a call with no expired row deletes none';
  ASSERT (SELECT array_agg(cache_key ORDER BY cache_key) FROM upstream_cache WHERE cache_key LIKE 't-cache-%')
         = ARRAY['t-cache-big', 't-cache-error', 't-cache-live', 't-cache-stale', 't-cache-text'],
         'each row that has not expired stays';
END
$$;

DO $$
BEGIN
  ASSERT (SELECT prosecdef AND NOT proisstrict AND provolatile = 's' FROM pg_proc
          WHERE oid = 'api.fn_upstream_cache_get(text)'::regprocedure),
         'api.fn_upstream_cache_get is SECURITY DEFINER, not STRICT, and STABLE';
  ASSERT (SELECT prosecdef AND proisstrict AND provolatile = 'v' FROM pg_proc
          WHERE oid = 'api.fn_upstream_cache_put(text, text, boolean, integer)'::regprocedure),
         'api.fn_upstream_cache_put is SECURITY DEFINER, STRICT, and VOLATILE';
  ASSERT (SELECT prosecdef AND proisstrict AND provolatile = 'v' FROM pg_proc
          WHERE oid = 'api.fn_upstream_cache_purge(integer)'::regprocedure),
         'api.fn_upstream_cache_purge is SECURITY DEFINER, STRICT, and VOLATILE';
  ASSERT (SELECT array_agg(proconfig::text) FROM pg_proc
          WHERE oid IN ('api.fn_upstream_cache_get(text)'::regprocedure,
                        'api.fn_upstream_cache_put(text, text, boolean, integer)'::regprocedure,
                        'api.fn_upstream_cache_purge(integer)'::regprocedure))
         = ARRAY['{search_path=pg_catalog}', '{search_path=pg_catalog}', '{search_path=pg_catalog}'],
         'the three functions set search_path to pg_catalog';
  ASSERT (SELECT relpersistence FROM pg_class WHERE oid = 'upstream_cache'::regclass) = 'u',
         'upstream_cache is an unlogged table';
END
$$;
