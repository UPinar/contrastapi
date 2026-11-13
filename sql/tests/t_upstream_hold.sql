INSERT INTO upstream_hold (hold_name, held_until) VALUES
  ('t_hold_long',         now() + interval '600 seconds'),
  ('t_hold_ended',        now() - interval '1 second'),
  ('t_hold_now',          now()),
  ('t_hold_half',         now() + interval '0.25 seconds'),
  ('t_hold_host:a.example', now() + interval '50 seconds');

PREPARE t_upstream_hold_set_query AS SELECT api.fn_upstream_hold_set($1, $2) AS is_set;
PREPARE t_upstream_hold_remaining_query AS SELECT api.fn_upstream_hold_remaining_seconds($1) AS remaining_seconds;
CREATE TEMP TABLE t_upstream_hold_set_answer AS EXECUTE t_upstream_hold_set_query('t_hold_text', '120');
CREATE TEMP TABLE t_upstream_hold_remaining_answer AS EXECUTE t_upstream_hold_remaining_query('t_hold_text');
DEALLOCATE t_upstream_hold_set_query;
DEALLOCATE t_upstream_hold_remaining_query;

DO $$
BEGIN
  ASSERT (SELECT array_agg(attname::text || ' ' || format_type(atttypid, atttypmod) ORDER BY attnum) FROM pg_attribute
          WHERE attrelid = 't_upstream_hold_set_answer'::regclass AND attnum > 0)
         = ARRAY['is_set boolean'],
         'the set query quota.c sends answers one boolean column, is_set';
  ASSERT (SELECT array_agg(is_set) FROM t_upstream_hold_set_answer) = ARRAY[true],
         'the set query writes the hold of a new name';
  ASSERT (SELECT array_agg(attname::text || ' ' || format_type(atttypid, atttypmod) ORDER BY attnum) FROM pg_attribute
          WHERE attrelid = 't_upstream_hold_remaining_answer'::regclass AND attnum > 0)
         = ARRAY['remaining_seconds integer'],
         'the remaining query quota.c sends answers one integer column, remaining_seconds';
  ASSERT (SELECT array_agg(remaining_seconds) FROM t_upstream_hold_remaining_answer) = ARRAY[120],
         'the remaining query answers the seconds the set query wrote';
END
$$;

DO $$
BEGIN
  ASSERT api.fn_upstream_hold_remaining_seconds('t_hold_long') = 600, 'a hold that ends in 600 seconds has 600 seconds left';
  ASSERT api.fn_upstream_hold_remaining_seconds('t_hold_ended') = 0, 'a hold that ended a second ago answers 0';
  ASSERT api.fn_upstream_hold_remaining_seconds('t_hold_now') = 0, 'a hold that ends now answers 0';
  ASSERT api.fn_upstream_hold_remaining_seconds('t_hold_half') = 1, 'a quarter of a second left rounds up to 1';
  ASSERT api.fn_upstream_hold_remaining_seconds('t_hold_none') = 0, 'a name with no row answers 0';
  ASSERT api.fn_upstream_hold_remaining_seconds('t_hold_host:a.example') = 50, 'a name with a host reads its own row';
  ASSERT api.fn_upstream_hold_remaining_seconds('t_hold_host') = 0, 'the source name alone does not read the row of a name with a host';
END
$$;

DO $$
BEGIN
  ASSERT api.fn_upstream_hold_set('t_hold_long', 900), 'a later end over a stored hold answers true';
  ASSERT api.fn_upstream_hold_remaining_seconds('t_hold_long') = 900, 'a later end replaces the stored one';
  ASSERT api.fn_upstream_hold_set('t_hold_long', 30), 'an earlier end over a stored hold answers true';
  ASSERT api.fn_upstream_hold_remaining_seconds('t_hold_long') = 900, 'an earlier end leaves the later stored end';
  ASSERT api.fn_upstream_hold_set('t_hold_ended', 45), 'a set over a hold that ended answers true';
  ASSERT api.fn_upstream_hold_remaining_seconds('t_hold_ended') = 45, 'a set over a hold that ended starts a new hold';
  ASSERT (SELECT array_agg(row(hold_name, held_until - now())::text ORDER BY hold_name) FROM upstream_hold WHERE hold_name LIKE 't_hold_%')
         = ARRAY[row('t_hold_ended', interval '45 seconds')::text, row('t_hold_half', interval '0.25 seconds')::text,
                 row('t_hold_host:a.example', interval '50 seconds')::text, row('t_hold_long', interval '900 seconds')::text,
                 row('t_hold_now', interval '0 seconds')::text, row('t_hold_text', interval '120 seconds')::text],
         'each set wrote only the row of its name';
END
$$;

DO $$
DECLARE
  refused_name text;
  refused_by   text;
BEGIN
  FOREACH refused_name IN ARRAY ARRAY['T_hold', '1hold', 't' || repeat('x', 32), 't_hold:', 't_hold:A.example',
                                      't_hold:a_b.example', 't_hold:a b', 't_hold:' || repeat('a', 254), 't_hold:a:b', 't-hold', '_hold']
  LOOP
    BEGIN
      PERFORM api.fn_upstream_hold_set(refused_name, 60);
      ASSERT false, format('the hold name %s is refused', refused_name);
    EXCEPTION WHEN check_violation THEN
      GET STACKED DIAGNOSTICS refused_by = CONSTRAINT_NAME;
      ASSERT refused_by = 'upstream_hold_hold_name_format', format('upstream_hold_hold_name_format refuses %s', refused_name);
    END;
  END LOOP;
  ASSERT api.fn_upstream_hold_set('t' || repeat('x', 31), 60), 'a source name of 32 bytes is written';
  ASSERT api.fn_upstream_hold_set('t_hold:' || repeat('a', 253), 60), 'a host of 253 bytes is written';
  ASSERT api.fn_upstream_hold_set('t_hold:rdap-1.example.org', 60), 'a host with a digit, a hyphen and dots is written';
  ASSERT api.fn_upstream_hold_set('t', 60), 'a source name of 1 byte is written';
  ASSERT api.fn_upstream_hold_set('t_hold2', 60), 'a source name with a digit is written';
  ASSERT api.fn_upstream_hold_set('t_hold:a', 60), 'a host of 1 byte is written';
END
$$;

DO $$
BEGIN
  ASSERT (SELECT prosecdef AND NOT proisstrict AND provolatile = 'v' FROM pg_proc
          WHERE oid = 'api.fn_upstream_hold_set(text, integer)'::regprocedure),
         'api.fn_upstream_hold_set is SECURITY DEFINER, not STRICT, and VOLATILE';
  ASSERT (SELECT prosecdef AND NOT proisstrict AND provolatile = 's' FROM pg_proc
          WHERE oid = 'api.fn_upstream_hold_remaining_seconds(text)'::regprocedure),
         'api.fn_upstream_hold_remaining_seconds is SECURITY DEFINER, not STRICT, and STABLE';
  ASSERT (SELECT array_agg(proconfig::text) FROM pg_proc
          WHERE oid IN ('api.fn_upstream_hold_set(text, integer)'::regprocedure,
                        'api.fn_upstream_hold_remaining_seconds(text)'::regprocedure))
         = ARRAY['{search_path=pg_catalog}', '{search_path=pg_catalog}'],
         'the two functions set search_path to pg_catalog';
  ASSERT (SELECT relpersistence FROM pg_class WHERE oid = 'upstream_hold'::regclass) = 'p',
         'upstream_hold is a logged table';
END
$$;
