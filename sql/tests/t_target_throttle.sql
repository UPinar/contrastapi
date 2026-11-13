INSERT INTO target_throttle (throttle_rule_name, target_name, window_seconds, window_start, charged_unit_count) VALUES
  ('t_fetch', 'full.example',    60,   api.fn_current_window_start(60),                       58),
  ('t_fetch', 'ended.example',   60,   api.fn_current_window_start(60) - interval '1 minute', 60),
  ('t_names', 'full.example',    3600, api.fn_current_window_start(3600),                     7),
  ('t_fetch', 'resized.example', 3600, api.fn_current_window_start(3600) - interval '1 hour', 9),
  ('t_fetch', 'grown.example',   60,   api.fn_current_window_start(3600),                     9),
  ('t_fetch', 'later.example',   60,   api.fn_current_window_start(60) + interval '1 minute', 2),
  ('t_fetch', 'laterfull.example', 60, api.fn_current_window_start(60) + interval '1 minute', 5);

PREPARE t_target_throttle_charge_query AS SELECT * FROM api.fn_target_throttle_charge($1, $2, $3, $4, $5);
PREPARE t_target_throttle_purge_query AS SELECT api.fn_target_throttle_purge($1) AS purged_row_count;
CREATE TEMP TABLE t_target_throttle_charge_answer AS EXECUTE t_target_throttle_charge_query('t_fetch', 'text.example', '60', '2', '60');
CREATE TEMP TABLE t_target_throttle_purge_answer AS EXECUTE t_target_throttle_purge_query('0');
DEALLOCATE t_target_throttle_charge_query;
DEALLOCATE t_target_throttle_purge_query;

DO $$
BEGIN
  ASSERT (SELECT array_agg(attname::text || ' ' || format_type(atttypid, atttypmod) ORDER BY attnum) FROM pg_attribute
          WHERE attrelid = 't_target_throttle_charge_answer'::regclass AND attnum > 0)
         = ARRAY['is_charged boolean', 'window_remaining_seconds integer'],
         'the charge query throttle.c sends answers is_charged and window_remaining_seconds, in that order';
  ASSERT (SELECT array_agg(is_charged) FROM t_target_throttle_charge_answer) = ARRAY[true],
         'the charge query writes the charge of a new target';
  ASSERT (SELECT charged_unit_count FROM target_throttle WHERE target_name = 'text.example') = 2,
         'the charge query writes its charge of 2';
  ASSERT (SELECT array_agg(attname::text || ' ' || format_type(atttypid, atttypmod) ORDER BY attnum) FROM pg_attribute
          WHERE attrelid = 't_target_throttle_purge_answer'::regclass AND attnum > 0)
         = ARRAY['purged_row_count integer'],
         'the purge query throttle.c sends answers one integer column, purged_row_count';
END
$$;

DO $$
DECLARE
  answer record;
BEGIN
  SELECT * INTO answer FROM api.fn_target_throttle_charge('t_fetch', 'new.example', 60, 3, 5);
  ASSERT answer.is_charged, 'a charge of 3 within a limit of 5 is written for a new target';
  ASSERT answer.window_remaining_seconds = ceil(extract(epoch FROM api.fn_current_window_start(60) + interval '1 minute' - now()))::integer,
         'window_remaining_seconds is the time left until the current window ends, rounded up';
  ASSERT answer.window_remaining_seconds BETWEEN 1 AND 60, 'window_remaining_seconds is between 1 and the window length';
  ASSERT (SELECT row(charged_unit_count, window_seconds, window_start = api.fn_current_window_start(60))::text
            FROM target_throttle WHERE throttle_rule_name = 't_fetch' AND target_name = 'new.example')
         = row(3, 60, true)::text,
         'the new row counts the charge, from the start of the current window';
  ASSERT (SELECT is_charged FROM api.fn_target_throttle_charge('t_fetch', 'new.example', 60, 2, 5)),
         'a charge that brings the load to the limit is written';
  ASSERT (SELECT NOT is_charged FROM api.fn_target_throttle_charge('t_fetch', 'new.example', 60, 1, 5)),
         'a charge one unit past the limit is refused';
  ASSERT (SELECT charged_unit_count FROM target_throttle WHERE throttle_rule_name = 't_fetch' AND target_name = 'new.example') = 5,
         'a refused charge leaves the load as it was';

  ASSERT (SELECT NOT is_charged FROM api.fn_target_throttle_charge('t_fetch', 'big.example', 60, 6, 5)),
         'a charge larger than the limit is refused for a new target';
  ASSERT (SELECT count(*) FROM target_throttle WHERE target_name = 'big.example') = 0,
         'a refused charge of a new target writes no row';

  ASSERT (SELECT is_charged FROM api.fn_target_throttle_charge('t_fetch', 'full.example', 60, 2, 60)),
         'p_charge_limit is the fifth argument: 58 plus a charge of 2 fits a limit of 60';
  ASSERT (SELECT NOT is_charged FROM api.fn_target_throttle_charge('t_fetch', 'full.example', 60, 1, 60)),
         '60 plus a charge of 1 does not fit a limit of 60';

  ASSERT (SELECT is_charged FROM api.fn_target_throttle_charge('t_fetch', 'ended.example', 60, 60, 60)),
         'a target whose last window ended full is charged in the current window';
  ASSERT (SELECT row(charged_unit_count, window_start = api.fn_current_window_start(60))::text
            FROM target_throttle WHERE throttle_rule_name = 't_fetch' AND target_name = 'ended.example')
         = row(60, true)::text,
         'an ended window counts from 0 again, and its row moves to the current window';

  ASSERT (SELECT is_charged FROM api.fn_target_throttle_charge('t_fetch', 'resized.example', 60, 1, 60)),
         'a target whose ended window was an hour long is charged in a window of a minute';
  ASSERT (SELECT row(charged_unit_count, window_seconds)::text FROM target_throttle WHERE target_name = 'resized.example')
         = row(1, 60)::text,
         'the charge writes the window length of the rule into the row';

  ASSERT (SELECT is_charged FROM api.fn_target_throttle_charge('t_fetch', 'grown.example', 3600, 1, 5)),
         'a row of a minute window that started at the top of the hour counts from 0 under an hour window';
  ASSERT (SELECT row(charged_unit_count, window_seconds)::text FROM target_throttle WHERE target_name = 'grown.example')
         = row(1, 3600)::text,
         'the load of the minute window does not carry into the hour window';

  ASSERT (SELECT is_charged FROM api.fn_target_throttle_charge('t_fetch', 'later.example', 60, 1, 5)),
         'a charge that sees an earlier window than the row holds adds to the later window';
  ASSERT (SELECT row(charged_unit_count, window_start = api.fn_current_window_start(60) + interval '1 minute')::text
            FROM target_throttle WHERE target_name = 'later.example')
         = row(3, true)::text,
         'the row keeps its later window and its load';
  ASSERT (SELECT NOT is_charged FROM api.fn_target_throttle_charge('t_fetch', 'laterfull.example', 60, 1, 5)),
         'a charge that sees an earlier window than a full row holds is refused';
  ASSERT (SELECT row(charged_unit_count, window_start = api.fn_current_window_start(60) + interval '1 minute')::text
            FROM target_throttle WHERE target_name = 'laterfull.example')
         = row(5, true)::text,
         'the refused charge leaves the later window full';

  SELECT * INTO answer FROM api.fn_target_throttle_charge('t_names', 'new.example', 3600, 100, 100);
  ASSERT answer.is_charged, 'a target that one throttle counts starts from 0 under another throttle';
  ASSERT answer.window_remaining_seconds = ceil(extract(epoch FROM api.fn_current_window_start(3600) + interval '1 hour' - now()))::integer,
         'window_remaining_seconds of an hour window is the time left until the hour ends';
  ASSERT (SELECT is_charged FROM api.fn_target_throttle_charge('t_names', 'full.example', 3600, 93, 100)),
         'p_charged_count is the fourth argument: 7 plus a charge of 93 fits a limit of 100';
  ASSERT (SELECT array_agg(row(throttle_rule_name, target_name, charged_unit_count)::text ORDER BY throttle_rule_name, target_name)
            FROM target_throttle WHERE throttle_rule_name IN ('t_fetch', 't_names'))
         = ARRAY[row('t_fetch', 'ended.example', 60)::text, row('t_fetch', 'full.example', 60)::text,
                 row('t_fetch', 'grown.example', 1)::text, row('t_fetch', 'later.example', 3)::text,
                 row('t_fetch', 'laterfull.example', 5)::text, row('t_fetch', 'new.example', 5)::text,
                 row('t_fetch', 'resized.example', 1)::text, row('t_fetch', 'text.example', 2)::text,
                 row('t_names', 'full.example', 100)::text, row('t_names', 'new.example', 100)::text],
         'each charge wrote only the row of its throttle and target';
END
$$;

DO $$
DECLARE
  w timestamptz := api.fn_current_window_start(60);
BEGIN
  ASSERT api.fn_target_throttle_is_window_kept(60, w, 60, w), 'the current window is kept';
  ASSERT api.fn_target_throttle_is_window_kept(60, w + interval '1 minute', 60, w), 'the next window is kept';
  ASSERT NOT api.fn_target_throttle_is_window_kept(60, w + interval '61 seconds', 60, w),
         'a window that starts one second after the next one is not kept';
  ASSERT NOT api.fn_target_throttle_is_window_kept(60, w - interval '1 second', 60, w),
         'a window that starts one second before the current one is not kept';
  ASSERT NOT api.fn_target_throttle_is_window_kept(3600, w, 60, w), 'a row of another length is not kept';
  ASSERT api.fn_target_throttle_is_window_kept(3600, w + interval '1 hour', 3600, w), 'the next hour window is kept';
  ASSERT NOT api.fn_target_throttle_is_window_kept(3600, w + interval '1 hour 1 second', 3600, w),
         'an hour window one second after the next one is not kept';
END
$$;

INSERT INTO target_throttle (throttle_rule_name, target_name, window_seconds, window_start, charged_unit_count) VALUES
  ('t_future', 'future.example', 60, api.fn_current_window_start(60) + interval '2 minutes', 5);

DO $$
BEGIN
  ASSERT (SELECT is_charged FROM api.fn_target_throttle_charge('t_future', 'future.example', 60, 1, 5)),
         'a full row two windows ahead counts from 0';
  ASSERT (SELECT row(charged_unit_count, window_start = api.fn_current_window_start(60))::text
            FROM target_throttle WHERE throttle_rule_name = 't_future')
         = row(1, true)::text,
         'the row two windows ahead moves to the current window and holds the charge alone';
END
$$;

INSERT INTO target_throttle (throttle_rule_name, target_name, window_seconds, window_start, charged_unit_count) VALUES
  ('t_grow', 'grownlate.example', 60, api.fn_current_window_start(3600) + interval '1 minute', 9);

DO $$
BEGIN
  ASSERT (SELECT is_charged FROM api.fn_target_throttle_charge('t_grow', 'grownlate.example', 3600, 1, 5)),
         'a minute row from later in the hour counts from 0 under an hour window';
  ASSERT (SELECT row(charged_unit_count, window_seconds, window_start = api.fn_current_window_start(3600))::text
            FROM target_throttle WHERE throttle_rule_name = 't_grow')
         = row(1, 3600, true)::text,
         'the row of another length moves to the start of the current hour window';
END
$$;

DO $$
DECLARE
  charge_index integer;
BEGIN
  FOR charge_index IN 1 .. 10 LOOP
    ASSERT (SELECT is_charged FROM api.fn_target_throttle_charge('rdap', 'h.example', 60, 1, 10)),
           'the rdap charge ' || charge_index || ' of the scan fits its limit of 10';
  END LOOP;
  ASSERT (SELECT NOT is_charged FROM api.fn_target_throttle_charge('rdap', 'h.example', 60, 1, 10)),
         'the 11th rdap charge of the scan is refused at its limit of 10';
  ASSERT (SELECT is_charged FROM api.fn_target_throttle_charge('rdap', 'h.example', 60, 1, 30)),
         'an rdap charge of the caller fits its limit of 30 after the scan is full';
  ASSERT (SELECT charged_unit_count FROM target_throttle WHERE throttle_rule_name = 'rdap' AND target_name = 'h.example') = 11,
         'the rdap row counts the charges of both callers';
  ASSERT (SELECT NOT is_charged FROM api.fn_target_throttle_charge('rdap', 'h.example', 60, 1, 10)),
         'the rdap charge of the scan stays refused while the row holds 11';
  FOR charge_index IN 1 .. 3 LOOP
    ASSERT (SELECT is_charged FROM api.fn_target_throttle_charge('whois', 'h.example', 60, 1, 3)),
           'the whois charge ' || charge_index || ' of the scan fits its limit of 3';
  END LOOP;
  ASSERT (SELECT NOT is_charged FROM api.fn_target_throttle_charge('whois', 'h.example', 60, 1, 3)),
         'the 4th whois charge of the scan is refused at its limit of 3';
  ASSERT (SELECT is_charged FROM api.fn_target_throttle_charge('whois', 'h.example', 60, 1, 10)),
         'a whois charge of the caller fits its limit of 10 after the scan is full';
  ASSERT (SELECT charged_unit_count FROM target_throttle WHERE throttle_rule_name = 'whois' AND target_name = 'h.example') = 4,
         'the whois row counts the charges of both callers';
  ASSERT (SELECT NOT is_charged FROM api.fn_target_throttle_charge('whois', 'h.example', 60, 1, 3)),
         'the whois charge of the scan stays refused while the row holds 4';
END
$$;

DO $$
DECLARE
  refused_by text;
BEGIN
  BEGIN
    PERFORM api.fn_target_throttle_charge('t_fetch', 'bad.example', 86400, 1, 1);
    ASSERT false, 'a window of a day is refused';
  EXCEPTION WHEN check_violation THEN
    GET STACKED DIAGNOSTICS refused_by = CONSTRAINT_NAME;
    ASSERT refused_by = 'target_throttle_window_seconds', 'target_throttle_window_seconds refuses a window of a day';
  END;
  BEGIN
    PERFORM api.fn_target_throttle_charge('t_fetch', 'bad.example', 60, -1, 1);
    ASSERT false, 'a negative charge of a new target is refused';
  EXCEPTION WHEN check_violation THEN
    GET STACKED DIAGNOSTICS refused_by = CONSTRAINT_NAME;
    ASSERT refused_by = 'target_throttle_charged_unit_count', 'target_throttle_charged_unit_count refuses a negative load';
  END;
  BEGIN
    PERFORM api.fn_target_throttle_charge('t-fetch', 'bad.example', 60, 1, 1);
    ASSERT false, 'a throttle rule name with a hyphen is refused';
  EXCEPTION WHEN check_violation THEN
    GET STACKED DIAGNOSTICS refused_by = CONSTRAINT_NAME;
    ASSERT refused_by = 'target_throttle_throttle_rule_name_format', 'target_throttle_throttle_rule_name_format refuses a hyphen';
  END;
  BEGIN
    PERFORM api.fn_target_throttle_charge('t_fetch', '', 60, 1, 1);
    ASSERT false, 'an empty target is refused';
  EXCEPTION WHEN check_violation THEN
    GET STACKED DIAGNOSTICS refused_by = CONSTRAINT_NAME;
    ASSERT refused_by = 'target_throttle_target_name_length', 'target_throttle_target_name_length refuses an empty target';
  END;
  BEGIN
    PERFORM api.fn_target_throttle_charge('t_fetch', repeat('t', 254), 60, 1, 1);
    ASSERT false, 'a target of 254 bytes is refused';
  EXCEPTION WHEN check_violation THEN
    GET STACKED DIAGNOSTICS refused_by = CONSTRAINT_NAME;
    ASSERT refused_by = 'target_throttle_target_name_length', 'target_throttle_target_name_length refuses a target of 254 bytes';
  END;
  ASSERT (SELECT is_charged FROM api.fn_target_throttle_charge('t_fetch', repeat('t', 253), 60, 1, 1)), 'a target of 253 bytes is written';
END
$$;

INSERT INTO target_throttle (throttle_rule_name, target_name, window_seconds, window_start, charged_unit_count) VALUES
  ('t_purge', 'old-a.example', 60,   now() - interval '1 minute 1 second', 1),
  ('t_purge', 'old-b.example', 3600, now() - interval '1 hour 1 second',   1),
  ('t_purge', 'ends.example',  60,   now() - interval '1 minute',          1),
  ('t_purge', 'hour.example',  3600, now() - interval '59 minutes',        1);

DO $$
BEGIN
  ASSERT api.fn_target_throttle_purge(NULL) IS NULL, 'a NULL limit answers NULL';
  ASSERT (SELECT count(*) FROM target_throttle WHERE throttle_rule_name = 't_purge') = 4, 'a NULL limit deletes nothing';
  ASSERT api.fn_target_throttle_purge(1) = 1, 'a limit of 1 deletes one of the three ended rows';
  ASSERT api.fn_target_throttle_purge(10) = 2, 'the next call deletes the other two';
  ASSERT api.fn_target_throttle_purge(10) = 0, 'a call with no ended row deletes none';
  ASSERT (SELECT array_agg(target_name) FROM target_throttle WHERE throttle_rule_name = 't_purge') = ARRAY['hour.example'],
         'a window that ends at now() has ended, and an hour window that started 59 minutes ago has not';
  ASSERT (SELECT count(*) FROM target_throttle WHERE throttle_rule_name IN ('t_fetch', 't_names')) = 11,
         'each row of a current window stays';
END
$$;

INSERT INTO target_throttle (throttle_rule_name, target_name, window_seconds, window_start, charged_unit_count) VALUES
  ('t_load',  'cur.example',   60,   api.fn_current_window_start(60),                        7),
  ('t_loadx', 'cur.example',   60,   api.fn_current_window_start(60),                        3),
  ('t_load',  'other.example', 60,   api.fn_current_window_start(60),                        2),
  ('t_load',  'hour.example',  3600, api.fn_current_window_start(3600),                      8),
  ('t_load',  'grown.example', 60,   api.fn_current_window_start(3600),                      9),
  ('t_load',  'ended.example', 60,   api.fn_current_window_start(60) - interval '1 minute',  9),
  ('t_load',  'next.example',  60,   api.fn_current_window_start(60) + interval '1 minute',  4),
  ('t_load',  'ahead.example', 60,   api.fn_current_window_start(60) + interval '2 minutes', 6),
  ('t_load',  'full.example',  60,   api.fn_current_window_start(60),                        5);

PREPARE t_target_throttle_load_query AS SELECT * FROM api.fn_target_throttle_load($1, $2, $3);
CREATE TEMP TABLE t_target_throttle_load_answer AS EXECUTE t_target_throttle_load_query('t_load', 'cur.example', '60');
DEALLOCATE t_target_throttle_load_query;

DO $$
DECLARE
  rows_before text[];
  answer      record;
BEGIN
  ASSERT (SELECT array_agg(attname::text || ' ' || format_type(atttypid, atttypmod) ORDER BY attnum) FROM pg_attribute
          WHERE attrelid = 't_target_throttle_load_answer'::regclass AND attnum > 0)
         = ARRAY['load_count integer', 'window_remaining_seconds integer'],
         'the load query throttle.c sends answers load_count and window_remaining_seconds, in that order';
  ASSERT (SELECT array_agg(load_count) FROM t_target_throttle_load_answer) = ARRAY[7],
         'the load query answers one row with the load of the target';

  rows_before := (SELECT array_agg(row(tt.ctid, tt.*)::text ORDER BY tt.throttle_rule_name, tt.target_name) FROM target_throttle AS tt);

  SELECT * INTO answer FROM api.fn_target_throttle_load('t_load', 'cur.example', 60);
  ASSERT answer.load_count = 7, 'a row of the current window answers its load';
  ASSERT answer.window_remaining_seconds = ceil(extract(epoch FROM api.fn_current_window_start(60) + interval '1 minute' - now()))::integer,
         'window_remaining_seconds is the time left until the current window ends, rounded up';
  ASSERT answer.window_remaining_seconds BETWEEN 1 AND 60, 'window_remaining_seconds is between 1 and the window length';
  ASSERT (SELECT load_count FROM api.fn_target_throttle_load('t_loadx', 'cur.example', 60)) = 3,
         'p_throttle_rule_name is the first argument: another throttle of the same target answers its own load';
  ASSERT (SELECT load_count FROM api.fn_target_throttle_load('t_load', 'other.example', 60)) = 2,
         'p_target_name is the second argument: another target of the same throttle answers its own load';
  ASSERT (SELECT load_count FROM api.fn_target_throttle_load('t_load', 'hour.example', 60)) = 0,
         'p_window_seconds is the third argument: a row of an hour window answers 0 under a minute window';
  SELECT * INTO answer FROM api.fn_target_throttle_load('t_load', 'hour.example', 3600);
  ASSERT answer.load_count = 8, 'a row of the current hour window answers its load under an hour window';
  ASSERT answer.window_remaining_seconds = ceil(extract(epoch FROM api.fn_current_window_start(3600) + interval '1 hour' - now()))::integer,
         'window_remaining_seconds of an hour window is the time left until the hour ends';
  ASSERT (SELECT load_count FROM api.fn_target_throttle_load('t_load', 'grown.example', 3600)) = 0,
         'a minute row that starts at the top of the hour answers 0 under an hour window: its length differs';
  ASSERT (SELECT load_count FROM api.fn_target_throttle_load('t_load', 'ended.example', 60)) = 0,
         'a row of an ended window answers 0';
  ASSERT (SELECT load_count FROM api.fn_target_throttle_load('t_load', 'next.example', 60)) = 4,
         'a row of the next window answers its load, as a charge keeps it';
  ASSERT (SELECT load_count FROM api.fn_target_throttle_load('t_load', 'ahead.example', 60)) = 0,
         'a row two windows ahead answers 0, as a charge counts it from 0';
  ASSERT (SELECT load_count FROM api.fn_target_throttle_load('t_load', 'full.example', 60)) = 5,
         'a row at a limit of 5 answers 5';
  SELECT * INTO answer FROM api.fn_target_throttle_load('t_load', 'none.example', 60);
  ASSERT answer.load_count = 0, 'a target with no row answers 0';
  ASSERT answer.window_remaining_seconds BETWEEN 1 AND 60, 'a target with no row answers the seconds left in the window';
  ASSERT (SELECT count(*) FROM api.fn_target_throttle_load('t_load', 'none.example', 60)) = 1,
         'a target with no row answers one row';
  ASSERT (SELECT count(*) FROM api.fn_target_throttle_load('t_load', 'cur.example', 60)) = 1,
         'a target with a row answers one row';

  ASSERT (SELECT array_agg(row(tt.ctid, tt.*)::text ORDER BY tt.throttle_rule_name, tt.target_name) FROM target_throttle AS tt) = rows_before,
         'the reads wrote no row of target_throttle';

  ASSERT (SELECT NOT is_charged FROM api.fn_target_throttle_charge('t_load', 'full.example', 60, 1, 5)),
         'a charge refuses the target whose load is at the limit';
  ASSERT (SELECT is_charged FROM api.fn_target_throttle_charge('t_load', 'ahead.example', 60, 5, 5)),
         'a charge counts the row two windows ahead from 0, as the load answered';
END
$$;

DO $$
BEGIN
  ASSERT (SELECT NOT prosecdef AND NOT proisstrict AND provolatile = 's' AND proconfig IS NULL FROM pg_proc
          WHERE oid = 'api.fn_target_throttle_is_window_kept(integer, timestamptz, integer, timestamptz)'::regprocedure),
         'api.fn_target_throttle_is_window_kept is SECURITY INVOKER, not STRICT, STABLE, and sets nothing';
  ASSERT (SELECT prosecdef AND NOT proisstrict AND provolatile = 'v' FROM pg_proc
          WHERE oid = 'api.fn_target_throttle_charge(text, text, integer, integer, integer)'::regprocedure),
         'api.fn_target_throttle_charge is SECURITY DEFINER, not STRICT, and VOLATILE';
  ASSERT (SELECT prosecdef AND proisstrict AND provolatile = 'v' FROM pg_proc
          WHERE oid = 'api.fn_target_throttle_purge(integer)'::regprocedure),
         'api.fn_target_throttle_purge is SECURITY DEFINER, STRICT, and VOLATILE';
  ASSERT (SELECT prosecdef AND NOT proisstrict AND provolatile = 's' FROM pg_proc
          WHERE oid = 'api.fn_target_throttle_load(text, text, integer)'::regprocedure),
         'api.fn_target_throttle_load is SECURITY DEFINER, not STRICT, and STABLE';
  ASSERT (SELECT array_agg(proconfig::text) FROM pg_proc
          WHERE oid IN ('api.fn_target_throttle_charge(text, text, integer, integer, integer)'::regprocedure,
                        'api.fn_target_throttle_purge(integer)'::regprocedure,
                        'api.fn_target_throttle_load(text, text, integer)'::regprocedure))
         = ARRAY['{search_path=pg_catalog}', '{search_path=pg_catalog}', '{search_path=pg_catalog}'],
         'the charge, the purge and the load set search_path to pg_catalog';
  ASSERT (SELECT relpersistence FROM pg_class WHERE oid = 'target_throttle'::regclass) = 'p',
         'target_throttle is a logged table';
END
$$;
