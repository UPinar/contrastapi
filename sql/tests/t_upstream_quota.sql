INSERT INTO upstream_quota (source_name, window_seconds, window_start, granted_call_count, refused_call_count) VALUES
  ('t_quota_full',  60,   api.fn_current_window_start(60),                       3, 4),
  ('t_quota_ended', 60,   api.fn_current_window_start(60) - interval '1 minute', 3, 0),
  ('t_quota_hour',  3600, api.fn_current_window_start(3600),                     3, 0);

PREPARE t_upstream_quota_reserve_query AS SELECT api.fn_upstream_quota_reserve($1, $2, $3) AS is_granted;
PREPARE t_upstream_quota_mark_exhausted_query AS SELECT api.fn_upstream_quota_mark_exhausted($1, $2, $3) AS is_marked;
PREPARE t_upstream_quota_purge_query AS SELECT api.fn_upstream_quota_purge($1) AS purged_row_count;
CREATE TEMP TABLE t_upstream_quota_reserve_answer AS EXECUTE t_upstream_quota_reserve_query('t_quota_text', '60', '5');
CREATE TEMP TABLE t_upstream_quota_mark_exhausted_answer AS EXECUTE t_upstream_quota_mark_exhausted_query('t_quota_text', '60', '5');
CREATE TEMP TABLE t_upstream_quota_purge_answer AS EXECUTE t_upstream_quota_purge_query('0');
DEALLOCATE t_upstream_quota_reserve_query;
DEALLOCATE t_upstream_quota_mark_exhausted_query;
DEALLOCATE t_upstream_quota_purge_query;

DO $$
BEGIN
  ASSERT (SELECT array_agg(attname::text || ' ' || format_type(atttypid, atttypmod) ORDER BY attnum) FROM pg_attribute
          WHERE attrelid = 't_upstream_quota_reserve_answer'::regclass AND attnum > 0)
         = ARRAY['is_granted boolean'],
         'the reserve query quota.c sends answers one boolean column, is_granted';
  ASSERT (SELECT array_agg(is_granted) FROM t_upstream_quota_reserve_answer) = ARRAY[true],
         'the reserve query takes a call of a new source';
  ASSERT (SELECT array_agg(attname::text || ' ' || format_type(atttypid, atttypmod) ORDER BY attnum) FROM pg_attribute
          WHERE attrelid = 't_upstream_quota_mark_exhausted_answer'::regclass AND attnum > 0)
         = ARRAY['is_marked boolean'],
         'the mark_exhausted query quota.c sends answers one boolean column, is_marked';
  ASSERT (SELECT array_agg(is_marked) FROM t_upstream_quota_mark_exhausted_answer) = ARRAY[true],
         'the mark_exhausted query answers true';
  ASSERT (SELECT granted_call_count FROM upstream_quota WHERE source_name = 't_quota_text' AND window_seconds = 60) = 5,
         'the mark_exhausted query raises the count of the source to its limit';
  ASSERT (SELECT array_agg(attname::text || ' ' || format_type(atttypid, atttypmod) ORDER BY attnum) FROM pg_attribute
          WHERE attrelid = 't_upstream_quota_purge_answer'::regclass AND attnum > 0)
         = ARRAY['purged_row_count integer'],
         'the purge query quota.c sends answers one integer column, purged_row_count';
END
$$;

DO $$
BEGIN
  ASSERT api.fn_upstream_quota_reserve('t_quota_new', 60, 2), 'the first call of a new source within its limit is granted';
  ASSERT api.fn_upstream_quota_reserve('t_quota_new', 60, 2), 'a call that brings granted_call_count to the limit is granted';
  ASSERT NOT api.fn_upstream_quota_reserve('t_quota_new', 60, 2), 'a call one past the limit is refused';
  ASSERT (SELECT row(granted_call_count, refused_call_count)::text FROM upstream_quota WHERE source_name = 't_quota_new')
         = row(2, 1)::text,
         'two granted calls count in granted_call_count, and the refused one in refused_call_count';
  ASSERT (SELECT window_start = api.fn_current_window_start(60) FROM upstream_quota WHERE source_name = 't_quota_new'),
         'the new row starts at the current window';

  ASSERT NOT api.fn_upstream_quota_reserve('t_quota_zero', 60, 0), 'a limit of 0 refuses the first call of a window';
  ASSERT NOT api.fn_upstream_quota_reserve('t_quota_zero', 60, 0), 'a limit of 0 refuses the next call too';
  ASSERT (SELECT row(granted_call_count, refused_call_count)::text FROM upstream_quota WHERE source_name = 't_quota_zero')
         = row(0, 2)::text,
         'a limit of 0 writes one row, with granted_call_count 0 and both refusals in refused_call_count';

  ASSERT NOT api.fn_upstream_quota_reserve('t_quota_full', 60, 3), 'a source whose granted_call_count is at its limit refuses';
  ASSERT (SELECT row(granted_call_count, refused_call_count)::text FROM upstream_quota WHERE source_name = 't_quota_full')
         = row(3, 5)::text,
         'the refusal adds 1 to the stored refused_call_count and leaves granted_call_count as it was';
  ASSERT api.fn_upstream_quota_reserve('t_quota_full', 60, 4), 'p_call_limit is the third argument: a limit of 4 grants a fourth call';

  ASSERT api.fn_upstream_quota_reserve('t_quota_ended', 60, 3), 'a source whose last window ended full is granted in the current window';
  ASSERT (SELECT array_agg(granted_call_count ORDER BY window_start) FROM upstream_quota WHERE source_name = 't_quota_ended')
         = ARRAY[3, 1],
         'the current window gets its own row, and the row of the ended window stays';

  ASSERT api.fn_upstream_quota_reserve('t_quota_hour', 60, 3), 'a full hour window does not count against a minute window of the same source';
  ASSERT NOT api.fn_upstream_quota_reserve('t_quota_hour', 3600, 3), 'p_window_seconds is the second argument: the full hour window refuses';
  ASSERT (SELECT array_agg(row(window_seconds, granted_call_count, refused_call_count)::text ORDER BY window_seconds)
            FROM upstream_quota WHERE source_name = 't_quota_hour')
         = ARRAY[row(60, 1, 0)::text, row(3600, 3, 1)::text],
         'each window length counts in its own row';
  ASSERT (SELECT array_agg(row(source_name, granted_call_count, refused_call_count)::text ORDER BY source_name, window_start)
            FROM upstream_quota WHERE source_name LIKE 't_quota_%' AND window_seconds = 60)
         = ARRAY[row('t_quota_ended', 3, 0)::text, row('t_quota_ended', 1, 0)::text, row('t_quota_full', 4, 5)::text,
                 row('t_quota_hour', 1, 0)::text, row('t_quota_new', 2, 1)::text, row('t_quota_text', 5, 0)::text,
                 row('t_quota_zero', 0, 2)::text],
         'each call wrote only the row of its source';
END
$$;

DO $$
BEGIN
  ASSERT api.fn_upstream_quota_mark_exhausted('t_quota_new', 60, 7), 'marking the window of a count of 2 answers true';
  ASSERT (SELECT granted_call_count FROM upstream_quota WHERE source_name = 't_quota_new') = 7, 'a count of 2 rises to a limit of 7';
  ASSERT NOT api.fn_upstream_quota_reserve('t_quota_new', 60, 7), 'a reserve after the window is marked exhausted is refused';
  ASSERT api.fn_upstream_quota_mark_exhausted('t_quota_full', 60, 2), 'marking the window of a count of 4 answers true';
  ASSERT (SELECT granted_call_count FROM upstream_quota WHERE source_name = 't_quota_full') = 4, 'a count of 4 stays above a limit of 2';
  ASSERT api.fn_upstream_quota_mark_exhausted('t_quota_spent', 3600, 9), 'marking a source with no row answers true';
  ASSERT (SELECT row(window_seconds, granted_call_count, refused_call_count)::text FROM upstream_quota WHERE source_name = 't_quota_spent')
         = row(3600, 9, 0)::text,
         'marking a window exhausted writes the window length it is given and counts no refusal';
  ASSERT NOT api.fn_upstream_quota_reserve('t_quota_spent', 3600, 9), 'a reserve of an hour window that was marked exhausted is refused';
END
$$;

INSERT INTO upstream_quota (source_name, window_seconds, window_start, granted_call_count, refused_call_count) VALUES
  ('t_purge_kept',  60,   now() - interval '35 days 1 minute',          1, 0),
  ('t_purge_old_a', 60,   now() - interval '35 days 1 minute 1 second', 1, 0),
  ('t_purge_old_b', 3600, now() - interval '35 days 1 hour 1 second',   1, 0),
  ('t_purge_hour',  3600, now() - interval '35 days 1 hour',            1, 0);

DO $$
BEGIN
  ASSERT api.fn_upstream_quota_purge(NULL) IS NULL, 'a NULL row limit answers NULL';
  ASSERT (SELECT count(*) FROM upstream_quota WHERE source_name LIKE 't_purge_%') = 4, 'a NULL row limit deletes nothing';
  ASSERT api.fn_upstream_quota_purge(1) = 1, 'a row limit of 1 deletes one of the two old rows';
  ASSERT api.fn_upstream_quota_purge(10) = 1, 'the next call deletes the other old row';
  ASSERT api.fn_upstream_quota_purge(10) = 0, 'a call with no old row deletes none';
  ASSERT (SELECT array_agg(source_name ORDER BY source_name) FROM upstream_quota WHERE source_name LIKE 't_purge_%')
         = ARRAY['t_purge_hour', 't_purge_kept'],
         'a row whose window ended exactly 35 days ago stays';
  ASSERT (SELECT count(*) FROM upstream_quota WHERE source_name LIKE 't_quota_%') = 9,
         'the purge keeps each row of the earlier tests';
END
$$;

DO $$
DECLARE
  refused_by text;
BEGIN
  BEGIN
    PERFORM api.fn_upstream_quota_reserve('t_quota_bad', 61, 1);
    ASSERT false, 'a window of 61 seconds is refused';
  EXCEPTION WHEN check_violation THEN
    GET STACKED DIAGNOSTICS refused_by = CONSTRAINT_NAME;
    ASSERT refused_by = 'upstream_quota_window_seconds', 'upstream_quota_window_seconds refuses a window of 61 seconds';
  END;
  BEGIN
    PERFORM api.fn_upstream_quota_reserve('t_window_bad', 11, 1);
    ASSERT false, 'a window of 11 seconds is refused';
  EXCEPTION WHEN check_violation THEN
    GET STACKED DIAGNOSTICS refused_by = CONSTRAINT_NAME;
    ASSERT refused_by = 'upstream_quota_window_seconds', 'upstream_quota_window_seconds refuses a window of 11 seconds';
  END;
  ASSERT api.fn_upstream_quota_reserve('t_window_ten', 10, 1), 'a window of 10 seconds is accepted';
  ASSERT (SELECT row(window_seconds, granted_call_count)::text FROM upstream_quota WHERE source_name = 't_window_ten')
         = '(10,1)', 'the call of a 10-second window is counted in a row of that window';
  BEGIN
    PERFORM api.fn_upstream_quota_reserve('T_quota_bad', 60, 1);
    ASSERT false, 'a source name with a capital letter is refused';
  EXCEPTION WHEN check_violation THEN
    GET STACKED DIAGNOSTICS refused_by = CONSTRAINT_NAME;
    ASSERT refused_by = 'upstream_quota_source_name_format', 'upstream_quota_source_name_format refuses a capital letter';
  END;
  BEGIN
    PERFORM api.fn_upstream_quota_reserve('t' || repeat('x', 32), 60, 1);
    ASSERT false, 'a source name of 33 bytes is refused';
  EXCEPTION WHEN check_violation THEN
    GET STACKED DIAGNOSTICS refused_by = CONSTRAINT_NAME;
    ASSERT refused_by = 'upstream_quota_source_name_format', 'upstream_quota_source_name_format refuses a name of 33 bytes';
  END;
  BEGIN
    PERFORM api.fn_upstream_quota_mark_exhausted('t_quota_bad', 60, -1);
    ASSERT false, 'a negative count is refused';
  EXCEPTION WHEN check_violation THEN
    GET STACKED DIAGNOSTICS refused_by = CONSTRAINT_NAME;
    ASSERT refused_by = 'upstream_quota_counts', 'upstream_quota_counts refuses a negative granted_call_count';
  END;
  ASSERT api.fn_upstream_quota_reserve('t' || repeat('x', 31), 60, 1), 'a source name of 32 bytes is written';
  ASSERT api.fn_upstream_quota_reserve('t_quota_day', 86400, 1), 'a window of a day is written';
END
$$;

DO $$
BEGIN
  ASSERT (SELECT prosecdef AND NOT proisstrict AND provolatile = 'v' FROM pg_proc
          WHERE oid = 'api.fn_upstream_quota_reserve(text, integer, integer)'::regprocedure),
         'api.fn_upstream_quota_reserve is SECURITY DEFINER, not STRICT, and VOLATILE';
  ASSERT (SELECT prosecdef AND NOT proisstrict AND provolatile = 'v' FROM pg_proc
          WHERE oid = 'api.fn_upstream_quota_mark_exhausted(text, integer, integer)'::regprocedure),
         'api.fn_upstream_quota_mark_exhausted is SECURITY DEFINER, not STRICT, and VOLATILE';
  ASSERT (SELECT prosecdef AND proisstrict AND provolatile = 'v' FROM pg_proc
          WHERE oid = 'api.fn_upstream_quota_purge(integer)'::regprocedure),
         'api.fn_upstream_quota_purge is SECURITY DEFINER, STRICT, and VOLATILE';
  ASSERT (SELECT array_agg(proconfig::text) FROM pg_proc
          WHERE oid IN ('api.fn_upstream_quota_reserve(text, integer, integer)'::regprocedure,
                        'api.fn_upstream_quota_mark_exhausted(text, integer, integer)'::regprocedure,
                        'api.fn_upstream_quota_purge(integer)'::regprocedure))
         = ARRAY['{search_path=pg_catalog}', '{search_path=pg_catalog}', '{search_path=pg_catalog}'],
         'the three functions set search_path to pg_catalog';
  ASSERT (SELECT relpersistence FROM pg_class WHERE oid = 'upstream_quota'::regclass) = 'p',
         'upstream_quota is a logged table';
END
$$;
