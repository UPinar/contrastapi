INSERT INTO credit_budget (ip_hash, has_key, credit_count, window_start) VALUES
  ('t-hour-start',     false, 1, date_trunc('hour', now())),
  ('t-hour-start',     true,  1, date_trunc('hour', now())),
  ('t-second-before',  false, 1, date_trunc('hour', now()) - interval '1 second'),
  ('t-hour-before',    true,  1, date_trunc('hour', now()) - interval '1 hour'),
  ('t-two-hours-a',    false, 1, date_trunc('hour', now()) - interval '2 hours'),
  ('t-two-hours-b',    false, 1, date_trunc('hour', now()) - interval '2 hours');

CREATE TEMP VIEW t_credit_budget_purge_call AS
  SELECT api.fn_credit_budget_purge(0) AS purged_row_count;

DO $$
BEGIN
  ASSERT api.fn_credit_budget_purge(NULL) IS NULL, 'a NULL limit answers NULL';
  ASSERT (SELECT count(*) FROM credit_budget) = 6, 'a NULL limit deletes nothing';
  ASSERT api.fn_credit_budget_purge(3) = 3, 'a limit of 3 deletes 3 of the 4 ended rows';
  ASSERT (SELECT count(*) FROM credit_budget WHERE window_start < date_trunc('hour', now())) = 1,
         'one ended row is left after the first call';
  ASSERT api.fn_credit_budget_purge(3) = 1, 'the next call deletes the last ended row';
  ASSERT api.fn_credit_budget_purge(3) = 0, 'a call with no ended row deletes none';
  ASSERT (SELECT count(*) FROM credit_budget WHERE ip_hash = 't-hour-start') = 2,
         'both rows whose window starts at the current hour stay';
  ASSERT (SELECT count(*) FROM credit_budget) = 2, 'only the two current rows are left';
  ASSERT (SELECT array_agg(attname::text || ' ' || format_type(atttypid, atttypmod) ORDER BY attnum)
            FROM pg_attribute
           WHERE attrelid = 't_credit_budget_purge_call'::regclass AND attnum > 0)
         = ARRAY['purged_row_count integer'],
         'the call ratelimit.c sends answers one integer column, purged_row_count';
END
$$;

DO $$
BEGIN
  ASSERT (SELECT prosecdef FROM pg_proc
          WHERE oid = 'api.fn_credit_budget_purge(integer)'::regprocedure),
         'api.fn_credit_budget_purge is SECURITY DEFINER';
  ASSERT (SELECT proconfig FROM pg_proc
          WHERE oid = 'api.fn_credit_budget_purge(integer)'::regprocedure)
         = ARRAY['search_path=pg_catalog'],
         'api.fn_credit_budget_purge sets search_path to pg_catalog';
END
$$;
