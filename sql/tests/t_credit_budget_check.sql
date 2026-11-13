INSERT INTO credit_budget (ip_hash, has_key, credit_count, window_start) VALUES
  ('t-charge-current', false, 25, date_trunc('hour', now())),
  ('t-charge-current', true,  7,  date_trunc('hour', now())),
  ('t-charge-ended',   false, 29, date_trunc('hour', now()) - interval '1 second'),
  ('t-charge-other',   false, 3,  date_trunc('hour', now()));

CREATE TEMP VIEW t_credit_budget_used_call AS
  SELECT * FROM api.fn_credit_budget_used('t-charge-current', false);
CREATE TEMP VIEW t_credit_budget_charge_call AS
  SELECT * FROM api.fn_credit_budget_charge('t-charge-view', false, 1, 1);

DO $$
BEGIN
  ASSERT (SELECT array_agg(attname::text ORDER BY attnum) FROM pg_attribute
          WHERE attrelid = 't_credit_budget_used_call'::regclass AND attnum > 0)
         = ARRAY['credit_count', 'window_expired'],
         'api.fn_credit_budget_used answers credit_count and window_expired, in that order';
  ASSERT (SELECT array_agg(format_type(atttypid, atttypmod) ORDER BY attnum) FROM pg_attribute
          WHERE attrelid = 't_credit_budget_used_call'::regclass AND attnum > 0)
         = ARRAY['integer', 'boolean'],
         'api.fn_credit_budget_used answers an integer and a boolean';
  ASSERT (SELECT array_agg(attname::text ORDER BY attnum) FROM pg_attribute
          WHERE attrelid = 't_credit_budget_charge_call'::regclass AND attnum > 0)
         = ARRAY['credit_count'],
         'api.fn_credit_budget_charge answers one column, credit_count';
  ASSERT (SELECT array_agg(format_type(atttypid, atttypmod) ORDER BY attnum) FROM pg_attribute
          WHERE attrelid = 't_credit_budget_charge_call'::regclass AND attnum > 0)
         = ARRAY['integer'],
         'api.fn_credit_budget_charge answers an integer';
END
$$;

DO $$
BEGIN
  ASSERT (SELECT row(credit_count, window_expired)::text
            FROM api.fn_credit_budget_used('t-charge-current', false))
         = row(25, false)::text,
         'a row of the current hour answers its count, with window_expired false';
  ASSERT (SELECT row(credit_count, window_expired)::text
            FROM api.fn_credit_budget_used('t-charge-current', true))
         = row(7, false)::text,
         'the key bucket of an ip_hash answers its own count';
  ASSERT (SELECT row(credit_count, window_expired)::text
            FROM api.fn_credit_budget_used('t-charge-ended', false))
         = row(29, true)::text,
         'a row whose window ended one second ago answers window_expired true';
  ASSERT (SELECT count(*) FROM api.fn_credit_budget_used('t-charge-none', false)) = 0,
         'a bucket with no row answers no row';
  ASSERT (SELECT count(*) FROM api.fn_credit_budget_used('t-charge-ended', true)) = 0,
         'an ip_hash whose row has the other has_key answers no row';
END
$$;

DO $$
BEGIN
  ASSERT (SELECT array_agg(credit_count) FROM api.fn_credit_budget_charge('t-charge-new', false, 5, 30))
         = ARRAY[5],
         'a bucket with no row gets a row whose count is the charge';
  ASSERT (SELECT window_start = date_trunc('hour', now()) FROM credit_budget
          WHERE ip_hash = 't-charge-new' AND NOT has_key),
         'the new row starts its window at the current hour';
  ASSERT (SELECT array_agg(credit_count) FROM api.fn_credit_budget_charge('t-charge-new', false, 4, 30))
         = ARRAY[9],
         'a second charge in the same hour adds to the count';
  ASSERT (SELECT array_agg(credit_count) FROM api.fn_credit_budget_charge('t-charge-current', false, 5, 30))
         = ARRAY[30],
         'a charge that brings the count to the limit is written';
  ASSERT (SELECT count(*) FROM api.fn_credit_budget_charge('t-charge-current', false, 1, 30)) = 0,
         'a charge one credit past the limit answers no row';
  ASSERT (SELECT credit_count FROM credit_budget WHERE ip_hash = 't-charge-current' AND NOT has_key)
         = 30,
         'a refused charge leaves the count as it was';
  ASSERT (SELECT array_agg(credit_count) FROM api.fn_credit_budget_charge('t-charge-ended', false, 5, 30))
         = ARRAY[5],
         'an ended window counts as 0, so its count starts again from the charge';
  ASSERT (SELECT window_start = date_trunc('hour', now()) FROM credit_budget
          WHERE ip_hash = 't-charge-ended' AND NOT has_key),
         'the charge moves an ended window to the current hour';
  ASSERT (SELECT array_agg(credit_count) FROM api.fn_credit_budget_charge('t-charge-current', true, 3, 10))
         = ARRAY[10],
         'p_credit_limit is the fourth argument: 7 plus a charge of 3 fits a limit of 10';
  ASSERT (SELECT count(*) FROM api.fn_credit_budget_charge('t-charge-current', true, 1, 10)) = 0,
         '10 plus a charge of 1 does not fit a limit of 10';
  ASSERT (SELECT array_agg(row(ip_hash, has_key, credit_count)::text ORDER BY ip_hash, has_key)
            FROM credit_budget WHERE ip_hash LIKE 't-charge-%')
         = ARRAY[row('t-charge-current', false, 30)::text, row('t-charge-current', true, 10)::text,
                 row('t-charge-ended', false, 5)::text, row('t-charge-new', false, 9)::text,
                 row('t-charge-other', false, 3)::text],
         'each charge wrote only the row of its bucket';
END
$$;

PREPARE t_credit_budget_used_query AS SELECT * FROM api.fn_credit_budget_used($1, $2);
PREPARE t_credit_budget_charge_query AS
  SELECT * FROM api.fn_credit_budget_charge($1, $2, $3, $4);
CREATE TEMP TABLE t_credit_budget_charge_answer AS
  EXECUTE t_credit_budget_charge_query('t-charge-text', 'false', '5', '30');
CREATE TEMP TABLE t_credit_budget_used_answer AS
  EXECUTE t_credit_budget_used_query('t-charge-text', 'false');
DEALLOCATE t_credit_budget_used_query;
DEALLOCATE t_credit_budget_charge_query;

DO $$
BEGIN
  ASSERT (SELECT array_agg(credit_count) FROM t_credit_budget_charge_answer) = ARRAY[5],
         'the charge query ratelimit_dbCreditBudgetCheck sends writes its charge';
  ASSERT (SELECT array_agg(row(credit_count, window_expired)::text) FROM t_credit_budget_used_answer)
         = ARRAY[row(5, false)::text],
         'the read query ratelimit_dbCreditBudgetCheck sends answers the row of its bucket';
END
$$;

DO $$
BEGIN
  ASSERT (SELECT prosecdef AND NOT proisstrict AND provolatile = 's' FROM pg_proc
          WHERE oid = 'api.fn_credit_budget_used(text, boolean)'::regprocedure),
         'api.fn_credit_budget_used is SECURITY DEFINER, not STRICT, and STABLE';
  ASSERT (SELECT prosecdef AND NOT proisstrict AND provolatile = 'v' FROM pg_proc
          WHERE oid = 'api.fn_credit_budget_charge(text, boolean, integer, integer)'::regprocedure),
         'api.fn_credit_budget_charge is SECURITY DEFINER, not STRICT, and VOLATILE';
  ASSERT (SELECT array_agg(proconfig::text) FROM pg_proc
          WHERE oid IN ('api.fn_credit_budget_used(text, boolean)'::regprocedure,
                        'api.fn_credit_budget_charge(text, boolean, integer, integer)'::regprocedure))
         = ARRAY['{search_path=pg_catalog}', '{search_path=pg_catalog}'],
         'both functions set search_path to pg_catalog';
END
$$;
