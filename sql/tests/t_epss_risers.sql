TRUNCATE epss_riser, epss_riser_window;

SELECT set_config('contrastapi.cve_events', 'off', true) AS t_epss_risers_events_off;
INSERT INTO cves (cve_id, in_kev, vulnerability_status) VALUES
  ('CVE-2026-8001', false, ''),
  ('CVE-2026-8002', true,  'Analyzed'),
  ('CVE-2026-8004', true,  ''),
  ('CVE-2026-8003', false, ''),
  ('CVE-2026-8005', false, ''),
  ('CVE-2026-8007', true,  'Rejected'),
  ('CVE-2026-8008', false, '');
SELECT set_config('contrastapi.cve_events', '', true) AS t_epss_risers_events_on;
INSERT INTO epss_riser (window_days, cve_id, previous_score, score, percentile, score_delta) VALUES
  (7,  'CVE-2026-8004', 0.15, 0.25,    0.6,  0.1),
  (7,  'CVE-2026-8001', 0.1,  0.6,     0.95, 0.5),
  (7,  'CVE-2026-8002', 0.2,  0.5,     0.9,  0.3),
  (7,  'CVE-2026-8003', 0.3,  0.4,     0.7,  0.1),
  (7,  'CVE-2026-8005', 0.45, 0.49999, 0.8,  0.04999),
  (7,  'CVE-2026-8007', 0.01, 0.9,     0.99, 0.89),
  (30, 'CVE-2026-8001', 0.05, 0.6,     0.95, 0.55),
  (30, 'CVE-2026-8008', 0.3,  0.9,     0.97, 0.6);

INSERT INTO cve_products (cve_id, vendor, product, is_vulnerable) VALUES
  ('CVE-2026-8001', 'acme',  'widget', true),
  ('CVE-2026-8002', 'acme',  'gadget', true),
  ('CVE-2026-8002', 'acme',  'gizmo',  true),
  ('CVE-2026-8003', 'other', 'widget', true),
  ('CVE-2026-8004', 'acme',  'x',      true),
  ('CVE-2026-8004', 'y',     'widget', true),
  ('CVE-2026-8004', 'z',     'widget', true),
  ('CVE-2026-8005', 'acme',  'widget', false),
  ('CVE-2026-8007', 'acme',  'widget', true);

CREATE TEMP TABLE t_epss_risers_case (
  label       text,
  window_days integer,
  min_epss    real,
  in_kev      boolean,
  vendor      text,
  product     text,
  expected    text[]);
INSERT INTO t_epss_risers_case VALUES
  ('window 7, no filter',  7,    NULL,  NULL, NULL,   NULL,     '{01,02,03,04,05}'),
  ('window 30, no filter', 30,   NULL,  NULL, NULL,   NULL,     '{08,01}'),
  ('a window with no row', 90,   NULL,  NULL, NULL,   NULL,     '{}'),
  ('a NULL window',        NULL, NULL,  NULL, NULL,   NULL,     '{}'),
  ('min_epss at a score',  7,    0.5,   NULL, NULL,   NULL,     '{01,02}'),
  ('min_epss 0',           7,    0,     NULL, NULL,   NULL,     '{01,02,03,04,05}'),
  ('in_kev true',          7,    NULL,  true, NULL,   NULL,     '{02,04}'),
  ('in_kev false',         7,    NULL,  false, NULL,  NULL,     '{01,03,05}'),
  ('vendor',               7,    NULL,  NULL, 'acme', NULL,     '{01,02,04}'),
  ('product',              7,    NULL,  NULL, NULL,   'widget', '{01,03,04}'),
  ('vendor and product',   7,    NULL,  NULL, 'acme', 'widget', '{01}'),
  ('every filter',         7,    0.5,   false, 'acme', 'widget', '{01}'),
  ('window 30 and vendor', 30,   NULL,  NULL, 'acme', NULL,     '{01}'),
  ('vendor with a _',      7,    NULL,  NULL, 'ac_e', NULL,     '{}'),
  ('product with a _',     7,    NULL,  NULL, NULL,   'wid_et', '{}');

SET enable_indexscan = off;
SET enable_indexonlyscan = off;
SET enable_bitmapscan = off;
SET enable_mergejoin = off;
DO $$
DECLARE
  test_case record;
  answered  text[];
  page_offset integer;
BEGIN
  FOR test_case IN SELECT * FROM t_epss_risers_case LOOP
    answered := (SELECT coalesce(array_agg(right(r.cve_id, 2) ORDER BY r.ordinality), '{}')
                   FROM api.fn_epss_risers(test_case.window_days, test_case.min_epss, test_case.in_kev,
                                           test_case.vendor, test_case.product, 100, 0) WITH ORDINALITY AS r);
    ASSERT answered = test_case.expected,
           format('api.fn_epss_risers, %s: %s, expected %s', test_case.label, answered, test_case.expected);
    answered := '{}';
    FOR page_offset IN 0 .. cardinality(test_case.expected) LOOP
      answered := answered || (SELECT coalesce(array_agg(right(r.cve_id, 2)), '{}')
                                 FROM api.fn_epss_risers(test_case.window_days, test_case.min_epss, test_case.in_kev,
                                                         test_case.vendor, test_case.product, 1, page_offset) AS r);
    END LOOP;
    ASSERT answered = test_case.expected,
           format('api.fn_epss_risers, %s, one row a page: %s, expected %s', test_case.label, answered, test_case.expected);
    ASSERT api.fn_epss_risers_match_count(test_case.window_days, test_case.min_epss, test_case.in_kev,
                                          test_case.vendor, test_case.product) = cardinality(test_case.expected),
           format('api.fn_epss_risers_match_count, %s: the total equals the rows of the page with no limit', test_case.label);
  END LOOP;
END
$$;
RESET enable_indexscan;
RESET enable_indexonlyscan;
RESET enable_bitmapscan;
RESET enable_mergejoin;

DO $$
BEGIN
  ASSERT (SELECT ROW(r.cve_id, r.epss_score, r.epss_previous_score, r.epss_delta, r.epss_percentile, r.in_kev)
            FROM api.fn_epss_risers(7, NULL, NULL, NULL, NULL, 100, 0) AS r
           WHERE r.cve_id = 'CVE-2026-8002')
         = ROW('CVE-2026-8002'::text, 0.5::real, 0.2::real, 0.3::real, 0.9::real, true),
         'api.fn_epss_risers answers score, previous_score, score_delta, percentile and in_kev in their own columns';
  ASSERT (SELECT ROW(r.epss_score, r.epss_previous_score, r.epss_delta, r.epss_percentile, r.in_kev)
            FROM api.fn_epss_risers(30, NULL, NULL, NULL, NULL, 100, 0) AS r
           WHERE r.cve_id = 'CVE-2026-8001')
         = ROW(0.6::real, 0.05::real, 0.55::real, 0.95::real, false),
         'a CVE stored for two windows answers the values of the window asked for';
END
$$;

DO $$
BEGIN
  ASSERT NOT EXISTS (SELECT 1 FROM api.fn_epss_risers(7, NULL, NULL, 'acme', 'widget', 100, 0) AS r
                      WHERE r.cve_id = 'CVE-2026-8007'),
         'api.fn_epss_risers leaves out a CVE that NVD marks Rejected';
  ASSERT api.fn_epss_risers_match_count(7, NULL, true, 'acme', 'widget') = 0,
         'api.fn_epss_risers_match_count leaves out a CVE that NVD marks Rejected';
END
$$;

DO $$
BEGIN
  ASSERT (SELECT array_agg(right(r.cve_id, 2) ORDER BY r.ordinality)
            FROM api.fn_epss_risers(7, NULL, NULL, NULL, NULL, 2, 0) WITH ORDINALITY AS r) = '{01,02}',
         'api.fn_epss_risers answers the first page';
  ASSERT (SELECT array_agg(right(r.cve_id, 2) ORDER BY r.ordinality)
            FROM api.fn_epss_risers(7, NULL, NULL, NULL, NULL, 2, 2) WITH ORDINALITY AS r) = '{03,04}',
         'api.fn_epss_risers answers the second page after the first, with no repeat';
  ASSERT (SELECT array_agg(right(r.cve_id, 2) ORDER BY r.ordinality)
            FROM api.fn_epss_risers(7, NULL, NULL, NULL, NULL, 2, 4) WITH ORDINALITY AS r) = '{05}',
         'api.fn_epss_risers answers the last row on the third page';
  ASSERT (SELECT count(*) FROM api.fn_epss_risers(7, NULL, NULL, NULL, NULL, NULL, 0)) = 0,
         'api.fn_epss_risers answers no row for a NULL row count';
  ASSERT (SELECT count(*) FROM api.fn_epss_risers(7, NULL, NULL, NULL, NULL, 100, NULL)) = 0,
         'api.fn_epss_risers answers no row for a NULL row offset';
END
$$;

INSERT INTO epss_riser_window (window_days, from_date, to_date) VALUES
  (7,  '2026-11-12', '2026-11-19'),
  (30, NULL,         '2026-11-18');
DO $$
BEGIN
  ASSERT (SELECT array_agg(w.from_date || '/' || w.to_date) FROM api.fn_epss_risers_window(7) AS w) = '{2026-11-12/2026-11-19}',
         'api.fn_epss_risers_window answers both dates of a computed window';
  ASSERT (SELECT array_agg(w.from_date || '/' || w.to_date) FROM api.fn_epss_risers_window(30) AS w) = '{/2026-11-18}',
         'api.fn_epss_risers_window answers an empty from_date and the to_date of a window it could not compute';
  ASSERT (SELECT array_agg(w.from_date || '/' || w.to_date) FROM api.fn_epss_risers_window(90) AS w) = '{/}',
         'api.fn_epss_risers_window answers two empty dates for a window with no row';
  ASSERT (SELECT array_agg(w.from_date || '/' || w.to_date) FROM api.fn_epss_risers_window(NULL) AS w) = '{/}',
         'api.fn_epss_risers_window answers two empty dates for a NULL window';
END
$$;

DO $$
DECLARE
  saved_time_zone text := current_setting('TimeZone');
BEGIN
  UPDATE epss_riser_window SET from_date = '2011-12-30', to_date = '2011-12-30' WHERE window_days = 7;
  PERFORM set_config('TimeZone', 'Pacific/Apia', true);
  ASSERT (SELECT w.from_date || '/' || w.to_date FROM api.fn_epss_risers_window(7) AS w) = '2011-12-30/2011-12-30',
         'api.fn_epss_risers_window prints a date in a session zone that skipped that day';
  PERFORM set_config('TimeZone', saved_time_zone, true);
  UPDATE epss_riser_window SET from_date = '2026-11-12', to_date = '2026-11-19' WHERE window_days = 7;
END
$$;

PREPARE t_epss_risers_window_query AS SELECT * FROM api.fn_epss_risers_window($1);
PREPARE t_epss_risers_match_count_query AS SELECT api.fn_epss_risers_match_count($1, $2, $3, $4, $5) AS cve_count;
PREPARE t_epss_risers_query AS SELECT * FROM api.fn_epss_risers($1, $2, $3, $4, $5, $6, $7);
CREATE TEMP TABLE t_epss_risers_window_answer AS EXECUTE t_epss_risers_window_query('7');
CREATE TEMP TABLE t_epss_risers_match_count_answer AS
  EXECUTE t_epss_risers_match_count_query('7', '0.250000', 'false', 'acme', NULL);
CREATE TEMP TABLE t_epss_risers_answer AS
  EXECUTE t_epss_risers_query('7', '0.250000', 'false', 'acme', NULL, '1', '0');
DEALLOCATE t_epss_risers_window_query;
DEALLOCATE t_epss_risers_match_count_query;
DEALLOCATE t_epss_risers_query;
DO $$
BEGIN
  ASSERT (SELECT array_agg(from_date || '/' || to_date) FROM t_epss_risers_window_answer) = '{2026-11-12/2026-11-19}',
         'the window call db.c sends answers the dates';
  ASSERT (SELECT array_agg(cve_id) FROM t_epss_risers_answer) = '{CVE-2026-8001}'
     AND (SELECT cve_count FROM t_epss_risers_match_count_answer) = 1,
         'the /epss_risers calls db.c sends answer the page and the total';
END
$$;

DO $$
BEGIN
  ASSERT pg_get_function_result('api.fn_epss_risers(integer, real, boolean, text, text, integer, integer)'::regprocedure)
         = 'TABLE(cve_id text, epss_score real, epss_previous_score real, epss_delta real, '
           'epss_percentile real, in_kev boolean)',
         'api.fn_epss_risers answers the six row columns';
  ASSERT pg_get_function_result('api.fn_epss_risers_match_count(integer, real, boolean, text, text)'::regprocedure) = 'bigint',
         'api.fn_epss_risers_match_count answers one bigint';
  ASSERT pg_get_function_result('api.fn_epss_risers_window(integer)'::regprocedure)
         = 'TABLE(from_date text, to_date text)',
         'api.fn_epss_risers_window answers the two dates as text';
END
$$;

CREATE TEMP TABLE epss_riser (LIKE public.epss_riser);
CREATE TEMP TABLE epss_riser_window (LIKE public.epss_riser_window);
CREATE TEMP TABLE cves (LIKE public.cves);
CREATE TEMP TABLE cve_products (LIKE public.cve_products);
DO $$
BEGIN
  ASSERT (SELECT array_agg(right(r.cve_id, 2) ORDER BY r.ordinality)
            FROM api.fn_epss_risers(7, NULL, NULL, 'acme', NULL, 100, 0) WITH ORDINALITY AS r) = '{01,02,04}'
     AND api.fn_epss_risers_match_count(7, NULL, NULL, 'acme', NULL) = 3
     AND (SELECT w.from_date FROM api.fn_epss_risers_window(7) AS w) = '2026-11-12',
         'the /epss_risers functions read the tables of public while temporary tables share their names';
END
$$;
DROP TABLE pg_temp.epss_riser, pg_temp.epss_riser_window, pg_temp.cves, pg_temp.cve_products;

DO $$
BEGIN
  ASSERT (SELECT bool_and(prosecdef
                          AND proconfig IS NOT DISTINCT FROM ARRAY['search_path=pg_catalog']
                          AND provolatile = 's')
            FROM pg_proc
           WHERE pronamespace = 'api'::regnamespace
             AND proname IN ('fn_epss_risers', 'fn_epss_risers_match_count', 'fn_epss_risers_window'))
     AND (SELECT count(*) FROM pg_proc
           WHERE pronamespace = 'api'::regnamespace
             AND proname IN ('fn_epss_risers', 'fn_epss_risers_match_count', 'fn_epss_risers_window')) = 3,
         'the three /epss_risers functions are SECURITY DEFINER, STABLE and set search_path to pg_catalog';
END
$$;
