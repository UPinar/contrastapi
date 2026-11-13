DO $$
BEGIN
  ASSERT (SELECT array_agg(public.fn_epss_level_next(0::smallint, s.score) ORDER BY s.n)
            FROM unnest('{0,0.04999,0.05,0.09999,0.1,0.19999,0.2,0.29999,0.3,0.49999,0.5,0.69999,0.7,0.89999,0.9,1}'::real[])
                 WITH ORDINALITY AS s (score, n))
         = '{0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7}'::smallint[],
         'from level 0, a score reaches each level at the score of that level';
  ASSERT (SELECT array_agg(public.fn_epss_level_next(7::smallint, s.score) ORDER BY s.n)
            FROM unnest('{1,0.72,0.71999,0.56,0.55999,0.4,0.39999,0.24,0.23999,0.16,0.15999,0.08,0.07999,0.04,0.03999,0}'::real[])
                 WITH ORDINALITY AS s (score, n))
         = '{7,7,6,6,5,5,4,4,3,3,2,2,1,1,0,0}'::smallint[],
         'from level 7, a score keeps each level down to 0.8 times the score of that level';
  ASSERT public.fn_epss_level_next(2::smallint, 0.45) = 4 AND public.fn_epss_level_next(4::smallint, 0.17) = 3,
         'a score above the old level rises to its own level, and a score below the old level keeps each level whose margin it is in';
END
$$;

DO $$
BEGIN
  ASSERT public.fn_epss_level_scores() = '{0.05,0.1,0.2,0.3,0.5,0.7,0.9}'::numeric[], 'fn_epss_level_scores names the seven scores';
  ASSERT (SELECT array_agg(public.fn_epss_score_is_held(c.was_held, c.score, 0.1) ORDER BY c.n)
            FROM unnest('{false,false,false,true,true,true}'::boolean[], '{0.1,0.0999,0.09,0.1,0.08,0.0799}'::real[])
                 WITH ORDINALITY AS c (was_held, score, n))
         = '{true,false,false,true,true,false}'::boolean[],
         'fn_epss_score_is_held holds at the threshold, and keeps a held score down to 0.8 times the threshold';
  ASSERT (SELECT bool_and(p.provolatile = 'i' AND NOT p.prosecdef AND p.proconfig IS NULL)
            FROM pg_proc AS p
           WHERE p.oid IN ('public.fn_epss_level_scores()'::regprocedure, 'public.fn_epss_score_is_held(boolean, real, numeric)'::regprocedure)),
         'fn_epss_level_scores and fn_epss_score_is_held are IMMUTABLE and SECURITY INVOKER, and set no search_path';
END
$$;

INSERT INTO cves (cve_id) VALUES ('CVE-2005-0063');

DO $$
DECLARE
  c record;
BEGIN
  FOR c IN SELECT * FROM (VALUES
      ('a rise to the score of a level',         0::real,    0.049::real, 0.05::real,    1::smallint),
      ('a rise to just under a level',           0,    0.04,  0.04999, 0),
      ('a rise inside one cell under a level',   0,    0.0491, 0.0499, 0),
      ('a fall to 0.8 times a level',            0.5,  0.5,   0.4,     5),
      ('a fall to just under 0.8 times a level', 0.5,  0.5,   0.39999, 4),
      ('a small fall under 0.8 times a level',   0.05, 0.041, 0.03999, 0),
      ('a rise back after a small fall',         0.5,  0.45,  0.5,     5),
      ('a rise past the seven levels',           0,    0.01,  0.95,    7),
      ('a fall past the seven levels',           0.95, 0.95,  0,       0),
      ('no change at a level',                   0.3,  0.3,   0.3,     4))
      AS t (label, reached_score, previous_score, current_score, expected_level) LOOP
    UPDATE cves SET epss_score = 0 WHERE cve_id = 'CVE-2005-0063';
    UPDATE cves SET epss_score = c.reached_score WHERE cve_id = 'CVE-2005-0063';
    UPDATE cves SET epss_score = c.previous_score WHERE cve_id = 'CVE-2005-0063';
    UPDATE cves SET epss_score = c.current_score WHERE cve_id = 'CVE-2005-0063';
    ASSERT (SELECT epss_level FROM cves WHERE cve_id = 'CVE-2005-0063') = c.expected_level, 'epss_level, ' || c.label;
  END LOOP;

  INSERT INTO cves (cve_id, epss_score) VALUES ('CVE-2005-0064', 0.75), ('CVE-2005-0065', 0.3);
  ASSERT (SELECT array_agg(epss_level ORDER BY cve_id) FROM cves WHERE cve_id IN ('CVE-2005-0064', 'CVE-2005-0065')) = '{6,4}',
         'an insert sets epss_level from its score';
  BEGIN
    UPDATE cves SET epss_level = 8 WHERE cve_id = 'CVE-2005-0065';
    ASSERT false, 'cves_epss_level_range refuses a level above 7';
  EXCEPTION WHEN check_violation THEN
    NULL;
  END;
  BEGIN
    UPDATE cves SET epss_level = -1 WHERE cve_id = 'CVE-2005-0065';
    ASSERT false, 'cves_epss_level_range refuses a level below 0';
  EXCEPTION WHEN check_violation THEN
    NULL;
  END;
END
$$;

DO $$
BEGIN
  ASSERT (SELECT array_agg(k.conname::text || ':' || (SELECT count(*) FROM regexp_matches(pg_get_constraintdef(k.oid), '''([^'']*)''', 'g'))
                           ORDER BY k.conname)
            FROM pg_constraint AS k
           WHERE k.conname IN ('cve_change_event_type_known', 'domain_change_event_type_known', 'package_advisory_change_event_type_known',
                               'eol_change_event_type_known'))
         = '{cve_change_event_type_known:27,domain_change_event_type_known:21,eol_change_event_type_known:3,package_advisory_change_event_type_known:3}',
         'the CHECK cve_change_event_type_known allows 27 event types, the CHECK domain_change_event_type_known 21, '
         'the CHECK eol_change_event_type_known 3 and the CHECK package_advisory_change_event_type_known 3';
  ASSERT (SELECT max(octet_length(m.name[1]))
            FROM pg_constraint AS k
            CROSS JOIN LATERAL regexp_matches(pg_get_constraintdef(k.oid), '''([^'']*)''', 'g') AS m (name)
           WHERE k.conname IN ('cve_change_event_type_known', 'domain_change_event_type_known', 'package_advisory_change_event_type_known',
                               'eol_change_event_type_known')) <= 32,
         'each event type of the four CHECKs fits in 32 bytes';
  ASSERT (SELECT max(octet_length(t.event_type))
            FROM pg_constraint AS k
            CROSS JOIN LATERAL regexp_matches(pg_get_constraintdef(k.oid), '''([^'']+)''', 'g') AS e (endpoint_name)
            CROSS JOIN LATERAL unnest(api.fn_watchlist_endpoint_event_types(e.endpoint_name[1])) AS t (event_type)
           WHERE k.conname = 'watchlist_item_endpoint_name_known') <= 32,
         'each event type that api.fn_watchlist_endpoint_event_types names fits in 32 bytes';
END
$$;

TRUNCATE cve_change_event RESTART IDENTITY;
SELECT set_config('contrastapi.cve_events', 'off', true);
INSERT INTO cves (cve_id) VALUES ('CVE-2005-0021'), ('CVE-2005-0022'), ('CVE-2005-0023'), ('CVE-2005-0024');
SELECT set_config('contrastapi.cve_events', '', true);
INSERT INTO cve_change_event (cve_id, event_type, previous_value, current_value) VALUES
  ('CVE-2005-0021', 'cve_added',         NULL, NULL),
  ('CVE-2005-0022', 'cve_added',         NULL, NULL),
  ('CVE-2005-0023', 'cve_added',         NULL, NULL),
  ('CVE-2005-0021', 'kev_added',         NULL, NULL),
  ('CVE-2005-0024', 'cve_added',         NULL, NULL),
  ('CVE-2005-0023', 'epss_changed',      0.4,  0.9),
  ('CVE-2005-0022', 'exploit_published', NULL, NULL),
  ('CVE-2005-0021', 'cvss_added',        NULL, 7.5);

DO $$
BEGIN
  ASSERT api.fn_cve_change_event_max_id() = 8, 'the largest event_id is the largest one in the table';
  ASSERT (SELECT ROW(s.is_cursor_valid, s.last_scanned_event_id, s.may_have_more_events) FROM api.fn_cve_change_event_scan(0, 100) AS s)
         = ROW(true, 8::bigint, false),
         'a scan from 0 reads every event and stops at the last one';
  ASSERT (SELECT ROW(s.is_cursor_valid, s.last_scanned_event_id, s.may_have_more_events) FROM api.fn_cve_change_event_scan(2, 3) AS s)
         = ROW(true, 5::bigint, true),
         'a scan reads at most p_event_row_count events after the cursor';
  ASSERT (SELECT ROW(s.is_cursor_valid, s.last_scanned_event_id, s.may_have_more_events) FROM api.fn_cve_change_event_scan(5, 3) AS s)
         = ROW(true, 8::bigint, true),
         'a scan that reads exactly p_event_row_count events may have more events';
  ASSERT (SELECT ROW(s.is_cursor_valid, s.last_scanned_event_id, s.may_have_more_events) FROM api.fn_cve_change_event_scan(6, 3) AS s)
         = ROW(true, 8::bigint, false),
         'a scan that reads one event fewer than p_event_row_count has no more events';
  ASSERT (SELECT ROW(s.is_cursor_valid, s.last_scanned_event_id, s.may_have_more_events) FROM api.fn_cve_change_event_scan(8, 3) AS s)
         = ROW(true, 8::bigint, false),
         'a scan from the largest event_id reads nothing and keeps the cursor';
  ASSERT NOT (SELECT s.is_cursor_valid FROM api.fn_cve_change_event_scan(9, 3) AS s),
         'a cursor above the largest event_id is refused';
  ASSERT (SELECT count(*) FROM api.fn_cve_change_event_scan(NULL, 3)) = 0
     AND (SELECT count(*) FROM api.fn_cve_change_event_scan(0, NULL)) = 0,
         'api.fn_cve_change_event_scan is STRICT';

  UPDATE change_event_purge_state SET max_purged_event_id = 3 WHERE event_table_name = 'cve_change_event';
  ASSERT NOT (SELECT s.is_cursor_valid FROM api.fn_cve_change_event_scan(2, 3) AS s),
         'a cursor below max_purged_event_id is refused';
  ASSERT (SELECT s.is_cursor_valid FROM api.fn_cve_change_event_scan(3, 3) AS s),
         'a cursor equal to max_purged_event_id is served';
  UPDATE change_event_purge_state SET max_purged_event_id = 20 WHERE event_table_name = 'cve_change_event';
  ASSERT api.fn_cve_change_event_max_id() = 20, 'the largest event_id is max_purged_event_id when it is larger';
  ASSERT (SELECT s.is_cursor_valid FROM api.fn_cve_change_event_scan(20, 3) AS s),
         'a cursor equal to a max_purged_event_id that is the largest event_id is served';
  UPDATE change_event_purge_state SET max_purged_event_id = 0 WHERE event_table_name = 'cve_change_event';

  DELETE FROM change_event_purge_state WHERE event_table_name = 'cve_change_event';
  ASSERT api.fn_cve_change_event_max_id() IS NULL, 'the largest event_id is NULL without a purge state row';
  ASSERT (SELECT count(*) FROM api.fn_cve_change_event_scan(0, 3)) = 0,
         'api.fn_cve_change_event_scan answers no row without a purge state row';
  INSERT INTO change_event_purge_state (event_table_name) VALUES ('cve_change_event');

  TRUNCATE cve_change_event;
  ASSERT api.fn_cve_change_event_max_id() = 0, 'the largest event_id is 0 with no event and no purge';
END
$$;

CREATE TEMP VIEW t_cve_change_event_purge_call AS SELECT api.fn_cve_change_event_purge(0) AS purged_event_count;

DO $$
BEGIN
  ASSERT (SELECT array_agg(attname::text || ' ' || format_type(atttypid, atttypmod) ORDER BY attnum)
            FROM pg_attribute WHERE attrelid = 't_cve_change_event_purge_call'::regclass AND attnum > 0)
         = ARRAY['purged_event_count integer'],
         'the purge call answers one integer column, purged_event_count';
END
$$;

TRUNCATE cve_change_event;
UPDATE change_event_purge_state SET max_purged_event_id = 0 WHERE event_table_name = 'cve_change_event';
INSERT INTO cve_change_event (event_id, cve_id, event_type, changed_at) OVERRIDING SYSTEM VALUE VALUES
  (6, 'CVE-2005-0022', 'kev_added', now() - interval '95 days'),
  (1, 'CVE-2005-0021', 'cve_added', now() - interval '200 days'),
  (2, 'CVE-2005-0022', 'cve_added', now() - interval '91 days'),
  (3, 'CVE-2005-0023', 'cve_added', now() - interval '90 days 1 second'),
  (4, 'CVE-2005-0024', 'cve_added', now() - interval '90 days'),
  (5, 'CVE-2005-0021', 'kev_added', now() - interval '89 days'),
  (7, 'CVE-2005-0023', 'kev_added', now());

DO $$
BEGIN
  ASSERT api.fn_cve_change_event_purge(NULL) IS NULL, 'a NULL limit answers NULL';
  ASSERT (SELECT count(*) FROM cve_change_event) = 7, 'a NULL limit deletes nothing';
  ASSERT api.fn_cve_change_event_purge(2) = 2, 'a limit of 2 deletes 2 of the 4 old events';
  ASSERT (SELECT array_agg(cce.event_id ORDER BY cce.event_id) FROM cve_change_event AS cce) = '{3,4,5,6,7}',
         'the first call deletes the two smallest event_ids';
  ASSERT (SELECT ps.max_purged_event_id FROM change_event_purge_state AS ps WHERE ps.event_table_name = 'cve_change_event') = 2,
         'max_purged_event_id rises to 2';
  UPDATE change_event_purge_state SET max_purged_event_id = 5 WHERE event_table_name = 'cve_change_event';
  ASSERT api.fn_cve_change_event_purge(2) = 2, 'the next call deletes the last two old events';
  ASSERT (SELECT array_agg(cce.event_id ORDER BY cce.event_id) FROM cve_change_event AS cce) = '{4,5,7}',
         'events of exactly 90 days and younger stay';
  ASSERT (SELECT ps.max_purged_event_id FROM change_event_purge_state AS ps WHERE ps.event_table_name = 'cve_change_event') = 6,
         'max_purged_event_id rises to the largest event_id deleted';
  ASSERT api.fn_cve_change_event_purge(2) = 0, 'a call with no old event deletes none';
  ASSERT (SELECT ps.max_purged_event_id FROM change_event_purge_state AS ps WHERE ps.event_table_name = 'cve_change_event') = 6,
         'a call that deletes none keeps max_purged_event_id';

  UPDATE change_event_purge_state SET max_purged_event_id = 100 WHERE event_table_name = 'cve_change_event';
  UPDATE cve_change_event SET changed_at = now() - interval '91 days' WHERE event_id = 4;
  ASSERT api.fn_cve_change_event_purge(10) = 1, 'the call deletes event 4';
  ASSERT (SELECT ps.max_purged_event_id FROM change_event_purge_state AS ps WHERE ps.event_table_name = 'cve_change_event') = 100,
         'the purge never lowers max_purged_event_id';
END
$$;

DO $$
DECLARE
  f record;
BEGIN
  FOR f IN SELECT * FROM (VALUES
      ('api.fn_cve_change_event_max_id()'::regprocedure,            's', false),
      ('api.fn_cve_change_event_scan(bigint, integer)'::regprocedure,     's', false),
      ('api.fn_cve_change_event_purge(integer)'::regprocedure,      'v', true),
      ('public.fn_watchlist_event_take_order_lock()'::regprocedure, 'v', false),
      ('public.fn_cves_update_ref_counts()'::regprocedure,          'v', false),
      ('public.fn_epss_level_next(smallint, real)'::regprocedure,   'i', false),
      ('public.fn_cves_set_epss_level()'::regprocedure,             'v', false)) AS t (oid, volatility, is_definer) LOOP
    ASSERT (SELECT p.prosecdef FROM pg_proc AS p WHERE p.oid = f.oid) = f.is_definer,
           f.oid::text || CASE WHEN f.is_definer THEN ' is SECURITY DEFINER' ELSE ' is SECURITY INVOKER' END;
    ASSERT (SELECT p.proconfig FROM pg_proc AS p WHERE p.oid = f.oid) = ARRAY['search_path=pg_catalog'],
           f.oid::text || ' sets search_path to pg_catalog';
    ASSERT (SELECT p.provolatile FROM pg_proc AS p WHERE p.oid = f.oid) = f.volatility,
           f.oid::text || ' has the volatility ' || f.volatility;
  END LOOP;
END
$$;
