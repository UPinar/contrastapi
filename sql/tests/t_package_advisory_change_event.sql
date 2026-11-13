TRUNCATE cve_change_event RESTART IDENTITY;
UPDATE change_event_purge_state SET max_purged_event_id = 0 WHERE event_table_name = 'cve_change_event';
TRUNCATE domain_change_event, package_advisory_change_event, watchlist_event_ref;
UPDATE change_event_purge_state SET max_purged_event_id = 0, max_unwatched_event_id = 0 WHERE event_table_name = 'domain_change_event';
UPDATE change_event_purge_state SET max_purged_event_id = 0 WHERE event_table_name = 'package_advisory_change_event';

SELECT set_config('contrastapi.cve_events', 'off', true);
INSERT INTO cves (cve_id) VALUES ('CVE-2003-0701');
SELECT set_config('contrastapi.cve_events', '', true);
INSERT INTO domain_watch (domain_name, registered_domain) VALUES ('pae.example', 'pae.example');

CREATE FUNCTION pg_temp.t_package_refusing_constraint(p_statement text) RETURNS text LANGUAGE plpgsql AS $$
DECLARE
  constraint_name text;
BEGIN
  BEGIN
    EXECUTE p_statement;
    RAISE SQLSTATE 'TUNDO';
  EXCEPTION
    WHEN SQLSTATE 'TUNDO' THEN
      RETURN NULL;
    WHEN integrity_constraint_violation THEN
      GET STACKED DIAGNOSTICS constraint_name = CONSTRAINT_NAME;
      RETURN constraint_name;
  END;
END
$$;

DO $$
DECLARE
  cve_event_id      bigint;
  package_event_id  bigint;
  domain_event_id   bigint;
  package_event_id2 bigint;
BEGIN
  ASSERT api.fn_package_advisory_change_event_max_id() = 0, 'S1 the largest package event_id is 0 with no event and no purge';
  INSERT INTO cve_change_event (cve_id, event_type) VALUES ('CVE-2003-0701', 'kev_added')
  RETURNING event_id INTO cve_event_id;
  INSERT INTO package_advisory_change_event (advisory_id, ecosystem, package_name_normalized, package_name, event_type)
  VALUES ('GHSA-pae1-0001-0001', 'npm', 'left-pad', 'Left-Pad', 'advisory_added')
  RETURNING event_id INTO package_event_id;
  INSERT INTO domain_change_event (domain_name, event_type) VALUES ('pae.example', 'ns_changed')
  RETURNING event_id INTO domain_event_id;
  INSERT INTO package_advisory_change_event (advisory_id, ecosystem, package_name_normalized, package_name, event_type, fixed_version)
  VALUES ('GHSA-pae1-0001-0001', 'npm', 'left-pad', 'Left-Pad', 'fix_available', '1.3.0')
  RETURNING event_id INTO package_event_id2;
  ASSERT ARRAY[cve_event_id, package_event_id, domain_event_id, package_event_id2] = ARRAY[1, 2, 3, 4]::bigint[],
         'S1 the events of the three tables take the event_ids 1 to 4 of one sequence, in the order they are written';
  ASSERT (SELECT pi.indexdef FROM pg_indexes AS pi WHERE pi.indexname = 'idx_package_advisory_change_event_package')
         = 'CREATE INDEX idx_package_advisory_change_event_package ON public.package_advisory_change_event USING btree (ecosystem, package_name_normalized, event_id)',
         'S1 idx_package_advisory_change_event_package holds the events of a package in event_id order';
  ASSERT (SELECT pi.indexdef FROM pg_indexes AS pi WHERE pi.indexname = 'idx_package_advisory_change_event_changed_at')
         = 'CREATE INDEX idx_package_advisory_change_event_changed_at ON public.package_advisory_change_event USING btree (changed_at)',
         'S1 the purge finds the old events through an index on changed_at';
END
$$;

DO $$
BEGIN
  ASSERT (SELECT array_agg(a.attname::text || ' ' || format_type(a.atttypid, a.atttypmod)
                           || CASE WHEN a.attnotnull THEN ' not null' ELSE '' END
                           || coalesce(' default ' || pg_get_expr(d.adbin, d.adrelid), '')
                           ORDER BY a.attnum)
            FROM pg_attribute AS a
            LEFT JOIN pg_attrdef AS d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
           WHERE a.attrelid = 'package_advisory_change_event'::regclass AND a.attnum > 0 AND NOT a.attisdropped)
         = ARRAY['event_id bigint not null default nextval(''watchlist_event_id_seq''::regclass)',
                 'advisory_id text not null',
                 'ecosystem text not null',
                 'package_name_normalized text not null',
                 'package_name text not null',
                 'event_type text not null',
                 'fixed_version text',
                 'changed_at timestamp with time zone not null default now()'],
         'S2 package_advisory_change_event holds its eight columns';
  ASSERT (SELECT array_agg(c.conname::text || ' ' || c.contype::text ORDER BY c.conname)
            FROM pg_constraint AS c WHERE c.conrelid = 'package_advisory_change_event'::regclass AND c.contype <> 'n')
         = ARRAY['package_advisory_change_event_fixed_version_set c', 'package_advisory_change_event_pkey p', 'package_advisory_change_event_type_known c'],
         'S2 package_advisory_change_event has its primary key and two CHECKs, and no foreign key';
END
$$;

INSERT INTO osv_advisories (advisory_id, source, license, published_time, modified_time)
VALUES ('GHSA-pae3-0003-0003', 'ghsa', 'CC-BY-4.0', now(), now());
INSERT INTO package_advisory_change_event (advisory_id, ecosystem, package_name_normalized, package_name, event_type)
VALUES ('GHSA-pae3-0003-0003', 'PyPI', 'requests', 'Requests', 'advisory_added');
DELETE FROM osv_advisories WHERE advisory_id = 'GHSA-pae3-0003-0003';
DO $$
BEGIN
  ASSERT (SELECT count(*) FROM package_advisory_change_event AS pae WHERE pae.advisory_id = 'GHSA-pae3-0003-0003') = 1,
         'S3 the event stays when its advisory row is deleted';
  ASSERT pg_temp.t_package_refusing_constraint($q$INSERT INTO package_advisory_change_event (advisory_id, ecosystem, package_name_normalized, package_name, event_type)
                                          VALUES ('GHSA-pae3-none-0000', 'npm', 'x', 'x', 'advisory_added')$q$) IS NULL,
         'S3 an event of an advisory that osv_advisories never held is accepted';
END
$$;

DO $$
DECLARE
  insert_head CONSTANT text := 'INSERT INTO package_advisory_change_event (advisory_id, ecosystem, package_name_normalized, package_name, event_type, fixed_version) VALUES (''GHSA-pae4-0004-0004'', ''npm'', ''x'', ''x'', ';
BEGIN
  ASSERT pg_temp.t_package_refusing_constraint(insert_head || '''advisory_added'', NULL)') IS NULL, 'S4 advisory_added with no fixed_version is accepted';
  ASSERT pg_temp.t_package_refusing_constraint(insert_head || '''fix_available'', ''2.0.1'')') IS NULL, 'S4 fix_available with a fixed_version is accepted';
  ASSERT pg_temp.t_package_refusing_constraint(insert_head || '''malware_added'', NULL)') IS NULL, 'S4 malware_added with no fixed_version is accepted';
  ASSERT pg_temp.t_package_refusing_constraint(insert_head || '''advisory_removed'', NULL)') = 'package_advisory_change_event_type_known',
         'S4 an unknown event type is refused';
  ASSERT pg_temp.t_package_refusing_constraint(insert_head || '''kev_added'', NULL)') = 'package_advisory_change_event_type_known',
         'S4 a CVE event type is refused';
  ASSERT pg_temp.t_package_refusing_constraint(insert_head || '''fix_available'', NULL)') = 'package_advisory_change_event_fixed_version_set',
         'S4 fix_available without a fixed_version is refused';
  ASSERT pg_temp.t_package_refusing_constraint(insert_head || '''advisory_added'', ''2.0.1'')') = 'package_advisory_change_event_fixed_version_set',
         'S4 advisory_added with a fixed_version is refused';
  ASSERT pg_temp.t_package_refusing_constraint(insert_head || '''malware_added'', ''2.0.1'')') = 'package_advisory_change_event_fixed_version_set',
         'S4 malware_added with a fixed_version is refused';
END
$$;

DO $$
BEGIN
  ASSERT (SELECT count(*) FROM change_event_purge_state AS ps WHERE ps.event_table_name = 'package_advisory_change_event') = 1,
         'S5 schema.sql writes the one row';
  ASSERT pg_temp.t_package_refusing_constraint($q$INSERT INTO change_event_purge_state (event_table_name) VALUES ('package_advisory_change_event')$q$)
         = 'change_event_purge_state_pkey', 'S5 a second row is refused';
  ASSERT pg_temp.t_package_refusing_constraint($q$UPDATE change_event_purge_state SET max_unwatched_event_id = 1 WHERE event_table_name = 'package_advisory_change_event'$q$)
         = 'change_event_purge_state_unwatched_domain_only', 'S5 the package row keeps max_unwatched_event_id at 0';
END
$$;

DO $$
DECLARE
  package_max_id bigint := (SELECT max(pae.event_id) FROM package_advisory_change_event AS pae);
BEGIN
  ASSERT package_max_id = 5, 'S6 the event of S3 is the largest package event';
  ASSERT api.fn_package_advisory_change_event_max_id() = package_max_id, 'S6 the largest package event_id is the largest one in package_advisory_change_event';
  UPDATE change_event_purge_state SET max_purged_event_id = package_max_id - 1 WHERE event_table_name = 'package_advisory_change_event';
  ASSERT api.fn_package_advisory_change_event_max_id() = package_max_id, 'S6 a smaller max_purged_event_id leaves the largest event_id';
  UPDATE change_event_purge_state SET max_purged_event_id = package_max_id + 10 WHERE event_table_name = 'package_advisory_change_event';
  ASSERT api.fn_package_advisory_change_event_max_id() = package_max_id + 10, 'S6 a larger max_purged_event_id is the answer';
  DELETE FROM change_event_purge_state WHERE event_table_name = 'package_advisory_change_event';
  ASSERT api.fn_package_advisory_change_event_max_id() IS NULL, 'S6 the answer is NULL without a purge state row';
  INSERT INTO change_event_purge_state (event_table_name) VALUES ('package_advisory_change_event');
  ASSERT api.fn_package_advisory_change_event_max_id() = package_max_id, 'S6 a new purge state row starts at 0';
END
$$;

CREATE TEMP VIEW t_package_advisory_change_event_purge_call AS SELECT api.fn_package_advisory_change_event_purge(0) AS purged_event_count;

INSERT INTO api_keys (key_hash) VALUES (repeat('7a', 32)), (repeat('7b', 32)), (repeat('7c', 32)), (repeat('7d', 32)), (repeat('7e', 32)), (repeat('7f', 32));
INSERT INTO watchlist_item (api_key_id, endpoint_name)
SELECT ak.id, 'cve_lookup' FROM api_keys AS ak WHERE ak.key_hash IN (repeat('7a', 32), repeat('7b', 32), repeat('7f', 32));
INSERT INTO watchlist_key_state (api_key_id, last_key_event_id, last_cve_event_id)
SELECT ak.id, k.last_key_event_id, k.last_cve_event_id
  FROM (VALUES ('7a', 8, 1000), ('7b', 0, 1000), ('7c', 0, 101), ('7d', 0, 102), ('7e', 0, 1000), ('7f', 1, 1000))
       AS k (key_label, last_key_event_id, last_cve_event_id)
  JOIN api_keys AS ak ON ak.key_hash = repeat(k.key_label, 32);
TRUNCATE package_advisory_change_event;
INSERT INTO package_advisory_change_event (event_id, advisory_id, ecosystem, package_name_normalized, package_name, event_type, changed_at) VALUES
  (106, 'GHSA-pae7-0007-0007', 'npm', 'left-pad', 'left-pad', 'advisory_added', now() - interval '95 days'),
  (101, 'GHSA-pae7-0007-0007', 'npm', 'left-pad', 'left-pad', 'advisory_added', now() - interval '200 days'),
  (102, 'GHSA-pae7-0007-0007', 'npm', 'left-pad', 'left-pad', 'advisory_added', now() - interval '91 days'),
  (103, 'GHSA-pae7-0007-0007', 'npm', 'left-pad', 'left-pad', 'advisory_added', now() - interval '90 days 1 second'),
  (104, 'GHSA-pae7-0007-0007', 'npm', 'left-pad', 'left-pad', 'advisory_added', now() - interval '90 days'),
  (105, 'GHSA-pae7-0007-0007', 'npm', 'left-pad', 'left-pad', 'advisory_added', now() - interval '89 days'),
  (107, 'GHSA-pae7-0007-0007', 'npm', 'left-pad', 'left-pad', 'advisory_added', now());
INSERT INTO watchlist_event_ref (api_key_id, item_id, event_id, key_event_id)
SELECT wi.api_key_id, wi.item_id, e.event_id, e.key_event_id
  FROM watchlist_item AS wi
  JOIN api_keys AS ak ON ak.id = wi.api_key_id
 CROSS JOIN unnest(ARRAY[101, 102, 103, 104, 105, 106, 107, 199], ARRAY[1, 2, 3, 4, 5, 6, 7, 8]) AS e (event_id, key_event_id)
 WHERE ak.key_hash = repeat('7a', 32);
INSERT INTO watchlist_event_ref (api_key_id, item_id, event_id, key_event_id)
SELECT wi.api_key_id, wi.item_id, 102, NULL
  FROM watchlist_item AS wi JOIN api_keys AS ak ON ak.id = wi.api_key_id
 WHERE ak.key_hash = repeat('7b', 32);
INSERT INTO watchlist_event_ref (api_key_id, item_id, event_id, key_event_id)
SELECT wi.api_key_id, wi.item_id, 107, 1
  FROM watchlist_item AS wi JOIN api_keys AS ak ON ak.id = wi.api_key_id
 WHERE ak.key_hash = repeat('7f', 32);
INSERT INTO cve_change_event (cve_id, event_type, changed_at) VALUES ('CVE-2003-0701', 'kev_added', now() - interval '200 days');
INSERT INTO domain_change_event (domain_name, event_type, changed_at) VALUES ('pae.example', 'ns_changed', now() - interval '200 days');

CREATE FUNCTION pg_temp.t_package_key_state(p_label text) RETURNS watchlist_key_state LANGUAGE sql AS $$
  SELECT wks.* FROM watchlist_key_state AS wks JOIN api_keys AS ak ON ak.id = wks.api_key_id WHERE ak.key_hash = repeat(p_label, 32)
$$;
CREATE FUNCTION pg_temp.t_is_package_key_locked(p_label text) RETURNS boolean LANGUAGE sql AS $$
  SELECT wks.xmax::text <> '0' FROM watchlist_key_state AS wks JOIN api_keys AS ak ON ak.id = wks.api_key_id
   WHERE ak.key_hash = repeat(p_label, 32)
$$;
CREATE FUNCTION pg_temp.t_package_key_refs(p_label text) RETURNS bigint[] LANGUAGE sql AS $$
  SELECT coalesce(array_agg(wer.event_id ORDER BY wer.event_id), '{}')
    FROM watchlist_event_ref AS wer JOIN api_keys AS ak ON ak.id = wer.api_key_id
   WHERE ak.key_hash = repeat(p_label, 32)
$$;

DO $$
BEGIN
  ASSERT (SELECT array_agg(attname::text || ' ' || format_type(atttypid, atttypmod) ORDER BY attnum)
            FROM pg_attribute WHERE attrelid = 't_package_advisory_change_event_purge_call'::regclass AND attnum > 0)
         = ARRAY['purged_event_count integer'],
         'S7 the purge call answers one integer column, purged_event_count';
  ASSERT NOT pg_temp.t_is_package_key_locked('7b') AND NOT pg_temp.t_is_package_key_locked('7c')
     AND NOT pg_temp.t_is_package_key_locked('7d') AND NOT pg_temp.t_is_package_key_locked('7e'),
         'S7 no key state is locked before the purge';

  ASSERT api.fn_package_advisory_change_event_purge(NULL) IS NULL, 'S7 a NULL limit answers NULL';
  ASSERT (SELECT count(*) FROM package_advisory_change_event) = 7 AND (SELECT count(*) FROM watchlist_event_ref) = 10,
         'S7 a NULL limit deletes nothing';

  ASSERT api.fn_package_advisory_change_event_purge(2) = 2, 'S7 a limit of 2 deletes 2 of the 4 old events';
  ASSERT (SELECT array_agg(pae.event_id ORDER BY pae.event_id) FROM package_advisory_change_event AS pae) = '{103,104,105,106,107}',
         'S7 the first call deletes the two smallest event_ids';
  ASSERT pg_temp.t_package_key_refs('7a') = '{103,104,105,106,107,199}' AND pg_temp.t_package_key_refs('7b') = '{}',
         'S7 the first call deletes the refs of the two events it deletes, numbered or waiting, and no other ref';
  ASSERT (SELECT ps.max_purged_event_id FROM change_event_purge_state AS ps WHERE ps.event_table_name = 'package_advisory_change_event') = 102, 'S7 max_purged_event_id rises to 102';
  ASSERT (pg_temp.t_package_key_state('7a')).max_purged_key_event_id = 2, 'S7 key 7a lost the refs numbered 1 and 2, so its floor rises to 2';
  ASSERT (pg_temp.t_package_key_state('7b')).max_purged_key_event_id = 0, 'S7 key 7b lost only a ref that waited for a number, so its floor stays';
  ASSERT pg_temp.t_is_package_key_locked('7b'), 'S7 the purge locks the key state of a key that holds a ref of a picked event';
  ASSERT pg_temp.t_is_package_key_locked('7c'), 'S7 the purge locks the key state of a key whose last_cve_event_id is below the largest picked event_id';
  ASSERT NOT pg_temp.t_is_package_key_locked('7d'), 'S7 the purge leaves the key state of a key whose last_cve_event_id is the largest picked event_id';
  ASSERT NOT pg_temp.t_is_package_key_locked('7e'), 'S7 the purge leaves the key state of a key whose last_cve_event_id is above the picked events';
  ASSERT NOT pg_temp.t_is_package_key_locked('7f'), 'S7 the purge leaves the key state of a key that holds only a ref of an event it does not pick';

  UPDATE change_event_purge_state SET max_purged_event_id = 105 WHERE event_table_name = 'package_advisory_change_event';
  ASSERT api.fn_package_advisory_change_event_purge(2) = 2, 'S7 the next call deletes the last two old events';
  ASSERT (SELECT array_agg(pae.event_id ORDER BY pae.event_id) FROM package_advisory_change_event AS pae) = '{104,105,107}',
         'S7 events of exactly 90 days and younger stay';
  ASSERT pg_temp.t_package_key_refs('7a') = '{104,105,107,199}', 'S7 the refs of the events that stay stay too';
  ASSERT (SELECT ps.max_purged_event_id FROM change_event_purge_state AS ps WHERE ps.event_table_name = 'package_advisory_change_event') = 106,
         'S7 max_purged_event_id rises to the largest event_id deleted';
  ASSERT (pg_temp.t_package_key_state('7a')).max_purged_key_event_id = 6, 'S7 key 7a lost the refs numbered 3 and 6, so its floor rises to 6';

  ASSERT api.fn_package_advisory_change_event_purge(2) = 0, 'S7 a call with no old event deletes none';
  ASSERT (SELECT count(*) FROM watchlist_event_ref) = 5, 'S7 a call with no old event deletes no ref';
  ASSERT (SELECT ps.max_purged_event_id FROM change_event_purge_state AS ps WHERE ps.event_table_name = 'package_advisory_change_event') = 106,
         'S7 a call that deletes none keeps max_purged_event_id';

  UPDATE watchlist_key_state AS wks SET max_purged_key_event_id = 3 FROM api_keys AS ak
   WHERE ak.id = wks.api_key_id AND ak.key_hash = repeat('7a', 32);
  UPDATE package_advisory_change_event SET changed_at = now() - interval '91 days' WHERE event_id = 104;
  ASSERT api.fn_package_advisory_change_event_purge(10) = 1, 'S7 the call deletes event 104';
  ASSERT pg_temp.t_package_key_refs('7a') = '{105,107,199}', 'S7 the call deletes the ref of event 104';
  ASSERT (pg_temp.t_package_key_state('7a')).max_purged_key_event_id = 4,
         'S7 key 7a lost the ref numbered 4, so its floor rises from 3 to 4';

  UPDATE change_event_purge_state SET max_purged_event_id = 1000 WHERE event_table_name = 'package_advisory_change_event';
  UPDATE watchlist_key_state AS wks SET max_purged_key_event_id = 8 FROM api_keys AS ak
   WHERE ak.id = wks.api_key_id AND ak.key_hash = repeat('7a', 32);
  UPDATE package_advisory_change_event SET changed_at = now() - interval '91 days' WHERE event_id = 105;
  ASSERT api.fn_package_advisory_change_event_purge(10) = 1, 'S7 the call deletes event 105';
  ASSERT (SELECT ps.max_purged_event_id FROM change_event_purge_state AS ps WHERE ps.event_table_name = 'package_advisory_change_event') = 1000,
         'S7 the purge never lowers max_purged_event_id';
  ASSERT pg_temp.t_package_key_refs('7a') = '{107,199}', 'S7 the call deletes the ref of event 105';
  ASSERT (pg_temp.t_package_key_state('7a')).max_purged_key_event_id = 8, 'S7 the purge never lowers the floor of a key';

  ASSERT (SELECT count(*) FROM cve_change_event) = 2 AND (SELECT count(*) FROM domain_change_event) = 2,
         'S7 the purge leaves the CVE and domain events alone, old ones too';
  ASSERT (SELECT ps.max_purged_event_id FROM change_event_purge_state AS ps WHERE ps.event_table_name = 'cve_change_event') = 0
     AND (SELECT ps.max_purged_event_id FROM change_event_purge_state AS ps WHERE ps.event_table_name = 'domain_change_event') = 0,
         'S7 the purge leaves the purge states of the CVE and domain events alone';
END
$$;

DO $$
BEGIN
  ASSERT api.fn_cve_change_event_max_id() < 107 AND api.fn_domain_change_event_max_id() < 107,
         'S8 every CVE and domain event is below package event 107';
  ASSERT api.fn_watchlist_event_max_id() = 1000, 'S8 the package purge of S7 at 1000 is the head';
  UPDATE change_event_purge_state SET max_purged_event_id = 0 WHERE event_table_name = 'package_advisory_change_event';
  ASSERT api.fn_watchlist_event_max_id() = 107, 'S8 without the purge, package event 107 is the head';
END
$$;

DO $$
DECLARE
  f record;
BEGIN
  FOR f IN SELECT * FROM (VALUES
      ('api.fn_package_advisory_change_event_purge(integer)'::regprocedure, 'v'::"char", true,  'plpgsql', true),
      ('api.fn_package_advisory_change_event_max_id()'::regprocedure,       's'::"char", false, 'sql', false)) AS t (oid, volatility, is_strict, language_name, is_definer) LOOP
    ASSERT (SELECT p.prosecdef FROM pg_proc AS p WHERE p.oid = f.oid) = f.is_definer,
           f.oid::text || CASE WHEN f.is_definer THEN ' is SECURITY DEFINER' ELSE ' is SECURITY INVOKER' END;
    ASSERT (SELECT p.proconfig FROM pg_proc AS p WHERE p.oid = f.oid) = ARRAY['search_path=pg_catalog'],
           f.oid::text || ' sets search_path to pg_catalog';
    ASSERT (SELECT p.provolatile FROM pg_proc AS p WHERE p.oid = f.oid) = f.volatility, f.oid::text || ' has its volatility';
    ASSERT (SELECT p.proisstrict FROM pg_proc AS p WHERE p.oid = f.oid) = f.is_strict, f.oid::text || ' is STRICT only when it takes a row count';
    ASSERT (SELECT l.lanname::text FROM pg_proc AS p JOIN pg_language AS l ON l.oid = p.prolang WHERE p.oid = f.oid) = f.language_name,
           f.oid::text || ' has its language';
  END LOOP;
  ASSERT (SELECT count(*) FROM pg_proc AS p WHERE p.pronamespace = 'api'::regnamespace AND p.proname LIKE 'fn_package_advisory_change_event%') = 2,
         'sql/fn_package_advisory_change_event.sql holds two functions';
END
$$;
