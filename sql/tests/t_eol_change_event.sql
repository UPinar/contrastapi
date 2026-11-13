TRUNCATE cve_change_event RESTART IDENTITY;
UPDATE change_event_purge_state SET max_purged_event_id = 0 WHERE event_table_name = 'cve_change_event';
TRUNCATE domain_change_event, package_advisory_change_event, eol_change_event, watchlist_event_ref;
UPDATE change_event_purge_state SET max_purged_event_id = 0, max_unwatched_event_id = 0 WHERE event_table_name = 'domain_change_event';
UPDATE change_event_purge_state SET max_purged_event_id = 0 WHERE event_table_name IN ('package_advisory_change_event', 'eol_change_event');

INSERT INTO api_keys (key_hash) VALUES (repeat('e1', 32));

INSERT INTO eol_product (product_name, product_label, url) VALUES
  ('eolwatch', 'EOL Watch', 'https://endoflife.date/eolwatch'),
  ('eolother', 'EOL Other', 'https://endoflife.date/eolother');
INSERT INTO eol_cycle (eol_product, cycle_name, release_date, eol_date, is_eol, is_maintained, is_lts) VALUES
  ('eolwatch', '2',   '2020-01-01', current_date + 30, false, true, false),
  ('eolwatch', '2.5', '2021-01-01', current_date - 1, true, false, false),
  ('eolwatch', '2-w', '2020-01-01', current_date + 200, false, true, false),
  ('eolwatch', '3',   '2022-01-01', NULL, true, false, false),
  ('eolother', '1',   '2019-01-01', NULL, true, false, false),
  ('eolother', '2.5.1', '2019-01-01', NULL, true, false, false),
  ('eolother', '3.1', '2019-01-01', NULL, true, false, false);
INSERT INTO eol_product_cpe (vendor, product, eol_product, series, source) VALUES
  ('eolacme', 'eolwidget', 'eolwatch', NULL, 'endoflife'),
  ('eolacme', 'eolwidget', 'eolother', NULL, 'manual'),
  ('eolacme', 'eolserver', 'eolwatch', '3', 'manual'),
  ('eolacme', 'eolelse', 'eolother', NULL, 'manual'),
  ('eolrival', 'eolwidget', 'eolother', NULL, 'endoflife'),
  ('eolacme', 'eolstale', 'eolgone', NULL, 'endoflife'),
  ('eolacme', 'eolstale', 'eolother', NULL, 'manual');

CREATE FUNCTION pg_temp.t_eol_refusing_constraint(p_statement text) RETURNS text LANGUAGE plpgsql AS $$
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

CREATE FUNCTION pg_temp.t_eol_add(p_product text, p_version text) RETURNS bigint LANGUAGE plpgsql AS $$
BEGIN
  PERFORM api.fn_watchlist_edit_product_exposure(repeat('e1', 32), 'add', 'eolacme', p_product, p_version, 100);
  RETURN (SELECT wic.item_id FROM watchlist_item_cve AS wic
           WHERE wic.api_key_id = (SELECT ak.id FROM api_keys AS ak WHERE ak.key_hash = repeat('e1', 32))
             AND wic.product = p_product AND wic.version IS NOT DISTINCT FROM p_version);
END
$$;

CREATE FUNCTION pg_temp.t_eol_event(p_eol_product text, p_cycle text, p_event_type text, p_eol_date date, p_previous_eol_date date)
  RETURNS bigint LANGUAGE sql AS $$
  INSERT INTO eol_change_event (eol_product, cycle_name, event_type, eol_date, previous_eol_date)
  VALUES (p_eol_product, p_cycle, p_event_type, p_eol_date, p_previous_eol_date)
  RETURNING event_id
$$;

CREATE TEMP TABLE t_eol_ids (label text PRIMARY KEY, id bigint);

DO $$
DECLARE
  cve_event_id bigint;
  eol_event_id bigint;
BEGIN
  ASSERT api.fn_eol_change_event_max_id() = 0, 'S1 the largest EOL event_id is 0 with no event and no purge';
  INSERT INTO domain_watch (domain_name, registered_domain) VALUES ('eolev.example', 'eolev.example');
  INSERT INTO domain_change_event (domain_name, event_type) VALUES ('eolev.example', 'ns_changed') RETURNING event_id INTO cve_event_id;
  eol_event_id := pg_temp.t_eol_event('eolnone', '1', 'eol_reached', NULL, NULL);
  ASSERT eol_event_id = cve_event_id + 1, 'S1 an EOL event takes the next event_id of the shared sequence';
  DELETE FROM eol_change_event;
  DELETE FROM domain_change_event;
  DELETE FROM domain_watch WHERE domain_name = 'eolev.example';
  ASSERT (SELECT array_agg(a.attname::text || ' ' || format_type(a.atttypid, a.atttypmod)
                           || CASE WHEN a.attnotnull THEN ' not null' ELSE '' END
                           || coalesce(' default ' || pg_get_expr(d.adbin, d.adrelid), '')
                           ORDER BY a.attnum)
            FROM pg_attribute AS a
            LEFT JOIN pg_attrdef AS d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
           WHERE a.attrelid = 'eol_change_event'::regclass AND a.attnum > 0 AND NOT a.attisdropped)
         = ARRAY['event_id bigint not null default nextval(''watchlist_event_id_seq''::regclass)',
                 'eol_product text not null',
                 'cycle_name text not null',
                 'event_type text not null',
                 'eol_date date',
                 'previous_eol_date date',
                 'changed_at timestamp with time zone not null default now()'],
         'S1 eol_change_event holds its seven columns';
  ASSERT (SELECT array_agg(c.conname::text || ' ' || c.contype::text ORDER BY c.conname)
            FROM pg_constraint AS c WHERE c.conrelid = 'eol_change_event'::regclass AND c.contype <> 'n')
         = ARRAY['eol_change_event_eol_date_set c', 'eol_change_event_pkey p', 'eol_change_event_previous_eol_date_set c',
                 'eol_change_event_type_known c'],
         'S1 eol_change_event has its primary key and three CHECKs, and no foreign key';
  ASSERT (SELECT array_agg(pi.indexdef ORDER BY pi.indexname) FROM pg_indexes AS pi WHERE pi.tablename = 'eol_change_event')
         = ARRAY['CREATE UNIQUE INDEX eol_change_event_pkey ON public.eol_change_event USING btree (event_id)',
                 'CREATE INDEX idx_eol_change_event_changed_at ON public.eol_change_event USING btree (changed_at)',
                 'CREATE INDEX idx_eol_change_event_product ON public.eol_change_event USING btree (eol_product, event_id)'],
         'S1 the events of a product are found in event_id order, and the purge finds the old events by changed_at';
  ASSERT (SELECT max(octet_length(m.name[1]))
            FROM pg_constraint AS k
            CROSS JOIN LATERAL regexp_matches(pg_get_constraintdef(k.oid), '''([^'']*)''', 'g') AS m (name)
           WHERE k.conname = 'eol_change_event_type_known') <= 32,
         'S1 each EOL event type fits in the 32 bytes db_WATCHLISTEVENTS reads';
END
$$;

DO $$
DECLARE
  insert_head CONSTANT text := 'INSERT INTO eol_change_event (eol_product, cycle_name, event_type, eol_date, previous_eol_date) VALUES (''eolnone'', ''1'', ';
BEGIN
  ASSERT pg_temp.t_eol_refusing_constraint(insert_head || '''eol_approaching'', current_date, NULL)') IS NULL, 'S2 eol_approaching with a date is accepted';
  ASSERT pg_temp.t_eol_refusing_constraint(insert_head || '''eol_reached'', current_date, NULL)') IS NULL, 'S2 eol_reached with a date is accepted';
  ASSERT pg_temp.t_eol_refusing_constraint(insert_head || '''eol_reached'', NULL, NULL)') IS NULL, 'S2 eol_reached with no date is accepted';
  ASSERT pg_temp.t_eol_refusing_constraint(insert_head || '''eol_date_changed'', current_date, current_date - 1)') IS NULL,
         'S2 eol_date_changed with both dates is accepted';
  ASSERT pg_temp.t_eol_refusing_constraint(insert_head || '''eol_removed'', current_date, NULL)') = 'eol_change_event_type_known',
         'S2 an unknown event type is refused';
  ASSERT pg_temp.t_eol_refusing_constraint(insert_head || '''kev_added'', current_date, NULL)') = 'eol_change_event_type_known',
         'S2 a CVE event type is refused';
  ASSERT pg_temp.t_eol_refusing_constraint(insert_head || '''eol_date_changed'', current_date, NULL)') = 'eol_change_event_previous_eol_date_set',
         'S2 eol_date_changed with no previous date is refused';
  ASSERT pg_temp.t_eol_refusing_constraint(insert_head || '''eol_approaching'', current_date, current_date - 1)') = 'eol_change_event_previous_eol_date_set',
         'S2 eol_approaching with a previous date is refused';
  ASSERT pg_temp.t_eol_refusing_constraint(insert_head || '''eol_approaching'', NULL, NULL)') = 'eol_change_event_eol_date_set',
         'S2 eol_approaching with no date is refused';
  ASSERT pg_temp.t_eol_refusing_constraint(insert_head || '''eol_date_changed'', NULL, current_date)') = 'eol_change_event_eol_date_set',
         'S2 eol_date_changed with no new date is refused';
END
$$;

DO $$
BEGIN
  ASSERT public.fn_eol_date_is_approaching(current_date) AND public.fn_eol_date_is_approaching(current_date + 90)
     AND NOT public.fn_eol_date_is_approaching(current_date - 1) AND NOT public.fn_eol_date_is_approaching(current_date + 91)
     AND public.fn_eol_date_is_approaching(NULL) IS NULL,
         'S3 the approaching window runs from today to today + 90, both ends included';
  ASSERT public.fn_eol_cycle_is_reached(current_date, false) AND NOT public.fn_eol_cycle_is_reached(current_date + 1, true)
     AND public.fn_eol_cycle_is_reached(NULL, true) AND NOT public.fn_eol_cycle_is_reached(NULL, false),
         'S3 a cycle is at its end on its eol_date, and by the flag only with no date';
  ASSERT (SELECT array_agg(row(p.eol_product, p.series)::text) FROM public.fn_eol_product_cpe_pick('eolacme', 'eolwidget') AS p)
         = ARRAY['(eolwatch,)'],
         'S3 the endoflife row is picked before a manual row that sorts first, and the endoflife row of eolrival eolwidget, another vendor, is not read';
  ASSERT (SELECT array_agg(row(p.eol_product, p.series)::text) FROM public.fn_eol_product_cpe_pick('eolacme', 'eolserver') AS p)
         = ARRAY['(eolwatch,3)'],
         'S3 a manual row brings its series';
  ASSERT NOT EXISTS (SELECT 1 FROM public.fn_eol_product_cpe_pick('eolacme', 'eolnothing')), 'S3 an unmapped pair picks nothing';
  ASSERT (SELECT array_agg(row(p.eol_product, p.series)::text) FROM public.fn_eol_product_cpe_pick('eolacme', 'eolstale') AS p)
         = ARRAY['(eolother,)'],
         'S3 the pick skips an endoflife row whose product left the feed, and takes the next row';
  ASSERT public.fn_eol_pick_series('eolwatch', '3', '2.5.1') = '3', 'S3 the series of the row wins over the version';
  ASSERT public.fn_eol_pick_series('eolwatch', NULL, '2.5.1') = '2.5',
         'S3 the longest dotted prefix wins, and a version that names a cycle of another product, eolother 2.5.1, is no series of eolwatch';
  ASSERT public.fn_eol_pick_series('eolwatch', NULL, '3.1.2') = '3',
         'S3 the longest prefix is a cycle of the product: eolother 3.1 is longer, and is not read';
  ASSERT public.fn_eol_pick_series('eolwatch', NULL, 'v2') = '2', 'S3 one leading v is stripped, and the version names a series';
  ASSERT public.fn_eol_pick_series('eolwatch', NULL, '2x') IS NULL, 'S3 a prefix needs a dot after it';
  ASSERT public.fn_eol_pick_series('eolwatch', NULL, NULL) IS NULL, 'S3 no version picks no series';
END
$$;

INSERT INTO t_eol_ids VALUES
  ('I1', pg_temp.t_eol_add('eolwidget', NULL)), ('I2', pg_temp.t_eol_add('eolwidget', '2.5.1')),
  ('I3', pg_temp.t_eol_add('eolwidget', 'v2')), ('I4', pg_temp.t_eol_add('eolserver', NULL)),
  ('I5', pg_temp.t_eol_add('eolserver', '2.5.1')), ('I6', pg_temp.t_eol_add('eolwidget', '9.9')),
  ('I7', pg_temp.t_eol_add('eolelse', NULL)), ('I8', pg_temp.t_eol_add('eolnothing', NULL));
INSERT INTO t_eol_ids VALUES
  ('e1', pg_temp.t_eol_event('eolwatch', '2', 'eol_approaching', current_date + 30, NULL)),
  ('e2', pg_temp.t_eol_event('eolwatch', '2.5', 'eol_reached', current_date - 1, NULL)),
  ('e3', pg_temp.t_eol_event('eolwatch', '2-w', 'eol_date_changed', current_date + 200, current_date + 100)),
  ('e4', pg_temp.t_eol_event('eolwatch', '3', 'eol_reached', NULL, NULL)),
  ('e5', pg_temp.t_eol_event('eolother', '1', 'eol_reached', NULL, NULL));

CREATE FUNCTION pg_temp.t_eol_pairs(p_event_labels text[]) RETURNS text[] LANGUAGE sql AS $$
  SELECT coalesce(array_agg(item.label || ':' || event.label ORDER BY item.label, event.label), '{}')
    FROM api.fn_watchlist_event_eol_pairs((SELECT ak.id FROM api_keys AS ak WHERE ak.key_hash = repeat('e1', 32)),
                                          ARRAY(SELECT i.id FROM t_eol_ids AS i WHERE i.label = ANY (p_event_labels))) AS pair
    JOIN t_eol_ids AS item ON item.id = pair.item_id AND item.label LIKE 'I%'
    JOIN t_eol_ids AS event ON event.id = pair.event_id AND event.label LIKE 'e%'
$$;

DO $$
BEGIN
  ASSERT pg_temp.t_eol_pairs(ARRAY['e1', 'e2', 'e3', 'e4', 'e5'])
         = ARRAY['I1:e1', 'I1:e2', 'I1:e3', 'I1:e4', 'I2:e2', 'I3:e1', 'I3:e3', 'I4:e4', 'I5:e4', 'I7:e5'],
         'S4 each item hears the cycles of its product, series and version: ' || pg_temp.t_eol_pairs(ARRAY['e1', 'e2', 'e3', 'e4', 'e5'])::text;
  ASSERT pg_temp.t_eol_pairs(ARRAY['e2']) = ARRAY['I1:e2', 'I2:e2'], 'S4 only the events of p_event_ids make pairs';
  ASSERT (SELECT count(*) FROM api.fn_watchlist_event_eol_pairs((SELECT ak.id FROM api_keys AS ak WHERE ak.key_hash = repeat('ab', 32)),
                                                                ARRAY(SELECT i.id FROM t_eol_ids AS i WHERE i.label LIKE 'e%'))) = 0,
         'S4 another key hears none of these events';
END
$$;

INSERT INTO t_eol_ids VALUES ('I9', pg_temp.t_eol_add('eolwidget', 'v2.5'));
INSERT INTO t_eol_ids VALUES ('e6', pg_temp.t_eol_event('eolwatch', '2.5', 'eol_date_changed', current_date - 1, current_date - 5));
DO $$
BEGIN
  ASSERT pg_temp.t_eol_pairs(ARRAY['e1', 'e2', 'e3', 'e4', 'e5', 'e6'])
         = ARRAY['I1:e1', 'I1:e2', 'I1:e3', 'I1:e4', 'I1:e6', 'I2:e2', 'I2:e6', 'I3:e1', 'I3:e3', 'I4:e4', 'I5:e4', 'I7:e5', 'I9:e6'],
         'S5 an item added after an event does not hear it';
END
$$;

DO $$
DECLARE
  key_e  integer := (SELECT ak.id FROM api_keys AS ak WHERE ak.key_hash = repeat('e1', 32));
  e      bigint[] := ARRAY(SELECT i.id FROM t_eol_ids AS i WHERE i.label LIKE 'e%' ORDER BY i.label);
  scan   record;
BEGIN
  ASSERT api.fn_eol_change_event_max_id() = e[6] AND api.fn_watchlist_event_max_id() = e[6],
         'S6 the head of the event tables is the largest EOL event';
  UPDATE change_event_purge_state SET max_purged_event_id = e[3] WHERE event_table_name = 'eol_change_event';
  SELECT * INTO scan FROM api.fn_watchlist_event_scan(key_e, 0, e[6], 50, 1000, 1000);
  ASSERT (SELECT array_agg(DISTINCT x.id ORDER BY x.id) FROM unnest(scan.page_event_ids) AS x (id)) = e[4:6],
         'S6 the scan skips the EOL events up to the EOL floor: ' || scan.page_event_ids::text;
  ASSERT scan.scanned_event_count = 3, 'S6 the window holds the three EOL events after the floor';
  UPDATE change_event_purge_state SET max_purged_event_id = e[6] + 5 WHERE event_table_name = 'eol_change_event';
  ASSERT api.fn_eol_change_event_max_id() = e[6] + 5 AND api.fn_watchlist_event_max_id() = e[6] + 5,
         'S6 the head counts the EOL floor';
  UPDATE change_event_purge_state SET max_purged_event_id = 0 WHERE event_table_name = 'eol_change_event';
  SELECT * INTO scan FROM api.fn_watchlist_event_scan(key_e, 0, e[6], 50, 1000, 1000);
  ASSERT (SELECT array_agg(DISTINCT x.id ORDER BY x.id) FROM unnest(scan.page_event_ids) AS x (id)) = e[1:6]
     AND NOT scan.is_page_full AND scan.scan_end_event_id = e[6],
         'S6 with the floor at 0 the page holds every EOL event the items hear';
  SELECT * INTO scan FROM api.fn_watchlist_event_scan(key_e, 0, e[6], 50, 2, 1000);
  ASSERT scan.scanned_event_count = 2 AND scan.scan_end_event_id = e[2],
         'S6 a scan row count below the EOL events keeps the oldest ones: ' || scan.scan_end_event_id::text;
END
$$;

DO $$
DECLARE
  e        bigint[] := ARRAY(SELECT i.id FROM t_eol_ids AS i WHERE i.label LIKE 'e%' ORDER BY i.label);
  answer   record;
  row_count integer := 0;
BEGIN
  FOR answer IN SELECT * FROM api.fn_watchlist_events(repeat('e1', 32), NULL, false, 50, 1000, 1000) LOOP
    row_count := row_count + 1;
    ASSERT answer.events_status = 'ok' AND NOT answer.has_more, 'S7 the call answers ok and nothing more';
    ASSERT answer.attribution = jsonb_build_array(jsonb_build_object(
             'source', 'endoflife.date', 'license', 'MIT', 'url', 'https://endoflife.date',
             'notice', 'Retrieved from endoflife.date. ContrastAPI selected the fields and matched the release cycles to the watched product. No warranty; the source does not endorse ContrastAPI.')),
           'S7 attribution names endoflife.date once: ' || answer.attribution::text;
    IF answer.is_first_row_of_event AND answer.event_type = 'eol_date_changed' AND answer.eol_cycle = '2-w' THEN
      ASSERT answer.eol_product = 'eolwatch' AND answer.eol_date = to_char(current_date + 200, 'YYYY-MM-DD')
         AND answer.previous_eol_date = to_char(current_date + 100, 'YYYY-MM-DD')
         AND answer.cve_id IS NULL AND answer.advisory_id IS NULL AND answer.previous_domain_value IS NULL
         AND NOT answer.is_first_event_of_cve AND NOT answer.is_first_event_of_advisory AND NOT answer.is_first_event_of_domain,
             'S7 the first row of e3 carries its EOL columns and no column of another table';
    END IF;
    IF answer.is_first_row_of_event AND answer.eol_cycle = '3' THEN
      ASSERT answer.event_type = 'eol_reached' AND answer.eol_date IS NULL AND answer.previous_eol_date IS NULL,
             'S7 an eol_reached event of a cycle with no date has no dates';
    END IF;
    IF NOT answer.is_first_row_of_event THEN
      ASSERT answer.eol_product IS NULL AND answer.eol_cycle IS NULL AND answer.eol_date IS NULL, 'S7 a later row of an event carries no event column';
    END IF;
  END LOOP;
  ASSERT row_count = 13, 'S7 the call answers the thirteen pairs, found ' || row_count;
  INSERT INTO t_eol_ids VALUES ('e7', pg_temp.t_eol_event('eolother', '1', 'eol_reached', NULL, NULL));
  SELECT * INTO answer FROM api.fn_watchlist_events(repeat('e1', 32), 0, false, 50, 1000, 1000) LIMIT 1;
  ASSERT answer.has_more, 'S7 a replay has more while an EOL event follows last_cve_event_id';
END
$$;

DO $$
DECLARE
  answer record;
BEGIN
  PERFORM api.fn_watchlist_edit_package_check(repeat('e1', 32), 'add', 'npm', 'eolattr', NULL, 500, 100, 100000, 20);
  INSERT INTO osv_advisories (advisory_id, source, license, published_time, modified_time) VALUES
    ('GHSA-eol8-0001-0001', 'ghsa', 'CC-BY-4.0', now(), now()), ('GO-2099-0801', 'go', 'CC-BY-4.0', now(), now()),
    ('PYSEC-2099-801', 'pysec', 'CC-BY-4.0', now(), now()), ('RUSTSEC-2099-0801', 'rustsec', 'CC0-1.0', now(), now()),
    ('RUSTSEC-2099-0802', 'rustsec', 'CC-BY-4.0', now(), now()), ('MAL-2099-801', 'mal', 'Apache-2.0', now(), now());
  INSERT INTO package_advisory_change_event (advisory_id, ecosystem, package_name_normalized, package_name, event_type)
  SELECT osva.advisory_id, 'npm', 'eolattr', 'eolattr', 'advisory_added'
    FROM osv_advisories AS osva WHERE osva.published_time = now() AND osva.advisory_id IN
         ('GHSA-eol8-0001-0001', 'GO-2099-0801', 'PYSEC-2099-801', 'RUSTSEC-2099-0801', 'RUSTSEC-2099-0802', 'MAL-2099-801');
  PERFORM pg_temp.t_eol_event('eolother', '1', 'eol_reached', NULL, NULL);
  SELECT * INTO answer FROM api.fn_watchlist_events(repeat('e1', 32), NULL, false, 50, 1000, 1000) LIMIT 1;
  ASSERT jsonb_array_length(answer.attribution) = 7
     AND (SELECT array_agg(a ->> 'source' ORDER BY ordinality) FROM jsonb_array_elements(answer.attribution) WITH ORDINALITY AS x (a, ordinality))
         = ARRAY['endoflife.date', 'ghsa', 'go', 'mal', 'pysec', 'rustsec', 'rustsec'],
         'S8 attribution lists the six OSV objects and endoflife.date: ' || answer.attribution::text;
  ASSERT octet_length(answer.attribution::text) < 4096, 'S8 the worst attribution stays below 4096 bytes';
  RAISE NOTICE 'S8 worst attribution text: % bytes', octet_length(answer.attribution::text);
  DELETE FROM package_advisory_change_event WHERE package_name_normalized = 'eolattr';
  DELETE FROM osv_advisories WHERE advisory_id IN ('GHSA-eol8-0001-0001', 'GO-2099-0801', 'PYSEC-2099-801', 'RUSTSEC-2099-0801',
                                                   'RUSTSEC-2099-0802', 'MAL-2099-801');
END
$$;

DO $$
DECLARE
  key_e      integer := (SELECT ak.id FROM api_keys AS ak WHERE ak.key_hash = repeat('e1', 32));
  item_1     bigint := (SELECT i.id FROM t_eol_ids AS i WHERE i.label = 'I1');
  old_ids    bigint[];
  young_id   bigint;
  low_id     bigint;
BEGIN
  old_ids := ARRAY[pg_temp.t_eol_event('eolpurge', '1', 'eol_reached', NULL, NULL), pg_temp.t_eol_event('eolpurge', '2', 'eol_reached', NULL, NULL)];
  young_id := pg_temp.t_eol_event('eolpurge', '3', 'eol_reached', NULL, NULL);
  UPDATE eol_change_event SET changed_at = now() - interval '91 days' WHERE event_id = ANY (old_ids);
  UPDATE eol_change_event SET changed_at = now() - interval '89 days' WHERE event_id = young_id;
  INSERT INTO watchlist_event_ref (api_key_id, item_id, event_id, key_event_id) VALUES (key_e, item_1, old_ids[2], NULL);
  ASSERT api.fn_eol_change_event_purge(NULL) IS NULL, 'S9 a NULL limit answers NULL';
  ASSERT api.fn_eol_change_event_purge(1) = 1, 'S9 the purge deletes one event at a limit of 1';
  ASSERT NOT EXISTS (SELECT 1 FROM eol_change_event AS ece WHERE ece.event_id = old_ids[1]), 'S9 the smallest old event goes first';
  ASSERT (SELECT ps.max_purged_event_id FROM change_event_purge_state AS ps WHERE ps.event_table_name = 'eol_change_event') = old_ids[1],
         'S9 the EOL floor rises to the deleted event';
  ASSERT api.fn_eol_change_event_purge(10) = 1, 'S9 the second old event goes, and the young one stays';
  ASSERT NOT EXISTS (SELECT 1 FROM watchlist_event_ref AS wer WHERE wer.event_id = old_ids[2]), 'S9 the ref of a purged event goes with it';
  ASSERT EXISTS (SELECT 1 FROM eol_change_event AS ece WHERE ece.event_id = young_id), 'S9 an event of 89 days stays';
  ASSERT (SELECT array_agg(ps.event_table_name || ':' || ps.max_purged_event_id ORDER BY ps.event_table_name) FROM change_event_purge_state AS ps)
         = ARRAY['cve_change_event:0', 'domain_change_event:0', 'eol_change_event:' || old_ids[2], 'ip_change_event:0',
                 'package_advisory_change_event:0'],
         'S9 the purge raises the EOL floor only';
  low_id := pg_temp.t_eol_event('eolpurge', '4', 'eol_reached', NULL, NULL);
  UPDATE eol_change_event SET changed_at = now() - interval '91 days' WHERE event_id = low_id;
  UPDATE change_event_purge_state SET max_purged_event_id = low_id + 1000 WHERE event_table_name = 'eol_change_event';
  ASSERT api.fn_eol_change_event_purge(10) = 1, 'S9 the purge deletes the old event below the floor';
  ASSERT (SELECT ps.max_purged_event_id FROM change_event_purge_state AS ps WHERE ps.event_table_name = 'eol_change_event') = low_id + 1000,
         'S9 the purge never lowers the EOL floor';
  ASSERT (SELECT p.prosrc ~ 'PERFORM api\.fn_watchlist_event_ref_purge\(picked_event_ids, true\);'
            FROM pg_proc AS p WHERE p.oid = 'api.fn_eol_change_event_purge(integer)'::regprocedure),
         'S9 the purge locks the keys that scan after last_cve_event_id, as the package purge does';
END
$$;

DO $$
DECLARE
  f record;
BEGIN
  FOR f IN SELECT * FROM (VALUES
      ('api.fn_eol_change_event_max_id()'::regprocedure, 's', true, false),
      ('api.fn_eol_change_event_purge(integer)'::regprocedure, 'v', true, true),
      ('api.fn_watchlist_event_eol_pairs(integer, bigint[])'::regprocedure, 's', true, false),
      ('public.fn_eol_product_cpe_pick(text, text)'::regprocedure, 's', true, false),
      ('public.fn_eol_pick_series(text, text, text)'::regprocedure, 's', true, false),
      ('public.fn_eol_cycle_is_reached(date, boolean)'::regprocedure, 's', false, false),
      ('public.fn_eol_date_is_approaching(date)'::regprocedure, 's', false, false)) AS t (oid, volatility, is_search_path_set, is_definer) LOOP
    ASSERT (SELECT p.prosecdef FROM pg_proc AS p WHERE p.oid = f.oid) = f.is_definer,
           f.oid::text || CASE WHEN f.is_definer THEN ' is SECURITY DEFINER' ELSE ' is SECURITY INVOKER' END;
    ASSERT (SELECT p.proconfig IS NOT DISTINCT FROM CASE WHEN f.is_search_path_set THEN ARRAY['search_path=pg_catalog'] END
              FROM pg_proc AS p WHERE p.oid = f.oid),
           f.oid::text || ' sets search_path to pg_catalog when it reads a table';
    ASSERT (SELECT p.provolatile FROM pg_proc AS p WHERE p.oid = f.oid) = f.volatility, f.oid::text || ' has the volatility ' || f.volatility;
  END LOOP;
  ASSERT (SELECT p.proisstrict FROM pg_proc AS p WHERE p.oid = 'api.fn_eol_change_event_purge(integer)'::regprocedure),
         'api.fn_eol_change_event_purge is STRICT';
END
$$;

DO $$
DECLARE
  key_e       integer := (SELECT ak.id FROM api_keys AS ak WHERE ak.key_hash = repeat('e1', 32));
  search_item bigint;
  edge_item   bigint;
  head_id     bigint;
  after_id    bigint;
  scan        record;
BEGIN
  UPDATE change_event_purge_state SET max_purged_event_id = 0 WHERE event_table_name = 'eol_change_event';
  PERFORM api.fn_watchlist_edit_cve_search(repeat('e1', 32), 'add', 'eolacme', 'eolwidget', NULL, NULL, NULL, NULL, NULL, NULL, NULL, 100);
  search_item := (SELECT wic.item_id FROM watchlist_item_cve AS wic WHERE wic.api_key_id = key_e AND wic.endpoint_name = 'cve_search');
  head_id := pg_temp.t_eol_event('eolwatch', '2', 'eol_reached', current_date, NULL);
  edge_item := pg_temp.t_eol_add('eolwidget', '2.0');
  after_id := pg_temp.t_eol_event('eolwatch', '2-w', 'eol_reached', current_date, NULL);
  ASSERT search_item IS NOT NULL
     AND (SELECT wic.last_event_id_before_add FROM watchlist_item_cve AS wic WHERE wic.item_id = edge_item) = head_id,
         'S11 the fixture holds the cve_search item, and edge_item was added at head_id';
  ASSERT NOT EXISTS (SELECT 1 FROM api.fn_watchlist_event_eol_pairs(key_e, ARRAY[head_id, after_id]) AS pair WHERE pair.item_id = search_item),
         'S11 a cve_search item of the same pair hears no EOL event';
  ASSERT ARRAY(SELECT pair.event_id FROM api.fn_watchlist_event_eol_pairs(key_e, ARRAY[head_id, after_id]) AS pair WHERE pair.item_id = edge_item)
         = ARRAY[after_id],
         'S11 an item hears the events after last_event_id_before_add, and not the event at it';
  SELECT * INTO scan FROM api.fn_watchlist_event_scan(key_e, head_id - 1, head_id, 50, 1000, 1000);
  ASSERT (SELECT array_agg(DISTINCT x.id) FROM unnest(scan.page_event_ids) AS x (id)) = ARRAY[head_id]
     AND scan.scanned_event_count = 1 AND scan.scan_end_event_id = head_id,
         'S11 the scan reads no EOL event after p_head_event_id: ' || scan.page_event_ids::text;
END
$$;

INSERT INTO api_keys (key_hash) VALUES (repeat('e5', 32));
INSERT INTO eol_product_package (ecosystem, package_name, eol_product) VALUES
  ('npm', 'eolpkg', 'eolwatch'), ('PyPI', 'Eol_Py', 'eolwatch'), ('npm', 'eolshared', 'eolwatch'), ('npm', 'eolshared', 'eolother');

CREATE FUNCTION pg_temp.t_eol_package_add(p_ecosystem text, p_package_name text, p_version text) RETURNS bigint LANGUAGE plpgsql AS $$
BEGIN
  PERFORM api.fn_watchlist_edit_package_check(repeat('e5', 32), 'add', p_ecosystem, p_package_name, p_version, 500, 100, 100000, 20);
  RETURN (SELECT wip.item_id FROM watchlist_item_package AS wip
           WHERE wip.api_key_id = (SELECT ak.id FROM api_keys AS ak WHERE ak.key_hash = repeat('e5', 32))
             AND wip.package_name = p_package_name AND wip.version IS NOT DISTINCT FROM p_version);
END
$$;

INSERT INTO t_eol_ids VALUES
  ('P1', pg_temp.t_eol_package_add('npm', 'eolpkg', NULL)), ('P2', pg_temp.t_eol_package_add('npm', 'eolpkg', '2.5.1')),
  ('P3', pg_temp.t_eol_package_add('npm', 'eolpkg', 'v2')), ('P4', pg_temp.t_eol_package_add('npm', 'eolpkg', '9.9')),
  ('P5', pg_temp.t_eol_package_add('npm', 'eolother', NULL)), ('P6', pg_temp.t_eol_package_add('npm', 'eolshared', NULL)),
  ('P7', pg_temp.t_eol_package_add('PyPI', 'eol.py', NULL));
DO $$
BEGIN
  PERFORM api.fn_watchlist_edit_product_exposure(repeat('e5', 32), 'add', 'eolacme', 'eolwidget', NULL, 100);
END
$$;
INSERT INTO t_eol_ids
SELECT 'X1', wic.item_id FROM watchlist_item_cve AS wic
 WHERE wic.api_key_id = (SELECT ak.id FROM api_keys AS ak WHERE ak.key_hash = repeat('e5', 32));
INSERT INTO t_eol_ids VALUES
  ('f1', pg_temp.t_eol_event('eolwatch', '2', 'eol_approaching', current_date + 30, NULL)),
  ('f2', pg_temp.t_eol_event('eolwatch', '2.5', 'eol_reached', current_date - 1, NULL)),
  ('f3', pg_temp.t_eol_event('eolwatch', '2-w', 'eol_date_changed', current_date + 200, current_date + 100)),
  ('f4', pg_temp.t_eol_event('eolwatch', '3', 'eol_reached', NULL, NULL)),
  ('f5', pg_temp.t_eol_event('eolother', '1', 'eol_reached', NULL, NULL));
INSERT INTO t_eol_ids VALUES ('P8', pg_temp.t_eol_package_add('npm', 'eolshared', '1'));
INSERT INTO t_eol_ids VALUES ('f6', pg_temp.t_eol_event('eolother', '1', 'eol_date_changed', current_date + 10, current_date + 5));

CREATE FUNCTION pg_temp.t_eol_package_pairs(p_key_hash text, p_event_labels text[]) RETURNS text[] LANGUAGE sql AS $$
  SELECT coalesce(array_agg(coalesce(item.label, '?') || ':' || event.label ORDER BY item.label, event.label), '{}')
    FROM api.fn_watchlist_event_eol_pairs((SELECT ak.id FROM api_keys AS ak WHERE ak.key_hash = p_key_hash),
                                          ARRAY(SELECT i.id FROM t_eol_ids AS i WHERE i.label = ANY (p_event_labels))) AS pair
    LEFT JOIN t_eol_ids AS item ON item.id = pair.item_id AND (item.label LIKE 'P%' OR item.label LIKE 'X%')
    JOIN t_eol_ids AS event ON event.id = pair.event_id AND (event.label LIKE 'e%' OR event.label LIKE 'f%')
$$;

DO $$
DECLARE
  key_e5 integer := (SELECT ak.id FROM api_keys AS ak WHERE ak.key_hash = repeat('e5', 32));
  f      bigint[] := ARRAY(SELECT i.id FROM t_eol_ids AS i WHERE i.label LIKE 'f%' ORDER BY i.label);
  p8     bigint := (SELECT i.id FROM t_eol_ids AS i WHERE i.label = 'P8');
  scan   record;
BEGIN
  ASSERT pg_temp.t_eol_package_pairs(repeat('e5', 32), ARRAY['e1', 'f1', 'f2', 'f3', 'f4', 'f5', 'f6'])
         = ARRAY['P1:f1', 'P1:f2', 'P1:f3', 'P1:f4', 'P2:f2', 'P3:f1', 'P3:f3', 'P6:f5', 'P6:f6', 'P7:f1', 'P7:f2', 'P7:f3', 'P7:f4',
                 'P8:f6', 'X1:f1', 'X1:f2', 'X1:f3', 'X1:f4'],
         'S12 each package item hears the cycles of its package''s product and series: '
         || pg_temp.t_eol_package_pairs(repeat('e5', 32), ARRAY['e1', 'f1', 'f2', 'f3', 'f4', 'f5', 'f6'])::text;
  ASSERT (SELECT wip.last_event_id_before_add FROM watchlist_item_package AS wip WHERE wip.item_id = p8) = f[5],
         'S12 P8 was added at f5';
  ASSERT NOT EXISTS (SELECT 1 FROM unnest(pg_temp.t_eol_package_pairs(repeat('e1', 32), ARRAY['f1', 'f2', 'f3', 'f4', 'f5', 'f6'])) AS x (label)
                      WHERE x.label NOT LIKE '?:%'),
         'S12 the key e1, whose items hear the same events, gets no pair of an item of e5';
  SELECT * INTO scan FROM api.fn_watchlist_event_scan(key_e5, 0, f[6], 50, 1000, 1000);
  ASSERT (SELECT array_agg(DISTINCT x.id ORDER BY x.id) FROM unnest(scan.page_event_ids) AS x (id)) = f
     AND (SELECT count(*) FROM unnest(scan.page_event_ids) AS x (id)) = 18 AND NOT scan.is_page_full,
         'S12 the scan pages the six events through their eighteen pairs: ' || scan.page_event_ids::text;
  UPDATE change_event_purge_state SET max_purged_event_id = f[4] WHERE event_table_name = 'eol_change_event';
  SELECT * INTO scan FROM api.fn_watchlist_event_scan(key_e5, 0, f[6], 50, 1000, 1000);
  ASSERT scan.page_event_ids = ARRAY[f[5], f[6], f[6]],
         'S12 the scan skips the events of package items up to the EOL floor: ' || scan.page_event_ids::text;
  UPDATE change_event_purge_state SET max_purged_event_id = 0 WHERE event_table_name = 'eol_change_event';
END
$$;

DO $$
DECLARE
  f          bigint[] := ARRAY(SELECT i.id FROM t_eol_ids AS i WHERE i.label LIKE 'f%' ORDER BY i.label);
  p1         bigint := (SELECT i.id FROM t_eol_ids AS i WHERE i.label = 'P1');
  package_ids bigint[] := ARRAY(SELECT i.id FROM t_eol_ids AS i WHERE i.label LIKE 'P%');
  old_id     bigint;
  answer     record;
BEGIN
  CREATE TEMP TABLE t_eol_answer AS
  SELECT * FROM api.fn_watchlist_events(repeat('e5', 32), NULL, false, 50, 1000, 1000);
  ASSERT (SELECT count(*) FROM t_eol_answer) = 18 AND (SELECT bool_and(a.events_status = 'ok') FROM t_eol_answer AS a),
         'S13 the call answers the eighteen pairs';
  ASSERT (SELECT count(DISTINCT a.event_rank) FROM t_eol_answer AS a) = 6
     AND (SELECT count(*) FROM t_eol_answer AS a WHERE a.is_first_row_of_event) = 6,
         'S13 the six events have one rank and one first row each';
  SELECT * INTO answer FROM t_eol_answer AS a WHERE a.is_first_row_of_event AND a.eol_cycle = '2';
  ASSERT answer.item_id = p1 AND answer.item_endpoint_name = 'package_check' AND answer.item_ecosystem = 'npm'
     AND answer.item_package_name = 'eolpkg' AND answer.item_version IS NULL
     AND answer.event_type = 'eol_approaching' AND answer.eol_product = 'eolwatch' AND answer.advisory_id IS NULL
     AND answer.cve_id IS NULL AND answer.affects_version IS NULL,
         'S13 the first row of f1 is the row of P1 and carries the EOL columns';
  ASSERT (SELECT bool_and(a.affects_version IS NULL) FROM t_eol_answer AS a WHERE a.item_id = ANY (package_ids)),
         'S13 no pair of a package item and an EOL event has an affects_version';
  ASSERT (SELECT count(*) FROM t_eol_answer AS a WHERE a.item_id = ANY (package_ids)) = 14,
         'S13 the package items hear fourteen of the pairs';
  DROP TABLE t_eol_answer;

  old_id := pg_temp.t_eol_event('eolwatch', '3', 'eol_reached', NULL, NULL);
  PERFORM count(*) FROM api.fn_watchlist_events(repeat('e5', 32), NULL, false, 50, 1000, 1000);
  ASSERT (SELECT count(*) FROM watchlist_event_ref AS wer WHERE wer.event_id = old_id AND wer.item_id = ANY (package_ids)) = 2,
         'S13 P1 and P7 hear the old event, and the call numbers their refs';
  UPDATE eol_change_event SET changed_at = now() - interval '91 days' WHERE event_id = old_id;
  ASSERT api.fn_eol_change_event_purge(10) = 1, 'S13 the purge deletes the old event';
  ASSERT NOT EXISTS (SELECT 1 FROM watchlist_event_ref AS wer WHERE wer.event_id = old_id), 'S13 the refs of package items go with it';
  ASSERT (SELECT count(*) FROM watchlist_event_ref AS wer WHERE wer.item_id = p1 AND wer.event_id = ANY (f)) = 4,
         'S13 the refs of P1 on the young events stay';
  ASSERT (SELECT ps.max_purged_event_id FROM change_event_purge_state AS ps WHERE ps.event_table_name = 'eol_change_event') = old_id,
         'S13 the EOL floor rises to the purged event';
END
$$;

DO $$
BEGIN
  PERFORM api.fn_watchlist_clear(repeat('e1', 32));
  PERFORM api.fn_watchlist_clear(repeat('e5', 32));
END
$$;
TRUNCATE eol_change_event, watchlist_event_ref;
UPDATE change_event_purge_state SET max_purged_event_id = 0 WHERE event_table_name = 'eol_change_event';
DELETE FROM eol_product_cpe WHERE vendor IN ('eolacme', 'eolrival');
DELETE FROM eol_product WHERE product_name IN ('eolwatch', 'eolother');
DROP TABLE t_eol_ids;
