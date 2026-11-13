INSERT INTO lol_drivers (driver_id, category, is_verified, attack_technique_ids, catalog_added, driver_description, use_case,
                         privileges, operating_system, command, tags, detection_rules, reference_urls, cve_ids) VALUES
  ('00000000-0000-0000-0000-00000000000b', 'malicious',         false, '', '', '', '', '', '', '', '[]', '[]', '[]', '[]'),
  ('00000000-0000-0000-0000-00000000000a', 'vulnerable driver', true,  'T1068', '2023-07-22', 'Driver text', 'Use text',
   'kernel', 'Windows', 'sc.exe start a', '["a.sys"]', '[{"type": "sigma", "value": "https://d"}]', '["https://r"]',
   '["CVE-2020-0001", "CVE-2021-0002"]');
INSERT INTO lol_driver_samples (driver_id, sample_index, file_name, md5, sha1, sha256, authentihash_md5, authentihash_sha1,
                                authentihash_sha256, publisher, company, sample_description, original_file_name, file_version,
                                product_version, product_name, imphash, loads_despite_hvci) VALUES
  ('00000000-0000-0000-0000-00000000000b', 0, '', '', '', '', '', '', repeat('c', 64), '', '', '', '', '', '', '', '', NULL),
  ('00000000-0000-0000-0000-00000000000a', 2, '', '', '', repeat('c', 64), '', '', '', '', '', '', '', '', '', '', '', false),
  ('00000000-0000-0000-0000-00000000000a', 1, '', repeat('1', 32), repeat('2', 40), repeat('3', 64), repeat('4', 32), repeat('5', 40), repeat('6', 64), '', '', '',
   '', '', '', '', '', NULL),
  ('00000000-0000-0000-0000-00000000000a', 0, 'a.sys', repeat('a', 32), repeat('b', 40), repeat('c', 64), repeat('d', 32),
   repeat('e', 40), repeat('c', 64), 'Pub', 'Co', 'Sample text', 'orig.sys', '1.2', '3.4', 'Prod', repeat('7', 32), true);

CREATE TEMP VIEW t_driver_lookup_call AS SELECT * FROM api.fn_driver_lookup(ARRAY[repeat('C', 64)], 16, true);

DO $$
BEGIN
  ASSERT (SELECT array_agg(attname::text ORDER BY attnum) FROM pg_attribute
          WHERE attrelid = 't_driver_lookup_call'::regclass AND attnum > 0)
         = ARRAY['file_hash', 'match_count', 'driver_feed_loaded', 'matches'],
         'api.fn_driver_lookup answers the 4 columns db_DRIVERLOOKUP reads, in its order';
  ASSERT (SELECT array_agg(format_type(atttypid, atttypmod) ORDER BY attnum) FROM pg_attribute
          WHERE attrelid = 't_driver_lookup_call'::regclass AND attnum > 0)
         = ARRAY['text', 'integer', 'boolean', 'jsonb'],
         'file_hash is text, match_count is integer, driver_feed_loaded is boolean and matches is jsonb';
  ASSERT (SELECT row(c.file_hash, c.match_count, c.driver_feed_loaded)::text FROM t_driver_lookup_call AS c)
         = row(repeat('c', 64), 3, true)::text,
         'a hash in upper case answers in lower case, with every sample that carries it counted';
  ASSERT (SELECT array_agg(row(m.value ->> 'driver_id', m.value -> 'matched_driver_file' ->> 'sha256', m.value ->> 'matched_on')::text ORDER BY m.position)
            FROM t_driver_lookup_call AS c, jsonb_array_elements(c.matches) WITH ORDINALITY AS m (value, position))
         = ARRAY[row('00000000-0000-0000-0000-00000000000a', repeat('c', 64), '["sha256", "authentihash_sha256"]')::text,
                 row('00000000-0000-0000-0000-00000000000a', repeat('c', 64), '["sha256"]')::text,
                 row('00000000-0000-0000-0000-00000000000b', NULL, '["authentihash_sha256"]')::text],
         'the matches come in driver_id order, then sample_index order, and matched_on lists each hash column that equals the hash';
  ASSERT (SELECT c.matches -> 0 FROM t_driver_lookup_call AS c)
         = jsonb_build_object('driver_id', '00000000-0000-0000-0000-00000000000a', 'category', 'vulnerable driver', 'verified', true,
                              'attack_technique_ids', 'T1068', 'cve_ids', '["CVE-2020-0001", "CVE-2021-0002"]'::jsonb,
                              'catalog_added', '2023-07-22', 'description', 'Driver text', 'use_case', 'Use text',
                              'privileges', 'kernel', 'operating_system', 'Windows', 'command', 'sc.exe start a',
                              'tags', '["a.sys"]'::jsonb, 'matched_on', '["sha256", "authentihash_sha256"]'::jsonb,
                              'matched_driver_file', jsonb_build_object('file_name', 'a.sys', 'original_file_name', 'orig.sys', 'md5', repeat('a', 32),
                                                                        'sha1', repeat('b', 40), 'sha256', repeat('c', 64),
                                                                        'authentihash', jsonb_build_object('md5', repeat('d', 32), 'sha1', repeat('e', 40),
                                                                                                           'sha256', repeat('c', 64)),
                                                                        'imphash', repeat('7', 32), 'publisher', 'Pub', 'company', 'Co',
                                                                        'product_name', 'Prod', 'product_version', '3.4', 'file_version', '1.2',
                                                                        'description', 'Sample text', 'loads_despite_hvci', true),
                              'detection_rules', '[{"type": "sigma", "value": "https://d"}]'::jsonb, 'references', '["https://r"]'::jsonb,
                              'source_url', 'https://www.loldrivers.io/drivers/00000000-0000-0000-0000-00000000000a/'),
         'a match holds each catalog value of its driver and its sample from its own column, and the page of the driver';
  ASSERT (SELECT c.matches -> 2 FROM t_driver_lookup_call AS c)
         = jsonb_build_object('driver_id', '00000000-0000-0000-0000-00000000000b', 'category', 'malicious', 'verified', false,
                              'attack_technique_ids', NULL, 'cve_ids', '[]'::jsonb, 'catalog_added', NULL, 'description', NULL, 'use_case', NULL,
                              'privileges', NULL,
                              'operating_system', NULL, 'command', NULL, 'tags', '[]'::jsonb,
                              'matched_on', '["authentihash_sha256"]'::jsonb,
                              'matched_driver_file', jsonb_build_object('file_name', NULL, 'original_file_name', NULL, 'md5', NULL, 'sha1', NULL,
                                                                        'sha256', NULL,
                                                                        'authentihash', jsonb_build_object('md5', NULL, 'sha1', NULL, 'sha256', repeat('c', 64)),
                                                                        'imphash', NULL, 'publisher', NULL, 'company', NULL, 'product_name', NULL,
                                                                        'product_version', NULL, 'file_version', NULL, 'description', NULL,
                                                                        'loads_despite_hvci', NULL),
                              'detection_rules', '[]'::jsonb, 'references', '[]'::jsonb,
                              'source_url', 'https://www.loldrivers.io/drivers/00000000-0000-0000-0000-00000000000b/'),
         'a text the catalog left empty is null, and so is a loads_despite_hvci the catalog does not know';
  ASSERT (SELECT c.matches -> 1 -> 'matched_driver_file' -> 'loads_despite_hvci' FROM t_driver_lookup_call AS c) = 'false'::jsonb,
         'a false loads_despite_hvci answers false, not null';
  ASSERT (SELECT (c.matches::json -> 0 -> 'command')::text FROM api.fn_driver_lookup(ARRAY[repeat('c', 64)], 16, false) AS c) = 'null',
         'command is null unless p_is_command_included is true';
  ASSERT (SELECT row(c.match_count, json_array_length(c.matches::json), c.matches::json -> 1 -> 'matched_driver_file' ->> 'sha256')::text
            FROM api.fn_driver_lookup(ARRAY[repeat('c', 64)], 2, true) AS c)
         = row(3, 2, repeat('c', 64))::text,
         'matches holds at most p_match_row_count samples, the first ones, and match_count still counts every sample';
  ASSERT (SELECT row(c.match_count, c.matches)::text FROM api.fn_driver_lookup(ARRAY[repeat('c', 64)], 0, true) AS c)
         = row(3, '[]')::text,
         'a row limit of 0 answers an empty list and the count';
  ASSERT (SELECT array_agg(row(c.file_hash, c.match_count, c.matches::json -> 0 ->> 'matched_on')::text)
            FROM api.fn_driver_lookup(ARRAY[repeat('f', 32), repeat('a', 32), repeat('b', 40), repeat('d', 32), repeat('e', 40)], 16, true) AS c)
         = ARRAY[row(repeat('f', 32), 0, NULL)::text,
                 row(repeat('a', 32), 1, '["md5"]')::text,
                 row(repeat('b', 40), 1, '["sha1"]')::text,
                 row(repeat('d', 32), 1, '["authentihash_md5"]')::text,
                 row(repeat('e', 40), 1, '["authentihash_sha1"]')::text],
         'the rows come in the order of the list, an unknown hash answers a count of 0, and each hash column finds its sample';
  ASSERT (SELECT row(c.file_hash, c.match_count, c.matches)::text FROM api.fn_driver_lookup(ARRAY[''], 16, true) AS c)
         = row('', 0, '[]')::text,
         'an empty hash matches no sample, though 10 hash columns of the samples are empty';
  ASSERT (SELECT count(*) FROM api.fn_driver_lookup(NULL, 16, true)) = 0
     AND (SELECT count(*) FROM api.fn_driver_lookup(ARRAY[repeat('c', 64)], NULL, true)) = 0
     AND (SELECT count(*) FROM api.fn_driver_lookup(ARRAY[repeat('c', 64)], 16, NULL)) = 0,
         'api.fn_driver_lookup is STRICT, so a NULL argument answers no row';
END
$$;

SAVEPOINT t_driver_lookup_empty_catalog;
DELETE FROM lol_drivers;
DO $$
BEGIN
  ASSERT (SELECT row(c.file_hash, c.match_count, c.driver_feed_loaded, c.matches)::text FROM api.fn_driver_lookup(ARRAY[repeat('c', 64)], 16, true) AS c)
         = row(repeat('c', 64), 0, false, '[]')::text,
         'an empty lol_drivers table answers a count of 0, a catalog that is not loaded and an empty list';
END
$$;
ROLLBACK TO SAVEPOINT t_driver_lookup_empty_catalog;

SAVEPOINT t_driver_lookup_longest;
DELETE FROM lol_drivers;
INSERT INTO lol_drivers
SELECT '00000000-0000-0000-0000-0000000000' || lpad(n::text, 2, '0'), 'vulnerable driver', false,
       'T1234.567' || repeat(', T1234.567', 5), '2026-10-19',
       repeat(chr(1), 2048), repeat(chr(1), 1024), repeat(chr(1), 256), repeat(chr(1), 128), repeat(chr(1), 512),
       jsonb_build_array(repeat('x', 1020)), jsonb_build_array(repeat('x', 12284)), jsonb_build_array(repeat('x', 2044)),
       (SELECT jsonb_agg('CVE-2026-' || lpad(i::text, CASE WHEN i = 19 THEN 13 ELSE 14 END, '0') ORDER BY i) FROM generate_series(1, 19) AS i)
  FROM generate_series(1, 16) AS n;
INSERT INTO lol_driver_samples
SELECT '00000000-0000-0000-0000-0000000000' || lpad(n::text, 2, '0'), 0, repeat(chr(1), 128),
       repeat('a', 32), repeat('b', 40), repeat('c', 64), repeat('d', 32), repeat('e', 40), repeat('c', 64),
       repeat(chr(1), 128), repeat(chr(1), 128), repeat(chr(1), 256),
       repeat(chr(1), 128), repeat(chr(1), 128), repeat(chr(1), 128), repeat(chr(1), 256), repeat('f', 32), false
  FROM generate_series(1, 16) AS n;
DO $$
BEGIN
  ASSERT (SELECT octet_length(ld.cve_ids::text) FROM lol_drivers AS ld LIMIT 1) = 512,
         'the cve_ids of the longest values are 512 bytes';
  ASSERT (SELECT octet_length(c.matches::text) FROM api.fn_driver_lookup(ARRAY[repeat('c', 64)], 16, true) AS c) = 776032,
         format('the longest values give a matches text of 776032 bytes for 16 matches, measured %s',
                (SELECT octet_length(c.matches::text) FROM api.fn_driver_lookup(ARRAY[repeat('c', 64)], 16, true) AS c));
  ASSERT (SELECT octet_length(c.matches::text) FROM api.fn_driver_lookup(ARRAY[repeat('c', 64)], 16, false) AS c) = 726912,
         format('without command text the longest values give a matches text of 726912 bytes, measured %s',
                (SELECT octet_length(c.matches::text) FROM api.fn_driver_lookup(ARRAY[repeat('c', 64)], 16, false) AS c));
END
$$;
ROLLBACK TO SAVEPOINT t_driver_lookup_longest;

PREPARE t_driver_lookup_query AS SELECT * FROM api.fn_driver_lookup(ARRAY[$1], $2, $3);
CREATE TEMP TABLE t_driver_lookup_answer AS EXECUTE t_driver_lookup_query('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', '16', 'false');
DEALLOCATE t_driver_lookup_query;

DO $$
BEGIN
  ASSERT (SELECT row(a.file_hash, a.match_count)::text FROM t_driver_lookup_answer AS a) = row(repeat('a', 32), 1)::text,
         'the query db_DRIVERLOOKUP sends answers the samples of its hash';
  ASSERT (SELECT p.prosecdef AND p.proisstrict AND p.provolatile = 's' AND p.proconfig = ARRAY['search_path=pg_catalog']
            FROM pg_proc AS p WHERE p.oid = 'api.fn_driver_lookup(text[], integer, boolean)'::regprocedure),
         'api.fn_driver_lookup is SECURITY DEFINER, STRICT, STABLE and sets search_path to pg_catalog';
END
$$;
