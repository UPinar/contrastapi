DELETE FROM osv_advisories;

DO $$
BEGIN
  ASSERT (SELECT row(b.advisory_feed_loaded, b.results, b.attribution)::text
            FROM api.fn_package_check_bulk(ARRAY['npm'], ARRAY['left-pad'], ARRAY['1.0.0'], 10) AS b)
         = row(false, '[{"ecosystem": "npm", "name": "left-pad", "version": "1.0.0", "has_advisory_data": false, "fixed_version": null,
                        "malicious": null, "advisory_total": 0, "advisories": [], "eol": null}]'::jsonb, '[]'::jsonb)::text,
         'an empty catalog answers one row with advisory_feed_loaded false and each package without data';
END
$$;

INSERT INTO osv_advisories (advisory_id, source, license, summary, aliases, published_time, modified_time) VALUES
  ('GHSA-at', 'ghsa', 'CC-BY-4.0', '', '{}'::text[], '2021-01-01T00:00:00Z', '2021-01-01T00:00:00Z'),
  ('GHSA-g1', 'ghsa', 'CC-BY-4.0', 'G1', ARRAY['CVE-2021-1', 'PYSEC-2021-7'], '2021-01-01T00:00:00Z', '2021-01-01T00:00:00Z'),
  ('GHSA-g4', 'ghsa', 'CC-BY-4.0', 'G4', '{}'::text[], '2023-01-01T00:00:00Z', '2023-01-01T00:00:00Z'),
  ('GHSA-g5', 'ghsa', 'CC-BY-4.0', 'G5', '{}'::text[], '2022-06-01T00:00:00Z', '2022-06-01T00:00:00Z'),
  ('GHSA-g7', 'ghsa', 'CC-BY-4.0', 'G7', ARRAY['CVE-2021-1'], '2021-01-05T00:00:00Z', '2021-01-05T00:00:00Z'),
  ('MAL-2', 'mal', 'Apache-2.0', 'M2', '{}'::text[], '2020-01-01T00:00:00Z', '2020-01-01T00:00:00Z'),
  ('MAL-3', 'mal', 'Apache-2.0', 'M3', '{}'::text[], '2020-01-01T00:00:00Z', '2020-01-01T00:00:00Z'),
  ('PYSEC-2021-7', 'pysec', 'CC-BY-4.0', '', '{}'::text[], '2021-04-01T00:00:00Z', '2021-04-01T00:00:00Z'),
  ('PYSEC-2022-1', 'pysec', 'CC-BY-4.0', '', '{}'::text[], '2022-01-01T00:00:00Z', '2022-01-01T00:00:00Z'),
  ('RUSTSEC-2021-1', 'rustsec', 'CC0-1.0', '', ARRAY['CVE-2021-1'], '2021-03-01T00:00:00Z', '2021-03-01T00:00:00Z'),
  ('RUSTSEC-at', 'rustsec', 'CC-BY-4.0', '', '{}'::text[], '2021-01-02T00:00:00Z', '2021-01-02T00:00:00Z');
INSERT INTO osv_affected (advisory_id, affected_index, ecosystem, package_name, version_ranges, listed_versions, listed_versions_sortable, is_unaffected_provable)
SELECT af.advisory_id, af.affected_index, af.ecosystem, af.package_name, af.version_ranges::jsonb, af.listed_versions,
       ARRAY(SELECT array_to_string(public.fn_osv_version_sortable(af.ecosystem, kv.version_text), ' ')
               FROM unnest(af.keyed_versions) WITH ORDINALITY AS kv (version_text, version_ordinal) ORDER BY kv.version_ordinal),
       af.is_unaffected_provable
  FROM (VALUES
    ('GHSA-at', 0, 'npm', 'attr', '[{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}]', '{}'::text[], '{}'::text[], true),
    ('GHSA-g1', 0, 'npm', 'left-pad', '[{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}]', '{}'::text[], '{}'::text[], true),
    ('GHSA-g4', 0, 'npm', 'left-pad', '[{"type": "SEMVER", "events": [{"introduced": "0"}, {"last_affected": "5.0.0"}]}]', '{}'::text[], '{}'::text[], true),
    ('GHSA-g5', 0, 'npm', 'left-pad', '[{"type": "SEMVER", "events": [{"introduced": "6.0.0"}]}]', '{}'::text[], '{}'::text[], false),
    ('GHSA-g7', 0, 'npm', 'left-pad', '[{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.2.0"}]}]', '{}'::text[], '{}'::text[], true),
    ('MAL-2', 0, 'npm', 'left-pad', '[{"type": "SEMVER", "events": [{"introduced": "0"}]}]', '{}'::text[], '{}'::text[], false),
    ('MAL-3', 0, 'npm', 'mal-later', '[{"type": "SEMVER", "events": [{"introduced": "6.0.0"}]}]', '{}'::text[], '{}'::text[], false),
    ('PYSEC-2021-7', 0, 'npm', 'left-pad', '[{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.8.0"}]}]', '{}'::text[], '{}'::text[], true),
    ('PYSEC-2022-1', 0, 'PyPI', 'Foo_Bar', '[{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.2"}]}]', ARRAY['1.0', '1.1'], ARRAY['1.0', '1.1'], true),
    ('RUSTSEC-2021-1', 0, 'npm', 'left-pad', '[{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.9.0"}]}]', '{}'::text[], '{}'::text[], true),
    ('RUSTSEC-at', 0, 'npm', 'attr', '[{"type": "SEMVER", "events": [{"introduced": "3.0.0"}, {"fixed": "4.0.0"}]}]', '{}'::text[], '{}'::text[], true)
  ) AS af (advisory_id, affected_index, ecosystem, package_name, version_ranges, listed_versions, keyed_versions, is_unaffected_provable);
INSERT INTO osv_affected_version_intervals (advisory_id, affected_index, interval_index, introduced_version_sortable, upper_version_sortable, upper_event, fixed_version)
SELECT iv.advisory_id, iv.affected_index, iv.interval_index,
       CASE WHEN iv.introduced_version IS NOT NULL THEN public.fn_osv_version_sortable(osvaf.ecosystem, iv.introduced_version) END,
       CASE WHEN iv.upper_version IS NOT NULL THEN public.fn_osv_version_sortable(osvaf.ecosystem, iv.upper_version) END,
       iv.upper_event, iv.fixed_version
  FROM (VALUES
    ('GHSA-at', 0, 0, NULL::text, '2.0.0'::text, 'fixed'::text, '2.0.0'::text),
    ('GHSA-g1', 0, 0, NULL, '2.0.0', 'fixed', '2.0.0'),
    ('GHSA-g4', 0, 0, NULL, '5.0.0', 'last_affected', NULL),
    ('GHSA-g5', 0, 0, '6.0.0', NULL, NULL, NULL),
    ('GHSA-g7', 0, 0, NULL, '2.2.0', 'fixed', '2.2.0'),
    ('MAL-2', 0, 0, NULL, NULL, NULL, NULL),
    ('MAL-3', 0, 0, '6.0.0', NULL, NULL, NULL),
    ('PYSEC-2021-7', 0, 0, NULL, '1.8.0', 'fixed', '1.8.0'),
    ('PYSEC-2022-1', 0, 0, NULL, '1.2', 'fixed', '1.2'),
    ('RUSTSEC-2021-1', 0, 0, NULL, '1.9.0', 'fixed', '1.9.0'),
    ('RUSTSEC-at', 0, 0, '3.0.0', '4.0.0', 'fixed', '4.0.0')
  ) AS iv (advisory_id, affected_index, interval_index, introduced_version, upper_version, upper_event, fixed_version)
  JOIN osv_affected AS osvaf ON osvaf.advisory_id = iv.advisory_id AND osvaf.affected_index = iv.affected_index;

CREATE TEMP VIEW t_package_check_bulk_call AS
  SELECT * FROM api.fn_package_check_bulk(ARRAY['npm', 'PyPI', 'npm', 'Pub', 'npm'], ARRAY['left-pad', 'foo.bar', 'attr', 'x', 'no-such'],
                                          ARRAY['1.5.0', '1.1', '3.5.0', '1.0', '1.0.0'], 10);

DO $$
DECLARE
  answer record;
BEGIN
  ASSERT (SELECT array_agg(attname::text ORDER BY attnum) FROM pg_attribute
          WHERE attrelid = 't_package_check_bulk_call'::regclass AND attnum > 0)
         = ARRAY['advisory_feed_loaded', 'results', 'attribution', 'failed_item_count'],
         'api.fn_package_check_bulk answers the 4 columns db_PACKAGECHECKBULK reads, in its order';
  ASSERT (SELECT array_agg(format_type(atttypid, atttypmod) ORDER BY attnum) FROM pg_attribute
          WHERE attrelid = 't_package_check_bulk_call'::regclass AND attnum > 0)
         = ARRAY['boolean', 'jsonb', 'jsonb', 'integer'],
         'advisory_feed_loaded is boolean, results and attribution are jsonb, and failed_item_count is integer';
  ASSERT (SELECT count(*) FROM t_package_check_bulk_call) = 1, 'the function answers one row';
  SELECT * INTO answer FROM t_package_check_bulk_call;
  ASSERT answer.advisory_feed_loaded, 'a catalog with an advisory is loaded';
  ASSERT answer.failed_item_count = 0, 'a list with no long eol series has no failed package';
  ASSERT (SELECT array_agg(row(r.item_json ->> 'ecosystem', r.item_json ->> 'name', r.item_json ->> 'version')::text ORDER BY r.item_index)
            FROM jsonb_array_elements(answer.results) WITH ORDINALITY AS r (item_json, item_index))
         = ARRAY[row('npm', 'left-pad', '1.5.0')::text, row('PyPI', 'foo.bar', '1.1')::text, row('npm', 'attr', '3.5.0')::text,
                 row('Pub', 'x', '1.0')::text, row('npm', 'no-such', '1.0.0')::text],
         'results holds one object for each package in request order, with the ecosystem, the name and the version as sent';
  ASSERT (SELECT bool_and(row(r.item_json -> 'has_advisory_data', r.item_json ->> 'fixed_version', (r.item_json ->> 'advisory_total')::integer,
                              r.item_json -> 'malicious' -> 'id', r.item_json -> 'malicious' -> 'affects_version',
                              (SELECT array_agg(a.advisory_json - 'aliases' ORDER BY a.advisory_ordinal)
                                 FROM jsonb_array_elements(r.item_json -> 'advisories') WITH ORDINALITY AS a (advisory_json, advisory_ordinal)))::text
                          = row(to_jsonb(c.has_advisory_data), c.fixed_version, c.result_count, c.malicious -> 'id', c.malicious -> 'affects_version',
                                (SELECT array_agg(jsonb_build_object('id', s.result_json -> 'id', 'affects_version', s.result_json -> 'affects_version')
                                                  ORDER BY s.result_ordinal)
                                   FROM jsonb_array_elements(c.results) WITH ORDINALITY AS s (result_json, result_ordinal)))::text)
            FROM jsonb_array_elements(answer.results) WITH ORDINALITY AS r (item_json, item_index)
            JOIN api.fn_package_check(r.item_json ->> 'ecosystem', r.item_json ->> 'name', r.item_json ->> 'version', 10, 0) AS c ON true),
         'each package of a known ecosystem has the has_advisory_data, fixed_version, result_count, malicious and page of api.fn_package_check';
  ASSERT answer.results -> 0
         = '{"ecosystem": "npm", "name": "left-pad", "version": "1.5.0", "has_advisory_data": true, "fixed_version": null,
             "malicious": {"id": "MAL-2", "affects_version": true}, "advisory_total": 4,
             "advisories": [{"id": "GHSA-g4", "aliases": [], "affects_version": true},
                            {"id": "GHSA-g5", "aliases": [], "affects_version": null},
                            {"id": "GHSA-g7", "aliases": ["CVE-2021-1", "RUSTSEC-2021-1"], "affects_version": true},
                            {"id": "GHSA-g1", "aliases": ["CVE-2021-1", "PYSEC-2021-7", "RUSTSEC-2021-1"], "affects_version": true}], "eol": null}'::jsonb,
         'a package holds advisory_total and its advisories newest first, each with its id, its aliases and affects_version, and malicious keeps the id and affects_version';
  ASSERT answer.results -> 1
         = '{"ecosystem": "PyPI", "name": "foo.bar", "version": "1.1", "has_advisory_data": true, "fixed_version": "1.2", "malicious": null,
             "advisory_total": 1, "advisories": [{"id": "PYSEC-2022-1", "aliases": [], "affects_version": true}], "eol": null}'::jsonb,
         'a PyPI package names the fixed version of its ECOSYSTEM range';
  ASSERT answer.results -> 2
         = '{"ecosystem": "npm", "name": "attr", "version": "3.5.0", "has_advisory_data": true, "fixed_version": "4.0.0", "malicious": null,
             "advisory_total": 1, "advisories": [{"id": "RUSTSEC-at", "aliases": [], "affects_version": true}], "eol": null}'::jsonb,
         'a package with a fixed version names it, and a package no mal advisory names has malicious null';
  ASSERT answer.results -> 3
         = '{"ecosystem": "Pub", "name": "x", "version": "1.0", "has_advisory_data": null, "fixed_version": null, "malicious": null,
             "advisory_total": null, "advisories": [], "eol": null}'::jsonb,
         'a package of an unknown ecosystem stays in its place, with null values and no advisory';
  ASSERT answer.results -> 4 -> 'has_advisory_data' = 'false'::jsonb AND answer.results -> 4 -> 'advisories' = '[]'::jsonb,
         'a package no advisory names has no advisory data and no advisory';
  ASSERT (SELECT array_agg(row(a.attribution_json ->> 'source', a.attribution_json ->> 'license', a.attribution_json ->> 'url')::text ORDER BY a.attribution_ordinal)
            FROM jsonb_array_elements(answer.attribution) WITH ORDINALITY AS a (attribution_json, attribution_ordinal))
         = ARRAY[row('ghsa', 'CC-BY-4.0', 'https://github.com/github/advisory-database')::text,
                 row('mal', 'Apache-2.0', 'https://github.com/ossf/malicious-packages')::text,
                 row('pysec', 'CC-BY-4.0', 'https://github.com/pypa/advisory-database')::text,
                 row('rustsec', 'CC-BY-4.0', 'https://github.com/rustsec/advisory-db')::text,
                 row('rustsec', 'CC0-1.0', 'https://github.com/rustsec/advisory-db')::text],
         'attribution names each source and license of every package once, with its link, by source and then by license in byte order';
  ASSERT (SELECT array_agg(DISTINCT k.key_name ORDER BY k.key_name)
            FROM jsonb_array_elements(answer.attribution) AS a (attribution_json), jsonb_object_keys(a.attribution_json) AS k (key_name))
         = ARRAY['license', 'source', 'url'],
         'an attribution entry holds the source, the license and the link';
  ASSERT (SELECT array_agg(jsonb_array_length(b.results -> 0 -> 'advisories') ORDER BY v.row_count)
            FROM unnest(ARRAY[3, 4]) AS v (row_count)
           CROSS JOIN LATERAL api.fn_package_check_bulk(ARRAY['npm'], ARRAY['left-pad'], ARRAY['1.5.0'], v.row_count) AS b)
         = ARRAY[3, 4],
         'advisories holds p_advisory_row_count advisories at most, and all four at four';
  ASSERT (SELECT b.results -> 0 ->> 'advisory_total' FROM api.fn_package_check_bulk(ARRAY['npm'], ARRAY['left-pad'], ARRAY['1.5.0'], 1) AS b) = '4',
         'advisory_total counts the results beyond the cut too';
  ASSERT (SELECT b.results -> 0 -> 'malicious'
            FROM api.fn_package_check_bulk(ARRAY['npm'], ARRAY['mal-later'], ARRAY['1.5.0'], 10) AS b)
         = (SELECT jsonb_build_object('id', c.malicious -> 'id', 'affects_version', c.malicious -> 'affects_version')
              FROM api.fn_package_check('npm', 'mal-later', '1.5.0', 10, 0) AS c)
     AND (SELECT c.malicious -> 'affects_version' FROM api.fn_package_check('npm', 'mal-later', '1.5.0', 10, 0) AS c) = 'null'::jsonb,
         'malicious keeps the affects_version of package_check when it is null';
  ASSERT (SELECT row(b.results -> 0 -> 'has_advisory_data', b.results -> 0 -> 'advisory_total')::text
            FROM api.fn_package_check_bulk(ARRAY['npm'], ARRAY['attr'], ARRAY['5.0.0'], 10) AS b)
         = row('true'::jsonb, '0'::jsonb)::text,
         'a package whose advisories all miss its version has advisory data and no result';
  ASSERT (SELECT bool_and(r.item_json
                          = jsonb_build_object(
                              'ecosystem',         i.ecosystem,
                              'name',              i.package_name,
                              'version',           i.package_version,
                              'has_advisory_data', c.has_advisory_data,
                              'fixed_version',     c.fixed_version,
                              'malicious',         CASE WHEN c.malicious IS NOT NULL
                                                        THEN jsonb_build_object('id', c.malicious -> 'id', 'affects_version', c.malicious -> 'affects_version')
                                                   END,
                              'advisory_total',    c.result_count,
                              'advisories',        (SELECT coalesce(jsonb_agg(jsonb_build_object('id',              s.result_json -> 'id',
                                                                                                 'aliases',         s.result_json -> 'aliases',
                                                                                                 'affects_version', s.result_json -> 'affects_version')
                                                                              ORDER BY s.result_ordinal), '[]'::jsonb)
                                                      FROM jsonb_array_elements(c.results) WITH ORDINALITY AS s (result_json, result_ordinal)),
                              'eol',               NULL::jsonb))
                 AND count(*) = 7
            FROM api.fn_package_check_bulk(ARRAY['npm', 'npm', 'npm', 'npm', 'NPM', 'npm', 'npm'],
                                           ARRAY['left-pad', 'attr', 'left-pad', 'attr', 'LEFT-PAD', 'attr', 'left-pad'],
                                           ARRAY['1.5.0', '3.5.0', '6.5.0', '1.0.0', '1.5.0', '5.0.0', '2.1.0'], 10) AS b
           CROSS JOIN LATERAL jsonb_array_elements(b.results) WITH ORDINALITY AS r (item_json, item_index)
            JOIN unnest(ARRAY['npm', 'npm', 'npm', 'npm', 'NPM', 'npm', 'npm'],
                        ARRAY['left-pad', 'attr', 'left-pad', 'attr', 'LEFT-PAD', 'attr', 'left-pad'],
                        ARRAY['1.5.0', '3.5.0', '6.5.0', '1.0.0', '1.5.0', '5.0.0', '2.1.0'])
                 WITH ORDINALITY AS i (ecosystem, package_name, package_version, item_index) ON i.item_index = r.item_index
           CROSS JOIN LATERAL api.fn_package_check(i.ecosystem, i.package_name, i.package_version, 10, 0) AS c),
         'each item of a package named several times gets the answer of api.fn_package_check for its own version';
  ASSERT (SELECT array_agg(row(r.item_json ->> 'version', r.item_json ->> 'fixed_version', r.item_json ->> 'advisory_total')::text ORDER BY r.item_index)
            FROM api.fn_package_check_bulk(ARRAY['npm', 'npm', 'npm', 'npm'], ARRAY['attr', 'left-pad', 'attr', 'attr'],
                                           ARRAY['1.0.0', '1.5.0', '3.5.0', '5.0.0'], 10) AS b
           CROSS JOIN LATERAL jsonb_array_elements(b.results) WITH ORDINALITY AS r (item_json, item_index))
         = ARRAY[row('1.0.0', '2.0.0', '1')::text, row('1.5.0', NULL, '4')::text, row('3.5.0', '4.0.0', '1')::text, row('5.0.0', NULL, '0')::text],
         'the versions of one package keep their own fixed version and their own count, in request order';
  ASSERT (SELECT count(*) FROM api.fn_package_check_bulk(NULL, ARRAY['left-pad'], ARRAY['1.5.0'], 10)) = 0
     AND (SELECT count(*) FROM api.fn_package_check_bulk(ARRAY['npm'], NULL, ARRAY['1.5.0'], 10)) = 0
     AND (SELECT count(*) FROM api.fn_package_check_bulk(ARRAY['npm'], ARRAY['left-pad'], NULL, 10)) = 0
     AND (SELECT count(*) FROM api.fn_package_check_bulk(ARRAY['npm'], ARRAY['left-pad'], ARRAY['1.5.0'], NULL)) = 0,
         'a NULL argument answers no row';
END
$$;

PREPARE t_package_check_bulk_query AS SELECT * FROM api.fn_package_check_bulk($1, $2, $3, $4);
CREATE TEMP TABLE t_package_check_bulk_answer AS
  EXECUTE t_package_check_bulk_query('{"NPM","npm"}', '{"LEFT-PAD","a\"b"}', '{"1.5.0","1.0.0"}', '10');
DEALLOCATE t_package_check_bulk_query;

DO $$
BEGIN
  ASSERT (SELECT array_agg(row(r.item_json ->> 'ecosystem', r.item_json ->> 'name', r.item_json ->> 'advisory_total')::text ORDER BY r.item_index)
            FROM t_package_check_bulk_answer AS b, jsonb_array_elements(b.results) WITH ORDINALITY AS r (item_json, item_index))
         = ARRAY[row('NPM', 'LEFT-PAD', '4')::text, row('npm', 'a"b', '0')::text],
         'the query db_PACKAGECHECKBULK sends answers each package as sent, a quote in a name included';
  ASSERT (SELECT p.prosecdef AND p.proisstrict AND p.provolatile = 's' AND p.prorows = 1 AND p.proconfig = ARRAY['search_path=pg_catalog']
            FROM pg_proc AS p WHERE p.oid = 'api.fn_package_check_bulk(text[], text[], text[], integer)'::regprocedure),
         'api.fn_package_check_bulk is SECURITY DEFINER, STRICT, STABLE, estimates 1 row and sets search_path to pg_catalog';
  ASSERT (SELECT p.prorows = 1 FROM pg_proc AS p WHERE p.oid = 'api.fn_package_check(text, text, text, integer, integer)'::regprocedure),
         'api.fn_package_check estimates 1 row';
  ASSERT (SELECT array_agg(row(pcv.version_index, pcv.result_count, pcv.fixed_version,
                               (SELECT array_agg(e.result_json ->> 'id' ORDER BY e.result_ordinal)
                                  FROM jsonb_array_elements(pcv.results) WITH ORDINALITY AS e (result_json, result_ordinal)))::text
                           ORDER BY pcv.version_index)
            FROM api.fn_package_check_versions('npm', 'left-pad', ARRAY['1.5.0', '2.1.0', '6.5.0'], 2, 2) AS pcv)
         = ARRAY[row(1, 4, NULL, ARRAY['GHSA-g7', 'GHSA-g1'])::text, row(2, 3, NULL, ARRAY['GHSA-g7'])::text, row(3, 1, NULL, NULL)::text],
         'each version has its own count and its own page of p_result_row_count results from p_result_offset';
  ASSERT (SELECT row(c.result_count, c.results)::text FROM api.fn_package_check('npm', 'left-pad', '1.5.0', 10, 2147483647) AS c)
         = row(4, '[]'::jsonb)::text,
         'an offset of 2147483647 answers an empty page and the full count, with no integer overflow';
  ASSERT (SELECT array_agg(row(pcv.version_index, pcv.advisory_feed_loaded, pcv.has_advisory_data, pcv.result_count, pcv.fixed_version,
                               pcv.malicious, pcv.results, pcv.attribution)::text ORDER BY pcv.version_index)
            FROM api.fn_package_check_versions('npm', 'attr', ARRAY['3.5.0', NULL, '1.0.0', '3.5.0'], 1, 0) AS pcv)
         = (SELECT array_agg(row(v.version_index, c.advisory_feed_loaded, c.has_advisory_data, c.result_count, c.fixed_version,
                                 c.malicious, c.results, c.attribution)::text ORDER BY v.version_index)
              FROM unnest(ARRAY['3.5.0', NULL, '1.0.0', '3.5.0']) WITH ORDINALITY AS v (version_text, version_index)
             CROSS JOIN LATERAL api.fn_package_check('npm', 'attr', v.version_text, 1, 0) AS c),
         'a list with a NULL version and a version named twice answers each one as api.fn_package_check answers it alone';
  ASSERT (SELECT count(*) FROM api.fn_package_check_versions('npm', 'attr', NULL, 1, 0)) = 0
     AND (SELECT count(*) FROM api.fn_package_check_versions('Pub', 'attr', ARRAY['1.0.0'], 1, 0)) = 0,
         'a NULL list of versions, or an unknown ecosystem, answers no row';
END
$$;

DELETE FROM osv_advisories;
CREATE TEMP TABLE t_package_check_bulk_weight_row AS
  SELECT 'GHSA-w' || f.fixture_index || '-' || g.advisory_number AS advisory_id, f.ecosystem, f.package_name
    FROM (VALUES (1, 'npm', 'wa', 3), (2, 'npm', 'wb', 5), (3, 'PyPI', 'wa', 7), (4, 'PyPI', 'Foo_Bar', 2), (5, 'npm', 'Left-Pad', 4))
           AS f (fixture_index, ecosystem, package_name, row_count)
   CROSS JOIN LATERAL generate_series(1, f.row_count) AS g (advisory_number);
INSERT INTO osv_advisories (advisory_id, source, license, published_time, modified_time)
SELECT advisory.advisory_id, 'ghsa', 'CC-BY-4.0', '2021-01-01T00:00:00Z', '2021-01-01T00:00:00Z'
  FROM (SELECT wr.advisory_id FROM t_package_check_bulk_weight_row AS wr UNION ALL VALUES ('GHSA-wd-1'), ('GHSA-wv-1')) AS advisory (advisory_id);
INSERT INTO osv_affected (advisory_id, affected_index, ecosystem, package_name, version_ranges)
SELECT wr.advisory_id, 0, wr.ecosystem, wr.package_name, '[{"type": "SEMVER", "events": [{"introduced": "0"}]}]'
  FROM t_package_check_bulk_weight_row AS wr;
INSERT INTO osv_affected_version_intervals (advisory_id, affected_index, interval_index)
SELECT wr.advisory_id, 0, 0 FROM t_package_check_bulk_weight_row AS wr;
INSERT INTO osv_affected (advisory_id, affected_index, ecosystem, package_name, version_ranges, is_unaffected_provable) VALUES
  ('GHSA-wd-1', 0, 'npm', 'wd', '[{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0.0"}]}]', true),
  ('GHSA-wd-1', 1, 'npm', 'wd', '[{"type": "SEMVER", "events": [{"introduced": "2.0.0"}]}]', false);
INSERT INTO osv_affected_version_intervals (advisory_id, affected_index, interval_index, introduced_version_sortable, upper_version_sortable, upper_event, fixed_version) VALUES
  ('GHSA-wd-1', 0, 0, NULL, public.fn_osv_version_sortable('npm', '1.0.0'), 'fixed', '1.0.0'),
  ('GHSA-wd-1', 1, 0, public.fn_osv_version_sortable('npm', '2.0.0'), NULL, NULL, NULL);
INSERT INTO osv_affected (advisory_id, affected_index, ecosystem, package_name, listed_versions, listed_versions_sortable)
SELECT 'GHSA-wv-1', e.entry_index - 1, 'npm', 'wv',
       ARRAY(SELECT e.entry_index || '.0.' || v.version_index FROM generate_series(1, 39) AS v (version_index) ORDER BY v.version_index),
       ARRAY(SELECT array_to_string(public.fn_osv_version_sortable('npm', e.entry_index || '.0.' || v.version_index), ' ')
               FROM generate_series(1, 39) AS v (version_index) ORDER BY v.version_index)
  FROM generate_series(1, 2) AS e (entry_index);

PREPARE t_package_check_bulk_weigh_query AS SELECT api.fn_package_check_bulk_weigh($1, $2, $3, $4, $5) AS served_item_count;
CREATE TEMP TABLE t_package_check_bulk_served_answer AS
  EXECUTE t_package_check_bulk_weigh_query('{"npm","npm","npm"}', '{"wa","a\"b","wb"}', '100', '204', '20');
DEALLOCATE t_package_check_bulk_weigh_query;

DO $$
BEGIN
  ASSERT (SELECT array_agg(row(attname::text, format_type(atttypid, atttypmod))::text ORDER BY attnum) FROM pg_attribute
          WHERE attrelid = 't_package_check_bulk_served_answer'::regclass AND attnum > 0)
         = ARRAY[row('served_item_count', 'integer')::text],
         'the query db_PACKAGECHECKBULKWeigh sends answers one integer column named served_item_count';
  ASSERT (SELECT array_agg(a.served_item_count) FROM t_package_check_bulk_served_answer AS a) = ARRAY[3],
         'the query db_PACKAGECHECKBULKWeigh sends answers one value: wa weighs 103 and a"b 100, so wb starts at 203, below 204';
  ASSERT (SELECT p.prosecdef AND p.proisstrict AND p.provolatile = 's' AND p.proconfig = ARRAY['search_path=pg_catalog']
            FROM pg_proc AS p WHERE p.oid = 'api.fn_package_check_bulk_weigh(text[], text[], integer, integer, integer)'::regprocedure),
         'api.fn_package_check_bulk_weigh is SECURITY DEFINER, STRICT, STABLE and sets search_path to pg_catalog';
  ASSERT (SELECT NOT p.prosecdef AND NOT p.proisstrict AND p.provolatile = 's' AND p.proconfig = ARRAY['search_path=pg_catalog']
            FROM pg_proc AS p WHERE p.oid = 'api.fn_package_check_package_weight(text, text, integer, integer)'::regprocedure),
         'api.fn_package_check_package_weight is SECURITY INVOKER, not STRICT, STABLE and sets search_path to pg_catalog';
  ASSERT (SELECT NOT p.prosecdef AND NOT p.proisstrict AND p.provolatile = 'i' AND p.proconfig = ARRAY['search_path=pg_catalog']
            FROM pg_proc AS p WHERE p.oid = 'api.fn_package_check_ecosystem(text)'::regprocedure),
         'api.fn_package_check_ecosystem is SECURITY INVOKER, IMMUTABLE and sets search_path to pg_catalog';

  ASSERT (SELECT array_agg(api.fn_package_check_ecosystem(e.ecosystem_name) ORDER BY e.ecosystem_index)
            FROM unnest(ARRAY['NPM', 'pypi', 'MaVeN', 'gO', 'NUGET', 'rubyGems', 'Crates.IO', 'PACKAGIST', 'swiftURL'])
                 WITH ORDINALITY AS e (ecosystem_name, ecosystem_index))
         = ARRAY['npm', 'PyPI', 'Maven', 'Go', 'NuGet', 'RubyGems', 'crates.io', 'Packagist', 'SwiftURL'],
         'api.fn_package_check_ecosystem writes each of the nine ecosystems, in any case, as OSV writes it';
  ASSERT api.fn_package_check_ecosystem('NPM ') IS NULL AND api.fn_package_check_ecosystem('unknown') IS NULL
     AND api.fn_package_check_ecosystem(NULL) IS NULL,
         'api.fn_package_check_ecosystem answers NULL for a name with a space, an unknown name and NULL';

  ASSERT (SELECT array_agg(api.fn_package_check_bulk_weigh(ARRAY['npm', 'npm', 'npm'], ARRAY['wa', 'wb', 'wc'], 100, b.weight_budget, 20)
                           ORDER BY b.weight_budget)
            FROM unnest(ARRAY[103, 104, 208, 209]) AS b (weight_budget))
         = ARRAY[1, 2, 2, 3],
         'an item is served when the weight before it is below the budget: 103 serves 1, 104 serves 2, 208 serves 2 and 209 serves 3';
  ASSERT (SELECT array_agg(api.fn_package_check_bulk_weigh(ARRAY['npm', 'npm', 'npm'], ARRAY['wa', 'wb', 'wc'], w.item_base_weight, 209, 20)
                           ORDER BY w.item_base_weight)
            FROM unnest(ARRAY[100, 101]) AS w (item_base_weight))
         = ARRAY[3, 2],
         'p_item_base_weight is added to each item: a base of 101 moves npm wc to 210, past a budget of 209';
  ASSERT api.fn_package_check_bulk_weigh(ARRAY['npm'], ARRAY['wb'], 100, 1, 20) = 1
     AND api.fn_package_check_bulk_weigh(ARRAY['npm', 'npm'], ARRAY['wb', 'wa'], 100, 1, 20) = 1,
         'the first item is served whatever it weighs, and the next one is not';
  ASSERT (SELECT array_agg(api.fn_package_check_bulk_weigh(ARRAY['pypi', 'PyPI', 'npm'], ARRAY['Foo_Bar', 'foo.bar', 'wa'], 100, b.weight_budget, 20)
                           ORDER BY b.weight_budget)
            FROM unnest(ARRAY[204, 205]) AS b (weight_budget))
         = ARRAY[2, 3]
     AND (SELECT array_agg(api.fn_package_check_bulk_weigh(ARRAY['npm', 'NPM', 'npm'], ARRAY['Left-Pad', 'left-pad', 'wa'], 100, b.weight_budget, 20)
                           ORDER BY b.weight_budget)
            FROM unnest(ARRAY[208, 209]) AS b (weight_budget))
         = ARRAY[2, 3],
         'two spellings of one package weigh the same: pypi Foo_Bar and PyPI foo.bar weigh 102 each, npm Left-Pad and NPM left-pad 104 each';
  ASSERT (SELECT array_agg(api.fn_package_check_bulk_weigh(ARRAY['npm', 'Pub', 'npm'], ARRAY['no-such', 'x', 'none'], 100, b.weight_budget, 20)
                           ORDER BY b.weight_budget)
            FROM unnest(ARRAY[200, 201]) AS b (weight_budget))
         = ARRAY[2, 3],
         'a package with no row and a package of an unknown ecosystem each weigh the base weight';
  ASSERT (SELECT array_agg(api.fn_package_check_bulk_weigh(ARRAY['npm', 'npm', 'npm', 'npm'], ARRAY['wa', 'wa', 'wa', 'wb'], 100, b.weight_budget, 20)
                           ORDER BY b.weight_budget)
            FROM unnest(ARRAY[309, 310]) AS b (weight_budget))
         = ARRAY[3, 4],
         'a package named three times weighs its rows each time: npm wb starts at 309';
  ASSERT (SELECT array_agg(api.fn_package_check_bulk_weigh(ARRAY['npm', 'npm'], ARRAY['wd', 'wa'], 100, b.weight_budget, 20)
                           ORDER BY b.weight_budget)
            FROM unnest(ARRAY[102, 103]) AS b (weight_budget))
         = ARRAY[1, 2],
         'an advisory that names a package in two affected entries gives it two rows: npm wd weighs 102';
  ASSERT (SELECT count(*) FROM osv_affected AS oa WHERE oa.ecosystem = 'npm' AND oa.package_name_normalized = 'wv'
             AND cardinality(oa.listed_versions) = 39) = 2,
         'npm wv has two rows, and each lists 39 versions';
  ASSERT (SELECT array_agg(api.fn_package_check_bulk_weigh(ARRAY['npm', 'npm'], ARRAY['wv', 'wa'], 100, b.weight_budget, b.listed_versions_per_weight)
                           ORDER BY b.case_index)
            FROM (VALUES (1, 105, 20), (2, 106, 20), (3, 104, 39), (4, 105, 39)) AS b (case_index, weight_budget, listed_versions_per_weight))
         = ARRAY[1, 2, 1, 2],
         'the 78 listed versions of npm wv add 78 / 20 = 3 units, summed over its rows and rounded down, so it weighs 105; at 39 per unit they add 2';
  ASSERT api.fn_package_check_package_weight('npm', 'wv', 100, 20) = 105
     AND api.fn_package_check_package_weight('npm', 'wv', 0, 78) = 3
     AND api.fn_package_check_package_weight('npm', 'no-such', 100, 20) = 100
     AND api.fn_package_check_package_weight(NULL, 'wv', 100, 20) = 100,
         'api.fn_package_check_package_weight adds the rows and the listed versions to the base; a package with no row, or a NULL ecosystem, weighs the base';
  ASSERT api.fn_package_check_package_weight('npm', 'wv', NULL, 20) IS NULL
     AND api.fn_package_check_package_weight('npm', 'wv', 100, NULL) IS NULL,
         'api.fn_package_check_package_weight answers NULL for a NULL base or a NULL divisor';
  ASSERT api.fn_package_check_bulk_weigh(array_fill('npm'::text, ARRAY[500]), array_fill('wb'::text, ARRAY[500]), 100, 2147483647, 20) = 500,
         'a budget of 2147483647 serves all 500 items';
  ASSERT api.fn_package_check_bulk_weigh(ARRAY[]::text[], ARRAY[]::text[], 100, 100000, 20) = 0,
         'empty arrays serve 0 items';
  ASSERT api.fn_package_check_bulk_weigh(NULL, ARRAY['wa'], 100, 100000, 20) IS NULL
     AND api.fn_package_check_bulk_weigh(ARRAY['npm'], NULL, 100, 100000, 20) IS NULL
     AND api.fn_package_check_bulk_weigh(ARRAY['npm'], ARRAY['wa'], NULL, 100000, 20) IS NULL
     AND api.fn_package_check_bulk_weigh(ARRAY['npm'], ARRAY['wa'], 100, NULL, 20) IS NULL
     AND api.fn_package_check_bulk_weigh(ARRAY['npm'], ARRAY['wa'], 100, 100000, NULL) IS NULL,
         'a NULL argument answers NULL';
END
$$;

INSERT INTO eol_product (product_name, product_label, url) VALUES
  ('e-pk', 'Pk', 'https://endoflife.date/e-pk'), ('e-pkwin', 'Pk Win', 'https://endoflife.date/e-pkwin'),
  ('e-pkmany', 'Pk Many', 'https://endoflife.date/e-pkmany'), ('e-pkeight', 'Pk Eight', 'https://endoflife.date/e-pkeight');
INSERT INTO eol_cycle (eol_product, cycle_name, release_date, eol_date, is_eol, is_maintained, is_lts, latest_version) VALUES
  ('e-pk', '4.2', current_date - 1000, current_date + 100, false, true, true, '4.2.7'),
  ('e-pk', '5.0', current_date - 100, NULL, false, true, false, '5.0.1'),
  ('e-pkwin', '11-24h2-w', current_date - 300, current_date + 10, false, true, false, '26100.1'),
  ('e-pkwin', '11-24h2-e', current_date - 300, current_date - 20, false, false, true, '26100.2');
INSERT INTO eol_cycle (eol_product, cycle_name, release_date, eol_date, is_eol, is_maintained, is_lts, latest_version)
  SELECT 'e-pkmany', v.cycle_name, current_date - 10, current_date + 10, false, true, false, NULL
    FROM unnest(ARRAY['9', '9-w', '9-e', '9-lts', '9-iot', '9-w-lts', '9-e-lts', '9-iot-lts', '9-w-iot']) AS v (cycle_name);
INSERT INTO eol_cycle (eol_product, cycle_name, release_date, eol_date, is_eol, is_maintained, is_lts, latest_version)
  SELECT 'e-pkeight', v.cycle_name, current_date - 10, current_date + 10, false, true, false, NULL
    FROM unnest(ARRAY['8', '8-w', '8-e', '8-lts', '8-iot', '8-w-lts', '8-e-lts', '8-iot-lts']) AS v (cycle_name);
INSERT INTO eol_product_package (ecosystem, package_name, eol_product) VALUES
  ('npm', 'left-pad', 'e-pk'), ('npm', 'winpkg', 'e-pkwin'), ('npm', 'manyvar', 'e-pkmany'), ('npm', 'eightvar', 'e-pkeight');

DO $$
DECLARE
  answer      record;
  e_pk        jsonb := '{"source": "endoflife.date", "product": "e-pk", "url": "https://endoflife.date/e-pk"}';
  in_100_days text  := to_char(current_date + 100, 'YYYY-MM-DD');
BEGIN
  SELECT * INTO answer
    FROM api.fn_package_check_bulk(ARRAY['npm', 'npm', 'npm', 'npm', 'npm', 'npm', 'NPM', 'npm'],
                                   ARRAY['left-pad', 'left-pad', 'left-pad', 'winpkg', 'no-such', 'manyvar', 'left-pad', 'eightvar'],
                                   ARRAY['4.2.7', '5.0.1', NULL, '11-24h2', '1.0.0', '9', '4.2.7', '8'], 10) AS b;
  ASSERT answer.results -> 0 -> 'eol'
         = e_pk || jsonb_build_object('cycle', jsonb_build_object('name', '4.2', 'eol_date', in_100_days, 'is_eol', false, 'is_maintained', true,
                                                                  'is_lts', true, 'latest_version', '4.2.7'),
                                      'cycle_variants', NULL),
         'a package whose version picks one cycle holds the product, its link and the cycle, with each field of the cycle';
  ASSERT answer.results -> 1 -> 'eol'
         = e_pk || '{"cycle": {"name": "5.0", "eol_date": null, "is_eol": false, "is_maintained": true, "is_lts": false, "latest_version": "5.0.1"},
                     "cycle_variants": null}',
         'the same package at another version holds its own cycle, and a cycle with no date has eol_date null';
  ASSERT answer.results -> 2 -> 'eol' = e_pk || '{"cycle": null, "cycle_variants": null}',
         'a package with no version holds the product with cycle and cycle_variants null';
  ASSERT answer.results -> 3 -> 'eol'
         = '{"source": "endoflife.date", "product": "e-pkwin", "url": "https://endoflife.date/e-pkwin", "cycle": null}'::jsonb
           || jsonb_build_object('cycle_variants',
                                 jsonb_build_array(jsonb_build_object('name', '11-24h2-e', 'eol_date', to_char(current_date - 20, 'YYYY-MM-DD'), 'is_eol', true, 'is_maintained', false),
                                                   jsonb_build_object('name', '11-24h2-w', 'eol_date', to_char(current_date + 10, 'YYYY-MM-DD'), 'is_eol', false, 'is_maintained', true))),
         'a series of two cycles is cycle_variants by date, each with its name, date and two flags, and cycle is null';
  ASSERT answer.results -> 4 ? 'eol' AND answer.results -> 4 -> 'eol' = 'null'::jsonb, 'a package that maps to no product has eol null';
  ASSERT (SELECT array_agg(row(r.item_json ->> 'name', r.item_json ->> 'version')::text ORDER BY r.item_index)
            FROM jsonb_array_elements(answer.results) WITH ORDINALITY AS r (item_json, item_index))
         = ARRAY[row('left-pad', '4.2.7')::text, row('left-pad', '5.0.1')::text, row('left-pad', NULL)::text, row('winpkg', '11-24h2')::text,
                 row('no-such', '1.0.0')::text, row('left-pad', '4.2.7')::text, row('eightvar', '8')::text],
         'results leaves out manyvar, whose series holds nine cycles, and keeps the other packages in request order';
  ASSERT answer.failed_item_count = 1, 'failed_item_count counts the package whose series holds nine cycles';
  ASSERT (SELECT array_agg(v.variant_json ->> 'name' ORDER BY v.variant_ordinal)
            FROM jsonb_array_elements(answer.results -> 6 -> 'eol' -> 'cycle_variants') WITH ORDINALITY AS v (variant_json, variant_ordinal))
         = ARRAY['8', '8-e', '8-e-lts', '8-iot', '8-iot-lts', '8-lts', '8-w', '8-w-lts'],
         'a series of eight cycles of one date lists all eight by name';
  ASSERT answer.results -> 5 -> 'eol' = answer.results -> 0 -> 'eol', 'the ecosystem matches in any letter case';
  ASSERT (SELECT array_agg(k.key ORDER BY k.key) FROM jsonb_object_keys(answer.results -> 0 -> 'eol') AS k (key))
         = ARRAY['cycle', 'cycle_variants', 'product', 'source', 'url'],
         'eol is compact: the keys of the eol of /package_check without maintained_cycles and maintained_cycles_truncated';
  ASSERT (SELECT array_agg(k.key ORDER BY k.key) FROM jsonb_object_keys(answer.results -> 3 -> 'eol' -> 'cycle_variants' -> 0) AS k (key))
         = ARRAY['eol_date', 'is_eol', 'is_maintained', 'name'],
         'a variant has the four keys static_PRODUCTEXPOSUREWriteEol writes for it';
  ASSERT (SELECT count(*) FROM jsonb_array_elements(answer.attribution) AS a (attribution_json)
           WHERE a.attribution_json = '{"source": "endoflife.date", "license": "MIT", "url": "https://endoflife.date"}') = 1,
         'attribution lists endoflife.date once, with MIT and its link';
  ASSERT (SELECT b.attribution FROM api.fn_package_check_bulk(ARRAY['npm'], ARRAY['no-such'], ARRAY['1.0.0'], 10) AS b) = '[]',
         'a list in which no package maps to a product lists no endoflife.date';
  ASSERT (SELECT b.attribution FROM api.fn_package_check_bulk(ARRAY['npm', 'npm'], ARRAY['no-such', 'winpkg'], ARRAY['1.0.0', NULL], 10) AS b)
         = '[{"source": "endoflife.date", "license": "MIT", "url": "https://endoflife.date"}]',
         'one mapped package in the list lists endoflife.date';
  SELECT * INTO answer FROM api.fn_package_check_bulk(ARRAY['npm'], ARRAY['manyvar'], ARRAY['9'], 10) AS b;
  ASSERT answer.results = '[]' AND answer.failed_item_count = 1 AND answer.attribution = '[]',
         'a list of only a failed package answers no result, one failed package and no endoflife.date';
  ASSERT (SELECT b.attribution FROM api.fn_package_check_bulk(ARRAY['npm', 'npm'], ARRAY['manyvar', 'winpkg'], ARRAY['9', NULL], 10) AS b)
         = '[{"source": "endoflife.date", "license": "MIT", "url": "https://endoflife.date"}]',
         'a package that is not failed still lists endoflife.date beside a failed one';
  ASSERT (SELECT row(b.failed_item_count, jsonb_array_length(b.results))::text
            FROM api.fn_package_check_bulk(ARRAY['npm', 'npm'], ARRAY['manyvar', 'manyvar'], ARRAY['9', '9'], 10) AS b) = row(2, 0)::text,
         'two items of one failed package are both failed';
END
$$;

CREATE FUNCTION pg_temp.t_bulk_oracle(p_ecosystems text[], p_package_names text[], p_package_versions text[])
  RETURNS TABLE (results jsonb, attribution jsonb)
  LANGUAGE sql STABLE
  AS $$
    WITH item AS (
      SELECT i.item_index, i.ecosystem, i.package_name, i.package_version,
             pcv.has_advisory_data, pcv.result_count, pcv.fixed_version, pcv.malicious, pcv.results, pcv.attribution
        FROM unnest(p_ecosystems, p_package_names, p_package_versions) WITH ORDINALITY AS i (ecosystem, package_name, package_version, item_index)
        LEFT JOIN LATERAL api.fn_package_check_versions(i.ecosystem, i.package_name, ARRAY[i.package_version], 10, 0) AS pcv ON true)
    SELECT (SELECT jsonb_agg(jsonb_build_object(
                               'ecosystem',         it.ecosystem,
                               'name',              it.package_name,
                               'version',           it.package_version,
                               'has_advisory_data', it.has_advisory_data,
                               'fixed_version',     it.fixed_version,
                               'malicious',         CASE WHEN it.malicious IS NOT NULL
                                                         THEN jsonb_build_object('id', it.malicious -> 'id', 'affects_version', it.malicious -> 'affects_version')
                                                    END,
                               'advisory_total',    it.result_count,
                               'advisories',        (SELECT coalesce(jsonb_agg(jsonb_build_object('id',              s.result_json -> 'id',
                                                                                                  'aliases',         s.result_json -> 'aliases',
                                                                                                  'affects_version', s.result_json -> 'affects_version')
                                                                               ORDER BY s.result_ordinal), '[]'::jsonb)
                                                       FROM jsonb_array_elements(it.results) WITH ORDINALITY AS s (result_json, result_ordinal)))
                             ORDER BY it.item_index)
              FROM item AS it),
           (SELECT coalesce(jsonb_agg(jsonb_build_object('source', c.source, 'license', c.license, 'url', c.source_url)
                                      ORDER BY c.source COLLATE "C", c.license COLLATE "C"), '[]'::jsonb)
              FROM (SELECT DISTINCT a.attribution_json ->> 'source'  AS source,
                                    a.attribution_json ->> 'license' AS license,
                                    a.attribution_json ->> 'url'     AS source_url
                      FROM item AS it
                     CROSS JOIN LATERAL jsonb_array_elements(it.attribution) AS a (attribution_json)) AS c)
  $$;

CREATE FUNCTION pg_temp.t_bulk_without_eol(p_ecosystems text[], p_package_names text[], p_package_versions text[])
  RETURNS TABLE (results jsonb, attribution jsonb)
  LANGUAGE sql STABLE
  AS $$
    SELECT (SELECT jsonb_agg(r.item_json - 'eol' ORDER BY r.item_index)
              FROM jsonb_array_elements(b.results) WITH ORDINALITY AS r (item_json, item_index)),
           b.attribution
      FROM api.fn_package_check_bulk(p_ecosystems, p_package_names, p_package_versions, 10) AS b
  $$;

DO $$
DECLARE
  lists        record;
  answer       record;
  eol_credit   jsonb := '{"source": "endoflife.date", "license": "MIT", "url": "https://endoflife.date"}';
  no_row_item  jsonb := '{"has_advisory_data": false, "fixed_version": null, "malicious": null, "advisory_total": 0, "advisories": []}';
BEGIN
  FOR lists IN
    SELECT *
      FROM (VALUES
        ('a no-row package with a version and one with none',
         ARRAY['npm', 'npm'], ARRAY['no-such', 'no-such-two'], ARRAY['1.0.0', NULL]),
        ('a no-row package that maps to an eol product',
         ARRAY['npm', 'npm'], ARRAY['winpkg', 'winpkg'], ARRAY['11-24h2', NULL]),
        ('a no-row package that maps to an eol product through its normalized name',
         ARRAY['npm'], ARRAY['WinPkg'], ARRAY['11-24h2']),
        ('a no-row package that maps to an eol product through its canonical ecosystem',
         ARRAY['NPM'], ARRAY['winpkg'], ARRAY['11-24h2']),
        ('an unknown ecosystem',
         ARRAY['Pub', 'npm'], ARRAY['x', 'no-such'], ARRAY['1.0', '1.0.0']),
        ('row and no-row packages mixed, a no-row package first, in the middle and last',
         ARRAY['npm', 'npm', 'npm', 'PyPI', 'npm', 'npm', 'npm'],
         ARRAY['no-such', 'wa', 'winpkg', 'WA', 'no-such-two', 'Left-Pad', 'no-such'],
         ARRAY['1.0.0', '1.0.0', NULL, '2.0', '3.0.0', '1.0.0', '2.0.0']),
        ('a no-row package named twice with two versions',
         ARRAY['npm', 'npm', 'npm'], ARRAY['no-such', 'wb', 'no-such'], ARRAY['1.0.0', '1.0.0', '2.0.0']),
        ('a NULL name',
         ARRAY['npm', 'npm'], ARRAY[NULL, 'no-such'], ARRAY['1.0.0', '1.0.0']))
           AS listed (label, ecosystems, package_names, package_versions)
  LOOP
    ASSERT (SELECT row(b.results, b.attribution)::text
              FROM pg_temp.t_bulk_without_eol(lists.ecosystems, lists.package_names, lists.package_versions) AS b)
           = (SELECT row(o.results, o.attribution)::text
                FROM pg_temp.t_bulk_oracle(lists.ecosystems, lists.package_names, lists.package_versions) AS o),
           format('%s: each item and the attribution equal the answer of api.fn_package_check_versions', lists.label);
  END LOOP;

  SELECT * INTO answer
    FROM api.fn_package_check_bulk(ARRAY['npm', 'npm', 'npm', 'PyPI', 'npm', 'npm', 'npm'],
                                   ARRAY['no-such', 'wa', 'winpkg', 'WA', 'no-such-two', 'Left-Pad', 'no-such'],
                                   ARRAY['1.0.0', '1.0.0', NULL, '2.0', '3.0.0', '1.0.0', '2.0.0'], 10) AS b;
  ASSERT (SELECT array_agg(row(r.item_json ->> 'name', r.item_json ->> 'version', r.item_json -> 'has_advisory_data')::text ORDER BY r.item_index)
            FROM jsonb_array_elements(answer.results) WITH ORDINALITY AS r (item_json, item_index))
         = ARRAY[row('no-such', '1.0.0', 'false'::jsonb)::text, row('wa', '1.0.0', 'true'::jsonb)::text,
                 row('winpkg', NULL, 'false'::jsonb)::text, row('WA', '2.0', 'true'::jsonb)::text,
                 row('no-such-two', '3.0.0', 'false'::jsonb)::text, row('Left-Pad', '1.0.0', 'true'::jsonb)::text,
                 row('no-such', '2.0.0', 'false'::jsonb)::text],
         'the mixed list keeps request order, and only the packages with rows have advisory data';
  ASSERT (answer.results -> 0) - ARRAY['ecosystem', 'name', 'version', 'eol'] = no_row_item
     AND (answer.results -> 4) - ARRAY['ecosystem', 'name', 'version', 'eol'] = no_row_item
     AND (answer.results -> 6) - ARRAY['ecosystem', 'name', 'version', 'eol'] = no_row_item,
         'a no-row package has no advisory data, a total of 0, no fixed version, no malicious and no advisory';
  ASSERT (answer.results -> 1 ->> 'advisory_total')::integer = 3 AND (answer.results -> 3 ->> 'advisory_total')::integer = 7,
         'a package with rows is still checked, PyPI WA through its normalized name';
  ASSERT answer.results -> 2 -> 'eol' ->> 'product' = 'e-pkwin',
         'a no-row package that maps to an eol product keeps its eol';
  ASSERT (SELECT count(*) FROM jsonb_array_elements(answer.attribution) AS a (attribution_json) WHERE a.attribution_json = eol_credit) = 1,
         'a no-row package that maps to an eol product credits endoflife.date';
  ASSERT (SELECT b.attribution FROM api.fn_package_check_bulk(ARRAY['npm', 'npm'], ARRAY['winpkg', 'no-such'], ARRAY['11-24h2', NULL], 10) AS b)
         = jsonb_build_array(eol_credit),
         'a list of no-row packages credits only endoflife.date when one maps to an eol product';
  ASSERT (SELECT b.attribution FROM api.fn_package_check_bulk(ARRAY['npm', 'npm'], ARRAY['no-such', 'no-such-two'], ARRAY['1.0.0', NULL], 10) AS b)
         = '[]',
         'a list of no-row packages that map to no eol product credits no source';
  ASSERT (SELECT b.results -> 0 FROM api.fn_package_check_bulk(ARRAY['Pub'], ARRAY['x'], ARRAY['1.0'], 10) AS b)
         = '{"ecosystem": "Pub", "name": "x", "version": "1.0", "has_advisory_data": null, "fixed_version": null, "malicious": null,
             "advisory_total": null, "advisories": [], "eol": null}'::jsonb,
         'a package of an unknown ecosystem keeps its null values';
END
$$;

DO $$
DECLARE
  osv_notice text := 'Retrieved through OSV.dev. ContrastAPI selected and normalized the fields and computed affects_version and fixed_version. No warranty; the source does not endorse ContrastAPI.';
  eol_notice text := 'Retrieved from endoflife.date. ContrastAPI selected the fields and matched the release cycles to the package. No warranty; the source does not endorse ContrastAPI.';
BEGIN
  ASSERT (SELECT array_agg(api.fn_package_check_attribution_entry(s.source, s.license) ORDER BY s.ordinality)
            FROM unnest(ARRAY['ghsa', 'go', 'pysec', 'rustsec', 'mal', 'endoflife.date', 'other'],
                        ARRAY['CC-BY-4.0', 'CC-BY-4.0', 'CC-BY-4.0', 'CC0-1.0', 'Apache-2.0', 'MIT', 'X-1'])
                 WITH ORDINALITY AS s (source, license, ordinality))
         = ARRAY[jsonb_build_object('source', 'ghsa', 'license', 'CC-BY-4.0', 'url', 'https://github.com/github/advisory-database', 'notice', osv_notice),
                 jsonb_build_object('source', 'go', 'license', 'CC-BY-4.0', 'url', 'https://github.com/golang/vulndb', 'notice', osv_notice),
                 jsonb_build_object('source', 'pysec', 'license', 'CC-BY-4.0', 'url', 'https://github.com/pypa/advisory-database', 'notice', osv_notice),
                 jsonb_build_object('source', 'rustsec', 'license', 'CC0-1.0', 'url', 'https://github.com/rustsec/advisory-db', 'notice', osv_notice),
                 jsonb_build_object('source', 'mal', 'license', 'Apache-2.0', 'url', 'https://github.com/ossf/malicious-packages', 'notice', osv_notice),
                 jsonb_build_object('source', 'endoflife.date', 'license', 'MIT', 'url', 'https://endoflife.date', 'notice', eol_notice),
                 jsonb_build_object('source', 'other', 'license', 'X-1', 'url', NULL, 'notice', osv_notice)],
         'each source has its own link and notice, and an unknown source has a NULL link';
  ASSERT (SELECT p.provolatile = 'i' AND NOT p.prosecdef AND p.proconfig = ARRAY['search_path=pg_catalog']
            FROM pg_proc AS p WHERE p.oid = 'api.fn_package_check_attribution_entry(text, text)'::regprocedure),
         'api.fn_package_check_attribution_entry is IMMUTABLE and SECURITY INVOKER, and sets search_path to pg_catalog';
END
$$;

DELETE FROM eol_product WHERE product_name IN ('e-pk', 'e-pkwin', 'e-pkmany', 'e-pkeight');

DELETE FROM osv_advisories;
