SAVEPOINT t_cve_ghsa_advisory_rows;

DO $$
BEGIN
  ASSERT (SELECT row(g.ghsa_feed_loaded, g.advisory)::text FROM api.fn_cve_ghsa_advisory('CVE-2030-0001', 32) AS g)
         = row(false, NULL)::text,
         'an empty catalog answers one row with ghsa_feed_loaded false';
END
$$;

INSERT INTO osv_advisories (advisory_id, source, license, summary, aliases, published_time, modified_time) VALUES
  ('MAL-1', 'mal', 'Apache-2.0', '', ARRAY['CVE-2030-0001'], '2020-01-01T00:00:00Z', '2020-01-01T00:00:00Z');
INSERT INTO osv_affected (advisory_id, affected_index, ecosystem, package_name, version_ranges, listed_versions, listed_versions_sortable, is_unaffected_provable)
SELECT af.advisory_id, af.affected_index, af.ecosystem, af.package_name, af.version_ranges::jsonb, af.listed_versions,
       ARRAY(SELECT array_to_string(public.fn_osv_version_sortable(af.ecosystem, kv.version_text), ' ')
               FROM unnest(af.keyed_versions) WITH ORDINALITY AS kv (version_text, version_ordinal) ORDER BY kv.version_ordinal),
       af.is_unaffected_provable
  FROM (VALUES
    ('MAL-1', 0, 'npm', 'evil', '[{"type": "SEMVER", "events": [{"introduced": "0"}]}]', '{}'::text[], '{}'::text[], false)
  ) AS af (advisory_id, affected_index, ecosystem, package_name, version_ranges, listed_versions, keyed_versions, is_unaffected_provable);
INSERT INTO osv_affected_version_intervals (advisory_id, affected_index, interval_index, introduced_version_sortable, upper_version_sortable, upper_event, fixed_version)
SELECT iv.advisory_id, iv.affected_index, iv.interval_index,
       CASE WHEN iv.introduced_version IS NOT NULL THEN public.fn_osv_version_sortable(osvaf.ecosystem, iv.introduced_version) END,
       CASE WHEN iv.upper_version IS NOT NULL THEN public.fn_osv_version_sortable(osvaf.ecosystem, iv.upper_version) END,
       iv.upper_event, iv.fixed_version
  FROM (VALUES
    ('MAL-1', 0, 0, NULL::text, NULL::text, NULL::text, NULL::text)
  ) AS iv (advisory_id, affected_index, interval_index, introduced_version, upper_version, upper_event, fixed_version)
  JOIN osv_affected AS osvaf ON osvaf.advisory_id = iv.advisory_id AND osvaf.affected_index = iv.affected_index;

DO $$
BEGIN
  ASSERT (SELECT row(g.ghsa_feed_loaded, g.advisory)::text FROM api.fn_cve_ghsa_advisory('CVE-2030-0001', 32) AS g)
         = row(false, NULL)::text,
         'a catalog with a mal advisory and no ghsa advisory answers ghsa_feed_loaded false';
END
$$;

INSERT INTO osv_advisories (advisory_id, source, license, summary, aliases, published_time, modified_time) VALUES
  ('GHSA-B1', 'ghsa', 'CC-BY-4.0', '', ARRAY['CVE-2030-0002'], '2022-01-01T00:00:00Z', '2022-01-01T00:00:00Z'),
  ('GHSA-a1', 'ghsa', 'CC-BY-4.0', '', ARRAY['CVE-2030-0001', 'PYSEC-2030-1'], '2021-02-01T00:00:00Z', '2021-02-01T00:00:00Z'),
  ('GHSA-a2', 'ghsa', 'CC-BY-4.0', '', ARRAY['CVE-2030-0001'], '2021-03-01T00:00:00Z', '2021-03-01T00:00:00Z'),
  ('GHSA-a9', 'ghsa', 'CC-BY-4.0', '', ARRAY['CVE-2030-0002'], '2022-01-01T00:00:00Z', '2022-01-01T00:00:00Z'),
  ('GHSA-p1', 'ghsa', 'CC-BY-4.0', '', ARRAY['CVE-2030-0004'], '2022-06-01T00:00:00Z', '2022-06-01T00:00:00Z'),
  ('GHSA-p2', 'ghsa', 'CC-BY-4.0', '', ARRAY['CVE-2030-0004'], '2020-06-01T00:00:00Z', '2020-06-01T00:00:00Z'),
  ('MAL-2', 'mal', 'Apache-2.0', '', ARRAY['CVE-2030-0003'], '2022-01-01T00:00:00Z', '2022-01-01T00:00:00Z');
INSERT INTO osv_affected (advisory_id, affected_index, ecosystem, package_name, version_ranges, listed_versions, listed_versions_sortable, is_unaffected_provable)
SELECT af.advisory_id, af.affected_index, af.ecosystem, af.package_name, af.version_ranges::jsonb, af.listed_versions,
       ARRAY(SELECT array_to_string(public.fn_osv_version_sortable(af.ecosystem, kv.version_text), ' ')
               FROM unnest(af.keyed_versions) WITH ORDINALITY AS kv (version_text, version_ordinal) ORDER BY kv.version_ordinal),
       af.is_unaffected_provable
  FROM (VALUES
    ('GHSA-B1', 0, 'npm', 'b1', '[]', ARRAY['1.0.0'], ARRAY['1.0.0'], false),
    ('GHSA-a1', 0, 'npm', 'alpha', '[{"type": "SEMVER", "events": [{"introduced": "1.0.0"}, {"fixed": "1.5.0"}]}]', '{}'::text[], '{}'::text[], true),
    ('GHSA-a1', 1, 'npm', 'Zeta', '[{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}]', '{}'::text[], '{}'::text[], true),
    ('GHSA-a1', 2, 'PyPI', 'beta', '[{"type": "ECOSYSTEM", "events": [{"introduced": "2.0"}, {"last_affected": "2.5"}]}]', '{}'::text[], '{}'::text[], true),
    ('GHSA-a1', 3, 'PyPI', 'beta', '[{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"last_affected": "3.0"}]}]', '{}'::text[], '{}'::text[], true),
    ('GHSA-a1', 4, 'crates.io', 'c', '[]', '{}'::text[], '{}'::text[], false),
    ('GHSA-a1', 5, 'Maven', 'g:d', '[]', ARRAY['1.0', '1.1'], ARRAY['1.0', '1.1'], false),
    ('GHSA-a1', 6, 'Maven', 'g:c', '[]', ARRAY['6.3.2.1'], ARRAY['6.3.2.1'], false),
    ('GHSA-a1', 7, 'Maven', 'g:b', '[{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]', ARRAY['0.1'], ARRAY['0.1'], false),
    ('GHSA-a1', 8, 'Maven', 'g:a', '[{"type": "ECOSYSTEM", "events": [{"introduced": "4.0"}]}]', '{}'::text[], '{}'::text[], false),
    ('GHSA-a1', 9, 'Go', 'y', '[{"type": "SEMVER", "events": [{"introduced": "1.0"}, {"limit": "5.0"}]}]', '{}'::text[], '{}'::text[], false),
    ('GHSA-a1', 10, 'Go', 'x', '[{"type": "SEMVER", "events": [{"introduced": "1.0"}, {"fixed": "1.2"}]}, {"type": "SEMVER", "events": [{"introduced": "2.0"}, {"fixed": "2.3"}]}]', '{}'::text[], '{}'::text[], false),
    ('GHSA-a2', 0, 'npm', 'late', '[{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "9.0.0"}]}]', '{}'::text[], '{}'::text[], true),
    ('GHSA-a9', 0, 'npm', 'a9', '[]', ARRAY['1.0.0'], ARRAY['1.0.0'], false),
    ('GHSA-p1', 0, 'npm', 'p1', '[]', ARRAY['1.0.0'], ARRAY['1.0.0'], false),
    ('GHSA-p2', 0, 'npm', 'p2', '[]', ARRAY['1.0.0'], ARRAY['1.0.0'], false),
    ('MAL-2', 0, 'npm', 'evil-two', '[]', '{}'::text[], '{}'::text[], false)
  ) AS af (advisory_id, affected_index, ecosystem, package_name, version_ranges, listed_versions, keyed_versions, is_unaffected_provable);
INSERT INTO osv_affected_version_intervals (advisory_id, affected_index, interval_index, introduced_version_sortable, upper_version_sortable, upper_event, fixed_version)
SELECT iv.advisory_id, iv.affected_index, iv.interval_index,
       CASE WHEN iv.introduced_version IS NOT NULL THEN public.fn_osv_version_sortable(osvaf.ecosystem, iv.introduced_version) END,
       CASE WHEN iv.upper_version IS NOT NULL THEN public.fn_osv_version_sortable(osvaf.ecosystem, iv.upper_version) END,
       iv.upper_event, iv.fixed_version
  FROM (VALUES
    ('GHSA-a1', 0, 0, '1.0.0'::text, '1.5.0'::text, 'fixed'::text, '1.5.0'::text),
    ('GHSA-a1', 1, 0, NULL, '2.0.0', 'fixed', '2.0.0'),
    ('GHSA-a1', 2, 0, '2.0', '2.5', 'last_affected', NULL),
    ('GHSA-a1', 3, 0, NULL, '3.0', 'last_affected', NULL),
    ('GHSA-a1', 7, 0, NULL, NULL, NULL, NULL),
    ('GHSA-a1', 8, 0, '4.0', NULL, NULL, NULL),
    ('GHSA-a2', 0, 0, NULL, '9.0.0', 'fixed', '9.0.0')
  ) AS iv (advisory_id, affected_index, interval_index, introduced_version, upper_version, upper_event, fixed_version)
  JOIN osv_affected AS osvaf ON osvaf.advisory_id = iv.advisory_id AND osvaf.affected_index = iv.affected_index;

CREATE TEMP VIEW t_cve_ghsa_advisory_call AS SELECT * FROM api.fn_cve_ghsa_advisory('CVE-2030-0001', 32);

DO $$
BEGIN
  ASSERT (SELECT array_agg(attname::text ORDER BY attnum) FROM pg_attribute
          WHERE attrelid = 't_cve_ghsa_advisory_call'::regclass AND attnum > 0)
         = ARRAY['ghsa_feed_loaded', 'advisory'],
         'api.fn_cve_ghsa_advisory answers the 2 columns db_CVELOOKUPGHSA reads, in its order';
  ASSERT (SELECT array_agg(format_type(atttypid, atttypmod) ORDER BY attnum) FROM pg_attribute
          WHERE attrelid = 't_cve_ghsa_advisory_call'::regclass AND attnum > 0)
         = ARRAY['boolean', 'jsonb'],
         'the flag is boolean and the advisory is jsonb';
  ASSERT (SELECT count(*) FROM t_cve_ghsa_advisory_call) = 1,
         'a CVE that a ghsa advisory names answers one row';
  ASSERT (SELECT row(g.ghsa_feed_loaded, g.advisory)::text FROM api.fn_cve_ghsa_advisory('CVE-2030-0009', 32) AS g)
         = row(true, NULL)::text,
         'a CVE that no advisory names answers one row with a NULL advisory';
  ASSERT (SELECT count(*) FROM api.fn_cve_ghsa_advisory(NULL, 32)) = 0,
         'a NULL id answers no row';
  ASSERT (SELECT count(*) FROM api.fn_cve_ghsa_advisory('CVE-2030-0001', NULL)) = 0,
         'a NULL row count answers no row';
END
$$;

DO $$
BEGIN
  ASSERT (SELECT g.advisory ->> 'ghsa_id' FROM t_cve_ghsa_advisory_call AS g) = 'GHSA-a1',
         'of two ghsa advisories, the one published first is the answer, and a mal advisory published before both is not';
  ASSERT (SELECT g.advisory ->> 'ghsa_id' FROM api.fn_cve_ghsa_advisory('CVE-2030-0002', 32) AS g) = 'GHSA-B1',
         'of two advisories with the same published_time, the id whose bytes sort first is the answer';
  ASSERT (SELECT row(g.ghsa_feed_loaded, g.advisory)::text FROM api.fn_cve_ghsa_advisory('CVE-2030-0003', 32) AS g)
         = row(true, NULL)::text,
         'a CVE that only a mal advisory names has no ghsa advisory';
  ASSERT (SELECT g.advisory ->> 'ghsa_id' FROM api.fn_cve_ghsa_advisory('CVE-2030-0004', 32) AS g) = 'GHSA-p2',
         'the advisory published first is the answer, though its id sorts last';
  ASSERT (SELECT g.advisory ->> 'ghsa_id' FROM api.fn_cve_ghsa_advisory('PYSEC-2030-1', 32) AS g) = 'GHSA-a1',
         'an alias of another kind than a CVE id finds its advisory too';
END
$$;

DO $$
BEGIN
  ASSERT (SELECT g.advisory FROM t_cve_ghsa_advisory_call AS g)
         = '{"ghsa_id": "GHSA-a1",
             "affected": [{"ecosystem": "Go", "package": "x", "vulnerable_version_range": ">= 1.0, < 1.2, >= 2.0, < 2.3", "patched_versions": "1.2"},
                          {"ecosystem": "Go", "package": "y", "vulnerable_version_range": ">= 1.0", "patched_versions": ""},
                          {"ecosystem": "Maven", "package": "g:a", "vulnerable_version_range": ">= 4.0", "patched_versions": ""},
                          {"ecosystem": "Maven", "package": "g:b", "vulnerable_version_range": ">= 0", "patched_versions": ""},
                          {"ecosystem": "Maven", "package": "g:c", "vulnerable_version_range": "= 6.3.2.1", "patched_versions": ""},
                          {"ecosystem": "Maven", "package": "g:d", "vulnerable_version_range": "= 1.0, = 1.1", "patched_versions": ""},
                          {"ecosystem": "PyPI", "package": "beta", "vulnerable_version_range": "<= 3.0", "patched_versions": ""},
                          {"ecosystem": "PyPI", "package": "beta", "vulnerable_version_range": ">= 2.0, <= 2.5", "patched_versions": ""},
                          {"ecosystem": "crates.io", "package": "c", "vulnerable_version_range": "", "patched_versions": ""},
                          {"ecosystem": "npm", "package": "Zeta", "vulnerable_version_range": "< 2.0.0", "patched_versions": "2.0.0"},
                          {"ecosystem": "npm", "package": "alpha", "vulnerable_version_range": ">= 1.0.0, < 1.5.0", "patched_versions": "1.5.0"}],
             "affected_total": 11,
             "attribution": {"source": "ghsa", "license": "CC-BY-4.0", "url": "https://github.com/github/advisory-database"}}'::jsonb,
         'each rule gives its range text, and the packages sort by the bytes of ecosystem, package and range';
  ASSERT (SELECT row(g.advisory -> 'affected', g.advisory -> 'affected_total')::text FROM api.fn_cve_ghsa_advisory('CVE-2030-0001', 3) AS g)
         = row('[{"ecosystem": "Go", "package": "x", "vulnerable_version_range": ">= 1.0, < 1.2, >= 2.0, < 2.3", "patched_versions": "1.2"},
                 {"ecosystem": "Go", "package": "y", "vulnerable_version_range": ">= 1.0", "patched_versions": ""},
                 {"ecosystem": "Maven", "package": "g:a", "vulnerable_version_range": ">= 4.0", "patched_versions": ""}]'::jsonb,
               '11'::jsonb)::text,
         'a row count of 3 lists the first 3 packages in the sorted order, and affected_total still counts all 11';
  ASSERT (SELECT row(jsonb_array_length(g.advisory -> 'affected'), g.advisory -> 'affected' -> 9 ->> 'package', g.advisory -> 'affected_total')::text
            FROM api.fn_cve_ghsa_advisory('CVE-2030-0001', 10) AS g)
         = row(10, 'Zeta', '11'::jsonb)::text,
         'a row count one below the package count leaves out the last package in the byte order, alpha';
  ASSERT (SELECT g.advisory -> 'affected' -> 6 ->> 'vulnerable_version_range' FROM api.fn_cve_ghsa_advisory('CVE-2030-0001', 7) AS g)
         = '<= 3.0',
         'a cut between the two ranges of PyPI beta keeps the range whose bytes sort first';
  ASSERT (SELECT row(jsonb_array_length(g.advisory -> 'affected'), g.advisory -> 'affected_total')::text FROM api.fn_cve_ghsa_advisory('CVE-2030-0001', 11) AS g)
         = row(11, '11'::jsonb)::text,
         'a row count equal to the package count lists every package';
END
$$;

INSERT INTO osv_advisories (advisory_id, source, license, summary, aliases, published_time, modified_time) VALUES
  ('GHSA-z1', 'ghsa', 'CC-BY-4.0', '', ARRAY['CVE-2030-0005'], '2023-01-01T00:00:00Z', '2023-01-01T00:00:00Z'),
  ('GHSA-z2', 'ghsa', 'CC-BY-4.0', '', ARRAY['CVE-2030-0006'], '2023-01-01T00:00:00Z', '2023-01-01T00:00:00Z');
INSERT INTO osv_affected (advisory_id, affected_index, ecosystem, package_name, version_ranges, listed_versions, listed_versions_sortable, is_unaffected_provable)
SELECT af.advisory_id, af.affected_index, af.ecosystem, af.package_name, af.version_ranges::jsonb, af.listed_versions,
       ARRAY(SELECT array_to_string(public.fn_osv_version_sortable(af.ecosystem, kv.version_text), ' ')
               FROM unnest(af.keyed_versions) WITH ORDINALITY AS kv (version_text, version_ordinal) ORDER BY kv.version_ordinal),
       af.is_unaffected_provable
  FROM (VALUES
    ('GHSA-z1', 0, 'Go', 'z', '[{"type": "SEMVER", "events": [{"introduced": "0"}, {"limit": "5.0"}]}]', '{}'::text[], '{}'::text[], false)
  ) AS af (advisory_id, affected_index, ecosystem, package_name, version_ranges, listed_versions, keyed_versions, is_unaffected_provable);

DO $$
BEGIN
  ASSERT (SELECT g.advisory -> 'affected' -> 0 ->> 'vulnerable_version_range' FROM api.fn_cve_ghsa_advisory('CVE-2030-0005', 32) AS g)
         = '>= 0',
         'an introduced 0 with a limit event and no listed version gives ">= 0"';
  ASSERT (SELECT row(g.advisory -> 'affected', g.advisory -> 'affected_total')::text FROM api.fn_cve_ghsa_advisory('CVE-2030-0006', 32) AS g)
         = row('[]'::jsonb, '0'::jsonb)::text,
         'an advisory with no package answers affected [] and affected_total 0';
END
$$;

PREPARE t_cve_ghsa_advisory_query AS SELECT * FROM api.fn_cve_ghsa_advisory($1, $2);
CREATE TEMP TABLE t_cve_ghsa_advisory_answer AS EXECUTE t_cve_ghsa_advisory_query('CVE-2030-0001', '32');
DEALLOCATE t_cve_ghsa_advisory_query;

DO $$
BEGIN
  ASSERT (SELECT row(a.ghsa_feed_loaded, a.advisory ->> 'ghsa_id', jsonb_array_length(a.advisory -> 'affected'))::text FROM t_cve_ghsa_advisory_answer AS a)
         = row(true, 'GHSA-a1', 11)::text,
         'the query db_CVELOOKUPGHSA sends answers the advisory of its CVE';
  ASSERT (SELECT p.prosecdef AND p.proisstrict AND p.provolatile = 's' AND p.proconfig = ARRAY['search_path=pg_catalog']
            FROM pg_proc AS p WHERE p.oid = 'api.fn_cve_ghsa_advisory(text, integer)'::regprocedure),
         'api.fn_cve_ghsa_advisory is SECURITY DEFINER, STRICT, STABLE and sets search_path to pg_catalog';
END
$$;
ROLLBACK TO SAVEPOINT t_cve_ghsa_advisory_rows;
