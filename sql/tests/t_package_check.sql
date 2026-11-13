DELETE FROM osv_advisories;

DO $$
BEGIN
  ASSERT (SELECT row(c.advisory_feed_loaded, c.has_advisory_data, c.result_count, c.fixed_version, c.malicious, c.results, c.attribution)::text
            FROM api.fn_package_check('npm', 'left-pad', '1.0.0', 20, 0) AS c)
         = row(false, false, 0, NULL, NULL, '[]', '[]')::text,
         'an empty catalog answers one row with advisory_feed_loaded false';
END
$$;

INSERT INTO osv_advisories (advisory_id, source, license, summary, aliases, published_time, modified_time) VALUES
  ('GHSA-at', 'ghsa', 'CC-BY-4.0', '', '{}'::text[], '2021-01-01T00:00:00Z', '2021-01-01T00:00:00Z'),
  ('GHSA-ch1', 'ghsa', 'CC-BY-4.0', '', '{}'::text[], '2021-01-01T00:00:00Z', '2021-01-01T00:00:00Z'),
  ('GHSA-eco', 'ghsa', 'CC-BY-4.0', '', '{}'::text[], '2021-01-01T00:00:00Z', '2021-01-01T00:00:00Z'),
  ('GHSA-f1', 'ghsa', 'CC-BY-4.0', '', '{}'::text[], '2021-01-01T00:00:00Z', '2021-01-01T00:00:00Z'),
  ('GHSA-f2', 'ghsa', 'CC-BY-4.0', '', '{}'::text[], '2021-01-02T00:00:00Z', '2021-01-01T00:00:00Z'),
  ('GHSA-f3', 'ghsa', 'CC-BY-4.0', '', '{}'::text[], '2021-01-03T00:00:00Z', '2021-01-01T00:00:00Z'),
  ('GHSA-fm', 'ghsa', 'CC-BY-4.0', '', '{}'::text[], '2021-01-01T00:00:00Z', '2021-01-01T00:00:00Z'),
  ('GHSA-g1', 'ghsa', 'CC-BY-4.0', 'G1', ARRAY['CVE-2021-1', 'PYSEC-2021-7'], '2021-01-01T00:00:00Z', '2021-01-01T00:00:00Z'),
  ('GHSA-g4', 'ghsa', 'CC-BY-4.0', 'G4', '{}'::text[], '2023-01-01T00:00:00Z', '2023-01-01T00:00:00Z'),
  ('GHSA-g5', 'ghsa', 'CC-BY-4.0', 'G5', ARRAY['SNYK-JS-1'], '2023-01-01T00:00:00Z', '2023-01-01T00:00:00Z'),
  ('GHSA-g7', 'ghsa', 'CC-BY-4.0', 'G7', ARRAY['CVE-2021-1'], '2021-01-05T00:00:00Z', '2021-01-05T00:00:00Z'),
  ('GHSA-hi', 'ghsa', 'CC-BY-4.0', '', '{}'::text[], '2021-01-01T00:00:00Z', '2021-01-01T00:00:00Z'),
  ('GHSA-ma', 'ghsa', 'CC-BY-4.0', '', '{}'::text[], '2021-01-01T00:00:00Z', '2021-01-01T00:00:00Z'),
  ('GHSA-mv1', 'ghsa', 'CC-BY-4.0', '', '{}'::text[], '2022-01-01T00:00:00Z', '2022-01-01T00:00:00Z'),
  ('GHSA-mv2', 'ghsa', 'CC-BY-4.0', '', '{}'::text[], '2022-01-01T00:00:00Z', '2022-01-01T00:00:00Z'),
  ('GHSA-mv3', 'ghsa', 'CC-BY-4.0', '', '{}'::text[], '2022-01-01T00:00:00Z', '2022-01-01T00:00:00Z'),
  ('GHSA-mv4', 'ghsa', 'CC-BY-4.0', '', '{}'::text[], '2022-01-01T00:00:00Z', '2022-01-01T00:00:00Z'),
  ('GHSA-mv5', 'ghsa', 'CC-BY-4.0', '', '{}'::text[], '2022-01-01T00:00:00Z', '2022-01-01T00:00:00Z'),
  ('GHSA-mv6', 'ghsa', 'CC-BY-4.0', '', '{}'::text[], '2022-01-01T00:00:00Z', '2022-01-01T00:00:00Z'),
  ('GHSA-mx', 'ghsa', 'CC-BY-4.0', '', '{}'::text[], '2021-01-01T00:00:00Z', '2021-01-01T00:00:00Z'),
  ('GHSA-nr', 'ghsa', 'CC-BY-4.0', '', '{}'::text[], '2021-01-01T00:00:00Z', '2021-01-01T00:00:00Z'),
  ('GHSA-ns', 'ghsa', 'CC-BY-4.0', '', '{}'::text[], '2021-01-01T00:00:00Z', '2021-01-01T00:00:00Z'),
  ('GHSA-op', 'ghsa', 'CC-BY-4.0', '', '{}'::text[], '2021-01-01T00:00:00Z', '2021-01-01T00:00:00Z'),
  ('GHSA-or', 'ghsa', 'CC-BY-4.0', '', '{}'::text[], '2021-01-01T00:00:00Z', '2021-01-01T00:00:00Z'),
  ('GHSA-pk1', 'ghsa', 'CC-BY-4.0', '', '{}'::text[], '2022-01-01T00:00:00Z', '2022-01-01T00:00:00Z'),
  ('GHSA-rg1', 'ghsa', 'CC-BY-4.0', '', '{}'::text[], '2022-01-01T00:00:00Z', '2022-01-01T00:00:00Z'),
  ('GHSA-rp', 'ghsa', 'CC-BY-4.0', '', ARRAY['CVE-2021-1'], '2021-01-01T00:00:00Z', '2021-01-01T00:00:00Z'),
  ('GHSA-se1', 'ghsa', 'CC-BY-4.0', '', '{}'::text[], '2021-01-01T00:00:00Z', '2021-01-01T00:00:00Z'),
  ('GHSA-se2', 'ghsa', 'CC-BY-4.0', '', '{}'::text[], '2021-01-01T00:00:00Z', '2021-01-01T00:00:00Z'),
  ('GHSA-sk1', 'ghsa', 'CC-BY-4.0', '', '{}'::text[], '2021-01-01T00:00:00Z', '2021-01-01T00:00:00Z'),
  ('GHSA-sk3', 'ghsa', 'CC-BY-4.0', '', '{}'::text[], '2021-01-02T00:00:00Z', '2021-01-02T00:00:00Z'),
  ('GHSA-tf', 'ghsa', 'CC-BY-4.0', '', '{}'::text[], '2021-01-01T00:00:00Z', '2021-01-01T00:00:00Z'),
  ('GHSA-tw', 'ghsa', 'CC-BY-4.0', '', '{}'::text[], '2021-01-01T00:00:00Z', '2021-01-01T00:00:00Z'),
  ('GO-2021-1', 'go', 'CC-BY-4.0', 'Go one', ARRAY['GHSA-g1'], '2021-02-01T00:00:00Z', '2021-02-01T00:00:00Z'),
  ('GO-2023-4', 'go', 'CC-BY-4.0', '', ARRAY['GHSA-g4'], '2023-02-01T00:00:00Z', '2023-02-01T00:00:00Z'),
  ('GO-ch2', 'go', 'CC-BY-4.0', '', ARRAY['GHSA-ch1', 'CVE-2099-1'], '2021-01-01T00:00:00Z', '2021-01-01T00:00:00Z'),
  ('GO-sk2', 'go', 'CC-BY-4.0', '', ARRAY['GHSA-sk1'], '2021-01-01T00:00:00Z', '2021-01-01T00:00:00Z'),
  ('MAL-1', 'mal', 'Apache-2.0', 'M1', '{}'::text[], '2024-01-01T00:00:00Z', '2024-01-01T00:00:00Z'),
  ('MAL-2', 'mal', 'Apache-2.0', 'M2', '{}'::text[], '2020-01-01T00:00:00Z', '2020-01-01T00:00:00Z'),
  ('MAL-3', 'mal', 'Apache-2.0', 'M3', '{}'::text[], '2025-01-01T00:00:00Z', '2025-01-01T00:00:00Z'),
  ('MAL-9', 'mal', 'Apache-2.0', '', '{}'::text[], '2024-01-01T00:00:00Z', '2024-01-01T00:00:00Z'),
  ('MAL-a', 'mal', 'Apache-2.0', '', '{}'::text[], '2025-01-01T00:00:00Z', '2025-01-01T00:00:00Z'),
  ('MAL-b', 'mal', 'Apache-2.0', '', '{}'::text[], '2020-01-01T00:00:00Z', '2020-01-01T00:00:00Z'),
  ('MAL-fm', 'mal', 'Apache-2.0', '', '{}'::text[], '2021-01-01T00:00:00Z', '2021-01-01T00:00:00Z'),
  ('MAL-ma', 'mal', 'Apache-2.0', '', ARRAY['GHSA-ma'], '2021-01-01T00:00:00Z', '2021-01-01T00:00:00Z'),
  ('MAL-ns', 'mal', 'Apache-2.0', '', '{}'::text[], '2021-01-01T00:00:00Z', '2021-01-01T00:00:00Z'),
  ('PYSEC-2021-7', 'pysec', 'CC-BY-4.0', '', '{}'::text[], '2021-04-01T00:00:00Z', '2021-04-01T00:00:00Z'),
  ('PYSEC-2021-9', 'pysec', 'CC-BY-4.0', 'P9', ARRAY['CVE-2021-9', 'SNYK-JS-1'], '2022-01-01T00:00:00Z', '2022-01-01T00:00:00Z'),
  ('PYSEC-2022-1', 'pysec', 'CC-BY-4.0', '', '{}'::text[], '2022-01-01T00:00:00Z', '2022-01-01T00:00:00Z'),
  ('PYSEC-2022-2', 'pysec', 'CC-BY-4.0', '', '{}'::text[], '2022-01-01T00:00:00Z', '2022-01-01T00:00:00Z'),
  ('PYSEC-2022-3', 'pysec', 'CC-BY-4.0', '', '{}'::text[], '2022-01-01T00:00:00Z', '2022-01-01T00:00:00Z'),
  ('PYSEC-2022-4', 'pysec', 'CC-BY-4.0', '', '{}'::text[], '2022-01-01T00:00:00Z', '2022-01-01T00:00:00Z'),
  ('PYSEC-2022-5', 'pysec', 'CC-BY-4.0', '', '{}'::text[], '2022-01-01T00:00:00Z', '2022-01-01T00:00:00Z'),
  ('PYSEC-2022-6', 'pysec', 'CC-BY-4.0', '', '{}'::text[], '2022-01-01T00:00:00Z', '2022-01-01T00:00:00Z'),
  ('PYSEC-ch3', 'pysec', 'CC-BY-4.0', '', ARRAY['CVE-2099-1'], '2021-01-01T00:00:00Z', '2021-01-01T00:00:00Z'),
  ('RUSTSEC-2021-1', 'rustsec', 'CC0-1.0', '', ARRAY['CVE-2021-1'], '2021-03-01T00:00:00Z', '2021-03-01T00:00:00Z'),
  ('RUSTSEC-at', 'rustsec', 'CC-BY-4.0', '', '{}'::text[], '2021-01-02T00:00:00Z', '2021-01-02T00:00:00Z');
INSERT INTO osv_affected (advisory_id, affected_index, ecosystem, package_name, version_ranges, listed_versions, listed_versions_sortable, is_unaffected_provable)
SELECT af.advisory_id, af.affected_index, af.ecosystem, af.package_name, af.version_ranges::jsonb, af.listed_versions,
       ARRAY(SELECT array_to_string(public.fn_osv_version_sortable(af.ecosystem, kv.version_text), ' ')
               FROM unnest(af.keyed_versions) WITH ORDINALITY AS kv (version_text, version_ordinal) ORDER BY kv.version_ordinal),
       af.is_unaffected_provable
  FROM (VALUES
    ('GHSA-at', 0, 'npm', 'attr', '[{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}]', '{}'::text[], '{}'::text[], true),
    ('GHSA-ch1', 0, 'npm', 'chain', '[{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0.0"}]}]', '{}'::text[], '{}'::text[], true),
    ('GHSA-eco', 0, 'npm', 'x', '[]', '{}'::text[], '{}'::text[], false),
    ('GHSA-eco', 1, 'PyPI', 'x', '[]', '{}'::text[], '{}'::text[], false),
    ('GHSA-eco', 2, 'Maven', 'x', '[]', '{}'::text[], '{}'::text[], false),
    ('GHSA-eco', 3, 'Go', 'x', '[]', '{}'::text[], '{}'::text[], false),
    ('GHSA-eco', 4, 'NuGet', 'x', '[]', '{}'::text[], '{}'::text[], false),
    ('GHSA-eco', 5, 'RubyGems', 'x', '[]', '{}'::text[], '{}'::text[], false),
    ('GHSA-eco', 6, 'crates.io', 'x', '[]', '{}'::text[], '{}'::text[], false),
    ('GHSA-eco', 7, 'Packagist', 'x', '[]', '{}'::text[], '{}'::text[], false),
    ('GHSA-eco', 8, 'SwiftURL', 'x', '[]', '{}'::text[], '{}'::text[], false),
    ('GHSA-f1', 0, 'npm', 'fixme', '[{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0.0"}]}]', '{}'::text[], '{}'::text[], true),
    ('GHSA-f1', 1, 'npm', 'fixfail', '[{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0.0"}]}]', '{}'::text[], '{}'::text[], true),
    ('GHSA-f2', 0, 'npm', 'fixme', '[{"type": "SEMVER", "events": [{"introduced": "0.5.0"}, {"fixed": "1.2.0"}]}]', '{}'::text[], '{}'::text[], true),
    ('GHSA-f2', 1, 'npm', 'fixfail', '[{"type": "SEMVER", "events": [{"introduced": "0.5.0"}, {"fixed": "1.2.0"}]}]', '{}'::text[], '{}'::text[], true),
    ('GHSA-f3', 0, 'npm', 'fixfail', '[{"type": "SEMVER", "events": [{"introduced": "1.1.0"}, {"fixed": "1.3.0"}]}]', '{}'::text[], '{}'::text[], true),
    ('GHSA-fm', 0, 'npm', 'fixmal', '[{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.1.1"}]}]', '{}'::text[], '{}'::text[], true),
    ('GHSA-g1', 0, 'npm', 'left-pad', '[{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}]', '{}'::text[], '{}'::text[], true),
    ('GHSA-g4', 0, 'npm', 'left-pad', '[{"type": "SEMVER", "events": [{"introduced": "0"}, {"last_affected": "5.0.0"}]}]', '{}'::text[], '{}'::text[], true),
    ('GHSA-g5', 0, 'npm', 'left-pad', '[{"type": "SEMVER", "events": [{"introduced": "6.0.0"}]}]', '{}'::text[], '{}'::text[], false),
    ('GHSA-g7', 0, 'npm', 'left-pad', '[{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.2.0"}]}]', '{}'::text[], '{}'::text[], true),
    ('GHSA-hi', 0, 'npm', 'highfix', '[{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}]', '{}'::text[], '{}'::text[], true),
    ('GHSA-hi', 1, 'npm', 'highfix', '[{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "3.0.0"}]}]', '{}'::text[], '{}'::text[], true),
    ('GHSA-ma', 0, 'npm', 'malalias', '[{"type": "SEMVER", "events": [{"introduced": "0"}]}]', '{}'::text[], '{}'::text[], false),
    ('GHSA-mv1', 0, 'Maven', 'org:unkeyed', '[{"type": "ECOSYSTEM", "events": [{"introduced": "1.0"}, {"last_affected": "2.0"}]}]', '{}'::text[], '{}'::text[], true),
    ('GHSA-mv2', 0, 'Maven', 'org:wildfly', '[{"type": "ECOSYSTEM", "events": [{"introduced": "9.0.0"}, {"fixed": "9.2.0.CR1"}]}]', '{}'::text[], '{}'::text[], true),
    ('GHSA-mv3', 0, 'Maven', 'org:dashfix', '[{"type": "ECOSYSTEM", "events": [{"introduced": "1.0"}, {"fixed": "2-1"}]}]', '{}'::text[], '{}'::text[], true),
    ('GHSA-mv4', 0, 'Maven', 'org:k3open', '[{"type": "ECOSYSTEM", "events": [{"introduced": "9.0"}, {"fixed": "9.3"}]}, {"type": "ECOSYSTEM", "events": [{"introduced": "9.2.0.CR1"}, {"last_affected": "9.2.5"}]}]', '{}'::text[], '{}'::text[], true),
    ('GHSA-mv5', 0, 'Maven', 'org:k3fix', '[{"type": "ECOSYSTEM", "events": [{"introduced": "9.0"}, {"fixed": "9.3"}]}, {"type": "ECOSYSTEM", "events": [{"introduced": "9.2.0.CR1"}, {"fixed": "9.4"}]}]', '{}'::text[], '{}'::text[], true),
    ('GHSA-mv6', 0, 'Maven', 'org:dashintro', '[{"type": "ECOSYSTEM", "events": [{"introduced": "2-1"}, {"fixed": "3.0"}]}]', '{}'::text[], '{}'::text[], true),
    ('GHSA-mx', 0, 'npm', 'mixed', '[{"type": "SEMVER", "events": [{"introduced": "0"}, {"last_affected": "1.0.0"}]}, {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}]', '{}'::text[], '{}'::text[], true),
    ('GHSA-nr', 0, 'npm', 'noranges', '[]', ARRAY['1.0.0'], ARRAY['1.0.0'], false),
    ('GHSA-ns', 0, 'npm', 'nosummary', '[{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0.0"}]}]', '{}'::text[], '{}'::text[], true),
    ('GHSA-op', 0, 'npm', 'openrange', '[{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}, {"type": "SEMVER", "events": [{"introduced": "5.0.0"}]}]', '{}'::text[], '{}'::text[], false),
    ('GHSA-or', 0, 'npm', 'order', '[{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0.0"}]}, {"type": "SEMVER", "events": [{"introduced": "2.0.0"}, {"fixed": "3.0.0"}]}]', '{}'::text[], '{}'::text[], true),
    ('GHSA-or', 1, 'npm', 'order', '[{"type": "SEMVER", "events": [{"introduced": "0.5.0"}, {"fixed": "1.0.0"}]}]', '{}'::text[], '{}'::text[], true),
    ('GHSA-pk1', 0, 'Packagist', 'vendor/pk', '[{"type": "ECOSYSTEM", "events": [{"introduced": "1.0.0"}, {"fixed": "2.0.0"}]}]', '{}'::text[], '{}'::text[], true),
    ('GHSA-rg1', 0, 'RubyGems', 'rg', '[{"type": "ECOSYSTEM", "events": [{"introduced": "1.0.a"}, {"fixed": "1.0.a.2"}]}, {"type": "ECOSYSTEM", "events": [{"introduced": "2.0"}, {"fixed": "3.0"}]}]', '{}'::text[], '{}'::text[], true),
    ('GHSA-rp', 0, 'npm', 'right-pad', '[{"type": "SEMVER", "events": [{"introduced": "0"}]}]', '{}'::text[], '{}'::text[], false),
    ('GHSA-se1', 0, 'npm', 'samekeyeval', '[{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "3.0.0+b"}]}, {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "3.0.0"}]}]', '{}'::text[], '{}'::text[], true),
    ('GHSA-se2', 0, 'npm', 'samekeyeval', '[{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "3.0.0+b"}]}]', '{}'::text[], '{}'::text[], true),
    ('GHSA-se2', 1, 'npm', 'samekeyeval', '[{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "3.0.0"}]}]', '{}'::text[], '{}'::text[], true),
    ('GHSA-sk1', 0, 'npm', 'samekey', '[{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.0.0+incompatible"}]}]', '{}'::text[], '{}'::text[], true),
    ('GHSA-sk3', 0, 'npm', 'samekey', '[{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.0.0+build"}]}]', '{}'::text[], '{}'::text[], true),
    ('GHSA-tf', 0, 'npm', 'twofix', '[{"type": "SEMVER", "events": [{"introduced": "10.0.0"}, {"fixed": "10.2.0"}]}, {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "9.0.0"}]}]', '{}'::text[], '{}'::text[], true),
    ('GHSA-tw', 0, 'npm', 'tworows', '[{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}]', '{}'::text[], '{}'::text[], true),
    ('GHSA-tw', 1, 'npm', 'tworows', '[{"type": "SEMVER", "events": [{"introduced": "0"}, {"last_affected": "1.5.0"}]}]', '{}'::text[], '{}'::text[], true),
    ('GO-2021-1', 0, 'npm', 'Left-Pad', '[{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.1.0"}]}]', '{}'::text[], '{}'::text[], true),
    ('GO-2023-4', 0, 'npm', 'left-pad', '[{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "6.0.0"}]}]', '{}'::text[], '{}'::text[], true),
    ('GO-ch2', 0, 'npm', 'chain', '[{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}]', '{}'::text[], '{}'::text[], true),
    ('GO-sk2', 0, 'npm', 'samekey', '[{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}]', '{}'::text[], '{}'::text[], true),
    ('MAL-1', 0, 'npm', 'left-pad', '[{"type": "SEMVER", "events": [{"introduced": "7.0.0"}, {"fixed": "8.0.0"}]}]', '{}'::text[], '{}'::text[], true),
    ('MAL-2', 0, 'npm', 'left-pad', '[{"type": "SEMVER", "events": [{"introduced": "0"}]}]', '{}'::text[], '{}'::text[], false),
    ('MAL-3', 0, 'npm', 'left-pad', '[{"type": "SEMVER", "events": [{"introduced": "9.0.0"}]}]', '{}'::text[], '{}'::text[], false),
    ('MAL-9', 0, 'npm', 'evil-only', '[]', '{}'::text[], '{}'::text[], false),
    ('MAL-a', 0, 'npm', 'evil-two', '[{"type": "SEMVER", "events": [{"introduced": "1.0.0"}, {"fixed": "2.0.0"}]}]', '{}'::text[], '{}'::text[], true),
    ('MAL-b', 0, 'npm', 'evil-two', '[]', '{}'::text[], '{}'::text[], false),
    ('MAL-fm', 0, 'npm', 'fixmal', '[]', ARRAY['4.1.1'], ARRAY['4.1.1'], false),
    ('MAL-ma', 0, 'npm', 'malalias', '[{"type": "SEMVER", "events": [{"introduced": "0"}]}]', '{}'::text[], '{}'::text[], false),
    ('MAL-ns', 0, 'npm', 'nosummary', '[]', '{}'::text[], '{}'::text[], false),
    ('PYSEC-2021-7', 0, 'npm', 'left-pad', '[{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.8.0"}]}]', '{}'::text[], '{}'::text[], true),
    ('PYSEC-2021-9', 0, 'npm', 'left-pad', '[{"type": "SEMVER", "events": [{"introduced": "3.0.0"}, {"fixed": "4.0.0"}]}]', '{}'::text[], '{}'::text[], true),
    ('PYSEC-2022-1', 0, 'PyPI', 'Foo_Bar', '[{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.2"}]}]', ARRAY['1.0', '1.1'], ARRAY['1.0', '1.1'], true),
    ('PYSEC-2022-2', 0, 'PyPI', 'gitonly', '[{"repo": "https://example.com/r", "type": "GIT", "events": [{"introduced": "a1"}, {"fixed": "b2"}]}]', ARRAY['1.1'], ARRAY['1.1'], true),
    ('PYSEC-2022-3', 0, 'PyPI', 'unkeyedlist', '[{"type": "ECOSYSTEM", "events": [{"introduced": "1.0"}, {"fixed": "2.0"}]}]', ARRAY['1.0-foo-bar'], '{}'::text[], false),
    ('PYSEC-2022-4', 0, 'PyPI', 'torchy', '[{"type": "ECOSYSTEM", "events": [{"introduced": "1.0"}, {"last_affected": "2.6.0"}]}]', ARRAY['2.8.0'], ARRAY['2.8.0'], true),
    ('PYSEC-2022-5', 0, 'PyPI', 'tenfix', '[{"type": "ECOSYSTEM", "events": [{"introduced": "1.0"}, {"fixed": "1.9"}]}, {"type": "ECOSYSTEM", "events": [{"introduced": "1.0"}, {"fixed": "1.10"}]}]', '{}'::text[], '{}'::text[], true),
    ('PYSEC-2022-6', 0, 'PyPI', 'localintro', '[{"type": "ECOSYSTEM", "events": [{"introduced": "3.0+a"}, {"fixed": "4.0"}]}]', '{}'::text[], '{}'::text[], true),
    ('PYSEC-ch3', 0, 'npm', 'chain', '[{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "3.0.0"}]}]', '{}'::text[], '{}'::text[], true),
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
    ('GHSA-ch1', 0, 0, NULL, '1.0.0', 'fixed', '1.0.0'),
    ('GHSA-f1', 0, 0, NULL, '1.0.0', 'fixed', '1.0.0'),
    ('GHSA-f1', 1, 0, NULL, '1.0.0', 'fixed', '1.0.0'),
    ('GHSA-f2', 0, 0, '0.5.0', '1.2.0', 'fixed', '1.2.0'),
    ('GHSA-f2', 1, 0, '0.5.0', '1.2.0', 'fixed', '1.2.0'),
    ('GHSA-f3', 0, 0, '1.1.0', '1.3.0', 'fixed', '1.3.0'),
    ('GHSA-fm', 0, 0, NULL, '4.1.1', 'fixed', '4.1.1'),
    ('GHSA-g1', 0, 0, NULL, '2.0.0', 'fixed', '2.0.0'),
    ('GHSA-g4', 0, 0, NULL, '5.0.0', 'last_affected', NULL),
    ('GHSA-g5', 0, 0, '6.0.0', NULL, NULL, NULL),
    ('GHSA-g7', 0, 0, NULL, '2.2.0', 'fixed', '2.2.0'),
    ('GHSA-hi', 0, 0, NULL, '2.0.0', 'fixed', '2.0.0'),
    ('GHSA-hi', 1, 0, NULL, '3.0.0', 'fixed', '3.0.0'),
    ('GHSA-ma', 0, 0, NULL, NULL, NULL, NULL),
    ('GHSA-mv1', 0, 0, '1.0', '2.0', 'last_affected', NULL),
    ('GHSA-mv2', 0, 0, '9.0.0', '9.2.0.CR1', 'fixed', '9.2.0.CR1'),
    ('GHSA-mv3', 0, 0, '1.0', '2-1', 'fixed', '2-1'),
    ('GHSA-mv4', 0, 0, '9.0', '9.3', 'fixed', '9.3'),
    ('GHSA-mv4', 0, 1, '9.2.0.CR1', '9.2.5', 'last_affected', NULL),
    ('GHSA-mv5', 0, 0, '9.0', '9.3', 'fixed', '9.3'),
    ('GHSA-mv5', 0, 1, '9.2.0.CR1', '9.4', 'fixed', '9.4'),
    ('GHSA-mv6', 0, 0, '2-1', '3.0', 'fixed', '3.0'),
    ('GHSA-mx', 0, 0, NULL, '1.0.0', 'last_affected', NULL),
    ('GHSA-mx', 0, 1, NULL, '2.0.0', 'fixed', '2.0.0'),
    ('GHSA-ns', 0, 0, NULL, '1.0.0', 'fixed', '1.0.0'),
    ('GHSA-op', 0, 0, NULL, '2.0.0', 'fixed', '2.0.0'),
    ('GHSA-op', 0, 1, '5.0.0', NULL, NULL, NULL),
    ('GHSA-or', 0, 0, NULL, '1.0.0', 'fixed', '1.0.0'),
    ('GHSA-or', 0, 1, '2.0.0', '3.0.0', 'fixed', '3.0.0'),
    ('GHSA-or', 1, 0, '0.5.0', '1.0.0', 'fixed', '1.0.0'),
    ('GHSA-pk1', 0, 0, '1.0.0', '2.0.0', 'fixed', '2.0.0'),
    ('GHSA-rg1', 0, 0, '1.0.a', '1.0.a.2', 'fixed', '1.0.a.2'),
    ('GHSA-rg1', 0, 1, '2.0', '3.0', 'fixed', '3.0'),
    ('GHSA-rp', 0, 0, NULL, NULL, NULL, NULL),
    ('GHSA-se1', 0, 0, NULL, '3.0.0+b', 'fixed', '3.0.0+b'),
    ('GHSA-se1', 0, 1, NULL, '3.0.0', 'fixed', '3.0.0'),
    ('GHSA-se2', 0, 0, NULL, '3.0.0+b', 'fixed', '3.0.0+b'),
    ('GHSA-se2', 1, 0, NULL, '3.0.0', 'fixed', '3.0.0'),
    ('GHSA-sk1', 0, 0, NULL, '2.0.0+incompatible', 'fixed', '2.0.0+incompatible'),
    ('GHSA-sk3', 0, 0, NULL, '2.0.0+build', 'fixed', '2.0.0+build'),
    ('GHSA-tf', 0, 0, '10.0.0', '10.2.0', 'fixed', '10.2.0'),
    ('GHSA-tf', 0, 1, NULL, '9.0.0', 'fixed', '9.0.0'),
    ('GHSA-tw', 0, 0, NULL, '2.0.0', 'fixed', '2.0.0'),
    ('GHSA-tw', 1, 0, NULL, '1.5.0', 'last_affected', NULL),
    ('GO-2021-1', 0, 0, NULL, '2.1.0', 'fixed', '2.1.0'),
    ('GO-2023-4', 0, 0, NULL, '6.0.0', 'fixed', '6.0.0'),
    ('GO-ch2', 0, 0, NULL, '2.0.0', 'fixed', '2.0.0'),
    ('GO-sk2', 0, 0, NULL, '2.0.0', 'fixed', '2.0.0'),
    ('MAL-1', 0, 0, '7.0.0', '8.0.0', 'fixed', '8.0.0'),
    ('MAL-2', 0, 0, NULL, NULL, NULL, NULL),
    ('MAL-3', 0, 0, '9.0.0', NULL, NULL, NULL),
    ('MAL-a', 0, 0, '1.0.0', '2.0.0', 'fixed', '2.0.0'),
    ('MAL-ma', 0, 0, NULL, NULL, NULL, NULL),
    ('PYSEC-2021-7', 0, 0, NULL, '1.8.0', 'fixed', '1.8.0'),
    ('PYSEC-2021-9', 0, 0, '3.0.0', '4.0.0', 'fixed', '4.0.0'),
    ('PYSEC-2022-1', 0, 0, NULL, '1.2', 'fixed', '1.2'),
    ('PYSEC-2022-3', 0, 0, '1.0', '2.0', 'fixed', '2.0'),
    ('PYSEC-2022-4', 0, 0, '1.0', '2.6.0', 'last_affected', NULL),
    ('PYSEC-2022-5', 0, 0, '1.0', '1.9', 'fixed', '1.9'),
    ('PYSEC-2022-5', 0, 1, '1.0', '1.10', 'fixed', '1.10'),
    ('PYSEC-2022-6', 0, 0, '3.0+a', '4.0', 'fixed', '4.0'),
    ('PYSEC-ch3', 0, 0, NULL, '3.0.0', 'fixed', '3.0.0'),
    ('RUSTSEC-2021-1', 0, 0, NULL, '1.9.0', 'fixed', '1.9.0'),
    ('RUSTSEC-at', 0, 0, '3.0.0', '4.0.0', 'fixed', '4.0.0')
  ) AS iv (advisory_id, affected_index, interval_index, introduced_version, upper_version, upper_event, fixed_version)
  JOIN osv_affected AS osvaf ON osvaf.advisory_id = iv.advisory_id AND osvaf.affected_index = iv.affected_index;

CREATE TEMP VIEW t_package_check_call AS SELECT * FROM api.fn_package_check('NPM', 'LEFT-PAD', NULL, 20, 0);

DO $$
DECLARE
  answer record;
BEGIN
  ASSERT (SELECT array_agg(attname::text ORDER BY attnum) FROM pg_attribute
          WHERE attrelid = 't_package_check_call'::regclass AND attnum > 0)
         = ARRAY['advisory_feed_loaded', 'has_advisory_data', 'result_count', 'fixed_version', 'malicious', 'results', 'attribution'],
         'api.fn_package_check answers the 7 columns db_PACKAGECHECK reads, in its order';
  ASSERT (SELECT array_agg(format_type(atttypid, atttypmod) ORDER BY attnum) FROM pg_attribute
          WHERE attrelid = 't_package_check_call'::regclass AND attnum > 0)
         = ARRAY['boolean', 'boolean', 'integer', 'text', 'jsonb', 'jsonb', 'jsonb'],
         'the flags are boolean, result_count is integer, fixed_version is text, and malicious, results and attribution are jsonb';

  SELECT * INTO answer FROM t_package_check_call;
  ASSERT row(answer.advisory_feed_loaded, answer.has_advisory_data, answer.result_count, answer.fixed_version)::text = row(true, true, 5, NULL)::text,
         'an ecosystem and a name in upper case find the package; without a version every vulnerability is listed, and there is no fixed version';
  ASSERT (SELECT array_agg(r.result_json ->> 'id' ORDER BY r.result_ordinal) FROM jsonb_array_elements(answer.results) WITH ORDINALITY AS r (result_json, result_ordinal))
         = ARRAY['GHSA-g4', 'GHSA-g5', 'PYSEC-2021-9', 'GHSA-g7', 'GHSA-g1'],
         'the results come newest first, then in id order; a folded advisory is no result, an advisory of the same source is, and a shared id that is no CVE id folds nothing';
  ASSERT answer.results -> 4
         = '{"id": "GHSA-g1", "aliases": ["CVE-2021-1", "GO-2021-1", "PYSEC-2021-7", "RUSTSEC-2021-1"], "source": "ghsa", "summary": "G1",
             "published_time": "2021-01-01T00:00:00Z", "fixed": ["2.0.0"],
             "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}]}'::jsonb,
         'a result holds the shown advisory and the ids and aliases of the folded ones; fixed and ranges are those of the shown advisory';
  ASSERT (SELECT array_agg(r.result_json -> 'aliases' ORDER BY r.result_ordinal) FROM jsonb_array_elements(answer.results) WITH ORDINALITY AS r (result_json, result_ordinal))
         = ARRAY['["GO-2023-4"]', '["SNYK-JS-1"]', '["CVE-2021-9", "SNYK-JS-1"]', '["CVE-2021-1", "RUSTSEC-2021-1"]',
                 '["CVE-2021-1", "GO-2021-1", "PYSEC-2021-7", "RUSTSEC-2021-1"]']::jsonb[],
         'an advisory folded into two results joins the aliases of both';
  ASSERT answer.malicious = '{"id": "MAL-3", "summary": "M3", "published_time": "2025-01-01T00:00:00Z"}',
         'without a version malicious is the newest mal advisory, without affects_version';
  ASSERT (SELECT array_agg(row(a.attribution_json ->> 'source', a.attribution_json ->> 'license', a.attribution_json ->> 'url')::text ORDER BY a.attribution_ordinal)
            FROM jsonb_array_elements(answer.attribution) WITH ORDINALITY AS a (attribution_json, attribution_ordinal))
         = ARRAY[row('ghsa', 'CC-BY-4.0', 'https://github.com/github/advisory-database')::text,
                 row('go', 'CC-BY-4.0', 'https://github.com/golang/vulndb')::text,
                 row('mal', 'Apache-2.0', 'https://github.com/ossf/malicious-packages')::text,
                 row('pysec', 'CC-BY-4.0', 'https://github.com/pypa/advisory-database')::text,
                 row('rustsec', 'CC0-1.0', 'https://github.com/rustsec/advisory-db')::text],
         'attribution names each source of the results, folded ones too, and of malicious, with its license and link, in source order';
  ASSERT (SELECT bool_and(a.attribution_json ->> 'notice' = 'Retrieved through OSV.dev. ContrastAPI selected and normalized the fields and computed affects_version and fixed_version. No warranty; the source does not endorse ContrastAPI.')
            FROM jsonb_array_elements(answer.attribution) AS a (attribution_json)),
         'each attribution carries the notice';

  SELECT * INTO answer FROM api.fn_package_check('npm', 'left-pad', '1.5.0', 20, 0);
  ASSERT row(answer.result_count, answer.fixed_version)::text = row(4, NULL)::text,
         'with a version a result that leaves it out is not listed, and one result without a fixed version leaves the answer without one';
  ASSERT (SELECT array_agg(row(r.result_json ->> 'id', r.result_json ->> 'affects_version', r.result_json ->> 'fixed_version')::text ORDER BY r.result_ordinal)
            FROM jsonb_array_elements(answer.results) WITH ORDINALITY AS r (result_json, result_ordinal))
         = ARRAY[row('GHSA-g4', 'true', NULL)::text, row('GHSA-g5', NULL, NULL)::text, row('GHSA-g7', 'true', '2.2.0')::text,
                 row('GHSA-g1', 'true', '2.1.0')::text],
         'affects_version is true or null, a folded group takes the highest fixed version of its advisories, and one member without one leaves the group without one';
  ASSERT (answer.results -> 1 ? 'affects_version') AND (answer.results -> 1 ? 'fixed_version'),
         'with a version each result carries both keys, null too';
  ASSERT answer.malicious = '{"id": "MAL-2", "summary": "M2", "published_time": "2020-01-01T00:00:00Z", "affects_version": true}',
         'a mal advisory that leaves the version out does not count, and an affected one comes before a newer one that cannot tell';
  ASSERT (SELECT array_agg(a.attribution_json ->> 'source' ORDER BY a.attribution_ordinal) FROM jsonb_array_elements(answer.attribution) WITH ORDINALITY AS a (attribution_json, attribution_ordinal))
         = ARRAY['ghsa', 'go', 'mal', 'pysec', 'rustsec'],
         'attribution names the source of a folded advisory of a listed result';
  ASSERT (SELECT array_agg(row(v.version_text, adv.affects_version)::text ORDER BY v.version_text)
            FROM unnest(ARRAY['5.0.0', '5.0.1']) AS v (version_text)
           CROSS JOIN LATERAL api.fn_package_check_advisory('npm', 'left-pad', v.version_text) AS adv
           WHERE adv.advisory_id = 'GHSA-g4')
         = ARRAY[row('5.0.0', true)::text, row('5.0.1', false)::text],
         'a last_affected version is inside its interval, and the version after it is outside';

  ASSERT (SELECT c.malicious ->> 'id' FROM api.fn_package_check('npm', 'left-pad', '7.5.0', 20, 0) AS c) = 'MAL-1',
         'of two affected mal advisories the newest comes first';
  ASSERT (SELECT c.malicious ->> 'id' FROM api.fn_package_check('npm', 'evil-two', '3.0.0', 20, 0) AS c) = 'MAL-b',
         'a mal advisory whose range leaves the version out does not count, even when it is the newest';
  ASSERT (SELECT row(c.result_count, c.fixed_version)::text FROM api.fn_package_check('npm', 'fixme', '0.6.0', 20, 0) AS c)
         = row(2, '1.2.0')::text,
         'the fixed version of the answer is the highest fixed version of the listed results';
  ASSERT (SELECT row(c.result_count, c.fixed_version)::text FROM api.fn_package_check('npm', 'fixme', '0.5.0', 20, 0) AS c)
         = row(2, '1.2.0')::text,
         'an introduced version is inside its interval';
  ASSERT (SELECT row(c.result_count, c.fixed_version)::text FROM api.fn_package_check('npm', 'fixfail', '0.6.0', 20, 0) AS c)
         = row(2, NULL)::text,
         'a fixed version that another advisory of the package still affects is not answered';
  ASSERT (SELECT row(c.result_count, c.fixed_version)::text FROM api.fn_package_check('npm', 'fixme', '1.2.0', 20, 0) AS c)
         = row(0, NULL)::text,
         'a fixed version is outside its interval, and a version no advisory affects lists no result and has no fixed version';
  ASSERT (SELECT jsonb_array_length(c.results -> 0 -> 'ranges') FROM api.fn_package_check('npm', 'fixme', NULL, 1, 1) AS c) = 1,
         'ranges holds the ranges of the package alone, not those of another package of the advisory';
  ASSERT (SELECT c.results -> 0 -> 'fixed' FROM api.fn_package_check('npm', 'twofix', NULL, 20, 0) AS c) = '["9.0.0", "10.2.0"]',
         'fixed lists the fixed versions in version order';

  ASSERT (SELECT array_agg(row(r.result_json ->> 'id', r.result_json ->> 'affects_version', r.result_json ->> 'fixed_version')::text)
            FROM api.fn_package_check('pypi', 'foo.bar', '1.1', 20, 0) AS c, jsonb_array_elements(c.results) AS r (result_json))
         = ARRAY[row('PYSEC-2022-1', 'true', '1.2')::text],
         'a PyPI version inside an ECOSYSTEM range is affected, with the fixed version of the range; the normalized name joins foo.bar and Foo_Bar';
  ASSERT (SELECT row(c.result_count, c.fixed_version)::text FROM api.fn_package_check('PyPI', 'Foo_Bar', '1.5', 20, 0) AS c)
         = row(0, NULL)::text,
         'a PyPI version above the fixed version of a provable package is not affected, so no result is listed';
  ASSERT (SELECT bool_and((SELECT c.has_advisory_data FROM api.fn_package_check(e.ecosystem_name, 'x', NULL, 20, 0) AS c))
            FROM unnest(ARRAY['npm', 'pypi', 'maven', 'go', 'nuget', 'rubygems', 'crates.io', 'packagist', 'swifturl',
                              'NPM', 'PYPI', 'MAVEN', 'GO', 'NUGET', 'RUBYGEMS', 'CRATES.IO', 'PACKAGIST', 'SWIFTURL']) AS e (ecosystem_name)),
         'each of the nine ecosystems finds its package in lower case and in upper case';

  ASSERT (SELECT row(c.result_count, (SELECT array_agg(r.result_json ->> 'id') FROM jsonb_array_elements(c.results) AS r (result_json)))::text
            FROM api.fn_package_check('npm', 'left-pad', NULL, 2, 1) AS c)
         = row(5, ARRAY['GHSA-g5', 'PYSEC-2021-9'])::text,
         'results holds p_result_row_count results from p_result_offset, and result_count counts them all';
  ASSERT (SELECT row(c.has_advisory_data, c.result_count, c.malicious ->> 'id', c.results)::text FROM api.fn_package_check('npm', 'evil-only', '1.0.0', 20, 0) AS c)
         = row(true, 0, 'MAL-9', '[]')::text,
         'a package that only a mal advisory names has advisory data and no result; a mal advisory without ranges cannot tell';
  ASSERT (SELECT row(c.advisory_feed_loaded, c.has_advisory_data, c.result_count)::text FROM api.fn_package_check('npm', 'no-such', NULL, 20, 0) AS c)
         = row(true, false, 0)::text,
         'a package no advisory names has no advisory data';
  ASSERT (SELECT row(c.has_advisory_data, c.result_count)::text FROM api.fn_package_check('PyPI', 'left-pad', NULL, 20, 0) AS c)
         = row(false, 0)::text,
         'a name of another ecosystem has no advisory data';
  ASSERT (SELECT count(*) FROM api.fn_package_check('npm', NULL, NULL, 20, 0)) = 0
     AND (SELECT count(*) FROM api.fn_package_check('npm', 'left-pad', NULL, NULL, 0)) = 0
     AND (SELECT count(*) FROM api.fn_package_check('npm', 'left-pad', NULL, 20, NULL)) = 0
     AND (SELECT count(*) FROM api.fn_package_check(NULL, 'left-pad', NULL, 20, 0)) = 0
     AND (SELECT count(*) FROM api.fn_package_check('Pub', 'left-pad', NULL, 20, 0)) = 0,
         'a NULL argument other than p_version answers no row, and so does an ecosystem outside the nine';
  ASSERT (SELECT row(c.result_count, jsonb_array_length(c.results), c.results -> 0 -> 'ranges', c.results -> 0 -> 'fixed')::text
            FROM api.fn_package_check('npm', 'noranges', NULL, 20, 0) AS c)
         = row(1, 1, '[]', '[]')::text,
         'an advisory whose package has no range is a result, with empty ranges and fixed lists';
  ASSERT (SELECT row(c.result_count, c.results -> 0 ->> 'id', c.results -> 0 -> 'aliases', c.results -> 0 ->> 'fixed_version')::text
            FROM api.fn_package_check('npm', 'chain', '2.5.0', 20, 0) AS c)
         = row(1, 'GHSA-ch1', '["CVE-2099-1", "GO-ch2", "PYSEC-ch3"]', '3.0.0')::text,
         'PYSEC-ch3 shares a CVE id only with GO-ch2, which is folded into GHSA-ch1, so it joins GHSA-ch1 and its range counts';
  ASSERT (SELECT row(c.result_count, c.fixed_version)::text FROM api.fn_package_check('npm', 'fixmal', '4.1.0', 20, 0) AS c)
         = row(1, NULL)::text,
         'a fixed version that a mal advisory names is not answered';
  ASSERT (SELECT row(c.fixed_version, c.results -> 0 ->> 'fixed_version')::text FROM api.fn_package_check('npm', 'openrange', '1.0.0', 20, 0) AS c)
         = row(NULL, '2.0.0')::text,
         'an advisory with an open interval cannot show that a version is outside it, so the answer does not name its fixed version';
  SELECT * INTO answer FROM api.fn_package_check('npm', 'nosummary', NULL, 20, 0);
  ASSERT row(answer.results -> 0 -> 'summary', answer.malicious -> 'summary')::text = row('null'::jsonb, 'null'::jsonb)::text,
         'an advisory without a summary has a null summary, in a result and in malicious';
  SELECT * INTO answer FROM api.fn_package_check('npm', 'order', NULL, 20, 0);
  ASSERT row(answer.results -> 0 -> 'ranges', answer.results -> 0 -> 'fixed')::text
         = row('[{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0.0"}]},
                 {"type": "SEMVER", "events": [{"introduced": "2.0.0"}, {"fixed": "3.0.0"}]},
                 {"type": "SEMVER", "events": [{"introduced": "0.5.0"}, {"fixed": "1.0.0"}]}]'::jsonb,
               '["1.0.0", "3.0.0"]'::jsonb)::text,
         'ranges keep the order of the package rows, then of their ranges, and fixed names each fixed version once';
  ASSERT (SELECT row(c.result_count, (SELECT array_agg(a.attribution_json ->> 'source') FROM jsonb_array_elements(c.attribution) AS a (attribution_json)))::text
            FROM api.fn_package_check('npm', 'attr', '1.0.0', 20, 0) AS c)
         = row(1, ARRAY['ghsa'])::text,
         'attribution names the sources of the listed results, not that of a result the version leaves out';
  ASSERT (SELECT row(c.result_count, c.results -> 0 ->> 'id', c.results -> 0 -> 'aliases', c.malicious ->> 'id')::text
            FROM api.fn_package_check('npm', 'malalias', NULL, 20, 0) AS c)
         = row(1, 'GHSA-ma', '[]', 'MAL-ma')::text,
         'a mal advisory that names an advisory among its aliases is not folded into its result';
  ASSERT (SELECT row(c.fixed_version, (SELECT array_agg(row(r.result_json ->> 'id', r.result_json ->> 'fixed_version')::text ORDER BY r.result_json ->> 'id')
                                         FROM jsonb_array_elements(c.results) AS r (result_json)))::text
            FROM api.fn_package_check('npm', 'samekey', '1.0.0', 20, 0) AS c)
         = row('2.0.0', ARRAY[row('GHSA-sk1', '2.0.0')::text, row('GHSA-sk3', '2.0.0+build')::text])::text,
         'of two fixed versions with one sortable form the first in text order counts, in a result and in the answer';
  ASSERT (SELECT array_agg(row(e.advisory_id, e.fixed_version)::text ORDER BY e.advisory_id)
            FROM api.fn_package_check_advisory('npm', 'samekeyeval', '1.0.0') AS e)
         = ARRAY[row('GHSA-se1', '3.0.0')::text, row('GHSA-se2', '3.0.0')::text],
         'of two fixed versions with one sortable form api.fn_package_check_advisory answers the first in text order, in one package row and across two';

  ASSERT (SELECT array_agg(row(g.shown_id, g.member_id)::text ORDER BY g.shown_id, g.member_id) FROM api.fn_package_check_group('npm', 'chain') AS g)
         = ARRAY[row('GHSA-ch1', 'GHSA-ch1')::text, row('GHSA-ch1', 'GO-ch2')::text, row('GHSA-ch1', 'PYSEC-ch3')::text],
         'the group of a chain of folds has one shown advisory, and it is a member of its own result';
  ASSERT (SELECT array_agg(row(g.shown_id, g.member_id)::text ORDER BY g.shown_id) FROM api.fn_package_check_group('npm', 'malalias') AS g)
         = ARRAY[row('GHSA-ma', 'GHSA-ma')::text, row('MAL-ma', 'MAL-ma')::text],
         'a mal advisory is a group of its own';
  ASSERT NOT EXISTS (SELECT 1 FROM api.fn_package_check_group('PyPI', 'left-pad')),
         'a group holds the advisories of the package in its own ecosystem alone';
  ASSERT (SELECT row(r.version_index, r.advisory_id, r.source, r.license, r.member_ids, r.affects_version, r.fixed_version)::text
            FROM api.fn_package_check_result('npm', 'chain', ARRAY['2.5.0']) AS r)
         = row(1, 'GHSA-ch1', 'ghsa', 'CC-BY-4.0', ARRAY['GHSA-ch1', 'GO-ch2', 'PYSEC-ch3'], true, '3.0.0')::text,
         'a result carries the source and the license of its shown advisory and the ids of its members';
  ASSERT (SELECT array_agg(row(r.version_index, r.advisory_id, r.affects_version, r.fixed_version)::text ORDER BY r.version_index)
            FROM api.fn_package_check_result('npm', 'chain', ARRAY['3.5.0', '2.5.0', NULL]) AS r)
         = ARRAY[row(1, 'GHSA-ch1', false, NULL)::text, row(2, 'GHSA-ch1', true, '3.0.0')::text, row(3, 'GHSA-ch1', NULL, NULL)::text],
         'a list of versions answers each version at its position, from 1: one version is outside the result, one is in it, and NULL is neither';
  ASSERT (SELECT row(r.ranges, r.fixed)::text FROM api.fn_package_check_ranges('npm', 'noranges', 'GHSA-nr') AS r)
         = row('[]'::jsonb, '[]'::jsonb)::text,
         'an advisory without ranges answers one row of empty lists';

  ASSERT (SELECT array_agg(row(e.advisory_id, e.affects_version, e.fixed_version, e.fixed_version_sortable)::text ORDER BY e.advisory_id)
            FROM api.fn_package_check_advisory('npm', 'fixfail', '1.1.5') AS e)
         = ARRAY[row('GHSA-f1', false, NULL, NULL::text[])::text,
                 row('GHSA-f2', true, '1.2.0', public.fn_osv_version_sortable('npm', '1.2.0'))::text,
                 row('GHSA-f3', true, '1.3.0', public.fn_osv_version_sortable('npm', '1.3.0'))::text],
         'api.fn_package_check_advisory answers each advisory of the package with its fixed version and its sortable form';
  ASSERT (SELECT row(e.affects_version, e.fixed_version, e.fixed_version_sortable)::text FROM api.fn_package_check_advisory('npm', 'tworows', '1.0.0') AS e)
         = row(true, NULL, NULL::text[])::text,
         'an advisory with two rows of the package has no fixed version when one affected row has none';
  ASSERT (SELECT row(e.affects_version, e.fixed_version)::text FROM api.fn_package_check_advisory('npm', 'highfix', '1.0.0') AS e)
         = row(true, '3.0.0')::text,
         'an advisory with two affected rows of the package answers the highest of their fixed versions';
  ASSERT (SELECT row(e.affects_version, e.fixed_version)::text FROM api.fn_package_check_advisory('npm', 'mixed', '0.5.0') AS e)
         = row(true, NULL)::text,
         'a row has no fixed version when one interval that holds the version ends at a last_affected version, though another ends at a higher fixed one';
  ASSERT (SELECT array_agg(row(e.advisory_id, e.affects_version)::text ORDER BY e.advisory_id)
            FROM api.fn_package_check_advisory('npm', 'fixfail', NULL) AS e)
         = ARRAY[row('GHSA-f1', NULL)::text, row('GHSA-f2', NULL)::text, row('GHSA-f3', NULL)::text],
         'without a version api.fn_package_check_advisory answers NULL';
END
$$;

DO $$
BEGIN
  ASSERT (SELECT array_agg(row(v.version_text, (SELECT a.affects_version FROM api.fn_package_check_advisory('PyPI', 'gitonly', v.version_text) AS a))::text
                           ORDER BY v.version_index)
            FROM unnest(ARRAY['1.1.0', 'v1.1', '1.2', '1.1+local']) WITH ORDINALITY AS v (version_text, version_index))
         = ARRAY[row('1.1.0', true)::text, row('v1.1', true)::text, row('1.2', false)::text, row('1.1+local', NULL)::text],
         'a GIT range with a list finds a listed version under another spelling of it, calls an unlisted one safe, and cannot tell for a local build of a listed one';
  ASSERT (SELECT array_agg(row(v.version_text, (SELECT a.affects_version FROM api.fn_package_check_advisory('PyPI', 'unkeyedlist', v.version_text) AS a))::text
                           ORDER BY v.version_index)
            FROM unnest(ARRAY['1.0-foo-bar', '1.0-foo-baz', '3.0']) WITH ORDINALITY AS v (version_text, version_index))
         = ARRAY[row('1.0-foo-bar', true)::text, row('1.0-foo-baz', NULL)::text, row('3.0', NULL)::text],
         'a listed PyPI version without a key is found by its text; with it on the list no version is called safe';
  ASSERT (SELECT array_agg(row(v.ecosystem, v.version_text, (SELECT a.affects_version FROM api.fn_package_check_advisory(v.ecosystem, v.package_name, v.version_text) AS a))::text
                           ORDER BY v.version_index)
            FROM (VALUES (1, 'Maven', 'org:unkeyed', 'latest'), (2, 'Maven', 'org:unkeyed', 'v2.14.1'), (3, 'Maven', 'org:unkeyed', '3.0'),
                         (4, 'RubyGems', 'rg', '1.0-rc1'), (5, 'RubyGems', 'rg', '3.5'), (6, 'Packagist', 'vendor/pk', '1.0'),
                         (7, 'Packagist', 'vendor/pk', '3.0.0')) AS v (version_index, ecosystem, package_name, version_text))
         = ARRAY[row('Maven', 'latest', NULL)::text, row('Maven', 'v2.14.1', NULL)::text, row('Maven', '3.0', false)::text,
                 row('RubyGems', '1.0-rc1', NULL)::text, row('RubyGems', '3.5', false)::text, row('Packagist', '1.0', NULL)::text,
                 row('Packagist', '3.0.0', false)::text],
         'a version without a key is never called safe, where a keyed version outside the same provable ranges is';
  ASSERT (SELECT array_agg(row(v.version_text, (SELECT a.affects_version FROM api.fn_package_check_advisory('PyPI', 'torchy', v.version_text) AS a))::text
                           ORDER BY v.version_index)
            FROM unnest(ARRAY['2.6.0+cu124', '2.5.0+cpu', '2.7.1+cu124', '2.8.0+cu1', '2.8.0']) WITH ORDINALITY AS v (version_text, version_index))
         = ARRAY[row('2.6.0+cu124', NULL)::text, row('2.5.0+cpu', true)::text, row('2.7.1+cu124', false)::text, row('2.8.0+cu1', NULL)::text,
                 row('2.8.0', true)::text],
         'a PyPI local version is unsure when it and its release fall on two sides of a bound, or when its release is listed';
  ASSERT (SELECT array_agg(row(v.ecosystem, v.version_text, (SELECT a.affects_version FROM api.fn_package_check_advisory(v.ecosystem, v.package_name, v.version_text) AS a))::text
                           ORDER BY v.version_index)
            FROM (VALUES (1, 'PyPI', 'localintro', '3.0+b'), (2, 'Maven', 'org:unkeyed', '2.0+x'), (3, 'RubyGems', 'rg', '1.0.a.1')) AS v (version_index, ecosystem, package_name, version_text))
         = ARRAY[row('PyPI', '3.0+b', NULL)::text, row('Maven', '2.0+x', false)::text, row('RubyGems', '1.0.a.1', true)::text],
         'a PyPI local build above an introduced bound whose release is below it is unsure; a + of Maven and the forms of RubyGems are not read with the PyPI and Maven rules';
  ASSERT (SELECT array_agg(row(v.package_name, v.version_text, (SELECT a.affects_version FROM api.fn_package_check_advisory('Maven', v.package_name, v.version_text) AS a))::text
                           ORDER BY v.version_index)
            FROM (VALUES (1, 'org:wildfly', '9.1.0'), (2, 'org:wildfly', '9.2.0-dev'), (3, 'org:wildfly', '9.2.0-redhat-1'), (4, 'org:wildfly', '9.2.0.Final'),
                         (5, 'org:dashfix', '2.0.RC1'), (6, 'org:dashfix', '1.5'), (7, 'org:dashintro', '2.0.RC1'), (8, 'org:dashintro', '2.5'))
                 AS v (version_index, package_name, version_text))
         = ARRAY[row('org:wildfly', '9.1.0', true)::text, row('org:wildfly', '9.2.0-dev', NULL)::text, row('org:wildfly', '9.2.0-redhat-1', NULL)::text,
                 row('org:wildfly', '9.2.0.Final', false)::text, row('org:dashfix', '2.0.RC1', NULL)::text, row('org:dashfix', '1.5', true)::text,
                 row('org:dashintro', '2.0.RC1', NULL)::text, row('org:dashintro', '2.5', true)::text],
         'a Maven version whose order against a lower or an upper bound is uncertain is neither affected nor safe, whichever side of the bound its form falls on';
  ASSERT (SELECT array_agg(row(v.package_name, a.affects_version, a.fixed_version, a.fixed_version_sortable)::text ORDER BY v.package_name)
            FROM unnest(ARRAY['org:k3open', 'org:k3fix']) AS v (package_name)
           CROSS JOIN LATERAL api.fn_package_check_advisory('Maven', v.package_name, '9.2.0-dev') AS a)
         = ARRAY[row('org:k3fix', true, '9.4', ARRAY['20019', '80014', '4'])::text, row('org:k3open', true, NULL, NULL::text[])::text],
         'an unsure interval counts for the fixed version: without a fixed event it leaves none, and with a higher one it raises it';
  ASSERT (SELECT row(a.affects_version, a.fixed_version, a.fixed_version_sortable)::text FROM api.fn_package_check_advisory('PyPI', 'foo-bar', '1.1') AS a)
         = row(true, '1.2', ARRAY['000', '0011', '0012', '!', '3', '1', '3', '1'])::text
     AND (SELECT row(a.affects_version, a.fixed_version, a.fixed_version_sortable)::text FROM api.fn_package_check_advisory('PyPI', 'tenfix', '1.5') AS a)
         = row(true, '1.10', ARRAY['000', '0011', '00210', '!', '3', '1', '3', '1'])::text,
         'fixed_version is the highest fixed version in PEP 440 order, 1.10 above 1.9, and fixed_version_sortable is its PEP 440 form';
  ASSERT (SELECT row(c.results -> 0 -> 'fixed', c.fixed_version)::text FROM api.fn_package_check('PyPI', 'tenfix', '1.5', 20, 0) AS c)
         = row('["1.9", "1.10"]'::jsonb, '1.10')::text,
         'fixed lists a PyPI advisory''s fixed versions in version order, and the answer names the highest';
END
$$;

INSERT INTO osv_advisories (advisory_id, source, license, summary, aliases, published_time, modified_time) VALUES
  ('GHSA-z0', 'ghsa', 'CC-BY-4.0', '', '{}'::text[], '2022-01-01T00:00:00Z', '2022-01-01T00:00:00Z');
INSERT INTO osv_affected (advisory_id, affected_index, ecosystem, package_name, version_ranges, listed_versions, listed_versions_sortable, is_unaffected_provable)
SELECT af.advisory_id, af.affected_index, af.ecosystem, af.package_name, af.version_ranges::jsonb, af.listed_versions,
       ARRAY(SELECT array_to_string(public.fn_osv_version_sortable(af.ecosystem, kv.version_text), ' ')
               FROM unnest(af.keyed_versions) WITH ORDINALITY AS kv (version_text, version_ordinal) ORDER BY kv.version_ordinal),
       af.is_unaffected_provable
  FROM (VALUES
    ('GHSA-z0', 0, 'PyPI', 'zero-py', '[{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.0"}]}]', '{}'::text[], '{}'::text[], true),
    ('GHSA-z0', 1, 'Maven', 'org:zero', '[{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.0"}]}]', '{}'::text[], '{}'::text[], true),
    ('GHSA-z0', 2, 'NuGet', 'Zero', '[{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.0"}]}]', '{}'::text[], '{}'::text[], true),
    ('GHSA-z0', 3, 'RubyGems', 'zero', '[{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.0"}]}]', '{}'::text[], '{}'::text[], true)
  ) AS af (advisory_id, affected_index, ecosystem, package_name, version_ranges, listed_versions, keyed_versions, is_unaffected_provable);
INSERT INTO osv_affected_version_intervals (advisory_id, affected_index, interval_index, introduced_version_sortable, upper_version_sortable, upper_event, fixed_version)
SELECT iv.advisory_id, iv.affected_index, iv.interval_index,
       CASE WHEN iv.introduced_version IS NOT NULL THEN public.fn_osv_version_sortable(osvaf.ecosystem, iv.introduced_version) END,
       CASE WHEN iv.upper_version IS NOT NULL THEN public.fn_osv_version_sortable(osvaf.ecosystem, iv.upper_version) END,
       iv.upper_event, iv.fixed_version
  FROM (VALUES
    ('GHSA-z0', 0, 0, NULL::text, '1.0'::text, 'fixed'::text, '1.0'::text),
    ('GHSA-z0', 1, 0, NULL, '1.0', 'fixed', '1.0'),
    ('GHSA-z0', 2, 0, NULL, '1.0', 'fixed', '1.0'),
    ('GHSA-z0', 3, 0, NULL, '1.0', 'fixed', '1.0')
  ) AS iv (advisory_id, affected_index, interval_index, introduced_version, upper_version, upper_event, fixed_version)
  JOIN osv_affected AS osvaf ON osvaf.advisory_id = iv.advisory_id AND osvaf.affected_index = iv.affected_index;

DO $$
BEGIN
  ASSERT (SELECT array_agg(row(z.ecosystem, z.version_text, adv.affects_version)::text ORDER BY z.ordinal)
            FROM unnest(ARRAY['PyPI', 'PyPI', 'Maven', 'NuGet', 'RubyGems', 'PyPI'], ARRAY['zero-py', 'zero-py', 'org:zero', 'zero', 'zero', 'zero-py'],
                        ARRAY['0a1', '0.dev1', '0-SNAPSHOT', '0.0.0-beta', '0.a', '1.0'])
                 WITH ORDINALITY AS z (ecosystem, package_name, version_text, ordinal)
           CROSS JOIN LATERAL api.fn_package_check_advisory(z.ecosystem, z.package_name, z.version_text) AS adv)
         = ARRAY[row('PyPI', '0a1', true)::text, row('PyPI', '0.dev1', true)::text, row('Maven', '0-SNAPSHOT', true)::text,
                 row('NuGet', '0.0.0-beta', true)::text, row('RubyGems', '0.a', true)::text, row('PyPI', '1.0', false)::text],
         'a pre-release of 0 is inside a range that starts at an introduced 0, and the fixed version is outside it';
END
$$;

INSERT INTO osv_advisories (advisory_id, source, license, summary, aliases, published_time, modified_time) VALUES
  ('GHSA-nm1', 'ghsa', 'CC-BY-4.0', '', '{}'::text[], '2022-01-01T00:00:00Z', '2022-01-01T00:00:00Z'),
  ('GHSA-nr1', 'ghsa', 'CC-BY-4.0', '', '{}'::text[], '2022-01-01T00:00:00Z', '2022-01-01T00:00:00Z'),
  ('GHSA-sn1', 'ghsa', 'CC-BY-4.0', '', '{}'::text[], '2022-01-01T00:00:00Z', '2022-01-01T00:00:00Z'),
  ('GHSA-sx1', 'ghsa', 'CC-BY-4.0', '', '{}'::text[], '2022-01-01T00:00:00Z', '2022-01-01T00:00:00Z'),
  ('GO-nm2', 'go', 'CC-BY-4.0', '', ARRAY['GHSA-nm1'], '2022-01-01T00:00:00Z', '2022-01-01T00:00:00Z'),
  ('MAL-tie-a', 'mal', 'Apache-2.0', '', '{}'::text[], '2022-01-01T00:00:00Z', '2022-01-01T00:00:00Z'),
  ('MAL-tie-b', 'mal', 'Apache-2.0', '', '{}'::text[], '2022-01-01T00:00:00Z', '2022-01-01T00:00:00Z'),
  ('PYSEC-sn2', 'pysec', 'CC-BY-4.0', '', '{}'::text[], '2022-01-01T00:00:00Z', '2022-01-01T00:00:00Z');
INSERT INTO osv_affected (advisory_id, affected_index, ecosystem, package_name, version_ranges, listed_versions, listed_versions_sortable, is_unaffected_provable)
SELECT af.advisory_id, af.affected_index, af.ecosystem, af.package_name, af.version_ranges::jsonb, af.listed_versions,
       ARRAY(SELECT array_to_string(public.fn_osv_version_sortable(af.ecosystem, kv.version_text), ' ')
               FROM unnest(af.keyed_versions) WITH ORDINALITY AS kv (version_text, version_ordinal) ORDER BY kv.version_ordinal),
       af.is_unaffected_provable
  FROM (VALUES
    ('GHSA-nm1', 0, 'npm', 'nullmember', '[{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}]', '{}'::text[], '{}'::text[], true),
    ('GHSA-nr1', 0, 'npm', 'nullrow', '[{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}]', '{}'::text[], '{}'::text[], true),
    ('GHSA-nr1', 1, 'npm', 'nullrow', '[]', '{}'::text[], '{}'::text[], false),
    ('GHSA-nr1', 2, 'npm', 'nullrow', '[{"type": "SEMVER", "events": [{"introduced": "5.0.0"}, {"fixed": "6.0.0"}]}]', '{}'::text[], '{}'::text[], true),
    ('GHSA-sn1', 0, 'npm', 'samename', '[{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}]', '{}'::text[], '{}'::text[], true),
    ('GHSA-sx1', 0, 'npm', 'samex', '[{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}]', '{}'::text[], '{}'::text[], true),
    ('GHSA-sx1', 1, 'PyPI', 'samex', '[{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "9.0"}]}]', '{}'::text[], '{}'::text[], true),
    ('GO-nm2', 0, 'npm', 'nullmember', '[]', '{}'::text[], '{}'::text[], false),
    ('MAL-tie-a', 0, 'npm', 'mal-tie', '[]', '{}'::text[], '{}'::text[], false),
    ('MAL-tie-b', 0, 'npm', 'mal-tie', '[]', '{}'::text[], '{}'::text[], false),
    ('PYSEC-sn2', 0, 'PyPI', 'samename', '[]', '{}'::text[], '{}'::text[], false)
  ) AS af (advisory_id, affected_index, ecosystem, package_name, version_ranges, listed_versions, keyed_versions, is_unaffected_provable);
INSERT INTO osv_affected_version_intervals (advisory_id, affected_index, interval_index, introduced_version_sortable, upper_version_sortable, upper_event, fixed_version)
SELECT iv.advisory_id, iv.affected_index, iv.interval_index,
       CASE WHEN iv.introduced_version IS NOT NULL THEN public.fn_osv_version_sortable(osvaf.ecosystem, iv.introduced_version) END,
       CASE WHEN iv.upper_version IS NOT NULL THEN public.fn_osv_version_sortable(osvaf.ecosystem, iv.upper_version) END,
       iv.upper_event, iv.fixed_version
  FROM (VALUES
    ('GHSA-nm1', 0, 0, NULL::text, '2.0.0'::text, 'fixed'::text, '2.0.0'::text),
    ('GHSA-nr1', 0, 0, NULL, '2.0.0', 'fixed', '2.0.0'),
    ('GHSA-nr1', 2, 0, '5.0.0', '6.0.0', 'fixed', '6.0.0'),
    ('GHSA-sn1', 0, 0, NULL, '2.0.0', 'fixed', '2.0.0'),
    ('GHSA-sx1', 0, 0, NULL, '2.0.0', 'fixed', '2.0.0'),
    ('GHSA-sx1', 1, 0, NULL, '9.0', 'fixed', '9.0')
  ) AS iv (advisory_id, affected_index, interval_index, introduced_version, upper_version, upper_event, fixed_version)
  JOIN osv_affected AS osvaf ON osvaf.advisory_id = iv.advisory_id AND osvaf.affected_index = iv.affected_index;

DO $$
BEGIN
  ASSERT (SELECT row(adv.affects_version, adv.fixed_version, adv.fixed_version_sortable)::text FROM api.fn_package_check_advisory('npm', 'nullrow', '1.0.0') AS adv)
         = row(true, '2.0.0', public.fn_osv_version_sortable('npm', '2.0.0'))::text,
         'an advisory takes the fixed version and its sortable form from its affected row; a row whose answer is NULL or false does not take them away';
  ASSERT (SELECT row(jsonb_array_length(c.results -> 0 -> 'ranges'), c.results -> 0 -> 'fixed')::text FROM api.fn_package_check('npm', 'samex', '1.0.0', 20, 0) AS c)
         = row(1, '["2.0.0"]'::jsonb)::text,
         'a result lists the ranges and fixed versions of its own ecosystem, not those of a package of the same name in another one';
  ASSERT (SELECT c.malicious ->> 'id' FROM api.fn_package_check('npm', 'mal-tie', '1.0.0', 20, 0) AS c) = 'MAL-tie-a',
         'of two mal advisories published at the same time, malicious is the one with the lower id';
  ASSERT (SELECT row(r.affects_version, r.fixed_version, r.member_ids)::text FROM api.fn_package_check_result('npm', 'nullmember', ARRAY['1.0.0']) AS r)
         = row(true, '2.0.0', ARRAY['GHSA-nm1', 'GO-nm2'])::text,
         'a result takes the fixed version of its affected member, and a member whose answer is NULL does not take it away';
  ASSERT (SELECT pc.fixed_version FROM api.fn_package_check('npm', 'samename', '1.0.0', 20, 0) AS pc) = '2.0.0',
         'an advisory of a package of the same name in another ecosystem does not hold back the fixed version';
END
$$;

INSERT INTO osv_advisories (advisory_id, source, license, summary, aliases, published_time, modified_time) VALUES
  ('PYSEC-long1', 'pysec', 'CC-BY-4.0', '', '{}'::text[], '2022-01-01T00:00:00Z', '2022-01-01T00:00:00Z');
INSERT INTO osv_affected (advisory_id, affected_index, ecosystem, package_name, version_ranges, listed_versions, listed_versions_sortable, is_unaffected_provable)
SELECT af.advisory_id, af.affected_index, af.ecosystem, af.package_name, af.version_ranges::jsonb, af.listed_versions,
       ARRAY(SELECT array_to_string(public.fn_osv_version_sortable(af.ecosystem, kv.version_text), ' ')
               FROM unnest(af.keyed_versions) WITH ORDINALITY AS kv (version_text, version_ordinal) ORDER BY kv.version_ordinal),
       af.is_unaffected_provable
  FROM (VALUES
    ('PYSEC-long1', 0, 'PyPI', 'longlist-a', '[{"type": "ECOSYSTEM", "events": [{"introduced": "2.0"}, {"fixed": "2.5"}]}]', ARRAY['2.0', '1.00' || repeat('.0', 62)], ARRAY['2.0', '1.00' || repeat('.0', 62)], true),
    ('PYSEC-long1', 1, 'PyPI', 'longlist-b', '[{"type": "ECOSYSTEM", "events": [{"introduced": "2.0"}, {"fixed": "2.5"}]}]', ARRAY['2.0', '1.000' || repeat('.0', 62)], ARRAY['2.0'], false)
  ) AS af (advisory_id, affected_index, ecosystem, package_name, version_ranges, listed_versions, keyed_versions, is_unaffected_provable);
INSERT INTO osv_affected_version_intervals (advisory_id, affected_index, interval_index, introduced_version_sortable, upper_version_sortable, upper_event, fixed_version)
SELECT iv.advisory_id, iv.affected_index, iv.interval_index,
       CASE WHEN iv.introduced_version IS NOT NULL THEN public.fn_osv_version_sortable(osvaf.ecosystem, iv.introduced_version) END,
       CASE WHEN iv.upper_version IS NOT NULL THEN public.fn_osv_version_sortable(osvaf.ecosystem, iv.upper_version) END,
       iv.upper_event, iv.fixed_version
  FROM (VALUES
    ('PYSEC-long1', 0, 0, '2.0'::text, '2.5'::text, 'fixed'::text, '2.5'::text),
    ('PYSEC-long1', 1, 0, '2.0', '2.5', 'fixed', '2.5')
  ) AS iv (advisory_id, affected_index, interval_index, introduced_version, upper_version, upper_event, fixed_version)
  JOIN osv_affected AS osvaf ON osvaf.advisory_id = iv.advisory_id AND osvaf.affected_index = iv.affected_index;

DO $$
BEGIN
  ASSERT (SELECT array_agg(row(z.package_name, octet_length(osvaf.listed_versions[2]), adv.affects_version)::text ORDER BY z.package_name)
            FROM unnest(ARRAY['longlist-a', 'longlist-b']) AS z (package_name)
            JOIN osv_affected AS osvaf ON osvaf.advisory_id = 'PYSEC-long1' AND osvaf.package_name = z.package_name
           CROSS JOIN LATERAL api.fn_package_check_advisory('PyPI', z.package_name, '1.0') AS adv)
         = ARRAY[row('longlist-a', 128, true)::text, row('longlist-b', 129, NULL)::text],
         'a listed version of 128 bytes has a form, so a lookup of 1.0 finds it; one of 129 bytes has none, so 1.0 may be affected, not unaffected';
END
$$;

PREPARE t_package_check_query AS SELECT * FROM api.fn_package_check($1, $2, $3, $4, $5);
CREATE TEMP TABLE t_package_check_answer AS EXECUTE t_package_check_query('npm', 'left-pad', NULL, '1', '0');
DEALLOCATE t_package_check_query;

DO $$
BEGIN
  ASSERT (SELECT row(a.result_count, jsonb_array_length(a.results))::text FROM t_package_check_answer AS a) = row(5, 1)::text,
         'the query db_PACKAGECHECK sends answers the page of its package';
  ASSERT (SELECT p.prosecdef AND NOT p.proisstrict AND p.provolatile = 's' AND p.proconfig = ARRAY['search_path=pg_catalog']
            FROM pg_proc AS p WHERE p.oid = 'api.fn_package_check(text, text, text, integer, integer)'::regprocedure),
         'api.fn_package_check is SECURITY DEFINER, not STRICT, STABLE and sets search_path to pg_catalog';
  ASSERT (SELECT NOT p.prosecdef AND NOT p.proisstrict AND p.provolatile = 's' AND p.prorows = 50 AND p.proconfig = ARRAY['search_path=pg_catalog']
            FROM pg_proc AS p WHERE p.oid = 'api.fn_package_check_advisory(text, text, text)'::regprocedure),
         'api.fn_package_check_advisory is SECURITY INVOKER, not STRICT, STABLE, estimates 50 rows and sets search_path to pg_catalog';
  ASSERT (SELECT array_agg(row(p.proname, NOT p.prosecdef AND NOT p.proisstrict AND p.provolatile = 's' AND p.proconfig = ARRAY['search_path=pg_catalog'], p.prorows)::text
                           ORDER BY p.proname)
            FROM pg_proc AS p
           WHERE p.oid IN ('api.fn_package_check_group(text, text)'::regprocedure, 'api.fn_package_check_result(text, text, text[])'::regprocedure,
                           'api.fn_package_check_ranges(text, text, text)'::regprocedure,
                           'api.fn_package_check_versions(text, text, text[], integer, integer)'::regprocedure))
         = ARRAY[row('fn_package_check_group', true, 50)::text, row('fn_package_check_ranges', true, 1)::text, row('fn_package_check_result', true, 50)::text,
                 row('fn_package_check_versions', true, 1)::text],
         'the three helpers and api.fn_package_check_versions are SECURITY INVOKER, not STRICT, STABLE, set search_path to pg_catalog, and estimate 50, 1, 50 and 1 rows';
END
$$;

INSERT INTO eol_product (product_name, product_label, url) VALUES
  ('e-pk', 'Pk', 'https://endoflife.date/e-pk'), ('e-pk-a', 'Pk A', 'https://endoflife.date/e-pk-a'),
  ('e-pk-b', 'Pk B', 'https://endoflife.date/e-pk-b'), ('e-pkwin', 'Pk Win', 'https://endoflife.date/e-pkwin');
INSERT INTO eol_cycle (eol_product, cycle_name, release_date, eol_date, is_eol, is_maintained, is_lts, latest_version) VALUES
  ('e-pk', '4.2', current_date - 1000, current_date + 100, false, true, true, '4.2.7'),
  ('e-pk', '5.0', current_date - 100, NULL, false, true, false, '5.0.1'),
  ('e-pk', '3.2', current_date - 2000, current_date - 10, false, false, false, '3.2.25'),
  ('e-pk-a', '1', current_date - 10, NULL, false, true, false, NULL),
  ('e-pk-b', '1', current_date - 10, NULL, false, true, false, NULL),
  ('e-pkwin', '11-24h2-w', current_date - 300, current_date + 10, false, true, false, '26100.1'),
  ('e-pkwin', '11-24h2-e', current_date - 300, current_date + 20, false, true, true, '26100.2');
INSERT INTO eol_product_package (ecosystem, package_name, eol_product) VALUES
  ('npm', 'left-pad', 'e-pk'), ('PyPI', 'Django_Pkg', 'e-pk'), ('npm', 'twoprod', 'e-pk-b'), ('npm', 'twoprod', 'e-pk-a'),
  ('npm', 'winpkg', 'e-pkwin');

CREATE FUNCTION pg_temp.t_package_eol(p_ecosystem text, p_package_name text, p_version text, p_row_count integer) RETURNS text[]
  LANGUAGE sql STABLE
  RETURN (SELECT coalesce(array_agg(row(e.row_kind, e.name, e.url, e.eol_date, e.is_eol, e.is_maintained, e.is_lts, e.latest_version,
                                        e.maintained_cycle_count)::text ORDER BY e.ordinality), '{}')
            FROM api.fn_package_check_eol(p_ecosystem, p_package_name, p_version, p_row_count) WITH ORDINALITY AS e);

DO $$
DECLARE
  eol_attribution jsonb := '{"source": "endoflife.date", "license": "MIT", "url": "https://endoflife.date",
                             "notice": "Retrieved from endoflife.date. ContrastAPI selected the fields and matched the release cycles to the package. No warranty; the source does not endorse ContrastAPI."}';
  answer          record;
BEGIN
  ASSERT pg_get_function_result('api.fn_package_check_eol(text, text, text, integer)'::regprocedure)
         = pg_get_function_result('api.fn_product_exposure_eol(text, text, text, integer)'::regprocedure),
         'api.fn_package_check_eol answers the columns of api.fn_product_exposure_eol, so one reader reads both';
  ASSERT pg_temp.t_package_eol('npm', 'left-pad', '4.2.7', 10)
         = ARRAY[row('product', 'e-pk', 'https://endoflife.date/e-pk', NULL, NULL, NULL, NULL, NULL, 2)::text,
                 row('series', '4.2', NULL, to_char(current_date + 100, 'YYYY-MM-DD'), false, true, true, '4.2.7', NULL)::text,
                 row('maintained', '5.0', NULL, NULL, false, true, false, '5.0.1', NULL)::text,
                 row('maintained', '4.2', NULL, to_char(current_date + 100, 'YYYY-MM-DD'), false, true, true, '4.2.7', NULL)::text],
         'a mapped package answers its product, the cycle its version picks and the maintained cycles, newest first';
  ASSERT pg_temp.t_package_eol('npm', 'left-pad', '3.2.1', 0)
         = ARRAY[row('product', 'e-pk', 'https://endoflife.date/e-pk', NULL, NULL, NULL, NULL, NULL, 2)::text,
                 row('series', '3.2', NULL, to_char(current_date - 10, 'YYYY-MM-DD'), true, false, false, '3.2.25', NULL)::text],
         'another version picks its own cycle, EOL by its date; a row count of 0 answers no maintained row';
  ASSERT pg_temp.t_package_eol('npm', 'left-pad', NULL, 10)
         = (pg_temp.t_package_eol('npm', 'left-pad', '4.2.7', 10))[1:1] || (pg_temp.t_package_eol('npm', 'left-pad', '4.2.7', 10))[3:4],
         'no version answers no series row, and still the maintained cycles';
  ASSERT pg_temp.t_package_eol('npm', 'left-pad', '9.9', 10) = pg_temp.t_package_eol('npm', 'left-pad', NULL, 10),
         'a version that picks no cycle answers no series row';
  ASSERT pg_temp.t_package_eol('NPM', 'left-pad', '4.2.7', 10) = pg_temp.t_package_eol('npm', 'left-pad', '4.2.7', 10),
         'the ecosystem matches in any letter case';
  ASSERT (pg_temp.t_package_eol('pypi', 'django.pkg', NULL, 0))[1] = row('product', 'e-pk', 'https://endoflife.date/e-pk', NULL, NULL, NULL, NULL, NULL, 2)::text,
         'the name matches through fn_osv_normalize_package_name';
  ASSERT pg_temp.t_package_eol('npm', 'twoprod', NULL, 10)
         = ARRAY[row('product', 'e-pk-a', 'https://endoflife.date/e-pk-a', NULL, NULL, NULL, NULL, NULL, 1)::text,
                 row('maintained', '1', NULL, NULL, false, true, false, NULL, NULL)::text],
         'a package of two products answers the one fn_eol_product_package_pick picks';
  ASSERT ARRAY(SELECT e.name FROM api.fn_package_check_eol('npm', 'winpkg', '11-24h2', 0) AS e WHERE e.row_kind = 'series') = ARRAY['11-24h2-w', '11-24h2-e'],
         'a version naming a series answers each cycle of the series, by date';
  ASSERT pg_temp.t_package_eol('npm', 'no-such', '1.0', 10) = '{}', 'a package that maps to no product answers no row';
  ASSERT pg_temp.t_package_eol('PyPI', 'left-pad', '4.2.7', 10) = '{}', 'the same name in another ecosystem maps to no product';
  ASSERT pg_temp.t_package_eol('Pub', 'left-pad', '4.2.7', 10) = '{}', 'an unknown ecosystem answers no row';
  ASSERT pg_temp.t_package_eol(NULL, 'left-pad', '4.2.7', 10) = '{}' AND pg_temp.t_package_eol('npm', NULL, '4.2.7', 10) = '{}',
         'a NULL ecosystem or name answers no row';

  SELECT * INTO answer FROM api.fn_package_check('npm', 'left-pad', NULL, 20, 0);
  ASSERT answer.attribution -> 0 = eol_attribution, 'a mapped package lists endoflife.date first in attribution, with MIT, its link and the notice';
  ASSERT (SELECT count(*) FROM jsonb_array_elements(answer.attribution) AS a (attribution_json) WHERE a.attribution_json ->> 'source' = 'endoflife.date') = 1,
         'endoflife.date is listed once';
  ASSERT jsonb_array_length(answer.attribution) > 1, 'the sources of the advisories stay listed';
  ASSERT (SELECT c.attribution FROM api.fn_package_check('npm', 'left-pad', '4.2.7', 20, 0) AS c) -> 0 = eol_attribution,
         'a request with a version lists endoflife.date too';
  ASSERT (SELECT c.attribution FROM api.fn_package_check('pypi', 'django.pkg', NULL, 20, 0) AS c) = jsonb_build_array(eol_attribution),
         'a mapped package with no advisory lists only endoflife.date';
  ASSERT (SELECT c.attribution FROM api.fn_package_check('npm', 'no-such', NULL, 20, 0) AS c) = '[]',
         'a package that maps to no product lists no endoflife.date';
  ASSERT (SELECT c.attribution FROM api.fn_package_check('PyPI', 'left-pad', NULL, 20, 0) AS c) = '[]',
         'the same name in another ecosystem lists no endoflife.date';
END
$$;

PREPARE t_package_check_eol_query AS SELECT * FROM api.fn_package_check_eol($1, $2, $3, $4);
CREATE TEMP TABLE t_package_check_eol_answer AS EXECUTE t_package_check_eol_query('npm', 'left-pad', NULL, '10');
DEALLOCATE t_package_check_eol_query;

DO $$
BEGIN
  ASSERT (SELECT array_agg(a.row_kind ORDER BY a.row_kind) FROM t_package_check_eol_answer AS a) = ARRAY['maintained', 'maintained', 'product'],
         'the eol query db_PACKAGECHECK sends answers the product and its maintained cycles';
  ASSERT (SELECT p.prosecdef AND NOT p.proisstrict AND p.provolatile = 's' AND p.proconfig = ARRAY['search_path=pg_catalog']
            FROM pg_proc AS p WHERE p.oid = 'api.fn_package_check_eol(text, text, text, integer)'::regprocedure),
         'api.fn_package_check_eol is SECURITY DEFINER, not STRICT, STABLE and sets search_path to pg_catalog';
END
$$;

DELETE FROM eol_product WHERE product_name IN ('e-pk', 'e-pk-a', 'e-pk-b', 'e-pkwin');

DELETE FROM osv_advisories;
