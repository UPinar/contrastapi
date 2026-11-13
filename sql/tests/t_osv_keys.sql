DO $$
DECLARE
  sorted_versions text[] := ARRAY['0.0.0-20191109021931-daa7c04131f5', '0.0.0', '1.0.0-0.3.7', '1.0.0-Beta', '1.0.0-alpha',
                                  '1.0.0-alpha.1', '1.0.0-alpha.beta', '1.0.0-beta', '1.0.0-beta.2', '1.0.0-beta.11',
                                  '1.0.0-rc.1', '1.0.0', '1.9.0', '1.10.0', '2.0.0', repeat('9', 99) || '.0.0'];
BEGIN
  ASSERT (SELECT array_agg(v.version_text ORDER BY public.fn_osv_version_sortable('npm', v.version_text) COLLATE "C")
            FROM unnest(ARRAY[sorted_versions[12], sorted_versions[4], sorted_versions[16], sorted_versions[1], sorted_versions[9],
                              sorted_versions[14], sorted_versions[2], sorted_versions[7], sorted_versions[11], sorted_versions[3],
                              sorted_versions[15], sorted_versions[6], sorted_versions[10], sorted_versions[5], sorted_versions[13],
                              sorted_versions[8]]) AS v (version_text))
         = sorted_versions,
         'the sortable forms sort the versions as Semantic Versioning does: numbers by value, a pre-release before its release, an upper case letter before a lower case one';
  ASSERT public.fn_osv_version_sortable('npm', '1.0.0-Beta') COLLATE "C" < public.fn_osv_version_sortable('npm', '1.0.0-alpha') COLLATE "C",
         'under COLLATE "C" 1.0.0-Beta sorts before 1.0.0-alpha';
  ASSERT public.fn_osv_version_sortable('npm', '1.0.0+build.5') = public.fn_osv_version_sortable('npm', '1.0.0'),
         'build metadata does not count';
  ASSERT public.fn_osv_version_sortable('npm', '1.0.0') = ARRAY['0011', '000', '000', 'b_release']
     AND public.fn_osv_version_sortable('npm', '10.0.0-x.7') = ARRAY['00210', '000', '000', 'a_prerelease', '1x', '0017'],
         'a number is 0, its digit count in two digits and its digits; a text is 1 and its text; the fourth element marks a pre-release';
  ASSERT public.fn_osv_version_sortable('Go', 'v1.2.3') = public.fn_osv_version_sortable('npm', '1.2.3')
     AND public.fn_osv_version_sortable('Go', 'v2.0.0+incompatible') = public.fn_osv_version_sortable('npm', '2.0.0'),
         'a Go version loses its leading v, and +incompatible is build metadata';
  ASSERT public.fn_osv_version_sortable('npm', 'v1.2.3') IS NULL,
         'only a Go version loses a leading v';
  ASSERT (SELECT array_agg(row(e.ecosystem, public.fn_osv_version_sortable(e.ecosystem, '1.0.0'))::text ORDER BY e.ecosystem_ordinal)
            FROM unnest(ARRAY['PyPI', 'Maven', 'NuGet', 'RubyGems', 'Packagist', 'npm', 'Go', 'crates.io', 'SwiftURL'])
                 WITH ORDINALITY AS e (ecosystem, ecosystem_ordinal))
         = ARRAY[row('PyPI', ARRAY['000', '0011', '!', '3', '1', '3', '1'])::text,
                 row('Maven', ARRAY['20011', '4'])::text,
                 row('NuGet', ARRAY['0011', '000', '000', '000', '2'])::text,
                 row('RubyGems', ARRAY['50011', '3'])::text,
                 row('Packagist', ARRAY['0011', '000', '000', '5'])::text,
                 row('npm', ARRAY['0011', '000', '000', 'b_release'])::text,
                 row('Go', ARRAY['0011', '000', '000', 'b_release'])::text,
                 row('crates.io', ARRAY['0011', '000', '000', 'b_release'])::text,
                 row('SwiftURL', ARRAY['0011', '000', '000', 'b_release'])::text],
         'fn_osv_version_sortable answers PyPI, Maven, NuGet, RubyGems and Packagist with their own forms, and npm, Go, crates.io and SwiftURL with the semver form';
  ASSERT (SELECT bool_and(public.fn_osv_version_sortable(e.ecosystem, '1.0.0') IS NULL)
            FROM unnest(ARRAY['npm ', 'pypi', 'Pub', '']) AS e (ecosystem)),
         'an ecosystem outside the nine, a name with a space or in another case, has no sortable form';
  ASSERT public.fn_osv_semver_sortable('npm', '10.0.0-x.7') = ARRAY['00210', '000', '000', 'a_prerelease', '1x', '0017']
     AND public.fn_osv_semver_sortable('Go', 'v2.0.0+incompatible') = ARRAY['0012', '000', '000', 'b_release']
     AND public.fn_osv_semver_sortable('PyPI', '1.0.0') IS NULL
     AND public.fn_osv_semver_sortable('npm', '1.0.0-01') IS NULL,
         'fn_osv_semver_sortable keeps the old semver answers, and gives no form for an ecosystem outside npm, Go, crates.io and SwiftURL';
  ASSERT (SELECT bool_and(public.fn_osv_version_sortable('npm', v.version_text) IS NULL)
            FROM unnest(ARRAY['1.0', '1.2.3.4', '01.0.0', '1.0.0-', '1.0.0-01', '1.0.0-alpha..1', '^1.2.3', '=1.2.3', '0', '',
                              repeat('9', 100) || '.0.0', '1.0.0-' || repeat('1', 100)]) AS v (version_text)),
         'a version Semantic Versioning refuses, or one with a number of more than 99 digits, has no sortable form';
  ASSERT public.fn_osv_version_sortable('npm', '1.0.0-0') IS NOT NULL AND public.fn_osv_version_sortable('npm', NULL) IS NULL,
         'a pre-release number 0 has a sortable form; NULL has none';
  ASSERT (SELECT p.provolatile = 'i' AND NOT p.proisstrict AND NOT p.prosecdef AND p.proconfig = ARRAY['search_path=pg_catalog']
                 AND l.lanname = 'plpgsql'
            FROM pg_proc AS p JOIN pg_language AS l ON l.oid = p.prolang WHERE p.oid = 'public.fn_osv_version_sortable(text, text)'::regprocedure),
         'fn_osv_version_sortable is PL/pgSQL, IMMUTABLE, SECURITY INVOKER and sets search_path to pg_catalog';

  ASSERT (SELECT array_agg(public.fn_osv_normalize_package_name(n.ecosystem, n.package_name) ORDER BY n.package_ordinal)
            FROM unnest(ARRAY['PyPI', 'npm', 'NuGet', 'Packagist', 'Go', 'Maven', 'RubyGems', 'crates.io', 'SwiftURL'],
                        ARRAY['Foo__Bar.-baz', 'Lodash', 'Newtonsoft.Json', 'KnpLabs/Snappy', 'Foo_Bar', 'Org:Foo_Bar', 'Foo_Bar',
                              'Foo_Bar', 'github.com/Foo/Bar']) WITH ORDINALITY AS n (ecosystem, package_name, package_ordinal))
         = ARRAY['foo-bar-baz', 'lodash', 'newtonsoft.json', 'knplabs/snappy', 'Foo_Bar', 'Org:Foo_Bar', 'Foo_Bar', 'Foo_Bar',
                 'github.com/Foo/Bar'],
         'PyPI lowers a name and joins each run of -, _ and . into one -; npm, NuGet and Packagist lower it; the others keep it';
  ASSERT (SELECT p.provolatile = 'i' AND NOT p.proisstrict AND NOT p.prosecdef AND p.proconfig = ARRAY['search_path=pg_catalog']
            FROM pg_proc AS p WHERE p.oid = 'public.fn_osv_normalize_package_name(text, text)'::regprocedure),
         'fn_osv_normalize_package_name is IMMUTABLE, SECURITY INVOKER and sets search_path to pg_catalog';
END
$$;

DO $$
BEGIN
  ASSERT (SELECT array_agg(public.fn_osv_number_sortable(n.number_text) ORDER BY n.number_ordinal)
            FROM unnest(ARRAY['0', '000', '11', '007', repeat('9', 99), '0' || repeat('9', 99), repeat('9', 100)]) WITH ORDINALITY AS n (number_text, number_ordinal))
         = ARRAY['000', '000', '00211', '0017', '099' || repeat('9', 99), '099' || repeat('9', 99), NULL],
         'fn_osv_number_sortable writes 0, the digit count in two digits and the digits without leading zeros, and gives no form past 99 digits';
  ASSERT public.fn_osv_number_sortable(NULL) IS NULL
     AND (SELECT l.lanname = 'sql' AND p.provolatile = 'i' AND p.proisstrict FROM pg_proc AS p JOIN pg_language AS l ON l.oid = p.prolang
           WHERE p.oid = 'public.fn_osv_number_sortable(text)'::regprocedure),
         'fn_osv_number_sortable is STRICT, so NULL has no form';
END
$$;

DO $$
DECLARE
  sorted_versions text[] := ARRAY['0.9', '1.0.dev0', '1.0a0', '1.0a1.dev2', '1.0a1', '1.0b1', '1.0rc1', '1.0', '1.0+abc', '1.0+abc.7',
                                  '1.0+1', '1.0.post1.dev1', '1.0.post1', '1.0.1', '1.9', '1.10', '2.0', '1!0.1'];
BEGIN
  ASSERT (SELECT array_agg(v.version_text ORDER BY public.fn_osv_pep440_sortable(v.version_text) COLLATE "C")
            FROM unnest(ARRAY(SELECT s.version_text FROM unnest(sorted_versions) AS s (version_text) ORDER BY md5(s.version_text))) AS v (version_text))
         = sorted_versions
     AND (SELECT count(DISTINCT public.fn_osv_pep440_sortable(v.version_text)) FROM unnest(sorted_versions) AS v (version_text)) = cardinality(sorted_versions),
         'fn_osv_pep440_sortable sorts versions as PEP 440 does: dev before pre before release, a local version after its release, a letter segment before a number';
  ASSERT (SELECT array_agg(public.fn_osv_pep440_sortable(v.version_text)::text ORDER BY v.version_index)
            FROM unnest(ARRAY['1.0.dev', '1.0.rev', '1.2.post3.dev4', '1!1.0+loc_al.7']) WITH ORDINALITY AS v (version_text, version_index))
         = ARRAY['{000,0011,!,1,1,2000,1}', '{000,0011,!,3,2000,3,1}', '{000,0011,0012,!,3,20013,20014,1}', '{0011,0011,!,3,1,3,2,1loc,1al,20017}'],
         'fn_osv_pep440_sortable writes the epoch, the release, !, the pre, post and dev parts and the local segments; 1.0.dev and 1.0.rev keep their final v and get the number 0';
  ASSERT (SELECT bool_and(coalesce(public.fn_osv_pep440_sortable(p.left_version) = public.fn_osv_pep440_sortable(p.right_version), false))
            FROM (VALUES ('1.0', '1.0.0'), ('1.0a1', '1.0.0-alpha.1'), ('1.0b2', '1.0.0-beta.2'), ('1.0RC1', '1.0c1'), ('1.0rc1', '1.0pre1'),
                         ('1.0rc1', '1.0preview1'), ('1.0-1', '1.0.post1'), ('1.0.rev', '1.0.post0'), ('1.0.dev', '1.0.dev0'), ('v1.0', '1.0'),
                         (E' \t1.0\n\x0b', '1.0'), ('1.0+LOCAL', '1.0+local'), ('1', '1.00'), ('1.0a', '1.0a0')) AS p (left_version, right_version)),
         'fn_osv_pep440_sortable gives one form to the spellings PEP 440 calls equal, with the white space and a leading v dropped';
  ASSERT (SELECT bool_and(public.fn_osv_pep440_sortable(v.version_text) IS NULL)
            FROM unnest(ARRAY['', 'abc', '1.0+', '1.0-', '1.0.', '1.0+a$', 'x1.0', '1.0 1', repeat('9', 100), '1.' || repeat('9', 100), NULL]) AS v (version_text))
     AND public.fn_osv_pep440_sortable('1.' || repeat('9', 99)) IS NOT NULL,
         'fn_osv_pep440_sortable gives no form to a version PEP 440 refuses, to one with a number past 99 digits, or to NULL';
END
$$;

DO $$
DECLARE
  sorted_versions text[] := ARRAY['1-alpha-1', '1-alpha-2', '1-beta-1', '1-milestone-1', '1-rc-1', '1-SNAPSHOT', '1', '1-sp', '1-xyz',
                                  '1-1', '1-2', '1.1', '1.2', '1.10', '2', '10'];
BEGIN
  ASSERT (SELECT array_agg(v.version_text ORDER BY public.fn_osv_maven_sortable(v.version_text) COLLATE "C")
            FROM unnest(ARRAY(SELECT s.version_text FROM unnest(sorted_versions) AS s (version_text) ORDER BY md5(s.version_text))) AS v (version_text))
         = sorted_versions
     AND (SELECT count(DISTINCT public.fn_osv_maven_sortable(v.version_text)) FROM unnest(sorted_versions) AS v (version_text)) = cardinality(sorted_versions),
         'fn_osv_maven_sortable sorts versions as scalibr does: alpha, beta, milestone, rc, snapshot, the release, sp, another qualifier, a - number, a . number';
  ASSERT (SELECT array_agg(public.fn_osv_maven_sortable(v.version_text)::text ORDER BY v.version_index)
            FROM unnest(ARRAY['2.0.RC1', '1.0.ga.1', '2.0.sp', '1..2', '1.a1', '1.ga.1', '2.sp', '2.v1', '2-alpha', '1m3', '1-snapshot',
                              '2-sp', '2-jre', '1-a', '1-+x', '9.2.0-redhat-1'])
                 WITH ORDINALITY AS v (version_text, version_index))
         = ARRAY['{20012,3,13,70011,4}', '{20011,3,15,80011,4}', '{20012,8000,50,4}', '{20011,8000,80012,4}', '{20011,10,70011,4}',
                 '{20011,15,80011,4}', '{20012,50,4}', '{20012,51v,70011,4}', '{20012,20,4}', '{20011,22,70013,4}', '{20011,24,4}',
                 '{20012,60,4}', '{20012,61jre,4}', '{20011,61a,4}', '{20011,61+x,4}', '{20019,80012,61redhat,70011,4}'],
         'fn_osv_maven_sortable writes each token with its class: .0 before a pre-release 3, . keyword 1, .sp 50, . text 51, - keyword 2, -sp 60, - text 61, - number 7, . number 8, end 4';
  ASSERT (SELECT bool_and(coalesce(public.fn_osv_maven_sortable(p.left_version) = public.fn_osv_maven_sortable(p.right_version), false))
            FROM (VALUES ('1', '1.0.0'), ('1', '1.00'), ('1', '1-ga'), ('1', '1.Final'), ('1', '1.RELEASE'), ('1', '1-'), ('1.0-cr1', '1-rc-1'),
                         ('1a1', '1-alpha-1'), ('1b2', '1-beta-2'), ('1M3', '1-milestone-3'), ('1.1', '1.01'), ('1x', '1.0-x'),
                         ('1.0-SNAPSHOT', '1-snapshot'), ('1-1', '1.0-1')) AS p (left_version, right_version)),
         'fn_osv_maven_sortable gives one form to the spellings scalibr calls equal: trailing zeros, ga, final, release, cr, a, b, m and case';
  ASSERT public.fn_osv_maven_sortable('2.0.0.RC1') = ARRAY['20012', '3', '3', '13', '70011', '4']
     AND public.fn_osv_maven_sortable('2.0.0.RC1') COLLATE "C" < public.fn_osv_maven_sortable('2') COLLATE "C",
         'fn_osv_maven_sortable writes 3 for each .0 of a run of .0 before a pre-release, so 2.0.0.RC1 sorts before 2';
  ASSERT (SELECT bool_and(public.fn_osv_maven_sortable(v.version_text) IS NULL)
            FROM unnest(ARRAY['latest', 'RELEASE', 'v2.14.1', '.1', 'log4j-2.14.1', '1$', '1 2', '1-ga.1', '1.+x', '1-' || repeat('x', 255),
                              '1-' || repeat('9', 100), NULL]) AS v (version_text))
     AND public.fn_osv_maven_sortable('1-' || repeat('x', 254)) IS NOT NULL
     AND public.fn_osv_maven_sortable('1-' || repeat('9', 99)) IS NOT NULL,
         'fn_osv_maven_sortable gives no form to a version that starts with a letter or a dot, holds another character, has an empty qualifier inside a - part or a .+ qualifier, or is past 256 characters or 99 digits';
END
$$;

DO $$
BEGIN
  ASSERT (SELECT array_agg(row(p.left_version, p.right_version,
                               public.fn_osv_maven_order_is_uncertain(public.fn_osv_maven_sortable(p.left_version), public.fn_osv_maven_sortable(p.right_version)),
                               public.fn_osv_maven_order_is_uncertain(public.fn_osv_maven_sortable(p.right_version), public.fn_osv_maven_sortable(p.left_version)))::text
                           ORDER BY p.pair_ordinal)
            FROM (VALUES (1, '2.0.RC1', '2-1'), (2, '2.0.RC1', '2-jre'), (3, '2.0.RC1', '2.v1'), (4, '2.0.RC1', '2.sp'), (5, '2-alpha', '2.v1'),
                         (6, '2.0.0.RC1', '2.0.v1'), (7, '9.2.0.CR1', '9.2.0-redhat-1')) AS p (pair_ordinal, left_version, right_version))
         = ARRAY[row('2.0.RC1', '2-1', true, true)::text, row('2.0.RC1', '2-jre', true, true)::text, row('2.0.RC1', '2.v1', true, true)::text,
                 row('2.0.RC1', '2.sp', true, true)::text, row('2-alpha', '2.v1', true, true)::text, row('2.0.0.RC1', '2.0.v1', true, true)::text,
                 row('9.2.0.CR1', '9.2.0-redhat-1', true, true)::text],
         'fn_osv_maven_order_is_uncertain is true, both ways round, for a .0 before a pre-release against a - number, a - or . qualifier, and for a - pre-release against a . qualifier';
  ASSERT (SELECT bool_and(NOT public.fn_osv_maven_order_is_uncertain(public.fn_osv_maven_sortable(p.left_version), public.fn_osv_maven_sortable(p.right_version))
                          AND NOT public.fn_osv_maven_order_is_uncertain(public.fn_osv_maven_sortable(p.right_version), public.fn_osv_maven_sortable(p.left_version)))
            FROM (VALUES ('2.0.RC1', '2'), ('2.0.RC1', '2.1'), ('2.0.RC1', '2.0.1'), ('2.0.RC1', '2-alpha'), ('2-alpha', '2-1'), ('2-alpha', '2-jre'),
                         ('1', '2'), ('2-1', '2-1'), ('9.2.0.CR1', '9.2.0.Final'), ('2.0.RC1', 'latest')) AS p (left_version, right_version))
     AND NOT public.fn_osv_maven_order_is_uncertain(NULL, NULL),
         'fn_osv_maven_order_is_uncertain is false against the end, a . number, a - pre-release, between - tokens, for equal forms, and when a form is NULL';
  ASSERT NOT public.fn_osv_maven_order_is_uncertain(ARRAY['3', '4'], ARRAY['50', '4'])
     AND public.fn_osv_maven_order_is_uncertain(ARRAY['20011', '3', '4'], ARRAY['20011', '50', '4']),
         'fn_osv_maven_order_is_uncertain never counts the first token, where the same pair of classes counts later';
END
$$;

DO $$
DECLARE
  sorted_versions text[] := ARRAY['0.9.9.1', '1.0.0-2', '1.0.0-10', '1.0.0-alpha', '1.0.0-beta', '1.0.0-beta.1', '1.0.0-beta.x', '1.0.0-beta2',
                                  '1.0.0', '1.0.0.1-alpha', '1.0.0.1', '1.0.1', '1.999.9999', '2.1.1'];
BEGIN
  ASSERT (SELECT array_agg(v.version_text ORDER BY public.fn_osv_nuget_sortable(v.version_text) COLLATE "C")
            FROM unnest(ARRAY(SELECT s.version_text FROM unnest(sorted_versions) AS s (version_text) ORDER BY md5(s.version_text))) AS v (version_text))
         = sorted_versions
     AND (SELECT count(DISTINCT public.fn_osv_nuget_sortable(v.version_text)) FROM unnest(sorted_versions) AS v (version_text)) = cardinality(sorted_versions),
         'fn_osv_nuget_sortable sorts versions as scalibr does: four numbers, a pre-release before its release, digits before letters, numbers by value';
  ASSERT (SELECT array_agg(public.fn_osv_nuget_sortable(v.version_text)::text ORDER BY v.version_index)
            FROM unnest(ARRAY['1.2', '1.0.0.1-Beta.11.0', 'v1.0.0-x-y']) WITH ORDINALITY AS v (version_text, version_index))
         = ARRAY['{0011,0012,000,000,2}', '{0011,000,000,0011,1,2beta,100211,1000}', '{0011,000,000,000,1,2x-y}'],
         'fn_osv_nuget_sortable writes four numbers, then 2 for a release, or 1 and each pre-release part: 1 and a number, 2 and a text in lower case';
  ASSERT (SELECT bool_and(coalesce(public.fn_osv_nuget_sortable(p.left_version) = public.fn_osv_nuget_sortable(p.right_version), false))
            FROM (VALUES ('1.0', '1.0.0.0'), ('1.0.01', '1.0.1'), ('1.0.0-BETA', '1.0.0-beta+aa'), ('1.0.0', '1.0.0+beta'), ('v1.0', '1.0'),
                         ('1.0.0.1-1.2.A', '1.0.0.1-1.2.a+A')) AS p (left_version, right_version)),
         'fn_osv_nuget_sortable gives one form to the spellings scalibr calls equal: missing numbers, leading zeros, case, build metadata and a v';
  ASSERT (SELECT bool_and(public.fn_osv_nuget_sortable(v.version_text) IS NULL)
            FROM unnest(ARRAY['V1.0', ' 1.0', '1.0.0.0.0', '1.0.0-', '1.0.0-a..b', '1.0.0-rc_1', '1.0.0-01', '1.0.0--1', '1.0.0+',
                              repeat('9', 100), '1.0.0-' || repeat('9', 100), NULL]) AS v (version_text))
     AND public.fn_osv_nuget_sortable('1.0.0-0') IS NOT NULL AND public.fn_osv_nuget_sortable('1.0.0-' || repeat('9', 99)) IS NOT NULL,
         'fn_osv_nuget_sortable gives no form to an upper case V, white space, five numbers, a malformed pre-release, a part with a leading zero or of - and digits, or past 99 digits';
END
$$;

DO $$
DECLARE
  sorted_versions text[] := ARRAY['0.9', '1.0.A', '1.0.a.0.b', '1.0.a', '1.0.a.0.1', '1.0.a.2', '1.0.a.10', '1.0.b1', '1.0', '1.0.0.1',
                                  '1.2.4.beta', '1.2.4', '3.2', '3.10'];
BEGIN
  ASSERT (SELECT array_agg(v.version_text ORDER BY public.fn_osv_rubygems_sortable(v.version_text) COLLATE "C")
            FROM unnest(ARRAY(SELECT s.version_text FROM unnest(sorted_versions) AS s (version_text) ORDER BY md5(s.version_text))) AS v (version_text))
         = sorted_versions
     AND (SELECT count(DISTINCT public.fn_osv_rubygems_sortable(v.version_text)) FROM unnest(sorted_versions) AS v (version_text)) = cardinality(sorted_versions),
         'fn_osv_rubygems_sortable sorts versions as Gem::Version does: letters below numbers, upper case before lower case, a zero before letters below the end';
  ASSERT (SELECT array_agg(public.fn_osv_rubygems_sortable(v.version_text)::text ORDER BY v.version_index)
            FROM unnest(ARRAY['0.9', '1.0.a.0.0.b', '1.0.a.0.1', '3.10']) WITH ORDINALITY AS v (version_text, version_index))
         = ARRAY['{4,50019,3}', '{50011,1a,2,2,1b,3}', '{50011,1a,4,50011,3}', '{50013,500210,3}'],
         'fn_osv_rubygems_sortable writes 1 and letters, 2 for a zero before letters, 4 for a zero before a number, 5 and a number, 3 at the end';
  ASSERT (SELECT bool_and(coalesce(public.fn_osv_rubygems_sortable(p.left_version) = public.fn_osv_rubygems_sortable(p.right_version), false))
            FROM (VALUES ('1', '1.0.0'), ('1.0.a', '1.00.a'), ('1.0.a2', '1.0.a.2'), ('1.a.0.0', '1.0.a')) AS p (left_version, right_version)),
         'fn_osv_rubygems_sortable gives one form to the spellings Gem::Version calls equal: trailing zeros of the numbers and of the letters, leading zeros';
  ASSERT (SELECT bool_and(public.fn_osv_rubygems_sortable(v.version_text) IS NULL)
            FROM unnest(ARRAY['', ' 1.0', '1.0 ', '1beta', '1..2', '1.0-rc1', '4.0.0-beta.2', 'a.1', repeat('9', 100), '1.' || repeat('a', 255), NULL]) AS v (version_text))
     AND public.fn_osv_rubygems_sortable('1.' || repeat('9', 99)) IS NOT NULL
     AND public.fn_osv_rubygems_sortable('1.' || repeat('a', 254)) IS NOT NULL,
         'fn_osv_rubygems_sortable gives no form to a version Gem::Version refuses, to an empty one, to white space, to a -, or past 256 characters or 99 digits';
END
$$;

DO $$
DECLARE
  sorted_versions text[] := ARRAY['1.0.0-dev', '1.0.0alpha', '1.0.0a1', '1.0.0-beta2', '1.0.0b3', '1.0.0RC1', '1.0.0', '1.0.0p', '1.0.0pl1',
                                  '1.0.1', '1.9.0', '1.10.0', '2.0.0', '12345.0.0'];
BEGIN
  ASSERT (SELECT array_agg(v.version_text ORDER BY public.fn_osv_packagist_sortable(v.version_text) COLLATE "C")
            FROM unnest(ARRAY(SELECT s.version_text FROM unnest(sorted_versions) AS s (version_text) ORDER BY md5(s.version_text))) AS v (version_text))
         = sorted_versions
     AND (SELECT count(DISTINCT public.fn_osv_packagist_sortable(v.version_text)) FROM unnest(sorted_versions) AS v (version_text)) = cardinality(sorted_versions),
         'fn_osv_packagist_sortable sorts versions as osv.dev and Composer do: dev, alpha, beta, RC, the release, pl, a word before its numbered form';
  ASSERT (SELECT array_agg(public.fn_osv_packagist_sortable(v.version_text)::text ORDER BY v.version_index)
            FROM unnest(ARRAY['1.2.3-dev', '1.2.3.alpha7', '1.2.3b', '1.2.3-rc.10', '1.2.3', '1.2.3pl']) WITH ORDINALITY AS v (version_text, version_index))
         = ARRAY['{0011,0012,0013,1}', '{0011,0012,0013,2,0017}', '{0011,0012,0013,3}', '{0011,0012,0013,4,00210}', '{0011,0012,0013,5}', '{0011,0012,0013,6}'],
         'fn_osv_packagist_sortable writes three numbers, then 1 for dev, 2 alpha, 3 beta, 4 RC, 5 none, 6 pl, then the word''s number';
  ASSERT (SELECT bool_and(coalesce(public.fn_osv_packagist_sortable(p.left_version) = public.fn_osv_packagist_sortable(p.right_version), false))
            FROM (VALUES ('v1.2.3', '1.2.3'), ('1.0.0-beta2', '1.0.0.beta.2'), ('1.0.0RC1', '1.0.0rc1'), ('1.0.0a1', '1.0.0alpha1'),
                         ('1.0.0p1', '1.0.0pl1'), ('1.0.0_b1', '1.0.0-beta1')) AS p (left_version, right_version)),
         'fn_osv_packagist_sortable gives one form to the spellings both orders call equal: a v, the separators and the short words';
  ASSERT (SELECT bool_and(public.fn_osv_packagist_sortable(v.version_text) IS NULL)
            FROM unnest(ARRAY['1.0', '1.0.0.0', '1.0.0-BETA1', '1.0.0Beta', '1.0.0-stable', '1.0.0-dev1', '1.0.0-patch1', 'V1.0.0', '123456.0.0',
                              '1.' || repeat('9', 100) || '.0', NULL]) AS v (version_text))
     AND public.fn_osv_packagist_sortable('1.' || repeat('9', 99) || '.0') IS NOT NULL,
         'fn_osv_packagist_sortable gives no form to two or four numbers, an upper case word other than RC, another word, a first number past five digits, or past 99 digits';
END
$$;

DO $$
BEGIN
  ASSERT (SELECT array_agg(row(p.proname, l.lanname, p.provolatile, p.proisstrict, p.prosecdef, p.proconfig)::text ORDER BY p.proname)
            FROM pg_proc AS p JOIN pg_language AS l ON l.oid = p.prolang
           WHERE p.oid IN ('public.fn_osv_number_sortable(text)'::regprocedure, 'public.fn_osv_pep440_sortable(text)'::regprocedure,
                           'public.fn_osv_maven_sortable(text)'::regprocedure, 'public.fn_osv_maven_order_is_uncertain(text[], text[])'::regprocedure,
                           'public.fn_osv_nuget_sortable(text)'::regprocedure, 'public.fn_osv_rubygems_sortable(text)'::regprocedure,
                           'public.fn_osv_packagist_sortable(text)'::regprocedure, 'public.fn_osv_semver_sortable(text, text)'::regprocedure))
         = ARRAY[row('fn_osv_maven_order_is_uncertain', 'plpgsql', 'i', false, false, ARRAY['search_path=pg_catalog'])::text,
                 row('fn_osv_maven_sortable', 'plpgsql', 'i', false, false, ARRAY['search_path=pg_catalog'])::text,
                 row('fn_osv_nuget_sortable', 'sql', 'i', false, false, ARRAY['search_path=pg_catalog'])::text,
                 row('fn_osv_number_sortable', 'sql', 'i', true, false, ARRAY['search_path=pg_catalog'])::text,
                 row('fn_osv_packagist_sortable', 'sql', 'i', false, false, ARRAY['search_path=pg_catalog'])::text,
                 row('fn_osv_pep440_sortable', 'sql', 'i', false, false, ARRAY['search_path=pg_catalog'])::text,
                 row('fn_osv_rubygems_sortable', 'plpgsql', 'i', false, false, ARRAY['search_path=pg_catalog'])::text,
                 row('fn_osv_semver_sortable', 'sql', 'i', false, false, ARRAY['search_path=pg_catalog'])::text],
         'the eight key functions are IMMUTABLE, SECURITY INVOKER and set search_path to pg_catalog; only fn_osv_number_sortable is STRICT; three are PL/pgSQL';
END
$$;
