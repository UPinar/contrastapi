INSERT INTO cwes (cwe_id, cwe_name, cwe_description, likelihood, parent_cwe, updated_at,
                  mitigations, extended_description, examples, abstract_type, cwe_status) VALUES
  ('CWE-2001', 'Name', 'Description', 'High', 'CWE-2000', '2001-01-01 00:00:00+00',
   '[]', 'Extended', '[]', 'Base', 'Stable'),
  ('CWE-2002', 'Empty', '', '', '', NULL, '[]', '', '[]', '', '');
INSERT INTO cves (cve_id, cwe_id, in_kev, cvss_v3, epss_score) VALUES
  ('CVE-2001-0021', 'CWE-2001', true,  9.0, 0.5),
  ('CVE-2001-0022', 'CWE-2001', false, 6.0, 0.25),
  ('CVE-2001-0023', 'CWE-2001', true,  0.0, 0.0);

CREATE TEMP VIEW t_cwe_lookup_call AS SELECT * FROM api.fn_cwe_lookup('CWE-2001');

DO $$
BEGIN
  ASSERT (SELECT array_agg(attname::text ORDER BY attnum) FROM pg_attribute
          WHERE attrelid = 't_cwe_lookup_call'::regclass AND attnum > 0)
         = ARRAY['cwe_id', 'cwe_name', 'cwe_description', 'likelihood', 'parent_cwe',
                 'updated_at', 'mitigations', 'extended_description', 'examples',
                 'abstract_type', 'cwe_status', 'kev_cve_count', 'avg_cvss', 'avg_epss',
                 'cve_count', 'owasp_top10'],
         'api.fn_cwe_lookup answers the 16 columns db_CWELOOKUP reads, in its order';
  ASSERT (SELECT array_agg(format_type(atttypid, atttypmod) ORDER BY attnum) FROM pg_attribute
          WHERE attrelid = 't_cwe_lookup_call'::regclass AND attnum > 0)
         = ARRAY['text', 'text', 'text', 'text', 'text', 'text', 'jsonb',
                 'text', 'jsonb', 'text', 'text', 'bigint', 'double precision',
                 'double precision', 'bigint', 'jsonb'],
         'updated_at is text, the numbers are bigint and double precision, and the rest keep their type';
  ASSERT (SELECT updated_at = '2001-01-01T00:00:00Z' AND cwe_name = 'Name'
             AND cwe_description = 'Description' AND likelihood = 'High'
             AND extended_description = 'Extended'
            FROM t_cwe_lookup_call),
         'updated_at answers UTC text, and each text column answers its own cwes column';
  ASSERT (SELECT updated_at IS NULL FROM api.fn_cwe_lookup('CWE-2002')),
         'a NULL updated_at answers NULL';
  ASSERT (SELECT abstract_type = 'Base' AND cwe_status = 'Stable' AND parent_cwe = 'CWE-2000'
            FROM t_cwe_lookup_call),
         'the cwes columns hold the row of the CWE';
  ASSERT (SELECT kev_cve_count = 2 AND cve_count = 3 FROM t_cwe_lookup_call),
         'kev_cve_count counts the CVEs in KEV, and cve_count counts them all';
  ASSERT (SELECT avg_cvss = 7.5 AND avg_epss = 0.375 FROM t_cwe_lookup_call),
         'the averages skip a score of 0';
  ASSERT (SELECT kev_cve_count = 0 AND cve_count = 0 AND avg_cvss = 0 AND avg_epss = 0
            FROM api.fn_cwe_lookup('CWE-2002')),
         'a CWE with no CVE answers its row with every number 0';
  ASSERT (SELECT count(*) FROM api.fn_cwe_lookup('CWE-2009')) = 0,
         'a CWE with no row answers no row';
END
$$;

INSERT INTO cves (cve_id, cwe_id, cvss_v3, epss_score) VALUES
  ('CVE-2001-0024', 'CWE-2002', 1.0, 0.00012),
  ('CVE-2001-0025', 'CWE-2002', 2.0, 0.00013),
  ('CVE-2001-0026', 'CWE-2002', 2.0, 0.00013);

DO $$
BEGIN
  ASSERT (SELECT avg_cvss = 1.67 AND avg_epss = 0.0001 FROM api.fn_cwe_lookup('CWE-2002')),
         'avg_cvss is rounded to 2 decimals, and avg_epss to 4';
END
$$;

DELETE FROM cwe_owasp_top10;

DO $$
BEGIN
  ASSERT (SELECT owasp_top10 IS NULL FROM api.fn_cwe_lookup('CWE-2001')),
         'owasp_top10 is NULL while cwe_owasp_top10 holds no row';
END
$$;

INSERT INTO cwe_owasp_top10 (cwe_id, edition_year, category_id, category_name) VALUES
  ('CWE-2001', 2025, 'A05', 'Injection'),
  ('CWE-2001', 2021, 'A03', 'Injection'),
  ('CWE-2002', 2021, 'A01', 'Broken Access Control');

DO $$
BEGIN
  ASSERT (SELECT owasp_top10::text FROM api.fn_cwe_lookup('CWE-2001'))
         = '[{"id": "A03", "name": "Injection", "year": 2021}, '
           '{"id": "A05", "name": "Injection", "year": 2025}]',
         'owasp_top10 holds one element for each edition, the older edition first';
  ASSERT (SELECT owasp_top10::text FROM api.fn_cwe_lookup('CWE-2002'))
         = '[{"id": "A01", "name": "Broken Access Control", "year": 2021}]',
         'owasp_top10 holds only the rows of its own CWE';
  DELETE FROM cwe_owasp_top10 WHERE cwe_id = 'CWE-2002';
  INSERT INTO cwe_owasp_top10 (cwe_id, edition_year, category_id, category_name) VALUES
    ('CWE-2003', 2021, 'A01', 'Broken Access Control');
  ASSERT (SELECT owasp_top10 = '[]'::jsonb FROM api.fn_cwe_lookup('CWE-2002')),
         'a CWE in no category answers [] once the table holds rows';
  INSERT INTO cwe_owasp_top10 (cwe_id, edition_year, category_id, category_name) VALUES
    ('CWE-2002', 2021, 'A10', 'Server-Side Request Forgery'),
    ('CWE-2002', 2025, 'A01', 'Broken Access Control');
  ASSERT (SELECT owasp_top10::text FROM api.fn_cwe_lookup('CWE-2002'))
         = '[{"id": "A10", "name": "Server-Side Request Forgery", "year": 2021}, '
           '{"id": "A01", "name": "Broken Access Control", "year": 2025}]',
         'the edition year orders the array, not the category id';
END
$$;

SAVEPOINT t_cwe_lookup_time_zone;
SET LOCAL TimeZone = 'Europe/Istanbul';
INSERT INTO cwes (cwe_id, updated_at) VALUES
  ('CWE-2004', '2026-05-20 17:07:56.162610+03'),
  ('CWE-2005', '2026-05-20 17:07:56.999999+03'),
  ('CWE-2006', '2027-01-01 15:00:00+03');

DO $$
BEGIN
  ASSERT (SELECT updated_at FROM api.fn_cwe_lookup('CWE-2004')) = '2026-05-20T14:07:56Z',
         'a session in Europe/Istanbul still reads updated_at in UTC';
  ASSERT (SELECT updated_at FROM api.fn_cwe_lookup('CWE-2005')) = '2026-05-20T14:07:56Z',
         'the fraction of a second is cut, not rounded';
  ASSERT (SELECT updated_at FROM api.fn_cwe_lookup('CWE-2006')) = '2027-01-01T12:00:00Z',
         'the year is the calendar year: 2027-01-01 lies in ISO week year 2026';
END
$$;

ROLLBACK TO SAVEPOINT t_cwe_lookup_time_zone;

PREPARE t_cwe_lookup_query AS SELECT * FROM api.fn_cwe_lookup($1);
CREATE TEMP TABLE t_cwe_lookup_answer AS EXECUTE t_cwe_lookup_query('CWE-2001');
DEALLOCATE t_cwe_lookup_query;

DO $$
BEGIN
  ASSERT (SELECT array_agg(cwe_id) FROM t_cwe_lookup_answer) = ARRAY['CWE-2001'],
         'the query db_CWELOOKUP sends answers the row of its id';
  ASSERT (SELECT prosecdef AND provolatile = 's' FROM pg_proc
          WHERE oid = 'api.fn_cwe_lookup(text)'::regprocedure),
         'api.fn_cwe_lookup is SECURITY DEFINER and STABLE';
  ASSERT (SELECT proconfig FROM pg_proc WHERE oid = 'api.fn_cwe_lookup(text)'::regprocedure)
         = ARRAY['search_path=pg_catalog'],
         'api.fn_cwe_lookup sets search_path to pg_catalog';
END
$$;
