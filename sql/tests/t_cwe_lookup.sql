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
                 'cve_count'],
         'api.fn_cwe_lookup answers the 15 columns db_CWELOOKUP reads, in its order';
  ASSERT (SELECT array_agg(format_type(atttypid, atttypmod) ORDER BY attnum) FROM pg_attribute
          WHERE attrelid = 't_cwe_lookup_call'::regclass AND attnum > 0)
         = ARRAY['text', 'text', 'text', 'text', 'text', 'timestamp with time zone', 'jsonb',
                 'text', 'jsonb', 'text', 'text', 'bigint', 'double precision',
                 'double precision', 'bigint'],
         'each cwes column keeps its type, and the numbers are bigint and double precision';
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
