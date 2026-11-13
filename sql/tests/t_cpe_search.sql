INSERT INTO cves (cve_id) VALUES
  ('CVE-2004-0001'), ('CVE-2004-0002'), ('CVE-2004-0003'), ('CVE-2004-0004'), ('CVE-2004-0005');
INSERT INTO cve_products (cve_id, vendor, product, is_vulnerable) VALUES
  ('CVE-2004-0001', 'Zq3001',           'Windows_10_Pro',   true),
  ('CVE-2004-0001', 'zq3002',           'notepad\+\+',      true),
  ('CVE-2004-0001', 'zq3003',           '100%_cpu',         true),
  ('CVE-2004-0001', 'zq3004',           'path\',            true),
  ('CVE-2004-0001', 'zq3005',           repeat('a', 128),   true),
  ('CVE-2004-0001', 'zq3005',           repeat('b', 129),   true),
  ('CVE-2004-0001', repeat('c', 129),   'zq3005v',          true),
  ('CVE-2004-0001', '',                 'zq3006',           true),
  ('CVE-2004-0001', 'zq3006',           '',                 true),
  ('CVE-2004-0001', 'zq3007',           'alpha',            true),
  ('CVE-2004-0001', 'zq3007',           'alpha',            true),
  ('CVE-2004-0002', 'zq3007',           'alpha',            true),
  ('CVE-2004-0003', 'zq3007',           'alpha',            false),
  ('CVE-2004-0003', 'zq3007',           'beta',             false),
  ('CVE-2004-0004', 'zq3008',           'gamma',            true),
  ('CVE-2004-0004', 'zq3008',           'delta',            true),
  ('CVE-2004-0005', 'zq3009',           'delta',            true);
INSERT INTO cve_products (cve_id, vendor, product, is_vulnerable, product_source) VALUES
  ('CVE-2004-0002', 'zq3007',           'alpha',            true,  'cna'),
  ('CVE-2004-0003', 'zq3007',           'beta',             false, 'cna_cpe');

REFRESH MATERIALIZED VIEW cpe_product_index;

CREATE TEMP VIEW t_cpe_search_call AS SELECT * FROM api.fn_cpe_search('zq3007', 10, 0);

DO $$
BEGIN
  ASSERT (SELECT array_agg(attname::text || ' ' || format_type(atttypid, atttypmod) ORDER BY attnum)
            FROM pg_attribute
           WHERE attrelid = 't_cpe_search_call'::regclass AND attnum > 0)
         = ARRAY['vendor text', 'product text', 'vulnerable_cve_count integer', 'product_named_by jsonb'],
         'api.fn_cpe_search answers vendor, product, an integer vulnerable_cve_count and a jsonb product_named_by, in that order';
  ASSERT (SELECT search_key FROM cpe_product_index WHERE vendor = 'Zq3001')
         = 'zq3001 windows 10 pro',
         'the search key is the pair in lower case, with each underscore a space';
  ASSERT (SELECT search_key FROM cpe_product_index WHERE vendor = 'zq3002')
         = 'zq3002 notepad++',
         'the search key resolves each CPE escape';
  ASSERT (SELECT count(*) FROM cpe_product_index WHERE vendor = 'zq3007' AND product = 'alpha') = 1,
         'the view holds each pair once';
  ASSERT (SELECT vulnerable_cve_count FROM api.fn_cpe_search('zq3007 alpha', 10, 0)) = 2,
         'vulnerable_cve_count counts each vulnerable CVE once, and no CVE that is not vulnerable';
  ASSERT (SELECT vulnerable_cve_count FROM api.fn_cpe_search('zq3007 beta', 10, 0)) = 0,
         'a pair with no vulnerable CVE is answered with vulnerable_cve_count 0';
  ASSERT (SELECT product_named_by FROM api.fn_cpe_search('zq3007 alpha', 10, 0)) = '["cna", "nvd"]'::jsonb,
         'product_named_by lists each source of the pair once, in name order';
  ASSERT (SELECT product_named_by FROM api.fn_cpe_search('zq3007 beta', 10, 0)) = '["cna_cpe", "nvd"]'::jsonb,
         'a row that is not vulnerable still gives the pair its source';
  ASSERT (SELECT product_named_by FROM api.fn_cpe_search('zq3008 gamma', 10, 0)) = '["nvd"]'::jsonb,
         'a pair with nvd rows only answers nvd alone';
END
$$;

DO $$
BEGIN
  ASSERT (SELECT array_agg(vendor) FROM api.fn_cpe_search('windows 10', 10, 0)) = ARRAY['Zq3001'],
         'a query with a space finds a name with an underscore';
  ASSERT (SELECT array_agg(vendor) FROM api.fn_cpe_search('WINDOWS_10', 10, 0)) = ARRAY['Zq3001'],
         'a query matches in any case, and its underscore is a space';
  ASSERT (SELECT array_agg(product) FROM api.fn_cpe_search('notepad++', 10, 0)) = ARRAY['notepad\+\+'],
         'a query with a + finds the name that escapes it, and the answer keeps the escape';
  ASSERT (SELECT array_agg(product) FROM api.fn_cpe_search('notepad\+\+', 10, 0)) = ARRAY['notepad\+\+'],
         'a name copied from an answer finds itself';
  ASSERT (SELECT array_agg(product) FROM api.fn_cpe_search('0% cpu', 10, 0)) = ARRAY['100%_cpu'],
         'a % in the query matches a %';
  ASSERT (SELECT count(*) FROM api.fn_cpe_search('zq30%1', 10, 0)) = 0
     AND api.fn_cpe_search_match_count('zq30%1') = 0,
         'a % in the query matches no other byte';
  ASSERT (SELECT count(*) FROM api.fn_cpe_search('zq300_', 10, 0)) = 0,
         'an underscore in the query matches a space only';
  ASSERT (SELECT array_agg(product) FROM api.fn_cpe_search('path\', 10, 0)) = ARRAY['path\'],
         'a \ at the end of the query matches a \';
  ASSERT (SELECT array_agg(product) FROM api.fn_cpe_search('zq3005', 10, 0)) = ARRAY[repeat('a', 128)],
         'a name of 128 bytes is found, and a pair with a name of 129 bytes is left out';
  ASSERT (SELECT count(*) FROM api.fn_cpe_search('zq3006', 10, 0)) = 0,
         'a pair with an empty name is left out';
  ASSERT (SELECT bool_and(api.fn_cpe_search_pattern(vendor || ' ' || product)
                          = '%' || replace(replace(search_key, '\', '\\'), '%', '\%') || '%')
            FROM cpe_product_index
           WHERE search_key LIKE 'zq30%'),
         'api.fn_cpe_search_pattern changes a name the way the view changes it into its search key';
END
$$;

DO $$
BEGIN
  ASSERT (SELECT array_agg(vendor || ' ' || product ORDER BY ord) FROM
            (SELECT vendor, product, row_number() OVER () AS ord
               FROM api.fn_cpe_search('zq300', 10, 0)) AS rows)
         = ARRAY['zq3007 alpha', 'Zq3001 Windows_10_Pro', 'zq3002 notepad\+\+', 'zq3003 100%_cpu',
                 'zq3004 path\', 'zq3005 ' || repeat('a', 128), 'zq3008 delta', 'zq3008 gamma',
                 'zq3009 delta', 'zq3007 beta'],
         'the pairs come by vulnerable_cve_count, a tie in vendor, then product order';
  ASSERT api.fn_cpe_search_match_count('zq300') = 10,
         'the match count counts every pair the query matches';
  ASSERT (SELECT array_agg(vendor || ' ' || product ORDER BY ord) FROM
            (SELECT vendor, product, row_number() OVER () AS ord
               FROM api.fn_cpe_search('zq300', 2, 7)) AS rows)
         = ARRAY['zq3008 gamma', 'zq3009 delta'],
         'the row count and the offset cut the page from the ordered pairs';
  ASSERT (SELECT count(*) FROM api.fn_cpe_search('zq300', NULL, 0)) = 0,
         'a NULL row count answers no row';
  ASSERT (SELECT count(*) FROM api.fn_cpe_search('zq300', 10, NULL)) = 0,
         'a NULL offset answers no row';
  ASSERT api.fn_cpe_search_match_count(NULL) = 0,
         'a NULL query counts no pair';
END
$$;

PREPARE t_cpe_search_match_count_query AS SELECT api.fn_cpe_search_match_count($1) AS product_count;
CREATE TEMP TABLE t_cpe_search_match_count_answer AS EXECUTE t_cpe_search_match_count_query('zq300');
DEALLOCATE t_cpe_search_match_count_query;
PREPARE t_cpe_search_query AS SELECT * FROM api.fn_cpe_search($1, $2, $3);
CREATE TEMP TABLE t_cpe_search_answer AS EXECUTE t_cpe_search_query('zq300', '2', '7');
DEALLOCATE t_cpe_search_query;

DO $$
BEGIN
  ASSERT (SELECT array_agg(attname::text || ' ' || format_type(atttypid, atttypmod) ORDER BY attnum)
            FROM pg_attribute
           WHERE attrelid = 't_cpe_search_match_count_answer'::regclass AND attnum > 0)
         = ARRAY['product_count bigint'],
         'the count call db_CPESEARCH sends answers one bigint column, product_count';
  ASSERT (SELECT product_count FROM t_cpe_search_match_count_answer) = 10,
         'the count call db_CPESEARCH sends counts the pairs';
  ASSERT (SELECT array_agg(vendor ORDER BY vendor) FROM t_cpe_search_answer) = ARRAY['zq3008', 'zq3009'],
         'the page call db_CPESEARCH sends answers the page';
  ASSERT (SELECT count(*) FROM pg_proc
          WHERE oid IN ('api.fn_cpe_search(text, integer, integer)'::regprocedure,
                        'api.fn_cpe_search_match_count(text)'::regprocedure)
            AND prosecdef AND provolatile = 's' AND proconfig = ARRAY['search_path=pg_catalog']
            AND prosqlbody IS NOT NULL) = 2,
         'both search functions are SECURITY DEFINER and STABLE, set search_path to pg_catalog and have a SQL-standard body';
  ASSERT (SELECT proisstrict FROM pg_proc WHERE oid = 'api.fn_cpe_search(text, integer, integer)'::regprocedure),
         'api.fn_cpe_search is STRICT';
  ASSERT (SELECT NOT proisstrict FROM pg_proc WHERE oid = 'api.fn_cpe_search_match_count(text)'::regprocedure),
         'api.fn_cpe_search_match_count is not STRICT';
  ASSERT (SELECT NOT prosecdef AND provolatile = 'i' AND proconfig IS NULL AND prosqlbody IS NOT NULL
            FROM pg_proc WHERE oid = 'api.fn_cpe_search_pattern(text)'::regprocedure),
         'api.fn_cpe_search_pattern is SECURITY INVOKER and IMMUTABLE, sets no parameter and has a SQL-standard body';
END
$$;

REFRESH MATERIALIZED VIEW CONCURRENTLY cpe_product_index;

DO $$
BEGIN
  ASSERT (SELECT indexdef FROM pg_indexes WHERE indexname = 'idx_cpe_product_index_vendor_product')
         = 'CREATE UNIQUE INDEX idx_cpe_product_index_vendor_product ON public.cpe_product_index USING btree (vendor, product)',
         'cpe_product_index has a unique index on vendor and product';
  ASSERT (SELECT count(*) FROM cpe_product_index WHERE search_key LIKE 'zq30%') = 10,
         'a concurrent refresh keeps the pairs';
END
$$;

INSERT INTO cve_products (cve_id, vendor, product, is_vulnerable) VALUES
  ('CVE-2004-0001', 'zq3101',                     repeat('é', 64), true),
  ('CVE-2004-0001', 'zq3101',                     repeat('é', 65), true),
  ('CVE-2004-0001', repeat('é', 65),              'zq3102',        true),
  ('CVE-2004-0001', 'zq3103' || repeat('d', 122), 'v',             true),
  ('CVE-2004-0001', 'zq3104_a',                   'z',             true),
  ('CVE-2004-0001', 'zq3104',                     'b',             true);

REFRESH MATERIALIZED VIEW cpe_product_index;

DO $$
BEGIN
  ASSERT (SELECT array_agg(octet_length(product)) FROM api.fn_cpe_search('zq3101', 10, 0)) = ARRAY[128],
         'a product of 128 bytes is kept; one of 130 bytes in 65 characters is left out';
  ASSERT (SELECT count(*) FROM api.fn_cpe_search('zq3102', 10, 0)) = 0,
         'a vendor of 130 bytes in 65 characters is left out';
  ASSERT (SELECT count(*) FROM api.fn_cpe_search('zq3103', 10, 0)) = 1,
         'a vendor of 128 bytes is kept';
  ASSERT (SELECT array_agg(vendor || ' ' || product ORDER BY ord) FROM
            (SELECT vendor, product, row_number() OVER () AS ord
               FROM api.fn_cpe_search('zq3104', 10, 0)) AS rows)
         = ARRAY['zq3104 b', 'zq3104_a z'],
         'a vulnerable_cve_count tie is broken by vendor, not by the search key';
END
$$;
