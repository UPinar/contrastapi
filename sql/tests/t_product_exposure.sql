INSERT INTO cves (cve_id, severity, cvss_v3, cvss_v3_vector, epss_score, in_kev, published_time, refs) VALUES
  ('CVE-2001-0061', 'CRITICAL', 9.8, 'CVSS:3.1/AV:N', 0.91234, true,  '2001-01-03',
   '[{"url": "https://a.example", "tags": ["Exploit"]}]'),
  ('CVE-2001-0062', 'HIGH',     7.25, 'CVSS:3.1/AV:N', 0.5,   false, '2001-01-05', '[]'),
  ('CVE-2001-0065', 'MEDIUM',   0.0, '',              0.25,  false, '2001-01-04', '[]'),
  ('CVE-2001-0066', 'LOW',      7.25, 'CVSS:3.1/AV:N', 0.5,   false, '2001-01-01', '[]'),
  ('CVE-2001-0063', 'CRITICAL', 10.0, 'CVSS:3.1/AV:N', 0.99,  true,  '2001-01-09', '[]'),
  ('CVE-2001-0064', 'CRITICAL', 10.0, 'CVSS:3.1/AV:N', 0.99,  true,  '2001-01-09', '[]');
INSERT INTO cve_products (cve_id, vendor, product, is_vulnerable) VALUES
  ('CVE-2001-0061', 'v2001', 'p2001', true),
  ('CVE-2001-0061', 'v2001', 'p2001', true),
  ('CVE-2001-0062', 'v2001', 'p2001', true),
  ('CVE-2001-0065', 'v2001', 'p2001', true),
  ('CVE-2001-0066', 'v2001', 'p2001', true),
  ('CVE-2001-0063', 'v2001', 'p2001', false),
  ('CVE-2001-0064', 'v2001', 'other', true);
INSERT INTO cves (cve_id, severity, cvss_v4, epss_score) VALUES ('CVE-2001-0067', 'HIGH', 8.5, 0.25);
INSERT INTO cve_products (cve_id, vendor, product, is_vulnerable) VALUES
  ('CVE-2001-0067', 'v2001', 'p2002', true);
INSERT INTO cves (cve_id, severity, cvss_v3, cvss_v3_vector, epss_score, in_kev) VALUES
  ('CVE-2001-0068', 'CRITICAL', 10.0, 'CVSS:3.1/AV:N', 0.99,  true),
  ('CVE-2001-0071', 'MEDIUM',   5.0,  'CVSS:3.1/AV:N', 0.1,   false),
  ('CVE-2001-0072', 'MEDIUM',   5.01, 'CVSS:3.1/AV:N', 0.1,   false),
  ('CVE-2001-0073', 'MEDIUM',   5.0,  'CVSS:3.1/AV:N', 0.101, false);
INSERT INTO cve_products (cve_id, vendor, product, is_vulnerable) VALUES
  ('CVE-2001-0068', 'v2009', 'p2001', true),
  ('CVE-2001-0071', 'v2001', 'p2003', true),
  ('CVE-2001-0072', 'v2001', 'p2003', true),
  ('CVE-2001-0073', 'v2001', 'p2003', true);
INSERT INTO cves (cve_id, severity, cvss_v3, cvss_v3_vector, epss_score, in_kev, refs) VALUES
  ('CVE-2001-0074', 'MEDIUM', 5.0, 'CVSS:3.1/AV:N', 0.1,   false,
   '[{"url": "https://packetstormsecurity.com/files/741/x.html"},
     {"url": "https://packetstormsecurity.com/files/742/x.html", "tags": ["Third Party Advisory"]},
     {"url": "https://packetstorm.news/files/id/743"},
     {"url": "https://packetstormsecurity.org/2401-exploits/x.txt", "tags": []}]'),
  ('CVE-2001-0075', 'MEDIUM', 5.0, 'CVSS:3.1/AV:N', 0.1,   false,
   '[{"url": "https://www.exploit-db.com/exploits/75"}, {"url": "https://www.exploit-db.com/exploits/76", "tags": []}]'),
  ('CVE-2001-0076', 'MEDIUM', 5.0, 'CVSS:3.1/AV:N', 0.102, false, '[]');
INSERT INTO cve_products (cve_id, vendor, product, is_vulnerable) VALUES
  ('CVE-2001-0074', 'v2001', 'p2004', true),
  ('CVE-2001-0075', 'v2001', 'p2004', true),
  ('CVE-2001-0076', 'v2001', 'p2004', true);
INSERT INTO github_poc_repos (cve_id, repo_full_name, star_count) VALUES
  ('CVE-2001-0067', 'a-owner/poc', 50),
  ('CVE-2001-0067', 'b-owner/poc', 0),
  ('CVE-2001-0076', 'a-owner/poc', 50),
  ('CVE-2001-0076', 'b-owner/poc', 0);

INSERT INTO cves (cve_id, severity, cvss_v3, cvss_v3_vector, epss_score, in_kev) VALUES
  ('CVE-2001-0083', 'MEDIUM', 5.0, 'CVSS:3.1/AV:N', 0.1, false),
  ('CVE-2001-0082', 'MEDIUM', 5.0, 'CVSS:3.1/AV:N', 0.1, false),
  ('CVE-2001-0081', 'MEDIUM', 5.0, 'CVSS:3.1/AV:N', 0.1, false);
INSERT INTO cve_products (cve_id, vendor, product, is_vulnerable) VALUES
  ('CVE-2001-0083', 'v2001', 'p2005', true),
  ('CVE-2001-0082', 'v2001', 'p2005', true),
  ('CVE-2001-0081', 'v2001', 'p2005', true);

INSERT INTO cves (cve_id, severity, cvss_v3, cvss_v3_vector, epss_score, in_kev, published_time, refs)
  SELECT format('CVE-2001-01%s', lpad(i::text, 2, '0')),
         CASE WHEN i = 1 THEN 'CRITICAL' WHEN i <= 3 THEN 'HIGH' WHEN i <= 6 THEN 'MEDIUM' ELSE 'LOW' END,
         10.0 - i * 0.5, 'CVSS:3.1/AV:N', i * 0.05, i <= 5, date '2012-01-01' + i,
         CASE WHEN i <= 6 THEN format('[{"url": "https://x%s.example", "tags": ["Exploit"]}]', i)::jsonb ELSE '[]'::jsonb END
    FROM generate_series(1, 10) AS i;
INSERT INTO cve_products (cve_id, vendor, product, is_vulnerable)
  SELECT format('CVE-2001-01%s', lpad(i::text, 2, '0')), 'v2001', 'p2012', true
    FROM generate_series(1, 10) AS i;

CREATE FUNCTION pg_temp.t_summary(p_product text, p_include_rejected boolean)
  RETURNS TABLE (cve_count bigint, critical_count bigint, high_count bigint, medium_count bigint,
                 low_count bigint, kev_count bigint, max_cvss double precision, avg_cvss double precision,
                 max_epss double precision, poc_backed_count bigint, worst_risk_score double precision,
                 most_recent_published text)
  LANGUAGE sql STABLE
  AS $$
    SELECT DISTINCT e.cve_count, e.critical_count, e.high_count, e.medium_count, e.low_count, e.kev_count,
           e.max_cvss, e.avg_cvss, e.max_epss, e.poc_backed_count, e.worst_risk_score, e.most_recent_published
      FROM api.fn_product_exposure('v2001', p_product, p_include_rejected, 10) AS e
  $$;

CREATE FUNCTION pg_temp.t_top(p_product text, p_include_rejected boolean, p_row_count integer)
  RETURNS text[]
  LANGUAGE sql STABLE
  AS $$
    SELECT array_agg(e.cve_id ORDER BY e.ordinality)
      FROM api.fn_product_exposure('v2001', p_product, p_include_rejected, p_row_count) WITH ORDINALITY AS e
     WHERE e.cve_id IS NOT NULL
  $$;

CREATE TEMP VIEW t_product_exposure_call AS
  SELECT * FROM api.fn_product_exposure('v2001', 'p2001', false, 10);

DO $$
BEGIN
  ASSERT (SELECT array_agg(attname::text ORDER BY attnum) FROM pg_attribute
          WHERE attrelid = 't_product_exposure_call'::regclass AND attnum > 0)
         = ARRAY['cve_count', 'critical_count', 'high_count', 'medium_count', 'low_count',
                 'kev_count', 'max_cvss', 'avg_cvss', 'max_epss', 'poc_backed_count',
                 'worst_risk_score', 'most_recent_published', 'cve_id', 'risk_score', 'risk_label'],
         'api.fn_product_exposure answers the fifteen columns db_PRODUCTEXPOSURE reads, in its order';
  ASSERT (SELECT array_agg(format_type(atttypid, atttypmod) ORDER BY attnum) FROM pg_attribute
          WHERE attrelid = 't_product_exposure_call'::regclass AND attnum > 0)
         = ARRAY['bigint', 'bigint', 'bigint', 'bigint', 'bigint', 'bigint', 'double precision',
                 'double precision', 'double precision', 'bigint', 'double precision', 'text',
                 'text', 'double precision', 'text'],
         'the counts are bigint, the scores double precision, most_recent_published, cve_id and risk_label text';
  ASSERT (SELECT count(*) FROM pg_temp.t_summary('p2001', false)) = 1,
         'each top row of p2001 carries the same summary values';
  ASSERT (SELECT cve_count = 4 AND critical_count = 1 AND high_count = 1 AND medium_count = 1
             AND low_count = 1 AND kev_count = 1
            FROM pg_temp.t_summary('p2001', false)),
         'each CVE counts once, and a row that is not vulnerable or names another vendor or product counts none';
  ASSERT (SELECT max_cvss = 9.8 AND avg_cvss = 8.1 AND max_epss = 0.9123 AND poc_backed_count = 1
            FROM pg_temp.t_summary('p2001', false)),
         'max_cvss is rounded to 1 decimal, avg_cvss skips a score of 0 and is rounded to 2, max_epss is rounded to 4';
  ASSERT (SELECT worst_risk_score = api.fn_cve_risk_score(9.8, 0.91234, true, false, 1, false)
             AND most_recent_published = '2001-01-05'
            FROM pg_temp.t_summary('p2001', false)),
         'worst_risk_score is the highest score and most_recent_published the latest date';
  ASSERT (SELECT count(*) FROM api.fn_product_exposure('v2001', 'none', false, 10)) = 1,
         'a product with no CVE answers exactly one row';
  ASSERT (SELECT cve_count = 0 AND critical_count = 0 AND high_count = 0 AND medium_count = 0
             AND low_count = 0 AND kev_count = 0 AND max_cvss = 0 AND avg_cvss = 0 AND max_epss = 0
             AND poc_backed_count = 0 AND worst_risk_score = 0 AND most_recent_published = ''
             AND cve_id IS NULL AND risk_score IS NULL AND risk_label IS NULL
            FROM api.fn_product_exposure('v2001', 'none', false, 10)),
         'a product with no CVE answers 0, an empty date and NULL top columns';
  ASSERT (SELECT count(*) FROM api.fn_product_exposure('v2001', 'p2001', false, 0)) = 1,
         'a row limit of 0 answers exactly one row';
  ASSERT (SELECT cve_count = 4 AND kev_count = 1 AND max_cvss = 9.8 AND most_recent_published = '2001-01-05'
             AND cve_id IS NULL AND risk_score IS NULL AND risk_label IS NULL
            FROM api.fn_product_exposure('v2001', 'p2001', false, 0)),
         'a row limit of 0 answers the summary with NULL top columns';
  ASSERT (SELECT s.worst_risk_score = api.fn_cve_risk_score(8.5, 0.25, false, false, 0, false)
             AND t.risk_score = s.worst_risk_score
            FROM pg_temp.t_summary('p2002', false) AS s,
                 api.fn_product_exposure('v2001', 'p2002', false, 10) AS t),
         'a CVE with no v3 vector is scored on its v4 score, in the summary and in the top rows, and its GitHub repositories do not count';
  ASSERT pg_temp.t_top('p2001', false, 10) = ARRAY['CVE-2001-0061', 'CVE-2001-0062', 'CVE-2001-0066', 'CVE-2001-0065'],
         'the top rows come by score, a tie in cve_id order, each CVE once';
  ASSERT (SELECT bool_and(risk_label = api.fn_cve_risk_label(risk_score)) AND count(DISTINCT risk_label) = 3
            FROM t_product_exposure_call),
         'each top row is labelled from its score';
  ASSERT pg_temp.t_top('p2001', false, 2) = ARRAY['CVE-2001-0061', 'CVE-2001-0062'],
         'a row limit of 2 answers the two highest scores, a tie in cve_id order';
  ASSERT pg_temp.t_top('p2003', false, 10) = ARRAY['CVE-2001-0073', 'CVE-2001-0072', 'CVE-2001-0071'],
         'top rows that tie on the score come by EPSS score, then CVSS score';
  ASSERT pg_temp.t_top('p2003', false, 2) = ARRAY['CVE-2001-0073', 'CVE-2001-0072'],
         'the row limit keeps the rows the tie breakers put first';
  ASSERT pg_temp.t_top('p2005', false, 1) = ARRAY['CVE-2001-0081']
     AND pg_temp.t_top('p2005', false, 10) = ARRAY['CVE-2001-0081', 'CVE-2001-0082', 'CVE-2001-0083'],
         'top rows that tie on each other key come by cve_id, and the row limit keeps the smallest';
  ASSERT (SELECT count(*) FROM api.fn_product_exposure(NULL, 'p2001', false, 10)) = 0
     AND (SELECT count(*) FROM api.fn_product_exposure('v2001', NULL, false, 10)) = 0
     AND (SELECT count(*) FROM api.fn_product_exposure('v2001', 'p2001', NULL, 10)) = 0
     AND (SELECT count(*) FROM api.fn_product_exposure('v2001', 'p2001', false, NULL)) = 0,
         'a NULL argument answers no row, as the function is STRICT';
END
$$;

DO $$
BEGIN
  ASSERT (SELECT count(*) FROM api.fn_product_exposure('v2001', 'p2012', false, 10)) = 10
     AND (SELECT count(*) FROM pg_temp.t_summary('p2012', false)) = 1,
         'each of the ten top rows of p2012 carries the same summary values';
  ASSERT (SELECT cve_count = 10 AND critical_count = 1 AND high_count = 2 AND medium_count = 3
             AND low_count = 4 AND kev_count = 5 AND max_cvss = 9.5 AND avg_cvss = 7.25
             AND max_epss = 0.5 AND poc_backed_count = 6 AND most_recent_published = '2012-01-11'
             AND worst_risk_score = (SELECT max(e.risk_score) FROM api.fn_product_exposure('v2001', 'p2012', false, 10) AS e)
             AND worst_risk_score > 0
            FROM pg_temp.t_summary('p2012', false)),
         'each summary column of p2012 holds its own value';
  ASSERT pg_temp.t_top('p2012', false, 3) = (pg_temp.t_top('p2012', false, 10))[1:3],
         'a row limit of 3 keeps the first three rows of the whole order';
END
$$;

DO $$
BEGIN
  ASSERT (SELECT cve_count = 3 AND poc_backed_count = 2
            FROM pg_temp.t_summary('p2004', false)),
         'poc_backed_count counts the two CVEs whose exploit references carry no Exploit tag, and not the CVE with only GitHub repositories';
  ASSERT (SELECT worst_risk_score = api.fn_cve_risk_score(5.0, 0.1, false, false, 4, false)
            FROM pg_temp.t_summary('p2004', false)),
         'worst_risk_score is the score of the four exploit references';
  ASSERT pg_temp.t_top('p2004', false, 10) = ARRAY['CVE-2001-0074', 'CVE-2001-0075', 'CVE-2001-0076'],
         'the exploit references put CVE-2001-0074 and CVE-2001-0075 above a CVE with a higher EPSS score';
  ASSERT (SELECT array_agg(risk_score ORDER BY cve_id) FROM api.fn_product_exposure('v2001', 'p2004', false, 10))
         = ARRAY[api.fn_cve_risk_score(5.0, 0.1, false, false, 4, false),
                 api.fn_cve_risk_score(5.0, 0.1, false, false, 2, false),
                 api.fn_cve_risk_score(5.0, 0.102, false, false, 0, false)],
         'each top row of p2004 is scored with its exploit_ref_count, and the GitHub repositories of CVE-2001-0076 do not count';
END
$$;

DO $$
BEGIN
  PERFORM set_config(s, 'off', true)
     FROM unnest(ARRAY['enable_indexscan', 'enable_indexonlyscan', 'enable_bitmapscan', 'enable_mergejoin']) AS s;
  ASSERT pg_temp.t_top('p2005', false, 1) = ARRAY['CVE-2001-0081']
     AND pg_temp.t_top('p2005', false, 2) = ARRAY['CVE-2001-0081', 'CVE-2001-0082'],
         'read in insert order, the row limit still keeps the smallest cve_id of the tied CVEs';
  PERFORM set_config(s, 'on', true)
     FROM unnest(ARRAY['enable_indexscan', 'enable_indexonlyscan', 'enable_bitmapscan', 'enable_mergejoin']) AS s;
END
$$;

INSERT INTO metasploit_modules (cve_id, module_name) VALUES ('CVE-2010-0401', 'm1');
INSERT INTO exploitdb_entries (cve_id, edb_id) VALUES ('CVE-2010-0402', 402);
INSERT INTO cves (cve_id, severity, cvss_v3, cvss_v3_vector, epss_score, in_kev) VALUES
  ('CVE-2010-0401', 'MEDIUM', 5.0, 'CVSS:3.1/AV:N', 0.1, false),
  ('CVE-2010-0402', 'HIGH',   7.0, 'CVSS:3.1/AV:N', 0.1, false),
  ('CVE-2010-0403', 'MEDIUM', 5.0, 'CVSS:3.1/AV:N', 0.1, false);
INSERT INTO cve_products (cve_id, vendor, product, is_vulnerable) VALUES
  ('CVE-2010-0401', 'v2001', 'p2010', true),
  ('CVE-2010-0402', 'v2001', 'p2010', true),
  ('CVE-2010-0403', 'v2001', 'p2010', true);

DO $$
BEGIN
  ASSERT (SELECT cve_count = 3 AND poc_backed_count = 2
            FROM pg_temp.t_summary('p2010', false)),
         'poc_backed_count counts the CVE with a Metasploit module and the CVE with an ExploitDB entry';
  ASSERT (SELECT worst_risk_score = api.fn_cve_risk_score(7.0, 0.1, false, false, 0, true)
             AND worst_risk_score <> api.fn_cve_risk_score(7.0, 0.1, false, false, 0, false)
            FROM pg_temp.t_summary('p2010', false)),
         'worst_risk_score counts the ExploitDB entry';
  ASSERT (SELECT array_agg(risk_score ORDER BY cve_id) FROM api.fn_product_exposure('v2001', 'p2010', false, 10))
         = ARRAY[api.fn_cve_risk_score(5.0, 0.1, false, true, 0, false),
                 api.fn_cve_risk_score(7.0, 0.1, false, false, 0, true),
                 api.fn_cve_risk_score(5.0, 0.1, false, false, 0, false)],
         'each top row of p2010 is scored with its Metasploit module and its ExploitDB entry';
END
$$;

DO $$
DECLARE
  product_name text;
BEGIN
  FOREACH product_name IN ARRAY ARRAY['p2001', 'p2003', 'p2004', 'p2012'] LOOP
    ASSERT (SELECT row(s.*)::text FROM pg_temp.t_summary(product_name, false) AS s)
           = (SELECT row(count(*), count(*) FILTER (WHERE c.severity = 'CRITICAL'),
                         count(*) FILTER (WHERE c.severity = 'HIGH'),
                         count(*) FILTER (WHERE c.severity = 'MEDIUM'),
                         count(*) FILTER (WHERE c.severity = 'LOW'),
                         count(*) FILTER (WHERE c.in_kev),
                         round(COALESCE(max(c.cvss_v3), 0)::numeric, 1)::float8,
                         round(COALESCE(avg(c.cvss_v3) FILTER (WHERE c.cvss_v3 > 0), 0)::numeric, 2)::float8,
                         round(COALESCE(max(c.epss_score), 0)::numeric, 4)::float8,
                         count(*) FILTER (WHERE api.fn_cve_has_public_poc(c.exploit_ref_count, c.has_metasploit, c.has_exploitdb)),
                         COALESCE(max(api.fn_cve_risk_score((CASE WHEN c.cvss_v3_vector <> '' THEN c.cvss_v3 ELSE c.cvss_v4 END),
                                                            c.epss_score, c.in_kev, c.has_metasploit, c.exploit_ref_count, c.has_exploitdb)), 0)::float8,
                         COALESCE(max(c.published_time)::text, ''))::text
                FROM (SELECT DISTINCT c.cve_id, c.severity, c.in_kev, c.cvss_v3, c.cvss_v3_vector, c.cvss_v4,
                             c.has_metasploit, c.has_exploitdb, c.epss_score, c.exploit_ref_count, c.published_time
                        FROM cves AS c JOIN cve_products AS cp ON c.cve_id = cp.cve_id
                       WHERE cp.vendor = 'v2001' AND cp.product = product_name AND cp.is_vulnerable = true) AS c),
           format('the EXISTS summary of %s equals the DISTINCT summary', product_name);
  END LOOP;
END
$$;

INSERT INTO cves (cve_id, severity, cvss_v3, cvss_v3_vector, epss_score, in_kev, published_time, refs, vulnerability_status) VALUES
  ('CVE-2011-0611', 'CRITICAL', 9.5, 'CVSS:3.1/AV:N', 0.9, true,  '2011-01-09',
   '[{"url": "https://r.example", "tags": ["Exploit"]}]', 'Rejected'),
  ('CVE-2011-0612', 'MEDIUM',   4.0, 'CVSS:3.1/AV:N', 0.2, false, '2011-01-02', '[]', ''),
  ('CVE-2011-0613', 'HIGH',     7.0, 'CVSS:3.1/AV:N', 0.4, false, '2011-01-03', '[]', 'Analyzed');
INSERT INTO cve_products (cve_id, vendor, product, is_vulnerable) VALUES
  ('CVE-2011-0611', 'v2001', 'p2011', true),
  ('CVE-2011-0612', 'v2001', 'p2011', true),
  ('CVE-2011-0613', 'v2001', 'p2011', true);

DO $$
BEGIN
  ASSERT (SELECT cve_count = 2 AND critical_count = 0 AND high_count = 1 AND medium_count = 1
             AND kev_count = 0 AND max_cvss = 7.0 AND avg_cvss = 5.5 AND max_epss = 0.4
             AND poc_backed_count = 0
             AND worst_risk_score = api.fn_cve_risk_score(7.0, 0.4, false, false, 0, false)
             AND most_recent_published = '2011-01-03'
            FROM pg_temp.t_summary('p2011', false)),
         'the summary leaves the Rejected CVE out of each number for false';
  ASSERT (SELECT cve_count = 3 AND critical_count = 1 AND kev_count = 1 AND max_cvss = 9.5
             AND poc_backed_count = 1
             AND worst_risk_score = api.fn_cve_risk_score(9.5, 0.9, true, false, 1, false)
             AND most_recent_published = '2011-01-09'
            FROM pg_temp.t_summary('p2011', true)),
         'the summary counts the Rejected CVE for true';
  ASSERT pg_temp.t_top('p2011', false, 10) = ARRAY['CVE-2011-0613', 'CVE-2011-0612'],
         'the top rows leave the Rejected CVE out for false';
  ASSERT pg_temp.t_top('p2011', true, 10) = ARRAY['CVE-2011-0611', 'CVE-2011-0613', 'CVE-2011-0612'],
         'the top rows keep the Rejected CVE for true, first by its score';
END
$$;

PREPARE t_product_exposure_query AS SELECT * FROM api.fn_product_exposure($1, $2, $3, $4);
CREATE TEMP TABLE t_product_exposure_answer AS
  EXECUTE t_product_exposure_query('v2001', 'p2001', 'false', '10');
DEALLOCATE t_product_exposure_query;

DO $$
BEGIN
  ASSERT (SELECT count(*) = 4 AND bool_and(cve_count = 4 AND cve_id IS NOT NULL) FROM t_product_exposure_answer),
         'the query db_PRODUCTEXPOSURE sends answers the product';
  ASSERT (SELECT count(*) FROM pg_proc
          WHERE oid = 'api.fn_product_exposure(text, text, boolean, integer)'::regprocedure
            AND prosecdef AND provolatile = 's' AND proisstrict AND proconfig = ARRAY['search_path=pg_catalog']) = 1,
         'api.fn_product_exposure is SECURITY DEFINER, STABLE and STRICT, and sets search_path to pg_catalog';
  ASSERT to_regprocedure('api.fn_product_exposure_summary(text, text, boolean)') IS NULL
     AND to_regprocedure('api.fn_product_exposure_top(text, text, boolean, integer)') IS NULL,
         'the summary and the top function of schema 78 are gone';
END
$$;

INSERT INTO eol_product (product_name, product_label, url) VALUES
  ('e-aaa', 'AAA', 'https://endoflife.date/e-aaa'), ('e-alpha', 'Alpha', 'https://endoflife.date/e-alpha'),
  ('e-beta', 'Beta', 'https://endoflife.date/e-beta'), ('e-win', 'Win', 'https://endoflife.date/e-win');
INSERT INTO eol_product_cpe (vendor, product, eol_product, series, source) VALUES
  ('v2101', 'p-two', 'e-beta', NULL, 'endoflife'), ('v2101', 'p-two', 'e-alpha', NULL, 'endoflife'),
  ('v2101', 'p-two', 'e-aaa', NULL, 'manual'), ('v2101', 'p-manual', 'e-aaa', NULL, 'manual'),
  ('v2101', 'p-gone', 'e-missing', NULL, 'manual'), ('v2101', 'p-win', 'e-win', '11-24h2', 'manual'),
  ('v2101', 'p-win-one', 'e-win', '10-22h2', 'manual'), ('v2101', 'p-win-all', 'e-win', NULL, 'manual');
INSERT INTO eol_cycle (eol_product, cycle_name, release_date, eol_date, is_eol, is_maintained, is_lts, latest_version) VALUES
  ('e-aaa', 'x1', current_date - 10, NULL, false, true, false, NULL),
  ('e-aaa', 'x0', current_date - 20, current_date - 1, true, true, false, NULL),
  ('e-alpha', '22', current_date - 500, current_date + 365, true, true, true, '22.21.1'),
  ('e-alpha', '22.1', current_date - 400, NULL, true, false, false, NULL),
  ('e-alpha', '2', current_date - 5000, current_date, false, false, false, '2.0.1'),
  ('e-alpha', '2_', current_date - 4000, NULL, false, false, false, NULL),
  ('e-win', '11-24h2-w', current_date - 300, current_date + 10, false, true, false, '26100.1'),
  ('e-win', '11-24h2-e', current_date - 300, current_date + 20, false, true, false, '26100.2'),
  ('e-win', '11-24h2-e-lts', current_date - 300, current_date + 30, false, true, true, NULL),
  ('e-win', '11-24h2-iot-lts', current_date - 300, current_date + 30, false, true, true, NULL),
  ('e-win', '11-24h2-e-iot', current_date - 300, NULL, false, true, false, NULL),
  ('e-win', '11-24h2x', current_date - 300, current_date + 5, false, true, false, NULL),
  ('e-win', '11-24h2-r2', current_date - 300, current_date + 5, false, true, false, NULL),
  ('e-win', '10-22h2', current_date - 900, current_date - 1, false, false, false, '19045.1'),
  ('e-win', '1', current_date - 9000, current_date - 8000, true, false, false, NULL);
INSERT INTO eol_cycle (eol_product, cycle_name, release_date, eol_date, is_eol, is_maintained, is_lts, latest_version)
  SELECT 'e-alpha', format('m%s', lpad(i::text, 2, '0')), current_date - 100 + i, current_date + 1, true, true, i % 2 = 0, NULL
    FROM generate_series(1, 10) AS i;

CREATE FUNCTION pg_temp.t_eol(p_product text, p_version text, p_row_count integer) RETURNS text[]
  LANGUAGE sql STABLE
  RETURN (SELECT coalesce(array_agg(row(e.row_kind, e.name, e.url, e.eol_date, e.is_eol, e.is_maintained, e.is_lts, e.latest_version,
                                        e.maintained_cycle_count)::text ORDER BY e.ordinality), '{}')
            FROM api.fn_product_exposure_eol('v2101', p_product, p_version, p_row_count) WITH ORDINALITY AS e);

CREATE FUNCTION pg_temp.t_eol_names(p_product text, p_version text, p_row_count integer, p_kind text) RETURNS text[]
  LANGUAGE sql STABLE
  RETURN (SELECT coalesce(array_agg(e.name ORDER BY e.ordinality), '{}')
            FROM api.fn_product_exposure_eol('v2101', p_product, p_version, p_row_count) WITH ORDINALITY AS e
           WHERE e.row_kind = p_kind);

DO $$
DECLARE
  today text := to_char(current_date, 'YYYY-MM-DD');
BEGIN
  ASSERT public.fn_eol_cycle_is_in_series('11-24h2', '11-24h2-w') AND public.fn_eol_cycle_is_in_series('11-24h2', '11-24h2-e')
         AND public.fn_eol_cycle_is_in_series('11-24h2', '11-24h2-e-lts') AND public.fn_eol_cycle_is_in_series('11-24h2', '11-24h2-iot-lts'),
         'the series 11-24h2 holds the variants w, e, e-lts and iot-lts';
  ASSERT public.fn_eol_cycle_is_in_series('10-1507', '10-1507') AND public.fn_eol_cycle_is_in_series('10-1507', '10-1507-e-lts')
         AND public.fn_eol_cycle_is_in_series('10-1507', '10-1507-iot'),
         'the series 10-1507 holds its own cycle and its variants';
  ASSERT NOT public.fn_eol_cycle_is_in_series('2012', '2012-r2'), '2012-r2 is a release of its own, not a variant of 2012';
  ASSERT NOT public.fn_eol_cycle_is_in_series('2003', '2003-sp2'), '2003-sp2 is a release of its own, not a variant of 2003';
  ASSERT NOT public.fn_eol_cycle_is_in_series('1', '10-1507'), 'a series is not a bare prefix of a cycle';
  ASSERT NOT public.fn_eol_cycle_is_in_series('11-24h2', '11-24h2x'), 'a series takes a suffix only after a hyphen';
  ASSERT NOT public.fn_eol_cycle_is_in_series('11-24h2', '11-24h2-'), 'an empty suffix is no variant';
  ASSERT NOT public.fn_eol_cycle_is_in_series('11-24h2', '11-24h2_w'), 'only a hyphen opens a suffix';
  ASSERT NOT public.fn_eol_cycle_is_in_series('11-24h2', '11-24h2-e-x'), 'each token of a suffix is a variant token';
  ASSERT NOT public.fn_eol_cycle_is_in_series('11', '11-24h2-e'), 'the first token after the series must be a variant token';
  ASSERT public.fn_eol_cycle_is_in_series(NULL, '11') IS NOT TRUE, 'a NULL series holds no cycle';

  ASSERT pg_temp.t_eol('p-none', NULL, 10) = '{}', 'a pair with no eol_product_cpe row answers no row';
  ASSERT pg_temp.t_eol('p-gone', NULL, 10) = '{}', 'a pair whose product is not in eol_product answers no row';
  ASSERT (pg_temp.t_eol('p-two', NULL, 10))[1] = row('product', 'e-alpha', 'https://endoflife.date/e-alpha', NULL, NULL, NULL, NULL, NULL, 11)::text,
         'the product row comes first: an endoflife row before a manual row, then by eol_product, with its maintained cycle count';
  ASSERT pg_temp.t_eol_names('p-manual', NULL, 10, 'product') = ARRAY['e-aaa'], 'a pair with only a manual row maps to its product';
  ASSERT (pg_temp.t_eol('p-manual', NULL, 10))[1] = row('product', 'e-aaa', 'https://endoflife.date/e-aaa', NULL, NULL, NULL, NULL, NULL, 2)::text,
         'maintained_cycle_count counts a maintained cycle past its eol_date too';
  ASSERT pg_temp.t_eol_names('p-two', 'V22.21.1', 0, 'series') = '{}', 'only a lower-case v is stripped from a version';

  ASSERT pg_temp.t_eol_names('p-two', NULL, 10, 'maintained') = ARRAY['m10', 'm09', 'm08', 'm07', 'm06', 'm05', 'm04', 'm03', 'm02', 'm01'],
         'the maintained cycles come newest release first, cut at the row count';
  ASSERT pg_temp.t_eol_names('p-two', NULL, 11, 'maintained') = ARRAY['m10', 'm09', 'm08', 'm07', 'm06', 'm05', 'm04', 'm03', 'm02', 'm01', '22'],
         'a row count of eleven answers each of the eleven maintained cycles';
  ASSERT pg_temp.t_eol_names('p-two', NULL, 12, 'maintained') = pg_temp.t_eol_names('p-two', NULL, 11, 'maintained'),
         'a row count past the maintained cycles answers each of them once';
  ASSERT pg_temp.t_eol_names('p-two', NULL, 3, 'maintained') = ARRAY['m10', 'm09', 'm08'], 'the row count cuts the list';
  ASSERT pg_temp.t_eol_names('p-two', NULL, NULL, 'maintained') = '{}', 'a NULL row count answers no maintained cycle';
  ASSERT pg_temp.t_eol_names('p-win-all', NULL, 3, 'maintained')
         = ARRAY(SELECT ec.cycle_name FROM eol_cycle AS ec WHERE ec.eol_product = 'e-win' AND ec.is_maintained ORDER BY ec.cycle_name LIMIT 3),
         'of the maintained cycles of one release date, the row count keeps the smallest names';
  ASSERT pg_temp.t_eol_names('p-win-all', NULL, 10, 'maintained')
         = ARRAY(SELECT ec.cycle_name FROM eol_cycle AS ec WHERE ec.eol_product = 'e-win' AND ec.is_maintained ORDER BY ec.cycle_name),
         'the maintained cycles of one release date come by name';
  ASSERT (pg_temp.t_eol('p-two', NULL, 2))[2:3]
         = ARRAY[row('maintained', 'm10', NULL, to_char(current_date + 1, 'YYYY-MM-DD'), false, true, true, NULL, NULL)::text,
                 row('maintained', 'm09', NULL, to_char(current_date + 1, 'YYYY-MM-DD'), false, true, false, NULL, NULL)::text],
         'a maintained row holds its date, is_eol from the date in the future, and its own is_lts';
  ASSERT pg_temp.t_eol_names('p-two', NULL, 10, 'series') = '{}', 'no version and no series answer no series row';

  ASSERT (pg_temp.t_eol('p-two', '22.21.1', 0))[2:]
         = ARRAY[row('series', '22', NULL, to_char(current_date + 365, 'YYYY-MM-DD'), false, true, true, '22.21.1', NULL)::text],
         'a version picks the cycle it starts with, followed by a dot; is_eol is false for a date in the future';
  ASSERT pg_temp.t_eol_names('p-two', '22', 0, 'series') = ARRAY['22'], 'a version equal to a cycle picks it';
  ASSERT pg_temp.t_eol_names('p-two', 'v22.21.1', 0, 'series') = ARRAY['22'], 'one leading v is stripped';
  ASSERT pg_temp.t_eol_names('p-two', 'vv22', 0, 'series') = '{}', 'only one leading v is stripped';
  ASSERT (pg_temp.t_eol('p-two', '22.1.5', 0))[2:] = ARRAY[row('series', '22.1', NULL, NULL, true, false, false, NULL, NULL)::text],
         'the longest cycle wins, and a cycle with no date keeps the stored is_eol';
  ASSERT pg_temp.t_eol_names('p-two', '220.1', 0, 'series') = '{}', 'a cycle must end at a dot of the version';
  ASSERT pg_temp.t_eol_names('p-two', '2a.1', 0, 'series') = '{}', 'an underscore of a cycle name is no wildcard';
  ASSERT (pg_temp.t_eol('p-two', '2.5', 0))[2:] = ARRAY[row('series', '2', NULL, today, true, false, false, '2.0.1', NULL)::text],
         'a cycle whose date is today is EOL, though its stored flag is not';
  ASSERT pg_temp.t_eol_names('p-two', 'zz', 0, 'series') = '{}', 'a version that picks no cycle answers no series row';

  ASSERT pg_temp.t_eol_names('p-win', NULL, 0, 'series') = ARRAY['11-24h2-w', '11-24h2-e', '11-24h2-e-lts', '11-24h2-iot-lts', '11-24h2-e-iot'],
         'a manual series answers its cycles by date, then by name, a cycle with no date last';
  ASSERT pg_temp.t_eol_names('p-win', '10-22h2', 0, 'series') = pg_temp.t_eol_names('p-win', NULL, 0, 'series'),
         'the series of a manual row wins over the version';
  ASSERT pg_temp.t_eol('p-win-one', NULL, 0)
         = ARRAY[row('product', 'e-win', 'https://endoflife.date/e-win', NULL, NULL, NULL, NULL, NULL, 7)::text,
                 row('series', '10-22h2', NULL, to_char(current_date - 1, 'YYYY-MM-DD'), true, false, false, '19045.1', NULL)::text],
         'a series of one cycle answers that cycle, EOL since yesterday';
  ASSERT pg_temp.t_eol_names('p-win-all', '11-24h2', 0, 'series') = pg_temp.t_eol_names('p-win', NULL, 0, 'series'),
         'a version naming a series root picks the whole series';
  ASSERT pg_temp.t_eol_names('p-win-all', NULL, 0, 'series') = '{}', 'a manual row with no series and no version answers no series row';
  ASSERT ARRAY(SELECT e.row_kind FROM api.fn_product_exposure_eol('v2101', 'p-win', NULL, 2) WITH ORDINALITY AS e ORDER BY e.ordinality)
         = ARRAY['product', 'series', 'series', 'series', 'series', 'series', 'maintained', 'maintained'],
         'the rows come by kind: the product row, then every series row, then the maintained rows';
END
$$;

PREPARE t_product_exposure_eol_query AS SELECT * FROM api.fn_product_exposure_eol($1, $2, $3, $4);
CREATE TEMP TABLE t_product_exposure_eol_answer AS
  EXECUTE t_product_exposure_eol_query('v2101', 'p-two', NULL, '10');
DEALLOCATE t_product_exposure_eol_query;

DO $$
BEGIN
  ASSERT (SELECT count(*) FROM t_product_exposure_eol_answer) = 11, 'the eol query db_PRODUCTEXPOSURE sends answers the product';
  ASSERT (SELECT count(*) FROM pg_proc
          WHERE oid = 'api.fn_product_exposure_eol(text, text, text, integer)'::regprocedure
            AND prosecdef AND provolatile = 's' AND proconfig = ARRAY['search_path=pg_catalog']) = 1,
         'api.fn_product_exposure_eol is SECURITY DEFINER and STABLE, and sets search_path to pg_catalog';
  ASSERT (SELECT provolatile = 'i' AND NOT prosecdef FROM pg_proc
          WHERE oid = 'public.fn_eol_cycle_is_in_series(text, text)'::regprocedure),
         'fn_eol_cycle_is_in_series is IMMUTABLE and SECURITY INVOKER';
END
$$;

DO $$
DECLARE
  jit_cost       double precision := current_setting('jit_above_cost')::double precision;
  exposure_plan  json;
  package_plan   json;
BEGIN
  EXECUTE 'EXPLAIN (FORMAT JSON) SELECT eol.row_kind'
       || '  FROM public.fn_eol_product_cpe_pick($1, $2) AS pick'
       || ' CROSS JOIN LATERAL api.fn_eol_answer(pick.eol_product, pick.series, $3, $4) WITH ORDINALITY AS eol'
       || ' ORDER BY eol.ordinality'
     INTO exposure_plan USING 'v2101'::text, 'p-two'::text, NULL::text, 10;
  EXECUTE 'EXPLAIN (FORMAT JSON) SELECT eol.row_kind'
       || '  FROM (SELECT api.fn_package_check_ecosystem($1)) AS canonical (ecosystem)'
       || ' CROSS JOIN LATERAL public.fn_eol_product_package_pick(canonical.ecosystem,'
       || '                    public.fn_osv_normalize_package_name(canonical.ecosystem, $2)) AS pick'
       || ' CROSS JOIN LATERAL api.fn_eol_answer(pick.eol_product, NULL, $3, $4) WITH ORDINALITY AS eol'
       || ' ORDER BY eol.ordinality'
     INTO package_plan USING 'npm'::text, 'nodejs'::text, NULL::text, 10;
  ASSERT (exposure_plan -> 0 -> 'Plan' ->> 'Total Cost')::double precision < jit_cost,
         format('the eol query of /product_exposure costs %s, at or above jit_above_cost %s',
                exposure_plan -> 0 -> 'Plan' ->> 'Total Cost', jit_cost);
  ASSERT (package_plan -> 0 -> 'Plan' ->> 'Total Cost')::double precision < jit_cost,
         format('the eol query of /package_check costs %s, at or above jit_above_cost %s',
                package_plan -> 0 -> 'Plan' ->> 'Total Cost', jit_cost);
  ASSERT (SELECT prorows FROM pg_proc WHERE oid = 'api.fn_eol_answer(text, text, text, integer)'::regprocedure) = 20,
         'api.fn_eol_answer tells the planner ROWS 20';
END
$$;

DELETE FROM eol_product_cpe WHERE vendor = 'v2101';
DELETE FROM eol_product WHERE product_name IN ('e-aaa', 'e-alpha', 'e-beta', 'e-win');
