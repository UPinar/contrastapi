TRUNCATE cves, kev_details, cwes, cve_products, epss_history, metasploit_modules, nuclei_templates CASCADE;

INSERT INTO cves (cve_id, severity, cvss_v3, cvss_v3_vector, cvss_v4, cvss_v4_vector,
                  epss_score, in_kev, cwe_id, published_time, epss_percentile) VALUES
  ('CVE-2002-0001', 'HIGH',     7.5,  'CVSS:3.1/AV:N', 0.0, '',              0.3,   true,
   'CWE-79', '2020-01-01', 0.61),
  ('CVE-2002-0002', 'CRITICAL', 9.8,  'CVSS:3.1/AV:N', 0.0, '',              0.9,   true,
   'CWE-89', '2021-06-01', 0.62),
  ('CVE-2002-0003', 'MEDIUM',   0.0,  '',              8.5, 'CVSS:4.0/AV:N', 0.1,   false,
   'CWE-79', '2022-03-01', 0.63),
  ('CVE-2002-0004', 'LOW',      3.1,  'CVSS:3.1/AV:N', 9.9, 'CVSS:4.0/AV:N', 0.5,   false,
   'CWE-20', '2019-05-05', 0.64),
  ('CVE-2002-0005', 'HIGH',     7.5,  'CVSS:3.1/AV:N', 0.0, '',              0.3,   false,
   'CWE-79', '2020-01-01', 0.65),
  ('CVE-2002-0006', 'HIGH',     8.0,  'CVSS:3.1/AV:N', 0.0, '',              0.3,   false,
   'CWE-20', '2018-01-01', 0.66),
  ('CVE-2002-0007', 'MEDIUM',   5.0,  'CVSS:3.1/AV:N', 0.0, '',              0.1,   false,
   'CWE-1',  '2010-01-04', 0.67),
  ('CVE-2002-0008', 'MEDIUM',   5.0,  'CVSS:3.1/AV:N', 0.0, '',              0.1,   false,
   'CWE-1',  '2010-01-03', 0.68),
  ('CVE-2002-0009', 'MEDIUM',   5.01, 'CVSS:3.1/AV:N', 0.0, '',              0.1,   false,
   'CWE-1',  '2010-01-02', 0.69),
  ('CVE-2002-0010', 'MEDIUM',   5.0,  'CVSS:3.1/AV:N', 0.0, '',              0.101, false,
   'CWE-1',  '2010-01-01', 0.70);

INSERT INTO kev_details (cve_id, known_ransomware_use) VALUES
  ('CVE-2002-0001', true),
  ('CVE-2002-0002', false);
INSERT INTO metasploit_modules (cve_id, module_name) VALUES ('CVE-2002-0004', 'm1');
UPDATE cves SET exploit_ref_count = 3 WHERE cve_id = 'CVE-2002-0004';
INSERT INTO github_poc_repos (cve_id, repo_full_name, star_count) VALUES
  ('CVE-2002-0003', 'a-owner/poc', 50),
  ('CVE-2002-0003', 'b-owner/poc', 0),
  ('CVE-2002-0008', 'c-owner/poc', 0);
UPDATE cves SET cvss_v3_source = 'cna', cvss_v4_source = 'adp', cwe_source = 'other' WHERE cve_id = 'CVE-2002-0004';
INSERT INTO nuclei_templates (template_path, cve_id) VALUES
  ('http/cves/2002/CVE-2002-0001.yaml',    'CVE-2002-0001'),
  ('http/cves/2002/CVE-2002-0003.yaml',    'CVE-2002-0003'),
  ('http/cves/2002/CVE-2002-0005.yaml',    'CVE-2002-0005'),
  ('network/cves/2002/CVE-2002-0005.yaml', 'CVE-2002-0005');
INSERT INTO cve_products (cve_id, vendor, product, is_vulnerable) VALUES
  ('CVE-2002-0001', 'acme',  'widget', true),
  ('CVE-2002-0001', 'acme',  'widget', false),
  ('CVE-2002-0002', 'acme',  'gadget', true),
  ('CVE-2002-0003', 'other', 'widget', true),
  ('CVE-2002-0004', 'acme',  'x',      true),
  ('CVE-2002-0004', 'y',     'widget', true),
  ('CVE-2002-0006', 'acme',  'widget', false),
  ('CVE-2002-0007', 'tie',   'tie',    true),
  ('CVE-2002-0008', 'tie',   'tie',    true),
  ('CVE-2002-0009', 'tie',   'tie',    true),
  ('CVE-2002-0010', 'tie',   'tie',    true);

CREATE TEMP TABLE t_cve_search_case (
  label                 text,
  severity              text,
  min_cvss              real,
  min_epss              real,
  in_kev                boolean,
  known_ransomware      boolean,
  cwe_id                text,
  published_after       date,
  published_before      date,
  vendor                text,
  product               text,
  sort                  text,
  expected              text[],
  has_nuclei_template   boolean);
INSERT INTO t_cve_search_case VALUES
  ('no filter, no sort',  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
   '{03,02,01,05,04,06,07,08,09,10}'),
  ('an unknown sort',     NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 'x',
   '{03,02,01,05,04,06,07,08,09,10}'),
  ('sort epss',           NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 'epss',
   '{02,04,01,05,06,10,03,07,08,09}'),
  ('sort cvss',           NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 'cvss',
   '{02,03,06,01,05,09,07,08,10,04}'),
  ('severity',            'HIGH', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
   '{01,05,06}'),
  ('min_cvss',            NULL, 8.0, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
   '{03,02,06}'),
  ('min_cvss reached',    NULL, 7.5, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
   '{03,02,01,05,06}'),
  ('min_epss',            NULL, NULL, 0.5, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
   '{02,04}'),
  ('in_kev true',         NULL, NULL, NULL, true, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
   '{02,01}'),
  ('in_kev false',        NULL, NULL, NULL, false, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
   '{03,05,04,06,07,08,09,10}'),
  ('known_ransomware',    NULL, NULL, NULL, NULL, true, NULL, NULL, NULL, NULL, NULL, NULL,
   '{01}'),
  ('known_ransomware false', NULL, NULL, NULL, NULL, false, NULL, NULL, NULL, NULL, NULL, NULL,
   '{03,02,01,05,04,06,07,08,09,10}'),
  ('cwe_id',              NULL, NULL, NULL, NULL, NULL, 'CWE-79', NULL, NULL, NULL, NULL, NULL,
   '{03,01,05}'),
  ('published_after',     NULL, NULL, NULL, NULL, NULL, NULL, '2021-06-01', NULL, NULL, NULL,
   NULL, '{03,02}'),
  ('published_before',    NULL, NULL, NULL, NULL, NULL, NULL, NULL, '2020-01-01', NULL, NULL,
   NULL, '{01,05,04,06,07,08,09,10}'),
  ('vendor',              NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 'acme', NULL, NULL,
   '{02,01,04}'),
  ('product',             NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 'widget', NULL,
   '{03,01,04}'),
  ('vendor and product',  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 'acme', 'widget', NULL,
   '{01}'),
  ('every filter',        'HIGH', 7.0, 0.3, true, true, 'CWE-79', '2020-01-01', '2020-01-01',
   'acme', 'widget', 'cvss', '{01}');
INSERT INTO t_cve_search_case VALUES
  ('has_nuclei_template',        NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
   '{03,01,05}', true),
  ('has_nuclei_template false',  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
   '{03,02,01,05,04,06,07,08,09,10}', false),
  ('every filter and has_nuclei_template', 'HIGH', 7.0, 0.3, true, true, 'CWE-79', '2020-01-01',
   '2020-01-01', 'acme', 'widget', 'cvss', '{01}', true);

DO $$
DECLARE
  c record;
BEGIN
  FOR c IN SELECT * FROM t_cve_search_case LOOP
    ASSERT (SELECT COALESCE(array_agg(right(s.cve_id, 2)), '{}')
              FROM api.fn_cve_search(c.severity, c.min_cvss, c.min_epss, c.in_kev,
                                     c.known_ransomware, c.cwe_id, c.published_after,
                                     c.published_before, c.vendor, c.product, c.has_nuclei_template,
                                     false, c.sort, 100, 0)
                   AS s)
           = c.expected,
           'api.fn_cve_search, ' || c.label;
    ASSERT api.fn_cve_search_match_count(c.severity, c.min_cvss, c.min_epss, c.in_kev,
                                         c.known_ransomware, c.cwe_id, c.published_after,
                                         c.published_before, c.vendor, c.product, c.has_nuclei_template,
                                         false)
           = cardinality(c.expected),
           'api.fn_cve_search_match_count, ' || c.label;
  END LOOP;
END
$$;

DO $$
BEGIN
  ASSERT (SELECT array_agg(right(s.cve_id, 2))
            FROM api.fn_cve_search(NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, false,
                                   NULL, 2, 1) AS s)
         = '{02,01}',
         'api.fn_cve_search answers p_row_count rows after skipping p_row_offset rows';
  ASSERT (SELECT count(*)
            FROM api.fn_cve_search(NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, false,
                                   NULL, NULL, 0)) = 0,
         'api.fn_cve_search answers no row for a NULL row count';
  ASSERT (SELECT count(*)
            FROM api.fn_cve_search(NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, false,
                                   NULL, 100, NULL)) = 0,
         'api.fn_cve_search answers no row for a NULL row offset';
  ASSERT (SELECT ROW(s.severity, s.cvss_v3, s.epss_score, s.epss_percentile, s.in_kev,
                     s.published_time, s.cwe_id, s.cvss_v4, s.has_cvss_v4, s.has_cvss_v3,
                     s.cvss_v3_source, s.cvss_v4_source, s.cwe_source)
            FROM api.fn_cve_search(NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, false,
                                   NULL, 100, 0) AS s
           WHERE s.cve_id = 'CVE-2002-0004')
         = ROW('LOW'::text, 3.1::real, 0.5::real, 0.64::real, false, '2019-05-05'::date,
               'CWE-20'::text, 9.9::real, true, true, 'cna'::text, 'adp'::text, 'other'::text),
         'each column of api.fn_cve_search holds its own cves value';
  ASSERT (SELECT ROW(s.has_cvss_v4, s.has_cvss_v3)
            FROM api.fn_cve_search(NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, false,
                                   NULL, 100, 0) AS s
           WHERE s.cve_id = 'CVE-2002-0003')
         = ROW(true, false),
         'has_cvss_v4 and has_cvss_v3 tell which vectors a CVE has';
END
$$;

CREATE TEMP TABLE t_cve_leading_case (
  label               text,
  min_epss            real,
  in_kev              boolean,
  known_ransomware    boolean,
  vendor              text,
  product             text,
  expected            text[],
  has_nuclei_template boolean);
INSERT INTO t_cve_leading_case VALUES
  ('no filter',          NULL, NULL,  NULL, NULL,   NULL,     '{02,04,06,01,05,10,09,07,08,03}'),
  ('min_epss',           0.5,  NULL,  NULL, NULL,   NULL,     '{02,04}'),
  ('in_kev false',       NULL, false, NULL, NULL,   NULL,     '{04,06,05,10,09,07,08,03}'),
  ('known_ransomware',   NULL, NULL,  true, NULL,   NULL,     '{01}'),
  ('vendor',             NULL, NULL,  NULL, 'acme', NULL,     '{02,04,01}'),
  ('product',            NULL, NULL,  NULL, NULL,   'widget', '{04,01,03}'),
  ('vendor and product', NULL, NULL,  NULL, 'acme', 'widget', '{01}'),
  ('every filter',       0.3,  true,  true, 'acme', 'widget', '{01}');
INSERT INTO t_cve_leading_case VALUES
  ('has_nuclei_template',       NULL, NULL,  NULL, NULL,   NULL,     '{01,05,03}', true),
  ('has_nuclei_template false', NULL, NULL,  NULL, NULL,   NULL,     '{02,04,06,01,05,10,09,07,08,03}', false),
  ('every filter and has_nuclei_template', 0.3, true, true, 'acme', 'widget', '{01}', true);

DO $$
DECLARE
  c record;
BEGIN
  FOR c IN SELECT * FROM t_cve_leading_case LOOP
    ASSERT (SELECT COALESCE(array_agg(right(l.cve_id, 2)), '{}')
              FROM api.fn_cve_leading(c.min_epss, c.in_kev, c.known_ransomware, c.vendor,
                                      c.product, c.has_nuclei_template, false, 100) AS l)
           = c.expected,
           'api.fn_cve_leading, ' || c.label;
    ASSERT api.fn_cve_leading_match_count(c.min_epss, c.in_kev, c.known_ransomware, c.vendor,
                                          c.product, c.has_nuclei_template, false)
           = cardinality(c.expected),
           'api.fn_cve_leading_match_count, ' || c.label;
  END LOOP;
  ASSERT (SELECT array_agg(right(l.cve_id, 2))
            FROM api.fn_cve_leading(NULL, NULL, NULL, NULL, NULL, NULL, false, 3) AS l)
         = '{02,04,06}',
         'api.fn_cve_leading answers p_row_count rows';
  ASSERT (SELECT count(*) FROM api.fn_cve_leading(NULL, NULL, NULL, NULL, NULL, NULL, false, NULL)) = 0,
         'api.fn_cve_leading answers no row for a NULL row count';
  ASSERT (SELECT ROW(l.cvss_v3_source, l.cvss_v4_source, l.cwe_source)
            FROM api.fn_cve_leading(NULL, NULL, NULL, NULL, NULL, NULL, false, 100) AS l
           WHERE l.cve_id = 'CVE-2002-0004')
         = ROW('cna'::text, 'adp'::text, 'other'::text),
         'each column of api.fn_cve_leading holds its own cves value';
  ASSERT (SELECT array_agg(l ORDER BY l.cve_id)
            FROM api.fn_cve_leading(NULL, NULL, NULL, NULL, NULL, NULL, false, 100) AS l)
         = (SELECT array_agg(s ORDER BY s.cve_id)
              FROM api.fn_cve_search(NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, false,
                                     NULL, 100, 0) AS s),
         'each row of api.fn_cve_leading holds the values api.fn_cve_search answers for it';
END
$$;

DO $$
DECLARE
  tie_score double precision := api.fn_cve_risk_score(5.0, 0.1, false, false, 0, false);
BEGIN
  ASSERT api.fn_cve_risk_score(5.01, 0.1, false, false, 0, false) = tie_score
     AND api.fn_cve_risk_score(5.0, 0.101, false, false, 0, false) = tie_score,
         'the tie CVEs share one risk score';
  ASSERT (SELECT array_agg(right(t.cve_id, 2))
            FROM api.fn_cve_triage('tie', 'tie', NULL, false, 100, 0) AS t)
         = '{10,09,07,08}',
         'api.fn_cve_triage orders a tie by EPSS score, then CVSS v3 score, then cve_id';
  ASSERT (SELECT array_agg(right(t.cve_id, 2))
            FROM api.fn_cve_triage('tie', 'tie', NULL, false, 2, 1) AS t)
         = '{09,07}',
         'api.fn_cve_triage answers p_row_count rows after skipping p_row_offset rows';
  ASSERT (SELECT array_agg(right(t.cve_id, 2))
            FROM api.fn_cve_triage(NULL, 'tie', tie_score, false, 100, 0) AS t)
         = '{10,09,07,08}',
         'a CVE whose score equals p_min_risk_score is kept';
  ASSERT (SELECT count(*) FROM api.fn_cve_triage(NULL, 'tie', tie_score + 0.01, false, 100, 0)) = 0,
         'a CVE whose score is below p_min_risk_score is dropped';
  ASSERT (SELECT array_agg(right(t.cve_id, 2))
            FROM api.fn_cve_triage('acme', 'widget', NULL, false, 100, 0) AS t)
         = '{01}',
         'api.fn_cve_triage keeps a CVE whose one cve_products row matches both filters';
  ASSERT (SELECT array_agg(right(t.cve_id, 2) ORDER BY t.cve_id)
            FROM api.fn_cve_triage(NULL, 'widget', NULL, false, 100, 0) AS t)
         = '{01,03,04}',
         'api.fn_cve_triage filters on the product alone';
  ASSERT (SELECT array_agg(right(t.cve_id, 2) ORDER BY t.cve_id)
            FROM api.fn_cve_triage('acme', NULL, NULL, false, 100, 0) AS t)
         = '{01,02,04}',
         'api.fn_cve_triage filters on the vendor alone';
  ASSERT (SELECT array_agg(t.risk_score ORDER BY t.risk_score DESC)
            FROM api.fn_cve_triage(NULL, NULL, NULL, false, 100, 0) AS t)
         = (SELECT array_agg(t.risk_score) FROM api.fn_cve_triage(NULL, NULL, NULL, false, 100, 0) AS t),
         'api.fn_cve_triage orders the rows by risk score, highest first';
  ASSERT (SELECT t.risk_score = api.fn_cve_risk_score(8.5, 0.1, false, false, 0, false)
             AND t.epss_score = 0.1::real AND t.cvss_v3 = 0.0::real
            FROM api.fn_cve_triage(NULL, NULL, NULL, false, 100, 0) AS t
           WHERE t.cve_id = 'CVE-2002-0003'),
         'a CVE with no v3 vector is scored on its v4 score, and its GitHub repositories do not count';
  ASSERT (SELECT bool_and(t.risk_label = api.fn_cve_risk_label(t.risk_score))
             AND count(DISTINCT t.risk_label) > 1
            FROM api.fn_cve_triage(NULL, NULL, NULL, false, 100, 0) AS t),
         'each label comes from the score of its row, and the rows hold more than one label';
  ASSERT (SELECT t.risk_score = api.fn_cve_risk_score(7.5, 0.3, true, false, 0, false)
            FROM api.fn_cve_triage(NULL, NULL, NULL, false, 100, 0) AS t
           WHERE t.cve_id = 'CVE-2002-0001'),
         'a CVE with a v3 vector is scored on its v3 score';
  ASSERT (SELECT t.risk_score = api.fn_cve_risk_score(3.1, 0.5, false, true, 3, false)
             AND t.risk_score <> api.fn_cve_risk_score(3.1, 0.5, false, false, 3, false)
             AND t.risk_score <> api.fn_cve_risk_score(3.1, 0.5, false, true, 0, false)
            FROM api.fn_cve_triage(NULL, NULL, NULL, false, 100, 0) AS t
           WHERE t.cve_id = 'CVE-2002-0004'),
         'the score reads has_metasploit and exploit_ref_count';
  ASSERT api.fn_cve_triage_match_count(NULL, NULL, NULL, false) = 10,
         'api.fn_cve_triage_match_count counts every CVE when no filter is set';
  ASSERT api.fn_cve_triage_match_count('acme', 'widget', NULL, false) = 1,
         'api.fn_cve_triage_match_count counts a CVE with two matching rows once';
  ASSERT api.fn_cve_triage_match_count(NULL, 'tie', tie_score, false) = 4
     AND api.fn_cve_triage_match_count(NULL, 'tie', tie_score + 0.01, false) = 0,
         'api.fn_cve_triage_match_count applies p_min_risk_score';
  ASSERT (SELECT count(*) FROM api.fn_cve_triage(NULL, NULL, NULL, false, NULL, 0)) = 0,
         'api.fn_cve_triage answers no row for a NULL row count';
  ASSERT (SELECT count(*) FROM api.fn_cve_triage(NULL, NULL, NULL, false, 100, NULL)) = 0,
         'api.fn_cve_triage answers no row for a NULL row offset';
END
$$;

DO $$
DECLARE
  lifted_score double precision := api.fn_cve_risk_score(5.0, 0.1, false, false, 6, false);
BEGIN
  UPDATE cves SET exploit_ref_count = 6 WHERE cve_id = 'CVE-2002-0008';
  ASSERT lifted_score > api.fn_cve_risk_score(5.0, 0.1, false, false, 0, false),
         'six exploit references raise the tie score';
  ASSERT (SELECT array_agg(right(t.cve_id, 2))
            FROM api.fn_cve_triage(NULL, 'tie', lifted_score, false, 100, 0) AS t)
         = '{08}',
         'api.fn_cve_triage keeps the CVE that only its exploit references lift to p_min_risk_score';
  ASSERT api.fn_cve_triage_match_count(NULL, 'tie', lifted_score, false) = 1,
         'api.fn_cve_triage_match_count counts the CVE that only its exploit references lift to p_min_risk_score';
  UPDATE cves SET exploit_ref_count = 0 WHERE cve_id = 'CVE-2002-0008';
END
$$;

PREPARE t_cve_search_query AS
  SELECT * FROM api.fn_cve_search($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15);
PREPARE t_cve_search_match_count_query AS
  SELECT api.fn_cve_search_match_count($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) AS cve_count;
PREPARE t_cve_leading_query AS SELECT * FROM api.fn_cve_leading($1, $2, $3, $4, $5, $6, $7, $8);
PREPARE t_cve_leading_match_count_query AS
  SELECT api.fn_cve_leading_match_count($1, $2, $3, $4, $5, $6, $7) AS cve_count;
PREPARE t_cve_triage_query AS SELECT * FROM api.fn_cve_triage($1, $2, $3, $4, $5, $6);
PREPARE t_cve_triage_match_count_query AS
  SELECT api.fn_cve_triage_match_count($1, $2, $3, $4) AS cve_count;
CREATE TEMP TABLE t_cve_search_answer AS
  EXECUTE t_cve_search_query('HIGH', '7.00', '0.300000', 'true', 'true', 'CWE-79', '2020-01-01',
                             '2020-01-01', 'acme', 'widget', 'true', 'false', 'cvss', '100', '0');
CREATE TEMP TABLE t_cve_search_match_count_answer AS
  EXECUTE t_cve_search_match_count_query('HIGH', '7.00', '0.300000', 'true', 'true', 'CWE-79',
                                   '2020-01-01', '2020-01-01', 'acme', 'widget', 'true', 'false');
CREATE TEMP TABLE t_cve_leading_answer AS
  EXECUTE t_cve_leading_query('0.300000', 'false', NULL, NULL, NULL, NULL, 'false', '2');
CREATE TEMP TABLE t_cve_leading_match_count_answer AS
  EXECUTE t_cve_leading_match_count_query('0.300000', 'false', NULL, NULL, NULL, NULL, 'false');
CREATE TEMP TABLE t_cve_triage_answer AS
  EXECUTE t_cve_triage_query(NULL, 'tie', '0.0000', 'false', '2', '1');
CREATE TEMP TABLE t_cve_triage_match_count_answer AS
  EXECUTE t_cve_triage_match_count_query(NULL, 'tie', '0.0000', 'false');
DEALLOCATE t_cve_search_query;
DEALLOCATE t_cve_search_match_count_query;
DEALLOCATE t_cve_leading_query;
DEALLOCATE t_cve_leading_match_count_query;
DEALLOCATE t_cve_triage_query;
DEALLOCATE t_cve_triage_match_count_query;

DO $$
BEGIN
  ASSERT (SELECT array_agg(cve_id) FROM t_cve_search_answer) = ARRAY['CVE-2002-0001']
     AND (SELECT cve_count FROM t_cve_search_match_count_answer) = 1,
         'the /cve_search calls db.c sends answer the page and the total';
  ASSERT (SELECT array_agg(cve_id) FROM t_cve_leading_answer)
         = ARRAY['CVE-2002-0004', 'CVE-2002-0006']
     AND (SELECT cve_count FROM t_cve_leading_match_count_answer) = 3,
         'the /cve_leading calls db.c sends answer the list and the total';
  ASSERT (SELECT array_agg(cve_id) FROM t_cve_triage_answer)
         = ARRAY['CVE-2002-0009', 'CVE-2002-0007']
     AND (SELECT cve_count FROM t_cve_triage_match_count_answer) = 4,
         'the /cve_triage calls db.c sends answer the page and the total';
END
$$;

DO $$
BEGIN
  ASSERT pg_get_function_result('api.fn_cve_search(text, real, real, boolean, boolean, text,'
                                ' date, date, text, text, boolean, boolean, text, integer, integer)'::regprocedure)
         = 'TABLE(cve_id text, severity text, cvss_v3 real, epss_score real, '
           'epss_percentile real, in_kev boolean, published_time date, cwe_id text, '
           'cvss_v4 real, has_cvss_v4 boolean, has_cvss_v3 boolean, cvss_v3_source text, '
           'cvss_v4_source text, cwe_source text)',
         'api.fn_cve_search answers the list columns, with the types of their cves columns';
  ASSERT pg_get_function_result('api.fn_cve_leading(real, boolean, boolean, text, text,'
                                ' boolean, boolean, integer)'::regprocedure)
         = pg_get_function_result('api.fn_cve_search(text, real, real, boolean, boolean, text,'
                                  ' date, date, text, text, boolean, boolean, text, integer, integer)'::regprocedure),
         'api.fn_cve_leading answers the columns of api.fn_cve_search';
  ASSERT pg_get_function_result('api.fn_cve_triage(text, text, double precision, boolean,'
                                ' integer, integer)'::regprocedure)
         = pg_get_function_result('api.fn_cve_triage_bulk(text[])'::regprocedure),
         'api.fn_cve_triage answers the columns of api.fn_cve_triage_bulk';
  ASSERT (SELECT array_agg(DISTINCT pg_get_function_result(oid)) FROM pg_proc
          WHERE oid IN ('api.fn_cve_search_match_count(text, real, real, boolean, boolean,'
                        ' text, date, date, text, text, boolean, boolean)'::regprocedure,
                        'api.fn_cve_leading_match_count(real, boolean, boolean, text,'
                        ' text, boolean, boolean)'::regprocedure,
                        'api.fn_cve_triage_match_count(text, text,'
                        ' double precision, boolean)'::regprocedure))
         = ARRAY['bigint'],
         'each _match_count function answers one bigint';
END
$$;

CREATE TEMP TABLE cves (LIKE public.cves);
CREATE TEMP TABLE cve_products (LIKE public.cve_products);
CREATE TEMP TABLE kev_details (LIKE public.kev_details);
DO $$
BEGIN
  ASSERT (SELECT array_agg(right(s.cve_id, 2))
            FROM api.fn_cve_search(NULL, NULL, NULL, NULL, true, NULL, NULL, NULL, 'acme',
                                   'widget', true, false, NULL, 100, 0) AS s)
         = '{01}'
     AND api.fn_cve_search_match_count(NULL, NULL, NULL, NULL, true, NULL, NULL, NULL, 'acme',
                                       'widget', true, false) = 1,
         'the list functions read the tables of public while temporary tables share their names';
END
$$;
DROP TABLE pg_temp.cves, pg_temp.cve_products, pg_temp.kev_details;

DO $$
BEGIN
  ASSERT (SELECT bool_and(prosecdef = (proname NOT IN ('fn_cve_list_from_where', 'fn_cve_list_match_count'))
                          AND proconfig IS NOT DISTINCT FROM ARRAY['search_path=pg_catalog']
                          AND provolatile = CASE WHEN proname = 'fn_cve_list_from_where'
                                                 THEN 'i' ELSE 's' END)
            FROM pg_proc
           WHERE pronamespace = 'api'::regnamespace
             AND proname IN ('fn_cve_list_from_where', 'fn_cve_list_match_count', 'fn_cve_search',
                             'fn_cve_search_match_count', 'fn_cve_leading',
                             'fn_cve_leading_match_count', 'fn_cve_triage',
                             'fn_cve_triage_match_count'))
     AND (SELECT count(*) FROM pg_proc
           WHERE pronamespace = 'api'::regnamespace
             AND proname IN ('fn_cve_list_from_where', 'fn_cve_list_match_count', 'fn_cve_search',
                             'fn_cve_search_match_count', 'fn_cve_leading',
                             'fn_cve_leading_match_count', 'fn_cve_triage',
                             'fn_cve_triage_match_count')) = 8,
         'the six list functions the server calls are SECURITY DEFINER, the two helpers are SECURITY INVOKER, '
         'all eight set search_path to pg_catalog; api.fn_cve_list_from_where is IMMUTABLE and the others STABLE';
END
$$;

DO $$
DECLARE
  pair             record;
  include_rejected boolean;
BEGIN
  FOR pair IN SELECT * FROM (VALUES ('tie', 'tie'), ('acme', 'widget')) AS p (vendor, product) LOOP
    FOREACH include_rejected IN ARRAY ARRAY[false, true] LOOP
      ASSERT (SELECT array_agg(t.cve_id ORDER BY t.ordinality)
                FROM api.fn_product_exposure(pair.vendor, pair.product, include_rejected, 100) WITH ORDINALITY AS t
               WHERE t.cve_id IS NOT NULL)
             = (SELECT array_agg(t.cve_id ORDER BY t.ordinality)
                  FROM api.fn_cve_triage(pair.vendor, pair.product, NULL, include_rejected, 100, 0) WITH ORDINALITY AS t),
             format('api.fn_cve_triage answers the top CVEs of api.fn_product_exposure in the same order, %s, %s',
                    pair.vendor, include_rejected);
    END LOOP;
  END LOOP;
  ASSERT (SELECT array_agg(t.cve_id) FROM api.fn_cve_triage('acme', 'widget', NULL, false, 100, 0) AS t) = '{CVE-2002-0001}',
         'a CVE whose only acme/widget row is not vulnerable is left out';
END
$$;

DO $$
DECLARE
  lifted_score        double precision := api.fn_cve_risk_score(5.0, 0.1, false, false, 0, true);
  saved_events_option text             := current_setting('contrastapi.cve_events', true);
BEGIN
  PERFORM set_config('contrastapi.cve_events', 'off', true);
  INSERT INTO exploitdb_entries (cve_id, edb_id) VALUES ('CVE-2010-0501', 501);
  INSERT INTO cves (cve_id, cvss_v3, cvss_v3_vector, epss_score) VALUES
    ('CVE-2010-0501', 5.0, 'CVSS:3.1/AV:N', 0.1),
    ('CVE-2010-0502', 5.0, 'CVSS:3.1/AV:N', 0.12);
  INSERT INTO cve_products (cve_id, vendor, product, is_vulnerable) VALUES
    ('CVE-2010-0501', 'v2010', 'p2010', true),
    ('CVE-2010-0502', 'v2010', 'p2010', true);
  ASSERT lifted_score > api.fn_cve_risk_score(5.0, 0.12, false, false, 0, false),
         'the entry scores CVE-2010-0501 above CVE-2010-0502';
  ASSERT (SELECT array_agg(t.cve_id ORDER BY t.ordinality)
            FROM api.fn_cve_triage('v2010', 'p2010', NULL, false, 100, 0) WITH ORDINALITY AS t)
         = '{CVE-2010-0501,CVE-2010-0502}',
         'api.fn_cve_triage puts the CVE with an ExploitDB entry above a CVE with a higher EPSS score';
  ASSERT (SELECT t.risk_score FROM api.fn_cve_triage('v2010', 'p2010', NULL, false, 100, 0) AS t
           WHERE t.cve_id = 'CVE-2010-0501') = lifted_score,
         'api.fn_cve_triage scores the ExploitDB entry';
  ASSERT (SELECT array_agg(t.cve_id) FROM api.fn_cve_triage('v2010', 'p2010', lifted_score, false, 100, 0) AS t)
         = '{CVE-2010-0501}'
     AND api.fn_cve_triage_match_count('v2010', 'p2010', lifted_score, false) = 1,
         'p_min_risk_score keeps the CVE that only its ExploitDB entry lifts to it';
  DELETE FROM cve_products WHERE vendor = 'v2010';
  DELETE FROM exploitdb_entries WHERE cve_id = 'CVE-2010-0501';
  DELETE FROM cves WHERE cve_id IN ('CVE-2010-0501', 'CVE-2010-0502');
  PERFORM set_config('contrastapi.cve_events', coalesce(saved_events_option, ''), true);
END
$$;

DO $$
DECLARE
  saved_events_option text := current_setting('contrastapi.cve_events', true);
  all_three           text[] := '{CVE-2011-0601,CVE-2011-0602,CVE-2011-0603}';
  not_rejected        text[] := '{CVE-2011-0602,CVE-2011-0603}';
  plan_line           text;
  plan_text           text;
BEGIN
  PERFORM set_config('contrastapi.cve_events', 'off', true);
  INSERT INTO cves (cve_id, cvss_v3, cvss_v3_vector, epss_score, in_kev, vulnerability_status) VALUES
    ('CVE-2011-0601', 9.0, 'CVSS:3.1/AV:N', 0.8, true, 'Rejected'),
    ('CVE-2011-0602', 4.0, 'CVSS:3.1/AV:N', 0.2, false, ''),
    ('CVE-2011-0603', 6.0, 'CVSS:3.1/AV:N', 0.4, false, 'Analyzed');
  INSERT INTO cve_products (cve_id, vendor, product, is_vulnerable) VALUES
    ('CVE-2011-0601', 'rj', 'rj', true),
    ('CVE-2011-0602', 'rj', 'rj', true),
    ('CVE-2011-0603', 'rj', 'rj', true);

  ASSERT (SELECT array_agg(s.cve_id ORDER BY s.cve_id)
            FROM api.fn_cve_search(NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 'rj', 'rj', NULL,
                                   false, NULL, 100, 0) AS s) = not_rejected
     AND api.fn_cve_search_match_count(NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 'rj', 'rj',
                                       NULL, false) = 2,
         'api.fn_cve_search and its total leave a Rejected CVE out for false';
  ASSERT (SELECT array_agg(s.cve_id ORDER BY s.cve_id)
            FROM api.fn_cve_search(NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 'rj', 'rj', NULL,
                                   true, NULL, 100, 0) AS s) = all_three
     AND api.fn_cve_search_match_count(NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 'rj', 'rj',
                                       NULL, true) = 3,
         'api.fn_cve_search and its total keep a Rejected CVE for true';

  ASSERT (SELECT array_agg(l.cve_id ORDER BY l.cve_id)
            FROM api.fn_cve_leading(NULL, NULL, NULL, 'rj', 'rj', NULL, false, 100) AS l) = not_rejected
     AND api.fn_cve_leading_match_count(NULL, NULL, NULL, 'rj', 'rj', NULL, false) = 2,
         'api.fn_cve_leading and its total leave a Rejected CVE out for false';
  ASSERT (SELECT array_agg(l.cve_id ORDER BY l.cve_id)
            FROM api.fn_cve_leading(NULL, NULL, NULL, 'rj', 'rj', NULL, true, 100) AS l) = all_three
     AND api.fn_cve_leading_match_count(NULL, NULL, NULL, 'rj', 'rj', NULL, true) = 3,
         'api.fn_cve_leading and its total keep a Rejected CVE for true';

  ASSERT (SELECT array_agg(t.cve_id ORDER BY t.cve_id)
            FROM api.fn_cve_triage('rj', 'rj', NULL, false, 100, 0) AS t) = not_rejected
     AND api.fn_cve_triage_match_count('rj', 'rj', NULL, false) = 2,
         'api.fn_cve_triage and its total leave a Rejected CVE out for false';
  ASSERT (SELECT array_agg(t.cve_id ORDER BY t.cve_id)
            FROM api.fn_cve_triage('rj', 'rj', NULL, true, 100, 0) AS t) = all_three
     AND api.fn_cve_triage_match_count('rj', 'rj', NULL, true) = 3,
         'api.fn_cve_triage and its total keep a Rejected CVE for true';
  ASSERT (SELECT array_agg(t.cve_id ORDER BY t.ordinality)
            FROM api.fn_product_exposure('rj', 'rj', false, 100) WITH ORDINALITY AS t
           WHERE t.cve_id IS NOT NULL)
         = (SELECT array_agg(t.cve_id ORDER BY t.ordinality)
              FROM api.fn_cve_triage('rj', 'rj', NULL, false, 100, 0) WITH ORDINALITY AS t)
     AND (SELECT array_agg(t.cve_id ORDER BY t.ordinality)
            FROM api.fn_product_exposure('rj', 'rj', true, 100) WITH ORDINALITY AS t
           WHERE t.cve_id IS NOT NULL)
         = (SELECT array_agg(t.cve_id ORDER BY t.ordinality)
              FROM api.fn_cve_triage('rj', 'rj', NULL, true, 100, 0) WITH ORDINALITY AS t),
         'the top rows of api.fn_product_exposure are the CVEs of api.fn_cve_triage for false and for true';

  ASSERT api.fn_cve_list_match_count(p_vendor => 'rj', p_product => 'rj') = 2
     AND api.fn_cve_list_match_count(p_vendor => 'rj', p_product => 'rj', p_include_rejected => false) = 2
     AND api.fn_cve_list_match_count(p_vendor => 'rj', p_product => 'rj', p_include_rejected => true) = 3,
         'api.fn_cve_list_match_count leaves a Rejected CVE out for NULL and false, and keeps it for true';
  ASSERT position($q$c.vulnerability_status <> 'Rejected'$q$ IN api.fn_cve_list_from_where()) > 0
     AND position($q$c.vulnerability_status <> 'Rejected'$q$
                  IN api.fn_cve_list_from_where(p_include_rejected => false)) > 0
     AND position('vulnerability_status' IN api.fn_cve_list_from_where(p_include_rejected => true)) = 0,
         'api.fn_cve_list_from_where adds the Rejected condition for NULL and false, and none for true';

  ASSERT (SELECT indexdef FROM pg_indexes
           WHERE schemaname = 'public' AND indexname = 'idx_cves_not_rejected')
         = $q$CREATE INDEX idx_cves_not_rejected ON public.cves USING btree (cve_id) WHERE (vulnerability_status <> 'Rejected'::text)$q$,
         'idx_cves_not_rejected indexes cve_id of the CVEs that are not Rejected';
  ASSERT (SELECT array_agg(indexdef ORDER BY indexname) FROM pg_indexes
           WHERE schemaname = 'public'
             AND indexname IN ('idx_cves_severity', 'idx_cves_published_time', 'idx_cves_epss',
                               'idx_cves_cwe_id'))
         = ARRAY[$q$CREATE INDEX idx_cves_cwe_id ON public.cves USING btree (cwe_id) INCLUDE (vulnerability_status, in_kev, cvss_v3, epss_score)$q$,
                 $q$CREATE INDEX idx_cves_epss ON public.cves USING btree (epss_score) INCLUDE (vulnerability_status)$q$,
                 $q$CREATE INDEX idx_cves_published_time ON public.cves USING btree (published_time) INCLUDE (vulnerability_status)$q$,
                 $q$CREATE INDEX idx_cves_severity ON public.cves USING btree (severity) INCLUDE (vulnerability_status)$q$],
         'the four filter indexes of cves carry vulnerability_status with INCLUDE';
  ASSERT (SELECT indexdef FROM pg_indexes
           WHERE schemaname = 'public' AND indexname = 'idx_cves_nuclei_published')
         = $q$CREATE INDEX idx_cves_nuclei_published ON public.cves USING btree (published_time DESC, cve_id) INCLUDE (severity, vulnerability_status) WHERE has_nuclei_template$q$,
         'idx_cves_nuclei_published holds the CVEs with a Nuclei template, newest first';
  ASSERT (SELECT indexdef FROM pg_indexes
           WHERE schemaname = 'public' AND indexname = 'idx_products_vulnerable_pair')
         = $q$CREATE INDEX idx_products_vulnerable_pair ON public.cve_products USING btree (vendor, product, cve_id) WHERE is_vulnerable$q$,
         'idx_products_vulnerable_pair holds the vulnerable rows by vendor, product and cve_id';

  SET LOCAL enable_seqscan = off;
  SET LOCAL enable_bitmapscan = off;
  plan_text := '';
  FOR plan_line IN EXECUTE 'EXPLAIN (COSTS OFF) SELECT count(*)' || api.fn_cve_list_from_where() LOOP
    plan_text := plan_text || plan_line || E'\n';
  END LOOP;
  ASSERT position('idx_cves_not_rejected' IN plan_text) > 0,
         'the default count of api.fn_cve_list_from_where can use idx_cves_not_rejected: ' || plan_text;
  plan_text := '';
  FOR plan_line IN EXECUTE 'EXPLAIN (COSTS OFF) SELECT count(*)'
                           || api.fn_cve_list_from_where(p_severity => 'HIGH')
                   USING 'HIGH' LOOP
    plan_text := plan_text || plan_line || E'\n';
  END LOOP;
  ASSERT position('Index Only Scan using idx_cves_severity' IN plan_text) > 0,
         'the default count with severity can read idx_cves_severity alone: ' || plan_text;
  plan_text := '';
  FOR plan_line IN EXECUTE 'EXPLAIN (COSTS OFF) SELECT count(*)'
                           || api.fn_cve_list_from_where(p_has_nuclei_template => true) LOOP
    plan_text := plan_text || plan_line || E'\n';
  END LOOP;
  ASSERT position('idx_cves_nuclei_published' IN plan_text) > 0,
         'the count with has_nuclei_template can use idx_cves_nuclei_published: ' || plan_text;
  plan_text := '';
  FOR plan_line IN EXECUTE 'EXPLAIN (COSTS OFF) SELECT count(*)'
                           || api.fn_cve_list_from_where(p_vendor => 'rj', p_product => 'rp')
                   USING NULL::text, NULL::real, NULL::real, NULL::boolean, NULL::boolean, NULL::text,
                         NULL::date, NULL::date, 'rj'::text, 'rp'::text LOOP
    plan_text := plan_text || plan_line || E'\n';
  END LOOP;
  ASSERT position('idx_products_vulnerable_pair' IN plan_text) > 0,
         'the count with vendor and product can use idx_products_vulnerable_pair: ' || plan_text;
  RESET enable_seqscan;
  RESET enable_bitmapscan;

  DELETE FROM cve_products WHERE vendor = 'rj';
  DELETE FROM cves WHERE cve_id IN ('CVE-2011-0601', 'CVE-2011-0602', 'CVE-2011-0603');
  PERFORM set_config('contrastapi.cve_events', coalesce(saved_events_option, ''), true);
END
$$;
