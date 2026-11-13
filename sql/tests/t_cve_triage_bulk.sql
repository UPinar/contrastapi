INSERT INTO cves (cve_id, cvss_v3, cvss_v3_vector, cvss_v4, cvss_v4_vector, epss_score, in_kev) VALUES
  ('CVE-2001-0051', 9.8, 'CVSS:3.1/AV:N', 0.0, '',              0.9, true),
  ('CVE-2001-0052', 5.0, 'CVSS:3.1/AV:N', 0.0, '',              0.1, false),
  ('CVE-2001-0053', 5.0, 'CVSS:3.1/AV:N', 0.0, '',              0.1, false),
  ('CVE-2001-0054', 0.0, '',              8.0, 'CVSS:4.0/AV:N', 0.1, false),
  ('CVE-2001-0055', 5.01, 'CVSS:3.1/AV:N', 0.0, '',             0.1, false),
  ('CVE-2001-0058', 5.0, 'CVSS:3.1/AV:N', 0.0, '',              0.101, false);
INSERT INTO github_poc_repos (cve_id, repo_full_name, star_count) VALUES
  ('CVE-2001-0054', 'a-owner/poc', 50),
  ('CVE-2001-0054', 'b-owner/poc', 0),
  ('CVE-2001-0053', 'c-owner/poc', 0);

CREATE TEMP VIEW t_cve_triage_bulk_call AS
  SELECT * FROM api.fn_cve_triage_bulk(ARRAY['CVE-2001-0053', 'CVE-2001-0059', 'CVE-2001-0052',
                                             'CVE-2001-0054', 'CVE-2001-0051', 'CVE-2001-0055',
                                             'CVE-2001-0058']);

DO $$
BEGIN
  ASSERT (SELECT array_agg(attname::text ORDER BY attnum) FROM pg_attribute
          WHERE attrelid = 't_cve_triage_bulk_call'::regclass AND attnum > 0)
         = ARRAY['cve_id', 'epss_score', 'cvss_v3', 'risk_score', 'risk_label'],
         'api.fn_cve_triage_bulk answers the five columns of a triage row, in their order';
  ASSERT (SELECT array_agg(format_type(atttypid, atttypmod) ORDER BY attnum) FROM pg_attribute
          WHERE attrelid = 't_cve_triage_bulk_call'::regclass AND attnum > 0)
         = ARRAY['text', 'real', 'real', 'double precision', 'text'],
         'epss_score and cvss_v3 keep the type of their cves column';
  ASSERT (SELECT array_agg(cve_id ORDER BY ord) FROM
            (SELECT cve_id, row_number() OVER () AS ord FROM t_cve_triage_bulk_call) AS rows)
         = ARRAY['CVE-2001-0051', 'CVE-2001-0054', 'CVE-2001-0058', 'CVE-2001-0055',
                 'CVE-2001-0052', 'CVE-2001-0053'],
         'the rows come by score, then EPSS score, then CVSS score, a full tie in cve_id order, and the unknown id answers no row';
  ASSERT (SELECT risk_score = api.fn_cve_risk_score(9.8, 0.9, true, false, 0, false)
             AND risk_label = api.fn_cve_risk_label(risk_score)
            FROM t_cve_triage_bulk_call WHERE cve_id = 'CVE-2001-0051'),
         'the score and the label come from the risk functions';
  ASSERT (SELECT risk_score = api.fn_cve_risk_score(8.0, 0.1, false, false, 0, false)
            FROM t_cve_triage_bulk_call WHERE cve_id = 'CVE-2001-0054'),
         'a CVE with no v3 vector is scored on its v4 score, and its GitHub repositories do not count';
END
$$;

INSERT INTO cves (cve_id, cvss_v3, cvss_v3_vector, epss_score, in_kev, refs) VALUES
  ('CVE-2001-0056', 5.0, 'CVSS:3.1/AV:N', 0.1,  false,
   '[{"url": "https://www.exploit-db.com/exploits/56"},
     {"url": "https://www.exploit-db.com/exploits/57", "tags": ["Third Party Advisory"]}]'),
  ('CVE-2001-0057', 5.0, 'CVSS:3.1/AV:N', 0.12, false, '[]');

DO $$
BEGIN
  ASSERT (SELECT array_agg(t.cve_id ORDER BY t.ord) FROM
            (SELECT cve_id, row_number() OVER () AS ord
               FROM api.fn_cve_triage_bulk(ARRAY['CVE-2001-0057', 'CVE-2001-0052', 'CVE-2001-0056'])) AS t)
         = ARRAY['CVE-2001-0056', 'CVE-2001-0057', 'CVE-2001-0052'],
         'the exploit references of CVE-2001-0056 put it above a CVE with a higher EPSS score';
  ASSERT (SELECT risk_score = api.fn_cve_risk_score(5.0, 0.1, false, false, 2, false)
            FROM api.fn_cve_triage_bulk(ARRAY['CVE-2001-0056'])),
         'the score counts the two exploit references';
END
$$;

INSERT INTO exploitdb_entries (cve_id, edb_id) VALUES ('CVE-2010-0301', 301);
INSERT INTO cves (cve_id, cvss_v3, cvss_v3_vector, epss_score, in_kev) VALUES
  ('CVE-2010-0301', 5.0, 'CVSS:3.1/AV:N', 0.1,  false),
  ('CVE-2010-0302', 5.0, 'CVSS:3.1/AV:N', 0.12, false);

DO $$
BEGIN
  ASSERT (SELECT array_agg(t.cve_id ORDER BY t.ord) FROM
            (SELECT cve_id, row_number() OVER () AS ord
               FROM api.fn_cve_triage_bulk(ARRAY['CVE-2010-0302', 'CVE-2010-0301'])) AS t)
         = ARRAY['CVE-2010-0301', 'CVE-2010-0302'],
         'the ExploitDB entry of CVE-2010-0301 puts it above a CVE with a higher EPSS score';
  ASSERT (SELECT risk_score = api.fn_cve_risk_score(5.0, 0.1, false, false, 0, true)
             AND risk_score <> api.fn_cve_risk_score(5.0, 0.1, false, false, 0, false)
            FROM api.fn_cve_triage_bulk(ARRAY['CVE-2010-0301'])),
         'the score counts the ExploitDB entry';
END
$$;

PREPARE t_cve_triage_bulk_query AS SELECT * FROM api.fn_cve_triage_bulk($1);
CREATE TEMP TABLE t_cve_triage_bulk_answer AS
  EXECUTE t_cve_triage_bulk_query('{CVE-2001-0052,CVE-2001-0051}');
DEALLOCATE t_cve_triage_bulk_query;

DO $$
BEGIN
  ASSERT (SELECT array_agg(cve_id ORDER BY cve_id) FROM t_cve_triage_bulk_answer)
         = ARRAY['CVE-2001-0051', 'CVE-2001-0052'],
         'the query db_CVETRIAGEBULK sends answers the rows of its ids';
  ASSERT (SELECT prosecdef AND provolatile = 's' FROM pg_proc
          WHERE oid = 'api.fn_cve_triage_bulk(text[])'::regprocedure),
         'api.fn_cve_triage_bulk is SECURITY DEFINER and STABLE';
  ASSERT (SELECT proconfig FROM pg_proc WHERE oid = 'api.fn_cve_triage_bulk(text[])'::regprocedure)
         = ARRAY['search_path=pg_catalog'],
         'api.fn_cve_triage_bulk sets search_path to pg_catalog';
END
$$;
