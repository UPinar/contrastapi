INSERT INTO github_poc_repos (cve_id, repo_full_name, star_count) VALUES
  ('CVE-2001-0032', 'a-owner/poc', 50),
  ('CVE-2001-0032', 'b-owner/poc', 0);
INSERT INTO cves (cve_id, cvss_v3, cvss_v3_vector, cvss_v4, cvss_v4_vector, epss_score, in_kev, refs) VALUES
  ('CVE-2001-0031', 9.8, 'CVSS:3.1/AV:N', 2.0, 'CVSS:4.0/AV:N', 0.5, true,
   '[{"url": "https://a.example", "tags": ["Exploit"]}]'),
  ('CVE-2001-0032', 0.0, '', 8.0, 'CVSS:4.0/AV:N', 0.5, false, '[]'),
  ('CVE-2001-0033', 5.5, 'CVSS:3.1/AV:N', 0.0, '', 0.2, false,
   '[{"url": "https://packetstormsecurity.com/files/33/x.html"},
     {"url": "https://packetstorm.news/files/id/34", "tags": ["Third Party Advisory"]}]'),
  ('CVE-2001-0034', 6.1, 'CVSS:3.1/AV:N', 0.0, '', 0.3, false,
   '[{"url": "https://b.example", "tags": ["Exploit"]},
     {"url": "https://www.exploit-db.com/exploits/41"},
     {"url": "https://www.exploit-db.com/exploits/42", "tags": []},
     {"url": "https://www.exploit-db.com/exploits/43", "tags": ["Third Party Advisory"]}]');
INSERT INTO metasploit_modules (cve_id, module_name) VALUES ('CVE-2001-0031', 'm1');

CREATE TEMP VIEW t_cve_risk_breakdown_call AS SELECT * FROM api.fn_cve_risk_breakdown('CVE-2001-0031');

DO $$
BEGIN
  ASSERT (SELECT array_agg(attname::text ORDER BY attnum) FROM pg_attribute
          WHERE attrelid = 't_cve_risk_breakdown_call'::regclass AND attnum > 0)
         = ARRAY['risk_score', 'exploitability', 'impact', 'evidence', 'has_public_poc', 'risk_label'],
         'api.fn_cve_risk_breakdown answers the six columns db_CVERISKSCORE reads, in its order';
  ASSERT (SELECT array_agg(format_type(atttypid, atttypmod) ORDER BY attnum) FROM pg_attribute
          WHERE attrelid = 't_cve_risk_breakdown_call'::regclass AND attnum > 0)
         = ARRAY['double precision', 'double precision', 'double precision', 'double precision',
                 'boolean', 'text'],
         'the score and its parts are double precision, has_public_poc boolean and the label text';
  ASSERT (SELECT risk_score = api.fn_cve_risk_score(9.8, 0.5, true, true, 1, false)
             AND exploitability = api.fn_cve_risk_exploitability(0.5, true, true)
             AND impact = api.fn_cve_risk_impact(9.8)
             AND evidence = api.fn_cve_risk_evidence(1, false)
             AND risk_label = api.fn_cve_risk_label(risk_score)
            FROM t_cve_risk_breakdown_call),
         'a CVE with a v3 vector is scored on its v3 score, with KEV, Metasploit and one exploit reference';
  ASSERT (SELECT has_public_poc FROM t_cve_risk_breakdown_call),
         'one exploit reference and a Metasploit module make has_public_poc true';
  ASSERT (SELECT risk_score = api.fn_cve_risk_score(8.0, 0.5, false, false, 0, false)
             AND impact = api.fn_cve_risk_impact(8.0)
             AND risk_label = api.fn_cve_risk_label(risk_score)
             AND risk_label <> api.fn_cve_risk_label(api.fn_cve_risk_score(0.0, 0.5, false, false, 0, false))
             AND NOT has_public_poc
             AND evidence = 0
            FROM api.fn_cve_risk_breakdown('CVE-2001-0032')),
         'a CVE with no v3 vector is scored and labelled on its v4 score, and GitHub repositories with no exploit reference make has_public_poc false and the evidence 0';
  ASSERT (SELECT has_public_poc
             AND evidence = api.fn_cve_risk_evidence(2, false)
             AND evidence > 0
             AND risk_score = api.fn_cve_risk_score(5.5, 0.2, false, false, 2, false)
             AND risk_score <> api.fn_cve_risk_score(5.5, 0.2, false, false, 0, false)
            FROM api.fn_cve_risk_breakdown('CVE-2001-0033')),
         'untagged exploit references alone, with a poc_count of 0, make has_public_poc true and the evidence above 0';
  ASSERT (SELECT has_public_poc
             AND evidence = api.fn_cve_risk_evidence(4, false)
             AND risk_score = api.fn_cve_risk_score(6.1, 0.3, false, false, 4, false)
             AND risk_score <> api.fn_cve_risk_score(6.1, 0.3, false, false, 1, false)
            FROM api.fn_cve_risk_breakdown('CVE-2001-0034')),
         'the evidence and the score count 4 exploit references, not the 1 tagged reference';
  ASSERT (SELECT count(*) FROM api.fn_cve_risk_breakdown('CVE-2001-0039')) = 0,
         'an unknown CVE answers no row';
END
$$;

INSERT INTO exploitdb_entries (cve_id, edb_id) VALUES ('CVE-2010-0201', 201), ('CVE-2010-0203', 203);
INSERT INTO metasploit_modules (cve_id, module_name) VALUES ('CVE-2010-0202', 'm1');
INSERT INTO github_poc_repos (cve_id, repo_full_name, star_count) VALUES ('CVE-2010-0204', 'a-owner/poc', 50);
INSERT INTO cves (cve_id, cvss_v3, cvss_v3_vector, epss_score, refs) VALUES
  ('CVE-2010-0201', 6.5, 'CVSS:3.1/AV:N', 0.2, '[]'),
  ('CVE-2010-0202', 6.5, 'CVSS:3.1/AV:N', 0.2, '[]'),
  ('CVE-2010-0203', 6.5, 'CVSS:3.1/AV:N', 0.2,
   '[{"url": "https://www.exploit-db.com/exploits/2031"}, {"url": "https://www.exploit-db.com/exploits/2032"},
     {"url": "https://www.exploit-db.com/exploits/2033"}]'),
  ('CVE-2010-0204', 6.5, 'CVSS:3.1/AV:N', 0.2, '[]'),
  ('CVE-2010-0205', 6.5, 'CVSS:3.1/AV:N', 0.2, '[{"url": "https://www.exploit-db.com/exploits/2051"}]');

DO $$
BEGIN
  ASSERT (SELECT has_public_poc
             AND evidence = api.fn_cve_risk_evidence(1, false)
             AND exploitability = api.fn_cve_risk_exploitability(0.2, false, false)
             AND risk_score = api.fn_cve_risk_score(6.5, 0.2, false, false, 0, true)
             AND risk_score <> api.fn_cve_risk_score(6.5, 0.2, false, false, 0, false)
            FROM api.fn_cve_risk_breakdown('CVE-2010-0201')),
         'an ExploitDB entry alone makes has_public_poc true and counts as one exploit reference';
  ASSERT (SELECT has_public_poc
             AND evidence = 0
             AND risk_score = api.fn_cve_risk_score(6.5, 0.2, false, true, 0, false)
            FROM api.fn_cve_risk_breakdown('CVE-2010-0202')),
         'a Metasploit module alone makes has_public_poc true and adds no evidence';
  ASSERT (SELECT has_public_poc
             AND evidence = api.fn_cve_risk_evidence(3, false)
             AND risk_score = api.fn_cve_risk_score(6.5, 0.2, false, false, 3, false)
            FROM api.fn_cve_risk_breakdown('CVE-2010-0203')),
         'an ExploitDB entry adds nothing to three exploit references';
  ASSERT (SELECT NOT has_public_poc
             AND evidence = 0
            FROM api.fn_cve_risk_breakdown('CVE-2010-0204')),
         'no exploit reference, Metasploit module or ExploitDB entry makes has_public_poc false';
  ASSERT (SELECT has_public_poc
             AND evidence = api.fn_cve_risk_evidence(1, false)
            FROM api.fn_cve_risk_breakdown('CVE-2010-0205')),
         'an exploit_ref_count of exactly 1 alone makes has_public_poc true';
END
$$;

PREPARE t_cve_risk_breakdown_query AS SELECT * FROM api.fn_cve_risk_breakdown($1);
CREATE TEMP TABLE t_cve_risk_breakdown_answer AS EXECUTE t_cve_risk_breakdown_query('CVE-2001-0031');
DEALLOCATE t_cve_risk_breakdown_query;

DO $$
BEGIN
  ASSERT (SELECT count(*) FROM t_cve_risk_breakdown_answer) = 1,
         'the query db_CVERISKSCORE sends answers the row of its id';
  ASSERT (SELECT prosecdef AND provolatile = 's' FROM pg_proc
          WHERE oid = 'api.fn_cve_risk_breakdown(text)'::regprocedure),
         'api.fn_cve_risk_breakdown is SECURITY DEFINER and STABLE';
  ASSERT (SELECT proconfig FROM pg_proc WHERE oid = 'api.fn_cve_risk_breakdown(text)'::regprocedure)
         = ARRAY['search_path=pg_catalog'],
         'api.fn_cve_risk_breakdown sets search_path to pg_catalog';
END
$$;
