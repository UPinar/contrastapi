CREATE FUNCTION api.fn_cve_triage_bulk(p_cve_ids text[])
  RETURNS TABLE (cve_id     text,
                 epss_score real,
                 cvss_v3    real,
                 risk_score double precision,
                 risk_label text)
  LANGUAGE sql STABLE SECURITY DEFINER
  SET search_path = pg_catalog
  BEGIN ATOMIC
    SELECT c.cve_id                                 AS cve_id,
           c.epss_score                             AS epss_score,
           c.cvss_v3                                AS cvss_v3,
           scored.risk_score                        AS risk_score,
           api.fn_cve_risk_label(scored.risk_score) AS risk_label
      FROM public.cves AS c
     CROSS JOIN LATERAL (SELECT CASE WHEN c.cvss_v3_vector <> '' THEN c.cvss_v3
                                     ELSE c.cvss_v4 END) AS effective (cvss)
     CROSS JOIN LATERAL (SELECT api.fn_cve_risk_score(effective.cvss, c.epss_score, c.in_kev,
                                                      c.has_metasploit, c.exploit_ref_count, c.has_exploitdb)) AS scored (risk_score)
     WHERE c.cve_id = ANY (p_cve_ids)
     ORDER BY scored.risk_score DESC, c.epss_score DESC, c.cvss_v3 DESC, c.cve_id ASC;
  END;
