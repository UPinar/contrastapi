CREATE FUNCTION api.fn_cve_risk_breakdown(p_cve_id text)
  RETURNS TABLE (risk_score     double precision,
                 exploitability double precision,
                 impact         double precision,
                 evidence       double precision,
                 has_public_poc boolean,
                 risk_label     text)
  LANGUAGE sql STABLE SECURITY DEFINER
  SET search_path = pg_catalog
  BEGIN ATOMIC
    SELECT scored.risk_score                                                        AS risk_score,
           api.fn_cve_risk_exploitability(c.epss_score, c.in_kev, c.has_metasploit) AS exploitability,
           api.fn_cve_risk_impact(effective.cvss)                                   AS impact,
           api.fn_cve_risk_evidence(c.exploit_ref_count, c.has_exploitdb)           AS evidence,
           api.fn_cve_has_public_poc(c.exploit_ref_count, c.has_metasploit,
                                     c.has_exploitdb)                               AS has_public_poc,
           api.fn_cve_risk_label(scored.risk_score)                                 AS risk_label
      FROM public.cves AS c
     CROSS JOIN LATERAL (SELECT CASE WHEN c.cvss_v3_vector <> '' THEN c.cvss_v3
                                     ELSE c.cvss_v4 END) AS effective (cvss)
     CROSS JOIN LATERAL (SELECT api.fn_cve_risk_score(effective.cvss, c.epss_score, c.in_kev,
                                                      c.has_metasploit, c.exploit_ref_count, c.has_exploitdb)) AS scored (risk_score)
     WHERE c.cve_id = p_cve_id;
  END;
