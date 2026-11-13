DO $$
BEGIN
  ASSERT api.fn_cve_risk_exploitability(0.5, true, true) = 40, 'EPSS 0.5 with KEV and Metasploit gives 40';
  ASSERT api.fn_cve_risk_exploitability(0.5, true, false) = 35, 'Metasploit adds 5';
  ASSERT api.fn_cve_risk_exploitability(0.5, false, true) = 25, 'KEV adds 15';
  ASSERT round(api.fn_cve_risk_impact(9.8)::numeric, 6) = 29.4, 'the impact is three times the CVSS score';
  ASSERT round(api.fn_cve_risk_evidence(3, false)::numeric, 4) = 3.0038, '3 PoCs give 3.0038';
  ASSERT api.fn_cve_risk_evidence(1, false) < api.fn_cve_risk_evidence(2, false), 'the evidence grows with the PoC count';
  ASSERT api.fn_cve_risk_score(9.8, 0.5, true, true, 3, false) = 72.4, 'the fixture scores 72.4';
END
$$;

DO $$
BEGIN
  ASSERT api.fn_cve_risk_exploitability(5, false, false) = 40, 'an EPSS score above 1 counts as 1';
  ASSERT api.fn_cve_risk_exploitability(1, true, true) = 60, 'EPSS 1 with KEV and Metasploit gives the full 60';
  ASSERT api.fn_cve_risk_exploitability(-1, false, false) = 0, 'an EPSS score below 0 counts as 0';
  ASSERT api.fn_cve_risk_impact(11) = 30, 'a CVSS score above 10 counts as 10, so the impact stops at 30';
  ASSERT api.fn_cve_risk_impact(-1) = 0, 'a CVSS score below 0 counts as 0';
  ASSERT api.fn_cve_risk_evidence(100, false) = 10, '100 PoCs give the full 10';
  ASSERT api.fn_cve_risk_evidence(1000000, false) = 10, 'the evidence stops at 10';
  ASSERT api.fn_cve_risk_evidence(0, false) = 0, 'no PoC gives 0';
  ASSERT api.fn_cve_risk_evidence(-5, false) = 0, 'a negative PoC count gives 0';
  ASSERT api.fn_cve_risk_score(10, 1, true, true, 1000000, false) = 100, 'every part at its cap gives 100';
END
$$;

DO $$
BEGIN
  ASSERT api.fn_cve_risk_score(0, 0.05125, false, false, 0, false) = 2.1, 'EPSS 0.05125 scores 2.1';
  ASSERT floor(0.05125::real::float8 * 40 * 10 + 0.5) / 10 = 2.0, 'a direct cast would score 2.0';
END
$$;

DO $$
BEGIN
  ASSERT api.fn_cve_risk_score('NaN', 0.5, true, true, 3, false) = 43, 'a NaN CVSS score zeroes only the impact';
  ASSERT api.fn_cve_risk_score(9.8, 'Infinity', false, false, 0, false) = 29.4, 'an infinite EPSS score zeroes only its points';
  ASSERT api.fn_cve_risk_score('-Infinity', 'NaN', false, false, 0, false) = 0, 'two non-finite scores give 0';
  ASSERT api.fn_cve_risk_score(NULL, NULL, NULL, NULL, NULL, NULL) = 0, 'NULL inputs give 0';
  ASSERT api.fn_cve_risk_exploitability(NULL, true, false) = 15, 'a NULL EPSS score counts as 0';
  ASSERT api.fn_cve_risk_exploitability('NaN', false, false) = 0, 'a NaN EPSS score counts as 0';
  ASSERT api.fn_cve_risk_exploitability('Infinity', false, false) = 0, 'an infinite EPSS score counts as 0';
  ASSERT api.fn_cve_risk_impact(NULL) = 0, 'a NULL CVSS score counts as 0';
  ASSERT api.fn_cve_risk_impact('NaN') = 0, 'a NaN CVSS score counts as 0';
  ASSERT api.fn_cve_risk_impact('Infinity') = 0, 'an infinite CVSS score counts as 0';
  ASSERT api.fn_cve_risk_evidence(NULL, false) = 0, 'a NULL PoC count gives 0';
END
$$;

DO $$
BEGIN
  ASSERT api.fn_cve_risk_evidence(0, true) = api.fn_cve_risk_evidence(1, false)
     AND api.fn_cve_risk_evidence(0, true) > 0,
         'an ExploitDB entry with no exploit reference gives the evidence of one reference';
  ASSERT api.fn_cve_risk_evidence(3, true) = api.fn_cve_risk_evidence(3, false),
         'an ExploitDB entry adds nothing to three exploit references';
  ASSERT api.fn_cve_risk_evidence(0, false) = 0 AND api.fn_cve_risk_evidence(NULL, NULL) = 0,
         'no exploit reference and no ExploitDB entry give 0';
  ASSERT api.fn_cve_risk_score(9.8, 0.5, false, false, 0, true) = api.fn_cve_risk_score(9.8, 0.5, false, false, 1, false)
     AND api.fn_cve_risk_score(9.8, 0.5, false, false, 0, true) > api.fn_cve_risk_score(9.8, 0.5, false, false, 0, false),
         'the score passes p_has_exploitdb to the evidence part';
  ASSERT api.fn_cve_risk_score(9.8, 0.5, false, true, 0, false) <> api.fn_cve_risk_score(9.8, 0.5, false, false, 0, true),
         'a Metasploit module and an ExploitDB entry add different points, so the two arguments cannot swap';
END
$$;

DO $$
BEGIN
  ASSERT api.fn_cve_has_public_poc(1, false, false), 'one exploit reference alone is a public PoC';
  ASSERT api.fn_cve_has_public_poc(0, true, false), 'a Metasploit module alone is a public PoC';
  ASSERT api.fn_cve_has_public_poc(0, false, true), 'an ExploitDB entry alone is a public PoC';
  ASSERT NOT api.fn_cve_has_public_poc(0, false, false), 'no source is no public PoC';
END
$$;

DO $$
BEGIN
  ASSERT api.fn_cve_risk_label(0) = 'LOW', '0 is LOW';
  ASSERT api.fn_cve_risk_label(39.9) = 'LOW', '39.9 is LOW';
  ASSERT api.fn_cve_risk_label(40) = 'MEDIUM', '40 is MEDIUM';
  ASSERT api.fn_cve_risk_label(69.9) = 'MEDIUM', '69.9 is MEDIUM';
  ASSERT api.fn_cve_risk_label(70) = 'HIGH', '70 is HIGH';
  ASSERT api.fn_cve_risk_label(89.9) = 'HIGH', '89.9 is HIGH';
  ASSERT api.fn_cve_risk_label(90) = 'CRITICAL', '90 is CRITICAL';
  ASSERT api.fn_cve_risk_label(100) = 'CRITICAL', '100 is CRITICAL';
END
$$;

DO $$
BEGIN
  ASSERT api.fn_cve_risk_exploitability(0.62375, true, false) + api.fn_cve_risk_impact(0)
         + api.fn_cve_risk_evidence(0, false) < 40, 'the parts add up to less than 40';
  ASSERT api.fn_cve_risk_score(0, 0.62375, true, false, 0, false) >= 40, 'the rounded score reaches 40';
END
$$;

DO $$
DECLARE
  risk_functions regprocedure[] := ARRAY[
    'api.fn_cve_risk_exploitability(real, boolean, boolean)'::regprocedure,
    'api.fn_cve_risk_impact(real)'::regprocedure,
    'api.fn_cve_risk_evidence(integer, boolean)'::regprocedure,
    'api.fn_cve_risk_score(real, real, boolean, boolean, integer, boolean)'::regprocedure,
    'api.fn_cve_risk_label(double precision)'::regprocedure,
    'api.fn_cve_has_public_poc(integer, boolean, boolean)'::regprocedure];
BEGIN
  ASSERT (SELECT count(*) FROM pg_proc WHERE oid = ANY (risk_functions) AND proconfig IS NULL) = 6,
         'no risk function sets a parameter';
  ASSERT (SELECT count(*) FROM pg_proc WHERE oid = ANY (risk_functions) AND NOT prosecdef) = 6,
         'every risk function is SECURITY INVOKER';
  ASSERT (SELECT count(*) FROM pg_proc WHERE oid = ANY (risk_functions) AND provolatile = 'i') = 6,
         'every risk function is IMMUTABLE';
  ASSERT (SELECT count(*) FROM pg_proc WHERE oid = ANY (risk_functions) AND NOT proisstrict) = 6,
         'no risk function is STRICT';
  ASSERT (SELECT count(*) FROM pg_proc WHERE oid = ANY (risk_functions) AND prosqlbody IS NOT NULL) = 6,
         'every risk function has a SQL-standard body';
END
$$;

DO $$
DECLARE
  plan_line text;
BEGIN
  FOR plan_line IN EXECUTE
    'EXPLAIN (VERBOSE, COSTS OFF) '
    || $q$SELECT c.cve_id AS cve_id, c.epss_score AS epss_score, c.cvss_v3 AS cvss_v3,
              scored.risk_score AS risk_score,
              api.fn_cve_risk_label(scored.risk_score) AS risk_label$q$
    || api.fn_cve_list_from_where(p_min_risk_score => 40)
    || ' ORDER BY scored.risk_score DESC, c.epss_score DESC, c.cvss_v3 DESC, c.cve_id ASC'
    || ' LIMIT $12 OFFSET $13'
    USING NULL::text, NULL::real, NULL::real, NULL::boolean, NULL::boolean, NULL::text,
          NULL::date, NULL::date, NULL::text, NULL::text, 40::double precision, 20, 0
  LOOP
    ASSERT plan_line NOT LIKE '%fn\_cve\_risk%', 'the triage page inlines every risk function';
  END LOOP;

  FOR plan_line IN EXECUTE $q$
    EXPLAIN (VERBOSE, COSTS OFF)
    SELECT api.fn_cve_risk_score((CASE WHEN c.cvss_v3_vector <> '' THEN c.cvss_v3 ELSE c.cvss_v4 END),
                                 c.epss_score, c.in_kev, c.has_metasploit, c.exploit_ref_count, c.has_exploitdb) AS risk_score,
           api.fn_cve_risk_exploitability(c.epss_score, c.in_kev, c.has_metasploit) AS exploitability,
           api.fn_cve_risk_impact((CASE WHEN c.cvss_v3_vector <> '' THEN c.cvss_v3 ELSE c.cvss_v4 END)) AS impact,
           api.fn_cve_risk_evidence(c.exploit_ref_count, c.has_exploitdb) AS evidence,
           api.fn_cve_has_public_poc(c.exploit_ref_count, c.has_metasploit, c.has_exploitdb) AS has_public_poc,
           api.fn_cve_risk_label(api.fn_cve_risk_score((CASE WHEN c.cvss_v3_vector <> '' THEN c.cvss_v3 ELSE c.cvss_v4 END),
                                                       c.epss_score, c.in_kev, c.has_metasploit, c.exploit_ref_count, c.has_exploitdb)) AS risk_label
      FROM public.cves AS c WHERE c.cve_id = 'CVE-2021-44228' LIMIT 1$q$
  LOOP
    ASSERT plan_line NOT LIKE '%fn\_cve\_risk%' AND plan_line NOT LIKE '%fn\_cve\_has\_public\_poc%',
           'the /cve_risk_score query inlines every risk function';
  END LOOP;
END
$$;

DO $$
BEGIN
  ASSERT (SELECT count(*)
            FROM pg_depend AS d
            JOIN pg_proc AS f ON d.refclassid = 'pg_proc'::regclass AND d.refobjid = f.oid
           CROSS JOIN LATERAL (
             SELECT CASE WHEN d.classid = 'pg_rewrite'::regclass
                         THEN (SELECT c.relnamespace FROM pg_rewrite AS r JOIN pg_class AS c ON c.oid = r.ev_class
                                WHERE r.oid = d.objid)
                         ELSE (SELECT n.oid FROM pg_namespace AS n
                                WHERE n.nspname = (pg_identify_object(d.classid, d.objid, d.objsubid)).schema)
                    END AS namespace_oid) AS dependent
           WHERE f.pronamespace = 'api'::regnamespace
             AND dependent.namespace_oid IS DISTINCT FROM 'api'::regnamespace
             AND dependent.namespace_oid IS DISTINCT FROM pg_my_temp_schema()) = 0,
         'no object outside the api schema depends on an api function';
END
$$;
