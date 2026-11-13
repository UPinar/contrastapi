CREATE FUNCTION api.fn_cve_risk_exploitability(p_epss_score     real,
                                               p_in_kev         boolean,
                                               p_has_metasploit boolean)
  RETURNS double precision
  LANGUAGE sql IMMUTABLE PARALLEL SAFE
  RETURN LEAST(60::float8,
               CASE WHEN p_epss_score IS NULL
                      OR p_epss_score IN ('NaN'::real, 'Infinity'::real, '-Infinity'::real)
                    THEN 0::float8
                    ELSE GREATEST(0::float8, LEAST(1::float8, p_epss_score::numeric::float8))
               END * 40
               + CASE WHEN p_in_kev THEN 15::float8 ELSE 0::float8 END
               + CASE WHEN p_has_metasploit THEN 5::float8 ELSE 0::float8 END);

CREATE FUNCTION api.fn_cve_risk_impact(p_cvss_score real)
  RETURNS double precision
  LANGUAGE sql IMMUTABLE PARALLEL SAFE
  RETURN CASE WHEN p_cvss_score IS NULL
                OR p_cvss_score IN ('NaN'::real, 'Infinity'::real, '-Infinity'::real)
              THEN 0::float8
              ELSE GREATEST(0::float8, LEAST(10::float8, p_cvss_score::numeric::float8)) END * 3;

CREATE FUNCTION api.fn_cve_risk_evidence(p_exploit_ref_count integer, p_has_exploitdb boolean)
  RETURNS double precision
  LANGUAGE sql IMMUTABLE PARALLEL SAFE
  RETURN LEAST(10::float8,
               ln(GREATEST(p_exploit_ref_count, CASE WHEN p_has_exploitdb THEN 1 ELSE 0 END)::float8 + 1)
               / ln(101::float8) * 10);

CREATE FUNCTION api.fn_cve_has_public_poc(p_exploit_ref_count integer,
                                          p_has_metasploit    boolean,
                                          p_has_exploitdb     boolean)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE PARALLEL SAFE
  RETURN p_exploit_ref_count > 0 OR p_has_metasploit OR p_has_exploitdb;

CREATE FUNCTION api.fn_cve_risk_score(p_cvss_score real, p_epss_score real, p_in_kev boolean,
                                      p_has_metasploit boolean, p_exploit_ref_count integer,
                                      p_has_exploitdb boolean)
  RETURNS double precision
  LANGUAGE sql IMMUTABLE PARALLEL SAFE
  RETURN floor(LEAST(100::float8, GREATEST(0::float8,
                 api.fn_cve_risk_exploitability(p_epss_score, p_in_kev, p_has_metasploit)
               + api.fn_cve_risk_impact(p_cvss_score)
               + api.fn_cve_risk_evidence(p_exploit_ref_count, p_has_exploitdb))) * 10 + 0.5) / 10;

CREATE FUNCTION api.fn_cve_risk_label(p_score double precision)
  RETURNS text
  LANGUAGE sql IMMUTABLE PARALLEL SAFE
  RETURN (ARRAY['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'])
           [width_bucket(p_score, ARRAY[40, 70, 90]::float8[]) + 1];
