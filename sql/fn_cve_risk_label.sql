CREATE FUNCTION api.fn_cve_has_public_poc(p_exploit_ref_count integer,
                                          p_has_metasploit    boolean,
                                          p_has_exploitdb     boolean)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE PARALLEL SAFE
  RETURN p_exploit_ref_count > 0 OR p_has_metasploit OR p_has_exploitdb;

CREATE FUNCTION api.fn_cve_risk_label(p_score double precision)
  RETURNS text
  LANGUAGE sql IMMUTABLE PARALLEL SAFE
  RETURN (ARRAY['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'])
           [width_bucket(p_score, ARRAY[40, 70, 90]::float8[]) + 1];
