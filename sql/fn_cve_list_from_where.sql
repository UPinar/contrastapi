CREATE FUNCTION api.fn_cve_list_from_where(p_severity            text             DEFAULT NULL,
                                           p_min_cvss            real             DEFAULT NULL,
                                           p_min_epss            real             DEFAULT NULL,
                                           p_in_kev              boolean          DEFAULT NULL,
                                           p_known_ransomware    boolean          DEFAULT NULL,
                                           p_cwe_id              text             DEFAULT NULL,
                                           p_published_after     date             DEFAULT NULL,
                                           p_published_before    date             DEFAULT NULL,
                                           p_vendor              text             DEFAULT NULL,
                                           p_product             text             DEFAULT NULL,
                                           p_min_risk_score      double precision DEFAULT NULL,
                                           p_has_nuclei_template boolean          DEFAULT NULL,
                                           p_include_rejected    boolean          DEFAULT NULL)
  RETURNS text
  LANGUAGE plpgsql IMMUTABLE SECURITY INVOKER
  SET search_path = pg_catalog
AS $$
DECLARE
  conditions text[] := ARRAY[]::text[];
  from_where text   :=
    $q$ FROM public.cves AS c
        CROSS JOIN LATERAL (SELECT CASE WHEN c.cvss_v3_vector    <> '' THEN c.cvss_v3
                                        ELSE c.cvss_v4 END) AS effective (cvss)
        CROSS JOIN LATERAL (SELECT api.fn_cve_risk_score(effective.cvss, c.epss_score, c.in_kev,
                                                         c.has_metasploit, c.exploit_ref_count,
                                                         c.has_exploitdb)) AS scored (risk_score)$q$;
BEGIN
  IF p_severity IS NOT NULL THEN
    conditions := array_append(conditions, 'c.severity = $1');
  END IF;
  IF p_min_cvss IS NOT NULL THEN
    conditions := array_append(conditions, 'effective.cvss >= $2');
  END IF;
  IF p_min_epss IS NOT NULL THEN
    conditions := array_append(conditions, 'c.epss_score >= $3');
  END IF;
  IF p_in_kev IS NOT NULL THEN
    conditions := array_append(conditions, 'c.in_kev = $4');
  END IF;
  IF p_known_ransomware THEN
    conditions := array_append(conditions,
      $q$EXISTS (SELECT 1 FROM public.kev_details AS kd
                  WHERE kd.cve_id = c.cve_id AND kd.known_ransomware_use = $5)$q$);
  END IF;
  IF p_cwe_id IS NOT NULL THEN
    conditions := array_append(conditions, 'c.cwe_id = $6');
  END IF;
  IF p_published_after IS NOT NULL THEN
    conditions := array_append(conditions, 'c.published_time >= $7');
  END IF;
  IF p_published_before IS NOT NULL THEN
    conditions := array_append(conditions, 'c.published_time <= $8');
  END IF;
  IF p_vendor IS NOT NULL OR p_product IS NOT NULL THEN
    conditions := array_append(conditions,
      'EXISTS (SELECT 1 FROM public.cve_products AS cp WHERE cp.cve_id = c.cve_id AND cp.is_vulnerable'
      || CASE WHEN p_vendor IS NOT NULL THEN ' AND cp.vendor = $9' ELSE '' END
      || CASE WHEN p_product IS NOT NULL THEN ' AND cp.product = $10' ELSE '' END
      || ')');
  END IF;
  IF p_min_risk_score IS NOT NULL THEN
    conditions := array_append(conditions, 'scored.risk_score >= $11');
  END IF;
  IF p_has_nuclei_template THEN
    conditions := array_append(conditions, 'c.has_nuclei_template');
  END IF;
  IF p_include_rejected IS NOT TRUE THEN
    conditions := array_append(conditions, 'c.vulnerability_status <> ''Rejected''');
  END IF;

  IF cardinality(conditions) = 0 THEN
    RETURN from_where;
  END IF;
  RETURN from_where || ' WHERE ' || array_to_string(conditions, ' AND ');
END
$$;

CREATE FUNCTION api.fn_cve_list_match_count(p_severity            text             DEFAULT NULL,
                                            p_min_cvss            real             DEFAULT NULL,
                                            p_min_epss            real             DEFAULT NULL,
                                            p_in_kev              boolean          DEFAULT NULL,
                                            p_known_ransomware    boolean          DEFAULT NULL,
                                            p_cwe_id              text             DEFAULT NULL,
                                            p_published_after     date             DEFAULT NULL,
                                            p_published_before    date             DEFAULT NULL,
                                            p_vendor              text             DEFAULT NULL,
                                            p_product             text             DEFAULT NULL,
                                            p_min_risk_score      double precision DEFAULT NULL,
                                            p_has_nuclei_template boolean          DEFAULT NULL,
                                            p_include_rejected    boolean          DEFAULT NULL)
  RETURNS bigint
  LANGUAGE plpgsql STABLE SECURITY INVOKER
  SET search_path = pg_catalog
AS $$
DECLARE
  cve_count bigint;
BEGIN
  EXECUTE
    'SELECT count(*)'
    || api.fn_cve_list_from_where(p_severity            => p_severity,
                                  p_min_cvss            => p_min_cvss,
                                  p_min_epss            => p_min_epss,
                                  p_in_kev              => p_in_kev,
                                  p_known_ransomware    => p_known_ransomware,
                                  p_cwe_id              => p_cwe_id,
                                  p_published_after     => p_published_after,
                                  p_published_before    => p_published_before,
                                  p_vendor              => p_vendor,
                                  p_product             => p_product,
                                  p_min_risk_score      => p_min_risk_score,
                                  p_has_nuclei_template => p_has_nuclei_template,
                                  p_include_rejected    => p_include_rejected)
    INTO cve_count
    USING p_severity,
          p_min_cvss,
          p_min_epss,
          p_in_kev,
          p_known_ransomware,
          p_cwe_id,
          p_published_after,
          p_published_before,
          p_vendor,
          p_product,
          p_min_risk_score;
  RETURN cve_count;
END
$$;
