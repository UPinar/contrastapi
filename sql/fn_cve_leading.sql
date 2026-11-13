CREATE FUNCTION api.fn_cve_leading(p_min_epss            real,
                                   p_in_kev              boolean,
                                   p_known_ransomware    boolean,
                                   p_vendor              text,
                                   p_product             text,
                                   p_has_nuclei_template boolean,
                                   p_include_rejected    boolean,
                                   p_cve_row_count       integer)
  RETURNS TABLE (cve_id          text,
                 severity        text,
                 cvss_v3         real,
                 epss_score      real,
                 epss_percentile real,
                 in_kev          boolean,
                 published_time  date,
                 cwe_id          text,
                 cvss_v4         real,
                 has_cvss_v4     boolean,
                 has_cvss_v3     boolean,
                 cvss_v3_source  text,
                 cvss_v4_source  text,
                 cwe_source      text)
  LANGUAGE plpgsql STABLE SECURITY DEFINER
  SET search_path = pg_catalog
AS $$
BEGIN
  IF p_cve_row_count IS NULL THEN
    RETURN;
  END IF;
  RETURN QUERY EXECUTE
    $q$SELECT c.cve_id                 AS cve_id,
              c.severity               AS severity,
              c.cvss_v3                AS cvss_v3,
              c.epss_score             AS epss_score,
              c.epss_percentile        AS epss_percentile,
              c.in_kev                 AS in_kev,
              c.published_time         AS published_time,
              c.cwe_id                 AS cwe_id,
              c.cvss_v4                AS cvss_v4,
              (c.cvss_v4_vector <> '') AS has_cvss_v4,
              (c.cvss_v3_vector <> '') AS has_cvss_v3,
              c.cvss_v3_source         AS cvss_v3_source,
              c.cvss_v4_source         AS cvss_v4_source,
              c.cwe_source             AS cwe_source$q$
    || api.fn_cve_list_from_where(p_min_epss            => p_min_epss,
                                  p_in_kev              => p_in_kev,
                                  p_known_ransomware    => p_known_ransomware,
                                  p_vendor              => p_vendor,
                                  p_product             => p_product,
                                  p_has_nuclei_template => p_has_nuclei_template,
                                  p_include_rejected    => p_include_rejected)
    || ' ORDER BY c.epss_score DESC, c.cvss_v3 DESC,    c.cve_id ASC LIMIT $12'
    USING NULL::text,
          NULL::real,
          p_min_epss,
          p_in_kev,
          p_known_ransomware,
          NULL::text,
          NULL::date,
          NULL::date,
          p_vendor,
          p_product,
          NULL::double precision,
          p_cve_row_count;
END
$$;

CREATE FUNCTION api.fn_cve_leading_match_count(p_min_epss            real,
                                               p_in_kev              boolean,
                                               p_known_ransomware    boolean,
                                               p_vendor              text,
                                               p_product             text,
                                               p_has_nuclei_template boolean,
                                               p_include_rejected    boolean)
  RETURNS bigint
  LANGUAGE sql STABLE SECURITY DEFINER
  SET search_path = pg_catalog
  RETURN api.fn_cve_list_match_count(p_min_epss            => p_min_epss,
                                     p_in_kev              => p_in_kev,
                                     p_known_ransomware    => p_known_ransomware,
                                     p_vendor              => p_vendor,
                                     p_product             => p_product,
                                     p_has_nuclei_template => p_has_nuclei_template,
                                     p_include_rejected    => p_include_rejected);
