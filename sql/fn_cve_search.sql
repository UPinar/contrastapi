CREATE FUNCTION api.fn_cve_search(p_severity            text,
                                  p_min_cvss            real,
                                  p_min_epss            real,
                                  p_in_kev              boolean,
                                  p_known_ransomware    boolean,
                                  p_cwe_id              text,
                                  p_published_after     date,
                                  p_published_before    date,
                                  p_vendor              text,
                                  p_product             text,
                                  p_has_nuclei_template boolean,
                                  p_include_rejected    boolean,
                                  p_sort                text,
                                  p_cve_row_count       integer,
                                  p_cve_row_offset      integer)
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
  IF p_cve_row_count IS NULL OR p_cve_row_offset IS NULL THEN
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
                                  p_has_nuclei_template => p_has_nuclei_template,
                                  p_include_rejected    => p_include_rejected)
    || ' ORDER BY '
    || CASE p_sort WHEN 'epss' THEN 'c.epss_score DESC'
                   WHEN 'cvss' THEN 'effective.cvss DESC'
                   ELSE 'c.published_time DESC' END
    || ', c.cve_id ASC LIMIT $12 OFFSET $13'
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
          NULL::double precision,
          p_cve_row_count,
          p_cve_row_offset;
END
$$;

CREATE FUNCTION api.fn_cve_search_match_count(p_severity            text,
                                              p_min_cvss            real,
                                              p_min_epss            real,
                                              p_in_kev              boolean,
                                              p_known_ransomware    boolean,
                                              p_cwe_id              text,
                                              p_published_after     date,
                                              p_published_before    date,
                                              p_vendor              text,
                                              p_product             text,
                                              p_has_nuclei_template boolean,
                                              p_include_rejected    boolean)
  RETURNS bigint
  LANGUAGE sql STABLE SECURITY DEFINER
  SET search_path = pg_catalog
  RETURN api.fn_cve_list_match_count(p_severity            => p_severity,
                                     p_min_cvss            => p_min_cvss,
                                     p_min_epss            => p_min_epss,
                                     p_in_kev              => p_in_kev,
                                     p_known_ransomware    => p_known_ransomware,
                                     p_cwe_id              => p_cwe_id,
                                     p_published_after     => p_published_after,
                                     p_published_before    => p_published_before,
                                     p_vendor              => p_vendor,
                                     p_product             => p_product,
                                     p_has_nuclei_template => p_has_nuclei_template,
                                     p_include_rejected    => p_include_rejected);
