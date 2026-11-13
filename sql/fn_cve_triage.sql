CREATE FUNCTION api.fn_cve_triage(p_vendor           text,
                                  p_product          text,
                                  p_min_risk_score   double precision,
                                  p_include_rejected boolean,
                                  p_cve_row_count    integer,
                                  p_cve_row_offset   integer)
  RETURNS TABLE (cve_id     text,
                 epss_score real,
                 cvss_v3    real,
                 risk_score double precision,
                 risk_label text)
  LANGUAGE plpgsql STABLE SECURITY DEFINER
  SET search_path = pg_catalog
AS $$
BEGIN
  IF p_cve_row_count IS NULL OR p_cve_row_offset IS NULL THEN
    RETURN;
  END IF;
  RETURN QUERY EXECUTE
    $q$SELECT c.cve_id                                 AS cve_id,
              c.epss_score                             AS epss_score,
              c.cvss_v3                                AS cvss_v3,
              scored.risk_score                        AS risk_score,
              api.fn_cve_risk_label(scored.risk_score) AS risk_label$q$
    || api.fn_cve_list_from_where(p_vendor           => p_vendor,
                                  p_product          => p_product,
                                  p_min_risk_score   => p_min_risk_score,
                                  p_include_rejected => p_include_rejected)
    || ' ORDER BY scored.risk_score DESC, c.epss_score DESC, c.cvss_v3 DESC, c.cve_id ASC'
    || ' LIMIT $12 OFFSET $13'
    USING NULL::text,
          NULL::real,
          NULL::real,
          NULL::boolean,
          NULL::boolean,
          NULL::text,
          NULL::date,
          NULL::date,
          p_vendor,
          p_product,
          p_min_risk_score,
          p_cve_row_count,
          p_cve_row_offset;
END
$$;

CREATE FUNCTION api.fn_cve_triage_match_count(p_vendor           text,
                                              p_product          text,
                                              p_min_risk_score   double precision,
                                              p_include_rejected boolean)
  RETURNS bigint
  LANGUAGE sql STABLE SECURITY DEFINER
  SET search_path = pg_catalog
  RETURN api.fn_cve_list_match_count(p_vendor           => p_vendor,
                                     p_product          => p_product,
                                     p_min_risk_score   => p_min_risk_score,
                                     p_include_rejected => p_include_rejected);
