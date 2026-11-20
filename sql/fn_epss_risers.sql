CREATE FUNCTION api.fn_epss_risers_window(p_window_days integer)
  RETURNS TABLE (from_date text,
                 to_date   text)
  LANGUAGE sql STABLE SECURITY DEFINER
  SET search_path = pg_catalog
  BEGIN ATOMIC
    SELECT coalesce(to_char(erw.from_date::timestamp, 'YYYY-MM-DD'), '') AS from_date,
           coalesce(to_char(erw.to_date::timestamp, 'YYYY-MM-DD'), '')   AS to_date
      FROM (VALUES (p_window_days)) AS asked (window_days)
      LEFT JOIN public.epss_riser_window AS erw ON erw.window_days = asked.window_days;
  END;

CREATE FUNCTION api.fn_epss_risers(p_window_days    integer,
                                   p_min_epss       real,
                                   p_in_kev         boolean,
                                   p_vendor         text,
                                   p_product        text,
                                   p_cve_row_count  integer,
                                   p_cve_row_offset integer)
  RETURNS TABLE (cve_id              text,
                 epss_score          real,
                 epss_previous_score real,
                 epss_delta          real,
                 epss_percentile     real,
                 in_kev              boolean)
  LANGUAGE plpgsql STABLE SECURITY DEFINER
  SET search_path = pg_catalog
AS $$
DECLARE
  conditions   text[] := ARRAY['er.window_days = $1', 'c.vulnerability_status <> ''Rejected'''];
  matched_with text   := '';
  matched_join text   := '';
BEGIN
  IF p_cve_row_count IS NULL OR p_cve_row_offset IS NULL THEN
    RETURN;
  END IF;
  IF p_min_epss IS NOT NULL THEN
    conditions := array_append(conditions, 'er.score >= $2');
  END IF;
  IF p_in_kev IS NOT NULL THEN
    conditions := array_append(conditions, 'c.in_kev = $3');
  END IF;
  IF p_vendor IS NOT NULL OR p_product IS NOT NULL THEN
    matched_with := 'WITH matched AS MATERIALIZED (SELECT DISTINCT cp.cve_id FROM public.cve_products AS cp WHERE cp.is_vulnerable'
      || CASE WHEN p_vendor IS NOT NULL THEN ' AND cp.vendor = $4' ELSE '' END
      || CASE WHEN p_product IS NOT NULL THEN ' AND cp.product = $5' ELSE '' END
      || ') ';
    matched_join := ' JOIN matched AS m ON m.cve_id = er.cve_id';
  END IF;

  RETURN QUERY EXECUTE
    matched_with
    || $q$SELECT er.cve_id         AS cve_id,
              er.score          AS epss_score,
              er.previous_score AS epss_previous_score,
              er.score_delta    AS epss_delta,
              er.percentile     AS epss_percentile,
              c.in_kev          AS in_kev
         FROM public.epss_riser AS er
         JOIN public.cves AS c ON c.cve_id = er.cve_id$q$ || matched_join || $q$
        WHERE $q$ || array_to_string(conditions, ' AND ')
    || ' ORDER BY er.score_delta DESC, er.cve_id ASC LIMIT $6 OFFSET $7'
    USING p_window_days,
          p_min_epss,
          p_in_kev,
          p_vendor,
          p_product,
          p_cve_row_count,
          p_cve_row_offset;
END
$$;

CREATE FUNCTION api.fn_epss_risers_match_count(p_window_days integer,
                                               p_min_epss    real,
                                               p_in_kev      boolean,
                                               p_vendor      text,
                                               p_product     text)
  RETURNS bigint
  LANGUAGE plpgsql STABLE SECURITY DEFINER
  SET search_path = pg_catalog
AS $$
DECLARE
  conditions text[] := ARRAY['er.window_days = $1', 'c.vulnerability_status <> ''Rejected'''];
  cve_count  bigint;
BEGIN
  IF p_min_epss IS NOT NULL THEN
    conditions := array_append(conditions, 'er.score >= $2');
  END IF;
  IF p_in_kev IS NOT NULL THEN
    conditions := array_append(conditions, 'c.in_kev = $3');
  END IF;
  IF p_vendor IS NOT NULL OR p_product IS NOT NULL THEN
    conditions := array_append(conditions,
      'EXISTS (SELECT 1 FROM public.cve_products AS cp WHERE cp.cve_id = c.cve_id AND cp.is_vulnerable'
      || CASE WHEN p_vendor IS NOT NULL THEN ' AND cp.vendor = $4' ELSE '' END
      || CASE WHEN p_product IS NOT NULL THEN ' AND cp.product = $5' ELSE '' END
      || ')');
  END IF;

  EXECUTE
    $q$SELECT count(*)
         FROM public.epss_riser AS er
         JOIN public.cves AS c ON c.cve_id = er.cve_id
        WHERE $q$ || array_to_string(conditions, ' AND ')
    INTO cve_count
    USING p_window_days,
          p_min_epss,
          p_in_kev,
          p_vendor,
          p_product;
  RETURN cve_count;
END
$$;
