CREATE FUNCTION api.fn_cpe_search_pattern(p_search text)
  RETURNS text
  LANGUAGE sql IMMUTABLE SECURITY INVOKER
  RETURN '%' || replace(replace(lower(translate(regexp_replace(p_search, '\\(.)', '\1', 'g'), '_', ' ')), '\', '\\'), '%', '\%') || '%';

CREATE FUNCTION api.fn_cpe_search(p_search             text,
                                  p_product_row_count  integer,
                                  p_product_row_offset integer)
  RETURNS TABLE (vendor               text,
                 product              text,
                 vulnerable_cve_count integer,
                 product_named_by     jsonb)
  LANGUAGE sql STABLE STRICT SECURITY DEFINER
  SET search_path = pg_catalog
  BEGIN ATOMIC
    SELECT cpi.vendor               AS vendor,
           cpi.product              AS product,
           cpi.vulnerable_cve_count AS vulnerable_cve_count,
           cpi.product_named_by     AS product_named_by
      FROM public.cpe_product_index AS cpi
     WHERE cpi.search_key LIKE (SELECT api.fn_cpe_search_pattern(p_search))
     ORDER BY cpi.vulnerable_cve_count DESC, cpi.vendor ASC, cpi.product ASC
     LIMIT p_product_row_count OFFSET p_product_row_offset;
  END;

CREATE FUNCTION api.fn_cpe_search_match_count(p_search text)
  RETURNS bigint
  LANGUAGE sql STABLE SECURITY DEFINER
  SET search_path = pg_catalog
  BEGIN ATOMIC
    SELECT count(*)
      FROM public.cpe_product_index AS cpi
     WHERE cpi.search_key LIKE (SELECT api.fn_cpe_search_pattern(p_search));
  END;
