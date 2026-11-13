CREATE FUNCTION api.fn_cve_products(p_cve_id             text,
                                    p_vendor             text,
                                    p_product            text,
                                    p_product_row_count  integer,
                                    p_product_row_offset integer)
  RETURNS TABLE (affected_product_count integer,
                 listed_product_count   integer,
                 affected_products      jsonb)
  LANGUAGE sql STABLE SECURITY DEFINER
  SET search_path = pg_catalog
  BEGIN ATOMIC
    WITH filtered_product AS (
      SELECT element.original                                      AS original,
             public.fn_cve_product_is_vulnerable(element.original) AS is_vulnerable,
             element.original ->> 'vendor'                         AS vendor,
             element.original ->> 'product'                        AS product,
             element.original::text                                AS original_text
        FROM public.cves AS c
       CROSS JOIN LATERAL jsonb_array_elements(public.fn_jsonb_array_or_empty(c.affected_products)) AS element (original)
       WHERE c.cve_id = p_cve_id
         AND (p_vendor IS NULL OR element.original ->> 'vendor' = p_vendor)
         AND (p_product IS NULL OR element.original ->> 'product' = p_product))
    SELECT filtered.product_count AS affected_product_count,
           listed.product_count   AS listed_product_count,
           listed.products        AS affected_products
      FROM public.cves AS c
     CROSS JOIN LATERAL (
       SELECT count(*)::integer
         FROM filtered_product) AS filtered (product_count)
     CROSS JOIN LATERAL (
       SELECT count(*)::integer,
              COALESCE(jsonb_agg(product_row.shown ORDER BY product_row.is_vulnerable DESC,
                                                            product_row.vendor COLLATE "C",
                                                            product_row.product COLLATE "C",
                                                            product_row.original_text COLLATE "C"), '[]'::jsonb)
         FROM (SELECT CASE WHEN jsonb_typeof(fp.original) = 'object'
                           THEN fp.original - ARRAY(SELECT product_field.field_name
                                                      FROM jsonb_each(fp.original) AS product_field (field_name, field_value)
                                                     WHERE product_field.field_name IN ('version_start_including', 'version_start_excluding',
                                                                                        'version_end_including', 'version_end_excluding')
                                                       AND product_field.field_value = 'null'::jsonb)
                           ELSE fp.original
                      END                                                          AS shown,
                      fp.is_vulnerable                                             AS is_vulnerable,
                      fp.vendor                                                    AS vendor,
                      fp.product                                                   AS product,
                      fp.original_text                                             AS original_text
                 FROM filtered_product AS fp
                ORDER BY fp.is_vulnerable DESC, fp.vendor COLLATE "C", fp.product COLLATE "C", fp.original_text COLLATE "C"
                LIMIT p_product_row_count OFFSET p_product_row_offset) AS product_row) AS listed (product_count, products)
     WHERE c.cve_id = p_cve_id
       AND p_product_row_count IS NOT NULL
       AND p_product_row_offset IS NOT NULL;
  END;
