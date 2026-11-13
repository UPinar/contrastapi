CREATE FUNCTION api.fn_email_disposable_domain(p_domain text)
  RETURNS TABLE (disposable_feed_loaded boolean,
                 listed_domain          text)
  LANGUAGE sql STABLE STRICT SECURITY DEFINER
  SET search_path = pg_catalog
  BEGIN ATOMIC
    SELECT EXISTS (SELECT 1 FROM public.email_disposable_domain) AS disposable_feed_loaded,
           listed.domain                                         AS listed_domain
      FROM (SELECT string_to_array(lower(p_domain), '.')) AS queried (labels)
      CROSS JOIN LATERAL (SELECT ARRAY(SELECT array_to_string(queried.labels[first_label.position:], '.')
                                         FROM generate_series(1, cardinality(queried.labels) - 1) AS first_label (position))) AS candidate (domains)
      LEFT JOIN LATERAL (SELECT edd.domain
                           FROM public.email_disposable_domain AS edd
                          WHERE edd.domain = ANY (candidate.domains)
                          ORDER BY length(edd.domain) DESC
                          LIMIT 1) AS listed ON true;
  END;
