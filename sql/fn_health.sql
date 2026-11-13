CREATE FUNCTION api.fn_health()
  RETURNS TABLE (cve_count               bigint,
                 nvd_last_cve_id         text,
                 nvd_last_published_time date,
                 kev_count               bigint,
                 kev_last_cve_id         text,
                 kev_last_date_added     text,
                 cwe_count               bigint,
                 cwe_last_id             text,
                 cwe_last_updated_at     timestamptz)
  LANGUAGE sql STABLE SECURITY DEFINER
  SET search_path = pg_catalog
  BEGIN ATOMIC
    SELECT (SELECT count(*) FROM public.cves)        AS cve_count,
           newest_cve.cve_id                         AS nvd_last_cve_id,
           newest_cve.published_time                 AS nvd_last_published_time,
           (SELECT count(*) FROM public.kev_details) AS kev_count,
           newest_kev.cve_id                         AS kev_last_cve_id,
           newest_kev.kev_date_added                 AS kev_last_date_added,
           (SELECT count(*) FROM public.cwes)        AS cwe_count,
           newest_cwe.cwe_id                         AS cwe_last_id,
           newest_cwe.updated_at                     AS cwe_last_updated_at
      FROM (VALUES (1)) AS one_row (n)
      LEFT JOIN LATERAL (
        SELECT c.cve_id, c.published_time
          FROM public.cves AS c
         ORDER BY c.published_time DESC, c.cve_id DESC
         LIMIT 1) AS newest_cve ON true
      LEFT JOIN LATERAL (
        SELECT kd.cve_id, c.kev_date_added
          FROM public.kev_details AS kd
          JOIN public.cves AS c ON c.cve_id = kd.cve_id
         WHERE c.kev_date_added <> ''
         ORDER BY c.kev_date_added DESC, kd.cve_id DESC
         LIMIT 1) AS newest_kev ON true
      LEFT JOIN LATERAL (
        SELECT w.cwe_id, w.updated_at
          FROM public.cwes AS w
         ORDER BY w.updated_at DESC, w.cwe_id DESC
         LIMIT 1) AS newest_cwe ON true;
  END;
