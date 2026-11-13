CREATE FUNCTION api.fn_cwe_lookup(p_cwe_id text)
  RETURNS TABLE (cwe_id               text,
                 cwe_name             text,
                 cwe_description      text,
                 likelihood           text,
                 parent_cwe           text,
                 updated_at           timestamptz,
                 mitigations          jsonb,
                 extended_description text,
                 examples             jsonb,
                 abstract_type        text,
                 cwe_status           text,
                 kev_cve_count        bigint,
                 avg_cvss             double precision,
                 avg_epss             double precision,
                 cve_count            bigint)
  LANGUAGE sql STABLE SECURITY DEFINER
  SET search_path = pg_catalog
  BEGIN ATOMIC
    SELECT c1.cwe_id               AS cwe_id,
           c1.cwe_name             AS cwe_name,
           c1.cwe_description      AS cwe_description,
           c1.likelihood           AS likelihood,
           c1.parent_cwe           AS parent_cwe,
           c1.updated_at           AS updated_at,
           c1.mitigations          AS mitigations,
           c1.extended_description AS extended_description,
           c1.examples             AS examples,
           c1.abstract_type        AS abstract_type,
           c1.cwe_status           AS cwe_status,
           cve_stats.kev_cve_count AS kev_cve_count,
           cve_stats.avg_cvss      AS avg_cvss,
           cve_stats.avg_epss      AS avg_epss,
           cve_stats.cve_count     AS cve_count
      FROM public.cwes AS c1
     CROSS JOIN LATERAL (
       SELECT count(*) FILTER (WHERE c2.in_kev)                                                           AS kev_cve_count,
              round(COALESCE(avg(c2.cvss_v3) FILTER (WHERE c2.cvss_v3 > 0), 0)::numeric, 2)::float8       AS avg_cvss,
              round(COALESCE(avg(c2.epss_score) FILTER (WHERE c2.epss_score > 0), 0)::numeric, 4)::float8 AS avg_epss,
              count(*)                                                                                    AS cve_count
         FROM public.cves AS c2
        WHERE c2.cwe_id = c1.cwe_id) AS cve_stats
     WHERE c1.cwe_id = p_cwe_id;
  END;
