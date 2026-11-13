CREATE FUNCTION api.fn_product_exposure(p_vendor           text,
                                        p_product          text,
                                        p_include_rejected boolean,
                                        p_cve_row_count    integer)
  RETURNS TABLE (cve_count             bigint,
                 critical_count        bigint,
                 high_count            bigint,
                 medium_count          bigint,
                 low_count             bigint,
                 kev_count             bigint,
                 max_cvss              double precision,
                 avg_cvss              double precision,
                 max_epss              double precision,
                 poc_backed_count      bigint,
                 worst_risk_score      double precision,
                 most_recent_published text,
                 cve_id                text,
                 risk_score            double precision,
                 risk_label            text)
  LANGUAGE sql STABLE STRICT SECURITY DEFINER
  SET search_path = pg_catalog
  BEGIN ATOMIC
    WITH matched AS MATERIALIZED (SELECT c.cve_id            AS cve_id,
                                         c.severity          AS severity,
                                         c.in_kev            AS in_kev,
                                         c.cvss_v3           AS cvss_v3,
                                         c.epss_score        AS epss_score,
                                         c.published_time    AS published_time,
                                         c.exploit_ref_count AS exploit_ref_count,
                                         c.has_metasploit    AS has_metasploit,
                                         c.has_exploitdb     AS has_exploitdb,
                                         scored.risk_score   AS risk_score
                                    FROM public.cves AS c
                                   CROSS JOIN LATERAL (SELECT CASE WHEN c.cvss_v3_vector <> '' THEN c.cvss_v3
                                                                   ELSE c.cvss_v4 END) AS effective (cvss)
                                   CROSS JOIN LATERAL (SELECT api.fn_cve_risk_score(effective.cvss, c.epss_score, c.in_kev,
                                                                                    c.has_metasploit, c.exploit_ref_count, c.has_exploitdb)) AS scored (risk_score)
                                   WHERE EXISTS (SELECT 1
                                                   FROM public.cve_products AS cp
                                                  WHERE cp.cve_id = c.cve_id AND cp.vendor = p_vendor AND cp.product = p_product
                                                    AND cp.is_vulnerable)
                                     AND (p_include_rejected OR c.vulnerability_status <> 'Rejected')),
         summary AS (SELECT count(*)                                                                            AS cve_count,
                            count(*) FILTER (WHERE m.severity = 'CRITICAL')                                     AS critical_count,
                            count(*) FILTER (WHERE m.severity = 'HIGH')                                         AS high_count,
                            count(*) FILTER (WHERE m.severity = 'MEDIUM')                                       AS medium_count,
                            count(*) FILTER (WHERE m.severity = 'LOW')                                          AS low_count,
                            count(*) FILTER (WHERE m.in_kev)                                                    AS kev_count,
                            round(COALESCE(max(m.cvss_v3), 0)::numeric, 1)::float8                              AS max_cvss,
                            round(COALESCE(avg(m.cvss_v3) FILTER (WHERE m.cvss_v3 > 0), 0)::numeric, 2)::float8 AS avg_cvss,
                            round(COALESCE(max(m.epss_score), 0)::numeric, 4)::float8                           AS max_epss,
                            count(*) FILTER (WHERE api.fn_cve_has_public_poc(m.exploit_ref_count, m.has_metasploit,
                                                                             m.has_exploitdb))                  AS poc_backed_count,
                            COALESCE(max(m.risk_score), 0)::float8                                              AS worst_risk_score,
                            COALESCE(max(m.published_time)::text, '')                                           AS most_recent_published
                       FROM matched AS m),
         top_cve AS (SELECT m.cve_id     AS cve_id,
                            m.epss_score AS epss_score,
                            m.cvss_v3    AS cvss_v3,
                            m.risk_score AS risk_score
                       FROM matched AS m
                      ORDER BY m.risk_score DESC, m.epss_score DESC, m.cvss_v3 DESC, m.cve_id ASC
                      LIMIT p_cve_row_count)
    SELECT summary.cve_count                         AS cve_count,
           summary.critical_count                    AS critical_count,
           summary.high_count                        AS high_count,
           summary.medium_count                      AS medium_count,
           summary.low_count                         AS low_count,
           summary.kev_count                         AS kev_count,
           summary.max_cvss                          AS max_cvss,
           summary.avg_cvss                          AS avg_cvss,
           summary.max_epss                          AS max_epss,
           summary.poc_backed_count                  AS poc_backed_count,
           summary.worst_risk_score                  AS worst_risk_score,
           summary.most_recent_published             AS most_recent_published,
           top_cve.cve_id                            AS cve_id,
           top_cve.risk_score                        AS risk_score,
           api.fn_cve_risk_label(top_cve.risk_score) AS risk_label
      FROM summary
      LEFT JOIN top_cve ON true
     ORDER BY top_cve.risk_score DESC, top_cve.epss_score DESC, top_cve.cvss_v3 DESC, top_cve.cve_id ASC;
  END;

CREATE FUNCTION api.fn_eol_answer(p_eol_product                text,
                                  p_series                     text,
                                  p_version                    text,
                                  p_maintained_cycle_row_count integer)
  RETURNS TABLE (row_kind               text,
                 name                   text,
                 url                    text,
                 eol_date               text,
                 is_eol                 boolean,
                 is_maintained          boolean,
                 is_lts                 boolean,
                 latest_version         text,
                 maintained_cycle_count integer)
  LANGUAGE sql STABLE SECURITY INVOKER ROWS 20
  SET search_path = pg_catalog
  BEGIN ATOMIC
    WITH picked AS (SELECT ep.product_name AS eol_product, ep.url AS url
                      FROM public.eol_product AS ep
                     WHERE ep.product_name = p_eol_product),
         product_cycle AS (SELECT ec.cycle_name                                                AS name,
                                  ec.release_date                                              AS release_date,
                                  ec.eol_date                                                  AS eol_date,
                                  public.fn_eol_cycle_is_reached(ec.eol_date, ec.is_eol)       AS is_eol,
                                  ec.is_maintained                                             AS is_maintained,
                                  ec.is_lts                                                    AS is_lts,
                                  ec.latest_version                                            AS latest_version
                             FROM public.eol_cycle AS ec
                             JOIN picked ON ec.eol_product = picked.eol_product),
         series AS (SELECT public.fn_eol_pick_series(picked.eol_product, p_series, p_version) AS name
                      FROM picked),
         answer AS (SELECT 1 AS kind_order, 1::bigint AS row_order, 'product' AS row_kind, picked.eol_product AS name, picked.url AS url,
                           NULL::date AS eol_date, NULL::boolean AS is_eol, NULL::boolean AS is_maintained, NULL::boolean AS is_lts,
                           NULL::text AS latest_version,
                           (SELECT count(*) FROM product_cycle AS pc WHERE pc.is_maintained)::integer AS maintained_cycle_count
                      FROM picked
                    UNION ALL
                    SELECT 2, row_number() OVER (ORDER BY pc.eol_date NULLS LAST, pc.name), 'series', pc.name, NULL,
                           pc.eol_date, pc.is_eol, pc.is_maintained, pc.is_lts, pc.latest_version, NULL
                      FROM product_cycle AS pc
                      JOIN series ON public.fn_eol_cycle_is_in_series(series.name, pc.name)
                    UNION ALL
                    SELECT 3, row_number() OVER (ORDER BY maintained.release_date DESC, maintained.name), 'maintained', maintained.name, NULL,
                           maintained.eol_date, maintained.is_eol, maintained.is_maintained, maintained.is_lts, maintained.latest_version, NULL
                      FROM (SELECT pc.*
                              FROM product_cycle AS pc
                             WHERE pc.is_maintained
                             ORDER BY pc.release_date DESC, pc.name
                             LIMIT coalesce(p_maintained_cycle_row_count, 0)) AS maintained)
    SELECT answer.row_kind                           AS row_kind,
           answer.name                               AS name,
           answer.url                                AS url,
           to_char(answer.eol_date, 'YYYY-MM-DD')    AS eol_date,
           answer.is_eol                             AS is_eol,
           answer.is_maintained                      AS is_maintained,
           answer.is_lts                             AS is_lts,
           answer.latest_version                     AS latest_version,
           answer.maintained_cycle_count             AS maintained_cycle_count
      FROM answer
     ORDER BY answer.kind_order, answer.row_order;
  END;

CREATE FUNCTION api.fn_product_exposure_eol(p_vendor                     text,
                                            p_product                    text,
                                            p_version                    text,
                                            p_maintained_cycle_row_count integer)
  RETURNS TABLE (row_kind               text,
                 name                   text,
                 url                    text,
                 eol_date               text,
                 is_eol                 boolean,
                 is_maintained          boolean,
                 is_lts                 boolean,
                 latest_version         text,
                 maintained_cycle_count integer)
  LANGUAGE sql STABLE SECURITY DEFINER
  SET search_path = pg_catalog
  BEGIN ATOMIC
    SELECT eol.row_kind               AS row_kind,
           eol.name                   AS name,
           eol.url                    AS url,
           eol.eol_date               AS eol_date,
           eol.is_eol                 AS is_eol,
           eol.is_maintained          AS is_maintained,
           eol.is_lts                 AS is_lts,
           eol.latest_version         AS latest_version,
           eol.maintained_cycle_count AS maintained_cycle_count
      FROM public.fn_eol_product_cpe_pick(p_vendor, p_product) AS pick
     CROSS JOIN LATERAL api.fn_eol_answer(pick.eol_product, pick.series, p_version, p_maintained_cycle_row_count) WITH ORDINALITY AS eol
     ORDER BY eol.ordinality;
  END;
