CREATE FUNCTION api.fn_cve_lookup(p_cve_ids                   text[],
                                  p_epss_trend_row_count      integer,
                                  p_nuclei_template_row_count integer,
                                  p_product_row_count         integer,
                                  p_vendor_row_count          integer,
                                  p_ref_row_count             integer)
  RETURNS TABLE (cve_id                      text,
                 cve_description             text,
                 severity                    text,
                 cvss_v3                     real,
                 cvss_v3_vector              text,
                 published_time              date,
                 epss_score                  real,
                 epss_percentile             real,
                 cwe_id                      text,
                 cwes                        jsonb,
                 in_kev                      boolean,
                 kev_date_added              text,
                 vulnerability_status        text,
                 poc_count                   integer,
                 vendor_advisory_count       integer,
                 cve_tags                    jsonb,
                 metasploit_module_count     integer,
                 affected_products           jsonb,
                 refs                        jsonb,
                 epss_trend                  jsonb,
                 ransomware_campaign         text,
                 cvss_v4                     real,
                 cvss_v4_vector              text,
                 ssvc_exploitation           text,
                 ssvc_automatable            text,
                 ssvc_technical_impact       text,
                 ssvc_version                text,
                 ssvc_scored_at              text,
                 metasploit_feed_loaded      boolean,
                 nuclei_template_count       integer,
                 nuclei_template_feed_loaded boolean,
                 nuclei_templates            jsonb,
                 cvss_v3_source              text,
                 cvss_v4_source              text,
                 cwe_source                  text,
                 affected_product_count      integer,
                 product_count_by_vendor     jsonb,
                 ref_count                   integer)
  LANGUAGE sql STABLE STRICT SECURITY DEFINER
  SET search_path = pg_catalog
  BEGIN ATOMIC
    SELECT c.cve_id                                                                   AS cve_id,
           c.cve_description                                                          AS cve_description,
           c.severity                                                                 AS severity,
           c.cvss_v3                                                                  AS cvss_v3,
           c.cvss_v3_vector                                                           AS cvss_v3_vector,
           c.published_time                                                           AS published_time,
           c.epss_score                                                               AS epss_score,
           c.epss_percentile                                                          AS epss_percentile,
           c.cwe_id                                                                   AS cwe_id,
           c.cwes                                                                     AS cwes,
           c.in_kev                                                                   AS in_kev,
           c.kev_date_added                                                           AS kev_date_added,
           c.vulnerability_status                                                     AS vulnerability_status,
           c.poc_count                                                                AS poc_count,
           c.vendor_advisory_count                                                    AS vendor_advisory_count,
           c.cve_tags                                                                 AS cve_tags,
           module_stats.module_count                                                  AS metasploit_module_count,
           listed.affected_products                                                   AS affected_products,
           listed_refs.refs                                                           AS refs,
           trend.epss_trend                                                           AS epss_trend,
           (SELECT CASE WHEN kd.known_ransomware_use THEN 'Known' ELSE 'Unknown' END
              FROM public.kev_details AS kd
             WHERE kd.cve_id = c.cve_id AND c.in_kev)                                 AS ransomware_campaign,
           c.cvss_v4                                                                  AS cvss_v4,
           c.cvss_v4_vector                                                           AS cvss_v4_vector,
           c.ssvc_exploitation                                                        AS ssvc_exploitation,
           c.ssvc_automatable                                                         AS ssvc_automatable,
           c.ssvc_technical_impact                                                    AS ssvc_technical_impact,
           c.ssvc_version                                                             AS ssvc_version,
           to_char(c.ssvc_scored_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS ssvc_scored_at,
           EXISTS (SELECT 1 FROM public.metasploit_modules)                           AS metasploit_feed_loaded,
           template_stats.template_count                                              AS nuclei_template_count,
           EXISTS (SELECT 1 FROM public.nuclei_templates)                             AS nuclei_template_feed_loaded,
           templates.nuclei_templates                                                 AS nuclei_templates,
           c.cvss_v3_source                                                           AS cvss_v3_source,
           c.cvss_v4_source                                                           AS cvss_v4_source,
           c.cwe_source                                                               AS cwe_source,
           listed.affected_product_count                                              AS affected_product_count,
           vendors.product_count_by_vendor                                            AS product_count_by_vendor,
           jsonb_array_length(c.refs)                                                 AS ref_count
      FROM public.cves AS c
     CROSS JOIN LATERAL (
       SELECT count(*)::integer
         FROM public.metasploit_modules
        WHERE metasploit_modules.cve_id = c.cve_id) AS module_stats (module_count)
     CROSS JOIN LATERAL (
       SELECT COALESCE(jsonb_agg(to_jsonb(trend_day)), '[]'::jsonb)
         FROM (SELECT eh.epss_date::text AS epss_date, eh.score, eh.percentile
                 FROM public.epss_history AS eh
                WHERE eh.cve_id = c.cve_id
                ORDER BY eh.epss_date DESC
                LIMIT p_epss_trend_row_count) AS trend_day) AS trend (epss_trend)
     CROSS JOIN LATERAL (
       SELECT count(*)::integer
         FROM public.nuclei_templates AS nt
        WHERE nt.cve_id = c.cve_id) AS template_stats (template_count)
     CROSS JOIN LATERAL (
       SELECT COALESCE(jsonb_agg(to_jsonb(template_row) ORDER BY template_row.template_path), '[]'::jsonb)
         FROM (SELECT nt.template_id                                                                        AS template_id,
                      nt.template_name                                                                      AS name,
                      nt.severity                                                                           AS severity,
                      nt.template_path                                                                      AS template_path,
                      'https://github.com/projectdiscovery/nuclei-templates/blob/main/' || nt.template_path AS url
                 FROM public.nuclei_templates AS nt
                WHERE nt.cve_id = c.cve_id
                ORDER BY nt.template_path
                LIMIT p_nuclei_template_row_count) AS template_row) AS templates (nuclei_templates)
     CROSS JOIN LATERAL api.fn_cve_products(c.cve_id, NULL, NULL, p_product_row_count, 0) AS listed
     CROSS JOIN LATERAL (
       SELECT COALESCE(jsonb_object_agg(vendor_stats.vendor, vendor_stats.product_count), '{}'::jsonb)
         FROM (SELECT element.original ->> 'vendor' AS vendor,
                      count(*)::integer             AS product_count
                 FROM jsonb_array_elements(public.fn_jsonb_array_or_empty(c.affected_products)) AS element (original)
                WHERE element.original ->> 'vendor' <> ''
                GROUP BY element.original ->> 'vendor'
                ORDER BY product_count DESC, (element.original ->> 'vendor') COLLATE "C"
                LIMIT p_vendor_row_count) AS vendor_stats) AS vendors (product_count_by_vendor)
     CROSS JOIN LATERAL (
       SELECT COALESCE(jsonb_agg(ref_row.ref_element - 'source' ORDER BY ref_row.ref_url COLLATE "C", ref_row.ref_text COLLATE "C"), '[]'::jsonb)
         FROM (SELECT sr.ref_element, sr.ref_url, sr.ref_text
                 FROM (SELECT r.ref_element            AS ref_element,
                              r.ref_element ->> 'url'  AS ref_url,
                              r.ref_element::text      AS ref_text
                         FROM jsonb_array_elements(c.refs) AS r (ref_element)) AS sr
                ORDER BY sr.ref_url COLLATE "C", sr.ref_text COLLATE "C"
                LIMIT p_ref_row_count) AS ref_row) AS listed_refs (refs)
     WHERE c.cve_id = ANY (p_cve_ids)
     ORDER BY array_position(p_cve_ids, c.cve_id);
  END;
