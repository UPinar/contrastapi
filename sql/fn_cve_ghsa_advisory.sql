CREATE FUNCTION api.fn_cve_ghsa_advisory(p_cve_id            text,
                                         p_package_row_count integer)
  RETURNS TABLE (ghsa_feed_loaded boolean,
                 advisory         jsonb)
  LANGUAGE sql STABLE STRICT SECURITY DEFINER
  SET search_path = pg_catalog
  BEGIN ATOMIC
    WITH first_advisory AS (
      SELECT osva.advisory_id,
             osva.license
        FROM public.osv_advisories AS osva
       WHERE osva.source = 'ghsa' AND osva.aliases @> ARRAY[p_cve_id]
       ORDER BY osva.published_time, osva.advisory_id COLLATE "C"
       LIMIT 1),
    package_text AS (
      SELECT osvaf.ecosystem,
             osvaf.package_name,
             coalesce(event_summary.range_text,
                      CASE WHEN event_summary.has_introduced_event THEN '>= 0' END,
                      CASE WHEN cardinality(osvaf.listed_versions) > 0 THEN '= ' || array_to_string(osvaf.listed_versions, ', = ') END,
                      '')                                    AS vulnerable_version_range,
             coalesce(event_summary.first_fixed_version, '') AS patched_versions
        FROM first_advisory AS fa
        JOIN public.osv_affected AS osvaf ON osvaf.advisory_id = fa.advisory_id
        LEFT JOIN LATERAL (
          SELECT string_agg(CASE WHEN osv_event.event_json ->> 'introduced' <> '0' THEN '>= ' || (osv_event.event_json ->> 'introduced')
                                 WHEN osv_event.event_json ? 'fixed'              THEN '< '  || (osv_event.event_json ->> 'fixed')
                                 WHEN osv_event.event_json ? 'last_affected'      THEN '<= ' || (osv_event.event_json ->> 'last_affected')
                            END, ', ' ORDER BY osv_event.event_ordinal),
                 bool_or(osv_event.event_json ? 'introduced'),
                 (array_agg(osv_event.event_json ->> 'fixed' ORDER BY osv_event.event_ordinal) FILTER (WHERE osv_event.event_json ? 'fixed'))[1]
            FROM jsonb_path_query(osvaf.version_ranges, '$[*].events[*]') WITH ORDINALITY AS osv_event (event_json, event_ordinal)) AS event_summary (range_text, has_introduced_event, first_fixed_version) ON true),
    advisory_object AS (
      SELECT jsonb_build_object(
               'ghsa_id',        fa.advisory_id,
               'affected',       package_list.packages,
               'affected_total', (SELECT count(*)::integer FROM package_text),
               'attribution',    jsonb_build_object('source',  'ghsa',
                                                    'license', fa.license,
                                                    'url',     'https://github.com/github/advisory-database')) AS advisory
        FROM first_advisory AS fa
       CROSS JOIN LATERAL (
         SELECT coalesce(jsonb_agg(jsonb_build_object('ecosystem',                listed.ecosystem,
                                                      'package',                  listed.package_name,
                                                      'vulnerable_version_range', listed.vulnerable_version_range,
                                                      'patched_versions',         listed.patched_versions)
                                   ORDER BY listed.ecosystem COLLATE "C", listed.package_name COLLATE "C",
                                            listed.vulnerable_version_range COLLATE "C"),
                         '[]'::jsonb)
           FROM (SELECT pt.*
                   FROM package_text AS pt
                  ORDER BY pt.ecosystem COLLATE "C", pt.package_name COLLATE "C",
                           pt.vulnerable_version_range COLLATE "C"
                  LIMIT p_package_row_count) AS listed) AS package_list (packages))
    SELECT EXISTS (SELECT 1 FROM public.osv_advisories AS osva WHERE osva.source = 'ghsa') AS ghsa_feed_loaded,
           (SELECT ao.advisory FROM advisory_object AS ao)                                 AS advisory;
  END;
