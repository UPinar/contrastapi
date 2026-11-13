CREATE FUNCTION api.fn_package_check_advisory(p_ecosystem               text, 
                                              p_package_name_normalized text, 
                                              p_version                 text)
  RETURNS TABLE (advisory_id            text,
                 affects_version        boolean,
                 fixed_version          text,
                 fixed_version_sortable text[])
  LANGUAGE sql STABLE SECURITY INVOKER ROWS 50
  SET search_path = pg_catalog
  BEGIN ATOMIC
    WITH checked_version AS MATERIALIZED (
      SELECT version_form.version_sortable,
             CASE WHEN p_ecosystem = 'PyPI' AND strpos(p_version, '+') > 0
                  THEN coalesce(public.fn_osv_version_sortable(p_ecosystem, split_part(p_version, '+', 1)), version_form.version_sortable)
                  ELSE version_form.version_sortable
             END AS base_version_sortable
        FROM (SELECT public.fn_osv_version_sortable(p_ecosystem, p_version) AS version_sortable) AS version_form),
    package_entry AS (
      SELECT osvaf.advisory_id,
             osvaf.affected_index,
             osvaf.listed_versions,
             osvaf.listed_versions_sortable,
             osvaf.is_unaffected_provable
        FROM public.osv_affected AS osvaf
       WHERE osvaf.ecosystem = p_ecosystem AND osvaf.package_name_normalized = p_package_name_normalized),
    entry_check AS (
      SELECT pe.advisory_id,
             CASE WHEN interval_summary.has_sure_interval OR p_version = ANY (pe.listed_versions)
                    OR array_to_string(cv.version_sortable, ' ') = ANY (pe.listed_versions_sortable) THEN true
                  WHEN interval_summary.has_unsure_interval OR array_to_string(cv.base_version_sortable, ' ') = ANY (pe.listed_versions_sortable) THEN NULL
                  WHEN cv.version_sortable IS NOT NULL AND pe.is_unaffected_provable THEN false
             END AS affects_version,
             CASE WHEN NOT interval_summary.has_unfixed_interval THEN interval_summary.fixed_version     END AS fixed_version,
             CASE WHEN NOT interval_summary.has_unfixed_interval THEN interval_summary.fixed_version_key END AS fixed_version_key
        FROM checked_version AS cv
        JOIN package_entry AS pe ON true
        CROSS JOIN LATERAL (
          SELECT coalesce(bool_or(tested_interval.is_sure), false)                                                                        AS has_sure_interval,
                 coalesce(bool_or(tested_interval.is_unsure), false)                                                                      AS has_unsure_interval,
                 bool_or((tested_interval.is_sure OR tested_interval.is_unsure) AND tested_interval.upper_event IS DISTINCT FROM 'fixed') AS has_unfixed_interval,
                 (array_agg(tested_interval.fixed_version ORDER BY tested_interval.upper_version_sortable COLLATE "C" DESC NULLS FIRST, tested_interval.fixed_version COLLATE "C")
                    FILTER (WHERE tested_interval.is_sure OR tested_interval.is_unsure))[1]                                               AS fixed_version,
                 (array_agg(array_to_string(tested_interval.upper_version_sortable, ' ') ORDER BY tested_interval.upper_version_sortable COLLATE "C" DESC NULLS FIRST, tested_interval.fixed_version COLLATE "C")
                    FILTER (WHERE tested_interval.is_sure OR tested_interval.is_unsure))[1]                                               AS fixed_version_key
            FROM (SELECT osvavi.upper_event,
                         osvavi.upper_version_sortable,
                         osvavi.fixed_version,
                         interval_test.holds AND interval_test.holds_for_base AND NOT interval_test.is_order_uncertain AS is_sure,
                         interval_test.is_order_uncertain OR interval_test.holds <> interval_test.holds_for_base       AS is_unsure
                    FROM public.osv_affected_version_intervals AS osvavi
                   CROSS JOIN LATERAL (
                     SELECT (osvavi.introduced_version_sortable IS NULL OR cv.version_sortable COLLATE "C" >= osvavi.introduced_version_sortable COLLATE "C")
                            AND (osvavi.upper_event IS NULL
                                 OR (osvavi.upper_event = 'fixed'         AND cv.version_sortable COLLATE "C" <  osvavi.upper_version_sortable COLLATE "C")
                                 OR (osvavi.upper_event = 'last_affected' AND cv.version_sortable COLLATE "C" <= osvavi.upper_version_sortable COLLATE "C")) AS holds,
                            (osvavi.introduced_version_sortable IS NULL OR cv.base_version_sortable COLLATE "C" >= osvavi.introduced_version_sortable COLLATE "C")
                            AND (osvavi.upper_event IS NULL
                                 OR (osvavi.upper_event = 'fixed'         AND cv.base_version_sortable COLLATE "C" <  osvavi.upper_version_sortable COLLATE "C")
                                 OR (osvavi.upper_event = 'last_affected' AND cv.base_version_sortable COLLATE "C" <= osvavi.upper_version_sortable COLLATE "C")) AS holds_for_base,
                            CASE WHEN p_ecosystem = 'Maven'
                                 THEN public.fn_osv_maven_order_is_uncertain(cv.version_sortable, osvavi.introduced_version_sortable)
                                      OR public.fn_osv_maven_order_is_uncertain(cv.version_sortable, osvavi.upper_version_sortable)
                                 ELSE false
                            END AS is_order_uncertain) AS interval_test
                   WHERE osvavi.advisory_id = pe.advisory_id AND osvavi.affected_index = pe.affected_index
                     AND cv.version_sortable IS NOT NULL) AS tested_interval) AS interval_summary),
    advisory_check AS (
      SELECT ec.advisory_id,
             CASE WHEN bool_or(ec.affects_version)                                 THEN true
                  WHEN count(*) FILTER (WHERE ec.affects_version IS NOT FALSE) = 0 THEN false
             END AS affects_version,
             (array_agg(ec.fixed_version ORDER BY string_to_array(ec.fixed_version_key, ' ') COLLATE "C" DESC NULLS FIRST, ec.fixed_version COLLATE "C")
                FILTER (WHERE ec.affects_version))[1] AS fixed_version,
             (array_agg(ec.fixed_version_key ORDER BY string_to_array(ec.fixed_version_key, ' ') COLLATE "C" DESC NULLS FIRST, ec.fixed_version COLLATE "C")
                FILTER (WHERE ec.affects_version))[1] AS fixed_version_key
        FROM entry_check AS ec
       GROUP BY ec.advisory_id)

    SELECT ac.advisory_id                             AS advisory_id,
           ac.affects_version                         AS affects_version,
           ac.fixed_version                           AS fixed_version,
           string_to_array(ac.fixed_version_key, ' ') AS fixed_version_sortable
      FROM advisory_check AS ac;
  END;

CREATE FUNCTION api.fn_package_check_group(p_ecosystem text, p_package_name_normalized text)
  RETURNS TABLE (shown_id  text,
                 member_id text)
  LANGUAGE sql STABLE SECURITY INVOKER ROWS 50
  SET search_path = pg_catalog
  BEGIN ATOMIC
    WITH RECURSIVE advisory AS (
      SELECT osva.advisory_id,
             osva.aliases,
             CASE osva.source WHEN 'ghsa' THEN 1 WHEN 'go' THEN 2 WHEN 'pysec' THEN 3 WHEN 'rustsec' THEN 4 END AS source_rank
        FROM public.osv_advisories AS osva
       WHERE osva.advisory_id IN (SELECT osvaf.advisory_id
                                  FROM public.osv_affected AS osvaf
                                 WHERE osvaf.ecosystem = p_ecosystem AND osvaf.package_name_normalized = p_package_name_normalized)),
    advisory_link AS (
      SELECT a.advisory_id, a.source_rank, alias.id AS alias_id
        FROM advisory AS a
       CROSS JOIN LATERAL unnest(a.aliases) AS alias (id)),
    folded AS (
      SELECT DISTINCT related.shown_id, related.member_id
        FROM (SELECT a1.advisory_id AS shown_id, a1.source_rank AS shown_rank, al2.advisory_id AS member_id, al2.source_rank AS member_rank
                FROM advisory AS a1 JOIN advisory_link AS al2 ON al2.alias_id = a1.advisory_id
              UNION ALL
              SELECT al1.advisory_id, al1.source_rank, a2.advisory_id, a2.source_rank
                FROM advisory_link AS al1 JOIN advisory AS a2 ON a2.advisory_id = al1.alias_id
              UNION ALL
              SELECT al1.advisory_id, al1.source_rank, al2.advisory_id, al2.source_rank
                FROM advisory_link AS al1 JOIN advisory_link AS al2 ON al2.alias_id = al1.alias_id
               WHERE al1.alias_id LIKE 'CVE-%') AS related
       WHERE related.member_rank > related.shown_rank),
    group_member (shown_id, member_id) AS (
      SELECT a.advisory_id, a.advisory_id
        FROM advisory AS a
       WHERE NOT EXISTS (SELECT 1 FROM folded AS f WHERE f.member_id = a.advisory_id)
      UNION
      SELECT gm.shown_id, f.member_id FROM group_member AS gm JOIN folded AS f ON f.shown_id = gm.member_id)

    SELECT gm.shown_id  AS shown_id,
           gm.member_id AS member_id
      FROM group_member AS gm;
  END;

CREATE FUNCTION api.fn_package_check_result(p_ecosystem text, p_package_name_normalized text, p_versions text[])
  RETURNS TABLE (version_index          integer,
                 advisory_id            text,
                 source                 text,
                 license                text,
                 summary                text,
                 published_time         timestamptz,
                 affects_version        boolean,
                 fixed_version          text,
                 fixed_version_sortable text[],
                 member_ids             text[])
  LANGUAGE sql STABLE SECURITY INVOKER ROWS 50
  SET search_path = pg_catalog
  BEGIN ATOMIC
    WITH package_group AS MATERIALIZED (
      SELECT g.shown_id,
             g.member_id
        FROM api.fn_package_check_group(p_ecosystem, p_package_name_normalized) AS g),
    member AS (
      SELECT pv.version_index::integer AS version_index,
             pg.shown_id,
             pg.member_id,
             adv.affects_version,
             adv.fixed_version,
             adv.fixed_version_sortable
        FROM unnest(p_versions) WITH ORDINALITY AS pv (version_text, version_index)
       CROSS JOIN LATERAL api.fn_package_check_advisory(p_ecosystem, p_package_name_normalized, pv.version_text) AS adv
        JOIN package_group AS pg ON pg.member_id = adv.advisory_id),
    member_check AS (
      SELECT m.version_index,
             m.shown_id,
             CASE WHEN bool_or(m.affects_version)                                 THEN true
                  WHEN count(*) FILTER (WHERE m.affects_version IS NOT FALSE) = 0 THEN false
             END AS affects_version,
             array_agg(m.member_id ORDER BY m.member_id) AS member_ids
        FROM member AS m
       GROUP BY m.version_index, m.shown_id),
    member_fix AS (
      SELECT DISTINCT ON (m.version_index, m.shown_id)
             m.version_index,
             m.shown_id,
             m.fixed_version,
             m.fixed_version_sortable
        FROM member AS m
       WHERE m.affects_version
       ORDER BY m.version_index, m.shown_id, m.fixed_version_sortable COLLATE "C" DESC NULLS FIRST, m.fixed_version COLLATE "C")

    SELECT mc.version_index          AS version_index,
           osva.advisory_id          AS advisory_id,
           osva.source               AS source,
           osva.license              AS license,
           osva.summary              AS summary,
           osva.published_time       AS published_time,
           mc.affects_version        AS affects_version,
           mf.fixed_version          AS fixed_version,
           mf.fixed_version_sortable AS fixed_version_sortable,
           mc.member_ids             AS member_ids
      FROM member_check AS mc
      JOIN public.osv_advisories AS osva ON osva.advisory_id = mc.shown_id
      LEFT JOIN member_fix AS mf ON mf.version_index = mc.version_index AND mf.shown_id = mc.shown_id;
  END;

CREATE FUNCTION api.fn_package_check_ranges(p_ecosystem text, p_package_name_normalized text, p_advisory_id text)
  RETURNS TABLE (ranges jsonb,
                 fixed  jsonb)
  LANGUAGE sql STABLE SECURITY INVOKER ROWS 1
  SET search_path = pg_catalog
  BEGIN ATOMIC
    WITH package_entry AS (
      SELECT osvaf.affected_index,
             osvaf.version_ranges
        FROM public.osv_affected AS osvaf
       WHERE osvaf.advisory_id = p_advisory_id AND osvaf.ecosystem = p_ecosystem AND osvaf.package_name_normalized = p_package_name_normalized),
    package_range AS (
      SELECT pe.affected_index,
             osv_range.range_ordinal,
             osv_range.range_json
        FROM package_entry AS pe
       CROSS JOIN LATERAL jsonb_array_elements(pe.version_ranges) WITH ORDINALITY AS osv_range (range_json, range_ordinal)),
    fixed_event AS (
      SELECT DISTINCT fixed_json.fixed_version_json #>> '{}' AS fixed_version
        FROM package_entry AS pe
       CROSS JOIN LATERAL jsonb_path_query(pe.version_ranges, '$[*].events[*].fixed') AS fixed_json (fixed_version_json))

    SELECT coalesce((SELECT jsonb_agg(pr.range_json ORDER BY pr.affected_index, pr.range_ordinal) FROM package_range AS pr), '[]'::jsonb) AS ranges,
           coalesce((SELECT jsonb_agg(fe.fixed_version ORDER BY public.fn_osv_version_sortable(p_ecosystem, fe.fixed_version) COLLATE "C" NULLS LAST, fe.fixed_version)
                       FROM fixed_event AS fe), '[]'::jsonb)                                                                              AS fixed;
  END;

CREATE FUNCTION api.fn_package_check_ecosystem(p_ecosystem text) RETURNS text
  LANGUAGE sql IMMUTABLE SECURITY INVOKER
  SET search_path = pg_catalog
  RETURN CASE lower(p_ecosystem)
           WHEN 'npm'       THEN 'npm'
           WHEN 'pypi'      THEN 'PyPI'
           WHEN 'maven'     THEN 'Maven'
           WHEN 'go'        THEN 'Go'
           WHEN 'nuget'     THEN 'NuGet'
           WHEN 'rubygems'  THEN 'RubyGems'
           WHEN 'crates.io' THEN 'crates.io'
           WHEN 'packagist' THEN 'Packagist'
           WHEN 'swifturl'  THEN 'SwiftURL'
         END;

CREATE FUNCTION api.fn_package_check_package_weight(p_ecosystem                  text,
                                                    p_package_name_normalized    text,
                                                    p_item_base_weight           integer,
                                                    p_listed_versions_per_weight integer)
  RETURNS bigint
  LANGUAGE sql STABLE SECURITY INVOKER
  SET search_path = pg_catalog
  RETURN p_item_base_weight
         + (SELECT count(*) + coalesce(sum(cardinality(oa.listed_versions)), 0) / p_listed_versions_per_weight
              FROM public.osv_affected AS oa
             WHERE oa.ecosystem = p_ecosystem
               AND oa.package_name_normalized = p_package_name_normalized);

CREATE FUNCTION api.fn_package_check_bulk_weigh(p_ecosystems                 text[],
                                                       p_package_names              text[],
                                                       p_item_base_weight           integer,
                                                       p_weight_budget              integer,
                                                       p_listed_versions_per_weight integer)
  RETURNS integer
  LANGUAGE sql STABLE STRICT SECURITY DEFINER
  SET search_path = pg_catalog
  BEGIN ATOMIC
    WITH package_item AS (
      SELECT pi.item_index,
             canonical.ecosystem,
             public.fn_osv_normalize_package_name(canonical.ecosystem, pi.package_name) AS package_name_normalized
        FROM unnest(p_ecosystems, p_package_names) WITH ORDINALITY AS pi (ecosystem, package_name, item_index)
       CROSS JOIN LATERAL (SELECT api.fn_package_check_ecosystem(pi.ecosystem)) AS canonical (ecosystem)),
    package_group AS (
      SELECT pi.ecosystem,
             pi.package_name_normalized,
             array_agg(pi.item_index) AS item_indexes
        FROM package_item AS pi
       GROUP BY pi.ecosystem, pi.package_name_normalized),
    item_weight AS (
      SELECT item.item_index,
             package_weight.weight AS item_weight
        FROM package_group AS pg
       CROSS JOIN LATERAL (SELECT api.fn_package_check_package_weight(pg.ecosystem, pg.package_name_normalized,
                                                                      p_item_base_weight, p_listed_versions_per_weight)) AS package_weight (weight)
       CROSS JOIN LATERAL unnest(pg.item_indexes) AS item (item_index)),
    weighed_item AS (
      SELECT coalesce(sum(iw.item_weight) OVER (ORDER BY iw.item_index ROWS BETWEEN UNBOUNDED PRECEDING AND 1 PRECEDING), 0) AS weight_before
        FROM item_weight AS iw)
    SELECT count(*)::integer
      FROM weighed_item AS wi
     WHERE wi.weight_before < p_weight_budget;
  END;

CREATE FUNCTION api.fn_package_check_attribution_entry(p_source text, p_license text)
  RETURNS jsonb
  LANGUAGE sql IMMUTABLE SECURITY INVOKER
  SET search_path = pg_catalog
  BEGIN ATOMIC
    SELECT jsonb_build_object(
             'source',  p_source,
             'license', p_license,
             'url',     CASE p_source
                          WHEN 'ghsa'           THEN 'https://github.com/github/advisory-database'
                          WHEN 'go'             THEN 'https://github.com/golang/vulndb'
                          WHEN 'pysec'          THEN 'https://github.com/pypa/advisory-database'
                          WHEN 'rustsec'        THEN 'https://github.com/rustsec/advisory-db'
                          WHEN 'mal'            THEN 'https://github.com/ossf/malicious-packages'
                          WHEN 'endoflife.date' THEN 'https://endoflife.date'
                        END,
             'notice',  CASE p_source
                          WHEN 'endoflife.date'
                            THEN 'Retrieved from endoflife.date. ContrastAPI selected the fields and matched the release cycles to the package. No warranty; the source does not endorse ContrastAPI.'
                          ELSE 'Retrieved through OSV.dev. ContrastAPI selected and normalized the fields and computed affects_version and fixed_version. No warranty; the source does not endorse ContrastAPI.'
                        END);
  END;

CREATE FUNCTION api.fn_package_check_versions(p_ecosystem        text,
                                              p_package_name     text,
                                              p_versions         text[],
                                              p_result_row_count integer,
                                              p_result_offset    integer)
  RETURNS TABLE (version_index        integer,
                 advisory_feed_loaded boolean,
                 has_advisory_data    boolean,
                 result_count         integer,
                 fixed_version        text,
                 malicious            jsonb,
                 results              jsonb,
                 attribution          jsonb)
  LANGUAGE sql STABLE SECURITY INVOKER ROWS 1
  SET search_path = pg_catalog
  BEGIN ATOMIC
    WITH package AS (
      SELECT canonical.ecosystem,
             public.fn_osv_normalize_package_name(canonical.ecosystem, p_package_name) AS package_name_normalized
        FROM (SELECT api.fn_package_check_ecosystem(p_ecosystem)) AS canonical (ecosystem)
       WHERE canonical.ecosystem IS NOT NULL AND p_package_name IS NOT NULL AND p_versions IS NOT NULL
         AND p_result_row_count IS NOT NULL AND p_result_offset IS NOT NULL),
    package_version AS (
      SELECT pv.version_text,
             pv.version_index::integer AS version_index
        FROM unnest(p_versions) WITH ORDINALITY AS pv (version_text, version_index)),
    result AS (
      SELECT r.*,
             pv.version_text
        FROM package AS p
       CROSS JOIN LATERAL api.fn_package_check_result(p.ecosystem, p.package_name_normalized, p_versions) AS r
        JOIN package_version AS pv ON pv.version_index = r.version_index),
    listed AS (
      SELECT r.*
        FROM result AS r
       WHERE r.source <> 'mal' AND (r.version_text IS NULL OR r.affects_version IS NOT FALSE)),
    fix_candidate AS (
      SELECT DISTINCT ON (l.version_index)
             l.version_index,
             l.fixed_version
        FROM listed AS l
       WHERE l.version_text IS NOT NULL
         AND NOT EXISTS (SELECT 1 FROM listed AS l2 WHERE l2.version_index = l.version_index AND l2.fixed_version IS NULL)
       ORDER BY l.version_index, l.fixed_version_sortable COLLATE "C" DESC, l.fixed_version COLLATE "C"),
    safe_fixed_version AS (
      SELECT fc.fixed_version
        FROM (SELECT DISTINCT fix_candidate.fixed_version FROM fix_candidate) AS fc
       CROSS JOIN package AS p
       WHERE NOT EXISTS (SELECT 1
                           FROM api.fn_package_check_advisory(p.ecosystem, p.package_name_normalized, fc.fixed_version) AS adv
                          WHERE adv.affects_version IS NOT FALSE)),
    malicious_advisory AS (
      SELECT DISTINCT ON (r.version_index)
             r.*
        FROM result AS r
       WHERE r.source = 'mal' AND (r.version_text IS NULL OR r.affects_version IS NOT FALSE)
       ORDER BY r.version_index, r.affects_version IS NOT TRUE, r.published_time DESC, r.advisory_id),
    result_page AS (
      SELECT ranked.*
        FROM (SELECT l.*,
                     row_number() OVER (PARTITION BY l.version_index ORDER BY l.published_time DESC, l.advisory_id) AS result_position
                FROM listed AS l) AS ranked
       WHERE ranked.result_position > p_result_offset
         AND ranked.result_position <= p_result_offset::bigint + p_result_row_count),
    page_advisory AS MATERIALIZED (
      SELECT page_result.advisory_id,
             alias_list.aliases,
             package_range.ranges,
             package_range.fixed
        FROM (SELECT DISTINCT ON (rp.advisory_id) rp.advisory_id, rp.member_ids
                FROM result_page AS rp
               ORDER BY rp.advisory_id) AS page_result
       CROSS JOIN package AS p
       CROSS JOIN LATERAL (
         SELECT coalesce(jsonb_agg(DISTINCT alias.id ORDER BY alias.id), '[]'::jsonb)
           FROM unnest(page_result.member_ids) AS member (id)
           JOIN public.osv_advisories AS osva ON osva.advisory_id = member.id
          CROSS JOIN LATERAL unnest(osva.aliases || osva.advisory_id) AS alias (id)
          WHERE alias.id <> page_result.advisory_id) AS alias_list (aliases)
       CROSS JOIN LATERAL api.fn_package_check_ranges(p.ecosystem, p.package_name_normalized, page_result.advisory_id) AS package_range),
    result_list AS (
      SELECT rp.version_index,
             jsonb_agg(jsonb_build_object(
                         'id',             rp.advisory_id,
                         'aliases',        pa.aliases,
                         'source',         rp.source,
                         'summary',        nullif(rp.summary, ''),
                         'published_time', to_char(rp.published_time AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
                         'fixed',          pa.fixed,
                         'ranges',         pa.ranges)
                       || CASE WHEN rp.version_text IS NULL THEN '{}'::jsonb
                               ELSE jsonb_build_object('affects_version', rp.affects_version, 'fixed_version', rp.fixed_version)
                          END
                       ORDER BY rp.published_time DESC, rp.advisory_id) AS results
        FROM result_page AS rp
        JOIN page_advisory AS pa ON pa.advisory_id = rp.advisory_id
       GROUP BY rp.version_index),
    listed_count AS (
      SELECT l.version_index,
             count(*)::integer AS result_count
        FROM listed AS l
       GROUP BY l.version_index),
    credited AS (
      SELECT l.version_index, osva.source, osva.license
        FROM listed AS l
       CROSS JOIN LATERAL unnest(l.member_ids) AS member (id)
        JOIN public.osv_advisories AS osva ON osva.advisory_id = member.id
      UNION
      SELECT ma.version_index, ma.source, ma.license FROM malicious_advisory AS ma
      UNION
      SELECT pv.version_index, 'endoflife.date', 'MIT'
        FROM package_version AS pv
       WHERE EXISTS (SELECT 1
                       FROM package AS p
                      CROSS JOIN LATERAL public.fn_eol_product_package_pick(p.ecosystem, p.package_name_normalized) AS pick)),
    attribution_list AS (
      SELECT c.version_index,
             jsonb_agg(api.fn_package_check_attribution_entry(c.source, c.license)
                       ORDER BY c.source, c.license) AS attribution
        FROM credited AS c
       GROUP BY c.version_index)

    SELECT pv.version_index                             AS version_index,
           EXISTS (SELECT 1 FROM public.osv_advisories) AS advisory_feed_loaded,
           package_data.has_advisory_data               AS has_advisory_data,
           coalesce(lc.result_count, 0)                 AS result_count,
           sfv.fixed_version                            AS fixed_version,
           malicious_object.malicious                   AS malicious,
           coalesce(rl.results, '[]'::jsonb)            AS results,
           coalesce(al.attribution, '[]'::jsonb)        AS attribution
      FROM package AS p
     CROSS JOIN LATERAL (
       SELECT EXISTS (SELECT 1
                        FROM public.osv_affected AS osvaf
                       WHERE osvaf.ecosystem = p.ecosystem AND osvaf.package_name_normalized = p.package_name_normalized)) AS package_data (has_advisory_data)
     CROSS JOIN package_version AS pv
      LEFT JOIN listed_count AS lc ON lc.version_index = pv.version_index
      LEFT JOIN fix_candidate AS fc ON fc.version_index = pv.version_index
      LEFT JOIN safe_fixed_version AS sfv ON sfv.fixed_version = fc.fixed_version
      LEFT JOIN LATERAL (
       SELECT jsonb_build_object(
                'id',             ma.advisory_id,
                'summary',        nullif(ma.summary, ''),
                'published_time', to_char(ma.published_time AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
              || CASE WHEN pv.version_text IS NULL THEN '{}'::jsonb
                      ELSE jsonb_build_object('affects_version', ma.affects_version)
                 END
         FROM malicious_advisory AS ma
        WHERE ma.version_index = pv.version_index) AS malicious_object (malicious) ON true
      LEFT JOIN result_list AS rl ON rl.version_index = pv.version_index
      LEFT JOIN attribution_list AS al ON al.version_index = pv.version_index;
  END;

CREATE FUNCTION api.fn_package_check( p_ecosystem         text,
                                      p_package_name      text,
                                      p_version           text,
                                      p_result_row_count  integer,
                                      p_result_offset     integer)
  RETURNS TABLE (advisory_feed_loaded boolean,
                 has_advisory_data    boolean,
                 result_count         integer,
                 fixed_version        text,
                 malicious            jsonb,
                 results              jsonb,
                 attribution          jsonb)
  LANGUAGE sql STABLE SECURITY DEFINER ROWS 1
  SET search_path = pg_catalog
  BEGIN ATOMIC
    SELECT pcv.advisory_feed_loaded AS advisory_feed_loaded,
           pcv.has_advisory_data    AS has_advisory_data,
           pcv.result_count         AS result_count,
           pcv.fixed_version        AS fixed_version,
           pcv.malicious            AS malicious,
           pcv.results              AS results,
           pcv.attribution          AS attribution
      FROM api.fn_package_check_versions(p_ecosystem, p_package_name, ARRAY[p_version], p_result_row_count, p_result_offset) AS pcv;
  END;

CREATE FUNCTION api.fn_package_check_eol(p_ecosystem                 text,
                                         p_package_name              text,
                                         p_version                   text,
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
      FROM (SELECT api.fn_package_check_ecosystem(p_ecosystem)) AS canonical (ecosystem)
     CROSS JOIN LATERAL public.fn_eol_product_package_pick(canonical.ecosystem,
                                                           public.fn_osv_normalize_package_name(canonical.ecosystem, p_package_name)) AS pick
     CROSS JOIN LATERAL api.fn_eol_answer(pick.eol_product, NULL, p_version, p_maintained_cycle_row_count) WITH ORDINALITY AS eol
     ORDER BY eol.ordinality;
  END;

CREATE FUNCTION api.fn_package_check_bulk(p_ecosystems         text[],
                                          p_package_names      text[],
                                          p_package_versions   text[],
                                          p_advisory_row_count integer)
  RETURNS TABLE (advisory_feed_loaded boolean,
                 results              jsonb,
                 attribution          jsonb,
                 failed_item_count    integer)
  LANGUAGE sql STABLE STRICT SECURITY DEFINER ROWS 1
  SET search_path = pg_catalog
  BEGIN ATOMIC
    WITH package_item AS (
      SELECT pi.item_index, pi.ecosystem, pi.package_name, pi.package_version
        FROM unnest(p_ecosystems, p_package_names, p_package_versions) WITH ORDINALITY AS pi (ecosystem, package_name, package_version, item_index)),
    package_request AS (
      SELECT grouped.ecosystem,
             grouped.package_name,
             grouped.package_versions,
             grouped.item_indexes,
             canonical.ecosystem AS canonical_ecosystem,
             normalized.package_name_normalized,
             EXISTS (SELECT 1
                       FROM public.osv_affected AS osvaf
                      WHERE osvaf.ecosystem = canonical.ecosystem
                        AND osvaf.package_name_normalized = normalized.package_name_normalized) AS has_advisory_data
        FROM (SELECT pi.ecosystem,
                     pi.package_name,
                     array_agg(pi.package_version ORDER BY pi.item_index) AS package_versions,
                     array_agg(pi.item_index ORDER BY pi.item_index)      AS item_indexes
                FROM package_item AS pi
               GROUP BY pi.ecosystem, pi.package_name) AS grouped
       CROSS JOIN LATERAL (SELECT api.fn_package_check_ecosystem(grouped.ecosystem)) AS canonical (ecosystem)
       CROSS JOIN LATERAL (SELECT public.fn_osv_normalize_package_name(canonical.ecosystem, grouped.package_name)) AS normalized (package_name_normalized)),
    package_answer AS (
      SELECT pr.item_indexes[pcv.version_index] AS item_index,
             pcv.has_advisory_data,
             pcv.result_count,
             pcv.fixed_version,
             pcv.malicious,
             pcv.results,
             pcv.attribution
        FROM package_request AS pr
       CROSS JOIN LATERAL api.fn_package_check_versions(pr.ecosystem, pr.package_name, pr.package_versions, p_advisory_row_count, 0) AS pcv
       WHERE pr.has_advisory_data
      UNION ALL
      SELECT no_row_item.item_index,
             false,
             0,
             NULL::text,
             NULL::jsonb,
             '[]'::jsonb,
             CASE WHEN EXISTS (SELECT 1 FROM public.fn_eol_product_package_pick(pr.canonical_ecosystem, pr.package_name_normalized))
                  THEN jsonb_build_array(api.fn_package_check_attribution_entry('endoflife.date', 'MIT'))
                  ELSE '[]'::jsonb
             END
        FROM package_request AS pr
       CROSS JOIN LATERAL unnest(pr.item_indexes) AS no_row_item (item_index)
       WHERE NOT pr.has_advisory_data AND pr.canonical_ecosystem IS NOT NULL AND pr.package_name IS NOT NULL),
    checked_item AS (
      SELECT pi.item_index,
             pi.ecosystem,
             pi.package_name,
             pi.package_version,
             pa.has_advisory_data,
             pa.result_count,
             pa.fixed_version,
             pa.malicious,
             pa.results,
             pa.attribution
        FROM package_item AS pi
        LEFT JOIN package_answer AS pa ON pa.item_index = pi.item_index),
    item_result AS (
      SELECT ci.item_index,
             item_eol.series_cycle_count > 8 AS is_eol_series_too_long,
             jsonb_build_object(
               'ecosystem',         ci.ecosystem,
               'name',              ci.package_name,
               'version',           ci.package_version,
               'has_advisory_data', ci.has_advisory_data,
               'fixed_version',     ci.fixed_version,
               'malicious',         CASE WHEN ci.malicious IS NOT NULL
                                         THEN jsonb_build_object('id', ci.malicious -> 'id', 'affects_version', ci.malicious -> 'affects_version')
                                    END,
               'advisory_total',    ci.result_count,
               'advisories',        advisory_list.advisories,
               'eol',               item_eol.eol) AS item_json
        FROM checked_item AS ci
       CROSS JOIN LATERAL (
         SELECT coalesce(jsonb_agg(jsonb_build_object(
                                     'id',              advisory_page.result_json -> 'id',
                                     'aliases',         advisory_page.result_json -> 'aliases',
                                     'affects_version', advisory_page.result_json -> 'affects_version')
                                   ORDER BY advisory_page.result_ordinal), '[]'::jsonb)
           FROM jsonb_array_elements(ci.results) WITH ORDINALITY AS advisory_page (result_json, result_ordinal)) AS advisory_list (advisories)
       CROSS JOIN LATERAL (
         SELECT CASE WHEN count(*) FILTER (WHERE eol.row_kind = 'product') = 1
                     THEN jsonb_build_object(
                            'source',         'endoflife.date',
                            'product',        min(eol.name) FILTER (WHERE eol.row_kind = 'product'),
                            'url',            min(eol.url) FILTER (WHERE eol.row_kind = 'product'),
                            'cycle',          CASE WHEN count(*) FILTER (WHERE eol.row_kind = 'series') = 1
                                                   THEN (jsonb_agg(jsonb_build_object('name',           eol.name,
                                                                                      'eol_date',       eol.eol_date,
                                                                                      'is_eol',         eol.is_eol,
                                                                                      'is_maintained',  eol.is_maintained,
                                                                                      'is_lts',         eol.is_lts,
                                                                                      'latest_version', eol.latest_version))
                                                           FILTER (WHERE eol.row_kind = 'series')) -> 0
                                              END,
                            'cycle_variants', CASE WHEN count(*) FILTER (WHERE eol.row_kind = 'series') > 1
                                                   THEN jsonb_agg(jsonb_build_object('name',          eol.name,
                                                                                     'eol_date',      eol.eol_date,
                                                                                     'is_eol',        eol.is_eol,
                                                                                     'is_maintained', eol.is_maintained)
                                                                  ORDER BY eol.ordinality) FILTER (WHERE eol.row_kind = 'series')
                                              END)
                END                                             AS eol,
                count(*) FILTER (WHERE eol.row_kind = 'series') AS series_cycle_count
           FROM api.fn_package_check_eol(ci.ecosystem, ci.package_name, ci.package_version, 0) WITH ORDINALITY AS eol) AS item_eol),
    credited AS (
      SELECT DISTINCT credit.attribution_json ->> 'source'  AS source,
                      credit.attribution_json ->> 'license' AS license,
                      credit.attribution_json ->> 'url'     AS source_url
        FROM checked_item AS ci
        JOIN item_result AS ir ON ir.item_index = ci.item_index AND NOT ir.is_eol_series_too_long
       CROSS JOIN LATERAL jsonb_array_elements(ci.attribution) AS credit (attribution_json))

    SELECT EXISTS (SELECT 1 FROM public.osv_advisories) AS advisory_feed_loaded,
           result_list.results                          AS results,
           attribution_list.attribution                 AS attribution,
           result_list.failed_item_count                AS failed_item_count
      FROM (SELECT coalesce(jsonb_agg(ir.item_json ORDER BY ir.item_index) FILTER (WHERE NOT ir.is_eol_series_too_long), '[]'::jsonb),
                   count(*) FILTER (WHERE ir.is_eol_series_too_long)::integer
              FROM item_result AS ir) AS result_list (results, failed_item_count)
     CROSS JOIN (
       SELECT coalesce(jsonb_agg(jsonb_build_object(
                         'source',  c.source,
                         'license', c.license,
                         'url',     c.source_url)
                       ORDER BY c.source COLLATE "C", c.license COLLATE "C"), '[]'::jsonb)
         FROM credited AS c) AS attribution_list (attribution);
  END;
