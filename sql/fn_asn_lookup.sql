CREATE FUNCTION api.fn_ip_asn_prefix(p_ip inet)
  RETURNS TABLE (asn    bigint,
                 prefix text)
  LANGUAGE sql STABLE STRICT SECURITY DEFINER
  ROWS 1
  SET search_path = pg_catalog
  BEGIN ATOMIC
    SELECT iap.asn            AS asn,
           iap.prefix::text   AS prefix
      FROM public.ip_asn_prefix AS iap
     WHERE iap.prefix >>= p_ip
     ORDER BY masklen(iap.prefix) DESC
     LIMIT 1;
  END;

CREATE FUNCTION api.fn_ip_hosting_classes(p_ip_addresses inet[])
  RETURNS text
  LANGUAGE sql STABLE SECURITY INVOKER
  SET search_path = pg_catalog
  BEGIN ATOMIC
    SELECT CASE WHEN octet_length(joined.hosting_classes) <= 2048 THEN joined.hosting_classes END
      FROM (SELECT CASE WHEN bool_and(hosted.is_ip_range_list_fresh)
                        THEN string_agg(hosted.hosting_class, E'\n' ORDER BY hosted.hosting_class COLLATE "C")
                   END AS hosting_classes
              FROM (SELECT classified.hosting_class AS hosting_class,
                           CASE WHEN classified.provider IS NOT NULL
                                THEN (SELECT min(icr.synced_at) FROM public.ip_cloud_range AS icr WHERE icr.provider = classified.provider) >= now() - interval '7 days'
                                ELSE EXISTS (SELECT 1 FROM public.upstream_feed_sync AS ufs
                                              WHERE ufs.feed_name = 'iptoasn' AND ufs.last_status = 'ok' AND ufs.last_synced >= now() - interval '7 days')
                                     AND coalesce((SELECT min(icr.synced_at) FROM public.ip_cloud_range AS icr) >= now() - interval '7 days', false)
                           END AS is_ip_range_list_fresh
                      FROM (SELECT DISTINCT
                                   CASE WHEN cloud.provider IS NOT NULL   THEN cloud.provider || '/' || cloud.service
                                        WHEN routed.asn IN (16625, 20940) THEN 'akamai/akamai'
                                        WHEN routed.asn IS NOT NULL       THEN 'AS' || routed.asn
                                        ELSE 'not_routed'
                                   END            AS hosting_class,
                                   cloud.provider AS provider
                              FROM unnest(p_ip_addresses) AS address (ip)
                              LEFT JOIN LATERAL api.fn_ip_cloud_provider(address.ip) AS cloud ON true
                              LEFT JOIN LATERAL api.fn_ip_asn_prefix(address.ip) AS routed ON true) AS classified) AS hosted) AS joined;
  END;

CREATE FUNCTION api.fn_asn_lookup(p_asn               bigint,
                                  p_prefix_row_count  integer,
                                  p_prefix_row_offset integer)
  RETURNS TABLE (asn               bigint,
                 asn_name          text,
                 asn_country       text,
                 ipv4_prefix_count integer,
                 ipv6_prefix_count integer,
                 ipv4_prefixes     jsonb,
                 ipv6_prefixes     jsonb)
  LANGUAGE sql STABLE STRICT SECURITY DEFINER
  SET search_path = pg_catalog
  BEGIN ATOMIC
    SELECT ia.asn                         AS asn,
           ia.asn_name                    AS asn_name,
           ia.country                     AS asn_country,
           prefix_stats.ipv4_prefix_count AS ipv4_prefix_count,
           prefix_stats.ipv6_prefix_count AS ipv6_prefix_count,
           ipv4_list.prefixes             AS ipv4_prefixes,
           ipv6_list.prefixes             AS ipv6_prefixes
      FROM public.ip_asn AS ia
     CROSS JOIN LATERAL (
       SELECT count(*) FILTER (WHERE family(iap.prefix) = 4)::integer AS ipv4_prefix_count,
              count(*) FILTER (WHERE family(iap.prefix) = 6)::integer AS ipv6_prefix_count
         FROM public.ip_asn_prefix AS iap
        WHERE iap.asn = ia.asn) AS prefix_stats
     CROSS JOIN LATERAL (
       SELECT coalesce(jsonb_agg(listed.prefix::text ORDER BY listed.prefix), '[]'::jsonb)
         FROM (SELECT iap.prefix
                 FROM public.ip_asn_prefix AS iap
                WHERE iap.asn = ia.asn AND family(iap.prefix) = 4
                ORDER BY iap.prefix
                LIMIT p_prefix_row_count OFFSET p_prefix_row_offset) AS listed) AS ipv4_list (prefixes)
     CROSS JOIN LATERAL (
       SELECT coalesce(jsonb_agg(listed.prefix::text ORDER BY listed.prefix), '[]'::jsonb)
         FROM (SELECT iap.prefix
                 FROM public.ip_asn_prefix AS iap
                WHERE iap.asn = ia.asn AND family(iap.prefix) = 6
                ORDER BY iap.prefix
                LIMIT p_prefix_row_count OFFSET p_prefix_row_offset) AS listed) AS ipv6_list (prefixes)
     WHERE ia.asn = p_asn;
  END;
