CREATE FUNCTION api.fn_ip_cloud_provider(p_ip inet)
  RETURNS TABLE (provider text,
                 service  text,
                 is_cdn   boolean)
  LANGUAGE sql STABLE STRICT SECURITY INVOKER
  ROWS 1
  SET search_path = pg_catalog
  BEGIN ATOMIC
    SELECT icr.provider AS provider,
           icr.service  AS service,
           icr.is_cdn   AS is_cdn
      FROM public.ip_cloud_range AS icr
     WHERE icr.prefix >>= p_ip
     ORDER BY masklen(icr.prefix) DESC, icr.is_cdn DESC, icr.service
     LIMIT 1;
  END;

CREATE FUNCTION api.fn_ip_listed_on(p_ip inet)
  RETURNS TABLE (source     text,
                 prefix     text,
                 listing_id text,
                 list_time  text,
                 copyright  text)
  LANGUAGE sql STABLE STRICT SECURITY INVOKER
  SET search_path = pg_catalog
  BEGIN ATOMIC
    SELECT 'drop'::text                                                             AS source,
           idlp.prefix::text                                                        AS prefix,
           idlp.listing_id                                                          AS listing_id,
           to_char(idlp.list_time AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS list_time,
           idlp.copyright                                                           AS copyright
      FROM public.ip_drop_list_prefix AS idlp
     WHERE idlp.prefix >>= p_ip
     ORDER BY masklen(idlp.prefix) DESC;
  END;

CREATE FUNCTION api.fn_ip_lookup(p_ip inet)
  RETURNS TABLE (asn                   bigint,
                 asn_name              text,
                 asn_country           text,
                 geo_country           text,
                 cloud_provider        text,
                 cloud_service         text,
                 is_cdn                boolean,
                 is_datacenter         boolean,
                 is_tor_exit           boolean,
                 listed_on             jsonb,
                 asn_feed_loaded       boolean,
                 geo_feed_loaded       boolean,
                 cloud_feed_loaded     boolean,
                 tor_feed_loaded       boolean,
                 drop_list_feed_loaded boolean)
  LANGUAGE sql STABLE STRICT SECURITY DEFINER
  SET search_path = pg_catalog
  BEGIN ATOMIC
    WITH feed AS (
      SELECT EXISTS (SELECT 1 FROM public.ip_asn_prefix)       AS asn_feed_loaded,
             EXISTS (SELECT 1 FROM public.ip_geo_prefix)       AS geo_feed_loaded,
             EXISTS (SELECT 1 FROM public.ip_cloud_range)      AS cloud_feed_loaded,
             EXISTS (SELECT 1 FROM public.ip_tor_exit)         AS tor_feed_loaded,
             EXISTS (SELECT 1 FROM public.ip_drop_list_prefix) AS drop_list_feed_loaded)
    SELECT ia.asn                                                          AS asn,
           ia.asn_name                                                     AS asn_name,
           ia.country                                                      AS asn_country,
           geo.country                                                     AS geo_country,
           host.provider                                                   AS cloud_provider,
           host.service                                                    AS cloud_service,
           host.is_cdn                                                     AS is_cdn,
           (CASE WHEN f.cloud_feed_loaded THEN host.provider IS NOT NULL END)
             OR (CASE WHEN f.asn_feed_loaded
                      THEN coalesce(ia.asn = ANY (ARRAY[8075, 12876, 13335, 14061, 14618, 15169, 16276, 16509, 20473,
                                                        24940, 31898, 45102, 63949, 132203, 396982]::bigint[]), false) END)
                                                                           AS is_datacenter,
           CASE WHEN f.tor_feed_loaded
                THEN EXISTS (SELECT 1 FROM public.ip_tor_exit AS ite WHERE ite.ip_address = p_ip) END AS is_tor_exit,
           CASE WHEN f.drop_list_feed_loaded
                THEN coalesce((SELECT jsonb_agg(jsonb_build_object('source', lo.source, 'prefix', lo.prefix, 'listing_id', lo.listing_id,
                                                                   'list_time', lo.list_time, 'copyright', lo.copyright)
                                                ORDER BY lo.position)
                                 FROM api.fn_ip_listed_on(p_ip) WITH ORDINALITY AS lo (source, prefix, listing_id, list_time, copyright, position)),
                              '[]'::jsonb) END                             AS listed_on,
           f.asn_feed_loaded                                               AS asn_feed_loaded,
           f.geo_feed_loaded                                               AS geo_feed_loaded,
           f.cloud_feed_loaded                                             AS cloud_feed_loaded,
           f.tor_feed_loaded                                               AS tor_feed_loaded,
           f.drop_list_feed_loaded                                         AS drop_list_feed_loaded
      FROM feed AS f
      LEFT JOIN LATERAL (SELECT iap.asn
                           FROM public.ip_asn_prefix AS iap
                          WHERE iap.prefix >>= p_ip
                          ORDER BY masklen(iap.prefix) DESC
                          LIMIT 1) AS asn_prefix ON true
      LEFT JOIN public.ip_asn AS ia ON ia.asn = asn_prefix.asn
      LEFT JOIN LATERAL (SELECT igp.country
                           FROM public.ip_geo_prefix AS igp
                          WHERE igp.prefix >>= p_ip
                          ORDER BY masklen(igp.prefix) DESC
                          LIMIT 1) AS geo ON true
      LEFT JOIN LATERAL (SELECT ip.provider, ip.service, ip.is_cdn
                           FROM api.fn_ip_cloud_provider(p_ip) AS ip) AS host ON true;
  END;
