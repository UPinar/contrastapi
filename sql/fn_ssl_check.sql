CREATE FUNCTION api.fn_ssl_blacklist_certificate(p_sha1 text)
  RETURNS TABLE (ssl_blacklist_feed_loaded boolean,
                 listing_reason            text,
                 listing_time              text)
  LANGUAGE sql STABLE STRICT SECURITY DEFINER
  SET search_path = pg_catalog
  BEGIN ATOMIC
    SELECT EXISTS (SELECT 1 FROM public.ssl_blacklist_certificate)                    AS ssl_blacklist_feed_loaded,
           sbc.listing_reason                                                         AS listing_reason,
           to_char(sbc.listing_time AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS listing_time
      FROM (SELECT lower(p_sha1)) AS queried (sha1)
      LEFT JOIN public.ssl_blacklist_certificate AS sbc ON sbc.sha1 = queried.sha1;
  END;
