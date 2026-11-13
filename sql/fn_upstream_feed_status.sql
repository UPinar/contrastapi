CREATE FUNCTION api.fn_upstream_feed_status(p_feed_row_count integer)
  RETURNS TABLE (feed_name       text,
                 last_synced     text,
                 last_status     text,
                 records_updated integer)
  LANGUAGE sql STABLE STRICT SECURITY DEFINER
  SET search_path = pg_catalog
  BEGIN ATOMIC
    SELECT ufs.feed_name                                                             AS feed_name,
           to_char(ufs.last_synced AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS last_synced,
           ufs.last_status                                                           AS last_status,
           ufs.records_updated                                                       AS records_updated
      FROM public.upstream_feed_sync AS ufs
     ORDER BY ufs.feed_name
     LIMIT p_feed_row_count;
  END;
