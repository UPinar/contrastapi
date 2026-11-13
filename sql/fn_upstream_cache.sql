CREATE FUNCTION api.fn_upstream_cache_get(p_cache_key text)
  RETURNS TABLE (body       text,
                 is_error   boolean,
                 fetched_at text)
  LANGUAGE sql STABLE SECURITY DEFINER
  SET search_path = pg_catalog
  BEGIN ATOMIC
    SELECT uc.body                                                                  AS body,
           uc.is_error                                                              AS is_error,
           to_char(uc.fetched_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')  AS fetched_at
      FROM public.upstream_cache AS uc
     WHERE uc.cache_key = p_cache_key AND uc.expires_at > now();
  END;

CREATE FUNCTION api.fn_upstream_cache_put(p_cache_key             text,
                                          p_body                  text,
                                          p_is_error              boolean,
                                          p_expires_after_seconds integer)
  RETURNS boolean
  LANGUAGE sql VOLATILE STRICT SECURITY DEFINER
  SET search_path = pg_catalog
  BEGIN ATOMIC
    WITH written AS (
      INSERT INTO public.upstream_cache AS uc (cache_key, body, is_error, fetched_at, expires_at)
      VALUES (p_cache_key, p_body, p_is_error, now(), now() + make_interval(secs => p_expires_after_seconds))
      ON CONFLICT (cache_key) DO UPDATE
         SET body       = excluded.body,
             is_error   = excluded.is_error,
             fetched_at = excluded.fetched_at,
             expires_at = excluded.expires_at
      RETURNING 1
    )
    SELECT EXISTS (SELECT FROM written);
  END;

CREATE FUNCTION api.fn_upstream_cache_purge(p_cache_row_count integer)
  RETURNS integer
  LANGUAGE sql VOLATILE STRICT SECURITY DEFINER
  SET search_path = pg_catalog
  BEGIN ATOMIC
    WITH purged AS (
      DELETE FROM public.upstream_cache AS uc
       WHERE uc.ctid = ANY (ARRAY(SELECT expired.ctid FROM public.upstream_cache AS expired
                                   WHERE expired.expires_at <= now()
                                   LIMIT p_cache_row_count))
      RETURNING 1)

    SELECT count(*)::integer FROM purged;
  END;
