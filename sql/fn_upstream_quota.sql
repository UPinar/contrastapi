CREATE FUNCTION api.fn_upstream_quota_reserve(p_source_name    text,
                                              p_window_seconds integer,
                                              p_call_limit     integer)
  RETURNS boolean
  LANGUAGE sql VOLATILE SECURITY DEFINER
  SET search_path = pg_catalog
  BEGIN ATOMIC
    WITH granted AS (
      INSERT INTO public.upstream_quota AS uq (source_name, window_seconds, window_start, granted_call_count, refused_call_count)
      SELECT p_source_name, p_window_seconds, api.fn_current_window_start(p_window_seconds), 1, 0
       WHERE p_call_limit > 0
      ON CONFLICT (source_name, window_seconds, window_start) DO UPDATE
         SET granted_call_count = uq.granted_call_count + 1
       WHERE uq.granted_call_count < p_call_limit
      RETURNING 1
    ), refused AS (
      INSERT INTO public.upstream_quota AS uq (source_name, window_seconds, window_start, granted_call_count, refused_call_count)
      SELECT p_source_name, p_window_seconds, api.fn_current_window_start(p_window_seconds), 0, 1
       WHERE NOT EXISTS (SELECT FROM granted)
      ON CONFLICT (source_name, window_seconds, window_start) DO UPDATE
         SET refused_call_count = uq.refused_call_count + 1
    )
    SELECT EXISTS (SELECT FROM granted);
  END;

CREATE FUNCTION api.fn_upstream_quota_mark_exhausted(p_source_name    text,
                                                     p_window_seconds integer,
                                                     p_call_limit     integer)
  RETURNS boolean
  LANGUAGE sql VOLATILE SECURITY DEFINER
  SET search_path = pg_catalog
  BEGIN ATOMIC
    WITH marked AS (
      INSERT INTO public.upstream_quota AS uq (source_name, window_seconds, window_start, granted_call_count, refused_call_count)
      VALUES (p_source_name, p_window_seconds, api.fn_current_window_start(p_window_seconds), p_call_limit, 0)
      ON CONFLICT (source_name, window_seconds, window_start) DO UPDATE
         SET granted_call_count = greatest(uq.granted_call_count, p_call_limit)
      RETURNING 1
    )
    SELECT EXISTS (SELECT FROM marked);
  END;

CREATE FUNCTION api.fn_upstream_quota_purge(p_quota_row_count integer)
  RETURNS integer
  LANGUAGE sql VOLATILE STRICT SECURITY DEFINER
  SET search_path = pg_catalog
  BEGIN ATOMIC
    WITH purged AS (
      DELETE FROM public.upstream_quota AS uq
       WHERE uq.ctid = ANY (ARRAY(SELECT expired.ctid FROM public.upstream_quota AS expired
                                   WHERE expired.window_start + make_interval(secs => expired.window_seconds) < now() - interval '35 days'
                                   LIMIT p_quota_row_count))
      RETURNING 1)
    SELECT count(*)::integer FROM purged;
  END;
