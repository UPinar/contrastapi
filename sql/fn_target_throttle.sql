CREATE FUNCTION api.fn_target_throttle_is_window_kept(p_row_window_seconds integer,
                                                      p_row_window_start   timestamptz,
                                                      p_window_seconds     integer,
                                                      p_window_start       timestamptz)
  RETURNS boolean
  LANGUAGE sql STABLE
  RETURN p_row_window_seconds = p_window_seconds
     AND p_row_window_start BETWEEN p_window_start AND p_window_start + make_interval(secs => p_window_seconds);

CREATE FUNCTION api.fn_target_throttle_charge(p_throttle_rule_name text,
                                              p_target_name        text,
                                              p_window_seconds     integer,
                                              p_charged_count      integer,
                                              p_charge_limit       integer)
  RETURNS TABLE (is_charged               boolean,
                 window_remaining_seconds integer)
  LANGUAGE sql VOLATILE SECURITY DEFINER
  SET search_path = pg_catalog
  BEGIN ATOMIC
    WITH charged AS (
      INSERT INTO public.target_throttle AS tt (throttle_rule_name, target_name, window_seconds, window_start, charged_unit_count)
      SELECT p_throttle_rule_name, p_target_name, p_window_seconds, api.fn_current_window_start(p_window_seconds), p_charged_count
       WHERE p_charged_count <= p_charge_limit
      ON CONFLICT (throttle_rule_name, target_name) DO UPDATE
         SET charged_unit_count = CASE WHEN api.fn_target_throttle_is_window_kept(tt.window_seconds, tt.window_start, excluded.window_seconds, excluded.window_start)
                                       THEN tt.charged_unit_count + excluded.charged_unit_count
                                       ELSE excluded.charged_unit_count END,
             window_seconds     = excluded.window_seconds,
             window_start       = CASE WHEN api.fn_target_throttle_is_window_kept(tt.window_seconds, tt.window_start, excluded.window_seconds, excluded.window_start)
                                       THEN tt.window_start
                                       ELSE excluded.window_start END
       WHERE (CASE WHEN api.fn_target_throttle_is_window_kept(tt.window_seconds, tt.window_start, excluded.window_seconds, excluded.window_start)
                   THEN tt.charged_unit_count ELSE 0 END) + excluded.charged_unit_count <= p_charge_limit
      RETURNING 1
    )
    SELECT EXISTS (SELECT FROM charged)                                                                                                       AS is_charged,
           ceil(extract(epoch FROM api.fn_current_window_start(p_window_seconds) + make_interval(secs => p_window_seconds) - now()))::integer AS window_remaining_seconds;
  END;

CREATE FUNCTION api.fn_target_throttle_load(p_throttle_rule_name text,
                                            p_target_name        text,
                                            p_window_seconds     integer)
  RETURNS TABLE (load_count               integer,
                 window_remaining_seconds integer)
  LANGUAGE sql STABLE SECURITY DEFINER
  SET search_path = pg_catalog
  BEGIN ATOMIC
    SELECT coalesce(kept.charged_unit_count, 0)                                                                             AS load_count,
           ceil(extract(epoch FROM current_window.window_start + make_interval(secs => p_window_seconds) - now()))::integer AS window_remaining_seconds
      FROM (SELECT api.fn_current_window_start(p_window_seconds)) AS current_window (window_start)
      LEFT JOIN LATERAL (SELECT tt.charged_unit_count
                           FROM public.target_throttle AS tt
                          WHERE tt.throttle_rule_name = p_throttle_rule_name
                            AND tt.target_name        = p_target_name
                            AND api.fn_target_throttle_is_window_kept(tt.window_seconds, tt.window_start, p_window_seconds, current_window.window_start)) AS kept ON true;
  END;

CREATE FUNCTION api.fn_target_throttle_purge(p_throttle_row_count integer)
  RETURNS integer
  LANGUAGE sql VOLATILE STRICT SECURITY DEFINER
  SET search_path = pg_catalog
  BEGIN ATOMIC
    WITH purged AS (
      DELETE FROM public.target_throttle AS tt
       WHERE tt.ctid = ANY (ARRAY(SELECT expired.ctid FROM public.target_throttle AS expired
                                   WHERE expired.window_start + make_interval(secs => expired.window_seconds) <= now()
                                   LIMIT p_throttle_row_count))
      RETURNING 1)

    SELECT count(*)::integer FROM purged;
  END;
