CREATE FUNCTION api.fn_upstream_hold_set(p_hold_name    text,
                                         p_hold_seconds integer)
  RETURNS boolean
  LANGUAGE sql VOLATILE SECURITY DEFINER
  SET search_path = pg_catalog
  BEGIN ATOMIC
    WITH held AS (
      INSERT INTO public.upstream_hold AS uh (hold_name, held_until)
      VALUES (p_hold_name, now() + make_interval(secs => p_hold_seconds))
      ON CONFLICT (hold_name) DO UPDATE
         SET held_until = greatest(uh.held_until, EXCLUDED.held_until)
      RETURNING 1
    )
    SELECT EXISTS (SELECT FROM held);
  END;

CREATE FUNCTION api.fn_upstream_hold_remaining_seconds(p_hold_name text)
  RETURNS integer
  LANGUAGE sql STABLE SECURITY DEFINER
  SET search_path = pg_catalog
  BEGIN ATOMIC
    SELECT coalesce((SELECT ceil(extract(epoch FROM uh.held_until - now()))::integer
                       FROM public.upstream_hold AS uh
                      WHERE uh.hold_name = p_hold_name
                        AND uh.held_until > now()), 0);
  END;
