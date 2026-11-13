CREATE FUNCTION api.fn_current_window_start(p_window_seconds integer)
  RETURNS timestamptz
  LANGUAGE sql STABLE
  RETURN date_bin(make_interval(secs => p_window_seconds), now(), timestamptz 'epoch');
