DO $$
DECLARE
  saved_time_zone text := current_setting('TimeZone');
  window_seconds  integer;
  window_start    timestamptz;
BEGIN
  PERFORM set_config('TimeZone', 'Asia/Kolkata', true);
  FOREACH window_seconds IN ARRAY ARRAY[10, 60, 3600, 86400] LOOP
    window_start := api.fn_current_window_start(window_seconds);
    ASSERT extract(epoch FROM window_start)::bigint % window_seconds = 0,
           format('a window of %s seconds starts at a multiple of %s seconds since the epoch', window_seconds, window_seconds);
    ASSERT window_start <= now() AND now() < window_start + make_interval(secs => window_seconds),
           format('the window of %s seconds that starts there holds now()', window_seconds);
  END LOOP;
  ASSERT api.fn_current_window_start(3600) = date_trunc('hour', now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC',
         'an hour window starts at the UTC hour, not at the hour of Asia/Kolkata';
  ASSERT api.fn_current_window_start(86400) = date_trunc('day', now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC',
         'a day window starts at midnight UTC, not at midnight of Asia/Kolkata';
  PERFORM set_config('TimeZone', saved_time_zone, true);
END
$$;

DO $$
BEGIN
  ASSERT (SELECT NOT prosecdef AND NOT proisstrict AND provolatile = 's' AND proconfig IS NULL FROM pg_proc
          WHERE oid = 'api.fn_current_window_start(integer)'::regprocedure),
         'api.fn_current_window_start is SECURITY INVOKER, not STRICT, STABLE, and sets nothing';
END
$$;
