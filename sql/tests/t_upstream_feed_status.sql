SET LOCAL TimeZone = 'Europe/Istanbul';
INSERT INTO upstream_feed_sync (feed_name, last_synced, last_status, records_updated, resume_cursor) VALUES
  ('nvd',        '2026-10-08 04:22:39+03', 'ok',          21874, 'cursor-nvd'),
  ('kev',        '2026-10-08 01:22:39+00', 'ok',          1734,  NULL),
  ('metasploit', NULL,                     'in_progress', 0,     NULL);

CREATE TEMP VIEW t_upstream_feed_status_call AS SELECT * FROM api.fn_upstream_feed_status(16);

DO $$
BEGIN
  ASSERT (SELECT array_agg(attname::text ORDER BY attnum) FROM pg_attribute
          WHERE attrelid = 't_upstream_feed_status_call'::regclass AND attnum > 0)
         = ARRAY['feed_name', 'last_synced', 'last_status', 'records_updated'],
         'api.fn_upstream_feed_status answers four columns, and no resume_cursor';
  ASSERT (SELECT array_agg(feed_name ORDER BY ord) FROM
            (SELECT feed_name, row_number() OVER () AS ord FROM api.fn_upstream_feed_status(16)) AS rows)
         = ARRAY['kev', 'metasploit', 'nvd'],
         'the rows come in feed_name order';
  ASSERT (SELECT last_synced FROM t_upstream_feed_status_call WHERE feed_name = 'nvd')
         = '2026-10-08T01:22:39Z',
         'last_synced is UTC text, whatever the session time zone';
  ASSERT (SELECT last_synced FROM t_upstream_feed_status_call WHERE feed_name = 'kev')
         = '2026-10-08T01:22:39Z',
         'a last_synced written in UTC reads the same';
  ASSERT (SELECT last_synced IS NULL FROM t_upstream_feed_status_call WHERE feed_name = 'metasploit'),
         'a NULL last_synced stays NULL';
  ASSERT (SELECT last_status = 'in_progress' AND records_updated = 0
          FROM t_upstream_feed_status_call WHERE feed_name = 'metasploit'),
         'last_status and records_updated are answered as stored';
  ASSERT (SELECT count(*) FROM api.fn_upstream_feed_status(2)) = 2,
         'a limit of 2 answers two rows';
  ASSERT (SELECT count(*) FROM api.fn_upstream_feed_status(NULL)) = 0,
         'a NULL limit answers no row';
END
$$;

DO $$
BEGIN
  ASSERT (SELECT prosecdef FROM pg_proc
          WHERE oid = 'api.fn_upstream_feed_status(integer)'::regprocedure),
         'api.fn_upstream_feed_status is SECURITY DEFINER';
  ASSERT (SELECT proconfig FROM pg_proc
          WHERE oid = 'api.fn_upstream_feed_status(integer)'::regprocedure)
         = ARRAY['search_path=pg_catalog'],
         'api.fn_upstream_feed_status sets search_path to pg_catalog';
END
$$;
