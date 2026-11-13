CREATE TEMP VIEW t_ssl_blacklist_certificate_call AS SELECT * FROM api.fn_ssl_blacklist_certificate(repeat('a', 40));

DO $$
BEGIN
  ASSERT (SELECT array_agg(attname::text || ' ' || format_type(atttypid, atttypmod) ORDER BY attnum) FROM pg_attribute
          WHERE attrelid = 't_ssl_blacklist_certificate_call'::regclass AND attnum > 0)
         = ARRAY['ssl_blacklist_feed_loaded boolean', 'listing_reason text', 'listing_time text'],
         'api.fn_ssl_blacklist_certificate answers ssl_blacklist_feed_loaded boolean, listing_reason text and listing_time text, in this order';
  ASSERT (SELECT indexdef FROM pg_indexes WHERE indexname = 'ssl_blacklist_certificate_pkey')
         = 'CREATE UNIQUE INDEX ssl_blacklist_certificate_pkey ON public.ssl_blacklist_certificate USING btree (sha1)',
         'the primary key of ssl_blacklist_certificate is the index a fingerprint is looked up in';
  ASSERT (SELECT array_agg(row(c.*)::text) FROM t_ssl_blacklist_certificate_call AS c) = ARRAY[row(false, NULL, NULL)::text],
         'with an empty table, a fingerprint answers one row: the feed is not loaded and nothing is listed';
END
$$;

INSERT INTO ssl_blacklist_certificate (sha1, listing_reason, listing_time) VALUES
  (repeat('a', 40), 'Dridex C&C', '2024-01-02 13:04:05+00'),
  (repeat('b', 39) || 'c', 'AsyncRAT C&C', '2026-10-25 10:56:45+00');

SET LOCAL TimeZone = 'Asia/Tokyo';

DO $$
BEGIN
  ASSERT (SELECT array_agg(row(q.sha1, c.ssl_blacklist_feed_loaded, c.listing_reason, c.listing_time)::text ORDER BY q.position)
            FROM unnest(ARRAY[repeat('a', 40), repeat('b', 39) || 'c', repeat('B', 39) || 'C', repeat('d', 40),
                              repeat('a', 39), '', repeat('_', 40), ' ' || repeat('a', 40)])
                 WITH ORDINALITY AS q (sha1, position),
                 LATERAL (SELECT * FROM api.fn_ssl_blacklist_certificate(q.sha1)) AS c)
         = ARRAY[row(repeat('a', 40), true, 'Dridex C&C', '2024-01-02T13:04:05Z')::text,
                 row(repeat('b', 39) || 'c', true, 'AsyncRAT C&C', '2026-10-25T10:56:45Z')::text,
                 row(repeat('B', 39) || 'C', true, 'AsyncRAT C&C', '2026-10-25T10:56:45Z')::text,
                 row(repeat('d', 40), true, NULL, NULL)::text,
                 row(repeat('a', 39), true, NULL, NULL)::text,
                 row('', true, NULL, NULL)::text,
                 row(repeat('_', 40), true, NULL, NULL)::text,
                 row(' ' || repeat('a', 40), true, NULL, NULL)::text],
         'each fingerprint answers one row: the reason and the UTC time of its listed row, or NULL when no row lists it';
  ASSERT NOT EXISTS (SELECT 1 FROM api.fn_ssl_blacklist_certificate(NULL)), 'api.fn_ssl_blacklist_certificate is STRICT';
  ASSERT (SELECT p.prosecdef AND p.proisstrict AND p.provolatile = 's' AND p.proconfig = ARRAY['search_path=pg_catalog']
            FROM pg_proc AS p
           WHERE p.oid = 'api.fn_ssl_blacklist_certificate(text)'::regprocedure),
         'api.fn_ssl_blacklist_certificate is SECURITY DEFINER, STRICT, STABLE and sets search_path to pg_catalog';
END
$$;

RESET TimeZone;
DELETE FROM ssl_blacklist_certificate;
