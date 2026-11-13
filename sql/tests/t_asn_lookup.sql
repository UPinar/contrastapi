CREATE TEMP VIEW t_ip_asn_prefix_call AS SELECT * FROM api.fn_ip_asn_prefix('192.0.2.1');
CREATE TEMP VIEW t_asn_lookup_call AS SELECT * FROM api.fn_asn_lookup(64500, 50, 0);

DO $$
BEGIN
  ASSERT (SELECT array_agg(attname::text || ' ' || format_type(atttypid, atttypmod) ORDER BY attnum) FROM pg_attribute
          WHERE attrelid = 't_ip_asn_prefix_call'::regclass AND attnum > 0)
         = ARRAY['asn bigint', 'prefix text'],
         'api.fn_ip_asn_prefix answers asn bigint and prefix text, in this order';
  ASSERT (SELECT array_agg(attname::text || ' ' || format_type(atttypid, atttypmod) ORDER BY attnum) FROM pg_attribute
          WHERE attrelid = 't_asn_lookup_call'::regclass AND attnum > 0)
         = ARRAY['asn bigint', 'asn_name text', 'asn_country text', 'ipv4_prefix_count integer', 'ipv6_prefix_count integer',
                 'ipv4_prefixes jsonb', 'ipv6_prefixes jsonb'],
         'api.fn_asn_lookup answers its 7 columns in this order, with these types';
  ASSERT (SELECT indexdef FROM pg_indexes WHERE indexname = 'idx_ip_asn_prefix_asn')
         = 'CREATE INDEX idx_ip_asn_prefix_asn ON public.ip_asn_prefix USING btree (asn, prefix)',
         'ip_asn_prefix has an index on asn and prefix, so api.fn_asn_lookup does not scan the whole table';
  ASSERT NOT EXISTS (SELECT 1 FROM t_ip_asn_prefix_call), 'with an empty table, an address answers no row';
  ASSERT NOT EXISTS (SELECT 1 FROM t_asn_lookup_call), 'with an empty table, an AS answers no row';
END
$$;

INSERT INTO ip_asn (asn, asn_name, country) VALUES
  (64503, 'No prefix AS', 'US'), (64500, 'Many AS', 'NL'), (64502, 'V6 only AS', 'DE'), (64501, 'V4 only AS', NULL),
  (64504, 'Wide AS', 'FR'), (64505, 'Narrow AS', 'BE'), (64506, 'Wide AS 2', 'IT'), (64507, 'Narrow AS 2', 'ES'),
  (64508, 'Host AS', 'SE');
INSERT INTO ip_asn_prefix (prefix, asn) VALUES
  ('2001:db8:10::/48',   64500),
  ('198.51.100.128/25',  64500),
  ('192.0.2.64/26',      64500),
  ('2001:db8:2::/48',    64500),
  ('198.51.100.0/25',    64500),
  ('2001:db8:1::/48',    64500),
  ('192.0.2.0/26',       64500),
  ('9.9.9.0/24',         64500),
  ('203.0.113.0/24',     64501),
  ('2001:db8:ff00::/40', 64502),
  ('100.64.1.0/24',      64505),
  ('100.64.0.0/10',      64504),
  ('172.16.0.0/12',      64506),
  ('172.16.5.0/24',      64507),
  ('192.0.2.77/32',      64508);

DO $$
BEGIN
  ASSERT (SELECT array_agg(row(p.asn, p.prefix)::text ORDER BY a.n)
            FROM unnest(ARRAY['192.0.2.1', '192.0.2.100', '9.9.9.9', '2001:db8:1::1', '2001:db8:ff12::5', '100.64.1.5',
                              '100.64.2.5', '172.16.5.9', '172.16.6.9', '192.0.2.77']::inet[]) WITH ORDINALITY AS a (ip, n),
                 LATERAL api.fn_ip_asn_prefix(a.ip) AS p)
         = ARRAY[row(64500, '192.0.2.0/26')::text, row(64500, '192.0.2.64/26')::text, row(64500, '9.9.9.0/24')::text,
                 row(64500, '2001:db8:1::/48')::text, row(64502, '2001:db8:ff00::/40')::text,
                 row(64505, '100.64.1.0/24')::text, row(64504, '100.64.0.0/10')::text,
                 row(64507, '172.16.5.0/24')::text, row(64506, '172.16.0.0/12')::text,
                 row(64508, '192.0.2.77/32')::text],
         'each address answers the AS and the CIDR text of the longest prefix that holds it, IPv4 and IPv6, a host prefix too';
  ASSERT (SELECT count(*) FROM api.fn_ip_asn_prefix('100.64.1.5')) = 1,
         'an address inside two prefixes answers one row';
  ASSERT NOT EXISTS (SELECT 1 FROM api.fn_ip_asn_prefix('192.0.2.200')),
         'an address that no prefix holds answers no row';
  ASSERT NOT EXISTS (SELECT 1 FROM api.fn_ip_asn_prefix('2001:db8:3::1')),
         'an IPv6 address that no prefix holds answers no row';
  ASSERT NOT EXISTS (SELECT 1 FROM api.fn_ip_asn_prefix(NULL)),
         'api.fn_ip_asn_prefix is STRICT: a NULL address answers no row';

  ASSERT (SELECT row(c.*)::text FROM api.fn_asn_lookup(64500, 2, 0) AS c)
         = row(64500, 'Many AS', 'NL', 5, 3, '["9.9.9.0/24", "192.0.2.0/26"]'::jsonb,
               '["2001:db8:1::/48", "2001:db8:2::/48"]'::jsonb)::text,
         'a row count of 2 cuts each family to its first 2 prefixes by address, and the counts stay the totals';
  ASSERT (SELECT row(c.*)::text FROM api.fn_asn_lookup(64500, 2, 2) AS c)
         = row(64500, 'Many AS', 'NL', 5, 3, '["192.0.2.64/26", "198.51.100.0/25"]'::jsonb,
               '["2001:db8:10::/48"]'::jsonb)::text,
         'an offset of 2 skips the first 2 prefixes of each family by address, and the shorter family lists what is left';
  ASSERT (SELECT row(c.ipv4_prefixes, c.ipv6_prefixes)::text FROM api.fn_asn_lookup(64500, 2, 4) AS c)
         = row('["198.51.100.128/25"]'::jsonb, '[]'::jsonb)::text,
         'an offset past the last prefix of a family answers an empty array for that family only';
  ASSERT (SELECT row(c.*)::text FROM api.fn_asn_lookup(64500, 50, 0) AS c)
         = row(64500, 'Many AS', 'NL', 5, 3,
               '["9.9.9.0/24", "192.0.2.0/26", "192.0.2.64/26", "198.51.100.0/25", "198.51.100.128/25"]'::jsonb,
               '["2001:db8:1::/48", "2001:db8:2::/48", "2001:db8:10::/48"]'::jsonb)::text,
         'a row count above the totals answers every prefix of each family, in address order';
  ASSERT (SELECT row(c.ipv4_prefix_count, c.ipv6_prefix_count, c.ipv4_prefixes, c.ipv6_prefixes)::text
            FROM api.fn_asn_lookup(64500, 50, 5) AS c)
         = row(5, 3, '[]'::jsonb, '[]'::jsonb)::text,
         'an offset past the last prefix of both families answers empty arrays, and the counts stay the totals';
  ASSERT (SELECT row(c.ipv4_prefix_count, c.ipv6_prefix_count, c.ipv4_prefixes, c.ipv6_prefixes)::text
            FROM api.fn_asn_lookup(64500, 0, 0) AS c)
         = row(5, 3, '[]'::jsonb, '[]'::jsonb)::text,
         'a row count of 0 answers empty arrays, and the counts stay the totals';
  ASSERT (SELECT row(c.*)::text FROM api.fn_asn_lookup(64501, 50, 0) AS c)
         = row(64501, 'V4 only AS', NULL, 1, 0, '["203.0.113.0/24"]'::jsonb, '[]'::jsonb)::text,
         'an AS with no country answers NULL, and an AS with no IPv6 prefix answers 0 and an empty array for it';
  ASSERT (SELECT row(c.*)::text FROM api.fn_asn_lookup(64502, 50, 0) AS c)
         = row(64502, 'V6 only AS', 'DE', 0, 1, '[]'::jsonb, '["2001:db8:ff00::/40"]'::jsonb)::text,
         'an AS with no IPv4 prefix answers 0 and an empty array for it';
  ASSERT (SELECT row(c.*)::text FROM api.fn_asn_lookup(64503, 50, 0) AS c)
         = row(64503, 'No prefix AS', 'US', 0, 0, '[]'::jsonb, '[]'::jsonb)::text,
         'an AS with no prefix answers its row, with 0 and an empty array for each family';
  ASSERT (SELECT count(*) FROM api.fn_asn_lookup(64500, 50, 0)) = 1,
         'an AS answers one row';
  ASSERT NOT EXISTS (SELECT 1 FROM api.fn_asn_lookup(64999, 50, 0)),
         'an AS that ip_asn does not hold answers no row';
  ASSERT NOT EXISTS (SELECT 1 FROM api.fn_asn_lookup(NULL, 50, 0)),
         'api.fn_asn_lookup is STRICT: a NULL AS answers no row';
  ASSERT NOT EXISTS (SELECT 1 FROM api.fn_asn_lookup(64500, NULL, 0)),
         'api.fn_asn_lookup is STRICT: a NULL row count answers no row, not every prefix';
  ASSERT NOT EXISTS (SELECT 1 FROM api.fn_asn_lookup(64500, 50, NULL)),
         'api.fn_asn_lookup is STRICT: a NULL offset answers no row';

  ASSERT (SELECT bool_and(p.prosecdef AND p.proisstrict AND p.provolatile = 's' AND p.proconfig = ARRAY['search_path=pg_catalog'])
            FROM pg_proc AS p
           WHERE p.oid IN ('api.fn_ip_asn_prefix(inet)'::regprocedure, 'api.fn_asn_lookup(bigint, integer, integer)'::regprocedure)),
         'the two functions are SECURITY DEFINER, STRICT, STABLE and set search_path to pg_catalog';
END
$$;

DELETE FROM ip_asn_prefix;
DELETE FROM ip_asn;
