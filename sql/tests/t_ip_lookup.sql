CREATE TEMP VIEW t_ip_lookup_call AS SELECT * FROM api.fn_ip_lookup('203.0.113.7');

DO $$
BEGIN
  ASSERT (SELECT array_agg(attname::text ORDER BY attnum) FROM pg_attribute
          WHERE attrelid = 't_ip_lookup_call'::regclass AND attnum > 0)
         = ARRAY['asn', 'asn_name', 'asn_country', 'geo_country', 'cloud_provider', 'cloud_service', 'is_cdn', 'is_datacenter',
                 'is_tor_exit', 'listed_on', 'asn_feed_loaded', 'geo_feed_loaded', 'cloud_feed_loaded', 'tor_feed_loaded',
                 'drop_list_feed_loaded'],
         'api.fn_ip_lookup answers its 15 columns in this order';
  ASSERT (SELECT array_agg(format_type(atttypid, atttypmod) ORDER BY attnum) FROM pg_attribute
          WHERE attrelid = 't_ip_lookup_call'::regclass AND attnum > 0)
         = ARRAY['bigint', 'text', 'text', 'text', 'text', 'text', 'boolean', 'boolean', 'boolean', 'jsonb',
                 'boolean', 'boolean', 'boolean', 'boolean', 'boolean'],
         'asn is bigint, listed_on is jsonb, the flags are boolean and the names are text';
  ASSERT (SELECT row(c.*)::text FROM t_ip_lookup_call AS c)
         = row(NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, false, false, false, false, false)::text,
         'with every table empty, each flag is false and each value is NULL';
END
$$;

INSERT INTO ip_asn (asn, asn_name, country) VALUES
  (64496, 'Example AS', 'NL'), (64497, 'Wide AS', 'DE'), (15169, 'GOOGLE', 'US'), (64498, 'No country AS', NULL);
INSERT INTO ip_asn_prefix (prefix, asn) VALUES
  ('203.0.113.0/24', 64496), ('203.0.0.0/16', 64497), ('8.8.8.0/24', 15169), ('2001:db8::/32', 64498);
INSERT INTO ip_geo_prefix (prefix, country) VALUES
  ('203.0.113.0/25', 'BE'), ('203.0.0.0/16', 'FR'), ('2001:db8::/32', 'JP');
INSERT INTO ip_cloud_range (provider, service, prefix, is_cdn, synced_at) VALUES
  ('aws',    'amazon',     '198.51.100.0/24', false, now()),
  ('aws',    'cloudfront', '198.51.100.0/26', true,  now()),
  ('aws',    'ec2',        '192.0.2.0/24',    false, now()),
  ('fastly', 'fastly',     '192.0.2.0/24',    true,  now()),
  ('aws',    's3',         '100.64.1.0/24',   false, now()),
  ('aws',    'ec2',        '100.64.1.0/24',   false, now()),
  ('aws',    'cloudfront', '100.64.2.0/24',   true,  now()),
  ('aws',    'ec2',        '100.64.2.0/26',   false, now());
INSERT INTO ip_tor_exit (ip_address) VALUES ('203.0.113.7'), ('203.0.113.8');
INSERT INTO ip_drop_list_prefix (prefix, listing_id, regional_registry, list_time, copyright) VALUES
  ('203.0.0.0/16',   'SBL2', 'ripencc', '2026-10-22 08:00:00+00', '(c) 2026 Wide'),
  ('203.0.113.0/24', 'SBL1', 'apnic',   '2026-10-23 09:24:02+00', '(c) 2026 Narrow');

DO $$
BEGIN
  ASSERT (SELECT array_agg(row(p.provider, p.service, p.is_cdn)::text)
            FROM unnest(ARRAY['198.51.100.10', '198.51.100.200', '192.0.2.5', '100.64.1.1', '100.64.2.1', '100.64.2.200',
                              '203.0.113.7']::inet[]) AS a (ip),
                 LATERAL (SELECT * FROM api.fn_ip_cloud_provider(a.ip)) AS p)
         = ARRAY[row('aws', 'cloudfront', true)::text, row('aws', 'amazon', false)::text, row('fastly', 'fastly', true)::text,
                 row('aws', 'ec2', false)::text, row('aws', 'ec2', false)::text, row('aws', 'cloudfront', true)::text],
         'the longest prefix wins, then a CDN service, then the first service name, and an address of no prefix answers no row';
  ASSERT NOT EXISTS (SELECT 1 FROM api.fn_ip_cloud_provider(NULL)),
         'api.fn_ip_cloud_provider is STRICT: a NULL address answers no row';

  ASSERT (SELECT array_agg(row(l.*)::text) FROM api.fn_ip_listed_on('203.0.113.7') AS l)
         = ARRAY[row('drop', '203.0.113.0/24', 'SBL1', '2026-10-23T09:24:02Z', '(c) 2026 Narrow')::text,
                 row('drop', '203.0.0.0/16',   'SBL2', '2026-10-22T08:00:00Z', '(c) 2026 Wide')::text],
         'each prefix that holds the address answers a row, the longest prefix first, each column from its own column';
  ASSERT NOT EXISTS (SELECT 1 FROM api.fn_ip_listed_on('198.51.100.10')),
         'an address that no prefix holds answers no row';
  ASSERT NOT EXISTS (SELECT 1 FROM api.fn_ip_listed_on(NULL)),
         'api.fn_ip_listed_on is STRICT: a NULL address answers no row';

  ASSERT (SELECT row(c.*)::text FROM api.fn_ip_lookup('203.0.113.7') AS c)
         = row(64496, 'Example AS', 'NL', 'BE', NULL, NULL, NULL, false, true,
               '[{"prefix": "203.0.113.0/24", "listing_id": "SBL1", "source": "drop", "copyright": "(c) 2026 Narrow", "list_time": "2026-10-23T09:24:02Z"},
                 {"prefix": "203.0.0.0/16", "listing_id": "SBL2", "source": "drop", "copyright": "(c) 2026 Wide", "list_time": "2026-10-22T08:00:00Z"}]'::jsonb,
               true, true, true, true, true)::text,
         'an address in a longer prefix and a /16 of a list answers the values of the longer prefix, every row of listed_on, and is_cdn NULL with no provider prefix';
  ASSERT (SELECT row(c.asn, c.is_datacenter, c.is_tor_exit, c.listed_on, c.geo_country)::text FROM api.fn_ip_lookup('8.8.8.8') AS c)
         = row(15169, true, false, '[]'::jsonb, NULL)::text,
         'an address of a hosting AS is a datacenter, an address off the lists is no Tor exit and has an empty listed_on';
  ASSERT (SELECT row(c.cloud_provider, c.cloud_service, c.is_cdn, c.is_datacenter, c.asn)::text FROM api.fn_ip_lookup('198.51.100.10') AS c)
         = row('aws', 'cloudfront', true, true, NULL)::text,
         'an address of a provider prefix answers its provider and service, and is a datacenter with no known AS';
  ASSERT (SELECT row(c.cloud_provider, c.cloud_service, c.is_cdn, c.is_datacenter)::text FROM api.fn_ip_lookup('100.64.1.1') AS c)
         = row('aws', 'ec2', false, true)::text,
         'an address of a provider prefix that is not a CDN answers is_cdn false';
  ASSERT (SELECT row(c.asn, c.asn_name, c.asn_country, c.geo_country)::text FROM api.fn_ip_lookup('2001:db8::1') AS c)
         = row(64498, 'No country AS', NULL, 'JP')::text,
         'an IPv6 address answers from the IPv6 prefixes, and an AS with no country answers NULL';
  ASSERT NOT EXISTS (SELECT 1 FROM api.fn_ip_lookup(NULL)),
         'api.fn_ip_lookup is STRICT: a NULL address answers no row';
END
$$;

INSERT INTO ip_asn (asn, asn_name, country)
SELECT h.asn, 'Host ' || h.asn, 'US' FROM unnest(ARRAY[8075, 12876, 13335, 14061, 14618, 16276, 16509, 20473, 24940, 31898, 45102,
                                                     63949, 132203, 396982]::bigint[]) AS h (asn);
INSERT INTO ip_asn_prefix (prefix, asn)
SELECT ('100.65.0.' || h.n || '/32')::cidr, h.asn
  FROM unnest(ARRAY[8075, 12876, 13335, 14061, 14618, 15169, 16276, 16509, 20473, 24940, 31898, 45102, 63949, 132203, 396982,
                    64496]::bigint[])
       WITH ORDINALITY AS h (asn, n);
INSERT INTO ip_asn_prefix (prefix, asn) VALUES ('192.0.2.77/32', 64496);
INSERT INTO ip_geo_prefix (prefix, country) VALUES ('192.0.2.77/32', 'NL');
INSERT INTO ip_cloud_range (provider, service, prefix, is_cdn, synced_at) VALUES ('bunny', 'bunnycdn', '192.0.2.77/32', true, now());
INSERT INTO ip_drop_list_prefix (prefix, listing_id, regional_registry, list_time, copyright) VALUES
  ('192.0.2.77/32', 'SBL77', 'arin', '2026-10-23 15:04:05+00', '(c) host');
DO $$
BEGIN
  ASSERT (SELECT row(c.asn, c.geo_country, c.cloud_provider, c.cloud_service, c.listed_on -> 0 ->> 'prefix')::text
            FROM api.fn_ip_lookup('192.0.2.77') AS c)
         = row(64496, 'NL', 'bunny', 'bunnycdn', '192.0.2.77/32')::text,
         'a host prefix equal to the address holds it in each table';
  ASSERT (SELECT c.listed_on -> 0 ->> 'list_time' FROM api.fn_ip_lookup('192.0.2.77') AS c) = '2026-10-23T15:04:05Z',
         'list_time is on the 24-hour clock';
  ASSERT (SELECT c.is_datacenter IS FALSE FROM api.fn_ip_lookup('100.64.200.1') AS c),
         'with both tables loaded, an address of no AS and no provider prefix is no datacenter';
  ASSERT (SELECT array_agg(c.is_datacenter ORDER BY n) FROM generate_series(1, 16) AS n,
                 LATERAL api.fn_ip_lookup(('100.65.0.' || n)::inet) AS c)
         = array_fill(true, ARRAY[15]) || false,
         'each of the 15 hosting ASes is a datacenter, and another AS is not';
END
$$;

SAVEPOINT t_ip_lookup_feed;
DELETE FROM ip_cloud_range;
DO $$
BEGIN
  ASSERT (SELECT row(c.cloud_provider, c.cloud_service, c.is_cdn, c.is_datacenter, c.asn_feed_loaded, c.geo_feed_loaded,
                     c.cloud_feed_loaded, c.tor_feed_loaded, c.drop_list_feed_loaded)::text
            FROM api.fn_ip_lookup('203.0.113.7') AS c)
         = row(NULL, NULL, NULL, NULL, true, true, false, true, true)::text,
         'with no provider row, is_cdn is NULL, and is_datacenter is NULL for an AS that is not a hosting AS';
  ASSERT (SELECT c.is_datacenter FROM api.fn_ip_lookup('8.8.8.8') AS c),
         'with no provider row, an address of a hosting AS is still a datacenter';
END
$$;
ROLLBACK TO SAVEPOINT t_ip_lookup_feed;

DELETE FROM ip_asn_prefix;
DO $$
BEGIN
  ASSERT (SELECT row(c.asn, c.asn_name, c.asn_country, c.is_datacenter, c.asn_feed_loaded, c.geo_feed_loaded, c.cloud_feed_loaded,
                     c.tor_feed_loaded, c.drop_list_feed_loaded)::text
            FROM api.fn_ip_lookup('203.0.113.7') AS c)
         = row(NULL, NULL, NULL, NULL, false, true, true, true, true)::text,
         'with no AS prefix, the AS columns are NULL, and is_datacenter is NULL for an address of no provider prefix';
  ASSERT (SELECT c.is_datacenter FROM api.fn_ip_lookup('198.51.100.10') AS c),
         'with no AS prefix, an address of a provider prefix is still a datacenter';
END
$$;
ROLLBACK TO SAVEPOINT t_ip_lookup_feed;

DELETE FROM ip_geo_prefix;
DO $$
BEGIN
  ASSERT (SELECT row(c.geo_country, c.asn_feed_loaded, c.geo_feed_loaded, c.cloud_feed_loaded, c.tor_feed_loaded,
                     c.drop_list_feed_loaded)::text
            FROM api.fn_ip_lookup('203.0.113.7') AS c)
         = row(NULL, true, false, true, true, true)::text,
         'with no geo row, geo_country is NULL';
END
$$;
ROLLBACK TO SAVEPOINT t_ip_lookup_feed;

DELETE FROM ip_tor_exit;
DO $$
BEGIN
  ASSERT (SELECT row(c.is_tor_exit, c.asn_feed_loaded, c.geo_feed_loaded, c.cloud_feed_loaded, c.tor_feed_loaded,
                     c.drop_list_feed_loaded)::text
            FROM api.fn_ip_lookup('203.0.113.7') AS c)
         = row(NULL, true, true, true, false, true)::text,
         'with no Tor row, is_tor_exit is NULL, not false';
END
$$;
ROLLBACK TO SAVEPOINT t_ip_lookup_feed;

DELETE FROM ip_drop_list_prefix;
DO $$
BEGIN
  ASSERT (SELECT row(c.listed_on, c.asn_feed_loaded, c.geo_feed_loaded, c.cloud_feed_loaded, c.tor_feed_loaded,
                     c.drop_list_feed_loaded)::text
            FROM api.fn_ip_lookup('203.0.113.7') AS c)
         = row(NULL, true, true, true, true, false)::text,
         'with no DROP row, listed_on is NULL, not an empty array';
END
$$;
ROLLBACK TO SAVEPOINT t_ip_lookup_feed;

SET LOCAL TimeZone = 'Asia/Tokyo';
DO $$
BEGIN
  ASSERT (SELECT l.list_time FROM api.fn_ip_listed_on('203.0.113.7') AS l LIMIT 1) = '2026-10-23T09:24:02Z',
         'list_time is UTC text in a session of another time zone';
END
$$;
RESET TimeZone;
ROLLBACK TO SAVEPOINT t_ip_lookup_feed;
RELEASE SAVEPOINT t_ip_lookup_feed;

DO $$
BEGIN
  ASSERT (SELECT bool_and(p.prosecdef = (p.oid = 'api.fn_ip_lookup(inet)'::regprocedure)
                          AND p.proisstrict AND p.provolatile = 's' AND p.proconfig = ARRAY['search_path=pg_catalog'])
            FROM pg_proc AS p
           WHERE p.oid IN ('api.fn_ip_cloud_provider(inet)'::regprocedure, 'api.fn_ip_listed_on(inet)'::regprocedure,
                           'api.fn_ip_lookup(inet)'::regprocedure)),
         'api.fn_ip_lookup is SECURITY DEFINER and the two helpers SECURITY INVOKER; the three are STRICT, STABLE and set search_path to pg_catalog';
END
$$;

DELETE FROM ip_drop_list_prefix;
DELETE FROM ip_tor_exit;
DELETE FROM ip_cloud_range;
DELETE FROM ip_geo_prefix;
DELETE FROM ip_asn_prefix;
DELETE FROM ip_asn;

SAVEPOINT t_ip_hosting;
DELETE FROM upstream_feed_sync WHERE feed_name IN ('iptoasn', 'cloud_ranges');
INSERT INTO upstream_feed_sync (feed_name, last_synced, last_status) VALUES ('iptoasn', now(), 'ok'), ('cloud_ranges', now(), 'ok');
INSERT INTO ip_asn (asn, asn_name, country) VALUES (64496, 'Example AS', 'NL'), (24940, 'Hosting AS', 'DE');
INSERT INTO ip_asn_prefix (prefix, asn) VALUES ('198.51.100.0/24', 64496), ('203.0.113.0/24', 24940);
INSERT INTO ip_cloud_range (provider, service, prefix, is_cdn, synced_at) VALUES
  ('aws',    'amazon',     '198.51.100.0/24', false, now()),
  ('aws',    'cloudfront', '198.51.100.0/26', true,  now()),
  ('fastly', 'fastly',     '192.0.2.0/25',    true,  now()),
  ('google', 'cloud_run',  '192.0.2.128/26',  false, now()),
  ('google', 'cloudcdn',   '192.0.2.192/26',  true,  now());

CREATE FUNCTION pg_temp.t_hosting(p_ip_addresses text) RETURNS text LANGUAGE sql AS $$
  SELECT api.fn_ip_hosting_classes(string_to_array(p_ip_addresses, ',')::inet[])
$$;

CREATE FUNCTION pg_temp.t_feed(p_feed_name text, p_last_status text, p_age interval DEFAULT interval '0') RETURNS void LANGUAGE plpgsql AS $$
BEGIN
  DELETE FROM upstream_feed_sync AS ufs WHERE ufs.feed_name = p_feed_name;
  IF p_last_status IS NOT NULL THEN
    INSERT INTO upstream_feed_sync (feed_name, last_synced, last_status) VALUES (p_feed_name, now() - p_age, p_last_status);
  END IF;
END
$$;

DO $$
BEGIN
  ASSERT pg_temp.t_hosting('198.51.100.10') = 'aws/cloudfront', 'an address of a cloud prefix answers provider/service';
  ASSERT pg_temp.t_hosting('198.51.100.200') = 'aws/amazon', 'an address outside the CloudFront /26 answers the AMAZON /24';
  ASSERT pg_temp.t_hosting('203.0.113.7') = 'AS24940', 'an address of no cloud prefix answers its AS';
  ASSERT pg_temp.t_hosting('100.64.200.1') = 'not_routed', 'an address of no prefix answers not_routed';
  ASSERT pg_temp.t_hosting('198.51.100.10,198.51.100.20') = 'aws/cloudfront', 'two addresses of one class answer one line';
  ASSERT pg_temp.t_hosting('203.0.113.7,203.0.113.7') = 'AS24940', 'a repeated address counts once';
  ASSERT pg_temp.t_hosting('100.64.200.1,192.0.2.200,203.0.113.7,192.0.2.130,192.0.2.5,198.51.100.10')
         = E'AS24940\naws/cloudfront\nfastly/fastly\ngoogle/cloud_run\ngoogle/cloudcdn\nnot_routed',
         'the classes come once each, one on each line, in byte order';
  ASSERT api.fn_ip_hosting_classes(NULL) IS NULL, 'a NULL array answers NULL';
  ASSERT api.fn_ip_hosting_classes('{}') IS NULL, 'an empty array answers NULL';
END
$$;

DO $$
BEGIN
  UPDATE ip_cloud_range AS icr SET synced_at = now() - interval '7 days' WHERE icr.provider = 'fastly';
  ASSERT pg_temp.t_hosting('192.0.2.5') = 'fastly/fastly', 'a provider synced exactly 7 days ago is fresh';
  UPDATE ip_cloud_range AS icr SET synced_at = now() - interval '7 days' + interval '1 minute' WHERE icr.provider = 'fastly';
  ASSERT pg_temp.t_hosting('192.0.2.5') = 'fastly/fastly', 'a provider synced 7 days less a minute ago is fresh';
  UPDATE ip_cloud_range AS icr SET synced_at = now() - interval '7 days' - interval '1 minute' WHERE icr.provider = 'fastly';
  ASSERT pg_temp.t_hosting('192.0.2.5') IS NULL, 'a provider synced 7 days and a minute ago is stale, and the answer is NULL';
  ASSERT pg_temp.t_hosting('198.51.100.10,192.0.2.5') IS NULL, 'one stale address makes the whole answer NULL';
  ASSERT pg_temp.t_hosting('198.51.100.10') = 'aws/cloudfront', 'a stale provider leaves the class of another provider';
  UPDATE ip_cloud_range AS icr SET synced_at = now() WHERE icr.provider = 'fastly';

  UPDATE ip_cloud_range AS icr SET synced_at = now() - interval '8 days' WHERE icr.provider = 'aws' AND icr.service = 'amazon';
  ASSERT pg_temp.t_hosting('198.51.100.10') IS NULL, 'the oldest row of the provider decides, not the row that holds the address';
  UPDATE ip_cloud_range AS icr SET synced_at = now() - interval '6 days' WHERE icr.provider = 'aws' AND icr.service = 'amazon';
  ASSERT pg_temp.t_hosting('198.51.100.10') = 'aws/cloudfront', 'a provider whose oldest row is 6 days old is fresh';
  UPDATE ip_cloud_range AS icr SET synced_at = now() WHERE icr.provider = 'aws';
END
$$;

DO $$
BEGIN
  PERFORM pg_temp.t_feed('iptoasn', NULL);
  ASSERT pg_temp.t_hosting('203.0.113.7') IS NULL, 'with no iptoasn row, an AS class is NULL';
  ASSERT pg_temp.t_hosting('100.64.200.1') IS NULL, 'with no iptoasn row, not_routed is NULL';
  PERFORM pg_temp.t_feed('iptoasn', 'error');
  ASSERT pg_temp.t_hosting('203.0.113.7') IS NULL, 'with iptoasn in error, an AS class is NULL';
  PERFORM pg_temp.t_feed('iptoasn', 'in_progress');
  ASSERT pg_temp.t_hosting('203.0.113.7') IS NULL, 'with iptoasn in progress, an AS class is NULL';
  PERFORM pg_temp.t_feed('iptoasn', 'ok', interval '7 days' + interval '1 minute');
  ASSERT pg_temp.t_hosting('203.0.113.7') IS NULL, 'with iptoasn synced 7 days and a minute ago, an AS class is NULL';
  PERFORM pg_temp.t_feed('iptoasn', 'ok', interval '7 days');
  ASSERT pg_temp.t_hosting('203.0.113.7') = 'AS24940', 'with iptoasn synced exactly 7 days ago, the AS class stays';
  PERFORM pg_temp.t_feed('iptoasn', 'ok', interval '7 days' - interval '1 minute');
  ASSERT pg_temp.t_hosting('100.64.200.1') = 'not_routed', 'with iptoasn synced 7 days less a minute ago, not_routed stays';
  PERFORM pg_temp.t_feed('iptoasn', 'ok');

  PERFORM pg_temp.t_feed('cloud_ranges', 'error');
  ASSERT pg_temp.t_hosting('203.0.113.7') = 'AS24940', 'with cloud_ranges in error, the AS class stays';
  PERFORM pg_temp.t_feed('cloud_ranges', NULL);
  ASSERT pg_temp.t_hosting('203.0.113.7') = 'AS24940', 'with no cloud_ranges row, the AS class stays';
  ASSERT pg_temp.t_hosting('100.64.200.1') = 'not_routed', 'with no cloud_ranges row, not_routed stays';

  UPDATE ip_cloud_range AS icr SET synced_at = now() - interval '8 days' WHERE icr.provider = 'google';
  ASSERT pg_temp.t_hosting('203.0.113.7') IS NULL, 'one provider synced 8 days ago makes an AS class NULL';
  ASSERT pg_temp.t_hosting('100.64.200.1') IS NULL, 'one provider synced 8 days ago makes not_routed NULL';
  ASSERT pg_temp.t_hosting('198.51.100.10') = 'aws/cloudfront', 'one stale provider leaves the class of a fresh provider';
  UPDATE ip_cloud_range AS icr SET synced_at = now() - interval '7 days' - interval '1 minute' WHERE icr.provider = 'google';
  ASSERT pg_temp.t_hosting('203.0.113.7') IS NULL, 'one provider synced 7 days and a minute ago makes an AS class NULL';
  UPDATE ip_cloud_range AS icr SET synced_at = now() - interval '7 days' WHERE icr.provider = 'google';
  ASSERT pg_temp.t_hosting('203.0.113.7') = 'AS24940', 'one provider synced exactly 7 days ago keeps the AS class';
  UPDATE ip_cloud_range AS icr SET synced_at = now() - interval '7 days' + interval '1 minute' WHERE icr.provider = 'google';
  ASSERT pg_temp.t_hosting('100.64.200.1') = 'not_routed', 'one provider synced 7 days less a minute ago keeps not_routed';
  UPDATE ip_cloud_range AS icr SET synced_at = now() WHERE icr.provider = 'google';

  PERFORM pg_temp.t_feed('iptoasn', NULL);
  ASSERT pg_temp.t_hosting('198.51.100.10,192.0.2.5') = E'aws/cloudfront\nfastly/fastly', 'an address of a cloud prefix needs no feed row';
  ASSERT pg_temp.t_hosting('198.51.100.10,203.0.113.7') IS NULL, 'a cloud address beside an AS address with no feed row answers NULL';
  PERFORM pg_temp.t_feed('iptoasn', 'ok');
END
$$;

SAVEPOINT t_ip_hosting_empty_cloud;
DELETE FROM ip_cloud_range;
DO $$
BEGIN
  ASSERT pg_temp.t_hosting('203.0.113.7') IS NULL, 'with an empty cloud table, an AS class is NULL';
  ASSERT pg_temp.t_hosting('100.64.200.1') IS NULL, 'with an empty cloud table, not_routed is NULL';
END
$$;
ROLLBACK TO SAVEPOINT t_ip_hosting_empty_cloud;
RELEASE SAVEPOINT t_ip_hosting_empty_cloud;

SAVEPOINT t_ip_hosting_gcore;
INSERT INTO ip_asn_prefix (prefix, asn) VALUES ('2001:db8:f000::/48', 64496), ('2001:db8:f001::/48', 24940);
INSERT INTO ip_cloud_range (provider, service, prefix, is_cdn, synced_at) VALUES ('gcore', 'gcore', '2001:db8:f000::/36', true, now());
DO $$
BEGIN
  ASSERT (SELECT row(p.provider, p.service, p.is_cdn)::text FROM api.fn_ip_cloud_provider('2001:db8:f001::1') AS p)
         = row('gcore', 'gcore', true)::text,
         'an address of the gcore prefix answers gcore/gcore';
  ASSERT pg_temp.t_hosting('2001:db8:f000::1,2001:db8:f001::1') = 'gcore/gcore',
         'two addresses of the gcore prefix in two ASes answer the one line gcore/gcore';
  UPDATE ip_cloud_range AS icr SET synced_at = now() - interval '7 days' - interval '1 minute' WHERE icr.provider = 'gcore';
  ASSERT pg_temp.t_hosting('2001:db8:f000::1') IS NULL, 'gcore synced 7 days and a minute ago is stale, and the answer is NULL';
END
$$;
ROLLBACK TO SAVEPOINT t_ip_hosting_gcore;
RELEASE SAVEPOINT t_ip_hosting_gcore;

SAVEPOINT t_ip_hosting_akamai;
INSERT INTO ip_asn (asn, asn_name, country) VALUES (16625, 'Akamai AS', 'US'), (20940, 'Akamai Intl AS', 'NL'), (63949, 'Linode AS', 'US');
INSERT INTO ip_asn_prefix (prefix, asn) VALUES ('2001:db8:a000::/48', 16625), ('2001:db8:a001::/48', 20940), ('2001:db8:a002::/48', 63949), ('198.18.0.0/24', 16625);
INSERT INTO ip_cloud_range (provider, service, prefix, is_cdn, synced_at) VALUES ('aws', 'cloudfront', '2001:db8:a000:1::/64', true, now());
DO $$
BEGIN
  ASSERT pg_temp.t_hosting('2001:db8:a000::1,2001:db8:a001::1') = 'akamai/akamai',
         'an address of AS 16625 and one of AS 20940 answer the one line akamai/akamai';
  ASSERT pg_temp.t_hosting('198.18.0.1') = 'akamai/akamai', 'an IPv4 address of AS 16625 answers akamai/akamai';
  ASSERT pg_temp.t_hosting('2001:db8:a000:1::1') = 'aws/cloudfront', 'a cloud prefix inside an AS 16625 prefix wins over akamai/akamai';
  ASSERT pg_temp.t_hosting('2001:db8:a002::1') = 'AS63949', 'an address of AS 63949 answers its AS, not akamai/akamai';

  PERFORM pg_temp.t_feed('iptoasn', 'ok', interval '7 days' + interval '1 minute');
  ASSERT pg_temp.t_hosting('2001:db8:a000::1') IS NULL, 'with iptoasn synced 7 days and a minute ago, akamai/akamai is NULL';
  PERFORM pg_temp.t_feed('iptoasn', 'error');
  ASSERT pg_temp.t_hosting('2001:db8:a001::1') IS NULL, 'with iptoasn in error, akamai/akamai is NULL';
  PERFORM pg_temp.t_feed('iptoasn', 'ok');
  UPDATE ip_cloud_range AS icr SET synced_at = now() - interval '8 days' WHERE icr.provider = 'google';
  ASSERT pg_temp.t_hosting('2001:db8:a000::1') IS NULL, 'one provider synced 8 days ago makes akamai/akamai NULL, as it does an AS class';
END
$$;
ROLLBACK TO SAVEPOINT t_ip_hosting_akamai;
RELEASE SAVEPOINT t_ip_hosting_akamai;

INSERT INTO ip_asn (asn, asn_name, country)
  SELECT n, 'Length AS ' || n, 'NL' FROM generate_series(10000, 10254) AS n
  UNION ALL SELECT n, 'Length AS ' || n, 'NL' FROM generate_series(100000, 100001) AS n;
INSERT INTO ip_asn_prefix (prefix, asn)
  SELECT ('2001:db8:' || to_hex(a.asn::integer - 9999) || '::/48')::cidr, a.asn FROM ip_asn AS a WHERE a.asn BETWEEN 10000 AND 10254
  UNION ALL SELECT ('2001:db8:' || to_hex(a.asn::integer - 100000 + 1000) || '::/48')::cidr, a.asn FROM ip_asn AS a WHERE a.asn IN (100000, 100001);

CREATE FUNCTION pg_temp.t_length_case(p_asns bigint[], OUT addresses text, OUT classes text) LANGUAGE sql AS $$
  SELECT string_agg(host(p.prefix) || '1', ','), string_agg('AS' || p.asn, E'\n' ORDER BY ('AS' || p.asn) COLLATE "C")
    FROM ip_asn_prefix AS p WHERE p.asn = ANY (p_asns)
$$;

DO $$
DECLARE
  at_limit   record := pg_temp.t_length_case(ARRAY(SELECT generate_series(10000, 10254)::bigint) || ARRAY[100000::bigint]);
  past_limit record := pg_temp.t_length_case(ARRAY(SELECT generate_series(10000, 10253)::bigint) || ARRAY[100000::bigint, 100001]);
BEGIN
  ASSERT octet_length(at_limit.classes) = 2048, 'the first case is 2048 bytes long';
  ASSERT octet_length(past_limit.classes) = 2049, 'the second case is 2049 bytes long';
  ASSERT pg_temp.t_hosting(at_limit.addresses) = at_limit.classes, 'an answer of 2048 bytes is given';
  ASSERT pg_temp.t_hosting(past_limit.addresses) IS NULL, 'an answer of 2049 bytes is NULL';
END
$$;

DO $$
BEGIN
  ASSERT (SELECT NOT p.prosecdef AND p.provolatile = 's' AND p.proconfig = ARRAY['search_path=pg_catalog'] AND p.prosqlbody IS NOT NULL
            FROM pg_proc AS p WHERE p.oid = 'api.fn_ip_hosting_classes(inet[])'::regprocedure),
         'api.fn_ip_hosting_classes is SECURITY INVOKER, STABLE, sets search_path to pg_catalog and has a SQL-standard body';
END
$$;

DO $$
BEGIN
  ASSERT (SELECT p.prorows FROM pg_proc AS p WHERE p.oid = 'api.fn_ip_cloud_provider(inet)'::regprocedure) = 1,
         'api.fn_ip_cloud_provider declares ROWS 1';
  ASSERT (SELECT p.prorows FROM pg_proc AS p WHERE p.oid = 'api.fn_ip_asn_prefix(inet)'::regprocedure) = 1,
         'api.fn_ip_asn_prefix declares ROWS 1';
END
$$;
ROLLBACK TO SAVEPOINT t_ip_hosting;
RELEASE SAVEPOINT t_ip_hosting;
