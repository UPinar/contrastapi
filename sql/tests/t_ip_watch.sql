SAVEPOINT t_ip_watch;
DELETE FROM watchlist_item WHERE endpoint_name = 'ip_lookup';
TRUNCATE ip_change_event;
UPDATE change_event_purge_state SET max_purged_event_id = 0 WHERE event_table_name = 'ip_change_event';
DELETE FROM ip_drop_list_prefix;
DELETE FROM ip_cloud_range;
DELETE FROM ip_asn_prefix;
DELETE FROM upstream_feed_sync WHERE feed_name IN ('drop_list', 'iptoasn', 'cloud_ranges', 'tor_exit');

INSERT INTO api_keys (key_hash, active, expires_at)
VALUES (repeat('e1', 32), true, NULL), (repeat('e2', 32), true, NULL), (repeat('e3', 32), true, NULL), (repeat('e4', 32), true, NULL);

INSERT INTO upstream_feed_sync (feed_name, last_synced, last_status)
VALUES ('drop_list', now() - interval '1 hour', 'ok'), ('iptoasn', now() - interval '1 hour', 'ok'),
       ('cloud_ranges', now() - interval '1 hour', 'ok');
INSERT INTO ip_asn (asn, asn_name, country)
VALUES (64500, 'Test AS 64500', 'NL'), (64501, 'Test AS 64501', 'NL'), (64502, 'Test AS 64502', 'NL'), (64503, 'Test AS 64503', 'NL')
ON CONFLICT DO NOTHING;
INSERT INTO ip_asn_prefix (prefix, asn) VALUES ('192.0.2.0/24', 64500), ('2001:db8::/32', 64501);
INSERT INTO ip_cloud_range (provider, service, prefix, is_cdn, synced_at) VALUES ('aws', 'ec2', '198.51.100.0/26', false, now());
INSERT INTO ip_drop_list_prefix (prefix, listing_id, regional_registry, list_time, copyright)
VALUES ('192.0.2.0/25', 'SBL100', 'ripencc', '2026-11-01T00:00:00Z', '(c) 2026 v4 file'),
       ('2001:db8::/48', 'SBL200', 'ripencc', '2026-11-02T00:00:00Z', '(c) 2026 v6 file');

CREATE FUNCTION pg_temp.t_ipw_add(p_ip_address text, p_key_hash text DEFAULT repeat('e1', 32)) RETURNS bigint LANGUAGE sql AS $$
  SELECT count(*) FROM api.fn_watchlist_edit_ip_lookup(p_key_hash, 'add', p_ip_address::inet, 100);
  SELECT wii.item_id FROM watchlist_item_ip AS wii JOIN api_keys AS ak ON ak.id = wii.api_key_id
   WHERE ak.key_hash = p_key_hash AND wii.ip_address = p_ip_address::inet
$$;

CREATE FUNCTION pg_temp.t_ipw_run(p_item_row_count integer DEFAULT 100) RETURNS integer LANGUAGE sql AS $$
  UPDATE watchlist_item_ip SET checked_at = checked_at - interval '2 hours';
  SELECT api.fn_ip_watch_write_values(p_item_row_count)
$$;

CREATE FUNCTION pg_temp.t_ipw_value(p_item_id bigint, p_value_kind text) RETURNS text LANGUAGE sql AS $$
  SELECT wiiv.current_value || '|' || coalesce(wiiv.candidate_value, 'null')
    FROM watchlist_item_ip_value AS wiiv WHERE wiiv.item_id = p_item_id AND wiiv.value_kind = p_value_kind
$$;

CREATE FUNCTION pg_temp.t_ipw_events(p_item_id bigint) RETURNS text[] LANGUAGE sql AS $$
  SELECT coalesce(array_agg(ice.event_type || '|' || coalesce(ice.previous_value, 'null') || '|' || coalesce(ice.current_value, 'null')
                            ORDER BY ice.event_id), '{}')
    FROM watchlist_event_ref AS wer JOIN ip_change_event AS ice ON ice.event_id = wer.event_id
   WHERE wer.item_id = p_item_id
$$;

CREATE FUNCTION pg_temp.t_ipw_reset() RETURNS void LANGUAGE sql AS $$
  DELETE FROM watchlist_item AS wi WHERE wi.endpoint_name = 'ip_lookup';
  DELETE FROM watchlist_event_ref AS wer WHERE wer.event_id IN (SELECT ice.event_id FROM ip_change_event AS ice);
  DELETE FROM ip_change_event;
$$;

DO $$
DECLARE
  refused text;
BEGIN
  ASSERT (SELECT count(*) FROM change_event_purge_state AS ps WHERE ps.event_table_name = 'ip_change_event') = 1
     AND (SELECT ps.max_purged_event_id FROM change_event_purge_state AS ps WHERE ps.event_table_name = 'ip_change_event') = 0,
         'S1 change_event_purge_state holds one row of the IP events, at 0';
  ASSERT api.fn_ip_change_event_max_id() = 0, 'S1 the largest IP event_id is 0 with no event and no purge';
  ASSERT (SELECT pi.indexdef FROM pg_indexes AS pi WHERE pi.indexname = 'idx_ip_change_event_changed_at')
         = 'CREATE INDEX idx_ip_change_event_changed_at ON public.ip_change_event USING btree (changed_at)',
         'S1 the purge finds the old IP events through an index on changed_at';
  ASSERT (SELECT pi.indexdef FROM pg_indexes AS pi WHERE pi.indexname = 'idx_watchlist_item_ip_checked_at') LIKE '%ON public.watchlist_item_ip USING btree (checked_at%',
         'S1 the writer finds the due items through an index on checked_at';
  ASSERT pg_get_constraintdef((SELECT c.oid FROM pg_constraint AS c WHERE c.conname = 'ip_change_event_type_known'))
         LIKE '%drop_listed%drop_unlisted%hosting_changed%',
         'S1 ip_change_event_type_known allows drop_listed, drop_unlisted and hosting_changed';
  ASSERT (SELECT count(*) FROM regexp_matches(pg_get_constraintdef((SELECT c.oid FROM pg_constraint AS c WHERE c.conname = 'ip_change_event_type_known')),
                                               '''([^'']+)''::text', 'g')) = 3,
         'S1 ip_change_event_type_known allows three types';
  FOR refused IN SELECT unnest(ARRAY[
      $s$INSERT INTO ip_change_event (ip_address, event_type) VALUES ('192.0.2.0/24', 'hosting_changed')$s$,
      $s$INSERT INTO ip_change_event (ip_address, event_type) VALUES ('192.0.2.1', 'domain_found')$s$,
      $s$INSERT INTO ip_change_event (ip_address, event_type) VALUES ('192.0.2.1', 'drop_listed')$s$,
      $s$INSERT INTO ip_change_event (ip_address, event_type, drop_list_time) VALUES ('192.0.2.1', 'drop_unlisted', now())$s$,
      $s$INSERT INTO ip_change_event (ip_address, event_type, drop_list_time, drop_copyright) VALUES ('192.0.2.1', 'hosting_changed', now(), 'c')$s$,
      $s$INSERT INTO ip_change_event (ip_address, event_type, drop_list_time, drop_copyright) VALUES ('192.0.2.1', 'drop_listed', now(), repeat('c', 257))$s$,
      $s$INSERT INTO ip_change_event (ip_address, event_type, current_value) VALUES ('192.0.2.1', 'hosting_changed', repeat('a', 4097))$s$,
      $s$INSERT INTO ip_change_event (ip_address, event_type, previous_value) VALUES ('192.0.2.1', 'hosting_changed', repeat('a', 4097))$s$,
      $s$UPDATE change_event_purge_state SET max_unwatched_event_id = 1 WHERE event_table_name = 'ip_change_event'$s$]) LOOP
    BEGIN
      EXECUTE refused;
      ASSERT false, 'S1 the IP tables refuse: ' || refused;
    EXCEPTION WHEN check_violation THEN
      NULL;
    END;
  END LOOP;
  BEGIN
    INSERT INTO ip_change_event (ip_address, event_type, current_value) VALUES ('2001:db8::1', 'hosting_changed', repeat('a', 4096));
    INSERT INTO ip_change_event (ip_address, event_type, previous_value, current_value, drop_list_time, drop_copyright)
    VALUES ('192.0.2.1', 'drop_listed', NULL, '192.0.2.0/25 SBL100', now(), repeat('c', 256));
    RAISE SQLSTATE 'TUNDO';
  EXCEPTION WHEN SQLSTATE 'TUNDO' THEN
    NULL;
  END;
END
$$;

DO $$
DECLARE
  ip_item_id bigint := pg_temp.t_ipw_add('192.0.2.200');
  refused text;
BEGIN
  ASSERT (SELECT wii.endpoint_name || '|' || host(wii.ip_address) || '|' || coalesce(wii.checked_at::text, 'null')
            FROM watchlist_item_ip AS wii WHERE wii.item_id = ip_item_id) = 'ip_lookup|192.0.2.200|null',
         'S2 the add writes the address with no check yet';
  FOR refused IN SELECT unnest(ARRAY[
      format($s$UPDATE watchlist_item_ip SET ip_address = '192.0.2.0/24' WHERE item_id = %s$s$, ip_item_id),
      format($s$UPDATE watchlist_item_ip SET endpoint_name = 'dns_lookup' WHERE item_id = %s$s$, ip_item_id),
      format($s$INSERT INTO watchlist_item_ip_value (item_id, value_kind, current_value) VALUES (%s, 'ns', '')$s$, ip_item_id),
      format($s$INSERT INTO watchlist_item_ip_value (item_id, value_kind, current_value, candidate_value) VALUES (%s, 'hosting', 'a', 'b')$s$, ip_item_id),
      format($s$INSERT INTO watchlist_item_ip_value (item_id, value_kind, current_value, candidate_seen_at) VALUES (%s, 'hosting', 'a', now())$s$, ip_item_id)]) LOOP
    BEGIN
      EXECUTE refused;
      ASSERT false, 'S2 the item tables refuse: ' || refused;
    EXCEPTION WHEN check_violation OR foreign_key_violation THEN
      NULL;
    END;
  END LOOP;
  BEGIN
    INSERT INTO watchlist_item (api_key_id, endpoint_name) SELECT ak.id, 'ip_lookup' FROM api_keys AS ak WHERE ak.key_hash = repeat('e1', 32);
    INSERT INTO watchlist_item_ip (item_id, api_key_id, endpoint_name, ip_address)
    SELECT max(wi.item_id), max(wi.api_key_id), 'ip_lookup', '192.0.2.200' FROM watchlist_item AS wi WHERE wi.endpoint_name = 'ip_lookup';
    ASSERT false, 'S2 a key holds each address once';
  EXCEPTION WHEN unique_violation THEN
    ASSERT SQLERRM LIKE '%watchlist_item_ip_key_address_unique%', 'S2 watchlist_item_ip_key_address_unique refuses a second row: ' || SQLERRM;
  END;
  PERFORM pg_temp.t_ipw_reset();
END
$$;

DO $$
DECLARE
  plain_id  bigint := pg_temp.t_ipw_add('192.0.2.200');
  listed_id bigint := pg_temp.t_ipw_add('192.0.2.10');
  v6_id     bigint := pg_temp.t_ipw_add('2001:db8::5');
  cloud_id  bigint := pg_temp.t_ipw_add('198.51.100.5');
BEGIN
  ASSERT api.fn_ip_watch_write_values(100) = 4, 'S3 the writer evaluates the four new items';
  ASSERT (SELECT bool_and(wii.checked_at = now()) FROM watchlist_item_ip AS wii), 'S3 each evaluated item is checked now';
  ASSERT pg_temp.t_ipw_value(plain_id, 'drop_listing') = '|null', 'S3 an unlisted first value stores the empty value';
  ASSERT pg_temp.t_ipw_value(plain_id, 'hosting') = 'AS64500|null', 'S3 the first hosting value is the AS of the address';
  ASSERT pg_temp.t_ipw_events(plain_id) = '{}', 'S3 an unlisted first value and a first hosting value write no event';
  ASSERT pg_temp.t_ipw_value(listed_id, 'drop_listing') = '192.0.2.0/25 SBL100|null', 'S3 a listed first value stores the prefix and the listing id';
  ASSERT pg_temp.t_ipw_events(listed_id) = '{"drop_listed|null|192.0.2.0/25 SBL100"}', 'S3 a listed first value writes drop_listed with no previous value';
  ASSERT pg_temp.t_ipw_events(v6_id) = '{"drop_listed|null|2001:db8::/48 SBL200"}', 'S3 an IPv6 address hears its own listing';
  ASSERT pg_temp.t_ipw_value(v6_id, 'hosting') = 'AS64501|null', 'S3 the IPv6 address is hosted in AS 64501';
  ASSERT pg_temp.t_ipw_value(cloud_id, 'hosting') = 'aws/ec2|null' AND pg_temp.t_ipw_events(cloud_id) = '{}',
         'S3 a cloud address stores its provider and service, and writes no event';
  ASSERT (SELECT array_agg(ice.drop_list_time::text || '|' || ice.drop_copyright ORDER BY ice.event_id) FROM ip_change_event AS ice)
         = ARRAY[('2026-11-02T00:00:00Z'::timestamptz)::text || '|(c) 2026 v6 file', ('2026-11-02T00:00:00Z'::timestamptz)::text || '|(c) 2026 v6 file'],
         'S3 every drop event carries the newest list_time and its copyright';
  ASSERT api.fn_ip_change_event_max_id() = (SELECT max(ice.event_id) FROM ip_change_event AS ice),
         'S3 the largest IP event_id is the newest event';
  ASSERT api.fn_watchlist_event_max_id() >= api.fn_ip_change_event_max_id(), 'S3 the watch list head counts the IP events';
END
$$;

DO $$
DECLARE
  plain_id  bigint := (SELECT wii.item_id FROM watchlist_item_ip AS wii WHERE wii.ip_address = '192.0.2.200');
  listed_id bigint := (SELECT wii.item_id FROM watchlist_item_ip AS wii WHERE wii.ip_address = '192.0.2.10');
BEGIN
  DELETE FROM ip_drop_list_prefix WHERE prefix = '192.0.2.0/25';
  ASSERT pg_temp.t_ipw_run() = 4, 'S4 the writer evaluates every item again';
  ASSERT pg_temp.t_ipw_events(listed_id) = '{"drop_listed|null|192.0.2.0/25 SBL100","drop_unlisted|192.0.2.0/25 SBL100|"}',
         'S4 the listing that went away writes drop_unlisted';
  ASSERT pg_temp.t_ipw_value(listed_id, 'drop_listing') = '|null', 'S4 the unlisted value is empty';
  INSERT INTO ip_drop_list_prefix (prefix, listing_id, regional_registry, list_time, copyright)
  VALUES ('192.0.2.0/25', 'SBL100', 'ripencc', '2026-11-03T00:00:00Z', '(c) 2026 v4 file');
  PERFORM pg_temp.t_ipw_run();
  ASSERT pg_temp.t_ipw_events(listed_id)
         = '{"drop_listed|null|192.0.2.0/25 SBL100","drop_unlisted|192.0.2.0/25 SBL100|","drop_listed||192.0.2.0/25 SBL100"}',
         'S4 the listing that came back writes drop_listed from the empty value';
  ASSERT (SELECT ice.drop_list_time FROM ip_change_event AS ice ORDER BY ice.event_id DESC LIMIT 1) = '2026-11-03T00:00:00Z'
     AND (SELECT ice.drop_copyright FROM ip_change_event AS ice ORDER BY ice.event_id DESC LIMIT 1) = '(c) 2026 v4 file',
         'S4 the new drop event carries the list_time and the copyright of the rows at its time';
  ASSERT pg_temp.t_ipw_events(plain_id) = '{}', 'S4 the item that was never listed writes nothing';
END
$$;

DO $$
DECLARE
  listed_id   bigint := (SELECT wii.item_id FROM watchlist_item_ip AS wii WHERE wii.ip_address = '192.0.2.10');
  plain_id    bigint := (SELECT wii.item_id FROM watchlist_item_ip AS wii WHERE wii.ip_address = '192.0.2.200');
  event_count bigint := (SELECT count(*) FROM ip_change_event);
BEGIN
  DELETE FROM ip_drop_list_prefix WHERE prefix = '192.0.2.0/25';
  INSERT INTO ip_drop_list_prefix (prefix, listing_id, regional_registry, list_time, copyright)
  VALUES ('192.0.2.0/26', 'SBL101', 'ripencc', '2026-11-03T00:00:00Z', '(c) 2026 v4 file');
  PERFORM pg_temp.t_ipw_run();
  ASSERT pg_temp.t_ipw_value(listed_id, 'drop_listing') = '192.0.2.0/26 SBL101|null', 'S5 the overlapping prefix becomes the value';
  UPDATE ip_drop_list_prefix SET listing_id = 'SBL102' WHERE prefix = '192.0.2.0/26';
  PERFORM pg_temp.t_ipw_run();
  ASSERT pg_temp.t_ipw_value(listed_id, 'drop_listing') = '192.0.2.0/26 SBL102|null', 'S5 the new listing id becomes the value';
  UPDATE ip_drop_list_prefix SET list_time = list_time + interval '1 day', copyright = '(c) 2026 changed';
  PERFORM pg_temp.t_ipw_run();
  ASSERT pg_temp.t_ipw_value(listed_id, 'drop_listing') = '192.0.2.0/26 SBL102|null', 'S5 list_time and copyright are not part of the value';
  ASSERT pg_temp.t_ipw_value(plain_id, 'drop_listing') = '|null', 'S5 the address outside the new prefix stays unlisted';
  ASSERT (SELECT count(*) FROM ip_change_event) = event_count, 'S5 none of these changes writes an event';
END
$$;

DO $$
DECLARE
  listed_id   bigint := (SELECT wii.item_id FROM watchlist_item_ip AS wii WHERE wii.ip_address = '192.0.2.10');
  new_id      bigint := pg_temp.t_ipw_add('192.0.2.11');
  event_count bigint := (SELECT count(*) FROM ip_change_event);
BEGIN
  CREATE TEMP TABLE t_ipw_saved_drop AS SELECT * FROM ip_drop_list_prefix;
  DELETE FROM ip_drop_list_prefix;
  ASSERT pg_temp.t_ipw_run() = 5, 'S6 the writer still evaluates every item';
  ASSERT pg_temp.t_ipw_value(listed_id, 'drop_listing') = '192.0.2.0/26 SBL102|null', 'S6 an empty list keeps the stored value';
  ASSERT pg_temp.t_ipw_value(new_id, 'drop_listing') IS NULL AND pg_temp.t_ipw_value(new_id, 'hosting') = 'AS64500|null',
         'S6 an empty list writes no drop value of a new item, and its hosting value still comes';
  ASSERT (SELECT count(*) FROM ip_change_event) = event_count, 'S6 an empty list writes no event';
  INSERT INTO ip_drop_list_prefix SELECT * FROM t_ipw_saved_drop;
  DROP TABLE t_ipw_saved_drop;
  PERFORM pg_temp.t_ipw_run();
  ASSERT pg_temp.t_ipw_events(new_id) = '{"drop_listed|null|192.0.2.0/26 SBL102"}', 'S6 the first drop value comes when the list is back';
  ASSERT cardinality(pg_temp.t_ipw_events(listed_id)) = 3, 'S6 the listed item hears nothing new and keeps its three events';
END
$$;

DO $$
DECLARE
  plain_id bigint := (SELECT wii.item_id FROM watchlist_item_ip AS wii WHERE wii.ip_address = '192.0.2.200');
  cloud_id bigint := (SELECT wii.item_id FROM watchlist_item_ip AS wii WHERE wii.ip_address = '198.51.100.5');
BEGIN
  UPDATE ip_asn_prefix SET asn = 64502 WHERE prefix = '192.0.2.0/24';
  PERFORM pg_temp.t_ipw_run();
  ASSERT pg_temp.t_ipw_value(plain_id, 'hosting') = 'AS64500|AS64502', 'S7 a different value becomes the candidate';
  ASSERT (SELECT wiiv.candidate_seen_at FROM watchlist_item_ip_value AS wiiv WHERE wiiv.item_id = plain_id AND wiiv.value_kind = 'hosting') > statement_timestamp(),
         'S7 the candidate is first seen after the start of the statement';
  ASSERT pg_temp.t_ipw_events(plain_id) = '{}', 'S7 a candidate writes no event';
  PERFORM pg_temp.t_ipw_run();
  ASSERT pg_temp.t_ipw_value(plain_id, 'hosting') = 'AS64500|AS64502' AND pg_temp.t_ipw_events(plain_id) = '{}',
         'S7 the candidate seen again before both hosting lists are newer stays a candidate';
  UPDATE watchlist_item_ip_value SET candidate_seen_at = now() - interval '2 hours' WHERE item_id = plain_id AND value_kind = 'hosting';
  PERFORM pg_temp.t_ipw_run();
  ASSERT pg_temp.t_ipw_value(plain_id, 'hosting') = 'AS64502|null', 'S7 the candidate seen again after both hosting lists becomes the current value';
  ASSERT pg_temp.t_ipw_events(plain_id) = '{"hosting_changed|AS64500|AS64502"}', 'S7 the confirmed change writes hosting_changed';
  ASSERT (SELECT ice.drop_list_time IS NULL AND ice.drop_copyright IS NULL FROM ip_change_event AS ice
            JOIN watchlist_event_ref AS wer ON wer.event_id = ice.event_id WHERE wer.item_id = plain_id),
         'S7 a hosting event carries no DROP list time and no copyright';
  UPDATE ip_asn_prefix SET asn = 64503 WHERE prefix = '192.0.2.0/24';
  PERFORM pg_temp.t_ipw_run();
  UPDATE ip_asn_prefix SET asn = 64502 WHERE prefix = '192.0.2.0/24';
  PERFORM pg_temp.t_ipw_run();
  ASSERT pg_temp.t_ipw_value(plain_id, 'hosting') = 'AS64502|null', 'S7 the current value seen again clears the candidate';
  UPDATE ip_asn_prefix SET asn = 64503 WHERE prefix = '192.0.2.0/24';
  PERFORM pg_temp.t_ipw_run();
  UPDATE ip_asn_prefix SET asn = 64500 WHERE prefix = '192.0.2.0/24';
  PERFORM pg_temp.t_ipw_run();
  ASSERT pg_temp.t_ipw_value(plain_id, 'hosting') = 'AS64502|AS64500', 'S7 a third value takes the place of the candidate';
  ASSERT pg_temp.t_ipw_events(plain_id) = '{"hosting_changed|AS64500|AS64502"}', 'S7 a dropped or replaced candidate writes no event';
  ASSERT pg_temp.t_ipw_events(cloud_id) = '{}' AND pg_temp.t_ipw_value(cloud_id, 'hosting') = 'aws/ec2|null',
         'S7 the cloud address keeps its value and hears nothing';
END
$$;

DO $$
DECLARE
  plain_id bigint := (SELECT wii.item_id FROM watchlist_item_ip AS wii WHERE wii.ip_address = '192.0.2.200');
  new_id   bigint := pg_temp.t_ipw_add('192.0.2.12');
BEGIN
  UPDATE upstream_feed_sync SET last_synced = now() - interval '8 days' WHERE feed_name = 'iptoasn';
  ASSERT api.fn_ip_hosting_classes(ARRAY['192.0.2.200'::inet]) IS NULL, 'S8 the hosting class of a stale list is NULL';
  PERFORM pg_temp.t_ipw_run();
  ASSERT pg_temp.t_ipw_value(plain_id, 'hosting') = 'AS64502|AS64500', 'S8 a NULL class keeps the hosting row as it was';
  ASSERT pg_temp.t_ipw_value(new_id, 'hosting') IS NULL AND pg_temp.t_ipw_value(new_id, 'drop_listing') = '192.0.2.0/26 SBL102|null',
         'S8 a new item gets no hosting value but its drop value';
  UPDATE upstream_feed_sync SET last_synced = now() - interval '1 hour' WHERE feed_name = 'iptoasn';
END
$$;

DO $$
DECLARE
  revoked_id bigint := pg_temp.t_ipw_add('192.0.2.13', repeat('e3', 32));
  expired_id bigint := pg_temp.t_ipw_add('192.0.2.13', repeat('e4', 32));
  active_id  bigint := pg_temp.t_ipw_add('192.0.2.13');
BEGIN
  UPDATE api_keys SET active = false WHERE key_hash = repeat('e3', 32);
  UPDATE api_keys SET expires_at = now() WHERE key_hash = repeat('e4', 32);
  PERFORM pg_temp.t_ipw_run();
  ASSERT (SELECT wii.checked_at FROM watchlist_item_ip AS wii WHERE wii.item_id = revoked_id) IS NULL
     AND (SELECT wii.checked_at FROM watchlist_item_ip AS wii WHERE wii.item_id = expired_id) IS NULL,
         'S9 the items of a revoked and of an expired key are not evaluated';
  ASSERT NOT EXISTS (SELECT 1 FROM watchlist_item_ip_value AS wiiv WHERE wiiv.item_id IN (revoked_id, expired_id))
     AND pg_temp.t_ipw_events(revoked_id) = '{}' AND pg_temp.t_ipw_events(expired_id) = '{}',
         'S9 they get no value and no event';
  ASSERT pg_temp.t_ipw_events(active_id) = '{"drop_listed|null|192.0.2.0/26 SBL102"}', 'S9 the item of the working key is evaluated';
  UPDATE api_keys SET active = true WHERE key_hash = repeat('e3', 32);
  UPDATE api_keys SET expires_at = NULL WHERE key_hash = repeat('e4', 32);
  PERFORM pg_temp.t_ipw_reset();
END
$$;

DO $$
DECLARE
  ip_item_id bigint := pg_temp.t_ipw_add('192.0.2.14');
  feed     text;
BEGIN
  ASSERT api.fn_ip_watch_write_values(100) = 1, 'S10 the new item is due';
  ASSERT api.fn_ip_watch_write_values(100) = 0, 'S10 an item checked after every sync is not due';
  UPDATE watchlist_item_ip SET checked_at = now() - interval '2 hours';
  ASSERT api.fn_ip_watch_write_values(100) = 1, 'S10 an item checked before the newest ok sync is due';
  FOREACH feed IN ARRAY ARRAY['drop_list', 'iptoasn', 'cloud_ranges'] LOOP
    UPDATE upstream_feed_sync SET last_synced = now() - interval '3 hours' WHERE feed_name IN ('drop_list', 'iptoasn', 'cloud_ranges');
    INSERT INTO upstream_feed_sync (feed_name, last_synced, last_status) VALUES ('tor_exit', now() - interval '1 hour', 'ok')
    ON CONFLICT (feed_name) DO UPDATE SET last_synced = EXCLUDED.last_synced, last_status = EXCLUDED.last_status;
    UPDATE upstream_feed_sync SET last_synced = now() - interval '1 hour', last_status = 'error' WHERE feed_name = feed;
    UPDATE watchlist_item_ip SET checked_at = now() - interval '2 hours';
    ASSERT api.fn_ip_watch_write_values(100) = 0, 'S10 a newer failed sync of ' || feed || ' or a newer sync of tor_exit makes no item due';
    UPDATE upstream_feed_sync SET last_status = 'ok' WHERE feed_name = feed;
    ASSERT api.fn_ip_watch_write_values(100) = 1, 'S10 a newer ok sync of ' || feed || ' makes the item due';
    UPDATE upstream_feed_sync SET last_status = 'ok', last_synced = now() - interval '1 hour' WHERE feed_name IN ('drop_list', 'iptoasn', 'cloud_ranges');
  END LOOP;
  DELETE FROM upstream_feed_sync WHERE feed_name = 'tor_exit';
  PERFORM pg_temp.t_ipw_reset();
END
$$;

DO $$
DECLARE
  old_id    bigint := pg_temp.t_ipw_add('192.0.2.15');
  first_id  bigint := pg_temp.t_ipw_add('192.0.2.16');
  second_id bigint := pg_temp.t_ipw_add('192.0.2.17');
BEGIN
  UPDATE watchlist_item_ip SET checked_at = now() - interval '3 hours' WHERE item_id = old_id;
  ASSERT api.fn_ip_watch_write_values(2) = 2, 'S11 the writer evaluates at most two items';
  ASSERT (SELECT array_agg(wii.item_id ORDER BY wii.item_id) FROM watchlist_item_ip AS wii WHERE wii.checked_at = now()) = ARRAY[first_id, second_id],
         'S11 the never checked items come first';
  ASSERT api.fn_ip_watch_write_values(2) = 1, 'S11 the next call evaluates the item that waited';
  ASSERT api.fn_ip_watch_write_values(2) = 0, 'S11 then no item is due';
  ASSERT api.fn_ip_watch_write_values(NULL) IS NULL, 'S11 the writer is STRICT, so a NULL bound evaluates nothing';
  PERFORM pg_temp.t_ipw_reset();
END
$$;

DO $$
DECLARE
  a_id     bigint := pg_temp.t_ipw_add('192.0.2.20');
  b_id     bigint := pg_temp.t_ipw_add('192.0.2.20', repeat('e2', 32));
  decoy_id bigint := pg_temp.t_ipw_add('192.0.2.21');
BEGIN
  ASSERT pg_temp.t_ipw_run() = 3, 'S12 the writer evaluates the three items';
  ASSERT (SELECT count(*) FROM ip_change_event) = 2, 'S12 two addresses write two event rows';
  ASSERT (SELECT count(DISTINCT wer.event_id) FROM watchlist_event_ref AS wer WHERE wer.item_id IN (a_id, b_id)) = 1,
         'S12 the two items of one address share one event row';
  ASSERT (SELECT array_agg(ak.key_hash || '|' || coalesce(wer.key_event_id::text, 'null') ORDER BY ak.key_hash)
            FROM watchlist_event_ref AS wer JOIN api_keys AS ak ON ak.id = wer.api_key_id WHERE wer.item_id IN (a_id, b_id))
         = ARRAY[repeat('e1', 32) || '|null', repeat('e2', 32) || '|null'],
         'S12 each item gets its own ref of its own key, waiting for a number';
  ASSERT pg_temp.t_ipw_events(decoy_id) = '{"drop_listed|null|192.0.2.0/26 SBL102"}'
     AND (SELECT wer.event_id FROM watchlist_event_ref AS wer WHERE wer.item_id = decoy_id)
         <> (SELECT wer.event_id FROM watchlist_event_ref AS wer WHERE wer.item_id = a_id),
         'S12 another address with the same values gets its own row';
  PERFORM pg_temp.t_ipw_reset();
END
$$;

DO $$
DECLARE
  writer_source text := regexp_replace((SELECT p.prosrc FROM pg_proc AS p WHERE p.oid = 'api.fn_ip_watch_write_values(integer)'::regprocedure),
                                       '--[^\n]*', '', 'g');
  after_lock    text;
BEGIN
  after_lock := substring(writer_source FROM 'PERFORM public\.fn_watchlist_event_take_order_lock\(\);(.*)$');
  ASSERT after_lock IS NOT NULL, 'S13 the writer takes the order lock';
  ASSERT (SELECT count(*) FROM regexp_matches(writer_source, 'fn_watchlist_event_take_order_lock', 'g')) = 1, 'S13 one call takes the lock';
  ASSERT after_lock ~ '^\s+WITH transition AS \(', 'S13 the statement right after the lock writes the events';
  ASSERT (SELECT count(*) FROM regexp_matches(writer_source, 'INSERT INTO public\.ip_change_event', 'g')) = 1
     AND after_lock ~ 'INSERT INTO public\.ip_change_event AS ice .*INSERT INTO public\.watchlist_event_ref',
         'S13 one statement after the lock writes the events, then the refs';
  ASSERT after_lock !~ '(public\.watchlist_item_ip|public\.watchlist_item |public\.ip_drop_list_prefix|public\.upstream_feed_sync|public\.ip_cloud_range|public\.ip_asn_prefix|api\.fn_ip_hosting_classes)',
         'S13 no item, value row or IP list is read or written after the lock';
  ASSERT writer_source !~ 'nextval', 'S13 the writer takes no number of the event sequence itself';
  ASSERT writer_source ~ 'FOR NO KEY UPDATE OF wii, wi SKIP LOCKED', 'S13 the writer locks each item and its child row, and skips a held one';
END
$$;

DO $$
DECLARE
  ip_item_id   bigint  := pg_temp.t_ipw_add('192.0.2.30');
  key_id       integer := (SELECT ak.id FROM api_keys AS ak WHERE ak.key_hash = repeat('e1', 32));
  old_ids      bigint[];
  recent_id    bigint;
  purged_count integer;
BEGIN
  INSERT INTO watchlist_key_state (api_key_id, last_cve_event_id) VALUES (key_id, 0) ON CONFLICT DO NOTHING;
  WITH ins AS (
    INSERT INTO ip_change_event (ip_address, event_type, changed_at, previous_value, current_value)
    SELECT '192.0.2.30', 'hosting_changed', now() - interval '91 days', 'AS1', 'AS' || n FROM generate_series(2, 4) AS n
    RETURNING event_id)
  SELECT array_agg(ins.event_id ORDER BY ins.event_id) INTO old_ids FROM ins;
  INSERT INTO ip_change_event (ip_address, event_type, changed_at, previous_value, current_value)
  VALUES ('192.0.2.30', 'hosting_changed', now() - interval '89 days', 'AS4', 'AS5') RETURNING event_id INTO recent_id;
  INSERT INTO watchlist_event_ref (api_key_id, item_id, event_id, key_event_id)
  VALUES (key_id, ip_item_id, old_ids[1], 9001), (key_id, ip_item_id, old_ids[2], NULL), (key_id, ip_item_id, old_ids[3], 9003), (key_id, ip_item_id, recent_id, NULL);
  UPDATE watchlist_key_state SET max_purged_key_event_id = 0, last_key_event_id = 9010 WHERE api_key_id = key_id;
  purged_count := api.fn_ip_change_event_purge(2);
  ASSERT purged_count = 2, 'S14 the purge deletes at most p_event_row_count events';
  ASSERT (SELECT array_agg(ice.event_id ORDER BY ice.event_id) FROM ip_change_event AS ice) = ARRAY[old_ids[3], recent_id],
         'S14 the smallest event_ids go first';
  ASSERT (SELECT ps.max_purged_event_id FROM change_event_purge_state AS ps WHERE ps.event_table_name = 'ip_change_event') = old_ids[2], 'S14 max_purged_event_id rises to the largest deleted id';
  ASSERT (SELECT wks.max_purged_key_event_id FROM watchlist_key_state AS wks WHERE wks.api_key_id = key_id) = 9001,
         'S14 the key that lost a numbered ref has its max_purged_key_event_id raised';
  ASSERT api.fn_ip_change_event_purge(100) = 1, 'S14 the next purge deletes the last old event';
  ASSERT (SELECT array_agg(wer.event_id) FROM watchlist_event_ref AS wer WHERE wer.item_id = ip_item_id) = ARRAY[recent_id],
         'S14 the refs of the purged events are gone, the ref of the recent event stays';
  ASSERT (SELECT wks.max_purged_key_event_id FROM watchlist_key_state AS wks WHERE wks.api_key_id = key_id) = 9003,
         'S14 max_purged_key_event_id rises to the largest number the key lost';
  ASSERT api.fn_ip_change_event_max_id() = recent_id, 'S14 the head is the recent event';
  DELETE FROM ip_change_event WHERE event_id = recent_id;
  ASSERT api.fn_ip_change_event_max_id() = old_ids[3], 'S14 with no event left, the head is max_purged_event_id';
  UPDATE change_event_purge_state SET max_purged_event_id = recent_id + 100 WHERE event_table_name = 'ip_change_event';
  ASSERT api.fn_watchlist_event_max_id() >= recent_id + 100, 'S14 the watch list head counts the IP purge state';
  ASSERT api.fn_ip_change_event_purge(NULL) IS NULL, 'S14 the purge is STRICT';
  UPDATE change_event_purge_state SET max_purged_event_id = 0 WHERE event_table_name = 'ip_change_event';
  PERFORM pg_temp.t_ipw_reset();
END
$$;

DO $$
DECLARE
  ip_item_id bigint := pg_temp.t_ipw_add('2001:db8:1111:2222:3333:4444:5555:6666');
BEGIN
  INSERT INTO ip_drop_list_prefix (prefix, listing_id, regional_registry, list_time, copyright)
  SELECT set_masklen('2001:db8:1111:2222:3333:4444:5555:6666'::cidr, n), 'SBL' || (1000000000 + n), 'ripencc', '2026-11-02T00:00:00Z',
         '(c) 2026 v6 file'
    FROM generate_series(1, 128) AS n;
  ASSERT (SELECT octet_length(string_agg(idlp.prefix::text || ' ' || idlp.listing_id, E'\n'))
            FROM ip_drop_list_prefix AS idlp WHERE idlp.prefix >>= '2001:db8:1111:2222:3333:4444:5555:6666'::inet) > 4096,
         'S15 the listings of the address pass 4096 bytes';
  PERFORM pg_temp.t_ipw_run();
  ASSERT pg_temp.t_ipw_value(ip_item_id, 'drop_listing') IS NULL AND pg_temp.t_ipw_events(ip_item_id) = '{}',
         'S15 a drop value past 4096 bytes is not written and writes no event';
  ASSERT pg_temp.t_ipw_value(ip_item_id, 'hosting') = 'AS64501|null', 'S15 the hosting value still comes';
  DELETE FROM ip_drop_list_prefix WHERE listing_id ~ '^SBL1[0-9]{9}$';
  PERFORM pg_temp.t_ipw_reset();
END
$$;

CREATE FUNCTION pg_temp.t_ipw_fill_drop(p_address inet, p_byte_count integer, p_copyright text) RETURNS void LANGUAGE plpgsql AS $$
DECLARE
  prefix_length integer := 1;
  value_length  integer := 0;
  line_length   integer;
  missing       integer;
  extra         integer;
  row_prefix    cidr;
BEGIN
  WHILE prefix_length <= CASE family(p_address) WHEN 4 THEN 32 ELSE 128 END LOOP
    line_length := octet_length(set_masklen(p_address::cidr, prefix_length)::text || ' SBL1') + CASE WHEN value_length = 0 THEN 0 ELSE 1 END;
    EXIT WHEN value_length + line_length > p_byte_count;
    INSERT INTO ip_drop_list_prefix (prefix, listing_id, regional_registry, list_time, copyright)
    VALUES (set_masklen(p_address::cidr, prefix_length), 'SBL1', 'ripencc', '2026-11-02T00:00:00Z', p_copyright);
    value_length  := value_length + line_length;
    prefix_length := prefix_length + 1;
  END LOOP;
  missing := p_byte_count - value_length;
  FOR row_prefix IN SELECT idlp.prefix FROM ip_drop_list_prefix AS idlp WHERE idlp.copyright = p_copyright AND idlp.prefix >>= p_address ORDER BY idlp.prefix LOOP
    EXIT WHEN missing = 0;
    extra := least(9, missing);
    UPDATE ip_drop_list_prefix SET listing_id = 'SBL1' || repeat('0', extra) WHERE prefix = row_prefix;
    missing := missing - extra;
  END LOOP;
  ASSERT missing = 0, 't_ipw_fill_drop reaches ' || p_byte_count || ' bytes';
END
$$;

DO $$
DECLARE
  host_id    bigint := pg_temp.t_ipw_add('203.0.113.7');
  decoy_id   bigint := pg_temp.t_ipw_add('203.0.113.8');
  at_id      bigint := pg_temp.t_ipw_add('2001:db8:1111:2222:3333:4444:5555:6666');
  over_id    bigint := pg_temp.t_ipw_add('a001:db8:1111:2222:3333:4444:5555:6666');
BEGIN
  INSERT INTO ip_drop_list_prefix (prefix, listing_id, regional_registry, list_time, copyright)
  VALUES ('203.0.113.0/24', 'SBL301', 'ripencc', '2026-11-05T00:00:00Z', '(c) 2026 b file'),
         ('203.0.113.0/25', 'SBL300', 'ripencc', '2026-11-05T00:00:00Z', '(c) 2026 a file'),
         ('203.0.113.7/32', 'SBL302', 'ripencc', '2026-11-05T00:00:00Z', '(c) 2026 c file');
  PERFORM pg_temp.t_ipw_fill_drop('2001:db8:1111:2222:3333:4444:5555:6666', 4096, '(c) 2026 bound file');
  PERFORM pg_temp.t_ipw_fill_drop('a001:db8:1111:2222:3333:4444:5555:6666', 4097, '(c) 2026 bound file');
  ASSERT (SELECT array_agg(octet_length(string_agg) ORDER BY address)
            FROM (SELECT a.address, string_agg(idlp.prefix::text || ' ' || idlp.listing_id, E'\n')
                    FROM unnest(ARRAY['2001:db8:1111:2222:3333:4444:5555:6666'::inet, 'a001:db8:1111:2222:3333:4444:5555:6666'::inet]) AS a (address)
                    JOIN ip_drop_list_prefix AS idlp ON idlp.prefix >>= a.address
                   GROUP BY a.address) AS v) = ARRAY[4096, 4097],
         'S17 the listings of the two addresses are 4096 and 4097 bytes';
  PERFORM pg_temp.t_ipw_run();
  ASSERT pg_temp.t_ipw_value(host_id, 'drop_listing') = E'203.0.113.0/24 SBL301\n203.0.113.0/25 SBL300\n203.0.113.7/32 SBL302|null',
         'S17 the value holds its lines in prefix order, with the /32 equal to the address';
  ASSERT pg_temp.t_ipw_value(decoy_id, 'drop_listing') = E'203.0.113.0/24 SBL301\n203.0.113.0/25 SBL300|null',
         'S17 the /32 of another address does not hold the decoy';
  ASSERT (SELECT ice.drop_list_time = '2026-11-05T00:00:00Z' AND ice.drop_copyright = '(c) 2026 a file'
            FROM ip_change_event AS ice JOIN watchlist_event_ref AS wer ON wer.event_id = ice.event_id WHERE wer.item_id = host_id),
         'S17 of three rows with the newest list_time, the event takes the copyright that sorts first';
  ASSERT (SELECT wer.event_id FROM watchlist_event_ref AS wer WHERE wer.item_id = host_id)
         < (SELECT wer.event_id FROM watchlist_event_ref AS wer WHERE wer.item_id = decoy_id),
         'S17 the event of the first item comes first';
  ASSERT (SELECT octet_length(wiiv.current_value) FROM watchlist_item_ip_value AS wiiv WHERE wiiv.item_id = at_id AND wiiv.value_kind = 'drop_listing') = 4096
     AND cardinality(pg_temp.t_ipw_events(at_id)) = 1,
         'S17 a value of exactly 4096 bytes is written and writes drop_listed';
  ASSERT pg_temp.t_ipw_value(over_id, 'drop_listing') IS NULL AND pg_temp.t_ipw_events(over_id) = '{}',
         'S17 a value of 4097 bytes is not written and writes no event';
  DELETE FROM ip_drop_list_prefix WHERE copyright = '(c) 2026 bound file' OR prefix <<= '203.0.113.0/24';
  PERFORM pg_temp.t_ipw_reset();
END
$$;

DO $$
DECLARE
  at_sync_id     bigint := pg_temp.t_ipw_add('192.0.2.40');
  before_sync_id bigint := pg_temp.t_ipw_add('192.0.2.41');
  older_id       bigint := pg_temp.t_ipw_add('192.0.2.42');
  oldest_id      bigint := pg_temp.t_ipw_add('192.0.2.43');
  tie_low_id     bigint := pg_temp.t_ipw_add('192.0.2.44');
  tie_high_id    bigint := pg_temp.t_ipw_add('192.0.2.45');
  synced_at      timestamptz := (SELECT max(ufs.last_synced) FROM upstream_feed_sync AS ufs WHERE ufs.feed_name IN ('drop_list', 'iptoasn', 'cloud_ranges'));
BEGIN
  ASSERT synced_at = now() - interval '1 hour', 'S18 the feeds synced one hour ago';
  UPDATE watchlist_item_ip SET checked_at = now() WHERE item_id IN (older_id, oldest_id, tie_low_id, tie_high_id);
  UPDATE watchlist_item_ip SET checked_at = synced_at WHERE item_id = at_sync_id;
  UPDATE watchlist_item_ip SET checked_at = synced_at - interval '1 microsecond' WHERE item_id = before_sync_id;
  ASSERT api.fn_ip_watch_write_values(100) = 1, 'S18 one item is due';
  ASSERT (SELECT wii.checked_at FROM watchlist_item_ip AS wii WHERE wii.item_id = before_sync_id) = now()
     AND (SELECT wii.checked_at FROM watchlist_item_ip AS wii WHERE wii.item_id = at_sync_id) = synced_at,
         'S18 an item checked at the newest sync is not due, and one checked just before it is';
  UPDATE watchlist_item_ip SET checked_at = now() WHERE item_id = at_sync_id;
  UPDATE watchlist_item_ip SET checked_at = now() - interval '4 hours' WHERE item_id = older_id;
  UPDATE watchlist_item_ip SET checked_at = now() - interval '5 hours' WHERE item_id = oldest_id;
  ASSERT api.fn_ip_watch_write_values(1) = 1, 'S18 a batch of one takes one item';
  ASSERT (SELECT wii.checked_at FROM watchlist_item_ip AS wii WHERE wii.item_id = oldest_id) = now()
     AND (SELECT wii.checked_at FROM watchlist_item_ip AS wii WHERE wii.item_id = older_id) = now() - interval '4 hours',
         'S18 the oldest check goes first';
  ASSERT api.fn_ip_watch_write_values(1) = 1, 'S18 the next batch of one takes one item';
  ASSERT (SELECT wii.checked_at FROM watchlist_item_ip AS wii WHERE wii.item_id = older_id) = now(), 'S18 the next oldest check goes next';
  UPDATE watchlist_item_ip SET checked_at = now() - interval '3 hours' WHERE item_id IN (tie_low_id, tie_high_id);
  ASSERT api.fn_ip_watch_write_values(1) = 1, 'S18 a batch of one takes one of the tie';
  ASSERT (SELECT wii.checked_at FROM watchlist_item_ip AS wii WHERE wii.item_id = tie_low_id) = now()
     AND (SELECT wii.checked_at FROM watchlist_item_ip AS wii WHERE wii.item_id = tie_high_id) = now() - interval '3 hours',
         'S18 of two equal checks, the smaller item_id goes first';
  PERFORM pg_temp.t_ipw_reset();
END
$$;

DO $$
DECLARE
  ip_item_id bigint  := pg_temp.t_ipw_add('192.0.2.46');
  key_id     integer := (SELECT ak.id FROM api_keys AS ak WHERE ak.key_hash = repeat('e1', 32));
  old_id     bigint;
  young_id   bigint;
BEGIN
  INSERT INTO watchlist_key_state (api_key_id, last_cve_event_id) VALUES (key_id, 0) ON CONFLICT DO NOTHING;
  INSERT INTO ip_change_event (ip_address, event_type, changed_at, previous_value, current_value)
  VALUES ('192.0.2.46', 'hosting_changed', now() - interval '90 days' - interval '1 hour', 'AS1', 'AS2') RETURNING event_id INTO old_id;
  INSERT INTO ip_change_event (ip_address, event_type, changed_at, previous_value, current_value)
  VALUES ('192.0.2.46', 'hosting_changed', now() - interval '90 days' + interval '1 hour', 'AS2', 'AS3') RETURNING event_id INTO young_id;
  INSERT INTO watchlist_event_ref (api_key_id, item_id, event_id, key_event_id)
  VALUES (key_id, ip_item_id, old_id, 9003), (key_id, ip_item_id, young_id, 9004);
  UPDATE watchlist_key_state SET max_purged_key_event_id = 9500, last_key_event_id = 9600 WHERE api_key_id = key_id;
  UPDATE change_event_purge_state SET max_purged_event_id = young_id + 1000 WHERE event_table_name = 'ip_change_event';
  ASSERT api.fn_ip_change_event_purge(100) = 1, 'S19 the purge deletes one event';
  ASSERT (SELECT array_agg(ice.event_id) FROM ip_change_event AS ice) = ARRAY[young_id], 'S19 the event short of 90 days stays';
  ASSERT (SELECT wks.max_purged_key_event_id FROM watchlist_key_state AS wks WHERE wks.api_key_id = key_id) = 9500,
         'S19 a key purge mark above the lost number stays';
  ASSERT (SELECT ps.max_purged_event_id FROM change_event_purge_state AS ps WHERE ps.event_table_name = 'ip_change_event') = young_id + 1000,
         'S19 an event purge mark above the deleted event_id stays';
  UPDATE change_event_purge_state SET max_purged_event_id = 0 WHERE event_table_name = 'ip_change_event';
  UPDATE watchlist_key_state SET max_purged_key_event_id = 0 WHERE api_key_id = key_id;
  PERFORM pg_temp.t_ipw_reset();
END
$$;

DO $$
DECLARE
  ip_item_id bigint  := pg_temp.t_ipw_add('192.0.2.47');
  key_id     integer := (SELECT ak.id FROM api_keys AS ak WHERE ak.key_hash = repeat('e1', 32));
  old_ids    bigint[];
BEGIN
  INSERT INTO watchlist_key_state (api_key_id, last_cve_event_id) VALUES (key_id, 0) ON CONFLICT DO NOTHING;
  WITH ins AS (
    INSERT INTO ip_change_event (ip_address, event_type, changed_at, previous_value, current_value)
    SELECT '192.0.2.47', 'hosting_changed', now() - interval '91 days', 'AS1', 'AS' || n FROM generate_series(2, 3) AS n
    RETURNING event_id)
  SELECT array_agg(ins.event_id ORDER BY ins.event_id) INTO old_ids FROM ins;
  INSERT INTO watchlist_event_ref (api_key_id, item_id, event_id, key_event_id)
  VALUES (key_id, ip_item_id, old_ids[1], 9101), (key_id, ip_item_id, old_ids[2], 9102);
  UPDATE watchlist_key_state SET max_purged_key_event_id = 0, last_key_event_id = 9110 WHERE api_key_id = key_id;
  ASSERT api.fn_ip_change_event_purge(100) = 2, 'S20 the purge deletes both old events';
  ASSERT (SELECT wks.max_purged_key_event_id FROM watchlist_key_state AS wks WHERE wks.api_key_id = key_id) = 9102,
         'S20 a key that lost two numbered refs in one purge gets the larger number';
  UPDATE watchlist_key_state SET max_purged_key_event_id = 0 WHERE api_key_id = key_id;
  UPDATE change_event_purge_state SET max_purged_event_id = 0 WHERE event_table_name = 'ip_change_event';
  PERFORM pg_temp.t_ipw_reset();
END
$$;

DO $$
DECLARE
  ip_item_id bigint  := pg_temp.t_ipw_add('2001:db8::7');
  key_id     integer := (SELECT ak.id FROM api_keys AS ak WHERE ak.key_hash = repeat('e1', 32));
  ev_id      bigint;
BEGIN
  INSERT INTO ip_change_event (ip_address, event_type, previous_value, current_value)
  VALUES ('2001:db8::7', 'hosting_changed', 'AS1', 'AS2') RETURNING event_id INTO ev_id;
  INSERT INTO watchlist_event_ref (api_key_id, item_id, event_id) VALUES (key_id, ip_item_id, ev_id);
  ASSERT (SELECT array_agg(DISTINCT x.item_ip_address) FROM api.fn_watchlist_events(repeat('e1', 32), NULL, false, 100, 100, 600) AS x
           WHERE x.item_endpoint_name = 'ip_lookup') = ARRAY['2001:db8::7'],
         'S21 the event row names the item address in host() text';
  PERFORM pg_temp.t_ipw_reset();
END
$$;

DO $$
DECLARE
  ev_id bigint;
BEGIN
  INSERT INTO ip_change_event (ip_address, event_type, changed_at, previous_value, current_value)
  VALUES ('192.0.2.49', 'hosting_changed', now() - interval '90 days', 'AS1', 'AS2') RETURNING event_id INTO ev_id;
  ASSERT api.fn_ip_change_event_purge(100) = 0, 'S22 an event exactly 90 days old stays';
  PERFORM pg_temp.t_ipw_reset();
END
$$;

DO $$
DECLARE
  ip_item_id bigint      := pg_temp.t_ipw_add('192.0.2.48');
  ahead_at   timestamptz := now() + interval '1 hour';
BEGIN
  UPDATE upstream_feed_sync SET last_synced = ahead_at WHERE feed_name = 'iptoasn';
  ASSERT api.fn_ip_watch_write_values(100) = 1, 'S23 the new item is due';
  ASSERT (SELECT wii.checked_at FROM watchlist_item_ip AS wii WHERE wii.item_id = ip_item_id) = ahead_at,
         'S23 the check is the sync time ahead of now()';
  ASSERT api.fn_ip_watch_write_values(100) = 0, 'S23 the next call finds the item not due';
  UPDATE upstream_feed_sync SET last_synced = now() - interval '1 hour' WHERE feed_name = 'iptoasn';
  PERFORM pg_temp.t_ipw_reset();
END
$$;

CREATE FUNCTION pg_temp.t_ipw_hosting_case(p_iptoasn_at timestamptz, p_iptoasn_status text,
                                           p_aws_at timestamptz, p_google_at timestamptz) RETURNS void LANGUAGE sql AS $$
  UPDATE upstream_feed_sync SET last_synced = p_iptoasn_at, last_status = p_iptoasn_status WHERE feed_name = 'iptoasn';
  UPDATE ip_cloud_range SET synced_at = CASE provider WHEN 'aws' THEN p_aws_at ELSE p_google_at END;
  UPDATE watchlist_item_ip_value SET candidate_seen_at = now() - interval '2 hours' WHERE candidate_value IS NOT NULL;
  SELECT pg_temp.t_ipw_run();
$$;

DO $$
DECLARE
  as_id    bigint;
  cloud_id bigint;
  seen_at  timestamptz := now() - interval '2 hours';
  older_at timestamptz := now() - interval '3 hours';
  newer_at timestamptz := now() - interval '1 hour';
  c        record;
BEGIN
  PERFORM pg_temp.t_ipw_reset();
  as_id    := pg_temp.t_ipw_add('192.0.2.201');
  cloud_id := pg_temp.t_ipw_add('198.51.100.6');
  INSERT INTO ip_cloud_range (provider, service, prefix, is_cdn, synced_at) VALUES ('google', 'gce', '203.0.113.0/26', false, now());
  PERFORM pg_temp.t_ipw_run();
  UPDATE ip_asn_prefix SET asn = 64502 WHERE prefix = '192.0.2.0/24';
  UPDATE ip_cloud_range SET service = 'lambda' WHERE provider = 'aws';
  PERFORM pg_temp.t_ipw_run();
  ASSERT pg_temp.t_ipw_value(as_id, 'hosting') = 'AS64500|AS64502' AND pg_temp.t_ipw_value(cloud_id, 'hosting') = 'aws/ec2|aws/lambda',
         'S24 each item holds a candidate';
  FOR c IN SELECT * FROM (VALUES
      ('a newer DROP list alone',                  older_at, 'ok',    older_at, older_at),
      ('a newer IPtoASN list alone',               newer_at, 'ok',    older_at, older_at),
      ('newer cloud ranges alone',                 older_at, 'ok',    newer_at, newer_at),
      ('one newer cloud provider of two',          newer_at, 'ok',    newer_at, older_at),
      ('a failed IPtoASN sync',                    newer_at, 'error', newer_at, newer_at),
      ('an IPtoASN sync at the candidate moment',  seen_at,  'ok',    newer_at, newer_at),
      ('cloud ranges synced at that moment',       newer_at, 'ok',    seen_at,  seen_at)) AS t (label, iptoasn_at, iptoasn_status, aws_at, google_at) LOOP
    PERFORM pg_temp.t_ipw_hosting_case(c.iptoasn_at, c.iptoasn_status, c.aws_at, c.google_at);
    ASSERT pg_temp.t_ipw_value(as_id, 'hosting') = 'AS64500|AS64502' AND pg_temp.t_ipw_value(cloud_id, 'hosting') = 'aws/ec2|aws/lambda'
       AND pg_temp.t_ipw_events(as_id) = '{}' AND pg_temp.t_ipw_events(cloud_id) = '{}',
           'S24 ' || c.label || ' keeps both candidates and writes no event';
    ASSERT (SELECT array_agg(wiiv.candidate_seen_at) FROM watchlist_item_ip_value AS wiiv WHERE wiiv.value_kind = 'hosting')
           = ARRAY[seen_at, seen_at],
           'S24 ' || c.label || ' keeps the candidate_seen_at of both candidates';
  END LOOP;
  PERFORM pg_temp.t_ipw_hosting_case(newer_at, 'ok', newer_at, newer_at);
  ASSERT pg_temp.t_ipw_value(as_id, 'hosting') = 'AS64502|null' AND pg_temp.t_ipw_events(as_id) = '{"hosting_changed|AS64500|AS64502"}',
         'S24 a newer sync of both lists makes the AS candidate the current value';
  ASSERT pg_temp.t_ipw_value(cloud_id, 'hosting') = 'aws/lambda|null' AND pg_temp.t_ipw_events(cloud_id) = '{"hosting_changed|aws/ec2|aws/lambda"}',
         'S24 a newer sync of both lists makes the cloud candidate the current value';
  DELETE FROM ip_cloud_range WHERE provider = 'google';
  UPDATE ip_cloud_range SET service = 'ec2', synced_at = now() WHERE provider = 'aws';
  UPDATE ip_asn_prefix SET asn = 64500 WHERE prefix = '192.0.2.0/24';
  UPDATE upstream_feed_sync SET last_synced = now() - interval '1 hour', last_status = 'ok' WHERE feed_name = 'iptoasn';
  PERFORM pg_temp.t_ipw_reset();
END
$$;

DO $$
DECLARE
  f record;
BEGIN
  FOR f IN SELECT * FROM (VALUES
      ('api.fn_ip_watch_write_values(integer)'::regprocedure, 'v'::"char", true, true),
      ('api.fn_ip_change_event_purge(integer)'::regprocedure, 'v'::"char", true, true),
      ('api.fn_ip_change_event_max_id()'::regprocedure,       's'::"char", false, false)) AS t (oid, volatility, is_strict, is_definer) LOOP
    ASSERT (SELECT p.prosecdef FROM pg_proc AS p WHERE p.oid = f.oid) = f.is_definer,
           f.oid::text || CASE WHEN f.is_definer THEN ' is SECURITY DEFINER' ELSE ' is SECURITY INVOKER' END;
    ASSERT (SELECT p.proconfig FROM pg_proc AS p WHERE p.oid = f.oid) = ARRAY['search_path=pg_catalog'], f.oid::text || ' sets search_path to pg_catalog';
    ASSERT (SELECT p.provolatile FROM pg_proc AS p WHERE p.oid = f.oid) = f.volatility, f.oid::text || ' has its volatility';
    ASSERT (SELECT p.proisstrict FROM pg_proc AS p WHERE p.oid = f.oid) = f.is_strict, f.oid::text || ' is STRICT only when it takes a row count';
  END LOOP;
  ASSERT (SELECT count(*) FROM pg_proc AS p WHERE p.pronamespace = 'api'::regnamespace AND (p.proname LIKE 'fn\_ip\_watch\_%' OR p.proname LIKE 'fn\_ip\_change\_event\_%')) = 3,
         'sql/fn_ip_watch.sql holds three functions';
END
$$;

ROLLBACK TO SAVEPOINT t_ip_watch;
RELEASE SAVEPOINT t_ip_watch;
