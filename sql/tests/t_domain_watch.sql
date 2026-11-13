TRUNCATE cve_change_event RESTART IDENTITY;
UPDATE change_event_purge_state SET max_purged_event_id = 0 WHERE event_table_name = 'cve_change_event';
TRUNCATE domain_change_event, package_advisory_change_event, watchlist_event_ref, domain_watch_dns_bucket;
DELETE FROM watchlist_item WHERE endpoint_name IN ('dns_lookup', 'ssl_check', 'whois_lookup', 'headers_check', 'cert_search');
DELETE FROM domain_watch;
UPDATE change_event_purge_state SET max_purged_event_id = 0, max_unwatched_event_id = 0 WHERE event_table_name = 'domain_change_event';
UPDATE change_event_purge_state SET max_purged_event_id = 0 WHERE event_table_name = 'package_advisory_change_event';
DO $$
BEGIN
  ASSERT (SELECT pi.indexdef FROM pg_indexes AS pi WHERE pi.indexname = 'idx_watchlist_item_domain_next_scan_at')
         = 'CREATE INDEX idx_watchlist_item_domain_next_scan_at ON public.watchlist_item_domain USING btree (endpoint_name, next_scan_at)',
         'the claims find the due items of a lane through an index on endpoint_name and next_scan_at';
  ASSERT (SELECT pi.indexdef FROM pg_indexes AS pi WHERE pi.indexname = 'idx_watchlist_event_ref_event_id')
         = 'CREATE INDEX idx_watchlist_event_ref_event_id ON public.watchlist_event_ref USING btree (event_id)',
         'the event purge finds the refs of an event through an index on event_id';
  ASSERT api.fn_domain_change_event_max_id() = 0, 'the largest domain event_id is 0 with no event and no purge';
END
$$;

INSERT INTO api_keys (key_hash) VALUES (repeat('9c', 32)), (repeat('a1', 32)), (repeat('b1', 32));

SELECT set_config('contrastapi.cve_events', 'off', true);
INSERT INTO cves (cve_id) VALUES ('CVE-2011-0091');
SELECT set_config('contrastapi.cve_events', '', true);

CREATE FUNCTION pg_temp.t_sha256(p_value text) RETURNS text LANGUAGE sql AS $$
  SELECT encode(sha256(convert_to(p_value, 'UTF8')), 'hex')
$$;

CREATE FUNCTION pg_temp.t_item(p_domain_name text, p_key_hash text DEFAULT repeat('9c', 32), p_endpoint_name text DEFAULT 'dns_lookup',
                               p_next_scan_at timestamptz DEFAULT now(), p_registered_domain text DEFAULT NULL)
  RETURNS bigint LANGUAGE sql AS $$
  INSERT INTO domain_watch (domain_name, registered_domain) VALUES (p_domain_name, coalesce(p_registered_domain, p_domain_name))
  ON CONFLICT DO NOTHING;
  INSERT INTO domain_watch_lane (domain_name, lane_name)
  VALUES (p_domain_name, CASE p_endpoint_name WHEN 'dns_lookup' THEN 'dns' WHEN 'ssl_check' THEN 'tls' WHEN 'whois_lookup' THEN 'rdap_whois'
                                              WHEN 'headers_check' THEN 'headers' WHEN 'cert_search' THEN 'ct' END)
  ON CONFLICT DO NOTHING;
  WITH parent AS (
    INSERT INTO watchlist_item (api_key_id, endpoint_name)
    SELECT ak.id, p_endpoint_name FROM api_keys AS ak WHERE ak.key_hash = p_key_hash
    RETURNING watchlist_item.item_id, watchlist_item.api_key_id, watchlist_item.endpoint_name)
  INSERT INTO watchlist_item_domain (item_id, api_key_id, endpoint_name, domain_name, registered_domain, next_scan_at)
  SELECT p.item_id, p.api_key_id, p.endpoint_name, p_domain_name, coalesce(p_registered_domain, p_domain_name), p_next_scan_at FROM parent AS p
  RETURNING watchlist_item_domain.item_id
$$;

CREATE FUNCTION pg_temp.t_add_dns(p_domain_name text, p_registered_domain text DEFAULT NULL) RETURNS bigint LANGUAGE sql AS $$
  SELECT pg_temp.t_item(p_domain_name, repeat('9c', 32), 'dns_lookup', now(), p_registered_domain)
$$;
CREATE FUNCTION pg_temp.t_add_tls(p_domain_name text) RETURNS bigint LANGUAGE sql AS $$
  SELECT pg_temp.t_item(p_domain_name, repeat('9c', 32), 'ssl_check', now())
$$;
CREATE FUNCTION pg_temp.t_add_rdap_whois(p_domain_name text) RETURNS bigint LANGUAGE sql AS $$
  SELECT pg_temp.t_item(p_domain_name, repeat('9c', 32), 'whois_lookup', now())
$$;
CREATE FUNCTION pg_temp.t_add_headers(p_domain_name text) RETURNS bigint LANGUAGE sql AS $$
  SELECT pg_temp.t_item(p_domain_name, repeat('9c', 32), 'headers_check', now())
$$;
CREATE FUNCTION pg_temp.t_add_ct(p_domain_name text, p_key_hash text DEFAULT repeat('9c', 32)) RETURNS bigint LANGUAGE sql AS $$
  SELECT pg_temp.t_item(p_domain_name, p_key_hash, 'cert_search', now())
$$;

CREATE FUNCTION pg_temp.t_reset() RETURNS void LANGUAGE sql AS $$
  DELETE FROM watchlist_item AS wi WHERE wi.endpoint_name IN ('dns_lookup', 'ssl_check', 'whois_lookup', 'headers_check', 'cert_search');
  DELETE FROM domain_watch;
  DELETE FROM domain_watch_dns_bucket;
$$;

CREATE FUNCTION pg_temp.t_record_dns(p_domain_name text, p_dns_presence text DEFAULT NULL, p_ns text DEFAULT NULL, p_mx text DEFAULT NULL,
                                     p_ip_address_reachability text DEFAULT NULL, p_cname_takeover text DEFAULT NULL,
                                     p_email_auth text DEFAULT NULL, p_email_check_ids text DEFAULT NULL,
                                     p_hosting_ip_addresses text DEFAULT NULL, p_question_count integer DEFAULT 40,
                                     p_claimed_at timestamptz DEFAULT now() + interval '2 days')
  RETURNS integer LANGUAGE plpgsql AS $$
BEGIN
  UPDATE domain_watch_lane AS dwl SET claimed_until = now() + interval '10 minutes', claimed_at = p_claimed_at WHERE dwl.domain_name = p_domain_name AND dwl.lane_name = 'dns';
  RETURN api.fn_domain_watch_record_dns(p_domain_name, now() + interval '10 minutes',
                                        p_dns_presence,            pg_temp.t_sha256(p_dns_presence),
                                        p_ns,                      pg_temp.t_sha256(p_ns),
                                        p_mx,                      pg_temp.t_sha256(p_mx),
                                        p_ip_address_reachability, pg_temp.t_sha256(p_ip_address_reachability),
                                        p_cname_takeover,          pg_temp.t_sha256(p_cname_takeover),
                                        p_email_auth,              pg_temp.t_sha256(p_email_auth),
                                        p_email_check_ids,         p_hosting_ip_addresses,
                                        p_question_count);
END
$$;

CREATE FUNCTION pg_temp.t_record_dns_kind(p_domain_name text, p_kind text, p_value text, p_email_check_ids text DEFAULT NULL)
  RETURNS integer LANGUAGE sql AS $$
  SELECT pg_temp.t_record_dns(p_domain_name,
                              p_dns_presence            => CASE WHEN p_kind = 'dns_presence'            THEN p_value END,
                              p_ns                      => CASE WHEN p_kind = 'ns'                      THEN p_value END,
                              p_mx                      => CASE WHEN p_kind = 'mx'                      THEN p_value END,
                              p_ip_address_reachability => CASE WHEN p_kind = 'ip_address_reachability' THEN p_value END,
                              p_cname_takeover          => CASE WHEN p_kind = 'cname_takeover'          THEN p_value END,
                              p_email_auth              => CASE WHEN p_kind = 'email_auth'              THEN p_value END,
                              p_hosting_ip_addresses    => CASE WHEN p_kind = 'hosting'                 THEN p_value END,
                              p_email_check_ids         => p_email_check_ids)
$$;

CREATE FUNCTION pg_temp.t_values(p_domain_name text, p_key_hash text DEFAULT repeat('9c', 32)) RETURNS text LANGUAGE sql AS $$
  SELECT coalesce(string_agg(replace(widv.value_kind || '=' || widv.current_value || coalesce('/' || widv.candidate_value, ''), E'\n', '+'), ' '
                             ORDER BY widv.value_kind), '')
    FROM watchlist_item_domain_value AS widv
    JOIN watchlist_item_domain AS wid ON wid.item_id = widv.item_id
    JOIN api_keys AS ak ON ak.id = wid.api_key_id
   WHERE wid.domain_name = p_domain_name AND ak.key_hash = p_key_hash
$$;

CREATE FUNCTION pg_temp.t_candidate(p_domain_name text, p_kind text, p_key_hash text DEFAULT repeat('9c', 32)) RETURNS text LANGUAGE sql AS $$
  SELECT widv.candidate_value || '|' || (now() - widv.candidate_seen_at)::text
    FROM watchlist_item_domain_value AS widv
    JOIN watchlist_item_domain AS wid ON wid.item_id = widv.item_id
    JOIN api_keys AS ak ON ak.id = wid.api_key_id
   WHERE wid.domain_name = p_domain_name AND widv.value_kind = p_kind AND ak.key_hash = p_key_hash
$$;

CREATE FUNCTION pg_temp.t_age(p_domain_name text, p_kind text, p_age interval) RETURNS void LANGUAGE sql AS $$
  UPDATE watchlist_item_domain_value AS widv SET candidate_seen_at = now() - p_age
   WHERE widv.value_kind = p_kind
     AND widv.candidate_seen_at IS NOT NULL
     AND widv.item_id IN (SELECT wid.item_id FROM watchlist_item_domain AS wid WHERE wid.domain_name = p_domain_name)
$$;

CREATE FUNCTION pg_temp.t_next_scan(p_domain_name text, p_key_hash text DEFAULT repeat('9c', 32), p_endpoint_name text DEFAULT 'dns_lookup')
  RETURNS timestamptz LANGUAGE sql AS $$
  SELECT wid.next_scan_at
    FROM watchlist_item_domain AS wid
    JOIN api_keys AS ak ON ak.id = wid.api_key_id
   WHERE wid.domain_name = p_domain_name AND wid.endpoint_name = p_endpoint_name AND ak.key_hash = p_key_hash
$$;

CREATE TEMP TABLE t_domain_mark (event_id bigint);
INSERT INTO t_domain_mark VALUES (0);
CREATE FUNCTION pg_temp.t_dw_mark() RETURNS void LANGUAGE sql AS $$
  INSERT INTO t_domain_mark SELECT coalesce(max(dce.event_id), 0) FROM domain_change_event AS dce
$$;
CREATE FUNCTION pg_temp.t_dw_events(p_domain_name text) RETURNS text[] LANGUAGE sql AS $$
  SELECT coalesce(array_agg(dce.event_type || coalesce(':' || dce.degraded_email_check_id, '') || ':'
                            || replace(coalesce(dce.previous_value, 'null') || '>' || coalesce(dce.current_value, 'null'), E'\n', '+')
                            ORDER BY dce.event_id), '{}')
    FROM domain_change_event AS dce
   WHERE dce.domain_name = p_domain_name AND dce.event_id > (SELECT max(m.event_id) FROM t_domain_mark AS m)
$$;

CREATE FUNCTION pg_temp.t_heard(p_key_hash text, p_domain_name text) RETURNS text[] LANGUAGE sql AS $$
  SELECT coalesce(array_agg(dce.event_type || coalesce(':' || dce.degraded_email_check_id, '') || ':'
                            || replace(coalesce(dce.previous_value, 'null') || '>' || coalesce(dce.current_value, 'null'), E'\n', '+')
                            ORDER BY dce.event_id), '{}')
    FROM watchlist_event_ref AS wer
    JOIN domain_change_event AS dce ON dce.event_id = wer.event_id
   WHERE wer.api_key_id = (SELECT ak.id FROM api_keys AS ak WHERE ak.key_hash = p_key_hash) AND dce.domain_name = p_domain_name
$$;

CREATE FUNCTION pg_temp.t_dns_change(p_domain_name text, p_kind text, p_value text, p_email_check_ids text DEFAULT NULL)
  RETURNS text LANGUAGE plpgsql AS $$
DECLARE
  written_event_count integer;
BEGIN
  PERFORM pg_temp.t_dw_mark();
  PERFORM pg_temp.t_record_dns_kind(p_domain_name, p_kind, p_value, p_email_check_ids);
  PERFORM pg_temp.t_age(p_domain_name, p_kind, interval '1 hour');
  written_event_count := pg_temp.t_record_dns_kind(p_domain_name, p_kind, p_value, p_email_check_ids);
  RETURN written_event_count || '|' || pg_temp.t_dw_events(p_domain_name)::text;
END
$$;

CREATE FUNCTION pg_temp.t_cve_event() RETURNS bigint LANGUAGE sql AS $$
  INSERT INTO cve_change_event (cve_id, event_type) VALUES ('CVE-2011-0091', 'kev_added') RETURNING event_id
$$;

CREATE FUNCTION pg_temp.t_snapshot(p_domain_name text) RETURNS text LANGUAGE sql AS $$
  SELECT (SELECT dw::text FROM domain_watch AS dw WHERE dw.domain_name = p_domain_name) || ' '
         || coalesce((SELECT dwl::text FROM domain_watch_lane AS dwl WHERE dwl.domain_name = p_domain_name AND dwl.lane_name = 'dns'), '')
         || ' '
         || coalesce((SELECT string_agg(wid::text, ' ' ORDER BY wid.item_id) FROM watchlist_item_domain AS wid WHERE wid.domain_name = p_domain_name), '')
         || ' ' || coalesce((SELECT string_agg(widv::text, ' ' ORDER BY widv.item_id, widv.value_kind)
                               FROM watchlist_item_domain_value AS widv JOIN watchlist_item_domain AS wid ON wid.item_id = widv.item_id
                              WHERE wid.domain_name = p_domain_name), '')
         || ' ' || (SELECT count(*) FROM domain_change_event AS dce WHERE dce.domain_name = p_domain_name)
         || ' ' || (SELECT count(*) FROM watchlist_event_ref AS wer JOIN domain_change_event AS dce ON dce.event_id = wer.event_id
                     WHERE dce.domain_name = p_domain_name)
$$;

CREATE FUNCTION pg_temp.t_claim(p_lane_name text, p_domain_row_count integer, p_lease_seconds integer DEFAULT 300)
  RETURNS text LANGUAGE sql AS $$
  SELECT coalesce(string_agg(x.domain_name, ',' ORDER BY x.ordinality), '')
    FROM api.fn_domain_watch_claim(p_lane_name, p_domain_row_count, p_lease_seconds) WITH ORDINALITY AS x
$$;

CREATE FUNCTION pg_temp.t_refused_by(p_statement text) RETURNS text LANGUAGE plpgsql AS $$
DECLARE
  refusing_constraint text;
BEGIN
  BEGIN
    EXECUTE p_statement;
    RAISE SQLSTATE 'TACPT';
  EXCEPTION WHEN SQLSTATE 'TACPT' THEN
    RETURN 'accepted';
  END;
EXCEPTION WHEN check_violation OR foreign_key_violation OR unique_violation OR not_null_violation THEN
  GET STACKED DIAGNOSTICS refusing_constraint = CONSTRAINT_NAME;
  RETURN coalesce(nullif(refusing_constraint, ''), SQLSTATE);
END
$$;

CREATE TEMP VIEW t_domain_watch_claim_call AS
  SELECT * FROM api.fn_domain_watch_claim('dns', 0, 0);
CREATE TEMP VIEW t_domain_watch_record_dns_call AS
  SELECT api.fn_domain_watch_record_dns(NULL::text, NULL::timestamptz, NULL::text, NULL::text, NULL::text, NULL::text, NULL::text,
                                        NULL::text, NULL::text, NULL::text, NULL::text, NULL::text, NULL::text, NULL::text, NULL::text,
                                        NULL::text, NULL::integer) AS written_event_count;
CREATE TEMP VIEW t_domain_watch_record_tls_call AS
  SELECT api.fn_domain_watch_record_tls(NULL::text, NULL::timestamptz, NULL::text, NULL::text, NULL::text, NULL::text,
                                        NULL::text, NULL::text, NULL::text, NULL::text) AS written_event_count;
CREATE TEMP VIEW t_domain_watch_record_rdap_whois_call AS
  SELECT api.fn_domain_watch_record_rdap_whois(NULL::text, NULL::timestamptz, NULL::text, NULL::text, NULL::text, NULL::text,
                                               NULL::text, NULL::text, NULL::text, NULL::text, NULL::integer) AS written_event_count;
CREATE TEMP VIEW t_domain_watch_record_headers_call AS
  SELECT api.fn_domain_watch_record_headers(NULL::text, NULL::timestamptz, NULL::text, NULL::text, NULL::integer) AS written_event_count;
CREATE TEMP VIEW t_domain_watch_record_ct_call AS
  SELECT api.fn_domain_watch_record_ct(NULL::text, NULL::timestamptz, NULL::text, NULL::text, NULL::integer) AS written_event_count;
CREATE TEMP VIEW t_domain_change_event_purge_call AS
  SELECT api.fn_domain_change_event_purge(0) AS purged_event_count;
CREATE TEMP VIEW t_domain_watch_purge_unwatched_call AS
  SELECT api.fn_domain_watch_purge_unwatched(0) AS purged_domain_count;

DO $$
BEGIN
  ASSERT (SELECT array_agg(attname::text || ' ' || format_type(atttypid, atttypmod) ORDER BY attnum)
            FROM pg_attribute WHERE attrelid = 't_domain_watch_claim_call'::regclass AND attnum > 0)
         = ARRAY['domain_name text', 'claimed_until timestamp with time zone'],
         'S1 the claim call answers its two columns, in order';
  ASSERT (SELECT array_agg(attname::text || ' ' || format_type(atttypid, atttypmod) ORDER BY attnum)
            FROM pg_attribute WHERE attrelid = 't_domain_watch_record_dns_call'::regclass AND attnum > 0)
         = ARRAY['written_event_count integer'],
         'S1 the DNS record call answers one integer column, written_event_count';
  ASSERT (SELECT p.proargnames FROM pg_proc AS p
           WHERE p.oid = 'api.fn_domain_watch_record_dns(text, timestamptz, text, text, text, text, text, text, text, text, text, text, text, text, text, text, integer)'::regprocedure)
         = ARRAY['p_domain_name', 'p_claimed_until', 'p_dns_presence_value', 'p_dns_presence_sha256', 'p_ns_value', 'p_ns_sha256', 'p_mx_value',
                 'p_mx_sha256', 'p_ip_address_reachability_value', 'p_ip_address_reachability_sha256', 'p_cname_takeover_value',
                 'p_cname_takeover_sha256', 'p_email_auth_value', 'p_email_auth_sha256', 'p_email_check_ids', 'p_hosting_ip_addresses',
                 'p_question_count'],
         'S1 the DNS record takes its seventeen parameters in this order, the check ids of the e-mail checks after the e-mail value';
  ASSERT (SELECT array_agg(attname::text || ' ' || format_type(atttypid, atttypmod) ORDER BY attnum)
            FROM pg_attribute WHERE attrelid = 't_domain_watch_record_tls_call'::regclass AND attnum > 0)
         = ARRAY['written_event_count integer'],
         'S1 the TLS record call answers one integer column, written_event_count';
  ASSERT (SELECT p.proargnames FROM pg_proc AS p
           WHERE p.oid = 'api.fn_domain_watch_record_tls(text, timestamptz, text, text, text, text, text, text, text, text)'::regprocedure)
         = ARRAY['p_domain_name', 'p_claimed_until', 'p_certificate_expiry_value', 'p_certificate_expiry_sha256', 'p_certificate_validity_value',
                 'p_certificate_validity_sha256', 'p_certificate_listing_value', 'p_certificate_listing_sha256', 'p_tls_protocol_value',
                 'p_tls_protocol_sha256'],
         'S1 the TLS record takes the domain, the lease, then each value with its SHA-256, as the DNS record does';
  ASSERT (SELECT array_agg(attname::text || ' ' || format_type(atttypid, atttypmod) ORDER BY attnum)
            FROM pg_attribute WHERE attrelid = 't_domain_watch_record_rdap_whois_call'::regclass AND attnum > 0)
         = ARRAY['written_event_count integer'],
         'S1 the RDAP/WHOIS record call answers one integer column, written_event_count';
  ASSERT (SELECT p.proargnames FROM pg_proc AS p
           WHERE p.oid = 'api.fn_domain_watch_record_rdap_whois(text, timestamptz, text, text, text, text, text, text, text, text, integer)'::regprocedure)
         = ARRAY['p_domain_name', 'p_claimed_until', 'p_registration_expiry_value', 'p_registration_expiry_sha256', 'p_registrar_value',
                 'p_registrar_sha256', 'p_transfer_lock_value', 'p_transfer_lock_sha256', 'p_dnssec_delegation_value',
                 'p_dnssec_delegation_sha256', 'p_retry_after_seconds'],
         'S1 the RDAP/WHOIS record takes the domain, the lease, then each value with its SHA-256, as the DNS record does';
  ASSERT (SELECT array_agg(attname::text || ' ' || format_type(atttypid, atttypmod) ORDER BY attnum)
            FROM pg_attribute WHERE attrelid = 't_domain_watch_record_headers_call'::regclass AND attnum > 0)
         = ARRAY['written_event_count integer'],
         'S1 the headers record call answers one integer column, written_event_count';
  ASSERT (SELECT p.proargnames FROM pg_proc AS p
           WHERE p.oid = 'api.fn_domain_watch_record_headers(text, timestamptz, text, text, integer)'::regprocedure)
         = ARRAY['p_domain_name', 'p_claimed_until', 'p_security_headers_value', 'p_security_headers_sha256', 'p_retry_after_seconds'],
         'S1 the headers record takes the domain, the lease, the value with its SHA-256, then the retry, as the RDAP/WHOIS record does';
  ASSERT (SELECT array_agg(attname::text || ' ' || format_type(atttypid, atttypmod) ORDER BY attnum)
            FROM pg_attribute WHERE attrelid = 't_domain_watch_record_ct_call'::regclass AND attnum > 0)
         = ARRAY['written_event_count integer'],
         'S1 the ct record call answers one integer column, written_event_count';
  ASSERT (SELECT p.proargnames FROM pg_proc AS p
           WHERE p.oid = 'api.fn_domain_watch_record_ct(text, timestamptz, text, text, integer)'::regprocedure)
         = ARRAY['p_domain_name', 'p_claimed_until', 'p_cert_issuers_value', 'p_cert_issuers_sha256', 'p_retry_after_seconds'],
         'S1 the ct record takes the domain, the lease, the value with its SHA-256, then the retry, as the headers record does';
  ASSERT (SELECT array_agg(attname::text || ' ' || format_type(atttypid, atttypmod) ORDER BY attnum)
            FROM pg_attribute WHERE attrelid = 't_domain_change_event_purge_call'::regclass AND attnum > 0)
         = ARRAY['purged_event_count integer'],
         'S1 the event purge call answers one integer column, purged_event_count';
  ASSERT (SELECT array_agg(attname::text || ' ' || format_type(atttypid, atttypmod) ORDER BY attnum)
            FROM pg_attribute WHERE attrelid = 't_domain_watch_purge_unwatched_call'::regclass AND attnum > 0)
         = ARRAY['purged_domain_count integer'],
         'S1 the unwatched purge call answers one integer column, purged_domain_count';
  ASSERT NOT EXISTS (SELECT 1 FROM pg_proc AS p WHERE p.pronamespace = 'api'::regnamespace
                        AND p.proname IN ('fn_domain_watch_last_event_id_after_scan')),
         'S1 no function answers a last_event_id_after_scan any more';
  ASSERT NOT EXISTS (SELECT 1 FROM pg_proc AS p WHERE p.pronamespace = 'api'::regnamespace AND p.proname = 'fn_domain_watch_claim_dns'),
         'S1 the dns lane has no claim of its own: api.fn_domain_watch_claim leases every lane';
END
$$;

DO $$
DECLARE
  first_cve_event_id  bigint;
  domain_event_id     bigint;
  second_cve_event_id bigint;
BEGIN
  ASSERT (SELECT pg_get_expr(ad.adbin, ad.adrelid)
            FROM pg_attrdef AS ad
            JOIN pg_attribute AS a ON a.attrelid = ad.adrelid AND a.attnum = ad.adnum
           WHERE ad.adrelid = 'domain_change_event'::regclass AND a.attname = 'event_id')
         = 'nextval(''watchlist_event_id_seq''::regclass)',
         'S2 the default of domain_change_event.event_id is the next value of watchlist_event_id_seq';
  ASSERT pg_get_serial_sequence('cve_change_event', 'event_id') = 'public.watchlist_event_id_seq',
         'S2 watchlist_event_id_seq is the identity sequence of cve_change_event.event_id';
  PERFORM pg_temp.t_add_dns('seq.example');
  first_cve_event_id := pg_temp.t_cve_event();
  INSERT INTO domain_change_event (domain_name, event_type) VALUES ('seq.example', 'ns_changed')
  RETURNING event_id INTO domain_event_id;
  second_cve_event_id := pg_temp.t_cve_event();
  ASSERT first_cve_event_id = 1 AND domain_event_id = 2 AND second_cve_event_id = 3,
         'S2 a CVE event, a domain event and a CVE event take 1, 2 and 3';
  ASSERT (SELECT dce.changed_at FROM domain_change_event AS dce WHERE dce.event_id = 2) = now(),
         'S2 changed_at is the start of the transaction';
  ASSERT (SELECT array_agg(a.attname::text ORDER BY a.attnum) FROM pg_attribute AS a
           WHERE a.attrelid = 'domain_change_event'::regclass AND a.attnum > 0 AND NOT a.attisdropped)
         = ARRAY['event_id', 'domain_name', 'event_type', 'degraded_email_check_id', 'changed_at', 'previous_value', 'current_value'],
         'S2 an event row holds no pairing number: it says nothing about any item';
END
$$;

SELECT pg_temp.t_add_dns('rec.example');
DO $$
BEGIN
  ASSERT pg_temp.t_record_dns('rec.example', p_dns_presence => 'found', p_ns => 'ns1', p_ip_address_reachability => 'public', p_cname_takeover => 'none',
                              p_email_auth => 'pp', p_email_check_ids => 'spf_all,dmarc_policy') = 0,
         'S3 a first scan with no problem answers 0 events';
  ASSERT pg_temp.t_values('rec.example') = 'cname_takeover=none dns_presence=found email_auth=pp ip_address_reachability=public ns=ns1',
         'S3 a first scan writes the current value of each kind that has a value and no candidate';
  ASSERT (SELECT bool_and(widv.current_value_sha256 = pg_temp.t_sha256(widv.current_value)) FROM watchlist_item_domain_value AS widv),
         'S3 each current value is stored with its own SHA-256';
  ASSERT (SELECT count(*) FROM domain_change_event AS dce WHERE dce.domain_name = 'rec.example') = 0, 'S3 a first scan with no problem writes no event';
  ASSERT (SELECT dwl.claimed_until IS NULL AND dwl.scanned_at = now() FROM domain_watch_lane AS dwl WHERE dwl.domain_name = 'rec.example' AND dwl.lane_name = 'dns'),
         'S3 the scan ends the claim and notes scanned_at';
  ASSERT pg_temp.t_next_scan('rec.example') = api.fn_domain_watch_next_daily_scan_at('rec.example'),
         'S3 a first scan brings the next scan of the item at the daily second of the name';
END
$$;

DO $$
BEGIN
  ASSERT pg_temp.t_record_dns('rec.example', p_dns_presence => 'found', p_ns => 'ns1', p_ip_address_reachability => 'public', p_cname_takeover => 'none',
                              p_email_auth => 'pp') = 0,
         'S4 the same values answer 0 events';
  ASSERT pg_temp.t_values('rec.example') = 'cname_takeover=none dns_presence=found email_auth=pp ip_address_reachability=public ns=ns1',
         'S4 the same values write no candidate';
END
$$;

DO $$
BEGIN
  ASSERT pg_temp.t_record_dns('rec.example', p_ns => 'ns2') = 0, 'S5 a new value answers 0 events';
  ASSERT pg_temp.t_values('rec.example') = 'cname_takeover=none dns_presence=found email_auth=pp ip_address_reachability=public ns=ns1/ns2',
         'S5 a new value becomes the candidate, and the current value stays';
  ASSERT pg_temp.t_candidate('rec.example', 'ns') = 'ns2|00:00:00', 'S5 the candidate is first seen now';
  ASSERT (SELECT widv.candidate_value_sha256 = pg_temp.t_sha256('ns2') FROM watchlist_item_domain_value AS widv
           WHERE widv.item_id = (SELECT wid.item_id FROM watchlist_item_domain AS wid WHERE wid.domain_name = 'rec.example') AND widv.value_kind = 'ns'),
         'S5 the candidate is stored with its SHA-256';
END
$$;

DO $$
BEGIN
  PERFORM pg_temp.t_age('rec.example', 'ns', interval '30 minutes');
  ASSERT pg_temp.t_record_dns('rec.example', p_ns => 'ns2') = 0, 'S6 the candidate after 30 minutes answers 0 events';
  ASSERT pg_temp.t_candidate('rec.example', 'ns') = 'ns2|00:30:00', 'S6 the candidate keeps its first sighting';
  PERFORM pg_temp.t_age('rec.example', 'ns', interval '59 minutes 59 seconds');
  ASSERT pg_temp.t_record_dns('rec.example', p_ns => 'ns2') = 0, 'S6 the candidate one second before an hour answers 0 events';
  ASSERT pg_temp.t_values('rec.example') = 'cname_takeover=none dns_presence=found email_auth=pp ip_address_reachability=public ns=ns1/ns2',
         'S6 the candidate one second before an hour stays a candidate';
END
$$;

DO $$
DECLARE
  confirm_event_id bigint;
BEGIN
  PERFORM pg_temp.t_dw_mark();
  PERFORM pg_temp.t_age('rec.example', 'ns', interval '1 hour');
  ASSERT pg_temp.t_record_dns('rec.example', p_ns => 'ns2') = 1, 'S7 a confirmed candidate answers 1 event';
  ASSERT pg_temp.t_dw_events('rec.example') = '{ns_changed:ns1>ns2}', 'S7 the event carries the old and the new value';
  ASSERT pg_temp.t_values('rec.example') = 'cname_takeover=none dns_presence=found email_auth=pp ip_address_reachability=public ns=ns2',
         'S7 the candidate becomes the current value and is cleared';
  ASSERT (SELECT widv.current_value_sha256 = pg_temp.t_sha256('ns2') AND num_nonnulls(widv.candidate_value, widv.candidate_value_sha256,
                                                                                        widv.candidate_seen_at) = 0
            FROM watchlist_item_domain_value AS widv
           WHERE widv.item_id = (SELECT wid.item_id FROM watchlist_item_domain AS wid WHERE wid.domain_name = 'rec.example') AND widv.value_kind = 'ns'),
         'S7 the current SHA-256 is the SHA-256 of the new value, and each candidate column is NULL';
  SELECT max(dce.event_id) INTO confirm_event_id FROM domain_change_event AS dce;
  ASSERT (SELECT array_agg(wer.item_id || ':' || ak.key_hash ORDER BY wer.item_id) FROM watchlist_event_ref AS wer
            JOIN api_keys AS ak ON ak.id = wer.api_key_id WHERE wer.event_id = confirm_event_id)
         = ARRAY[(SELECT wid.item_id FROM watchlist_item_domain AS wid WHERE wid.domain_name = 'rec.example') || ':' || repeat('9c', 32)],
         'S7 the item that went through the change hears the event, with the key of the item';
  ASSERT pg_temp.t_heard(repeat('9c', 32), 'rec.example') = '{ns_changed:ns1>ns2}', 'S7 the key of the item reads the event';
  ASSERT (SELECT count(*) FROM pg_locks AS l
           WHERE l.locktype = 'advisory' AND l.pid = pg_backend_pid()
             AND l.classid = 0 AND l.objid = 'public.watchlist_event_id_seq'::regclass::oid
             AND l.objsubid = 1 AND l.granted) = 1,
         'S7 the transaction that wrote the event holds the advisory lock keyed by the OID of watchlist_event_id_seq';
END
$$;

DO $$
BEGIN
  ASSERT pg_temp.t_record_dns('rec.example', p_ns => 'ns3') = 0, 'S8 a new value answers 0 events';
  PERFORM pg_temp.t_age('rec.example', 'ns', interval '2 hours');
  ASSERT pg_temp.t_record_dns('rec.example', p_ns => 'ns4') = 0, 'S8 another new value answers 0 events';
  ASSERT pg_temp.t_candidate('rec.example', 'ns') = 'ns4|00:00:00', 'S8 the newer value is the candidate, first seen now';
  ASSERT pg_temp.t_values('rec.example') = 'cname_takeover=none dns_presence=found email_auth=pp ip_address_reachability=public ns=ns2/ns4',
         'S8 the current value stays';
  ASSERT (SELECT count(*) FROM domain_change_event AS dce WHERE dce.domain_name = 'rec.example') = 1, 'S8 the old candidate writes no event';
END
$$;

DO $$
BEGIN
  ASSERT pg_temp.t_record_dns('rec.example', p_ns => 'ns2') = 0, 'S9 the current value answers 0 events';
  ASSERT pg_temp.t_values('rec.example') = 'cname_takeover=none dns_presence=found email_auth=pp ip_address_reachability=public ns=ns2',
         'S9 the current value seen again clears the candidate';
  ASSERT (SELECT num_nonnulls(widv.candidate_value, widv.candidate_value_sha256, widv.candidate_seen_at) = 0
            FROM watchlist_item_domain_value AS widv
           WHERE widv.item_id = (SELECT wid.item_id FROM watchlist_item_domain AS wid WHERE wid.domain_name = 'rec.example') AND widv.value_kind = 'ns'),
         'S9 each candidate column is NULL';
END
$$;

DO $$
DECLARE
  ip_address_reachability_before text;
BEGIN
  ASSERT pg_temp.t_record_dns('rec.example', p_ip_address_reachability => 'not_public') = 0, 'S10 a new ip_address_reachability value answers 0 events';
  PERFORM pg_temp.t_age('rec.example', 'ip_address_reachability', interval '2 hours');
  SELECT widv::text INTO ip_address_reachability_before FROM watchlist_item_domain_value AS widv
   WHERE widv.value_kind = 'ip_address_reachability' AND widv.item_id = (SELECT wid.item_id FROM watchlist_item_domain AS wid WHERE wid.domain_name = 'rec.example');
  ASSERT pg_temp.t_record_dns('rec.example', p_dns_presence => 'found') = 0, 'S10 a scan without the ip_address_reachability value answers 0 events';
  ASSERT (SELECT widv::text FROM watchlist_item_domain_value AS widv
           WHERE widv.value_kind = 'ip_address_reachability' AND widv.item_id = (SELECT wid.item_id FROM watchlist_item_domain AS wid WHERE wid.domain_name = 'rec.example'))
         = ip_address_reachability_before,
         'S10 a scan with no ip_address_reachability value leaves the ip_address_reachability row and its candidate as they are';
  ASSERT pg_temp.t_next_scan('rec.example') = api.fn_domain_watch_next_daily_scan_at('rec.example'),
         'S10 a candidate of a kind with no value in the scan brings no hourly scan';
  ASSERT pg_temp.t_record_dns('rec.example', p_ip_address_reachability => 'public') = 0, 'S10 the current ip_address_reachability value answers 0 events';
  PERFORM pg_temp.t_dw_mark();
  ASSERT pg_temp.t_record_dns('rec.example', p_mx => 'mx1') = 0, 'S10 a kind with its first value answers 0 events';
  ASSERT pg_temp.t_values('rec.example') = 'cname_takeover=none dns_presence=found email_auth=pp ip_address_reachability=public mx=mx1 ns=ns2',
         'S10 a kind with its first value writes its current value and no candidate';
  ASSERT pg_temp.t_dw_events('rec.example') = '{}', 'S10 a kind with a first value that shows no problem writes no event';
END
$$;

SELECT pg_temp.t_add_dns('map.example');
SELECT pg_temp.t_record_dns('map.example', p_dns_presence => 'found', p_ns => 'n1', p_mx => 'm1', p_ip_address_reachability => 'public',
                            p_cname_takeover => 'none', p_email_auth => 'pp');
DO $$
DECLARE
  check_ids CONSTANT text := 'spf_all,dmarc_policy';
BEGIN
  ASSERT pg_temp.t_dns_change('map.example', 'dns_presence', 'not_found') = '1|{domain_not_found:found>not_found}',
         'S11 found to not_found is domain_not_found';
  ASSERT pg_temp.t_dns_change('map.example', 'dns_presence', 'found') = '1|{domain_found:not_found>found}',
         'S11 not_found to found is domain_found';
  ASSERT pg_temp.t_dns_change('map.example', 'ns', 'n2') = '1|{ns_changed:n1>n2}', 'S11 a new ns is ns_changed';
  ASSERT pg_temp.t_dns_change('map.example', 'mx', 'm2') = '1|{mx_changed:m1>m2}', 'S11 a new mx is mx_changed';
  ASSERT pg_temp.t_dns_change('map.example', 'ip_address_reachability', 'not_public') = '1|{ip_address_not_public:public>not_public}',
         'S11 a not_public ip_address_reachability is ip_address_not_public';
  ASSERT pg_temp.t_dns_change('map.example', 'ip_address_reachability', 'empty') = '1|{ip_address_lost:not_public>empty}',
         'S11 an empty ip_address_reachability is ip_address_lost';
  ASSERT pg_temp.t_dns_change('map.example', 'ip_address_reachability', 'public') = '1|{ip_address_restored:empty>public}',
         'S11 a public ip_address_reachability is ip_address_restored';
  ASSERT pg_temp.t_dns_change('map.example', 'cname_takeover', 'vulnerable:a') = '1|{cname_takeover_detected:none>vulnerable:a}',
         'S11 none to vulnerable is cname_takeover_detected';
  ASSERT pg_temp.t_dns_change('map.example', 'cname_takeover', 'vulnerable:b') = '0|{}', 'S11 one vulnerable value to another writes no event';
  ASSERT pg_temp.t_values('map.example') LIKE 'cname_takeover=vulnerable:b %', 'S11 the other vulnerable value still becomes current';
  ASSERT pg_temp.t_dns_change('map.example', 'cname_takeover', 'none') = '1|{cname_takeover_resolved:vulnerable:b>none}',
         'S11 vulnerable to none is cname_takeover_resolved';
  ASSERT pg_temp.t_dns_change('map.example', 'cname_takeover', 'unchecked') = '0|{}', 'S11 none to a value that is not vulnerable writes no event';
  ASSERT pg_temp.t_dns_change('map.example', 'cname_takeover', 'none') = '0|{}', 'S11 a value that is not vulnerable back to none writes no event';
  ASSERT pg_temp.t_dns_change('map.example', 'cname_takeover', 'vulnerable') = '1|{cname_takeover_detected:none>vulnerable}',
         'S11 none to vulnerable with no service name is cname_takeover_detected';
  ASSERT pg_temp.t_dns_change('map.example', 'cname_takeover', 'none') = '1|{cname_takeover_resolved:vulnerable>none}',
         'S11 vulnerable with no service name to none is cname_takeover_resolved';

  ASSERT pg_temp.t_dns_change('map.example', 'email_auth', 'wf', check_ids)
         = '2|{email_auth_degraded:spf_all:pp>wf,email_auth_degraded:dmarc_policy:pp>wf}',
         'S11 p to w and p to f each write email_auth_degraded with their check id, in letter order';
  ASSERT pg_temp.t_dns_change('map.example', 'email_auth', 'ff', check_ids) = '1|{email_auth_degraded:spf_all:wf>ff}',
         'S11 w to f writes email_auth_degraded, and f to f writes none';
  ASSERT pg_temp.t_dns_change('map.example', 'email_auth', 'p-', check_ids) = '0|{}', 'S11 f to p and f to - write no event';
  ASSERT pg_temp.t_dns_change('map.example', 'email_auth', 'w-', check_ids) = '1|{email_auth_degraded:spf_all:p->w-}',
         'S11 p to w writes its event, and - to - writes none';
  ASSERT pg_temp.t_dns_change('map.example', 'email_auth', '-f', check_ids) = '0|{}', 'S11 w to - and - to f write no event';
  ASSERT pg_temp.t_dns_change('map.example', 'email_auth', 'pp', check_ids) = '0|{}', 'S11 letters that get better write no event';
  ASSERT pg_temp.t_dns_change('map.example', 'email_auth', 'fff', check_ids) = '0|{}',
         'S11 a confirmed value with more letters than check ids writes no event, though its first letters got worse';
  ASSERT pg_temp.t_dns_change('map.example', 'email_auth', 'ppp', check_ids) = '0|{}', 'S11 three letters to three better ones write no event';
  ASSERT pg_temp.t_dns_change('map.example', 'email_auth', 'ff', check_ids) = '0|{}',
         'S11 a current value with more letters than check ids writes no event, though the letters got worse';
  ASSERT pg_temp.t_dns_change('map.example', 'email_auth', 'pp', check_ids) = '0|{}', 'S11 back to pp writes no event';
  ASSERT pg_temp.t_dns_change('map.example', 'email_auth', 'ff') = '0|{}', 'S11 a confirmed e-mail change with no check id writes no event';
  ASSERT pg_temp.t_dns_change('map.example', 'email_auth', 'pp', check_ids) = '0|{}', 'S11 back to pp again writes no event';
  ASSERT pg_temp.t_dns_change('map.example', 'email_auth', 'ff', '') = '0|{}', 'S11 a confirmed e-mail change with an empty list writes no event';
  ASSERT pg_temp.t_values('map.example') LIKE '%email_auth=ff %', 'S11 the e-mail value still becomes current';
  PERFORM pg_temp.t_dw_mark();
  ASSERT pg_temp.t_record_dns('map.example', p_email_auth => 'ff', p_email_check_ids => check_ids) = 0,
         'S11 check ids with no confirmed e-mail change write no event';
  ASSERT pg_temp.t_dns_change('map.example', 'ns', 'n3', check_ids) = '1|{ns_changed:n2>n3}',
         'S11 check ids with a confirmed change of another kind write only that kind''s event';
END
$$;

DO $$
BEGIN
  PERFORM pg_temp.t_dw_mark();
  PERFORM pg_temp.t_record_dns('map.example', p_ns => 'n4', p_mx => 'm3');
  PERFORM pg_temp.t_age('map.example', 'ns', interval '1 hour');
  PERFORM pg_temp.t_age('map.example', 'mx', interval '1 hour');
  ASSERT pg_temp.t_record_dns('map.example', p_ns => 'n4', p_mx => 'm3') = 2, 'S12 two confirmed candidates answer 2 events';
  ASSERT pg_temp.t_dw_events('map.example') = '{ns_changed:n3>n4,mx_changed:m2>m3}', 'S12 the ns event comes before the mx event';
END
$$;

DO $$
DECLARE
  before_call text;
BEGIN
  UPDATE domain_watch_lane AS dwl SET claimed_until = now() + interval '10 minutes', claimed_at = now() + interval '2 days' WHERE dwl.domain_name = 'map.example' AND dwl.lane_name = 'dns';
  before_call := pg_temp.t_snapshot('map.example');
  ASSERT api.fn_domain_watch_record_dns('map.example', now() + interval '9 minutes', NULL, NULL, 'n9', pg_temp.t_sha256('n9'),
                                        NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 40) = 0,
         'S13 another lease answers 0';
  ASSERT pg_temp.t_snapshot('map.example') = before_call, 'S13 another lease changes nothing';
  ASSERT api.fn_domain_watch_record_dns('map.example', NULL, NULL, NULL, 'n9', pg_temp.t_sha256('n9'),
                                        NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 40) = 0,
         'S13 a NULL lease against a held one answers 0';
  ASSERT pg_temp.t_snapshot('map.example') = before_call, 'S13 a NULL lease changes nothing';
  UPDATE domain_watch_lane AS dwl SET claimed_until = NULL WHERE dwl.domain_name = 'map.example' AND dwl.lane_name = 'dns';
  before_call := pg_temp.t_snapshot('map.example');
  ASSERT api.fn_domain_watch_record_dns('map.example', NULL, NULL, NULL, 'n9', pg_temp.t_sha256('n9'),
                                        NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 40) = 0,
         'S13 a row with no lease answers 0, even to a NULL lease';
  ASSERT pg_temp.t_snapshot('map.example') = before_call, 'S13 a row with no lease changes nothing';
  ASSERT api.fn_domain_watch_record_dns('none.example', now(), 'found', pg_temp.t_sha256('found'),
                                        NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 40) = 0,
         'S13 an unknown domain answers 0';
  ASSERT NOT EXISTS (SELECT 1 FROM domain_watch AS dw WHERE dw.domain_name = 'none.example'), 'S13 an unknown domain writes no row';
END
$$;

DO $$
BEGIN
  BEGIN
    PERFORM api.fn_domain_watch_record_dns('map.example', now(), NULL, NULL, NULL, NULL, 'm9', NULL,
                                           NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 40);
    ASSERT false, 'S14 a value without its SHA-256 is refused';
  EXCEPTION WHEN invalid_parameter_value THEN
    ASSERT SQLERRM LIKE '%mx%', 'S14 the refusal names the kind mx';
  END;
  BEGIN
    PERFORM api.fn_domain_watch_record_dns('map.example', now(), NULL, NULL, NULL, NULL, NULL, NULL,
                                           NULL, NULL, NULL, NULL, NULL, pg_temp.t_sha256('e9'), NULL, NULL, 40);
    ASSERT false, 'S14 a SHA-256 without its value is refused';
  EXCEPTION WHEN invalid_parameter_value THEN
    ASSERT SQLERRM LIKE '%email_auth%', 'S14 the refusal names the kind email_auth';
  END;
END
$$;

DO $$
BEGIN
  UPDATE domain_watch_lane AS dwl SET not_before = now() - interval '1 minute' WHERE dwl.domain_name = 'rec.example' AND dwl.lane_name = 'dns';
  PERFORM pg_temp.t_record_dns('rec.example', p_dns_presence => 'found', p_claimed_at => now() + interval '3 days');
  ASSERT (SELECT dwl::text FROM domain_watch_lane AS dwl WHERE dwl.domain_name = 'rec.example' AND dwl.lane_name = 'dns')
         = ROW('rec.example', 'dns', NULL::timestamptz, now() + interval '3 days', now(), now() - interval '1 minute')::text,
         'S15 the record ends the lease, notes scanned_at and keeps every other column of the lane row';
  ASSERT (SELECT dw::text FROM domain_watch AS dw WHERE dw.domain_name = 'rec.example') = ROW('rec.example', 'rec.example')::text,
         'S15 the record writes nothing in the domain_watch row';
END
$$;

DO $$
DECLARE
  saved_time_zone text        := current_setting('TimeZone');
  utc_day_start   timestamptz := date_trunc('day', now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC';
  last_second     timestamptz := utc_day_start + interval '86399 seconds';
  first_slot      timestamptz;
BEGIN
  PERFORM pg_temp.t_record_dns('rec.example', p_ns => 'ns7');
  ASSERT pg_temp.t_next_scan('rec.example') = now() + interval '1 hour',
         'S16 a scan that leaves a candidate brings the next scan of the item one hour after now';

  ASSERT abs(hashtextextended('slot175334.example', 0) % 86400) = 0, 'S16 slot175334.example has the second 0';
  ASSERT abs(hashtextextended('slot338929.example', 0) % 86400) = 86399, 'S16 slot338929.example has the second 86399';
  PERFORM pg_temp.t_add_dns('slot175334.example');
  PERFORM pg_temp.t_add_dns('slot338929.example', 'slot-registrable.example');
  ASSERT hashtextextended('neg2999.example', 0) % 86400 = -86399, 'S16 neg2999.example has a negative remainder';
  PERFORM pg_temp.t_add_dns('neg2999.example');
  PERFORM pg_temp.t_record_dns('neg2999.example', p_dns_presence => 'found');
  ASSERT pg_temp.t_next_scan('neg2999.example') = CASE WHEN last_second > now() THEN last_second ELSE last_second + interval '1 day' END,
         'S16 a negative remainder takes its absolute value as the second';
  PERFORM set_config('TimeZone', 'Pacific/Kiritimati', true);
  PERFORM pg_temp.t_record_dns('slot338929.example', p_dns_presence => 'found');
  PERFORM pg_temp.t_record_dns('slot175334.example', p_dns_presence => 'found');
  ASSERT pg_temp.t_next_scan('slot338929.example') = CASE WHEN last_second > now() THEN last_second ELSE last_second + interval '1 day' END,
         'S16 the last second of the UTC day brings the next scan today while it is ahead, and tomorrow once it has come';
  ASSERT pg_temp.t_next_scan('slot175334.example') = utc_day_start + interval '1 day',
         'S16 a second of the UTC day already passed brings the next scan tomorrow';
  first_slot := pg_temp.t_next_scan('slot338929.example');
  PERFORM set_config('TimeZone', 'Pacific/Pago_Pago', true);
  PERFORM pg_temp.t_record_dns('slot338929.example', p_dns_presence => 'found');
  ASSERT pg_temp.t_next_scan('slot338929.example') = first_slot, 'S16 a scan under another session time zone gives the same next scan';
  PERFORM set_config('TimeZone', saved_time_zone, true);
END
$$;

DO $$
DECLARE
  compare_source text := regexp_replace((SELECT p.prosrc FROM pg_proc AS p
                                          WHERE p.oid = 'api.fn_domain_watch_write_scan_values(text, text, timestamptz, text[], text[], text)'::regprocedure),
                                        '--[^\n]*', '', 'g');
  after_lock     text;
  record_sources text[] := ARRAY[regexp_replace((SELECT p.prosrc FROM pg_proc AS p
                                                  WHERE p.oid = 'api.fn_domain_watch_record_dns(text, timestamptz, text, text, text, text, text, text, text, text, text, text, text, text, text, text, integer)'::regprocedure),
                                                '--[^\n]*', '', 'g'),
                                 regexp_replace((SELECT p.prosrc FROM pg_proc AS p
                                                  WHERE p.oid = 'api.fn_domain_watch_record_tls(text, timestamptz, text, text, text, text, text, text, text, text)'::regprocedure),
                                                '--[^\n]*', '', 'g'),
                                 regexp_replace((SELECT p.prosrc FROM pg_proc AS p
                                                  WHERE p.oid = 'api.fn_domain_watch_record_rdap_whois(text, timestamptz, text, text, text, text, text, text, text, text, integer)'::regprocedure),
                                                '--[^\n]*', '', 'g'),
                                 regexp_replace((SELECT p.prosrc FROM pg_proc AS p
                                                  WHERE p.oid = 'api.fn_domain_watch_record_headers(text, timestamptz, text, text, integer)'::regprocedure),
                                                '--[^\n]*', '', 'g'),
                                 regexp_replace((SELECT p.prosrc FROM pg_proc AS p
                                                  WHERE p.oid = 'api.fn_domain_watch_record_ct(text, timestamptz, text, text, integer)'::regprocedure),
                                                '--[^\n]*', '', 'g')];
  record_source  text;
BEGIN
  after_lock := substring(compare_source FROM 'PERFORM public\.fn_watchlist_event_take_order_lock\(\);(.*)$');
  ASSERT after_lock IS NOT NULL, 'S17 the function takes the order lock';
  ASSERT (SELECT count(*) FROM regexp_matches(compare_source, 'PERFORM public\.fn_watchlist_event_take_order_lock\(\)', 'g')) = 1,
         'S17 one call takes the lock';
  ASSERT after_lock ~ '^\s+WITH transition AS \(',
         'S17 the statement right after the lock is the one that writes the events';
  ASSERT (SELECT count(*) FROM regexp_matches(compare_source, 'INSERT INTO public\.domain_change_event', 'g')) = 1
     AND after_lock ~ 'INSERT INTO public\.domain_change_event AS dce .*INSERT INTO public\.watchlist_event_ref',
         'S17 one statement after the lock writes the events, then the refs';
  ASSERT (SELECT count(*) FROM regexp_matches(compare_source, 'INSERT INTO public\.watchlist_event_ref', 'g')) = 1,
         'S17 the refs are written in one place';
  ASSERT after_lock !~ '(public\.watchlist_item_domain_value|public\.watchlist_item_domain |public\.watchlist_item |public\.domain_watch)',
         'S17 no item, value row or domain row is read or written after the lock';
  ASSERT compare_source ~ 'WHERE wid\.domain_name = p_domain_name\s+AND wid\.endpoint_name = p_endpoint_name\s+AND wid\.next_scan_at <= p_claimed_at\s+FOR NO KEY UPDATE OF wid, wi SKIP LOCKED\) AS taken;',
         'S17 one statement locks each item it serves and its child row, and skips an item that another transaction holds';
  ASSERT compare_source ~ 'FOR NO KEY UPDATE OF wid, wi SKIP LOCKED\) AS taken;.*INSERT INTO public\.watchlist_item_domain_value.*UPDATE public\.watchlist_item_domain AS wid.*PERFORM public\.fn_watchlist_event_take_order_lock',
         'S17 the items are locked first, then the value rows and the items are written, then the lock is taken';
  ASSERT compare_source !~ 'nextval',
         'S17 the function takes no number of the event sequence itself: only the event insert does, after the lock';
  FOREACH record_source IN ARRAY record_sources LOOP
    ASSERT (SELECT count(*) FROM regexp_matches(record_source, 'api\.fn_domain_watch_write_scan_values\(', 'g')) = 1,
           'S17 each record calls api.fn_domain_watch_write_scan_values once';
    ASSERT record_source !~ '(fn_watchlist_event_take_order_lock|domain_change_event|watchlist_event_ref|watchlist_item_domain|nextval)',
           'S17 a record takes no lock, writes no event, no ref, no value row and no item itself';
  END LOOP;
  ASSERT record_sources[1] ~ 'api\.fn_domain_watch_write_scan_values\(p_domain_name, lane_endpoint_name, watched_lane\.claimed_at,',
         'S17 the DNS record serves the items due at the claimed_at of its lane lease';
  ASSERT record_sources[1] ~ 'lane_endpoint_name\s+CONSTANT text\s+:= \(SELECT l\.endpoint_name FROM api\.fn_domain_watch_lanes\(\) AS l WHERE l\.lane_name = ''dns''\);',
         'S17 the DNS record reads the endpoint of the dns lane from the lane map';
  ASSERT record_sources[1] ~ 'FROM public\.domain_watch AS dw WHERE dw\.domain_name = p_domain_name FOR KEY SHARE;\s+SELECT \* INTO watched_lane FROM public\.domain_watch_lane AS dwl\s+WHERE dwl\.domain_name = p_domain_name AND dwl\.lane_name = ''dns''\s+FOR UPDATE;',
         'S17 the DNS record holds the domain_watch row, then locks its lane row';
  ASSERT record_sources[2] ~ 'api\.fn_domain_watch_write_scan_values\(p_domain_name, lane_endpoint_name, watched_lane\.claimed_at,',
         'S17 the TLS record serves the items due at the claimed_at of its lane lease';
  ASSERT record_sources[2] ~ 'lane_endpoint_name\s+CONSTANT text\s+:= \(SELECT l\.endpoint_name FROM api\.fn_domain_watch_lanes\(\) AS l WHERE l\.lane_name = ''tls''\);',
         'S17 the TLS record reads the endpoint of the tls lane from the lane map';
  ASSERT record_sources[2] ~ 'FROM public\.domain_watch AS dw WHERE dw\.domain_name = p_domain_name FOR KEY SHARE;\s+SELECT \* INTO watched_lane FROM public\.domain_watch_lane AS dwl\s+WHERE dwl\.domain_name = p_domain_name AND dwl\.lane_name = ''tls''\s+FOR UPDATE;',
         'S17 the TLS record holds the domain_watch row, then locks its lane row';
  ASSERT record_sources[3] ~ 'api\.fn_domain_watch_write_scan_values\(p_domain_name, lane_endpoint_name, watched_lane\.claimed_at,',
         'S17 the RDAP/WHOIS record serves the items due at the claimed_at of its lane lease';
  ASSERT record_sources[3] ~ 'lane_endpoint_name\s+CONSTANT text\s+:= \(SELECT l\.endpoint_name FROM api\.fn_domain_watch_lanes\(\) AS l WHERE l\.lane_name = ''rdap_whois''\);',
         'S17 the RDAP/WHOIS record reads the endpoint of the rdap_whois lane from the lane map';
  ASSERT record_sources[3] ~ 'FROM public\.domain_watch AS dw WHERE dw\.domain_name = p_domain_name FOR KEY SHARE;\s+SELECT \* INTO watched_lane FROM public\.domain_watch_lane AS dwl\s+WHERE dwl\.domain_name = p_domain_name AND dwl\.lane_name = ''rdap_whois''\s+FOR UPDATE;',
         'S17 the RDAP/WHOIS record holds the domain_watch row, then locks its lane row';
  ASSERT record_sources[4] ~ 'api\.fn_domain_watch_write_scan_values\(p_domain_name, lane_endpoint_name, watched_lane\.claimed_at,',
         'S17 the headers record serves the items due at the claimed_at of its lane lease';
  ASSERT record_sources[4] ~ 'lane_endpoint_name\s+CONSTANT text\s+:= \(SELECT l\.endpoint_name FROM api\.fn_domain_watch_lanes\(\) AS l WHERE l\.lane_name = ''headers''\);',
         'S17 the headers record reads the endpoint of the headers lane from the lane map';
  ASSERT record_sources[4] ~ 'FROM public\.domain_watch AS dw WHERE dw\.domain_name = p_domain_name FOR KEY SHARE;\s+SELECT \* INTO watched_lane FROM public\.domain_watch_lane AS dwl\s+WHERE dwl\.domain_name = p_domain_name AND dwl\.lane_name = ''headers''\s+FOR UPDATE;',
         'S17 the headers record holds the domain_watch row, then locks its lane row';
  ASSERT record_sources[5] ~ 'api\.fn_domain_watch_write_scan_values\(p_domain_name, lane_endpoint_name, watched_lane\.claimed_at,',
         'S17 the ct record serves the items due at the claimed_at of its lane lease';
  ASSERT record_sources[5] ~ 'lane_endpoint_name\s+CONSTANT text\s+:= \(SELECT l\.endpoint_name FROM api\.fn_domain_watch_lanes\(\) AS l WHERE l\.lane_name = ''ct''\);',
         'S17 the ct record reads the endpoint of the ct lane from the lane map';
  ASSERT record_sources[5] ~ 'FROM public\.domain_watch AS dw WHERE dw\.domain_name = p_domain_name FOR KEY SHARE;\s+SELECT \* INTO watched_lane FROM public\.domain_watch_lane AS dwl\s+WHERE dwl\.domain_name = p_domain_name AND dwl\.lane_name = ''ct''\s+FOR UPDATE;',
         'S17 the ct record holds the domain_watch row, then locks its lane row';
END
$$;

CREATE FUNCTION pg_temp.t_watch(p_domain_name text, p_registered_domain text, p_next_scan_at timestamptz,
                                p_claimed_until timestamptz DEFAULT NULL, p_scanned_at timestamptz DEFAULT NULL)
  RETURNS void LANGUAGE sql AS $$
  SELECT pg_temp.t_item(p_domain_name, repeat('9c', 32), 'dns_lookup', p_next_scan_at, p_registered_domain);
  UPDATE domain_watch_lane AS dwl SET claimed_until = p_claimed_until, scanned_at = p_scanned_at WHERE dwl.domain_name = p_domain_name AND dwl.lane_name = 'dns';
$$;

CREATE FUNCTION pg_temp.t_item_times() RETURNS text LANGUAGE sql AS $$
  SELECT coalesce(string_agg(wid.domain_name || '=' || (wid.next_scan_at - now()), ',' ORDER BY wid.domain_name, wid.item_id), '')
    FROM watchlist_item_domain AS wid
$$;

SELECT pg_temp.t_reset();
SELECT pg_temp.t_watch('c4.example', 'c4.example', now() + interval '1 second');
SELECT pg_temp.t_watch('c2.example', 'c2.example', now() - interval '2 hours');
SELECT pg_temp.t_watch('c1.example', 'c1.example', now() - interval '3 hours');
SELECT pg_temp.t_watch('c3.example', 'c3.example', now());
SELECT pg_temp.t_watch('c5.example', 'c5.example', now() - interval '4 hours', now() + interval '1 minute');
SELECT pg_temp.t_watch('c6.example', 'c6.example', now() - interval '5 hours', now() - interval '1 second');
SELECT pg_temp.t_watch('c7.example', 'c7.example', now() - interval '6 hours', now());
DO $$
DECLARE
  item_times_before text := pg_temp.t_item_times();
BEGIN
  ASSERT pg_temp.t_claim('dns', NULL) = '', 'S18 a NULL row count claims nothing';
  ASSERT pg_temp.t_claim('dns', 10, NULL) = '', 'S18 a NULL lease claims nothing';
  ASSERT (SELECT count(*) FROM domain_watch_lane AS dwl WHERE dwl.lane_name = 'dns' AND dwl.claimed_until > now() + interval '1 minute') = 0,
         'S18 a call with a NULL argument leases nothing';
  ASSERT pg_temp.t_claim('dns', 2) = 'c6.example,c1.example', 'S18 a claim of 2 answers the two oldest due domains with no running lease';
  ASSERT (SELECT array_agg(dwl.domain_name ORDER BY dwl.domain_name) FROM domain_watch_lane AS dwl WHERE dwl.lane_name = 'dns' AND dwl.claimed_until = now() + interval '300 seconds')
         = '{c1.example,c6.example}',
         'S18 each claimed domain holds a lease of p_lease_seconds';
  ASSERT pg_temp.t_claim('dns', 10) = 'c2.example,c3.example', 'S18 the next claim skips the leased domains and takes a domain due at now()';
  ASSERT pg_temp.t_claim('dns', 10) = '', 'S18 a claim with no due domain left answers none';
  ASSERT (SELECT dwl.claimed_until FROM domain_watch_lane AS dwl WHERE dwl.domain_name = 'c5.example' AND dwl.lane_name = 'dns') = now() + interval '1 minute',
         'S18 a running lease is not claimed';
  ASSERT (SELECT dwl.claimed_until FROM domain_watch_lane AS dwl WHERE dwl.domain_name = 'c7.example' AND dwl.lane_name = 'dns') = now(),
         'S18 a lease that ends at now() is not claimed';
  ASSERT (SELECT dwl.claimed_until IS NULL FROM domain_watch_lane AS dwl WHERE dwl.domain_name = 'c4.example' AND dwl.lane_name = 'dns'),
         'S18 a domain due after now() is not claimed';
  ASSERT pg_temp.t_item_times() = item_times_before, 'S18 a claim moves no time of an item';
END
$$;

SELECT pg_temp.t_reset();
SELECT pg_temp.t_watch('tie-b.example', 'tie-b.example', now() - interval '1 hour');
SELECT pg_temp.t_watch('tie-a.example', 'tie-a.example', now() - interval '1 hour');
DO $$
BEGIN
  ASSERT pg_temp.t_claim('dns', 0) = '', 'S18 a row count of 0 claims nothing';
  ASSERT pg_temp.t_claim('dns', -1) = '', 'S18 a negative row count claims nothing';
  ASSERT pg_temp.t_claim('dns', 1, 0) = '', 'S18 a lease of 0 seconds claims nothing';
  ASSERT pg_temp.t_claim('dns', 1, -1) = '', 'S18 a negative lease claims nothing';
  ASSERT pg_temp.t_claim('dns', 1) = 'tie-a.example', 'S18 a tie of the due time goes to the smaller domain';
  ASSERT pg_temp.t_claim('dns', 1, 1) = 'tie-b.example', 'S18 a lease of 1 second is the shortest one claimed';
  ASSERT (SELECT dwl.claimed_until FROM domain_watch_lane AS dwl WHERE dwl.domain_name = 'tie-b.example' AND dwl.lane_name = 'dns') = now() + interval '1 second',
         'S18 the lease of 1 second ends 1 second after now()';
END
$$;

SELECT pg_temp.t_reset();
SELECT pg_temp.t_watch('col-a.example', 'col-a.example', now() - interval '2 hours');
DO $$
DECLARE
  before_claim timestamptz := clock_timestamp();
  claim_answer text;
BEGIN
  SELECT string_agg(x.domain_name || '|' || (x.claimed_until - now()), ',') INTO claim_answer FROM api.fn_domain_watch_claim('dns', 10, 600) AS x;
  ASSERT claim_answer = 'col-a.example|00:10:00', 'S19 the claim answers the domain and its lease';
  ASSERT (SELECT dwl.claimed_at > before_claim AND dwl.claimed_at < clock_timestamp() FROM domain_watch_lane AS dwl WHERE dwl.domain_name = 'col-a.example' AND dwl.lane_name = 'dns'),
         'S19 claimed_at is the clock at the claim, not the start of the transaction';
  ASSERT regexp_replace(pg_get_functiondef('api.fn_domain_watch_claim(text, integer, integer)'::regprocedure), '--[^\n]*', '', 'g')
         ~ 'FOR UPDATE OF dwl SKIP LOCKED;.*SET claimed_until = now\(\) \+ p_lease_seconds \* interval ''1 second'',\s+claimed_at    = clock_timestamp\(\)',
         'S19 the claim takes claimed_at from clock_timestamp() after it locked the lane row';
END
$$;

SELECT pg_temp.t_reset();
SELECT pg_temp.t_watch('b1.bucket.example',   'bucket.example',   now() - interval '3 hours');
SELECT pg_temp.t_watch('b2.bucket.example',   'bucket.example',   now() - interval '2 hours');
SELECT pg_temp.t_watch('b3.bucket.example',   'bucket.example',   now() - interval '1 hour');
SELECT pg_temp.t_watch('s1.separate.example', 'separate.example', now() - interval '30 minutes');
DO $$
DECLARE
  item_times_before text := pg_temp.t_item_times();
BEGIN
  ASSERT pg_temp.t_claim('dns', 10) = 'b1.bucket.example,b2.bucket.example,s1.separate.example',
         'S20 two domains of one registrable domain empty its bucket, and the third is refused, while another bucket still pays';
  ASSERT (SELECT dwdb.question_allowance || '|' || (dwdb.refilled_at = now())::text FROM domain_watch_dns_bucket AS dwdb WHERE dwdb.registered_domain = 'bucket.example')
         = '0|true',
         'S20 two claims took 80 questions from the new bucket';
  ASSERT (SELECT dwdb.question_allowance FROM domain_watch_dns_bucket AS dwdb WHERE dwdb.registered_domain = 'separate.example') = 40,
         'S20 a new bucket starts at 80 and one claim takes 40';
  ASSERT (SELECT dwl.claimed_until IS NULL AND dwl.not_before = now() + interval '80 seconds'
            FROM domain_watch_lane AS dwl WHERE dwl.domain_name = 'b3.bucket.example' AND dwl.lane_name = 'dns'),
         'S20 the refused domain holds no lease, and not_before holds it back the 80 seconds that 40 questions take';
  ASSERT (SELECT dwl.not_before IS NULL FROM domain_watch_lane AS dwl WHERE dwl.domain_name = 's1.separate.example' AND dwl.lane_name = 'dns'),
         'S20 the refusal holds back only the refused registered domain';
  ASSERT pg_temp.t_item_times() = item_times_before, 'S20 the refusal moves no time of an item';

  UPDATE domain_watch_dns_bucket AS dwdb SET refilled_at = now() - interval '60 seconds' WHERE dwdb.registered_domain = 'bucket.example';
  UPDATE domain_watch_lane AS dwl SET not_before = now() WHERE dwl.domain_name = 'b3.bucket.example' AND dwl.lane_name = 'dns';
  ASSERT pg_temp.t_claim('dns', 10) = '', 'S20 60 seconds give 30 questions, too few for a claim';
  ASSERT (SELECT dwdb.question_allowance || '|' || (dwdb.refilled_at = now())::text FROM domain_watch_dns_bucket AS dwdb WHERE dwdb.registered_domain = 'bucket.example')
         = '30|true',
         'S20 the refused claim still keeps the refilled questions';
  ASSERT (SELECT dwl.not_before FROM domain_watch_lane AS dwl WHERE dwl.domain_name = 'b3.bucket.example' AND dwl.lane_name = 'dns') = now() + interval '20 seconds',
         'S20 a not_before that has come counts as no refusal, and the next refusal holds back the 20 seconds that the 10 missing questions take';

  UPDATE domain_watch_dns_bucket AS dwdb SET refilled_at = now() - interval '20 seconds' WHERE dwdb.registered_domain = 'bucket.example';
  ASSERT pg_temp.t_claim('dns', 10) = '', 'S20 a not_before after now() holds the domain back, though the bucket would pay';
  UPDATE domain_watch_lane AS dwl SET not_before = now() - interval '1 minute' WHERE dwl.domain_name = 'b3.bucket.example' AND dwl.lane_name = 'dns';
  ASSERT pg_temp.t_claim('dns', 10) = 'b3.bucket.example', 'S20 20 more seconds give 40 questions, exactly one claim';
  ASSERT (SELECT dwdb.question_allowance FROM domain_watch_dns_bucket AS dwdb WHERE dwdb.registered_domain = 'bucket.example') = 0,
         'S20 the claim took the 40 questions';

  UPDATE domain_watch_dns_bucket AS dwdb SET refilled_at = now() - interval '1 day' WHERE dwdb.registered_domain = 'bucket.example';
  UPDATE domain_watch_lane AS dwl SET claimed_until = NULL WHERE dwl.domain_name = 'b1.bucket.example' AND dwl.lane_name = 'dns';
  ASSERT pg_temp.t_claim('dns', 10) = 'b1.bucket.example', 'S20 a day refills the bucket';
  ASSERT (SELECT dwdb.question_allowance FROM domain_watch_dns_bucket AS dwdb WHERE dwdb.registered_domain = 'bucket.example') = 40,
         'S20 the bucket holds 80 at most, so one claim leaves 40';

  UPDATE domain_watch_dns_bucket AS dwdb SET refilled_at = now() + interval '10 seconds' WHERE dwdb.registered_domain = 'bucket.example';
  UPDATE domain_watch_lane AS dwl SET claimed_until = NULL WHERE dwl.domain_name = 'b2.bucket.example' AND dwl.lane_name = 'dns';
  ASSERT pg_temp.t_claim('dns', 10) = 'b2.bucket.example', 'S20 a refill time after now() takes no question away';
  ASSERT (SELECT dwdb.question_allowance || '|' || (dwdb.refilled_at = now() + interval '10 seconds')::text
            FROM domain_watch_dns_bucket AS dwdb WHERE dwdb.registered_domain = 'bucket.example')
         = '0|true',
         'S20 a refill time after now() stays where it is';
  ASSERT pg_temp.t_item_times() = item_times_before, 'S20 no claim and no refusal moved a time of an item';
END
$$;

SELECT pg_temp.t_item('b4.bucket.example', repeat('9c', 32), n.endpoint_name, now() - interval '1 hour', 'bucket.example')
  FROM (VALUES ('dns_lookup'), ('ssl_check'), ('whois_lookup')) AS n (endpoint_name);
UPDATE domain_watch_dns_bucket AS dwdb SET question_allowance = 0, refilled_at = now() WHERE dwdb.registered_domain = 'bucket.example';
DO $$
BEGIN
  ASSERT pg_temp.t_claim('dns', 10) = '', 'S20 the empty bucket refuses the dns row of b4';
  ASSERT pg_temp.t_claim('tls', 10) = 'b4.bucket.example', 'S20 the tls lane leases b4 though its bucket is empty';
  ASSERT pg_temp.t_claim('rdap_whois', 10) = 'b4.bucket.example', 'S20 the rdap_whois lane leases b4 though its bucket is empty';
  ASSERT (SELECT array_agg(dwl.lane_name || '=' || (dwl.claimed_until IS NOT NULL)::text || '/' || coalesce((dwl.not_before - now())::text, 'null')
                           ORDER BY dwl.lane_name)
            FROM domain_watch_lane AS dwl WHERE dwl.domain_name = 'b4.bucket.example')
         = '{dns=false/00:01:20,rdap_whois=true/null,tls=true/null}',
         'S20 the refusal holds back the dns row only, and the other lanes hold a lease';
  ASSERT (SELECT dwdb.question_allowance FROM domain_watch_dns_bucket AS dwdb WHERE dwdb.registered_domain = 'bucket.example') = 0,
         'S20 the tls and rdap_whois claims take no question';
END
$$;

SELECT pg_temp.t_reset();
SELECT pg_temp.t_watch('f' || n || '.flood.example', 'flood.example', now() - (7 - n) * interval '1 hour') FROM generate_series(1, 6) AS n;
SELECT pg_temp.t_watch('f7.flood.example', 'flood.example', now() + interval '1 hour');
SELECT pg_temp.t_watch('f8.flood.example', 'flood.example', now() - interval '7 hours', now() + interval '1 minute');
SELECT pg_temp.t_watch('calm.example',     'calm.example',  now() - interval '30 minutes');
INSERT INTO domain_watch_dns_bucket (registered_domain, question_allowance, refilled_at) VALUES ('flood.example', 0, now());
DO $$
DECLARE
  item_times_before text := pg_temp.t_item_times();
BEGIN
  ASSERT pg_temp.t_claim('dns', 4) = 'calm.example', 'S26 a claim passes over an empty bucket with six older domains and leases a domain of another bucket';
  ASSERT (SELECT array_agg(dwl.domain_name ORDER BY dwl.domain_name) FROM domain_watch_lane AS dwl
           WHERE dwl.lane_name = 'dns' AND dwl.claimed_until IS NULL AND dwl.not_before = now() + interval '80 seconds')
         = '{f1.flood.example,f2.flood.example,f3.flood.example,f4.flood.example,f5.flood.example,f6.flood.example}',
         'S26 each due flood domain holds no lease, and not_before holds it back the 80 seconds that 40 questions take';
  ASSERT (SELECT dwl.not_before IS NULL FROM domain_watch_lane AS dwl WHERE dwl.domain_name = 'f7.flood.example' AND dwl.lane_name = 'dns'),
         'S26 a flood domain that is not due is not held back';
  ASSERT (SELECT dwl.not_before IS NULL AND dwl.claimed_until = now() + interval '1 minute' FROM domain_watch_lane AS dwl WHERE dwl.domain_name = 'f8.flood.example' AND dwl.lane_name = 'dns'),
         'S26 a flood domain with a running lease keeps its lease and is not held back';
  ASSERT (SELECT dwl.claimed_until FROM domain_watch_lane AS dwl WHERE dwl.domain_name = 'calm.example' AND dwl.lane_name = 'dns') = now() + interval '300 seconds',
         'S26 the domain of the other bucket holds a lease';
  ASSERT (SELECT dwdb.question_allowance FROM domain_watch_dns_bucket AS dwdb WHERE dwdb.registered_domain = 'flood.example') = 0,
         'S26 the refusal takes no question';
  ASSERT pg_temp.t_item_times() = item_times_before, 'S26 the refusal moves no time of an item, so each flood domain keeps its place in line';
  ASSERT pg_temp.t_claim('dns', 4) = '', 'S26 the next claim finds no flood domain due';
END
$$;

SELECT pg_temp.t_reset();
SELECT pg_temp.t_watch('e1.flood.example', 'flood.example', now() - interval '3 hours', now() - interval '1 second');
SELECT pg_temp.t_watch('e2.flood.example', 'flood.example', now());
SELECT pg_temp.t_watch('e3.flood.example', 'flood.example', now() - interval '2 hours');
SELECT pg_temp.t_watch('e4.flood.example', 'flood.example', now() - interval '4 hours', now());
SELECT pg_temp.t_watch('e5.flood.example', 'flood.example', now() - interval '4 hours');
SELECT pg_temp.t_watch('e6.flood.example', 'flood.example', now() + interval '1 hour');
SELECT pg_temp.t_item('e7.flood.example', repeat('9c', 32), 'ssl_check', now() - interval '4 hours', 'flood.example');
SELECT pg_temp.t_watch('calm.example',     'calm.example',  now() - interval '30 minutes');
UPDATE domain_watch_lane SET not_before = now() + interval '1 hour' WHERE domain_name = 'e5.flood.example' AND lane_name = 'dns';
UPDATE domain_watch_lane SET not_before = now() WHERE domain_name = 'e3.flood.example' AND lane_name = 'dns';
INSERT INTO domain_watch_dns_bucket (registered_domain, question_allowance, refilled_at) VALUES ('flood.example', 0, now());
DO $$
BEGIN
  ASSERT pg_temp.t_claim('dns', 4) = 'calm.example', 'S26 a refused bucket whose oldest due domain had a lease that ended does not hold back calm.example';
  ASSERT (SELECT array_agg(dwl.domain_name ORDER BY dwl.domain_name) FROM domain_watch_lane AS dwl WHERE dwl.lane_name = 'dns' AND dwl.not_before = now() + interval '80 seconds')
         = '{e1.flood.example,e2.flood.example,e3.flood.example}',
         'S26 the refusal holds back a sibling whose lease ended, one due at now() and one whose not_before is now()';
  ASSERT (SELECT array_agg(dwl.domain_name || '=' || coalesce((dwl.not_before - now())::text, 'null') ORDER BY dwl.domain_name) FROM domain_watch_lane AS dwl
           WHERE dwl.lane_name = 'dns' AND dwl.domain_name IN ('e4.flood.example', 'e5.flood.example', 'e6.flood.example', 'e7.flood.example'))
         = '{e4.flood.example=null,e5.flood.example=01:00:00,e6.flood.example=null}',
         'S26 the refusal holds back no sibling with a lease that ends at now(), a later not_before or no due item, and e7 has no dns lane row';
  ASSERT (SELECT array_agg(dwl.lane_name || '=' || coalesce((dwl.not_before - now())::text, 'null')) FROM domain_watch_lane AS dwl
           WHERE dwl.domain_name = 'e7.flood.example')
         = '{tls=null}',
         'S26 the refusal holds back no row of another lane: the tls row of a sibling with only a due ssl_check item keeps no not_before';
END
$$;

SELECT pg_temp.t_reset();
SELECT pg_temp.t_watch('cap' || n || '.example', 'cap' || n || '.example', now() - interval '2 hours' + n * interval '1 second') FROM generate_series(1, 64) AS n;
INSERT INTO domain_watch_dns_bucket (registered_domain, question_allowance, refilled_at) SELECT dw.registered_domain, 0, now() FROM domain_watch AS dw;
SELECT pg_temp.t_add_dns('pay.example');
DO $$
BEGIN
  ASSERT pg_temp.t_claim('dns', 4) = 'pay.example', 'S26 a claim that refuses 64 buckets still leases the next domain';
  ASSERT (SELECT count(*) FROM domain_watch_lane AS dwl WHERE dwl.lane_name = 'dns' AND dwl.not_before = now() + interval '80 seconds') = 64,
         'S26 the claim held back the 64 refused domains';
END
$$;

SELECT pg_temp.t_reset();
SELECT pg_temp.t_watch('cap' || n || '.example', 'cap' || n || '.example', now() - interval '2 hours' + n * interval '1 second') FROM generate_series(1, 65) AS n;
INSERT INTO domain_watch_dns_bucket (registered_domain, question_allowance, refilled_at) SELECT dw.registered_domain, 0, now() FROM domain_watch AS dw;
SELECT pg_temp.t_add_dns('pay.example');
DO $$
BEGIN
  ASSERT pg_temp.t_claim('dns', 4) = '', 'S26 a claim with 65 refused buckets ahead stops after the 64th and leases none';
  ASSERT (SELECT count(*) FROM domain_watch_lane AS dwl WHERE dwl.lane_name = 'dns' AND dwl.not_before = now() + interval '80 seconds') = 64,
         'S26 the claim held back 64 refused domains only';
  ASSERT (SELECT dwl.not_before IS NULL FROM domain_watch_lane AS dwl WHERE dwl.domain_name = 'cap65.example' AND dwl.lane_name = 'dns'),
         'S26 the claim stops at the 65th bucket without refusing it, so its domain is not held back';
  ASSERT (SELECT dwl.claimed_until IS NULL FROM domain_watch_lane AS dwl WHERE dwl.domain_name = 'pay.example' AND dwl.lane_name = 'dns'), 'S26 pay.example holds no lease yet';
  ASSERT pg_temp.t_claim('dns', 4) = 'pay.example', 'S26 the next claim refuses the 65th bucket and leases pay.example';
END
$$;

SELECT pg_temp.t_reset();
SELECT pg_temp.t_watch('m' || n || '.many.example', 'many.example', now() - interval '2 hours' + n * interval '1 second') FROM generate_series(1, 65) AS n;
INSERT INTO domain_watch_dns_bucket (registered_domain, question_allowance, refilled_at) VALUES ('many.example', 0, now());
SELECT pg_temp.t_add_dns('pay.example');
DO $$
BEGIN
  ASSERT pg_temp.t_claim('dns', 4) = 'pay.example', 'S26 65 due domains of one empty bucket are one refusal, so the claim leases pay.example';
  ASSERT (SELECT count(*) FROM domain_watch_lane AS dwl WHERE dwl.lane_name = 'dns' AND dwl.not_before = now() + interval '80 seconds') = 65,
         'S26 the one refusal held back all 65 domains';
END
$$;

SELECT pg_temp.t_reset();
SELECT pg_temp.t_add_dns('r1.settle.example', 'settle.example');
SELECT pg_temp.t_add_dns('other.example');
INSERT INTO domain_watch_dns_bucket (registered_domain, question_allowance, refilled_at) VALUES
  ('settle.example', 10, now() - interval '5 seconds'),
  ('other.example',  10, now() - interval '5 seconds');
DO $$
DECLARE
  before_call text;
BEGIN
  ASSERT api.fn_domain_watch_dns_scan_cost() = 40, 'S28 a scan costs 40 questions';
  ASSERT api.fn_domain_watch_dns_bucket_burst() = 80, 'S28 a bucket holds 80 questions at most';

  PERFORM pg_temp.t_record_dns('r1.settle.example', p_ns => 'ns-a', p_question_count => 25);
  ASSERT (SELECT dwdb.question_allowance || '|' || (dwdb.refilled_at = now() - interval '5 seconds')::text
            FROM domain_watch_dns_bucket AS dwdb WHERE dwdb.registered_domain = 'settle.example') = '25|true',
         'S28 a scan of 25 questions gives 15 back, and the refill time stays';
  ASSERT (SELECT dwdb.question_allowance FROM domain_watch_dns_bucket AS dwdb WHERE dwdb.registered_domain = 'other.example') = 10,
         'S28 the bucket of another registered domain stays';

  UPDATE domain_watch_dns_bucket AS dwdb SET question_allowance = 70 WHERE dwdb.registered_domain = 'settle.example';
  PERFORM pg_temp.t_record_dns('r1.settle.example', p_ns => 'ns-a', p_question_count => 0);
  ASSERT (SELECT dwdb.question_allowance FROM domain_watch_dns_bucket AS dwdb WHERE dwdb.registered_domain = 'settle.example') = 80,
         'S28 the refund stops at 80';

  UPDATE domain_watch_dns_bucket AS dwdb SET question_allowance = 10 WHERE dwdb.registered_domain = 'settle.example';
  PERFORM pg_temp.t_record_dns('r1.settle.example', p_ns => 'ns-a', p_question_count => 61);
  ASSERT (SELECT dwdb.question_allowance FROM domain_watch_dns_bucket AS dwdb WHERE dwdb.registered_domain = 'settle.example') = -11,
         'S28 a scan of 61 questions takes 21 more, and the bucket goes below 0';

  UPDATE domain_watch_lane AS dwl SET claimed_until = now() + interval '10 minutes', claimed_at = now() + interval '2 days'
   WHERE dwl.domain_name = 'r1.settle.example' AND dwl.lane_name = 'dns';
  before_call := pg_temp.t_snapshot('r1.settle.example');
  ASSERT api.fn_domain_watch_record_dns('r1.settle.example', now() + interval '9 minutes', NULL, NULL, 'ns-b', pg_temp.t_sha256('ns-b'),
                                        NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 30) = 0,
         'S28 a lost lease answers 0';
  ASSERT pg_temp.t_snapshot('r1.settle.example') = before_call, 'S28 a lost lease writes no value';
  ASSERT (SELECT dwdb.question_allowance FROM domain_watch_dns_bucket AS dwdb WHERE dwdb.registered_domain = 'settle.example') = -1,
         'S28 a lost lease still settles: a scan of 30 questions gives 10 back';

  ASSERT api.fn_domain_watch_record_dns('gone.settle.example', now(), NULL, NULL, 'ns-b', pg_temp.t_sha256('ns-b'),
                                        NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0) = 0,
         'S28 a domain with no row answers 0';
  ASSERT (SELECT array_agg(dwdb.registered_domain || '=' || dwdb.question_allowance ORDER BY dwdb.registered_domain) FROM domain_watch_dns_bucket AS dwdb)
         = '{other.example=10,settle.example=-1}',
         'S28 a domain with no row settles no bucket';

  BEGIN
    PERFORM api.fn_domain_watch_record_dns('r1.settle.example', now(), NULL, NULL, NULL, NULL, NULL, NULL,
                                           NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    ASSERT false, 'S28 a NULL question count is refused';
  EXCEPTION WHEN invalid_parameter_value THEN
    ASSERT SQLERRM LIKE '%question count%', 'S28 the refusal names the question count';
  END;
  BEGIN
    PERFORM api.fn_domain_watch_record_dns('r1.settle.example', now(), NULL, NULL, NULL, NULL, NULL, NULL,
                                           NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, -1);
    ASSERT false, 'S28 a question count of -1 is refused';
  EXCEPTION WHEN invalid_parameter_value THEN
    ASSERT SQLERRM LIKE '%question count%', 'S28 the refusal of -1 names the question count';
  END;
  ASSERT (SELECT dwdb.question_allowance FROM domain_watch_dns_bucket AS dwdb WHERE dwdb.registered_domain = 'settle.example') = -1,
         'S28 a refused count settles nothing';
END
$$;

SELECT pg_temp.t_reset();
SELECT pg_temp.t_watch('e.tie.example', 'tie.example', now() - interval '1 hour', NULL, now() - interval '1 hour');
SELECT pg_temp.t_watch('a.tie.example', 'tie.example', now() - interval '1 hour', NULL, now() - interval '1 hour');
SELECT pg_temp.t_watch('b.tie.example', 'tie.example', now() - interval '1 hour', NULL, now() - interval '2 hours');
SELECT pg_temp.t_watch('d.tie.example', 'tie.example', now() - interval '1 hour');
SELECT pg_temp.t_watch('c.tie.example', 'tie.example', now() - interval '1 hour');
SELECT pg_temp.t_watch('z.tie.example', 'tie.example', now() - interval '2 hours', NULL, now());
SELECT pg_temp.t_watch('y.tie.example', 'tie.example', now() - interval '30 minutes', NULL, now());
SELECT pg_temp.t_item('y.tie.example', repeat('a1', 32), 'dns_lookup', now() - interval '3 hours', 'tie.example');
DO $$
DECLARE
  claimed_names text[] := '{}';
BEGIN
  FOR i IN 1 .. 7 LOOP
    UPDATE domain_watch_dns_bucket AS dwdb SET question_allowance = 80 WHERE dwdb.registered_domain = 'tie.example';
    claimed_names := claimed_names || pg_temp.t_claim('dns', 1);
  END LOOP;
  ASSERT claimed_names = '{y.tie.example,z.tie.example,c.tie.example,d.tie.example,b.tie.example,a.tie.example,e.tie.example}',
         'S29 the oldest due item first; on a tie the never-scanned domain, then the older scan, then the smaller name: ' || claimed_names::text;
END
$$;

SELECT pg_temp.t_reset();
SELECT pg_temp.t_watch('v.churn.example', 'churn.example', now() - interval '1 hour', NULL, now() - interval '1 day');
INSERT INTO domain_watch_dns_bucket (registered_domain, question_allowance, refilled_at) VALUES ('churn.example', 0, now());
DO $$
BEGIN
  ASSERT pg_temp.t_claim('dns', 10) = '', 'S31 the empty bucket refuses v';
  ASSERT (SELECT dwl.not_before = now() + interval '80 seconds' FROM domain_watch_lane AS dwl WHERE dwl.domain_name = 'v.churn.example' AND dwl.lane_name = 'dns')
     AND pg_temp.t_next_scan('v.churn.example') = now() - interval '1 hour',
         'S31 the refusal holds v back and leaves the time of its item';

  PERFORM pg_temp.t_watch('n1.churn.example', 'churn.example', now() - interval '40 seconds');
  UPDATE domain_watch_lane AS dwl SET not_before = now() WHERE dwl.domain_name = 'v.churn.example' AND dwl.lane_name = 'dns';
  UPDATE domain_watch_dns_bucket AS dwdb SET refilled_at = now() - interval '80 seconds' WHERE dwdb.registered_domain = 'churn.example';
  ASSERT pg_temp.t_claim('dns', 10) = 'v.churn.example', 'S31 the bucket pays one scan, and v goes before the name added while it waited';
  ASSERT (SELECT dwl.not_before = now() + interval '80 seconds' FROM domain_watch_lane AS dwl WHERE dwl.domain_name = 'n1.churn.example' AND dwl.lane_name = 'dns')
     AND pg_temp.t_next_scan('n1.churn.example') = now() - interval '40 seconds',
         'S31 the empty bucket then refuses n1, and n1 keeps its place in line';

  PERFORM pg_temp.t_record_dns('v.churn.example', p_ns => 'ns-v');
  ASSERT pg_temp.t_next_scan('v.churn.example') = api.fn_domain_watch_next_daily_scan_at('v.churn.example'),
         'S31 the record moves the item of v to its next scan';
END
$$;

SELECT pg_temp.t_reset();
SELECT pg_temp.t_add_dns('late.example');
INSERT INTO domain_watch_dns_bucket (registered_domain, question_allowance, refilled_at) VALUES ('late.example', 0, now());
DO $$
DECLARE
  lease_a     timestamptz := now() - interval '1 second';
  before_call text;
BEGIN
  UPDATE domain_watch_lane AS dwl SET claimed_until = lease_a WHERE dwl.domain_name = 'late.example' AND dwl.lane_name = 'dns';
  PERFORM pg_temp.t_record_dns('late.example', p_ns => 'ns-b');
  ASSERT (SELECT dwl.claimed_until IS NULL FROM domain_watch_lane AS dwl WHERE dwl.domain_name = 'late.example' AND dwl.lane_name = 'dns'),
         'S32 the record of B ends the lease';
  ASSERT (SELECT dwdb.question_allowance FROM domain_watch_dns_bucket AS dwdb WHERE dwdb.registered_domain = 'late.example') = 0,
         'S32 B asked its 40 questions, so the bucket stays at 0';

  before_call := pg_temp.t_snapshot('late.example');
  ASSERT api.fn_domain_watch_record_dns('late.example', lease_a, NULL, NULL, 'ns-a', pg_temp.t_sha256('ns-a'),
                                        NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 10) = 0,
         'S32 the late record of A answers 0';
  ASSERT pg_temp.t_snapshot('late.example') = before_call, 'S32 the late record of A writes no value';
  ASSERT (SELECT dwdb.question_allowance FROM domain_watch_dns_bucket AS dwdb WHERE dwdb.registered_domain = 'late.example') = 30,
         'S32 the late record of A gives back the 30 questions its scan did not ask';
END
$$;

SELECT pg_temp.t_reset();
SELECT pg_temp.t_item('tls-only.example', repeat('9c', 32), 'ssl_check', now() - interval '3 hours');
SELECT pg_temp.t_item('mixed.example', repeat('9c', 32), 'ssl_check', now() - interval '3 hours');
SELECT pg_temp.t_item('mixed.example', repeat('9c', 32), 'dns_lookup', now() + interval '1 hour');
INSERT INTO domain_watch (domain_name, registered_domain) VALUES ('none.example', 'none.example'), ('stale.example', 'stale.example');
INSERT INTO domain_watch_lane (domain_name, lane_name) VALUES ('stale.example', 'dns');
SELECT pg_temp.t_item('dns-only.example', repeat('9c', 32), 'dns_lookup', now() - interval '1 hour');
INSERT INTO domain_watch_dns_bucket (registered_domain, question_allowance, refilled_at) VALUES ('tls-only.example', 10, now());
DO $$
BEGIN
  ASSERT pg_temp.t_claim('dns', 10) = 'dns-only.example',
         'S34 the claim leases the name of a due dns_lookup item, and passes over the others';
  ASSERT (SELECT array_agg(dwl.domain_name || '=' || (dwl.claimed_until IS NOT NULL)::text ORDER BY dwl.domain_name)
            FROM domain_watch_lane AS dwl WHERE dwl.lane_name = 'dns')
         = '{dns-only.example=true,mixed.example=false,stale.example=false}',
         'S34 the names the claim passes over hold no lease, and only a name a dns_lookup item named has a dns lane row';
  ASSERT NOT EXISTS (SELECT 1 FROM domain_watch_lane AS dwl WHERE dwl.lane_name = 'dns' AND dwl.domain_name IN ('tls-only.example', 'none.example')),
         'S34 a name with no dns_lookup item has no dns lane row';
  ASSERT api.fn_domain_watch_record_dns('tls-only.example', now() + interval '5 minutes', NULL, NULL, 'ns-a', pg_temp.t_sha256('ns-a'),
                                        NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0) = 0,
         'S34 a DNS record of a name with no dns lane row answers 0';
  ASSERT (SELECT dwdb.question_allowance FROM domain_watch_dns_bucket AS dwdb WHERE dwdb.registered_domain = 'tls-only.example') = 10,
         'S34 a DNS record of a name with no dns lane row settles no bucket';
  ASSERT NOT EXISTS (SELECT 1 FROM domain_change_event AS dce WHERE dce.domain_name = 'tls-only.example'),
         'S34 a DNS record of a name with no dns lane row writes no event';
END
$$;

SELECT pg_temp.t_reset();
SELECT pg_temp.t_add_dns('purge.example');
TRUNCATE domain_change_event, watchlist_event_ref;
INSERT INTO domain_change_event (event_id, domain_name, event_type, changed_at) VALUES
  (6, 'purge.example', 'ns_changed', now() - interval '95 days'),
  (1, 'purge.example', 'ns_changed', now() - interval '200 days'),
  (2, 'purge.example', 'ns_changed', now() - interval '91 days'),
  (3, 'purge.example', 'ns_changed', now() - interval '90 days 1 second'),
  (4, 'purge.example', 'ns_changed', now() - interval '90 days'),
  (5, 'purge.example', 'ns_changed', now() - interval '89 days'),
  (7, 'purge.example', 'ns_changed', now());
INSERT INTO watchlist_event_ref (api_key_id, item_id, event_id)
SELECT wid.api_key_id, wid.item_id, e.event_id
  FROM watchlist_item_domain AS wid CROSS JOIN unnest(ARRAY[1, 2, 3, 4, 5, 6, 7, 99]) AS e (event_id)
 WHERE wid.domain_name = 'purge.example';
DO $$
BEGIN
  ASSERT api.fn_domain_change_event_purge(NULL) IS NULL, 'S21 a NULL limit answers NULL';
  ASSERT (SELECT count(*) FROM domain_change_event) = 7 AND (SELECT count(*) FROM watchlist_event_ref) = 8, 'S21 a NULL limit deletes nothing';
  ASSERT api.fn_domain_change_event_purge(2) = 2, 'S21 a limit of 2 deletes 2 of the 4 old events';
  ASSERT (SELECT array_agg(dce.event_id ORDER BY dce.event_id) FROM domain_change_event AS dce) = '{3,4,5,6,7}',
         'S21 the first call deletes the two smallest event_ids';
  ASSERT (SELECT array_agg(wer.event_id ORDER BY wer.event_id) FROM watchlist_event_ref AS wer) = '{3,4,5,6,7,99}',
         'S21 the first call deletes the refs of the two events it deletes, and no other ref';
  ASSERT (SELECT ps.max_purged_event_id FROM change_event_purge_state AS ps WHERE ps.event_table_name = 'domain_change_event') = 2, 'S21 max_purged_event_id rises to 2';
  UPDATE change_event_purge_state SET max_purged_event_id = 5 WHERE event_table_name = 'domain_change_event';
  ASSERT api.fn_domain_change_event_purge(2) = 2, 'S21 the next call deletes the last two old events';
  ASSERT (SELECT array_agg(dce.event_id ORDER BY dce.event_id) FROM domain_change_event AS dce) = '{4,5,7}',
         'S21 events of exactly 90 days and younger stay';
  ASSERT (SELECT array_agg(wer.event_id ORDER BY wer.event_id) FROM watchlist_event_ref AS wer) = '{4,5,7,99}',
         'S21 the refs of the events that stay stay too';
  ASSERT (SELECT ps.max_purged_event_id FROM change_event_purge_state AS ps WHERE ps.event_table_name = 'domain_change_event') = 6,
         'S21 max_purged_event_id rises to the largest event_id deleted';
  ASSERT api.fn_domain_change_event_purge(2) = 0, 'S21 a call with no old event deletes none';
  ASSERT (SELECT count(*) FROM watchlist_event_ref) = 4, 'S21 a call with no old event deletes no ref';
  UPDATE change_event_purge_state SET max_purged_event_id = 100 WHERE event_table_name = 'domain_change_event';
  UPDATE domain_change_event SET changed_at = now() - interval '91 days' WHERE event_id = 4;
  ASSERT api.fn_domain_change_event_purge(10) = 1, 'S21 the call deletes event 4';
  ASSERT (SELECT ps.max_purged_event_id FROM change_event_purge_state AS ps WHERE ps.event_table_name = 'domain_change_event') = 100,
         'S21 the purge never lowers max_purged_event_id';
  ASSERT (SELECT ps.max_purged_event_id FROM change_event_purge_state AS ps WHERE ps.event_table_name = 'cve_change_event') = 0,
         'S21 the purge leaves the purge state of cve_change_event alone';
  DELETE FROM watchlist_event_ref AS wer WHERE wer.event_id = 99;
END
$$;

SELECT pg_temp.t_cve_event() FROM generate_series(1, 3);
DO $$
DECLARE
  cve_max_id bigint := (SELECT max(cce.event_id) FROM cve_change_event AS cce);
BEGIN
  UPDATE change_event_purge_state SET max_purged_event_id = 0 WHERE event_table_name = 'domain_change_event';
  ASSERT cve_max_id > 7, 'S22 the CVE head is above the domain events of S21';
  ASSERT api.fn_watchlist_event_max_id() = cve_max_id, 'S22 with every domain event below the CVE head, the head is the CVE head';
  INSERT INTO domain_change_event (event_id, domain_name, event_type) VALUES (cve_max_id + 10, 'purge.example', 'ns_changed');
  ASSERT api.fn_domain_change_event_max_id() = cve_max_id + 10, 'S22 the largest domain event_id is the largest one in domain_change_event';
  ASSERT api.fn_watchlist_event_max_id() = cve_max_id + 10, 'S22 a larger domain event raises the watch list head';
  UPDATE change_event_purge_state SET max_purged_event_id = cve_max_id + 20 WHERE event_table_name = 'domain_change_event';
  ASSERT api.fn_domain_change_event_max_id() = cve_max_id + 20, 'S22 the largest domain event_id is max_purged_event_id when it is larger';
  ASSERT api.fn_watchlist_event_max_id() = cve_max_id + 20, 'S22 a larger domain max_purged_event_id raises the watch list head too';
  UPDATE change_event_purge_state SET max_purged_event_id = 0 WHERE event_table_name = 'domain_change_event';
  DELETE FROM change_event_purge_state WHERE event_table_name = 'domain_change_event';
  ASSERT api.fn_domain_change_event_max_id() IS NULL, 'S22 the largest domain event_id is NULL without a purge state row';
  ASSERT api.fn_watchlist_event_max_id() = cve_max_id, 'S22 without a domain purge state row the head is the CVE head';
  INSERT INTO change_event_purge_state (event_table_name) VALUES ('domain_change_event');
  DELETE FROM domain_change_event AS dce WHERE dce.event_id = cve_max_id + 10;
END
$$;

SELECT pg_temp.t_reset();
INSERT INTO domain_watch (domain_name, registered_domain) VALUES ('g3.example', 'g3.example'), ('g2.example', 'g2.example');
SELECT pg_temp.t_item('g1.example', repeat('a1', 32), 'dns_lookup');
SELECT pg_temp.t_item('g4.example', repeat('a1', 32), 'ssl_check');
INSERT INTO domain_change_event (domain_name, event_type) VALUES ('g1.example', 'ns_changed'), ('g2.example', 'ns_changed');
DO $$
BEGIN
  ASSERT api.fn_domain_watch_purge_unwatched(NULL) IS NULL, 'S23 a NULL limit answers NULL';
  ASSERT (SELECT count(*) FROM domain_watch) = 4, 'S23 a NULL limit deletes nothing';
  ASSERT api.fn_domain_watch_purge_unwatched(1) = 1, 'S23 a limit of 1 deletes one domain';
  ASSERT (SELECT array_agg(dw.domain_name ORDER BY dw.domain_name) FROM domain_watch AS dw) = '{g1.example,g3.example,g4.example}',
         'S23 the first call deletes the smallest unwatched domain';
  ASSERT NOT EXISTS (SELECT 1 FROM domain_change_event AS dce WHERE dce.domain_name = 'g2.example'),
         'S23 the events of a deleted domain go with it';
  ASSERT api.fn_domain_watch_purge_unwatched(10) = 1, 'S23 the next call deletes the other unwatched domain';
  ASSERT api.fn_domain_watch_purge_unwatched(10) = 0, 'S23 a call with no unwatched domain deletes none';
  ASSERT (SELECT array_agg(dw.domain_name ORDER BY dw.domain_name) FROM domain_watch AS dw) = '{g1.example,g4.example}',
         'S23 a domain that a dns_lookup or an ssl_check item names stays';
  ASSERT EXISTS (SELECT 1 FROM domain_change_event AS dce WHERE dce.domain_name = 'g1.example'),
         'S23 a watched domain keeps its events';
  ASSERT pg_temp.t_refused_by($q$DELETE FROM domain_watch WHERE domain_name = 'g1.example'$q$) = 'watchlist_item_domain_domain_name_fkey',
         'S23 a watched domain cannot be deleted';
END
$$;

INSERT INTO domain_watch (domain_name, registered_domain) VALUES ('u2.example', 'u2.example'), ('u1.example', 'u1.example');
DO $$
DECLARE
  newest_event_id  bigint;
  watched_event_id bigint;
BEGIN
  UPDATE change_event_purge_state SET max_unwatched_event_id = 0 WHERE event_table_name = 'domain_change_event';
  INSERT INTO domain_change_event (domain_name, event_type) VALUES ('u2.example', 'ns_changed');
  INSERT INTO domain_change_event (domain_name, event_type) VALUES ('u1.example', 'ns_changed')
    RETURNING event_id INTO newest_event_id;
  ASSERT api.fn_watchlist_event_max_id() = newest_event_id, 'S30 the event of u1 is the head';
  ASSERT api.fn_domain_watch_purge_unwatched(1) = 1, 'S30 the first call deletes one domain';
  ASSERT NOT EXISTS (SELECT 1 FROM domain_change_event AS dce WHERE dce.event_id = newest_event_id),
         'S30 the first call deletes u1 with its event';
  ASSERT (SELECT ps.max_unwatched_event_id FROM change_event_purge_state AS ps WHERE ps.event_table_name = 'domain_change_event') = newest_event_id,
         'S30 max_unwatched_event_id is the largest event_id the call deleted';
  ASSERT api.fn_domain_change_event_max_id() = newest_event_id, 'S30 the largest domain event_id is max_unwatched_event_id when it is larger';
  ASSERT api.fn_watchlist_event_max_id() = newest_event_id, 'S30 the head does not fall when the newest event goes with its domain';
  INSERT INTO domain_change_event (domain_name, event_type) VALUES ('g1.example', 'mx_changed')
    RETURNING event_id INTO watched_event_id;
  ASSERT api.fn_domain_watch_purge_unwatched(1) = 1, 'S30 the second call deletes one domain';
  ASSERT NOT EXISTS (SELECT 1 FROM domain_watch AS dw WHERE dw.domain_name = 'u2.example'),
         'S30 the second call deletes u2 with its smaller event';
  ASSERT (SELECT ps.max_unwatched_event_id FROM change_event_purge_state AS ps WHERE ps.event_table_name = 'domain_change_event') = newest_event_id,
         'S30 a call that deletes a smaller event keeps max_unwatched_event_id, and counts no event of a watched domain';
  DELETE FROM domain_change_event AS dce WHERE dce.event_id = watched_event_id;
  UPDATE change_event_purge_state SET max_unwatched_event_id = 0 WHERE event_table_name = 'domain_change_event';
END
$$;

DELETE FROM domain_watch_dns_bucket;
INSERT INTO domain_watch (domain_name, registered_domain) VALUES ('gone.example', 'gone.example');
INSERT INTO domain_watch_dns_bucket (registered_domain, question_allowance, refilled_at) VALUES
  ('idle-b.example', 0, now() - interval '1 day 1 second'),
  ('idle-a.example', 0, now() - interval '2 days'),
  ('day.example',    0, now() - interval '1 day'),
  ('g1.example',     0, now() - interval '2 days'),
  ('gone.example',   0, now() - interval '2 days');
DO $$
BEGIN
  ASSERT api.fn_domain_watch_purge_unwatched(1) = 1, 'S27 the first call deletes gone.example and counts no bucket';
  ASSERT (SELECT array_agg(dwdb.registered_domain ORDER BY dwdb.registered_domain) FROM domain_watch_dns_bucket AS dwdb)
         = '{day.example,g1.example,gone.example,idle-b.example}',
         'S27 the first call deletes only the smallest idle bucket, and gone.example keeps its bucket';
  ASSERT api.fn_domain_watch_purge_unwatched(10) = 0, 'S27 the next call deletes no domain';
  ASSERT (SELECT array_agg(dwdb.registered_domain ORDER BY dwdb.registered_domain) FROM domain_watch_dns_bucket AS dwdb)
         = '{day.example,g1.example}',
         'S27 a bucket refilled exactly a day ago stays, and so does the bucket of a registered domain with a domain left';
END
$$;

DO $$
DECLARE
  key_id      integer := (SELECT ak.id FROM api_keys AS ak WHERE ak.key_hash = repeat('a1', 32));
  other_key   integer := (SELECT ak.id FROM api_keys AS ak WHERE ak.key_hash = repeat('b1', 32));
  g1_item_id  bigint  := (SELECT wid.item_id FROM watchlist_item_domain AS wid WHERE wid.domain_name = 'g1.example');
  parent      text    := 'WITH p AS (INSERT INTO watchlist_item (api_key_id, endpoint_name) VALUES (' || key_id || ', %L) RETURNING item_id, api_key_id) ';
  domain_row  text    := 'INSERT INTO watchlist_item_domain (item_id, api_key_id, endpoint_name, domain_name, registered_domain, next_scan_at) '
                         || 'SELECT p.item_id, %s, %L, %L, %L, %s FROM p';
  cve_row     text    := 'INSERT INTO watchlist_item_cve (item_id, api_key_id, endpoint_name, last_event_id_before_add, cve_id) '
                         || 'SELECT p.item_id, p.api_key_id, %L, 0, ''CVE-2011-0091'' FROM p';
BEGIN
  ASSERT pg_temp.t_refused_by(format('INSERT INTO watchlist_item (api_key_id, endpoint_name) VALUES (%s, %L)', key_id, 'dns_takeover_check'))
         = 'watchlist_item_endpoint_name_known',
         'S24 a dns_takeover_check item is refused';
  ASSERT pg_temp.t_refused_by(format('INSERT INTO watchlist_item (api_key_id, endpoint_name) VALUES (%s, %L)', key_id, 'tls_check'))
         = 'watchlist_item_endpoint_name_known',
         'S24 a tls_check item is refused';
  ASSERT pg_temp.t_refused_by(format(parent, 'dns_lookup') || format(domain_row, 'p.api_key_id', 'dns_lookup', 'g4.example', 'g4.example', 'now()'))
         = 'accepted',
         'S24 a dns_lookup item of a watched name with its child row is accepted';
  ASSERT pg_temp.t_refused_by(format(parent, 'ssl_check') || format(domain_row, 'p.api_key_id', 'ssl_check', 'g1.example', 'g1.example', 'now()'))
         = 'accepted',
         'S24 an ssl_check item with its child row is accepted';
  ASSERT pg_temp.t_refused_by(format(parent, 'dns_lookup') || format(domain_row, 'p.api_key_id', 'ssl_check', 'g1.example', 'g1.example', 'now()'))
         = 'watchlist_item_domain_item_fkey',
         'S24 a child row of another endpoint than its item is refused';
  ASSERT pg_temp.t_refused_by(format(parent, 'dns_lookup') || format(domain_row, other_key::text, 'dns_lookup', 'g4.example', 'g4.example', 'now()'))
         = 'watchlist_item_domain_item_fkey',
         'S24 a child row of another key than its item is refused';
  ASSERT pg_temp.t_refused_by(format(parent, 'cve_lookup') || format(domain_row, 'p.api_key_id', 'cve_lookup', 'g4.example', 'g4.example', 'now()'))
         = 'watchlist_item_domain_endpoint_name_known',
         'S24 a domain child row of a CVE endpoint is refused';
  ASSERT pg_temp.t_refused_by(format(parent, 'dns_lookup') || format(cve_row, 'dns_lookup')) = 'watchlist_item_cve_endpoint_name_known',
         'S24 a CVE child row of a dns_lookup item is refused';
  ASSERT pg_temp.t_refused_by(format(parent, 'ssl_check') || format(cve_row, 'ssl_check')) = 'watchlist_item_cve_endpoint_name_known',
         'S24 a CVE child row of an ssl_check item is refused';
  ASSERT pg_temp.t_refused_by(format(parent, 'dns_lookup') || format(domain_row, 'p.api_key_id', 'dns_lookup', 'unwatched.example', 'unwatched.example', 'now()'))
         = 'watchlist_item_domain_domain_name_fkey',
         'S24 a domain item of a name with no domain_watch row is refused';
  ASSERT pg_temp.t_refused_by(format(parent, 'dns_lookup') || format(domain_row, 'p.api_key_id', 'dns_lookup', 'g1.example', 'g1.example', 'now()'))
         = 'watchlist_item_domain_key_name_unique',
         'S24 a second dns_lookup item of one name for one key is refused';
  ASSERT pg_temp.t_refused_by(format(parent, 'dns_lookup') || format(domain_row, 'p.api_key_id', 'dns_lookup', 'g4.example', 'G4.example', 'now()'))
         = 'watchlist_item_domain_registered_domain_form',
         'S24 a registered domain with an upper case letter is refused';
  ASSERT pg_temp.t_refused_by(format(parent, 'dns_lookup') || format(domain_row, 'p.api_key_id', 'dns_lookup', 'g4.example', '', 'now()'))
         = 'watchlist_item_domain_registered_domain_form',
         'S24 an empty registered domain is refused';
  ASSERT pg_temp.t_refused_by(format(parent, 'dns_lookup') || format(domain_row, 'p.api_key_id', 'dns_lookup', 'g4.example', repeat('é', 127), 'now()'))
         = 'watchlist_item_domain_registered_domain_form',
         'S24 a registered domain of 254 bytes is refused';
  ASSERT pg_temp.t_refused_by(format(parent, 'dns_lookup') || format(domain_row, 'p.api_key_id', 'dns_lookup', 'g4.example', repeat('a', 253), 'now()'))
         = 'accepted',
         'S24 a registered domain of 253 bytes is accepted';
  ASSERT pg_temp.t_refused_by(format(parent, 'dns_lookup') || format(domain_row, 'p.api_key_id', 'dns_lookup', 'g4.example', 'g4.example', 'NULL::timestamptz'))
         = '23502',
         'S24 a domain item without a next scan is refused';
  ASSERT pg_temp.t_refused_by(format('INSERT INTO watchlist_event_ref (api_key_id, item_id, event_id) VALUES (%s, %s, 1)', other_key, g1_item_id))
         = 'watchlist_event_ref_item_fkey',
         'S24 a ref with another key than its item is refused';
  ASSERT pg_temp.t_refused_by(format('INSERT INTO watchlist_event_ref (api_key_id, item_id, event_id) VALUES (%s, %s, 1)', key_id, g1_item_id))
         = 'accepted',
         'S24 a ref with the key of its item is accepted, and needs no event row';
END
$$;

SELECT pg_temp.t_add_dns('chk.example');
DO $$
DECLARE
  chk_item_id  bigint := (SELECT wid.item_id FROM watchlist_item_domain AS wid WHERE wid.domain_name = 'chk.example');
  watch_insert text   := 'INSERT INTO domain_watch (domain_name, registered_domain) VALUES (%L, %L)';
  value_insert text;
  event_insert text   := 'INSERT INTO domain_change_event (domain_name, event_type, degraded_email_check_id) VALUES (''chk.example'', %L, %L)';
  good_sha256  text   := repeat('0123456789abcdef', 4);
  value_kind   text;
  event_type   text;
BEGIN
  value_insert := 'INSERT INTO watchlist_item_domain_value (item_id, value_kind, current_value, current_value_sha256, candidate_value, '
                  || 'candidate_value_sha256, candidate_seen_at) VALUES (' || chk_item_id || ', %L, ''v'', %L, %L, %L, %L)';
  ASSERT pg_temp.t_refused_by(format(watch_insert, 'Upper.example', 'upper.example')) = 'domain_watch_domain_name_form',
         'S25 a domain with an upper case letter is refused';
  ASSERT pg_temp.t_refused_by(format(watch_insert, '', 'x.example')) = 'domain_watch_domain_name_form', 'S25 an empty domain is refused';
  ASSERT pg_temp.t_refused_by(format(watch_insert, repeat('a', 254), 'x.example')) = 'domain_watch_domain_name_form',
         'S25 a domain of 254 bytes is refused';
  ASSERT pg_temp.t_refused_by(format(watch_insert, repeat('é', 127), 'x.example')) = 'domain_watch_domain_name_form',
         'S25 a domain of 127 letters and 254 bytes is refused';
  ASSERT pg_temp.t_refused_by(format(watch_insert, repeat('a', 253), 'x.example')) = 'accepted', 'S25 a domain of 253 bytes is accepted';
  ASSERT pg_temp.t_refused_by(format(watch_insert, 'y.example', 'Upper.example')) = 'domain_watch_registered_domain_form',
         'S25 a registered domain with an upper case letter is refused';
  ASSERT pg_temp.t_refused_by(format(watch_insert, 'y.example', '')) = 'domain_watch_registered_domain_form',
         'S25 an empty registered domain is refused';
  ASSERT pg_temp.t_refused_by(format(watch_insert, 'y.example', repeat('é', 127))) = 'domain_watch_registered_domain_form',
         'S25 a registered domain of 254 bytes is refused';
  ASSERT pg_temp.t_refused_by(format(watch_insert, 'y.example', repeat('a', 253))) = 'accepted',
         'S25 a registered domain of 253 bytes is accepted';
  ASSERT (SELECT array_agg(a.attname::text ORDER BY a.attnum) FROM pg_attribute AS a
           WHERE a.attrelid = 'domain_watch'::regclass AND a.attnum > 0 AND NOT a.attisdropped)
         = ARRAY['domain_name', 'registered_domain'],
         'S25 a domain_watch row holds no value, no selector, no time of an item and no lease: each lane keeps its lease in domain_watch_lane';

  FOREACH value_kind IN ARRAY ARRAY['dns_presence', 'ns', 'mx', 'ip_address_reachability', 'cname_takeover', 'email_auth', 'hosting',
                                    'certificate_expiry', 'certificate_validity', 'certificate_listing', 'tls_protocol',
                                    'registration_expiry', 'registrar', 'transfer_lock', 'dnssec_delegation'] LOOP
    ASSERT pg_temp.t_refused_by(format(value_insert, value_kind, good_sha256, NULL, NULL, NULL)) = 'accepted',
           'S25 the value kind ' || value_kind || ' is accepted';
  END LOOP;
  ASSERT pg_temp.t_refused_by(format(value_insert, 'whois', good_sha256, NULL, NULL, NULL)) = 'watchlist_item_domain_value_kind_known',
         'S25 an unknown value kind is refused';
  ASSERT pg_temp.t_refused_by(format(value_insert, 'tls_version', good_sha256, NULL, NULL, NULL)) = 'watchlist_item_domain_value_kind_known',
         'S25 a TLS kind of another name is refused';
  ASSERT pg_temp.t_refused_by(format(value_insert, 'ns', upper(good_sha256), NULL, NULL, NULL)) = 'watchlist_item_domain_value_current_value_sha256_form',
         'S25 a current SHA-256 in upper case is refused';
  ASSERT pg_temp.t_refused_by(format(value_insert, 'ns', left(good_sha256, 63), NULL, NULL, NULL)) = 'watchlist_item_domain_value_current_value_sha256_form',
         'S25 a current SHA-256 of 63 digits is refused';
  ASSERT pg_temp.t_refused_by(format(value_insert, 'ns', good_sha256 || '0', NULL, NULL, NULL)) = 'watchlist_item_domain_value_current_value_sha256_form',
         'S25 a current SHA-256 of 65 digits is refused';
  ASSERT pg_temp.t_refused_by(format(value_insert, 'ns', good_sha256, 'c', good_sha256, now())) = 'accepted',
         'S25 a whole candidate is accepted';
  ASSERT pg_temp.t_refused_by(format(value_insert, 'ns', good_sha256, 'c', NULL, NULL)) = 'watchlist_item_domain_value_candidate_whole',
         'S25 a candidate value alone is refused';
  ASSERT pg_temp.t_refused_by(format(value_insert, 'ns', good_sha256, NULL, NULL, now())) = 'watchlist_item_domain_value_candidate_whole',
         'S25 a candidate sighting alone is refused';
  ASSERT pg_temp.t_refused_by(format(value_insert, 'ns', good_sha256, 'c', good_sha256, NULL)) = 'watchlist_item_domain_value_candidate_whole',
         'S25 a candidate value and SHA-256 without the sighting are refused';
  ASSERT pg_temp.t_refused_by(format(value_insert, 'ns', good_sha256, 'c', 'G' || left(good_sha256, 63), now()))
         = 'watchlist_item_domain_value_candidate_value_sha256_form',
         'S25 a candidate SHA-256 with a digit that is not hex is refused';
  ASSERT pg_temp.t_refused_by(format(value_insert, 'ns', good_sha256, 'c', left(good_sha256, 63), now()))
         = 'watchlist_item_domain_value_candidate_value_sha256_form',
         'S25 a candidate SHA-256 of 63 digits is refused';
  ASSERT pg_temp.t_refused_by(format(value_insert, 'ns', good_sha256, 'c', good_sha256 || '0', now()))
         = 'watchlist_item_domain_value_candidate_value_sha256_form',
         'S25 a candidate SHA-256 of 65 digits is refused';
  ASSERT pg_temp.t_refused_by(replace(format(value_insert, 'ns', good_sha256, NULL, NULL, NULL), '(' || chk_item_id || ',', '(-1,'))
         = 'watchlist_item_domain_value_item_id_fkey',
         'S25 a value row of no domain item is refused';

  FOREACH event_type IN ARRAY ARRAY['domain_not_found', 'domain_found', 'ns_changed', 'mx_changed', 'ip_address_not_public', 'ip_address_lost',
                                    'ip_address_restored', 'cname_takeover_detected', 'cname_takeover_resolved', 'hosting_changed',
                                    'cert_expiring', 'cert_invalid', 'cert_listed', 'tls_downgraded'] LOOP
    ASSERT pg_temp.t_refused_by(format(event_insert, event_type, NULL)) = 'accepted', 'S25 the event type ' || event_type || ' is accepted';
  END LOOP;
  ASSERT pg_temp.t_refused_by(format(event_insert, 'email_auth_degraded', 'spf_all')) = 'accepted',
         'S25 an email_auth_degraded event with a check id is accepted';
  ASSERT pg_temp.t_refused_by(format(event_insert, 'cve_added', NULL)) = 'domain_change_event_type_known',
         'S25 an event type of the CVE events is refused';
  ASSERT pg_temp.t_refused_by(format(event_insert, 'cert_revoked', NULL)) = 'domain_change_event_type_known',
         'S25 cert_revoked, a type of a later round, is refused';
  ASSERT pg_temp.t_refused_by(format(event_insert, 'email_auth_degraded', NULL)) = 'domain_change_event_degraded_email_check_id_set',
         'S25 an email_auth_degraded event without a check id is refused';
  ASSERT pg_temp.t_refused_by(format(event_insert, 'ns_changed', 'spf_all')) = 'domain_change_event_degraded_email_check_id_set',
         'S25 another event with a check id is refused';
  ASSERT pg_temp.t_refused_by(format(event_insert, 'email_auth_degraded', 'Spf_all')) = 'domain_change_event_degraded_email_check_id_form',
         'S25 a check id with an upper case letter is refused';
  ASSERT pg_temp.t_refused_by(format(event_insert, 'email_auth_degraded', '1spf')) = 'domain_change_event_degraded_email_check_id_form',
         'S25 a check id that starts with a digit is refused';
  ASSERT pg_temp.t_refused_by(format(event_insert, 'email_auth_degraded', 'spf-all')) = 'domain_change_event_degraded_email_check_id_form',
         'S25 a check id with a hyphen is refused';
  ASSERT pg_temp.t_refused_by(format(event_insert, 'email_auth_degraded', '')) = 'domain_change_event_degraded_email_check_id_form',
         'S25 an empty check id is refused';
  ASSERT pg_temp.t_refused_by(format(event_insert, 'email_auth_degraded', 'a' || repeat('b_1', 10) || 'c')) = 'accepted',
         'S25 a check id of 32 characters is accepted';
  ASSERT pg_temp.t_refused_by(format(event_insert, 'email_auth_degraded', 'a' || repeat('b_1', 10) || 'cd')) = 'domain_change_event_degraded_email_check_id_form',
         'S25 a check id of 33 characters is refused';

  ASSERT pg_temp.t_refused_by($q$INSERT INTO domain_watch_dns_bucket VALUES ('q.example', -1, now())$q$) = 'accepted',
         'S25 a negative question allowance is accepted, because a settlement can take more than the claim took';
  ASSERT pg_temp.t_refused_by($q$INSERT INTO domain_watch_dns_bucket VALUES ('q.example', 0, now())$q$) = 'accepted', 'S25 a question allowance of 0 is accepted';
  ASSERT pg_temp.t_refused_by($q$INSERT INTO change_event_purge_state (event_table_name) VALUES ('domain_change_event')$q$) = 'change_event_purge_state_pkey',
         'S25 a second purge state row of the domain events is refused';
  ASSERT pg_temp.t_refused_by($q$UPDATE change_event_purge_state SET max_unwatched_event_id = 1 WHERE event_table_name = 'domain_change_event'$q$) = 'accepted',
         'S25 the domain row takes a max_unwatched_event_id';
END
$$;

SAVEPOINT t_domain_watch_hosting;
DELETE FROM upstream_feed_sync WHERE feed_name IN ('iptoasn', 'cloud_ranges');
INSERT INTO upstream_feed_sync (feed_name, last_synced, last_status) VALUES ('iptoasn', now(), 'ok');
INSERT INTO ip_asn (asn, asn_name, country) SELECT n, 'Length AS ' || n, 'NL' FROM generate_series(10000, 10256) AS n;
INSERT INTO ip_asn_prefix (prefix, asn) SELECT ('2001:db8:' || to_hex(n - 9999) || '::/48')::cidr, n FROM generate_series(10000, 10256) AS n;
INSERT INTO ip_asn (asn, asn_name, country) VALUES (24940, 'Hosting AS', 'DE');
INSERT INTO ip_asn_prefix (prefix, asn) VALUES ('203.0.113.0/24', 24940);
INSERT INTO ip_cloud_range (provider, service, prefix, is_cdn, synced_at) VALUES ('aws', 'cloudfront', '198.51.100.0/26', true, now());
SELECT pg_temp.t_add_dns('host.example');
SELECT pg_temp.t_add_dns('nohost.example');

CREATE FUNCTION pg_temp.t_hosting_row() RETURNS text LANGUAGE sql AS $$
  SELECT widv.current_value || '|' || widv.current_value_sha256 || '|' || coalesce(widv.candidate_value, 'null')
    FROM watchlist_item_domain_value AS widv
    JOIN watchlist_item_domain AS wid ON wid.item_id = widv.item_id
   WHERE wid.domain_name = 'host.example' AND widv.value_kind = 'hosting'
$$;

CREATE FUNCTION pg_temp.t_hosting_events() RETURNS text[] LANGUAGE sql AS $$
  SELECT coalesce(array_agg(dce.event_type || '|' || dce.previous_value || '|' || dce.current_value ORDER BY dce.event_id), '{}')
    FROM domain_change_event AS dce
   WHERE dce.domain_name = 'host.example' AND dce.event_id > (SELECT max(m.event_id) FROM t_domain_mark AS m)
$$;

DO $$
DECLARE
  first_value text := E'AS24940\naws/cloudfront';
  before_call text;
BEGIN
  ASSERT (SELECT array_agg(p.pronargs) FROM pg_proc AS p WHERE p.pronamespace = 'api'::regnamespace AND p.proname = 'fn_domain_watch_record_dns')
         = ARRAY[17::int2],
         'S33 the record is one function of 17 parameters';
  ASSERT (SELECT p.proargnames[16:17] FROM pg_proc AS p WHERE p.oid = 'api.fn_domain_watch_record_dns'::regproc)
         = ARRAY['p_hosting_ip_addresses', 'p_question_count'],
         'S33 the address list is the only hosting parameter, right before the question count';
  ASSERT NOT EXISTS (SELECT 1 FROM pg_proc AS p WHERE p.oid = 'api.fn_domain_watch_record_dns'::regproc AND p.proargnames && ARRAY['p_hosting_cdn_class']),
         'S33 the record takes no CDN class';

  PERFORM pg_temp.t_dw_mark();
  ASSERT pg_temp.t_record_dns('host.example', p_hosting_ip_addresses => '198.51.100.10,203.0.113.7') = 0,
         'S33 a first hosting value writes no event';
  ASSERT pg_temp.t_hosting_row() = first_value || '|' || pg_temp.t_sha256(first_value) || '|null',
         'S33 the first value is the current value, with its SHA-256';
  ASSERT pg_temp.t_hosting_events() = '{}', 'S33 the first value wrote no event';

  ASSERT pg_temp.t_record_dns('host.example', p_hosting_ip_addresses => '203.0.113.7,198.51.100.10,203.0.113.7') = 0,
         'S33 the same classes in another order answer 0';
  ASSERT pg_temp.t_hosting_row() = first_value || '|' || pg_temp.t_sha256(first_value) || '|null',
         'S33 the same classes keep the row and make no candidate';

  ASSERT pg_temp.t_record_dns('host.example', p_hosting_ip_addresses => '203.0.113.7') = 0, 'S33 another class answers 0';
  ASSERT pg_temp.t_hosting_row() = first_value || '|' || pg_temp.t_sha256(first_value) || '|AS24940',
         'S33 another class becomes the candidate';
  PERFORM pg_temp.t_age('host.example', 'hosting', interval '1 hour');
  ASSERT pg_temp.t_record_dns('host.example', p_hosting_ip_addresses => '203.0.113.7') = 1,
         'S33 the candidate seen again an hour later is confirmed with one event';
  ASSERT pg_temp.t_hosting_events() = ARRAY['hosting_changed|' || first_value || '|AS24940'],
         'S33 the confirmed change writes hosting_changed from the old value to the new one';
  ASSERT pg_temp.t_hosting_row() = 'AS24940|' || pg_temp.t_sha256('AS24940') || '|null', 'S33 the new value is current';

  ASSERT pg_temp.t_record_dns_kind('host.example', 'hosting', '198.51.100.10') = 0, 'S33 an address list of t_record_dns_kind answers 0';
  ASSERT pg_temp.t_hosting_row() = 'AS24940|' || pg_temp.t_sha256('AS24940') || '|aws/cloudfront',
         'S33 the class of the address list of t_record_dns_kind becomes the candidate';
  PERFORM pg_temp.t_record_dns('host.example', p_hosting_ip_addresses => '203.0.113.7');
  ASSERT pg_temp.t_hosting_row() = 'AS24940|' || pg_temp.t_sha256('AS24940') || '|null', 'S33 the current class seen again clears the candidate';

  ASSERT pg_temp.t_record_dns('nohost.example', p_ns => 'ns-n') = 0, 'S33 a first scan with no address list answers 0';
  ASSERT pg_temp.t_values('nohost.example') = 'ns=ns-n',
         'S33 a first scan with no address list writes no hosting row';

  before_call := pg_temp.t_hosting_row();
  PERFORM pg_temp.t_record_dns('host.example', p_ns => 'ns-h');
  ASSERT pg_temp.t_hosting_row() = before_call, 'S33 a scan with no hosting value keeps the hosting row';

  UPDATE ip_cloud_range AS icr SET synced_at = now() - interval '8 days' WHERE icr.provider = 'aws';
  PERFORM pg_temp.t_record_dns('host.example', p_hosting_ip_addresses => '198.51.100.10');
  ASSERT pg_temp.t_hosting_row() = before_call, 'S33 a stale cloud list makes no value and keeps the hosting row';
  PERFORM pg_temp.t_record_dns('host.example', p_hosting_ip_addresses => '203.0.113.7');
  ASSERT pg_temp.t_hosting_row() = before_call, 'S33 a stale cloud table makes no AS value and keeps the hosting row';
  UPDATE ip_cloud_range AS icr SET synced_at = now() WHERE icr.provider = 'aws';
  UPDATE upstream_feed_sync AS ufs SET last_status = 'error' WHERE ufs.feed_name = 'iptoasn';
  PERFORM pg_temp.t_record_dns('host.example', p_hosting_ip_addresses => '203.0.113.7');
  ASSERT pg_temp.t_hosting_row() = before_call, 'S33 a stale AS list makes no value and keeps the hosting row';
  UPDATE upstream_feed_sync AS ufs SET last_status = 'ok' WHERE ufs.feed_name = 'iptoasn';

  ASSERT octet_length((SELECT string_agg('AS' || n, E'\n') FROM generate_series(10000, 10256) AS n)) = 2055,
         'S33 the classes of the long list are 2055 bytes long';
  PERFORM pg_temp.t_record_dns('host.example',
                               p_hosting_ip_addresses => (SELECT string_agg('2001:db8:' || to_hex(n - 9999) || '::1', ',') FROM generate_series(10000, 10256) AS n));
  ASSERT pg_temp.t_hosting_row() = before_call, 'S33 a value longer than 2048 bytes is no value and keeps the hosting row';
  PERFORM pg_temp.t_record_dns('host.example', p_hosting_ip_addresses => '2001:db8:1::1');
  ASSERT pg_temp.t_hosting_row() = 'AS24940|' || pg_temp.t_sha256('AS24940') || '|AS10000',
         'S33 a short list of the same table still makes a value, and it becomes the candidate';
END
$$;
ROLLBACK TO SAVEPOINT t_domain_watch_hosting;
RELEASE SAVEPOINT t_domain_watch_hosting;

SELECT pg_temp.t_reset();
INSERT INTO domain_watch (domain_name, registered_domain) VALUES ('lane.example', 'lane.example');
DO $$
DECLARE
  lane_insert text := 'INSERT INTO domain_watch_lane (domain_name, lane_name) VALUES (%L, %L)';
BEGIN
  ASSERT pg_temp.t_refused_by(format(lane_insert, 'lane.example', 'dns')) = 'accepted', 'S35 a dns lane row is accepted';
  ASSERT pg_temp.t_refused_by(format(lane_insert, 'lane.example', 'tls')) = 'accepted', 'S35 a tls lane row is accepted';
  ASSERT pg_temp.t_refused_by(format(lane_insert, 'lane.example', 'rdap_whois')) = 'accepted', 'S35 a rdap_whois lane row is accepted';
  ASSERT pg_temp.t_refused_by(format(lane_insert, 'lane.example', 'headers')) = 'accepted', 'S35 a headers lane row is accepted';
  ASSERT pg_temp.t_refused_by(format(lane_insert, 'lane.example', 'headers_check')) = 'domain_watch_lane_name_known',
         'S35 the endpoint name headers_check is refused: its lane is named headers';
  ASSERT pg_temp.t_refused_by(format(lane_insert, 'lane.example', 'ct')) = 'accepted', 'S35 a ct lane row is accepted';
  ASSERT pg_temp.t_refused_by(format(lane_insert, 'lane.example', 'cert_search')) = 'domain_watch_lane_name_known',
         'S35 the endpoint name cert_search is refused: its lane is named ct';
  ASSERT pg_temp.t_refused_by(format(lane_insert, 'lane.example', 'whois')) = 'domain_watch_lane_name_known',
         'S35 the lane whois is refused: the rdap_whois lane carries WHOIS too';
  ASSERT pg_temp.t_refused_by(format(lane_insert, 'lane.example', 'rdap')) = 'domain_watch_lane_name_known',
         'S35 the lane rdap is refused: the rdap_whois lane took its place';
  ASSERT pg_temp.t_refused_by(format(lane_insert, 'lane.example', 'TLS')) = 'domain_watch_lane_name_known',
         'S35 a lane name in upper case is refused';
  ASSERT pg_temp.t_refused_by(format(lane_insert, 'lane.example', 'dns_lookup')) = 'domain_watch_lane_name_known',
         'S35 an endpoint name is refused: the dns lane is named dns';
  ASSERT pg_temp.t_refused_by(format(lane_insert, 'nolane.example', 'tls')) = 'domain_watch_lane_domain_name_fkey',
         'S35 a lane row without its domain_watch row is refused';
  ASSERT (SELECT array_agg(a.attname::text ORDER BY a.attnum) FROM pg_attribute AS a
           WHERE a.attrelid = 'domain_watch_lane'::regclass AND a.attnum > 0 AND NOT a.attisdropped)
         = ARRAY['domain_name', 'lane_name', 'claimed_until', 'claimed_at', 'scanned_at', 'not_before'],
         'S35 a lane row holds its lease, its last scan and its not_before, and no time of an item';
  ASSERT (SELECT format_type(a.atttypid, a.atttypmod) || ' ' || NOT a.attnotnull FROM pg_attribute AS a
           WHERE a.attrelid = 'domain_watch_lane'::regclass AND a.attname = 'not_before') = 'timestamp with time zone true',
         'S35 not_before is a timestamptz that may be NULL';
  EXECUTE format(lane_insert, 'lane.example', 'tls');
  ASSERT pg_temp.t_refused_by(format(lane_insert, 'lane.example', 'tls')) = 'domain_watch_lane_pkey',
         'S35 a second tls lane row of one domain is refused';
  DELETE FROM domain_watch AS dw WHERE dw.domain_name = 'lane.example';
  ASSERT NOT EXISTS (SELECT 1 FROM domain_watch_lane AS dwl WHERE dwl.domain_name = 'lane.example'),
         'S35 the lane row goes with its domain_watch row';
END
$$;

SELECT pg_temp.t_item(n.domain_name, repeat('9c', 32), 'ssl_check', n.next_scan_at)
  FROM (VALUES ('q4.example', now() - interval '4 hours'), ('qn.example', now() - interval '3 hours'), ('qb.example', now() - interval '3 hours'),
               ('qa.example', now() - interval '3 hours'), ('qo.example', now() - interval '3 hours'), ('ended.example', now() - interval '1 hour'),
               ('at-now.example', now()), ('later.example', now() + interval '1 second'), ('held.example', now() - interval '6 hours'),
               ('heldnow.example', now() - interval '6 hours'), ('q2.example', now() - interval '1 minute')) AS n (domain_name, next_scan_at);
SELECT pg_temp.t_item('q2.example', repeat('a1', 32), 'ssl_check', now() - interval '3 hours 30 minutes');
SELECT pg_temp.t_item('dns-item.example', repeat('9c', 32), 'dns_lookup', now() - interval '6 hours');
INSERT INTO domain_watch_lane (domain_name, lane_name) VALUES ('dns-item.example', 'tls');
INSERT INTO domain_watch (domain_name, registered_domain) VALUES ('no-item.example', 'no-item.example');
INSERT INTO domain_watch_lane (domain_name, lane_name) VALUES ('no-item.example', 'tls');
UPDATE domain_watch_lane AS dwl
   SET scanned_at    = CASE dwl.domain_name WHEN 'q4.example' THEN now() WHEN 'qo.example' THEN now() - interval '7 hours'
                                            WHEN 'qa.example' THEN now() - interval '5 hours' WHEN 'qb.example' THEN now() - interval '5 hours'
                                            WHEN 'qn.example' THEN NULL ELSE now() - interval '1 hour' END,
       claimed_until = CASE dwl.domain_name WHEN 'ended.example' THEN now() - interval '1 second' WHEN 'held.example' THEN now() + interval '1 minute'
                                            WHEN 'heldnow.example' THEN now() END;

SAVEPOINT t_domain_watch_rdap_whois_lane;
SELECT pg_temp.t_item('qa.example', repeat('9c', 32), 'whois_lookup', now() - interval '2 hours');
SELECT pg_temp.t_item('rdap-only.example', repeat('9c', 32), 'whois_lookup', now() - interval '5 hours');
DO $$
BEGIN
  ASSERT pg_temp.t_claim('tls', 1) = 'q4.example', 'S36 the tls lane passes over the rdap_whois rows';
  ASSERT pg_temp.t_claim('tls', 10) = 'q2.example,qn.example,qo.example,qa.example,qb.example,ended.example,at-now.example',
         'S36 the tls lane leases the tls row of a name that also has a rdap_whois row';
  ASSERT (SELECT dwl.claimed_until IS NULL FROM domain_watch_lane AS dwl WHERE dwl.domain_name = 'qa.example' AND dwl.lane_name = 'rdap_whois'),
         'S36 the lease of a tls row leaves the rdap_whois row of the name as it is';
  ASSERT pg_temp.t_claim('rdap_whois', 10) = 'rdap-only.example,qa.example',
         'S36 the rdap_whois lane leases the rows its whois_lookup items make due, and the tls lane passes over them';
  ASSERT (SELECT array_agg(dwl.domain_name || ':' || dwl.lane_name ORDER BY dwl.domain_name, dwl.lane_name) FROM domain_watch_lane AS dwl
           WHERE dwl.claimed_until = now() + interval '300 seconds')
         = '{at-now.example:tls,ended.example:tls,q2.example:tls,q4.example:tls,qa.example:rdap_whois,qa.example:tls,qb.example:tls,qn.example:tls,qo.example:tls,rdap-only.example:rdap_whois}',
         'S36 each lane leases only its own rows';
END
$$;
ROLLBACK TO SAVEPOINT t_domain_watch_rdap_whois_lane;
RELEASE SAVEPOINT t_domain_watch_rdap_whois_lane;

DO $$
DECLARE
  before_claim timestamptz := clock_timestamp();
BEGIN
  ASSERT pg_temp.t_claim(NULL, 10) = '' AND pg_temp.t_claim('tls', NULL) = '' AND pg_temp.t_claim('tls', 10, NULL) = '',
         'S36 a NULL argument leases nothing';
  ASSERT pg_temp.t_claim('tls', 0) = '' AND pg_temp.t_claim('tls', -1) = '', 'S36 a row count of 0 or below leases nothing';
  ASSERT pg_temp.t_claim('tls', 10, 0) = '' AND pg_temp.t_claim('tls', 10, -1) = '', 'S36 a lease shorter than 1 second leases nothing';
  ASSERT pg_temp.t_claim('rdap_whois', 10) = '', 'S36 a lane with no row leases nothing';
  ASSERT NOT EXISTS (SELECT 1 FROM domain_watch_lane AS dwl WHERE dwl.claimed_until > now() + interval '1 minute'),
         'S36 the calls that lease nothing write no lease';

  ASSERT pg_temp.t_claim('tls', 2) = 'q4.example,q2.example',
         'S36 a claim of 2 answers the two oldest places in line: q4, then q2 by the oldest of its two items';
  ASSERT (SELECT array_agg(dwl.domain_name ORDER BY dwl.domain_name) FROM domain_watch_lane AS dwl WHERE dwl.claimed_until = now() + interval '300 seconds')
         = '{q2.example,q4.example}',
         'S36 each leased row holds a lease of p_lease_seconds';
  ASSERT (SELECT bool_and(dwl.claimed_at > before_claim AND dwl.claimed_at < clock_timestamp()) FROM domain_watch_lane AS dwl
           WHERE dwl.domain_name IN ('q2.example', 'q4.example')),
         'S36 each leased row notes claimed_at, the clock at the claim';
  ASSERT pg_temp.t_claim('tls', 10, 1) = 'qn.example,qo.example,qa.example,qb.example,ended.example,at-now.example',
         'S36 the next claim takes the never scanned row, then the older scan, then the smaller name, then a lease that ended and a row due at now()';
  ASSERT (SELECT array_agg(dwl.domain_name ORDER BY dwl.domain_name) FROM domain_watch_lane AS dwl WHERE dwl.claimed_until = now() + interval '1 second')
         = '{at-now.example,ended.example,qa.example,qb.example,qn.example,qo.example}',
         'S36 a lease of 1 second ends 1 second after now()';
  ASSERT pg_temp.t_claim('tls', 10) = '', 'S36 a claim with no due row left leases nothing';
  ASSERT (SELECT array_agg(dwl.domain_name || '=' || coalesce((dwl.claimed_until - now())::text, 'null') ORDER BY dwl.domain_name)
            FROM domain_watch_lane AS dwl
           WHERE dwl.lane_name = 'tls' AND dwl.domain_name IN ('later.example', 'held.example', 'heldnow.example', 'dns-item.example', 'no-item.example'))
         = '{dns-item.example=null,held.example=00:01:00,heldnow.example=00:00:00,later.example=null,no-item.example=null}',
         'S36 a row due after now(), a running lease, a lease that ends at now(), a name of a dns_lookup item only and a name of no item keep their lease';
  ASSERT NOT EXISTS (SELECT 1 FROM domain_watch_lane AS dwl WHERE dwl.lane_name = 'dns' AND dwl.claimed_until IS NOT NULL), 'S36 the tls lane leases no dns lane row';
END
$$;

CREATE FUNCTION pg_temp.t_record_tls(p_domain_name text, p_certificate_expiry text DEFAULT NULL, p_certificate_validity text DEFAULT NULL,
                                     p_certificate_listing text DEFAULT NULL, p_tls_protocol text DEFAULT NULL,
                                     p_claimed_at timestamptz DEFAULT now() + interval '2 days')
  RETURNS integer LANGUAGE plpgsql AS $$
BEGIN
  UPDATE domain_watch_lane AS dwl SET claimed_until = now() + interval '10 minutes', claimed_at = p_claimed_at
   WHERE dwl.domain_name = p_domain_name AND dwl.lane_name = 'tls';
  RETURN api.fn_domain_watch_record_tls(p_domain_name, now() + interval '10 minutes',
                                        p_certificate_expiry,   pg_temp.t_sha256(p_certificate_expiry),
                                        p_certificate_validity, pg_temp.t_sha256(p_certificate_validity),
                                        p_certificate_listing,  pg_temp.t_sha256(p_certificate_listing),
                                        p_tls_protocol,         pg_temp.t_sha256(p_tls_protocol));
END
$$;

CREATE FUNCTION pg_temp.t_record_tls_kind(p_domain_name text, p_kind text, p_value text) RETURNS integer LANGUAGE sql AS $$
  SELECT pg_temp.t_record_tls(p_domain_name,
                              p_certificate_expiry   => CASE WHEN p_kind = 'certificate_expiry'   THEN p_value END,
                              p_certificate_validity => CASE WHEN p_kind = 'certificate_validity' THEN p_value END,
                              p_certificate_listing  => CASE WHEN p_kind = 'certificate_listing'  THEN p_value END,
                              p_tls_protocol         => CASE WHEN p_kind = 'tls_protocol'         THEN p_value END)
$$;

CREATE FUNCTION pg_temp.t_tls_change(p_domain_name text, p_kind text, p_value text) RETURNS text LANGUAGE plpgsql AS $$
DECLARE
  written_event_count integer;
BEGIN
  PERFORM pg_temp.t_dw_mark();
  PERFORM pg_temp.t_record_tls_kind(p_domain_name, p_kind, p_value);
  PERFORM pg_temp.t_age(p_domain_name, p_kind, interval '1 hour');
  written_event_count := pg_temp.t_record_tls_kind(p_domain_name, p_kind, p_value);
  RETURN written_event_count || '|' || pg_temp.t_dw_events(p_domain_name)::text;
END
$$;

CREATE FUNCTION pg_temp.t_lane_snapshot(p_domain_name text) RETURNS text LANGUAGE sql AS $$
  SELECT (SELECT dwl::text FROM domain_watch_lane AS dwl WHERE dwl.domain_name = p_domain_name AND dwl.lane_name = 'tls') || ' '
         || pg_temp.t_snapshot(p_domain_name)
$$;

SELECT pg_temp.t_reset();
SELECT pg_temp.t_add_tls('tls1.example');
SELECT pg_temp.t_add_dns('dnsonly.example');
DO $$
DECLARE
  watch_row_before text := (SELECT dw::text FROM domain_watch AS dw WHERE dw.domain_name = 'tls1.example');
  valid_sha256     text := pg_temp.t_sha256('valid');
  before_call      text;
BEGIN
  BEGIN
    PERFORM api.fn_domain_watch_record_tls('tls1.example', now(), 'none', NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    ASSERT false, 'S37 a certificate_expiry value without its SHA-256 is refused';
  EXCEPTION WHEN invalid_parameter_value THEN
    ASSERT SQLERRM LIKE '%certificate_expiry%', 'S37 the refusal names the kind certificate_expiry';
  END;
  BEGIN
    PERFORM api.fn_domain_watch_record_tls('tls1.example', now(), NULL, NULL, 'valid', NULL, NULL, NULL, NULL, NULL);
    ASSERT false, 'S37 a certificate_validity value without its SHA-256 is refused';
  EXCEPTION WHEN invalid_parameter_value THEN
    ASSERT SQLERRM LIKE '%certificate_validity%', 'S37 the refusal names the kind certificate_validity';
  END;
  BEGIN
    PERFORM api.fn_domain_watch_record_tls('tls1.example', now(), NULL, NULL, NULL, NULL, NULL, pg_temp.t_sha256('not_listed'), NULL, NULL);
    ASSERT false, 'S37 a certificate_listing SHA-256 without its value is refused';
  EXCEPTION WHEN invalid_parameter_value THEN
    ASSERT SQLERRM LIKE '%certificate_listing%', 'S37 the refusal names the kind certificate_listing';
  END;
  BEGIN
    PERFORM api.fn_domain_watch_record_tls('tls1.example', now(), NULL, NULL, NULL, NULL, NULL, NULL, NULL, pg_temp.t_sha256('TLSv1.3'));
    ASSERT false, 'S37 a tls_protocol SHA-256 without its value is refused';
  EXCEPTION WHEN invalid_parameter_value THEN
    ASSERT SQLERRM LIKE '%tls_protocol%', 'S37 the refusal names the kind tls_protocol';
  END;

  UPDATE domain_watch_lane AS dwl SET claimed_until = now() + interval '10 minutes', claimed_at = now() + interval '2 days'
   WHERE dwl.domain_name = 'tls1.example';
  before_call := pg_temp.t_lane_snapshot('tls1.example');
  ASSERT api.fn_domain_watch_record_tls('tls1.example', now() + interval '9 minutes', NULL, NULL, 'valid', valid_sha256, NULL, NULL, NULL, NULL) = 0,
         'S37 another lease answers 0';
  ASSERT pg_temp.t_lane_snapshot('tls1.example') = before_call, 'S37 another lease changes nothing';
  ASSERT api.fn_domain_watch_record_tls('tls1.example', NULL, NULL, NULL, 'valid', valid_sha256, NULL, NULL, NULL, NULL) = 0,
         'S37 a NULL lease against a held one answers 0';
  ASSERT pg_temp.t_lane_snapshot('tls1.example') = before_call, 'S37 a NULL lease changes nothing';
  UPDATE domain_watch_lane AS dwl SET claimed_until = NULL WHERE dwl.domain_name = 'tls1.example';
  before_call := pg_temp.t_lane_snapshot('tls1.example');
  ASSERT api.fn_domain_watch_record_tls('tls1.example', NULL, NULL, NULL, 'valid', valid_sha256, NULL, NULL, NULL, NULL) = 0,
         'S37 a lane row with no lease answers 0, even to a NULL lease';
  ASSERT pg_temp.t_lane_snapshot('tls1.example') = before_call, 'S37 a lane row with no lease changes nothing';
  UPDATE domain_watch_lane AS dwl SET claimed_until = now() + interval '10 minutes', claimed_at = now() + interval '2 days' WHERE dwl.domain_name = 'dnsonly.example' AND dwl.lane_name = 'dns';
  ASSERT api.fn_domain_watch_record_tls('dnsonly.example', now() + interval '10 minutes', NULL, NULL, 'valid', valid_sha256, NULL, NULL, NULL, NULL) = 0,
         'S37 a domain with no tls lane row answers 0, even when the lease is the one of its dns lane';
  ASSERT pg_temp.t_values('dnsonly.example') = '', 'S37 a domain with no tls lane row gets no value';
  UPDATE domain_watch_lane AS dwl SET claimed_until = NULL WHERE dwl.domain_name = 'dnsonly.example' AND dwl.lane_name = 'dns';
  ASSERT api.fn_domain_watch_record_tls('none.example', now(), NULL, NULL, 'valid', valid_sha256, NULL, NULL, NULL, NULL) = 0,
         'S37 an unknown domain answers 0';

  PERFORM pg_temp.t_dw_mark();
  ASSERT pg_temp.t_record_tls('tls1.example', E'none\n2027-01-01T00:00:00Z', 'valid', 'not_listed', 'TLSv1.3') = 0,
         'S37 a first scan with no problem answers 0 events';
  ASSERT pg_temp.t_values('tls1.example')
         = 'certificate_expiry=none+2027-01-01T00:00:00Z certificate_listing=not_listed certificate_validity=valid tls_protocol=TLSv1.3',
         'S37 a first scan writes the current value of each TLS kind and no candidate';
  ASSERT (SELECT bool_and(widv.current_value_sha256 = pg_temp.t_sha256(widv.current_value)) FROM watchlist_item_domain_value AS widv
           JOIN watchlist_item_domain AS wid ON wid.item_id = widv.item_id WHERE wid.domain_name = 'tls1.example'),
         'S37 each current value is stored with its own SHA-256';
  ASSERT pg_temp.t_dw_events('tls1.example') = '{}', 'S37 a first scan with no problem writes no event';
  ASSERT (SELECT dwl.claimed_until IS NULL AND dwl.scanned_at = now() FROM domain_watch_lane AS dwl WHERE dwl.domain_name = 'tls1.example')
     AND pg_temp.t_next_scan('tls1.example', p_endpoint_name => 'ssl_check') = api.fn_domain_watch_next_daily_scan_at('tls1.example'),
         'S37 the record ends the lease, notes scanned_at, and puts the item at its daily second';
  ASSERT (SELECT dw::text FROM domain_watch AS dw WHERE dw.domain_name = 'tls1.example') = watch_row_before,
         'S37 the TLS record leaves the domain_watch row as it is';

  ASSERT pg_temp.t_record_tls('tls1.example', p_tls_protocol => 'TLSv1.2') = 0, 'S37 a new value answers 0 events';
  ASSERT pg_temp.t_candidate('tls1.example', 'tls_protocol') = 'TLSv1.2|00:00:00', 'S37 a new value becomes the candidate';
  ASSERT pg_temp.t_next_scan('tls1.example', p_endpoint_name => 'ssl_check') = now() + interval '1 hour',
         'S37 a scan that leaves a candidate brings the next scan of the item one hour after now';
  ASSERT pg_temp.t_record_tls('tls1.example', p_tls_protocol => 'TLSv1.3') = 0
     AND pg_temp.t_values('tls1.example') LIKE '%tls_protocol=TLSv1.3',
         'S37 the current value seen again clears the candidate';
END
$$;

DO $$
DECLARE
  event_ids bigint[];
BEGIN
  PERFORM pg_temp.t_add_tls(d.domain_name) FROM (VALUES ('tls2.example'), ('tls3.example'), ('tls4.example'), ('tls5.example'), ('tls6.example')) AS d (domain_name);
  INSERT INTO domain_watch (domain_name, registered_domain) VALUES ('tls7.example', 'tls7.example');
  INSERT INTO domain_watch_lane (domain_name, lane_name) VALUES ('tls7.example', 'tls');
  PERFORM pg_temp.t_dw_mark();
  ASSERT pg_temp.t_record_tls('tls2.example', E'7\n2026-11-05T00:00:00Z', E'expired\nself_signed', E'listed\nkey_compromise', 'TLSv1.1') = 4,
         'S38 four first values with a problem answer 4 events';
  ASSERT pg_temp.t_dw_events('tls2.example')
         = '{cert_expiring:null>7+2026-11-05T00:00:00Z,cert_invalid:null>expired+self_signed,cert_listed:null>listed+key_compromise,tls_downgraded:null>TLSv1.1}',
         'S38 each value with a problem writes its event with no previous value, in the order of the kinds';
  ASSERT pg_temp.t_heard(repeat('9c', 32), 'tls2.example') = pg_temp.t_dw_events('tls2.example'), 'S38 the item reads its four events';
  ASSERT pg_temp.t_values('tls2.example') LIKE 'certificate_expiry=7+2026-11-05T00:00:00Z %',
         'S38 a first value with a problem is still the current value';

  ASSERT pg_temp.t_record_tls('tls3.example', E'1\n2026-10-31T00:00:00Z', 'valid', 'not_listed', 'TLSv1') = 2
     AND pg_temp.t_dw_events('tls3.example') = '{cert_expiring:null>1+2026-10-31T00:00:00Z,tls_downgraded:null>TLSv1}',
         'S38 bucket 1 writes cert_expiring and TLSv1 writes tls_downgraded, while valid and not_listed write none';
  ASSERT pg_temp.t_record_tls('tls4.example', E'none\n2027-06-01T00:00:00Z', 'valid', 'not_listed', 'TLSv1.2') = 0
     AND pg_temp.t_dw_events('tls4.example') = '{}',
         'S38 bucket none, valid, not_listed and TLSv1.2 write no event';

  PERFORM pg_temp.t_record_tls('tls5.example', p_tls_protocol => 'TLSv1.3');
  ASSERT pg_temp.t_record_tls('tls5.example', p_certificate_validity => 'hostname_mismatch') = 1,
         'S38 a kind with its first value in a later scan answers 1 event';
  ASSERT pg_temp.t_dw_events('tls5.example') = '{cert_invalid:null>hostname_mismatch}',
         'S38 that first value writes the event of its problem with no previous value';

  ASSERT pg_temp.t_record_tls('tls6.example') = 0 AND pg_temp.t_values('tls6.example') = '',
         'S38 a scan whose handshake failed reads no value and writes no event';
  ASSERT pg_temp.t_next_scan('tls6.example', p_endpoint_name => 'ssl_check') = api.fn_domain_watch_next_daily_scan_at('tls6.example'),
         'S38 the item of a scan that read no value gets its daily second';
  PERFORM pg_temp.t_item('tls6.example', repeat('a1', 32), 'ssl_check');
  ASSERT pg_temp.t_record_tls('tls6.example', E'none\n2027-06-01T00:00:00Z', 'expired', 'not_listed', 'TLSv1.3') = 1
     AND pg_temp.t_dw_events('tls6.example') = '{cert_invalid:null>expired}',
         'S38 the two items of one scan with the same first problem share one event row';
  event_ids := ARRAY(SELECT dce.event_id FROM domain_change_event AS dce WHERE dce.domain_name = 'tls6.example');
  ASSERT (SELECT count(*) FROM watchlist_event_ref AS wer WHERE wer.event_id = ANY (event_ids)) = 2,
         'S38 each of the two items hears the event through its own ref';
  ASSERT pg_temp.t_heard(repeat('9c', 32), 'tls6.example') = '{cert_invalid:null>expired}'
     AND pg_temp.t_heard(repeat('a1', 32), 'tls6.example') = '{cert_invalid:null>expired}',
         'S38 the key that watched tls6 before its failed scan and the key that added it after both read the event';
  PERFORM pg_temp.t_item('tls6.example', repeat('b1', 32), 'ssl_check');
  ASSERT pg_temp.t_heard(repeat('b1', 32), 'tls6.example') = '{}', 'S38 a key that adds tls6 after the event does not read it';

  ASSERT pg_temp.t_record_tls('tls7.example', E'7\n2026-11-05T00:00:00Z', 'expired', 'listed', 'TLSv1') = 0
     AND pg_temp.t_dw_events('tls7.example') = '{}',
         'S38 a scan that serves no item writes no event';
END
$$;

DO $$
BEGIN
  ASSERT pg_temp.t_tls_change('tls1.example', 'certificate_expiry', E'7\n2026-11-05T00:00:00Z')
         = '1|{cert_expiring:none+2027-01-01T00:00:00Z>7+2026-11-05T00:00:00Z}', 'S39 none to 7 is cert_expiring';
  ASSERT pg_temp.t_tls_change('tls1.example', 'certificate_expiry', E'7\n2026-11-06T00:00:00Z') = '0|{}',
         'S39 7 to 7 with another end date writes no event';
  ASSERT pg_temp.t_tls_change('tls1.example', 'certificate_expiry', E'1\n2026-11-01T00:00:00Z')
         = '1|{cert_expiring:7+2026-11-06T00:00:00Z>1+2026-11-01T00:00:00Z}', 'S39 7 to 1 is cert_expiring';
  ASSERT pg_temp.t_tls_change('tls1.example', 'certificate_expiry', E'1\n2026-11-02T00:00:00Z') = '0|{}',
         'S39 1 to 1 with another end date writes no event';
  ASSERT pg_temp.t_tls_change('tls1.example', 'certificate_expiry', E'7\n2026-11-08T00:00:00Z') = '0|{}', 'S39 1 to 7 writes no event';
  ASSERT pg_temp.t_tls_change('tls1.example', 'certificate_expiry', E'none\n2027-02-01T00:00:00Z') = '0|{}', 'S39 7 to none writes no event';
  ASSERT pg_temp.t_tls_change('tls1.example', 'certificate_expiry', E'1\n2026-11-03T00:00:00Z')
         = '1|{cert_expiring:none+2027-02-01T00:00:00Z>1+2026-11-03T00:00:00Z}', 'S39 none to 1 is cert_expiring';
  ASSERT pg_temp.t_tls_change('tls1.example', 'certificate_expiry', E'none\n2027-03-01T00:00:00Z') = '0|{}', 'S39 1 to none writes no event';

  ASSERT pg_temp.t_tls_change('tls1.example', 'certificate_validity', 'expired') = '1|{cert_invalid:valid>expired}',
         'S39 valid to a problem is cert_invalid';
  ASSERT pg_temp.t_tls_change('tls1.example', 'certificate_validity', E'expired\nself_signed') = '0|{}',
         'S39 one problem to more problems writes no event';
  ASSERT pg_temp.t_tls_change('tls1.example', 'certificate_validity', 'valid') = '0|{}', 'S39 a problem to valid writes no event';
  ASSERT pg_temp.t_tls_change('tls1.example', 'certificate_validity', 'hostname_mismatch') = '1|{cert_invalid:valid>hostname_mismatch}',
         'S39 valid to another problem is cert_invalid';
  ASSERT pg_temp.t_tls_change('tls1.example', 'certificate_validity', 'valid') = '0|{}', 'S39 back to valid writes no event';

  ASSERT pg_temp.t_tls_change('tls1.example', 'certificate_listing', E'listed\nr1') = '1|{cert_listed:not_listed>listed+r1}',
         'S39 not_listed to listed is cert_listed';
  ASSERT pg_temp.t_tls_change('tls1.example', 'certificate_listing', E'listed\nr2') = '0|{}', 'S39 listed with another reason writes no event';
  ASSERT pg_temp.t_tls_change('tls1.example', 'certificate_listing', 'not_listed') = '0|{}', 'S39 listed to not_listed writes no event';
  ASSERT pg_temp.t_tls_change('tls1.example', 'certificate_listing', 'listed') = '1|{cert_listed:not_listed>listed}',
         'S39 not_listed to listed with no reason is cert_listed';
  ASSERT pg_temp.t_tls_change('tls1.example', 'certificate_listing', 'not_listed') = '0|{}', 'S39 back to not_listed writes no event';

  ASSERT pg_temp.t_tls_change('tls1.example', 'tls_protocol', 'TLSv1.2') = '0|{}', 'S39 TLSv1.3 to TLSv1.2 writes no event';
  ASSERT pg_temp.t_tls_change('tls1.example', 'tls_protocol', 'TLSv1.1') = '1|{tls_downgraded:TLSv1.2>TLSv1.1}',
         'S39 TLSv1.2 to TLSv1.1 is tls_downgraded';
  ASSERT pg_temp.t_tls_change('tls1.example', 'tls_protocol', 'TLSv1') = '0|{}', 'S39 TLSv1.1 to TLSv1 writes no event';
  ASSERT pg_temp.t_tls_change('tls1.example', 'tls_protocol', 'TLSv1.3') = '0|{}', 'S39 TLSv1 to TLSv1.3 writes no event';
  ASSERT pg_temp.t_tls_change('tls1.example', 'tls_protocol', 'TLSv1') = '1|{tls_downgraded:TLSv1.3>TLSv1}',
         'S39 TLSv1.3 to TLSv1 is tls_downgraded';
  ASSERT pg_temp.t_tls_change('tls1.example', 'tls_protocol', 'TLSv1.3') = '0|{}', 'S39 back to TLSv1.3 writes no event';
END
$$;

DO $$
BEGIN
  PERFORM pg_temp.t_add_dns(d.domain_name) FROM (VALUES ('fv1.example'), ('fv2.example'), ('fv3.example'), ('fv4.example')) AS d (domain_name);
  PERFORM pg_temp.t_dw_mark();
  ASSERT pg_temp.t_record_dns('fv1.example', p_dns_presence => 'not_found', p_ns => 'ns1', p_mx => 'mx1', p_ip_address_reachability => 'not_public',
                              p_cname_takeover => 'vulnerable:svc', p_email_auth => 'pf', p_email_check_ids => 'spf_all,dmarc_policy') = 3,
         'S40 three values with a problem answer 3 events';
  ASSERT pg_temp.t_dw_events('fv1.example')
         = '{domain_not_found:null>not_found,ip_address_not_public:null>not_public,cname_takeover_detected:null>vulnerable:svc}',
         'S40 not_found, not_public and a vulnerable value write their events with no previous value, and a first e-mail value writes none';
  ASSERT pg_temp.t_record_dns('fv2.example', p_dns_presence => 'found', p_ns => 'ns1', p_mx => 'mx1', p_ip_address_reachability => 'public',
                              p_cname_takeover => 'none', p_email_auth => 'pp') = 0
     AND pg_temp.t_dw_events('fv2.example') = '{}',
         'S40 found, an ns, an mx, public, none and an e-mail value write no event';
  ASSERT pg_temp.t_record_dns('fv3.example', p_ip_address_reachability => 'empty', p_cname_takeover => 'unchecked') = 0
     AND pg_temp.t_dw_events('fv3.example') = '{}',
         'S40 empty and unchecked write no event';
  PERFORM pg_temp.t_record_dns('fv4.example', p_dns_presence => 'found', p_cname_takeover => 'none');
  ASSERT pg_temp.t_record_dns('fv4.example', p_ip_address_reachability => 'not_public', p_cname_takeover => 'vulnerable') = 1,
         'S40 a kind with its first value after the first scan of the item answers 1 event';
  ASSERT pg_temp.t_dw_events('fv4.example') = '{ip_address_not_public:null>not_public}'
     AND pg_temp.t_values('fv4.example') LIKE '%ip_address_reachability=not_public%'
     AND pg_temp.t_heard(repeat('9c', 32), 'fv4.example') = '{ip_address_not_public:null>not_public}',
         'S40 that first value writes it as current and the event of its problem, and the item reads it';
  ASSERT api.fn_domain_problem_event_type('cname_takeover', 'vulnerable:svc') = 'cname_takeover_detected'
     AND api.fn_domain_problem_event_type('hosting', 'AS24940') IS NULL
     AND api.fn_domain_problem_event_type('ns', 'not_found') IS NULL
     AND api.fn_domain_problem_event_type('tls_protocol', 'not_public') IS NULL
     AND api.fn_domain_problem_event_type(NULL, NULL) IS NULL,
         'S40 a value names its problem only with its own kind';
END
$$;

DO $$
BEGIN
  PERFORM pg_temp.t_item('tls1.example', repeat('9c', 32), 'dns_lookup');
  PERFORM pg_temp.t_record_dns('tls1.example', p_ns => 'n1');
  PERFORM pg_temp.t_record_dns('tls1.example', p_ns => 'n2');
  ASSERT pg_temp.t_candidate('tls1.example', 'ns') LIKE 'n2|%', 'S41 ns n2 is the candidate';
  PERFORM pg_temp.t_record_tls('tls1.example', p_tls_protocol => 'TLSv1.3');
  ASSERT pg_temp.t_next_scan('tls1.example', p_endpoint_name => 'ssl_check') = api.fn_domain_watch_next_daily_scan_at('tls1.example'),
         'S41 a DNS candidate does not bring the next scan of the ssl_check item';
  PERFORM pg_temp.t_record_tls('tls1.example', p_tls_protocol => 'TLSv1.2');
  ASSERT pg_temp.t_candidate('tls1.example', 'tls_protocol') LIKE 'TLSv1.2|%', 'S41 TLSv1.2 is the candidate';
  PERFORM pg_temp.t_record_dns('tls1.example', p_ns => 'n1');
  ASSERT pg_temp.t_next_scan('tls1.example') = api.fn_domain_watch_next_daily_scan_at('tls1.example'),
         'S41 a TLS candidate does not bring the next scan of the dns_lookup item';

  DELETE FROM watchlist_item AS wi
   WHERE wi.item_id IN (SELECT wid.item_id FROM watchlist_item_domain AS wid WHERE wid.domain_name = 'tls1.example');
  PERFORM api.fn_domain_watch_purge_unwatched(1000);
  ASSERT NOT EXISTS (SELECT 1 FROM domain_watch_lane AS dwl WHERE dwl.domain_name = 'tls1.example'),
         'S41 the unwatched purge deletes the lane row with its domain';
END
$$;

SELECT pg_temp.t_add_tls('tls8.example');
SELECT pg_temp.t_add_tls('tls9.example');
DO $$
DECLARE
  other_before text;
BEGIN
  PERFORM pg_temp.t_record_tls('tls9.example', p_tls_protocol => 'TLSv1.3');
  PERFORM pg_temp.t_record_tls('tls9.example', p_tls_protocol => 'TLSv1.2');
  ASSERT pg_temp.t_candidate('tls9.example', 'tls_protocol') LIKE 'TLSv1.2|%', 'S42 TLSv1.2 is the candidate of tls9.example';
  UPDATE domain_watch_lane AS dwl SET claimed_until = now() + interval '5 minutes' WHERE dwl.domain_name = 'tls9.example';
  other_before := pg_temp.t_lane_snapshot('tls9.example');
  PERFORM pg_temp.t_record_tls('tls8.example', p_tls_protocol => 'TLSv1.3');
  ASSERT pg_temp.t_next_scan('tls8.example', p_endpoint_name => 'ssl_check') = api.fn_domain_watch_next_daily_scan_at('tls8.example'),
         'S42 a candidate of another domain does not bring the next TLS scan';
  ASSERT pg_temp.t_lane_snapshot('tls9.example') = other_before, 'S42 the record of tls8.example leaves tls9.example as it was';
END
$$;

SELECT pg_temp.t_add_tls('m1.example');
SELECT pg_temp.t_add_dns('m2.example');
SELECT pg_temp.t_add_tls('m3.example');
DO $$
DECLARE
  hour_later CONSTANT timestamptz := now() + interval '1 hour';
BEGIN
  PERFORM pg_temp.t_record_tls('m1.example', p_tls_protocol => 'TLSv1.3');
  ASSERT pg_temp.t_next_scan('m1.example', p_endpoint_name => 'ssl_check') = api.fn_domain_watch_next_daily_scan_at('m1.example'),
         'S43 a first TLS scan brings the next scan at the daily second';
  PERFORM pg_temp.t_record_tls('m1.example', p_tls_protocol => 'TLSv1.2');
  ASSERT pg_temp.t_next_scan('m1.example', p_endpoint_name => 'ssl_check') = hour_later,
         'S43 a TLS candidate where the kind had none brings the next scan one hour after now';
  PERFORM pg_temp.t_record_tls('m1.example');
  ASSERT pg_temp.t_next_scan('m1.example', p_endpoint_name => 'ssl_check') = api.fn_domain_watch_next_daily_scan_at('m1.example'),
         'S43 a TLS scan that read no value brings no hourly scan while a candidate waits';
  PERFORM pg_temp.t_record_tls('m1.example', p_tls_protocol => 'TLSv1.2');
  ASSERT pg_temp.t_next_scan('m1.example', p_endpoint_name => 'ssl_check') = hour_later
     AND pg_temp.t_candidate('m1.example', 'tls_protocol') LIKE 'TLSv1.2|%',
         'S43 the waiting TLS candidate seen again before its hour keeps the hourly rescan';
  PERFORM pg_temp.t_record_tls('m1.example', p_tls_protocol => 'TLSv1');
  ASSERT pg_temp.t_next_scan('m1.example', p_endpoint_name => 'ssl_check') = api.fn_domain_watch_next_daily_scan_at('m1.example')
     AND pg_temp.t_candidate('m1.example', 'tls_protocol') LIKE 'TLSv1|%',
         'S43 another TLS value in place of the waiting candidate brings no hourly scan';
  PERFORM pg_temp.t_record_tls('m1.example', p_certificate_validity => 'valid');
  ASSERT pg_temp.t_next_scan('m1.example', p_endpoint_name => 'ssl_check') = api.fn_domain_watch_next_daily_scan_at('m1.example'),
         'S43 a first value of another TLS kind brings no hourly scan';
  PERFORM pg_temp.t_record_tls('m1.example', p_certificate_validity => 'expired');
  ASSERT pg_temp.t_next_scan('m1.example', p_endpoint_name => 'ssl_check') = hour_later,
         'S43 a candidate of a TLS kind that had none brings the hourly scan, while another kind keeps its candidate';

  PERFORM pg_temp.t_record_dns('m2.example', p_ns => 'n1');
  ASSERT pg_temp.t_next_scan('m2.example') = api.fn_domain_watch_next_daily_scan_at('m2.example'), 'S43 a first DNS scan brings the next scan at the daily second';
  PERFORM pg_temp.t_record_dns('m2.example', p_ns => 'n2');
  ASSERT pg_temp.t_next_scan('m2.example') = hour_later, 'S43 a DNS candidate where the kind had none brings the next scan one hour after now';
  PERFORM pg_temp.t_record_dns('m2.example', p_mx => 'mx1');
  ASSERT pg_temp.t_next_scan('m2.example') = api.fn_domain_watch_next_daily_scan_at('m2.example'),
         'S43 a DNS scan that read no ns value brings no hourly scan while the ns candidate waits';
  PERFORM pg_temp.t_record_dns('m2.example', p_ns => 'n3');
  ASSERT pg_temp.t_next_scan('m2.example') = api.fn_domain_watch_next_daily_scan_at('m2.example')
     AND pg_temp.t_candidate('m2.example', 'ns') LIKE 'n3|%',
         'S43 another DNS value in place of the waiting candidate brings no hourly scan';
  PERFORM pg_temp.t_record_dns('m2.example', p_ns => 'n3');
  ASSERT pg_temp.t_next_scan('m2.example') = hour_later, 'S43 the waiting DNS candidate seen again before its hour keeps the hourly rescan';

  PERFORM pg_temp.t_record_tls('m3.example', p_tls_protocol => 'TLSv1.3');
  PERFORM pg_temp.t_record_tls('m3.example', p_tls_protocol => 'TLSv1');
  PERFORM pg_temp.t_age('m3.example', 'tls_protocol', interval '20 minutes');
  PERFORM pg_temp.t_dw_mark();
  ASSERT pg_temp.t_record_tls('m3.example', p_tls_protocol => 'TLSv1') = 0
     AND pg_temp.t_candidate('m3.example', 'tls_protocol') = 'TLSv1|00:20:00',
         'S43 a scan 20 minutes after the candidate sees it again and keeps it unconfirmed';
  ASSERT pg_temp.t_next_scan('m3.example', p_endpoint_name => 'ssl_check') = hour_later, 'S43 that scan keeps the hourly rescan';
  PERFORM pg_temp.t_age('m3.example', 'tls_protocol', interval '80 minutes');
  ASSERT pg_temp.t_record_tls('m3.example', p_tls_protocol => 'TLSv1') = 1, 'S43 the scan after the hour answers 1 event';
  ASSERT pg_temp.t_dw_events('m3.example') = '{tls_downgraded:TLSv1.3>TLSv1}',
         'S43 the scan after the hour confirms the candidate and writes its event';
  ASSERT pg_temp.t_next_scan('m3.example', p_endpoint_name => 'ssl_check') = api.fn_domain_watch_next_daily_scan_at('m3.example'),
         'S43 the confirming scan brings the daily scan';
END
$$;

SELECT pg_temp.t_add_tls('m5.example');
SELECT pg_temp.t_add_dns('m6.example');
SELECT pg_temp.t_add_tls('m7.example');
DO $$
DECLARE
  hour_later CONSTANT timestamptz := now() + interval '1 hour';
BEGIN
  PERFORM pg_temp.t_record_tls('m5.example', p_certificate_validity => 'valid', p_tls_protocol => 'TLSv1.3');
  PERFORM pg_temp.t_record_tls('m5.example', p_certificate_validity => 'self_signed', p_tls_protocol => 'TLSv1.3');
  ASSERT pg_temp.t_next_scan('m5.example', p_endpoint_name => 'ssl_check') = hour_later,
         'S44 a TLS candidate keeps the hourly rescan while another kind only sees its current value again';
  PERFORM pg_temp.t_record_tls('m5.example', p_certificate_validity => 'valid', p_tls_protocol => 'TLSv1.2');
  ASSERT pg_temp.t_next_scan('m5.example', p_endpoint_name => 'ssl_check') = api.fn_domain_watch_next_daily_scan_at('m5.example')
     AND pg_temp.t_candidate('m5.example', 'tls_protocol') LIKE 'TLSv1.2|%',
         'S44 an earlier TLS kind that clears its candidate brings the daily scan, though a later kind got one';
  PERFORM pg_temp.t_record_tls('m5.example', p_certificate_validity => 'self_signed', p_tls_protocol => 'TLSv1.3');
  ASSERT pg_temp.t_next_scan('m5.example', p_endpoint_name => 'ssl_check') = api.fn_domain_watch_next_daily_scan_at('m5.example'),
         'S44 a later TLS kind that clears its candidate brings the daily scan, though an earlier kind got one';
  PERFORM pg_temp.t_record_tls('m5.example', p_certificate_validity => 'expired', p_tls_protocol => 'TLSv1.2');
  ASSERT pg_temp.t_next_scan('m5.example', p_endpoint_name => 'ssl_check') = api.fn_domain_watch_next_daily_scan_at('m5.example')
     AND pg_temp.t_dw_events('m5.example') = '{}',
         'S44 a TLS kind whose candidate another value replaces brings the daily scan, and the turns write no event';

  PERFORM pg_temp.t_record_tls('m7.example', p_certificate_expiry => '30', p_certificate_validity => 'valid', p_tls_protocol => 'TLSv1.3');
  PERFORM pg_temp.t_record_tls('m7.example', p_certificate_expiry => '7');
  PERFORM pg_temp.t_record_tls('m7.example', p_certificate_expiry => '30', p_certificate_validity => 'self_signed', p_tls_protocol => 'TLSv1.3');
  ASSERT pg_temp.t_next_scan('m7.example', p_endpoint_name => 'ssl_check') = api.fn_domain_watch_next_daily_scan_at('m7.example'),
         'S44 a later TLS kind that sees its current value again keeps the loss of an earlier kind, though a kind between got a candidate';

  PERFORM pg_temp.t_record_dns('m6.example', p_ns => 'n1', p_mx => 'mx1');
  PERFORM pg_temp.t_record_dns('m6.example', p_ns => 'n2', p_mx => 'mx1');
  ASSERT pg_temp.t_next_scan('m6.example') = hour_later,
         'S44 a DNS candidate keeps the hourly rescan while another kind only sees its current value again';
  PERFORM pg_temp.t_record_dns('m6.example', p_ns => 'n1', p_mx => 'mx2');
  ASSERT pg_temp.t_next_scan('m6.example') = api.fn_domain_watch_next_daily_scan_at('m6.example'),
         'S44 an earlier DNS kind that clears its candidate brings the daily scan, though a later kind got one';
  PERFORM pg_temp.t_record_dns('m6.example', p_ns => 'n2', p_mx => 'mx1');
  ASSERT pg_temp.t_next_scan('m6.example') = api.fn_domain_watch_next_daily_scan_at('m6.example'),
         'S44 a later DNS kind that clears its candidate brings the daily scan, though an earlier kind got one';
  PERFORM pg_temp.t_record_dns('m6.example', p_ns => 'n3', p_mx => 'mx2');
  ASSERT pg_temp.t_next_scan('m6.example') = api.fn_domain_watch_next_daily_scan_at('m6.example')
     AND pg_temp.t_dw_events('m6.example') = '{}',
         'S44 a DNS kind whose candidate another value replaces brings the daily scan, and the turns write no event';

  ASSERT api.fn_domain_problem_event_type('cname_takeover', 'vulnerable') = 'cname_takeover_detected'
     AND api.fn_domain_problem_event_type('cname_takeover', 'vulnerable svc') = 'cname_takeover_detected',
         'S44 the cname_takeover values the producer writes show cname_takeover_detected';
  ASSERT api.fn_domain_problem_event_type('certificate_listing', 'listed') = 'cert_listed',
         'S44 a listed certificate with no reason shows cert_listed';
END
$$;

SELECT pg_temp.t_add_tls('p1.example');
DO $$
DECLARE
  listed CONSTANT text := E'listed\nmalware C&C';
BEGIN
  ASSERT pg_temp.t_record_tls('p1.example', p_certificate_validity => 'valid') = 0, 'S45 the first scan of the 9c item writes no event';
  PERFORM pg_temp.t_item('p1.example', repeat('a1', 32), 'ssl_check');
  ASSERT pg_temp.t_record_tls('p1.example', p_certificate_validity => 'valid') = 0, 'S45 the first scan of the a1 item writes no event';
  PERFORM pg_temp.t_item('p1.example', repeat('b1', 32), 'ssl_check');
  ASSERT pg_temp.t_record_tls('p1.example', p_certificate_validity => 'valid') = 0, 'S45 the first scan of the b1 item writes no event';
  ASSERT pg_temp.t_record_tls('p1.example', p_certificate_validity => 'valid', p_certificate_listing => listed) = 1,
         'S45 the first listing value writes one event row for the three items';
  ASSERT (SELECT count(*) FROM watchlist_event_ref AS wer JOIN domain_change_event AS dce ON dce.event_id = wer.event_id
           WHERE dce.domain_name = 'p1.example') = 3,
         'S45 each of the three items hears the event through its own ref';
  ASSERT pg_temp.t_heard(repeat('9c', 32), 'p1.example') = ARRAY['cert_listed:null>listed+malware C&C']
     AND pg_temp.t_heard(repeat('a1', 32), 'p1.example') = ARRAY['cert_listed:null>listed+malware C&C']
     AND pg_temp.t_heard(repeat('b1', 32), 'p1.example') = ARRAY['cert_listed:null>listed+malware C&C'],
         'S45 each key reads the one event';
  ASSERT pg_temp.t_record_tls('p1.example', p_certificate_validity => 'valid', p_certificate_listing => listed) = 0,
         'S45 the next scan writes no event';
END
$$;

SELECT pg_temp.t_add_dns('n7.example');
SELECT pg_temp.t_item('n7.example', repeat('9c', 32), 'ssl_check', now() - interval '1 minute');
DO $$
BEGIN
  PERFORM pg_temp.t_record_dns('n7.example', p_dns_presence => 'found');
  ASSERT pg_temp.t_values('n7.example') = 'dns_presence=found'
     AND pg_temp.t_next_scan('n7.example', p_endpoint_name => 'ssl_check') = now() - interval '1 minute',
         'S46 a DNS scan writes no value of the ssl_check item and leaves its next scan';
  PERFORM pg_temp.t_record_tls('n7.example', p_tls_protocol => 'TLSv1.3', p_claimed_at => now());
  ASSERT pg_temp.t_values('n7.example') = 'dns_presence=found tls_protocol=TLSv1.3'
     AND pg_temp.t_next_scan('n7.example') = api.fn_domain_watch_next_daily_scan_at('n7.example'),
         'S46 a TLS scan writes the values of the ssl_check item only and leaves the next scan of the dns_lookup item';
END
$$;

CREATE FUNCTION pg_temp.t_view(p_key_hash text) RETURNS text LANGUAGE sql AS $$
  INSERT INTO watchlist_key_state (api_key_id, last_cve_event_id)
  SELECT ak.id, api.fn_cve_change_event_max_id() FROM api_keys AS ak WHERE ak.key_hash = p_key_hash
  ON CONFLICT (api_key_id) DO UPDATE SET last_key_event_id = 0, max_purged_key_event_id = 0, last_cve_event_id = EXCLUDED.last_cve_event_id;
  INSERT INTO watchlist_event_cursor (api_key_id, previous_cursor, delivered_cursor)
  SELECT ak.id, 0, 0 FROM api_keys AS ak WHERE ak.key_hash = p_key_hash
  ON CONFLICT (api_key_id) DO UPDATE SET previous_cursor = 0, delivered_cursor = 0;
  UPDATE watchlist_event_ref AS wer SET key_event_id = NULL
   WHERE wer.api_key_id = (SELECT ak.id FROM api_keys AS ak WHERE ak.key_hash = p_key_hash);
  SELECT coalesce(string_agg(row(x.events_status, x.next_cursor, x.item_endpoint_name, x.item_domain_name, x.event_rank, x.is_first_row_of_event,
                                 x.event_type, x.changed_at, x.degraded_email_check_id, x.previous_domain_value, x.current_domain_value,
                                 x.is_first_event_of_domain, x.registered_domain, x.dns_presence_value, x.ns_value, x.mx_value,
                                 x.ip_address_reachability_value, x.cname_takeover_value, x.email_auth_value)::text, E'\n' ORDER BY x.ordinality), '')
    FROM api.fn_watchlist_events(p_key_hash, NULL, false, 1000, 100000, 600) WITH ORDINALITY AS x;
$$;

CREATE FUNCTION pg_temp.t_isolated(p_scenario text, p_with_other boolean) RETURNS text LANGUAGE plpgsql AS $$
DECLARE
  answer text;
BEGIN
  BEGIN
    EXECUTE format('SELECT pg_temp.%I($1)', p_scenario) INTO answer USING p_with_other;
    RAISE SQLSTATE 'TUNDO';
  EXCEPTION WHEN SQLSTATE 'TUNDO' THEN
    NULL;
  END;
  RETURN answer;
END
$$;

CREATE FUNCTION pg_temp.t_edit_domain(p_key_hash text, p_action text, p_endpoint_name text, p_domain_name text, p_registered_domain text,
                                      p_domain_name_max_count integer DEFAULT 20) RETURNS text LANGUAGE sql AS $$
  SELECT string_agg(DISTINCT x.edit_status, ',')
    FROM pg_temp.t_watchlist_edit(p_key_hash, p_action, p_endpoint_name, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, false, 100,
                                  p_domain_name, p_registered_domain, p_domain_name_max_count, NULL, NULL, NULL, 500, 100, 100000, 20) AS x
$$;

SELECT pg_temp.t_reset();

CREATE FUNCTION pg_temp.t_s47(p_with_other boolean) RETURNS text LANGUAGE plpgsql AS $$
BEGIN
  IF p_with_other THEN
    PERFORM pg_temp.t_item('l1.example', repeat('a1', 32), 'dns_lookup');
    PERFORM pg_temp.t_item('l1.example', repeat('a1', 32), 'ssl_check');
    PERFORM pg_temp.t_record_dns('l1.example', p_dns_presence => 'found', p_ip_address_reachability => 'public');
    PERFORM pg_temp.t_record_tls('l1.example', p_certificate_validity => 'valid', p_tls_protocol => 'TLSv1.3');
  END IF;
  PERFORM pg_temp.t_item('l1.example', repeat('b1', 32), 'dns_lookup');
  PERFORM pg_temp.t_item('l1.example', repeat('b1', 32), 'ssl_check');
  PERFORM pg_temp.t_record_dns('l1.example', p_dns_presence => 'found');
  PERFORM pg_temp.t_record_tls('l1.example', p_tls_protocol => 'TLSv1.3');
  PERFORM pg_temp.t_record_dns('l1.example', p_dns_presence => 'found', p_ip_address_reachability => 'not_public');
  PERFORM pg_temp.t_record_tls('l1.example', p_certificate_validity => 'expired', p_tls_protocol => 'TLSv1.3');
  RETURN pg_temp.t_view(repeat('b1', 32));
END
$$;
DO $$
DECLARE
  alone  text := pg_temp.t_isolated('t_s47', false);
  shared text := pg_temp.t_isolated('t_s47', true);
BEGIN
  ASSERT alone LIKE '%ip_address_not_public%not_public%' AND alone LIKE '%cert_invalid%expired%' AND alone LIKE '%(ok,2,dns_lookup,l1.example,1,t,ip_address_not_public,%,,,not_public,t,l1.example,found,,,not_public,,)%',
         'S47 key B alone hears ip_address_not_public with no previous value, and cert_invalid of expired: ' || alone;
  ASSERT shared = alone, 'S47 key B beside key A reads what it reads alone: ' || shared;
END
$$;

CREATE FUNCTION pg_temp.t_s48(p_with_other boolean) RETURNS text LANGUAGE plpgsql AS $$
BEGIN
  IF p_with_other THEN
    PERFORM pg_temp.t_item('l2.example', repeat('a1', 32), 'dns_lookup');
    PERFORM pg_temp.t_record_dns('l2.example', p_dns_presence => 'found', p_ns => 'nsA');
  END IF;
  PERFORM pg_temp.t_item('l2.example', repeat('b1', 32), 'dns_lookup');
  PERFORM pg_temp.t_record_dns('l2.example', p_dns_presence => 'not_found', p_ns => 'nsB');
  RETURN pg_temp.t_view(repeat('b1', 32));
END
$$;
DO $$
DECLARE
  alone  text := pg_temp.t_isolated('t_s48', false);
  shared text := pg_temp.t_isolated('t_s48', true);
BEGIN
  ASSERT alone LIKE '%domain_not_found%,l2.example,not_found,nsB,,,,)' AND alone NOT LIKE '%nsA%',
         'S48 key B alone hears its first problem, and its map shows its own ns: ' || alone;
  ASSERT shared = alone, 'S48 key B beside key A reads what it reads alone, and not the ns of key A: ' || shared;
END
$$;

SELECT pg_temp.t_item('l7.example', repeat('a1', 32), 'dns_lookup', now() - interval '1 hour');
DO $$
DECLARE
  lease_end  timestamptz;
  b_item_due timestamptz;
BEGIN
  SELECT x.claimed_until INTO lease_end FROM api.fn_domain_watch_claim('dns', 10, 300) AS x WHERE x.domain_name = 'l7.example';
  ASSERT lease_end IS NOT NULL, 'S49 the claim leases l7.example';
  ASSERT pg_temp.t_edit_domain(repeat('b1', 32), 'add', 'dns_lookup', 'l7.example', 'l7.example') = 'ok', 'S49 key B adds l7.example';
  b_item_due := pg_temp.t_next_scan('l7.example', repeat('b1', 32));
  ASSERT b_item_due > (SELECT dwl.claimed_at FROM domain_watch_lane AS dwl WHERE dwl.domain_name = 'l7.example' AND dwl.lane_name = 'dns'),
         'S49 the new item is due after the claimed_at of the claim that came before the add';
  ASSERT api.fn_domain_watch_record_dns('l7.example', lease_end, 'found', pg_temp.t_sha256('found'), NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
                                        NULL, NULL, NULL, NULL, 40) = 0,
         'S49 the record of that lease answers 0';
  ASSERT pg_temp.t_values('l7.example', repeat('a1', 32)) = 'dns_presence=found' AND pg_temp.t_values('l7.example', repeat('b1', 32)) = ''
     AND pg_temp.t_next_scan('l7.example', repeat('b1', 32)) = b_item_due,
         'S49 the record serves key A''s item, and leaves the new item with no value and its next scan';
  UPDATE domain_watch_lane AS dwl SET claimed_until = now() + interval '10 minutes', claimed_at = clock_timestamp() WHERE dwl.domain_name = 'l7.example' AND dwl.lane_name = 'dns';
  PERFORM api.fn_domain_watch_record_dns('l7.example', now() + interval '10 minutes', 'found', pg_temp.t_sha256('found'), NULL, NULL, NULL, NULL,
                                         NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 40);
  ASSERT pg_temp.t_values('l7.example', repeat('b1', 32)) = 'dns_presence=found',
         'S49 a claim after the add serves the new item';
  ASSERT regexp_replace(pg_get_functiondef('api.fn_watchlist_item_edit(text, text, text, text, text, text, text, text, real, real, boolean, boolean, boolean, integer, text, text, integer, text, text, text, integer, integer, integer, integer, inet)'::regprocedure), '--[^\n]*', '', 'g')
         ~ 'ON CONFLICT ON CONSTRAINT domain_watch_pkey DO UPDATE SET domain_name = EXCLUDED\.domain_name;.*ON CONFLICT ON CONSTRAINT domain_watch_lane_pkey DO UPDATE SET lane_name = EXCLUDED\.lane_name;.*INSERT INTO public\.watchlist_item_domain \(item_id, api_key_id, endpoint_name, domain_name, registered_domain, next_scan_at\)\s+VALUES \(new_item_id, caller_api_key_id, p_endpoint_name, p_domain_name, p_registered_domain, clock_timestamp\(\)\);',
         'S49 the add takes the next_scan_at of its item from clock_timestamp(), after it locked the domain row and its lane row';
END
$$;

CREATE FUNCTION pg_temp.t_s50(p_with_other boolean) RETURNS text LANGUAGE plpgsql AS $$
BEGIN
  PERFORM pg_temp.t_item('l8.example', repeat('a1', 32), 'dns_lookup');
  PERFORM pg_temp.t_record_dns('l8.example', p_ns => 'n1');
  PERFORM pg_temp.t_record_dns('l8.example', p_ns => 'n2');
  IF p_with_other THEN
    ASSERT pg_temp.t_edit_domain(repeat('b1', 32), 'add', 'dns_lookup', 'l8.example', 'l8.example') = 'ok', 'S50 key B adds l8.example';
    ASSERT pg_temp.t_next_scan('l8.example', repeat('a1', 32)) = now() + interval '1 hour', 'S50 the add of key B leaves the next scan of key A';
    PERFORM pg_temp.t_record_dns('l8.example', p_ns => 'n3', p_claimed_at => clock_timestamp());
    ASSERT pg_temp.t_values('l8.example', repeat('b1', 32)) = 'ns=n3' AND pg_temp.t_candidate('l8.example', 'ns', repeat('a1', 32)) = 'n2|00:00:00',
           'S50 the scan after the add gives key B''s item its first value, and key A''s candidate stays';
    UPDATE watchlist_item_domain AS wid SET next_scan_at = now() + interval '2 hours'
     WHERE wid.item_id IN (SELECT w.item_id FROM watchlist_item_domain AS w JOIN api_keys AS ak ON ak.id = w.api_key_id
                            WHERE w.domain_name = 'l8.example' AND ak.key_hash = repeat('b1', 32));
  END IF;
  PERFORM pg_temp.t_age('l8.example', 'ns', interval '1 hour');
  PERFORM pg_temp.t_record_dns('l8.example', p_ns => 'n2', p_claimed_at => now() + interval '1 hour');
  IF p_with_other THEN
    ASSERT pg_temp.t_next_scan('l8.example', repeat('b1', 32)) = now() + interval '2 hours' AND pg_temp.t_values('l8.example', repeat('b1', 32)) = 'ns=n3',
           'S50 key A''s hourly scan does not serve key B''s item, which is not due';
  END IF;
  RETURN pg_temp.t_view(repeat('a1', 32)) || E'\n' || (pg_temp.t_next_scan('l8.example', repeat('a1', 32)) = api.fn_domain_watch_next_daily_scan_at('l8.example'))::text;
END
$$;
DO $$
DECLARE
  alone  text := pg_temp.t_isolated('t_s50', false);
  shared text := pg_temp.t_isolated('t_s50', true);
BEGIN
  ASSERT alone LIKE '%ns_changed%,n1,n2,%' AND alone LIKE '%' || E'\n' || 'true',
         'S50 key A alone confirms n1 to n2 in its hourly scan and gets its daily scan: ' || alone;
  ASSERT shared = alone, 'S50 key A beside key B reads what it reads alone and keeps the same next scan: ' || shared;
END
$$;

CREATE FUNCTION pg_temp.t_s51(p_with_other boolean) RETURNS text LANGUAGE plpgsql AS $$
BEGIN
  IF p_with_other THEN
    PERFORM pg_temp.t_item('l10.example', repeat('a1', 32), 'dns_lookup');
    PERFORM pg_temp.t_record_dns('l10.example', p_ns => 'nA');
  END IF;
  PERFORM pg_temp.t_item('l10.example', repeat('b1', 32), 'dns_lookup');
  PERFORM pg_temp.t_record_dns('l10.example', p_ns => 'nB');
  PERFORM pg_temp.t_record_dns('l10.example', p_ns => 'nC');
  PERFORM pg_temp.t_age('l10.example', 'ns', interval '1 hour');
  PERFORM pg_temp.t_dw_mark();
  ASSERT pg_temp.t_record_dns('l10.example', p_ns => 'nC') = CASE WHEN p_with_other THEN 2 ELSE 1 END,
         'S51 two items with different previous values make two event rows';
  RETURN pg_temp.t_view(repeat('b1', 32));
END
$$;
DO $$
DECLARE
  alone  text := pg_temp.t_isolated('t_s51', false);
  shared text := pg_temp.t_isolated('t_s51', true);
BEGIN
  ASSERT alone LIKE '%ns_changed%,nB,nC,%' AND alone NOT LIKE '%nA%', 'S51 key B alone hears nB to nC: ' || alone;
  ASSERT shared = alone, 'S51 key B beside key A hears its own previous value, never key A''s: ' || shared;
END
$$;

CREATE FUNCTION pg_temp.t_s52(p_with_other boolean) RETURNS text LANGUAGE plpgsql AS $$
BEGIN
  IF p_with_other THEN
    PERFORM pg_temp.t_item('l6.example', repeat('a1', 32), 'dns_lookup');
    PERFORM pg_temp.t_record_dns('l6.example', p_email_auth => 'pp', p_email_check_ids => 'spf_all,dmarc_policy');
  END IF;
  PERFORM pg_temp.t_item('l6.example', repeat('b1', 32), 'dns_lookup');
  PERFORM pg_temp.t_record_dns('l6.example', p_email_auth => 'fp', p_email_check_ids => 'spf_all,dmarc_policy');
  PERFORM pg_temp.t_record_dns('l6.example', p_email_auth => 'ff', p_email_check_ids => 'spf_all,dmarc_policy');
  PERFORM pg_temp.t_age('l6.example', 'email_auth', interval '1 hour');
  PERFORM pg_temp.t_dw_mark();
  PERFORM pg_temp.t_record_dns('l6.example', p_email_auth => 'ff', p_email_check_ids => 'spf_all,dmarc_policy');
  IF p_with_other THEN
    ASSERT pg_temp.t_dw_events('l6.example')
           = '{email_auth_degraded:spf_all:pp>ff,email_auth_degraded:dmarc_policy:pp>ff,email_auth_degraded:dmarc_policy:fp>ff}',
           'S52 key A gets both checks from pp, and key B one check from fp';
  END IF;
  RETURN pg_temp.t_view(repeat('b1', 32));
END
$$;
DO $$
DECLARE
  alone  text := pg_temp.t_isolated('t_s52', false);
  shared text := pg_temp.t_isolated('t_s52', true);
BEGIN
  ASSERT alone LIKE '%email_auth_degraded%,dmarc_policy,fp,ff,%' AND alone NOT LIKE '%spf_all%',
         'S52 key B alone hears one degraded check: ' || alone;
  ASSERT shared = alone, 'S52 key B beside key A reads its degraded checks from its own current value: ' || shared;
END
$$;

CREATE FUNCTION pg_temp.t_s53(p_with_other boolean) RETURNS text LANGUAGE plpgsql AS $$
DECLARE
  statuses text;
BEGIN
  IF p_with_other THEN
    ASSERT pg_temp.t_edit_domain(repeat('a1', 32), 'add', 'dns_lookup', 'x.l11.example', 'other.example') = 'ok', 'S53 key A adds x.l11.example';
  END IF;
  statuses := pg_temp.t_edit_domain(repeat('b1', 32), 'add', 'dns_lookup', 'x.l11.example', 'l11.example', 1) || ','
              || pg_temp.t_edit_domain(repeat('b1', 32), 'add', 'dns_lookup', 'y.l11.example', 'l11.example', 1);
  PERFORM pg_temp.t_record_dns('x.l11.example', p_dns_presence => 'not_found');
  RETURN statuses || E'\n' || pg_temp.t_view(repeat('b1', 32));
END
$$;
DO $$
DECLARE
  alone  text := pg_temp.t_isolated('t_s53', false);
  shared text := pg_temp.t_isolated('t_s53', true);
BEGIN
  ASSERT alone LIKE 'ok,over_domain_limit' || E'\n' || '%,x.l11.example,%,l11.example,not_found,%' AND alone NOT LIKE '%other.example%',
         'S53 key B alone reaches its cap at the second name, and its map shows its own registered domain: ' || alone;
  ASSERT shared = alone, 'S53 key B beside key A counts and shows its own registered domain: ' || shared;
END
$$;

CREATE FUNCTION pg_temp.t_s54(p_with_other boolean) RETURNS text LANGUAGE plpgsql AS $$
BEGIN
  IF p_with_other THEN
    PERFORM pg_temp.t_item('l18.example', repeat('a1', 32), 'dns_lookup');
    PERFORM pg_temp.t_record_dns('l18.example', p_dns_presence => 'not_found');
  END IF;
  ASSERT pg_temp.t_edit_domain(repeat('b1', 32), 'add', 'dns_lookup', 'l18.example', 'l18.example') = 'ok', 'S54 key B adds l18.example';
  PERFORM pg_temp.t_record_dns('l18.example', p_dns_presence => 'not_found');
  PERFORM pg_temp.t_record_dns('l18.example', p_dns_presence => 'found');
  PERFORM pg_temp.t_age('l18.example', 'dns_presence', interval '1 hour');
  PERFORM pg_temp.t_record_dns('l18.example', p_dns_presence => 'found');
  ASSERT pg_temp.t_heard(repeat('b1', 32), 'l18.example') = '{domain_not_found:null>not_found,domain_found:not_found>found}',
         'S54 the first item of key B heard its first value and its change';
  ASSERT pg_temp.t_edit_domain(repeat('b1', 32), 'remove', 'dns_lookup', 'l18.example', 'l18.example') = 'ok'
     AND pg_temp.t_edit_domain(repeat('b1', 32), 'add', 'dns_lookup', 'l18.example', 'l18.example') = 'ok',
         'S54 key B removes the name and adds it again';
  ASSERT pg_temp.t_values('l18.example', repeat('b1', 32)) = '', 'S54 the item added again has no value';
  PERFORM pg_temp.t_record_dns('l18.example', p_dns_presence => 'not_found');
  RETURN pg_temp.t_view(repeat('b1', 32));
END
$$;
DO $$
DECLARE
  alone  text := pg_temp.t_isolated('t_s54', false);
  shared text := pg_temp.t_isolated('t_s54', true);
BEGIN
  ASSERT alone LIKE '(ok,1,dns_lookup,l18.example,1,t,domain_not_found,%,,,not_found,t,l18.example,not_found,,,,,)' AND alone NOT LIKE '%' || E'\n' || '%',
         'S54 key B alone reads one event of its new item, a first value with no previous value: ' || alone;
  ASSERT shared = alone, 'S54 key B beside key A starts again from no value: ' || shared;
END
$$;

CREATE FUNCTION pg_temp.t_s55(p_with_other boolean) RETURNS text LANGUAGE plpgsql AS $$
DECLARE
  views text;
BEGIN
  IF p_with_other THEN
    PERFORM pg_temp.t_item('l19.example', repeat('a1', 32), 'dns_lookup');
    PERFORM pg_temp.t_record_dns('l19.example', p_dns_presence => 'found', p_ns => 'nA', p_email_auth => 'pp');
  END IF;
  PERFORM pg_temp.t_item('l19.example', repeat('b1', 32), 'ssl_check');
  PERFORM pg_temp.t_item('l19.example', repeat('b1', 32), 'dns_lookup', now() + interval '1 day');
  PERFORM pg_temp.t_record_tls('l19.example', p_certificate_validity => 'expired');
  views := pg_temp.t_view(repeat('b1', 32));
  PERFORM pg_temp.t_record_dns('l19.example', p_dns_presence => 'found', p_ns => 'nX', p_claimed_at => now() + interval '1 hour');
  views := views || E'\n' || pg_temp.t_view(repeat('b1', 32));
  PERFORM pg_temp.t_record_dns('l19.example', p_dns_presence => 'found', p_ns => 'nB');
  RETURN views || E'\n' || pg_temp.t_view(repeat('b1', 32));
END
$$;
DO $$
DECLARE
  alone  text := pg_temp.t_isolated('t_s55', false);
  shared text := pg_temp.t_isolated('t_s55', true);
BEGIN
  ASSERT alone = '(ok,1,ssl_check,l19.example,1,t,cert_invalid,' || to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')
                 || ',,,expired,t,l19.example,,,,,,)' || E'\n'
                 || '(ok,1,ssl_check,l19.example,1,t,cert_invalid,' || to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')
                 || ',,,expired,t,l19.example,,,,,,)' || E'\n'
                 || '(ok,1,ssl_check,l19.example,1,t,cert_invalid,' || to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')
                 || ',,,expired,t,l19.example,found,nB,,,,)',
         'S55 key B alone sees no DNS value until the scan that served its dns_lookup item: ' || alone;
  ASSERT shared = alone, 'S55 key B beside key A sees none of key A''s DNS values: ' || shared;
END
$$;

SELECT pg_temp.t_item('dd.example', repeat('a1', 32), 'dns_lookup');
SELECT pg_temp.t_item('dd.example', repeat('b1', 32), 'dns_lookup');
DO $$
DECLARE
  event_ids bigint[];
BEGIN
  PERFORM pg_temp.t_record_dns('dd.example', p_ns => 'n1');
  PERFORM pg_temp.t_add_dns('dd.example');
  PERFORM pg_temp.t_record_dns('dd.example', p_ns => 'n0');
  PERFORM pg_temp.t_record_dns('dd.example', p_ns => 'n2');
  PERFORM pg_temp.t_age('dd.example', 'ns', interval '1 hour');
  PERFORM pg_temp.t_dw_mark();
  ASSERT pg_temp.t_record_dns('dd.example', p_ns => 'n2') = 2, 'S56 three transitions with two previous values answer 2 event rows';
  ASSERT pg_temp.t_dw_events('dd.example') = '{ns_changed:n1>n2,ns_changed:n0>n2}', 'S56 the shared row comes first, then the other';
  event_ids := ARRAY(SELECT dce.event_id FROM domain_change_event AS dce WHERE dce.domain_name = 'dd.example' ORDER BY dce.event_id);
  ASSERT (SELECT array_agg(ak.key_hash || '=' || array_position(event_ids, wer.event_id) ORDER BY ak.key_hash)
            FROM watchlist_event_ref AS wer JOIN api_keys AS ak ON ak.id = wer.api_key_id WHERE wer.event_id = ANY (event_ids))
         = ARRAY[repeat('9c', 32) || '=2', repeat('a1', 32) || '=1', repeat('b1', 32) || '=1'],
         'S56 a1 and b1 hear the shared row, and 9c hears its own';
END
$$;

SELECT pg_temp.t_item('do.example', repeat('a1', 32), 'dns_lookup');
SELECT pg_temp.t_item('do.example', repeat('b1', 32), 'dns_lookup');
DO $$
BEGIN
  PERFORM pg_temp.t_record_dns('do.example', p_ns => 'n1', p_mx => 'm1');
  UPDATE watchlist_item_domain_value AS widv
     SET candidate_value = CASE widv.value_kind WHEN 'mx' THEN 'm2' ELSE 'n2' END,
         candidate_value_sha256 = pg_temp.t_sha256(CASE widv.value_kind WHEN 'mx' THEN 'm2' ELSE 'n2' END),
         candidate_seen_at = now() - interval '1 hour'
   WHERE widv.item_id IN (SELECT wid.item_id FROM watchlist_item_domain AS wid JOIN api_keys AS ak ON ak.id = wid.api_key_id
                           WHERE wid.domain_name = 'do.example'
                             AND ((ak.key_hash = repeat('a1', 32) AND widv.value_kind = 'mx') OR (ak.key_hash = repeat('b1', 32) AND widv.value_kind = 'ns')));
  PERFORM pg_temp.t_dw_mark();
  ASSERT pg_temp.t_record_dns('do.example', p_ns => 'n2', p_mx => 'm2') = 2, 'S56 the two confirmations answer 2 event rows';
  ASSERT pg_temp.t_dw_events('do.example') = '{ns_changed:n1>n2,mx_changed:m1>m2}',
         'S56 the ns event of the newer item comes before the mx event of the older item';
END
$$;

INSERT INTO api_keys (key_hash) VALUES (repeat('c1', 32));
SELECT pg_temp.t_item('sc.example', repeat('a1', 32), 'dns_lookup');
DO $$
BEGIN
  PERFORM pg_temp.t_record_dns('sc.example', p_ns => 'n1');
  PERFORM pg_temp.t_item('sc.example', repeat('b1', 32), 'dns_lookup');
  PERFORM pg_temp.t_item('sc.example', repeat('9c', 32), 'dns_lookup', now() + interval '3 hours');
  PERFORM pg_temp.t_item('sc.example', repeat('c1', 32), 'dns_lookup', now() + interval '3 hours 1 second');
  UPDATE watchlist_item_domain AS wid SET next_scan_at = now() + interval '3 hours'
   WHERE wid.domain_name = 'sc.example' AND wid.api_key_id = (SELECT ak.id FROM api_keys AS ak WHERE ak.key_hash = repeat('a1', 32));
  PERFORM pg_temp.t_record_dns('sc.example', p_ns => 'n2', p_claimed_at => now() + interval '3 hours');
  ASSERT pg_temp.t_next_scan('sc.example', repeat('a1', 32)) = now() + interval '1 hour', 'S57 the item with a new candidate gets the hourly scan';
  ASSERT pg_temp.t_next_scan('sc.example', repeat('b1', 32)) = api.fn_domain_watch_next_daily_scan_at('sc.example'),
         'S57 the item with a first value gets the daily second in the same scan';
  ASSERT pg_temp.t_values('sc.example', repeat('9c', 32)) = 'ns=n2', 'S57 an item due exactly at claimed_at is served';
  ASSERT pg_temp.t_values('sc.example', repeat('c1', 32)) = '' AND pg_temp.t_next_scan('sc.example', repeat('c1', 32)) = now() + interval '3 hours 1 second',
         'S57 an item due after claimed_at keeps no value and its next scan';
END
$$;

DO $$
DECLARE
  f record;
BEGIN
  FOR f IN SELECT * FROM (VALUES
      ('api.fn_domain_watch_claim(text, integer, integer)'::regprocedure,         true, true),
      ('api.fn_domain_watch_dns_bucket_charge(text)'::regprocedure,                          false, false),
      ('api.fn_domain_watch_record_tls(text, timestamptz, text, text, text, text, text, text, text, text)'::regprocedure,
                                                                                         false, true),
      ('api.fn_domain_watch_record_rdap_whois(text, timestamptz, text, text, text, text, text, text, text, text, integer)'::regprocedure,
                                                                                         false, true),
      ('api.fn_domain_watch_record_headers(text, timestamptz, text, text, integer)'::regprocedure,
                                                                                         false, true),
      ('api.fn_domain_watch_record_ct(text, timestamptz, text, text, integer)'::regprocedure,
                                                                                         false, true),
      ('api.fn_domain_watch_write_scan_values(text, text, timestamptz, text[], text[], text)'::regprocedure,
                                                                                         false, false),
      ('api.fn_domain_watch_record_dns(text, timestamptz, text, text, text, text, text, text, text, text, text, text, text, text, text, text, integer)'::regprocedure,
                                                                                         false, true),
      ('api.fn_domain_change_event_purge(integer)'::regprocedure,                      true, true),
      ('api.fn_domain_watch_purge_unwatched(integer)'::regprocedure,                   true, true)) AS t (oid, is_strict, is_definer) LOOP
    ASSERT (SELECT p.prosecdef FROM pg_proc AS p WHERE p.oid = f.oid) = f.is_definer,
           f.oid::text || CASE WHEN f.is_definer THEN ' is SECURITY DEFINER' ELSE ' is SECURITY INVOKER' END;
    ASSERT (SELECT p.proconfig FROM pg_proc AS p WHERE p.oid = f.oid) = ARRAY['search_path=pg_catalog'],
           f.oid::text || ' sets search_path to pg_catalog';
    ASSERT (SELECT p.provolatile FROM pg_proc AS p WHERE p.oid = f.oid) = 'v', f.oid::text || ' is VOLATILE';
    ASSERT (SELECT p.proisstrict FROM pg_proc AS p WHERE p.oid = f.oid) = f.is_strict, f.oid::text || ' is STRICT only when it takes a row count';
  END LOOP;
  FOR f IN SELECT * FROM (VALUES
      ('api.fn_domain_change_event_type(text, text, text)'::regprocedure, 'i'::"char"),
      ('api.fn_domain_problem_event_type(text, text)'::regprocedure,      'i'::"char"),
      ('api.fn_domain_watch_next_daily_scan_at(text)'::regprocedure,      's'::"char"),
      ('api.fn_domain_watch_next_scan_at(text, boolean, boolean, text)'::regprocedure,
                                                                          's'::"char"),
      ('api.fn_domain_watch_next_weekly_scan_at(text)'::regprocedure,     's'::"char"),
      ('api.fn_domain_watch_registration_expires_at(text)'::regprocedure, 's'::"char"),
      ('api.fn_domain_watch_expiry_bucket_rank(text)'::regprocedure,      'i'::"char"),
      ('api.fn_domain_watch_lanes()'::regprocedure,                       'i'::"char"),
      ('api.fn_domain_watch_cert_issuers_union(text, text)'::regprocedure,
                                                                          'i'::"char"),
      ('api.fn_domain_watch_cert_unexpected_value(text, text)'::regprocedure,
                                                                          'i'::"char"),
      ('api.fn_domain_change_event_max_id()'::regprocedure,               's'::"char"),
      ('api.fn_domain_watch_dns_scan_cost()'::regprocedure,                   'i'::"char"),
      ('api.fn_domain_watch_dns_bucket_burst()'::regprocedure,                'i'::"char")) AS t (oid, volatility) LOOP
    ASSERT (SELECT NOT p.prosecdef FROM pg_proc AS p WHERE p.oid = f.oid), f.oid::text || ' is SECURITY INVOKER';
    ASSERT (SELECT p.proconfig FROM pg_proc AS p WHERE p.oid = f.oid) = ARRAY['search_path=pg_catalog'],
           f.oid::text || ' sets search_path to pg_catalog';
    ASSERT (SELECT p.provolatile FROM pg_proc AS p WHERE p.oid = f.oid) = f.volatility, f.oid::text || ' has its volatility';
    ASSERT (SELECT NOT p.proisstrict FROM pg_proc AS p WHERE p.oid = f.oid), f.oid::text || ' is not STRICT';
  END LOOP;
  ASSERT (SELECT count(*) FROM pg_proc AS p WHERE p.pronamespace = 'api'::regnamespace
             AND (p.proname LIKE 'fn_domain_watch%' OR p.proname LIKE 'fn_domain_change_event%' OR p.proname = 'fn_domain_problem_event_type')) = 23,
         'sql/fn_domain_watch.sql holds twenty-three functions';
  ASSERT regexp_replace(pg_get_functiondef('api.fn_domain_watch_record_dns(text, timestamptz, text, text, text, text, text, text, text, text, text, text, text, text, text, text, integer)'::regprocedure), '--[^\n]*', '', 'g')
         ~ 'FROM public\.domain_watch AS dw WHERE dw\.domain_name = p_domain_name FOR KEY SHARE;',
         'the DNS record holds the domain row with FOR KEY SHARE, as the other records do';
  ASSERT regexp_replace(pg_get_functiondef('api.fn_domain_watch_record_dns(text, timestamptz, text, text, text, text, text, text, text, text, text, text, text, text, text, text, integer)'::regprocedure), '--[^\n]*', '', 'g')
         !~ 'public\.domain_watch AS dw [^;]*FOR UPDATE',
         'the DNS record takes no FOR UPDATE lock of the domain row';
  ASSERT (SELECT count(*) FROM regexp_matches(regexp_replace(pg_get_functiondef('api.fn_domain_watch_claim(text, integer, integer)'::regprocedure), '--[^\n]*', '', 'g'),
                                               'FOR UPDATE (OF \w+ )?SKIP LOCKED', 'g')) = 2,
         'the claim skips a row another claim, a record or an add holds, both where it picks a row and where it holds back the rows of a refused bucket';
  ASSERT regexp_replace(pg_get_functiondef('api.fn_domain_watch_claim(text, integer, integer)'::regprocedure), '--[^\n]*', '', 'g')
         ~ 'ORDER BY due_item\.first_due_at, dwl\.scanned_at NULLS FIRST, dwl\.domain_name\s+LIMIT 1\s+FOR UPDATE OF dwl SKIP LOCKED;',
         'the claim locks the lane row it picks, and no item and no domain row';
  ASSERT regexp_replace(pg_get_functiondef('api.fn_domain_watch_claim(text, integer, integer)'::regprocedure), '--[^\n]*', '', 'g')
         ~ 'has_question_bucket\s+CONSTANT boolean := p_lane_name = ''dns'';.*CASE WHEN has_question_bucket THEN api\.fn_domain_watch_dns_bucket_charge\(picked_row\.registered_domain\) ELSE 0 END',
         'the claim pays from the question bucket in the dns lane only';
  ASSERT (SELECT count(*) FROM regexp_matches(regexp_replace(pg_get_functiondef('api.fn_domain_watch_dns_bucket_charge(text)'::regprocedure), '--[^\n]*', '', 'g'),
                                               'api\.fn_domain_watch_dns_scan_cost\(\)', 'g')) = 3,
         'the bucket take reads the scan cost from api.fn_domain_watch_dns_scan_cost where it compares, takes and waits';
  ASSERT (SELECT count(*) FROM regexp_matches(regexp_replace(pg_get_functiondef('api.fn_domain_watch_dns_bucket_charge(text)'::regprocedure), '--[^\n]*', '', 'g'),
                                               'api\.fn_domain_watch_dns_bucket_burst\(\)', 'g')) = 2,
         'the bucket take reads the burst from api.fn_domain_watch_dns_bucket_burst where it creates and refills a bucket';
  ASSERT regexp_replace(pg_get_functiondef('api.fn_domain_watch_dns_bucket_charge(text)'::regprocedure), '--[^\n]*', '', 'g')
         || regexp_replace(pg_get_functiondef('api.fn_domain_watch_claim(text, integer, integer)'::regprocedure), '--[^\n]*', '', 'g')
         !~ '(scan_cost|bucket_burst)\s+CONSTANT', 'the bucket take and the claim keep no copy of the scan cost or the burst';
  ASSERT regexp_replace(pg_get_functiondef('api.fn_domain_watch_claim(text, integer, integer)'::regprocedure), '--[^\n]*', '', 'g')
         ~ 'AND wid\.next_scan_at <= now\(\)\)\s+FOR UPDATE OF dwl2 SKIP LOCKED\);', 'the claim locks the rows of a refused bucket it holds back';
  ASSERT (SELECT count(*) FROM regexp_matches(regexp_replace(pg_get_functiondef('api.fn_domain_watch_purge_unwatched(integer)'::regprocedure), '--[^\n]*', '', 'g'),
                                               'LIMIT \S+\s+FOR UPDATE (OF \w+ )?SKIP LOCKED', 'g')) = 2,
         'the unwatched purge skips a domain and a bucket that another transaction holds';
END
$$;

DO $$
DECLARE
  v text := pg_temp.t_isolated('t_s47', false);
BEGIN
  ASSERT (SELECT count(*) FROM regexp_matches(v, ',t,l1\.example,', 'g')) = 1,
         'S58 the facts of l1.example come on one row, though its dns_lookup and ssl_check items both hear events: ' || v;
END
$$;

CREATE FUNCTION pg_temp.t_s59(p_with_other boolean) RETURNS text LANGUAGE plpgsql AS $$
BEGIN
  PERFORM pg_temp.t_item('g2.example', repeat('a1', 32), 'dns_lookup');
  PERFORM pg_temp.t_record_dns('g2.example', p_ns => 'n1');
  PERFORM pg_temp.t_record_dns('g2.example', p_ns => 'n2');
  IF p_with_other THEN
    ASSERT pg_temp.t_edit_domain(repeat('b1', 32), 'add', 'dns_lookup', 'g2.example', 'g2.example') = 'ok', 'S59 key B adds g2.example';
    PERFORM pg_temp.t_record_dns('g2.example', p_ns => 'n2', p_claimed_at => clock_timestamp());
    UPDATE watchlist_item_domain AS wid SET next_scan_at = now()
     WHERE wid.item_id IN (SELECT w.item_id FROM watchlist_item_domain AS w JOIN api_keys AS ak ON ak.id = w.api_key_id
                            WHERE w.domain_name = 'g2.example' AND ak.key_hash = repeat('b1', 32));
    PERFORM pg_temp.t_record_dns('g2.example', p_ns => 'n2', p_claimed_at => clock_timestamp());
    ASSERT pg_temp.t_values('g2.example', repeat('b1', 32)) = 'ns=n2', 'S59 key B holds n2 as its current value';
  END IF;
  PERFORM pg_temp.t_age('g2.example', 'ns', interval '1 hour');
  PERFORM pg_temp.t_record_dns('g2.example', p_ns => 'n2', p_claimed_at => now() + interval '1 hour');
  RETURN pg_temp.t_view(repeat('a1', 32));
END
$$;
DO $$
DECLARE
  alone  text := pg_temp.t_isolated('t_s59', false);
  shared text := pg_temp.t_isolated('t_s59', true);
BEGIN
  ASSERT alone LIKE '%ns_changed%,n1,n2,%', 'S59 key A alone confirms n1 to n2: ' || alone;
  ASSERT shared = alone, 'S59 key A beside key B reads what it reads alone: ' || shared;
END
$$;

CREATE FUNCTION pg_temp.t_record_rdap_whois(p_domain_name text, p_registration_expiry text DEFAULT NULL, p_registrar text DEFAULT NULL,
                                      p_transfer_lock text DEFAULT NULL, p_dnssec_delegation text DEFAULT NULL,
                                      p_claimed_at timestamptz DEFAULT now() + interval '2 days')
  RETURNS integer LANGUAGE plpgsql AS $$
BEGIN
  UPDATE domain_watch_lane AS dwl SET claimed_until = now() + interval '10 minutes', claimed_at = p_claimed_at
   WHERE dwl.domain_name = p_domain_name AND dwl.lane_name = 'rdap_whois';
  RETURN api.fn_domain_watch_record_rdap_whois(p_domain_name, now() + interval '10 minutes',
                                         p_registration_expiry, pg_temp.t_sha256(p_registration_expiry),
                                         p_registrar,           pg_temp.t_sha256(p_registrar),
                                         p_transfer_lock,       pg_temp.t_sha256(p_transfer_lock),
                                         p_dnssec_delegation,   pg_temp.t_sha256(p_dnssec_delegation),
                                         NULL);
END
$$;

CREATE FUNCTION pg_temp.t_lane_row(p_domain_name text, p_lane_name text) RETURNS text LANGUAGE sql AS $$
  SELECT dwl::text FROM domain_watch_lane AS dwl WHERE dwl.domain_name = p_domain_name AND dwl.lane_name = p_lane_name
$$;

CREATE FUNCTION pg_temp.t_utc_day(p_days integer) RETURNS text LANGUAGE sql AS $$
  SELECT to_char((now() AT TIME ZONE 'UTC') + p_days * interval '1 day', 'YYYY-MM-DD')
$$;

CREATE FUNCTION pg_temp.t_utc_time(p_time timestamptz) RETURNS text LANGUAGE sql AS $$
  SELECT to_char(p_time AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')
$$;

CREATE FUNCTION pg_temp.t_cadence(p_value text) RETURNS timestamptz LANGUAGE sql AS $$
  SELECT api.fn_domain_watch_next_scan_at(current_setting('t_domain_watch.cadence_name'), false, true, p_value)
$$;

SELECT pg_temp.t_reset();
SELECT pg_temp.t_add_rdap_whois('c1.example');
SELECT pg_temp.t_item('c1.example', repeat('9c', 32), 'ssl_check');
SELECT pg_temp.t_item('c1tls.example', repeat('9c', 32), 'ssl_check', now() - interval '1 hour');
INSERT INTO domain_watch_lane (domain_name, lane_name) VALUES ('c1tls.example', 'rdap_whois');
SELECT pg_temp.t_item('c1rdap.example', repeat('9c', 32), 'whois_lookup', now() - interval '1 hour');
INSERT INTO domain_watch_lane (domain_name, lane_name) VALUES ('c1rdap.example', 'tls');
UPDATE domain_watch_lane AS dwl
   SET claimed_until = now() + CASE dwl.lane_name WHEN 'tls' THEN interval '10 minutes' ELSE interval '20 minutes' END,
       claimed_at    = now() + interval '2 days',
       scanned_at    = now() - interval '3 hours',
       not_before    = CASE dwl.lane_name WHEN 'rdap_whois' THEN now() - interval '1 hour' END
 WHERE dwl.domain_name = 'c1.example';
DO $$
DECLARE
  rdap_whois_before text := pg_temp.t_lane_row('c1.example', 'rdap_whois');
  tls_after   text;
BEGIN
  ASSERT api.fn_domain_watch_record_tls('c1.example', now() + interval '10 minutes', E'none\n2027-03-01', pg_temp.t_sha256(E'none\n2027-03-01'),
                                        NULL, NULL, NULL, NULL, NULL, NULL) = 0,
         'S60 the TLS record writes no event';
  ASSERT (SELECT dwl.claimed_until IS NULL AND dwl.scanned_at = now() FROM domain_watch_lane AS dwl
           WHERE dwl.domain_name = 'c1.example' AND dwl.lane_name = 'tls'),
         'S60 the TLS record ends the lease of the tls row and notes its scan';
  ASSERT pg_temp.t_lane_row('c1.example', 'rdap_whois') = rdap_whois_before, 'S60 a TLS record leaves the rdap_whois row as it was: ' || rdap_whois_before;
  UPDATE domain_watch_lane AS dwl SET claimed_until = now() + interval '5 minutes', scanned_at = now() - interval '1 hour'
   WHERE dwl.domain_name = 'c1.example' AND dwl.lane_name = 'tls';
  tls_after := pg_temp.t_lane_row('c1.example', 'tls');
  ASSERT api.fn_domain_watch_record_rdap_whois('c1.example', now() + interval '20 minutes', NULL, NULL, NULL, NULL, NULL, NULL,
                                         'signed', pg_temp.t_sha256('signed'), NULL) = 0,
         'S60 the RDAP/WHOIS record writes no event';
  ASSERT (SELECT dwl.claimed_until IS NULL AND dwl.scanned_at = now() AND dwl.not_before = now() - interval '1 hour'
            FROM domain_watch_lane AS dwl WHERE dwl.domain_name = 'c1.example' AND dwl.lane_name = 'rdap_whois'),
         'S60 the RDAP/WHOIS record ends the lease of the rdap_whois row, notes its scan and leaves not_before as it is';
  ASSERT pg_temp.t_lane_row('c1.example', 'tls') = tls_after, 'S60 an RDAP/WHOIS record leaves the tls row as it was: ' || tls_after;
  ASSERT pg_temp.t_values('c1.example') = 'certificate_expiry=none+2027-03-01 dnssec_delegation=signed',
         'S60 each record writes the values of the items of its own lane';
  ASSERT pg_temp.t_claim('rdap_whois', 10) = 'c1rdap.example', 'S60 the rdap_whois claim passes over a name with only an ssl_check item';
  ASSERT pg_temp.t_claim('tls', 10) = 'c1tls.example', 'S60 the tls claim passes over a name with only a whois_lookup item';
END
$$;

SELECT pg_temp.t_reset();
SELECT pg_temp.t_add_rdap_whois('r0.example');
SELECT pg_temp.t_item('r0.example', repeat('9c', 32), 'ssl_check');
DELETE FROM domain_watch_lane AS dwl WHERE dwl.domain_name = 'r0.example' AND dwl.lane_name = 'rdap_whois';
SELECT pg_temp.t_add_rdap_whois('r1.example');
SELECT pg_temp.t_add_rdap_whois('r2.example');
SELECT pg_temp.t_item('r2.example', repeat('9c', 32), 'ssl_check');
DELETE FROM domain_watch_lane AS dwl WHERE dwl.domain_name = 'r2.example' AND dwl.lane_name = 'tls';
UPDATE domain_watch_lane AS dwl SET claimed_until = now() + interval '10 minutes', claimed_at = now() + interval '2 days'
 WHERE dwl.domain_name IN ('r0.example', 'r1.example', 'r2.example');
DO $$
DECLARE
  kinds       CONSTANT text[]      := ARRAY['registration_expiry', 'registrar', 'transfer_lock', 'dnssec_delegation'];
  lease       CONSTANT timestamptz := now() + interval '10 minutes';
  r1_before   CONSTANT text        := pg_temp.t_snapshot('r1.example') || ' ' || pg_temp.t_lane_row('r1.example', 'rdap_whois');
  r0_before   CONSTANT text        := pg_temp.t_snapshot('r0.example') || ' ' || pg_temp.t_lane_row('r0.example', 'tls');
  r2_before   CONSTANT text        := pg_temp.t_snapshot('r2.example') || ' ' || pg_temp.t_lane_row('r2.example', 'rdap_whois');
  kind_index  integer;
  args        text[];
  retry       integer;
BEGIN
  FOR kind_index IN 1 .. cardinality(kinds) LOOP
    args := array_fill(NULL::text, ARRAY[8]);
    args[2 * kind_index - 1] := 'v';
    BEGIN
      PERFORM api.fn_domain_watch_record_rdap_whois('r1.example', lease, args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8], NULL);
      ASSERT false, 'S61 a ' || kinds[kind_index] || ' value without its SHA-256 is refused';
    EXCEPTION WHEN invalid_parameter_value THEN
      ASSERT SQLERRM = 'fn_domain_watch_record_rdap_whois refuses ' || kinds[kind_index] || ' of r1.example: a value and its SHA-256 come together',
             'S61 the refusal names the kind ' || kinds[kind_index] || ': ' || SQLERRM;
    END;
    args := array_fill(NULL::text, ARRAY[8]);
    args[2 * kind_index] := pg_temp.t_sha256('v');
    BEGIN
      PERFORM api.fn_domain_watch_record_rdap_whois('r1.example', lease, args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8], NULL);
      ASSERT false, 'S61 a ' || kinds[kind_index] || ' SHA-256 without its value is refused';
    EXCEPTION WHEN invalid_parameter_value THEN
      ASSERT SQLERRM LIKE 'fn_domain_watch_record_rdap_whois refuses ' || kinds[kind_index] || ' of r1.example%',
             'S61 the refusal names the kind ' || kinds[kind_index] || ': ' || SQLERRM;
    END;
    args := array_fill(NULL::text, ARRAY[8]);
    args[2 * kind_index - 1] := 'v';
    args[2 * kind_index] := pg_temp.t_sha256('v');
    BEGIN
      PERFORM api.fn_domain_watch_record_rdap_whois('r1.example', lease, args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8], 60);
      ASSERT false, 'S61 a deferred scan with a ' || kinds[kind_index] || ' value is refused';
    EXCEPTION WHEN invalid_parameter_value THEN
      ASSERT SQLERRM = 'fn_domain_watch_record_rdap_whois refuses the values of r1.example: a deferred scan sends none',
             'S61 the refusal says a deferred scan sends no value: ' || SQLERRM;
    END;
  END LOOP;
  FOREACH retry IN ARRAY ARRAY[0, 3601, -1] LOOP
    BEGIN
      PERFORM api.fn_domain_watch_record_rdap_whois('r1.example', lease, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, retry);
      ASSERT false, 'S61 a retry of ' || retry || ' seconds is refused';
    EXCEPTION WHEN invalid_parameter_value THEN
      ASSERT SQLERRM = 'fn_domain_watch_record_rdap_whois refuses a retry of ' || retry || ' seconds of r1.example: a deferred scan waits 1 to 3600 seconds',
             'S61 the refusal names the retry: ' || SQLERRM;
    END;
  END LOOP;
  ASSERT pg_temp.t_snapshot('r1.example') || ' ' || pg_temp.t_lane_row('r1.example', 'rdap_whois') = r1_before, 'S61 a refused call changes nothing';
  ASSERT api.fn_domain_watch_record_rdap_whois('none.example', lease, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 1) = 0
     AND api.fn_domain_watch_record_rdap_whois('none.example', lease, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 3600) = 0,
         'S61 a retry of 1 or 3600 seconds passes the check';
  ASSERT api.fn_domain_watch_record_rdap_whois('none.example', lease, 'v', pg_temp.t_sha256('v'), NULL, NULL, NULL, NULL, NULL, NULL, NULL) = 0,
         'S61 an unknown domain answers 0';
  ASSERT api.fn_domain_watch_record_rdap_whois('r0.example', lease, E'none\n2027-03-01', pg_temp.t_sha256(E'none\n2027-03-01'),
                                         NULL, NULL, NULL, NULL, NULL, NULL, NULL) = 0
     AND api.fn_domain_watch_record_rdap_whois('r0.example', lease, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 60) = 0,
         'S61 a domain with no rdap_whois row answers 0';
  ASSERT pg_temp.t_snapshot('r0.example') || ' ' || pg_temp.t_lane_row('r0.example', 'tls') = r0_before,
         'S61 a domain with no rdap_whois row keeps its items, its values and its tls row';
  ASSERT api.fn_domain_watch_record_tls('r2.example', lease, E'none\n2027-03-01', pg_temp.t_sha256(E'none\n2027-03-01'),
                                        NULL, NULL, NULL, NULL, NULL, NULL) = 0,
         'S61 a domain with no tls row answers 0 to the TLS record';
  ASSERT pg_temp.t_snapshot('r2.example') || ' ' || pg_temp.t_lane_row('r2.example', 'rdap_whois') = r2_before,
         'S61 a domain with no tls row keeps its items, its values and its rdap_whois row';
  ASSERT api.fn_domain_watch_record_rdap_whois('r1.example', lease + interval '1 second', E'none\n2027-03-01', pg_temp.t_sha256(E'none\n2027-03-01'),
                                         NULL, NULL, NULL, NULL, NULL, NULL, NULL) = 0
     AND api.fn_domain_watch_record_rdap_whois('r1.example', lease + interval '1 second', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 60) = 0
     AND api.fn_domain_watch_record_rdap_whois('r1.example', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 60) = 0,
         'S61 a lease other than the one of the row answers 0';
  ASSERT pg_temp.t_snapshot('r1.example') || ' ' || pg_temp.t_lane_row('r1.example', 'rdap_whois') = r1_before,
         'S61 a lease other than the one of the row changes nothing, a deferred scan too';
  UPDATE domain_watch_lane AS dwl SET claimed_until = NULL WHERE dwl.domain_name = 'r1.example';
  ASSERT api.fn_domain_watch_record_rdap_whois('r1.example', lease, E'none\n2027-03-01', pg_temp.t_sha256(E'none\n2027-03-01'),
                                         NULL, NULL, NULL, NULL, NULL, NULL, NULL) = 0
     AND api.fn_domain_watch_record_rdap_whois('r1.example', lease, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 60) = 0
     AND api.fn_domain_watch_record_rdap_whois('r1.example', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 60) = 0,
         'S61 a row with no lease answers 0';
  ASSERT pg_temp.t_values('r1.example') = ''
     AND (SELECT dwl.not_before IS NULL AND dwl.scanned_at IS NULL FROM domain_watch_lane AS dwl WHERE dwl.domain_name = 'r1.example'),
         'S61 a row with no lease changes nothing';
END
$$;

SELECT pg_temp.t_reset();
SELECT pg_temp.t_item('d1.example', repeat('9c', 32), 'whois_lookup', now() - interval '1 hour');
SELECT pg_temp.t_item('d1.example', repeat('9c', 32), 'ssl_check', now() - interval '1 hour');
INSERT INTO watchlist_item_domain_value (item_id, value_kind, current_value, current_value_sha256)
SELECT wid.item_id, 'dnssec_delegation', 'signed', pg_temp.t_sha256('signed') FROM watchlist_item_domain AS wid
 WHERE wid.domain_name = 'd1.example' AND wid.endpoint_name = 'whois_lookup';
UPDATE domain_watch_lane AS dwl
   SET claimed_until = now() + interval '10 minutes', claimed_at = now() - interval '1 minute', scanned_at = now() - interval '2 days'
 WHERE dwl.domain_name = 'd1.example';
DO $$
DECLARE
  snapshot_before CONSTANT text := pg_temp.t_snapshot('d1.example');
  tls_before      CONSTANT text := pg_temp.t_lane_row('d1.example', 'tls');
BEGIN
  ASSERT api.fn_domain_watch_record_rdap_whois('d1.example', now() + interval '10 minutes', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 120) = 0,
         'S62 a deferred scan answers 0';
  ASSERT (SELECT row(dwl.claimed_until, dwl.claimed_at = now() - interval '1 minute', dwl.scanned_at = now() - interval '2 days',
                     dwl.not_before = now() + interval '120 seconds')::text
            FROM domain_watch_lane AS dwl WHERE dwl.domain_name = 'd1.example' AND dwl.lane_name = 'rdap_whois') = '(,t,t,t)',
         'S62 a deferred scan sets not_before now()+retry and ends the lease, and keeps claimed_at and scanned_at';
  ASSERT pg_temp.t_snapshot('d1.example') = snapshot_before,
         'S62 a deferred scan writes no value, event or ref, and moves no next_scan_at';
  ASSERT pg_temp.t_lane_row('d1.example', 'tls') = tls_before, 'S62 a deferred scan leaves the tls row as it was';
  ASSERT pg_temp.t_claim('rdap_whois', 10) = '', 'S62 the claim passes over a row whose not_before is after now()';
  UPDATE domain_watch_lane AS dwl SET not_before = now() + interval '1 second' WHERE dwl.domain_name = 'd1.example' AND dwl.lane_name = 'rdap_whois';
  ASSERT pg_temp.t_claim('rdap_whois', 10) = '', 'S62 the claim passes over a row whose not_before is one second after now()';
  UPDATE domain_watch_lane AS dwl SET not_before = now() WHERE dwl.domain_name = 'd1.example' AND dwl.lane_name = 'rdap_whois';
  ASSERT pg_temp.t_claim('rdap_whois', 10) = 'd1.example', 'S62 the claim takes a row whose not_before is now()';
  UPDATE domain_watch_lane AS dwl SET claimed_until = NULL, not_before = now() - interval '1 second'
   WHERE dwl.domain_name = 'd1.example' AND dwl.lane_name = 'rdap_whois';
  ASSERT pg_temp.t_claim('rdap_whois', 10) = 'd1.example', 'S62 the claim takes a row whose not_before has passed';
  ASSERT api.fn_domain_watch_record_rdap_whois('d1.example', (SELECT dwl.claimed_until FROM domain_watch_lane AS dwl
                                                         WHERE dwl.domain_name = 'd1.example' AND dwl.lane_name = 'rdap_whois'),
                                         NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL) = 0,
         'S62 the record after the defer writes no event';
  ASSERT (SELECT dwl.claimed_until IS NULL AND dwl.scanned_at = now() AND dwl.not_before = now() - interval '1 second'
            FROM domain_watch_lane AS dwl WHERE dwl.domain_name = 'd1.example' AND dwl.lane_name = 'rdap_whois'),
         'S62 the record after the defer ends the lease, notes its scan and leaves not_before as it is';
  ASSERT pg_temp.t_next_scan('d1.example', p_endpoint_name => 'whois_lookup') > now(), 'S62 the record after the defer serves the item';
END
$$;

DO $$
DECLARE
  chosen_name text;
BEGIN
  ASSERT (SELECT bool_and(abs(hashtextextended(n.name, 0) % 604800) % 86400 = abs(hashtextextended(n.name, 0) % 86400))
            FROM (SELECT 'w' || g || '.example' AS name FROM generate_series(1, 500) AS g) AS n),
         'S63 the weekly second of a name is one of its daily seconds';
  ASSERT (SELECT bool_and(extract(epoch FROM api.fn_domain_watch_next_weekly_scan_at(n.name) - api.fn_domain_watch_next_daily_scan_at(n.name))::bigint
                          IN (0, 86400, 172800, 259200, 345600, 432000, 518400))
            FROM (SELECT 'w' || g || '.example' AS name FROM generate_series(1, 500) AS g) AS n),
         'S63 the weekly scan comes 0 to 6 whole days after the daily scan';
  ASSERT (SELECT bool_and(api.fn_domain_watch_next_weekly_scan_at(n.name) > now()
                          AND api.fn_domain_watch_next_weekly_scan_at(n.name) <= now() + interval '7 days'
                          AND extract(epoch FROM api.fn_domain_watch_next_weekly_scan_at(n.name)
                                                 - (date_trunc('week', now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'))::bigint % 604800
                              = abs(hashtextextended(n.name, 0) % 604800))
            FROM (SELECT 'w' || g || '.example' AS name FROM generate_series(1, 500) AS g) AS n),
         'S63 the weekly scan is the next second of the name in the week from Monday 00:00 UTC, after now() and at most 7 days ahead';
  SELECT c.name INTO chosen_name
    FROM unnest(ARRAY['cad0.example', 'cad1.example', 'cad2.example', 'cad3.example', 'cad4.example', 'cad5.example',
                      'cad6.example', 'cad7.example', 'cad8.example', 'cad9.example', 'cad10.example', 'cad11.example']) WITH ORDINALITY AS c (name, list_order)
   WHERE api.fn_domain_watch_next_weekly_scan_at(c.name) - api.fn_domain_watch_next_daily_scan_at(c.name) >= interval '3 days'
   ORDER BY c.list_order
   LIMIT 1;
  ASSERT chosen_name IS NOT NULL, 'S63 a name of the list has its weekly scan 3 or more days after its daily scan, now() is ' || now()::text;
  PERFORM set_config('t_domain_watch.cadence_name', chosen_name, true);
END
$$;
DO $$
DECLARE
  cadence_name CONSTANT text        := current_setting('t_domain_watch.cadence_name');
  daily        CONSTANT timestamptz := api.fn_domain_watch_next_daily_scan_at(current_setting('t_domain_watch.cadence_name'));
  weekly       CONSTANT timestamptz := api.fn_domain_watch_next_weekly_scan_at(current_setting('t_domain_watch.cadence_name'));
  saved_zone   CONSTANT text        := current_setting('TimeZone');
  utc_answer   timestamptz;
  zone_answer  timestamptz;
BEGIN
  ASSERT api.fn_domain_watch_next_scan_at(cadence_name, true, true, E'none\n2099-01-01') = now() + interval '1 hour'
     AND api.fn_domain_watch_next_scan_at(cadence_name, true, false, NULL) = now() + interval '1 hour',
         'S63 the hourly rescan comes first, for every lane';
  ASSERT api.fn_domain_watch_next_scan_at(cadence_name, false, false, E'1\n' || pg_temp.t_utc_day(1)) = daily
     AND api.fn_domain_watch_next_scan_at(cadence_name, false, false, E'none\n2099-01-01') = daily
     AND api.fn_domain_watch_next_scan_at(cadence_name, NULL, NULL, E'none\n2099-01-01') = daily
     AND api.fn_domain_watch_next_scan_at(cadence_name, false, false, NULL) = daily,
         'S63 a DNS or TLS item gets the daily second, whatever the value';
  ASSERT pg_temp.t_cadence(NULL) = weekly AND pg_temp.t_cadence('none') = weekly AND pg_temp.t_cadence(E'none\nnot a date') = weekly
     AND pg_temp.t_cadence(E'30\n2026-02-30') = weekly AND pg_temp.t_cadence(E'7\n0000-01-01') = weekly
     AND pg_temp.t_cadence(E'7\n2026-12-01T10:00:00') = weekly AND pg_temp.t_cadence(E'7\n2026-12-01 10:00:00Z') = weekly
     AND pg_temp.t_cadence(E'7\n2026-02-30T10:00:00Z') = weekly,
         'S63 a whois_lookup item whose registration end is unknown gets the weekly second, and the value raises no error';
  ASSERT pg_temp.t_cadence(E'7\n' || pg_temp.t_utc_day(5)) = daily AND pg_temp.t_cadence(E'1\n' || pg_temp.t_utc_day(-3)) = daily
     AND pg_temp.t_cadence(E'30\n' || pg_temp.t_utc_time(daily + interval '30 days')) = daily,
         'S63 a registration that ends within 30 days of the daily scan, or ended, gets the daily second';
  ASSERT pg_temp.t_cadence(E'none\n' || pg_temp.t_utc_time(daily + interval '30 days 1 second')) = daily + interval '1 day'
     AND pg_temp.t_cadence(E'none\n' || pg_temp.t_utc_time(daily + interval '31 days')) = daily + interval '1 day'
     AND pg_temp.t_cadence(E'none\n' || pg_temp.t_utc_time(daily + interval '31 days 1 second')) = daily + interval '2 days',
         'S63 a registration that ends between gets the first daily second at or after 30 days before its end';
  ASSERT pg_temp.t_cadence(E'none\n' || pg_temp.t_utc_day(200)) = weekly
     AND pg_temp.t_cadence(E'none\n' || pg_temp.t_utc_time(weekly + interval '30 days 1 second')) = weekly,
         'S63 a registration that ends far ahead gets the weekly second';
  ASSERT api.fn_domain_watch_registration_expires_at(E'7\n2026-12-01T10:00:00+02:00') = '2026-12-01T08:00:00Z'::timestamptz
     AND api.fn_domain_watch_registration_expires_at(E'7\n2026-12-01t10:00:00.5z') = '2026-12-01T10:00:00.5Z'::timestamptz
     AND api.fn_domain_watch_registration_expires_at(E'7\n2026-12-01T10:00:00-05:30') = '2026-12-01T15:30:00Z'::timestamptz,
         'S63 a time with its zone is read in that zone';
  ASSERT api.fn_domain_watch_registration_expires_at(NULL) IS NULL AND api.fn_domain_watch_registration_expires_at('2026-12-01') IS NULL
     AND api.fn_domain_watch_registration_expires_at(E'7\n2026-12-01T10:00Z') IS NULL
     AND api.fn_domain_watch_registration_expires_at(E'7\n 2026-12-01') IS NULL
     AND api.fn_domain_watch_registration_expires_at(E'7\n2026-12-01x') IS NULL,
         'S63 any other form is unknown';
  PERFORM set_config('TimeZone', 'UTC', true);
  utc_answer := api.fn_domain_watch_registration_expires_at(E'7\n2026-12-01');
  PERFORM set_config('TimeZone', 'Pacific/Kiritimati', true);
  zone_answer := api.fn_domain_watch_registration_expires_at(E'7\n2026-12-01');
  PERFORM set_config('TimeZone', saved_zone, true);
  ASSERT utc_answer = '2026-12-01T00:00:00Z'::timestamptz AND zone_answer = utc_answer,
         'S63 a date is UTC midnight, whatever the session TimeZone: ' || utc_answer::text || ' / ' || zone_answer::text;
END
$$;

DO $$
DECLARE
  c record;
BEGIN
  ASSERT api.fn_domain_watch_expiry_bucket_rank('none') = 0 AND api.fn_domain_watch_expiry_bucket_rank(E'30\n2026-12-01') = 1
     AND api.fn_domain_watch_expiry_bucket_rank(E'7\n2026-12-01') = 2 AND api.fn_domain_watch_expiry_bucket_rank(E'1\n2026-12-01') = 3
     AND api.fn_domain_watch_expiry_bucket_rank('x') IS NULL AND api.fn_domain_watch_expiry_bucket_rank(NULL) IS NULL
     AND api.fn_domain_watch_expiry_bucket_rank(E'2\n30') IS NULL,
         'S64 the bucket rank reads line 1: none 0, 30 1, 7 2, 1 3, anything else NULL';
  FOR c IN SELECT * FROM (VALUES
      ('certificate_expiry',  E'none\nd',  E'7\nd',  'cert_expiring'),
      ('certificate_expiry',  E'none\nd',  E'1\nd',  'cert_expiring'),
      ('certificate_expiry',  E'7\nd',     E'1\nd',  'cert_expiring'),
      ('certificate_expiry',  E'1\nd',     E'7\nd',  NULL),
      ('certificate_expiry',  E'none\nd',  E'none\ne', NULL),
      ('certificate_expiry',  E'7\nd',     E'7\ne',  NULL),
      ('registration_expiry', E'none\nd',  E'30\nd', 'domain_expiring'),
      ('registration_expiry', E'none\nd',  E'7\nd',  'domain_expiring'),
      ('registration_expiry', E'none\nd',  E'1\nd',  'domain_expiring'),
      ('registration_expiry', E'30\nd',    E'7\nd',  'domain_expiring'),
      ('registration_expiry', E'30\nd',    E'1\nd',  'domain_expiring'),
      ('registration_expiry', E'7\nd',     E'1\nd',  'domain_expiring'),
      ('registration_expiry', E'30\nd',    E'30\ne', NULL),
      ('registration_expiry', E'7\nd',     E'30\ne', NULL),
      ('registration_expiry', E'1\nd',     E'none\ne', NULL),
      ('registration_expiry', E'30\nd',    E'none\ne', NULL),
      ('registration_expiry', E'none\nd',  E'none\ne', NULL),
      ('registrar',           E'292\nA',   E'146\nA', 'registrar_changed'),
      ('registrar',           E'292\nA',   E'292\nB', NULL),
      ('registrar',           E'292\n',    E'146\n',  'registrar_changed'),
      ('registrar',           E'-\nA',     E'-\nB',   'registrar_changed'),
      ('registrar',           E'-\nA',     E'-\nA',   NULL),
      ('registrar',           E'292\nA',   E'-\nA',   NULL),
      ('registrar',           E'292\nA',   E'-\nB',   'registrar_changed'),
      ('registrar',           E'-\nA',     E'146\nA', NULL),
      ('registrar',           E'-\nA',     E'146\nB', 'registrar_changed'),
      ('transfer_lock',       E'client transfer prohibited\nserver transfer prohibited', 'server transfer prohibited', 'transfer_lock_removed'),
      ('transfer_lock',       E'client transfer prohibited\nserver transfer prohibited', 'client transfer prohibited', 'transfer_lock_removed'),
      ('transfer_lock',       'client transfer prohibited', '',  'transfer_lock_removed'),
      ('transfer_lock',       'client transfer prohibited', 'server transfer prohibited', 'transfer_lock_removed'),
      ('transfer_lock',       '',  'client transfer prohibited', NULL),
      ('transfer_lock',       'server transfer prohibited', E'client transfer prohibited\nserver transfer prohibited', NULL),
      ('dnssec_delegation',   'signed',    'unsigned', 'dnssec_disabled'),
      ('dnssec_delegation',   'unsigned',  'signed',   NULL),
      ('dnssec_delegation',   'signed',    'signed',   NULL),
      ('dnssec_delegation',   'unsigned',  'unsigned', NULL)) AS t (value_kind, current_value, candidate_value, expected) LOOP
    ASSERT api.fn_domain_change_event_type(c.value_kind, c.current_value, c.candidate_value) IS NOT DISTINCT FROM c.expected,
           'S64 ' || c.value_kind || ' ' || replace(c.current_value, E'\n', '+') || ' to ' || replace(c.candidate_value, E'\n', '+')
           || ' writes ' || coalesce(c.expected, 'no event');
  END LOOP;
  FOR c IN SELECT * FROM (VALUES
      ('certificate_expiry',  E'30\nd',   'cert_expiring'),
      ('certificate_expiry',  E'7\nd',    'cert_expiring'),
      ('certificate_expiry',  E'1\nd',    'cert_expiring'),
      ('certificate_expiry',  E'none\nd', NULL),
      ('registration_expiry', E'30\nd',   'domain_expiring'),
      ('registration_expiry', E'7\nd',    'domain_expiring'),
      ('registration_expiry', E'1\nd',    'domain_expiring'),
      ('registration_expiry', E'none\nd', NULL),
      ('registration_expiry', 'x',        NULL),
      ('registrar',           E'292\nA',  NULL),
      ('transfer_lock',       '',         NULL),
      ('transfer_lock',       'client transfer prohibited', NULL),
      ('dnssec_delegation',   'unsigned', NULL),
      ('dnssec_delegation',   'signed',   NULL)) AS t (value_kind, first_value, expected) LOOP
    ASSERT api.fn_domain_problem_event_type(c.value_kind, c.first_value) IS NOT DISTINCT FROM c.expected,
           'S64 a first ' || c.value_kind || ' value ' || replace(c.first_value, E'\n', '+') || ' shows ' || coalesce(c.expected, 'no problem');
  END LOOP;
END
$$;

SELECT pg_temp.t_reset();
DO $$
DECLARE
  cadence_name CONSTANT text        := current_setting('t_domain_watch.cadence_name');
  daily        CONSTANT timestamptz := api.fn_domain_watch_next_daily_scan_at(current_setting('t_domain_watch.cadence_name'));
  weekly       CONSTANT timestamptz := api.fn_domain_watch_next_weekly_scan_at(current_setting('t_domain_watch.cadence_name'));
  near_value   CONSTANT text        := E'30\n' || pg_temp.t_utc_day(20);
  far_value    CONSTANT text        := E'none\n' || pg_temp.t_utc_day(200);
  seven_value  CONSTANT text        := E'7\n' || pg_temp.t_utc_day(5);
  registrar    CONSTANT text        := E'292\nMarkMonitor Inc.';
  locks        CONSTANT text        := E'client transfer prohibited\nserver transfer prohibited';
BEGIN
  PERFORM pg_temp.t_add_rdap_whois(cadence_name);
  PERFORM pg_temp.t_item(cadence_name, repeat('a1', 32), 'whois_lookup', now() + interval '1 hour');
  PERFORM pg_temp.t_item(cadence_name, repeat('b1', 32), 'whois_lookup', now() + interval '1 hour');
  PERFORM pg_temp.t_dw_mark();
  ASSERT pg_temp.t_record_rdap_whois(cadence_name, near_value, registrar, locks, 'signed', now()) = 1, 'S65 the first scan writes one event';
  ASSERT pg_temp.t_dw_events(cadence_name) = ARRAY['domain_expiring:null>' || replace(near_value, E'\n', '+')],
         'S65 a first registration_expiry of bucket 30 writes domain_expiring with no previous value, and the other first values write none';
  ASSERT pg_temp.t_values(cadence_name, repeat('9c', 32))
         = replace('dnssec_delegation=signed registrar=' || registrar || ' registration_expiry=' || near_value || ' transfer_lock=' || locks, E'\n', '+'),
         'S65 the first scan writes the four values of the item';
  ASSERT pg_temp.t_next_scan(cadence_name, repeat('9c', 32), 'whois_lookup') = daily,
         'S65 an item whose registration ends within 30 days gets the daily second';
  UPDATE watchlist_item_domain AS wid SET next_scan_at = now() - interval '1 minute'
   WHERE wid.domain_name = cadence_name AND wid.api_key_id IN (SELECT ak.id FROM api_keys AS ak WHERE ak.key_hash IN (repeat('a1', 32), repeat('b1', 32)));
  ASSERT pg_temp.t_record_rdap_whois(cadence_name, far_value, registrar, locks, 'signed', now()) = 0, 'S65 a far registration writes no event';
  ASSERT pg_temp.t_next_scan(cadence_name, repeat('a1', 32), 'whois_lookup') = weekly
     AND pg_temp.t_next_scan(cadence_name, repeat('b1', 32), 'whois_lookup') = weekly
     AND pg_temp.t_next_scan(cadence_name, repeat('9c', 32), 'whois_lookup') = daily,
         'S65 the items with a far registration get the weekly second, and the item the scan did not serve keeps its daily second';
  UPDATE watchlist_item_domain AS wid SET next_scan_at = now() - interval '1 minute'
   WHERE wid.domain_name = cadence_name AND wid.api_key_id = (SELECT ak.id FROM api_keys AS ak WHERE ak.key_hash = repeat('a1', 32));
  ASSERT pg_temp.t_record_rdap_whois(cadence_name, seven_value, NULL, NULL, NULL, now()) = 0, 'S65 the change to bucket 7 is a candidate first';
  ASSERT pg_temp.t_next_scan(cadence_name, repeat('a1', 32), 'whois_lookup') = now() + interval '1 hour',
         'S65 the candidate brings the hourly rescan';
  PERFORM pg_temp.t_age(cadence_name, 'registration_expiry', interval '1 hour');
  UPDATE watchlist_item_domain AS wid SET next_scan_at = now() - interval '1 minute'
   WHERE wid.domain_name = cadence_name AND wid.api_key_id = (SELECT ak.id FROM api_keys AS ak WHERE ak.key_hash = repeat('a1', 32));
  PERFORM pg_temp.t_dw_mark();
  ASSERT pg_temp.t_record_rdap_whois(cadence_name, seven_value, NULL, NULL, NULL, now()) = 1, 'S65 the confirmed change writes one event';
  ASSERT pg_temp.t_dw_events(cadence_name) = ARRAY['domain_expiring:' || replace(far_value, E'\n', '+') || '>' || replace(seven_value, E'\n', '+')],
         'S65 none to 7 confirmed after one hour writes domain_expiring';
  ASSERT pg_temp.t_next_scan(cadence_name, repeat('a1', 32), 'whois_lookup') = daily,
         'S65 the confirmed bucket 7 brings the daily second';
  UPDATE watchlist_item_domain AS wid SET next_scan_at = now() - interval '1 minute' WHERE wid.domain_name = cadence_name;
  ASSERT pg_temp.t_record_rdap_whois(cadence_name, p_claimed_at => now()) = 0, 'S65 a scan with no value writes no event';
  ASSERT pg_temp.t_next_scan(cadence_name, repeat('9c', 32), 'whois_lookup') = daily
     AND pg_temp.t_next_scan(cadence_name, repeat('a1', 32), 'whois_lookup') = daily
     AND pg_temp.t_next_scan(cadence_name, repeat('b1', 32), 'whois_lookup') = weekly,
         'S65 a scan with no value moves each item to the cadence of its own value';
  ASSERT cardinality(pg_temp.t_heard(repeat('9c', 32), cadence_name)) = 1 AND cardinality(pg_temp.t_heard(repeat('a1', 32), cadence_name)) = 1
     AND cardinality(pg_temp.t_heard(repeat('b1', 32), cadence_name)) = 0,
         'S65 each key hears the events of its own item';
END
$$;

DO $$
DECLARE
  cadence_name CONSTANT text        := current_setting('t_domain_watch.cadence_name');
  weekly       CONSTANT timestamptz := api.fn_domain_watch_next_weekly_scan_at(current_setting('t_domain_watch.cadence_name'));
BEGIN
  UPDATE watchlist_item_domain AS wid SET next_scan_at = now() - interval '1 minute'
   WHERE wid.domain_name = cadence_name AND wid.api_key_id = (SELECT ak.id FROM api_keys AS ak WHERE ak.key_hash = repeat('b1', 32));
  ASSERT pg_temp.t_record_rdap_whois(cadence_name, E'7\n' || pg_temp.t_utc_day(6), NULL, NULL, NULL, now()) = 0, 'S66 a first candidate';
  ASSERT pg_temp.t_next_scan(cadence_name, repeat('b1', 32), 'whois_lookup') = now() + interval '1 hour', 'S66 the candidate brings the hourly rescan';
  UPDATE watchlist_item_domain AS wid SET next_scan_at = now() - interval '1 minute'
   WHERE wid.domain_name = cadence_name AND wid.api_key_id = (SELECT ak.id FROM api_keys AS ak WHERE ak.key_hash = repeat('b1', 32));
  ASSERT pg_temp.t_record_rdap_whois(cadence_name, E'30\n' || pg_temp.t_utc_day(20), NULL, NULL, NULL, now()) = 0, 'S66 a third value drops the candidate';
  ASSERT pg_temp.t_next_scan(cadence_name, repeat('b1', 32), 'whois_lookup') = weekly,
         'S66 a dropped candidate leaves the schedule on the confirmed far value: the weekly second';
END
$$;

SELECT pg_temp.t_reset();
SELECT pg_temp.t_watch('g0.flood.example', 'flood.example', now() - interval '3 hours');
SELECT pg_temp.t_watch('g1.flood.example', 'flood.example', now() + interval '1 hour');
SELECT pg_temp.t_item('g1.flood.example', repeat('9c', 32), 'ssl_check', now() - interval '4 hours', 'flood.example');
SELECT pg_temp.t_watch('g2.flood.example', 'flood.example', now() - interval '2 hours', now() + interval '1 minute');
SELECT pg_temp.t_item('g2.flood.example', repeat('9c', 32), 'ssl_check', now() - interval '4 hours', 'flood.example');
SELECT pg_temp.t_watch('g3.flood.example', 'flood.example', now() - interval '2 hours');
SELECT pg_temp.t_item('g3.flood.example', repeat('9c', 32), 'ssl_check', now() - interval '4 hours', 'flood.example');
UPDATE domain_watch_lane SET not_before = now() + interval '1 hour' WHERE domain_name = 'g3.flood.example' AND lane_name = 'dns';
SELECT pg_temp.t_watch('calm.example', 'calm.example', now() - interval '30 minutes');
INSERT INTO domain_watch_dns_bucket (registered_domain, question_allowance, refilled_at) VALUES ('flood.example', 0, now());
DO $$
BEGIN
  ASSERT pg_temp.t_claim('dns', 4) = 'calm.example', 'S67 calm.example is leased';
  ASSERT (SELECT array_agg(dwl.domain_name || '=' || coalesce((dwl.not_before - now())::text, 'null') ORDER BY dwl.domain_name)
            FROM domain_watch_lane AS dwl WHERE dwl.lane_name = 'dns' AND dwl.domain_name LIKE 'g_.flood.example')
         = '{g0.flood.example=00:01:20,g1.flood.example=null,g2.flood.example=null,g3.flood.example=01:00:00}',
         'S67 the refusal holds back only free dns rows due by a dns_lookup item';
END
$$;

SELECT pg_temp.t_reset();
SELECT pg_temp.t_watch('n1.neg.example', 'neg.example', now() - interval '1 hour');
INSERT INTO domain_watch_dns_bucket (registered_domain, question_allowance, refilled_at) VALUES ('neg.example', -20, now() - interval '20 seconds');
DO $$
BEGIN
  ASSERT pg_temp.t_claim('dns', 4) = '', 'S68 a bucket of -10 after refill refuses';
  ASSERT (SELECT dwdb.question_allowance FROM domain_watch_dns_bucket AS dwdb WHERE dwdb.registered_domain = 'neg.example') = -10,
         'S68 20 seconds add 10 questions to -20';
  ASSERT (SELECT dwl.not_before - now() FROM domain_watch_lane AS dwl WHERE dwl.domain_name = 'n1.neg.example' AND dwl.lane_name = 'dns') = interval '100 seconds',
         'S68 the 50 missing questions take 100 seconds';
END
$$;

INSERT INTO api_keys (key_hash, active, expires_at) VALUES
  (repeat('d0', 32), false, NULL),
  (repeat('d1', 32), true,  now() - interval '1 second');
SELECT pg_temp.t_reset();
SELECT pg_temp.t_item(n.domain_name, n.key_hash, 'dns_lookup', n.next_scan_at)
  FROM (VALUES ('r1.revoked.example', repeat('d0', 32), now() - interval '5 hours'),
               ('x1.expired.example', repeat('d1', 32), now() - interval '5 hours'),
               ('both.example',       repeat('d0', 32), now() - interval '6 hours'),
               ('both.example',       repeat('9c', 32), now() - interval '1 minute'),
               ('plain.example',      repeat('9c', 32), now() - interval '1 hour')) AS n (domain_name, key_hash, next_scan_at);
DO $$
BEGIN
  ASSERT pg_temp.t_claim('dns', 10) = 'plain.example,both.example',
         'S69 the claim passes over the items of a revoked and an expired key, and the item of the active key places both.example';
  ASSERT (SELECT array_agg(dwl.domain_name ORDER BY dwl.domain_name) FROM domain_watch_lane AS dwl WHERE dwl.claimed_until IS NULL)
         = '{r1.revoked.example,x1.expired.example}',
         'S69 the rows due only by an inactive key hold no lease';
  ASSERT (SELECT count(*) FROM regexp_matches(regexp_replace(pg_get_functiondef('api.fn_domain_watch_claim(text, integer, integer)'::regprocedure), '--[^\n]*', '', 'g'),
                                               'api\.fn_api_key_is_active\(ak\.active, ak\.expires_at\)', 'g')) = 2,
         'S69 the claim takes the rule of an active key from api.fn_api_key_is_active, where it picks and where it holds back';
END
$$;

SELECT pg_temp.t_reset();
SELECT pg_temp.t_item(n.domain_name, n.key_hash, 'dns_lookup', n.next_scan_at, 'flood.example')
  FROM (VALUES ('h0.flood.example', repeat('9c', 32), now() - interval '2 hours'),
               ('h1.flood.example', repeat('d0', 32), now() - interval '3 hours'),
               ('h2.flood.example', repeat('d1', 32), now() - interval '3 hours'),
               ('h3.flood.example', repeat('9c', 32), now() - interval '1 hour'),
               ('h3.flood.example', repeat('d0', 32), now() - interval '4 hours')) AS n (domain_name, key_hash, next_scan_at);
SELECT pg_temp.t_item('calm.example', repeat('9c', 32), 'dns_lookup', now() - interval '30 minutes');
INSERT INTO domain_watch_dns_bucket (registered_domain, question_allowance, refilled_at) VALUES ('flood.example', 0, now());
DO $$
BEGIN
  ASSERT pg_temp.t_claim('dns', 4) = 'calm.example', 'S69 the refused bucket does not hold back calm.example';
  ASSERT (SELECT array_agg(dwl.domain_name || '=' || coalesce((dwl.not_before - now())::text, 'null') ORDER BY dwl.domain_name)
            FROM domain_watch_lane AS dwl WHERE dwl.lane_name = 'dns' AND dwl.domain_name LIKE 'h_.flood.example')
         = '{h0.flood.example=00:01:20,h1.flood.example=null,h2.flood.example=null,h3.flood.example=00:01:20}',
         'S69 the refusal holds back the rows due by an active key, and no row due only by a revoked or an expired key';
END
$$;

CREATE FUNCTION pg_temp.t_record_headers(p_domain_name text, p_security_headers text,
                                         p_claimed_at timestamptz DEFAULT now() + interval '2 days')
  RETURNS integer LANGUAGE plpgsql AS $$
BEGIN
  UPDATE domain_watch_lane AS dwl SET claimed_until = now() + interval '10 minutes', claimed_at = p_claimed_at
   WHERE dwl.domain_name = p_domain_name AND dwl.lane_name = 'headers';
  RETURN api.fn_domain_watch_record_headers(p_domain_name, now() + interval '10 minutes', p_security_headers,
                                            pg_temp.t_sha256(p_security_headers), NULL);
END
$$;

CREATE FUNCTION pg_temp.t_sqlstate(p_statement text) RETURNS text LANGUAGE plpgsql AS $$
BEGIN
  BEGIN
    EXECUTE p_statement;
    RAISE SQLSTATE 'TACPT';
  EXCEPTION WHEN SQLSTATE 'TACPT' THEN
    RETURN 'accepted';
  END;
EXCEPTION WHEN OTHERS THEN
  RETURN SQLSTATE;
END
$$;

SELECT pg_temp.t_reset();
SELECT pg_temp.t_add_headers('h1.example');
DO $$
DECLARE
  long_value  CONSTANT text := 'https://h1.example/' || repeat('a', 2048 - octet_length('https://h1.example/'));
  before_call text;
BEGIN
  ASSERT octet_length(long_value) = 2048, 'S70 the long value is 2048 bytes';
  BEGIN
    PERFORM api.fn_domain_watch_record_headers('h1.example', now(), 'https://h1.example/', NULL, NULL);
    ASSERT false, 'S70 a value without its SHA-256 is refused';
  EXCEPTION WHEN invalid_parameter_value THEN
    ASSERT SQLERRM LIKE '%security_headers%', 'S70 the refusal of a value without its SHA-256 names the kind security_headers';
  END;
  BEGIN
    PERFORM api.fn_domain_watch_record_headers('h1.example', now(), NULL, pg_temp.t_sha256('https://h1.example/'), NULL);
    ASSERT false, 'S70 a SHA-256 without its value is refused';
  EXCEPTION WHEN invalid_parameter_value THEN
    ASSERT SQLERRM LIKE '%security_headers%', 'S70 the refusal of a SHA-256 without its value names the kind security_headers';
  END;
  ASSERT pg_temp.t_sqlstate($q$SELECT api.fn_domain_watch_record_headers('h1.example', now(), NULL, NULL, 0)$q$) = '22023',
         'S70 a retry of 0 seconds is refused';
  ASSERT pg_temp.t_sqlstate($q$SELECT api.fn_domain_watch_record_headers('h1.example', now(), NULL, NULL, 3601)$q$) = '22023',
         'S70 a retry of 3601 seconds is refused';
  ASSERT pg_temp.t_sqlstate($q$SELECT api.fn_domain_watch_record_headers('h1.example', now(), 'u', pg_temp.t_sha256('u'), 60)$q$) = '22023',
         'S70 a deferred scan that sends a value is refused';
  ASSERT pg_temp.t_sqlstate(format('SELECT api.fn_domain_watch_record_headers(%L, now(), %L, %L, NULL)', 'h1.example', long_value || 'a',
                                     pg_temp.t_sha256(long_value || 'a'))) = '22023',
         'S70 a value of 2049 bytes is refused';

  UPDATE domain_watch_lane AS dwl SET claimed_until = now() + interval '10 minutes', claimed_at = now() + interval '2 days'
   WHERE dwl.domain_name = 'h1.example';
  before_call := pg_temp.t_lane_row('h1.example', 'headers') || ' ' || pg_temp.t_snapshot('h1.example');
  ASSERT api.fn_domain_watch_record_headers('h1.example', now() + interval '9 minutes', 'u', pg_temp.t_sha256('u'), NULL) = 0,
         'S70 another lease answers 0';
  ASSERT pg_temp.t_lane_row('h1.example', 'headers') || ' ' || pg_temp.t_snapshot('h1.example') = before_call, 'S70 another lease changes nothing';
  ASSERT api.fn_domain_watch_record_headers('none.example', now(), 'u', pg_temp.t_sha256('u'), NULL) = 0, 'S70 an unknown domain answers 0';

  ASSERT pg_temp.t_record_headers('h1.example', long_value) = 0, 'S70 a first value of 2048 bytes answers 0 events';
  ASSERT (SELECT octet_length(widv.current_value) FROM watchlist_item_domain_value AS widv
            JOIN watchlist_item_domain AS wid ON wid.item_id = widv.item_id
           WHERE wid.domain_name = 'h1.example' AND widv.value_kind = 'security_headers') = 2048,
         'S70 a value of 2048 bytes is written whole';
  ASSERT pg_temp.t_record_headers('h1.example', NULL) = 0
     AND pg_temp.t_next_scan('h1.example', p_endpoint_name => 'headers_check') = api.fn_domain_watch_next_daily_scan_at('h1.example'),
         'S70 a scan with no value keeps the value and gives the item its next daily scan';
  ASSERT (SELECT octet_length(widv.current_value) FROM watchlist_item_domain_value AS widv
            JOIN watchlist_item_domain AS wid ON wid.item_id = widv.item_id
           WHERE wid.domain_name = 'h1.example' AND widv.value_kind = 'security_headers') = 2048,
         'S70 a scan with no value keeps the stored value';
END
$$;

SELECT pg_temp.t_reset();
SELECT pg_temp.t_item('h2.example', repeat('9c', 32), 'headers_check', now() - interval '1 hour');
SELECT pg_temp.t_item('h2.example', repeat('9c', 32), 'dns_lookup', now() - interval '1 hour');
UPDATE domain_watch_lane AS dwl
   SET claimed_until = now() + interval '10 minutes', claimed_at = now() - interval '1 minute', scanned_at = now() - interval '2 days'
 WHERE dwl.domain_name = 'h2.example';
DO $$
DECLARE
  snapshot_before CONSTANT text := pg_temp.t_snapshot('h2.example');
  dns_before      CONSTANT text := pg_temp.t_lane_row('h2.example', 'dns');
BEGIN
  ASSERT api.fn_domain_watch_record_headers('h2.example', now() + interval '10 minutes', NULL, NULL, 45) = 0, 'S71 a deferred scan answers 0';
  ASSERT (SELECT row(dwl.claimed_until, dwl.claimed_at = now() - interval '1 minute', dwl.scanned_at = now() - interval '2 days',
                     dwl.not_before = now() + interval '45 seconds')::text
            FROM domain_watch_lane AS dwl WHERE dwl.domain_name = 'h2.example' AND dwl.lane_name = 'headers') = '(,t,t,t)',
         'S71 a deferred scan sets not_before now()+retry and ends the lease, and keeps claimed_at and scanned_at';
  ASSERT pg_temp.t_snapshot('h2.example') = snapshot_before, 'S71 a deferred scan writes no value, event or ref, and moves no next_scan_at';
  ASSERT pg_temp.t_lane_row('h2.example', 'dns') = dns_before, 'S71 a deferred scan leaves the dns row as it was';
  ASSERT pg_temp.t_claim('headers', 10) = '', 'S71 the claim passes over a row whose not_before is after now()';
  UPDATE domain_watch_lane AS dwl SET not_before = now() WHERE dwl.domain_name = 'h2.example' AND dwl.lane_name = 'headers';
  ASSERT pg_temp.t_claim('headers', 10) = 'h2.example', 'S71 the claim takes a row whose not_before is now()';
END
$$;

DO $$
DECLARE
  base_value CONSTANT text := E'https://h.example/\ncontent-security-policy\nstrict-transport-security';
BEGIN
  ASSERT api.fn_domain_change_event_type('security_headers', base_value, E'https://h.example/\ncontent-security-policy') = 'security_header_removed',
         'S72 a header missing under the same URL writes security_header_removed';
  ASSERT api.fn_domain_change_event_type('security_headers', base_value, 'https://h.example/') = 'security_header_removed',
         'S72 every header missing under the same URL writes security_header_removed';
  ASSERT api.fn_domain_change_event_type('security_headers', base_value, E'https://h.example/\ncontent-security-policy\nx-content-type-options')
         = 'security_header_removed',
         'S72 a header missing and another added under the same URL writes security_header_removed';
  ASSERT api.fn_domain_change_event_type('security_headers', base_value, E'https://www.h.example/\ncontent-security-policy') IS NULL,
         'S72 a header missing under another URL writes no event';
  ASSERT api.fn_domain_change_event_type('security_headers', base_value, E'https://h.example/x\ncontent-security-policy') IS NULL,
         'S72 a URL that only starts with the old one is another URL';
  ASSERT api.fn_domain_change_event_type('security_headers', base_value, E'https://h.example/\ncontent-security-policy\nstrict-transport-security\nreferrer-policy')
         IS NULL,
         'S72 an added header writes no event';
  ASSERT api.fn_domain_change_event_type('security_headers', 'https://h.example/', E'https://h.example/\nreferrer-policy') IS NULL,
         'S72 a first header after none writes no event';
  ASSERT api.fn_domain_change_event_type('security_headers', base_value, base_value) IS NULL, 'S72 an equal value writes no event';
  ASSERT api.fn_domain_change_event_type('tls_protocol', base_value, 'https://h.example/') IS NULL,
         'S72 the rule belongs to the security_headers kind only';
  ASSERT api.fn_domain_problem_event_type('security_headers', base_value) IS NULL
     AND api.fn_domain_problem_event_type('security_headers', 'https://h.example/') IS NULL,
         'S72 the first value of an item shows no problem, even with no header line';
END
$$;

SELECT pg_temp.t_reset();
SELECT pg_temp.t_add_headers('h3.example');
SELECT pg_temp.t_add_dns('h3.example');
DO $$
DECLARE
  full_value    CONSTANT text := E'https://h3.example/\ncontent-security-policy\nstrict-transport-security';
  reduced_value CONSTANT text := E'https://h3.example/\ncontent-security-policy';
BEGIN
  PERFORM pg_temp.t_dw_mark();
  ASSERT pg_temp.t_record_headers('h3.example', full_value) = 0, 'S73 the first scan writes no event';
  ASSERT pg_temp.t_values('h3.example') = 'security_headers=https://h3.example/+content-security-policy+strict-transport-security',
         'S73 the first scan writes the baseline of the headers_check item, and no value of the dns_lookup item';
  ASSERT (SELECT dwl.claimed_until IS NULL AND dwl.scanned_at = now() FROM domain_watch_lane AS dwl
           WHERE dwl.domain_name = 'h3.example' AND dwl.lane_name = 'headers')
     AND pg_temp.t_next_scan('h3.example', p_endpoint_name => 'headers_check') = api.fn_domain_watch_next_daily_scan_at('h3.example'),
         'S73 the record ends the lease, notes scanned_at, and puts the item at its daily second';
  ASSERT pg_temp.t_next_scan('h3.example') <= now(), 'S73 the dns_lookup item keeps its next scan';

  ASSERT pg_temp.t_record_headers('h3.example', reduced_value) = 0, 'S73 a value with a header missing answers 0 events at first';
  ASSERT pg_temp.t_candidate('h3.example', 'security_headers') = E'https://h3.example/\ncontent-security-policy|00:00:00',
         'S73 the value with a header missing becomes the candidate';
  ASSERT pg_temp.t_next_scan('h3.example', p_endpoint_name => 'headers_check') = now() + interval '1 hour',
         'S73 a new candidate brings the hourly rescan';
  PERFORM pg_temp.t_age('h3.example', 'security_headers', interval '1 hour');
  ASSERT pg_temp.t_record_headers('h3.example', reduced_value) = 1, 'S73 the candidate seen an hour later writes one event';
  ASSERT pg_temp.t_dw_events('h3.example')
         = ARRAY['security_header_removed:https://h3.example/+content-security-policy+strict-transport-security>https://h3.example/+content-security-policy'],
         'S73 the event carries the value before and after the change';
  ASSERT pg_temp.t_heard(repeat('9c', 32), 'h3.example')
         = ARRAY['security_header_removed:https://h3.example/+content-security-policy+strict-transport-security>https://h3.example/+content-security-policy'],
         'S73 the key of the item hears the event';
END
$$;

CREATE FUNCTION pg_temp.t_record_ct(p_domain_name text, p_cert_issuers text,
                                    p_claimed_at timestamptz DEFAULT now() + interval '2 days')
  RETURNS integer LANGUAGE plpgsql AS $$
BEGIN
  UPDATE domain_watch_lane AS dwl SET claimed_until = now() + interval '10 minutes', claimed_at = p_claimed_at
   WHERE dwl.domain_name = p_domain_name AND dwl.lane_name = 'ct';
  RETURN api.fn_domain_watch_record_ct(p_domain_name, now() + interval '10 minutes', p_cert_issuers, pg_temp.t_sha256(p_cert_issuers), NULL);
END
$$;

SELECT pg_temp.t_reset();
SELECT pg_temp.t_add_ct('c1.example');
DO $$
DECLARE
  long_value  CONSTANT text := 'new_issuer ' || repeat('a', 2048 - octet_length('new_issuer '));
  before_call text;
BEGIN
  ASSERT octet_length(long_value) = 2048, 'S74 the long value is 2048 bytes';
  BEGIN
    PERFORM api.fn_domain_watch_record_ct('c1.example', now(), 'new_issuer pki.goog', NULL, NULL);
    ASSERT false, 'S74 a value without its SHA-256 is refused';
  EXCEPTION WHEN invalid_parameter_value THEN
    ASSERT SQLERRM LIKE '%cert_issuers%', 'S74 the refusal of a value without its SHA-256 names the kind cert_issuers';
  END;
  BEGIN
    PERFORM api.fn_domain_watch_record_ct('c1.example', now(), NULL, pg_temp.t_sha256('new_issuer pki.goog'), NULL);
    ASSERT false, 'S74 a SHA-256 without its value is refused';
  EXCEPTION WHEN invalid_parameter_value THEN
    ASSERT SQLERRM LIKE '%cert_issuers%', 'S74 the refusal of a SHA-256 without its value names the kind cert_issuers';
  END;
  ASSERT pg_temp.t_sqlstate($q$SELECT api.fn_domain_watch_record_ct('c1.example', now(), NULL, NULL, 0)$q$) = '22023',
         'S74 a retry of 0 seconds is refused';
  ASSERT pg_temp.t_sqlstate($q$SELECT api.fn_domain_watch_record_ct('c1.example', now(), NULL, NULL, 3601)$q$) = '22023',
         'S74 a retry of 3601 seconds is refused';
  ASSERT pg_temp.t_sqlstate($q$SELECT api.fn_domain_watch_record_ct('c1.example', now(), 'new_issuer a', pg_temp.t_sha256('new_issuer a'), 60)$q$) = '22023',
         'S74 a deferred scan that sends a value is refused';
  ASSERT pg_temp.t_sqlstate(format('SELECT api.fn_domain_watch_record_ct(%L, now(), %L, %L, NULL)', 'c1.example', long_value || 'a',
                                     pg_temp.t_sha256(long_value || 'a'))) = '22023',
         'S74 a value of 2049 bytes is refused';
  ASSERT pg_temp.t_sqlstate($q$SELECT api.fn_domain_watch_record_ct('c1.example', now(), 'known pki.goog', pg_temp.t_sha256('known pki.goog'), NULL)$q$) = '22023',
         'S74 a line with another reason is refused';
  ASSERT pg_temp.t_sqlstate($q$SELECT api.fn_domain_watch_record_ct('c1.example', now(), E'new_issuer a\nnew_issuer ', pg_temp.t_sha256(E'new_issuer a\nnew_issuer '), NULL)$q$) = '22023',
         'S74 a line with no key is refused';
  ASSERT pg_temp.t_sqlstate($q$SELECT api.fn_domain_watch_record_ct('c1.example', now(), 'caa_mismatchpki.goog', pg_temp.t_sha256('caa_mismatchpki.goog'), NULL)$q$) = '22023',
         'S74 a reason with no space after it is refused';
  ASSERT pg_temp.t_sqlstate($q$SELECT api.fn_domain_watch_record_ct('c1.example', now(), 'xnew_issuer a', pg_temp.t_sha256('xnew_issuer a'), NULL)$q$) = '22023',
         'S74 a reason with a byte before it is refused';
  ASSERT pg_temp.t_sqlstate($q$SELECT api.fn_domain_watch_record_ct('c1.example', now(), 'caa_other a', pg_temp.t_sha256('caa_other a'), NULL)$q$) = '22023',
         'S74 a reason other than new_issuer and caa_mismatch is refused';
  ASSERT pg_temp.t_sqlstate($q$SELECT api.fn_domain_watch_record_ct('c1.example', now(), E'new_issuer\ta', pg_temp.t_sha256(E'new_issuer\ta'), NULL)$q$) = '22023',
         'S74 a tab after the reason is refused';
  ASSERT pg_temp.t_sqlstate($q$SELECT api.fn_domain_watch_record_ct('c1.example', now(), E'new_issuer Some CA\nnew_issuer Other CA', pg_temp.t_sha256(E'new_issuer Some CA\nnew_issuer Other CA'), NULL)$q$) = 'accepted',
         'S74 two keys that end in the same word are two keys';

  UPDATE domain_watch_lane AS dwl SET claimed_until = now() + interval '10 minutes', claimed_at = now() + interval '2 days'
   WHERE dwl.domain_name = 'c1.example';
  before_call := pg_temp.t_lane_row('c1.example', 'ct') || ' ' || pg_temp.t_snapshot('c1.example');
  ASSERT api.fn_domain_watch_record_ct('c1.example', now() + interval '9 minutes', 'new_issuer a', pg_temp.t_sha256('new_issuer a'), NULL) = 0,
         'S74 another lease answers 0';
  ASSERT pg_temp.t_lane_row('c1.example', 'ct') || ' ' || pg_temp.t_snapshot('c1.example') = before_call, 'S74 another lease changes nothing';
  ASSERT api.fn_domain_watch_record_ct('none.example', now(), 'new_issuer a', pg_temp.t_sha256('new_issuer a'), NULL) = 0,
         'S74 an unknown domain answers 0';
  ASSERT pg_temp.t_sqlstate($q$SELECT api.fn_domain_watch_record_ct('c1.example', now(), 'new_issuer  ', pg_temp.t_sha256('new_issuer  '), NULL)$q$) = '22023',
         'S74 a line whose key is one space is refused';
  ASSERT pg_temp.t_sqlstate($q$SELECT api.fn_domain_watch_record_ct('c1.example', now(), E'new_issuer a\ncaa_mismatch    ', pg_temp.t_sha256(E'new_issuer a\ncaa_mismatch    '), NULL)$q$) = '22023',
         'S74 a line whose key is three spaces is refused';
  ASSERT pg_temp.t_sqlstate($q$SELECT api.fn_domain_watch_record_ct('c1.example', now(), E'new_issuer a\nnew_issuer a', pg_temp.t_sha256(E'new_issuer a\nnew_issuer a'), NULL)$q$) = '22023',
         'S74 a key on two lines with the same reason is refused';
  ASSERT pg_temp.t_sqlstate($q$SELECT api.fn_domain_watch_record_ct('c1.example', now(), E'caa_mismatch a\nnew_issuer b\nnew_issuer a', pg_temp.t_sha256(E'caa_mismatch a\nnew_issuer b\nnew_issuer a'), NULL)$q$) = '22023',
         'S74 a key on two lines with two reasons is refused';
  ASSERT pg_temp.t_sqlstate($q$SELECT api.fn_domain_watch_record_ct('c1.example', now() + interval '10 minutes', E'new_issuer a\ncaa_mismatch b\nnew_issuer  Some CA ', pg_temp.t_sha256(E'new_issuer a\ncaa_mismatch b\nnew_issuer  Some CA '), NULL)$q$) = 'accepted',
         'S74 three keys, one with spaces around and inside it, are accepted';
  ASSERT pg_temp.t_sqlstate($q$SELECT api.fn_domain_watch_record_ct('c1.example', now() + interval '10 minutes', '', pg_temp.t_sha256(''), NULL)$q$) = 'accepted',
         'S74 an empty value is accepted';

  ASSERT pg_temp.t_record_ct('c1.example', long_value) = 0, 'S74 a first value of 2048 bytes answers 0 events';
  ASSERT pg_temp.t_values('c1.example') = 'cert_issuers=' || repeat('a', 2048 - octet_length('new_issuer ')),
         'S74 a value of 2048 bytes is written, as its key alone';
  ASSERT pg_temp.t_record_ct('c1.example', NULL) = 0
     AND pg_temp.t_next_scan('c1.example', p_endpoint_name => 'cert_search') = api.fn_domain_watch_next_daily_scan_at('c1.example'),
         'S74 a scan with no value keeps the value and gives the item its next daily scan';
  ASSERT pg_temp.t_values('c1.example') = 'cert_issuers=' || repeat('a', 2048 - octet_length('new_issuer ')),
         'S74 a scan with no value keeps the stored value';
END
$$;

SELECT pg_temp.t_reset();
SELECT pg_temp.t_item('c2.example', repeat('9c', 32), 'cert_search', now() - interval '1 hour');
UPDATE domain_watch_lane AS dwl
   SET claimed_until = now() + interval '10 minutes', claimed_at = now() - interval '1 minute', scanned_at = now() - interval '2 days'
 WHERE dwl.domain_name = 'c2.example';
DO $$
DECLARE
  snapshot_before CONSTANT text := pg_temp.t_snapshot('c2.example');
BEGIN
  ASSERT api.fn_domain_watch_record_ct('c2.example', now() + interval '10 minutes', NULL, NULL, 45) = 0, 'S75 a deferred scan answers 0';
  ASSERT (SELECT row(dwl.claimed_until, dwl.claimed_at = now() - interval '1 minute', dwl.scanned_at = now() - interval '2 days',
                     dwl.not_before = now() + interval '45 seconds')::text
            FROM domain_watch_lane AS dwl WHERE dwl.domain_name = 'c2.example' AND dwl.lane_name = 'ct') = '(,t,t,t)',
         'S75 a deferred scan sets not_before now()+retry and ends the lease, and keeps claimed_at and scanned_at';
  ASSERT pg_temp.t_snapshot('c2.example') = snapshot_before, 'S75 a deferred scan writes no value, event or ref, and moves no next_scan_at';
  ASSERT pg_temp.t_claim('ct', 10) = '', 'S75 the claim passes over a row whose not_before is after now()';
  UPDATE domain_watch_lane AS dwl SET not_before = now() WHERE dwl.domain_name = 'c2.example' AND dwl.lane_name = 'ct';
  ASSERT pg_temp.t_claim('ct', 10) = 'c2.example', 'S75 the claim takes a row whose not_before is now()';
END
$$;

DO $$
BEGIN
  ASSERT api.fn_domain_watch_cert_issuers_union(NULL, E'new_issuer pki.goog\ncaa_mismatch letsencrypt.org') = E'letsencrypt.org\npki.goog',
         'S76 a first union holds the scanned keys in byte order, with no reason';
  ASSERT api.fn_domain_watch_cert_issuers_union(E'letsencrypt.org\npki.goog', 'new_issuer digicert.com,symantec.com')
         = E'digicert.com,symantec.com\nletsencrypt.org\npki.goog',
         'S76 the union keeps the stored keys the scan no longer sees';
  ASSERT api.fn_domain_watch_cert_issuers_union(E'letsencrypt.org\npki.goog', 'new_issuer Some CA') = E'Some CA\nletsencrypt.org\npki.goog',
         'S76 the union sorts by byte, so an upper case name comes first, and a key keeps its spaces';
  ASSERT api.fn_domain_watch_cert_issuers_union('letsencrypt.org', 'caa_mismatch letsencrypt.org') = 'letsencrypt.org',
         'S76 a key that is stored and scanned is held once';
  ASSERT api.fn_domain_watch_cert_issuers_union('letsencrypt.org', '') = 'letsencrypt.org',
         'S76 a scan with no issuer keeps the stored keys';
  ASSERT api.fn_domain_watch_cert_issuers_union(NULL, '') = '', 'S76 a first scan with no issuer stores an empty set';

  ASSERT api.fn_domain_watch_cert_unexpected_value('letsencrypt.org', E'new_issuer pki.goog\ncaa_mismatch letsencrypt.org')
         = E'known letsencrypt.org\nnew_issuer pki.goog',
         'S76 the event text marks the stored key known and the new key with its reason';
  ASSERT api.fn_domain_watch_cert_unexpected_value(E'letsencrypt.org\npki.goog', E'caa_mismatch digicert.com\nnew_issuer Some CA')
         = E'new_issuer Some CA\ncaa_mismatch digicert.com\nknown letsencrypt.org\nknown pki.goog',
         'S76 the event text follows the byte order of the keys, and keeps the reason of each new key';
  ASSERT api.fn_domain_watch_cert_unexpected_value(E'letsencrypt.org\npki.goog', 'caa_mismatch letsencrypt.org') IS NULL,
         'S76 a renewal from a stored issuer writes no event, whatever its reason';
  ASSERT api.fn_domain_watch_cert_unexpected_value('letsencrypt.org', '') IS NULL, 'S76 a scan with no issuer writes no event';
  ASSERT api.fn_domain_watch_cert_unexpected_value('', 'new_issuer pki.goog') = 'new_issuer pki.goog',
         'S76 the first issuer after an empty set is new';
END
$$;

SELECT pg_temp.t_reset();
SELECT pg_temp.t_add_ct('c3.example');
SELECT pg_temp.t_add_dns('c3.example');
DO $$
DECLARE
  daily_scan CONSTANT timestamptz := api.fn_domain_watch_next_daily_scan_at('c3.example');
BEGIN
  PERFORM pg_temp.t_dw_mark();
  ASSERT pg_temp.t_record_ct('c3.example', E'caa_mismatch letsencrypt.org\nnew_issuer pki.goog') = 0, 'S77 the first scan writes no event';
  ASSERT pg_temp.t_values('c3.example') = 'cert_issuers=letsencrypt.org+pki.goog',
         'S77 the first scan stores the keys of the cert_search item, and no value of the dns_lookup item';
  ASSERT (SELECT dwl.claimed_until IS NULL AND dwl.scanned_at = now() FROM domain_watch_lane AS dwl
           WHERE dwl.domain_name = 'c3.example' AND dwl.lane_name = 'ct'),
         'S77 the record ends the lease and notes scanned_at';
  ASSERT pg_temp.t_next_scan('c3.example', p_endpoint_name => 'cert_search') = daily_scan
     AND pg_temp.t_next_scan('c3.example') <= now(),
         'S77 the first scan puts the cert_search item at its daily second, and the dns_lookup item keeps its next scan';
  ASSERT (SELECT widv.current_value_sha256 FROM watchlist_item_domain_value AS widv
            JOIN watchlist_item_domain AS wid ON wid.item_id = widv.item_id
           WHERE wid.domain_name = 'c3.example' AND widv.value_kind = 'cert_issuers') = pg_temp.t_sha256(E'letsencrypt.org\npki.goog'),
         'S77 the stored SHA-256 is the one of the stored keys';

  ASSERT pg_temp.t_record_ct('c3.example', 'new_issuer pki.goog') = 0, 'S77 a renewal from a stored issuer writes no event';
  ASSERT pg_temp.t_values('c3.example') = 'cert_issuers=letsencrypt.org+pki.goog', 'S77 a scan that sees fewer issuers keeps every stored key';

  ASSERT pg_temp.t_record_ct('c3.example', E'caa_mismatch digicert.com\nnew_issuer pki.goog') = 1, 'S77 a new issuer writes one event at once';
  ASSERT pg_temp.t_dw_events('c3.example') = ARRAY['cert_unexpected:letsencrypt.org+pki.goog>caa_mismatch digicert.com+known letsencrypt.org+known pki.goog'],
         'S77 the event holds the stored keys before, and the marked union after';
  ASSERT pg_temp.t_values('c3.example') = 'cert_issuers=digicert.com+letsencrypt.org+pki.goog',
         'S77 the union becomes the stored value, with no candidate';
  ASSERT (SELECT widv.current_value_sha256 FROM watchlist_item_domain_value AS widv
            JOIN watchlist_item_domain AS wid ON wid.item_id = widv.item_id
           WHERE wid.domain_name = 'c3.example' AND widv.value_kind = 'cert_issuers')
         = pg_temp.t_sha256(E'digicert.com\nletsencrypt.org\npki.goog'),
         'S77 the stored SHA-256 follows the union';
  ASSERT pg_temp.t_next_scan('c3.example', p_endpoint_name => 'cert_search') = daily_scan, 'S77 a new issuer brings no hourly rescan';
  ASSERT pg_temp.t_heard(repeat('9c', 32), 'c3.example')
         = ARRAY['cert_unexpected:letsencrypt.org+pki.goog>caa_mismatch digicert.com+known letsencrypt.org+known pki.goog'],
         'S77 the key of the item hears the event';
  ASSERT pg_temp.t_record_ct('c3.example', E'caa_mismatch digicert.com\nnew_issuer pki.goog') = 0, 'S77 the same scan again writes no event';

  PERFORM pg_temp.t_reset();
  PERFORM pg_temp.t_add_ct('c4.example');
  PERFORM pg_temp.t_record_ct('c4.example', 'new_issuer ' || repeat('a', 2029));
  ASSERT pg_temp.t_record_ct('c4.example', 'new_issuer b') = 1, 'S77 an event text of 2048 bytes is written';
  ASSERT (SELECT octet_length(dce.current_value) FROM domain_change_event AS dce WHERE dce.domain_name = 'c4.example') = 2048,
         'S77 the event text is 2048 bytes';
  PERFORM pg_temp.t_reset();
  PERFORM pg_temp.t_add_ct('c5.example');
  PERFORM pg_temp.t_record_ct('c5.example', 'new_issuer ' || repeat('a', 2030));
  ASSERT pg_temp.t_record_ct('c5.example', 'new_issuer b') = 0, 'S77 an event text of 2049 bytes writes no event';
  ASSERT pg_temp.t_values('c5.example') = 'cert_issuers=' || repeat('a', 2030), 'S77 a union past the cap keeps the stored value';
END
$$;

SELECT pg_temp.t_reset();
SELECT pg_temp.t_add_ct('c6.example');
DO $$
BEGIN
  PERFORM pg_temp.t_dw_mark();
  PERFORM pg_temp.t_record_ct('c6.example', 'new_issuer globalsign.com');
  PERFORM pg_temp.t_add_ct('c6.example', repeat('a1', 32));
  ASSERT pg_temp.t_record_ct('c6.example', 'new_issuer letsencrypt.org') = 1, 'S78 the scan writes one event, for key 9c';
  ASSERT pg_temp.t_values('c6.example', repeat('a1', 32)) = 'cert_issuers=letsencrypt.org', 'S78 the item of key a1 stores its baseline';
  ASSERT pg_temp.t_heard(repeat('a1', 32), 'c6.example') = '{}', 'S78 the baseline of key a1 writes it no event';

  ASSERT pg_temp.t_record_ct('c6.example', E'new_issuer letsencrypt.org\nnew_issuer pki.goog') = 2, 'S78 the next scan writes one event for each key';
  ASSERT pg_temp.t_heard(repeat('9c', 32), 'c6.example')
         = ARRAY['cert_unexpected:globalsign.com>known globalsign.com+new_issuer letsencrypt.org',
                 'cert_unexpected:globalsign.com+letsencrypt.org>known globalsign.com+known letsencrypt.org+new_issuer pki.goog'],
         'S78 key 9c hears each new issuer against its own set';
  ASSERT pg_temp.t_heard(repeat('a1', 32), 'c6.example') = ARRAY['cert_unexpected:letsencrypt.org>known letsencrypt.org+new_issuer pki.goog'],
         'S78 key a1 hears only pki.goog, against its own set';
END
$$;
