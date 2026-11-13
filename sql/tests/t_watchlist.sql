TRUNCATE cve_change_event RESTART IDENTITY;
UPDATE change_event_purge_state SET max_purged_event_id = 0 WHERE event_table_name = 'cve_change_event';
TRUNCATE domain_change_event, package_advisory_change_event, eol_change_event, watchlist_event_ref;
DELETE FROM watchlist_item WHERE endpoint_name IN ('dns_lookup', 'ssl_check', 'whois_lookup', 'headers_check', 'cert_search');
DELETE FROM domain_watch;
UPDATE change_event_purge_state SET max_purged_event_id = 0, max_unwatched_event_id = 0 WHERE event_table_name = 'domain_change_event';
UPDATE change_event_purge_state SET max_purged_event_id = 0 WHERE event_table_name IN ('package_advisory_change_event', 'eol_change_event');

CREATE TEMP TABLE t_watchlist_key (label text, key_hash text);
INSERT INTO t_watchlist_key VALUES ('A', repeat('ab', 32)), ('B', repeat('cd', 32)), ('unknown', repeat('ef', 32));
INSERT INTO api_keys (key_hash) SELECT k.key_hash FROM t_watchlist_key AS k WHERE k.label IN ('A', 'B');

CREATE FUNCTION pg_temp.t_hash(p_label text) RETURNS text LANGUAGE sql AS $$
  SELECT k.key_hash FROM t_watchlist_key AS k WHERE k.label = p_label
$$;
CREATE FUNCTION pg_temp.t_key_id(p_label text) RETURNS integer LANGUAGE sql AS $$
  SELECT ak.id FROM api_keys AS ak WHERE ak.key_hash = pg_temp.t_hash(p_label)
$$;

CREATE FUNCTION pg_temp.t_edit(p_label text, p_action text, p_endpoint_name text,
                               p_cve_id text DEFAULT NULL, p_vendor text DEFAULT NULL, p_product text DEFAULT NULL,
                               p_severity text DEFAULT NULL, p_cwe_id text DEFAULT NULL,
                               p_min_cvss real DEFAULT NULL, p_min_epss real DEFAULT NULL,
                               p_in_kev boolean DEFAULT NULL, p_known_ransomware boolean DEFAULT NULL,
                               p_has_nuclei_template boolean DEFAULT NULL,
                               p_is_cleared boolean DEFAULT false, p_item_max_count integer DEFAULT 100,
                               p_domain_name text DEFAULT NULL, p_registered_domain text DEFAULT NULL,
                               p_domain_name_max_count integer DEFAULT 20,
                               p_ecosystem text DEFAULT NULL, p_package_name text DEFAULT NULL, p_version text DEFAULT NULL,
                               p_package_item_max_count integer DEFAULT 500,
                               p_package_item_base_weight integer DEFAULT 100, p_package_weight_budget integer DEFAULT 100000,
                               p_listed_versions_per_weight integer DEFAULT 20)
  RETURNS text LANGUAGE sql AS $$
  SELECT string_agg(DISTINCT x.edit_status, ',')
    FROM pg_temp.t_watchlist_edit(pg_temp.t_hash(p_label), p_action, p_endpoint_name, p_cve_id, p_vendor, p_product,
                                  p_severity, p_cwe_id, p_min_cvss, p_min_epss, p_in_kev, p_known_ransomware, p_has_nuclei_template,
                                  p_is_cleared, p_item_max_count, p_domain_name,
                                  coalesce(p_registered_domain, substring(p_domain_name FROM '[^.]+\.[^.]+$')),
                                  p_domain_name_max_count, p_ecosystem, p_package_name, p_version, p_package_item_max_count,
                                  p_package_item_base_weight, p_package_weight_budget, p_listed_versions_per_weight) AS x
$$;

CREATE FUNCTION pg_temp.t_items(p_label text) RETURNS text[] LANGUAGE sql AS $$
  SELECT coalesce(array_agg(x.endpoint_name || ':'
                            || concat_ws(',', x.cve_id, x.vendor, x.product, x.domain_name, x.severity, x.cwe_id,
                                         x.min_cvss, x.min_epss, x.in_kev::text, x.known_ransomware::text,
                                         x.has_nuclei_template::text, x.ecosystem, x.package_name, x.version)
                            || coalesce(':' || x.product_has_cves::text, '')
                            ORDER BY x.ordinality) FILTER (WHERE x.endpoint_name IS NOT NULL), '{}')
    FROM pg_temp.t_watchlist_edit(pg_temp.t_hash(p_label), NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
                                  NULL, NULL, NULL, false, 100, NULL, NULL, 20, NULL, NULL, NULL, 500, 100, 100000, 20) WITH ORDINALITY AS x
$$;

CREATE FUNCTION pg_temp.t_events(p_label text, p_replay_cursor bigint, p_is_repeat_requested boolean,
                                 p_event_row_count integer, p_scan_row_count integer, p_pair_row_count integer DEFAULT 600)
  RETURNS text LANGUAGE sql AS $$
  SELECT min(x.events_status) || '|' || coalesce(min(x.next_cursor)::text, 'null') || '|' || bool_and(x.has_more)::text
         || '|' || coalesce(array_agg(coalesce(right(x.cve_id, 2), x.item_domain_name) || ':' || x.event_type ORDER BY x.event_rank)
                            FILTER (WHERE x.event_type IS NOT NULL), '{}')::text
    FROM api.fn_watchlist_events(pg_temp.t_hash(p_label), p_replay_cursor, p_is_repeat_requested, p_event_row_count,
                                 p_scan_row_count, p_pair_row_count) AS x
$$;

CREATE FUNCTION pg_temp.t_event_cursor(p_label text) RETURNS text LANGUAGE sql AS $$
  SELECT coalesce((SELECT wec.previous_cursor || ',' || wec.delivered_cursor
                     FROM watchlist_event_cursor AS wec WHERE wec.api_key_id = pg_temp.t_key_id(p_label)), 'none')
$$;

CREATE FUNCTION pg_temp.t_key_state(p_label text) RETURNS text LANGUAGE sql AS $$
  SELECT coalesce((SELECT wks.last_key_event_id || ',' || wks.max_purged_key_event_id || ',' || wks.last_cve_event_id
                     FROM watchlist_key_state AS wks WHERE wks.api_key_id = pg_temp.t_key_id(p_label)), 'none')
$$;

CREATE FUNCTION pg_temp.t_rewind(p_label text, p_after_event_id bigint) RETURNS void LANGUAGE sql AS $$
  DELETE FROM watchlist_event_ref AS wer
   WHERE wer.api_key_id = pg_temp.t_key_id(p_label)
     AND NOT EXISTS (SELECT 1 FROM domain_change_event AS dce WHERE dce.event_id = wer.event_id)
     AND NOT EXISTS (SELECT 1 FROM ip_change_event AS ice WHERE ice.event_id = wer.event_id);
  UPDATE watchlist_event_ref AS wer SET key_event_id = NULL WHERE wer.api_key_id = pg_temp.t_key_id(p_label);
  UPDATE watchlist_key_state AS wks SET last_key_event_id = 0, max_purged_key_event_id = 0, last_cve_event_id = p_after_event_id
   WHERE wks.api_key_id = pg_temp.t_key_id(p_label);
  UPDATE watchlist_event_cursor AS wec SET previous_cursor = 0, delivered_cursor = 0 WHERE wec.api_key_id = pg_temp.t_key_id(p_label);
$$;

CREATE FUNCTION pg_temp.t_events_after(p_label text, p_after_event_id bigint, p_event_row_count integer, p_scan_row_count integer,
                                       p_pair_row_count integer DEFAULT 600)
  RETURNS text LANGUAGE sql AS $$
  SELECT pg_temp.t_rewind(p_label, p_after_event_id);
  SELECT pg_temp.t_events(p_label, NULL, false, p_event_row_count, p_scan_row_count, p_pair_row_count);
$$;

CREATE FUNCTION pg_temp.t_item_count(p_label text) RETURNS bigint LANGUAGE sql AS $$
  SELECT count(*) FROM watchlist_item AS wi WHERE wi.api_key_id = pg_temp.t_key_id(p_label)
$$;

SELECT set_config('contrastapi.cve_events', 'off', true);
INSERT INTO cves (cve_id, severity, cwe_id, cvss_v3, cvss_v3_vector, cvss_v4, cvss_v4_vector, epss_score, in_kev, refs) VALUES
  ('CVE-2006-0001', 'HIGH',     'CWE-79', 7.5, 'CVSS:3.1/AV:N', 5.0, 'CVSS:4.0/AV:N', 0.5,  true,
   '[{"url": "https://e.example", "tags": ["Exploit"]}, {"url": "https://f.example", "tags": ["Exploit"]},
     {"url": "https://www.exploit-db.com/exploits/61"}, {"url": "https://www.exploit-db.com/exploits/62"},
     {"url": "https://www.exploit-db.com/exploits/63"}, {"url": "https://packetstormsecurity.com/files/64/x.html"},
     {"url": "https://packetstorm.news/files/id/65", "tags": ["Third Party Advisory"]}]'),
  ('CVE-2006-0002', 'MEDIUM',   'CWE-89', 7.4, 'CVSS:3.1/AV:N', 0.0, '',              0.49, false, '[]'),
  ('CVE-2006-0003', 'CRITICAL', 'CWE-20', 0.0, '',              0.0, '',              0.0,  false, '[]'),
  ('CVE-2006-0004', 'LOW',      'CWE-22', 9.8, '',              5.0, 'CVSS:4.0/AV:N', 0.0,  false, '[]');
INSERT INTO github_poc_repos (cve_id, repo_full_name, star_count) VALUES
  ('CVE-2006-0002', 'a-owner/poc', 50),
  ('CVE-2006-0002', 'b-owner/poc', 0);
UPDATE cves SET has_metasploit = true WHERE cve_id = 'CVE-2006-0001';
UPDATE cves SET has_nuclei_template = true WHERE cve_id = 'CVE-2006-0002';
INSERT INTO cve_products (cve_id, vendor, product, is_vulnerable) VALUES
  ('CVE-2006-0001', 'wlacme',  'wlwidget', true),
  ('CVE-2006-0001', 'wlbeta',  'wlgadget', true),
  ('CVE-2006-0002', 'wlother', 'wlwidget', true),
  ('CVE-2006-0003', 'wlacme',  'wlwidget', false);
INSERT INTO kev_details (cve_id, known_ransomware_use, patch_deadline, required_action) VALUES
  ('CVE-2006-0001', true,  '2024-02-03', 'Apply updates per vendor instructions.'),
  ('CVE-2006-0003', false, '2024-02-04', 'Discontinue use.');
SELECT set_config('contrastapi.cve_events', '', true);
INSERT INTO cve_change_event (cve_id, event_type) VALUES
  ('CVE-2006-0001', 'cve_added'), ('CVE-2006-0002', 'cve_added'), ('CVE-2006-0003', 'cve_added'), ('CVE-2006-0004', 'cve_added');

CREATE TEMP VIEW t_watchlist_list_call AS SELECT * FROM api.fn_watchlist_list(repeat('ab', 32));
CREATE TEMP VIEW t_watchlist_clear_call AS SELECT * FROM api.fn_watchlist_clear(repeat('ab', 32));
CREATE TEMP VIEW t_watchlist_edit_cve_lookup_call AS SELECT * FROM api.fn_watchlist_edit_cve_lookup(repeat('ab', 32), 'add', NULL::text, 100);
CREATE TEMP VIEW t_watchlist_edit_kev_lookup_call AS SELECT * FROM api.fn_watchlist_edit_kev_lookup(repeat('ab', 32), 'add', NULL::text, 100);
CREATE TEMP VIEW t_watchlist_edit_cve_exploit_call AS SELECT * FROM api.fn_watchlist_edit_cve_exploit(repeat('ab', 32), 'add', NULL::text, 100);
CREATE TEMP VIEW t_watchlist_edit_product_exposure_call AS
  SELECT * FROM api.fn_watchlist_edit_product_exposure(repeat('ab', 32), 'add', NULL::text, NULL::text, NULL::text, 100);
CREATE TEMP VIEW t_watchlist_edit_cve_search_call AS
  SELECT * FROM api.fn_watchlist_edit_cve_search(repeat('ab', 32), 'add', NULL::text, NULL::text, NULL::text, NULL::text, NULL::real, NULL::real,
                                                 NULL::boolean, NULL::boolean, NULL::boolean, 100);
CREATE TEMP VIEW t_watchlist_edit_dns_lookup_call AS SELECT * FROM api.fn_watchlist_edit_dns_lookup(repeat('ab', 32), 'add', NULL::text, NULL::text, 100, 20);
CREATE TEMP VIEW t_watchlist_edit_ssl_check_call AS SELECT * FROM api.fn_watchlist_edit_ssl_check(repeat('ab', 32), 'add', NULL::text, NULL::text, 100, 20);
CREATE TEMP VIEW t_watchlist_edit_whois_lookup_call AS SELECT * FROM api.fn_watchlist_edit_whois_lookup(repeat('ab', 32), 'add', NULL::text, NULL::text, 100, 20);
CREATE TEMP VIEW t_watchlist_edit_headers_check_call AS SELECT * FROM api.fn_watchlist_edit_headers_check(repeat('ab', 32), 'add', NULL::text, NULL::text, 100, 20);
CREATE TEMP VIEW t_watchlist_edit_cert_search_call AS SELECT * FROM api.fn_watchlist_edit_cert_search(repeat('ab', 32), 'add', NULL::text, NULL::text, 100, 20);
CREATE TEMP VIEW t_watchlist_edit_package_check_call AS
  SELECT * FROM api.fn_watchlist_edit_package_check(repeat('ab', 32), 'add', NULL::text, NULL::text, NULL::text, 500, 100, 100000, 20);
CREATE TEMP VIEW t_watchlist_edit_ip_lookup_call AS SELECT * FROM api.fn_watchlist_edit_ip_lookup(repeat('ab', 32), 'add', NULL::inet, 100);
CREATE TEMP VIEW t_watchlist_events_call AS
  SELECT * FROM api.fn_watchlist_events(repeat('ab', 32), NULL::bigint, false, 20, 10000, 600);
CREATE TEMP VIEW t_watchlist_purge_call AS SELECT api.fn_watchlist_purge(0) AS cleared_key_count;

DO $$
DECLARE
  head_columns  CONSTANT text[] := ARRAY['edit_status text', 'endpoint_name text'];
  count_columns CONSTANT text[] := ARRAY['item_count integer', 'package_item_count integer'];
  wide_columns  CONSTANT text[] := ARRAY['edit_status text', 'endpoint_name text', 'cve_id text', 'vendor text', 'product text', 'severity text',
                                         'cwe_id text', 'min_cvss real', 'min_epss real', 'in_kev boolean', 'known_ransomware boolean',
                                         'has_nuclei_template boolean', 'product_has_cves boolean', 'domain_name text', 'ecosystem text',
                                         'package_name text', 'version text', 'ip_address text', 'item_count integer',
                                         'package_item_count integer'];
  call          record;
  view_count    integer := 0;
BEGIN
  FOR call IN SELECT * FROM (VALUES
      ('t_watchlist_list_call', wide_columns), ('t_watchlist_clear_call', wide_columns),
      ('t_watchlist_edit_cve_lookup_call', head_columns || ARRAY['cve_id text'] || count_columns),
      ('t_watchlist_edit_kev_lookup_call', head_columns || ARRAY['cve_id text'] || count_columns),
      ('t_watchlist_edit_cve_exploit_call', head_columns || ARRAY['cve_id text'] || count_columns),
      ('t_watchlist_edit_product_exposure_call', head_columns || ARRAY['vendor text', 'product text', 'product_has_cves boolean', 'version text'] || count_columns),
      ('t_watchlist_edit_cve_search_call', head_columns || ARRAY['vendor text', 'product text', 'severity text', 'cwe_id text', 'min_cvss real',
                                                                 'min_epss real', 'in_kev boolean', 'known_ransomware boolean',
                                                                 'has_nuclei_template boolean'] || count_columns),
      ('t_watchlist_edit_dns_lookup_call', head_columns || ARRAY['domain_name text'] || count_columns),
      ('t_watchlist_edit_ssl_check_call', head_columns || ARRAY['domain_name text'] || count_columns),
      ('t_watchlist_edit_whois_lookup_call', head_columns || ARRAY['domain_name text'] || count_columns),
      ('t_watchlist_edit_headers_check_call', head_columns || ARRAY['domain_name text'] || count_columns),
      ('t_watchlist_edit_cert_search_call', head_columns || ARRAY['domain_name text'] || count_columns),
      ('t_watchlist_edit_package_check_call', head_columns || ARRAY['ecosystem text', 'package_name text', 'version text'] || count_columns),
      ('t_watchlist_edit_ip_lookup_call', head_columns || ARRAY['ip_address text'] || count_columns))
      AS c (view_name, columns) LOOP
    ASSERT (SELECT array_agg(attname::text || ' ' || format_type(atttypid, atttypmod) ORDER BY attnum)
              FROM pg_attribute WHERE attrelid = call.view_name::regclass AND attnum > 0) = call.columns,
           call.view_name || ' answers the columns db_WATCHLISTEDITItems reads, in order';
    view_count := view_count + 1;
  END LOOP;
  ASSERT view_count = 14, 'the fourteen edit calls are checked';
  ASSERT (SELECT array_agg(attname::text || ' ' || format_type(atttypid, atttypmod) ORDER BY attnum)
            FROM pg_attribute WHERE attrelid = 't_watchlist_events_call'::regclass AND attnum > 0)
         = ARRAY['events_status text', 'next_cursor bigint', 'has_more boolean',
                 'item_id bigint', 'item_endpoint_name text', 'item_cve_id text', 'item_vendor text', 'item_product text',
                 'item_severity text', 'item_cwe_id text', 'item_min_cvss real', 'item_min_epss real', 'item_in_kev boolean',
                 'item_known_ransomware boolean', 'item_has_nuclei_template boolean', 'item_product_has_cves boolean',
                 'item_domain_name text', 'item_ecosystem text', 'item_package_name text', 'item_version text',
                 'item_ip_address text', 'event_rank integer', 'is_first_row_of_event boolean', 'event_type text', 'changed_at text',
                 'cve_id text', 'previous_value real', 'current_value real', 'vendor text', 'product text',
                 'degraded_email_check_id text', 'previous_domain_value text', 'current_domain_value text',
                 'is_first_event_of_cve boolean', 'risk_score double precision', 'risk_label text', 'in_kev boolean',
                 'kev_patch_deadline text', 'kev_known_ransomware boolean', 'has_metasploit boolean', 'poc_count integer',
                 'is_first_event_of_domain boolean', 'registered_domain text', 'dns_presence_value text', 'ns_value text',
                 'mx_value text', 'ip_address_reachability_value text', 'cname_takeover_value text', 'email_auth_value text',
                 'advisory_id text', 'fixed_version text', 'previous_ip_value text', 'current_ip_value text',
                 'drop_list_time text', 'drop_copyright text', 'eol_product text', 'eol_cycle text', 'eol_date text',
                 'previous_eol_date text', 'affects_version boolean', 'is_first_event_of_advisory boolean',
                 'advisory_source text', 'advisory_aliases jsonb', 'advisory_cve_facts jsonb', 'attribution jsonb'],
         'the events call answers the sixty-five columns db_WATCHLISTEVENTS reads, in order';
  ASSERT (SELECT array_agg(attname::text || ' ' || format_type(atttypid, atttypmod) ORDER BY attnum)
            FROM pg_attribute WHERE attrelid = 't_watchlist_purge_call'::regclass AND attnum > 0)
         = ARRAY['cleared_key_count integer'],
         'the purge call answers one integer column, cleared_key_count';
  ASSERT (SELECT array_agg(pi.indexdef ORDER BY pi.indexname) FROM pg_indexes AS pi WHERE pi.tablename = 'watchlist_event_ref')
         = ARRAY['CREATE INDEX idx_watchlist_event_ref_event_id ON public.watchlist_event_ref USING btree (event_id)',
                 'CREATE INDEX idx_watchlist_event_ref_key_event_id ON public.watchlist_event_ref USING btree (api_key_id, key_event_id)',
                 'CREATE INDEX idx_watchlist_event_ref_pending ON public.watchlist_event_ref USING btree (api_key_id, event_id) WHERE (key_event_id IS NULL)',
                 'CREATE UNIQUE INDEX watchlist_event_ref_pkey ON public.watchlist_event_ref USING btree (item_id, event_id)'],
         'watchlist_event_ref finds the numbered refs of a key, the waiting refs of a key and the refs of an event, and keeps one ref per item and event';
END
$$;

DO $$
BEGIN
  ASSERT pg_temp.t_edit('A', NULL, NULL) = 'ok', 'a key with no item answers ok';
  ASSERT (SELECT count(*) FROM t_watchlist_list_call) = 1
     AND (SELECT c.endpoint_name IS NULL AND c.product_has_cves IS NULL FROM t_watchlist_list_call AS c),
         'a key with no item answers one row whose endpoint_name and product_has_cves are NULL';
  ASSERT pg_temp.t_edit('unknown', 'add', 'cve_lookup', p_cve_id => 'CVE-2006-0001') = 'unknown_key',
         'a hash with no api_keys row answers unknown_key';
  ASSERT (SELECT count(*) FROM watchlist_item) = 0, 'unknown_key inserts nothing';
  ASSERT pg_temp.t_edit('A', 'add', 'cve_lookup', p_cve_id => 'CVE-2006-0001') = 'ok', 'the first add answers ok';
  ASSERT pg_temp.t_items('A') = '{cve_lookup:CVE-2006-0001}', 'the list holds the new item';
  ASSERT (SELECT wi.last_event_id_before_add FROM watchlist_item_cve AS wi WHERE wi.api_key_id = pg_temp.t_key_id('A')) = 4,
         'last_event_id_before_add is the largest event_id at the add';
  ASSERT pg_temp.t_event_cursor('A') = '0,0', 'the first add opens the position at the key''s own number 0';
  ASSERT pg_temp.t_key_state('A') = '0,0,4', 'the first add writes the key state with the CVE head as last_cve_event_id';
  ASSERT pg_temp.t_edit('A', 'add', 'kev_lookup', p_cve_id => 'CVE-2006-0001') = 'ok', 'kev_lookup item';
  ASSERT pg_temp.t_edit('A', 'add', 'cve_exploit', p_cve_id => 'CVE-2006-0001') = 'ok', 'cve_exploit item';
  ASSERT pg_temp.t_edit('A', 'add', 'product_exposure', p_vendor => 'wlacme', p_product => 'wlwidget') = 'ok', 'product_exposure item with CVEs';
  ASSERT pg_temp.t_edit('A', 'add', 'product_exposure', p_vendor => 'wlacme', p_product => 'wlgadget') = 'ok', 'product_exposure item';
  ASSERT pg_temp.t_edit('A', 'add', 'cve_search', p_severity => 'HIGH', p_cwe_id => 'CWE-79', p_min_cvss => 7.5,
                        p_min_epss => 0.5, p_in_kev => true, p_known_ransomware => true) = 'ok', 'cve_search item';
  ASSERT pg_temp.t_edit('A', 'add', 'cve_search', p_vendor => 'wlacme') = 'ok', 'cve_search item with a vendor alone';
  ASSERT pg_temp.t_items('A') = '{cve_lookup:CVE-2006-0001,kev_lookup:CVE-2006-0001,cve_exploit:CVE-2006-0001,'
                                 '"product_exposure:wlacme,wlwidget:true","product_exposure:wlacme,wlgadget:false",'
                                 '"cve_search:HIGH,CWE-79,7.5,0.5,true,true",cve_search:wlacme}',
         'the list comes in item_id order, with product_has_cves on the two product items only';
  UPDATE watchlist_event_cursor SET previous_cursor = 1, delivered_cursor = 2 WHERE api_key_id = pg_temp.t_key_id('A');
  INSERT INTO cve_change_event (cve_id, event_type) VALUES ('CVE-2006-0001', 'kev_added');
  ASSERT pg_temp.t_edit('A', 'add', 'cve_lookup', p_cve_id => 'CVE-2006-0001') = 'ok', 'a repeated add answers ok';
  ASSERT pg_temp.t_item_count('A') = 7, 'a repeated add inserts nothing';
  ASSERT (SELECT wi.last_event_id_before_add FROM watchlist_item_cve AS wi
           WHERE wi.api_key_id = pg_temp.t_key_id('A') AND wi.endpoint_name = 'cve_lookup') = 4,
         'a repeated add keeps last_event_id_before_add';
  ASSERT pg_temp.t_event_cursor('A') = '1,2', 'a repeated add keeps the position';
  ASSERT pg_temp.t_key_state('A') = '0,0,4', 'a repeated add keeps the key state';
  ASSERT pg_temp.t_edit('A', 'add', 'product_exposure', p_vendor => 'wlacme', p_product => 'wlwidget') = 'ok', 'a repeated product item answers ok';
  ASSERT pg_temp.t_item_count('A') = 7, 'a repeated product item inserts nothing';
  ASSERT pg_temp.t_edit('A', NULL, NULL) = 'ok', 'a call with no action answers ok';
  ASSERT pg_temp.t_item_count('A') = 7, 'a call with no action changes nothing';
  ASSERT pg_temp.t_edit('A', 'add', 'product_exposure', p_vendor => 'wlacme', p_product => 'wlwidget', p_is_cleared => false) = 'ok', 'an add with is_cleared false answers ok';
  ASSERT pg_temp.t_item_count('A') = 7, 'is_cleared false clears nothing';
END
$$;

DO $$
BEGIN
  ASSERT pg_temp.t_edit('A', 'add', 'product_exposure', p_vendor => 'wlbeta', p_product => 'wlwidget') = 'ok', 'an add of an item with another vendor answers ok';
  ASSERT pg_temp.t_item_count('A') = 8, 'an item with another vendor is another item';
  ASSERT pg_temp.t_edit('A', 'add', 'product_exposure', p_vendor => 'wlacme', p_product => 'wlbolt') = 'ok', 'an add of an item with another product answers ok';
  ASSERT pg_temp.t_item_count('A') = 9, 'an item with another product is another item';
  ASSERT pg_temp.t_edit('A', 'add', 'cve_search', p_min_cvss => 7.5) = 'ok', 'a cve_search add with min_cvss alone answers ok';
  ASSERT pg_temp.t_item_count('A') = 10,
         'a cve_search item with min_cvss alone is a new item';
  ASSERT pg_temp.t_edit('A', 'add', 'cve_search', p_min_cvss => 7.4) = 'ok' AND pg_temp.t_item_count('A') = 11,
         'an item with another min_cvss is another item';
  ASSERT pg_temp.t_edit('A', 'add', 'cve_search', p_min_cvss => 7.5, p_min_epss => 0.5) = 'ok' AND pg_temp.t_item_count('A') = 12,
         'an item with a min_epss too is another item';
  ASSERT pg_temp.t_edit('A', 'add', 'cve_search', p_in_kev => true) = 'ok' AND pg_temp.t_item_count('A') = 13,
         'a cve_search item with in_kev alone';
  ASSERT pg_temp.t_edit('A', 'add', 'cve_search', p_in_kev => false) = 'ok' AND pg_temp.t_item_count('A') = 14,
         'an item with another in_kev is another item';
  ASSERT pg_temp.t_edit('A', 'add', 'cve_search', p_severity => 'HIGH') = 'ok' AND pg_temp.t_item_count('A') = 15,
         'a cve_search item with a severity alone';
  ASSERT pg_temp.t_edit('A', 'add', 'cve_search', p_severity => 'HIGH', p_cwe_id => 'CWE-79') = 'ok' AND pg_temp.t_item_count('A') = 16,
         'an item with a cwe_id too is another item';
  ASSERT pg_temp.t_edit('A', 'add', 'cve_search', p_known_ransomware => true) = 'ok' AND pg_temp.t_item_count('A') = 17,
         'a cve_search item with known_ransomware alone';
  ASSERT pg_temp.t_edit('A', 'add', 'cve_search', p_has_nuclei_template => true) = 'ok' AND pg_temp.t_item_count('A') = 18,
         'a cve_search item with has_nuclei_template alone is another item than the known_ransomware item';
  ASSERT pg_temp.t_edit('A', 'add', 'cve_search', p_known_ransomware => true, p_has_nuclei_template => true) = 'ok'
     AND pg_temp.t_item_count('A') = 19,
         'an item with has_nuclei_template and known_ransomware is another item';
  ASSERT pg_temp.t_edit('A', 'add', 'cve_search', p_has_nuclei_template => true) = 'ok' AND pg_temp.t_item_count('A') = 19,
         'the same has_nuclei_template item again inserts nothing';
  ASSERT (SELECT array_agg(coalesce(x.known_ransomware::text, 'null') || '|' || coalesce(x.has_nuclei_template::text, 'null')
                           ORDER BY x.ordinality)
            FROM pg_temp.t_watchlist_edit(pg_temp.t_hash('A'), NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
                                          false, 100, NULL, NULL, 20, NULL, NULL, NULL, 500, 100, 100000, 20) WITH ORDINALITY AS x
           WHERE x.endpoint_name = 'cve_search' AND num_nonnulls(x.vendor, x.product, x.severity, x.cwe_id, x.min_cvss, x.min_epss, x.in_kev) = 0)
         = ARRAY['true|null', 'null|true', 'true|true'],
         'the list answers has_nuclei_template in its own column, apart from known_ransomware';
  ASSERT (SELECT array_agg(wic.has_nuclei_template ORDER BY wic.item_id) FROM watchlist_item_cve AS wic
           WHERE wic.api_key_id = pg_temp.t_key_id('A') AND wic.has_nuclei_template IS NOT NULL) = ARRAY[true, true],
         'watchlist_item_cve stores has_nuclei_template';
  ASSERT pg_temp.t_edit('A', 'remove', 'cve_search', p_has_nuclei_template => true) = 'ok' AND pg_temp.t_item_count('A') = 18,
         'remove deletes the has_nuclei_template item';
  ASSERT (SELECT count(*) FROM watchlist_item_cve AS wic WHERE wic.api_key_id = pg_temp.t_key_id('A') AND wic.has_nuclei_template) = 1,
         'remove of the has_nuclei_template item keeps the item that holds known_ransomware too';
  ASSERT pg_temp.t_edit('A', 'remove', 'cve_search', p_known_ransomware => true, p_has_nuclei_template => true) = 'ok'
     AND pg_temp.t_item_count('A') = 17,
         'remove deletes the item with both true-only filters';
  ASSERT pg_temp.t_edit('A', 'add', 'cve_search', p_in_kev => true) = 'ok' AND pg_temp.t_item_count('A') = 17,
         'the same in_kev item again inserts nothing';
  ASSERT pg_temp.t_edit('A', 'add', 'cve_search', p_min_cvss => 7.5) = 'ok' AND pg_temp.t_item_count('A') = 17,
         'the same min_cvss item again inserts nothing';
  ASSERT pg_temp.t_edit('A', 'remove', 'cve_search', p_severity => 'HIGH') = 'ok' AND pg_temp.t_item_count('A') = 16,
         'remove deletes the equal item';
  ASSERT (SELECT count(*) FROM watchlist_item_cve AS wi WHERE wi.api_key_id = pg_temp.t_key_id('A') AND wi.severity = 'HIGH') = 2,
         'remove keeps the items that hold the same severity with another column set';
  ASSERT pg_temp.t_edit('A', 'remove', 'product_exposure', p_vendor => 'wlacme', p_product => 'wlbolt') = 'ok' AND pg_temp.t_item_count('A') = 15,
         'remove deletes the product item that matches both names';
  ASSERT (SELECT count(*) FROM watchlist_item_cve AS wi WHERE wi.api_key_id = pg_temp.t_key_id('A') AND wi.vendor = 'wlacme') = 3,
         'remove keeps the other items of that vendor';
  ASSERT pg_temp.t_edit('A', 'remove', 'cve_search', p_min_cvss => 7.4) = 'ok' AND pg_temp.t_item_count('A') = 14,
         'remove deletes the item with the equal min_cvss';
  ASSERT pg_temp.t_edit('A', 'remove', 'cve_search', p_in_kev => false) = 'ok' AND pg_temp.t_item_count('A') = 13,
         'remove deletes the item with the equal in_kev';
  ASSERT pg_temp.t_edit('A', 'remove', 'product_exposure', p_vendor => 'wlbeta', p_product => 'wlwidget') = 'ok' AND pg_temp.t_item_count('A') = 12,
         'remove deletes the item with the equal vendor';
  ASSERT pg_temp.t_edit('A', 'remove', 'cve_search', p_severity => 'LOW') = 'ok' AND pg_temp.t_item_count('A') = 12,
         'removing an absent item answers ok and deletes nothing';
  ASSERT pg_temp.t_edit('A', 'remove', 'cve_search', p_in_kev => true, p_min_cvss => 7.5) = 'ok' AND pg_temp.t_item_count('A') = 12,
         'removing an item that two items each half match deletes nothing';
  ASSERT pg_temp.t_edit('A', 'remove', 'kev_lookup', p_cve_id => 'CVE-2006-0002') = 'ok' AND pg_temp.t_item_count('A') = 12,
         'removing a cve item of another cve_id deletes nothing';
  ASSERT pg_temp.t_edit('A', 'remove', 'cve_exploit', p_cve_id => 'CVE-2006-0001') = 'ok' AND pg_temp.t_item_count('A') = 11,
         'remove deletes the cve item of that endpoint';
  ASSERT (SELECT count(*) FROM watchlist_item_cve AS wi WHERE wi.api_key_id = pg_temp.t_key_id('A') AND wi.cve_id = 'CVE-2006-0001') = 2,
         'remove keeps the items of other endpoints with the same cve_id';
END
$$;

DO $$
DECLARE
  item_index integer;
BEGIN
  FOR item_index IN 12..99 LOOP
    ASSERT pg_temp.t_edit('A', 'add', 'cve_lookup', p_cve_id => 'CVE-2006-' || lpad(item_index::text, 4, '0')) = 'ok',
           'item ' || item_index || ' is added';
  END LOOP;
  ASSERT pg_temp.t_item_count('A') = 99, '99 items before the 100th';
  ASSERT pg_temp.t_edit('A', 'add', 'cve_lookup', p_cve_id => 'CVE-2006-0100') = 'ok', 'the 100th item is added';
  ASSERT pg_temp.t_item_count('A') = 100, 'the 100th item is in the list';
  ASSERT pg_temp.t_edit('A', 'add', 'cve_lookup', p_cve_id => 'CVE-2006-0101') = 'over_limit', 'the 101st item answers over_limit';
  ASSERT pg_temp.t_item_count('A') = 100, 'over_limit inserts nothing';
  ASSERT (SELECT array_agg(x.edit_status || '|' || coalesce(x.endpoint_name, '-') || '|' || x.item_count || '|' || x.package_item_count)
            FROM pg_temp.t_watchlist_edit(pg_temp.t_hash('A'), 'add', 'cve_lookup', 'CVE-2006-0101', NULL, NULL, NULL, NULL,
                                          NULL, NULL, NULL, NULL, NULL, false, 100, NULL, NULL, 20, NULL, NULL, NULL, 500, 100, 100000, 20) AS x)
         = ARRAY['over_limit|-|100|0'],
         'over_limit answers one row with that status, the counts and no item';
  ASSERT pg_temp.t_edit('A', 'add', 'cve_lookup', p_cve_id => 'CVE-2006-0100') = 'ok', 'an item already in a full list answers ok';
  ASSERT pg_temp.t_item_count('A') = 100,
         'an item already in a full list inserts nothing';
  ASSERT pg_temp.t_edit('A', 'add', 'cve_lookup', p_cve_id => 'CVE-2006-0101', p_item_max_count => 101) = 'ok'
     AND pg_temp.t_item_count('A') = 101, 'the cap is p_item_max_count';
  ASSERT pg_temp.t_edit('A', 'remove', 'cve_lookup', p_cve_id => 'CVE-2006-0101') = 'ok', 'removing the 101st item answers ok';
  ASSERT pg_temp.t_item_count('A') = 100,
         'the remove brings key A back to 100 items';
END
$$;

DO $$
BEGIN
  ASSERT pg_temp.t_items('B') = '{}', 'key B starts with no item while A holds 100';
  ASSERT pg_temp.t_edit('B', 'add', 'cve_lookup', p_cve_id => 'CVE-2006-0002') = 'ok',
         'key B adds an item while A is at the cap: the cap counts the items of one key';
  ASSERT pg_temp.t_items('B') = '{cve_lookup:CVE-2006-0002}' AND pg_temp.t_item_count('A') = 100,
         'key B lists its own item only';
  ASSERT pg_temp.t_edit('B', 'remove', 'cve_lookup', p_cve_id => 'CVE-2006-0001') = 'ok', 'key B removing a cve item that only A holds answers ok';
  ASSERT pg_temp.t_item_count('A') = 100 AND pg_temp.t_item_count('B') = 1,
         'key B removing an item that only A holds deletes nothing';
  ASSERT pg_temp.t_edit('B', 'remove', 'product_exposure', p_vendor => 'wlacme', p_product => 'wlwidget') = 'ok'
     AND pg_temp.t_item_count('A') = 100, 'key B removing a product item that only A holds deletes nothing';
  UPDATE watchlist_item_cve SET last_event_id_before_add = 0;
  ASSERT pg_temp.t_events_after('B', 0, 100, 100) = 'ok|1|false|{02:cve_added}',
         'key B sees the events of its own item only, not those of A''s items';
  ASSERT pg_temp.t_events_after('A', 0, 100, 100) = 'ok|2|false|{01:cve_added,01:kev_added}',
         'key A sees the events of its own items, and none of B''s';
  ASSERT pg_temp.t_edit('B', NULL, NULL, p_is_cleared => true) = 'ok', 'key B clearing its list answers ok';
  ASSERT pg_temp.t_item_count('A') = 100,
         'key B clearing its list leaves A''s items';
  ASSERT pg_temp.t_event_cursor('A') <> 'none', 'key B clearing its list leaves A''s position';
END
$$;

DO $$
BEGIN
  ASSERT pg_temp.t_edit('A', NULL, NULL, p_is_cleared => true) = 'ok', 'clear answers ok';
  ASSERT pg_temp.t_items('A') = '{}' AND pg_temp.t_item_count('A') = 0, 'clear deletes the items';
  ASSERT pg_temp.t_event_cursor('A') = 'none', 'clear deletes the position';
  ASSERT pg_temp.t_key_state('A') = '2,2,5', 'clear keeps the key state and raises max_purged_key_event_id to last_key_event_id';
  ASSERT pg_temp.t_edit('A', NULL, NULL, p_is_cleared => true) = 'ok', 'clearing an empty list answers ok';
  ASSERT pg_temp.t_edit('A', 'add', 'cve_lookup', p_cve_id => 'CVE-2006-0001') = 'ok', 'an add after clear answers ok';
  ASSERT pg_temp.t_event_cursor('A') = '2,2', 'the add after clear opens a new position at last_key_event_id';
  ASSERT (SELECT wi.last_event_id_before_add FROM watchlist_item_cve AS wi WHERE wi.api_key_id = pg_temp.t_key_id('A')) = 5,
         'the item after clear sees only later events';
  UPDATE change_event_purge_state SET max_purged_event_id = 9 WHERE event_table_name = 'cve_change_event';
  ASSERT pg_temp.t_edit('A', 'add', 'cve_lookup', p_cve_id => 'CVE-2006-0002') = 'ok', 'a later add answers ok';
  ASSERT (SELECT wi.last_event_id_before_add FROM watchlist_item_cve AS wi
           WHERE wi.api_key_id = pg_temp.t_key_id('A') AND wi.cve_id = 'CVE-2006-0002') = 9,
         'last_event_id_before_add counts a larger max_purged_event_id';
  ASSERT pg_temp.t_event_cursor('A') = '2,2', 'a later add keeps the position';
  UPDATE change_event_purge_state SET max_purged_event_id = 0 WHERE event_table_name = 'cve_change_event';
  ASSERT pg_temp.t_edit('A', NULL, NULL, p_is_cleared => true) = 'ok', 'a second clear answers ok';
END
$$;

DO $$
BEGIN
  ASSERT pg_temp.t_edit('A', 'add', 'cve_lookup', p_cve_id => 'CVE-2006-0001') = 'ok', 'S14: the first add answers ok';
  ASSERT pg_temp.t_edit('A', 'add', 'cve_lookup', p_cve_id => 'CVE-2006-0002') = 'ok', 'S14: the second add answers ok';
  UPDATE watchlist_event_cursor SET previous_cursor = 2, delivered_cursor = 4
   WHERE api_key_id = pg_temp.t_key_id('A');
  UPDATE watchlist_key_state SET last_key_event_id = 4 WHERE api_key_id = pg_temp.t_key_id('A');
  ASSERT pg_temp.t_edit('A', 'remove', 'cve_lookup', p_cve_id => 'CVE-2006-0002') = 'ok', 'S14: the first remove answers ok';
  ASSERT pg_temp.t_event_cursor('A') = '2,4', 'S14: a remove that leaves one item keeps the position';
  ASSERT pg_temp.t_key_state('A') = '4,2,5', 'S14: a remove that leaves one item keeps max_purged_key_event_id';
  ASSERT pg_temp.t_edit('A', 'remove', 'cve_lookup', p_cve_id => 'CVE-2006-0001') = 'ok', 'S14: the last remove answers ok';
  ASSERT pg_temp.t_item_count('A') = 0, 'S14: the last remove leaves no item';
  ASSERT pg_temp.t_event_cursor('A') = 'none', 'S14: a remove that leaves no item deletes the position';
  ASSERT pg_temp.t_key_state('A') = '4,4,5', 'S14: a remove that leaves no item raises max_purged_key_event_id to last_key_event_id';
  ASSERT pg_temp.t_edit('A', 'add', 'cve_lookup', p_cve_id => 'CVE-2006-0001') = 'ok', 'S14: an add after it answers ok';
  ASSERT pg_temp.t_event_cursor('A') = '4,4', 'S14: the add opens a new position at last_key_event_id';
  ASSERT pg_temp.t_edit('A', NULL, NULL, p_is_cleared => true) = 'ok', 'S14: the closing clear answers ok';
END
$$;

DO $$
DECLARE
  old_key_b integer := pg_temp.t_key_id('B');
BEGIN
  ASSERT pg_temp.t_edit('B', 'add', 'cve_lookup', p_cve_id => 'CVE-2006-0002') = 'ok', 'key B adds an item';
  ASSERT pg_temp.t_item_count('B') = 1 AND pg_temp.t_event_cursor('B') <> 'none' AND pg_temp.t_key_state('B') <> 'none',
         'the three rows of B exist';
  DELETE FROM api_keys WHERE key_hash = pg_temp.t_hash('B');
  ASSERT NOT EXISTS (SELECT 1 FROM watchlist_key_state AS wks WHERE wks.api_key_id = old_key_b), 'deleting the key deletes its key state';
  ASSERT (SELECT count(*) FROM watchlist_item) = 0 AND (SELECT count(*) FROM watchlist_item_cve) = 0,
         'deleting the key deletes its items and their child rows';
  ASSERT (SELECT count(*) FROM watchlist_event_cursor) = 0, 'deleting the key deletes its position';
  INSERT INTO api_keys (key_hash) VALUES (pg_temp.t_hash('B'));
END
$$;

CREATE FUNCTION pg_temp.t_cve_item(p_key_id integer, p_endpoint_name text, p_cve_id text DEFAULT NULL, p_vendor text DEFAULT NULL,
                                   p_product text DEFAULT NULL, p_severity text DEFAULT NULL, p_cwe_id text DEFAULT NULL,
                                   p_min_cvss real DEFAULT NULL, p_min_epss real DEFAULT NULL, p_in_kev boolean DEFAULT NULL,
                                   p_known_ransomware boolean DEFAULT NULL, p_has_nuclei_template boolean DEFAULT NULL,
                                   p_version text DEFAULT NULL)
  RETURNS void LANGUAGE sql AS $$
  WITH parent AS (
    INSERT INTO watchlist_item (api_key_id, endpoint_name) VALUES (p_key_id, p_endpoint_name)
    RETURNING watchlist_item.item_id, watchlist_item.api_key_id, watchlist_item.endpoint_name)
  INSERT INTO watchlist_item_cve (item_id, api_key_id, endpoint_name, last_event_id_before_add, cve_id, vendor, product, severity, cwe_id,
                                  min_cvss, min_epss, in_kev, known_ransomware, has_nuclei_template, version)
  SELECT p.item_id, p.api_key_id, p.endpoint_name, 0, p_cve_id, p_vendor, p_product, p_severity, p_cwe_id, p_min_cvss, p_min_epss, p_in_kev,
         p_known_ransomware, p_has_nuclei_template, p_version
    FROM parent AS p
$$;

DO $$
DECLARE
  key_a integer := pg_temp.t_key_id('A');
BEGIN
  BEGIN
    PERFORM pg_temp.t_cve_item(key_a, 'cve_lookup', 'CVE-2006-0001', 'wlacme');
    ASSERT false, 'watchlist_item_cve_shape refuses a cve item with a vendor';
  EXCEPTION WHEN check_violation THEN
    ASSERT SQLERRM LIKE '%watchlist_item_cve_shape%', 'the cve item with a vendor fails watchlist_item_cve_shape';
  END;
  BEGIN
    PERFORM pg_temp.t_cve_item(key_a, 'kev_lookup', 'CVE-2006-0001', p_min_cvss => 7.5);
    ASSERT false, 'watchlist_item_cve_shape refuses a kev item with a min_cvss';
  EXCEPTION WHEN check_violation THEN
    NULL;
  END;
  BEGIN
    PERFORM pg_temp.t_cve_item(key_a, 'cve_exploit');
    ASSERT false, 'watchlist_item_cve_shape refuses a cve item without a cve_id';
  EXCEPTION WHEN check_violation THEN
    NULL;
  END;
  BEGIN
    PERFORM pg_temp.t_cve_item(key_a, 'product_exposure', p_vendor => 'wlacme');
    ASSERT false, 'watchlist_item_cve_shape refuses a product item without a product';
  EXCEPTION WHEN check_violation THEN
    NULL;
  END;
  BEGIN
    PERFORM pg_temp.t_cve_item(key_a, 'product_exposure', p_product => 'wlwidget');
    ASSERT false, 'watchlist_item_cve_shape refuses a product item without a vendor';
  EXCEPTION WHEN check_violation THEN
    NULL;
  END;
  BEGIN
    PERFORM pg_temp.t_cve_item(key_a, 'product_exposure', 'CVE-2006-0001', 'wlacme', 'wlwidget');
    ASSERT false, 'watchlist_item_cve_shape refuses a product item with a cve_id';
  EXCEPTION WHEN check_violation THEN
    NULL;
  END;
  BEGIN
    PERFORM pg_temp.t_cve_item(key_a, 'product_exposure', NULL, 'wlacme', 'wlwidget', p_in_kev => true);
    ASSERT false, 'watchlist_item_cve_shape refuses a product item with in_kev';
  EXCEPTION WHEN check_violation THEN
    NULL;
  END;
  BEGIN
    PERFORM pg_temp.t_cve_item(key_a, 'cve_search', 'CVE-2006-0001');
    ASSERT false, 'watchlist_item_cve_shape refuses a cve_search item with a cve_id';
  EXCEPTION WHEN check_violation THEN
    NULL;
  END;
  BEGIN
    PERFORM pg_temp.t_cve_item(key_a, 'dns_lookup');
    ASSERT false, 'watchlist_item_cve_endpoint_name_known refuses a CVE item of a domain endpoint';
  EXCEPTION WHEN check_violation THEN
    ASSERT SQLERRM LIKE '%watchlist_item_cve_endpoint_name_known%', 'the dns_lookup child fails watchlist_item_cve_endpoint_name_known';
  END;
  BEGIN
    PERFORM pg_temp.t_cve_item(key_a, 'cve_search', p_known_ransomware => false);
    ASSERT false, 'watchlist_item_cve_shape refuses known_ransomware false';
  EXCEPTION WHEN check_violation THEN
    NULL;
  END;
  BEGIN
    PERFORM pg_temp.t_cve_item(key_a, 'cve_search', p_min_cvss => 7.5, p_has_nuclei_template => false);
    ASSERT false, 'watchlist_item_cve_shape refuses has_nuclei_template false';
  EXCEPTION WHEN check_violation THEN
    ASSERT SQLERRM LIKE '%watchlist_item_cve_shape%', 'has_nuclei_template false fails watchlist_item_cve_shape';
  END;
  BEGIN
    PERFORM pg_temp.t_cve_item(key_a, 'cve_search');
    ASSERT false, 'watchlist_item_cve_shape refuses a cve_search item with no filter';
  EXCEPTION WHEN check_violation THEN
    ASSERT SQLERRM LIKE '%watchlist_item_cve_shape%', 'the cve_search item with no filter fails watchlist_item_cve_shape';
  END;
  BEGIN
    PERFORM pg_temp.t_cve_item(key_a, 'kev_lookup', 'CVE-2006-0001', p_has_nuclei_template => true);
    ASSERT false, 'watchlist_item_cve_shape refuses a CVE id item with has_nuclei_template';
  EXCEPTION WHEN check_violation THEN
    ASSERT SQLERRM LIKE '%watchlist_item_cve_shape%', 'the kev_lookup item with has_nuclei_template fails watchlist_item_cve_shape';
  END;
  BEGIN
    PERFORM pg_temp.t_cve_item(key_a, 'product_exposure', NULL, 'wlacme', 'wlwidget', p_has_nuclei_template => true);
    ASSERT false, 'watchlist_item_cve_shape refuses a product item with has_nuclei_template';
  EXCEPTION WHEN check_violation THEN
    ASSERT SQLERRM LIKE '%watchlist_item_cve_shape%', 'the product item with has_nuclei_template fails watchlist_item_cve_shape';
  END;
  BEGIN
    PERFORM pg_temp.t_cve_item(key_a, 'dns_takeover_check', 'CVE-2006-0001');
    ASSERT false, 'watchlist_item_endpoint_name_known refuses dns_takeover_check';
  EXCEPTION WHEN check_violation THEN
    ASSERT SQLERRM LIKE '%watchlist_item_endpoint_name_known%', 'the unknown endpoint fails watchlist_item_endpoint_name_known';
  END;
  BEGIN
    PERFORM pg_temp.t_cve_item(key_a, 'cve_triage', NULL, 'wlacme', 'wlwidget');
    ASSERT false, 'watchlist_item_endpoint_name_known refuses cve_triage, whose items product_exposure holds';
  EXCEPTION WHEN check_violation THEN
    ASSERT SQLERRM LIKE '%watchlist_item_endpoint_name_known%', 'cve_triage fails watchlist_item_endpoint_name_known';
  END;
  BEGIN
    PERFORM pg_temp.t_cve_item(key_a, 'cve_lookup', 'CVE-2006-0001', p_version => '1.0');
    ASSERT false, 'watchlist_item_cve_shape refuses a cve_lookup item with a version';
  EXCEPTION WHEN check_violation THEN
    ASSERT SQLERRM LIKE '%watchlist_item_cve_shape%', 'the cve_lookup item with a version fails watchlist_item_cve_shape';
  END;
  BEGIN
    PERFORM pg_temp.t_cve_item(key_a, 'kev_lookup', 'CVE-2006-0001', p_version => '1.0');
    ASSERT false, 'watchlist_item_cve_shape refuses a kev_lookup item with a version';
  EXCEPTION WHEN check_violation THEN
    ASSERT SQLERRM LIKE '%watchlist_item_cve_shape%', 'the kev_lookup item with a version fails watchlist_item_cve_shape';
  END;
  BEGIN
    PERFORM pg_temp.t_cve_item(key_a, 'cve_exploit', 'CVE-2006-0001', p_version => '1.0');
    ASSERT false, 'watchlist_item_cve_shape refuses a cve_exploit item with a version';
  EXCEPTION WHEN check_violation THEN
    ASSERT SQLERRM LIKE '%watchlist_item_cve_shape%', 'the cve_exploit item with a version fails watchlist_item_cve_shape';
  END;
  BEGIN
    PERFORM pg_temp.t_cve_item(key_a, 'cve_search', p_min_cvss => 7.5, p_version => '1.0');
    ASSERT false, 'watchlist_item_cve_shape refuses a cve_search item with a version';
  EXCEPTION WHEN check_violation THEN
    ASSERT SQLERRM LIKE '%watchlist_item_cve_shape%', 'the cve_search item with a version fails watchlist_item_cve_shape';
  END;
  BEGIN
    PERFORM pg_temp.t_cve_item(key_a, 'cve_search', p_version => '1.0');
    ASSERT false, 'watchlist_item_cve_shape refuses a cve_search item whose one value is a version';
  EXCEPTION WHEN check_violation THEN
    ASSERT SQLERRM LIKE '%watchlist_item_cve_shape%', 'a version is no cve_search filter';
  END;
  BEGIN
    PERFORM pg_temp.t_cve_item(key_a, 'product_exposure', NULL, 'wlacme', NULL, p_version => '1.0');
    ASSERT false, 'watchlist_item_cve_shape refuses a product item with a version and no product';
  EXCEPTION WHEN check_violation THEN
    ASSERT SQLERRM LIKE '%watchlist_item_cve_shape%', 'the product item with a version and no product fails watchlist_item_cve_shape';
  END;
  BEGIN
    PERFORM pg_temp.t_cve_item(key_a, 'product_exposure', NULL, 'wlacme', 'wlwidget', p_version => '');
    ASSERT false, 'watchlist_item_cve_version_form refuses an empty version';
  EXCEPTION WHEN check_violation THEN
    ASSERT SQLERRM LIKE '%watchlist_item_cve_version_form%', 'the empty version fails watchlist_item_cve_version_form';
  END;
  BEGIN
    PERFORM pg_temp.t_cve_item(key_a, 'product_exposure', NULL, 'wlacme', 'wlwidget', p_version => '1.0 beta');
    ASSERT false, 'watchlist_item_cve_version_form refuses a version with a space';
  EXCEPTION WHEN check_violation THEN
    ASSERT SQLERRM LIKE '%watchlist_item_cve_version_form%', 'the version with a space fails watchlist_item_cve_version_form';
  END;
  BEGIN
    PERFORM pg_temp.t_cve_item(key_a, 'product_exposure', NULL, 'wlacme', 'wlwidget', p_version => repeat('v', 129));
    ASSERT false, 'watchlist_item_cve_version_form refuses a version of 129 bytes';
  EXCEPTION WHEN check_violation THEN
    ASSERT SQLERRM LIKE '%watchlist_item_cve_version_form%', 'the version of 129 bytes fails watchlist_item_cve_version_form';
  END;
  PERFORM pg_temp.t_cve_item(key_a, 'product_exposure', NULL, 'wlacme', 'wlwidget', p_version => repeat('v', 128));
  PERFORM pg_temp.t_cve_item(key_a, 'product_exposure', NULL, 'wlacme', 'wlwidget', p_version => '!~');
  PERFORM pg_temp.t_cve_item(key_a, 'product_exposure', NULL, 'wlacme', 'wlwidget');
  BEGIN
    PERFORM pg_temp.t_cve_item(key_a, 'product_exposure', NULL, 'wlacme', 'wlwidget', p_version => '!~');
    ASSERT false, 'idx_watchlist_item_cve_key_value refuses a second product item of the same version';
  EXCEPTION WHEN unique_violation THEN
    ASSERT SQLERRM LIKE '%idx_watchlist_item_cve_key_value%', 'the second product item of !~ fails idx_watchlist_item_cve_key_value';
  END;
  BEGIN
    PERFORM pg_temp.t_cve_item(key_a, 'product_exposure', NULL, 'wlacme', 'wlwidget');
    ASSERT false, 'idx_watchlist_item_cve_key_value refuses a second product item of every version';
  EXCEPTION WHEN unique_violation THEN
    ASSERT SQLERRM LIKE '%idx_watchlist_item_cve_key_value%', 'the second product item of every version fails idx_watchlist_item_cve_key_value';
  END;
  PERFORM pg_temp.t_cve_item(key_a, 'cve_search', NULL, 'wlacme', 'wlwidget', 'HIGH', 'CWE-79', 7.5, 0.5, true, true, true);
  PERFORM pg_temp.t_cve_item(key_a, 'cve_search', p_has_nuclei_template => true);
  PERFORM pg_temp.t_cve_item(key_a, 'cve_search', p_known_ransomware => true);
  PERFORM pg_temp.t_cve_item(key_a, 'cve_search', p_known_ransomware => true, p_has_nuclei_template => true);
  BEGIN
    PERFORM pg_temp.t_cve_item(key_a, 'cve_search', p_has_nuclei_template => true);
    ASSERT false, 'idx_watchlist_item_cve_key_value refuses a second item whose other columns are all NULL';
  EXCEPTION WHEN unique_violation THEN
    ASSERT SQLERRM LIKE '%idx_watchlist_item_cve_key_value%', 'the second has_nuclei_template item fails idx_watchlist_item_cve_key_value';
  END;
  BEGIN
    INSERT INTO watchlist_event_cursor (api_key_id, previous_cursor, delivered_cursor) VALUES (key_a, 3, 2);
    ASSERT false, 'watchlist_event_cursor refuses previous_cursor above delivered_cursor';
  EXCEPTION WHEN check_violation THEN
    NULL;
  END;
  INSERT INTO watchlist_event_cursor (api_key_id, previous_cursor, delivered_cursor) VALUES (key_a, 2, 2);
  DELETE FROM watchlist_event_cursor WHERE api_key_id = key_a;
  BEGIN
    UPDATE watchlist_key_state SET max_purged_key_event_id = last_key_event_id + 1 WHERE api_key_id = key_a;
    ASSERT false, 'watchlist_key_state refuses max_purged_key_event_id above last_key_event_id';
  EXCEPTION WHEN check_violation THEN
    ASSERT SQLERRM LIKE '%watchlist_key_state_order%', 'max_purged_key_event_id above last_key_event_id fails watchlist_key_state_order';
  END;
  BEGIN
    UPDATE watchlist_key_state SET max_purged_key_event_id = -1 WHERE api_key_id = key_a;
    ASSERT false, 'watchlist_key_state refuses a negative max_purged_key_event_id';
  EXCEPTION WHEN check_violation THEN
    ASSERT SQLERRM LIKE '%watchlist_key_state_max_purged_key_event_id_range%', 'a negative max_purged_key_event_id fails its CHECK';
  END;
  BEGIN
    UPDATE watchlist_key_state SET last_cve_event_id = -1 WHERE api_key_id = key_a;
    ASSERT false, 'watchlist_key_state refuses a negative last_cve_event_id';
  EXCEPTION WHEN check_violation THEN
    ASSERT SQLERRM LIKE '%watchlist_key_state_last_cve_event_id_range%', 'a negative last_cve_event_id fails its CHECK';
  END;
  UPDATE watchlist_key_state SET max_purged_key_event_id = last_key_event_id, last_cve_event_id = 0 WHERE api_key_id = key_a;
  DELETE FROM watchlist_item WHERE api_key_id = key_a;
  ASSERT NOT EXISTS (SELECT 1 FROM watchlist_item_cve AS wic WHERE wic.api_key_id = key_a), 'the delete of the items deletes their child rows';
END
$$;

CREATE TEMP TABLE t_match_case (label text, endpoint_name text, cve_id text, vendor text, product text, severity text, cwe_id text,
                                min_cvss real, min_epss real, in_kev boolean, known_ransomware boolean, has_nuclei_template boolean,
                                expected text[]);
INSERT INTO t_match_case VALUES
  ('cve_id',                       'cve_lookup',       'CVE-2006-0002', NULL,   NULL,     NULL,   NULL,     NULL, NULL, NULL,  NULL, NULL, '{02:cve_added}'),
  ('severity',                     'cve_search',       NULL,            NULL,   NULL,     'HIGH', NULL,     NULL, NULL, NULL,  NULL, NULL, '{01:cve_added,01:kev_added}'),
  ('cwe_id',                       'cve_search',       NULL,            NULL,   NULL,     NULL,   'CWE-79', NULL, NULL, NULL,  NULL, NULL, '{01:cve_added,01:kev_added}'),
  ('min_cvss equal',               'cve_search',       NULL,            NULL,   NULL,     NULL,   NULL,     7.5,  NULL, NULL,  NULL, NULL, '{01:cve_added,01:kev_added}'),
  ('min_cvss one step below',      'cve_search',       NULL,            NULL,   NULL,     NULL,   NULL,     7.4,  NULL, NULL,  NULL, NULL, '{01:cve_added,02:cve_added,01:kev_added}'),
  ('min_cvss above the v3 score behind no vector', 'cve_search', NULL,  NULL,   NULL,     NULL,   NULL,     9.0,  NULL, NULL,  NULL, NULL, '{}'),
  ('min_cvss at the v4 score',     'cve_search',       NULL,            NULL,   NULL,     NULL,   NULL,     5.0,  NULL, NULL,  NULL, NULL, '{01:cve_added,02:cve_added,04:cve_added,01:kev_added}'),
  ('min_epss equal',               'cve_search',       NULL,            NULL,   NULL,     NULL,   NULL,     NULL, 0.5,  NULL,  NULL, NULL, '{01:cve_added,01:kev_added}'),
  ('min_epss one step below',      'cve_search',       NULL,            NULL,   NULL,     NULL,   NULL,     NULL, 0.49, NULL,  NULL, NULL, '{01:cve_added,02:cve_added,01:kev_added}'),
  ('in_kev true',                  'cve_search',       NULL,            NULL,   NULL,     NULL,   NULL,     NULL, NULL, true,  NULL, NULL, '{01:cve_added,01:kev_added}'),
  ('in_kev false',                 'cve_search',       NULL,            NULL,   NULL,     NULL,   NULL,     NULL, NULL, false, NULL, NULL, '{02:cve_added,03:cve_added,04:cve_added}'),
  ('known_ransomware',             'cve_search',       NULL,            NULL,   NULL,     NULL,   NULL,     NULL, NULL, NULL,  true, NULL, '{01:cve_added,01:kev_added}'),
  ('vendor and product',           'product_exposure', NULL,            'wlacme', 'wlwidget', NULL,   NULL,     NULL, NULL, NULL,  NULL, NULL, '{01:cve_added,01:kev_added}'),
  ('vendor and product of two rows', 'product_exposure', NULL,            'wlacme', 'wlgadget', NULL,   NULL,     NULL, NULL, NULL,  NULL, NULL, '{}'),
  ('product_exposure',             'product_exposure', NULL,            'wlbeta', 'wlgadget', NULL,   NULL,     NULL, NULL, NULL,  NULL, NULL, '{01:cve_added,01:kev_added}'),
  ('vendor alone',                 'cve_search',       NULL,            'wlacme', NULL,     NULL,   NULL,     NULL, NULL, NULL,  NULL, NULL, '{01:cve_added,01:kev_added}'),
  ('product alone',                'cve_search',       NULL,            NULL,   'wlwidget', NULL,   NULL,     NULL, NULL, NULL,  NULL, NULL, '{01:cve_added,02:cve_added,01:kev_added}'),
  ('product alone of one CVE',     'cve_search',       NULL,            NULL,   'wlgadget', NULL,   NULL,     NULL, NULL, NULL,  NULL, NULL, '{01:cve_added,01:kev_added}'),
  ('every filter',                 'cve_search',       NULL,            'wlacme', 'wlwidget', 'HIGH', 'CWE-79', 7.5,  0.5,  true,  true, NULL, '{01:cve_added,01:kev_added}'),
  ('every filter but one',         'cve_search',       NULL,            'wlacme', 'wlwidget', 'HIGH', 'CWE-79', 7.5,  0.5,  false, true, NULL, '{}'),
  ('has_nuclei_template',          'cve_search',       NULL,            NULL,   NULL,     NULL,   NULL,     NULL, NULL, NULL,  NULL, true, '{02:cve_added}'),
  ('has_nuclei_template and known_ransomware', 'cve_search', NULL,      NULL,   NULL,     NULL,   NULL,     NULL, NULL, NULL,  true, true, '{}'),
  ('has_nuclei_template and min_cvss', 'cve_search',   NULL,            NULL,   NULL,     NULL,   NULL,     7.4,  NULL, NULL,  NULL, true, '{02:cve_added}'),
  ('min_cvss of every CVE',        'cve_search',       NULL,            NULL,   NULL,     NULL,   NULL,     0,    NULL, NULL,  NULL, NULL, '{01:cve_added,02:cve_added,03:cve_added,04:cve_added,01:kev_added}');

DO $$
DECLARE
  c record;
BEGIN
  FOR c IN SELECT * FROM t_match_case LOOP
    ASSERT pg_temp.t_edit('A', NULL, NULL, p_is_cleared => true) = 'ok', 'clear before ' || c.label;
    ASSERT pg_temp.t_edit('A', 'add', c.endpoint_name, c.cve_id, c.vendor, c.product, c.severity, c.cwe_id, c.min_cvss, c.min_epss,
                          c.in_kev, c.known_ransomware, c.has_nuclei_template) = 'ok', 'add for ' || c.label;
    UPDATE watchlist_item_cve SET last_event_id_before_add = 0 WHERE api_key_id = pg_temp.t_key_id('A');
    ASSERT pg_temp.t_events_after('A', 0, 100, 100) = 'ok|' || cardinality(c.expected) || '|false|' || c.expected::text, 'matcher, ' || c.label;
  END LOOP;
END
$$;

INSERT INTO cve_change_event (cve_id, event_type, previous_value, current_value, vendor, product) VALUES
  ('CVE-2006-0001', 'exploit_published',      NULL, NULL, NULL,     NULL),
  ('CVE-2006-0002', 'exploit_published',      NULL, NULL, NULL,     NULL),
  ('CVE-2006-0001', 'kev_removed',            NULL, NULL, NULL,     NULL),
  ('CVE-2006-0001', 'ransomware_linked',      NULL, NULL, NULL,     NULL),
  ('CVE-2006-0001', 'epss_level_up',          0.4,  0.5,  NULL,     NULL),
  ('CVE-2006-0001', 'cvss_added',             NULL, 7.5,  NULL,     NULL),
  ('CVE-2006-0001', 'cvss_risk_band_changed', 5.0,  7.5,  NULL,     NULL),
  ('CVE-2006-0001', 'product_added',          NULL, NULL, 'wlacme', 'wlwidget');

CREATE TEMP TABLE t_type_case (label text, endpoint_name text, cve_id text, vendor text, product text, severity text,
                               last_event_id_before_add bigint, expected text[]);
INSERT INTO t_type_case VALUES
  ('kev_lookup watches the KEV types of the fixture', 'kev_lookup', 'CVE-2006-0001', NULL, NULL, NULL, 0,
   '{01:kev_added,01:kev_removed,01:ransomware_linked}'),
  ('cve_exploit watches exploit_published', 'cve_exploit', 'CVE-2006-0001', NULL, NULL, NULL, 0, '{01:exploit_published}'),
  ('cve_lookup watches every type of the fixture', 'cve_lookup', 'CVE-2006-0001', NULL, NULL, NULL, 0,
   '{01:cve_added,01:kev_added,01:exploit_published,01:kev_removed,01:ransomware_linked,01:epss_level_up,01:cvss_added,01:cvss_risk_band_changed,01:product_added}'),
  ('product_exposure watches every type of the fixture', 'product_exposure', NULL, 'wlacme', 'wlwidget', NULL, 0,
   '{01:cve_added,01:kev_added,01:exploit_published,01:kev_removed,01:ransomware_linked,01:epss_level_up,01:cvss_added,01:cvss_risk_band_changed,01:product_added}'),
  ('cve_search watches every type of the fixture', 'cve_search', NULL, NULL, NULL, 'HIGH', 0,
   '{01:cve_added,01:kev_added,01:exploit_published,01:kev_removed,01:ransomware_linked,01:epss_level_up,01:cvss_added,01:cvss_risk_band_changed,01:product_added}'),
  ('an item sees only the events after last_event_id_before_add', 'cve_lookup', 'CVE-2006-0001', NULL, NULL, NULL, 5,
   '{01:exploit_published,01:kev_removed,01:ransomware_linked,01:epss_level_up,01:cvss_added,01:cvss_risk_band_changed,01:product_added}'),
  ('an item sees the event right after last_event_id_before_add', 'cve_lookup', 'CVE-2006-0001', NULL, NULL, NULL, 4,
   '{01:kev_added,01:exploit_published,01:kev_removed,01:ransomware_linked,01:epss_level_up,01:cvss_added,01:cvss_risk_band_changed,01:product_added}'),
  ('an item added after the last event sees nothing', 'cve_lookup', 'CVE-2006-0001', NULL, NULL, NULL, 13, '{}');

DO $$
DECLARE
  c record;
BEGIN
  FOR c IN SELECT * FROM t_type_case LOOP
    ASSERT pg_temp.t_edit('A', NULL, NULL, p_is_cleared => true) = 'ok', 'clear before ' || c.label;
    ASSERT pg_temp.t_edit('A', 'add', c.endpoint_name, c.cve_id, c.vendor, c.product, c.severity) = 'ok', 'add for ' || c.label;
    UPDATE watchlist_item_cve SET last_event_id_before_add = c.last_event_id_before_add WHERE api_key_id = pg_temp.t_key_id('A');
    ASSERT pg_temp.t_events_after('A', 0, 100, 100) = 'ok|' || cardinality(c.expected) || '|false|' || c.expected::text, c.label;
  END LOOP;
  ASSERT (SELECT array_agg(array_to_string(api.fn_watchlist_endpoint_event_types(e.endpoint_name), ',') ORDER BY e.endpoint_index)
            FROM unnest(ARRAY['cve_lookup', 'kev_lookup', 'cve_exploit', 'cve_triage', 'product_exposure', 'cve_search', 'dns_lookup',
                              'dns_takeover_check', 'whois_lookup', 'ssl_check', 'headers_check', 'cert_search', 'package_check', 'ip_lookup'])
                 WITH ORDINALITY AS e (endpoint_name, endpoint_index))
         = ARRAY['cve_added,kev_added,kev_removed,epss_level_up,epss_level_down,cvss_added,cvss_risk_band_changed,exploit_published,product_added,ransomware_linked,product_removed,vendor_advisory_published,patch_published,cve_disputed,cve_rejected,metasploit_added,nuclei_template_added,exploitdb_added,ssvc_added,ssvc_changed,github_poc_added,description_changed,cvss_score_changed,cwe_changed,kev_updated,ghsa_linked',
                 'kev_added,kev_removed,ransomware_linked,kev_updated',
                 'exploit_published,metasploit_added,exploitdb_added,github_poc_added',
                 '',
                 'cve_added,kev_added,kev_removed,epss_level_up,epss_level_down,cvss_added,cvss_risk_band_changed,exploit_published,product_added,ransomware_linked,product_removed,vendor_advisory_published,patch_published,cve_disputed,cve_rejected,metasploit_added,nuclei_template_added,exploitdb_added,ssvc_added,ssvc_changed,github_poc_added,description_changed,cvss_score_changed,cwe_changed,kev_updated,ghsa_linked,eol_approaching,eol_reached,eol_date_changed',
                 'cve_added,kev_added,kev_removed,epss_level_up,epss_level_down,cvss_added,cvss_risk_band_changed,exploit_published,product_added,ransomware_linked,product_removed,vendor_advisory_published,patch_published,cve_disputed,cve_rejected,metasploit_added,nuclei_template_added,exploitdb_added,ssvc_added,ssvc_changed,github_poc_added,description_changed,cvss_score_changed,cwe_changed,kev_updated,ghsa_linked,epss_above_min,epss_below_min',
                 'domain_not_found,domain_found,ns_changed,mx_changed,ip_address_not_public,ip_address_lost,ip_address_restored,cname_takeover_detected,cname_takeover_resolved,email_auth_degraded,hosting_changed',
                 '',
                 'domain_expiring,registrar_changed,transfer_lock_removed,dnssec_disabled',
                 'cert_expiring,cert_invalid,cert_listed,tls_downgraded',
                 'security_header_removed',
                 'cert_unexpected',
                 'advisory_added,fix_available,malware_added,kev_added,ransomware_linked,eol_approaching,eol_reached,eol_date_changed',
                 'drop_listed,drop_unlisted,hosting_changed'],
         'api.fn_watchlist_endpoint_event_types maps each endpoint to its event types, and an unknown endpoint to none';
  ASSERT api.fn_watchlist_endpoint_event_types(NULL) = ARRAY[]::text[],
         'a NULL endpoint watches no event type';
  ASSERT (SELECT array_agg(array_to_string(api.fn_watchlist_endpoint_value_kinds(e.endpoint_name), ',') ORDER BY e.endpoint_index)
            FROM unnest(ARRAY['dns_lookup', 'ssl_check', 'cve_lookup', 'whois_lookup', 'headers_check', 'cert_search']) WITH ORDINALITY AS e (endpoint_name, endpoint_index))
         = ARRAY['dns_presence,ns,mx,ip_address_reachability,cname_takeover,email_auth,hosting',
                 'certificate_expiry,certificate_validity,certificate_listing,tls_protocol',
                 '',
                 'registration_expiry,registrar,transfer_lock,dnssec_delegation',
                 'security_headers',
                 'cert_issuers'],
         'api.fn_watchlist_endpoint_value_kinds maps each domain endpoint to the value kinds of its lane, in scan order, and any other endpoint to none';
  ASSERT api.fn_watchlist_endpoint_value_kinds(NULL) = ARRAY[]::text[], 'a NULL endpoint has no value kind';
END
$$;

DO $$
BEGIN
  ASSERT pg_temp.t_edit('A', NULL, NULL, p_is_cleared => true) = 'ok', 'clear before paging';
  ASSERT pg_temp.t_edit('A', 'add', 'cve_lookup', p_cve_id => 'CVE-2006-0001') = 'ok', 'the paging item';
  UPDATE watchlist_item_cve SET last_event_id_before_add = 0 WHERE api_key_id = pg_temp.t_key_id('A');
  ASSERT pg_temp.t_events_after('A', 0, 3, 100) = 'ok|3|true|{01:cve_added,01:kev_added,01:exploit_published}'
     AND pg_temp.t_key_state('A') = '3,0,6',
         'a full page numbers its events, has more, and moves last_cve_event_id to its last event only';
  ASSERT pg_temp.t_events('A', NULL, false, 100, 100)
         = 'ok|9|false|{01:kev_removed,01:ransomware_linked,01:epss_level_up,01:cvss_added,01:cvss_risk_band_changed,01:product_added}'
     AND pg_temp.t_key_state('A') = '9,0,13',
         'the next normal call continues after the full page with no gap and no repeat';
  ASSERT pg_temp.t_events_after('A', 0, 100, 4) = 'ok|1|true|{01:cve_added}' AND pg_temp.t_key_state('A') = '1,0,4',
         'a full window with few matches ends at the window end and has more';
  ASSERT pg_temp.t_events('A', NULL, false, 100, 4) = 'ok|4|true|{01:kev_added,01:exploit_published,01:kev_removed}'
     AND pg_temp.t_key_state('A') = '4,0,8',
         'the next window starts after the last scanned event';
  ASSERT pg_temp.t_events_after('A', 1, 2, 3) = 'ok|0|true|{}' AND pg_temp.t_key_state('A') = '0,0,4',
         'a full window with no match still moves last_cve_event_id to the window end and has more';
  ASSERT pg_temp.t_events_after('A', 0, 100, 100)
         = 'ok|9|false|{01:cve_added,01:kev_added,01:exploit_published,01:kev_removed,01:ransomware_linked,01:epss_level_up,01:cvss_added,01:cvss_risk_band_changed,01:product_added}'
     AND pg_temp.t_key_state('A') = '9,0,13',
         'a page that reads every event ends at the head and has no more';
  ASSERT pg_temp.t_events_after('A', 0, 1, 1) = 'ok|1|true|{01:cve_added}' AND pg_temp.t_key_state('A') = '1,0,1',
         'a page and a window full at once number the event and have more';
  ASSERT pg_temp.t_events_after('A', 9, 100, 4) = 'ok|4|true|{01:epss_level_up,01:cvss_added,01:cvss_risk_band_changed,01:product_added}',
         'a full window whose events all match has more, though no later event exists';
  ASSERT pg_temp.t_events_after('A', 9, 4, 100) = 'ok|4|false|{01:epss_level_up,01:cvss_added,01:cvss_risk_band_changed,01:product_added}'
     AND pg_temp.t_key_state('A') = '4,0,13',
         'a page that takes exactly the last four events leaves no candidate out, so it is not full and has no more';
  ASSERT pg_temp.t_events_after('A', 9, 3, 100) = 'ok|3|true|{01:epss_level_up,01:cvss_added,01:cvss_risk_band_changed}'
     AND pg_temp.t_key_state('A') = '3,0,12',
         'a page one event short of the candidates is full, and has more';
  ASSERT pg_temp.t_events_after('A', 13, 100, 100) = 'ok|0|false|{}' AND pg_temp.t_key_state('A') = '0,0,13',
         'an empty window numbers nothing and has no more';
  ASSERT pg_temp.t_events_after('A', 12, 100, 1) = 'ok|1|true|{01:product_added}',
         'a window of one event that is the last one is full and has more';
END
$$;

DO $$
DECLARE
  ref_text text;
BEGIN
  PERFORM pg_temp.t_rewind('A', 0);
  ASSERT pg_temp.t_events('A', NULL, false, 3, 100) = 'ok|3|true|{01:cve_added,01:kev_added,01:exploit_published}',
         'a normal call numbers and answers the page after delivered_cursor';
  ASSERT pg_temp.t_event_cursor('A') = '0,3', 'a normal call sets previous_cursor to the old delivered_cursor and delivered_cursor to next_cursor';
  ref_text := (SELECT string_agg(wer::text, ';' ORDER BY wer.item_id, wer.event_id) FROM watchlist_event_ref AS wer);
  ASSERT pg_temp.t_events('A', NULL, true, 100, 100) = 'ok|3|true|{01:cve_added,01:kev_added,01:exploit_published}',
         'repeat answers the last batch again, with has_more while CVE events follow last_cve_event_id';
  ASSERT pg_temp.t_events('A', NULL, true, 2, 100) = 'ok|3|true|{01:cve_added,01:kev_added,01:exploit_published}',
         'repeat answers the whole last batch, which fitted the bounds of its normal call';
  ASSERT pg_temp.t_event_cursor('A') = '0,3' AND pg_temp.t_key_state('A') = '3,0,6', 'repeat moves nothing';
  ASSERT pg_temp.t_events('A', 1, false, 1, 100) = 'ok|2|true|{01:kev_added}',
         'a replay reads the numbered page after its cursor';
  ASSERT pg_temp.t_events('A', 1, false, 100, 100) = 'ok|3|true|{01:kev_added,01:exploit_published}',
         'a replay up to the last number has more while CVE events follow last_cve_event_id';
  ASSERT pg_temp.t_event_cursor('A') = '0,3' AND pg_temp.t_key_state('A') = '3,0,6', 'a replay moves nothing';
  ASSERT pg_temp.t_events('A', 1, true, 1, 100) = 'ok|2|true|{01:kev_added}'
     AND pg_temp.t_event_cursor('A') = '0,3', 'a cursor with repeat is a replay';
  ASSERT (SELECT string_agg(wer::text, ';' ORDER BY wer.item_id, wer.event_id) FROM watchlist_event_ref AS wer) = ref_text,
         'a repeat and a replay write no ref and no number';
  ASSERT pg_temp.t_events('A', NULL, false, 100, 100)
         = 'ok|9|false|{01:kev_removed,01:ransomware_linked,01:epss_level_up,01:cvss_added,01:cvss_risk_band_changed,01:product_added}',
         'the next normal call continues after the last batch';
  ASSERT pg_temp.t_event_cursor('A') = '3,9', 'the next normal call moves both cursors';
  ASSERT pg_temp.t_events('A', NULL, true, 100, 100)
         = 'ok|9|false|{01:kev_removed,01:ransomware_linked,01:epss_level_up,01:cvss_added,01:cvss_risk_band_changed,01:product_added}',
         'repeat at the last number has no more';
  ASSERT pg_temp.t_events('A', NULL, false, 100, 100) = 'ok|9|false|{}', 'a normal call with no new event answers none';
  ASSERT pg_temp.t_event_cursor('A') = '9,9', 'a normal call with no new event moves previous_cursor to the end';
  ASSERT pg_temp.t_events('A', NULL, true, 100, 100) = 'ok|9|false|{}', 'repeat of an empty batch answers none';
  ASSERT pg_temp.t_edit('B', 'remove', 'cve_lookup', p_cve_id => 'CVE-2006-0002') = 'ok'
     AND pg_temp.t_edit('B', NULL, NULL, p_is_cleared => true) = 'ok' AND pg_temp.t_edit('B', NULL, NULL) = 'ok',
         'key B, inserted again in S6, removes, clears and lists';
  ASSERT pg_temp.t_key_state('B') = 'none', 'key B has no key state: only an add writes one';
  ASSERT pg_temp.t_events('B', NULL, false, 100, 100) = 'no_position|null|false|{}', 'a key with no key state answers no_position';
  ASSERT pg_temp.t_events('B', NULL, true, 100, 100) = 'no_position|null|false|{}', 'repeat with no key state answers no_position';
  ASSERT pg_temp.t_events('B', 0, false, 100, 100) = 'ok|0|false|{}', 'a replay at 0 needs no key state and no position';
  ASSERT pg_temp.t_events('B', 1, false, 100, 100) = 'cursor_invalid|null|false|{}', 'a replay above 0 of a key with no key state is invalid';
  ASSERT pg_temp.t_events('unknown', NULL, false, 100, 100) = 'unknown_key|null|false|{}'
     AND pg_temp.t_events('unknown', 0, false, 100, 100) = 'unknown_key|null|false|{}',
         'a hash with no api_keys row answers unknown_key';
  ASSERT pg_temp.t_events('A', 9, false, 100, 100) = 'ok|9|false|{}', 'a replay at last_key_event_id is served';
  ASSERT pg_temp.t_events('A', 10, false, 100, 100) = 'cursor_invalid|null|false|{}', 'a replay above last_key_event_id is invalid';
  ASSERT pg_temp.t_events('A', -1, false, 100, 100) = 'cursor_invalid|null|false|{}', 'a replay below max_purged_key_event_id is invalid';
  ASSERT pg_temp.t_events('A', 0, false, 100, 100) LIKE 'ok|9|false|{01:cve_added,%', 'a replay at max_purged_key_event_id is served';
  ASSERT pg_temp.t_event_cursor('A') = '9,9', 'a replay with an invalid cursor moves nothing';
  ASSERT pg_temp.t_edit('B', 'add', 'cve_lookup', p_cve_id => 'CVE-2006-0002', p_item_max_count => 0) = 'over_limit'
     AND pg_temp.t_key_state('B') = '0,0,13' AND pg_temp.t_event_cursor('B') = 'none',
         'an add that opens no position still writes the key state, with the CVE head as last_cve_event_id';
END
$$;

DO $$
BEGIN
  UPDATE change_event_purge_state SET max_purged_event_id = 5 WHERE event_table_name = 'cve_change_event';
  ASSERT pg_temp.t_events_after('A', 2, 100, 100)
         = 'ok|7|false|{01:exploit_published,01:kev_removed,01:ransomware_linked,01:epss_level_up,01:cvss_added,01:cvss_risk_band_changed,01:product_added}',
         'a last_cve_event_id below max_purged_event_id is raised to it';
  ASSERT pg_temp.t_events_after('A', 6, 100, 100) LIKE 'ok|6|false|{01:kev_removed,%',
         'a last_cve_event_id above max_purged_event_id stays';
  UPDATE change_event_purge_state SET max_purged_event_id = 0 WHERE event_table_name = 'cve_change_event';
END
$$;

INSERT INTO api_keys (key_hash, expires_at) VALUES
  (repeat('10', 32), now() - interval '31 days'),
  (repeat('20', 32), now() - interval '29 days'),
  (repeat('30', 32), NULL),
  (repeat('40', 32), now() - interval '30 days'),
  (repeat('50', 32), now() - interval '40 days'),
  (repeat('60', 32), now() - interval '50 days'),
  (repeat('70', 32), now() - interval '31 days');
SELECT pg_temp.t_cve_item(ak.id, 'cve_lookup', 'CVE-2006-' || lpad(n.item_index::text, 4, '0'))
  FROM api_keys AS ak CROSS JOIN generate_series(1, 3) AS n (item_index)
 WHERE ak.key_hash IN (repeat('10', 32), repeat('20', 32), repeat('30', 32), repeat('40', 32), repeat('50', 32));
INSERT INTO watchlist_event_cursor (api_key_id, previous_cursor, delivered_cursor)
  SELECT ak.id, 0, 0 FROM api_keys AS ak
   WHERE ak.key_hash IN (repeat('10', 32), repeat('20', 32), repeat('30', 32), repeat('40', 32), repeat('60', 32));

CREATE FUNCTION pg_temp.t_purge_rows(p_hash text) RETURNS text LANGUAGE sql AS $$
  SELECT (SELECT count(*) FROM watchlist_item AS wi JOIN api_keys AS ak ON ak.id = wi.api_key_id WHERE ak.key_hash = p_hash)
         || ',' ||
         (SELECT count(*) FROM watchlist_event_cursor AS wec JOIN api_keys AS ak ON ak.id = wec.api_key_id WHERE ak.key_hash = p_hash)
$$;

DO $$
BEGIN
  ASSERT api.fn_watchlist_purge(NULL) IS NULL, 'a NULL limit answers NULL';
  ASSERT (SELECT count(*) FROM watchlist_item) = 16 AND (SELECT count(*) FROM watchlist_event_cursor) = 6,
         'a NULL limit deletes nothing';
  ASSERT api.fn_watchlist_purge(1) = 1, 'a limit of 1 clears one key';
  ASSERT (SELECT count(*) FROM watchlist_item) = 13 AND (SELECT count(*) FROM watchlist_item_cve) = 13
     AND (SELECT count(*) FROM watchlist_event_cursor) = 5,
         'the limit counts keys: the one cleared key loses its three items, their child rows and its position';
  ASSERT pg_temp.t_purge_rows(repeat('10', 32)) = '0,0' OR pg_temp.t_purge_rows(repeat('50', 32)) = '0,0'
      OR pg_temp.t_purge_rows(repeat('60', 32)) = '0,0', 'the cleared key is one of the three expired ones';
  ASSERT api.fn_watchlist_purge(10) = 2, 'the next call clears the other two expired keys';
  ASSERT pg_temp.t_purge_rows(repeat('10', 32)) = '0,0' AND pg_temp.t_purge_rows(repeat('50', 32)) = '0,0'
     AND pg_temp.t_purge_rows(repeat('60', 32)) = '0,0', 'the keys expired 31, 40 and 50 days ago are cleared';
  ASSERT pg_temp.t_purge_rows(repeat('20', 32)) = '3,1', 'the key expired 29 days ago keeps its rows';
  ASSERT pg_temp.t_purge_rows(repeat('30', 32)) = '3,1', 'the key with no expires_at keeps its rows';
  ASSERT pg_temp.t_purge_rows(repeat('40', 32)) = '3,1', 'the key expired exactly 30 days ago keeps its rows';
  ASSERT api.fn_watchlist_purge(10) = 0, 'a call with no key to clear answers 0, though an expired key with no row exists';
  ASSERT pg_temp.t_item_count('A') = 1 AND pg_temp.t_event_cursor('A') = '0,6', 'key A, which never expires, keeps its rows';
  UPDATE api_keys SET active = false WHERE key_hash = repeat('30', 32);
  ASSERT api.fn_watchlist_purge(10) = 0, 'a revoked key with no expires_at keeps its list';
END
$$;

DO $$
DECLARE
  r record;
  saved_time_zone text := current_setting('TimeZone');
BEGIN
  UPDATE cve_change_event SET changed_at = '2024-03-04 05:06:07+00' WHERE event_id = 1;
  PERFORM set_config('TimeZone', 'Asia/Tokyo', true);
  PERFORM pg_temp.t_rewind('A', 0);
  SELECT * INTO r FROM api.fn_watchlist_events(pg_temp.t_hash('A'), NULL, false, 1, 100, 600) AS x;
  PERFORM set_config('TimeZone', saved_time_zone, true);
  ASSERT r.cve_id = 'CVE-2006-0001' AND r.event_type = 'cve_added', 'the first row is event 1';
  ASSERT r.changed_at = '2024-03-04T05:06:07Z', 'changed_at is UTC text, whatever the session time zone';
  ASSERT r.previous_value IS NULL AND r.current_value IS NULL, 'cve_added carries no value';
  ASSERT r.risk_score = api.fn_cve_risk_score(7.5, 0.5, true, true, 7, false)
     AND r.risk_score <> api.fn_cve_risk_score(7.5, 0.5, true, true, 2, false),
         'risk_score comes from api.fn_cve_risk_score with the effective score, EPSS, in_kev, has_metasploit and exploit_ref_count';
  ASSERT r.risk_label = api.fn_cve_risk_label(r.risk_score), 'risk_label comes from api.fn_cve_risk_label';
  ASSERT r.in_kev IS TRUE, 'in_kev is true for a CVE in KEV';
  ASSERT r.kev_patch_deadline = '2024-02-03' AND r.kev_known_ransomware IS TRUE,
         'kev_patch_deadline and kev_known_ransomware come from the kev_details row';
  ASSERT r.has_metasploit AND r.poc_count = 2,
         'has_metasploit and poc_count come from cves, and poc_count leaves the untagged exploit references out';

  PERFORM pg_temp.t_rewind('A', 9);
  SELECT * INTO r FROM api.fn_watchlist_events(pg_temp.t_hash('A'), NULL, false, 1, 100, 600) AS x;
  ASSERT r.event_type = 'epss_level_up' AND r.previous_value = 0.4::real AND r.current_value = 0.5::real,
         'epss_level_up carries its two values';

  ASSERT pg_temp.t_edit('A', NULL, NULL, p_is_cleared => true) = 'ok', 'the clear before the CVE-2006-0002 item answers ok';
  ASSERT pg_temp.t_edit('A', 'add', 'cve_lookup', p_cve_id => 'CVE-2006-0002') = 'ok', 'an add of a CVE-2006-0002 item answers ok';
  UPDATE watchlist_item_cve SET last_event_id_before_add = 0 WHERE api_key_id = pg_temp.t_key_id('A');
  PERFORM pg_temp.t_rewind('A', 0);
  SELECT * INTO r FROM api.fn_watchlist_events(pg_temp.t_hash('A'), NULL, false, 1, 100, 600) AS x;
  ASSERT r.cve_id = 'CVE-2006-0002' AND r.event_type = 'cve_added', 'the first row is event 2';
  ASSERT r.in_kev IS FALSE, 'in_kev is false for a CVE outside KEV';
  ASSERT r.kev_patch_deadline IS NULL, 'kev_patch_deadline is NULL for a CVE with no kev_details row';
  ASSERT r.kev_known_ransomware IS FALSE, 'kev_known_ransomware is false, not NULL, for a CVE with no kev_details row';
  ASSERT NOT r.has_metasploit AND r.poc_count = 0, 'has_metasploit false and poc_count 0 for CVE-2006-0002';
  ASSERT r.risk_score = api.fn_cve_risk_score(7.4, 0.49, false, false, 0, false), 'the risk score of CVE-2006-0002';

  ASSERT pg_temp.t_edit('A', NULL, NULL, p_is_cleared => true) = 'ok', 'the clear before the CVE-2006-0003 item answers ok';
  ASSERT pg_temp.t_edit('A', 'add', 'cve_lookup', p_cve_id => 'CVE-2006-0003') = 'ok', 'an add of a CVE-2006-0003 item answers ok';
  UPDATE watchlist_item_cve SET last_event_id_before_add = 0 WHERE api_key_id = pg_temp.t_key_id('A');
  PERFORM pg_temp.t_rewind('A', 0);
  SELECT * INTO r FROM api.fn_watchlist_events(pg_temp.t_hash('A'), NULL, false, 1, 100, 600) AS x;
  ASSERT r.cve_id = 'CVE-2006-0003' AND r.in_kev IS FALSE AND r.kev_patch_deadline = '2024-02-04' AND r.kev_known_ransomware IS FALSE,
         'a CVE outside KEV with a kev_details row answers in_kev false and the row''s patch deadline and ransomware value';
  PERFORM set_config('contrastapi.cve_events', 'off', true);
  UPDATE kev_details SET known_ransomware_use = true WHERE cve_id = 'CVE-2006-0003';
  PERFORM set_config('contrastapi.cve_events', '', true);
  INSERT INTO cve_change_event (cve_id, event_type) VALUES ('CVE-2006-0003', 'ransomware_linked');
  SELECT * INTO r FROM api.fn_watchlist_events(pg_temp.t_hash('A'), NULL, true, 1, 100, 600) AS x;
  ASSERT r.in_kev IS FALSE AND r.kev_known_ransomware IS TRUE,
         'in_kev reads cves and kev_known_ransomware reads kev_details: a CVE outside KEV with ransomware use answers false and true';
  UPDATE kev_details SET known_ransomware_use = false WHERE cve_id = 'CVE-2006-0003';
  SELECT count(*) AS row_count INTO r FROM api.fn_watchlist_events(pg_temp.t_hash('A'), NULL, false, NULL, 100, 600);
  ASSERT r.row_count = 0, 'a NULL event row count answers no row';
  SELECT count(*) AS row_count INTO r FROM api.fn_watchlist_events(pg_temp.t_hash('A'), NULL, false, 10, NULL, 600);
  ASSERT r.row_count = 0, 'a NULL scan row count answers no row';
  ASSERT (SELECT count(*) FROM api.fn_watchlist_event_scan(pg_temp.t_key_id('A'), 0, 13, NULL, 100, 600)) = 0
     AND (SELECT count(*) FROM api.fn_watchlist_event_scan(pg_temp.t_key_id('A'), 0, 13, 10, NULL, 600)) = 0
     AND (SELECT count(*) FROM api.fn_watchlist_event_scan(pg_temp.t_key_id('A'), 0, 13, 10, 100, 600)) = 1,
         'api.fn_watchlist_event_scan answers no row for a NULL row count, and one row otherwise';
  ASSERT (SELECT count(*) FROM api.fn_watchlist_cve_facts('CVE-1999-0000')) = 0,
         'api.fn_watchlist_cve_facts answers no row for a CVE with no cves row';
  ASSERT (SELECT f.risk_score = api.fn_cve_risk_score(7.5, 0.5, true, true, 7, false) AND f.poc_count = 2
            FROM api.fn_watchlist_cve_facts('CVE-2006-0001') AS f),
         'api.fn_watchlist_cve_facts scores exploit_ref_count, and its poc_count stays the tagged count';
  ASSERT (SELECT f.kev_patch_deadline IS NULL AND f.kev_known_ransomware IS FALSE AND NOT f.in_kev
            FROM api.fn_watchlist_cve_facts('CVE-2006-0002') AS f),
         'api.fn_watchlist_cve_facts answers no patch deadline and no ransomware use for a CVE with no kev_details row';
END
$$;

DO $$
DECLARE
  start_event_id bigint;
BEGIN
  ASSERT pg_temp.t_edit('A', NULL, NULL, p_is_cleared => true) = 'ok', 'the clear before S15 answers ok';
  ASSERT pg_temp.t_edit('A', 'add', 'cve_search', p_min_cvss => 0) = 'ok', 'an add of a cve_search item with min_cvss 0 answers ok';
  start_event_id := api.fn_cve_change_event_max_id();
  INSERT INTO cve_change_event (cve_id, event_type) VALUES
    ('CVE-2006-0001', 'kev_added'), ('CVE-2006-0002', 'kev_added'), ('CVE-2006-0001', 'kev_removed');

  PERFORM pg_temp.t_rewind('A', start_event_id);
  ASSERT (SELECT array_agg(right(x.cve_id, 2) || ':' || x.is_first_event_of_cve::text ORDER BY x.ordinality)
            FROM api.fn_watchlist_events(pg_temp.t_hash('A'), NULL, false, 10, 100, 600) WITH ORDINALITY AS x)
         = ARRAY['01:true', '02:true', '01:false'],
         'the first row of each CVE answers is_first_event_of_cve true, and the later row of CVE-2006-0001 false';
  ASSERT (SELECT array_agg(num_nonnulls(x.risk_score, x.risk_label, x.in_kev, x.kev_patch_deadline, x.kev_known_ransomware,
                                        x.has_metasploit, x.poc_count) ORDER BY x.ordinality)
            FROM api.fn_watchlist_events(pg_temp.t_hash('A'), NULL, true, 10, 100, 600) WITH ORDINALITY AS x)
         = ARRAY[7, 6, 0],
         'a first row answers every fact, kev_patch_deadline NULL without a kev_details row, and a later row answers no fact';
  ASSERT (SELECT x.risk_score = api.fn_cve_risk_score(7.5, 0.5, true, true, 7, false) AND x.in_kev AND x.kev_patch_deadline = '2024-02-03'
                 AND x.kev_known_ransomware AND x.has_metasploit AND x.poc_count = 2
            FROM api.fn_watchlist_events(pg_temp.t_hash('A'), NULL, true, 10, 100, 600) AS x
           WHERE x.cve_id = 'CVE-2006-0001' AND x.is_first_event_of_cve),
         'the first row of CVE-2006-0001 answers the facts of CVE-2006-0001';
  ASSERT (SELECT x.risk_score = api.fn_cve_risk_score(7.4, 0.49, false, false, 0, false) AND NOT x.in_kev AND NOT x.kev_known_ransomware
                 AND NOT x.has_metasploit AND x.poc_count = 0
            FROM api.fn_watchlist_events(pg_temp.t_hash('A'), NULL, true, 10, 100, 600) AS x
           WHERE x.cve_id = 'CVE-2006-0002'),
         'the first row of CVE-2006-0002 answers the facts of CVE-2006-0002';
  PERFORM pg_temp.t_rewind('A', start_event_id + 1);
  ASSERT (SELECT array_agg(right(x.cve_id, 2) || ':' || x.is_first_event_of_cve::text ORDER BY x.ordinality)
            FROM api.fn_watchlist_events(pg_temp.t_hash('A'), NULL, false, 10, 100, 600) WITH ORDINALITY AS x)
         = ARRAY['02:true', '01:true'],
         'a CVE is first in each answer: CVE-2006-0001 is first again in a page that starts after its first event';
  PERFORM pg_temp.t_rewind('A', start_event_id + 3);
  ASSERT (SELECT bool_and(x.event_type IS NULL AND x.is_first_event_of_cve IS NULL) AND count(*) = 1
            FROM api.fn_watchlist_events(pg_temp.t_hash('A'), NULL, false, 10, 100, 600) AS x),
         'a call with no event answers one row with is_first_event_of_cve NULL';
END
$$;

DO $$
DECLARE
  r                   record;
  b_cursor            text;
  a_last_key_event_id bigint := (SELECT wks.last_key_event_id FROM watchlist_key_state AS wks WHERE wks.api_key_id = pg_temp.t_key_id('A'));
BEGIN
  ASSERT pg_temp.t_edit('A', NULL, NULL, p_is_cleared => true) = 'ok', 'S16 clear';
  ASSERT pg_temp.t_edit('A', 'add', 'cve_search', p_min_cvss => 0) = 'ok' AND pg_temp.t_item_count('A') = 1, 'S16 the item with min_cvss 0';
  ASSERT pg_temp.t_edit('A', 'add', 'cve_search', p_min_cvss => 0, p_known_ransomware => true) = 'ok' AND pg_temp.t_item_count('A') = 2,
         'S16 known_ransomware is another item than the item with min_cvss 0 alone';
  ASSERT pg_temp.t_edit('A', 'add', 'cve_search', p_min_cvss => 0, p_severity => 'HIGH') = 'ok' AND pg_temp.t_item_count('A') = 3,
         'S16 severity is another item than the item with min_cvss 0 alone';
  ASSERT pg_temp.t_edit('A', 'add', 'cve_search', p_min_cvss => 0, p_has_nuclei_template => true) = 'ok' AND pg_temp.t_item_count('A') = 4,
         'S16 has_nuclei_template is another item than the item with min_cvss 0 alone';
  ASSERT pg_temp.t_edit('A', 'remove', 'cve_search', p_min_cvss => 0, p_known_ransomware => true) = 'ok'
     AND pg_temp.t_edit('A', 'remove', 'cve_search', p_min_cvss => 0, p_severity => 'HIGH') = 'ok'
     AND pg_temp.t_edit('A', 'remove', 'cve_search', p_min_cvss => 0, p_has_nuclei_template => true) = 'ok'
     AND pg_temp.t_items('A') = '{cve_search:0}', 'S16 the three removes keep the item with min_cvss 0 alone';

  PERFORM set_config('contrastapi.cve_events', 'off', true);
  INSERT INTO cve_products (cve_id, vendor, product, is_vulnerable) VALUES ('CVE-2006-0003', 'wlacme', 'wlfixed', false);
  PERFORM set_config('contrastapi.cve_events', '', true);
  ASSERT pg_temp.t_edit('A', 'add', 'product_exposure', p_vendor => 'wlacme', p_product => 'wlfixed') = 'ok', 'S16 add';
  ASSERT pg_temp.t_items('A') = '{cve_search:0,"product_exposure:wlacme,wlfixed:false"}', 'S16 a pair with no vulnerable row has no CVEs';

  ASSERT pg_temp.t_edit('B', 'add', 'cve_lookup', p_cve_id => 'CVE-2006-0002') = 'ok', 'S16 B adds';
  ASSERT pg_temp.t_edit('A', NULL, NULL, p_is_cleared => true) = 'ok'
     AND pg_temp.t_edit('A', 'add', 'cve_lookup', p_cve_id => 'CVE-2006-0001') = 'ok', 'S16 A holds one item';
  ASSERT pg_temp.t_edit('A', 'remove', 'cve_lookup', p_cve_id => 'CVE-2006-0001') = 'ok', 'S16 A removes it';
  ASSERT pg_temp.t_event_cursor('A') = 'none', 'S16 A loses its position though B still holds an item';
  ASSERT pg_temp.t_event_cursor('B') <> 'none' AND pg_temp.t_item_count('B') = 1, 'S16 B keeps its item and its position';

  ASSERT pg_temp.t_edit('A', 'add', 'cve_lookup', p_cve_id => 'CVE-2006-0001') = 'ok', 'S16 A adds';
  b_cursor := pg_temp.t_event_cursor('B');
  ASSERT pg_temp.t_events('A', NULL, false, 100, 100) = format('ok|%s|false|{}', a_last_key_event_id), 'S16 A reads';
  ASSERT pg_temp.t_event_cursor('A') = format('%s,%s', a_last_key_event_id, a_last_key_event_id) AND pg_temp.t_event_cursor('B') = b_cursor,
         'S16 the read of A leaves B''s position';

  ASSERT pg_temp.t_edit('A', 'add', 'cve_lookup', p_cve_id => 'CVE-2006-0002') = 'ok', 'S16 A adds a second item';
  UPDATE watchlist_item_cve SET last_event_id_before_add = 0 WHERE api_key_id = pg_temp.t_key_id('A') AND cve_id = 'CVE-2006-0001';
  UPDATE watchlist_item_cve SET last_event_id_before_add = 6 WHERE api_key_id = pg_temp.t_key_id('A') AND cve_id = 'CVE-2006-0002';
  ASSERT pg_temp.t_events_after('A', 0, 100, 100)
         = 'ok|13|false|{01:cve_added,01:kev_added,01:exploit_published,02:exploit_published,01:kev_removed,01:ransomware_linked,'
           '01:epss_level_up,01:cvss_added,01:cvss_risk_band_changed,01:product_added,01:kev_added,02:kev_added,01:kev_removed}',
         'S16 the CVE-2006-0002 item misses event 2, before its add, and the CVE-2006-0001 item sees event 1';

  ASSERT pg_temp.t_events_after('A', 15, 100, 3) = 'ok|2|false|{02:kev_added,01:kev_removed}',
         'S16 a window of two events with a scan count of three has no more';

  ASSERT api.fn_cve_risk_score(0.0, 0.0, false, true, 0, false) <> api.fn_cve_risk_score(0.0, 0.0, true, false, 0, false),
         'S16 the risk score weighs in_kev and has_metasploit differently';
  PERFORM set_config('contrastapi.cve_events', 'off', true);
  UPDATE cves SET has_metasploit = true WHERE cve_id = 'CVE-2006-0003';
  PERFORM set_config('contrastapi.cve_events', '', true);
  SELECT * INTO r FROM api.fn_watchlist_cve_facts('CVE-2006-0003') AS f;
  ASSERT r.in_kev IS FALSE AND r.has_metasploit IS TRUE AND r.poc_count = 0, 'S16 in_kev false, has_metasploit true, poc_count 0';
  ASSERT r.risk_score = api.fn_cve_risk_score(0.0, 0.0, false, true, 0, false), 'S16 the risk score takes in_kev and has_metasploit in their places';

  ASSERT pg_temp.t_edit('A', NULL, NULL, p_is_cleared => true) = 'ok' AND pg_temp.t_edit('B', NULL, NULL, p_is_cleared => true) = 'ok',
         'the clear after S16 answers ok';
END
$$;

DO $$
DECLARE
  scan_count_before bigint;
  one_item_scan_count bigint;
  twenty_item_scan_count bigint;
BEGIN
  ASSERT pg_temp.t_edit('A', NULL, NULL, p_is_cleared => true) = 'ok', 'the clear before S17 answers ok';
  ASSERT pg_temp.t_edit('A', 'add', 'cve_search', p_vendor => 'wlnomatch1') = 'ok'
     AND pg_temp.t_edit('A', 'add', 'cve_search', p_min_cvss => 0.1, p_known_ransomware => true) = 'ok', 'S17 adds one item of each kind';
  UPDATE watchlist_item_cve SET last_event_id_before_add = 0 WHERE api_key_id = pg_temp.t_key_id('A');
  SELECT sum(t.seq_scan + coalesce(t.idx_scan, 0)) INTO scan_count_before
    FROM pg_stat_xact_user_tables AS t WHERE t.relid IN ('public.cve_products'::regclass, 'public.kev_details'::regclass);
  PERFORM api.fn_watchlist_event_scan(pg_temp.t_key_id('A'), 0, api.fn_watchlist_event_max_id(), 100, 100, 600);
  SELECT sum(t.seq_scan + coalesce(t.idx_scan, 0)) - scan_count_before INTO one_item_scan_count
    FROM pg_stat_xact_user_tables AS t WHERE t.relid IN ('public.cve_products'::regclass, 'public.kev_details'::regclass);

  FOR i IN 2..20 LOOP
    ASSERT pg_temp.t_edit('A', 'add', 'cve_search', p_vendor => 'wlnomatch' || i) = 'ok'
       AND pg_temp.t_edit('A', 'add', 'cve_search', p_min_cvss => i / 10.0, p_known_ransomware => true) = 'ok', 'S17 adds item ' || i;
  END LOOP;
  UPDATE watchlist_item_cve SET last_event_id_before_add = 0 WHERE api_key_id = pg_temp.t_key_id('A');
  SELECT sum(t.seq_scan + coalesce(t.idx_scan, 0)) INTO scan_count_before
    FROM pg_stat_xact_user_tables AS t WHERE t.relid IN ('public.cve_products'::regclass, 'public.kev_details'::regclass);
  PERFORM api.fn_watchlist_event_scan(pg_temp.t_key_id('A'), 0, api.fn_watchlist_event_max_id(), 100, 100, 600);
  SELECT sum(t.seq_scan + coalesce(t.idx_scan, 0)) - scan_count_before INTO twenty_item_scan_count
    FROM pg_stat_xact_user_tables AS t WHERE t.relid IN ('public.cve_products'::regclass, 'public.kev_details'::regclass);

  ASSERT one_item_scan_count > 0, 'S17 a scan with one item of each kind reads cve_products or kev_details';
  ASSERT twenty_item_scan_count = one_item_scan_count,
         format('S17 a scan with 20 items of each kind reads cve_products and kev_details as often as with one: %s, %s',
                one_item_scan_count, twenty_item_scan_count);
  ASSERT pg_temp.t_edit('A', NULL, NULL, p_is_cleared => true) = 'ok', 'the clear after S17 answers ok';
END
$$;

INSERT INTO cve_change_event (cve_id, event_type, vendor, product) VALUES
  ('CVE-2006-0001', 'product_added',         'wlbeta',  'wlgadget'),
  ('CVE-2006-0003', 'product_removed',       'wlacme',  'wlwidget'),
  ('CVE-2006-0001', 'kev_added',             NULL,      NULL),
  ('CVE-2006-0002', 'product_removed',       'wlother', 'wlwidget'),
  ('CVE-2006-0001', 'metasploit_added',      NULL,      NULL),
  ('CVE-2006-0004', 'cve_rejected',          NULL,      NULL),
  ('CVE-2006-0001', 'nuclei_template_added', NULL,      NULL);

CREATE TEMP TABLE t_pair_case (label text, endpoint_name text, cve_id text, vendor text, product text, expected text[]);
INSERT INTO t_pair_case VALUES
  ('a product item sees a product event of its pair, and not one of another pair of its CVE',
   'product_exposure', NULL, 'wlacme', 'wlwidget', '{03:product_removed:wlacme/wlwidget,01:kev_added,01:metasploit_added,01:nuclei_template_added}'),
  ('a product item sees the product event of its pair and the other events of its CVE',
   'product_exposure', NULL, 'wlbeta', 'wlgadget', '{01:product_added:wlbeta/wlgadget,01:kev_added,01:metasploit_added,01:nuclei_template_added}'),
  ('a vendor alone matches the vendor of the pair',
   'cve_search', NULL, 'wlother', NULL, '{02:product_removed:wlother/wlwidget}'),
  ('a product alone matches the product of the pair',
   'cve_search', NULL, NULL, 'wlwidget', '{03:product_removed:wlacme/wlwidget,01:kev_added,02:product_removed:wlother/wlwidget,01:metasploit_added,01:nuclei_template_added}'),
  ('cve_exploit sees metasploit_added', 'cve_exploit', 'CVE-2006-0001', NULL, NULL, '{01:metasploit_added}'),
  ('cve_lookup sees product_removed', 'cve_lookup', 'CVE-2006-0003', NULL, NULL, '{03:product_removed:wlacme/wlwidget}'),
  ('cve_lookup sees cve_rejected', 'cve_lookup', 'CVE-2006-0004', NULL, NULL, '{04:cve_rejected}'),
  ('cve_lookup sees nuclei_template_added', 'cve_lookup', 'CVE-2006-0001', NULL, NULL,
   '{01:product_added:wlbeta/wlgadget,01:kev_added,01:metasploit_added,01:nuclei_template_added}'),
  ('kev_lookup sees no newer event type', 'kev_lookup', 'CVE-2006-0001', NULL, NULL, '{01:kev_added}');

DO $$
DECLARE
  c record;
BEGIN
  FOR c IN SELECT * FROM t_pair_case LOOP
    ASSERT pg_temp.t_edit('A', NULL, NULL, p_is_cleared => true) = 'ok', 'S18 clear before ' || c.label;
    ASSERT pg_temp.t_edit('A', 'add', c.endpoint_name, c.cve_id, c.vendor, c.product) = 'ok', 'S18 add for ' || c.label;
    UPDATE watchlist_item_cve SET last_event_id_before_add = 17 WHERE api_key_id = pg_temp.t_key_id('A');
    PERFORM pg_temp.t_rewind('A', 17);
    ASSERT (SELECT coalesce(array_agg(right(x.cve_id, 2) || ':' || x.event_type || coalesce(':' || x.vendor || '/' || x.product, '')
                                      ORDER BY x.ordinality) FILTER (WHERE x.event_type IS NOT NULL), '{}')
              FROM api.fn_watchlist_events(pg_temp.t_hash('A'), NULL, false, 100, 100, 600) WITH ORDINALITY AS x)
           = c.expected, 'S18 ' || c.label;
  END LOOP;
  ASSERT pg_temp.t_edit('A', NULL, NULL, p_is_cleared => true) = 'ok', 'S18 clear before the column check';
  ASSERT pg_temp.t_edit('A', 'add', 'cve_search', p_min_cvss => 0) = 'ok', 'S18 add an item that sees every event';
  UPDATE watchlist_item_cve SET last_event_id_before_add = 0 WHERE api_key_id = pg_temp.t_key_id('A');
  PERFORM pg_temp.t_rewind('A', 0);
  ASSERT (SELECT count(*) FILTER (WHERE x.event_type IN ('product_added', 'product_removed')) > 0
                 AND count(*) FILTER (WHERE x.event_type NOT IN ('product_added', 'product_removed')) > 0
                 AND bool_and((x.vendor IS NULL) = (x.event_type NOT IN ('product_added', 'product_removed'))
                              AND (x.product IS NULL) = (x.vendor IS NULL))
            FROM api.fn_watchlist_events(pg_temp.t_hash('A'), NULL, false, 100, 100, 600) AS x
           WHERE x.event_type IS NOT NULL),
         'S18 an event row answers vendor and product for a product event, and NULL for any other';
  ASSERT pg_temp.t_edit('A', NULL, NULL, p_is_cleared => true) = 'ok', 'the clear after S18 answers ok';
END
$$;

CREATE FUNCTION pg_temp.t_cve_event_of(p_cve_id text, p_event_type text DEFAULT 'kev_added', p_previous_value real DEFAULT NULL,
                                       p_current_value real DEFAULT NULL, p_vendor text DEFAULT NULL, p_product text DEFAULT NULL)
  RETURNS bigint LANGUAGE sql AS $$
  INSERT INTO cve_change_event (cve_id, event_type, previous_value, current_value, vendor, product)
  VALUES (p_cve_id, p_event_type, p_previous_value, p_current_value, p_vendor, p_product) RETURNING event_id
$$;
CREATE FUNCTION pg_temp.t_domain_event(p_domain_name text, p_event_type text, p_heard_by text,
                                       p_previous_value text DEFAULT NULL, p_current_value text DEFAULT NULL,
                                       p_degraded_email_check_id text DEFAULT NULL)
  RETURNS bigint LANGUAGE sql AS $$
  WITH written AS (
    INSERT INTO domain_change_event (domain_name, event_type, degraded_email_check_id, previous_value, current_value)
    VALUES (p_domain_name, p_event_type, p_degraded_email_check_id, p_previous_value, p_current_value)
    RETURNING domain_change_event.event_id),
  heard AS (
    INSERT INTO watchlist_event_ref (api_key_id, item_id, event_id)
    SELECT wid.api_key_id, wid.item_id, w.event_id
      FROM written AS w
      CROSS JOIN watchlist_item_domain AS wid
     WHERE wid.domain_name = p_domain_name
       AND p_event_type = ANY (api.fn_watchlist_endpoint_event_types(wid.endpoint_name))
       AND wid.api_key_id IN (SELECT pg_temp.t_key_id(l.label) FROM unnest(string_to_array(p_heard_by, ',')) AS l (label)))
  SELECT w.event_id FROM written AS w
$$;
CREATE FUNCTION pg_temp.t_ref(p_label text, p_domain_name text, p_event_id bigint) RETURNS void LANGUAGE sql AS $$
  INSERT INTO watchlist_event_ref (api_key_id, item_id, event_id)
  SELECT wid.api_key_id, wid.item_id, p_event_id FROM watchlist_item_domain AS wid
   WHERE wid.domain_name = p_domain_name AND wid.api_key_id = pg_temp.t_key_id(p_label)
$$;

CREATE TEMP VIEW t_item_column AS
  SELECT wi.item_id, wi.api_key_id, wi.endpoint_name, wic.last_event_id_before_add, wic.cve_id, wic.vendor, wic.product, wic.severity,
         wic.cwe_id, wic.min_cvss, wic.min_epss, wic.in_kev, wic.known_ransomware, wid.domain_name, wid.registered_domain, wid.next_scan_at
    FROM watchlist_item AS wi
    LEFT JOIN watchlist_item_cve AS wic ON wic.item_id = wi.item_id
    LEFT JOIN watchlist_item_domain AS wid ON wid.item_id = wi.item_id;

DO $$
DECLARE
  name_index  integer;
  before_add  timestamptz;
BEGIN
  ASSERT pg_temp.t_edit('A', NULL, NULL, p_is_cleared => true) = 'ok' AND pg_temp.t_edit('B', NULL, NULL, p_is_cleared => true) = 'ok',
         'S19 the clear before the domain items answers ok';
  before_add := clock_timestamp();
  ASSERT pg_temp.t_edit('A', 'add', 'dns_lookup', p_domain_name => 'a.wl.example') = 'ok', 'S19 a dns_lookup add answers ok';
  ASSERT (SELECT dw::text FROM domain_watch AS dw WHERE dw.domain_name = 'a.wl.example') = '(a.wl.example,wl.example)',
         'S19 the add of a new name writes its domain_watch row with the registered domain of the call';
  ASSERT (SELECT array_agg(dwl::text) FROM domain_watch_lane AS dwl WHERE dwl.domain_name = 'a.wl.example') = '{"(a.wl.example,dns,,,,)"}',
         'S19 the dns_lookup add of a new name writes its dns lane row with no lease, scan or refusal, and no row of another lane';
  ASSERT (SELECT ic.registered_domain = 'wl.example' AND ic.next_scan_at > before_add AND ic.next_scan_at < clock_timestamp()
            FROM t_item_column AS ic WHERE ic.api_key_id = pg_temp.t_key_id('A')),
         'S19 the item holds the registered domain of the call and is due at the clock of the add';
  ASSERT pg_temp.t_items('A') = '{dns_lookup:a.wl.example}', 'S19 the answer carries the domain_name of the item and no product_has_cves';
  ASSERT pg_temp.t_event_cursor('A') = (SELECT wks.last_key_event_id || ',' || wks.last_key_event_id
                                           FROM watchlist_key_state AS wks WHERE wks.api_key_id = pg_temp.t_key_id('A')),
         'S19 the first domain item opens the position at last_key_event_id';

  UPDATE watchlist_item_domain AS wid SET next_scan_at = now() + interval '1 day' WHERE wid.domain_name = 'a.wl.example';
  ASSERT pg_temp.t_edit('A', 'add', 'dns_lookup', p_domain_name => 'a.wl.example') = 'ok' AND pg_temp.t_item_count('A') = 1,
         'S19 a repeated domain add inserts nothing';
  ASSERT (SELECT ic.next_scan_at = now() + interval '1 day' FROM t_item_column AS ic WHERE ic.domain_name = 'a.wl.example'),
         'S19 a repeated domain add keeps the next scan';
  ASSERT pg_temp.t_edit('B', 'add', 'dns_lookup', p_domain_name => 'a.wl.example', p_registered_domain => 'other.example') = 'ok',
         'S19 key B adds the same name';
  ASSERT (SELECT dw.registered_domain FROM domain_watch AS dw WHERE dw.domain_name = 'a.wl.example') = 'wl.example'
     AND (SELECT ic.registered_domain FROM t_item_column AS ic WHERE ic.api_key_id = pg_temp.t_key_id('B')) = 'other.example',
         'S19 an add of a name domain_watch holds keeps its registered domain there, and the new item holds the registered domain of its call';
  ASSERT (SELECT ic.next_scan_at = now() + interval '1 day' FROM t_item_column AS ic WHERE ic.api_key_id = pg_temp.t_key_id('A')),
         'S19 the add of key B moves no time of key A''s item';
  ASSERT (SELECT count(*) FROM domain_watch AS dw WHERE dw.domain_name = 'a.wl.example') = 1, 'S19 a domain has one domain_watch row';
  ASSERT regexp_replace(pg_get_functiondef('api.fn_watchlist_item_edit(text, text, text, text, text, text, text, text, real, real, boolean, boolean, boolean, integer, text, text, integer, text, text, text, integer, integer, integer, integer, inet)'::regprocedure), '--[^\n]*', '', 'g')
         ~ 'ON CONFLICT ON CONSTRAINT domain_watch_pkey DO UPDATE SET domain_name = EXCLUDED\.domain_name;',
         'S19 the add locks a domain_watch row it finds, so the unwatched purge passes over it';

  FOR name_index IN 2..19 LOOP
    ASSERT pg_temp.t_edit('A', 'add', 'dns_lookup', p_domain_name => chr(96 + name_index) || '.wl.example') = 'ok',
           'S19 the add of name ' || name_index || ' answers ok';
  END LOOP;
  ASSERT pg_temp.t_item_count('A') = 19, 'S19 key A holds 19 items of 19 names';
  ASSERT pg_temp.t_edit('B', 'add', 'dns_lookup', p_domain_name => 'b1.wl.example') = 'ok'
     AND pg_temp.t_edit('B', 'add', 'dns_lookup', p_domain_name => 'b2.wl.example') = 'ok', 'S19 key B adds two more names';
  ASSERT pg_temp.t_edit('A', 'add', 'dns_lookup', p_domain_name => 'a.wo.example') = 'ok', 'S19 key A adds a name under wo.example';
  ASSERT pg_temp.t_edit('A', 'add', 'dns_lookup', p_domain_name => 't.wl.example') = 'ok',
         'S19 the 20th name answers ok: the names of key B and a name under another registered domain count for nothing';
  ASSERT pg_temp.t_item_count('A') = 21, 'S19 the 20th name is in the list';
  ASSERT pg_temp.t_edit('A', 'add', 'dns_lookup', p_domain_name => 'u.wl.example') = 'over_domain_limit',
         'S19 the 21st name answers over_domain_limit';
  ASSERT (SELECT array_agg(x.edit_status || '|' || coalesce(x.endpoint_name, '-') || '|' || x.item_count || '|' || x.package_item_count)
            FROM pg_temp.t_watchlist_edit(pg_temp.t_hash('A'), 'add', 'dns_lookup', NULL, NULL, NULL, NULL, NULL,
                                          NULL, NULL, NULL, NULL, NULL, false, 100, 'u.wl.example', 'wl.example', 20, NULL, NULL, NULL, 500, 100, 100000, 20) AS x)
         = ARRAY['over_domain_limit|-|21|0'],
         'S19 over_domain_limit answers one row with that status, the counts and no item';
  ASSERT pg_temp.t_item_count('A') = 21 AND NOT EXISTS (SELECT 1 FROM domain_watch AS dw WHERE dw.domain_name = 'u.wl.example'),
         'S19 over_domain_limit inserts no item and no domain_watch row';
  ASSERT pg_temp.t_edit('A', 'add', 'dns_lookup', p_domain_name => 'u.wl.example', p_item_max_count => 21) = 'over_limit',
         'S19 over_limit comes before over_domain_limit';
  ASSERT pg_temp.t_edit('A', 'add', 'dns_lookup', p_domain_name => 'u.wl.example', p_domain_name_max_count => 21) = 'ok'
     AND pg_temp.t_item_count('A') = 22, 'S19 the cap is p_domain_name_max_count';
  ASSERT pg_temp.t_edit('B', 'add', 'dns_lookup', p_domain_name => 'b3.wl.example', p_domain_name_max_count => 3) = 'ok'
     AND pg_temp.t_edit('B', 'add', 'dns_lookup', p_domain_name => 'b4.wl.example', p_domain_name_max_count => 3) = 'over_domain_limit',
         'S19 key B counts its own three names under wl.example, b1, b2 and b3: its a.wl.example sits under other.example';

  ASSERT pg_temp.t_edit('A', 'remove', 'dns_lookup', p_domain_name => 'c.wl.example') = 'ok' AND pg_temp.t_item_count('A') = 21,
         'S19 remove deletes the domain item of that name';
  ASSERT NOT EXISTS (SELECT 1 FROM t_item_column AS ic WHERE ic.domain_name = 'c.wl.example')
     AND EXISTS (SELECT 1 FROM t_item_column AS ic WHERE ic.api_key_id = pg_temp.t_key_id('A') AND ic.domain_name = 'd.wl.example'),
         'S19 remove keeps the items of the other names';
  ASSERT EXISTS (SELECT 1 FROM domain_watch AS dw WHERE dw.domain_name = 'c.wl.example'),
         'S19 remove leaves the domain_watch row to api.fn_domain_watch_purge_unwatched';
  ASSERT pg_temp.t_edit('A', 'remove', 'dns_lookup', p_domain_name => 'c.wl.example') = 'ok' AND pg_temp.t_item_count('A') = 21,
         'S19 removing a domain item the list does not hold deletes nothing';
  ASSERT pg_temp.t_edit('A', 'remove', 'ssl_check', p_domain_name => 'd.wl.example') = 'ok' AND pg_temp.t_item_count('A') = 21,
         'S19 removing the ssl_check item of a name the key watches through dns_lookup deletes nothing';

  BEGIN
    PERFORM pg_temp.t_watchlist_edit(pg_temp.t_hash('A'), 'add', 'dns_lookup', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
                                     false, 100, 'v.wl.example', NULL, 20, NULL, NULL, NULL, 500, 100, 100000, 20);
    ASSERT false, 'S19 a dns_lookup item without a registered domain raises';
  EXCEPTION WHEN invalid_parameter_value THEN
    NULL;
  END;
  BEGIN
    PERFORM pg_temp.t_watchlist_edit(pg_temp.t_hash('A'), 'remove', 'dns_lookup', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
                                     false, 100, 'a.wl.example', NULL, 20, NULL, NULL, NULL, 500, 100, 100000, 20);
    ASSERT false, 'S19 a dns_lookup remove without a registered domain raises';
  EXCEPTION WHEN invalid_parameter_value THEN
    NULL;
  END;
  ASSERT pg_temp.t_item_count('A') = 21 AND NOT EXISTS (SELECT 1 FROM domain_watch AS dw WHERE dw.domain_name = 'v.wl.example'),
         'S19 the calls that raise change nothing';
  ASSERT (SELECT string_agg(DISTINCT x.edit_status, ',')
            FROM pg_temp.t_watchlist_edit(pg_temp.t_hash('A'), 'add', 'cve_lookup', 'CVE-2006-0001', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
                                          false, 100, NULL, NULL, 20, NULL, NULL, NULL, 500, 100, 100000, 20) AS x) = 'ok',
         'S19 an item of another endpoint takes no registered domain';
  ASSERT pg_temp.t_edit('A', NULL, NULL, p_is_cleared => true) = 'ok' AND pg_temp.t_edit('B', NULL, NULL, p_is_cleared => true) = 'ok',
         'S19 the clear after the domain items answers ok';
END
$$;

DO $$
DECLARE
  cve_max_id       bigint := api.fn_cve_change_event_max_id();
  domain_event_id  bigint;
  package_event_id bigint;
  a_cursor         text;
BEGIN
  ASSERT cve_max_id = 24 AND NOT EXISTS (SELECT 1 FROM domain_change_event) AND NOT EXISTS (SELECT 1 FROM package_advisory_change_event),
         'S20 starts with 24 CVE events, no domain event and no package event';
  ASSERT api.fn_watchlist_event_max_id() = 24, 'S20 with no domain event, the head is the CVE head';
  ASSERT pg_temp.t_edit('A', 'add', 'dns_lookup', p_domain_name => 'h.wl.example') = 'ok', 'S20 key A adds a domain item';
  a_cursor := pg_temp.t_event_cursor('A');
  INSERT INTO domain_change_event (domain_name, event_type) VALUES ('h.wl.example', 'ns_changed')
  RETURNING event_id INTO domain_event_id;
  ASSERT domain_event_id = 25 AND api.fn_watchlist_event_max_id() = 25, 'S20 a domain event above every CVE event raises the head';
  ASSERT pg_temp.t_edit('A', 'add', 'dns_lookup', p_domain_name => 'i.wl.example') = 'ok', 'S20 key A adds a second domain item';
  ASSERT NOT EXISTS (SELECT 1 FROM watchlist_event_ref AS wer WHERE wer.event_id = 25)
     AND pg_temp.t_event_cursor('A') = a_cursor,
         'S20 an add gives no item a ref to an earlier event, and keeps the position the first add opened';
  INSERT INTO package_advisory_change_event (advisory_id, ecosystem, package_name_normalized, package_name, event_type)
  VALUES ('GHSA-wl20-0020-0020', 'npm', 'left-pad', 'left-pad', 'advisory_added')
  RETURNING event_id INTO package_event_id;
  ASSERT package_event_id = 26 AND api.fn_watchlist_event_max_id() = 26, 'S20 a package event above every other event raises the head';
  PERFORM pg_temp.t_cve_event_of('CVE-2006-0001');
  ASSERT api.fn_watchlist_event_max_id() = 27, 'S20 a CVE event above the domain and package events is the head';
  UPDATE change_event_purge_state SET max_purged_event_id = 40 WHERE event_table_name = 'domain_change_event';
  ASSERT api.fn_watchlist_event_max_id() = 40, 'S20 a domain purge above every event raises the head to it';
  UPDATE change_event_purge_state SET max_purged_event_id = 50 WHERE event_table_name = 'cve_change_event';
  ASSERT api.fn_watchlist_event_max_id() = 50, 'S20 a CVE purge above every event raises the head to it';
  UPDATE change_event_purge_state SET max_purged_event_id = 60 WHERE event_table_name = 'package_advisory_change_event';
  ASSERT api.fn_watchlist_event_max_id() = 60, 'S20 a package purge above every event raises the head to it';
  UPDATE change_event_purge_state SET max_purged_event_id = 0 WHERE event_table_name = 'cve_change_event';
  UPDATE change_event_purge_state SET max_purged_event_id = 0 WHERE event_table_name = 'domain_change_event';
  UPDATE change_event_purge_state SET max_purged_event_id = 0 WHERE event_table_name = 'package_advisory_change_event';
  DELETE FROM domain_change_event;
  DELETE FROM package_advisory_change_event;
  ASSERT api.fn_watchlist_event_max_id() = 27, 'S20 with no purge and no domain or package event, the head is the CVE event';
  ASSERT pg_temp.t_edit('A', NULL, NULL, p_is_cleared => true) = 'ok', 'S20 the clear after the head answers ok';
END
$$;

CREATE TEMP TABLE t_mixed (base bigint);
CREATE TEMP TABLE t_mixed_item (label text, item_id bigint);
DO $$
DECLARE
  base  bigint := api.fn_watchlist_event_max_id();
  key_a integer := pg_temp.t_key_id('A');
BEGIN
  INSERT INTO t_mixed VALUES (base);
  ASSERT pg_temp.t_edit('A', NULL, NULL, p_is_cleared => true) = 'ok' AND pg_temp.t_edit('B', NULL, NULL, p_is_cleared => true) = 'ok',
         'S21 the clear before the mixed events answers ok';
  ASSERT pg_temp.t_edit('A', 'add', 'cve_lookup', p_cve_id => 'CVE-2006-0001') = 'ok'
     AND pg_temp.t_edit('A', 'add', 'dns_lookup', p_domain_name => 'd4.wl.example') = 'ok'
     AND pg_temp.t_edit('A', 'add', 'cve_search', p_min_cvss => 7.4, p_min_epss => 0.4) = 'ok'
     AND pg_temp.t_edit('A', 'add', 'dns_lookup', p_domain_name => 'd1.wl.example') = 'ok'
     AND pg_temp.t_edit('A', 'add', 'dns_lookup', p_domain_name => 'd2.wo.example') = 'ok'
     AND pg_temp.t_edit('A', 'add', 'product_exposure', p_vendor => 'wlacme', p_product => 'wlwidget') = 'ok'
     AND pg_temp.t_edit('A', 'add', 'cve_search', p_vendor => 'wlacme', p_product => 'wlwidget', p_severity => 'HIGH', p_cwe_id => 'CWE-79',
                        p_min_cvss => 7.5, p_min_epss => 0.5, p_in_kev => true, p_known_ransomware => true) = 'ok',
         'S21 key A adds its seven items';
  ASSERT pg_temp.t_edit('B', 'add', 'dns_lookup', p_domain_name => 'd1.wl.example') = 'ok'
     AND pg_temp.t_edit('B', 'add', 'dns_lookup', p_domain_name => 'd3.wl.example') = 'ok', 'S21 key B adds its two items';
  INSERT INTO t_mixed_item SELECT 'I' || row_number() OVER (ORDER BY wi.item_id), wi.item_id FROM watchlist_item AS wi WHERE wi.api_key_id = key_a;
  ASSERT (SELECT bool_and(wi.last_event_id_before_add = base) FROM watchlist_item_cve AS wi WHERE wi.api_key_id IN (key_a, pg_temp.t_key_id('B'))),
         'S21 every CVE item is added at base';

  ASSERT pg_temp.t_cve_event_of('CVE-2006-0001') = base + 1, 'S21 e1';
  ASSERT pg_temp.t_domain_event('d1.wl.example', 'ns_changed', 'A,B', 'p2', 'c2') = base + 2, 'S21 e2';
  ASSERT pg_temp.t_cve_event_of('CVE-2006-0002', 'epss_level_up', 0.25, 0.5) = base + 3, 'S21 e3';
  ASSERT pg_temp.t_domain_event('d1.wl.example', 'cname_takeover_detected', 'A,B', 'p4', 'c4') = base + 4, 'S21 e4';
  ASSERT pg_temp.t_domain_event('d2.wo.example', 'mx_changed', '', 'p5', 'c5') = base + 5, 'S21 e5';
  ASSERT pg_temp.t_domain_event('d2.wo.example', 'mx_changed', '', 'p6', 'c6') = base + 6, 'S21 e6';
  ASSERT pg_temp.t_domain_event('d2.wo.example', 'email_auth_degraded', 'A', 'p7', 'c7', 'spf_all') = base + 7, 'S21 e7';
  ASSERT pg_temp.t_cve_event_of('CVE-2006-0001', 'product_removed', NULL, NULL, 'wlacme', 'wlwidget') = base + 8, 'S21 e8';
  ASSERT pg_temp.t_domain_event('d3.wl.example', 'ns_changed', 'B', 'p9', 'c9') = base + 9, 'S21 e9';
  UPDATE watchlist_item_cve SET last_event_id_before_add = base + 1 WHERE item_id = (SELECT m.item_id FROM t_mixed_item AS m WHERE m.label = 'I1');

  INSERT INTO watchlist_item_domain_value (item_id, value_kind, current_value, current_value_sha256)
  SELECT wid.item_id, v.value_kind, v.current_value, repeat(v.digit, 64)
    FROM watchlist_item_domain AS wid
    JOIN (VALUES ('A', 'd1.wl.example', 'dns_presence',            'd1-presence', '1'),
                 ('A', 'd1.wl.example', 'ns',                      'd1-ns',       '2'),
                 ('A', 'd1.wl.example', 'mx',                      'd1-mx',       '3'),
                 ('A', 'd1.wl.example', 'ip_address_reachability', 'd1-address',  '4'),
                 ('A', 'd1.wl.example', 'cname_takeover',          'd1-cname',    '5'),
                 ('A', 'd2.wo.example', 'email_auth',              'd2-email',    '6'),
                 ('B', 'd1.wl.example', 'dns_presence',            'b-presence',  '7'),
                 ('B', 'd1.wl.example', 'ns',                      'b-ns',        '8'),
                 ('B', 'd1.wl.example', 'mx',                      'b-mx',        '9')) AS v (label, domain_name, value_kind, current_value, digit)
      ON wid.domain_name = v.domain_name AND wid.api_key_id = pg_temp.t_key_id(v.label);
  UPDATE watchlist_item_domain_value SET candidate_value = 'd1-ns-candidate', candidate_value_sha256 = repeat('7', 64), candidate_seen_at = now()
   WHERE value_kind = 'ns' AND current_value = 'd1-ns';
END
$$;

SELECT pg_temp.t_rewind('A', t.base) FROM t_mixed AS t;
CREATE TEMP TABLE t_mixed_answer AS
  SELECT m.label, x.*
    FROM api.fn_watchlist_events(pg_temp.t_hash('A'), NULL, false, 100, 100, 600) WITH ORDINALITY AS x
    LEFT JOIN t_mixed_item AS m ON m.item_id = x.item_id;

DO $$
DECLARE
  base       bigint := (SELECT t.base FROM t_mixed AS t);
  key_a      integer := pg_temp.t_key_id('A');
  key_b      integer := pg_temp.t_key_id('B');
  answer_row record;
BEGIN
  ASSERT (SELECT array_agg(a.label || '|' || a.event_rank || '|' || a.is_first_row_of_event || '|' || coalesce(a.is_first_event_of_cve::text, 'null')
                           || '|' || coalesce(a.is_first_event_of_domain::text, 'null') ORDER BY a.ordinality)
            FROM t_mixed_answer AS a)
         = ARRAY['I1|6|true|true|false', 'I3|1|true|false|false', 'I3|3|true|true|false', 'I3|6|false|false|false',
                 'I4|2|true|false|true', 'I4|4|true|false|false', 'I5|5|true|false|true', 'I6|1|false|false|false', 'I6|6|false|false|false',
                 'I7|1|false|false|false', 'I7|6|false|false|false'],
         'S21 one row per item and event, item by item, each event in number order, with the rank of its event and its first-row flags; an item with no event has no row';
  ASSERT (SELECT array_agg(DISTINCT wer.event_id - base || ':' || wer.key_event_id) FROM watchlist_event_ref AS wer WHERE wer.api_key_id = key_a)
         = ARRAY['1:1', '2:2', '3:3', '4:4', '7:5', '8:6'],
         'S21 the numbers of key A follow event_id over both tables, and each event has one number for all its items';
  ASSERT (SELECT bool_and(a.event_rank IS NOT NULL AND a.is_first_row_of_event IS NOT NULL
                          AND a.is_first_event_of_cve IS NOT NULL AND a.is_first_event_of_domain IS NOT NULL)
            FROM t_mixed_answer AS a),
         'S21 no row has a NULL rank or first-row flag, since db.c refuses such a row';
  ASSERT (SELECT bool_and(a.events_status = 'ok' AND a.next_cursor = 6 AND NOT a.has_more) FROM t_mixed_answer AS a),
         'S21 every row carries the status, next_cursor and has_more';
  ASSERT (SELECT bool_and(a.item_endpoint_name = wi.endpoint_name
                          AND a.item_cve_id IS NOT DISTINCT FROM wi.cve_id AND a.item_vendor IS NOT DISTINCT FROM wi.vendor
                          AND a.item_product IS NOT DISTINCT FROM wi.product AND a.item_severity IS NOT DISTINCT FROM wi.severity
                          AND a.item_cwe_id IS NOT DISTINCT FROM wi.cwe_id AND a.item_min_cvss IS NOT DISTINCT FROM wi.min_cvss
                          AND a.item_min_epss IS NOT DISTINCT FROM wi.min_epss AND a.item_in_kev IS NOT DISTINCT FROM wi.in_kev
                          AND a.item_known_ransomware IS NOT DISTINCT FROM wi.known_ransomware
                          AND a.item_domain_name IS NOT DISTINCT FROM wi.domain_name)
            FROM t_mixed_answer AS a JOIN t_item_column AS wi ON wi.item_id = a.item_id),
         'S21 every row carries the columns of its item';
  ASSERT (SELECT array_agg(DISTINCT a.label || ':' || coalesce(a.item_product_has_cves::text, 'null')) FROM t_mixed_answer AS a)
         = ARRAY['I1:null', 'I3:null', 'I4:null', 'I5:null', 'I6:true', 'I7:null'],
         'S21 item_product_has_cves is set for the product_exposure item only';
  ASSERT (SELECT array_agg(format('%s|%s|%s|%s|%s|%s|%s|%s|%s', a.event_type, a.cve_id, a.previous_value, a.current_value, a.vendor, a.product,
                                  a.degraded_email_check_id, a.previous_domain_value, a.current_domain_value) ORDER BY a.ordinality)
            FROM t_mixed_answer AS a)
         = ARRAY['product_removed|CVE-2006-0001|||wlacme|wlwidget|||', 'kev_added|CVE-2006-0001|||||||',
                 'epss_level_up|CVE-2006-0002|0.25|0.5|||||', '||||||||', 'ns_changed|||||||p2|c2', 'cname_takeover_detected|||||||p4|c4',
                 'email_auth_degraded||||||spf_all|p7|c7', '||||||||', '||||||||', '||||||||', '||||||||'],
         'S21 the first row of an event carries its columns, the CVE columns for a CVE event and the domain columns for a domain event';
  ASSERT (SELECT bool_and((a.changed_at IS NOT NULL) = a.is_first_row_of_event) FROM t_mixed_answer AS a),
         'S21 changed_at is set on the first row of an event only';
  ASSERT (SELECT array_agg(num_nonnulls(a.risk_score, a.risk_label, a.in_kev, a.kev_patch_deadline, a.kev_known_ransomware, a.has_metasploit,
                                        a.poc_count) ORDER BY a.ordinality)
            FROM t_mixed_answer AS a)
         = ARRAY[7, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0],
         'S21 the facts of a CVE come once, on the first row of the CVE';
  ASSERT (SELECT a.risk_score = api.fn_cve_risk_score(7.5, 0.5, true, true, 7, false) AND a.kev_patch_deadline = '2024-02-03'
            FROM t_mixed_answer AS a WHERE a.ordinality = 1),
         'S21 the first row of CVE-2006-0001 carries its facts';
  ASSERT (SELECT array_agg(format('%s|%s|%s|%s|%s|%s|%s', a.registered_domain, a.dns_presence_value, a.ns_value, a.mx_value,
                                  a.ip_address_reachability_value, a.cname_takeover_value, a.email_auth_value)
                           ORDER BY a.ordinality)
            FROM t_mixed_answer AS a)
         = ARRAY['||||||', '||||||', '||||||', '||||||', 'wl.example|d1-presence|d1-ns|d1-mx|d1-address|d1-cname|', '||||||',
                 'wo.example||||||d2-email', '||||||', '||||||', '||||||', '||||||'],
         'S21 the facts of a domain come once, on the first row of the domain: the confirmed values of the key''s own item, NULL for a kind with no value';

  PERFORM pg_temp.t_rewind('A', base);
  ASSERT (SELECT row(s.scanned_event_count, s.scan_end_event_id, ARRAY(SELECT DISTINCT e.event_id - base FROM unnest(s.page_event_ids) AS e (event_id) ORDER BY 1),
                     cardinality(s.page_event_ids), (SELECT count(*) FROM unnest(s.page_pending_flags) AS f (is_pending) WHERE f.is_pending), s.is_page_full)::text
            FROM api.fn_watchlist_event_scan(key_a, base, base + 9, 100, 100, 600) AS s)
         = row(3, base + 9, ARRAY[1, 2, 3, 4, 7, 8], 11, 3, false)::text,
         'S21 the scan reads the three CVE events, takes the three waiting domain refs, and keeps all eleven pairs';
  ASSERT (SELECT row(ARRAY(SELECT DISTINCT e.event_id - base FROM unnest(s.page_event_ids) AS e (event_id) ORDER BY 1), s.is_page_full)::text
            FROM api.fn_watchlist_event_scan(key_a, base, base + 9, 4, 100, 600) AS s)
         = row(ARRAY[1, 2, 3, 4], true)::text,
         'S21 an event that several items hear takes one place of the page, and a page that leaves events out is full';
  ASSERT (SELECT s.page_pending_flags = ARRAY[false, false, false, true, false, true, true, false, false, false, false]
            FROM api.fn_watchlist_event_scan(key_a, base, base + 9, 100, 100, 600) AS s),
         'S21 page_pending_flags is true for the waiting domain refs only, in event_id order';
  ASSERT (SELECT s.page_event_ids FROM api.fn_watchlist_event_scan(key_a, base, base + 2, 100, 100, 600) AS s)
         = ARRAY[base + 1, base + 1, base + 1, base + 2],
         'S21 the scan stops at p_head_event_id, for the CVE events and the waiting refs';
  ASSERT pg_temp.t_events_after('B', base, 100, 100)
         = 'ok|3|false|{d1.wl.example:ns_changed,d1.wl.example:cname_takeover_detected,d3.wl.example:ns_changed}',
         'S21 key B sees every event of the domains it watches, under numbers of its own';
  ASSERT pg_temp.t_events_after('A', base, 100, 2) = 'ok|3|true|{01:kev_added,d1.wl.example:ns_changed,02:epss_level_up}'
     AND pg_temp.t_key_state('A') = format('3,0,%s', base + 3),
         'S21 a full window of two CVE events ends the scan at the second, and the waiting ref below it joins in event_id order';
  ASSERT pg_temp.t_events('A', NULL, false, 100, 100)
         = 'ok|6|false|{d1.wl.example:cname_takeover_detected,d2.wo.example:email_auth_degraded,01:product_removed}',
         'S21 the next normal call numbers the refs after the window with the next CVE event, with no gap';
  ASSERT pg_temp.t_events_after('A', base, 2, 100) = 'ok|2|true|{01:kev_added,d1.wl.example:ns_changed}'
     AND pg_temp.t_key_state('A') = format('2,0,%s', base + 2),
         'S21 a full page ends at its last event, a domain event here, and last_cve_event_id stops there';
  ASSERT pg_temp.t_events('A', NULL, false, 100, 100)
         = 'ok|6|false|{02:epss_level_up,d1.wl.example:cname_takeover_detected,d2.wo.example:email_auth_degraded,01:product_removed}',
         'S21 the next normal call goes on with the CVE event the page left out';
  ASSERT pg_temp.t_events('A', 3, false, 100, 100)
         = 'ok|6|false|{d1.wl.example:cname_takeover_detected,d2.wo.example:email_auth_degraded,01:product_removed}',
         'S21 a replay reads the numbered events after its cursor';

  PERFORM pg_temp.t_rewind('A', base);
  ASSERT pg_temp.t_events('A', NULL, false, 3, 100) = 'ok|3|true|{01:kev_added,d1.wl.example:ns_changed,02:epss_level_up}',
         'S21 a normal call reads the first page';
  ASSERT pg_temp.t_events('A', NULL, true, 100, 100) = 'ok|3|true|{01:kev_added,d1.wl.example:ns_changed,02:epss_level_up}',
         'S21 a repeat answers the same page, and has more while domain refs wait';
  ASSERT pg_temp.t_events('A', NULL, false, 100, 100)
         = 'ok|6|false|{d1.wl.example:cname_takeover_detected,d2.wo.example:email_auth_degraded,01:product_removed}',
         'S21 the next normal call reads the rest';
  ASSERT pg_temp.t_events('A', NULL, true, 100, 100)
         = 'ok|6|false|{d1.wl.example:cname_takeover_detected,d2.wo.example:email_auth_degraded,01:product_removed}',
         'S21 a repeat of the last page has no more';

  ASSERT (SELECT array_agg(m.label || ':' || w.event_rank || ':' || w.is_first_row_of_event ORDER BY w.item_id, w.event_rank)
            FROM api.fn_watchlist_event_rows(key_a, 4, 6) AS w JOIN t_mixed_item AS m ON m.item_id = w.item_id)
         = ARRAY['I1:2:true', 'I3:2:false', 'I5:1:true', 'I6:2:false', 'I7:2:false'],
         'S21 the rows answer the numbers after p_after_key_event_id up to p_last_key_event_id, and rank them among themselves';
  ASSERT (SELECT array_agg(w.event_type ORDER BY w.event_rank) FILTER (WHERE w.is_first_row_of_event)
            FROM api.fn_watchlist_event_rows(key_b, 0, 3) AS w)
         = ARRAY['ns_changed', 'cname_takeover_detected', 'ns_changed'],
         'S21 the rows answer the items of the key p_api_key_id names';
  ASSERT (SELECT array_agg(w.item_domain_name || '|' || coalesce(w.registered_domain, 'null') || '|'
                           || concat_ws(',', w.dns_presence_value, w.ns_value, w.mx_value, w.ip_address_reachability_value, w.cname_takeover_value,
                                        w.email_auth_value) ORDER BY w.event_rank)
                 FILTER (WHERE w.is_first_event_of_domain)
            FROM api.fn_watchlist_event_rows(key_b, 0, 3) AS w)
         = ARRAY['d1.wl.example|wl.example|b-presence,b-ns,b-mx', 'd3.wl.example|wl.example|'],
         'S21 key B''s map shows the values of its own d1 item, never key A''s, and a name with no value yet still carries its registered domain';
  ASSERT (SELECT array_agg(m.label ORDER BY w.ordinality)
            FROM api.fn_watchlist_event_rows(key_a, 0, 2) WITH ORDINALITY AS w JOIN t_mixed_item AS m ON m.item_id = w.item_id)
         = ARRAY['I3', 'I4', 'I6', 'I7'],
         'S21 the rows come in item_id order';
  ASSERT pg_temp.t_edit('A', NULL, NULL, p_is_cleared => true) = 'ok' AND pg_temp.t_edit('B', NULL, NULL, p_is_cleared => true) = 'ok',
         'S21 the clear after the mixed events answers ok';
END
$$;

DO $$
DECLARE
  base  bigint := api.fn_watchlist_event_max_id();
  scan_source text;
BEGIN
  ASSERT pg_temp.t_edit('A', NULL, NULL, p_is_cleared => true) = 'ok'
     AND pg_temp.t_edit('A', 'add', 'cve_lookup', p_cve_id => 'CVE-2006-0002') = 'ok'
     AND pg_temp.t_edit('A', 'add', 'dns_lookup', p_domain_name => 'd1.wl.example') = 'ok', 'S22 key A adds its two items';
  INSERT INTO cve_change_event (event_id, cve_id, event_type) OVERRIDING SYSTEM VALUE VALUES (base + 4, 'CVE-2006-0002', 'kev_removed');
  INSERT INTO domain_change_event (event_id, domain_name, event_type, previous_value, current_value)
    VALUES (base + 3, 'd1.wl.example', 'ns_changed', 'p', 'c');
  INSERT INTO cve_change_event (event_id, cve_id, event_type) OVERRIDING SYSTEM VALUE VALUES (base + 2, 'CVE-2006-0002', 'kev_added');
  INSERT INTO domain_change_event (event_id, domain_name, event_type, previous_value, current_value)
    VALUES (base + 1, 'd1.wl.example', 'mx_changed', 'p', 'c');
  PERFORM pg_temp.t_ref('A', 'd1.wl.example', base + 3);
  PERFORM pg_temp.t_ref('A', 'd1.wl.example', base + 1);
  PERFORM setval('watchlist_event_id_seq', base + 4);

  ASSERT pg_temp.t_events_after('A', base, 100, 1) = 'ok|2|true|{d1.wl.example:mx_changed,02:kev_added}',
         'S22 a window of one event takes the smallest CVE event, not the first one written, and the smaller waiting ref comes first';
  ASSERT pg_temp.t_events('A', NULL, false, 100, 1) = 'ok|4|true|{d1.wl.example:ns_changed,02:kev_removed}',
         'S22 the next window of one event takes the next CVE event, with the waiting ref below it, and a full window has more';
  PERFORM pg_temp.t_rewind('A', base);
  ASSERT (SELECT array_agg(coalesce(x.item_cve_id, x.item_domain_name) || ':' || x.event_rank || ':' || x.is_first_row_of_event || ':'
                           || coalesce(x.is_first_event_of_cve::text, 'null') || ':' || coalesce(x.is_first_event_of_domain::text, 'null')
                           ORDER BY x.ordinality)
            FROM api.fn_watchlist_events(pg_temp.t_hash('A'), NULL, false, 100, 100, 600) WITH ORDINALITY AS x)
         = ARRAY['CVE-2006-0002:2:true:true:false', 'CVE-2006-0002:4:true:false:false',
                 'd1.wl.example:1:true:false:true', 'd1.wl.example:3:true:false:false'],
         'S22 the first row of a CVE and of a domain is its smallest event under the first item, not the first one written';
  scan_source := pg_get_functiondef('api.fn_watchlist_event_scan(integer, bigint, bigint, integer, integer, integer)'::regprocedure);
  ASSERT (SELECT count(*) FROM regexp_matches(scan_source, 'ORDER BY cce\.event_id\s+LIMIT fn_watchlist_event_scan\.p_scan_row_count\s*\)', 'g')) = 1,
         'S22 the scan reads cve_change_event in event_id order and stops after p_scan_row_count events, so the plan needs no sort of every later event';
  ASSERT (SELECT count(*) FROM regexp_matches(scan_source, 'ORDER BY pae\.event_id\s+LIMIT fn_watchlist_event_scan\.p_scan_row_count\s*\)', 'g')) = 1,
         'S22 the scan reads package_advisory_change_event the same way';
  ASSERT pg_temp.t_edit('A', NULL, NULL, p_is_cleared => true) = 'ok', 'S22 the clear after the order checks answers ok';
END
$$;

DO $$
DECLARE
  base      bigint := api.fn_watchlist_event_max_id();
  key_a     integer := pg_temp.t_key_id('A');
  is_raised boolean := false;
BEGIN
  ASSERT pg_temp.t_edit('A', NULL, NULL, p_is_cleared => true) = 'ok'
     AND pg_temp.t_edit('A', 'add', 'cve_lookup', p_cve_id => 'CVE-2006-0002') = 'ok'
     AND pg_temp.t_edit('A', 'add', 'cve_search', p_min_cvss => 0) = 'ok'
     AND pg_temp.t_edit('A', 'add', 'dns_lookup', p_domain_name => 'd1.wl.example') = 'ok', 'S23 key A adds its three items';
  INSERT INTO cve_change_event (event_id, cve_id, event_type) OVERRIDING SYSTEM VALUE VALUES
    (base + 1, 'CVE-2006-0002', 'kev_added'), (base + 2, 'CVE-2006-0002', 'kev_removed'), (base + 4, 'CVE-2006-0002', 'kev_added');
  INSERT INTO domain_change_event (event_id, domain_name, event_type, previous_value, current_value)
    VALUES (base + 3, 'd1.wl.example', 'ns_changed', 'p', 'c');
  PERFORM pg_temp.t_ref('A', 'd1.wl.example', base + 3);
  PERFORM setval('watchlist_event_id_seq', base + 4);

  ASSERT pg_temp.t_events_after('A', base, 100, 100, 3) = 'ok|1|true|{02:kev_added}'
     AND pg_temp.t_key_state('A') = format('1,0,%s', base + 1),
         'S23 a page ends before the event whose pairs would pass the bound, has more, and moves last_cve_event_id to its last event';
  ASSERT pg_temp.t_events('A', NULL, false, 100, 100, 3) = 'ok|3|true|{02:kev_removed,d1.wl.example:ns_changed}'
     AND pg_temp.t_key_state('A') = format('3,0,%s', base + 3),
         'S23 the next page starts with the event that did not fit, and 2 + 1 pairs meet the bound of 3, so both stay';
  ASSERT pg_temp.t_events('A', NULL, false, 100, 100, 3) = 'ok|4|false|{02:kev_added}'
     AND pg_temp.t_key_state('A') = format('4,0,%s', base + 4),
         'S23 a page whose pairs fit the bound is not full, so it ends at the head with no more';
  PERFORM pg_temp.t_rewind('A', base);
  ASSERT (SELECT row(s.scanned_event_count, s.scan_end_event_id, s.page_event_ids, s.is_page_full)::text
            FROM api.fn_watchlist_event_scan(key_a, base, base + 4, 100, 100, 3) AS s)
         = row(3, base + 4, ARRAY[base + 1, base + 1], true)::text,
         'S23 the scan reads the whole window, keeps the two pairs of base + 1 and says the page left events out';
  ASSERT (SELECT row(s.page_event_ids, s.is_page_full)::text FROM api.fn_watchlist_event_scan(key_a, base, base + 4, 1, 100, 3) AS s)
         = row(ARRAY[base + 1, base + 1], true)::text,
         'S23 the row count ends the page at one event too';
  ASSERT (SELECT row(s.page_event_ids, s.is_page_full)::text FROM api.fn_watchlist_event_scan(key_a, base, base + 4, 100, 100, 7) AS s)
         = row(ARRAY[base + 1, base + 1, base + 2, base + 2, base + 3, base + 4, base + 4], false)::text,
         'S23 a bound of exactly the seven pairs of the window keeps every event';
  ASSERT (SELECT row(s.page_event_ids, s.is_page_full)::text FROM api.fn_watchlist_event_scan(key_a, base, base + 4, 100, 100, 6) AS s)
         = row(ARRAY[base + 1, base + 1, base + 2, base + 2, base + 3], true)::text,
         'S23 a bound one pair short of the window leaves the last event out';
  ASSERT pg_temp.t_events_after('A', base, 100, 100) = 'ok|4|false|{02:kev_added,02:kev_removed,d1.wl.example:ns_changed,02:kev_added}',
         'S23 the bound db.c sends keeps all four events';

  ASSERT pg_temp.t_events('A', 0, false, 100, 100, 3) = 'ok|1|true|{02:kev_added}',
         'S23 a replay ends before the number whose pairs would pass the bound';
  ASSERT pg_temp.t_events('A', 1, false, 100, 100, 3) = 'ok|3|true|{02:kev_removed,d1.wl.example:ns_changed}',
         'S23 a replay keeps two numbers whose 2 + 1 pairs meet the bound of 3';
  ASSERT pg_temp.t_events('A', 0, false, 2, 100) = 'ok|2|true|{02:kev_added,02:kev_removed}',
         'S23 a replay holds at most p_event_row_count numbers, and has more while numbers follow';
  ASSERT pg_temp.t_events('A', 2, false, 2, 100) = 'ok|4|false|{d1.wl.example:ns_changed,02:kev_added}',
         'S23 a replay that reaches the last number, with no waiting ref and no later CVE event, has no more';

  PERFORM pg_temp.t_rewind('A', base);
  ASSERT pg_temp.t_events('A', NULL, false, 100, 100, 3) = 'ok|1|true|{02:kev_added}',
         'S23 a normal call reads the bounded first page';
  ASSERT pg_temp.t_event_cursor('A') = '0,1', 'S23 the normal call moves the position to the number of the last event of its page';
  ASSERT pg_temp.t_events('A', NULL, true, 100, 100, 3) = 'ok|1|true|{02:kev_added}',
         'S23 a repeat of a bounded page answers the same event';
  ASSERT pg_temp.t_events('A', NULL, false, 100, 100, 3) = 'ok|3|true|{02:kev_removed,d1.wl.example:ns_changed}',
         'S23 the next normal call starts with the event that did not fit';
  ASSERT pg_temp.t_events('A', NULL, true, 100, 100, 3) = 'ok|3|true|{02:kev_removed,d1.wl.example:ns_changed}',
         'S23 a repeat of the second bounded page answers the same two events';
  ASSERT pg_temp.t_event_cursor('A') = '1,3', 'S23 the repeat moved nothing';

  ASSERT (SELECT count(*) FROM api.fn_watchlist_events(pg_temp.t_hash('A'), NULL, false, 100, 100, NULL)) = 0,
         'S23 a NULL pair row count answers no row';
  ASSERT (SELECT count(*) FROM api.fn_watchlist_event_scan(key_a, base, base + 4, 100, 100, NULL)) = 0,
         'S23 api.fn_watchlist_event_scan answers no row for a NULL pair row count';

  BEGIN
    PERFORM pg_temp.t_events_after('A', base, 100, 100, 1);
  EXCEPTION WHEN program_limit_exceeded THEN
    is_raised := true;
  END;
  ASSERT is_raised, 'S23 a first event whose pairs pass the bound raises program_limit_exceeded, as the page would hold no event';
  ASSERT pg_temp.t_events_after('A', base, 100, 100) LIKE 'ok|4|%', 'S23 the key reads all four events again';
  is_raised := false;
  BEGIN
    PERFORM pg_temp.t_events('A', 0, false, 100, 100, 1);
  EXCEPTION WHEN program_limit_exceeded THEN
    is_raised := true;
  END;
  ASSERT is_raised, 'S23 a replay whose first number has more refs than the bound raises program_limit_exceeded';
  ASSERT pg_temp.t_edit('A', NULL, NULL, p_is_cleared => true) = 'ok', 'S23 the clear after the pair bound checks answers ok';
END
$$;

DO $$
DECLARE
  event_id bigint;
BEGIN
  ASSERT pg_temp.t_edit('A', NULL, NULL, p_is_cleared => true) = 'ok'
     AND pg_temp.t_edit('A', 'add', 'product_exposure', p_vendor => 'wlacme', p_product => 'wlfixed') = 'ok'
     AND pg_temp.t_edit('A', 'add', 'cve_search', p_in_kev => false) = 'ok', 'S24 key A adds its two items';
  event_id := pg_temp.t_cve_event_of('CVE-2006-0003', 'product_removed', NULL, NULL, 'wlacme', 'wlfixed');
  PERFORM pg_temp.t_rewind('A', event_id - 1);
  ASSERT (SELECT array_agg(x.item_endpoint_name || '|' || coalesce(x.item_product_has_cves::text, 'null') || '|'
                           || coalesce(x.item_in_kev::text, 'null') || '|' || coalesce(x.item_known_ransomware::text, 'null') ORDER BY x.item_id)
            FROM api.fn_watchlist_events(pg_temp.t_hash('A'), NULL, false, 100, 100, 600) AS x)
         = ARRAY['product_exposure|false|null|null', 'cve_search|null|false|null'],
         'S24 a pair with no vulnerable row has no CVEs though its vendor has one, and item_in_kev is not item_known_ransomware';
  ASSERT pg_temp.t_edit('A', NULL, NULL, p_is_cleared => true) = 'ok', 'S24 the clear answers ok';
END
$$;

CREATE FUNCTION pg_temp.t_check_values(p_constraint_name text) RETURNS text[] LANGUAGE sql AS $$
  SELECT array_agg(m.quoted[1] ORDER BY m.ordinality)
    FROM pg_constraint AS c
         CROSS JOIN LATERAL regexp_matches(pg_get_constraintdef(c.oid), '''([^'']+)''::text', 'g') WITH ORDINALITY AS m (quoted, ordinality)
   WHERE c.conname = p_constraint_name
$$;

DO $$
DECLARE
  endpoint_names text[] := pg_temp.t_check_values('watchlist_item_endpoint_name_known');
  cve_types      text[] := pg_temp.t_check_values('cve_change_event_type_known');
  domain_types   text[] := pg_temp.t_check_values('domain_change_event_type_known');
  package_types  text[] := pg_temp.t_check_values('package_advisory_change_event_type_known');
  ip_types       text[] := pg_temp.t_check_values('ip_change_event_type_known');
  eol_types      text[] := pg_temp.t_check_values('eol_change_event_type_known');
  shown_types    text[] := ARRAY['epss_above_min', 'epss_below_min'];
BEGIN
  ASSERT 'package_check' = ANY (endpoint_names) AND package_types = ARRAY['advisory_added', 'fix_available', 'malware_added'],
         'S25 the item CHECK allows package_check, and the package CHECK allows three types';
  ASSERT 'ip_lookup' = ANY (endpoint_names) AND ip_types = ARRAY['drop_listed', 'drop_unlisted', 'hosting_changed'],
         'S25 the item CHECK allows ip_lookup, and the IP CHECK allows three types';
  ASSERT 'product_exposure' = ANY (endpoint_names) AND eol_types = ARRAY['eol_approaching', 'eol_reached', 'eol_date_changed'],
         'S25 the item CHECK allows product_exposure, and the EOL CHECK allows three types';
  ASSERT api.fn_watchlist_endpoint_event_types('product_exposure') = api.fn_watchlist_endpoint_event_types('cve_lookup') || eol_types,
         'S25 product_exposure watches the types of cve_lookup and the three EOL types';
  ASSERT (SELECT bool_and(cardinality(api.fn_watchlist_endpoint_event_types(e.endpoint_name)) > 0
                          AND CASE WHEN e.endpoint_name = 'package_check'
                                   THEN api.fn_watchlist_endpoint_event_types(e.endpoint_name) = package_types || ARRAY['kev_added', 'ransomware_linked'] || eol_types
                                   WHEN e.endpoint_name = 'ip_lookup'
                                   THEN api.fn_watchlist_endpoint_event_types(e.endpoint_name) = ip_types
                                   WHEN e.endpoint_name = 'product_exposure'
                                   THEN api.fn_watchlist_endpoint_event_types(e.endpoint_name) <@ (cve_types || eol_types)
                                   ELSE api.fn_watchlist_endpoint_event_types(e.endpoint_name) <@ (cve_types || shown_types)
                                        OR api.fn_watchlist_endpoint_event_types(e.endpoint_name) <@ domain_types
                              END)
            FROM unnest(endpoint_names) AS e (endpoint_name)),
         'S25 each item endpoint watches at least one event type, all from one event table, package_check the package types, two CVE types and the EOL types, and ip_lookup the IP types';
  ASSERT NOT (shown_types && (cve_types || domain_types || package_types || ip_types || eol_types)), 'S25 no CHECK allows epss_above_min or epss_below_min';
  ASSERT (SELECT array_agg(DISTINCT t.event_type ORDER BY t.event_type)
            FROM unnest(endpoint_names) AS e (endpoint_name)
                 CROSS JOIN LATERAL unnest(api.fn_watchlist_endpoint_event_types(e.endpoint_name)) AS t (event_type))
         = (SELECT array_agg(DISTINCT t.event_type ORDER BY t.event_type)
              FROM unnest(cve_types || domain_types || package_types || ip_types || eol_types || shown_types) AS t (event_type)
             WHERE t.event_type <> 'epss_changed'),
         'S25 the item endpoints together watch every event type the five CHECKs allow, except epss_changed, plus the two shown EPSS types';
  ASSERT (SELECT array_agg(k.value_kind ORDER BY k.value_kind)
            FROM unnest(endpoint_names) AS e (endpoint_name)
                 CROSS JOIN LATERAL unnest(api.fn_watchlist_endpoint_value_kinds(e.endpoint_name)) AS k (value_kind))
         = (SELECT array_agg(k.value_kind ORDER BY k.value_kind) FROM unnest(pg_temp.t_check_values('watchlist_item_domain_value_kind_known')) AS k (value_kind)),
         'S25 the lanes of the item endpoints hold every value kind watchlist_item_domain_value_kind_known allows, each once';
  ASSERT (SELECT bool_and((cardinality(api.fn_watchlist_endpoint_value_kinds(e.endpoint_name)) > 0)
                          = (api.fn_watchlist_endpoint_event_types(e.endpoint_name) <@ domain_types))
            FROM unnest(endpoint_names) AS e (endpoint_name)),
         'S25 an endpoint has value kinds exactly when it watches domain events';
  ASSERT api.fn_watchlist_endpoint_value_kinds('ip_lookup') = ARRAY[]::text[],
         'S25 an ip_lookup item has no value kind of a domain lane: its values sit in watchlist_item_ip_value';
END
$$;

DO $$
DECLARE
  endpoint_names text[] := pg_temp.t_check_values('watchlist_item_endpoint_name_known');
  cve_types      text[] := pg_temp.t_check_values('cve_change_event_type_known');
  domain_types   text[] := pg_temp.t_check_values('domain_change_event_type_known');
  package_types  text[] := pg_temp.t_check_values('package_advisory_change_event_type_known');
  ip_types       text[] := pg_temp.t_check_values('ip_change_event_type_known');
  base           bigint := api.fn_watchlist_event_max_id();
  event_type     text;
BEGIN
  INSERT INTO osv_advisories (advisory_id, source, license, summary, aliases, published_time, modified_time) VALUES
    ('GHSA-wl26-0001', 'ghsa', 'CC-BY-4.0', '', ARRAY['CVE-2006-0001'], '2021-01-01T00:00:00Z', '2021-01-01T00:00:00Z');
  INSERT INTO osv_affected (advisory_id, affected_index, ecosystem, package_name, version_ranges, listed_versions, listed_versions_sortable, is_unaffected_provable)
  SELECT af.advisory_id, af.affected_index, af.ecosystem, af.package_name, af.version_ranges::jsonb, af.listed_versions,
         ARRAY(SELECT array_to_string(public.fn_osv_version_sortable(af.ecosystem, kv.version_text), ' ')
                 FROM unnest(af.listed_versions) WITH ORDINALITY AS kv (version_text, version_ordinal) ORDER BY kv.version_ordinal),
         af.is_unaffected_provable
    FROM (VALUES
      ('GHSA-wl26-0001', 0, 'npm', 'wl26-pkg', '[{"type": "SEMVER", "events": [{"introduced": "0"}]}]', '{}'::text[], false)
    ) AS af (advisory_id, affected_index, ecosystem, package_name, version_ranges, listed_versions, is_unaffected_provable);
  INSERT INTO osv_affected_version_intervals (advisory_id, affected_index, interval_index, introduced_version_sortable, upper_version_sortable, upper_event, fixed_version)
  SELECT iv.advisory_id, iv.affected_index, iv.interval_index,
         CASE WHEN iv.introduced_version IS NOT NULL THEN public.fn_osv_version_sortable(osvaf.ecosystem, iv.introduced_version) END,
         CASE WHEN iv.upper_version IS NOT NULL THEN public.fn_osv_version_sortable(osvaf.ecosystem, iv.upper_version) END,
         iv.upper_event, iv.fixed_version
    FROM (VALUES
      ('GHSA-wl26-0001', 0, 0, NULL::text, NULL::text, NULL::text, NULL::text)
    ) AS iv (advisory_id, affected_index, interval_index, introduced_version, upper_version, upper_event, fixed_version)
    JOIN osv_affected AS osvaf ON osvaf.advisory_id = iv.advisory_id AND osvaf.affected_index = iv.affected_index;
  ASSERT pg_temp.t_edit('A', NULL, NULL, p_is_cleared => true) = 'ok' AND pg_temp.t_edit('B', NULL, NULL, p_is_cleared => true) = 'ok',
         'S26 the clear before the events of every type answers ok';
  ASSERT pg_temp.t_edit('A', 'add', 'cve_lookup', p_cve_id => 'CVE-2006-0001') = 'ok'
     AND pg_temp.t_edit('A', 'add', 'kev_lookup', p_cve_id => 'CVE-2006-0001') = 'ok'
     AND pg_temp.t_edit('A', 'add', 'cve_exploit', p_cve_id => 'CVE-2006-0001') = 'ok'
     AND pg_temp.t_edit('A', 'add', 'product_exposure', p_vendor => 'wlacme', p_product => 'wlwidget') = 'ok'
     AND pg_temp.t_edit('A', 'add', 'cve_search', p_min_cvss => 7.5) = 'ok'
     AND pg_temp.t_edit('A', 'add', 'dns_lookup', p_domain_name => 'm.wl.example') = 'ok'
     AND pg_temp.t_edit('A', 'add', 'ssl_check', p_domain_name => 'm.wl.example') = 'ok'
     AND pg_temp.t_edit('A', 'add', 'whois_lookup', p_domain_name => 'm.wl.example') = 'ok'
     AND pg_temp.t_edit('A', 'add', 'headers_check', p_domain_name => 'm.wl.example') = 'ok'
     AND pg_temp.t_edit('A', 'add', 'cert_search', p_domain_name => 'm.wl.example') = 'ok'
     AND pg_temp.t_edit('A', 'add', 'package_check', p_ecosystem => 'npm', p_package_name => 'wl26-pkg') = 'ok'
     AND (SELECT x.edit_status FROM api.fn_watchlist_edit_ip_lookup(pg_temp.t_hash('A'), 'add', '192.0.2.26', 100) AS x) = 'ok',
         'S26 key A adds one item of each endpoint';
  ASSERT (SELECT array_agg(wi.endpoint_name ORDER BY wi.endpoint_name) FROM watchlist_item AS wi WHERE wi.api_key_id = pg_temp.t_key_id('A'))
         = (SELECT array_agg(e.endpoint_name ORDER BY e.endpoint_name) FROM unnest(endpoint_names) AS e (endpoint_name)),
         'S26 key A holds one item of each endpoint the CHECK allows';

  FOREACH event_type IN ARRAY cve_types LOOP
    PERFORM pg_temp.t_cve_event_of('CVE-2006-0001', event_type, NULL, NULL,
                                   CASE WHEN event_type IN ('product_added', 'product_removed') THEN 'wlacme' END,
                                   CASE WHEN event_type IN ('product_added', 'product_removed') THEN 'wlwidget' END);
  END LOOP;
  FOREACH event_type IN ARRAY domain_types LOOP
    PERFORM pg_temp.t_domain_event('m.wl.example', event_type, 'A', 'p', 'c',
                                   CASE WHEN event_type = 'email_auth_degraded' THEN 'spf_all' END);
  END LOOP;
  FOREACH event_type IN ARRAY package_types LOOP
    INSERT INTO package_advisory_change_event (advisory_id, ecosystem, package_name_normalized, package_name, event_type, fixed_version)
    VALUES ('GHSA-wl26-0001', 'npm', 'wl26-pkg', 'wl26-pkg', event_type, CASE WHEN event_type = 'fix_available' THEN '9.9.9' END);
  END LOOP;
  ASSERT NOT EXISTS (SELECT 1 FROM watchlist_event_ref AS wer JOIN watchlist_item AS wi ON wi.item_id = wer.item_id
                      WHERE wi.api_key_id = pg_temp.t_key_id('A') AND wi.endpoint_name = 'ip_lookup'),
         'S26 the IP item hears no event of the other event tables';
  FOREACH event_type IN ARRAY ip_types LOOP
    WITH written AS (
      INSERT INTO ip_change_event (ip_address, event_type, previous_value, current_value, drop_list_time, drop_copyright)
      VALUES ('192.0.2.26', event_type, 'p', 'c',
              CASE WHEN event_type <> 'hosting_changed' THEN timestamptz '2026-11-01T02:03:04Z' END,
              CASE WHEN event_type <> 'hosting_changed' THEN '(c) 2026 wl26' END)
      RETURNING ip_change_event.event_id)
    INSERT INTO watchlist_event_ref (api_key_id, item_id, event_id)
    SELECT wii.api_key_id, wii.item_id, w.event_id
      FROM written AS w
      CROSS JOIN watchlist_item_ip AS wii
     WHERE wii.api_key_id = pg_temp.t_key_id('A');
  END LOOP;

  PERFORM pg_temp.t_rewind('A', base);
  ASSERT (WITH answer AS (SELECT * FROM api.fn_watchlist_events(pg_temp.t_hash('A'), NULL, false, 100, 100, 600))
          SELECT array_agg(pair.item_endpoint_name || ':' || first_row.event_type ORDER BY pair.item_id, pair.event_rank)
            FROM answer AS pair
                 JOIN answer AS first_row ON first_row.event_rank = pair.event_rank AND first_row.is_first_row_of_event)
         = (SELECT array_agg(wi.endpoint_name || ':' || t.event_type ORDER BY wi.item_id, t.ordinality)
              FROM watchlist_item AS wi
                   CROSS JOIN unnest(CASE WHEN wi.endpoint_name = 'ip_lookup' THEN ip_types
                                          ELSE cve_types || domain_types || package_types END) WITH ORDINALITY AS t (event_type, ordinality)
             WHERE wi.api_key_id = pg_temp.t_key_id('A')
               AND t.event_type = ANY (api.fn_watchlist_endpoint_event_types(wi.endpoint_name))),
         'S26 each item answers the events of every type its endpoint watches, and no other';
  ASSERT (SELECT count(*) FROM watchlist_event_ref AS wer JOIN watchlist_item_ip AS wii ON wii.item_id = wer.item_id
           WHERE wer.api_key_id = pg_temp.t_key_id('A') AND wer.key_event_id IS NOT NULL) = cardinality(ip_types)
     AND (SELECT count(*) FROM api.fn_watchlist_events(pg_temp.t_hash('A'), 0, false, 100, 100, 600) AS x
           WHERE x.item_endpoint_name = 'ip_lookup' AND x.event_type IS NOT NULL) = cardinality(ip_types),
         'S26 the normal call numbers each IP ref, and a replay answers each numbered IP ref';
  ASSERT (SELECT array_agg(x.event_type || '|' || x.previous_ip_value || '|' || x.current_ip_value || '|' || coalesce(x.drop_list_time, 'null')
                          || '|' || coalesce(x.drop_copyright, 'null') ORDER BY x.event_type)
            FROM api.fn_watchlist_events(pg_temp.t_hash('A'), 0, false, 100, 100, 600) AS x
           WHERE x.item_endpoint_name = 'ip_lookup' AND x.is_first_row_of_event)
         = ARRAY['drop_listed|p|c|2026-11-01T02:03:04Z|(c) 2026 wl26', 'drop_unlisted|p|c|2026-11-01T02:03:04Z|(c) 2026 wl26',
                 'hosting_changed|p|c|null|null'],
         'S26 each IP event row carries its values, and a drop row its list_time in UTC and its copyright';
  ASSERT pg_temp.t_edit('A', NULL, NULL, p_is_cleared => true) = 'ok', 'S26 the clear answers ok';
  DELETE FROM ip_change_event WHERE ip_address = '192.0.2.26';
  DELETE FROM package_advisory_change_event;
  DELETE FROM osv_advisories WHERE advisory_id = 'GHSA-wl26-0001';
END
$$;


DO $$
DECLARE
  lane_before text;
BEGIN
  ASSERT pg_temp.t_edit('A', NULL, NULL, p_is_cleared => true) = 'ok' AND pg_temp.t_edit('B', NULL, NULL, p_is_cleared => true) = 'ok',
         'S28 the clear before the lane rows answers ok';
  ASSERT pg_temp.t_edit('A', 'add', 'dns_lookup', p_domain_name => 'l.wl.example') = 'ok', 'S28 a dns_lookup add answers ok';
  ASSERT (SELECT array_agg(dwl::text) FROM domain_watch_lane AS dwl WHERE dwl.domain_name = 'l.wl.example') = '{"(l.wl.example,dns,,,,)"}',
         'S28 the first dns_lookup add writes a dns lane row with no lease, no scan and no not_before, and no row of another lane';
  ASSERT pg_temp.t_edit('A', 'add', 'ssl_check', p_domain_name => 'l.wl.example') = 'ok', 'S28 an ssl_check add answers ok';
  ASSERT (SELECT dwl::text FROM domain_watch_lane AS dwl WHERE dwl.domain_name = 'l.wl.example' AND dwl.lane_name = 'tls') = '(l.wl.example,tls,,,,)',
         'S28 the first ssl_check add writes a tls lane row with no lease, no scan and no not_before';
  UPDATE domain_watch_lane AS dwl SET claimed_until = now() + interval '5 minutes', claimed_at = now() - interval '1 minute', scanned_at = now() - interval '1 hour'
   WHERE dwl.domain_name = 'l.wl.example';
  lane_before := (SELECT string_agg(dwl::text, ' ' ORDER BY dwl.lane_name) FROM domain_watch_lane AS dwl WHERE dwl.domain_name = 'l.wl.example');
  ASSERT pg_temp.t_edit('B', 'add', 'ssl_check', p_domain_name => 'l.wl.example') = 'ok', 'S28 key B adds an ssl_check item of the same name';
  ASSERT (SELECT string_agg(dwl::text, ' ' ORDER BY dwl.lane_name) FROM domain_watch_lane AS dwl WHERE dwl.domain_name = 'l.wl.example') = lane_before,
         'S28 another ssl_check add keeps the lane rows of the name as they were';
  ASSERT pg_temp.t_edit('B', 'add', 'dns_lookup', p_domain_name => 'l.wl.example') = 'ok', 'S28 key B adds a dns_lookup item of the same name';
  ASSERT (SELECT string_agg(dwl::text, ' ' ORDER BY dwl.lane_name) FROM domain_watch_lane AS dwl WHERE dwl.domain_name = 'l.wl.example') = lane_before,
         'S28 another dns_lookup add keeps the lane rows of the name as they were';
  ASSERT pg_temp.t_edit('A', 'add', 'ssl_check', p_domain_name => 'm.wo.example') = 'ok', 'S28 an ssl_check add of a new name answers ok';
  ASSERT EXISTS (SELECT 1 FROM domain_watch AS dw WHERE dw.domain_name = 'm.wo.example' AND dw.registered_domain = 'wo.example')
     AND (SELECT array_agg(dwl.lane_name) FROM domain_watch_lane AS dwl WHERE dwl.domain_name = 'm.wo.example') = '{tls}',
         'S28 an ssl_check add of a new name writes its domain_watch row and its tls row alone';
  ASSERT pg_temp.t_edit('A', NULL, NULL, p_is_cleared => true) = 'ok' AND pg_temp.t_edit('B', NULL, NULL, p_is_cleared => true) = 'ok',
         'S28 the clear after the lane rows answers ok';
END
$$;

DO $$
DECLARE
  lane_before text;
BEGIN
  ASSERT pg_temp.t_edit('A', NULL, NULL, p_is_cleared => true) = 'ok' AND pg_temp.t_edit('B', NULL, NULL, p_is_cleared => true) = 'ok',
         'S42 the clear before the rdap_whois rows answers ok';
  ASSERT pg_temp.t_edit('A', 'add', 'whois_lookup', p_domain_name => 'r.wr.example') = 'ok', 'S42 a whois_lookup add answers ok';
  ASSERT EXISTS (SELECT 1 FROM domain_watch AS dw WHERE dw.domain_name = 'r.wr.example' AND dw.registered_domain = 'wr.example')
     AND (SELECT array_agg(dwl::text) FROM domain_watch_lane AS dwl WHERE dwl.domain_name = 'r.wr.example') = '{"(r.wr.example,rdap_whois,,,,)"}',
         'S42 the whois_lookup add of a new name writes its domain_watch row and a rdap_whois row with no lease, no scan and no not_before, and no tls row';
  ASSERT pg_temp.t_items('A') = '{whois_lookup:r.wr.example}', 'S42 the answer carries the whois_lookup item and its domain_name';
  ASSERT pg_temp.t_edit('A', 'add', 'dns_lookup', p_domain_name => 'd.wr.example') = 'ok', 'S42 a dns_lookup add answers ok';
  ASSERT EXISTS (SELECT 1 FROM domain_watch AS dw WHERE dw.domain_name = 'd.wr.example')
     AND (SELECT array_agg(dwl.lane_name) FROM domain_watch_lane AS dwl WHERE dwl.domain_name = 'd.wr.example') = '{dns}',
         'S42 a dns_lookup add writes the dns row alone';
  ASSERT pg_temp.t_edit('A', 'add', 'ssl_check', p_domain_name => 's.wr.example') = 'ok', 'S42 an ssl_check add answers ok';
  ASSERT (SELECT array_agg(dwl.lane_name) FROM domain_watch_lane AS dwl WHERE dwl.domain_name = 's.wr.example') = '{tls}',
         'S42 an ssl_check add writes the tls row alone';
  UPDATE domain_watch_lane AS dwl
     SET claimed_until = now() + interval '5 minutes', claimed_at = now() - interval '1 minute', scanned_at = now() - interval '1 hour',
         not_before = now() - interval '2 minutes'
   WHERE dwl.domain_name = 'r.wr.example';
  lane_before := (SELECT string_agg(dwl::text, ' ') FROM domain_watch_lane AS dwl WHERE dwl.domain_name = 'r.wr.example');
  ASSERT pg_temp.t_edit('B', 'add', 'whois_lookup', p_domain_name => 'r.wr.example') = 'ok', 'S42 key B adds a whois_lookup item of the same name';
  ASSERT (SELECT string_agg(dwl::text, ' ') FROM domain_watch_lane AS dwl WHERE dwl.domain_name = 'r.wr.example') = lane_before,
         'S42 another whois_lookup add keeps the one rdap_whois row of the name as it was';
  ASSERT pg_temp.t_edit('A', 'remove', 'whois_lookup', p_domain_name => 'r.wr.example') = 'ok', 'S42 key A removes its whois_lookup item';
  ASSERT pg_temp.t_edit('B', 'remove', 'whois_lookup', p_domain_name => 'r.wr.example') = 'ok', 'S42 key B removes its whois_lookup item';
  ASSERT NOT EXISTS (SELECT 1 FROM watchlist_item_domain AS wid WHERE wid.domain_name = 'r.wr.example'), 'S42 no item of r.wr.example is left';
  ASSERT (SELECT string_agg(dwl::text, ' ') FROM domain_watch_lane AS dwl WHERE dwl.domain_name = 'r.wr.example') = lane_before,
         'S42 a remove keeps the rdap_whois row';
  ASSERT pg_temp.t_edit('A', 'add', 'whois_lookup', p_domain_name => 'd.wr.example', p_domain_name_max_count => 2) = 'ok',
         'S42 a name the key watches through dns_lookup is not counted again by its whois_lookup add';
  ASSERT pg_temp.t_edit('A', 'add', 'whois_lookup', p_domain_name => 'n.wr.example', p_domain_name_max_count => 2) = 'over_domain_limit',
         'S42 the names of the other domain endpoints count in the name cap of a whois_lookup add';
  ASSERT pg_temp.t_edit('A', 'add', 'whois_lookup', p_domain_name => 'n.wr.example', p_domain_name_max_count => 3) = 'ok',
         'S42 a whois_lookup add of a third name fits a cap of 3';
  ASSERT pg_temp.t_edit('A', NULL, NULL, p_is_cleared => true) = 'ok' AND pg_temp.t_edit('B', NULL, NULL, p_is_cleared => true) = 'ok',
         'S42 the clear after the rdap_whois rows answers ok';
END
$$;

CREATE FUNCTION pg_temp.t_domain_state(p_domain_name text) RETURNS text LANGUAGE sql AS $$
  SELECT (SELECT dw::text FROM domain_watch AS dw WHERE dw.domain_name = p_domain_name) || ' lanes='
         || coalesce((SELECT string_agg(dwl::text, ' ' ORDER BY dwl.lane_name) FROM domain_watch_lane AS dwl WHERE dwl.domain_name = p_domain_name), 'none')
$$;
CREATE FUNCTION pg_temp.t_item_state(p_domain_name text, p_label text DEFAULT '') RETURNS text LANGUAGE sql AS $$
  SELECT coalesce(string_agg(k.label || ':' || wid.endpoint_name || ':' || (wid.next_scan_at - now()) || ':'
                             || coalesce((SELECT string_agg(widv.value_kind, ',' ORDER BY widv.value_kind) FROM watchlist_item_domain_value AS widv
                                           WHERE widv.item_id = wid.item_id), ''),
                             ' ' ORDER BY wid.item_id), '')
    FROM watchlist_item_domain AS wid
    JOIN t_watchlist_key AS k ON pg_temp.t_key_id(k.label) = wid.api_key_id
   WHERE wid.domain_name = p_domain_name AND k.label <> p_label
$$;
CREATE FUNCTION pg_temp.t_fill_items(p_domain_name text) RETURNS void LANGUAGE sql AS $$
  INSERT INTO watchlist_item_domain_value (item_id, value_kind, current_value, current_value_sha256)
  SELECT wid.item_id, v.value_kind, v.current_value, encode(sha256(convert_to(v.current_value, 'UTF8')), 'hex')
    FROM watchlist_item_domain AS wid
    JOIN (VALUES ('dns_lookup', 'dns_presence', 'found'), ('dns_lookup', 'ns', 'n1'), ('dns_lookup', 'mx', 'm1'),
                 ('dns_lookup', 'ip_address_reachability', 'public'), ('dns_lookup', 'cname_takeover', 'none'), ('dns_lookup', 'email_auth', 'pp'),
                 ('dns_lookup', 'hosting', 'AS1'), ('ssl_check', 'certificate_expiry', E'none\n2027-01-01T00:00:00Z'),
                 ('ssl_check', 'certificate_validity', 'valid'), ('ssl_check', 'certificate_listing', 'not_listed'),
                 ('ssl_check', 'tls_protocol', 'TLSv1.3')) AS v (endpoint_name, value_kind, current_value)
      ON v.endpoint_name = wid.endpoint_name
   WHERE wid.domain_name = p_domain_name
  ON CONFLICT DO NOTHING;
  UPDATE watchlist_item_domain AS wid SET next_scan_at = now() + interval '1 day' WHERE wid.domain_name = p_domain_name;
  UPDATE domain_watch_lane AS dwl
     SET claimed_until = now() + interval '5 minutes', claimed_at = now() - interval '1 minute', scanned_at = now() - interval '1 hour',
         not_before = now() - interval '2 minutes'
   WHERE dwl.domain_name = p_domain_name AND dwl.lane_name = 'dns';
  UPDATE domain_watch_lane AS dwl
     SET claimed_until = now() + interval '6 minutes', claimed_at = now() - interval '3 minutes', scanned_at = now() - interval '2 hours'
   WHERE dwl.domain_name = p_domain_name AND dwl.lane_name <> 'dns';
$$;

DO $$
DECLARE
  dns_kinds    CONSTANT text := 'cname_takeover,dns_presence,email_auth,hosting,ip_address_reachability,mx,ns';
  tls_kinds    CONSTANT text := 'certificate_expiry,certificate_listing,certificate_validity,tls_protocol';
  domain_state text;
  before_add   timestamptz;
BEGIN
  ASSERT pg_temp.t_edit('A', NULL, NULL, p_is_cleared => true) = 'ok' AND pg_temp.t_edit('B', NULL, NULL, p_is_cleared => true) = 'ok',
         'S29 the clear before the adds answers ok';
  ASSERT pg_temp.t_edit('A', 'add', 'dns_lookup', p_domain_name => 'r.wl.example') = 'ok'
     AND pg_temp.t_edit('B', 'add', 'dns_lookup', p_domain_name => 'r.wl.example') = 'ok'
     AND pg_temp.t_edit('A', 'add', 'ssl_check', p_domain_name => 'r.wl.example') = 'ok'
     AND pg_temp.t_edit('A', 'add', 'cve_lookup', p_cve_id => 'CVE-2006-0001') = 'ok',
         'S29 the items of r.wl.example are added';
  PERFORM pg_temp.t_fill_items('r.wl.example');
  domain_state := pg_temp.t_domain_state('r.wl.example');
  ASSERT pg_temp.t_item_state('r.wl.example') = 'A:dns_lookup:1 day:' || dns_kinds || ' B:dns_lookup:1 day:' || dns_kinds
                                                  || ' A:ssl_check:1 day:' || tls_kinds,
         'S29 each item of r.wl.example holds the values of its lane';

  ASSERT pg_temp.t_edit('A', 'remove', 'cve_lookup', p_cve_id => 'CVE-2006-0001') = 'ok'
     AND pg_temp.t_domain_state('r.wl.example') = domain_state
     AND pg_temp.t_item_state('r.wl.example') = 'A:dns_lookup:1 day:' || dns_kinds || ' B:dns_lookup:1 day:' || dns_kinds
                                                  || ' A:ssl_check:1 day:' || tls_kinds,
         'S29 the remove of a cve_lookup item changes no domain item and no scan state';
  ASSERT pg_temp.t_edit('A', 'remove', 'dns_lookup', p_domain_name => 'r.wl.example') = 'ok'
     AND pg_temp.t_domain_state('r.wl.example') = domain_state
     AND pg_temp.t_item_state('r.wl.example') = 'B:dns_lookup:1 day:' || dns_kinds || ' A:ssl_check:1 day:' || tls_kinds,
         'S29 the remove of key A''s dns_lookup item deletes that item with its values, and leaves the others and the scan state';
  ASSERT (SELECT count(*) FROM watchlist_item_domain_value AS widv JOIN watchlist_item_domain AS wid ON wid.item_id = widv.item_id
           WHERE wid.domain_name = 'r.wl.example') = 11,
         'S29 the values of the removed item went with it';

  before_add := clock_timestamp();
  ASSERT pg_temp.t_edit('A', 'add', 'dns_lookup', p_domain_name => 'r.wl.example') = 'ok'
     AND pg_temp.t_domain_state('r.wl.example') = domain_state
     AND pg_temp.t_item_state('r.wl.example', 'A') = 'B:dns_lookup:1 day:' || dns_kinds,
         'S29 an add writes no time of the domain row or the lane rows, and leaves the item of key B';
  ASSERT (SELECT string_agg(ic.endpoint_name || ':' || (ic.next_scan_at > before_add AND ic.next_scan_at < clock_timestamp()) || ':'
                            || (SELECT count(*) FROM watchlist_item_domain_value AS widv WHERE widv.item_id = ic.item_id), ' ' ORDER BY ic.item_id)
            FROM t_item_column AS ic WHERE ic.api_key_id = pg_temp.t_key_id('A') AND ic.domain_name = 'r.wl.example')
         = 'ssl_check:false:4 dns_lookup:true:0',
         'S29 the new item is due at the clock of its add with no value, and key A''s other item keeps its time and its values';
  PERFORM pg_temp.t_fill_items('r.wl.example');
  domain_state := pg_temp.t_domain_state('r.wl.example');
  ASSERT pg_temp.t_edit('A', 'add', 'ssl_check', p_domain_name => 'r.wl.example') = 'ok'
     AND pg_temp.t_domain_state('r.wl.example') = domain_state
     AND pg_temp.t_item_state('r.wl.example') = 'B:dns_lookup:1 day:' || dns_kinds || ' A:ssl_check:1 day:' || tls_kinds
                                                  || ' A:dns_lookup:1 day:' || dns_kinds,
         'S29 an add of an item the list already holds changes nothing';
  ASSERT pg_temp.t_edit('B', 'add', 'ssl_check', p_domain_name => 'r.wl.example') = 'ok'
     AND pg_temp.t_domain_state('r.wl.example') = domain_state
     AND pg_temp.t_item_state('r.wl.example', 'B') = 'A:ssl_check:1 day:' || tls_kinds || ' A:dns_lookup:1 day:' || dns_kinds,
         'S29 an ssl_check add beside another key''s ssl_check item writes no lane time and leaves the items of key A';

  PERFORM pg_temp.t_fill_items('r.wl.example');
  domain_state := pg_temp.t_domain_state('r.wl.example');
  ASSERT pg_temp.t_edit('A', NULL, NULL, p_is_cleared => true) = 'ok'
     AND pg_temp.t_domain_state('r.wl.example') = domain_state
     AND pg_temp.t_item_state('r.wl.example') = 'B:dns_lookup:1 day:' || dns_kinds || ' B:ssl_check:1 day:' || tls_kinds,
         'S29 a clear of key A deletes its items and leaves the items of key B and the scan state';
  ASSERT pg_temp.t_edit('B', NULL, NULL, p_is_cleared => true) = 'ok' AND pg_temp.t_domain_state('r.wl.example') = domain_state
     AND pg_temp.t_item_state('r.wl.example') = '',
         'S29 a clear of the last items leaves the domain row and the lane rows';
END
$$;

INSERT INTO t_watchlist_key VALUES ('C', repeat('9c', 32));
INSERT INTO api_keys (key_hash) VALUES (repeat('9c', 32));
DO $$
DECLARE
  dns_kinds    CONSTANT text := 'cname_takeover,dns_presence,email_auth,hosting,ip_address_reachability,mx,ns';
  domain_state text;
BEGIN
  ASSERT pg_temp.t_edit('C', 'add', 'dns_lookup', p_domain_name => 'p.wl.example') = 'ok'
     AND pg_temp.t_edit('C', 'add', 'ssl_check', p_domain_name => 'p.wl.example') = 'ok'
     AND pg_temp.t_edit('A', 'add', 'dns_lookup', p_domain_name => 'p.wl.example') = 'ok', 'S29 keys C and A add their items of p.wl.example';
  PERFORM pg_temp.t_fill_items('p.wl.example');
  domain_state := pg_temp.t_domain_state('p.wl.example');
  UPDATE api_keys AS ak SET expires_at = now() - interval '31 days' WHERE ak.key_hash = pg_temp.t_hash('C');
  ASSERT api.fn_watchlist_purge(10) = 1 AND pg_temp.t_item_count('C') = 0, 'S29 the purge clears key C, which expired 31 days ago';
  ASSERT pg_temp.t_domain_state('p.wl.example') = domain_state AND pg_temp.t_item_state('p.wl.example') = 'A:dns_lookup:1 day:' || dns_kinds,
         'S29 the purge deletes the items of key C with their values, and leaves key A''s item and the scan state';

  UPDATE api_keys AS ak SET expires_at = NULL WHERE ak.key_hash = pg_temp.t_hash('C');
  ASSERT pg_temp.t_edit('C', 'add', 'dns_lookup', p_domain_name => 'k.wl.example') = 'ok'
     AND pg_temp.t_edit('C', 'add', 'ssl_check', p_domain_name => 'k.wl.example') = 'ok', 'S29 key C adds its two items of k.wl.example';
  PERFORM pg_temp.t_fill_items('k.wl.example');
  domain_state := pg_temp.t_domain_state('k.wl.example');
  DELETE FROM api_keys AS ak WHERE ak.key_hash = pg_temp.t_hash('C');
  ASSERT NOT EXISTS (SELECT 1 FROM watchlist_item_domain AS wid WHERE wid.domain_name = 'k.wl.example')
     AND NOT EXISTS (SELECT 1 FROM watchlist_item_domain_value AS widv WHERE widv.item_id NOT IN (SELECT wid.item_id FROM watchlist_item_domain AS wid))
     AND pg_temp.t_domain_state('k.wl.example') = domain_state,
         'S29 the delete of key C deletes its items and their values, and leaves the scan state of k.wl.example';
  ASSERT pg_temp.t_edit('A', NULL, NULL, p_is_cleared => true) = 'ok', 'S29 the clear after the adds answers ok';
END
$$;


DO $$
DECLARE
  name_index integer;
BEGIN
  ASSERT pg_temp.t_edit('A', NULL, NULL, p_is_cleared => true) = 'ok' AND pg_temp.t_edit('B', NULL, NULL, p_is_cleared => true) = 'ok',
         'S30 the clear before the cap answers ok';
  FOR name_index IN 1..19 LOOP
    ASSERT pg_temp.t_edit('A', 'add', 'dns_lookup', p_domain_name => 'n' || name_index || '.cap.example') = 'ok'
       AND pg_temp.t_edit('A', 'add', 'ssl_check', p_domain_name => 'n' || name_index || '.cap.example') = 'ok',
           'S30 key A adds both items of name ' || name_index;
  END LOOP;
  ASSERT pg_temp.t_item_count('A') = 38, 'S30 key A holds 38 items of 19 names';
  ASSERT pg_temp.t_edit('B', 'add', 'ssl_check', p_domain_name => 'x20.cap.example') = 'ok', 'S30 key B adds x20.cap.example';
  ASSERT pg_temp.t_edit('A', 'add', 'ssl_check', p_domain_name => 'n20.cap.example') = 'ok',
         'S30 the 20th name answers ok: 38 items count as 19 names';
  ASSERT pg_temp.t_edit('A', 'add', 'dns_lookup', p_domain_name => 'n20.cap.example') = 'ok',
         'S30 a name the key watches through ssl_check is not counted again by its dns_lookup add';
  ASSERT pg_temp.t_edit('A', 'add', 'dns_lookup', p_domain_name => 'n21.cap.example') = 'over_domain_limit',
         'S30 the 21st name answers over_domain_limit';
  ASSERT pg_temp.t_edit('A', 'add', 'ssl_check', p_domain_name => 'x20.cap.example') = 'over_domain_limit',
         'S30 a name that only another key watches is counted';
  ASSERT pg_temp.t_item_count('A') = 40 AND NOT EXISTS (SELECT 1 FROM domain_watch AS dw WHERE dw.domain_name = 'n21.cap.example'),
         'S30 over_domain_limit inserts no item and no domain_watch row';
  ASSERT pg_temp.t_edit('A', NULL, NULL, p_is_cleared => true) = 'ok' AND pg_temp.t_edit('B', NULL, NULL, p_is_cleared => true) = 'ok',
         'S30 the clear after the cap answers ok';
END
$$;


CREATE FUNCTION pg_temp.t_scan(p_endpoint_name text, p_domain_name text, p_values text[]) RETURNS integer LANGUAGE plpgsql AS $$
DECLARE
  sha256s text[] := ARRAY(SELECT encode(sha256(convert_to(v.value, 'UTF8')), 'hex') FROM unnest(p_values) WITH ORDINALITY AS v (value, n) ORDER BY v.n);
BEGIN
  IF p_endpoint_name = 'ssl_check' THEN
    UPDATE domain_watch_lane AS dwl SET claimed_until = now() + interval '10 minutes', claimed_at = now() + interval '2 days'
     WHERE dwl.domain_name = p_domain_name AND dwl.lane_name = 'tls';
    RETURN api.fn_domain_watch_record_tls(p_domain_name, now() + interval '10 minutes', p_values[1], sha256s[1], p_values[2], sha256s[2],
                                          p_values[3], sha256s[3], p_values[4], sha256s[4]);
  END IF;
  UPDATE domain_watch_lane AS dwl SET claimed_until = now() + interval '10 minutes', claimed_at = now() + interval '2 days'
   WHERE dwl.domain_name = p_domain_name AND dwl.lane_name = 'dns';
  RETURN api.fn_domain_watch_record_dns(p_domain_name, now() + interval '10 minutes', p_values[1], sha256s[1], NULL, NULL, NULL, NULL,
                                        p_values[2], sha256s[2], NULL, NULL, NULL, NULL, NULL, NULL, 40);
END
$$;
CREATE FUNCTION pg_temp.t_read(p_label text, p_domain_name text) RETURNS text[] LANGUAGE sql AS $$
  SELECT coalesce(array_agg(dce.event_type || ':' || coalesce(dce.previous_value, 'null') || '>' || dce.current_value ORDER BY dce.event_id), '{}')
    FROM watchlist_event_ref AS wer
    JOIN domain_change_event AS dce ON dce.event_id = wer.event_id
   WHERE wer.api_key_id = pg_temp.t_key_id(p_label) AND dce.domain_name = p_domain_name
$$;
CREATE FUNCTION pg_temp.t_map(p_label text, p_domain_name text) RETURNS text LANGUAGE sql AS $$
  SELECT pg_temp.t_rewind(p_label, api.fn_cve_change_event_max_id());
  SELECT string_agg(coalesce(x.registered_domain, 'null') || '|' || coalesce(x.dns_presence_value, 'null') || '|'
                    || coalesce(x.ip_address_reachability_value, 'null'), ',')
    FROM api.fn_watchlist_events(pg_temp.t_hash(p_label), NULL, false, 100, 100, 600) AS x
   WHERE x.item_domain_name = p_domain_name AND x.is_first_event_of_domain;
$$;

DO $$
DECLARE
  tls_problem   CONSTANT text[] := ARRAY['none', 'expired', 'not_listed', 'TLSv1'];
  tls_clean     CONSTANT text[] := ARRAY['none', 'valid', 'not_listed', 'TLSv1.3'];
  tls_events    CONSTANT text[] := ARRAY['cert_invalid:null>expired', 'tls_downgraded:null>TLSv1'];
  alone_answer  text;
  beside_answer text;
BEGIN
  ASSERT pg_temp.t_edit('A', NULL, NULL, p_is_cleared => true) = 'ok' AND pg_temp.t_edit('B', NULL, NULL, p_is_cleared => true) = 'ok',
         'S31 the clear before the first scans answers ok';

  alone_answer := pg_temp.t_edit('B', 'add', 'ssl_check', p_domain_name => 'f1.wl.example');
  ASSERT pg_temp.t_scan('ssl_check', 'f1.wl.example', tls_problem) = 2 AND pg_temp.t_read('B', 'f1.wl.example') = tls_events,
         'S31 an item added alone reads the problems of its first scan';

  ASSERT pg_temp.t_edit('A', 'add', 'ssl_check', p_domain_name => 'f2.wl.example') = 'ok'
     AND pg_temp.t_scan('ssl_check', 'f2.wl.example', tls_clean) = 0, 'S31 key A watches f2.wl.example, and its first scan shows no problem';
  beside_answer := pg_temp.t_edit('B', 'add', 'ssl_check', p_domain_name => 'f2.wl.example');
  ASSERT beside_answer = alone_answer AND pg_temp.t_items('B') = ARRAY['ssl_check:f1.wl.example', 'ssl_check:f2.wl.example'],
         'S31 the add beside an older watcher answers as the add alone, and the answer shows no state of either name';
  ASSERT pg_temp.t_scan('ssl_check', 'f2.wl.example', tls_problem) = 2 AND pg_temp.t_read('B', 'f2.wl.example') = tls_events,
         'S31 an item added beside an older watcher reads the same events as one added alone';
  ASSERT pg_temp.t_read('A', 'f2.wl.example') = '{}', 'S31 the older watcher reads none of them';

  ASSERT pg_temp.t_scan('ssl_check', 'f1.wl.example', tls_problem) = 0 AND pg_temp.t_read('B', 'f1.wl.example') = tls_events,
         'S31 a second scan writes no first-value event for the item';
  ASSERT pg_temp.t_edit('B', 'remove', 'ssl_check', p_domain_name => 'f1.wl.example') = 'ok'
     AND pg_temp.t_read('B', 'f1.wl.example') = '{}', 'S31 a remove takes the refs of the item with it';
  ASSERT pg_temp.t_edit('B', 'add', 'ssl_check', p_domain_name => 'f1.wl.example') = 'ok', 'S31 key B adds f1.wl.example again';
  ASSERT NOT EXISTS (SELECT 1 FROM watchlist_item_domain_value AS widv JOIN watchlist_item_domain AS wid ON wid.item_id = widv.item_id
                      WHERE wid.domain_name = 'f1.wl.example'),
         'S31 a remove and a new add start from no value';
  ASSERT pg_temp.t_scan('ssl_check', 'f1.wl.example', tls_problem) = 2 AND pg_temp.t_read('B', 'f1.wl.example') = tls_events,
         'S31 the item added again reads the problems of its new first scan, and none of the scan of the old item';

  ASSERT pg_temp.t_edit('B', 'add', 'ssl_check', p_domain_name => 'f3.wl.example') = 'ok'
     AND pg_temp.t_scan('ssl_check', 'f3.wl.example', ARRAY[NULL, NULL, NULL, NULL]) = 0, 'S31 key B adds f3.wl.example, and its scan reads no value';
  ASSERT NOT EXISTS (SELECT 1 FROM watchlist_item_domain_value AS widv JOIN watchlist_item_domain AS wid ON wid.item_id = widv.item_id
                      WHERE wid.domain_name = 'f3.wl.example'),
         'S31 a scan that read no value writes no event and no value';
  ASSERT pg_temp.t_scan('ssl_check', 'f3.wl.example', tls_problem) = 2 AND pg_temp.t_read('B', 'f3.wl.example') = tls_events,
         'S31 the next scan that reads values writes the first values of the item';

  ASSERT pg_temp.t_edit('A', 'add', 'ssl_check', p_domain_name => 'f4.wl.example') = 'ok'
     AND pg_temp.t_scan('ssl_check', 'f4.wl.example', tls_problem) = 2,
         'S31 key A watches f4.wl.example, and its item stores the TLS problems';
  ASSERT pg_temp.t_edit('B', 'add', 'ssl_check', p_domain_name => 'f4.wl.example') = 'ok'
     AND pg_temp.t_scan('ssl_check', 'f4.wl.example', tls_clean) = 0 AND pg_temp.t_read('B', 'f4.wl.example') = '{}',
         'S31 a value with a problem that another item stores writes no event when the item''s own first value shows none';

  ASSERT pg_temp.t_edit('A', 'add', 'dns_lookup', p_domain_name => 'f2.wl.example') = 'ok'
     AND pg_temp.t_scan('dns_lookup', 'f2.wl.example', ARRAY['found', 'public']) = 0,
         'S31 key A watches f2.wl.example through dns_lookup too, and its DNS scan stores found';
  INSERT INTO watchlist_item_domain_value (item_id, value_kind, current_value, current_value_sha256)
  SELECT ic.item_id, 'dns_presence', 'ssl-row', repeat('0', 64) FROM t_item_column AS ic
   WHERE ic.api_key_id = pg_temp.t_key_id('B') AND ic.domain_name = 'f2.wl.example' AND ic.endpoint_name = 'ssl_check';
  ASSERT pg_temp.t_map('B', 'f2.wl.example') = 'wl.example|null|null',
         'S31 the map of a key with only an ssl_check item shows no DNS value, though another key''s item stores one, and reads no row of the ssl_check item';
  ASSERT pg_temp.t_edit('B', 'add', 'dns_lookup', p_domain_name => 'f2.wl.example', p_registered_domain => 'zz.example') = 'ok'
     AND pg_temp.t_map('B', 'f2.wl.example') = 'wl.example|null|null',
         'S31 the map of a key whose dns_lookup item no scan has served yet shows no DNS value';
  ASSERT pg_temp.t_scan('dns_lookup', 'f2.wl.example', ARRAY['found', 'public']) = 0
     AND pg_temp.t_map('B', 'f2.wl.example') = 'wl.example|found|public',
         'S31 the scan that serves the dns_lookup item of the key fills its map, and the map keeps the registered domain of the key''s older item';

  ASSERT pg_temp.t_edit('A', 'add', 'dns_lookup', p_domain_name => 'dfs.wl.example') = 'ok'
     AND pg_temp.t_edit('A', 'add', 'ssl_check', p_domain_name => 'dfs.wl.example') = 'ok'
     AND pg_temp.t_scan('dns_lookup', 'dfs.wl.example', ARRAY['found', 'public']) = 0,
         'S31 key A watches dfs.wl.example, and its first DNS scan shows no problem';
  ASSERT (SELECT string_agg(ic.endpoint_name || '=' || (SELECT count(*) FROM watchlist_item_domain_value AS widv WHERE widv.item_id = ic.item_id), ','
                            ORDER BY ic.item_id)
            FROM t_item_column AS ic WHERE ic.domain_name = 'dfs.wl.example') = 'dns_lookup=2,ssl_check=0',
         'S31 a DNS scan writes values of the dns_lookup items only';
  ASSERT pg_temp.t_edit('B', 'add', 'dns_lookup', p_domain_name => 'dfs.wl.example') = 'ok'
     AND pg_temp.t_scan('dns_lookup', 'dfs.wl.example', ARRAY['not_found', 'not_public']) = 2
     AND pg_temp.t_read('B', 'dfs.wl.example') = '{domain_not_found:null>not_found,ip_address_not_public:null>not_public}',
         'S31 a dns_lookup item added beside an older watcher reads the DNS problems of its first scan';
  ASSERT pg_temp.t_read('A', 'dfs.wl.example') = '{}', 'S31 the older DNS watcher reads none of them, and the ssl_check item none either';
  ASSERT pg_temp.t_edit('A', NULL, NULL, p_is_cleared => true) = 'ok' AND pg_temp.t_edit('B', NULL, NULL, p_is_cleared => true) = 'ok',
         'S31 the clear after the first scans answers ok';
END
$$;

DO $$
DECLARE
  domain_state text;
  item_state   text;
BEGIN
  ASSERT pg_temp.t_edit('A', 'add', 'dns_lookup', p_domain_name => 'o2.wl.example') = 'ok', 'S32 key A watches o2.wl.example';
  PERFORM pg_temp.t_fill_items('o2.wl.example');
  domain_state := pg_temp.t_domain_state('o2.wl.example');
  item_state := pg_temp.t_item_state('o2.wl.example');
  ASSERT pg_temp.t_edit('A', 'add', 'dns_lookup', p_domain_name => 'p2.wl.example') = 'ok'
     AND pg_temp.t_edit('A', 'add', 'ssl_check', p_domain_name => 'p2.wl.example') = 'ok'
     AND pg_temp.t_domain_state('o2.wl.example') = domain_state AND pg_temp.t_item_state('o2.wl.example') = item_state,
         'S32 the adds of p2.wl.example leave the scan state and the item of o2.wl.example as they were';
  ASSERT pg_temp.t_edit('A', NULL, NULL, p_is_cleared => true) = 'ok', 'S32 the clear answers ok';
END
$$;

CREATE FUNCTION pg_temp.t_items_whole() RETURNS boolean LANGUAGE sql AS $$
  SELECT coalesce(bool_and((wi.endpoint_name IN ('dns_lookup', 'ssl_check', 'whois_lookup')) = (wid.item_id IS NOT NULL)
                           AND (wi.endpoint_name IN ('dns_lookup', 'ssl_check', 'whois_lookup')) = (wic.item_id IS NULL)), true)
    FROM watchlist_item AS wi
    LEFT JOIN watchlist_item_cve AS wic ON wic.item_id = wi.item_id
    LEFT JOIN watchlist_item_domain AS wid ON wid.item_id = wi.item_id
$$;
DO $$
DECLARE
  endpoint_label text;
  a_item_id      bigint;
BEGIN
  ASSERT pg_temp.t_edit('A', 'add', 'cve_lookup', p_cve_id => 'CVE-2006-0001') = 'ok'
     AND pg_temp.t_edit('A', 'add', 'kev_lookup', p_cve_id => 'CVE-2006-0001') = 'ok'
     AND pg_temp.t_edit('A', 'add', 'cve_exploit', p_cve_id => 'CVE-2006-0001') = 'ok'
     AND pg_temp.t_edit('A', 'add', 'product_exposure', p_vendor => 'wlacme', p_product => 'wlwidget') = 'ok'
     AND pg_temp.t_edit('A', 'add', 'cve_search', p_min_cvss => 7.5) = 'ok'
     AND pg_temp.t_edit('A', 'add', 'dns_lookup', p_domain_name => 'w.wl.example') = 'ok'
     AND pg_temp.t_edit('A', 'add', 'ssl_check', p_domain_name => 'w.wl.example') = 'ok'
     AND pg_temp.t_edit('B', 'add', 'dns_lookup', p_domain_name => 'w.wl.example') = 'ok',
         'S33 key A adds one item of each endpoint but whois_lookup, and key B one domain item';
  ASSERT pg_temp.t_items_whole()
     AND (SELECT count(*) FROM watchlist_item_cve AS wic WHERE wic.api_key_id IN (pg_temp.t_key_id('A'), pg_temp.t_key_id('B'))) = 5
     AND (SELECT count(*) FROM watchlist_item_domain AS wid WHERE wid.api_key_id IN (pg_temp.t_key_id('A'), pg_temp.t_key_id('B'))) = 3,
         'S33 each item has the one child row of its endpoint';
  a_item_id := (SELECT ic.item_id FROM t_item_column AS ic WHERE ic.api_key_id = pg_temp.t_key_id('A') AND ic.endpoint_name = 'dns_lookup');
  INSERT INTO watchlist_item_domain_value (item_id, value_kind, current_value, current_value_sha256) VALUES (a_item_id, 'ns', 'n', repeat('0', 64));
  INSERT INTO domain_change_event (event_id, domain_name, event_type) OVERRIDING SYSTEM VALUE VALUES (9999, 'w.wl.example', 'ns_changed');
  INSERT INTO watchlist_event_ref (api_key_id, item_id, event_id)
  SELECT wid.api_key_id, wid.item_id, 9999 FROM watchlist_item_domain AS wid WHERE wid.domain_name = 'w.wl.example';
  ASSERT pg_temp.t_edit('B', 'remove', 'ssl_check', p_domain_name => 'w.wl.example') = 'ok', 'S33 key B removes an ssl_check item it does not hold';
  ASSERT pg_temp.t_item_count('A') = 7 AND (SELECT count(*) FROM watchlist_event_ref AS wer WHERE wer.event_id = 9999) = 3,
         'S33 key B removing the ssl_check item that only key A holds deletes nothing';
  ASSERT pg_temp.t_edit('A', 'remove', 'dns_lookup', p_domain_name => 'w.wl.example') = 'ok', 'S33 key A removes its dns_lookup item';
  ASSERT NOT EXISTS (SELECT 1 FROM watchlist_item_domain AS wid WHERE wid.item_id = a_item_id)
     AND NOT EXISTS (SELECT 1 FROM watchlist_item_domain_value AS widv WHERE widv.item_id = a_item_id)
     AND (SELECT array_agg(wer.item_id ORDER BY wer.item_id) FROM watchlist_event_ref AS wer WHERE wer.event_id = 9999)
         = (SELECT array_agg(wid.item_id ORDER BY wid.item_id) FROM watchlist_item_domain AS wid WHERE wid.domain_name = 'w.wl.example'),
         'S33 the remove of a domain item deletes its child row, its value rows and its refs, and leaves the refs of the other items';
  ASSERT pg_temp.t_items_whole(), 'S33 every item keeps its one child row after the remove';
  FOREACH endpoint_label IN ARRAY ARRAY['cve_lookup', 'kev_lookup', 'cve_exploit'] LOOP
    ASSERT pg_temp.t_edit('A', 'remove', endpoint_label, p_cve_id => 'CVE-2006-0001') = 'ok' AND pg_temp.t_items_whole(),
           'S33 the remove of the ' || endpoint_label || ' item leaves every item whole';
  END LOOP;
  ASSERT pg_temp.t_edit('A', 'remove', 'product_exposure', p_vendor => 'wlacme', p_product => 'wlwidget') = 'ok'
     AND pg_temp.t_edit('A', 'remove', 'cve_search', p_min_cvss => 7.5) = 'ok', 'S33 key A removes its product_exposure and its cve_search item';
  ASSERT pg_temp.t_items_whole()
     AND (SELECT count(*) FROM watchlist_item_cve AS wic WHERE wic.api_key_id = pg_temp.t_key_id('A')) = 0,
         'S33 the removes of the product_exposure and the cve_search item delete their child rows';
  ASSERT pg_temp.t_event_cursor('A') <> 'none', 'S33 key A still holds its ssl_check item and its position';
  ASSERT pg_temp.t_edit('A', 'remove', 'ssl_check', p_domain_name => 'w.wl.example') = 'ok', 'S33 key A removes its last item';
  ASSERT pg_temp.t_item_count('A') = 0 AND pg_temp.t_event_cursor('A') = 'none'
     AND NOT EXISTS (SELECT 1 FROM watchlist_item_domain AS wid WHERE wid.api_key_id = pg_temp.t_key_id('A')),
         'S33 the remove of the last item deletes its child row and the position';
  ASSERT pg_temp.t_edit('B', NULL, NULL, p_is_cleared => true) = 'ok', 'S33 key B clears its list';
  ASSERT pg_temp.t_items_whole()
     AND NOT EXISTS (SELECT 1 FROM watchlist_item_domain AS wid WHERE wid.domain_name = 'w.wl.example')
     AND NOT EXISTS (SELECT 1 FROM watchlist_event_ref AS wer WHERE wer.event_id = 9999),
         'S33 a clear deletes the child rows and the refs of the items of the key';
  DELETE FROM domain_change_event AS dce WHERE dce.event_id = 9999;
END
$$;

DO $$
DECLARE
  f             record;
  edit_source   text := regexp_replace(pg_get_functiondef('api.fn_watchlist_item_edit(text, text, text, text, text, text, text, text, real, real, boolean, boolean, boolean, integer, text, text, integer, text, text, text, integer, integer, integer, integer, inet)'::regprocedure), '--[^\n]*', '', 'g');
  events_source text := regexp_replace(pg_get_functiondef('api.fn_watchlist_events(text, bigint, boolean, integer, integer, integer)'::regprocedure), '--[^\n]*', '', 'g');
  key_state_lock_at integer;
BEGIN
  FOR f IN SELECT * FROM (VALUES
      ('api.fn_watchlist_item_edit(text, text, text, text, text, text, text, text, real, real, boolean, boolean, boolean, integer, text, text, integer, text, text, text, integer, integer, integer, integer, inet)'::regprocedure, 'v', false),
      ('api.fn_watchlist_edit_cve_lookup(text, text, text, integer)'::regprocedure, 'v', true),
      ('api.fn_watchlist_edit_kev_lookup(text, text, text, integer)'::regprocedure, 'v', true),
      ('api.fn_watchlist_edit_cve_exploit(text, text, text, integer)'::regprocedure, 'v', true),
      ('api.fn_watchlist_edit_product_exposure(text, text, text, text, text, integer)'::regprocedure, 'v', true),
      ('api.fn_watchlist_edit_cve_search(text, text, text, text, text, text, real, real, boolean, boolean, boolean, integer)'::regprocedure, 'v', true),
      ('api.fn_watchlist_edit_dns_lookup(text, text, text, text, integer, integer)'::regprocedure, 'v', true),
      ('api.fn_watchlist_edit_ssl_check(text, text, text, text, integer, integer)'::regprocedure, 'v', true),
      ('api.fn_watchlist_edit_whois_lookup(text, text, text, text, integer, integer)'::regprocedure, 'v', true),
      ('api.fn_watchlist_edit_headers_check(text, text, text, text, integer, integer)'::regprocedure, 'v', true),
      ('api.fn_watchlist_edit_cert_search(text, text, text, text, integer, integer)'::regprocedure, 'v', true),
      ('api.fn_watchlist_edit_package_check(text, text, text, text, text, integer, integer, integer, integer)'::regprocedure, 'v', true),
      ('api.fn_watchlist_edit_ip_lookup(text, text, inet, integer)'::regprocedure, 'v', true),
      ('api.fn_watchlist_package_list_edit(text, text, text[], text[], text[], integer, integer, integer, integer)'::regprocedure, 'v', true),
      ('api.fn_watchlist_list(text)'::regprocedure, 'v', true),
      ('api.fn_watchlist_clear(text)'::regprocedure, 'v', true),
      ('api.fn_watchlist_events(text, bigint, boolean, integer, integer, integer)'::regprocedure, 'v', true),
      ('api.fn_watchlist_event_scan(integer, bigint, bigint, integer, integer, integer)'::regprocedure, 's', false),
      ('api.fn_watchlist_event_item_pairs(integer, bigint[])'::regprocedure, 's', false),
      ('api.fn_watchlist_event_package_pairs(integer, bigint[])'::regprocedure, 's', false),
      ('api.fn_watchlist_event_eol_pairs(integer, bigint[])'::regprocedure, 's', false),
      ('api.fn_watchlist_event_rows(integer, bigint, bigint)'::regprocedure, 's', false),
      ('api.fn_watchlist_cve_facts(text)'::regprocedure, 's', false),
      ('api.fn_watchlist_event_max_id()'::regprocedure, 's', false),
      ('api.fn_watchlist_purge(integer)'::regprocedure, 'v', true),
      ('api.fn_watchlist_event_ref_purge(bigint[], boolean)'::regprocedure, 'v', false),
      ('api.fn_watchlist_endpoint_event_types(text)'::regprocedure, 'i', false),
      ('api.fn_watchlist_endpoint_value_kinds(text)'::regprocedure, 'i', false),
      ('api.fn_watchlist_item_product_has_cves(text, text, text)'::regprocedure, 's', false),
      ('api.fn_watchlist_event_shown_type(text, real, real)'::regprocedure, 'i', false)) AS t (oid, volatility, is_definer) LOOP
    ASSERT (SELECT p.prosecdef FROM pg_proc AS p WHERE p.oid = f.oid) = f.is_definer,
           f.oid::text || CASE WHEN f.is_definer THEN ' is SECURITY DEFINER' ELSE ' is SECURITY INVOKER' END;
    ASSERT (SELECT p.proconfig FROM pg_proc AS p WHERE p.oid = f.oid) = ARRAY['search_path=pg_catalog'],
           f.oid::text || ' sets search_path to pg_catalog';
    ASSERT (SELECT p.provolatile FROM pg_proc AS p WHERE p.oid = f.oid) = f.volatility,
           f.oid::text || ' has the volatility ' || f.volatility;
  END LOOP;
  ASSERT (SELECT p.proisstrict FROM pg_proc AS p WHERE p.oid = 'api.fn_watchlist_purge(integer)'::regprocedure),
         'api.fn_watchlist_purge is STRICT';
  ASSERT (SELECT p.proisstrict FROM pg_proc AS p WHERE p.oid = 'api.fn_watchlist_event_ref_purge(bigint[], boolean)'::regprocedure),
         'api.fn_watchlist_event_ref_purge is STRICT';
  ASSERT (SELECT count(*) FROM pg_proc AS p WHERE p.pronamespace = 'api'::regnamespace AND p.proname LIKE 'fn\_watchlist\_%') = 30,
         'sql/fn_watchlist.sql holds thirty api functions, and the list above names each';
  ASSERT edit_source ~ 'FROM public\.api_keys AS ak WHERE ak\.key_hash = p_key_hash FOR UPDATE;.*INSERT INTO public\.watchlist_event_cursor .*ON CONFLICT ON CONSTRAINT domain_watch_pkey DO UPDATE SET domain_name = EXCLUDED\.domain_name;.*ON CONFLICT ON CONSTRAINT domain_watch_lane_pkey DO UPDATE SET lane_name = EXCLUDED\.lane_name;.*INSERT INTO public\.watchlist_item \(api_key_id, endpoint_name\).*INSERT INTO public\.watchlist_item_domain ',
         'the add of a domain item locks the key row, opens the position, locks the domain row and the row of its lane, then inserts the item and its child row';
  ASSERT edit_source ~ 'item_lane_name\s+text\s+:= \(SELECT l\.lane_name FROM api\.fn_domain_watch_lanes\(\) AS l WHERE l\.endpoint_name = p_endpoint_name\);\s+is_domain_item\s+boolean := item_lane_name IS NOT NULL;',
         'the edit reads the lane of an endpoint from the lane map, and an endpoint with a lane is a domain endpoint';
  ASSERT edit_source !~ '(watchlist_item_domain_value|UPDATE public\.domain_watch|UPDATE public\.watchlist_item_domain|next_scan_at =)',
         'the edit writes no value row, no time of a lane and no time of another item';
  key_state_lock_at := strpos(edit_source, 'FROM public.watchlist_key_state AS wks
   WHERE wks.api_key_id = caller_api_key_id FOR UPDATE;');
  ASSERT key_state_lock_at > strpos(edit_source, 'FROM public.api_keys AS ak WHERE ak.key_hash = p_key_hash FOR UPDATE;')
     AND strpos(edit_source, 'FROM public.api_keys AS ak WHERE ak.key_hash = p_key_hash FOR UPDATE;') > 0,
         'the edit locks the key state after the key row';
  ASSERT key_state_lock_at < strpos(edit_source, 'DELETE FROM public.watchlist_item ')
     AND key_state_lock_at < strpos(edit_source, 'INSERT INTO public.watchlist_item ')
     AND key_state_lock_at < strpos(edit_source, 'DELETE FROM public.watchlist_event_cursor ')
     AND key_state_lock_at < strpos(edit_source, 'INSERT INTO public.watchlist_event_cursor '),
         'the edit locks the key state before it deletes or inserts an item or a position';
  ASSERT edit_source !~ 'IF [^;]*THEN\s+SELECT wks\.last_key_event_id INTO caller_last_key_event_id',
         'the edit locks the key state on every path, not inside a branch';
  ASSERT events_source ~ 'FROM public\.api_keys AS ak WHERE ak\.key_hash = p_key_hash FOR NO KEY UPDATE;.*FROM public\.watchlist_key_state AS wks\s+WHERE wks\.api_key_id = caller_api_key_id FOR UPDATE;.*FROM public\.watchlist_event_cursor AS wec\s+WHERE wec\.api_key_id = caller_api_key_id FOR UPDATE;',
         'a call without a replay cursor locks the key row, then the key state, then the position, in the order of the edit';
END
$$;

DO $$
DECLARE
  helper       CONSTANT regprocedure := 'api.fn_watchlist_item_edit(text, text, text, text, text, text, text, text, real, real, boolean, boolean, boolean, integer, text, text, integer, text, text, text, integer, integer, integer, integer, inet)'::regprocedure;
  s49_key_hash CONSTANT text := repeat('c4', 32);
  f            record;
  item         record;
  edit_count   integer := 0;
  answered     text;
  error_text   text;
  list_source  text := regexp_replace(pg_get_functiondef('api.fn_watchlist_list(text)'::regprocedure), '--[^\n]*', '', 'g');
  clear_source text := regexp_replace(pg_get_functiondef('api.fn_watchlist_clear(text)'::regprocedure), '--[^\n]*', '', 'g');
BEGIN
  FOR f IN SELECT * FROM (VALUES
      ('api.fn_watchlist_edit_cve_lookup(text, text, text, integer)', '{p_key_hash,p_action,p_cve_id,p_item_max_count}'),
      ('api.fn_watchlist_edit_kev_lookup(text, text, text, integer)', '{p_key_hash,p_action,p_cve_id,p_item_max_count}'),
      ('api.fn_watchlist_edit_cve_exploit(text, text, text, integer)', '{p_key_hash,p_action,p_cve_id,p_item_max_count}'),
      ('api.fn_watchlist_edit_product_exposure(text, text, text, text, text, integer)', '{p_key_hash,p_action,p_vendor,p_product,p_version,p_item_max_count}'),
      ('api.fn_watchlist_edit_cve_search(text, text, text, text, text, text, real, real, boolean, boolean, boolean, integer)',
       '{p_key_hash,p_action,p_vendor,p_product,p_severity,p_cwe_id,p_min_cvss,p_min_epss,p_in_kev,p_known_ransomware,p_has_nuclei_template,p_item_max_count}'),
      ('api.fn_watchlist_edit_dns_lookup(text, text, text, text, integer, integer)', '{p_key_hash,p_action,p_domain_name,p_registered_domain,p_item_max_count,p_domain_name_max_count}'),
      ('api.fn_watchlist_edit_ssl_check(text, text, text, text, integer, integer)', '{p_key_hash,p_action,p_domain_name,p_registered_domain,p_item_max_count,p_domain_name_max_count}'),
      ('api.fn_watchlist_edit_whois_lookup(text, text, text, text, integer, integer)', '{p_key_hash,p_action,p_domain_name,p_registered_domain,p_item_max_count,p_domain_name_max_count}'),
      ('api.fn_watchlist_edit_headers_check(text, text, text, text, integer, integer)', '{p_key_hash,p_action,p_domain_name,p_registered_domain,p_item_max_count,p_domain_name_max_count}'),
      ('api.fn_watchlist_edit_cert_search(text, text, text, text, integer, integer)', '{p_key_hash,p_action,p_domain_name,p_registered_domain,p_item_max_count,p_domain_name_max_count}'),
      ('api.fn_watchlist_edit_package_check(text, text, text, text, text, integer, integer, integer, integer)',
       '{p_key_hash,p_action,p_ecosystem,p_package_name,p_version,p_package_item_max_count,p_package_item_base_weight,p_package_weight_budget,p_listed_versions_per_weight}'),
      ('api.fn_watchlist_edit_ip_lookup(text, text, inet, integer)', '{p_key_hash,p_action,p_ip_address,p_item_max_count}'),
      ('api.fn_watchlist_list(text)', '{p_key_hash}'),
      ('api.fn_watchlist_clear(text)', '{p_key_hash}'),
      (helper::text, '{p_key_hash,p_action,p_endpoint_name,p_cve_id,p_vendor,p_product,p_severity,p_cwe_id,p_min_cvss,p_min_epss,p_in_kev,p_known_ransomware,p_has_nuclei_template,p_item_max_count,p_domain_name,p_registered_domain,p_domain_name_max_count,p_ecosystem,p_package_name,p_version,p_package_item_max_count,p_package_item_base_weight,p_package_weight_budget,p_listed_versions_per_weight,p_ip_address}'))
      AS t (signature, argument_names) LOOP
    ASSERT (SELECT array_agg(a.name ORDER BY a.n) FROM pg_proc AS p
              CROSS JOIN LATERAL unnest(p.proargnames, p.proargmodes) WITH ORDINALITY AS a (name, mode, n)
             WHERE p.oid = f.signature::regprocedure AND a.mode = 'i') = f.argument_names::text[],
           'S49 ' || f.signature || ' takes the arguments ' || f.argument_names;
  END LOOP;
  ASSERT (SELECT p.pronargdefaults FROM pg_proc AS p WHERE p.oid = helper) = 22,
         'S49 every argument of the item edit after its first three defaults to NULL';

  FOR f IN SELECT p.oid, p.proname::text AS name FROM pg_proc AS p
            WHERE p.pronamespace = 'api'::regnamespace AND p.proname LIKE 'fn\_watchlist\_edit\_%' LOOP
    ASSERT (SELECT p.prolang FROM pg_proc AS p WHERE p.oid = f.oid) = (SELECT l.oid FROM pg_language AS l WHERE l.lanname = 'sql')
       AND (SELECT p.prosqlbody IS NOT NULL FROM pg_proc AS p WHERE p.oid = f.oid),
           'S49 ' || f.name || ' has a SQL-standard body';
    ASSERT NOT EXISTS (SELECT 1 FROM pg_depend AS d WHERE d.classid = 'pg_proc'::regclass AND d.objid = f.oid AND d.refclassid = 'pg_class'::regclass),
           'S49 ' || f.name || ' reads no table, so it takes no lock of its own';
    ASSERT (SELECT array_agg(DISTINCT d.refobjid) FROM pg_depend AS d
             WHERE d.classid = 'pg_proc'::regclass AND d.objid = f.oid AND d.refclassid = 'pg_proc'::regclass) = ARRAY[helper::oid],
           'S49 ' || f.name || ' calls api.fn_watchlist_item_edit and no other function';
    edit_count := edit_count + 1;
  END LOOP;
  ASSERT edit_count = 12, 'S49 there are twelve edit functions';

  ASSERT list_source ~ 'FROM public\.api_keys AS ak WHERE ak\.key_hash = p_key_hash FOR UPDATE;.*FROM public\.watchlist_key_state AS wks\s+WHERE wks\.api_key_id = caller_api_key_id FOR UPDATE;',
         'S49 the list locks the key row, then the key state';
  ASSERT list_source !~ '(INSERT INTO|UPDATE public\.|DELETE FROM)',
         'S49 the list writes nothing';
  ASSERT clear_source ~ 'FROM public\.api_keys AS ak WHERE ak\.key_hash = p_key_hash FOR UPDATE;.*FROM public\.watchlist_key_state AS wks\s+WHERE wks\.api_key_id = caller_api_key_id FOR UPDATE;.*DELETE FROM public\.watchlist_item .*DELETE FROM public\.watchlist_event_cursor .*RETURN QUERY\s+SELECT wl\.edit_status\s+AS edit_status,.*FROM api\.fn_watchlist_list\(p_key_hash\) AS wl;',
         'S49 the clear locks the key row and the key state, deletes the items, then the position, then answers the list';
  ASSERT (SELECT array_agg(x.edit_status || '|' || coalesce(x.endpoint_name, '-')) FROM api.fn_watchlist_clear(s49_key_hash) AS x) = ARRAY['unknown_key|-']
     AND (SELECT array_agg(x.edit_status || '|' || coalesce(x.endpoint_name, '-')) FROM api.fn_watchlist_list(s49_key_hash) AS x) = ARRAY['unknown_key|-'],
         'S49 a clear and a list of a hash with no api_keys row answer one unknown_key row';

  BEGIN
    INSERT INTO api_keys (key_hash) VALUES (s49_key_hash);
    FOR item IN SELECT * FROM (VALUES
        ('cve_lookup', $a$'CVE-2006-0001', 100$a$),
        ('kev_lookup', $a$'CVE-2006-0002', 100$a$),
        ('cve_exploit', $a$'CVE-2006-0003', 100$a$),
        ('product_exposure', $a$'s49vendor', 's49product', '1.0', 100$a$),
        ('cve_search', $a$'s49vendor', NULL, 'HIGH', NULL, 7.5, NULL, true, NULL, NULL, 100$a$),
        ('dns_lookup', $a$'a.s49.example', 's49.example', 100, 20$a$),
        ('ssl_check', $a$'a.s49.example', 's49.example', 100, 20$a$),
        ('whois_lookup', $a$'a.s49.example', 's49.example', 100, 20$a$),
        ('headers_check', $a$'a.s49.example', 's49.example', 100, 20$a$),
        ('cert_search', $a$'a.s49.example', 's49.example', 100, 20$a$),
        ('package_check', $a$'npm', 's49-package', NULL, 500, 100, 100000, 20$a$),
        ('ip_lookup', $a$'192.0.2.49', 100$a$)) AS t (endpoint_name, arguments) LOOP
      EXECUTE format('SELECT x.edit_status || ''|'' || x.endpoint_name FROM api.%I(%L, %L, %s) AS x',
                     'fn_watchlist_edit_' || item.endpoint_name, s49_key_hash, 'add', item.arguments) INTO answered;
      ASSERT answered = 'ok|' || item.endpoint_name, 'S49 the add of ' || item.endpoint_name || ' answers its own endpoint: ' || answered;
      ASSERT (SELECT array_agg(wi.endpoint_name) FROM watchlist_item AS wi JOIN api_keys AS ak ON ak.id = wi.api_key_id WHERE ak.key_hash = s49_key_hash)
             = ARRAY[item.endpoint_name],
             'S49 the add of ' || item.endpoint_name || ' stores an item of its own endpoint';
      EXECUTE format('SELECT x.edit_status || ''|'' || x.endpoint_name FROM api.%I(%L, %L, %s) AS x',
                     'fn_watchlist_edit_' || item.endpoint_name, s49_key_hash, 'remove', item.arguments) INTO answered;
      ASSERT answered = 'ok|' || item.endpoint_name, 'S49 the remove of ' || item.endpoint_name || ' answers its own endpoint: ' || answered;
      ASSERT NOT EXISTS (SELECT 1 FROM watchlist_item AS wi JOIN api_keys AS ak ON ak.id = wi.api_key_id WHERE ak.key_hash = s49_key_hash),
             'S49 the remove of ' || item.endpoint_name || ' deletes the item';
    END LOOP;

    FOR item IN SELECT * FROM (VALUES
        ('NULL action', $a$SELECT * FROM api.fn_watchlist_edit_cve_lookup(%L, NULL, 'CVE-2006-0001', 100)$a$, 'an item edit is an add or a remove'),
        ('list action', $a$SELECT * FROM api.fn_watchlist_item_edit(%L, 'list', 'cve_lookup', p_cve_id => 'CVE-2006-0001', p_item_max_count => 100)$a$, 'an item edit is an add or a remove'),
        ('clear action', $a$SELECT * FROM api.fn_watchlist_item_edit(%L, 'clear', 'dns_lookup', p_domain_name => 'a.s49.example', p_registered_domain => 's49.example', p_item_max_count => 100, p_domain_name_max_count => 20)$a$, 'an item edit is an add or a remove'),
        ('CVE cap', $a$SELECT * FROM api.fn_watchlist_edit_cve_lookup(%L, 'add', 'CVE-2006-0001', NULL)$a$, 'a cap of the item is NULL'),
        ('product cap', $a$SELECT * FROM api.fn_watchlist_edit_cve_search(%L, 'add', 's49vendor', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)$a$, 'a cap of the item is NULL'),
        ('domain item cap', $a$SELECT * FROM api.fn_watchlist_edit_ssl_check(%L, 'add', 'b.s49.example', 's49.example', NULL, 20)$a$, 'a cap of the item is NULL'),
        ('domain name cap', $a$SELECT * FROM api.fn_watchlist_edit_dns_lookup(%L, 'add', 'b.s49.example', 's49.example', 100, NULL)$a$, 'a cap of the item is NULL'),
        ('package item cap', $a$SELECT * FROM api.fn_watchlist_edit_package_check(%L, 'add', 'npm', 's49-package', NULL, NULL, 100, 100000, 20)$a$, 'a cap of the item is NULL'),
        ('package base weight', $a$SELECT * FROM api.fn_watchlist_edit_package_check(%L, 'add', 'npm', 's49-package', NULL, 500, NULL, 100000, 20)$a$, 'a cap of the item is NULL'),
        ('package budget', $a$SELECT * FROM api.fn_watchlist_edit_package_check(%L, 'add', 'npm', 's49-package', NULL, 500, 100, NULL, 20)$a$, 'a cap of the item is NULL'),
        ('package versions per weight', $a$SELECT * FROM api.fn_watchlist_edit_package_check(%L, 'add', 'npm', 's49-package', NULL, 500, 100, 100000, NULL)$a$, 'a cap of the item is NULL'),
        ('package remove cap', $a$SELECT * FROM api.fn_watchlist_edit_package_check(%L, 'remove', 'npm', 's49-package', NULL, 500, 100, NULL, 20)$a$, 'a cap of the item is NULL'),
        ('IP item cap', $a$SELECT * FROM api.fn_watchlist_edit_ip_lookup(%L, 'add', '192.0.2.49', NULL)$a$, 'a cap of the item is NULL'),
        ('IP item with no address', $a$SELECT * FROM api.fn_watchlist_edit_ip_lookup(%L, 'add', NULL, 100)$a$, 'an IP item needs one address'),
        ('IP item of a prefix', $a$SELECT * FROM api.fn_watchlist_edit_ip_lookup(%L, 'add', '192.0.2.0/24', 100)$a$, 'an IP item needs one address'),
        ('CVE item with an address', $a$SELECT * FROM api.fn_watchlist_item_edit(%L, 'add', 'cve_lookup', p_cve_id => 'CVE-2006-0001', p_item_max_count => 100, p_ip_address => '192.0.2.49')$a$, 'only an IP item takes an address'),
        ('domain item with an address', $a$SELECT * FROM api.fn_watchlist_item_edit(%L, 'add', 'dns_lookup', p_domain_name => 'b.s49.example', p_registered_domain => 's49.example', p_item_max_count => 100, p_domain_name_max_count => 20, p_ip_address => '192.0.2.49')$a$, 'only an IP item takes an address'),
        ('package item with an address', $a$SELECT * FROM api.fn_watchlist_item_edit(%L, 'add', 'package_check', p_ecosystem => 'npm', p_package_name => 's49-package', p_package_item_max_count => 500, p_package_item_base_weight => 100, p_package_weight_budget => 100000, p_listed_versions_per_weight => 20, p_ip_address => '192.0.2.49')$a$, 'only an IP item takes an address'))
        AS t (label, call_text, reason) LOOP
      error_text := NULL;
      BEGIN
        EXECUTE format(item.call_text, s49_key_hash);
      EXCEPTION WHEN invalid_parameter_value THEN
        error_text := SQLERRM;
      END;
      ASSERT error_text LIKE '%' || item.reason, 'S49 a call with a ' || item.label || ' raises: ' || coalesce(error_text, 'no error');
      ASSERT NOT EXISTS (SELECT 1 FROM watchlist_item AS wi JOIN api_keys AS ak ON ak.id = wi.api_key_id WHERE ak.key_hash = s49_key_hash)
         AND NOT EXISTS (SELECT 1 FROM watchlist_event_cursor AS wec JOIN api_keys AS ak ON ak.id = wec.api_key_id WHERE ak.key_hash = s49_key_hash),
             'S49 a call with a ' || item.label || ' changes nothing';
    END LOOP;
    RAISE SQLSTATE 'TUNDO';
  EXCEPTION WHEN SQLSTATE 'TUNDO' THEN
    NULL;
  END;
END
$$;

DO $$
DECLARE
  saved_events_option text := current_setting('contrastapi.cve_events', true);
BEGIN
  PERFORM set_config('contrastapi.cve_events', 'off', true);
  INSERT INTO exploitdb_entries (cve_id, edb_id) VALUES ('CVE-2010-0601', 601);
  INSERT INTO cves (cve_id, cvss_v3, cvss_v3_vector, epss_score) VALUES ('CVE-2010-0601', 6.0, 'CVSS:3.1/AV:N', 0.2);
  ASSERT (SELECT f.risk_score = api.fn_cve_risk_score(6.0, 0.2, false, false, 0, true)
             AND f.risk_score <> api.fn_cve_risk_score(6.0, 0.2, false, false, 0, false)
             AND NOT f.has_metasploit
            FROM api.fn_watchlist_cve_facts('CVE-2010-0601') AS f),
         'api.fn_watchlist_cve_facts scores the ExploitDB entry';
  DELETE FROM exploitdb_entries WHERE cve_id = 'CVE-2010-0601';
  DELETE FROM cves WHERE cve_id = 'CVE-2010-0601';
  PERFORM set_config('contrastapi.cve_events', coalesce(saved_events_option, ''), true);
END
$$;

DO $$
BEGIN
  BEGIN
    PERFORM pg_temp.t_edit('A', NULL, NULL, p_is_cleared => true);
    ASSERT pg_temp.t_edit('A', 'add', 'dns_lookup', p_cve_id => 'CVE-2006-0001', p_vendor => 'v', p_min_cvss => 5,
                          p_domain_name => 'stray.wl.example') = 'ok', 'S34 a dns_lookup add with CVE arguments answers ok';
    ASSERT pg_temp.t_edit('A', 'add', 'cve_lookup', p_cve_id => 'CVE-2006-0001', p_domain_name => 'stray2.wl.example') = 'ok',
           'S34 a cve_lookup add with a domain answers ok';
    ASSERT pg_temp.t_items('A')::text LIKE '{dns_lookup:stray.wl.example,cve_lookup:CVE-2006-0001%}',
           'S34 the items hold only their own arguments: ' || pg_temp.t_items('A')::text;
    ASSERT NOT EXISTS (SELECT 1 FROM watchlist_item_cve AS wic WHERE wic.api_key_id = pg_temp.t_key_id('A') AND wic.endpoint_name = 'dns_lookup')
           AND NOT EXISTS (SELECT 1 FROM domain_watch AS dw WHERE dw.domain_name = 'stray2.wl.example'),
           'S34 no CVE row for the domain item and no domain row for the CVE item';
    RAISE SQLSTATE 'TUNDO';
  EXCEPTION WHEN SQLSTATE 'TUNDO' THEN
    NULL;
  END;
END
$$;

CREATE FUNCTION pg_temp.t_undone(p_scenario text, p_with_other boolean) RETURNS text LANGUAGE plpgsql AS $$
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

CREATE FUNCTION pg_temp.t_s35(p_with_other boolean) RETURNS text LANGUAGE plpgsql AS $$
DECLARE
  answers text;
BEGIN
  PERFORM pg_temp.t_edit('A', NULL, NULL, p_is_cleared => true);
  PERFORM pg_temp.t_edit('B', NULL, NULL, p_is_cleared => true);
  UPDATE watchlist_key_state AS wks SET last_key_event_id = 0, max_purged_key_event_id = 0 WHERE wks.api_key_id = pg_temp.t_key_id('A');
  PERFORM pg_temp.t_edit('A', 'add', 'cve_lookup', p_cve_id => 'CVE-2006-0001');
  PERFORM pg_temp.t_edit('A', 'add', 'dns_lookup', p_domain_name => 'n1.wl.example');
  IF p_with_other THEN
    PERFORM pg_temp.t_edit('B', 'add', 'cve_lookup', p_cve_id => 'CVE-2006-0002');
    PERFORM pg_temp.t_edit('B', 'add', 'dns_lookup', p_domain_name => 'n2.wl.example');
  END IF;
  PERFORM pg_temp.t_cve_event_of('CVE-2006-0001');
  PERFORM pg_temp.t_cve_event_of('CVE-2006-0002');
  IF p_with_other THEN
    PERFORM pg_temp.t_domain_event('n2.wl.example', 'ns_changed', 'B', 'p', 'c');
    PERFORM pg_temp.t_events('B', NULL, false, 100, 100);
  END IF;
  PERFORM pg_temp.t_domain_event('n1.wl.example', 'ns_changed', 'A', 'p', 'c');
  answers := pg_temp.t_events('A', NULL, false, 1, 100) || ' ' || pg_temp.t_event_cursor('A');
  IF p_with_other THEN
    PERFORM pg_temp.t_domain_event('n2.wl.example', 'mx_changed', 'B', 'p', 'c');
    PERFORM pg_temp.t_events('B', NULL, false, 100, 100);
  END IF;
  PERFORM pg_temp.t_cve_event_of('CVE-2006-0001', 'kev_removed');
  PERFORM pg_temp.t_cve_event_of('CVE-2006-0002', 'kev_removed');
  answers := answers || ' ' || pg_temp.t_events('A', NULL, false, 100, 100) || ' ' || pg_temp.t_event_cursor('A')
             || ' ' || pg_temp.t_events('A', NULL, true, 100, 100) || ' ' || pg_temp.t_events('A', 1, false, 100, 100)
             || ' ' || pg_temp.t_events('A', 0, false, 2, 100);
  RETURN answers || ' ' || (SELECT wks.last_key_event_id || ',' || wks.max_purged_key_event_id
                              FROM watchlist_key_state AS wks WHERE wks.api_key_id = pg_temp.t_key_id('A'));
END
$$;
DO $$
DECLARE
  alone  text := pg_temp.t_undone('t_s35', false);
  shared text := pg_temp.t_undone('t_s35', true);
BEGIN
  ASSERT alone = 'ok|1|true|{01:kev_added} 0,1 ok|3|false|{n1.wl.example:ns_changed,01:kev_removed} 1,3 '
                 'ok|3|false|{n1.wl.example:ns_changed,01:kev_removed} ok|3|false|{n1.wl.example:ns_changed,01:kev_removed} '
                 'ok|2|true|{01:kev_added,n1.wl.example:ns_changed} 3,0',
         'S35 key A alone numbers its three events 1 to 3: ' || alone;
  ASSERT shared = alone, 'S35 key A beside key B answers the same numbers, cursors and has_more: ' || shared;
END
$$;

CREATE FUNCTION pg_temp.t_s35p(p_with_other boolean) RETURNS text LANGUAGE plpgsql AS $$
DECLARE
  answers text;
BEGIN
  PERFORM pg_temp.t_edit('A', NULL, NULL, p_is_cleared => true);
  PERFORM pg_temp.t_edit('B', NULL, NULL, p_is_cleared => true);
  UPDATE watchlist_key_state AS wks SET last_key_event_id = 0, max_purged_key_event_id = 0 WHERE wks.api_key_id = pg_temp.t_key_id('A');
  PERFORM pg_temp.t_edit('A', 'add', 'dns_lookup', p_domain_name => 'n1.wl.example');
  IF p_with_other THEN
    PERFORM pg_temp.t_edit('B', 'add', 'dns_lookup', p_domain_name => 'n2.wl.example');
  END IF;
  PERFORM pg_temp.t_domain_event('n1.wl.example', 'ns_changed', 'A', 'p', 'c');
  answers := pg_temp.t_events('A', NULL, false, 100, 100);
  IF p_with_other THEN
    PERFORM pg_temp.t_domain_event('n2.wl.example', 'ns_changed', 'B', 'p', 'c');
  END IF;
  RETURN answers || ' ' || pg_temp.t_events('A', NULL, true, 100, 100) || ' ' || pg_temp.t_events('A', 0, false, 100, 100)
         || ' ' || pg_temp.t_events('A', 1, false, 100, 100);
END
$$;
DO $$
DECLARE
  alone  text := pg_temp.t_undone('t_s35p', false);
  shared text := pg_temp.t_undone('t_s35p', true);
BEGIN
  ASSERT alone = 'ok|1|false|{n1.wl.example:ns_changed} ok|1|false|{n1.wl.example:ns_changed} ok|1|false|{n1.wl.example:ns_changed} ok|1|false|{}',
         'S35P key A alone answers has_more false in each call: ' || alone;
  ASSERT shared = alone, 'S35P key A beside a waiting ref of key B answers the same has_more: ' || shared;
END
$$;

DO $$
DECLARE
  key_a               integer := pg_temp.t_key_id('A');
  key_last            bigint;
  before_add_event_id bigint;
  after_add_event_id  bigint;
BEGIN
  ASSERT pg_temp.t_edit('A', NULL, NULL, p_is_cleared => true) = 'ok', 'S36 the clear answers ok';
  key_last := (SELECT wks.last_key_event_id FROM watchlist_key_state AS wks WHERE wks.api_key_id = key_a);
  before_add_event_id := pg_temp.t_cve_event_of('CVE-2006-0001');
  ASSERT pg_temp.t_edit('A', 'add', 'cve_lookup', p_cve_id => 'CVE-2006-0001') = 'ok'
     AND pg_temp.t_edit('A', 'add', 'cve_search', p_min_cvss => 0) = 'ok', 'S36 key A adds two items that match every event of CVE-2006-0001';
  after_add_event_id := pg_temp.t_cve_event_of('CVE-2006-0001', 'kev_removed');
  ASSERT NOT EXISTS (SELECT 1 FROM watchlist_event_ref AS wer WHERE wer.api_key_id = key_a),
         'S36 a CVE event writes no ref before a normal call';
  ASSERT pg_temp.t_events('A', NULL, false, 100, 100) = format('ok|%s|false|{01:kev_removed}', key_last + 1),
         'S36 the normal call numbers the event after the add, and not the one before it';
  ASSERT (SELECT array_agg(wer.event_id || ':' || wer.key_event_id ORDER BY wer.item_id) FROM watchlist_event_ref AS wer WHERE wer.api_key_id = key_a)
         = ARRAY[after_add_event_id || ':' || key_last + 1, after_add_event_id || ':' || key_last + 1],
         'S36 the normal call writes one ref for each item, and both share one number';
  ASSERT (SELECT array_agg(x.event_rank || ':' || x.is_first_row_of_event ORDER BY x.ordinality)
            FROM api.fn_watchlist_events(pg_temp.t_hash('A'), NULL, true, 100, 100, 600) WITH ORDINALITY AS x)
         = ARRAY['1:true', '1:false'],
         'S36 the two rows of the event share rank 1, and the first carries the event';
  PERFORM pg_temp.t_rewind('A', 0);
  ASSERT pg_temp.t_events('A', NULL, false, 100, 100) LIKE 'ok|%|false|{%01:kev_removed}'
     AND NOT EXISTS (SELECT 1 FROM watchlist_event_ref AS wer WHERE wer.event_id = before_add_event_id),
         'S36 a scan that reads the event from before the add still gives it no ref, by last_event_id_before_add';
END
$$;

DO $$
DECLARE
  key_a     integer := pg_temp.t_key_id('A');
  key_last  bigint;
  cve_head  bigint;
BEGIN
  ASSERT pg_temp.t_edit('A', NULL, NULL, p_is_cleared => true) = 'ok', 'S37 the first clear answers ok';
  key_last := (SELECT wks.last_key_event_id FROM watchlist_key_state AS wks WHERE wks.api_key_id = key_a);
  ASSERT key_last > 0, 'S37 key A has numbered events before';
  ASSERT pg_temp.t_edit('A', 'add', 'cve_search', p_min_cvss => 0) = 'ok', 'S37 key A adds an item that matches every event';
  ASSERT pg_temp.t_event_cursor('A') = format('%s,%s', key_last, key_last), 'S37 the add after a clear opens the position at the old last_key_event_id';
  PERFORM pg_temp.t_cve_event_of('CVE-2006-0001');
  PERFORM pg_temp.t_cve_event_of('CVE-2006-0002');
  ASSERT pg_temp.t_events('A', NULL, false, 100, 100) = format('ok|%s|false|{01:kev_added,02:kev_added}', key_last + 2),
         'S37 the numbers go on after the clear';
  ASSERT pg_temp.t_events('A', key_last, false, 100, 100) = format('ok|%s|false|{01:kev_added,02:kev_added}', key_last + 2)
     AND pg_temp.t_events('A', key_last + 1, false, 100, 100) = format('ok|%s|false|{02:kev_added}', key_last + 2),
         'S37 a replay from the start of the new numbers is valid';
  ASSERT pg_temp.t_events('A', key_last - 1, false, 100, 100) = 'cursor_invalid|null|false|{}',
         'S37 a replay into the numbers of the first clear is invalid';

  ASSERT pg_temp.t_edit('A', NULL, NULL, p_is_cleared => true) = 'ok', 'S37 the second clear answers ok';
  ASSERT pg_temp.t_events('A', key_last + 1, false, 100, 100) = 'cursor_invalid|null|false|{}',
         'S37 a replay into the cleared numbers is invalid';
  ASSERT pg_temp.t_events('A', key_last + 2, false, 100, 100) = format('ok|%s|false|{}', key_last + 2),
         'S37 a replay at the last number of a cleared key is valid and answers nothing';
  PERFORM pg_temp.t_cve_event_of('CVE-2006-0003');
  cve_head := api.fn_cve_change_event_max_id();
  ASSERT pg_temp.t_edit('A', 'add', 'cve_search', p_min_cvss => 0) = 'ok', 'S37 key A adds the item again';
  ASSERT pg_temp.t_event_cursor('A') = format('%s,%s', key_last + 2, key_last + 2)
     AND pg_temp.t_key_state('A') = format('%s,%s,%s', key_last + 2, key_last + 2, cve_head),
         'S37 the add opens the position at last_key_event_id and raises last_cve_event_id to the CVE head';
  PERFORM pg_temp.t_cve_event_of('CVE-2006-0001', 'kev_removed');
  ASSERT pg_temp.t_events('A', NULL, false, 100, 100) = format('ok|%s|false|{01:kev_removed}', key_last + 3),
         'S37 the first number after the add is the next one';

  PERFORM pg_temp.t_cve_event_of('CVE-2006-0004');
  ASSERT pg_temp.t_edit('A', 'add', 'cve_lookup', p_cve_id => 'CVE-2006-0001') = 'ok'
     AND pg_temp.t_key_state('A') = format('%s,%s,%s', key_last + 3, key_last + 2, cve_head + 1),
         'S37 an add beside an item keeps last_cve_event_id below the new CVE head';
  ASSERT pg_temp.t_edit('A', 'remove', 'cve_lookup', p_cve_id => 'CVE-2006-0001') = 'ok'
     AND pg_temp.t_events('A', key_last + 2, false, 100, 100) = format('ok|%s|true|{01:kev_removed}', key_last + 3),
         'S37 a remove that leaves an item keeps the replay into its numbers valid';
  ASSERT pg_temp.t_edit('A', 'remove', 'cve_search', p_min_cvss => 0) = 'ok'
     AND pg_temp.t_events('A', key_last + 2, false, 100, 100) = 'cursor_invalid|null|false|{}'
     AND pg_temp.t_events('A', key_last + 3, false, 100, 100) = format('ok|%s|true|{}', key_last + 3),
         'S37 a remove that leaves no item makes the replay into its numbers invalid, as a clear does';
  ASSERT pg_temp.t_key_state('A') = format('%s,%s,%s', key_last + 3, key_last + 3, cve_head + 1),
         'S37 the remove keeps the numbering and raises max_purged_key_event_id';
END
$$;

DO $$
DECLARE
  key_a          integer := pg_temp.t_key_id('A');
  key_last       bigint;
  first_event_id bigint;
BEGIN
  ASSERT pg_temp.t_edit('A', NULL, NULL, p_is_cleared => true) = 'ok'
     AND pg_temp.t_edit('A', 'add', 'cve_lookup', p_cve_id => 'CVE-2006-0004') = 'ok', 'S38 key A adds its item';
  key_last := (SELECT wks.last_key_event_id FROM watchlist_key_state AS wks WHERE wks.api_key_id = key_a);
  first_event_id := pg_temp.t_cve_event_of('CVE-2006-0004');
  PERFORM pg_temp.t_cve_event_of('CVE-2006-0004', 'kev_removed');
  ASSERT pg_temp.t_events('A', NULL, false, 100, 100) = format('ok|%s|false|{04:kev_added,04:kev_removed}', key_last + 2),
         'S38 the normal call numbers both events';
  DELETE FROM cve_change_event WHERE event_id = first_event_id;
  ASSERT pg_temp.t_events('A', NULL, true, 100, 100) = format('ok|%s|false|{04:kev_removed}', key_last + 2)
     AND pg_temp.t_events('A', key_last, false, 100, 100) = format('ok|%s|false|{04:kev_removed}', key_last + 2),
         'S38 a ref whose event row is gone has no row in a repeat or a replay';
  ASSERT (SELECT array_agg(x.event_rank) FROM api.fn_watchlist_events(pg_temp.t_hash('A'), NULL, true, 100, 100, 600) AS x) = '{1}',
         'S38 the rank of the event that is left is 1';

  INSERT INTO watchlist_event_ref (api_key_id, item_id, event_id)
  SELECT wi.api_key_id, wi.item_id, 1000000000 FROM watchlist_item AS wi WHERE wi.api_key_id = key_a;
  ASSERT pg_temp.t_events('A', NULL, false, 100, 100) = format('ok|%s|true|{}', key_last + 2),
         'S38 a normal call has more while a ref of the key waits above the head';
  ASSERT pg_temp.t_events('A', NULL, true, 100, 100) = format('ok|%s|true|{}', key_last + 2)
     AND pg_temp.t_events('A', key_last + 2, false, 100, 100) = format('ok|%s|true|{}', key_last + 2),
         'S38 a repeat and a replay have more while a ref of the key waits';
  DELETE FROM watchlist_event_ref AS wer WHERE wer.event_id = 1000000000;
  ASSERT pg_temp.t_events('A', NULL, true, 100, 100) = format('ok|%s|false|{}', key_last + 2),
         'S38 with no waiting ref the repeat has no more';
  ASSERT pg_temp.t_edit('A', NULL, NULL, p_is_cleared => true) = 'ok', 'S38 the clear answers ok';
END
$$;

DO $$
BEGIN
  ASSERT pg_temp.t_edit('A', NULL, NULL, p_is_cleared => true) = 'ok'
     AND pg_temp.t_edit('A', 'add', 'dns_lookup', p_domain_name => 'p.wl.example') = 'ok'
     AND pg_temp.t_edit('A', 'add', 'ssl_check', p_domain_name => 'p.wl.example') = 'ok', 'S39 key A adds its two items';
  PERFORM pg_temp.t_domain_event('p.wl.example', 'cert_expiring', 'A', 'p', 'c');
  PERFORM pg_temp.t_domain_event('p.wl.example', 'ns_changed', 'A', 'p', 'c');
  ASSERT (SELECT array_agg(x.item_endpoint_name || ':' || x.event_rank || ':' || x.is_first_event_of_domain ORDER BY x.ordinality)
            FROM api.fn_watchlist_events(pg_temp.t_hash('A'), NULL, false, 100, 100, 600) WITH ORDINALITY AS x)
         = ARRAY['dns_lookup:2:true', 'ssl_check:1:false'],
         'S39 the first row of a domain in answer order carries its facts, whatever the number order';
  ASSERT pg_temp.t_edit('A', NULL, NULL, p_is_cleared => true) = 'ok', 'S39 the clear answers ok';
END
$$;

DO $$
DECLARE
  key_a         integer := pg_temp.t_key_id('A');
  key_b         integer := pg_temp.t_key_id('B');
  key_20        integer := (SELECT ak.id FROM api_keys AS ak WHERE ak.key_hash = repeat('20', 32));
  a_last        bigint;
  b_last        bigint;
  d1            bigint;
  d2            bigint;
  d3            bigint;
  d4            bigint;
  c1            bigint;
  c1b           bigint;
  c1c           bigint;
  c2            bigint;
  old_cve_count bigint;
BEGIN
  ASSERT pg_temp.t_edit('A', NULL, NULL, p_is_cleared => true) = 'ok'
     AND pg_temp.t_edit('B', NULL, NULL, p_is_cleared => true) = 'ok', 'S40 both clears answer ok';
  ASSERT pg_temp.t_edit('A', 'add', 'dns_lookup', p_domain_name => 'pg.wl.example') = 'ok'
     AND pg_temp.t_edit('A', 'add', 'cve_lookup', p_cve_id => 'CVE-2006-0001') = 'ok'
     AND pg_temp.t_edit('B', 'add', 'dns_lookup', p_domain_name => 'pg.wl.example') = 'ok'
     AND pg_temp.t_edit('B', 'add', 'cve_lookup', p_cve_id => 'CVE-2006-0001') = 'ok', 'S40 both keys add their two items';
  a_last := (SELECT wks.last_key_event_id FROM watchlist_key_state AS wks WHERE wks.api_key_id = key_a);
  b_last := (SELECT wks.last_key_event_id FROM watchlist_key_state AS wks WHERE wks.api_key_id = key_b);
  d1 := pg_temp.t_domain_event('pg.wl.example', 'ns_changed', 'A,B', 'p', 'c');
  c1 := pg_temp.t_cve_event_of('CVE-2006-0001');
  d3 := pg_temp.t_domain_event('pg.wl.example', 'ns_changed', 'A,B', 'p', 'c');
  c1b := pg_temp.t_cve_event_of('CVE-2006-0001', 'cvss_added', NULL, 7.5);
  c1c := pg_temp.t_cve_event_of('CVE-2006-0001', 'kev_removed');
  d2 := pg_temp.t_domain_event('pg.wl.example', 'ns_changed', 'A', 'p', 'c');
  c2 := pg_temp.t_cve_event_of('CVE-2006-0001', 'kev_added');
  UPDATE domain_change_event SET changed_at = now() - interval '100 days' WHERE event_id IN (d1, d2);
  UPDATE cve_change_event SET changed_at = now() - interval '100 days' WHERE event_id IN (c1, c1b, c1c);
  ASSERT pg_temp.t_events('A', NULL, false, 100, 100) LIKE format('ok|%s|false|%%', a_last + 7)
     AND pg_temp.t_events('B', NULL, false, 100, 100) LIKE format('ok|%s|false|%%', b_last + 6), 'S40 a normal call of each key numbers its events';
  d4 := pg_temp.t_domain_event('pg.wl.example', 'ns_changed', 'A,B', 'p', 'c');
  UPDATE domain_change_event SET changed_at = now() - interval '100 days' WHERE event_id = d4;

  old_cve_count := (SELECT count(*) FROM cve_change_event AS cce WHERE cce.changed_at < now() - interval '90 days');
  ASSERT old_cve_count >= 3 AND api.fn_cve_change_event_purge((old_cve_count - 2)::integer) = old_cve_count - 2,
         'S40 the first CVE purge deletes c1 and the older CVE events';
  ASSERT NOT EXISTS (SELECT 1 FROM watchlist_event_ref AS wer WHERE wer.event_id = c1)
     AND (SELECT count(*) FROM watchlist_event_ref AS wer WHERE wer.event_id IN (c1b, c1c)) = 4,
         'S40 the first CVE purge deletes the refs of c1, and the refs of c1b and c1c stay';
  ASSERT pg_temp.t_key_state('A') LIKE format('%s,%s,%%', a_last + 7, a_last + 2)
     AND pg_temp.t_key_state('B') LIKE format('%s,%s,%%', b_last + 6, b_last + 2),
         'S40 both keys lost the number 2 of c1, so max_purged_key_event_id rises to it';

  ASSERT api.fn_domain_change_event_purge(2) = 2, 'S40 the domain purge deletes d1 and d2';
  ASSERT NOT EXISTS (SELECT 1 FROM watchlist_event_ref AS wer WHERE wer.event_id IN (d1, d2))
     AND (SELECT count(*) FROM watchlist_event_ref AS wer WHERE wer.event_id IN (d3, d4, c1b, c1c)) = 8,
         'S40 the domain purge deletes the refs of d1 and d2, and the refs of d3, d4, c1b and c1c stay';
  ASSERT pg_temp.t_key_state('A') LIKE format('%s,%s,%%', a_last + 7, a_last + 6),
         'S40 key A lost the numbers 1 of d1 and 6 of d2, so max_purged_key_event_id rises to 6';
  ASSERT pg_temp.t_key_state('B') LIKE format('%s,%s,%%', b_last + 6, b_last + 2),
         'S40 key B lost the number 1 of d1, below its floor, and the floor stays';
  ASSERT pg_temp.t_events('A', a_last + 5, false, 100, 100) = 'cursor_invalid|null|false|{}',
         'S40 a replay of key A below its floor is invalid';
  ASSERT pg_temp.t_events('A', a_last + 6, false, 100, 100) = format('ok|%s|true|{01:kev_added}', a_last + 7),
         'S40 a replay of key A from its floor answers the event after it, and the waiting ref of d4 makes has_more true';
  ASSERT api.fn_domain_change_event_purge(10) = 1, 'S40 the next domain purge deletes d4';
  ASSERT NOT EXISTS (SELECT 1 FROM watchlist_event_ref AS wer WHERE wer.event_id = d4), 'S40 the next domain purge deletes the waiting refs of d4';
  ASSERT pg_temp.t_key_state('A') LIKE format('%s,%s,%%', a_last + 7, a_last + 6)
     AND pg_temp.t_key_state('B') LIKE format('%s,%s,%%', b_last + 6, b_last + 2),
         'S40 a waiting ref has no number, so its purge keeps the floor of each key';

  ASSERT api.fn_cve_change_event_purge(10) = 2, 'S40 the next CVE purge deletes c1b and c1c';
  ASSERT NOT EXISTS (SELECT 1 FROM watchlist_event_ref AS wer WHERE wer.event_id IN (c1b, c1c))
     AND (SELECT count(*) FROM watchlist_event_ref AS wer WHERE wer.event_id IN (d3, c2)) = 4,
         'S40 the next CVE purge deletes the refs of c1b and c1c, and the refs of d3 and c2 stay';
  ASSERT pg_temp.t_key_state('A') LIKE format('%s,%s,%%', a_last + 7, a_last + 6),
         'S40 key A lost the numbers 4 and 5, below its floor, and the floor stays';
  ASSERT pg_temp.t_key_state('B') LIKE format('%s,%s,%%', b_last + 6, b_last + 5),
         'S40 key B lost the numbers 4 and 5, above its floor, and the floor rises to the larger one';

  INSERT INTO watchlist_key_state (api_key_id, last_key_event_id, max_purged_key_event_id, last_cve_event_id) VALUES (key_20, 3, 1, 0);
  UPDATE api_keys SET expires_at = now() - interval '31 days' WHERE id IN (key_a, key_b);
  ASSERT api.fn_watchlist_purge(10) = 2, 'S40 the expired-key purge clears keys A and B';
  ASSERT pg_temp.t_item_count('A') = 0 AND pg_temp.t_item_count('B') = 0
     AND pg_temp.t_event_cursor('A') = 'none' AND pg_temp.t_event_cursor('B') = 'none'
     AND NOT EXISTS (SELECT 1 FROM watchlist_event_ref AS wer WHERE wer.api_key_id IN (key_a, key_b)),
         'S40 the expired-key purge deletes the items, the refs and the position of both keys';
  ASSERT pg_temp.t_key_state('A') LIKE format('%s,%s,%%', a_last + 7, a_last + 7)
     AND pg_temp.t_key_state('B') LIKE format('%s,%s,%%', b_last + 6, b_last + 6),
         'S40 the expired-key purge keeps the key states and raises max_purged_key_event_id to last_key_event_id';
  ASSERT (SELECT wks.last_key_event_id || ',' || wks.max_purged_key_event_id FROM watchlist_key_state AS wks WHERE wks.api_key_id = key_20) = '3,1',
         'S40 the expired-key purge leaves the key state of a key it does not clear alone';
  DELETE FROM watchlist_key_state AS wks WHERE wks.api_key_id = key_20;
  UPDATE api_keys SET expires_at = NULL WHERE id IN (key_a, key_b);
  UPDATE change_event_purge_state SET max_purged_event_id = 0 WHERE event_table_name = 'cve_change_event';
  UPDATE change_event_purge_state SET max_purged_event_id = 0 WHERE event_table_name = 'domain_change_event';
END
$$;

CREATE FUNCTION pg_temp.t_s41_read(p_event_row_count integer) RETURNS text LANGUAGE sql AS $$
  SELECT min(x.next_cursor) || '|' || bool_and(x.has_more) || '|' || coalesce(string_agg(x.current_domain_value, ',' ORDER BY x.event_rank), '')
    FROM api.fn_watchlist_events(pg_temp.t_hash('A'), NULL, false, p_event_row_count, 100, 600) AS x
$$;
CREATE FUNCTION pg_temp.t_s41(p_event_count integer) RETURNS text LANGUAGE plpgsql AS $$
DECLARE
  key_a            integer := pg_temp.t_key_id('A');
  first_event_id   bigint;
  written_event_id bigint;
  answers          text;
  answer           text;
BEGIN
  BEGIN
    PERFORM pg_temp.t_edit('A', NULL, NULL, p_is_cleared => true);
    PERFORM pg_temp.t_edit('B', NULL, NULL, p_is_cleared => true);
    UPDATE watchlist_key_state AS wks SET last_key_event_id = 0, max_purged_key_event_id = 0 WHERE wks.api_key_id = key_a;
    PERFORM pg_temp.t_edit('A', 'add', 'dns_lookup', p_domain_name => 's41.wl.example');
    PERFORM pg_temp.t_edit('B', 'add', 'dns_lookup', p_domain_name => 's41.wl.example');
    PERFORM pg_temp.t_edit('B', 'add', 'dns_lookup', p_domain_name => 's41b.wl.example');
    FOR i IN 1..3 LOOP
      PERFORM pg_temp.t_domain_event('s41b.wl.example', 'ns_changed', 'B', 'p', 'b' || i);
    END LOOP;
    FOR i IN 1..p_event_count LOOP
      written_event_id := pg_temp.t_domain_event('s41.wl.example', 'ns_changed', 'A,B', 'p', 'v' || i);
      first_event_id := coalesce(first_event_id, written_event_id);
    END LOOP;
    answers := (SELECT coalesce(string_agg(page.event_id - first_event_id + 1 || ':' || CASE WHEN wi.api_key_id = key_a THEN 'A' ELSE 'B' END,
                                           ',' ORDER BY page.event_id, page.item_id), '')
                       || '|' || min(scan.is_page_full::text)
                  FROM api.fn_watchlist_event_scan(key_a, api.fn_cve_change_event_max_id(), api.fn_watchlist_event_max_id(), 2, 100, 600) AS scan
                  LEFT JOIN LATERAL unnest(scan.page_event_ids, scan.page_item_ids) AS page (event_id, item_id) ON true
                  LEFT JOIN watchlist_item AS wi ON wi.item_id = page.item_id);
    FOR i IN 1..10 LOOP
      answer := pg_temp.t_s41_read(2);
      answers := answers || ' ' || answer;
      EXIT WHEN answer LIKE '%|false|%';
    END LOOP;
    PERFORM pg_temp.t_rewind('A', api.fn_cve_change_event_max_id());
    answers := answers || ' / ' || pg_temp.t_s41_read(100);
    RAISE SQLSTATE 'TUNDO';
  EXCEPTION WHEN SQLSTATE 'TUNDO' THEN
    NULL;
  END;
  RETURN answers;
END
$$;
DO $$
DECLARE
  answer text;
BEGIN
  answer := pg_temp.t_s41(2);
  ASSERT answer = '1:A,2:A|false 2|false|v1,v2 / 2|false|v1,v2',
         'S41 with as many waiting events as a page holds, the page is not full: ' || answer;
  answer := pg_temp.t_s41(3);
  ASSERT answer = '1:A,2:A|true 2|true|v1,v2 3|false|v3 / 3|false|v1,v2,v3',
         'S41 one waiting event more than a page holds makes the page full: ' || answer;
  answer := pg_temp.t_s41(4);
  ASSERT answer = '1:A,2:A|true 2|true|v1,v2 4|false|v3,v4 / 4|false|v1,v2,v3,v4',
         'S41 two waiting events more than a page holds come on the next page: ' || answer;
  answer := pg_temp.t_s41(7);
  ASSERT answer = '1:A,2:A|true 2|true|v1,v2 4|true|v3,v4 6|true|v5,v6 7|false|v7 / 7|false|v1,v2,v3,v4,v5,v6,v7',
         'S41 four pages give the events of one big call, in the same order: ' || answer;
END
$$;

DO $$
DECLARE
  scan_source text := pg_get_functiondef('api.fn_watchlist_event_scan(integer, bigint, bigint, integer, integer, integer)'::regprocedure);
BEGIN
  ASSERT (SELECT count(*) FROM regexp_matches(scan_source, 'SELECT pending\.event_id\s+FROM watchlist_event_ref pending\s+'
                                                           'WHERE \(\(\(pending\.api_key_id >= fn_watchlist_event_scan\.p_api_key_id\) AND '
                                                           '\(pending\.api_key_id <= fn_watchlist_event_scan\.p_api_key_id\)\) AND .*?'
                                                           'GROUP BY pending\.api_key_id, pending\.event_id\s+'
                                                           'ORDER BY pending\.api_key_id, pending\.event_id\s+'
                                                           'LIMIT \(fn_watchlist_event_scan\.p_event_row_count \+ 1\)', 'g')) = 1,
         'S41 the scan takes the waiting refs of the first p_event_row_count + 1 events of the key only, in the order of idx_watchlist_event_ref_pending';
END
$$;

DO $$
DECLARE
  purge_name   text;
  purge_source text;
  lock_at      integer;
BEGIN
  FOREACH purge_name IN ARRAY ARRAY['api.fn_watchlist_event_ref_purge(bigint[], boolean)', 'api.fn_watchlist_purge(integer)'] LOOP
    purge_source := (SELECT p.prosrc FROM pg_proc AS p WHERE p.oid = purge_name::regprocedure);
    lock_at := strpos(purge_source, 'ORDER BY wks.api_key_id
     FOR UPDATE;');
    ASSERT lock_at > 0, format('%s locks the key states in api_key_id order', purge_name);
    ASSERT purge_source !~ 'DELETE FROM public\.watchlist_event_ref' OR lock_at < strpos(purge_source, 'DELETE FROM public.watchlist_event_ref'),
           format('%s locks the key states before it deletes a ref', purge_name);
    ASSERT purge_source !~ 'DELETE FROM public\.watchlist_item ' OR lock_at < strpos(purge_source, 'DELETE FROM public.watchlist_item '),
           format('%s locks the key states before it deletes an item', purge_name);
  END LOOP;
  ASSERT strpos((SELECT p.prosrc FROM pg_proc AS p WHERE p.oid = 'api.fn_watchlist_event_ref_purge(bigint[], boolean)'::regprocedure),
                'DELETE FROM public.watchlist_event_ref') > 0,
         'api.fn_watchlist_event_ref_purge deletes the refs';
END
$$;

DO $$
DECLARE
  purge         record;
  purge_source  text;
  call_at       integer;
BEGIN
  FOR purge IN SELECT * FROM (VALUES
      ('api.fn_cve_change_event_purge(integer)', 'cve_change_event', 'true'),
      ('api.fn_domain_change_event_purge(integer)', 'domain_change_event', 'false'),
      ('api.fn_package_advisory_change_event_purge(integer)', 'package_advisory_change_event', 'true'),
      ('api.fn_eol_change_event_purge(integer)', 'eol_change_event', 'true'),
      ('api.fn_ip_change_event_purge(integer)', 'ip_change_event', 'false')) AS t (function_name, event_table_name, is_scanned) LOOP
    purge_source := regexp_replace((SELECT p.prosrc FROM pg_proc AS p WHERE p.oid = purge.function_name::regprocedure), '--[^\n]*', '', 'g');
    call_at := strpos(purge_source, format('PERFORM api.fn_watchlist_event_ref_purge(picked_event_ids, %s);', purge.is_scanned));
    ASSERT call_at > 0, format('%s calls api.fn_watchlist_event_ref_purge with %s', purge.function_name, purge.is_scanned);
    ASSERT call_at < strpos(purge_source, format('DELETE FROM public.%s ', purge.event_table_name)),
           format('%s deletes the refs before its events', purge.function_name);
    ASSERT purge_source !~ 'watchlist_event_ref\M|watchlist_key_state',
           format('%s touches no ref and no key state itself', purge.function_name);
  END LOOP;
END
$$;

DO $$
DECLARE
  lock_step text := substring((SELECT p.prosrc FROM pg_proc AS p WHERE p.oid = 'api.fn_watchlist_event_ref_purge(bigint[], boolean)'::regprocedure)
                              FROM 'PERFORM 1(.*?)FOR UPDATE;');
BEGIN
  ASSERT lock_step ~ 'OR \(p_is_scanned_after_last_cve_event_id\s+AND wks\.last_cve_event_id < \(SELECT max\(picked\.event_id\) FROM unnest\(p_event_ids\) AS picked \(event_id\)\)\)',
         'api.fn_watchlist_event_ref_purge also locks the key states whose last_cve_event_id is below its largest event_id, when asked';
END
$$;

DO $$
DECLARE
  refusing_constraint text;
  statement_text      text;
BEGIN
  ASSERT (SELECT array_agg(ps.event_table_name || ':' || ps.max_purged_event_id || ':' || ps.max_unwatched_event_id ORDER BY ps.event_table_name)
            FROM change_event_purge_state AS ps)
         = ARRAY['cve_change_event:0:0', 'domain_change_event:0:0', 'eol_change_event:0:0', 'ip_change_event:0:0',
                 'package_advisory_change_event:0:0'],
         'change_event_purge_state holds one row for each event table, each at 0';
  ASSERT to_regclass('public.cve_change_event_purge_state') IS NULL
     AND to_regclass('public.domain_change_event_purge_state') IS NULL
     AND to_regclass('public.package_advisory_change_event_purge_state') IS NULL
     AND to_regclass('public.ip_change_event_purge_state') IS NULL,
         'the four one-row purge state tables are gone';
  FOREACH statement_text IN ARRAY ARRAY[
      $q$INSERT INTO change_event_purge_state (event_table_name) VALUES ('other_change_event')$q$,
      $q$INSERT INTO change_event_purge_state (event_table_name) VALUES ('cve_change_event')$q$,
      $q$UPDATE change_event_purge_state SET max_unwatched_event_id = 1 WHERE event_table_name = 'cve_change_event'$q$] LOOP
    refusing_constraint := 'accepted';
    BEGIN
      EXECUTE statement_text;
    EXCEPTION WHEN check_violation OR unique_violation THEN
      GET STACKED DIAGNOSTICS refusing_constraint = CONSTRAINT_NAME;
    END;
    ASSERT refusing_constraint = CASE WHEN statement_text ~ 'other_change_event' THEN 'change_event_purge_state_event_table_name'
                                      WHEN statement_text ~ '^INSERT' THEN 'change_event_purge_state_pkey'
                                      ELSE 'change_event_purge_state_unwatched_domain_only' END,
           format('%s is refused, by %s', statement_text, refusing_constraint);
  END LOOP;
END
$$;

DO $$
DECLARE
  key_a  integer;
  key_b  integer;
  item_a bigint;
  item_b bigint;
BEGIN
  INSERT INTO api_keys (key_hash) VALUES (repeat('7', 64)) RETURNING id INTO key_a;
  INSERT INTO api_keys (key_hash) VALUES (repeat('8', 64)) RETURNING id INTO key_b;
  INSERT INTO watchlist_item (api_key_id, endpoint_name) VALUES (key_a, 'cve_lookup') RETURNING item_id INTO item_a;
  INSERT INTO watchlist_item (api_key_id, endpoint_name) VALUES (key_b, 'cve_lookup') RETURNING item_id INTO item_b;
  INSERT INTO watchlist_key_state (api_key_id, last_cve_event_id, last_key_event_id, max_purged_key_event_id)
  VALUES (key_a, 0, 9, 2), (key_b, 0, 9, 7);
  INSERT INTO watchlist_event_ref (api_key_id, item_id, event_id, key_event_id)
  VALUES (key_a, item_a, 901, 3), (key_a, item_a, 902, 5), (key_a, item_a, 903, 6),
         (key_b, item_b, 901, 4), (key_b, item_b, 904, NULL), (key_b, item_b, 905, 8);
  ASSERT api.fn_watchlist_event_ref_purge(ARRAY[]::bigint[], true) = 0, 'an empty array answers 0';
  ASSERT (SELECT count(*) FROM watchlist_event_ref AS wer WHERE wer.api_key_id IN (key_a, key_b)) = 6, 'an empty array deletes no ref';
  ASSERT api.fn_watchlist_event_ref_purge(NULL, true) IS NULL AND api.fn_watchlist_event_ref_purge(ARRAY[901]::bigint[], NULL) IS NULL,
         'api.fn_watchlist_event_ref_purge is STRICT';
  ASSERT api.fn_watchlist_event_ref_purge(ARRAY[901, 902, 904]::bigint[], false) = 4, 'the call answers the four refs it deleted';
  ASSERT (SELECT array_agg(wer.api_key_id::text || ':' || wer.event_id ORDER BY wer.api_key_id, wer.event_id)
            FROM watchlist_event_ref AS wer WHERE wer.api_key_id IN (key_a, key_b))
         = ARRAY[key_a || ':903', key_b || ':905'],
         'the refs of the given events go, numbered or waiting, and the others stay';
  ASSERT (SELECT wks.max_purged_key_event_id FROM watchlist_key_state AS wks WHERE wks.api_key_id = key_a) = 5,
         'a key that lost numbers 3 and 5 gets 5';
  ASSERT (SELECT wks.max_purged_key_event_id FROM watchlist_key_state AS wks WHERE wks.api_key_id = key_b) = 7,
         'a key that lost number 4 and a waiting ref keeps its higher 7';
  DELETE FROM api_keys AS ak WHERE ak.id IN (key_a, key_b);
END
$$;

CREATE FUNCTION pg_temp.t_item_rows(p_label text, p_replay_cursor bigint, p_is_repeat_requested boolean) RETURNS text[] LANGUAGE sql AS $$
  WITH answer AS (SELECT * FROM api.fn_watchlist_events(pg_temp.t_hash(p_label), p_replay_cursor, p_is_repeat_requested, 100, 100, 600))
  SELECT coalesce(array_agg(format('%s:%s|%s:%s:%s>%s', pair.item_endpoint_name, pair.item_min_epss, right(first_row.cve_id, 2),
                                   first_row.event_type, first_row.previous_value, first_row.current_value)
                            ORDER BY pair.item_id, pair.event_rank), '{}')
    FROM answer AS pair
    JOIN answer AS first_row ON first_row.event_rank = pair.event_rank AND first_row.is_first_row_of_event
$$;
CREATE FUNCTION pg_temp.t_item_events(p_label text, p_after_event_id bigint) RETURNS text[] LANGUAGE sql AS $$
  SELECT pg_temp.t_rewind(p_label, p_after_event_id);
  SELECT pg_temp.t_item_rows(p_label, NULL, false);
$$;

SELECT set_config('contrastapi.cve_events', 'off', true);
INSERT INTO cves (cve_id, severity, cwe_id, epss_score) VALUES
  ('CVE-2006-0071', 'HIGH',   'CWE-787', 0.2),
  ('CVE-2006-0072', 'MEDIUM', 'CWE-416', 0.152),
  ('CVE-2006-0073', 'MEDIUM', 'CWE-787', 0.105),
  ('CVE-2006-0074', 'MEDIUM', 'CWE-416', 0.3);
INSERT INTO cve_products (cve_id, vendor, product, is_vulnerable) VALUES ('CVE-2006-0071', 'wlepss', 'wlmeter', true);
SELECT set_config('contrastapi.cve_events', '', true);

DO $$
BEGIN
  ASSERT api.fn_watchlist_event_shown_type('epss_changed', 0.05, 0.1) = 'epss_above_min'
     AND api.fn_watchlist_event_shown_type('epss_changed', 0.1, 0.085) = 'epss_below_min',
         'S43 a rise shows as epss_above_min, and a fall as epss_below_min';
  ASSERT api.fn_watchlist_event_shown_type('cvss_risk_band_changed', 6.1, 8.2) = 'cvss_risk_band_changed'
     AND api.fn_watchlist_event_shown_type('epss_level_up', 0.05, 0.1) = 'epss_level_up'
     AND api.fn_watchlist_event_shown_type('ns_changed', NULL, NULL) = 'ns_changed',
         'S43 every other type shows as it is stored';
END
$$;

DO $$
DECLARE
  base       bigint;
  a_expected text[] := ARRAY[
    'cve_search:0.1|71:epss_above_min:0.05>0.1', 'cve_search:0.1|71:epss_below_min:0.1>0.085',
    'cve_search:0.1|71:epss_above_min:0.099>0.1', 'cve_search:0.1|71:epss_below_min:0.1>0.0999',
    'cve_search:0.1|71:epss_above_min:0.0999>0.35', 'cve_search:0.1|73:epss_below_min:0.12>0.09',
    'cve_search:0.1|73:epss_above_min:0.09>0.105', 'cve_search:0.1|71:cvss_risk_band_changed:6.1>8.2',
    'cve_search:0.3|71:epss_above_min:0.0999>0.35', 'cve_search:0.3|71:epss_below_min:0.3>0.2',
    'cve_search:0.151|72:cvss_risk_band_changed:5>7.5', 'cve_search:0.151|72:epss_above_min:0.149>0.152',
    'cve_search:|71:cvss_risk_band_changed:6.1>8.2', 'cve_lookup:|71:cvss_risk_band_changed:6.1>8.2', 'product_exposure:|71:cvss_risk_band_changed:6.1>8.2'];
  b_expected text[] := ARRAY['cve_search:0.2|71:epss_above_min:0.0999>0.35', 'cve_search:0.2|74:epss_above_min:0.151>0.3',
                             'cve_search:0.2|71:cvss_risk_band_changed:6.1>8.2'];
  a_alone    text[];
  b_alone    text[];
BEGIN
  ASSERT pg_temp.t_edit('A', NULL, NULL, p_is_cleared => true) = 'ok' AND pg_temp.t_edit('B', NULL, NULL, p_is_cleared => true) = 'ok',
         'S43 the clear before the EPSS events answers ok';
  base := api.fn_watchlist_event_max_id();
  ASSERT pg_temp.t_edit('A', 'add', 'cve_search', p_cwe_id => 'CWE-787', p_min_epss => 0.1) = 'ok'
     AND pg_temp.t_edit('A', 'add', 'cve_search', p_cwe_id => 'CWE-787', p_min_epss => 0.3) = 'ok'
     AND pg_temp.t_edit('A', 'add', 'cve_search', p_cwe_id => 'CWE-416', p_min_epss => 0.151) = 'ok'
     AND pg_temp.t_edit('A', 'add', 'cve_search', p_severity => 'HIGH') = 'ok'
     AND pg_temp.t_edit('A', 'add', 'cve_lookup', p_cve_id => 'CVE-2006-0071') = 'ok'
     AND pg_temp.t_edit('A', 'add', 'product_exposure', p_vendor => 'wlepss', p_product => 'wlmeter') = 'ok',
         'S43 key A adds its six items';

  PERFORM pg_temp.t_cve_event_of('CVE-2006-0071', 'epss_changed', e.previous_value, e.current_value)
     FROM unnest('{0.05,0.1,0.085,0.099,0.1,0.12,0.1,0.0999,0.35,0.3}'::real[], '{0.1,0.085,0.099,0.1,0.12,0.1,0.0999,0.35,0.3,0.2}'::real[])
          WITH ORDINALITY AS e (previous_value, current_value, n)
    ORDER BY e.n;
  PERFORM pg_temp.t_cve_event_of('CVE-2006-0072', 'epss_changed', 0.16, 0.155);
  PERFORM pg_temp.t_cve_event_of('CVE-2006-0072', 'cvss_risk_band_changed', 5.0, 7.5);
  PERFORM pg_temp.t_cve_event_of('CVE-2006-0072', 'epss_changed', 0.149, 0.152);
  PERFORM pg_temp.t_cve_event_of('CVE-2006-0073', 'epss_changed', 0.12, 0.09);
  PERFORM pg_temp.t_cve_event_of('CVE-2006-0073', 'epss_changed', 0.09, 0.105);
  PERFORM pg_temp.t_cve_event_of('CVE-2006-0074', 'epss_changed', 0.16, 0.151);
  PERFORM pg_temp.t_cve_event_of('CVE-2006-0074', 'epss_changed', 0.151, 0.3);
  PERFORM pg_temp.t_cve_event_of('CVE-2006-0071', 'cvss_risk_band_changed', 6.1, 8.2);

  a_alone := pg_temp.t_item_events('A', base);
  ASSERT a_alone = a_expected, format('S43 each item of key A hears its own EPSS crossings: %s', a_alone);
  ASSERT pg_temp.t_item_rows('A', NULL, true) = a_expected, 'S43 a repeat shows the same types';
  ASSERT pg_temp.t_item_rows('A', 0, false) = a_expected, 'S43 a replay shows the same types';

  ASSERT pg_temp.t_edit('B', 'add', 'cve_search', p_min_epss => 0.2) = 'ok', 'S43 key B adds K1';
  UPDATE watchlist_item_cve SET last_event_id_before_add = base WHERE api_key_id = pg_temp.t_key_id('B');
  ASSERT pg_temp.t_item_events('A', base) = a_alone, 'S43 key A reads the same beside key B';
  ASSERT pg_temp.t_item_events('B', base) = b_expected, format('S43 key B hears the crossings of its own item: %s', pg_temp.t_item_rows('B', 0, false));
  ASSERT pg_temp.t_edit('A', NULL, NULL, p_is_cleared => true) = 'ok', 'S43 key A clears its items';
  b_alone := pg_temp.t_item_events('B', base);
  ASSERT b_alone = b_expected, 'S43 key B reads the same without the items of key A';
  ASSERT pg_temp.t_edit('B', NULL, NULL, p_is_cleared => true) = 'ok', 'S43 key B clears its item';
END
$$;

SELECT set_config('contrastapi.cve_events', 'off', true);
INSERT INTO cves (cve_id, cwe_id, epss_score) VALUES
  ('CVE-2006-0075', 'CWE-862', 0.08), ('CVE-2006-0076', 'CWE-862', 0.04), ('CVE-2006-0078', 'CWE-862', 0.16),
  ('CVE-2006-0079', 'CWE-862', 0.16), ('CVE-2006-0080', 'CWE-862', 0.16);
SELECT set_config('contrastapi.cve_events', '', true);

DO $$
DECLARE
  base       bigint;
  a_expected text[] := ARRAY[
    'cve_search:0.1|75:epss_above_min:0.08>0.16', 'cve_search:0.1|75:epss_level_up:0.16>0.21',
    'cve_search:0.1|76:epss_above_min:0.04>0.25', 'cve_search:0.1|80:epss_below_min:0.16>0.07',
    'cve_search:0.1|79:epss_level_up:0.12>0.21',
    'cve_search:0.15|75:epss_above_min:0.08>0.16', 'cve_search:0.15|75:epss_level_up:0.08>0.16',
    'cve_search:0.15|75:epss_level_up:0.16>0.21',
    'cve_search:0.15|76:epss_above_min:0.04>0.25', 'cve_search:0.15|76:epss_level_up:0.04>0.25',
    'cve_search:0.15|80:epss_below_min:0.16>0.07', 'cve_search:0.15|80:epss_level_down:0.16>0.07',
    'cve_search:0.15|78:epss_level_up:0.08>0.16',
    'cve_search:0.15|79:epss_above_min:0.12>0.21', 'cve_search:0.15|79:epss_level_up:0.12>0.21'];
  answer     text[];
BEGIN
  base := api.fn_watchlist_event_max_id();
  ASSERT pg_temp.t_edit('A', 'add', 'cve_search', p_cwe_id => 'CWE-862', p_min_epss => 0.1) = 'ok'
     AND pg_temp.t_edit('A', 'add', 'cve_search', p_cwe_id => 'CWE-862', p_min_epss => 0.15) = 'ok',
         'S43 key A adds J1 and J2';
  PERFORM set_config('contrastapi.cve_events', 'off', true);
  UPDATE cves SET epss_score = 0.16 WHERE cve_id = 'CVE-2006-0075';
  UPDATE cves SET epss_score = 0.21 WHERE cve_id = 'CVE-2006-0075';
  UPDATE cves SET epss_score = 0.25 WHERE cve_id = 'CVE-2006-0076';
  UPDATE cves SET epss_score = 0.07 WHERE cve_id = 'CVE-2006-0080';
  UPDATE cves SET epss_score = 0.16 WHERE cve_id = 'CVE-2006-0080';
  PERFORM set_config('contrastapi.cve_events', '', true);
  INSERT INTO cve_change_event (cve_id, event_type, previous_value, current_value) VALUES
    ('CVE-2006-0075', 'epss_changed',    0.08, 0.16),
    ('CVE-2006-0075', 'epss_level_up',   0.08, 0.16),
    ('CVE-2006-0075', 'epss_changed',    0.16, 0.21),
    ('CVE-2006-0075', 'epss_level_up',   0.16, 0.21),
    ('CVE-2006-0076', 'epss_changed',    0.04, 0.25),
    ('CVE-2006-0076', 'epss_level_up',   0.04, 0.25),
    ('CVE-2006-0080', 'epss_changed',    0.16, 0.07),
    ('CVE-2006-0080', 'epss_level_down', 0.16, 0.07);
  INSERT INTO cve_change_event (cve_id, event_type, changed_at, previous_value, current_value) VALUES
    ('CVE-2006-0078', 'epss_level_up', now(), 0.08, 0.16),
    ('CVE-2006-0079', 'epss_changed',  now(), 0.12, 0.21),
    ('CVE-2006-0079', 'epss_level_up', now(), 0.12, 0.21);
  answer := pg_temp.t_item_events('A', base);
  ASSERT answer = a_expected, format('S43 a level event is left out only when it crosses a min_epss that is the score of a level: %s', answer);
  ASSERT pg_temp.t_edit('A', NULL, NULL, p_is_cleared => true) = 'ok', 'S43 the clear after the level events answers ok';
END
$$;

SELECT set_config('contrastapi.cve_events', 'off', true);
INSERT INTO cves (cve_id, severity, cwe_id, epss_score) VALUES
  ('CVE-2006-0081', 'LOW', 'CWE-200', 0.2),
  ('CVE-2006-0082', 'LOW', 'CWE-200', 0.2);
UPDATE cves SET has_nuclei_template = true WHERE cve_id = 'CVE-2006-0081';
INSERT INTO kev_details (cve_id, known_ransomware_use, patch_deadline, required_action) VALUES
  ('CVE-2006-0082', true, '2024-02-05', 'Apply updates per vendor instructions.');
SELECT set_config('contrastapi.cve_events', '', true);

DO $$
DECLARE
  base     bigint;
  answer   text[];
BEGIN
  ASSERT pg_temp.t_edit('A', NULL, NULL, p_is_cleared => true) = 'ok', 'S44 the clear before the has_nuclei_template events answers ok';
  base := api.fn_watchlist_event_max_id();
  ASSERT pg_temp.t_edit('A', 'add', 'cve_search', p_has_nuclei_template => true) = 'ok'
     AND pg_temp.t_edit('A', 'add', 'cve_search', p_known_ransomware => true) = 'ok'
     AND pg_temp.t_edit('A', 'add', 'cve_search', p_min_epss => 0.1, p_has_nuclei_template => true) = 'ok',
         'S44 key A adds H1, R1 and H2';
  PERFORM pg_temp.t_cve_event_of('CVE-2006-0081', 'exploit_published');
  PERFORM pg_temp.t_cve_event_of('CVE-2006-0082', 'exploit_published');
  PERFORM pg_temp.t_cve_event_of('CVE-2006-0081', 'epss_changed', 0.05, 0.2);
  PERFORM pg_temp.t_cve_event_of('CVE-2006-0082', 'epss_changed', 0.05, 0.2);

  answer := pg_temp.t_item_events('A', base);
  ASSERT answer = ARRAY['cve_search:|81:exploit_published:>', 'cve_search:|82:exploit_published:>',
                        'cve_search:0.1|81:exploit_published:>', 'cve_search:0.1|81:epss_above_min:0.05>0.2'],
         format('S44 H1 and H2 hear the CVE with a template, R1 the CVE with ransomware use, and H2 no epss_above_min of 0082: %s', answer);
  ASSERT (SELECT array_agg(DISTINCT coalesce(x.item_min_epss::text, 'null') || '|' || coalesce(x.item_known_ransomware::text, 'null')
                                    || '|' || coalesce(x.item_has_nuclei_template::text, 'null'))
            FROM api.fn_watchlist_events(pg_temp.t_hash('A'), NULL, true, 100, 100, 600) AS x)
         = ARRAY['0.1|null|true', 'null|null|true', 'null|true|null'],
         'S44 each events row carries item_has_nuclei_template apart from item_known_ransomware';

  PERFORM set_config('contrastapi.cve_events', 'off', true);
  UPDATE cves SET has_nuclei_template = (cve_id = 'CVE-2006-0082') WHERE cve_id IN ('CVE-2006-0081', 'CVE-2006-0082');
  PERFORM set_config('contrastapi.cve_events', '', true);
  answer := pg_temp.t_item_events('A', base);
  ASSERT answer = ARRAY['cve_search:|82:exploit_published:>', 'cve_search:|82:exploit_published:>',
                        'cve_search:0.1|82:exploit_published:>', 'cve_search:0.1|82:epss_above_min:0.05>0.2'],
         format('S44 the template is tested as it is now, for the epss_above_min row too: %s', answer);
  ASSERT pg_temp.t_edit('A', NULL, NULL, p_is_cleared => true) = 'ok', 'S44 the clear after the has_nuclei_template events answers ok';
END
$$;

INSERT INTO t_watchlist_key VALUES ('P', repeat('9a', 32)), ('Q', repeat('9b', 32));
INSERT INTO api_keys (key_hash) VALUES (repeat('9a', 32)), (repeat('9b', 32));

CREATE FUNCTION pg_temp.t_edit_rows(p_label text, p_action text, p_endpoint_name text, p_cve_id text DEFAULT NULL,
                                    p_ecosystem text DEFAULT NULL, p_package_name text DEFAULT NULL, p_version text DEFAULT NULL,
                                    p_item_max_count integer DEFAULT 100, p_package_item_max_count integer DEFAULT 500,
                                    p_package_item_base_weight integer DEFAULT 100, p_package_weight_budget integer DEFAULT 100000,
                                    p_listed_versions_per_weight integer DEFAULT 20)
  RETURNS text[] LANGUAGE sql AS $$
  SELECT array_agg(x.edit_status || '|' || coalesce(x.endpoint_name, '-') || '|'
                   || concat_ws(',', x.cve_id, x.domain_name, x.ecosystem, x.package_name, x.version) || '|'
                   || coalesce(x.item_count::text, 'null') || '|' || coalesce(x.package_item_count::text, 'null')
                   ORDER BY x.ordinality)
    FROM pg_temp.t_watchlist_edit(pg_temp.t_hash(p_label), p_action, p_endpoint_name, p_cve_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
                                  NULL, NULL, false, p_item_max_count, NULL, NULL, 20, p_ecosystem, p_package_name, p_version,
                                  p_package_item_max_count, p_package_item_base_weight, p_package_weight_budget,
                                  p_listed_versions_per_weight) WITH ORDINALITY AS x
$$;

CREATE FUNCTION pg_temp.t_package_row_refusal(p_endpoint_name text, p_ecosystem text, p_package_name text, p_version text)
  RETURNS text LANGUAGE plpgsql AS $$
DECLARE
  new_item_id bigint;
  refused_by  text := 'none';
BEGIN
  BEGIN
    INSERT INTO watchlist_item (api_key_id, endpoint_name) VALUES (pg_temp.t_key_id('A'), p_endpoint_name)
    RETURNING watchlist_item.item_id INTO new_item_id;
    INSERT INTO watchlist_item_package (item_id, api_key_id, endpoint_name, last_event_id_before_add, ecosystem, package_name, version)
    VALUES (new_item_id, pg_temp.t_key_id('A'), p_endpoint_name, 0, p_ecosystem, p_package_name, p_version);
    RAISE SQLSTATE 'TUNDO';
  EXCEPTION
    WHEN check_violation OR unique_violation THEN
      GET STACKED DIAGNOSTICS refused_by = CONSTRAINT_NAME;
    WHEN SQLSTATE 'TUNDO' THEN
      NULL;
  END;
  RETURN refused_by;
END
$$;

DO $$
DECLARE
  c record;
BEGIN
  ASSERT pg_temp.t_edit('A', NULL, NULL, p_is_cleared => true) = 'ok' AND pg_temp.t_edit('B', NULL, NULL, p_is_cleared => true) = 'ok',
         'S45 the clear before the package items answers ok';
  FOR c IN SELECT * FROM (VALUES
      ('package_check', 'npm',       'lodash',                       NULL,                'none'),
      ('package_check', 'npm',       'lodash',                       '4.17.20',           'none'),
      ('package_check', 'SwiftURL',  'github.com/apple/swift-nio',   '2.0.0+build.1',     'none'),
      ('package_check', 'npm',       repeat('a', 256),               repeat('1', 128),    'none'),
      ('package_check', 'npm',       'løda',                         NULL,                'none'),
      ('package_check', 'NPM',       'lodash',                       NULL,                'watchlist_item_package_ecosystem_known'),
      ('package_check', 'Pub',       'lodash',                       NULL,                'watchlist_item_package_ecosystem_known'),
      ('package_check', 'npm',       '',                             NULL,                'watchlist_item_package_package_name_format'),
      ('package_check', 'npm',       'left pad',                     NULL,                'watchlist_item_package_package_name_format'),
      ('package_check', 'npm',       'lod' || chr(9) || 'ash',       NULL,                'watchlist_item_package_package_name_format'),
      ('package_check', 'npm',       'lod' || chr(127) || 'ash',     NULL,                'watchlist_item_package_package_name_format'),
      ('package_check', 'npm',       repeat('a', 257),               NULL,                'watchlist_item_package_package_name_format'),
      ('package_check', 'npm',       'lodash',                       '',                  'watchlist_item_package_version_form'),
      ('package_check', 'npm',       'lodash',                       '1.0 beta',          'watchlist_item_package_version_form'),
      ('package_check', 'npm',       'lodash',                       '1.0' || chr(10),    'watchlist_item_package_version_form'),
      ('package_check', 'npm',       'lodash',                       'é',                 'watchlist_item_package_version_form'),
      ('package_check', 'npm',       'lodash',                       repeat('1', 129),    'watchlist_item_package_version_form'),
      ('cve_lookup',    'npm',       'lodash',                       NULL,                'watchlist_item_package_endpoint_name_known'),
      ('dns_lookup',    'npm',       'lodash',                       NULL,                'watchlist_item_package_endpoint_name_known'))
      AS t (endpoint_name, ecosystem, package_name, version, refused_by) LOOP
    ASSERT pg_temp.t_package_row_refusal(c.endpoint_name, c.ecosystem, c.package_name, c.version) = c.refused_by,
           format('S45 the row %s/%s/%s/%s is refused by %s, got %s', c.endpoint_name, c.ecosystem, left(c.package_name, 20), left(c.version, 20),
                  c.refused_by, pg_temp.t_package_row_refusal(c.endpoint_name, c.ecosystem, c.package_name, c.version));
  END LOOP;
  ASSERT pg_temp.t_item_count('A') = 0, 'S45 the row checks leave no item';

  ASSERT pg_temp.t_edit('A', 'add', 'package_check', p_ecosystem => 'npm', p_package_name => 'Lodash') = 'ok', 'S45 key A adds npm Lodash';
  ASSERT pg_temp.t_package_row_refusal('package_check', 'npm', 'LODASH', NULL) = 'watchlist_item_package_key_package_unique',
         'S45 a second row of the same normalized name and no version breaks the unique key';
  ASSERT pg_temp.t_package_row_refusal('package_check', 'npm', 'LODASH', '1.0.0') = 'none', 'S45 a row with a version is another row';
  ASSERT pg_temp.t_edit('A', NULL, NULL, p_is_cleared => true) = 'ok', 'S45 the clear after the unique key answers ok';

  ASSERT (SELECT pg_get_indexdef(i.indexrelid) FROM pg_index AS i WHERE i.indexrelid = 'public.idx_watchlist_item_api_key_id'::regclass)
         = 'CREATE INDEX idx_watchlist_item_api_key_id ON public.watchlist_item USING btree (api_key_id, item_id)',
         'S45 idx_watchlist_item_api_key_id finds the items of a key in item_id order';
  ASSERT (SELECT p.oid FROM pg_proc AS p WHERE p.oid = 'api.fn_package_check_ecosystem(text)'::regprocedure)
         < 'api.fn_watchlist_endpoint_event_types(text)'::regprocedure::oid,
         'S45 sql/api.sql loads fn_package_check.sql before fn_watchlist.sql, so a body of fn_watchlist.sql can bind a function of it';
END
$$;

DO $$
DECLARE
  head bigint;
BEGIN
  UPDATE change_event_purge_state SET max_purged_event_id = api.fn_watchlist_event_max_id() + 7 WHERE event_table_name = 'package_advisory_change_event';
  head := api.fn_watchlist_event_max_id();
  ASSERT head > api.fn_cve_change_event_max_id(), 'S45 the head comes from the package side';
  ASSERT pg_temp.t_key_state('P') = 'none', 'S45 key P has no state before its first add';

  ASSERT pg_temp.t_edit_rows('P', 'add', 'package_check', p_ecosystem => 'NPM', p_package_name => 'Lodash')
         = ARRAY['ok|package_check|npm,Lodash|0|1'],
         'S45 the add answers the new item alone, with npm in its canonical case and the counts';
  ASSERT (SELECT wip.ecosystem || '|' || wip.package_name || '|' || wip.package_name_normalized || '|' || coalesce(wip.version, 'null')
                 || '|' || (wip.last_event_id_before_add = head)::text || '|' || wip.endpoint_name
            FROM watchlist_item_package AS wip WHERE wip.api_key_id = pg_temp.t_key_id('P'))
         = 'npm|Lodash|lodash|null|true|package_check',
         'S45 the child row holds the canonical ecosystem, the name as given, its normalized form and the head of the add';
  ASSERT pg_temp.t_key_state('P') = '0,0,' || head, 'S45 the first add of key P starts its scan at the head of every event table';
  ASSERT pg_temp.t_edit('Q', 'add', 'cve_lookup', p_cve_id => 'CVE-2006-0001', p_item_max_count => 0) = 'over_limit'
     AND pg_temp.t_key_state('Q') = '0,0,' || head,
         'S45 a refused first add of key Q writes its state at the head of every event table too';
  ASSERT (SELECT wks.last_cve_event_id < head FROM watchlist_key_state AS wks WHERE wks.api_key_id = pg_temp.t_key_id('A')),
         'S45 key A starts below the head';
  ASSERT pg_temp.t_edit('A', 'add', 'kev_lookup', p_cve_id => 'CVE-2006-0003') = 'ok', 'S45 key A adds an item';
  ASSERT (SELECT wks.last_cve_event_id = head FROM watchlist_key_state AS wks WHERE wks.api_key_id = pg_temp.t_key_id('A')),
         'S45 the add that opens the position of key A raises its scan start to the head of every event table';
  ASSERT pg_temp.t_edit('A', NULL, NULL, p_is_cleared => true) = 'ok', 'S45 the clear of key A answers ok';
  ASSERT pg_temp.t_edit_rows('P', 'add', 'package_check', p_ecosystem => 'npm', p_package_name => 'lodash')
         = ARRAY['ok|package_check|npm,Lodash|0|1'],
         'S45 an add of the same npm name in another case answers the item it holds and adds nothing';
  ASSERT pg_temp.t_edit_rows('P', 'add', 'package_check', p_ecosystem => 'npm', p_package_name => 'lodash', p_version => '4.17.20')
         = ARRAY['ok|package_check|npm,lodash,4.17.20|0|2'],
         'S45 a version makes another item';
  ASSERT pg_temp.t_edit_rows('P', 'add', 'package_check', p_ecosystem => 'npm', p_package_name => 'LODASH', p_version => '4.17.20')
         = ARRAY['ok|package_check|npm,lodash,4.17.20|0|2'],
         'S45 the same name and version is the same item';
  ASSERT pg_temp.t_edit_rows('P', 'add', 'package_check', p_ecosystem => 'npm', p_package_name => 'lodash', p_version => '4.17.21')
         = ARRAY['ok|package_check|npm,lodash,4.17.21|0|3'],
         'S45 another version is another item';
  ASSERT pg_temp.t_edit_rows('P', 'add', 'package_check', p_ecosystem => 'PyPI', p_package_name => 'Django_X')
         = ARRAY['ok|package_check|PyPI,Django_X|0|4']
     AND pg_temp.t_edit_rows('P', 'add', 'package_check', p_ecosystem => 'pypi', p_package_name => 'django-x')
         = ARRAY['ok|package_check|PyPI,Django_X|0|4']
     AND pg_temp.t_edit_rows('P', 'add', 'package_check', p_ecosystem => 'PYPI', p_package_name => 'django..x')
         = ARRAY['ok|package_check|PyPI,Django_X|0|4'],
         'S45 a PyPI name equals its PEP 503 form';
  ASSERT pg_temp.t_edit_rows('P', 'add', 'package_check', p_ecosystem => 'Maven', p_package_name => 'Org.Foo:Bar')
         = ARRAY['ok|package_check|Maven,Org.Foo:Bar|0|5']
     AND pg_temp.t_edit_rows('P', 'add', 'package_check', p_ecosystem => 'maven', p_package_name => 'org.foo:bar')
         = ARRAY['ok|package_check|Maven,org.foo:bar|0|6'],
         'S45 a Maven name keeps its case, so the two names are two items';
  ASSERT pg_temp.t_edit_rows('P', 'add', 'cve_lookup', p_cve_id => 'CVE-2006-0001') = ARRAY['ok|cve_lookup|CVE-2006-0001|1|6'],
         'S45 a CVE item answers alone, and counts apart from the package items';
  ASSERT (SELECT wic.last_event_id_before_add = head FROM watchlist_item_cve AS wic WHERE wic.api_key_id = pg_temp.t_key_id('P')),
         'S45 a CVE item starts at the same head';
  ASSERT pg_temp.t_edit_rows('P', NULL, NULL)
         = ARRAY['ok|package_check|npm,Lodash|1|6', 'ok|package_check|npm,lodash,4.17.20|1|6', 'ok|package_check|npm,lodash,4.17.21|1|6',
                 'ok|package_check|PyPI,Django_X|1|6', 'ok|package_check|Maven,Org.Foo:Bar|1|6', 'ok|package_check|Maven,org.foo:bar|1|6',
                 'ok|cve_lookup|CVE-2006-0001|1|6'],
         'S45 the list answers every item in item_id order, each row with the two counts';
  ASSERT pg_temp.t_items('P') @> ARRAY['package_check:npm,lodash,4.17.20'], 'S45 pg_temp.t_items shows a package item';

  ASSERT pg_temp.t_edit_rows('P', 'remove', 'package_check', p_ecosystem => 'Npm', p_package_name => 'LODASH')
         = ARRAY['ok|package_check|npm,Lodash|1|5'],
         'S45 the remove answers the item it deleted, as the add wrote it, and the counts after it';
  ASSERT (SELECT count(*) FROM watchlist_item_package AS wip WHERE wip.api_key_id = pg_temp.t_key_id('P')) = 5
     AND pg_temp.t_item_count('P') = 6
     AND NOT EXISTS (SELECT 1 FROM watchlist_item_package AS wip
                      WHERE wip.api_key_id = pg_temp.t_key_id('P') AND wip.package_name_normalized = 'lodash' AND wip.version IS NULL),
         'S45 the remove deletes the item and its child row, and keeps the items with a version';
  ASSERT pg_temp.t_edit_rows('P', 'remove', 'package_check', p_ecosystem => 'npm', p_package_name => 'left-pad')
         = ARRAY['ok|-||1|5'],
         'S45 the remove of an item the list does not hold answers no item, and the counts';
  ASSERT pg_temp.t_edit_rows('P', 'remove', 'package_check', p_ecosystem => 'npm', p_package_name => 'lodash', p_version => '4.17.22')
         = ARRAY['ok|-||1|5'],
         'S45 the remove finds no item of another version';
  ASSERT pg_temp.t_edit_rows('P', 'remove', 'cve_lookup', p_cve_id => 'CVE-2006-0001') = ARRAY['ok|cve_lookup|CVE-2006-0001|0|5'],
         'S45 the remove of a CVE item answers it alone';
  ASSERT pg_temp.t_edit_rows('P', 'add', 'cve_lookup', p_cve_id => 'CVE-2006-0002', p_ecosystem => 'npm', p_package_name => 'x')
         = ARRAY['ok|cve_lookup|CVE-2006-0002|1|5'],
         'S45 a CVE item ignores the package arguments';
  ASSERT pg_temp.t_edit_rows('P', NULL, NULL, p_ecosystem => 'npm', p_package_name => 'lodash')
         = ARRAY['ok|package_check|npm,lodash,4.17.20|1|5', 'ok|package_check|npm,lodash,4.17.21|1|5',
                 'ok|package_check|PyPI,Django_X|1|5', 'ok|package_check|Maven,Org.Foo:Bar|1|5', 'ok|package_check|Maven,org.foo:bar|1|5',
                 'ok|cve_lookup|CVE-2006-0002|1|5'],
         'S45 a list ignores the package arguments';

  BEGIN
    PERFORM pg_temp.t_edit_rows('P', 'add', 'package_check', p_ecosystem => 'Pub', p_package_name => 'x');
    ASSERT false, 'S45 a package item of an unknown ecosystem raises';
  EXCEPTION WHEN invalid_parameter_value THEN
    NULL;
  END;
  BEGIN
    PERFORM pg_temp.t_edit_rows('P', 'remove', 'package_check', p_ecosystem => 'npm');
    ASSERT false, 'S45 a package item without a name raises';
  EXCEPTION WHEN invalid_parameter_value THEN
    NULL;
  END;

  ASSERT pg_temp.t_edit('P', NULL, NULL, p_is_cleared => true) = 'ok',
         'S45 the clear of key P answers ok';
  ASSERT pg_temp.t_edit_rows('P', NULL, NULL) = ARRAY['ok|-||0|0'], 'S45 a list with no item answers the two counts at 0';
  UPDATE change_event_purge_state SET max_purged_event_id = 0 WHERE event_table_name = 'package_advisory_change_event';
END
$$;

DO $$
BEGIN
  ASSERT (SELECT count(*) FROM generate_series(1, 500) AS g (n)
           WHERE pg_temp.t_edit('A', 'add', 'package_check', p_ecosystem => 'npm', p_package_name => 'pkg-' || g.n) = 'ok') = 500,
         'S45 key A adds 500 package items';
  ASSERT pg_temp.t_edit('A', 'add', 'package_check', p_ecosystem => 'npm', p_package_name => 'pkg-1001') = 'over_package_limit',
         'S45 the 501st package item answers over_package_limit';
  ASSERT pg_temp.t_edit_rows('A', 'add', 'package_check', p_ecosystem => 'npm', p_package_name => 'pkg-1001') = ARRAY['over_package_limit|-||0|500'],
         'S45 over_package_limit answers one row with that status, the counts and no item';
  ASSERT pg_temp.t_edit('A', 'add', 'package_check', p_ecosystem => 'npm', p_package_name => 'PKG-7') = 'ok'
     AND pg_temp.t_item_count('A') = 500,
         'S45 an item already in a full list answers ok';
  ASSERT pg_temp.t_edit('A', 'add', 'package_check', p_ecosystem => 'npm', p_package_name => 'pkg-1001', p_package_item_max_count => 501) = 'ok'
     AND pg_temp.t_edit('A', 'remove', 'package_check', p_ecosystem => 'npm', p_package_name => 'pkg-1001') = 'ok',
         'S45 the package cap is p_package_item_max_count';

  ASSERT (SELECT count(*) FROM generate_series(1, 99) AS g (n)
           WHERE pg_temp.t_edit('A', 'add', 'cve_lookup', p_cve_id => 'CVE-2007-' || lpad(g.n::text, 4, '0')) = 'ok') = 99,
         'S45 500 package items do not count against the cap of the other items';
  ASSERT pg_temp.t_edit_rows('A', 'add', 'kev_lookup', p_cve_id => 'CVE-2007-0001') = ARRAY['ok|kev_lookup|CVE-2007-0001|100|500'],
         'S45 the 100th item that is no package item is added';
  ASSERT pg_temp.t_edit('A', 'add', 'kev_lookup', p_cve_id => 'CVE-2007-0002') = 'over_limit',
         'S45 the 101st item that is no package item answers over_limit';
  ASSERT pg_temp.t_edit('A', 'remove', 'package_check', p_ecosystem => 'npm', p_package_name => 'pkg-1') = 'ok'
     AND pg_temp.t_edit_rows('A', 'add', 'package_check', p_ecosystem => 'npm', p_package_name => 'pkg-1001')
         = ARRAY['ok|package_check|npm,pkg-1001|100|500'],
         'S45 a package item is added beside 100 other items, once a package item left';
  ASSERT pg_temp.t_edit('A', 'add', 'package_check', p_ecosystem => 'npm', p_package_name => 'pkg-1002') = 'over_package_limit'
     AND pg_temp.t_item_count('A') = 600,
         'S45 the package cap still holds beside 100 other items, with over_package_limit and not over_limit';
  ASSERT pg_temp.t_edit('A', 'add', 'cve_lookup', p_cve_id => 'CVE-2007-0100') = 'over_limit'
     AND pg_temp.t_edit('A', 'remove', 'kev_lookup', p_cve_id => 'CVE-2007-0001') = 'ok'
     AND pg_temp.t_edit_rows('A', 'add', 'cve_lookup', p_cve_id => 'CVE-2007-0100') = ARRAY['ok|cve_lookup|CVE-2007-0100|100|500'],
         'S45 an item that is no package item is added beside 500 package items, once such an item left';
  ASSERT pg_temp.t_edit('A', NULL, NULL, p_is_cleared => true) = 'ok', 'S45 the clear after the caps answers ok';
END
$$;

INSERT INTO osv_advisories (advisory_id, source, license, summary, aliases, published_time, modified_time) VALUES
  ('GHSA-wl46-0001', 'ghsa', 'CC-BY-4.0', '', ARRAY['CVE-2006-0003', 'GO-wl46-0001'], '2021-01-01T00:00:00Z', '2021-01-01T00:00:00Z'),
  ('GHSA-wl46-0002', 'ghsa', 'CC-BY-4.0', '', ARRAY['CVE-2006-0002', 'CVE-2006-0003', 'CVE-2099-0046'], '2021-01-02T00:00:00Z', '2021-01-02T00:00:00Z'),
  ('MAL-wl46-0001', 'mal', 'Apache-2.0', '', '{}'::text[], '2021-01-03T00:00:00Z', '2021-01-03T00:00:00Z'),
  ('GHSA-wl46-0003', 'ghsa', 'CC-BY-4.0', '', ARRAY['CVE-2006-0004'], '2021-01-04T00:00:00Z', '2021-01-04T00:00:00Z'),
  ('GHSA-wl46-0004', 'ghsa', 'CC-BY-4.0', '', '{}'::text[], '2021-01-05T00:00:00Z', '2021-01-05T00:00:00Z');
INSERT INTO osv_affected (advisory_id, affected_index, ecosystem, package_name, version_ranges, listed_versions, listed_versions_sortable, is_unaffected_provable)
SELECT af.advisory_id, af.affected_index, af.ecosystem, af.package_name, af.version_ranges::jsonb, af.listed_versions,
       ARRAY(SELECT array_to_string(public.fn_osv_version_sortable(af.ecosystem, kv.version_text), ' ')
               FROM unnest(af.listed_versions) WITH ORDINALITY AS kv (version_text, version_ordinal) ORDER BY kv.version_ordinal),
       af.is_unaffected_provable
  FROM (VALUES
    ('GHSA-wl46-0001', 0, 'npm', 'wl-pkg', '[{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}]', '{}'::text[], true),
    ('GHSA-wl46-0002', 0, 'npm', 'wl-pkg', '[{"type": "SEMVER", "events": [{"introduced": "3.0.0"}, {"fixed": "4.0.0"}]}]', '{}'::text[], true),
    ('MAL-wl46-0001', 0, 'npm', 'wl-pkg', '[{"type": "SEMVER", "events": [{"introduced": "0"}]}]', '{}'::text[], false),
    ('GHSA-wl46-0003', 0, 'npm', 'wl-other', '[{"type": "SEMVER", "events": [{"introduced": "0"}]}]', '{}'::text[], false),
    ('GHSA-wl46-0004', 0, 'PyPI', 'Wl_Pkg', '[{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]', '{}'::text[], false)
  ) AS af (advisory_id, affected_index, ecosystem, package_name, version_ranges, listed_versions, is_unaffected_provable);
INSERT INTO osv_affected_version_intervals (advisory_id, affected_index, interval_index, introduced_version_sortable, upper_version_sortable, upper_event, fixed_version)
SELECT iv.advisory_id, iv.affected_index, iv.interval_index,
       CASE WHEN iv.introduced_version IS NOT NULL THEN public.fn_osv_version_sortable(osvaf.ecosystem, iv.introduced_version) END,
       CASE WHEN iv.upper_version IS NOT NULL THEN public.fn_osv_version_sortable(osvaf.ecosystem, iv.upper_version) END,
       iv.upper_event, iv.fixed_version
  FROM (VALUES
    ('GHSA-wl46-0001', 0, 0, NULL::text, '2.0.0'::text, 'fixed'::text, '2.0.0'::text),
    ('GHSA-wl46-0002', 0, 0, '3.0.0', '4.0.0', 'fixed', '4.0.0'),
    ('MAL-wl46-0001', 0, 0, NULL, NULL, NULL, NULL),
    ('GHSA-wl46-0003', 0, 0, NULL, NULL, NULL, NULL),
    ('GHSA-wl46-0004', 0, 0, NULL, NULL, NULL, NULL)
  ) AS iv (advisory_id, affected_index, interval_index, introduced_version, upper_version, upper_event, fixed_version)
  JOIN osv_affected AS osvaf ON osvaf.advisory_id = iv.advisory_id AND osvaf.affected_index = iv.affected_index;

CREATE FUNCTION pg_temp.t_package_event(p_advisory_id text, p_event_type text, p_ecosystem text DEFAULT 'npm',
                                        p_package_name text DEFAULT 'wl-pkg', p_fixed_version text DEFAULT NULL)
  RETURNS bigint LANGUAGE sql AS $$
  INSERT INTO package_advisory_change_event (advisory_id, ecosystem, package_name_normalized, package_name, event_type, fixed_version)
  VALUES (p_advisory_id, p_ecosystem, public.fn_osv_normalize_package_name(p_ecosystem, p_package_name), p_package_name, p_event_type,
          p_fixed_version)
  RETURNING event_id
$$;

CREATE FUNCTION pg_temp.t_package_events(p_label text, p_replay_cursor bigint, p_is_repeat_requested boolean,
                                         p_event_row_count integer DEFAULT 100, p_scan_row_count integer DEFAULT 100)
  RETURNS text[] LANGUAGE sql AS $$
  WITH answer AS (
    SELECT * FROM api.fn_watchlist_events(pg_temp.t_hash(p_label), p_replay_cursor, p_is_repeat_requested, p_event_row_count,
                                          p_scan_row_count, 600) WITH ORDINALITY AS x)
  SELECT ARRAY[(SELECT min(a.events_status) || '|' || coalesce(min(a.next_cursor)::text, 'null') || '|' || bool_and(a.has_more)::text
                  FROM answer AS a)]
         || coalesce((SELECT array_agg(coalesce(pair.item_package_name || '@' || coalesce(pair.item_version, '*'), pair.item_cve_id) || ':'
                                       || first_row.event_type || ':' || coalesce(first_row.advisory_id, first_row.cve_id) || ':'
                                       || coalesce(pair.affects_version::text, 'null')
                                       ORDER BY pair.ordinality)
                        FROM answer AS pair
                        JOIN answer AS first_row ON first_row.event_rank = pair.event_rank AND first_row.is_first_row_of_event), '{}')
$$;

CREATE TEMP TABLE t_s46 (base bigint, event_ids bigint[]);

DO $$
DECLARE
  base      bigint;
  e         bigint[] := '{}';
  all_rows  text[];
BEGIN
  ASSERT pg_temp.t_edit('A', NULL, NULL, p_is_cleared => true) = 'ok' AND pg_temp.t_edit('B', NULL, NULL, p_is_cleared => true) = 'ok',
         'S46 the clear before the package events answers ok';
  ASSERT pg_temp.t_edit('A', 'add', 'package_check', p_ecosystem => 'npm', p_package_name => 'Wl-Pkg') = 'ok'
     AND pg_temp.t_edit('A', 'add', 'package_check', p_ecosystem => 'npm', p_package_name => 'WL-PKG', p_version => '1.0.0') = 'ok'
     AND pg_temp.t_edit('A', 'add', 'package_check', p_ecosystem => 'npm', p_package_name => 'wl-pkg', p_version => 'abc') = 'ok'
     AND pg_temp.t_edit('A', 'add', 'package_check', p_ecosystem => 'npm', p_package_name => 'wl-other') = 'ok'
     AND pg_temp.t_edit('A', 'add', 'package_check', p_ecosystem => 'PyPI', p_package_name => 'Wl_Pkg') = 'ok'
     AND pg_temp.t_edit('A', 'add', 'package_check', p_ecosystem => 'npm', p_package_name => 'wl-pkg', p_version => '1.0.1') = 'ok'
     AND pg_temp.t_edit('B', 'add', 'package_check', p_ecosystem => 'npm', p_package_name => 'wl-pkg') = 'ok',
         'S46 keys A and B add their package items';
  base := api.fn_watchlist_event_max_id();
  e := e || pg_temp.t_package_event('GHSA-wl46-0001', 'advisory_added');
  e := e || pg_temp.t_package_event('GHSA-wl46-0002', 'advisory_added');
  e := e || pg_temp.t_cve_event_of('CVE-2006-0003', 'cve_added');
  e := e || pg_temp.t_cve_event_of('CVE-2006-0003', 'kev_added');
  e := e || pg_temp.t_package_event('GHSA-wl46-0001', 'fix_available', p_fixed_version => '2.0.0');
  e := e || pg_temp.t_cve_event_of('CVE-2006-0002', 'ransomware_linked');
  e := e || pg_temp.t_package_event('MAL-wl46-0001', 'malware_added');
  e := e || pg_temp.t_package_event('GHSA-wl46-0003', 'advisory_added', p_package_name => 'wl-other');
  e := e || pg_temp.t_package_event('GHSA-wl46-0004', 'advisory_added', p_ecosystem => 'PyPI', p_package_name => 'wl.pkg');
  e := e || pg_temp.t_cve_event_of('CVE-2006-0001', 'kev_added');
  e := e || pg_temp.t_cve_event_of('CVE-2006-0004', 'kev_added');
  INSERT INTO t_s46 VALUES (base, e);
  ASSERT e[11] = base + 11, 'S46 the eleven events follow base';
  UPDATE watchlist_item_package SET last_event_id_before_add = base WHERE api_key_id IN (pg_temp.t_key_id('A'), pg_temp.t_key_id('B'));
  UPDATE watchlist_item_package SET last_event_id_before_add = e[5] WHERE api_key_id = pg_temp.t_key_id('A') AND version = '1.0.1';

  PERFORM pg_temp.t_rewind('A', base);
  all_rows := pg_temp.t_package_events('A', NULL, false);
  ASSERT all_rows
         = ARRAY['ok|9|false',
                 'Wl-Pkg@*:advisory_added:GHSA-wl46-0001:null', 'Wl-Pkg@*:advisory_added:GHSA-wl46-0002:null',
                 'Wl-Pkg@*:kev_added:CVE-2006-0003:null', 'Wl-Pkg@*:fix_available:GHSA-wl46-0001:null',
                 'Wl-Pkg@*:ransomware_linked:CVE-2006-0002:null', 'Wl-Pkg@*:malware_added:MAL-wl46-0001:null',
                 'WL-PKG@1.0.0:advisory_added:GHSA-wl46-0001:true', 'WL-PKG@1.0.0:kev_added:CVE-2006-0003:true',
                 'WL-PKG@1.0.0:fix_available:GHSA-wl46-0001:true', 'WL-PKG@1.0.0:malware_added:MAL-wl46-0001:true',
                 'wl-pkg@abc:advisory_added:GHSA-wl46-0001:null', 'wl-pkg@abc:advisory_added:GHSA-wl46-0002:null',
                 'wl-pkg@abc:kev_added:CVE-2006-0003:null', 'wl-pkg@abc:fix_available:GHSA-wl46-0001:null',
                 'wl-pkg@abc:ransomware_linked:CVE-2006-0002:null', 'wl-pkg@abc:malware_added:MAL-wl46-0001:null',
                 'wl-other@*:advisory_added:GHSA-wl46-0003:null', 'wl-other@*:kev_added:CVE-2006-0004:null',
                 'Wl_Pkg@*:advisory_added:GHSA-wl46-0004:null',
                 'wl-pkg@1.0.1:malware_added:MAL-wl46-0001:true'],
         'S46 each package item hears the events of its package and of the CVEs its advisories name, and the version filter drops false: '
         || all_rows::text;
  ASSERT (SELECT array_agg(wer.event_id - base || ':' || coalesce(wer.affects_version::text, 'null') ORDER BY wer.event_id)
            FROM watchlist_event_ref AS wer
            JOIN watchlist_item_package AS wip ON wip.item_id = wer.item_id
           WHERE wip.api_key_id = pg_temp.t_key_id('A') AND wip.version = '1.0.0')
         = ARRAY['1:true', '4:true', '5:true', '7:true'],
         'S46 the refs of I2 store affects_version true';
  ASSERT (SELECT bool_and(wer.affects_version IS NULL) AND count(*) = 6
            FROM watchlist_event_ref AS wer
            JOIN watchlist_item_package AS wip ON wip.item_id = wer.item_id
           WHERE wip.api_key_id = pg_temp.t_key_id('A') AND wip.version IS NULL AND wip.package_name = 'Wl-Pkg'),
         'S46 the refs of an item without a version store affects_version NULL';
  ASSERT pg_temp.t_package_events('A', NULL, true) = all_rows AND pg_temp.t_package_events('A', 0, false) = all_rows,
         'S46 a repeat and a replay answer the same rows, with the same affects_version';

  PERFORM pg_temp.t_rewind('B', base);
  ASSERT pg_temp.t_package_events('B', NULL, false)
         = ARRAY['ok|6|false',
                 'wl-pkg@*:advisory_added:GHSA-wl46-0001:null', 'wl-pkg@*:advisory_added:GHSA-wl46-0002:null',
                 'wl-pkg@*:kev_added:CVE-2006-0003:null', 'wl-pkg@*:fix_available:GHSA-wl46-0001:null',
                 'wl-pkg@*:ransomware_linked:CVE-2006-0002:null', 'wl-pkg@*:malware_added:MAL-wl46-0001:null'],
         'S46 key B hears the events of its own item only';
END
$$;

DO $$
DECLARE
  base bigint := (SELECT t.base FROM t_s46 AS t);
  e    bigint[] := (SELECT t.event_ids FROM t_s46 AS t);
BEGIN
  PERFORM pg_temp.t_rewind('A', base);
  ASSERT pg_temp.t_package_events('A', NULL, false, 100, 3)
         = ARRAY['ok|2|true',
                 'Wl-Pkg@*:advisory_added:GHSA-wl46-0001:null', 'Wl-Pkg@*:advisory_added:GHSA-wl46-0002:null',
                 'WL-PKG@1.0.0:advisory_added:GHSA-wl46-0001:true',
                 'wl-pkg@abc:advisory_added:GHSA-wl46-0001:null', 'wl-pkg@abc:advisory_added:GHSA-wl46-0002:null'],
         'S46 the first window holds e1, e2 and e3';
  ASSERT pg_temp.t_key_state('A') = '2,0,' || e[3], 'S46 the first window ends at e3, a CVE event';
  ASSERT pg_temp.t_package_events('A', NULL, false, 100, 3)
         = ARRAY['ok|5|true',
                 'Wl-Pkg@*:kev_added:CVE-2006-0003:null', 'Wl-Pkg@*:fix_available:GHSA-wl46-0001:null',
                 'Wl-Pkg@*:ransomware_linked:CVE-2006-0002:null',
                 'WL-PKG@1.0.0:kev_added:CVE-2006-0003:true', 'WL-PKG@1.0.0:fix_available:GHSA-wl46-0001:true',
                 'wl-pkg@abc:kev_added:CVE-2006-0003:null', 'wl-pkg@abc:fix_available:GHSA-wl46-0001:null',
                 'wl-pkg@abc:ransomware_linked:CVE-2006-0002:null'],
         'S46 the second window holds e4, e5 and e6';
  ASSERT pg_temp.t_package_events('A', NULL, false, 100, 3)
         = ARRAY['ok|8|true',
                 'Wl-Pkg@*:malware_added:MAL-wl46-0001:null', 'WL-PKG@1.0.0:malware_added:MAL-wl46-0001:true',
                 'wl-pkg@abc:malware_added:MAL-wl46-0001:null', 'wl-other@*:advisory_added:GHSA-wl46-0003:null',
                 'Wl_Pkg@*:advisory_added:GHSA-wl46-0004:null', 'wl-pkg@1.0.1:malware_added:MAL-wl46-0001:true'],
         'S46 the third window holds e7, e8 and e9';
  ASSERT pg_temp.t_package_events('A', NULL, false, 100, 3) = ARRAY['ok|9|false', 'wl-other@*:kev_added:CVE-2006-0004:null'],
         'S46 the last window holds e10 and e11, and has no more';

  UPDATE change_event_purge_state SET max_purged_event_id = e[5] WHERE event_table_name = 'package_advisory_change_event';
  PERFORM pg_temp.t_rewind('A', base);
  ASSERT pg_temp.t_package_events('A', NULL, false)
         = ARRAY['ok|6|false',
                 'Wl-Pkg@*:kev_added:CVE-2006-0003:null', 'Wl-Pkg@*:ransomware_linked:CVE-2006-0002:null',
                 'Wl-Pkg@*:malware_added:MAL-wl46-0001:null',
                 'WL-PKG@1.0.0:kev_added:CVE-2006-0003:true', 'WL-PKG@1.0.0:malware_added:MAL-wl46-0001:true',
                 'wl-pkg@abc:kev_added:CVE-2006-0003:null', 'wl-pkg@abc:ransomware_linked:CVE-2006-0002:null',
                 'wl-pkg@abc:malware_added:MAL-wl46-0001:null',
                 'wl-other@*:advisory_added:GHSA-wl46-0003:null', 'wl-other@*:kev_added:CVE-2006-0004:null',
                 'Wl_Pkg@*:advisory_added:GHSA-wl46-0004:null', 'wl-pkg@1.0.1:malware_added:MAL-wl46-0001:true'],
         'S46 the package floor at e5 skips e1, e2 and e5 and keeps the CVE events e4 and e6 below it';
  UPDATE change_event_purge_state SET max_purged_event_id = 0 WHERE event_table_name = 'package_advisory_change_event';
  UPDATE change_event_purge_state SET max_purged_event_id = e[6] WHERE event_table_name = 'cve_change_event';
  PERFORM pg_temp.t_rewind('A', base);
  ASSERT pg_temp.t_package_events('A', NULL, false)
         = ARRAY['ok|7|false',
                 'Wl-Pkg@*:advisory_added:GHSA-wl46-0001:null', 'Wl-Pkg@*:advisory_added:GHSA-wl46-0002:null',
                 'Wl-Pkg@*:fix_available:GHSA-wl46-0001:null', 'Wl-Pkg@*:malware_added:MAL-wl46-0001:null',
                 'WL-PKG@1.0.0:advisory_added:GHSA-wl46-0001:true', 'WL-PKG@1.0.0:fix_available:GHSA-wl46-0001:true',
                 'WL-PKG@1.0.0:malware_added:MAL-wl46-0001:true',
                 'wl-pkg@abc:advisory_added:GHSA-wl46-0001:null', 'wl-pkg@abc:advisory_added:GHSA-wl46-0002:null',
                 'wl-pkg@abc:fix_available:GHSA-wl46-0001:null', 'wl-pkg@abc:malware_added:MAL-wl46-0001:null',
                 'wl-other@*:advisory_added:GHSA-wl46-0003:null', 'wl-other@*:kev_added:CVE-2006-0004:null',
                 'Wl_Pkg@*:advisory_added:GHSA-wl46-0004:null', 'wl-pkg@1.0.1:malware_added:MAL-wl46-0001:true'],
         'S46 the CVE floor at e6 skips e3, e4 and e6 and keeps the package events e1, e2 and e5 below it';
  UPDATE change_event_purge_state SET max_purged_event_id = 0 WHERE event_table_name = 'cve_change_event';
END
$$;

DO $$
DECLARE
  base bigint := (SELECT t.base FROM t_s46 AS t);
  e    bigint[] := (SELECT t.event_ids FROM t_s46 AS t);
BEGIN
  UPDATE change_event_purge_state SET max_purged_event_id = e[6] WHERE event_table_name = 'cve_change_event';
  PERFORM pg_temp.t_rewind('A', base);
  CREATE TEMP TABLE t_s46_answer AS
    SELECT * FROM api.fn_watchlist_events(pg_temp.t_hash('A'), NULL, false, 100, 100, 600) WITH ORDINALITY AS x;
  UPDATE change_event_purge_state SET max_purged_event_id = 0 WHERE event_table_name = 'cve_change_event';

  ASSERT (SELECT array_agg(a.advisory_id || '|' || coalesce(a.advisory_source, 'null') || '|' || a.advisory_aliases::text || '|'
                           || (SELECT coalesce(array_agg(f ->> 'cve_id' ORDER BY f ->> 'cve_id'), '{}')::text
                                 FROM jsonb_array_elements(a.advisory_cve_facts) AS f)
                           ORDER BY a.ordinality)
            FROM t_s46_answer AS a WHERE a.is_first_event_of_advisory)
         = ARRAY['GHSA-wl46-0001|ghsa|["CVE-2006-0003", "GO-wl46-0001"]|{CVE-2006-0003}',
                 'GHSA-wl46-0002|ghsa|["CVE-2006-0002", "CVE-2006-0003", "CVE-2099-0046"]|{CVE-2006-0002}',
                 'MAL-wl46-0001|mal|[]|{}',
                 'GHSA-wl46-0003|ghsa|["CVE-2006-0004"]|{}',
                 'GHSA-wl46-0004|ghsa|[]|{}'],
         'S46 each advisory of the page has one first row with its source, its aliases and the facts of the CVEs no event names';
  ASSERT (SELECT bool_and(a.is_first_row_of_event AND a.advisory_id IS NOT NULL) FROM t_s46_answer AS a WHERE a.is_first_event_of_advisory)
     AND (SELECT bool_and(a.advisory_source IS NULL AND a.advisory_aliases IS NULL AND a.advisory_cve_facts IS NULL)
            FROM t_s46_answer AS a WHERE NOT a.is_first_event_of_advisory)
     AND (SELECT bool_and(a.is_first_event_of_advisory IS NOT NULL) FROM t_s46_answer AS a),
         'S46 the first row of an advisory is the first row of an event, only it carries the advisory columns, and the flag is never NULL';
  ASSERT (SELECT a.advisory_cve_facts -> 0 FROM t_s46_answer AS a WHERE a.is_first_event_of_advisory AND a.advisory_id = 'GHSA-wl46-0001')
         = (SELECT to_jsonb(f) || jsonb_build_object('cve_id', 'CVE-2006-0003') FROM api.fn_watchlist_cve_facts('CVE-2006-0003') AS f)
     AND (SELECT a.advisory_cve_facts -> 0 FROM t_s46_answer AS a WHERE a.is_first_event_of_advisory AND a.advisory_id = 'GHSA-wl46-0002')
         = (SELECT to_jsonb(f) || jsonb_build_object('cve_id', 'CVE-2006-0002') FROM api.fn_watchlist_cve_facts('CVE-2006-0002') AS f),
         'S46 an alias fact holds the cve_id and the columns of api.fn_watchlist_cve_facts';
  ASSERT (SELECT array_agg(a.cve_id ORDER BY a.ordinality) FROM t_s46_answer AS a WHERE a.is_first_event_of_cve) = ARRAY['CVE-2006-0004'],
         'S46 the facts of the CVE of e11 come on its own row';
  ASSERT (SELECT array_agg(coalesce(a.fixed_version, 'null') ORDER BY a.ordinality)
            FROM t_s46_answer AS a WHERE a.is_first_row_of_event AND a.item_package_name = 'Wl-Pkg')
         = ARRAY['null', 'null', '2.0.0', 'null'],
         'S46 only the fix_available event carries its fixed_version';
  ASSERT (SELECT count(DISTINCT a.attribution) = 1 AND bool_and(a.attribution IS NOT NULL) FROM t_s46_answer AS a)
     AND (SELECT a.attribution FROM t_s46_answer AS a WHERE a.ordinality = 1)
         = (SELECT v.attribution FROM api.fn_package_check_versions('npm', 'wl-pkg', ARRAY[NULL::text], 100, 0) AS v)
     AND jsonb_array_length((SELECT a.attribution FROM t_s46_answer AS a WHERE a.ordinality = 1)) = 2,
         'S46 every row carries the attribution of the ghsa and the mal advisories of the page, as api.fn_package_check_versions writes it';
  ASSERT (SELECT row(a.attribution, a.advisory_id, a.is_first_event_of_advisory)::text
            FROM api.fn_watchlist_events(pg_temp.t_hash('A'), 6, false, 100, 100, 600) AS a)
         = '([],,f)',
         'S46 a replay of e11 alone, a CVE event, carries an empty attribution and no advisory';
  ASSERT (SELECT row(a.events_status, a.attribution)::text FROM api.fn_watchlist_events(pg_temp.t_hash('A'), 7, false, 100, 100, 600) AS a)
         = '(ok,[])',
         'S46 an answer with no event carries an empty attribution';
  ASSERT (SELECT row(a.events_status, a.attribution)::text FROM api.fn_watchlist_events(pg_temp.t_hash('unknown'), NULL, false, 100, 100, 600) AS a)
         = '(unknown_key,[])',
         'S46 an answer with a status other than ok carries an empty attribution too';
  DROP TABLE t_s46_answer;

  BEGIN
    PERFORM pg_temp.t_package_event('GHSA-wl46-0099', 'advisory_added');
    PERFORM pg_temp.t_rewind('A', e[11]);
    ASSERT pg_temp.t_package_events('A', NULL, false)
           = ARRAY['ok|1|false', 'Wl-Pkg@*:advisory_added:GHSA-wl46-0099:null', 'WL-PKG@1.0.0:advisory_added:GHSA-wl46-0099:null',
                   'wl-pkg@abc:advisory_added:GHSA-wl46-0099:null', 'wl-pkg@1.0.1:advisory_added:GHSA-wl46-0099:null'],
           'S46 an event of an unknown advisory reaches I1, I2, I3 and I6, with affects_version NULL';
    ASSERT (SELECT row(a.advisory_source, a.advisory_aliases, a.advisory_cve_facts, a.attribution)::text
              FROM api.fn_watchlist_events(pg_temp.t_hash('A'), 0, false, 100, 100, 600) AS a WHERE a.is_first_event_of_advisory)
           = '(,[],[],[])',
           'S46 the first row of an unknown advisory has no source, no alias and no fact, and the answer credits no source';
    RAISE SQLSTATE 'TUNDO';
  EXCEPTION WHEN SQLSTATE 'TUNDO' THEN
    NULL;
  END;
END
$$;

DO $$
DECLARE
  base     bigint := (SELECT t.base FROM t_s46 AS t);
  all_rows text[];
BEGIN
  PERFORM pg_temp.t_rewind('A', base);
  all_rows := pg_temp.t_package_events('A', NULL, false);
  ASSERT all_rows[1] = 'ok|9|false' AND (pg_temp.t_package_events('A', NULL, true))[1] = 'ok|9|false'
     AND (pg_temp.t_package_events('A', 0, false))[1] = 'ok|9|false',
         'S46 with no event left, the normal call, the repeat and the replay have no more';
  BEGIN
    DELETE FROM osv_affected_version_intervals WHERE advisory_id IN ('GHSA-wl46-0001', 'MAL-wl46-0001');
    ASSERT pg_temp.t_package_events('A', 0, false) = all_rows AND pg_temp.t_package_events('A', NULL, true) = all_rows,
           'S46 a replay and a repeat answer the stored affects_version';
    PERFORM pg_temp.t_rewind('A', base);
    ASSERT ARRAY(SELECT r.row_text FROM unnest(pg_temp.t_package_events('A', NULL, false)) WITH ORDINALITY AS r (row_text, ordinality)
                  WHERE r.row_text LIKE 'WL-PKG@1.0.0:%' OR r.row_text LIKE 'wl-pkg@1.0.1:%' ORDER BY r.ordinality)
           = ARRAY['WL-PKG@1.0.0:malware_added:MAL-wl46-0001:null', 'wl-pkg@1.0.1:malware_added:MAL-wl46-0001:null'],
           'S46 a new scan asks the advisories again: GHSA-wl46-0001 now leaves I2 out, and MAL-wl46-0001 may affect I2 and I6';
    RAISE SQLSTATE 'TUNDO';
  EXCEPTION WHEN SQLSTATE 'TUNDO' THEN
    NULL;
  END;

  PERFORM pg_temp.t_package_event('GHSA-wl46-0001', 'advisory_added', p_package_name => 'wl-quiet');
  ASSERT (pg_temp.t_package_events('A', NULL, true))[1] = 'ok|9|true' AND (pg_temp.t_package_events('A', 0, false))[1] = 'ok|9|true',
         'S46 a repeat and a replay have more while a package event follows last_cve_event_id';
  DELETE FROM package_advisory_change_event WHERE package_name = 'wl-quiet';
END
$$;

DO $$
DECLARE
  e                    bigint[] := (SELECT t.event_ids FROM t_s46 AS t);
  key_a                integer := pg_temp.t_key_id('A');
  scan_count_before    bigint;
  one_event_scan_count bigint;
  four_event_scan_count bigint;
  quiet_item_scan_count bigint;
BEGIN
  ASSERT pg_temp.t_edit('A', NULL, NULL, p_is_cleared => true) = 'ok'
     AND pg_temp.t_edit('A', 'add', 'package_check', p_ecosystem => 'npm', p_package_name => 'wl-pkg', p_version => '1.0.0') = 'ok',
         'S46 key A holds I2 alone';
  UPDATE watchlist_item_package SET last_event_id_before_add = 0 WHERE api_key_id = key_a;
  SELECT sum(t.seq_scan + coalesce(t.idx_scan, 0)) INTO scan_count_before
    FROM pg_stat_xact_user_tables AS t WHERE t.relid = 'public.osv_affected_version_intervals'::regclass;
  ASSERT (SELECT count(*) FROM api.fn_watchlist_event_package_pairs(key_a, ARRAY[e[1]])) = 1, 'S46 I2 hears e1';
  SELECT sum(t.seq_scan + coalesce(t.idx_scan, 0)) - scan_count_before INTO one_event_scan_count
    FROM pg_stat_xact_user_tables AS t WHERE t.relid = 'public.osv_affected_version_intervals'::regclass;

  SELECT sum(t.seq_scan + coalesce(t.idx_scan, 0)) INTO scan_count_before
    FROM pg_stat_xact_user_tables AS t WHERE t.relid = 'public.osv_affected_version_intervals'::regclass;
  ASSERT (SELECT count(*) FROM api.fn_watchlist_event_package_pairs(key_a, ARRAY[e[1], e[4], e[5], e[7]])) = 4, 'S46 I2 hears four events';
  SELECT sum(t.seq_scan + coalesce(t.idx_scan, 0)) - scan_count_before INTO four_event_scan_count
    FROM pg_stat_xact_user_tables AS t WHERE t.relid = 'public.osv_affected_version_intervals'::regclass;

  FOR i IN 1..20 LOOP
    ASSERT pg_temp.t_edit('A', 'add', 'package_check', p_ecosystem => 'npm', p_package_name => 'wl-other', p_version => '1.0.' || i) = 'ok',
           'S46 key A adds quiet item ' || i;
  END LOOP;
  UPDATE watchlist_item_package SET last_event_id_before_add = 0 WHERE api_key_id = key_a;
  SELECT sum(t.seq_scan + coalesce(t.idx_scan, 0)) INTO scan_count_before
    FROM pg_stat_xact_user_tables AS t WHERE t.relid = 'public.osv_affected_version_intervals'::regclass;
  ASSERT (SELECT count(*) FROM api.fn_watchlist_event_package_pairs(key_a, ARRAY[e[1]])) = 1, 'S46 the quiet items hear nothing';
  SELECT sum(t.seq_scan + coalesce(t.idx_scan, 0)) - scan_count_before INTO quiet_item_scan_count
    FROM pg_stat_xact_user_tables AS t WHERE t.relid = 'public.osv_affected_version_intervals'::regclass;

  ASSERT one_event_scan_count > 0, 'S46 the version check of I2 reads osv_affected_version_intervals';
  ASSERT four_event_scan_count = one_event_scan_count AND quiet_item_scan_count = one_event_scan_count,
         format('S46 the version check runs once per item an event reaches: %s, %s, %s',
                one_event_scan_count, four_event_scan_count, quiet_item_scan_count);
  ASSERT pg_temp.t_edit('A', NULL, NULL, p_is_cleared => true) = 'ok' AND pg_temp.t_edit('B', NULL, NULL, p_is_cleared => true) = 'ok',
         'S46 the clear at the end answers ok';
  DELETE FROM package_advisory_change_event;
END
$$;

DO $$
DECLARE
  c record;
BEGIN
  FOR c IN SELECT * FROM (VALUES ('npm'), ('PyPI'), ('Maven'), ('Go'), ('NuGet'), ('RubyGems'), ('crates.io'), ('Packagist'), ('SwiftURL'))
                         AS t (ecosystem) LOOP
    ASSERT pg_temp.t_package_row_refusal('package_check', c.ecosystem, 'g-pkg', NULL) = 'none',
           format('S47 the ecosystem %s is known', c.ecosystem);
  END LOOP;
  ASSERT pg_temp.t_package_row_refusal('package_check', 'npm', 'g-pkg', '!1.0~') = 'none', 'S47 a version may hold ! and ~';
END
$$;

INSERT INTO osv_advisories (advisory_id, source, license, summary, aliases, published_time, modified_time) VALUES
  ('GHSA-gd47-0001', 'ghsa', 'CC-BY-4.0', '', ARRAY['CVE-2006-0003', 'CVE-2006-0002'], '2021-01-01T00:00:00Z', '2021-01-01T00:00:00Z'),
  ('GHSA-gd47-0002', 'ghsa', 'CC-BY-4.0', '', '{}'::text[], '2021-01-01T00:00:00Z', '2021-01-01T00:00:00Z'),
  ('GHSA-gd47-0003', 'ghsa', 'CC-BY-4.0', '', ARRAY['CVE-2006-0004'], '2021-01-01T00:00:00Z', '2021-01-01T00:00:00Z'),
  ('GHSA-gd47-0004', 'ghsa', 'CC-BY-4.0', '', ARRAY['CVE-2006-0004'], '2021-01-01T00:00:00Z', '2021-01-01T00:00:00Z'),
  ('GO-gd47-0005', 'go', 'CC-BY-4.0', '', '{}'::text[], '2021-01-01T00:00:00Z', '2021-01-01T00:00:00Z'),
  ('PYSEC-gd47-0006', 'pysec', 'CC-BY-4.0', '', '{}'::text[], '2021-01-01T00:00:00Z', '2021-01-01T00:00:00Z'),
  ('RUSTSEC-gd47-0007', 'rustsec', 'CC0-1.0', '', '{}'::text[], '2021-01-01T00:00:00Z', '2021-01-01T00:00:00Z'),
  ('MAL-gd47-0008', 'mal', 'Apache-2.0', '', '{}'::text[], '2021-01-01T00:00:00Z', '2021-01-01T00:00:00Z');
INSERT INTO osv_affected (advisory_id, affected_index, ecosystem, package_name, version_ranges, listed_versions, listed_versions_sortable, is_unaffected_provable)
SELECT af.advisory_id, af.affected_index, af.ecosystem, af.package_name, af.version_ranges::jsonb, af.listed_versions,
       ARRAY(SELECT array_to_string(public.fn_osv_version_sortable(af.ecosystem, kv.version_text), ' ')
               FROM unnest(af.listed_versions) WITH ORDINALITY AS kv (version_text, version_ordinal) ORDER BY kv.version_ordinal),
       af.is_unaffected_provable
  FROM (VALUES
    ('GHSA-gd47-0001', 0, 'npm', 'gd-a', '[{"type": "SEMVER", "events": [{"introduced": "0"}]}]', '{}'::text[], false),
    ('GHSA-gd47-0002', 0, 'npm', 'gd-a', '[{"type": "SEMVER", "events": [{"introduced": "0"}]}]', '{}'::text[], false),
    ('GHSA-gd47-0002', 1, 'npm', 'gd-b', '[{"type": "SEMVER", "events": [{"introduced": "0"}]}]', '{}'::text[], false),
    ('GHSA-gd47-0003', 0, 'npm', 'gd-a', '[{"type": "SEMVER", "events": [{"introduced": "3.0.0"}, {"fixed": "4.0.0"}]}]', '{}'::text[], true),
    ('GHSA-gd47-0004', 0, 'npm', 'gd-a', '[{"type": "GIT", "repo": "https://example.com/r", "events": [{"introduced": "0"}, {"fixed": "abc"}]}]', '{}'::text[], false),
    ('GO-gd47-0005', 0, 'npm', 'gd-a', '[{"type": "SEMVER", "events": [{"introduced": "0"}]}]', '{}'::text[], false),
    ('PYSEC-gd47-0006', 0, 'npm', 'gd-a', '[{"type": "SEMVER", "events": [{"introduced": "0"}]}]', '{}'::text[], false),
    ('RUSTSEC-gd47-0007', 0, 'npm', 'gd-a', '[{"type": "SEMVER", "events": [{"introduced": "0"}]}]', '{}'::text[], false),
    ('MAL-gd47-0008', 0, 'npm', 'gd-a', '[{"type": "SEMVER", "events": [{"introduced": "0"}]}]', '{}'::text[], false)
  ) AS af (advisory_id, affected_index, ecosystem, package_name, version_ranges, listed_versions, is_unaffected_provable);
INSERT INTO osv_affected_version_intervals (advisory_id, affected_index, interval_index, introduced_version_sortable, upper_version_sortable, upper_event, fixed_version)
SELECT iv.advisory_id, iv.affected_index, iv.interval_index,
       CASE WHEN iv.introduced_version IS NOT NULL THEN public.fn_osv_version_sortable(osvaf.ecosystem, iv.introduced_version) END,
       CASE WHEN iv.upper_version IS NOT NULL THEN public.fn_osv_version_sortable(osvaf.ecosystem, iv.upper_version) END,
       iv.upper_event, iv.fixed_version
  FROM (VALUES
    ('GHSA-gd47-0001', 0, 0, NULL::text, NULL::text, NULL::text, NULL::text),
    ('GHSA-gd47-0002', 0, 0, NULL, NULL, NULL, NULL),
    ('GHSA-gd47-0002', 1, 0, NULL, NULL, NULL, NULL),
    ('GHSA-gd47-0003', 0, 0, '3.0.0', '4.0.0', 'fixed', '4.0.0'),
    ('GO-gd47-0005', 0, 0, NULL, NULL, NULL, NULL),
    ('PYSEC-gd47-0006', 0, 0, NULL, NULL, NULL, NULL),
    ('RUSTSEC-gd47-0007', 0, 0, NULL, NULL, NULL, NULL),
    ('MAL-gd47-0008', 0, 0, NULL, NULL, NULL, NULL)
  ) AS iv (advisory_id, affected_index, interval_index, introduced_version, upper_version, upper_event, fixed_version)
  JOIN osv_affected AS osvaf ON osvaf.advisory_id = iv.advisory_id AND osvaf.affected_index = iv.affected_index;

DO $$
DECLARE
  base bigint;
  e    bigint[] := '{}';
  rows text[];
BEGIN
  ASSERT pg_temp.t_edit('A', 'add', 'package_check', p_ecosystem => 'npm', p_package_name => 'gd-b') = 'ok'
     AND pg_temp.t_edit('A', 'add', 'package_check', p_ecosystem => 'npm', p_package_name => 'gd-a', p_version => '1.0.0') = 'ok',
         'S47 key A adds gd-b, then gd-a at 1.0.0';
  ASSERT (SELECT array_agg(a.advisory_id || ':' || coalesce(a.affects_version::text, 'null') ORDER BY a.advisory_id)
            FROM api.fn_package_check_advisory('npm', 'gd-a', '1.0.0') AS a WHERE a.advisory_id IN ('GHSA-gd47-0003', 'GHSA-gd47-0004'))
         = ARRAY['GHSA-gd47-0003:false', 'GHSA-gd47-0004:null'],
         'S47 GHSA-gd47-0003 proves 1.0.0 unaffected and GHSA-gd47-0004 cannot judge it';
  base := api.fn_watchlist_event_max_id();
  e := e || pg_temp.t_package_event('GHSA-gd47-0002', 'advisory_added', p_package_name => 'gd-a');
  e := e || pg_temp.t_package_event('GHSA-gd47-0002', 'advisory_added', p_package_name => 'gd-b');
  e := e || pg_temp.t_cve_event_of('CVE-2006-0004', 'kev_added');
  e := e || pg_temp.t_package_event('GHSA-gd47-0001', 'advisory_added', p_package_name => 'gd-a');
  e := e || pg_temp.t_package_event('GO-gd47-0005', 'advisory_added', p_package_name => 'gd-a');
  e := e || pg_temp.t_package_event('PYSEC-gd47-0006', 'advisory_added', p_package_name => 'gd-a');
  e := e || pg_temp.t_package_event('RUSTSEC-gd47-0007', 'advisory_added', p_package_name => 'gd-a');
  e := e || pg_temp.t_package_event('MAL-gd47-0008', 'malware_added', p_package_name => 'gd-a');
  UPDATE watchlist_item_package SET last_event_id_before_add = base WHERE api_key_id = pg_temp.t_key_id('A');
  PERFORM pg_temp.t_rewind('A', base);
  ASSERT (SELECT s.page_event_ids FROM api.fn_watchlist_event_scan(pg_temp.t_key_id('A'), base, e[1], 100, 100, 600) AS s) = ARRAY[e[1]],
         'S47 the scan stops at p_head_event_id for the package events too';
  CREATE TEMP TABLE t_s47_answer AS
    SELECT * FROM api.fn_watchlist_events(pg_temp.t_hash('A'), NULL, false, 100, 100, 600) WITH ORDINALITY AS x;
  rows := pg_temp.t_package_events('A', 0, false);
  ASSERT rows[1] = 'ok|8|false' AND (pg_temp.t_package_events('A', NULL, true))[1] = 'ok|8|false',
         'S47 the scan ended at e8, a package event, so a replay and a repeat have no more: ' || rows[1];
  ASSERT 'gd-a@1.0.0:kev_added:CVE-2006-0004:null' = ANY (rows),
         'S47 an alias event that one advisory proves unaffected and another cannot judge keeps affects_version NULL: ' || rows::text;
  ASSERT (SELECT wer.affects_version IS NULL FROM watchlist_event_ref AS wer WHERE wer.event_id = e[3]),
         'S47 its ref stores NULL, never false';
  ASSERT (SELECT bool_and(a.item_ecosystem = 'npm') FROM t_s47_answer AS a),
         'S47 every row carries item_ecosystem';
  ASSERT (SELECT jsonb_path_query_array(a.advisory_cve_facts, '$[*].cve_id') FROM t_s47_answer AS a
           WHERE a.is_first_event_of_advisory AND a.advisory_id = 'GHSA-gd47-0001') = '["CVE-2006-0002", "CVE-2006-0003"]'::jsonb,
         'S47 advisory_cve_facts come in cve_id order';
  ASSERT (SELECT a.item_package_name FROM t_s47_answer AS a WHERE a.is_first_event_of_advisory AND a.advisory_id = 'GHSA-gd47-0002') = 'gd-b',
         'S47 the first row of an advisory of two packages is the first one in answer order';
  ASSERT (SELECT a.attribution FROM t_s47_answer AS a WHERE a.ordinality = 1)
         = (SELECT v.attribution FROM api.fn_package_check_versions('npm', 'gd-a', ARRAY[NULL::text], 100, 0) AS v)
     AND jsonb_array_length((SELECT a.attribution FROM t_s47_answer AS a WHERE a.ordinality = 1)) = 5,
         'S47 the attribution of five sources equals the one api.fn_package_check_versions writes';
  DROP TABLE t_s47_answer;

  UPDATE watchlist_item_package SET last_event_id_before_add = e[3] WHERE api_key_id = pg_temp.t_key_id('A') AND version = '1.0.0';
  PERFORM pg_temp.t_rewind('A', base);
  rows := pg_temp.t_package_events('A', NULL, false);
  ASSERT NOT ('gd-a@1.0.0:kev_added:CVE-2006-0004:null' = ANY (rows)) AND 'gd-a@1.0.0:advisory_added:GHSA-gd47-0001:true' = ANY (rows),
         'S47 an item does not hear the alias event whose event_id is its last_event_id_before_add: ' || rows::text;
  ASSERT pg_temp.t_edit('A', NULL, NULL, p_is_cleared => true) = 'ok', 'S47 the clear at the end answers ok';
  DELETE FROM package_advisory_change_event;
END
$$;

INSERT INTO osv_advisories (advisory_id, source, license, summary, aliases, published_time, modified_time) VALUES
  ('GHSA-wt48-0001', 'ghsa', 'CC-BY-4.0', '', '{}'::text[], '2021-01-01T00:00:00Z', '2021-01-01T00:00:00Z'),
  ('GHSA-wt48-0002', 'ghsa', 'CC-BY-4.0', '', '{}'::text[], '2021-01-01T00:00:00Z', '2021-01-01T00:00:00Z'),
  ('GHSA-wt48-0003', 'ghsa', 'CC-BY-4.0', '', '{}'::text[], '2021-01-01T00:00:00Z', '2021-01-01T00:00:00Z'),
  ('GHSA-wt48-0004', 'ghsa', 'CC-BY-4.0', '', '{}'::text[], '2021-01-01T00:00:00Z', '2021-01-01T00:00:00Z');
INSERT INTO osv_affected (advisory_id, affected_index, ecosystem, package_name, version_ranges, listed_versions, listed_versions_sortable, is_unaffected_provable)
SELECT af.advisory_id, af.affected_index, af.ecosystem, af.package_name, af.version_ranges::jsonb, af.listed_versions,
       ARRAY(SELECT array_to_string(public.fn_osv_version_sortable(af.ecosystem, kv.version_text), ' ')
               FROM unnest(af.listed_versions) WITH ORDINALITY AS kv (version_text, version_ordinal) ORDER BY kv.version_ordinal),
       af.is_unaffected_provable
  FROM (VALUES
    ('GHSA-wt48-0001', 0, 'npm', 'wt-rows', '[{"type": "SEMVER", "events": [{"introduced": "0"}]}]', '{}'::text[], false),
    ('GHSA-wt48-0002', 0, 'npm', 'wt-rows', '[{"type": "SEMVER", "events": [{"introduced": "0"}]}]', '{}'::text[], false),
    ('GHSA-wt48-0003', 0, 'PyPI', 'wt-rows', '[{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]', '{}'::text[], false),
    ('GHSA-wt48-0004', 0, 'npm', 'wt-list', '[]', ARRAY['0.1.0', '0.2.0', '0.3.0', '0.4.0', '0.5.0', '0.6.0', '0.7.0', '0.8.0', '0.9.0', '0.10.0', '0.11.0', '0.12.0', '0.13.0', '0.14.0', '0.15.0', '0.16.0', '0.17.0', '0.18.0', '0.19.0', '0.20.0', '0.21.0', '0.22.0', '0.23.0', '0.24.0', '0.25.0', '0.26.0', '0.27.0', '0.28.0', '0.29.0', '0.30.0', '0.31.0', '0.32.0', '0.33.0', '0.34.0', '0.35.0', '0.36.0', '0.37.0', '0.38.0', '0.39.0', '0.40.0'], false)
  ) AS af (advisory_id, affected_index, ecosystem, package_name, version_ranges, listed_versions, is_unaffected_provable);
INSERT INTO osv_affected_version_intervals (advisory_id, affected_index, interval_index, introduced_version_sortable, upper_version_sortable, upper_event, fixed_version)
SELECT iv.advisory_id, iv.affected_index, iv.interval_index,
       CASE WHEN iv.introduced_version IS NOT NULL THEN public.fn_osv_version_sortable(osvaf.ecosystem, iv.introduced_version) END,
       CASE WHEN iv.upper_version IS NOT NULL THEN public.fn_osv_version_sortable(osvaf.ecosystem, iv.upper_version) END,
       iv.upper_event, iv.fixed_version
  FROM (VALUES
    ('GHSA-wt48-0001', 0, 0, NULL::text, NULL::text, NULL::text, NULL::text),
    ('GHSA-wt48-0002', 0, 0, NULL, NULL, NULL, NULL),
    ('GHSA-wt48-0003', 0, 0, NULL, NULL, NULL, NULL)
  ) AS iv (advisory_id, affected_index, interval_index, introduced_version, upper_version, upper_event, fixed_version)
  JOIN osv_affected AS osvaf ON osvaf.advisory_id = iv.advisory_id AND osvaf.affected_index = iv.affected_index;

DO $$
BEGIN
  ASSERT (SELECT count(*) FROM osv_affected AS oa WHERE oa.ecosystem = 'npm' AND oa.package_name_normalized = 'wt-rows') = 2
     AND (SELECT count(*) FROM osv_affected AS oa WHERE oa.ecosystem = 'PyPI' AND oa.package_name_normalized = 'wt-rows') = 1
     AND NOT EXISTS (SELECT 1 FROM osv_affected AS oa WHERE oa.ecosystem = 'npm' AND oa.package_name_normalized = 'wt-a'),
         'S48 npm wt-rows has two rows in osv_affected, PyPI wt-rows has one, and wt-a has none';
  ASSERT (SELECT array_agg(cardinality(oa.listed_versions)) FROM osv_affected AS oa
           WHERE oa.ecosystem = 'npm' AND oa.package_name_normalized = 'wt-list') = ARRAY[40],
         'S48 npm wt-list has one row that lists 40 versions';
  ASSERT pg_temp.t_edit('A', NULL, NULL, p_is_cleared => true) = 'ok'
     AND pg_temp.t_edit('B', NULL, NULL, p_is_cleared => true) = 'ok', 'S48 keys A and B start empty';
  ASSERT pg_temp.t_edit('A', 'add', 'package_check', p_ecosystem => 'npm', p_package_name => 'wt-a',
                        p_package_weight_budget => 301) = 'ok'
     AND pg_temp.t_edit('A', 'add', 'package_check', p_ecosystem => 'npm', p_package_name => 'wt-rows', p_version => '1.0.0',
                        p_package_weight_budget => 301) = 'ok',
         'S48 wt-a and wt-rows at 1.0.0 weigh 100 + 102 = 202, within 301';
  ASSERT pg_temp.t_edit_rows('A', 'add', 'package_check', p_ecosystem => 'npm', p_package_name => 'WT-Rows', p_version => '2.0.0',
                             p_package_weight_budget => 303)
         = ARRAY['over_package_weight|-||0|2'],
         'S48 a second version of wt-rows, named in another case, is weighed in its normalized form and counts its rows again: 304 is past 303, so the add answers one row with over_package_weight and no item';
  ASSERT pg_temp.t_items('A') = ARRAY['package_check:npm,wt-a', 'package_check:npm,wt-rows,1.0.0'],
         'S48 the refused add changed nothing';
  ASSERT pg_temp.t_edit('A', 'add', 'package_check', p_ecosystem => 'npm', p_package_name => 'wt-rows', p_version => '2.0.0',
                        p_package_weight_budget => 304) = 'ok',
         'S48 a weight equal to the budget is within it';
  ASSERT pg_temp.t_edit('A', 'add', 'package_check', p_ecosystem => 'npm', p_package_name => 'wt-a', p_version => '1.0.0',
                        p_package_item_base_weight => 0, p_package_weight_budget => 4) = 'ok'
     AND pg_temp.t_edit('A', 'add', 'package_check', p_ecosystem => 'npm', p_package_name => 'wt-a', p_version => '2.0.0',
                        p_package_item_base_weight => 1, p_package_weight_budget => 8) = 'over_package_weight',
         'S48 the base weight is p_package_item_base_weight: 0 + 2 + 2 + 0 = 4 fits 4, and 1 + 3 + 3 + 1 + 1 = 9 does not fit 8';
  ASSERT pg_temp.t_edit('A', 'add', 'cve_lookup', p_cve_id => 'CVE-2006-0001', p_package_weight_budget => 0) = 'ok',
         'S48 an item that is not a package item is never weighed';
  ASSERT pg_temp.t_edit('A', 'add', 'package_check', p_ecosystem => 'npm', p_package_name => 'wt-b',
                        p_package_item_max_count => 4, p_package_weight_budget => 0) = 'over_package_limit',
         'S48 an add past both the package item cap and the budget answers over_package_limit';
  ASSERT pg_temp.t_edit('B', 'add', 'package_check', p_ecosystem => 'npm', p_package_name => 'wt-rows', p_version => '9.0.0',
                        p_package_weight_budget => 102) = 'ok',
         'S48 the items of key A weigh nothing for key B';
  ASSERT pg_temp.t_edit('B', 'add', 'package_check', p_ecosystem => 'npm', p_package_name => 'wt-list', p_version => '0.1.0',
                        p_package_weight_budget => 204) = 'over_package_weight',
         'S48 the 40 listed versions of wt-list add 2 units at 20 per unit: 102 + 103 = 205 is past 204';
  ASSERT pg_temp.t_edit('B', 'add', 'package_check', p_ecosystem => 'npm', p_package_name => 'wt-list', p_version => '0.1.0',
                        p_package_weight_budget => 204, p_listed_versions_per_weight => 40) = 'ok',
         'S48 p_listed_versions_per_weight divides the listed versions: at 40 per unit wt-list weighs 102, and 204 fits 204';
  ASSERT pg_temp.t_edit('A', NULL, NULL, p_is_cleared => true) = 'ok'
     AND pg_temp.t_edit('B', NULL, NULL, p_is_cleared => true) = 'ok', 'S48 the clears at the end answer ok';
  DELETE FROM package_advisory_change_event;
END
$$;

DO $$
DECLARE
  r record;
BEGIN
  SELECT * INTO r FROM api.fn_watchlist_edit_cve_search(pg_temp.t_hash('A'), 'add', NULL, NULL, 'HIGH', 'CWE-79', 7.5, 0.25, true, true, NULL, 100);
  ASSERT r.edit_status = 'ok' AND r.endpoint_name = 'cve_search' AND r.severity = 'HIGH' AND r.cwe_id = 'CWE-79'
     AND r.min_cvss = 7.5 AND r.min_epss = 0.25 AND r.in_kev AND r.known_ransomware AND r.has_nuclei_template IS NULL,
         'S50 a cve_search add answers each filter in its own column';
  SELECT * INTO r FROM api.fn_watchlist_edit_product_exposure(pg_temp.t_hash('A'), 'add', 'wlacme', 'wlwidget', NULL, 100);
  ASSERT r.edit_status = 'ok' AND r.vendor = 'wlacme' AND r.product = 'wlwidget' AND r.product_has_cves IS TRUE AND r.version IS NULL,
         'S50 a product_exposure add of a pair with CVEs answers product_has_cves true and no version';
  SELECT * INTO r FROM api.fn_watchlist_edit_product_exposure(pg_temp.t_hash('A'), 'add', 'wlnobody', 'wlnothing', NULL, 100);
  ASSERT r.edit_status = 'ok' AND r.product_has_cves IS FALSE,
         'S50 a pair without CVEs answers false';
  ASSERT pg_temp.t_edit('A', NULL, NULL, p_is_cleared => true) = 'ok', 'S50 the clear at the end answers ok';
END
$$;

DO $$
DECLARE
  endpoint text;
BEGIN
  ASSERT pg_temp.t_edit('A', 'add', 'cve_lookup', p_cve_id => 'CVE-2006-0001') = 'ok', 'S51 key A holds one item';
  FOREACH endpoint IN ARRAY ARRAY['cve_lookup', 'kev_lookup', 'cve_exploit', 'product_exposure', 'cve_search',
                                  'dns_lookup', 'ssl_check', 'whois_lookup', 'headers_check', 'cert_search'] LOOP
    ASSERT pg_temp.t_edit('A', 'add', endpoint, p_cve_id => CASE WHEN endpoint IN ('cve_lookup', 'kev_lookup', 'cve_exploit') THEN 'CVE-2006-0002' END,
                          p_vendor => CASE WHEN endpoint = 'product_exposure' THEN 'wlcap' END,
                          p_product => CASE WHEN endpoint = 'product_exposure' THEN 'wlcap' END,
                          p_severity => CASE WHEN endpoint = 'cve_search' THEN 'LOW' END,
                          p_domain_name => CASE WHEN endpoint IN ('dns_lookup', 'ssl_check', 'whois_lookup', 'headers_check', 'cert_search') THEN 'wlcap.example' END,
                          p_item_max_count => 1) = 'over_limit',
           'S51 ' || endpoint || ' refuses an add at a cap of 1 beside one item';
  END LOOP;
  ASSERT pg_temp.t_item_count('A') = 1, 'S51 no refused add inserted an item';
  ASSERT pg_temp.t_edit('A', NULL, NULL, p_is_cleared => true) = 'ok', 'S51 the clear at the end answers ok';
END
$$;

DO $$
DECLARE
  endpoint text;
BEGIN
  ASSERT pg_temp.t_edit('A', 'add', 'dns_lookup', p_domain_name => 'a.wlreg.example') = 'ok', 'S52 key A holds a.wlreg.example';
  FOREACH endpoint IN ARRAY ARRAY['dns_lookup', 'ssl_check', 'whois_lookup', 'headers_check', 'cert_search'] LOOP
    ASSERT pg_temp.t_edit('A', 'add', endpoint, p_domain_name => 'b.wlreg.example', p_registered_domain => 'wlreg.example',
                          p_domain_name_max_count => 1) = 'over_domain_limit',
           'S52 ' || endpoint || ' refuses a second name of wlreg.example at a cap of 1';
  END LOOP;
  ASSERT pg_temp.t_edit('A', NULL, NULL, p_is_cleared => true) = 'ok', 'S52 the clear at the end answers ok';
END
$$;

DO $$
DECLARE
  endpoint text;
  r        record;
  n        integer := 0;
BEGIN
  ASSERT pg_temp.t_edit('A', 'add', 'package_check', p_ecosystem => 'npm', p_package_name => 'wlcount') = 'ok', 'S53 one package item';
  FOREACH endpoint IN ARRAY ARRAY['cve_lookup', 'kev_lookup', 'cve_exploit'] LOOP
    n := n + 1;
    SELECT * INTO r FROM pg_temp.t_watchlist_edit(pg_temp.t_hash('A'), 'add', endpoint, 'CVE-2006-0003', NULL, NULL, NULL, NULL,
                                                  NULL, NULL, NULL, NULL, NULL, false, 100, NULL, NULL, 20, NULL, NULL, NULL, 500, 100, 100000, 20);
    ASSERT r.edit_status = 'ok' AND r.endpoint_name = endpoint AND r.cve_id = 'CVE-2006-0003'
       AND r.item_count = n AND r.package_item_count = 1,
           'S53 ' || endpoint || ' answers item_count ' || n || ' and package_item_count 1';
  END LOOP;
  ASSERT pg_temp.t_edit('A', NULL, NULL, p_is_cleared => true) = 'ok', 'S53 the clear at the end answers ok';
END
$$;

DO $$
DECLARE
  r record;
BEGIN
  SELECT * INTO r FROM api.fn_watchlist_edit_ip_lookup(pg_temp.t_hash('A'), 'add', '192.0.2.54', 3);
  ASSERT r.edit_status = 'ok' AND r.endpoint_name = 'ip_lookup' AND r.ip_address = '192.0.2.54' AND r.item_count = 1 AND r.package_item_count = 0,
         'S54 an IP add answers its address and the counts: ' || r::text;
  SELECT * INTO r FROM api.fn_watchlist_edit_ip_lookup(pg_temp.t_hash('A'), 'add', '192.0.2.54/32', 3);
  ASSERT r.edit_status = 'ok' AND r.ip_address = '192.0.2.54' AND r.item_count = 1, 'S54 the /32 text names the same item: ' || r::text;
  SELECT * INTO r FROM api.fn_watchlist_edit_ip_lookup(pg_temp.t_hash('A'), 'add', '2001:DB8:0:0::54', 3);
  ASSERT r.edit_status = 'ok' AND r.ip_address = '2001:db8::54' AND r.item_count = 2, 'S54 an IPv6 add answers the canonical text: ' || r::text;
  SELECT * INTO r FROM api.fn_watchlist_edit_ip_lookup(pg_temp.t_hash('A'), 'add', '2001:db8::54', 3);
  ASSERT r.edit_status = 'ok' AND r.item_count = 2, 'S54 the short IPv6 text names the same item';
  ASSERT pg_temp.t_edit('A', 'add', 'cve_lookup', p_cve_id => 'CVE-2006-0001', p_item_max_count => 3) = 'ok', 'S54 a CVE item fills the cap of 3';
  SELECT * INTO r FROM api.fn_watchlist_edit_ip_lookup(pg_temp.t_hash('A'), 'add', '192.0.2.55', 3);
  ASSERT r.edit_status = 'over_limit' AND r.endpoint_name IS NULL AND r.item_count = 3, 'S54 an IP add past the shared cap answers over_limit';
  ASSERT pg_temp.t_edit('A', 'add', 'kev_lookup', p_cve_id => 'CVE-2006-0001', p_item_max_count => 3) = 'over_limit',
         'S54 the IP items count in the cap of a CVE add too';
  ASSERT (SELECT count(*) FROM watchlist_item_ip AS wii WHERE wii.api_key_id = pg_temp.t_key_id('A')) = 2, 'S54 key A holds two IP items';
  SELECT * INTO r FROM api.fn_watchlist_edit_ip_lookup(pg_temp.t_hash('B'), 'add', '192.0.2.54', 3);
  ASSERT r.edit_status = 'ok' AND r.item_count = 1, 'S54 key B adds its own item of the same address';
  ASSERT (SELECT array_agg(x.endpoint_name || '=' || coalesce(x.ip_address, 'null') ORDER BY x.endpoint_name, x.ip_address)
            FROM api.fn_watchlist_list(pg_temp.t_hash('A')) AS x)
         = ARRAY['cve_lookup=null', 'ip_lookup=192.0.2.54', 'ip_lookup=2001:db8::54'],
         'S54 the list shows the IP items with their addresses';
  SELECT * INTO r FROM api.fn_watchlist_edit_ip_lookup(pg_temp.t_hash('A'), 'remove', '192.0.2.54', 3);
  ASSERT r.edit_status = 'ok' AND r.ip_address = '192.0.2.54' AND r.item_count = 2, 'S54 a remove answers the item and the count after it';
  ASSERT NOT EXISTS (SELECT 1 FROM watchlist_item_ip AS wii WHERE wii.api_key_id = pg_temp.t_key_id('A') AND wii.ip_address = '192.0.2.54'),
         'S54 the remove deletes the child row';
  SELECT * INTO r FROM api.fn_watchlist_edit_ip_lookup(pg_temp.t_hash('A'), 'remove', '192.0.2.54', 3);
  ASSERT r.edit_status = 'ok' AND r.endpoint_name IS NULL AND r.item_count = 2, 'S54 a remove of no item answers no item';
  ASSERT EXISTS (SELECT 1 FROM watchlist_item_ip AS wii WHERE wii.api_key_id = pg_temp.t_key_id('B') AND wii.ip_address = '192.0.2.54'),
         'S54 the item of key B stays';
  ASSERT (SELECT array_agg(x.endpoint_name || '=' || coalesce(x.ip_address, 'null') ORDER BY x.endpoint_name, x.ip_address)
            FROM api.fn_watchlist_clear(pg_temp.t_hash('A')) AS x)
         = ARRAY[NULL::text],
         'S54 the clear answers the one row with no item';
  ASSERT pg_temp.t_edit('B', NULL, NULL, p_is_cleared => true) = 'ok', 'S54 the clear at the end answers ok';
  ASSERT NOT EXISTS (SELECT 1 FROM watchlist_item_ip), 'S54 the clear deletes the IP child rows';
END
$$;

DO $$
DECLARE
  r        record;
  event_id bigint;
BEGIN
  ASSERT pg_temp.t_edit('A', NULL, NULL, p_is_cleared => true) = 'ok', 'S55 key A starts empty';
  SELECT * INTO r FROM api.fn_watchlist_edit_product_exposure(pg_temp.t_hash('A'), 'add', 'wlacme', 'wlwidget', '2.14.1', 100);
  ASSERT r.edit_status = 'ok' AND r.endpoint_name = 'product_exposure' AND r.vendor = 'wlacme' AND r.product = 'wlwidget'
     AND r.version = '2.14.1' AND r.product_has_cves IS TRUE AND r.item_count = 1,
         'S55 an add with a version answers the version';
  ASSERT (SELECT wic.version FROM watchlist_item_cve AS wic WHERE wic.api_key_id = pg_temp.t_key_id('A')) = '2.14.1',
         'S55 the child row stores the version';
  ASSERT pg_temp.t_edit('A', 'add', 'product_exposure', p_vendor => 'wlacme', p_product => 'wlwidget') = 'ok'
     AND pg_temp.t_item_count('A') = 2, 'S55 the pair without a version is another item';
  ASSERT pg_temp.t_edit('A', 'add', 'product_exposure', p_vendor => 'wlacme', p_product => 'wlwidget', p_version => '2.15.0') = 'ok'
     AND pg_temp.t_item_count('A') = 3, 'S55 another version of the pair is another item';
  ASSERT pg_temp.t_edit('A', 'add', 'product_exposure', p_vendor => 'wlacme', p_product => 'wlwidget', p_version => '2.14.1') = 'ok'
     AND pg_temp.t_item_count('A') = 3, 'S55 a repeated add of a version inserts nothing';
  ASSERT pg_temp.t_edit('A', 'add', 'product_exposure', p_vendor => 'wlacme', p_product => 'wlwidget') = 'ok'
     AND pg_temp.t_item_count('A') = 3, 'S55 a repeated add without a version inserts nothing';
  ASSERT pg_temp.t_items('A') = '{"product_exposure:wlacme,wlwidget,2.14.1:true","product_exposure:wlacme,wlwidget:true",'
                                 '"product_exposure:wlacme,wlwidget,2.15.0:true"}',
         'S55 the list answers the version of each item, and none for the item of every version';

  event_id := pg_temp.t_cve_event_of('CVE-2006-0001', 'product_added', NULL, NULL, 'wlacme', 'wlwidget');
  PERFORM pg_temp.t_rewind('A', event_id - 1);
  ASSERT (SELECT array_agg(coalesce(x.item_version, 'null') ORDER BY x.item_id)
            FROM api.fn_watchlist_events(pg_temp.t_hash('A'), NULL, false, 100, 100, 600) AS x
           WHERE x.item_id IS NOT NULL)
         = ARRAY['2.14.1', 'null', '2.15.0'],
         'S55 the three items hear the event, and the events answer the version of each in item_version';

  SELECT * INTO r FROM api.fn_watchlist_edit_product_exposure(pg_temp.t_hash('A'), 'remove', 'wlacme', 'wlwidget', '2.14.1', 100);
  ASSERT r.edit_status = 'ok' AND r.version = '2.14.1' AND r.item_count = 2, 'S55 a remove with a version answers the removed version';
  ASSERT pg_temp.t_items('A') = '{"product_exposure:wlacme,wlwidget:true","product_exposure:wlacme,wlwidget,2.15.0:true"}',
         'S55 a remove with a version deletes only the item of that version';
  SELECT * INTO r FROM api.fn_watchlist_edit_product_exposure(pg_temp.t_hash('A'), 'remove', 'wlacme', 'wlwidget', NULL, 100);
  ASSERT r.edit_status = 'ok' AND r.endpoint_name = 'product_exposure' AND r.version IS NULL AND r.item_count = 1,
         'S55 a remove without a version answers the item of every version';
  ASSERT pg_temp.t_items('A') = '{"product_exposure:wlacme,wlwidget,2.15.0:true"}',
         'S55 a remove without a version leaves the item of a version';
  SELECT * INTO r FROM api.fn_watchlist_edit_product_exposure(pg_temp.t_hash('A'), 'remove', 'wlacme', 'wlwidget', NULL, 100);
  ASSERT r.edit_status = 'ok' AND r.endpoint_name IS NULL AND r.item_count = 1,
         'S55 a second remove without a version finds no item';
  ASSERT pg_temp.t_edit('A', NULL, NULL, p_is_cleared => true) = 'ok', 'S55 the clear at the end answers ok';
END
$$;

CREATE FUNCTION pg_temp.t_package_list(p_key_hash text, p_action text, p_packages text[],
                                       p_max_count integer DEFAULT 500, p_weight_budget integer DEFAULT 100000)
  RETURNS text LANGUAGE sql AS $$
  SELECT min(x.edit_status) || '|' || coalesce(min(x.added_count)::text, '-') || ',' || coalesce(min(x.removed_count)::text, '-') || ','
         || coalesce(min(x.unchanged_count)::text, '-') || '|' || coalesce(min(x.package_item_count)::text, '-') || '|'
         || coalesce(string_agg(x.package_index || '<' || x.earlier_package_index, ' ' ORDER BY x.package_index), '')
    FROM api.fn_watchlist_package_list_edit(
           p_key_hash, p_action,
           (SELECT array_agg(split_part(u.p, ':', 1) ORDER BY u.o) FROM unnest(p_packages) WITH ORDINALITY AS u (p, o)),
           (SELECT array_agg(split_part(split_part(u.p, ':', 2), '@', 1) ORDER BY u.o) FROM unnest(p_packages) WITH ORDINALITY AS u (p, o)),
           (SELECT array_agg(nullif(split_part(split_part(u.p, ':', 2), '@', 2), '') ORDER BY u.o) FROM unnest(p_packages) WITH ORDINALITY AS u (p, o)),
           p_max_count, 100, p_weight_budget, 20) AS x
$$;
CREATE FUNCTION pg_temp.t_package_rows(p_key_hash text) RETURNS text LANGUAGE sql AS $$
  SELECT coalesce(string_agg(wip.package_name || '@' || coalesce(wip.version, '*'), ' '
                             ORDER BY wip.package_name || '@' || coalesce(wip.version, '*') COLLATE "C"), '')
    FROM watchlist_item_package AS wip JOIN api_keys AS ak ON ak.id = wip.api_key_id
   WHERE ak.key_hash = p_key_hash
$$;

DO $$
DECLARE
  k1          CONSTANT text := repeat('e1', 32);
  k2          CONSTANT text := repeat('e2', 32);
  k1_id       integer;
  a_item_id   bigint;
  a_before    bigint;
  answered    text;
  list_source text := regexp_replace(pg_get_functiondef('api.fn_watchlist_package_list_edit(text, text, text[], text[], text[], integer, integer, integer, integer)'::regprocedure), '--[^\n]*', '', 'g');
  bad         record;
  key_state_lock_at integer;
BEGIN
  INSERT INTO api_keys (key_hash) VALUES (k1), (k2);
  k1_id := (SELECT ak.id FROM api_keys AS ak WHERE ak.key_hash = k1);

  ASSERT (SELECT array_agg(c.name || ' ' || c.type ORDER BY c.position)
            FROM pg_proc AS p,
                 unnest(p.proargnames[10:], ARRAY(SELECT format_type(t, NULL) FROM unnest(p.proallargtypes[10:]) AS t)) WITH ORDINALITY AS c (name, type, position)
           WHERE p.oid = 'api.fn_watchlist_package_list_edit(text, text, text[], text[], text[], integer, integer, integer, integer)'::regprocedure)
         = ARRAY['edit_status text', 'package_index integer', 'earlier_package_index integer', 'added_count integer', 'removed_count integer',
                 'unchanged_count integer', 'package_item_count integer'],
         'S56 the list edit answers its seven columns in order';

  answered := pg_temp.t_package_list(k1, 'add', ARRAY['npm:a@1', 'npm:b@1', 'PyPI:Foo_Bar@2']);
  ASSERT answered = 'ok|3,0,0|3|', 'S56 the first add answers ' || answered;
  ASSERT pg_temp.t_package_rows(k1) = 'Foo_Bar@2 a@1 b@1', 'S56 the first add leaves ' || pg_temp.t_package_rows(k1);
  SELECT wip.item_id, wip.last_event_id_before_add INTO a_item_id, a_before
    FROM watchlist_item_package AS wip WHERE wip.api_key_id = k1_id AND wip.package_name = 'a';
  INSERT INTO watchlist_event_ref (api_key_id, item_id, event_id, key_event_id) VALUES (k1_id, a_item_id, 900001, NULL);
  answered := pg_temp.t_package_list(k1, 'add', ARRAY['NPM:a@1', 'pypi:foo-bar@2', 'npm:c@1']);
  ASSERT answered = 'ok|1,0,2|4|', 'S56 an add of watched packages counts them unchanged, answered ' || answered;
  ASSERT pg_temp.t_package_rows(k1) = 'Foo_Bar@2 a@1 b@1 c@1', 'S56 the second add leaves ' || pg_temp.t_package_rows(k1);
  ASSERT (SELECT wip.item_id = a_item_id AND wip.last_event_id_before_add = a_before
            FROM watchlist_item_package AS wip WHERE wip.api_key_id = k1_id AND wip.package_name = 'a'),
         'S56 the unchanged item keeps its item_id and its add point';
  ASSERT EXISTS (SELECT 1 FROM watchlist_event_ref AS wer WHERE wer.item_id = a_item_id AND wer.event_id = 900001),
         'S56 the pending ref of the unchanged item survives the add';
  answered := pg_temp.t_package_list(k1, 'add', ARRAY['npm:a@1', 'npm:b@1', 'npm:c@1']);
  ASSERT answered = 'ok|0,0,3|4|', 'S56 an add of watched packages only changes nothing, answered ' || answered;

  answered := pg_temp.t_package_list(k1, 'remove', ARRAY['npm:b@1', 'npm:zz@1', 'npm:c@2']);
  ASSERT answered = 'ok|0,1,2|3|', 'S56 a remove answers ' || answered;
  ASSERT pg_temp.t_package_rows(k1) = 'Foo_Bar@2 a@1 c@1', 'S56 the remove deletes only the listed package: ' || pg_temp.t_package_rows(k1);
  answered := pg_temp.t_package_list(k1, 'remove', ARRAY['PYPI:foo.bar@2']);
  ASSERT answered = 'ok|0,1,0|2|', 'S56 a remove matches the normalized name, answered ' || answered;

  answered := pg_temp.t_package_list(k1, 'add', ARRAY['PyPI:Foo_Bar@9', 'npm:z@1', 'PyPI:foo-bar@9', 'npm:z@2', 'PyPI:FOO.bar@9', 'PyPI:z@1']);
  ASSERT answered = 'package_problem|-,-,-|-|2<0 4<0', 'S56 a normalized repeat answers ' || answered;
  ASSERT (SELECT array_agg(x.package_index)
            FROM api.fn_watchlist_package_list_edit(k1, 'add', ARRAY['PyPI', 'PyPI', 'PyPI'], ARRAY['a_b', 'a-b', 'A.b'], ARRAY['1', '1', '1'],
                                                    500, 100, 100000, 20) AS x)
         = ARRAY[1, 2], 'S56 the repeat rows come in the order of the entries';
  answered := pg_temp.t_package_list(k1, 'remove', ARRAY['npm:a@1', 'npm:A@1']);
  ASSERT answered = 'package_problem|-,-,-|-|1<0', 'S56 a remove answers its repeat too: ' || answered;
  ASSERT pg_temp.t_package_rows(k1) = 'a@1 c@1', 'S56 the refused calls changed nothing: ' || pg_temp.t_package_rows(k1);
  ASSERT (SELECT array_agg(x.edit_status || ':' || x.package_index || '<' || x.earlier_package_index)
            FROM api.fn_watchlist_package_list_edit(k1, 'add', ARRAY['npm', 'npm'], ARRAY['r', 'r'], ARRAY['', NULL], 500, 100, 100000, 20) AS x)
         = ARRAY['package_problem:1<0'], 'S56 an empty and a NULL version of one package are a repeat';

  answered := pg_temp.t_package_list(k1, 'add', ARRAY['npm:d@1', ':d@1']);
  ASSERT answered = 'package_problem|-,-,-|-|', 'S56 a refused entry alone answers one row with no index: ' || answered;
  answered := pg_temp.t_package_list(k1, 'add', ARRAY[':x', 'npm:d@1', ':x', 'npm:D@1']);
  ASSERT answered = 'package_problem|-,-,-|-|3<1', 'S56 a refused entry beside a repeat answers the repeat: ' || answered;
  answered := pg_temp.t_package_list(k1, 'remove', ARRAY['npm:a@1', ':a@1']);
  ASSERT answered = 'package_problem|-,-,-|-|', 'S56 a remove with a refused entry answers ' || answered;
  ASSERT pg_temp.t_package_rows(k1) = 'a@1 c@1', 'S56 a call with a refused entry changes nothing: ' || pg_temp.t_package_rows(k1);
  ASSERT pg_temp.t_package_list(repeat('ef', 32), 'add', ARRAY[':x']) = 'package_problem|-,-,-|-|',
         'S56 a call with a refused entry reads no key';

  PERFORM pg_temp.t_package_list(k1, 'add', ARRAY['npm:o1', 'npm:o3', 'npm:o2']);
  ASSERT (SELECT array_agg(wip.package_name ORDER BY wip.item_id)
            FROM watchlist_item_package AS wip WHERE wip.api_key_id = k1_id AND wip.package_name LIKE 'o_')
         = ARRAY['o1', 'o3', 'o2'],
         'S56 the added packages take item ids in request order';
  PERFORM pg_temp.t_package_list(k1, 'remove', ARRAY['npm:o1', 'npm:o2', 'npm:o3']);

  answered := pg_temp.t_package_list(k2, 'remove', ARRAY['npm:p1']);
  ASSERT answered = 'ok|0,0,1|0|', 'S56 a remove from a key with no item answers ' || answered;
  ASSERT NOT EXISTS (SELECT 1 FROM watchlist_key_state AS wks JOIN api_keys AS ak ON ak.id = wks.api_key_id WHERE ak.key_hash = k2),
         'S56 a remove writes no key state';
  answered := pg_temp.t_package_list(k2, 'add', ARRAY['npm:p1', 'npm:p2'], 1);
  ASSERT answered = 'over_package_limit|0,0,0|0|', 'S56 a refused add of K2 answers ' || answered;
  ASSERT (SELECT wks.last_cve_event_id FROM watchlist_key_state AS wks JOIN api_keys AS ak ON ak.id = wks.api_key_id WHERE ak.key_hash = k2) = api.fn_watchlist_event_max_id(),
         'S56 an add writes the key state of a key that has none at the event head';

  answered := pg_temp.t_package_list(k2, 'add', ARRAY['npm:p1', 'npm:p2', 'npm:p3'], 3);
  ASSERT answered = 'ok|3,0,0|3|', 'S56 K2 adds three items, answered ' || answered;
  answered := pg_temp.t_package_list(k2, 'add', ARRAY['npm:p1', 'npm:p4'], 3);
  ASSERT answered = 'over_package_limit|0,0,0|3|', 'S56 an add past the cap answers ' || answered;
  answered := pg_temp.t_package_list(k2, 'add', ARRAY['npm:p1', 'npm:p4'], 4);
  ASSERT answered = 'ok|1,0,1|4|', 'S56 a watched package counts once for the cap, answered ' || answered;
  answered := pg_temp.t_package_list(k2, 'remove', ARRAY['npm:p4']);
  ASSERT answered = 'ok|0,1,0|3|', 'S56 K2 removes p4 again, answered ' || answered;
  answered := pg_temp.t_package_list(k2, 'add', ARRAY['npm:p1', 'npm:p2'], 0, 0);
  ASSERT answered = 'ok|0,0,2|3|', 'S56 an add that adds nothing passes the caps, answered ' || answered;
  answered := pg_temp.t_package_list(k2, 'remove', ARRAY['npm:p3'], 0, 0);
  ASSERT answered = 'ok|0,1,0|2|', 'S56 a remove passes the caps, answered ' || answered;
  answered := pg_temp.t_package_list(k2, 'add', ARRAY['npm:p5'], 500, 299);
  ASSERT answered = 'over_package_weight|0,0,0|2|', 'S56 a weight one past the budget is refused, answered ' || answered;
  answered := pg_temp.t_package_list(k2, 'add', ARRAY['npm:p5'], 500, 300);
  ASSERT answered = 'ok|1,0,0|3|', 'S56 a weight at the budget fits, answered ' || answered;
  answered := pg_temp.t_package_list(k2, 'add', ARRAY['npm:p6@1', 'npm:p6@2'], 4);
  ASSERT answered = 'over_package_limit|0,0,0|3|', 'S56 two versions of one package count twice, answered ' || answered;
  ASSERT pg_temp.t_package_rows(k2) = 'p1@* p2@* p5@*', 'S56 the refused adds changed nothing: ' || pg_temp.t_package_rows(k2);

  ASSERT EXISTS (SELECT 1 FROM watchlist_event_cursor AS wec JOIN api_keys AS ak ON ak.id = wec.api_key_id WHERE ak.key_hash = k2),
         'S56 K2 holds a position before its last remove';
  UPDATE watchlist_key_state AS wks SET last_key_event_id = 7, max_purged_key_event_id = 0
    FROM api_keys AS ak WHERE ak.id = wks.api_key_id AND ak.key_hash = k2;
  answered := pg_temp.t_package_list(k2, 'remove', ARRAY['npm:p1', 'npm:p2', 'npm:p5']);
  ASSERT answered = 'ok|0,3,0|0|', 'S56 the last remove of K2 answers ' || answered;
  ASSERT (SELECT wks.max_purged_key_event_id FROM watchlist_key_state AS wks JOIN api_keys AS ak ON ak.id = wks.api_key_id WHERE ak.key_hash = k2) = 7,
         'S56 a remove that empties the key raises max_purged_key_event_id to last_key_event_id';
  UPDATE watchlist_key_state AS wks SET last_cve_event_id = 0
    FROM api_keys AS ak WHERE ak.id = wks.api_key_id AND ak.key_hash = k2;
  ASSERT NOT EXISTS (SELECT 1 FROM watchlist_event_cursor AS wec JOIN api_keys AS ak ON ak.id = wec.api_key_id WHERE ak.key_hash = k2),
         'S56 a remove that empties the key deletes its position';
  answered := pg_temp.t_package_list(k2, 'remove', ARRAY['npm:p1']);
  ASSERT answered = 'ok|0,0,1|0|', 'S56 a remove from an empty key answers ' || answered;
  ASSERT NOT EXISTS (SELECT 1 FROM watchlist_event_cursor AS wec JOIN api_keys AS ak ON ak.id = wec.api_key_id WHERE ak.key_hash = k2),
         'S56 a call that adds no item opens no position';
  answered := pg_temp.t_package_list(k2, 'add', ARRAY['npm:p1']);
  ASSERT answered = 'ok|1,0,0|1|', 'S56 K2 adds p1 again, answered ' || answered;
  ASSERT (SELECT wks.last_cve_event_id FROM watchlist_key_state AS wks JOIN api_keys AS ak ON ak.id = wks.api_key_id WHERE ak.key_hash = k2) = api.fn_watchlist_event_max_id(),
         'S56 an add that opens a position raises last_cve_event_id to the event head';
  ASSERT (SELECT wec.previous_cursor || ',' || wec.delivered_cursor FROM watchlist_event_cursor AS wec JOIN api_keys AS ak ON ak.id = wec.api_key_id WHERE ak.key_hash = k2) = '7,7',
         'S56 an add that opens a position opens it at last_key_event_id';
  DELETE FROM watchlist_event_cursor AS wec USING api_keys AS ak WHERE ak.id = wec.api_key_id AND ak.key_hash = k2;
  answered := pg_temp.t_package_list(k2, 'add', ARRAY['npm:p1']);
  ASSERT answered = 'ok|0,0,1|1|', 'S56 an add of a watched package answers ' || answered;
  ASSERT NOT EXISTS (SELECT 1 FROM watchlist_event_cursor AS wec JOIN api_keys AS ak ON ak.id = wec.api_key_id WHERE ak.key_hash = k2),
         'S56 an add that adds no item opens no position';
  answered := pg_temp.t_package_list(k2, 'remove', ARRAY['npm:p1']);
  ASSERT answered = 'ok|0,1,0|0|', 'S56 K2 removes p1 again, answered ' || answered;

  answered := pg_temp.t_package_list(k2, 'add', ARRAY['npm:a@1', 'npm:c@1']);
  ASSERT answered = 'ok|2,0,0|2|', 'S56 K2 does not see the items of K1, answered ' || answered;
  answered := pg_temp.t_package_list(k2, 'remove', ARRAY['npm:a@1']);
  ASSERT answered = 'ok|0,1,0|1|' AND pg_temp.t_package_rows(k1) = 'a@1 c@1', 'S56 a remove of K2 leaves the items of K1, answered ' || answered;

  ASSERT (SELECT min(x.added_count) FROM api.fn_watchlist_package_list_edit(k2, 'add', ARRAY['npm'], ARRAY['q'], ARRAY[''], 500, 100, 100000, 20) AS x) = 1,
         'S56 an add with an empty version adds one item';
  ASSERT pg_temp.t_package_rows(k2) = 'c@1 q@*', 'S56 an add with an empty version adds an item of every version: ' || pg_temp.t_package_rows(k2);
  ASSERT (SELECT min(x.removed_count) FROM api.fn_watchlist_package_list_edit(k2, 'remove', ARRAY['npm'], ARRAY['q'], ARRAY[''], 500, 100, 100000, 20) AS x) = 1,
         'S56 a remove with an empty version matches the item of every version';

  PERFORM api.fn_watchlist_edit_cve_lookup(k2, 'add', 'CVE-2021-44228', 100);
  ASSERT (SELECT min(x.package_item_count) = 2
            FROM api.fn_watchlist_package_list_edit(k2, 'add', ARRAY['npm'], ARRAY['q'], ARRAY[''], 500, 100, 100000, 20) AS x),
         'S56 package_item_count of a list edit leaves out the items that are not package items';

  ASSERT (SELECT array_agg(x.edit_status || '|' || num_nulls(VARIADIC ARRAY[x.package_index::text, x.earlier_package_index::text, x.added_count::text,
                                                                      x.removed_count::text, x.unchanged_count::text,
                                                                      x.package_item_count::text]))
            FROM api.fn_watchlist_package_list_edit(repeat('ef', 32), 'add', ARRAY['npm'], ARRAY['a'], ARRAY[NULL]::text[], 500, 100, 100000, 20) AS x)
         = ARRAY['unknown_key|6'],
         'S56 an unknown key answers one unknown_key row with NULL in every other column';
  ASSERT (SELECT array_agg(num_nulls(x.package_index, x.earlier_package_index))
            FROM api.fn_watchlist_package_list_edit(k2, 'add', ARRAY['npm'], ARRAY['q'], ARRAY[''], 500, 100, 100000, 20) AS x)
         = ARRAY[2], 'S56 an ok answer is one row with NULL in both index columns';

  FOR bad IN SELECT * FROM (VALUES
      ('list', ARRAY['npm'], ARRAY['a'], ARRAY[NULL]::text[], 500),
      ('replace', ARRAY['npm'], ARRAY['a'], ARRAY[NULL]::text[], 500),
      (NULL, ARRAY['npm'], ARRAY['a'], ARRAY[NULL]::text[], 500),
      ('add', NULL, NULL, NULL, 500),
      ('remove', ARRAY[]::text[], ARRAY[]::text[], ARRAY[]::text[], 500),
      ('add', ARRAY['npm', 'npm'], ARRAY['a'], ARRAY[NULL, NULL]::text[], 500),
      ('add', ARRAY['npm'], ARRAY['a'], ARRAY[NULL, NULL]::text[], 500),
      ('add', ARRAY['cpan'], ARRAY['a'], ARRAY[NULL]::text[], 500),
      ('add', ARRAY[NULL]::text[], ARRAY['a'], ARRAY[NULL]::text[], 500),
      ('add', ARRAY['npm'], ARRAY[NULL]::text[], ARRAY[NULL]::text[], 500),
      ('add', ARRAY['npm'], ARRAY['a'], ARRAY[NULL]::text[], NULL::integer)) AS t (action, ecosystems, names, versions, max_count) LOOP
    BEGIN
      PERFORM api.fn_watchlist_package_list_edit(k1, bad.action, bad.ecosystems, bad.names, bad.versions, bad.max_count, 100, 100000, 20);
      ASSERT false, 'S56 the call ' || bad::text || ' raises';
    EXCEPTION WHEN invalid_parameter_value THEN
      NULL;
    END;
  END LOOP;
  FOR bad IN SELECT * FROM (VALUES (NULL::integer, 100000, 20), (500, NULL, 20), (500, 100000, NULL)) AS t (base_weight, budget, per_weight) LOOP
    BEGIN
      PERFORM api.fn_watchlist_package_list_edit(k1, 'add', ARRAY['npm'], ARRAY['a'], ARRAY[NULL]::text[], 500, bad.base_weight, bad.budget, bad.per_weight);
      ASSERT false, 'S56 the caps ' || bad::text || ' raise';
    EXCEPTION WHEN invalid_parameter_value THEN
      NULL;
    END;
  END LOOP;

  ASSERT api.fn_watchlist_event_max_id() > 0, 'S56 the event tables hold an event above 0';
  ASSERT EXISTS (SELECT 1 FROM watchlist_event_cursor AS wec WHERE wec.api_key_id = k1_id), 'S56 key K1 holds a position';
  UPDATE watchlist_key_state AS wks SET last_cve_event_id = 0 WHERE wks.api_key_id = k1_id;
  ASSERT pg_temp.t_package_list(k1, 'add', ARRAY['npm:floorkept']) LIKE 'ok|1,0,0|%', 'S56 the add beside the items answers ok';
  ASSERT (SELECT wks.last_cve_event_id FROM watchlist_key_state AS wks WHERE wks.api_key_id = k1_id) = 0,
         'S56 a list add beside the items keeps last_cve_event_id';

  key_state_lock_at := strpos(list_source, 'FROM public.watchlist_key_state AS wks
   WHERE wks.api_key_id = caller_api_key_id FOR UPDATE;');
  ASSERT strpos(list_source, 'FROM public.api_keys AS ak WHERE ak.key_hash = p_key_hash FOR UPDATE;') BETWEEN 1 AND key_state_lock_at - 1,
         'S56 the list edit locks the key state after the key row';
  ASSERT key_state_lock_at < strpos(list_source, 'DELETE FROM public.watchlist_item ')
     AND key_state_lock_at < strpos(list_source, 'INSERT INTO public.watchlist_event_cursor ')
     AND strpos(list_source, 'INSERT INTO public.watchlist_event_cursor ') < strpos(list_source, 'INSERT INTO public.watchlist_item '),
         'S56 the list edit locks the key state first, then opens the position before it inserts items';

  INSERT INTO api_keys (key_hash) VALUES (repeat('a7', 32));
  answered := pg_temp.t_package_list(repeat('a7', 32), 'add', ARRAY['npm:pl-x@1']);
  ASSERT answered = 'ok|1,0,0|1|', 'S56 the first add of a fresh key answers ' || answered;
  ASSERT (SELECT wip.last_event_id_before_add FROM watchlist_item_package AS wip JOIN api_keys AS ak ON ak.id = wip.api_key_id
           WHERE ak.key_hash = repeat('a7', 32) AND wip.package_name = 'pl-x') = api.fn_watchlist_event_max_id(),
         'S56 a list-added item starts at the event head';
  answered := pg_temp.t_package_list(repeat('a7', 32), 'add', ARRAY['npm:pl-d@1', 'PyPI:pl-d@1', 'PyPI:pl-x@1']);
  ASSERT answered = 'ok|3,0,0|4|', 'S56 one name in two ecosystems is two packages, answered ' || answered;
  DELETE FROM api_keys WHERE key_hash = repeat('a7', 32);

  DELETE FROM api_keys WHERE key_hash IN (k1, k2);
END
$$;
