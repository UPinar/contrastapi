SAVEPOINT t_watch_isolation;
TRUNCATE cve_change_event RESTART IDENTITY;
UPDATE change_event_purge_state SET max_purged_event_id = 0 WHERE event_table_name = 'cve_change_event';
TRUNCATE domain_change_event, package_advisory_change_event, eol_change_event, watchlist_event_ref, domain_watch_dns_bucket;
DELETE FROM watchlist_item WHERE endpoint_name IN ('dns_lookup', 'ssl_check', 'whois_lookup', 'headers_check', 'cert_search');
DELETE FROM domain_watch;
UPDATE change_event_purge_state SET max_purged_event_id = 0, max_unwatched_event_id = 0 WHERE event_table_name = 'domain_change_event';
UPDATE change_event_purge_state SET max_purged_event_id = 0 WHERE event_table_name = 'package_advisory_change_event';

INSERT INTO api_keys (key_hash) VALUES (repeat('a2', 32)), (repeat('b2', 32));
SELECT set_config('contrastapi.cve_events', 'off', true);
INSERT INTO cves (cve_id) VALUES ('CVE-2026-0420');
SELECT set_config('contrastapi.cve_events', '', true);

DELETE FROM upstream_feed_sync WHERE feed_name IN ('iptoasn', 'cloud_ranges');
INSERT INTO upstream_feed_sync (feed_name, last_synced, last_status) VALUES ('iptoasn', now(), 'ok');
INSERT INTO ip_asn (asn, asn_name, country) VALUES (24940, 'Hosting AS', 'DE') ON CONFLICT DO NOTHING;
INSERT INTO ip_asn_prefix (prefix, asn) VALUES ('203.0.113.0/24', 24940) ON CONFLICT DO NOTHING;
INSERT INTO ip_cloud_range (provider, service, prefix, is_cdn, synced_at) VALUES ('aws', 'cloudfront', '198.51.100.0/26', true, now());

CREATE FUNCTION pg_temp.t_isolation_sha256(p_value text) RETURNS text LANGUAGE sql AS $$
  SELECT encode(sha256(convert_to(p_value, 'UTF8')), 'hex')
$$;

CREATE TEMP TABLE t_isolation_lane (endpoint_name text PRIMARY KEY, claim_sql text NOT NULL, record_sql text NOT NULL, day_pass interval NOT NULL);
INSERT INTO t_isolation_lane VALUES
  ('dns_lookup',
   'SELECT x.claimed_until FROM api.fn_domain_watch_claim(''dns'', 100, 300) AS x WHERE x.domain_name = $1',
   'SELECT api.fn_domain_watch_record_dns($1, $2, $3[1], pg_temp.t_isolation_sha256($3[1]), $3[2], pg_temp.t_isolation_sha256($3[2]),
                                          $3[3], pg_temp.t_isolation_sha256($3[3]), $3[4], pg_temp.t_isolation_sha256($3[4]),
                                          $3[5], pg_temp.t_isolation_sha256($3[5]), $3[6], pg_temp.t_isolation_sha256($3[6]),
                                          ''spf_all,dmarc_policy'', $3[7], 0)',
   '1 day'),
  ('ssl_check',
   'SELECT x.claimed_until FROM api.fn_domain_watch_claim(''tls'', 100, 300) AS x WHERE x.domain_name = $1',
   'SELECT api.fn_domain_watch_record_tls($1, $2, $3[1], pg_temp.t_isolation_sha256($3[1]), $3[2], pg_temp.t_isolation_sha256($3[2]),
                                          $3[3], pg_temp.t_isolation_sha256($3[3]), $3[4], pg_temp.t_isolation_sha256($3[4]))',
   '1 day'),
  ('whois_lookup',
   'SELECT x.claimed_until FROM api.fn_domain_watch_claim(''rdap_whois'', 100, 300) AS x WHERE x.domain_name = $1',
   'SELECT api.fn_domain_watch_record_rdap_whois($1, $2, $3[1], pg_temp.t_isolation_sha256($3[1]), $3[2], pg_temp.t_isolation_sha256($3[2]),
                                                 $3[3], pg_temp.t_isolation_sha256($3[3]), $3[4], pg_temp.t_isolation_sha256($3[4]), NULL)',
   '7 days'),
  ('headers_check',
   'SELECT x.claimed_until FROM api.fn_domain_watch_claim(''headers'', 100, 300) AS x WHERE x.domain_name = $1',
   'SELECT api.fn_domain_watch_record_headers($1, $2, $3[1], pg_temp.t_isolation_sha256($3[1]), NULL)',
   '1 day'),
  ('cert_search',
   'SELECT x.claimed_until FROM api.fn_domain_watch_claim(''ct'', 100, 300) AS x WHERE x.domain_name = $1',
   'SELECT api.fn_domain_watch_record_ct($1, $2, $3[1], pg_temp.t_isolation_sha256($3[1]), NULL)',
   '1 day');

CREATE TEMP TABLE t_isolation_sample (endpoint_name text, value_kind text, quiet_value text, problem_value text, change_value text,
                                PRIMARY KEY (endpoint_name, value_kind));
INSERT INTO t_isolation_sample VALUES
  ('dns_lookup', 'dns_presence',            'found',                 'not_found',               'not_found'),
  ('dns_lookup', 'ns',                      'ns1.example.net',       NULL,                      'ns2.example.net'),
  ('dns_lookup', 'mx',                      '10 mx1.example.net',    NULL,                      '10 mx2.example.net'),
  ('dns_lookup', 'ip_address_reachability', 'public',                'not_public',              'empty'),
  ('dns_lookup', 'cname_takeover',          'none',                  'vulnerable:github-pages', 'vulnerable:heroku'),
  ('dns_lookup', 'email_auth',              'pp',                    NULL,                      'ff'),
  ('dns_lookup', 'hosting',                 '203.0.113.7',           NULL,                      '198.51.100.10'),
  ('ssl_check',  'certificate_expiry',      E'none\n2027-03-01',     E'7\n2026-11-05',          E'1\n2026-11-01'),
  ('ssl_check',  'certificate_validity',    'valid',                 'expired',                 'hostname_mismatch'),
  ('ssl_check',  'certificate_listing',     'not_listed',            'listed:crt.sh',           'listed:other'),
  ('ssl_check',  'tls_protocol',            'TLSv1.3',               'TLSv1',                   'TLSv1.1'),
  ('whois_lookup', 'registration_expiry', E'none\n' || to_char((now() AT TIME ZONE 'UTC') + interval '200 days', 'YYYY-MM-DD'),
                                          E'30\n' || to_char((now() AT TIME ZONE 'UTC') + interval '20 days', 'YYYY-MM-DD'),
                                          E'7\n' || to_char((now() AT TIME ZONE 'UTC') + interval '5 days', 'YYYY-MM-DD')),
  ('whois_lookup', 'registrar',           E'292\nMarkMonitor Inc.', NULL, E'146\nGoDaddy.com, LLC'),
  ('whois_lookup', 'transfer_lock',       E'client transfer prohibited\nserver transfer prohibited', NULL, 'server transfer prohibited'),
  ('whois_lookup', 'dnssec_delegation',   'signed', NULL, 'unsigned'),
  ('headers_check', 'security_headers',   E'https://iso.example/\ncontent-security-policy\nstrict-transport-security', NULL,
                                          E'https://iso.example/\ncontent-security-policy'),
  ('cert_search',   'cert_issuers',       'new_issuer letsencrypt.org', NULL, E'caa_mismatch pki.goog\nnew_issuer letsencrypt.org');

CREATE TEMP TABLE t_isolation_step (phase text, name text, step_no integer, pass_before interval, action text, value_choice text, registered_domain text);
INSERT INTO t_isolation_step VALUES
  ('history', 'same',          1,  '0',      'a_add_domain',    NULL,                   NULL),
  ('history', 'same',          2,  '1 hour', 'scan_all',        'quiet',                NULL),
  ('history', 'different',     1,  '0',      'a_add_domain',    NULL,                   'other.example'),
  ('history', 'different',     2,  '1 hour', 'scan_all',        'change',               NULL),
  ('history', 'pending',       1,  '0',      'a_add_domain',    NULL,                   NULL),
  ('history', 'pending',       2,  '1 hour', 'scan_all',        'quiet',                NULL),
  ('history', 'pending',       3,  '1 day',  'scan',            'change',               NULL),
  ('history', 'never',         1,  '0',      'a_add_domain',    NULL,                   'other.example'),
  ('history', 'never',         2,  '1 hour', 'scan_all',        'none',                 NULL),
  ('history', 'lease',         1,  '0',      'a_add_domain',    NULL,                   NULL),
  ('history', 'lease',         2,  '1 hour', 'scan_all',        'quiet',                NULL),
  ('history', 'lease',         3,  '1 day',  'claim',           NULL,                   NULL),
  ('history', 'removed',       1,  '0',      'a_add_domain',    NULL,                   NULL),
  ('history', 'removed',       2,  '1 hour', 'scan_all',        'problem_else_change',  NULL),
  ('history', 'removed',       3,  '0',      'a_remove_domain', NULL,                   NULL),
  ('history', 'cleared',       1,  '0',      'a_add_domain',    NULL,                   NULL),
  ('history', 'cleared',       2,  '0',      'a_add_cve',       NULL,                   NULL),
  ('history', 'cleared',       3,  '0',      'cve_event',       NULL,                   NULL),
  ('history', 'cleared',       4,  '1 hour', 'scan_all',        'problem_else_change',  NULL),
  ('history', 'cleared',       5,  '0',      'a_clear',         NULL,                   NULL),
  ('history', 'cve',           1,  '0',      'a_add_domain',    NULL,                   'other.example'),
  ('history', 'cve',           2,  '0',      'a_add_cve',       NULL,                   NULL),
  ('history', 'cve',           3,  '0',      'cve_event',       NULL,                   NULL),
  ('history', 'cve',           4,  '1 hour', 'scan_all',        'quiet',                NULL),
  ('history', 'silent',        1,  '0',      'a_add_domain',    NULL,                   NULL),
  ('history', 'silent',        2,  '0',      'a_silent',        NULL,                   NULL),
  ('history', 'silent',        3,  '1 hour', 'scan_all',        'problem_everywhere',   NULL),
  ('script',  'first_problem', 1,  '1 hour', 'scan',            'problem_else_change',  NULL),
  ('script',  'first_problem', 2,  '1 day',  'scan',            'quiet',                NULL),
  ('script',  'first_problem', 3,  '1 hour', 'scan',            'quiet',                NULL),
  ('script',  'late_read',     1,  '1 hour', 'scan',            'none',                 NULL),
  ('script',  'late_read',     2,  '1 day',  'scan',            'problem_else_change',  NULL),
  ('script',  'late_read',     3,  '1 day',  'scan',            'quiet',                NULL),
  ('script',  'late_read',     4,  '1 hour', 'scan',            'quiet',                NULL),
  ('script',  'confirm',       1,  '1 hour', 'scan',            'quiet',                NULL),
  ('script',  'confirm',       2,  '1 day',  'scan',            'change',               NULL),
  ('script',  'confirm',       3,  '1 hour', 'scan',            'change',               NULL),
  ('script',  'differs',       1,  '1 hour', 'scan',            'change',               NULL),
  ('script',  'differs',       2,  '1 day',  'scan',            'quiet',                NULL),
  ('script',  'differs',       3,  '1 hour', 'scan',            'quiet',                NULL),
  ('script',  'flap',          1,  '1 hour', 'scan',            'quiet',                NULL),
  ('script',  'flap',          2,  '1 day',  'scan',            'change',               NULL),
  ('script',  'flap',          3,  '1 hour', 'scan',            'quiet',                NULL),
  ('script',  'flap',          4,  '1 day',  'scan',            'change',               NULL),
  ('script',  'flap',          5,  '1 hour', 'scan',            'change',               NULL),
  ('script',  'readd',         1,  '1 hour', 'scan',            'quiet',                NULL),
  ('script',  'readd',         2,  '1 day',  'scan',            'change',               NULL),
  ('script',  'readd',         3,  '1 hour', 'scan',            'change',               NULL),
  ('script',  'readd',         4,  '0',      'b_remove',        NULL,                   NULL),
  ('script',  'readd',         5,  '0',      'b_add',           NULL,                   NULL),
  ('script',  'readd',         6,  '1 hour', 'scan',            'problem_else_change',  NULL),
  ('script',  'all_kinds',     1,  '1 day',  'scan',            'problem_everywhere',   NULL),
  ('script',  'all_kinds',     2,  '1 hour', 'scan',            'quiet',                NULL),
  ('script',  'early',         1,  '1 day',  'scan',            'change',               NULL),
  ('script',  'early',         2,  '1 hour', 'scan',            'quiet',                NULL),
  ('script',  'early',         3,  '1 hour', 'scan',            'quiet',                NULL);
INSERT INTO t_isolation_step SELECT 'history', h.name, 9, '0', 'b_add', NULL, NULL FROM (SELECT DISTINCT s.name FROM t_isolation_step AS s WHERE s.phase = 'history') AS h;
INSERT INTO t_isolation_step VALUES ('history', 'lease', 10, '0', 'record_held', 'problem_else_change', NULL);

DO $$
BEGIN
  ASSERT (SELECT count(DISTINCT s.name) FROM t_isolation_step AS s WHERE s.phase = 'history') = 9
     AND (SELECT count(DISTINCT s.name) FROM t_isolation_step AS s WHERE s.phase = 'script') = 8,
         'docs/TESTING.md names nine histories and eight scripts, update it with the step table';
END
$$;

DO $$
DECLARE
  window_start    CONSTANT interval := interval '3 hours';
  window_end      CONSTANT interval := interval '21 hours';
  longest_stretch interval;
  chosen_name     text;
BEGIN
  SELECT max(stretch.forward) INTO longest_stretch
    FROM (SELECT sum(step_pass.pass_before) FILTER (WHERE step_pass.pass_before < interval '1 day') AS forward
            FROM (SELECT h.name AS history, sc.name AS script, st.pass_before,
                         count(*) FILTER (WHERE st.pass_before >= interval '1 day')
                           OVER (PARTITION BY h.name, sc.name ORDER BY st.phase = 'script', st.step_no) AS day_count
                    FROM (SELECT DISTINCT s.name FROM t_isolation_step AS s WHERE s.phase = 'history') AS h
                    CROSS JOIN (SELECT DISTINCT s.name FROM t_isolation_step AS s WHERE s.phase = 'script') AS sc
                    JOIN t_isolation_step AS st ON (st.phase = 'history' AND st.name = h.name) OR (st.phase = 'script' AND st.name = sc.name)) AS step_pass
           GROUP BY step_pass.history, step_pass.script, step_pass.day_count) AS stretch;
  ASSERT longest_stretch < window_start,
         'the longest stretch of passes with no pass of 1 day stays below the window start, found ' || longest_stretch::text;
  SELECT c.name INTO chosen_name
    FROM unnest(ARRAY['iso0.example', 'iso1.example', 'iso2.example', 'iso3.example',
                      'iso4.example', 'iso5.example', 'iso6.example', 'iso7.example']) WITH ORDINALITY AS c (name, list_order)
   WHERE api.fn_domain_watch_next_daily_scan_at(c.name) - now() BETWEEN window_start AND window_end
   ORDER BY c.list_order
   LIMIT 1;
  ASSERT chosen_name IS NOT NULL,
         'a name of the list has its daily second between ' || window_start::text || ' and ' || window_end::text
         || ' after now(), now() is ' || now()::text;
  PERFORM set_config('t_isolation.domain_name', chosen_name, true);
END
$$;

CREATE TEMP TABLE t_isolation_time_shift AS
  SELECT format('UPDATE public.%I SET %s', col.table_name, string_agg(format('%1$I = %1$I - $1', col.column_name), ', ' ORDER BY col.column_name))
           AS statement
    FROM information_schema.columns AS col
    JOIN information_schema.tables AS tab ON tab.table_schema = col.table_schema AND tab.table_name = col.table_name
   WHERE col.table_schema = 'public' AND tab.table_type = 'BASE TABLE' AND col.data_type = 'timestamp with time zone'
     AND col.table_name ~ '^(watchlist_|domain_watch|domain_change_event|cve_change_event)'
   GROUP BY col.table_name;

CREATE FUNCTION pg_temp.t_isolation_pass_time(p_interval interval) RETURNS void LANGUAGE plpgsql AS $$
DECLARE
  shift_statement text;
BEGIN
  FOR shift_statement IN SELECT ts.statement FROM t_isolation_time_shift AS ts LOOP
    EXECUTE shift_statement USING p_interval;
  END LOOP;
END
$$;

CREATE FUNCTION pg_temp.t_isolation_values(p_endpoint_name text, p_value_kind text, p_value_choice text, p_is_quiet_elsewhere boolean)
  RETURNS text[] LANGUAGE sql AS $$
  SELECT array_agg(CASE WHEN p_value_choice = 'problem_everywhere' THEN coalesce(s.problem_value, s.quiet_value)
                        WHEN k.value_kind = p_value_kind
                        THEN CASE p_value_choice WHEN 'quiet' THEN s.quiet_value WHEN 'change' THEN s.change_value
                                          WHEN 'problem_else_change' THEN coalesce(s.problem_value, s.change_value) END
                        WHEN p_is_quiet_elsewhere THEN s.quiet_value
                   END ORDER BY k.kind_order)
    FROM unnest(api.fn_watchlist_endpoint_value_kinds(p_endpoint_name)) WITH ORDINALITY AS k (value_kind, kind_order)
    JOIN t_isolation_sample AS s ON s.endpoint_name = p_endpoint_name AND s.value_kind = k.value_kind
$$;

CREATE FUNCTION pg_temp.t_isolation_claim(p_endpoint_name text) RETURNS timestamptz LANGUAGE plpgsql AS $$
DECLARE
  lease_end timestamptz;
BEGIN
  EXECUTE (SELECT l.claim_sql FROM t_isolation_lane AS l WHERE l.endpoint_name = p_endpoint_name) INTO lease_end
    USING current_setting('t_isolation.domain_name');
  RETURN lease_end;
END
$$;
CREATE FUNCTION pg_temp.t_isolation_record(p_endpoint_name text, p_lease_end timestamptz, p_values text[]) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
  IF p_lease_end IS NOT NULL THEN
    EXECUTE (SELECT l.record_sql FROM t_isolation_lane AS l WHERE l.endpoint_name = p_endpoint_name) USING current_setting('t_isolation.domain_name'), p_lease_end, p_values;
  END IF;
END
$$;

CREATE FUNCTION pg_temp.t_isolation_edit(p_key_hash text, p_action text, p_endpoint_name text, p_is_cleared boolean DEFAULT false,
                                         p_domain_name_max_count integer DEFAULT 20, p_registered_domain text DEFAULT NULL,
                                         p_item_max_count integer DEFAULT 100, p_domain_name text DEFAULT NULL)
  RETURNS jsonb LANGUAGE sql AS $$
  SELECT jsonb_build_array(jsonb_build_object('edit', concat_ws(':', p_action, p_endpoint_name, p_domain_name, p_is_cleared::text),
                                              'rows', jsonb_agg(to_jsonb(x) - 'ordinality' ORDER BY x.ordinality)))
    FROM pg_temp.t_watchlist_edit(p_key_hash, p_action, p_endpoint_name,
                                  CASE WHEN p_endpoint_name IN ('cve_lookup', 'kev_lookup') THEN 'CVE-2026-0420' END,
                                  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, p_is_cleared, p_item_max_count,
                                  CASE WHEN p_endpoint_name IN ('dns_lookup', 'ssl_check', 'whois_lookup', 'headers_check', 'cert_search')
                                    THEN coalesce(p_domain_name, current_setting('t_isolation.domain_name')) END,
                               CASE WHEN p_endpoint_name IN ('dns_lookup', 'ssl_check', 'whois_lookup', 'headers_check', 'cert_search')
                                    THEN coalesce(p_registered_domain, current_setting('t_isolation.domain_name')) END,
                               p_domain_name_max_count, NULL, NULL, NULL, 500, 100, 100000, 20) WITH ORDINALITY AS x
$$;

CREATE FUNCTION pg_temp.t_isolation_read(p_key_hash text, p_replay_cursor bigint, p_is_repeat_requested boolean) RETURNS jsonb LANGUAGE sql AS $$
  SELECT jsonb_build_array(jsonb_build_object('read', coalesce('replay ' || p_replay_cursor, CASE WHEN p_is_repeat_requested THEN 'repeat' ELSE 'normal' END),
                                              'rows', jsonb_agg(to_jsonb(x) - 'item_id' - 'ordinality' ORDER BY x.ordinality)))
    FROM api.fn_watchlist_events(p_key_hash, p_replay_cursor, p_is_repeat_requested, 2, 1000, 600) WITH ORDINALITY AS x
$$;

CREATE FUNCTION pg_temp.t_isolation_last_has_more(p_log jsonb) RETURNS boolean LANGUAGE sql AS $$
  SELECT (p_log -> -1 -> 'rows' -> 0 ->> 'has_more')::boolean
$$;

CREATE FUNCTION pg_temp.t_isolation_run(p_endpoint_name text, p_value_kind text, p_history text, p_script text, p_with_a boolean, p_with_b boolean)
  RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE
  key_a       CONSTANT text := repeat('a2', 32);
  key_b       CONSTANT text := repeat('b2', 32);
  cve_types   CONSTANT text[] := ARRAY['kev_added', 'exploit_published', 'kev_removed', 'cve_disputed', 'metasploit_added', 'patch_published'];
  step        record;
  lane        text;
  held_lease  timestamptz;
  is_a_silent boolean := false;
  a_facts     jsonb;
  has_b_cve   boolean := false;
  a_log       jsonb := '[]';
  b_log       jsonb := '[]';
  page_number integer;
BEGIN
  FOR step IN
    SELECT s.* FROM t_isolation_step AS s
     WHERE (s.phase = 'history' AND s.name = p_history) OR (s.phase = 'script' AND s.name = p_script)
     ORDER BY s.phase = 'script', s.step_no
  LOOP
    IF step.pass_before = interval '1 day' THEN
      PERFORM pg_temp.t_isolation_pass_time((SELECT l.day_pass FROM t_isolation_lane AS l WHERE l.endpoint_name = p_endpoint_name));
    ELSIF step.pass_before > interval '0' THEN
      PERFORM pg_temp.t_isolation_pass_time(step.pass_before);
    END IF;
    CASE step.action
      WHEN 'a_add_domain' THEN
        IF p_with_a THEN
          a_log := a_log || pg_temp.t_isolation_edit(key_a, 'add', 'dns_lookup', false, 20, step.registered_domain)
                         || pg_temp.t_isolation_edit(key_a, 'add', 'ssl_check', false, 20, step.registered_domain)
                         || pg_temp.t_isolation_edit(key_a, 'add', 'whois_lookup', false, 20, step.registered_domain)
                         || pg_temp.t_isolation_edit(key_a, 'add', 'headers_check', false, 20, step.registered_domain)
                         || pg_temp.t_isolation_edit(key_a, 'add', 'cert_search', false, 20, step.registered_domain);
        END IF;
      WHEN 'a_add_cve' THEN
        IF p_with_a THEN
          a_log := a_log || pg_temp.t_isolation_edit(key_a, 'add', 'cve_lookup') || pg_temp.t_isolation_edit(key_a, 'add', 'kev_lookup');
        END IF;
      WHEN 'a_remove_domain' THEN
        IF p_with_a THEN
          a_log := a_log || pg_temp.t_isolation_edit(key_a, 'remove', 'dns_lookup') || pg_temp.t_isolation_edit(key_a, 'remove', 'ssl_check')
                         || pg_temp.t_isolation_edit(key_a, 'remove', 'whois_lookup') || pg_temp.t_isolation_edit(key_a, 'remove', 'headers_check')
                         || pg_temp.t_isolation_edit(key_a, 'remove', 'cert_search');
        END IF;
      WHEN 'a_clear' THEN
        IF p_with_a THEN
          a_log := a_log || pg_temp.t_isolation_edit(key_a, NULL, NULL, true);
        END IF;
      WHEN 'a_silent' THEN
        is_a_silent := true;
      WHEN 'b_add' THEN
        IF step.phase = 'history' THEN
          a_facts := jsonb_build_object(
            'value_count', (SELECT count(*) FROM watchlist_item_domain_value AS widv JOIN watchlist_item AS wi ON wi.item_id = widv.item_id
                             JOIN api_keys AS ak ON ak.id = wi.api_key_id WHERE ak.key_hash = key_a),
            'waiting_ref_count', (SELECT count(*) FROM watchlist_event_ref AS wer JOIN api_keys AS ak ON ak.id = wer.api_key_id
                                   WHERE ak.key_hash = key_a AND wer.key_event_id IS NULL));
        END IF;
        IF p_with_b THEN
          b_log := b_log || pg_temp.t_isolation_edit(key_b, 'add', p_endpoint_name, false, 1);
          IF NOT has_b_cve THEN
            b_log := b_log || pg_temp.t_isolation_edit(key_b, 'add', 'cve_lookup');
            has_b_cve := true;
          END IF;
        END IF;
      WHEN 'b_remove' THEN
        IF p_with_b THEN
          b_log := b_log || pg_temp.t_isolation_edit(key_b, 'remove', p_endpoint_name);
        END IF;
      WHEN 'cve_event' THEN
        INSERT INTO cve_change_event (cve_id, event_type) VALUES ('CVE-2026-0420', 'kev_added');
      WHEN 'scan' THEN
        PERFORM pg_temp.t_isolation_record(p_endpoint_name, pg_temp.t_isolation_claim(p_endpoint_name),
                                     pg_temp.t_isolation_values(p_endpoint_name, p_value_kind, step.value_choice, false));
      WHEN 'scan_all' THEN
        FOR lane IN SELECT l.endpoint_name FROM t_isolation_lane AS l ORDER BY l.endpoint_name LOOP
          PERFORM pg_temp.t_isolation_record(lane, pg_temp.t_isolation_claim(lane), pg_temp.t_isolation_values(lane, p_value_kind, step.value_choice, true));
        END LOOP;
      WHEN 'claim' THEN
        held_lease := pg_temp.t_isolation_claim(p_endpoint_name);
      WHEN 'record_held' THEN
        PERFORM pg_temp.t_isolation_record(p_endpoint_name, held_lease, pg_temp.t_isolation_values(p_endpoint_name, p_value_kind, step.value_choice, false));
    END CASE;
    IF step.phase = 'script' THEN
      INSERT INTO cve_change_event (cve_id, event_type) VALUES ('CVE-2026-0420', cve_types[1 + step.step_no % 6]);
    END IF;
    IF p_with_b THEN
      b_log := b_log || pg_temp.t_isolation_read(key_b, NULL, false) || pg_temp.t_isolation_read(key_b, NULL, true);
    END IF;
    IF p_with_a AND NOT is_a_silent AND (step.phase = 'history' OR step.step_no % 2 = 0) THEN
      a_log := a_log || pg_temp.t_isolation_read(key_a, NULL, false);
    END IF;
  END LOOP;

  IF p_with_b THEN
    b_log := b_log || pg_temp.t_isolation_read(key_b, NULL, true) || pg_temp.t_isolation_read(key_b, 0, false);
    page_number := 0;
    WHILE page_number < 6 AND (page_number = 0 OR pg_temp.t_isolation_last_has_more(b_log)) LOOP
      b_log := b_log || pg_temp.t_isolation_read(key_b, NULL, false);
      page_number := page_number + 1;
    END LOOP;
  END IF;
  IF p_with_a THEN
    a_log := a_log || pg_temp.t_isolation_read(key_a, NULL, true) || pg_temp.t_isolation_read(key_a, 0, false);
    page_number := 0;
    WHILE page_number < 6 AND (page_number = 0 OR pg_temp.t_isolation_last_has_more(a_log)) LOOP
      a_log := a_log || pg_temp.t_isolation_read(key_a, NULL, false);
      page_number := page_number + 1;
    END LOOP;
  END IF;
  RETURN jsonb_build_object('a', a_log, 'b', b_log, 'a_facts', a_facts);
END
$$;

CREATE FUNCTION pg_temp.t_isolation_isolated(p_endpoint_name text, p_value_kind text, p_history text, p_script text, p_with_a boolean,
                                       p_with_b boolean)
  RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE
  answer jsonb;
BEGIN
  BEGIN
    answer := pg_temp.t_isolation_run(p_endpoint_name, p_value_kind, p_history, p_script, p_with_a, p_with_b);
    RAISE SQLSTATE 'TUNDO';
  EXCEPTION WHEN SQLSTATE 'TUNDO' THEN
    NULL;
  END;
  RETURN answer;
END
$$;

CREATE FUNCTION pg_temp.t_isolation_first_difference(p_first jsonb, p_second jsonb) RETURNS text LANGUAGE sql AS $$
  SELECT 'entry ' || n || ': ' || coalesce((p_first -> (n - 1))::text, 'none') || ' / ' || coalesce((p_second -> (n - 1))::text, 'none')
    FROM generate_series(1, greatest(jsonb_array_length(p_first), jsonb_array_length(p_second))) AS n
   WHERE (p_first -> (n - 1)) IS DISTINCT FROM (p_second -> (n - 1))
   ORDER BY n
   LIMIT 1
$$;

DO $$
DECLARE
  lane_endpoints text[] := ARRAY(SELECT known.endpoint_name
                                   FROM pg_constraint AS con
                                   CROSS JOIN LATERAL regexp_matches(pg_get_constraintdef(con.oid), '''(\w+)''', 'g') AS m
                                   CROSS JOIN LATERAL (SELECT m[1]) AS known (endpoint_name)
                                  WHERE con.conname = 'watchlist_item_endpoint_name_known'
                                    AND cardinality(api.fn_watchlist_endpoint_value_kinds(known.endpoint_name)) > 0
                                  ORDER BY known.endpoint_name);
  lane_endpoint text;
BEGIN
  ASSERT cardinality(lane_endpoints) > 0, 'the CHECK of watchlist_item.endpoint_name names domain endpoints';
  ASSERT lane_endpoints = ARRAY(SELECT l.endpoint_name FROM t_isolation_lane AS l ORDER BY 1),
         'every endpoint with value kinds has a lane adapter row, expected ' || lane_endpoints::text;
  FOREACH lane_endpoint IN ARRAY lane_endpoints LOOP
    ASSERT api.fn_watchlist_endpoint_value_kinds(lane_endpoint)
           = ARRAY(SELECT s.value_kind FROM t_isolation_sample AS s JOIN unnest(api.fn_watchlist_endpoint_value_kinds(lane_endpoint)) WITH ORDINALITY AS k (value_kind, kind_order)
                     ON k.value_kind = s.value_kind WHERE s.endpoint_name = lane_endpoint ORDER BY k.kind_order)
       AND (SELECT count(*) FROM t_isolation_sample AS s WHERE s.endpoint_name = lane_endpoint) = cardinality(api.fn_watchlist_endpoint_value_kinds(lane_endpoint)),
           'the samples of ' || lane_endpoint || ' are its value kinds ' || api.fn_watchlist_endpoint_value_kinds(lane_endpoint)::text;
  END LOOP;
END
$$;

DO $$
DECLARE
  forbidden_tables CONSTANT text[] := ARRAY['domain_watch', 'domain_watch_lane', 'domain_watch_dns_bucket'];
  allowed_tables   CONSTANT text[] := ARRAY['api_keys', 'watchlist_item', 'watchlist_item_cve', 'watchlist_item_domain',
                                            'watchlist_item_domain_value', 'watchlist_key_state', 'watchlist_event_cursor',
                                            'watchlist_event_ref', 'cve_change_event', 'change_event_purge_state',
                                            'domain_change_event', 'package_advisory_change_event', 'cves', 'kev_details', 'cve_products',
                                            'watchlist_item_package', 'osv_advisories', 'osv_affected', 'osv_affected_version_intervals',
                                            'eol_change_event', 'eol_product', 'eol_cycle', 'eol_product_cpe', 'eol_product_package',
                                            'ip_change_event', 'watchlist_item_ip'];
  closure_names    text[];
  read_tables      text[];
BEGIN
  WITH RECURSIVE closure (function_oid) AS (
    SELECT p.oid FROM pg_proc AS p
     WHERE p.oid IN ('api.fn_watchlist_edit_cve_lookup'::regproc, 'api.fn_watchlist_edit_kev_lookup'::regproc,
                     'api.fn_watchlist_edit_cve_exploit'::regproc, 'api.fn_watchlist_edit_product_exposure'::regproc,
                     'api.fn_watchlist_edit_cve_search'::regproc, 'api.fn_watchlist_edit_dns_lookup'::regproc,
                     'api.fn_watchlist_edit_ssl_check'::regproc, 'api.fn_watchlist_edit_whois_lookup'::regproc,
                     'api.fn_watchlist_edit_headers_check'::regproc, 'api.fn_watchlist_edit_cert_search'::regproc,
                     'api.fn_watchlist_edit_package_check'::regproc, 'api.fn_watchlist_edit_ip_lookup'::regproc,
                     'api.fn_watchlist_package_list_edit'::regproc,
                     'api.fn_watchlist_list'::regproc,
                     'api.fn_watchlist_clear'::regproc, 'api.fn_watchlist_events'::regproc)
    UNION
    SELECT callee.function_oid
      FROM closure AS c
      JOIN pg_proc AS p ON p.oid = c.function_oid
      CROSS JOIN LATERAL (SELECT d.refobjid AS function_oid
                            FROM pg_depend AS d
                           WHERE p.prosqlbody IS NOT NULL AND d.classid = 'pg_proc'::regclass AND d.objid = p.oid
                             AND d.refclassid = 'pg_proc'::regclass
                          UNION
                          SELECT q.oid
                            FROM regexp_matches(regexp_replace(p.prosrc, '--[^\n]*', '', 'g'), '(api|public)\.(fn_\w+)', 'g') AS m
                            JOIN pg_proc AS q ON q.proname = m[2] AND q.pronamespace = m[1]::regnamespace
                           WHERE p.prosqlbody IS NULL) AS callee)
  SELECT array_agg(c.function_oid::regproc::text ORDER BY 1),
         ARRAY(SELECT DISTINCT t.table_name
                 FROM closure AS c2
                 JOIN pg_proc AS p ON p.oid = c2.function_oid
                 CROSS JOIN LATERAL (SELECT d.refobjid::regclass::text AS table_name
                                       FROM pg_depend AS d
                                      WHERE p.prosqlbody IS NOT NULL AND d.classid = 'pg_proc'::regclass AND d.objid = p.oid
                                        AND d.refclassid = 'pg_class'::regclass
                                     UNION
                                     SELECT m[1]
                                       FROM regexp_matches(regexp_replace(regexp_replace(p.prosrc, '--[^\n]*', '', 'g'),
                                                                          '(INSERT INTO|UPDATE|DELETE FROM)\s+public\.\w+', '\1', 'g'),
                                                           'public\.(\w+)', 'g') AS m
                                      WHERE p.prosqlbody IS NULL
                                        AND EXISTS (SELECT 1 FROM pg_class AS cl
                                                     WHERE cl.relname = m[1] AND cl.relnamespace = 'public'::regnamespace AND cl.relkind = 'r')) AS t
                ORDER BY 1)
    INTO closure_names, read_tables
    FROM closure AS c;
  ASSERT closure_names @> ARRAY['api.fn_watchlist_event_rows', 'api.fn_watchlist_event_scan', 'api.fn_watchlist_event_item_pairs',
                                'api.fn_watchlist_event_package_pairs', 'api.fn_package_check_advisory', 'api.fn_watchlist_event_eol_pairs',
                                'fn_eol_product_cpe_pick', 'fn_eol_product_package_pick', 'fn_eol_pick_series', 'api.fn_ip_change_event_max_id'],
         'the closure reaches api.fn_watchlist_event_rows, api.fn_watchlist_event_scan, api.fn_watchlist_event_item_pairs, '
         || 'api.fn_watchlist_event_package_pairs, api.fn_package_check_advisory, api.fn_watchlist_event_eol_pairs, '
         || 'the three EOL pick functions and api.fn_ip_change_event_max_id, found ' || closure_names::text;
  ASSERT read_tables @> ARRAY['watchlist_item_ip', 'ip_change_event', 'change_event_purge_state'],
         'the closure reads the IP item table and the IP event head, found ' || read_tables::text;
  ASSERT NOT closure_names && ARRAY['api.fn_ip_watch_write_values', 'api.fn_ip_change_event_purge'],
         'no entry point reaches the IP writer or the IP purge';
  ASSERT NOT read_tables && forbidden_tables,
         'expected no entry point to read the shared scan state, but the closure reads '
         || ARRAY(SELECT unnest(read_tables) INTERSECT SELECT unnest(forbidden_tables) ORDER BY 1)::text;
  ASSERT read_tables <@ allowed_tables,
         'expected the closure to read only listed tables, unlisted: ' || ARRAY(SELECT unnest(read_tables) EXCEPT SELECT unnest(allowed_tables) ORDER BY 1)::text;
END
$$;

CREATE FUNCTION pg_temp.t_isolation_package_edit(p_key_hash text, p_action text, p_package_name text, p_version text)
  RETURNS jsonb LANGUAGE sql AS $$
  SELECT jsonb_agg(to_jsonb(x) - 'ordinality' ORDER BY x.ordinality)
    FROM pg_temp.t_watchlist_edit(p_key_hash, p_action, CASE WHEN p_action IS NOT NULL THEN 'package_check' END, NULL, NULL, NULL, NULL,
                                  NULL, NULL, NULL, NULL, NULL, NULL, false, 100, NULL, NULL, 20,
                                  CASE WHEN p_action IS NOT NULL THEN 'npm' END, p_package_name, p_version, 500, 100, 100000, 20) WITH ORDINALITY AS x
$$;
CREATE FUNCTION pg_temp.t_isolation_package_probe(p_with_a boolean) RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE
  key_a CONSTANT text := repeat('a2', 32);
  key_b CONSTANT text := repeat('b2', 32);
  b_log jsonb := '[]';
  a_log jsonb := '[]';
BEGIN
  BEGIN
    IF p_with_a THEN
      PERFORM pg_temp.t_isolation_package_edit(key_a, 'add', 'lodash', NULL);
      PERFORM pg_temp.t_isolation_package_edit(key_a, 'add', 'Lodash', '4.17.20');
    END IF;
    b_log := b_log || pg_temp.t_isolation_package_edit(key_b, 'add', 'LODASH', NULL)
                   || pg_temp.t_isolation_package_edit(key_b, 'add', 'lodash', '4.17.20')
                   || pg_temp.t_isolation_package_edit(key_b, 'add', 'left-pad', NULL)
                   || pg_temp.t_isolation_package_edit(key_b, NULL, NULL, NULL)
                   || pg_temp.t_isolation_package_edit(key_b, 'remove', 'lodash', NULL)
                   || pg_temp.t_isolation_package_edit(key_b, NULL, NULL, NULL);
    IF p_with_a THEN
      a_log := pg_temp.t_isolation_package_edit(key_a, NULL, NULL, NULL);
    END IF;
    RAISE SQLSTATE 'TUNDO';
  EXCEPTION WHEN SQLSTATE 'TUNDO' THEN
    NULL;
  END;
  RETURN jsonb_build_object('a', a_log, 'b', b_log);
END
$$;

DO $$
DECLARE
  alone  jsonb := pg_temp.t_isolation_package_probe(false);
  beside jsonb := pg_temp.t_isolation_package_probe(true);
BEGIN
  ASSERT beside -> 'b' = alone -> 'b',
         format('the package edits of key B answer the same beside key A: alone %s, beside %s', alone -> 'b', beside -> 'b');
  ASSERT jsonb_array_length(alone -> 'b') = 9
     AND alone -> 'b' -> 0 ->> 'package_name' = 'LODASH'
     AND (alone -> 'b' -> 2 ->> 'package_item_count')::integer = 3
     AND alone -> 'b' -> 6 ->> 'package_name' = 'LODASH'
     AND (alone -> 'b' -> 8 ->> 'package_item_count')::integer = 2,
         format('key B adds its own lodash, lists three items and removes one: %s', alone -> 'b');
  ASSERT (SELECT array_agg((r ->> 'package_name') || '|' || coalesce(r ->> 'version', 'null') || '|' || (r ->> 'item_count') || '|'
                           || (r ->> 'package_item_count'))
            FROM jsonb_array_elements(beside -> 'a') AS r)
         = ARRAY['lodash|null|0|2', 'Lodash|4.17.20|0|2'],
         format('key A keeps its two package items and counts only them: %s', beside -> 'a');
END
$$;

CREATE FUNCTION pg_temp.t_isolation_package_seed() RETURNS void LANGUAGE sql AS $$
  INSERT INTO osv_advisories (advisory_id, source, license, summary, aliases, published_time, modified_time) VALUES
    ('GHSA-wliso-0001', 'ghsa', 'CC-BY-4.0', '', ARRAY['CVE-2026-0420'], '2021-01-01T00:00:00Z', '2021-01-01T00:00:00Z');
  INSERT INTO osv_affected (advisory_id, affected_index, ecosystem, package_name, version_ranges, listed_versions, listed_versions_sortable,
                            is_unaffected_provable) VALUES
    ('GHSA-wliso-0001', 0, 'npm', 'wliso-pkg', '[{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}]', '{}', '{}', true);
  INSERT INTO osv_affected_version_intervals (advisory_id, affected_index, interval_index, introduced_version_sortable, upper_version_sortable,
                                              upper_event, fixed_version)
  SELECT 'GHSA-wliso-0001', 0, 0, NULL, public.fn_osv_version_sortable('npm', '2.0.0'), 'fixed', '2.0.0';
$$;
CREATE FUNCTION pg_temp.t_isolation_package_add(p_key_hash text, p_version text) RETURNS void LANGUAGE sql AS $$
  SELECT count(*) FROM pg_temp.t_watchlist_edit(p_key_hash, 'add', 'package_check', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
                                                NULL, false, 100, NULL, NULL, 20, 'npm', 'wliso-pkg', p_version, 500, 100, 100000, 20);
$$;
CREATE FUNCTION pg_temp.t_isolation_package_read(p_key_hash text, p_replay_cursor bigint, p_is_repeat_requested boolean)
  RETURNS jsonb LANGUAGE sql AS $$
  SELECT jsonb_agg(to_jsonb(x) - 'item_id' - 'ordinality' ORDER BY x.ordinality)
    FROM api.fn_watchlist_events(p_key_hash, p_replay_cursor, p_is_repeat_requested, 100, 100, 600) WITH ORDINALITY AS x
$$;
CREATE FUNCTION pg_temp.t_isolation_package_event_probe(p_with_a boolean, p_with_b boolean) RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE
  key_a CONSTANT text := repeat('a2', 32);
  key_b CONSTANT text := repeat('b2', 32);
  b_log jsonb := '[]';
  a_log jsonb := '[]';
BEGIN
  BEGIN
    PERFORM pg_temp.t_isolation_package_seed();
    INSERT INTO eol_product (product_name, product_label, url) VALUES ('wliso-eol', 'WLISO EOL', 'https://endoflife.date/wliso-eol');
    INSERT INTO eol_cycle (eol_product, cycle_name, release_date, eol_date, is_eol, is_maintained, is_lts) VALUES
      ('wliso-eol', '1', '2020-01-01', NULL, true, false, false), ('wliso-eol', '3', '2022-01-01', NULL, true, false, false);
    INSERT INTO eol_product_package (ecosystem, package_name, eol_product) VALUES ('npm', 'wliso-pkg', 'wliso-eol');
    IF p_with_a THEN
      PERFORM pg_temp.t_isolation_package_add(key_a, NULL);
      PERFORM pg_temp.t_isolation_package_add(key_a, '1.0.0');
    END IF;
    IF p_with_b THEN
      PERFORM pg_temp.t_isolation_package_add(key_b, NULL);
      PERFORM pg_temp.t_isolation_package_add(key_b, '1.0.0');
      PERFORM pg_temp.t_isolation_package_add(key_b, '3.0.0');
    END IF;
    INSERT INTO package_advisory_change_event (advisory_id, ecosystem, package_name_normalized, package_name, event_type, fixed_version)
    VALUES ('GHSA-wliso-0001', 'npm', 'wliso-pkg', 'wliso-pkg', 'advisory_added', NULL),
           ('GHSA-wliso-0001', 'npm', 'wliso-pkg', 'wliso-pkg', 'fix_available', '2.0.0');
    INSERT INTO cve_change_event (cve_id, event_type) VALUES ('CVE-2026-0420', 'kev_added');
    INSERT INTO eol_change_event (eol_product, cycle_name, event_type, eol_date, previous_eol_date)
    VALUES ('wliso-eol', '1', 'eol_reached', NULL, NULL), ('wliso-eol', '3', 'eol_reached', NULL, NULL);
    IF p_with_b THEN
      b_log := jsonb_build_array(pg_temp.t_isolation_package_read(key_b, NULL, false), pg_temp.t_isolation_package_read(key_b, NULL, true),
                                 pg_temp.t_isolation_package_read(key_b, 0, false));
    END IF;
    IF p_with_a THEN
      a_log := jsonb_build_array(pg_temp.t_isolation_package_read(key_a, NULL, false));
    END IF;
    RAISE SQLSTATE 'TUNDO';
  EXCEPTION WHEN SQLSTATE 'TUNDO' THEN
    NULL;
  END;
  RETURN jsonb_build_object('a', a_log, 'b', b_log);
END
$$;

DO $$
DECLARE
  b_alone   jsonb := pg_temp.t_isolation_package_event_probe(false, true);
  both_keys jsonb := pg_temp.t_isolation_package_event_probe(true, true);
  a_alone   jsonb := pg_temp.t_isolation_package_event_probe(true, false);
BEGIN
  ASSERT both_keys -> 'b' = b_alone -> 'b',
         format('the package events of key B read the same beside key A: alone %s, beside %s', b_alone -> 'b', both_keys -> 'b');
  ASSERT both_keys -> 'a' = a_alone -> 'a',
         format('the package events of key A read the same beside key B: alone %s, beside %s', a_alone -> 'a', both_keys -> 'a');
  ASSERT (SELECT array_agg(coalesce(r ->> 'item_version', '*') || ':' || coalesce(r ->> 'affects_version', 'null') ORDER BY o)
            FROM jsonb_array_elements(b_alone #> '{b,0}') WITH ORDINALITY AS t (r, o))
         = ARRAY['*:null', '*:null', '*:null', '*:null', '*:null', '1.0.0:true', '1.0.0:true', '1.0.0:true', '1.0.0:null', '3.0.0:null'],
         format('key B hears the three package events through two items, and each EOL event through the item of its series and the item with no version: %s',
                b_alone #> '{b,0}');
  ASSERT b_alone #> '{b,0}' = b_alone #> '{b,1}' AND b_alone #> '{b,0}' = b_alone #> '{b,2}',
         'key B reads the same rows in its normal call, its repeat and its replay';
  ASSERT jsonb_array_length(a_alone #> '{a,0}') = 9, format('key A hears the five events through its two items: %s', a_alone #> '{a,0}');
END
$$;

CREATE TEMP TABLE t_isolation_case AS
  WITH kind AS (
    SELECT s.endpoint_name, s.value_kind, row_number() OVER (ORDER BY s.endpoint_name, s.value_kind) - 1 AS kind_number
      FROM t_isolation_sample AS s),
  history AS (
    SELECT h.name, row_number() OVER (ORDER BY h.name) - 1 AS history_number
      FROM (SELECT DISTINCT st.name FROM t_isolation_step AS st WHERE st.phase = 'history') AS h),
  script AS (
    SELECT sc.name, row_number() OVER (ORDER BY sc.name) - 1 AS script_number, count(*) OVER () AS script_count
      FROM (SELECT DISTINCT st.name FROM t_isolation_step AS st WHERE st.phase = 'script') AS sc)
  SELECT k.endpoint_name, k.value_kind, h.name AS history, sc.name AS script
    FROM kind AS k
    CROSS JOIN history AS h
    JOIN script AS sc ON sc.script_number = (k.kind_number + h.history_number) % sc.script_count;

INSERT INTO t_isolation_case
  SELECT pin.endpoint_name, pin.value_kind, pin.history, pin.script
    FROM (VALUES ('ssl_check', 'certificate_expiry', 'silent', 'flap')) AS pin (endpoint_name, value_kind, history, script)
   WHERE NOT EXISTS (SELECT 1 FROM t_isolation_case AS c
                      WHERE (c.endpoint_name, c.value_kind, c.history, c.script) = (pin.endpoint_name, pin.value_kind, pin.history, pin.script));

DO $$
BEGIN
  ASSERT (SELECT count(DISTINCT (c.endpoint_name, c.value_kind, c.history)) FROM t_isolation_case AS c)
         = (SELECT count(*) FROM t_isolation_sample) * (SELECT count(DISTINCT st.name) FROM t_isolation_step AS st WHERE st.phase = 'history'),
         'every kind meets every history';
  ASSERT (SELECT count(DISTINCT (c.endpoint_name, c.value_kind, c.script)) FROM t_isolation_case AS c)
         = (SELECT count(*) FROM t_isolation_sample) * (SELECT count(DISTINCT st.name) FROM t_isolation_step AS st WHERE st.phase = 'script'),
         'every kind meets every script';
  ASSERT (SELECT count(DISTINCT (c.history, c.script)) FROM t_isolation_case AS c)
         = (SELECT count(DISTINCT st.name) FROM t_isolation_step AS st WHERE st.phase = 'history')
           * (SELECT count(DISTINCT st.name) FROM t_isolation_step AS st WHERE st.phase = 'script'),
         'every history meets every script';
END
$$;

DO $$
DECLARE
  c             record;
  b_alone       jsonb;
  both_keys     jsonb;
  a_alone       jsonb;
  run_count     integer := 0;
  seen_types    text[] := '{}';
  case_label    text;
BEGIN
  FOR c IN SELECT * FROM t_isolation_case ORDER BY 1, 2, 3, 4 LOOP
    case_label := c.endpoint_name || '/' || c.value_kind || '/' || c.history || '/' || c.script;
    b_alone   := pg_temp.t_isolation_isolated(c.endpoint_name, c.value_kind, c.history, c.script, false, true);
    both_keys := pg_temp.t_isolation_isolated(c.endpoint_name, c.value_kind, c.history, c.script, true, true);
    a_alone   := pg_temp.t_isolation_isolated(c.endpoint_name, c.value_kind, c.history, c.script, true, false);
    run_count := run_count + 3;
    ASSERT both_keys -> 'b' = b_alone -> 'b',
           case_label || ': expected key B beside key A to read what it reads alone, alone / beside at '
           || pg_temp.t_isolation_first_difference(b_alone -> 'b', both_keys -> 'b');
    ASSERT both_keys -> 'a' = a_alone -> 'a',
           case_label || ': expected key A beside key B to read what it reads alone, alone / beside at '
           || pg_temp.t_isolation_first_difference(a_alone -> 'a', both_keys -> 'a');
    ASSERT CASE c.history WHEN 'removed' THEN (a_alone #>> '{a_facts,value_count}')::integer = 0
                          WHEN 'cleared' THEN (a_alone #>> '{a_facts,value_count}')::integer = 0
                          WHEN 'silent'  THEN (a_alone #>> '{a_facts,waiting_ref_count}')::integer = 8
                          ELSE (a_alone #>> '{a_facts,value_count}')::integer > 0 END,
           case_label || ': expected the history to give key A its values, or its waiting refs, found ' || (a_alone -> 'a_facts')::text;
    seen_types := seen_types || ARRAY(SELECT jsonb_path_query(both_keys, '$.*[*].rows[*].event_type ? (@ != null)') #>> '{}');
  END LOOP;
  ASSERT ARRAY(SELECT DISTINCT t FROM unnest(seen_types) AS t WHERE t IN (SELECT unnest(api.fn_watchlist_endpoint_event_types(l.endpoint_name)) FROM t_isolation_lane AS l) ORDER BY 1)
         = ARRAY(SELECT DISTINCT t FROM t_isolation_lane AS l CROSS JOIN LATERAL unnest(api.fn_watchlist_endpoint_event_types(l.endpoint_name)) AS t ORDER BY 1),
         'the matrix produces every event type of every domain endpoint, seen '
         || ARRAY(SELECT DISTINCT t FROM unnest(seen_types) AS t ORDER BY 1)::text;
  RAISE NOTICE 't_watch_isolation: % runs', run_count;
END
$$;

CREATE FUNCTION pg_temp.t_isolation_edit_probe(p_with_a boolean, p_with_b boolean DEFAULT true) RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE
  key_a    CONSTANT text := repeat('a2', 32);
  key_b    CONSTANT text := repeat('b2', 32);
  www_name CONSTANT text := 'www.' || current_setting('t_isolation.domain_name');
  a_log    jsonb := '[]';
  b_log    jsonb := '[]';
BEGIN
  IF p_with_a THEN
    PERFORM pg_temp.t_isolation_edit(key_a, 'add', 'ssl_check', p_domain_name => www_name);
    PERFORM pg_temp.t_isolation_edit(key_a, 'add', 'dns_lookup');
    PERFORM pg_temp.t_isolation_edit(key_a, 'add', 'cve_lookup');
    PERFORM pg_temp.t_isolation_pass_time('1 hour');
    PERFORM pg_temp.t_isolation_record('dns_lookup', pg_temp.t_isolation_claim('dns_lookup'),
                                       pg_temp.t_isolation_values('dns_lookup', 'dns_presence', 'problem_else_change', true));
    INSERT INTO cve_change_event (cve_id, event_type) VALUES ('CVE-2026-0420', 'kev_added');
    a_log := a_log || pg_temp.t_isolation_read(key_a, NULL, false);
    INSERT INTO cve_change_event (cve_id, event_type) VALUES ('CVE-2026-0420', 'cve_disputed');
  END IF;
  IF p_with_b THEN
    b_log := b_log || pg_temp.t_isolation_edit(key_b, 'add', 'dns_lookup', p_domain_name_max_count => 1, p_item_max_count => 2)
                   || pg_temp.t_isolation_edit(key_b, 'add', 'ssl_check', p_domain_name_max_count => 1, p_item_max_count => 2,
                                               p_domain_name => www_name)
                   || pg_temp.t_isolation_edit(key_b, 'add', 'cve_lookup', p_domain_name_max_count => 1, p_item_max_count => 2)
                   || pg_temp.t_isolation_edit(key_b, 'add', 'kev_lookup', p_domain_name_max_count => 1, p_item_max_count => 2)
                   || pg_temp.t_isolation_read(key_b, NULL, false)
                   || pg_temp.t_isolation_edit(key_b, 'remove', 'cve_lookup')
                   || pg_temp.t_isolation_edit(key_b, 'remove', 'dns_lookup')
                   || pg_temp.t_isolation_read(key_b, NULL, false)
                   || pg_temp.t_isolation_read(key_b, 0, false)
                   || pg_temp.t_isolation_edit(key_b, NULL, NULL, true);
  END IF;
  INSERT INTO cve_change_event (cve_id, event_type) VALUES ('CVE-2026-0420', 'exploit_published');
  IF p_with_a THEN
    a_log := a_log || pg_temp.t_isolation_read(key_a, NULL, false) || pg_temp.t_isolation_read(key_a, NULL, true)
                   || pg_temp.t_isolation_read(key_a, 0, false);
  END IF;
  RETURN jsonb_build_object('a', a_log, 'b', b_log);
END
$$;

CREATE FUNCTION pg_temp.t_isolation_purge_probe(p_with_a boolean) RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE
  key_a         CONSTANT text := repeat('a2', 32);
  key_b         CONSTANT text := repeat('b2', 32);
  b_log         jsonb := '[]';
  purged_counts jsonb;
BEGIN
  IF p_with_a THEN
    PERFORM pg_temp.t_isolation_edit(key_a, 'add', 'dns_lookup');
    PERFORM pg_temp.t_isolation_edit(key_a, 'add', 'cve_lookup');
  END IF;
  PERFORM pg_temp.t_isolation_pass_time('1 hour');
  PERFORM pg_temp.t_isolation_record('dns_lookup', pg_temp.t_isolation_claim('dns_lookup'),
                                     pg_temp.t_isolation_values('dns_lookup', 'dns_presence', 'problem_else_change', true));
  INSERT INTO cve_change_event (cve_id, event_type) VALUES ('CVE-2026-0420', 'kev_added');
  IF p_with_a THEN
    PERFORM pg_temp.t_isolation_read(key_a, NULL, false);
  END IF;
  PERFORM pg_temp.t_isolation_pass_time('91 days');
  b_log := b_log || pg_temp.t_isolation_edit(key_b, 'add', 'dns_lookup') || pg_temp.t_isolation_edit(key_b, 'add', 'cve_lookup');
  PERFORM pg_temp.t_isolation_pass_time('1 day');
  PERFORM pg_temp.t_isolation_record('dns_lookup', pg_temp.t_isolation_claim('dns_lookup'),
                                     pg_temp.t_isolation_values('dns_lookup', 'dns_presence', 'problem_else_change', true));
  INSERT INTO cve_change_event (cve_id, event_type) VALUES ('CVE-2026-0420', 'exploit_published');
  b_log := b_log || pg_temp.t_isolation_read(key_b, NULL, false);
  UPDATE api_keys SET expires_at = now() - interval '31 days' WHERE key_hash = key_a;
  purged_counts := jsonb_build_object('domain_events', api.fn_domain_change_event_purge(100),
                                      'cve_events', api.fn_cve_change_event_purge(100),
                                      'keys', api.fn_watchlist_purge(100));
  b_log := b_log || pg_temp.t_isolation_read(key_b, 0, false) || pg_temp.t_isolation_read(key_b, NULL, true)
                 || pg_temp.t_isolation_read(key_b, NULL, false);
  RETURN jsonb_build_object('b', b_log, 'purged_counts', purged_counts);
END
$$;

CREATE FUNCTION pg_temp.t_isolation_probe_isolated(p_probe text, p_with_a boolean) RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE
  answer jsonb;
BEGIN
  BEGIN
    EXECUTE format('SELECT pg_temp.%I($1)', p_probe) INTO answer USING p_with_a;
    RAISE SQLSTATE 'TUNDO';
  EXCEPTION WHEN SQLSTATE 'TUNDO' THEN
    NULL;
  END;
  RETURN answer;
END
$$;

CREATE FUNCTION pg_temp.t_isolation_edit_probe_a_alone() RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE
  answer jsonb;
BEGIN
  BEGIN
    answer := pg_temp.t_isolation_edit_probe(true, false);
    RAISE SQLSTATE 'TUNDO';
  EXCEPTION WHEN SQLSTATE 'TUNDO' THEN
    NULL;
  END;
  RETURN answer;
END
$$;

DO $$
DECLARE
  probe   text;
  alone   jsonb;
  beside  jsonb;
  a_alone jsonb;
BEGIN
  FOREACH probe IN ARRAY ARRAY['t_isolation_edit_probe', 't_isolation_purge_probe'] LOOP
    alone  := pg_temp.t_isolation_probe_isolated(probe, false);
    beside := pg_temp.t_isolation_probe_isolated(probe, true);
    ASSERT beside -> 'b' = alone -> 'b',
           probe || ': expected key B beside key A to read what it reads alone, alone / beside at '
           || pg_temp.t_isolation_first_difference(alone -> 'b', beside -> 'b');
    IF probe = 't_isolation_edit_probe' THEN
      a_alone := pg_temp.t_isolation_edit_probe_a_alone();
      ASSERT beside -> 'a' = a_alone -> 'a',
             'edit probe: expected key A beside key B to read what it reads alone, alone / beside at '
             || pg_temp.t_isolation_first_difference(a_alone -> 'a', beside -> 'a');
      ASSERT ARRAY(SELECT jsonb_path_query(alone, '$.b[*].rows[*].edit_status') #>> '{}') @> ARRAY['over_domain_limit', 'over_limit'],
             'the edit probe reaches over_domain_limit and over_limit, found ' || (alone -> 'b')::text;
    ELSE
      ASSERT (beside #>> '{purged_counts,keys}')::integer = 1 AND (beside #>> '{purged_counts,domain_events}')::integer > 0
         AND (beside #>> '{purged_counts,cve_events}')::integer > 0,
             'the purge probe purges key A and its old events, found ' || (beside -> 'purged_counts')::text;
    END IF;
  END LOOP;
END
$$;

CREATE TEMP TABLE t_isolation_ip_step (phase text, name text, step_no integer, actor text, action text);
INSERT INTO t_isolation_ip_step VALUES
  ('history', 'same',     1, 'a',     'add'),
  ('history', 'same',     2, 'world', 'run'),
  ('history', 'pending',  1, 'a',     'add'),
  ('history', 'pending',  2, 'world', 'run'),
  ('history', 'pending',  3, 'world', 'asn_change'),
  ('history', 'pending',  4, 'world', 'run'),
  ('history', 'pending',  5, 'world', 'asn_back'),
  ('history', 'unlisted', 1, 'world', 'unlist'),
  ('history', 'unlisted', 2, 'a',     'add'),
  ('history', 'unlisted', 3, 'world', 'run'),
  ('history', 'unlisted', 4, 'world', 'relist'),
  ('history', 'removed',  1, 'a',     'add'),
  ('history', 'removed',  2, 'world', 'run'),
  ('history', 'removed',  3, 'a',     'remove'),
  ('history', 'cleared',  1, 'a',     'add'),
  ('history', 'cleared',  2, 'world', 'run'),
  ('history', 'cleared',  3, 'a',     'clear'),
  ('history', 'held',     1, 'a',     'add'),
  ('history', 'held',     2, 'world', 'run'),
  ('history', 'held',     3, 'world', 'unlist'),
  ('history', 'held',     4, 'world', 'run'),
  ('history', 'held',     5, 'world', 'relist'),
  ('script',  'b',        1, 'b',     'add'),
  ('script',  'b',        2, 'world', 'run'),
  ('script',  'b',        3, 'world', 'asn_change'),
  ('script',  'b',        4, 'world', 'run'),
  ('script',  'b',        5, 'world', 'run'),
  ('script',  'b',        6, 'world', 'unlist'),
  ('script',  'b',        7, 'world', 'run'),
  ('script',  'b',        8, 'world', 'relist'),
  ('script',  'b',        9, 'world', 'run');

CREATE FUNCTION pg_temp.t_isolation_ip_read(p_key_hash text) RETURNS jsonb LANGUAGE sql AS $$
  SELECT count(*) FROM api.fn_watchlist_events(p_key_hash, NULL, false, 100, 100, 600);
  SELECT jsonb_build_object(
    'events', (SELECT coalesce(jsonb_agg(to_jsonb(x) - 'item_id' - 'ordinality' ORDER BY x.ordinality)
                                 FILTER (WHERE x.event_type IS NOT NULL), '[]')
                 FROM api.fn_watchlist_events(p_key_hash, 0, false, 100, 100, 600) WITH ORDINALITY AS x),
    'values', (SELECT coalesce(jsonb_agg(jsonb_build_object('kind', wiiv.value_kind, 'current', wiiv.current_value,
                                                            'candidate', wiiv.candidate_value, 'has_seen_at', wiiv.candidate_seen_at IS NOT NULL)
                                         ORDER BY wiiv.value_kind), '[]')
                 FROM watchlist_item_ip_value AS wiiv
                 JOIN watchlist_item_ip AS wii ON wii.item_id = wiiv.item_id
                 JOIN api_keys AS ak ON ak.id = wii.api_key_id
                WHERE ak.key_hash = p_key_hash),
    'list', (SELECT jsonb_agg(to_jsonb(x) - 'ordinality' ORDER BY x.ordinality) FROM api.fn_watchlist_list(p_key_hash) WITH ORDINALITY AS x))
$$;

CREATE FUNCTION pg_temp.t_isolation_ip_probe(p_history text, p_with_a boolean, p_with_b boolean) RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE
  key_a   CONSTANT text := repeat('a2', 32);
  key_b   CONSTANT text := repeat('b2', 32);
  address CONSTANT inet := '192.0.2.77';
  step    record;
  key_hash text;
  a_log   jsonb := '[]';
  b_log   jsonb := '[]';
BEGIN
  BEGIN
    DELETE FROM watchlist_item WHERE endpoint_name = 'ip_lookup';
    DELETE FROM ip_change_event;
    DELETE FROM ip_drop_list_prefix;
    DELETE FROM ip_asn_prefix WHERE prefix && '192.0.2.0/24'::cidr;
    INSERT INTO ip_asn (asn, asn_name, country) VALUES (64510, 'Isolation AS 64510', 'NL'), (64511, 'Isolation AS 64511', 'NL')
    ON CONFLICT DO NOTHING;
    INSERT INTO ip_asn_prefix (prefix, asn) VALUES ('192.0.2.0/24', 64510);
    INSERT INTO ip_drop_list_prefix (prefix, listing_id, regional_registry, list_time, copyright)
    VALUES ('192.0.2.0/25', 'SBL77', 'ripencc', '2026-11-01T00:00:00Z', '(c) 2026 isolation'),
           ('198.18.0.0/15', 'SBL78', 'arin', '2026-11-01T00:00:00Z', '(c) 2026 isolation');
    FOR step IN SELECT * FROM t_isolation_ip_step AS st
                 WHERE (st.phase = 'history' AND st.name = p_history) OR st.phase = 'script'
                 ORDER BY st.phase, st.step_no LOOP
      IF (step.actor <> 'a' OR p_with_a) AND (step.actor <> 'b' OR p_with_b) THEN
        key_hash := CASE step.actor WHEN 'a' THEN key_a ELSE key_b END;
        CASE step.action
          WHEN 'add'        THEN PERFORM count(*) FROM api.fn_watchlist_edit_ip_lookup(key_hash, 'add', address, 100);
          WHEN 'remove'     THEN PERFORM count(*) FROM api.fn_watchlist_edit_ip_lookup(key_hash, 'remove', address, 100);
          WHEN 'clear'      THEN PERFORM count(*) FROM api.fn_watchlist_clear(key_hash);
          WHEN 'run'        THEN UPDATE watchlist_item_ip SET checked_at = checked_at - interval '2 hours';
                                 UPDATE watchlist_item_ip_value SET candidate_seen_at = candidate_seen_at - interval '2 hours';
                                 PERFORM api.fn_ip_watch_write_values(100);
          WHEN 'unlist'     THEN DELETE FROM ip_drop_list_prefix WHERE prefix = '192.0.2.0/25';
          WHEN 'relist'     THEN INSERT INTO ip_drop_list_prefix (prefix, listing_id, regional_registry, list_time, copyright)
                                 VALUES ('192.0.2.0/25', 'SBL77', 'ripencc', '2026-11-01T00:00:00Z', '(c) 2026 isolation');
          WHEN 'asn_change' THEN UPDATE ip_asn_prefix SET asn = 64511 WHERE prefix = '192.0.2.0/24';
          WHEN 'asn_back'   THEN UPDATE ip_asn_prefix SET asn = 64510 WHERE prefix = '192.0.2.0/24';
        END CASE;
      END IF;
      IF step.phase = 'script' THEN
        IF p_with_b THEN
          b_log := b_log || jsonb_build_array(pg_temp.t_isolation_ip_read(key_b));
        END IF;
        IF p_with_a THEN
          a_log := a_log || jsonb_build_array(pg_temp.t_isolation_ip_read(key_a));
        END IF;
      END IF;
    END LOOP;
    RAISE SQLSTATE 'TUNDO';
  EXCEPTION WHEN SQLSTATE 'TUNDO' THEN
    NULL;
  END;
  RETURN jsonb_build_object('a', a_log, 'b', b_log);
END
$$;

DO $$
DECLARE
  history   text;
  b_alone   jsonb;
  both_keys jsonb;
  a_alone   jsonb;
BEGIN
  FOR history IN SELECT DISTINCT st.name FROM t_isolation_ip_step AS st WHERE st.phase = 'history' ORDER BY 1 LOOP
    b_alone   := pg_temp.t_isolation_ip_probe(history, false, true);
    both_keys := pg_temp.t_isolation_ip_probe(history, true, true);
    a_alone   := pg_temp.t_isolation_ip_probe(history, true, false);
    ASSERT both_keys -> 'b' = b_alone -> 'b',
           'ip/' || history || ': expected key B beside key A to read what it reads alone, alone / beside at '
           || pg_temp.t_isolation_first_difference(b_alone -> 'b', both_keys -> 'b');
    ASSERT both_keys -> 'a' = a_alone -> 'a',
           'ip/' || history || ': expected key A beside key B to read what it reads alone, alone / beside at '
           || pg_temp.t_isolation_first_difference(a_alone -> 'a', both_keys -> 'a');
    ASSERT ARRAY(SELECT DISTINCT e ->> 'event_type' FROM jsonb_array_elements(b_alone #> '{b,-1,events}') AS e ORDER BY 1)
           = ARRAY['drop_listed', 'drop_unlisted', 'hosting_changed'],
           'ip/' || history || ': the script of key B writes each IP event type, found ' || (b_alone #> '{b,-1,events}')::text;
    ASSERT CASE WHEN history IN ('removed', 'cleared') THEN jsonb_array_length(a_alone #> '{a,0,values}') = 0
                ELSE jsonb_array_length(a_alone #> '{a,0,values}') = 2 END,
           'ip/' || history || ': the history gives key A its two values, or none after a remove or a clear, found ' || (a_alone #> '{a,0}')::text;
  END LOOP;
  ASSERT (SELECT count(DISTINCT st.name) FROM t_isolation_ip_step AS st WHERE st.phase = 'history') = 6, 'the IP probe runs six histories';
END
$$;

CREATE ROLE t_isolation_tenant NOLOGIN;
GRANT USAGE ON SCHEMA public, api TO t_isolation_tenant;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO t_isolation_tenant;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO t_isolation_tenant;
REVOKE SELECT ON public.domain_watch, public.domain_watch_lane, public.domain_watch_dns_bucket FROM t_isolation_tenant;
GRANT SELECT (domain_name) ON public.domain_watch TO t_isolation_tenant;
GRANT SELECT (domain_name, lane_name) ON public.domain_watch_lane TO t_isolation_tenant;
DO $$
DECLARE
  definer_function regprocedure;
BEGIN
  FOR definer_function IN
    SELECT p.oid::regprocedure FROM pg_proc AS p
     WHERE p.pronamespace IN ('api'::regnamespace, 'public'::regnamespace) AND p.prosecdef
  LOOP
    EXECUTE format('ALTER FUNCTION %s SECURITY INVOKER', definer_function);
  END LOOP;
END
$$;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA api, public TO t_isolation_tenant;

SET LOCAL ROLE t_isolation_tenant;
DO $$
DECLARE
  key_b       CONSTANT text := repeat('b2', 32);
  domain_name CONSTANT text := current_setting('t_isolation.domain_name');
BEGIN
  PERFORM count(*) FROM api.fn_watchlist_edit_dns_lookup(key_b, 'add', domain_name, domain_name, 100, 20);
  PERFORM count(*) FROM api.fn_watchlist_edit_ssl_check(key_b, 'add', domain_name, domain_name, 100, 20);
  PERFORM count(*) FROM api.fn_watchlist_edit_whois_lookup(key_b, 'add', domain_name, domain_name, 100, 20);
  PERFORM count(*) FROM api.fn_watchlist_edit_headers_check(key_b, 'add', domain_name, domain_name, 100, 20);
  PERFORM count(*) FROM api.fn_watchlist_edit_cert_search(key_b, 'add', domain_name, domain_name, 100, 20);
  ASSERT (SELECT array_agg(dwl.lane_name ORDER BY dwl.lane_name) FROM domain_watch_lane AS dwl WHERE dwl.domain_name = current_setting('t_isolation.domain_name'))
         = '{ct,dns,headers,rdap_whois,tls}',
         'the role guard writes the ct, the dns, the headers, the tls and the rdap_whois row as the role';
  PERFORM count(*) FROM api.fn_watchlist_edit_cve_lookup(key_b, 'add', 'CVE-2026-0420', 100);
  PERFORM count(*) FROM api.fn_watchlist_edit_cve_exploit(key_b, 'add', 'CVE-2026-0420', 100);
  PERFORM count(*) FROM api.fn_watchlist_edit_product_exposure(key_b, 'add', 'isolation_vendor', 'isolation_product', '2.0', 100);
  PERFORM count(*) FROM api.fn_watchlist_edit_cve_search(key_b, 'add', 'isolation_vendor', NULL, 'HIGH', NULL, 7.0, NULL, true, NULL, NULL, 100);
  PERFORM count(*) FROM api.fn_watchlist_edit_package_check(key_b, 'add', 'npm', 'isolation-package', NULL, 500, 100, 100000, 20);
  PERFORM count(*) FROM api.fn_watchlist_edit_ip_lookup(key_b, 'add', '192.0.2.78', 100);
  ASSERT (SELECT count(*) FROM api.fn_watchlist_list(key_b) AS x WHERE x.endpoint_name IS NOT NULL) = 11,
         'the role guard lists the eleven items of key B as the role';
  ASSERT (SELECT x.edit_status FROM api.fn_watchlist_edit_kev_lookup(key_b, 'add', 'CVE-2026-0420', 3) AS x LIMIT 1) = 'over_limit',
         'the role guard reaches over_limit as the role';
END
$$;
RESET ROLE;

DO $$
BEGIN
  PERFORM pg_temp.t_isolation_pass_time('1 hour');
  PERFORM pg_temp.t_isolation_record(l.endpoint_name, pg_temp.t_isolation_claim(l.endpoint_name),
                                     pg_temp.t_isolation_values(l.endpoint_name, NULL, 'problem_everywhere', true))
     FROM t_isolation_lane AS l;
  INSERT INTO cve_change_event (cve_id, event_type) VALUES ('CVE-2026-0420', 'kev_added');
END
$$;
SET LOCAL ROLE t_isolation_tenant;
DO $$
DECLARE
  key_b       CONSTANT text := repeat('b2', 32);
  domain_name CONSTANT text := current_setting('t_isolation.domain_name');
  event_count bigint;
BEGIN
  SELECT count(*) INTO event_count FROM api.fn_watchlist_events(key_b, NULL, false, 2, 1000, 600) AS x WHERE x.event_type IS NOT NULL;
  ASSERT event_count > 0, 'the role guard reads events of key B';
  PERFORM count(*) FROM api.fn_watchlist_events(key_b, NULL, true, 2, 1000, 600);
  PERFORM count(*) FROM api.fn_watchlist_events(key_b, 0, false, 2, 1000, 600);
  PERFORM count(*) FROM api.fn_watchlist_edit_dns_lookup(key_b, 'remove', domain_name, domain_name, 100, 20);
  PERFORM count(*) FROM api.fn_watchlist_edit_ssl_check(key_b, 'remove', domain_name, domain_name, 100, 20);
  PERFORM count(*) FROM api.fn_watchlist_edit_whois_lookup(key_b, 'remove', domain_name, domain_name, 100, 20);
  PERFORM count(*) FROM api.fn_watchlist_edit_headers_check(key_b, 'remove', domain_name, domain_name, 100, 20);
  PERFORM count(*) FROM api.fn_watchlist_edit_cert_search(key_b, 'remove', domain_name, domain_name, 100, 20);
  PERFORM count(*) FROM api.fn_watchlist_edit_cve_exploit(key_b, 'remove', 'CVE-2026-0420', 100);
  PERFORM count(*) FROM api.fn_watchlist_edit_product_exposure(key_b, 'remove', 'isolation_vendor', 'isolation_product', '2.0', 100);
  PERFORM count(*) FROM api.fn_watchlist_edit_cve_search(key_b, 'remove', 'isolation_vendor', NULL, 'HIGH', NULL, 7.0, NULL, true, NULL, NULL, 100);
  PERFORM count(*) FROM api.fn_watchlist_edit_package_check(key_b, 'remove', 'npm', 'isolation-package', NULL, 500, 100, 100000, 20);
  PERFORM count(*) FROM api.fn_watchlist_edit_ip_lookup(key_b, 'remove', '192.0.2.78', 100);
  PERFORM count(*) FROM api.fn_watchlist_edit_cve_lookup(key_b, 'remove', 'CVE-2026-0420', 100);
  ASSERT NOT EXISTS (SELECT 1 FROM watchlist_event_cursor AS wec JOIN api_keys AS ak ON ak.id = wec.api_key_id WHERE ak.key_hash = key_b),
         'the role guard removes the last item of key B as the role';
  PERFORM count(*) FROM api.fn_watchlist_clear(key_b);
END
$$;
RESET ROLE;

ROLLBACK TO SAVEPOINT t_watch_isolation;
RELEASE SAVEPOINT t_watch_isolation;
