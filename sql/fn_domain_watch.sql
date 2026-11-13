CREATE FUNCTION api.fn_domain_watch_dns_scan_cost() RETURNS real
  LANGUAGE sql IMMUTABLE SECURITY INVOKER
  SET search_path = pg_catalog
  RETURN 40;

CREATE FUNCTION api.fn_domain_watch_dns_bucket_burst() RETURNS real
  LANGUAGE sql IMMUTABLE SECURITY INVOKER
  SET search_path = pg_catalog
  RETURN 80;

CREATE FUNCTION api.fn_domain_watch_dns_bucket_charge(p_registered_domain text)
  RETURNS real
  LANGUAGE plpgsql VOLATILE SECURITY INVOKER
  SET search_path = pg_catalog
AS $$
DECLARE
  bucket_refill_rate        CONSTANT real := 0.5;
  bucket_question_allowance real;
BEGIN
  INSERT INTO public.domain_watch_dns_bucket AS dwdb (registered_domain, question_allowance, refilled_at)
  VALUES (p_registered_domain, api.fn_domain_watch_dns_bucket_burst(), now())
  ON CONFLICT (registered_domain) DO UPDATE
     SET question_allowance = least(api.fn_domain_watch_dns_bucket_burst(),
                                    dwdb.question_allowance + greatest(extract(epoch FROM now() - dwdb.refilled_at), 0) * bucket_refill_rate),
         refilled_at        = greatest(dwdb.refilled_at, now())
  RETURNING dwdb.question_allowance INTO bucket_question_allowance;

  IF bucket_question_allowance >= api.fn_domain_watch_dns_scan_cost() THEN
    UPDATE public.domain_watch_dns_bucket AS dwdb
       SET question_allowance = dwdb.question_allowance - api.fn_domain_watch_dns_scan_cost()
     WHERE dwdb.registered_domain = p_registered_domain;
    RETURN 0;
  END IF;
  RETURN (api.fn_domain_watch_dns_scan_cost() - bucket_question_allowance) / bucket_refill_rate;
END
$$;

CREATE FUNCTION api.fn_domain_watch_lanes()
  RETURNS TABLE (lane_name     text,
                 endpoint_name text)
  LANGUAGE sql IMMUTABLE SECURITY INVOKER
  SET search_path = pg_catalog
  BEGIN ATOMIC
    SELECT l.lane_name     AS lane_name,
           l.endpoint_name AS endpoint_name
      FROM (VALUES ('dns', 'dns_lookup'), ('tls', 'ssl_check'), ('rdap_whois', 'whois_lookup'), ('headers', 'headers_check'),
                   ('ct', 'cert_search'))
           AS l (lane_name, endpoint_name);
  END;

CREATE FUNCTION api.fn_domain_watch_claim(p_lane_name text, p_domain_row_count integer, p_lease_seconds integer)
  RETURNS TABLE (domain_name   text,
                 claimed_until timestamptz)
  LANGUAGE plpgsql VOLATILE STRICT SECURITY DEFINER
  SET search_path = pg_catalog
AS $$
DECLARE
  lane_endpoint_name       CONSTANT text    := (SELECT l.endpoint_name FROM api.fn_domain_watch_lanes() AS l WHERE l.lane_name = p_lane_name);
  picked_row               record;
  leased_row_count         integer := 0;
  has_question_bucket      CONSTANT boolean := p_lane_name = 'dns';
  max_refused_bucket_count CONSTANT integer := 64;
  bucket_wait_seconds      real;
  refused_bucket_count     integer := 0;
BEGIN
  IF p_lease_seconds < 1 THEN
    RETURN;
  END IF;
  WHILE leased_row_count < p_domain_row_count LOOP
    SELECT dwl.domain_name, dw.registered_domain INTO picked_row
      FROM (SELECT wid.domain_name, min(wid.next_scan_at) AS first_due_at
              FROM public.watchlist_item_domain AS wid
              JOIN public.api_keys AS ak ON ak.id = wid.api_key_id
             WHERE wid.endpoint_name = lane_endpoint_name AND wid.next_scan_at <= now()
               AND api.fn_api_key_is_active(ak.active, ak.expires_at)
             GROUP BY wid.domain_name) AS due_item
      JOIN public.domain_watch_lane AS dwl ON dwl.domain_name = due_item.domain_name AND dwl.lane_name = p_lane_name
      JOIN public.domain_watch AS dw ON dw.domain_name = dwl.domain_name
     WHERE (dwl.claimed_until IS NULL OR dwl.claimed_until < now())
       AND (dwl.not_before IS NULL OR dwl.not_before <= now())
     ORDER BY due_item.first_due_at, dwl.scanned_at NULLS FIRST, dwl.domain_name
     LIMIT 1
       FOR UPDATE OF dwl SKIP LOCKED;
    EXIT WHEN NOT FOUND;

    bucket_wait_seconds := CASE WHEN has_question_bucket THEN api.fn_domain_watch_dns_bucket_charge(picked_row.registered_domain) ELSE 0 END;
    IF bucket_wait_seconds = 0 THEN
      UPDATE public.domain_watch_lane AS dwl
         SET claimed_until = now() + p_lease_seconds * interval '1 second',
             claimed_at    = clock_timestamp()
       WHERE dwl.domain_name = picked_row.domain_name AND dwl.lane_name = p_lane_name
      RETURNING dwl.claimed_until INTO claimed_until;
      domain_name := picked_row.domain_name;
      RETURN NEXT;
      leased_row_count := leased_row_count + 1;
    ELSE
      EXIT WHEN refused_bucket_count >= max_refused_bucket_count;
      UPDATE public.domain_watch_lane AS dwl1
         SET not_before = now() + bucket_wait_seconds * interval '1 second'
       WHERE dwl1.lane_name = p_lane_name
         AND dwl1.domain_name IN (SELECT dwl2.domain_name
                                    FROM public.domain_watch AS dw
                                    JOIN public.domain_watch_lane AS dwl2 ON dwl2.domain_name = dw.domain_name AND dwl2.lane_name = p_lane_name
                                   WHERE dw.registered_domain = picked_row.registered_domain
                                     AND (dwl2.claimed_until IS NULL OR dwl2.claimed_until < now())
                                     AND (dwl2.not_before IS NULL OR dwl2.not_before <= now())
                                     AND EXISTS (SELECT 1 FROM public.watchlist_item_domain AS wid
                                                  JOIN public.api_keys AS ak ON ak.id = wid.api_key_id
                                                  WHERE wid.domain_name = dwl2.domain_name AND wid.endpoint_name = lane_endpoint_name
                                                    AND api.fn_api_key_is_active(ak.active, ak.expires_at)
                                                    AND wid.next_scan_at <= now())
                                     FOR UPDATE OF dwl2 SKIP LOCKED);
      refused_bucket_count := refused_bucket_count + 1;
    END IF;
  END LOOP;
END
$$;

CREATE FUNCTION api.fn_domain_watch_expiry_bucket_rank(p_value text)
  RETURNS integer
  LANGUAGE sql IMMUTABLE SECURITY INVOKER
  SET search_path = pg_catalog
  RETURN CASE split_part(p_value, E'\n', 1) WHEN 'none' THEN 0
                                            WHEN '30'   THEN 1
                                            WHEN '7'    THEN 2
                                            WHEN '1'    THEN 3
         END;

CREATE FUNCTION api.fn_domain_change_event_type(p_value_kind text, p_current_value text, p_candidate_value text)
  RETURNS text
  LANGUAGE sql IMMUTABLE SECURITY INVOKER
  SET search_path = pg_catalog
  RETURN CASE
           WHEN p_value_kind = 'dns_presence'            AND p_candidate_value = 'not_found'  THEN 'domain_not_found'
           WHEN p_value_kind = 'dns_presence'            AND p_candidate_value = 'found'      THEN 'domain_found'
           WHEN p_value_kind = 'ns'                                                           THEN 'ns_changed'
           WHEN p_value_kind = 'mx'                                                           THEN 'mx_changed'
           WHEN p_value_kind = 'hosting'                                                      THEN 'hosting_changed'
           WHEN p_value_kind = 'ip_address_reachability' AND p_candidate_value = 'not_public' THEN 'ip_address_not_public'
           WHEN p_value_kind = 'ip_address_reachability' AND p_candidate_value = 'empty'      THEN 'ip_address_lost'
           WHEN p_value_kind = 'ip_address_reachability' AND p_candidate_value = 'public'     THEN 'ip_address_restored'
           WHEN p_value_kind = 'cname_takeover'          AND p_current_value = 'none' AND p_candidate_value LIKE 'vulnerable%'
             THEN 'cname_takeover_detected'
           WHEN p_value_kind = 'cname_takeover'          AND p_current_value LIKE 'vulnerable%' AND p_candidate_value = 'none'
             THEN 'cname_takeover_resolved'
           WHEN p_value_kind = 'certificate_expiry'
                AND api.fn_domain_watch_expiry_bucket_rank(p_candidate_value) > api.fn_domain_watch_expiry_bucket_rank(p_current_value)
             THEN 'cert_expiring'
           WHEN p_value_kind = 'registration_expiry'
                AND api.fn_domain_watch_expiry_bucket_rank(p_candidate_value) > api.fn_domain_watch_expiry_bucket_rank(p_current_value)
             THEN 'domain_expiring'
           WHEN p_value_kind = 'registrar'               AND split_part(p_current_value, E'\n', 1) ~ '^[0-9]+$'
                                                         AND split_part(p_candidate_value, E'\n', 1) ~ '^[0-9]+$'
             THEN CASE WHEN split_part(p_current_value, E'\n', 1) <> split_part(p_candidate_value, E'\n', 1) THEN 'registrar_changed' END
           WHEN p_value_kind = 'registrar'               AND split_part(p_current_value, E'\n', 2) <> split_part(p_candidate_value, E'\n', 2)
             THEN 'registrar_changed'
           WHEN p_value_kind = 'transfer_lock'           AND NOT (string_to_array(p_current_value, E'\n') <@ string_to_array(p_candidate_value, E'\n'))
             THEN 'transfer_lock_removed'
           WHEN p_value_kind = 'dnssec_delegation'       AND p_current_value = 'signed' AND p_candidate_value = 'unsigned'
             THEN 'dnssec_disabled'
           WHEN p_value_kind = 'certificate_validity'    AND p_current_value = 'valid' AND p_candidate_value <> 'valid'
             THEN 'cert_invalid'
           WHEN p_value_kind = 'certificate_listing'     AND p_current_value = 'not_listed' AND p_candidate_value LIKE 'listed%'
             THEN 'cert_listed'
           WHEN p_value_kind = 'tls_protocol'            AND p_current_value IN ('TLSv1.2', 'TLSv1.3')
                                                         AND p_candidate_value IN ('TLSv1', 'TLSv1.1')
             THEN 'tls_downgraded'
           WHEN p_value_kind = 'security_headers'        AND split_part(p_current_value, E'\n', 1) = split_part(p_candidate_value, E'\n', 1)
                                                         AND NOT (string_to_array(p_current_value, E'\n') <@ string_to_array(p_candidate_value, E'\n'))
             THEN 'security_header_removed'
         END;

CREATE FUNCTION api.fn_domain_problem_event_type(p_value_kind text, p_value text)
  RETURNS text
  LANGUAGE sql IMMUTABLE SECURITY INVOKER
  SET search_path = pg_catalog
  RETURN CASE
           WHEN p_value_kind = 'dns_presence'            AND p_value = 'not_found'                                THEN 'domain_not_found'
           WHEN p_value_kind = 'ip_address_reachability' AND p_value = 'not_public'                               THEN 'ip_address_not_public'
           WHEN p_value_kind = 'cname_takeover'          AND p_value LIKE 'vulnerable%'                           THEN 'cname_takeover_detected'
           WHEN p_value_kind = 'certificate_expiry'      AND api.fn_domain_watch_expiry_bucket_rank(p_value) >= 1 THEN 'cert_expiring'
           WHEN p_value_kind = 'registration_expiry'     AND api.fn_domain_watch_expiry_bucket_rank(p_value) >= 1 THEN 'domain_expiring'
           WHEN p_value_kind = 'certificate_validity'    AND p_value <> 'valid'                                   THEN 'cert_invalid'
           WHEN p_value_kind = 'certificate_listing'     AND p_value LIKE 'listed%'                               THEN 'cert_listed'
           WHEN p_value_kind = 'tls_protocol'            AND p_value IN ('TLSv1', 'TLSv1.1')                      THEN 'tls_downgraded'
         END;

CREATE FUNCTION api.fn_domain_watch_next_daily_scan_at(p_domain_name text)
  RETURNS timestamptz
  LANGUAGE sql STABLE SECURITY INVOKER
  SET search_path = pg_catalog
  BEGIN ATOMIC
    SELECT CASE WHEN today.scan_at > now() THEN today.scan_at ELSE today.scan_at + interval '1 day' END
      FROM (SELECT (date_trunc('day', now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC')
                   + abs(hashtextextended(p_domain_name, 0) % extract(epoch FROM interval '1 day')::bigint) * interval '1 second'
                   AS scan_at) AS today;
  END;

CREATE FUNCTION api.fn_domain_watch_next_weekly_scan_at(p_domain_name text)
  RETURNS timestamptz
  LANGUAGE sql STABLE SECURITY INVOKER
  SET search_path = pg_catalog
  BEGIN ATOMIC
    SELECT CASE WHEN this_week.scan_at > now() THEN this_week.scan_at ELSE this_week.scan_at + interval '7 days' END
      FROM (SELECT (date_trunc('week', now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC')
                   + abs(hashtextextended(p_domain_name, 0) % extract(epoch FROM interval '7 days')::bigint) * interval '1 second'
                   AS scan_at) AS this_week;
  END;

CREATE FUNCTION api.fn_domain_watch_registration_expires_at(p_value text)
  RETURNS timestamptz
  LANGUAGE sql STABLE SECURITY INVOKER
  SET search_path = pg_catalog
  BEGIN ATOMIC
    SELECT CASE WHEN expiry.line ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}$' AND pg_input_is_valid(expiry.line || 'T00:00:00Z', 'timestamptz')
                  THEN (expiry.line || 'T00:00:00Z')::timestamptz
                WHEN expiry.line ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt][0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?([Zz]|[+-][0-9]{2}:[0-9]{2})$'
                     AND pg_input_is_valid(expiry.line, 'timestamptz')
                  THEN expiry.line::timestamptz
           END
      FROM (SELECT split_part(p_value, E'\n', 2)) AS expiry (line);
  END;

CREATE FUNCTION api.fn_domain_watch_next_scan_at(p_domain_name                 text,
                                                 p_needs_hourly_rescan         boolean,
                                                 p_is_weekly                   boolean,
                                                 p_registration_expiry_value   text)
  RETURNS timestamptz
  LANGUAGE sql STABLE SECURITY INVOKER
  SET search_path = pg_catalog
  BEGIN ATOMIC
    SELECT CASE WHEN p_needs_hourly_rescan                                            THEN now() + interval '1 hour'
                WHEN p_is_weekly IS NOT TRUE                                          THEN next_day.scan_at
                WHEN registration.expires_at IS NULL                                  THEN next_week.scan_at
                WHEN registration.expires_at - interval '30 days' <= next_day.scan_at THEN next_day.scan_at
                ELSE least(next_week.scan_at,
                           next_day.scan_at
                           + ceil(extract(epoch FROM registration.expires_at - interval '30 days' - next_day.scan_at) / 86400) * interval '1 day')
           END
      FROM (SELECT api.fn_domain_watch_next_daily_scan_at(p_domain_name)) AS next_day (scan_at)
     CROSS JOIN (SELECT api.fn_domain_watch_next_weekly_scan_at(p_domain_name)) AS next_week (scan_at)
     CROSS JOIN (SELECT api.fn_domain_watch_registration_expires_at(p_registration_expiry_value)) AS registration (expires_at);
  END;

CREATE FUNCTION api.fn_domain_watch_cert_issuers_union(p_current_value text, p_scan_value text)
  RETURNS text
  LANGUAGE sql IMMUTABLE SECURITY INVOKER
  SET search_path = pg_catalog
  RETURN (SELECT coalesce(string_agg(issuer.issuer_key, E'\n' ORDER BY issuer.issuer_key COLLATE "C"), '')
            FROM (SELECT current_line AS issuer_key
                    FROM unnest(string_to_array(p_current_value, E'\n')) AS current_line
                  UNION
                  SELECT substr(scan_line, strpos(scan_line, ' ') + 1) AS issuer_key
                    FROM unnest(string_to_array(p_scan_value, E'\n')) AS scan_line) AS issuer);

CREATE FUNCTION api.fn_domain_watch_cert_unexpected_value(p_current_value text, p_scan_value text)
  RETURNS text
  LANGUAGE sql IMMUTABLE SECURITY INVOKER
  SET search_path = pg_catalog
  RETURN (SELECT CASE WHEN bool_or(stored.issuer_key IS NULL)
                      THEN string_agg(coalesce(stored.mark, scanned.reason) || ' ' || coalesce(stored.issuer_key, scanned.issuer_key), E'\n'
                                      ORDER BY coalesce(stored.issuer_key, scanned.issuer_key) COLLATE "C")
                 END
            FROM (SELECT current_line AS issuer_key, 'known' AS mark
                    FROM unnest(string_to_array(p_current_value, E'\n')) AS current_line) AS stored
            FULL JOIN (SELECT substr(scan_line, strpos(scan_line, ' ') + 1) AS issuer_key, split_part(scan_line, ' ', 1) AS reason
                         FROM unnest(string_to_array(p_scan_value, E'\n')) AS scan_line) AS scanned
                   ON scanned.issuer_key = stored.issuer_key);

CREATE FUNCTION api.fn_domain_watch_write_scan_values(p_domain_name     text,
                                                      p_endpoint_name   text,
                                                      p_claimed_at      timestamptz,
                                                      p_scan_values     text[],
                                                      p_scan_sha256s    text[],
                                                      p_email_check_ids text)
  RETURNS integer
  LANGUAGE plpgsql VOLATILE SECURITY INVOKER
  SET search_path = pg_catalog
AS $$
DECLARE
  candidate_confirm_wait     CONSTANT interval := interval '1 hour';
  value_kinds                CONSTANT text[]   := api.fn_watchlist_endpoint_value_kinds(p_endpoint_name);
  is_weekly_lane             CONSTANT boolean  := p_endpoint_name = 'whois_lookup';
  email_check_ids            CONSTANT text[]   := string_to_array(p_email_check_ids, ',');
  served_item_ids            bigint[];
  served_api_key_ids         integer[];
  served_item_id             bigint;
  kind_name                  text;
  scan_value                 text;
  scan_sha256                text;
  stored                     public.watchlist_item_domain_value%ROWTYPE;
  issuer_union               text;
  unexpected_value           text;
  confirmed_event_type       text;
  problem_event_type         text;
  degraded_email_check_id    text;
  needs_hourly_rescan        boolean;
  is_candidate_dropped       boolean;
  transition_kind_indexes    integer[] := '{}';
  transition_item_ids        bigint[]  := '{}';
  transition_api_key_ids     integer[] := '{}';
  transition_event_types     text[]    := '{}';
  transition_check_ids       text[]    := '{}';
  transition_previous_values text[]    := '{}';
  transition_current_values  text[]    := '{}';
  written_event_count        integer   := 0;
BEGIN
  SELECT coalesce(array_agg(taken.item_id ORDER BY taken.item_id), '{}'), coalesce(array_agg(taken.api_key_id ORDER BY taken.item_id), '{}')
    INTO served_item_ids, served_api_key_ids
    FROM (SELECT wid.item_id, wid.api_key_id
            FROM public.watchlist_item_domain AS wid
            JOIN public.watchlist_item AS wi ON wi.item_id = wid.item_id
           WHERE wid.domain_name = p_domain_name
             AND wid.endpoint_name = p_endpoint_name
             AND wid.next_scan_at <= p_claimed_at
             FOR NO KEY UPDATE OF wid, wi SKIP LOCKED) AS taken;

  FOR served_index IN 1 .. cardinality(served_item_ids) LOOP
    served_item_id       := served_item_ids[served_index];
    needs_hourly_rescan  := false;
    is_candidate_dropped := false;

    FOR kind_index IN 1 .. cardinality(value_kinds) LOOP
      kind_name   := value_kinds[kind_index];
      scan_value  := p_scan_values[kind_index];
      scan_sha256 := p_scan_sha256s[kind_index];
      CONTINUE WHEN scan_value IS NULL;

      SELECT * INTO stored FROM public.watchlist_item_domain_value AS widv
       WHERE widv.item_id = served_item_id AND widv.value_kind = kind_name;

      IF kind_name = 'cert_issuers' THEN
        issuer_union := api.fn_domain_watch_cert_issuers_union(stored.current_value, scan_value);
        IF NOT FOUND THEN
          INSERT INTO public.watchlist_item_domain_value (item_id, value_kind, current_value, current_value_sha256)
          VALUES (served_item_id, kind_name, issuer_union, encode(sha256(convert_to(issuer_union, 'UTF8')), 'hex'));
        ELSE
          unexpected_value := api.fn_domain_watch_cert_unexpected_value(stored.current_value, scan_value);
          IF octet_length(unexpected_value) <= 2048 THEN
            UPDATE public.watchlist_item_domain_value AS widv
               SET current_value = issuer_union, current_value_sha256 = encode(sha256(convert_to(issuer_union, 'UTF8')), 'hex')
             WHERE widv.item_id = served_item_id AND widv.value_kind = kind_name;
            transition_kind_indexes    := transition_kind_indexes || kind_index;
            transition_item_ids        := transition_item_ids || served_item_id;
            transition_api_key_ids     := transition_api_key_ids || served_api_key_ids[served_index];
            transition_event_types     := transition_event_types || 'cert_unexpected'::text;
            transition_check_ids       := transition_check_ids || NULL::text;
            transition_previous_values := transition_previous_values || stored.current_value;
            transition_current_values  := transition_current_values || unexpected_value;
          END IF;
        END IF;
        CONTINUE;
      END IF;

      IF NOT FOUND THEN
        INSERT INTO public.watchlist_item_domain_value (item_id, value_kind, current_value, current_value_sha256)
        VALUES (served_item_id, kind_name, scan_value, scan_sha256);
        problem_event_type := api.fn_domain_problem_event_type(kind_name, scan_value);
        IF problem_event_type IS NOT NULL THEN
          transition_kind_indexes    := transition_kind_indexes || kind_index;
          transition_item_ids        := transition_item_ids || served_item_id;
          transition_api_key_ids     := transition_api_key_ids || served_api_key_ids[served_index];
          transition_event_types     := transition_event_types || problem_event_type;
          transition_check_ids       := transition_check_ids || NULL::text;
          transition_previous_values := transition_previous_values || NULL::text;
          transition_current_values  := transition_current_values || scan_value;
        END IF;
      ELSIF scan_sha256 = stored.current_value_sha256 THEN
        is_candidate_dropped := is_candidate_dropped OR stored.candidate_value_sha256 IS NOT NULL;
        UPDATE public.watchlist_item_domain_value AS widv
           SET candidate_value = NULL, candidate_value_sha256 = NULL, candidate_seen_at = NULL
         WHERE widv.item_id = served_item_id AND widv.value_kind = kind_name;
      ELSIF scan_sha256 = stored.candidate_value_sha256 AND now() - stored.candidate_seen_at >= candidate_confirm_wait THEN
        UPDATE public.watchlist_item_domain_value AS widv
           SET current_value = stored.candidate_value, current_value_sha256 = stored.candidate_value_sha256, candidate_value = NULL,
               candidate_value_sha256 = NULL, candidate_seen_at = NULL
         WHERE widv.item_id = served_item_id AND widv.value_kind = kind_name;

        IF kind_name = 'email_auth' THEN
          FOR degraded_email_check_id IN
            SELECT ids.check_id
              FROM unnest(email_check_ids) WITH ORDINALITY AS ids (check_id, letter_index)
             WHERE char_length(stored.current_value) = cardinality(email_check_ids)
               AND char_length(stored.candidate_value) = cardinality(email_check_ids)
               AND substr(stored.current_value, ids.letter_index::integer, 1) || substr(stored.candidate_value, ids.letter_index::integer, 1)
                   IN ('pw', 'pf', 'wf')
             ORDER BY ids.letter_index
          LOOP
            transition_kind_indexes    := transition_kind_indexes || kind_index;
            transition_item_ids        := transition_item_ids || served_item_id;
            transition_api_key_ids     := transition_api_key_ids || served_api_key_ids[served_index];
            transition_event_types     := transition_event_types || 'email_auth_degraded'::text;
            transition_check_ids       := transition_check_ids || degraded_email_check_id;
            transition_previous_values := transition_previous_values || stored.current_value;
            transition_current_values  := transition_current_values || stored.candidate_value;
          END LOOP;
        ELSE
          confirmed_event_type := api.fn_domain_change_event_type(kind_name, stored.current_value, stored.candidate_value);
          IF confirmed_event_type IS NOT NULL THEN
            transition_kind_indexes    := transition_kind_indexes || kind_index;
            transition_item_ids        := transition_item_ids || served_item_id;
            transition_api_key_ids     := transition_api_key_ids || served_api_key_ids[served_index];
            transition_event_types     := transition_event_types || confirmed_event_type;
            transition_check_ids       := transition_check_ids || NULL::text;
            transition_previous_values := transition_previous_values || stored.current_value;
            transition_current_values  := transition_current_values || stored.candidate_value;
          END IF;
        END IF;
      ELSIF scan_sha256 = stored.candidate_value_sha256 THEN
        needs_hourly_rescan := true;
      ELSE
        IF stored.candidate_value_sha256 IS NULL THEN
          needs_hourly_rescan := true;
        ELSE
          is_candidate_dropped := true;
        END IF;
        UPDATE public.watchlist_item_domain_value AS widv
           SET candidate_value = scan_value, candidate_value_sha256 = scan_sha256, candidate_seen_at = now()
         WHERE widv.item_id = served_item_id AND widv.value_kind = kind_name;
      END IF;
    END LOOP;

    UPDATE public.watchlist_item_domain AS wid
       SET next_scan_at = api.fn_domain_watch_next_scan_at(p_domain_name, needs_hourly_rescan AND NOT is_candidate_dropped, is_weekly_lane,
                                                           (SELECT widv.current_value FROM public.watchlist_item_domain_value AS widv
                                                             WHERE widv.item_id = served_item_id AND widv.value_kind = 'registration_expiry'))
     WHERE wid.item_id = served_item_id;
  END LOOP;

  IF cardinality(transition_item_ids) > 0 THEN
    PERFORM public.fn_watchlist_event_take_order_lock();
    WITH transition AS (
      SELECT t.kind_index, t.item_id, t.api_key_id, t.event_type, t.degraded_email_check_id, t.previous_value, t.current_value, t.transition_number
        FROM unnest(transition_kind_indexes, transition_item_ids, transition_api_key_ids, transition_event_types, transition_check_ids,
                    transition_previous_values, transition_current_values)
             WITH ORDINALITY AS t (kind_index, item_id, api_key_id, event_type, degraded_email_check_id, previous_value, current_value,
                                   transition_number)),
    shared_event AS (
      SELECT tr.event_type, tr.degraded_email_check_id, tr.previous_value, tr.current_value, min(tr.kind_index) AS first_kind_index,
             min(tr.item_id) AS first_item_id, min(tr.transition_number) AS first_transition_number
        FROM transition AS tr
       GROUP BY tr.event_type, tr.degraded_email_check_id, tr.previous_value, tr.current_value),
    inserted AS (
      INSERT INTO public.domain_change_event AS dce (domain_name, event_type, degraded_email_check_id, previous_value, current_value)
      SELECT p_domain_name, se.event_type, se.degraded_email_check_id, se.previous_value, se.current_value
        FROM shared_event AS se
       ORDER BY se.first_kind_index, se.first_item_id, se.first_transition_number
      RETURNING dce.event_id, dce.event_type, dce.degraded_email_check_id, dce.previous_value, dce.current_value),
    refs AS (
      INSERT INTO public.watchlist_event_ref (api_key_id, item_id, event_id)
      SELECT tr.api_key_id, tr.item_id, ins.event_id
        FROM transition AS tr
        JOIN inserted AS ins ON ins.event_type = tr.event_type
                            AND ins.degraded_email_check_id IS NOT DISTINCT FROM tr.degraded_email_check_id
                            AND ins.previous_value IS NOT DISTINCT FROM tr.previous_value
                            AND ins.current_value = tr.current_value)
    SELECT count(*)::integer INTO written_event_count FROM inserted;
  END IF;

  RETURN written_event_count;
END
$$;

CREATE FUNCTION api.fn_domain_watch_record_dns(p_domain_name                    text,
                                               p_claimed_until                  timestamptz,
                                               p_dns_presence_value             text,
                                               p_dns_presence_sha256            text,
                                               p_ns_value                       text,
                                               p_ns_sha256                      text,
                                               p_mx_value                       text,
                                               p_mx_sha256                      text,
                                               p_ip_address_reachability_value  text,
                                               p_ip_address_reachability_sha256 text,
                                               p_cname_takeover_value           text,
                                               p_cname_takeover_sha256          text,
                                               p_email_auth_value               text,
                                               p_email_auth_sha256              text,
                                               p_email_check_ids                text,
                                               p_hosting_ip_addresses           text,
                                               p_question_count                 integer)
  RETURNS integer
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER
  SET search_path = pg_catalog
AS $$
DECLARE
  lane_endpoint_name     CONSTANT text     := (SELECT l.endpoint_name FROM api.fn_domain_watch_lanes() AS l WHERE l.lane_name = 'dns');
  value_kinds            CONSTANT text[]   := api.fn_watchlist_endpoint_value_kinds(lane_endpoint_name);
  scan_values            text[]   := ARRAY[p_dns_presence_value, p_ns_value, p_mx_value, p_ip_address_reachability_value, p_cname_takeover_value, p_email_auth_value];
  scan_sha256s           text[]   := ARRAY[p_dns_presence_sha256, p_ns_sha256, p_mx_sha256, p_ip_address_reachability_sha256, p_cname_takeover_sha256, p_email_auth_sha256];
  hosting_value          text;
  registered_domain_name text;
  watched_lane           public.domain_watch_lane%ROWTYPE;
  written_event_count    integer;
BEGIN
  FOR kind_index IN 1 .. cardinality(scan_values) LOOP
    IF (scan_values[kind_index] IS NULL) <> (scan_sha256s[kind_index] IS NULL) THEN
      RAISE EXCEPTION 'fn_domain_watch_record_dns refuses % of %: a value and its SHA-256 come together', value_kinds[kind_index], p_domain_name
        USING ERRCODE = 'invalid_parameter_value';
    END IF;
  END LOOP;
  IF p_question_count IS NULL OR p_question_count < 0 THEN
    RAISE EXCEPTION 'fn_domain_watch_record_dns refuses the question count % of %: it must be 0 or more', p_question_count, p_domain_name
      USING ERRCODE = 'invalid_parameter_value';
  END IF;

  SELECT dw.registered_domain INTO registered_domain_name FROM public.domain_watch AS dw WHERE dw.domain_name = p_domain_name FOR KEY SHARE;
  SELECT * INTO watched_lane FROM public.domain_watch_lane AS dwl
   WHERE dwl.domain_name = p_domain_name AND dwl.lane_name = 'dns'
     FOR UPDATE;
  IF NOT FOUND THEN
    RETURN 0;
  END IF;

  UPDATE public.domain_watch_dns_bucket AS dwdb
     SET question_allowance = least(api.fn_domain_watch_dns_bucket_burst(),
                                    dwdb.question_allowance + (api.fn_domain_watch_dns_scan_cost() - p_question_count))
   WHERE dwdb.registered_domain = registered_domain_name;

  IF watched_lane.claimed_until IS NULL OR watched_lane.claimed_until IS DISTINCT FROM p_claimed_until THEN
    RETURN 0;
  END IF;

  hosting_value := api.fn_ip_hosting_classes(string_to_array(p_hosting_ip_addresses, ',')::inet[]);
  scan_values   := scan_values || hosting_value;
  scan_sha256s  := scan_sha256s || encode(sha256(convert_to(hosting_value, 'UTF8')), 'hex');
  written_event_count := api.fn_domain_watch_write_scan_values(p_domain_name, lane_endpoint_name, watched_lane.claimed_at, scan_values,
                                                               scan_sha256s, p_email_check_ids);

  UPDATE public.domain_watch_lane AS dwl
     SET claimed_until = NULL,
         scanned_at    = now()
   WHERE dwl.domain_name = p_domain_name AND dwl.lane_name = 'dns';

  RETURN written_event_count;
END
$$;

CREATE FUNCTION api.fn_domain_watch_record_tls(p_domain_name                 text,
                                               p_claimed_until               timestamptz,
                                               p_certificate_expiry_value    text,
                                               p_certificate_expiry_sha256   text,
                                               p_certificate_validity_value  text,
                                               p_certificate_validity_sha256 text,
                                               p_certificate_listing_value   text,
                                               p_certificate_listing_sha256  text,
                                               p_tls_protocol_value          text,
                                               p_tls_protocol_sha256         text)
  RETURNS integer
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER
  SET search_path = pg_catalog
AS $$
DECLARE
  lane_endpoint_name     CONSTANT text     := (SELECT l.endpoint_name FROM api.fn_domain_watch_lanes() AS l WHERE l.lane_name = 'tls');
  value_kinds            CONSTANT text[]   := api.fn_watchlist_endpoint_value_kinds(lane_endpoint_name);
  scan_values            text[]   := ARRAY[p_certificate_expiry_value, p_certificate_validity_value, p_certificate_listing_value, p_tls_protocol_value];
  scan_sha256s           text[]   := ARRAY[p_certificate_expiry_sha256, p_certificate_validity_sha256, p_certificate_listing_sha256, p_tls_protocol_sha256];
  watched_lane           public.domain_watch_lane%ROWTYPE;
  written_event_count    integer;
BEGIN
  FOR kind_index IN 1 .. cardinality(scan_values) LOOP
    IF (scan_values[kind_index] IS NULL) <> (scan_sha256s[kind_index] IS NULL) THEN
      RAISE EXCEPTION 'fn_domain_watch_record_tls refuses % of %: a value and its SHA-256 come together', value_kinds[kind_index], p_domain_name
        USING ERRCODE = 'invalid_parameter_value';
    END IF;
  END LOOP;

  PERFORM 1 FROM public.domain_watch AS dw WHERE dw.domain_name = p_domain_name FOR KEY SHARE;
  SELECT * INTO watched_lane FROM public.domain_watch_lane AS dwl
   WHERE dwl.domain_name = p_domain_name AND dwl.lane_name = 'tls'
     FOR UPDATE;
  IF NOT FOUND THEN
    RETURN 0;
  END IF;

  IF watched_lane.claimed_until IS NULL OR watched_lane.claimed_until IS DISTINCT FROM p_claimed_until THEN
    RETURN 0;
  END IF;

  written_event_count := api.fn_domain_watch_write_scan_values(p_domain_name, lane_endpoint_name, watched_lane.claimed_at, scan_values,
                                                               scan_sha256s, NULL);

  UPDATE public.domain_watch_lane AS dwl
     SET claimed_until = NULL,
         scanned_at    = now()
   WHERE dwl.domain_name = p_domain_name AND dwl.lane_name = 'tls';

  RETURN written_event_count;
END
$$;

CREATE FUNCTION api.fn_domain_watch_record_rdap_whois(p_domain_name                text,
                                                      p_claimed_until              timestamptz,
                                                      p_registration_expiry_value  text,
                                                      p_registration_expiry_sha256 text,
                                                      p_registrar_value            text,
                                                      p_registrar_sha256           text,
                                                      p_transfer_lock_value        text,
                                                      p_transfer_lock_sha256       text,
                                                      p_dnssec_delegation_value    text,
                                                      p_dnssec_delegation_sha256   text,
                                                      p_retry_after_seconds        integer)
  RETURNS integer
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER
  SET search_path = pg_catalog
AS $$
DECLARE
  lane_endpoint_name     CONSTANT text     := (SELECT l.endpoint_name FROM api.fn_domain_watch_lanes() AS l WHERE l.lane_name = 'rdap_whois');
  value_kinds            CONSTANT text[]   := api.fn_watchlist_endpoint_value_kinds(lane_endpoint_name);
  scan_values            text[]   := ARRAY[p_registration_expiry_value, p_registrar_value, p_transfer_lock_value, p_dnssec_delegation_value];
  scan_sha256s           text[]   := ARRAY[p_registration_expiry_sha256, p_registrar_sha256, p_transfer_lock_sha256, p_dnssec_delegation_sha256];
  watched_lane           public.domain_watch_lane%ROWTYPE;
  written_event_count    integer;
BEGIN
  FOR kind_index IN 1 .. cardinality(scan_values) LOOP
    IF (scan_values[kind_index] IS NULL) <> (scan_sha256s[kind_index] IS NULL) THEN
      RAISE EXCEPTION 'fn_domain_watch_record_rdap_whois refuses % of %: a value and its SHA-256 come together', value_kinds[kind_index], p_domain_name
        USING ERRCODE = 'invalid_parameter_value';
    END IF;
  END LOOP;
  IF p_retry_after_seconds IS NOT NULL AND p_retry_after_seconds NOT BETWEEN 1 AND 3600 THEN
    RAISE EXCEPTION 'fn_domain_watch_record_rdap_whois refuses a retry of % seconds of %: a deferred scan waits 1 to 3600 seconds',
                    p_retry_after_seconds, p_domain_name
      USING ERRCODE = 'invalid_parameter_value';
  END IF;
  IF p_retry_after_seconds IS NOT NULL AND num_nonnulls(VARIADIC scan_values) > 0 THEN
    RAISE EXCEPTION 'fn_domain_watch_record_rdap_whois refuses the values of %: a deferred scan sends none', p_domain_name
      USING ERRCODE = 'invalid_parameter_value';
  END IF;

  PERFORM 1 FROM public.domain_watch AS dw WHERE dw.domain_name = p_domain_name FOR KEY SHARE;
  SELECT * INTO watched_lane FROM public.domain_watch_lane AS dwl
   WHERE dwl.domain_name = p_domain_name AND dwl.lane_name = 'rdap_whois'
     FOR UPDATE;
  IF NOT FOUND THEN
    RETURN 0;
  END IF;

  IF watched_lane.claimed_until IS NULL OR watched_lane.claimed_until IS DISTINCT FROM p_claimed_until THEN
    RETURN 0;
  END IF;

  IF p_retry_after_seconds IS NOT NULL THEN
    UPDATE public.domain_watch_lane AS dwl
       SET claimed_until = NULL,
           not_before    = now() + p_retry_after_seconds * interval '1 second'
     WHERE dwl.domain_name = p_domain_name AND dwl.lane_name = 'rdap_whois';
    RETURN 0;
  END IF;

  written_event_count := api.fn_domain_watch_write_scan_values(p_domain_name, lane_endpoint_name, watched_lane.claimed_at, scan_values,
                                                               scan_sha256s, NULL);

  UPDATE public.domain_watch_lane AS dwl
     SET claimed_until = NULL,
         scanned_at    = now()
   WHERE dwl.domain_name = p_domain_name AND dwl.lane_name = 'rdap_whois';

  RETURN written_event_count;
END
$$;

CREATE FUNCTION api.fn_domain_watch_record_headers(p_domain_name               text,
                                                   p_claimed_until             timestamptz,
                                                   p_security_headers_value    text,
                                                   p_security_headers_sha256   text,
                                                   p_retry_after_seconds       integer)
  RETURNS integer
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER
  SET search_path = pg_catalog
AS $$
DECLARE
  lane_endpoint_name     CONSTANT text      := (SELECT l.endpoint_name FROM api.fn_domain_watch_lanes() AS l WHERE l.lane_name = 'headers');
  value_kinds            CONSTANT text[]    := api.fn_watchlist_endpoint_value_kinds(lane_endpoint_name);
  scan_values            text[]             := ARRAY[p_security_headers_value];
  scan_sha256s           text[]             := ARRAY[p_security_headers_sha256];
  watched_lane           public.domain_watch_lane%ROWTYPE;
  written_event_count    integer;
BEGIN
  IF (p_security_headers_value IS NULL) <> (p_security_headers_sha256 IS NULL) THEN
    RAISE EXCEPTION 'fn_domain_watch_record_headers refuses % of %: a value and its SHA-256 come together', value_kinds[1], p_domain_name
      USING ERRCODE = 'invalid_parameter_value';
  END IF;
  IF octet_length(p_security_headers_value) > 2048 THEN
    RAISE EXCEPTION 'fn_domain_watch_record_headers refuses % of %: a value holds at most 2048 bytes', value_kinds[1], p_domain_name
      USING ERRCODE = 'invalid_parameter_value';
  END IF;
  IF p_retry_after_seconds IS NOT NULL AND p_retry_after_seconds NOT BETWEEN 1 AND 3600 THEN
    RAISE EXCEPTION 'fn_domain_watch_record_headers refuses a retry of % seconds of %: a deferred scan waits 1 to 3600 seconds',
                    p_retry_after_seconds, p_domain_name
      USING ERRCODE = 'invalid_parameter_value';
  END IF;
  IF p_retry_after_seconds IS NOT NULL AND p_security_headers_value IS NOT NULL THEN
    RAISE EXCEPTION 'fn_domain_watch_record_headers refuses the value of %: a deferred scan sends none', p_domain_name
      USING ERRCODE = 'invalid_parameter_value';
  END IF;

  PERFORM 1 FROM public.domain_watch AS dw WHERE dw.domain_name = p_domain_name FOR KEY SHARE;
  SELECT * INTO watched_lane FROM public.domain_watch_lane AS dwl
   WHERE dwl.domain_name = p_domain_name AND dwl.lane_name = 'headers'
     FOR UPDATE;
  IF NOT FOUND THEN
    RETURN 0;
  END IF;

  IF watched_lane.claimed_until IS NULL OR watched_lane.claimed_until IS DISTINCT FROM p_claimed_until THEN
    RETURN 0;
  END IF;

  IF p_retry_after_seconds IS NOT NULL THEN
    UPDATE public.domain_watch_lane AS dwl
       SET claimed_until = NULL,
           not_before    = now() + p_retry_after_seconds * interval '1 second'
     WHERE dwl.domain_name = p_domain_name AND dwl.lane_name = 'headers';
    RETURN 0;
  END IF;

  written_event_count := api.fn_domain_watch_write_scan_values(p_domain_name, lane_endpoint_name, watched_lane.claimed_at, scan_values,
                                                               scan_sha256s, NULL);

  UPDATE public.domain_watch_lane AS dwl
     SET claimed_until = NULL,
         scanned_at    = now()
   WHERE dwl.domain_name = p_domain_name AND dwl.lane_name = 'headers';

  RETURN written_event_count;
END
$$;

CREATE FUNCTION api.fn_domain_watch_record_ct(p_domain_name           text,
                                              p_claimed_until         timestamptz,
                                              p_cert_issuers_value    text,
                                              p_cert_issuers_sha256   text,
                                              p_retry_after_seconds   integer)
  RETURNS integer
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER
  SET search_path = pg_catalog
AS $$
DECLARE
  lane_endpoint_name     CONSTANT text     := (SELECT l.endpoint_name FROM api.fn_domain_watch_lanes() AS l WHERE l.lane_name = 'ct');
  value_kinds            CONSTANT text[]   := api.fn_watchlist_endpoint_value_kinds(lane_endpoint_name);
  scan_values            text[]   := ARRAY[p_cert_issuers_value];
  scan_sha256s           text[]   := ARRAY[p_cert_issuers_sha256];
  watched_lane           public.domain_watch_lane%ROWTYPE;
  written_event_count    integer;
BEGIN
  IF (p_cert_issuers_value IS NULL) <> (p_cert_issuers_sha256 IS NULL) THEN
    RAISE EXCEPTION 'fn_domain_watch_record_ct refuses % of %: a value and its SHA-256 come together', value_kinds[1], p_domain_name
      USING ERRCODE = 'invalid_parameter_value';
  END IF;
  IF octet_length(p_cert_issuers_value) > 2048 THEN
    RAISE EXCEPTION 'fn_domain_watch_record_ct refuses % of %: a value holds at most 2048 bytes', value_kinds[1], p_domain_name
      USING ERRCODE = 'invalid_parameter_value';
  END IF;
  IF EXISTS (SELECT 1 FROM unnest(string_to_array(p_cert_issuers_value, E'\n')) AS scan_line
              WHERE scan_line !~ '^(new_issuer|caa_mismatch) .*[^ ]') THEN
    RAISE EXCEPTION 'fn_domain_watch_record_ct refuses % of %: each line holds new_issuer or caa_mismatch, a space and a key',
                    value_kinds[1], p_domain_name
      USING ERRCODE = 'invalid_parameter_value';
  END IF;
  IF EXISTS (SELECT 1 FROM unnest(string_to_array(p_cert_issuers_value, E'\n')) AS scan_line
              GROUP BY substr(scan_line, strpos(scan_line, ' ') + 1)
             HAVING count(*) > 1) THEN
    RAISE EXCEPTION 'fn_domain_watch_record_ct refuses % of %: each key comes on one line only',
                    value_kinds[1], p_domain_name
      USING ERRCODE = 'invalid_parameter_value';
  END IF;
  IF p_retry_after_seconds IS NOT NULL AND p_retry_after_seconds NOT BETWEEN 1 AND 3600 THEN
    RAISE EXCEPTION 'fn_domain_watch_record_ct refuses a retry of % seconds of %: a deferred scan waits 1 to 3600 seconds',
                    p_retry_after_seconds, p_domain_name
      USING ERRCODE = 'invalid_parameter_value';
  END IF;
  IF p_retry_after_seconds IS NOT NULL AND p_cert_issuers_value IS NOT NULL THEN
    RAISE EXCEPTION 'fn_domain_watch_record_ct refuses the value of %: a deferred scan sends none', p_domain_name
      USING ERRCODE = 'invalid_parameter_value';
  END IF;

  PERFORM 1 FROM public.domain_watch AS dw WHERE dw.domain_name = p_domain_name FOR KEY SHARE;
  SELECT * INTO watched_lane FROM public.domain_watch_lane AS dwl
   WHERE dwl.domain_name = p_domain_name AND dwl.lane_name = 'ct'
     FOR UPDATE;
  IF NOT FOUND THEN
    RETURN 0;
  END IF;

  IF watched_lane.claimed_until IS NULL OR watched_lane.claimed_until IS DISTINCT FROM p_claimed_until THEN
    RETURN 0;
  END IF;

  IF p_retry_after_seconds IS NOT NULL THEN
    UPDATE public.domain_watch_lane AS dwl
       SET claimed_until = NULL,
           not_before    = now() + p_retry_after_seconds * interval '1 second'
     WHERE dwl.domain_name = p_domain_name AND dwl.lane_name = 'ct';
    RETURN 0;
  END IF;

  written_event_count := api.fn_domain_watch_write_scan_values(p_domain_name, lane_endpoint_name, watched_lane.claimed_at, scan_values,
                                                               scan_sha256s, NULL);

  UPDATE public.domain_watch_lane AS dwl
     SET claimed_until = NULL,
         scanned_at    = now()
   WHERE dwl.domain_name = p_domain_name AND dwl.lane_name = 'ct';

  RETURN written_event_count;
END
$$;

CREATE FUNCTION api.fn_domain_change_event_max_id() RETURNS bigint
  LANGUAGE sql STABLE SECURITY INVOKER
  SET search_path = pg_catalog
  RETURN (SELECT greatest(ps.max_purged_event_id, ps.max_unwatched_event_id,
                          (SELECT max(dce.event_id) FROM public.domain_change_event AS dce))
            FROM public.change_event_purge_state AS ps
           WHERE ps.event_table_name = 'domain_change_event');

CREATE FUNCTION api.fn_domain_change_event_purge(p_event_row_count integer) RETURNS integer
  LANGUAGE plpgsql VOLATILE STRICT SECURITY DEFINER
  SET search_path = pg_catalog
AS $$
DECLARE
  picked_event_ids   bigint[];
  purged_event_count integer;
BEGIN
  picked_event_ids := ARRAY(SELECT dce.event_id
                              FROM public.domain_change_event AS dce
                             WHERE dce.changed_at < now() - interval '90 days'
                             ORDER BY dce.event_id
                             LIMIT p_event_row_count);

  PERFORM api.fn_watchlist_event_ref_purge(picked_event_ids, false);

  WITH purged AS (
    DELETE FROM public.domain_change_event AS dce
     WHERE dce.event_id = ANY (picked_event_ids)
    RETURNING dce.event_id),
  deleted AS (
    SELECT max(p.event_id) AS max_event_id FROM purged AS p),
  raised AS (
    UPDATE public.change_event_purge_state AS ps
       SET max_purged_event_id = deleted.max_event_id
      FROM deleted
     WHERE ps.event_table_name = 'domain_change_event'
       AND ps.max_purged_event_id < deleted.max_event_id)
  SELECT count(*)::integer INTO purged_event_count FROM purged;
  RETURN purged_event_count;
END
$$;

CREATE FUNCTION api.fn_domain_watch_purge_unwatched(p_domain_row_count integer) RETURNS integer
  LANGUAGE sql VOLATILE STRICT SECURITY DEFINER
  SET search_path = pg_catalog
  BEGIN ATOMIC
    WITH unwatched AS (
      SELECT dw1.domain_name
        FROM public.domain_watch AS dw1
       WHERE NOT EXISTS (SELECT 1 FROM public.watchlist_item_domain AS wid WHERE wid.domain_name = dw1.domain_name)
       ORDER BY dw1.domain_name
       LIMIT p_domain_row_count
         FOR UPDATE SKIP LOCKED),
    purged AS (
      DELETE FROM public.domain_watch AS dw2
       WHERE dw2.domain_name IN (SELECT u.domain_name FROM unwatched AS u)
      RETURNING dw2.domain_name),
    purged_event AS (
      SELECT max(dce.event_id) AS max_event_id
        FROM public.domain_change_event AS dce
       WHERE dce.domain_name IN (SELECT p.domain_name FROM purged AS p)),
    raised AS (
      UPDATE public.change_event_purge_state AS ps
         SET max_unwatched_event_id = purged_event.max_event_id
        FROM purged_event
       WHERE ps.event_table_name = 'domain_change_event'
         AND ps.max_unwatched_event_id < purged_event.max_event_id),
    idle_bucket AS (
      SELECT dwq1.registered_domain
        FROM public.domain_watch_dns_bucket AS dwq1
       WHERE dwq1.refilled_at < now() - interval '1 day'
         AND NOT EXISTS (SELECT 1 FROM public.domain_watch AS dw3 WHERE dw3.registered_domain = dwq1.registered_domain)
       ORDER BY dwq1.registered_domain
       LIMIT p_domain_row_count
         FOR UPDATE SKIP LOCKED),
    purged_bucket AS (
      DELETE FROM public.domain_watch_dns_bucket AS dwq2
       WHERE dwq2.registered_domain IN (SELECT ib.registered_domain FROM idle_bucket AS ib))
    SELECT count(*)::integer FROM purged;
  END;
