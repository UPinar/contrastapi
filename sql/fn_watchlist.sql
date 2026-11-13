CREATE FUNCTION api.fn_watchlist_endpoint_event_types(p_endpoint_name text)
  RETURNS text[]
  LANGUAGE sql IMMUTABLE SECURITY INVOKER
  SET search_path = pg_catalog
  RETURN CASE
           WHEN p_endpoint_name = 'kev_lookup'
             THEN ARRAY['kev_added', 'kev_removed', 'ransomware_linked', 'kev_updated']
           WHEN p_endpoint_name = 'cve_exploit'
             THEN ARRAY['exploit_published', 'metasploit_added', 'exploitdb_added', 'github_poc_added']
           WHEN p_endpoint_name = 'cve_lookup'
             THEN ARRAY['cve_added', 'kev_added', 'kev_removed', 'epss_level_up', 'epss_level_down', 'cvss_added', 'cvss_risk_band_changed',
                        'exploit_published', 'product_added', 'ransomware_linked', 'product_removed',
                        'vendor_advisory_published', 'patch_published', 'cve_disputed', 'cve_rejected', 'metasploit_added',
                        'nuclei_template_added', 'exploitdb_added', 'ssvc_added', 'ssvc_changed', 'github_poc_added',
                        'description_changed', 'cvss_score_changed', 'cwe_changed', 'kev_updated', 'ghsa_linked']
           WHEN p_endpoint_name = 'product_exposure'
             THEN ARRAY['cve_added', 'kev_added', 'kev_removed', 'epss_level_up', 'epss_level_down', 'cvss_added', 'cvss_risk_band_changed',
                        'exploit_published', 'product_added', 'ransomware_linked', 'product_removed',
                        'vendor_advisory_published', 'patch_published', 'cve_disputed', 'cve_rejected', 'metasploit_added',
                        'nuclei_template_added', 'exploitdb_added', 'ssvc_added', 'ssvc_changed', 'github_poc_added',
                        'description_changed', 'cvss_score_changed', 'cwe_changed', 'kev_updated', 'ghsa_linked',
                        'eol_approaching', 'eol_reached', 'eol_date_changed']
           WHEN p_endpoint_name = 'cve_search'
             THEN ARRAY['cve_added', 'kev_added', 'kev_removed', 'epss_level_up', 'epss_level_down', 'cvss_added', 'cvss_risk_band_changed',
                        'exploit_published', 'product_added', 'ransomware_linked', 'product_removed',
                        'vendor_advisory_published', 'patch_published', 'cve_disputed', 'cve_rejected', 'metasploit_added',
                        'nuclei_template_added', 'exploitdb_added', 'ssvc_added', 'ssvc_changed', 'github_poc_added',
                        'description_changed', 'cvss_score_changed', 'cwe_changed', 'kev_updated', 'ghsa_linked',
                        'epss_above_min', 'epss_below_min']
           WHEN p_endpoint_name = 'dns_lookup'
             THEN ARRAY['domain_not_found', 'domain_found', 'ns_changed', 'mx_changed', 'ip_address_not_public', 'ip_address_lost',
                        'ip_address_restored', 'cname_takeover_detected', 'cname_takeover_resolved', 'email_auth_degraded',
                        'hosting_changed']
           WHEN p_endpoint_name = 'ssl_check'
             THEN ARRAY['cert_expiring', 'cert_invalid', 'cert_listed', 'tls_downgraded']
           WHEN p_endpoint_name = 'whois_lookup'
             THEN ARRAY['domain_expiring', 'registrar_changed', 'transfer_lock_removed', 'dnssec_disabled']
           WHEN p_endpoint_name = 'headers_check'
             THEN ARRAY['security_header_removed']
           WHEN p_endpoint_name = 'cert_search'
             THEN ARRAY['cert_unexpected']
           WHEN p_endpoint_name = 'package_check'
             THEN ARRAY['advisory_added', 'fix_available', 'malware_added', 'kev_added', 'ransomware_linked', 'eol_approaching',
                        'eol_reached', 'eol_date_changed']
           WHEN p_endpoint_name = 'ip_lookup'
             THEN ARRAY['drop_listed', 'drop_unlisted', 'hosting_changed']
           ELSE ARRAY[]::text[]
         END;

CREATE FUNCTION api.fn_watchlist_endpoint_value_kinds(p_endpoint_name text)
  RETURNS text[]
  LANGUAGE sql IMMUTABLE SECURITY INVOKER
  SET search_path = pg_catalog
  RETURN CASE
           WHEN p_endpoint_name = 'dns_lookup'
             THEN ARRAY['dns_presence', 'ns', 'mx', 'ip_address_reachability', 'cname_takeover', 'email_auth', 'hosting']
           WHEN p_endpoint_name = 'ssl_check'
             THEN ARRAY['certificate_expiry', 'certificate_validity', 'certificate_listing', 'tls_protocol']
           WHEN p_endpoint_name = 'whois_lookup'
             THEN ARRAY['registration_expiry', 'registrar', 'transfer_lock', 'dnssec_delegation']
           WHEN p_endpoint_name = 'headers_check'
             THEN ARRAY['security_headers']
           WHEN p_endpoint_name = 'cert_search'
             THEN ARRAY['cert_issuers']
           ELSE ARRAY[]::text[]
         END;

CREATE FUNCTION api.fn_watchlist_event_max_id() RETURNS bigint
  LANGUAGE sql STABLE SECURITY INVOKER
  SET search_path = pg_catalog
  RETURN greatest(api.fn_cve_change_event_max_id(), api.fn_domain_change_event_max_id(), api.fn_package_advisory_change_event_max_id(),
                  api.fn_ip_change_event_max_id(), api.fn_eol_change_event_max_id());

CREATE FUNCTION api.fn_watchlist_item_product_has_cves(p_endpoint_name text, p_vendor text, p_product text)
  RETURNS boolean
  LANGUAGE sql STABLE SECURITY INVOKER
  SET search_path = pg_catalog
  RETURN CASE WHEN p_endpoint_name = 'product_exposure'
              THEN EXISTS (SELECT 1 FROM public.cve_products AS cp
                            WHERE cp.vendor = p_vendor AND cp.product = p_product AND cp.is_vulnerable)
         END;

CREATE FUNCTION api.fn_watchlist_item_edit(p_key_hash                   text,
                                           p_action                     text,
                                           p_endpoint_name              text,
                                           p_cve_id                     text    DEFAULT NULL,
                                           p_vendor                     text    DEFAULT NULL,
                                           p_product                    text    DEFAULT NULL,
                                           p_severity                   text    DEFAULT NULL,
                                           p_cwe_id                     text    DEFAULT NULL,
                                           p_min_cvss                   real    DEFAULT NULL,
                                           p_min_epss                   real    DEFAULT NULL,
                                           p_in_kev                     boolean DEFAULT NULL,
                                           p_known_ransomware           boolean DEFAULT NULL,
                                           p_has_nuclei_template        boolean DEFAULT NULL,
                                           p_item_max_count             integer DEFAULT NULL,
                                           p_domain_name                text    DEFAULT NULL,
                                           p_registered_domain          text    DEFAULT NULL,
                                           p_domain_name_max_count      integer DEFAULT NULL,
                                           p_ecosystem                  text    DEFAULT NULL,
                                           p_package_name               text    DEFAULT NULL,
                                           p_version                    text    DEFAULT NULL,
                                           p_package_item_max_count     integer DEFAULT NULL,
                                           p_package_item_base_weight   integer DEFAULT NULL,
                                           p_package_weight_budget      integer DEFAULT NULL,
                                           p_listed_versions_per_weight integer DEFAULT NULL,
                                           p_ip_address                 inet    DEFAULT NULL)
  RETURNS TABLE (edit_status         text,
                 endpoint_name       text,
                 cve_id              text,
                 vendor              text,
                 product             text,
                 severity            text,
                 cwe_id              text,
                 min_cvss            real,
                 min_epss            real,
                 in_kev              boolean,
                 known_ransomware    boolean,
                 has_nuclei_template boolean,
                 product_has_cves    boolean,
                 domain_name         text,
                 ecosystem           text,
                 package_name        text,
                 version             text,
                 ip_address          text,
                 item_count          integer,
                 package_item_count  integer)
  LANGUAGE plpgsql VOLATILE SECURITY INVOKER
  SET search_path = pg_catalog
AS $$
DECLARE
  item_lane_name           text    := (SELECT l.lane_name FROM api.fn_domain_watch_lanes() AS l WHERE l.endpoint_name = p_endpoint_name);
  is_domain_item           boolean := item_lane_name IS NOT NULL;
  is_package_item          boolean := p_endpoint_name IS NOT DISTINCT FROM 'package_check';
  is_ip_item               boolean := p_endpoint_name IS NOT DISTINCT FROM 'ip_lookup';
  package_ecosystem        text    := api.fn_package_check_ecosystem(p_ecosystem);
  caller_api_key_id        integer;
  existing_item_id         bigint;
  new_item_id              bigint;
  same_kind_item_count     bigint;
  package_weight           bigint;
  domain_name_count        bigint;
  max_event_id             bigint;
  caller_last_key_event_id bigint;
  answered_item_id         bigint;
  answer_status            text := 'ok';
BEGIN
  IF p_action IS NULL OR p_action NOT IN ('add', 'remove') THEN
    RAISE EXCEPTION 'fn_watchlist_item_edit refuses action % of %: an item edit is an add or a remove', p_action, p_endpoint_name
      USING ERRCODE = 'invalid_parameter_value';
  END IF;
  IF (is_package_item AND (p_package_item_max_count IS NULL OR p_package_item_base_weight IS NULL
                           OR p_package_weight_budget IS NULL OR p_listed_versions_per_weight IS NULL))
     OR (NOT is_package_item AND p_item_max_count IS NULL)
     OR (is_domain_item AND p_domain_name_max_count IS NULL) THEN
    RAISE EXCEPTION 'fn_watchlist_item_edit refuses % of %: a cap of the item is NULL', p_action, p_endpoint_name
      USING ERRCODE = 'invalid_parameter_value';
  END IF;
  IF is_domain_item AND p_registered_domain IS NULL THEN
    RAISE EXCEPTION 'fn_watchlist_item_edit refuses % of %: a domain item needs its registered domain', p_endpoint_name, p_domain_name
      USING ERRCODE = 'invalid_parameter_value';
  END IF;
  IF is_package_item AND (package_ecosystem IS NULL OR p_package_name IS NULL) THEN
    RAISE EXCEPTION 'fn_watchlist_item_edit refuses % of %: a package item needs a known ecosystem and a name', p_endpoint_name, p_ecosystem
      USING ERRCODE = 'invalid_parameter_value';
  END IF;
  IF is_ip_item AND (p_ip_address IS NULL OR masklen(p_ip_address) <> CASE family(p_ip_address) WHEN 4 THEN 32 ELSE 128 END) THEN
    RAISE EXCEPTION 'fn_watchlist_item_edit refuses % of %: an IP item needs one address', p_endpoint_name, p_ip_address
      USING ERRCODE = 'invalid_parameter_value';
  END IF;
  IF NOT is_ip_item AND p_ip_address IS NOT NULL THEN
    RAISE EXCEPTION 'fn_watchlist_item_edit refuses % of %: only an IP item takes an address', p_endpoint_name, p_ip_address
      USING ERRCODE = 'invalid_parameter_value';
  END IF;

  SELECT ak.id INTO caller_api_key_id FROM public.api_keys AS ak WHERE ak.key_hash = p_key_hash FOR UPDATE;
  IF NOT FOUND THEN
    edit_status := 'unknown_key';
    RETURN NEXT;
    RETURN;
  END IF;
  IF p_action = 'add' THEN
    INSERT INTO public.watchlist_key_state (api_key_id, last_cve_event_id)
    VALUES (caller_api_key_id, api.fn_watchlist_event_max_id())
    ON CONFLICT DO NOTHING;
  END IF;
  SELECT wks.last_key_event_id INTO caller_last_key_event_id
    FROM public.watchlist_key_state AS wks
   WHERE wks.api_key_id = caller_api_key_id FOR UPDATE;

  IF is_domain_item THEN
    SELECT wid.item_id INTO existing_item_id
      FROM public.watchlist_item_domain AS wid
     WHERE wid.api_key_id    = caller_api_key_id
       AND wid.endpoint_name = p_endpoint_name
       AND wid.domain_name   IS NOT DISTINCT FROM p_domain_name;
  ELSIF is_ip_item THEN
    SELECT wii.item_id INTO existing_item_id
      FROM public.watchlist_item_ip AS wii
     WHERE wii.api_key_id = caller_api_key_id
       AND wii.ip_address = p_ip_address;
  ELSIF is_package_item THEN
    SELECT wip.item_id INTO existing_item_id
      FROM public.watchlist_item_package AS wip
     WHERE wip.api_key_id              = caller_api_key_id
       AND wip.ecosystem               = package_ecosystem
       AND wip.package_name_normalized = public.fn_osv_normalize_package_name(package_ecosystem, p_package_name)
       AND wip.version                 IS NOT DISTINCT FROM p_version;
  ELSE
    SELECT wic.item_id INTO existing_item_id
      FROM public.watchlist_item_cve AS wic
     WHERE wic.api_key_id    = caller_api_key_id
       AND wic.endpoint_name = p_endpoint_name
       AND wic.cve_id              IS NOT DISTINCT FROM p_cve_id
       AND wic.vendor              IS NOT DISTINCT FROM p_vendor
       AND wic.product             IS NOT DISTINCT FROM p_product
       AND wic.severity            IS NOT DISTINCT FROM p_severity
       AND wic.cwe_id              IS NOT DISTINCT FROM p_cwe_id
       AND wic.min_cvss            IS NOT DISTINCT FROM p_min_cvss
       AND wic.min_epss            IS NOT DISTINCT FROM p_min_epss
       AND wic.in_kev              IS NOT DISTINCT FROM p_in_kev
       AND wic.known_ransomware    IS NOT DISTINCT FROM p_known_ransomware
       AND wic.has_nuclei_template IS NOT DISTINCT FROM p_has_nuclei_template
       AND wic.version             IS NOT DISTINCT FROM p_version;
  END IF;

  IF p_action = 'add' AND existing_item_id IS NOT NULL THEN
    answered_item_id := existing_item_id;
  ELSIF p_action = 'add' THEN
    SELECT count(*) INTO same_kind_item_count
      FROM public.watchlist_item AS wi
     WHERE wi.api_key_id = caller_api_key_id
       AND (wi.endpoint_name = 'package_check') = is_package_item;
    IF is_package_item THEN
      SELECT sum(api.fn_package_check_package_weight(item.ecosystem, item.package_name_normalized,
                                                     p_package_item_base_weight, p_listed_versions_per_weight)) INTO package_weight
        FROM (SELECT wip.ecosystem, wip.package_name_normalized
                FROM public.watchlist_item_package AS wip
               WHERE wip.api_key_id = caller_api_key_id
              UNION ALL
              SELECT package_ecosystem, public.fn_osv_normalize_package_name(package_ecosystem, p_package_name)) AS item (ecosystem, package_name_normalized);
    END IF;
    IF is_domain_item
       AND NOT EXISTS (SELECT 1 FROM public.watchlist_item_domain AS wid WHERE wid.api_key_id = caller_api_key_id AND wid.domain_name = p_domain_name) THEN
      SELECT count(DISTINCT wid.domain_name) INTO domain_name_count
        FROM public.watchlist_item_domain AS wid
       WHERE wid.api_key_id = caller_api_key_id
         AND wid.registered_domain = p_registered_domain;
    END IF;
    IF is_package_item AND same_kind_item_count >= p_package_item_max_count THEN
      answer_status := 'over_package_limit';
    ELSIF package_weight > p_package_weight_budget THEN
      answer_status := 'over_package_weight';
    ELSIF NOT is_package_item AND same_kind_item_count >= p_item_max_count THEN
      answer_status := 'over_limit';
    ELSIF domain_name_count >= p_domain_name_max_count THEN
      answer_status := 'over_domain_limit';
    ELSE
      max_event_id := api.fn_watchlist_event_max_id();
      INSERT INTO public.watchlist_event_cursor (api_key_id, previous_cursor, delivered_cursor)
      VALUES (caller_api_key_id, caller_last_key_event_id, caller_last_key_event_id)
      ON CONFLICT DO NOTHING;
      IF FOUND THEN
        UPDATE public.watchlist_key_state AS wks
           SET last_cve_event_id = greatest(wks.last_cve_event_id, max_event_id)
         WHERE wks.api_key_id = caller_api_key_id;
      END IF;
      IF is_domain_item THEN
        INSERT INTO public.domain_watch (domain_name, registered_domain)
        VALUES (p_domain_name, p_registered_domain)
        ON CONFLICT ON CONSTRAINT domain_watch_pkey DO UPDATE SET domain_name = EXCLUDED.domain_name;
        INSERT INTO public.domain_watch_lane (domain_name, lane_name)
        VALUES (p_domain_name, item_lane_name)
        ON CONFLICT ON CONSTRAINT domain_watch_lane_pkey DO UPDATE SET lane_name = EXCLUDED.lane_name;
        INSERT INTO public.watchlist_item (api_key_id, endpoint_name)
        VALUES (caller_api_key_id, p_endpoint_name)
        RETURNING watchlist_item.item_id INTO new_item_id;
        INSERT INTO public.watchlist_item_domain (item_id, api_key_id, endpoint_name, domain_name, registered_domain, next_scan_at)
        VALUES (new_item_id, caller_api_key_id, p_endpoint_name, p_domain_name, p_registered_domain, clock_timestamp());
      ELSIF is_ip_item THEN
        INSERT INTO public.watchlist_item (api_key_id, endpoint_name)
        VALUES (caller_api_key_id, p_endpoint_name)
        RETURNING watchlist_item.item_id INTO new_item_id;
        INSERT INTO public.watchlist_item_ip (item_id, api_key_id, endpoint_name, ip_address)
        VALUES (new_item_id, caller_api_key_id, p_endpoint_name, p_ip_address);
      ELSIF is_package_item THEN
        INSERT INTO public.watchlist_item (api_key_id, endpoint_name)
        VALUES (caller_api_key_id, p_endpoint_name)
        RETURNING watchlist_item.item_id INTO new_item_id;
        INSERT INTO public.watchlist_item_package (item_id, api_key_id, endpoint_name, last_event_id_before_add, ecosystem, package_name, version)
        VALUES (new_item_id, caller_api_key_id, p_endpoint_name, max_event_id, package_ecosystem, p_package_name, p_version);
      ELSE
        INSERT INTO public.watchlist_item (api_key_id, endpoint_name)
        VALUES (caller_api_key_id, p_endpoint_name)
        RETURNING watchlist_item.item_id INTO new_item_id;
        INSERT INTO public.watchlist_item_cve (item_id, api_key_id, endpoint_name, last_event_id_before_add, cve_id, vendor, product,
                                               severity, cwe_id, min_cvss, min_epss, in_kev, known_ransomware, has_nuclei_template, version)
        VALUES (new_item_id, caller_api_key_id, p_endpoint_name, max_event_id, p_cve_id, p_vendor, p_product,
                p_severity, p_cwe_id, p_min_cvss, p_min_epss, p_in_kev, p_known_ransomware, p_has_nuclei_template, p_version);
      END IF;
      answered_item_id := new_item_id;
    END IF;

  ELSIF p_action = 'remove' THEN
    answered_item_id := existing_item_id;
  END IF;

  RETURN QUERY
    SELECT answer_status                                                                     AS edit_status,
           wi.endpoint_name                                                                  AS endpoint_name,
           wic.cve_id                                                                        AS cve_id,
           wic.vendor                                                                        AS vendor,
           wic.product                                                                       AS product,
           wic.severity                                                                      AS severity,
           wic.cwe_id                                                                        AS cwe_id,
           wic.min_cvss                                                                      AS min_cvss,
           wic.min_epss                                                                      AS min_epss,
           wic.in_kev                                                                        AS in_kev,
           wic.known_ransomware                                                              AS known_ransomware,
           wic.has_nuclei_template                                                           AS has_nuclei_template,
           api.fn_watchlist_item_product_has_cves(wi.endpoint_name, wic.vendor, wic.product) AS product_has_cves,
           wid.domain_name                                                                   AS domain_name,
           wip.ecosystem                                                                     AS ecosystem,
           wip.package_name                                                                  AS package_name,
           coalesce(wip.version, wic.version)                                                AS version,
           host(wii.ip_address)                                                              AS ip_address,
           kc.item_count                                                                     AS item_count,
           kc.package_item_count                                                             AS package_item_count
      FROM (SELECT (count(*) FILTER (WHERE wik.endpoint_name <> 'package_check'))::integer AS item_count,
                   (count(*) FILTER (WHERE wik.endpoint_name = 'package_check'))::integer  AS package_item_count
              FROM public.watchlist_item AS wik
             WHERE wik.api_key_id = caller_api_key_id
               AND (p_action IS DISTINCT FROM 'remove' OR wik.item_id IS DISTINCT FROM existing_item_id)) AS kc
      LEFT JOIN (public.watchlist_item AS wi
                 LEFT JOIN public.watchlist_item_cve AS wic ON wic.item_id = wi.item_id
                 LEFT JOIN public.watchlist_item_domain AS wid ON wid.item_id = wi.item_id
                 LEFT JOIN public.watchlist_item_package AS wip ON wip.item_id = wi.item_id
                 LEFT JOIN public.watchlist_item_ip AS wii ON wii.item_id = wi.item_id)
             ON wi.api_key_id = caller_api_key_id
            AND wi.item_id = answered_item_id;

  IF p_action = 'remove' THEN
    DELETE FROM public.watchlist_item AS wi WHERE wi.item_id = existing_item_id;
    IF NOT EXISTS (SELECT 1 FROM public.watchlist_item AS wi WHERE wi.api_key_id = caller_api_key_id) THEN
      DELETE FROM public.watchlist_event_cursor AS wec WHERE wec.api_key_id = caller_api_key_id;
      UPDATE public.watchlist_key_state AS wks
         SET max_purged_key_event_id = wks.last_key_event_id
       WHERE wks.api_key_id = caller_api_key_id;
    END IF;
  END IF;
END
$$;

CREATE FUNCTION api.fn_watchlist_edit_cve_lookup(p_key_hash       text,
                                                 p_action         text,
                                                 p_cve_id         text,
                                                 p_item_max_count integer)
  RETURNS TABLE (edit_status        text,
                 endpoint_name      text,
                 cve_id             text,
                 item_count         integer,
                 package_item_count integer)
  LANGUAGE sql VOLATILE SECURITY DEFINER
  SET search_path = pg_catalog
  BEGIN ATOMIC
    SELECT edit.edit_status        AS edit_status,
           edit.endpoint_name      AS endpoint_name,
           edit.cve_id             AS cve_id,
           edit.item_count         AS item_count,
           edit.package_item_count AS package_item_count
      FROM api.fn_watchlist_item_edit(p_key_hash => p_key_hash, p_action => p_action, p_endpoint_name => 'cve_lookup', p_cve_id => p_cve_id, p_item_max_count => p_item_max_count) AS edit;
  END;

CREATE FUNCTION api.fn_watchlist_edit_kev_lookup(p_key_hash       text,
                                                 p_action         text,
                                                 p_cve_id         text,
                                                 p_item_max_count integer)
  RETURNS TABLE (edit_status        text,
                 endpoint_name      text,
                 cve_id             text,
                 item_count         integer,
                 package_item_count integer)
  LANGUAGE sql VOLATILE SECURITY DEFINER
  SET search_path = pg_catalog
  BEGIN ATOMIC
    SELECT edit.edit_status        AS edit_status,
           edit.endpoint_name      AS endpoint_name,
           edit.cve_id             AS cve_id,
           edit.item_count         AS item_count,
           edit.package_item_count AS package_item_count
      FROM api.fn_watchlist_item_edit(p_key_hash => p_key_hash, p_action => p_action, p_endpoint_name => 'kev_lookup', p_cve_id => p_cve_id, p_item_max_count => p_item_max_count) AS edit;
  END;

CREATE FUNCTION api.fn_watchlist_edit_cve_exploit(p_key_hash       text,
                                                  p_action         text,
                                                  p_cve_id         text,
                                                  p_item_max_count integer)
  RETURNS TABLE (edit_status        text,
                 endpoint_name      text,
                 cve_id             text,
                 item_count         integer,
                 package_item_count integer)
  LANGUAGE sql VOLATILE SECURITY DEFINER
  SET search_path = pg_catalog
  BEGIN ATOMIC
    SELECT edit.edit_status        AS edit_status,
           edit.endpoint_name      AS endpoint_name,
           edit.cve_id             AS cve_id,
           edit.item_count         AS item_count,
           edit.package_item_count AS package_item_count
      FROM api.fn_watchlist_item_edit(p_key_hash => p_key_hash, p_action => p_action, p_endpoint_name => 'cve_exploit', p_cve_id => p_cve_id, p_item_max_count => p_item_max_count) AS edit;
  END;

CREATE FUNCTION api.fn_watchlist_edit_product_exposure(p_key_hash       text,
                                                       p_action         text,
                                                       p_vendor         text,
                                                       p_product        text,
                                                       p_version        text,
                                                       p_item_max_count integer)
  RETURNS TABLE (edit_status        text,
                 endpoint_name      text,
                 vendor             text,
                 product            text,
                 product_has_cves   boolean,
                 version            text,
                 item_count         integer,
                 package_item_count integer)
  LANGUAGE sql VOLATILE SECURITY DEFINER
  SET search_path = pg_catalog
  BEGIN ATOMIC
    SELECT edit.edit_status        AS edit_status,
           edit.endpoint_name      AS endpoint_name,
           edit.vendor             AS vendor,
           edit.product            AS product,
           edit.product_has_cves   AS product_has_cves,
           edit.version            AS version,
           edit.item_count         AS item_count,
           edit.package_item_count AS package_item_count
      FROM api.fn_watchlist_item_edit(p_key_hash => p_key_hash, p_action => p_action, p_endpoint_name => 'product_exposure', p_vendor => p_vendor, p_product => p_product, p_version => p_version, p_item_max_count => p_item_max_count) AS edit;
  END;

CREATE FUNCTION api.fn_watchlist_edit_cve_search(p_key_hash            text,
                                                 p_action              text,
                                                 p_vendor              text,
                                                 p_product             text,
                                                 p_severity            text,
                                                 p_cwe_id              text,
                                                 p_min_cvss            real,
                                                 p_min_epss            real,
                                                 p_in_kev              boolean,
                                                 p_known_ransomware    boolean,
                                                 p_has_nuclei_template boolean,
                                                 p_item_max_count      integer)
  RETURNS TABLE (edit_status         text,
                 endpoint_name       text,
                 vendor              text,
                 product             text,
                 severity            text,
                 cwe_id              text,
                 min_cvss            real,
                 min_epss            real,
                 in_kev              boolean,
                 known_ransomware    boolean,
                 has_nuclei_template boolean,
                 item_count          integer,
                 package_item_count  integer)
  LANGUAGE sql VOLATILE SECURITY DEFINER
  SET search_path = pg_catalog
  BEGIN ATOMIC
    SELECT edit.edit_status         AS edit_status,
           edit.endpoint_name       AS endpoint_name,
           edit.vendor              AS vendor,
           edit.product             AS product,
           edit.severity            AS severity,
           edit.cwe_id              AS cwe_id,
           edit.min_cvss            AS min_cvss,
           edit.min_epss            AS min_epss,
           edit.in_kev              AS in_kev,
           edit.known_ransomware    AS known_ransomware,
           edit.has_nuclei_template AS has_nuclei_template,
           edit.item_count          AS item_count,
           edit.package_item_count  AS package_item_count
      FROM api.fn_watchlist_item_edit(p_key_hash => p_key_hash, p_action => p_action, p_endpoint_name => 'cve_search', p_vendor => p_vendor, p_product => p_product, p_severity => p_severity, p_cwe_id => p_cwe_id, p_min_cvss => p_min_cvss, p_min_epss => p_min_epss, p_in_kev => p_in_kev, p_known_ransomware => p_known_ransomware, p_has_nuclei_template => p_has_nuclei_template, p_item_max_count => p_item_max_count) AS edit;
  END;

CREATE FUNCTION api.fn_watchlist_edit_dns_lookup(p_key_hash              text,
                                                 p_action                text,
                                                 p_domain_name           text,
                                                 p_registered_domain     text,
                                                 p_item_max_count        integer,
                                                 p_domain_name_max_count integer)
  RETURNS TABLE (edit_status        text,
                 endpoint_name      text,
                 domain_name        text,
                 item_count         integer,
                 package_item_count integer)
  LANGUAGE sql VOLATILE SECURITY DEFINER
  SET search_path = pg_catalog
  BEGIN ATOMIC
    SELECT edit.edit_status        AS edit_status,
           edit.endpoint_name      AS endpoint_name,
           edit.domain_name        AS domain_name,
           edit.item_count         AS item_count,
           edit.package_item_count AS package_item_count
      FROM api.fn_watchlist_item_edit(p_key_hash => p_key_hash, p_action => p_action, p_endpoint_name => 'dns_lookup', p_domain_name => p_domain_name, p_registered_domain => p_registered_domain, p_item_max_count => p_item_max_count, p_domain_name_max_count => p_domain_name_max_count) AS edit;
  END;

CREATE FUNCTION api.fn_watchlist_edit_ssl_check(p_key_hash              text,
                                                p_action                text,
                                                p_domain_name           text,
                                                p_registered_domain     text,
                                                p_item_max_count        integer,
                                                p_domain_name_max_count integer)
  RETURNS TABLE (edit_status        text,
                 endpoint_name      text,
                 domain_name        text,
                 item_count         integer,
                 package_item_count integer)
  LANGUAGE sql VOLATILE SECURITY DEFINER
  SET search_path = pg_catalog
  BEGIN ATOMIC
    SELECT edit.edit_status        AS edit_status,
           edit.endpoint_name      AS endpoint_name,
           edit.domain_name        AS domain_name,
           edit.item_count         AS item_count,
           edit.package_item_count AS package_item_count
      FROM api.fn_watchlist_item_edit(p_key_hash => p_key_hash, p_action => p_action, p_endpoint_name => 'ssl_check', p_domain_name => p_domain_name, p_registered_domain => p_registered_domain, p_item_max_count => p_item_max_count, p_domain_name_max_count => p_domain_name_max_count) AS edit;
  END;

CREATE FUNCTION api.fn_watchlist_edit_whois_lookup(p_key_hash              text,
                                                   p_action                text,
                                                   p_domain_name           text,
                                                   p_registered_domain     text,
                                                   p_item_max_count        integer,
                                                   p_domain_name_max_count integer)
  RETURNS TABLE (edit_status        text,
                 endpoint_name      text,
                 domain_name        text,
                 item_count         integer,
                 package_item_count integer)
  LANGUAGE sql VOLATILE SECURITY DEFINER
  SET search_path = pg_catalog
  BEGIN ATOMIC
    SELECT edit.edit_status        AS edit_status,
           edit.endpoint_name      AS endpoint_name,
           edit.domain_name        AS domain_name,
           edit.item_count         AS item_count,
           edit.package_item_count AS package_item_count
      FROM api.fn_watchlist_item_edit(p_key_hash => p_key_hash, p_action => p_action, p_endpoint_name => 'whois_lookup', p_domain_name => p_domain_name, p_registered_domain => p_registered_domain, p_item_max_count => p_item_max_count, p_domain_name_max_count => p_domain_name_max_count) AS edit;
  END;

CREATE FUNCTION api.fn_watchlist_edit_headers_check(p_key_hash              text,
                                                    p_action                text,
                                                    p_domain_name           text,
                                                    p_registered_domain     text,
                                                    p_item_max_count        integer,
                                                    p_domain_name_max_count integer)
  RETURNS TABLE (edit_status        text,
                 endpoint_name      text,
                 domain_name        text,
                 item_count         integer,
                 package_item_count integer)
  LANGUAGE sql VOLATILE SECURITY DEFINER
  SET search_path = pg_catalog
  BEGIN ATOMIC
    SELECT edit.edit_status        AS edit_status,
           edit.endpoint_name      AS endpoint_name,
           edit.domain_name        AS domain_name,
           edit.item_count         AS item_count,
           edit.package_item_count AS package_item_count
      FROM api.fn_watchlist_item_edit(p_key_hash => p_key_hash, p_action => p_action, p_endpoint_name => 'headers_check', p_domain_name => p_domain_name, p_registered_domain => p_registered_domain, p_item_max_count => p_item_max_count, p_domain_name_max_count => p_domain_name_max_count) AS edit;
  END;

CREATE FUNCTION api.fn_watchlist_edit_cert_search(p_key_hash              text,
                                                  p_action                text,
                                                  p_domain_name           text,
                                                  p_registered_domain     text,
                                                  p_item_max_count        integer,
                                                  p_domain_name_max_count integer)
  RETURNS TABLE (edit_status        text,
                 endpoint_name      text,
                 domain_name        text,
                 item_count         integer,
                 package_item_count integer)
  LANGUAGE sql VOLATILE SECURITY DEFINER
  SET search_path = pg_catalog
  BEGIN ATOMIC
    SELECT edit.edit_status        AS edit_status,
           edit.endpoint_name      AS endpoint_name,
           edit.domain_name        AS domain_name,
           edit.item_count         AS item_count,
           edit.package_item_count AS package_item_count
      FROM api.fn_watchlist_item_edit(p_key_hash => p_key_hash, p_action => p_action, p_endpoint_name => 'cert_search', p_domain_name => p_domain_name, p_registered_domain => p_registered_domain, p_item_max_count => p_item_max_count, p_domain_name_max_count => p_domain_name_max_count) AS edit;
  END;

CREATE FUNCTION api.fn_watchlist_edit_package_check(p_key_hash                   text,
                                                    p_action                     text,
                                                    p_ecosystem                  text,
                                                    p_package_name               text,
                                                    p_version                    text,
                                                    p_package_item_max_count     integer,
                                                    p_package_item_base_weight   integer,
                                                    p_package_weight_budget      integer,
                                                    p_listed_versions_per_weight integer)
  RETURNS TABLE (edit_status        text,
                 endpoint_name      text,
                 ecosystem          text,
                 package_name       text,
                 version            text,
                 item_count         integer,
                 package_item_count integer)
  LANGUAGE sql VOLATILE SECURITY DEFINER
  SET search_path = pg_catalog
  BEGIN ATOMIC
    SELECT edit.edit_status        AS edit_status,
           edit.endpoint_name      AS endpoint_name,
           edit.ecosystem          AS ecosystem,
           edit.package_name       AS package_name,
           edit.version            AS version,
           edit.item_count         AS item_count,
           edit.package_item_count AS package_item_count
      FROM api.fn_watchlist_item_edit(p_key_hash => p_key_hash, p_action => p_action, p_endpoint_name => 'package_check', p_ecosystem => p_ecosystem, p_package_name => p_package_name, p_version => p_version, p_package_item_max_count => p_package_item_max_count, p_package_item_base_weight => p_package_item_base_weight, p_package_weight_budget => p_package_weight_budget, p_listed_versions_per_weight => p_listed_versions_per_weight) AS edit;
  END;

CREATE FUNCTION api.fn_watchlist_package_list_edit(p_key_hash                   text,
                                                   p_action                     text,
                                                   p_ecosystems                 text[],
                                                   p_package_names              text[],
                                                   p_versions                   text[],
                                                   p_package_item_max_count     integer,
                                                   p_package_item_base_weight   integer,
                                                   p_package_weight_budget      integer,
                                                   p_listed_versions_per_weight integer)
  RETURNS TABLE (edit_status           text,
                 package_index         integer,
                 earlier_package_index integer,
                 added_count           integer,
                 removed_count         integer,
                 unchanged_count       integer,
                 package_item_count    integer)
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER
  SET search_path = pg_catalog
AS $$
DECLARE
  listed_count             integer := coalesce(cardinality(p_ecosystems), 0);
  listed_versions          text[]  := array_replace(p_versions, '', NULL);
  listed_ecosystems        text[];
  listed_names_normalized  text[];
  caller_api_key_id        integer;
  caller_last_key_event_id bigint;
  matched_item_ids         bigint[];
  matched_count            integer;
  package_count_after      bigint;
  package_weight           bigint;
  max_event_id             bigint;
  new_item_id              bigint;
  added_ordinal            bigint;
  answer_status            text := 'ok';
BEGIN
  IF p_action IS NULL OR p_action NOT IN ('add', 'remove') THEN
    RAISE EXCEPTION 'fn_watchlist_package_list_edit refuses action %: a package list edit is an add or a remove', p_action
      USING ERRCODE = 'invalid_parameter_value';
  END IF;
  IF p_package_item_max_count IS NULL OR p_package_item_base_weight IS NULL OR p_package_weight_budget IS NULL
     OR p_listed_versions_per_weight IS NULL THEN
    RAISE EXCEPTION 'fn_watchlist_package_list_edit refuses %: a cap is NULL', p_action
      USING ERRCODE = 'invalid_parameter_value';
  END IF;
  IF listed_count = 0 OR listed_count <> coalesce(cardinality(p_package_names), 0) OR listed_count <> coalesce(cardinality(p_versions), 0) THEN
    RAISE EXCEPTION 'fn_watchlist_package_list_edit refuses %: the three package arrays need one entry or more, and as many each', p_action
      USING ERRCODE = 'invalid_parameter_value';
  END IF;
  SELECT array_agg(CASE WHEN l.ecosystem = '' THEN '' ELSE api.fn_package_check_ecosystem(l.ecosystem) END ORDER BY l.ordinal),
         array_agg(public.fn_osv_normalize_package_name(api.fn_package_check_ecosystem(l.ecosystem), l.package_name) ORDER BY l.ordinal)
    INTO listed_ecosystems, listed_names_normalized
    FROM unnest(p_ecosystems, p_package_names) WITH ORDINALITY AS l (ecosystem, package_name, ordinal);
  IF array_position(listed_ecosystems, NULL) IS NOT NULL OR array_position(p_package_names, NULL) IS NOT NULL THEN
    RAISE EXCEPTION 'fn_watchlist_package_list_edit refuses %: each package needs a known ecosystem and a name', p_action
      USING ERRCODE = 'invalid_parameter_value';
  END IF;

  RETURN QUERY
    SELECT 'package_problem'                AS edit_status,
           (r.ordinal - 1)::integer         AS package_index,
           (r.first_ordinal - 1)::integer   AS earlier_package_index,
           NULL::integer                    AS added_count,
           NULL::integer                    AS removed_count,
           NULL::integer                    AS unchanged_count,
           NULL::integer                    AS package_item_count
      FROM (SELECT l.ordinal, min(l.ordinal) OVER (PARTITION BY l.ecosystem, l.package_name_normalized, l.version) AS first_ordinal
              FROM unnest(listed_ecosystems, listed_names_normalized, listed_versions) WITH ORDINALITY AS l (ecosystem, package_name_normalized, version, ordinal)
             WHERE l.ecosystem <> '') AS r
     WHERE r.ordinal > r.first_ordinal
     ORDER BY r.ordinal;
  IF FOUND THEN
    RETURN;
  END IF;
  IF array_position(listed_ecosystems, '') IS NOT NULL THEN
    edit_status := 'package_problem';
    RETURN NEXT;
    RETURN;
  END IF;

  SELECT ak.id INTO caller_api_key_id FROM public.api_keys AS ak WHERE ak.key_hash = p_key_hash FOR UPDATE;
  IF NOT FOUND THEN
    edit_status := 'unknown_key';
    RETURN NEXT;
    RETURN;
  END IF;
  IF p_action = 'add' THEN
    INSERT INTO public.watchlist_key_state (api_key_id, last_cve_event_id)
    VALUES (caller_api_key_id, api.fn_watchlist_event_max_id())
    ON CONFLICT DO NOTHING;
  END IF;
  SELECT wks.last_key_event_id INTO caller_last_key_event_id
    FROM public.watchlist_key_state AS wks
   WHERE wks.api_key_id = caller_api_key_id FOR UPDATE;

  matched_item_ids := ARRAY(SELECT (SELECT wip.item_id
                                      FROM public.watchlist_item_package AS wip
                                     WHERE wip.api_key_id              = caller_api_key_id
                                       AND wip.ecosystem               = l.ecosystem
                                       AND wip.package_name_normalized = l.package_name_normalized
                                       AND wip.version                 IS NOT DISTINCT FROM l.version)
                              FROM unnest(listed_ecosystems, listed_names_normalized, listed_versions) WITH ORDINALITY AS l (ecosystem, package_name_normalized, version, ordinal)
                             ORDER BY l.ordinal);
  matched_count := cardinality(array_remove(matched_item_ids, NULL));

  IF p_action = 'add' THEN
    added_count     := listed_count - matched_count;
    removed_count   := 0;
    unchanged_count := matched_count;
    IF added_count > 0 THEN
      SELECT count(*), sum(api.fn_package_check_package_weight(kept.ecosystem, kept.package_name_normalized,
                                                               p_package_item_base_weight, p_listed_versions_per_weight))
        INTO package_count_after, package_weight
        FROM (SELECT wip.ecosystem, wip.package_name_normalized
                FROM public.watchlist_item_package AS wip
               WHERE wip.api_key_id = caller_api_key_id
              UNION ALL
              SELECT l.ecosystem, l.package_name_normalized
                FROM unnest(listed_ecosystems, listed_names_normalized, matched_item_ids) AS l (ecosystem, package_name_normalized, item_id)
               WHERE l.item_id IS NULL) AS kept (ecosystem, package_name_normalized);
      IF package_count_after > p_package_item_max_count THEN
        answer_status := 'over_package_limit';
      ELSIF package_weight > p_package_weight_budget THEN
        answer_status := 'over_package_weight';
      END IF;
    END IF;
    IF answer_status <> 'ok' THEN
      added_count     := 0;
      unchanged_count := 0;
    ELSIF added_count > 0 THEN
      max_event_id := api.fn_watchlist_event_max_id();
      INSERT INTO public.watchlist_event_cursor (api_key_id, previous_cursor, delivered_cursor)
      VALUES (caller_api_key_id, caller_last_key_event_id, caller_last_key_event_id)
      ON CONFLICT DO NOTHING;
      IF FOUND THEN
        UPDATE public.watchlist_key_state AS wks
           SET last_cve_event_id = greatest(wks.last_cve_event_id, max_event_id)
         WHERE wks.api_key_id = caller_api_key_id;
      END IF;
      FOR added_ordinal IN SELECT l.ordinal
                             FROM unnest(matched_item_ids) WITH ORDINALITY AS l (item_id, ordinal)
                            WHERE l.item_id IS NULL
                            ORDER BY l.ordinal LOOP
        INSERT INTO public.watchlist_item (api_key_id, endpoint_name)
        VALUES (caller_api_key_id, 'package_check')
        RETURNING watchlist_item.item_id INTO new_item_id;
        INSERT INTO public.watchlist_item_package (item_id, api_key_id, endpoint_name, last_event_id_before_add, ecosystem, package_name, version)
        VALUES (new_item_id, caller_api_key_id, 'package_check', max_event_id, listed_ecosystems[added_ordinal], p_package_names[added_ordinal],
                listed_versions[added_ordinal]);
      END LOOP;
    END IF;
  ELSE
    added_count     := 0;
    removed_count   := matched_count;
    unchanged_count := listed_count - matched_count;
    DELETE FROM public.watchlist_item AS wi WHERE wi.item_id = ANY (matched_item_ids);
    IF NOT EXISTS (SELECT 1 FROM public.watchlist_item AS wi WHERE wi.api_key_id = caller_api_key_id) THEN
      DELETE FROM public.watchlist_event_cursor AS wec WHERE wec.api_key_id = caller_api_key_id;
      UPDATE public.watchlist_key_state AS wks
         SET max_purged_key_event_id = wks.last_key_event_id
       WHERE wks.api_key_id = caller_api_key_id;
    END IF;
  END IF;

  edit_status := answer_status;
  SELECT count(*)::integer
    INTO package_item_count
    FROM public.watchlist_item AS wik
   WHERE wik.api_key_id = caller_api_key_id
     AND wik.endpoint_name = 'package_check';
  RETURN NEXT;
END
$$;

CREATE FUNCTION api.fn_watchlist_edit_ip_lookup(p_key_hash       text,
                                                p_action         text,
                                                p_ip_address     inet,
                                                p_item_max_count integer)
  RETURNS TABLE (edit_status        text,
                 endpoint_name      text,
                 ip_address         text,
                 item_count         integer,
                 package_item_count integer)
  LANGUAGE sql VOLATILE SECURITY DEFINER
  SET search_path = pg_catalog
  BEGIN ATOMIC
    SELECT edit.edit_status        AS edit_status,
           edit.endpoint_name      AS endpoint_name,
           edit.ip_address         AS ip_address,
           edit.item_count         AS item_count,
           edit.package_item_count AS package_item_count
      FROM api.fn_watchlist_item_edit(p_key_hash => p_key_hash, p_action => p_action, p_endpoint_name => 'ip_lookup', p_ip_address => p_ip_address, p_item_max_count => p_item_max_count) AS edit;
  END;

CREATE FUNCTION api.fn_watchlist_list(p_key_hash text)
  RETURNS TABLE (edit_status         text,
                 endpoint_name       text,
                 cve_id              text,
                 vendor              text,
                 product             text,
                 severity            text,
                 cwe_id              text,
                 min_cvss            real,
                 min_epss            real,
                 in_kev              boolean,
                 known_ransomware    boolean,
                 has_nuclei_template boolean,
                 product_has_cves    boolean,
                 domain_name         text,
                 ecosystem           text,
                 package_name        text,
                 version             text,
                 ip_address          text,
                 item_count          integer,
                 package_item_count  integer)
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER
  SET search_path = pg_catalog
AS $$
DECLARE
  caller_api_key_id integer;
BEGIN
  SELECT ak.id INTO caller_api_key_id FROM public.api_keys AS ak WHERE ak.key_hash = p_key_hash FOR UPDATE;
  IF NOT FOUND THEN
    edit_status := 'unknown_key';
    RETURN NEXT;
    RETURN;
  END IF;
  PERFORM 1
     FROM public.watchlist_key_state AS wks
    WHERE wks.api_key_id = caller_api_key_id FOR UPDATE;

  RETURN QUERY
    SELECT 'ok'::text                                                                        AS edit_status,
           wi.endpoint_name                                                                  AS endpoint_name,
           wic.cve_id                                                                        AS cve_id,
           wic.vendor                                                                        AS vendor,
           wic.product                                                                       AS product,
           wic.severity                                                                      AS severity,
           wic.cwe_id                                                                        AS cwe_id,
           wic.min_cvss                                                                      AS min_cvss,
           wic.min_epss                                                                      AS min_epss,
           wic.in_kev                                                                        AS in_kev,
           wic.known_ransomware                                                              AS known_ransomware,
           wic.has_nuclei_template                                                           AS has_nuclei_template,
           api.fn_watchlist_item_product_has_cves(wi.endpoint_name, wic.vendor, wic.product) AS product_has_cves,
           wid.domain_name                                                                   AS domain_name,
           wip.ecosystem                                                                     AS ecosystem,
           wip.package_name                                                                  AS package_name,
           coalesce(wip.version, wic.version)                                                AS version,
           host(wii.ip_address)                                                              AS ip_address,
           kc.item_count                                                                     AS item_count,
           kc.package_item_count                                                             AS package_item_count
      FROM (SELECT (count(*) FILTER (WHERE wik.endpoint_name <> 'package_check'))::integer AS item_count,
                   (count(*) FILTER (WHERE wik.endpoint_name = 'package_check'))::integer  AS package_item_count
              FROM public.watchlist_item AS wik
             WHERE wik.api_key_id = caller_api_key_id) AS kc
      LEFT JOIN (public.watchlist_item AS wi
                 LEFT JOIN public.watchlist_item_cve AS wic ON wic.item_id = wi.item_id
                 LEFT JOIN public.watchlist_item_domain AS wid ON wid.item_id = wi.item_id
                 LEFT JOIN public.watchlist_item_package AS wip ON wip.item_id = wi.item_id
                 LEFT JOIN public.watchlist_item_ip AS wii ON wii.item_id = wi.item_id)
             ON wi.api_key_id = caller_api_key_id
     ORDER BY wi.item_id;
END
$$;

CREATE FUNCTION api.fn_watchlist_clear(p_key_hash text)
  RETURNS TABLE (edit_status         text,
                 endpoint_name       text,
                 cve_id              text,
                 vendor              text,
                 product             text,
                 severity            text,
                 cwe_id              text,
                 min_cvss            real,
                 min_epss            real,
                 in_kev              boolean,
                 known_ransomware    boolean,
                 has_nuclei_template boolean,
                 product_has_cves    boolean,
                 domain_name         text,
                 ecosystem           text,
                 package_name        text,
                 version             text,
                 ip_address          text,
                 item_count          integer,
                 package_item_count  integer)
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER
  SET search_path = pg_catalog
AS $$
DECLARE
  caller_api_key_id integer;
BEGIN
  SELECT ak.id INTO caller_api_key_id FROM public.api_keys AS ak WHERE ak.key_hash = p_key_hash FOR UPDATE;
  IF FOUND THEN
    PERFORM 1
       FROM public.watchlist_key_state AS wks
      WHERE wks.api_key_id = caller_api_key_id FOR UPDATE;
    DELETE FROM public.watchlist_item AS wi WHERE wi.api_key_id = caller_api_key_id;
    DELETE FROM public.watchlist_event_cursor AS wec WHERE wec.api_key_id = caller_api_key_id;
    UPDATE public.watchlist_key_state AS wks
       SET max_purged_key_event_id = wks.last_key_event_id
     WHERE wks.api_key_id = caller_api_key_id;
  END IF;
  RETURN QUERY
    SELECT wl.edit_status         AS edit_status,
           wl.endpoint_name       AS endpoint_name,
           wl.cve_id              AS cve_id,
           wl.vendor              AS vendor,
           wl.product             AS product,
           wl.severity            AS severity,
           wl.cwe_id              AS cwe_id,
           wl.min_cvss            AS min_cvss,
           wl.min_epss            AS min_epss,
           wl.in_kev              AS in_kev,
           wl.known_ransomware    AS known_ransomware,
           wl.has_nuclei_template AS has_nuclei_template,
           wl.product_has_cves    AS product_has_cves,
           wl.domain_name         AS domain_name,
           wl.ecosystem           AS ecosystem,
           wl.package_name        AS package_name,
           wl.version             AS version,
           wl.ip_address          AS ip_address,
           wl.item_count          AS item_count,
           wl.package_item_count  AS package_item_count
      FROM api.fn_watchlist_list(p_key_hash) AS wl;
END
$$;

CREATE FUNCTION api.fn_watchlist_event_shown_type(p_event_type text, p_previous_value real, p_current_value real)
  RETURNS text
  LANGUAGE sql IMMUTABLE SECURITY INVOKER
  SET search_path = pg_catalog
  RETURN CASE
           WHEN p_event_type <> 'epss_changed' THEN p_event_type
           WHEN p_current_value > p_previous_value THEN 'epss_above_min'
           ELSE 'epss_below_min'
         END;

CREATE FUNCTION api.fn_watchlist_event_item_pairs(p_api_key_id integer, p_event_ids bigint[])
  RETURNS TABLE (event_id bigint,
                 item_id  bigint)
  LANGUAGE sql STABLE SECURITY INVOKER
  SET search_path = pg_catalog
  BEGIN ATOMIC
    WITH caller_watchlist_items AS MATERIALIZED (
      SELECT wic.item_id, wic.endpoint_name, wic.last_event_id_before_add, wic.cve_id, wic.vendor, wic.product, wic.severity,
             wic.cwe_id, wic.min_cvss, wic.min_epss, wic.in_kev, wic.known_ransomware, wic.has_nuclei_template,
             api.fn_watchlist_endpoint_event_types(wic.endpoint_name) AS event_types
        FROM public.watchlist_item_cve AS wic
       WHERE wic.api_key_id = p_api_key_id),
    cve_event AS MATERIALIZED (
      SELECT cce.event_id, cce.cve_id, cce.event_type, shown.event_type AS shown_event_type, cce.previous_value, cce.current_value,
             cce.vendor, cce.product, c.severity, c.cwe_id, c.in_kev, effective.cvss, c.epss_score, c.has_nuclei_template,
             kd.known_ransomware_use
        FROM public.cve_change_event AS cce
        JOIN public.cves AS c ON c.cve_id = cce.cve_id
        LEFT JOIN public.kev_details AS kd ON kd.cve_id = cce.cve_id
        CROSS JOIN LATERAL (SELECT CASE WHEN c.cvss_v3_vector <> '' THEN c.cvss_v3 ELSE c.cvss_v4 END) AS effective (cvss)
        CROSS JOIN LATERAL (SELECT api.fn_watchlist_event_shown_type(cce.event_type, cce.previous_value, cce.current_value)) AS shown (event_type)
       WHERE cce.event_id = ANY (p_event_ids)),
    scan_product AS MATERIALIZED (
      SELECT ce.event_id, ce.vendor, ce.product
        FROM cve_event AS ce
       WHERE ce.vendor IS NOT NULL
      UNION ALL
      SELECT ce.event_id, cp.vendor, cp.product
        FROM cve_event AS ce
        JOIN public.cve_products AS cp ON cp.cve_id = ce.cve_id AND cp.is_vulnerable
       WHERE ce.vendor IS NULL),
    item_product_event AS (
      SELECT sp.event_id, wi.item_id
        FROM scan_product AS sp
        JOIN caller_watchlist_items AS wi ON wi.vendor = sp.vendor AND (wi.product IS NULL OR wi.product = sp.product)
      UNION
      SELECT sp.event_id, wi.item_id
        FROM scan_product AS sp
        JOIN caller_watchlist_items AS wi ON wi.vendor IS NULL AND wi.product = sp.product),
    cve_pair AS (
      SELECT ce.event_id, wi.item_id
        FROM cve_event AS ce
        JOIN caller_watchlist_items AS wi ON ce.event_id > wi.last_event_id_before_add AND ce.shown_event_type = ANY (wi.event_types)
        CROSS JOIN LATERAL (SELECT (ce.event_id, wi.item_id) IN (SELECT ipe.event_id, ipe.item_id FROM item_product_event AS ipe)) AS item_product (is_event_product)
        CROSS JOIN LATERAL (SELECT coalesce(least(ce.previous_value, ce.current_value)::numeric < wi.min_epss::numeric
                                            AND wi.min_epss::numeric <= greatest(ce.previous_value, ce.current_value)::numeric,
                                            false)) AS min_epss_crossing (is_crossed)
       WHERE CASE
               WHEN wi.endpoint_name IN ('cve_lookup', 'kev_lookup', 'cve_exploit')
                 THEN wi.cve_id = ce.cve_id
               WHEN wi.endpoint_name = 'product_exposure'
                 THEN item_product.is_event_product
               WHEN wi.endpoint_name = 'cve_search'
                 THEN (wi.severity IS NULL OR wi.severity = ce.severity)
                      AND (wi.cwe_id IS NULL OR wi.cwe_id = ce.cwe_id)
                      AND (wi.in_kev IS NULL OR wi.in_kev = ce.in_kev)
                      AND (wi.min_cvss IS NULL OR wi.min_cvss <= ce.cvss)
                      AND CASE
                            WHEN ce.shown_event_type IN ('epss_above_min', 'epss_below_min')
                              THEN min_epss_crossing.is_crossed
                            ELSE wi.min_epss IS NULL OR wi.min_epss <= ce.epss_score
                          END
                      AND NOT (ce.event_type IN ('epss_level_up', 'epss_level_down')
                               AND wi.min_epss::numeric = ANY (public.fn_epss_level_scores())
                               AND min_epss_crossing.is_crossed)
                      AND (wi.known_ransomware IS NULL OR ce.known_ransomware_use)
                      AND (wi.has_nuclei_template IS NULL OR ce.has_nuclei_template)
                      AND ((wi.vendor IS NULL AND wi.product IS NULL) OR item_product.is_event_product)
               ELSE false
             END)

    SELECT cp.event_id AS event_id,
           cp.item_id  AS item_id
      FROM cve_pair AS cp;
  END;

CREATE FUNCTION api.fn_watchlist_event_package_pairs(p_api_key_id integer, p_event_ids bigint[])
  RETURNS TABLE (event_id        bigint,
                 item_id         bigint,
                 affects_version boolean)
  LANGUAGE sql STABLE SECURITY INVOKER
  SET search_path = pg_catalog
  BEGIN ATOMIC
    WITH caller_package_item AS MATERIALIZED (
      SELECT wip.item_id, wip.last_event_id_before_add, wip.ecosystem, wip.package_name_normalized, wip.version
        FROM public.watchlist_item_package AS wip
       WHERE wip.api_key_id = p_api_key_id),
    package_event AS MATERIALIZED (
      SELECT pae.event_id, pae.event_type, pae.advisory_id, pae.ecosystem, pae.package_name_normalized
        FROM public.package_advisory_change_event AS pae
       WHERE pae.event_id = ANY (p_event_ids) AND pae.event_type = ANY (api.fn_watchlist_endpoint_event_types('package_check'))),
    alias_event AS MATERIALIZED (
      SELECT cce.event_id, cce.event_type, cce.cve_id
        FROM public.cve_change_event AS cce
       WHERE cce.event_id = ANY (p_event_ids) AND cce.event_type = ANY (api.fn_watchlist_endpoint_event_types('package_check'))),
    item_alias AS (
      SELECT wi.item_id, osvaf.advisory_id, alias.id AS cve_id
        FROM caller_package_item AS wi
        JOIN public.osv_affected AS osvaf ON osvaf.ecosystem = wi.ecosystem AND osvaf.package_name_normalized = wi.package_name_normalized
        JOIN public.osv_advisories AS osva ON osva.advisory_id = osvaf.advisory_id
        CROSS JOIN LATERAL unnest(osva.aliases) AS alias (id)
       WHERE alias.id IN (SELECT ae.cve_id FROM alias_event AS ae)),
    matched_pair AS (
      SELECT pe.event_id, wi.item_id, pe.advisory_id
        FROM package_event AS pe
        JOIN caller_package_item AS wi
          ON wi.ecosystem = pe.ecosystem AND wi.package_name_normalized = pe.package_name_normalized
         AND pe.event_id > wi.last_event_id_before_add
      UNION
      SELECT ae.event_id, wi.item_id, ia.advisory_id
        FROM alias_event AS ae
        JOIN item_alias AS ia ON ia.cve_id = ae.cve_id
        JOIN caller_package_item AS wi ON wi.item_id = ia.item_id AND ae.event_id > wi.last_event_id_before_add),
    checked_item AS MATERIALIZED (
      SELECT wi.item_id, wi.ecosystem, wi.package_name_normalized, wi.version
        FROM caller_package_item AS wi
       WHERE wi.version IS NOT NULL AND wi.item_id IN (SELECT mp.item_id FROM matched_pair AS mp)),
    version_check AS (
      SELECT ci.item_id, adv.advisory_id, adv.affects_version
        FROM checked_item AS ci
        CROSS JOIN LATERAL api.fn_package_check_advisory(ci.ecosystem, ci.package_name_normalized, ci.version) AS adv)

    SELECT mp.event_id                                            AS event_id,
           mp.item_id                                             AS item_id,
           CASE WHEN bool_or(vc.affects_version) THEN true END    AS affects_version
      FROM matched_pair AS mp
      LEFT JOIN version_check AS vc ON vc.item_id = mp.item_id AND vc.advisory_id = mp.advisory_id
     GROUP BY mp.event_id, mp.item_id
    HAVING NOT bool_and(vc.affects_version IS FALSE);
  END;

CREATE FUNCTION api.fn_watchlist_event_eol_pairs(p_api_key_id integer, p_event_ids bigint[])
  RETURNS TABLE (event_id bigint,
                 item_id  bigint)
  LANGUAGE sql STABLE SECURITY INVOKER
  SET search_path = pg_catalog
  BEGIN ATOMIC
    WITH caller_eol_item AS MATERIALIZED (
      SELECT wic.item_id, wic.endpoint_name, wic.last_event_id_before_add, wic.version, pick.eol_product,
             public.fn_eol_pick_series(pick.eol_product, pick.series, wic.version) AS series
        FROM public.watchlist_item_cve AS wic
        CROSS JOIN LATERAL public.fn_eol_product_cpe_pick(wic.vendor, wic.product) AS pick
       WHERE wic.api_key_id = p_api_key_id AND wic.endpoint_name = 'product_exposure'
      UNION ALL
      SELECT wip.item_id, wip.endpoint_name, wip.last_event_id_before_add, wip.version, pick.eol_product,
             public.fn_eol_pick_series(pick.eol_product, NULL, wip.version) AS series
        FROM public.watchlist_item_package AS wip
        CROSS JOIN LATERAL public.fn_eol_product_package_pick(wip.ecosystem, wip.package_name_normalized) AS pick
       WHERE wip.api_key_id = p_api_key_id),
    eol_event AS MATERIALIZED (
      SELECT ece.event_id, ece.event_type, ece.eol_product, ece.cycle_name
        FROM public.eol_change_event AS ece
       WHERE ece.event_id = ANY (p_event_ids))

    SELECT ee.event_id AS event_id,
           wi.item_id  AS item_id
      FROM eol_event AS ee
      JOIN caller_eol_item AS wi ON wi.eol_product = ee.eol_product AND ee.event_id > wi.last_event_id_before_add
     WHERE ee.event_type = ANY (api.fn_watchlist_endpoint_event_types(wi.endpoint_name))
       AND CASE WHEN wi.series IS NOT NULL THEN public.fn_eol_cycle_is_in_series(wi.series, ee.cycle_name)
                ELSE wi.version IS NULL END;
  END;

CREATE FUNCTION api.fn_watchlist_event_scan(p_api_key_id      integer,
                                            p_after_event_id  bigint,
                                            p_head_event_id   bigint,
                                            p_event_row_count integer,
                                            p_scan_row_count  integer,
                                            p_pair_row_count  integer)
  RETURNS TABLE (scanned_event_count   bigint,
                 scan_end_event_id     bigint,
                 page_event_ids        bigint[],
                 page_item_ids         bigint[],
                 page_pending_flags    boolean[],
                 page_affects_versions boolean[],
                 is_page_full          boolean)
  LANGUAGE sql STABLE SECURITY INVOKER
  SET search_path = pg_catalog
  BEGIN ATOMIC
    WITH scan_window AS (
      SELECT window_event.event_id
        FROM ((SELECT cce.event_id
                 FROM public.cve_change_event AS cce
                WHERE cce.event_id > greatest(p_after_event_id,
                                              (SELECT cps.max_purged_event_id FROM public.change_event_purge_state AS cps WHERE cps.event_table_name = 'cve_change_event'))
                  AND cce.event_id <= p_head_event_id
                ORDER BY cce.event_id
                LIMIT p_scan_row_count)
              UNION ALL
              (SELECT pae.event_id
                 FROM public.package_advisory_change_event AS pae
                WHERE pae.event_id > greatest(p_after_event_id,
                                              (SELECT pps.max_purged_event_id FROM public.change_event_purge_state AS pps WHERE pps.event_table_name = 'package_advisory_change_event'))
                  AND pae.event_id <= p_head_event_id
                ORDER BY pae.event_id
                LIMIT p_scan_row_count)
              UNION ALL
              (SELECT ece.event_id
                 FROM public.eol_change_event AS ece
                WHERE ece.event_id > greatest(p_after_event_id,
                                              (SELECT eps.max_purged_event_id FROM public.change_event_purge_state AS eps WHERE eps.event_table_name = 'eol_change_event'))
                  AND ece.event_id <= p_head_event_id
                ORDER BY ece.event_id
                LIMIT p_scan_row_count)) AS window_event
       ORDER BY window_event.event_id
       LIMIT p_scan_row_count),
    scan_end AS (
      SELECT count(*)                                                                             AS scanned_event_count,
             CASE WHEN count(*) = p_scan_row_count THEN max(sw.event_id) ELSE p_head_event_id END AS end_event_id
        FROM scan_window AS sw),
    candidate AS (
      SELECT pair.event_id, pair.item_id, false AS is_pending, NULL::boolean AS affects_version
        FROM api.fn_watchlist_event_item_pairs(p_api_key_id, ARRAY(SELECT sw.event_id FROM scan_window AS sw)) AS pair
      UNION ALL
      SELECT pair.event_id, pair.item_id, false AS is_pending, pair.affects_version
        FROM api.fn_watchlist_event_package_pairs(p_api_key_id, ARRAY(SELECT sw.event_id FROM scan_window AS sw)) AS pair
      UNION ALL
      SELECT pair.event_id, pair.item_id, false AS is_pending, NULL::boolean AS affects_version
        FROM api.fn_watchlist_event_eol_pairs(p_api_key_id, ARRAY(SELECT sw.event_id FROM scan_window AS sw)) AS pair
      UNION ALL
      SELECT wer.event_id, wer.item_id, true AS is_pending, NULL::boolean AS affects_version
        FROM public.watchlist_event_ref AS wer
       WHERE wer.api_key_id = p_api_key_id
         AND wer.key_event_id IS NULL
         AND wer.event_id = ANY (ARRAY(SELECT pending.event_id
                                         FROM public.watchlist_event_ref AS pending
                                        WHERE pending.api_key_id BETWEEN p_api_key_id AND p_api_key_id
                                          AND pending.key_event_id IS NULL
                                          AND pending.event_id <= (SELECT se.end_event_id FROM scan_end AS se)
                                        GROUP BY pending.api_key_id, pending.event_id
                                        ORDER BY pending.api_key_id, pending.event_id
                                        LIMIT p_event_row_count + 1))),
    candidate_event AS (
      SELECT c.event_id                               AS event_id,
             row_number() OVER (ORDER BY c.event_id)  AS event_number,
             sum(count(*)) OVER (ORDER BY c.event_id) AS running_pair_count
        FROM candidate AS c
       GROUP BY c.event_id),
    page_pair AS (
      SELECT c.event_id, c.item_id, c.is_pending, c.affects_version
        FROM candidate AS c
        JOIN candidate_event AS ce ON ce.event_id = c.event_id
       WHERE ce.event_number <= p_event_row_count AND ce.running_pair_count <= p_pair_row_count)

    SELECT se.scanned_event_count                                                                       AS scanned_event_count,
           se.end_event_id                                                                              AS scan_end_event_id,
           (SELECT array_agg(pp.event_id ORDER BY pp.event_id, pp.item_id) FROM page_pair AS pp)        AS page_event_ids,
           (SELECT array_agg(pp.item_id ORDER BY pp.event_id, pp.item_id) FROM page_pair AS pp)         AS page_item_ids,
           (SELECT array_agg(pp.is_pending ORDER BY pp.event_id, pp.item_id) FROM page_pair AS pp)      AS page_pending_flags,
           (SELECT array_agg(pp.affects_version ORDER BY pp.event_id, pp.item_id) FROM page_pair AS pp) AS page_affects_versions,
           (SELECT count(*) FROM candidate) > (SELECT count(*) FROM page_pair)                          AS is_page_full
      FROM scan_end AS se
     WHERE p_event_row_count IS NOT NULL AND p_scan_row_count IS NOT NULL AND p_pair_row_count IS NOT NULL;
  END;

CREATE FUNCTION api.fn_watchlist_cve_facts(p_cve_id text)
  RETURNS TABLE (risk_score               double precision,
                 risk_label               text,
                 in_kev                   boolean,
                 kev_patch_deadline       text,
                 kev_known_ransomware     boolean,
                 has_metasploit           boolean,
                 poc_count                integer)
  LANGUAGE sql STABLE SECURITY INVOKER
  SET search_path = pg_catalog
  BEGIN ATOMIC
    SELECT scored.risk_score                        AS risk_score,
           api.fn_cve_risk_label(scored.risk_score) AS risk_label,
           c.in_kev                                 AS in_kev,
           kd.patch_deadline                        AS kev_patch_deadline,
           coalesce(kd.known_ransomware_use, false) AS kev_known_ransomware,
           c.has_metasploit                         AS has_metasploit,
           c.poc_count                              AS poc_count
      FROM public.cves AS c
      CROSS JOIN LATERAL (SELECT CASE WHEN c.cvss_v3_vector <> '' THEN c.cvss_v3 ELSE c.cvss_v4 END) AS effective (cvss)
      CROSS JOIN LATERAL (SELECT api.fn_cve_risk_score(effective.cvss, c.epss_score, c.in_kev, c.has_metasploit, c.exploit_ref_count, c.has_exploitdb)) AS scored (risk_score)
      LEFT JOIN public.kev_details AS kd ON kd.cve_id = c.cve_id
     WHERE c.cve_id = p_cve_id;
  END;

CREATE FUNCTION api.fn_watchlist_event_rows(p_api_key_id integer, p_after_key_event_id bigint, p_last_key_event_id bigint)
  RETURNS TABLE (item_id                       bigint,
                 item_endpoint_name            text,
                 item_cve_id                   text,
                 item_vendor                   text,
                 item_product                  text,
                 item_severity                 text,
                 item_cwe_id                   text,
                 item_min_cvss                 real,
                 item_min_epss                 real,
                 item_in_kev                   boolean,
                 item_known_ransomware         boolean,
                 item_has_nuclei_template      boolean,
                 item_product_has_cves         boolean,
                 item_domain_name              text,
                 item_ecosystem                text,
                 item_package_name             text,
                 item_version                  text,
                 item_ip_address               text,
                 event_rank                    integer,
                 is_first_row_of_event         boolean,
                 event_type                    text,
                 changed_at                    text,
                 cve_id                        text,
                 previous_value                real,
                 current_value                 real,
                 vendor                        text,
                 product                       text,
                 degraded_email_check_id       text,
                 previous_domain_value         text,
                 current_domain_value          text,
                 is_first_event_of_cve         boolean,
                 risk_score                    double precision,
                 risk_label                    text,
                 in_kev                        boolean,
                 kev_patch_deadline            text,
                 kev_known_ransomware          boolean,
                 has_metasploit                boolean,
                 poc_count                     integer,
                 is_first_event_of_domain      boolean,
                 registered_domain             text,
                 dns_presence_value            text,
                 ns_value                      text,
                 mx_value                      text,
                 ip_address_reachability_value text,
                 cname_takeover_value          text,
                 email_auth_value              text,
                 advisory_id                   text,
                 fixed_version                 text,
                 previous_ip_value             text,
                 current_ip_value              text,
                 drop_list_time                text,
                 drop_copyright                text,
                 eol_product                   text,
                 eol_cycle                     text,
                 eol_date                      text,
                 previous_eol_date             text,
                 affects_version               boolean,
                 is_first_event_of_advisory    boolean,
                 advisory_source               text,
                 advisory_aliases              jsonb,
                 advisory_cve_facts            jsonb,
                 attribution                   jsonb)
  LANGUAGE sql STABLE SECURITY INVOKER
  SET search_path = pg_catalog
  BEGIN ATOMIC
    WITH page_ref AS (
      SELECT wer.event_id, wer.item_id, wer.key_event_id, wer.affects_version
        FROM public.watchlist_event_ref AS wer
       WHERE wer.api_key_id = p_api_key_id
         AND wer.key_event_id > p_after_key_event_id
         AND wer.key_event_id <= p_last_key_event_id),
    page_event AS (
      SELECT cce.event_id, api.fn_watchlist_event_shown_type(cce.event_type, cce.previous_value, cce.current_value) AS event_type,
             cce.changed_at, cce.cve_id, NULL::text AS domain_name, cce.previous_value, cce.current_value, cce.vendor, cce.product,
             NULL::text AS degraded_email_check_id, NULL::text AS previous_domain_value, NULL::text AS current_domain_value,
             NULL::text AS advisory_id, NULL::text AS fixed_version, NULL::text AS previous_ip_value, NULL::text AS current_ip_value,
             NULL::timestamptz AS drop_list_time, NULL::text AS drop_copyright, NULL::text AS eol_product, NULL::text AS eol_cycle,
             NULL::date AS eol_date, NULL::date AS previous_eol_date
        FROM public.cve_change_event AS cce
       WHERE cce.event_id IN (SELECT pr.event_id FROM page_ref AS pr)
      UNION ALL
      SELECT dce.event_id, dce.event_type, dce.changed_at, NULL, dce.domain_name, NULL, NULL,
             NULL, NULL, dce.degraded_email_check_id, dce.previous_value, dce.current_value, NULL, NULL,
             NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
        FROM public.domain_change_event AS dce
       WHERE dce.event_id IN (SELECT pr.event_id FROM page_ref AS pr)
      UNION ALL
      SELECT pae.event_id, pae.event_type, pae.changed_at, NULL, NULL, NULL, NULL,
             NULL, NULL, NULL, NULL, NULL, pae.advisory_id, pae.fixed_version,
             NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
        FROM public.package_advisory_change_event AS pae
       WHERE pae.event_id IN (SELECT pr.event_id FROM page_ref AS pr)
      UNION ALL
      SELECT ice.event_id, ice.event_type, ice.changed_at, NULL, NULL, NULL, NULL,
             NULL, NULL, NULL, NULL, NULL, NULL, NULL,
             ice.previous_value, ice.current_value, ice.drop_list_time, ice.drop_copyright, NULL, NULL, NULL, NULL
        FROM public.ip_change_event AS ice
       WHERE ice.event_id IN (SELECT pr.event_id FROM page_ref AS pr)
      UNION ALL
      SELECT ece.event_id, ece.event_type, ece.changed_at, NULL, NULL, NULL, NULL,
             NULL, NULL, NULL, NULL, NULL, NULL, NULL,
             NULL, NULL, NULL, NULL, ece.eol_product, ece.cycle_name, ece.eol_date, ece.previous_eol_date
        FROM public.eol_change_event AS ece
       WHERE ece.event_id IN (SELECT pr.event_id FROM page_ref AS pr)),
    page_pair AS (
      SELECT pr.event_id, pr.item_id, pr.key_event_id, pr.affects_version, pe.cve_id, pe.domain_name, pe.advisory_id, pe.eol_product,
             row_number() OVER (ORDER BY pr.item_id, pr.key_event_id)                 AS row_position,
             dense_rank() OVER (ORDER BY pr.key_event_id)                             AS event_rank,
             row_number() OVER (PARTITION BY pr.key_event_id ORDER BY pr.item_id) = 1 AS is_first_row_of_event,
             CASE WHEN pe.cve_id IS NOT NULL
                  THEN row_number() OVER (PARTITION BY pe.cve_id ORDER BY pr.item_id, pr.key_event_id) = 1
                  ELSE false
             END                                                                      AS is_first_event_of_cve,
             CASE WHEN pe.domain_name IS NOT NULL
                  THEN row_number() OVER (PARTITION BY pe.domain_name ORDER BY pr.item_id, pr.key_event_id) = 1
                  ELSE false
             END                                                                      AS is_first_event_of_domain,
             CASE WHEN pe.advisory_id IS NOT NULL
                  THEN row_number() OVER (PARTITION BY pe.advisory_id ORDER BY pr.item_id, pr.key_event_id) = 1
                  ELSE false
             END                                                                      AS is_first_event_of_advisory
        FROM page_ref AS pr
        JOIN page_event AS pe ON pe.event_id = pr.event_id),
    caller_item AS (
      SELECT wi.item_id, wi.endpoint_name, wic.cve_id, wic.vendor, wic.product, wic.severity, wic.cwe_id, wic.min_cvss, wic.min_epss,
             wic.in_kev, wic.known_ransomware, wic.has_nuclei_template, wid.domain_name, wip.ecosystem, wip.package_name,
             coalesce(wip.version, wic.version) AS version,
             host(wii.ip_address) AS ip_address,
             api.fn_watchlist_item_product_has_cves(wi.endpoint_name, wic.vendor, wic.product) AS product_has_cves
        FROM public.watchlist_item AS wi
        LEFT JOIN public.watchlist_item_cve AS wic ON wic.item_id = wi.item_id
        LEFT JOIN public.watchlist_item_domain AS wid ON wid.item_id = wi.item_id
        LEFT JOIN public.watchlist_item_package AS wip ON wip.item_id = wi.item_id
        LEFT JOIN public.watchlist_item_ip AS wii ON wii.item_id = wi.item_id
       WHERE wi.api_key_id = p_api_key_id),
    first_cve_fact AS (
      SELECT pp.event_id, pp.item_id, fact.*
        FROM page_pair AS pp
        CROSS JOIN LATERAL api.fn_watchlist_cve_facts(pp.cve_id) AS fact
       WHERE pp.is_first_event_of_cve),
    first_domain_fact AS (
      SELECT fd.domain_name,
             first_item.registered_domain,
             max(widv.current_value) FILTER (WHERE widv.value_kind = 'dns_presence')            AS dns_presence_value,
             max(widv.current_value) FILTER (WHERE widv.value_kind = 'ns')                      AS ns_value,
             max(widv.current_value) FILTER (WHERE widv.value_kind = 'mx')                      AS mx_value,
             max(widv.current_value) FILTER (WHERE widv.value_kind = 'ip_address_reachability') AS ip_address_reachability_value,
             max(widv.current_value) FILTER (WHERE widv.value_kind = 'cname_takeover')          AS cname_takeover_value,
             max(widv.current_value) FILTER (WHERE widv.value_kind = 'email_auth')              AS email_auth_value
        FROM (SELECT DISTINCT pp.domain_name FROM page_pair AS pp WHERE pp.is_first_event_of_domain) AS fd
        CROSS JOIN LATERAL (SELECT wid1.registered_domain
                              FROM public.watchlist_item_domain AS wid1
                             WHERE wid1.api_key_id = p_api_key_id AND wid1.domain_name = fd.domain_name
                             ORDER BY wid1.item_id
                             LIMIT 1) AS first_item
        LEFT JOIN public.watchlist_item_domain AS wid2
               ON wid2.api_key_id = p_api_key_id AND wid2.domain_name = fd.domain_name AND wid2.endpoint_name = 'dns_lookup'
        LEFT JOIN public.watchlist_item_domain_value AS widv ON widv.item_id = wid2.item_id
       GROUP BY fd.domain_name, first_item.registered_domain),
    first_advisory AS (
      SELECT pp.event_id, pp.item_id, pp.row_position, osva.source, osva.aliases
        FROM page_pair AS pp
        LEFT JOIN public.osv_advisories AS osva ON osva.advisory_id = pp.advisory_id
       WHERE pp.is_first_event_of_advisory),
    alias_cve AS (
      SELECT DISTINCT ON (alias.id)
             fa.event_id, fa.item_id, alias.id AS cve_id
        FROM first_advisory AS fa
        CROSS JOIN LATERAL unnest(fa.aliases) AS alias (id)
       WHERE alias.id NOT IN (SELECT pp.cve_id FROM page_pair AS pp WHERE pp.cve_id IS NOT NULL)
       ORDER BY alias.id, fa.row_position),
    alias_cve_fact AS (
      SELECT ac.event_id, ac.item_id,
             jsonb_agg(jsonb_build_object(
                         'cve_id',               ac.cve_id,
                         'risk_score',           fact.risk_score,
                         'risk_label',           fact.risk_label,
                         'in_kev',               fact.in_kev,
                         'kev_patch_deadline',   fact.kev_patch_deadline,
                         'kev_known_ransomware', fact.kev_known_ransomware,
                         'has_metasploit',       fact.has_metasploit,
                         'poc_count',            fact.poc_count)
                       ORDER BY ac.cve_id) AS cve_facts
        FROM alias_cve AS ac
        CROSS JOIN LATERAL api.fn_watchlist_cve_facts(ac.cve_id) AS fact
       GROUP BY ac.event_id, ac.item_id),
    advisory_entry AS (
      SELECT fa.event_id, fa.item_id, fa.source,
             coalesce(to_jsonb(fa.aliases), '[]'::jsonb) AS aliases,
             coalesce(acf.cve_facts, '[]'::jsonb)        AS cve_facts
        FROM first_advisory AS fa
        LEFT JOIN alias_cve_fact AS acf ON acf.event_id = fa.event_id AND acf.item_id = fa.item_id),
    page_attribution AS (
      SELECT coalesce(jsonb_agg(jsonb_build_object(
                                  'source',  credited.source,
                                  'license', credited.license,
                                  'url',     CASE credited.source
                                               WHEN 'ghsa'    THEN 'https://github.com/github/advisory-database'
                                               WHEN 'go'      THEN 'https://github.com/golang/vulndb'
                                               WHEN 'pysec'   THEN 'https://github.com/pypa/advisory-database'
                                               WHEN 'rustsec' THEN 'https://github.com/rustsec/advisory-db'
                                               WHEN 'mal'     THEN 'https://github.com/ossf/malicious-packages'
                                               WHEN 'endoflife.date' THEN 'https://endoflife.date'
                                             END,
                                  'notice',  CASE credited.source
                                               WHEN 'endoflife.date'
                                                 THEN 'Retrieved from endoflife.date. ContrastAPI selected the fields and matched the release cycles to the watched product. No warranty; the source does not endorse ContrastAPI.'
                                               ELSE 'Retrieved through OSV.dev. ContrastAPI selected and normalized the fields and computed affects_version and fixed_version. No warranty; the source does not endorse ContrastAPI.'
                                             END)
                                ORDER BY credited.source, credited.license),
                      '[]'::jsonb) AS attribution
        FROM (SELECT DISTINCT osva.source, osva.license
                FROM page_pair AS pp
                JOIN public.osv_advisories AS osva ON osva.advisory_id = pp.advisory_id
              UNION
              SELECT 'endoflife.date', 'MIT'
               WHERE EXISTS (SELECT 1 FROM page_pair AS pp WHERE pp.eol_product IS NOT NULL)) AS credited)

    SELECT pp.item_id                                                              AS item_id,
           ci.endpoint_name                                                        AS item_endpoint_name,
           ci.cve_id                                                               AS item_cve_id,
           ci.vendor                                                               AS item_vendor,
           ci.product                                                              AS item_product,
           ci.severity                                                             AS item_severity,
           ci.cwe_id                                                               AS item_cwe_id,
           ci.min_cvss                                                             AS item_min_cvss,
           ci.min_epss                                                             AS item_min_epss,
           ci.in_kev                                                               AS item_in_kev,
           ci.known_ransomware                                                     AS item_known_ransomware,
           ci.has_nuclei_template                                                  AS item_has_nuclei_template,
           ci.product_has_cves                                                     AS item_product_has_cves,
           ci.domain_name                                                          AS item_domain_name,
           ci.ecosystem                                                            AS item_ecosystem,
           ci.package_name                                                         AS item_package_name,
           ci.version                                                              AS item_version,
           ci.ip_address                                                           AS item_ip_address,
           pp.event_rank::integer                                                  AS event_rank,
           pp.is_first_row_of_event                                                AS is_first_row_of_event,
           pe.event_type                                                           AS event_type,
           to_char(pe.changed_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS changed_at,
           pe.cve_id                                                               AS cve_id,
           pe.previous_value                                                       AS previous_value,
           pe.current_value                                                        AS current_value,
           pe.vendor                                                               AS vendor,
           pe.product                                                              AS product,
           pe.degraded_email_check_id                                              AS degraded_email_check_id,
           pe.previous_domain_value                                                AS previous_domain_value,
           pe.current_domain_value                                                 AS current_domain_value,
           pp.is_first_event_of_cve                                                AS is_first_event_of_cve,
           cf.risk_score                                                           AS risk_score,
           cf.risk_label                                                           AS risk_label,
           cf.in_kev                                                               AS in_kev,
           cf.kev_patch_deadline                                                   AS kev_patch_deadline,
           cf.kev_known_ransomware                                                 AS kev_known_ransomware,
           cf.has_metasploit                                                       AS has_metasploit,
           cf.poc_count                                                            AS poc_count,
           pp.is_first_event_of_domain                                             AS is_first_event_of_domain,
           df.registered_domain                                                    AS registered_domain,
           df.dns_presence_value                                                   AS dns_presence_value,
           df.ns_value                                                             AS ns_value,
           df.mx_value                                                             AS mx_value,
           df.ip_address_reachability_value                                        AS ip_address_reachability_value,
           df.cname_takeover_value                                                 AS cname_takeover_value,
           df.email_auth_value                                                     AS email_auth_value,
           pe.advisory_id                                                          AS advisory_id,
           pe.fixed_version                                                        AS fixed_version,
           pe.previous_ip_value                                                    AS previous_ip_value,
           pe.current_ip_value                                                     AS current_ip_value,
           to_char(pe.drop_list_time AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS drop_list_time,
           pe.drop_copyright                                                       AS drop_copyright,
           pe.eol_product                                                          AS eol_product,
           pe.eol_cycle                                                            AS eol_cycle,
           to_char(pe.eol_date, 'YYYY-MM-DD')                                      AS eol_date,
           to_char(pe.previous_eol_date, 'YYYY-MM-DD')                             AS previous_eol_date,
           pp.affects_version                                                      AS affects_version,
           pp.is_first_event_of_advisory                                           AS is_first_event_of_advisory,
           ae.source                                                               AS advisory_source,
           ae.aliases                                                              AS advisory_aliases,
           ae.cve_facts                                                            AS advisory_cve_facts,
           pa.attribution                                                          AS attribution
      FROM page_pair AS pp
      JOIN caller_item AS ci ON ci.item_id = pp.item_id
      CROSS JOIN page_attribution AS pa
      LEFT JOIN page_event AS pe ON pe.event_id = pp.event_id AND pp.is_first_row_of_event
      LEFT JOIN first_cve_fact AS cf ON cf.event_id = pp.event_id AND cf.item_id = pp.item_id
      LEFT JOIN first_domain_fact AS df ON df.domain_name = pp.domain_name AND pp.is_first_event_of_domain
      LEFT JOIN advisory_entry AS ae ON ae.event_id = pp.event_id AND ae.item_id = pp.item_id
     ORDER BY pp.item_id, pp.key_event_id;
  END;

CREATE FUNCTION api.fn_watchlist_events(p_key_hash            text,
                                        p_replay_cursor       bigint,
                                        p_is_repeat_requested boolean,
                                        p_event_row_count     integer,
                                        p_scan_row_count      integer,
                                        p_pair_row_count      integer)
  RETURNS TABLE (events_status                 text,
                 next_cursor                   bigint,
                 has_more                      boolean,
                 item_id                       bigint,
                 item_endpoint_name            text,
                 item_cve_id                   text,
                 item_vendor                   text,
                 item_product                  text,
                 item_severity                 text,
                 item_cwe_id                   text,
                 item_min_cvss                 real,
                 item_min_epss                 real,
                 item_in_kev                   boolean,
                 item_known_ransomware         boolean,
                 item_has_nuclei_template      boolean,
                 item_product_has_cves         boolean,
                 item_domain_name              text,
                 item_ecosystem                text,
                 item_package_name             text,
                 item_version                  text,
                 item_ip_address               text,
                 event_rank                    integer,
                 is_first_row_of_event         boolean,
                 event_type                    text,
                 changed_at                    text,
                 cve_id                        text,
                 previous_value                real,
                 current_value                 real,
                 vendor                        text,
                 product                       text,
                 degraded_email_check_id       text,
                 previous_domain_value         text,
                 current_domain_value          text,
                 is_first_event_of_cve         boolean,
                 risk_score                    double precision,
                 risk_label                    text,
                 in_kev                        boolean,
                 kev_patch_deadline            text,
                 kev_known_ransomware          boolean,
                 has_metasploit                boolean,
                 poc_count                     integer,
                 is_first_event_of_domain      boolean,
                 registered_domain             text,
                 dns_presence_value            text,
                 ns_value                      text,
                 mx_value                      text,
                 ip_address_reachability_value text,
                 cname_takeover_value          text,
                 email_auth_value              text,
                 advisory_id                   text,
                 fixed_version                 text,
                 previous_ip_value             text,
                 current_ip_value              text,
                 drop_list_time                text,
                 drop_copyright                text,
                 eol_product                   text,
                 eol_cycle                     text,
                 eol_date                      text,
                 previous_eol_date             text,
                 affects_version               boolean,
                 is_first_event_of_advisory    boolean,
                 advisory_source               text,
                 advisory_aliases              jsonb,
                 advisory_cve_facts            jsonb,
                 attribution                   jsonb)
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER
  SET search_path = pg_catalog
AS $$
DECLARE
  caller_api_key_id              integer;
  caller_last_key_event_id       bigint;
  caller_max_purged_key_event_id bigint;
  caller_last_cve_event_id       bigint;
  cursor_previous                bigint;
  cursor_delivered               bigint;
  call_kind                      text;
  scanned_event_count            bigint;
  scan_end_event_id              bigint;
  page_event_ids                 bigint[];
  page_item_ids                  bigint[];
  page_pending_flags             boolean[];
  page_affects_versions          boolean[];
  is_page_full                   boolean;
  page_event_count               integer;
  answer_status                  text := 'ok';
  answer_after_cursor            bigint;
  answer_next_cursor             bigint;
  answer_has_more                boolean;
BEGIN
  IF p_event_row_count IS NULL OR p_scan_row_count IS NULL OR p_pair_row_count IS NULL THEN
    RETURN;
  END IF;

  IF p_replay_cursor IS NOT NULL THEN
    call_kind := 'replay';
    SELECT ak.id INTO caller_api_key_id FROM public.api_keys AS ak WHERE ak.key_hash = p_key_hash;
  ELSE
    call_kind := CASE WHEN p_is_repeat_requested THEN 'repeat' ELSE 'normal' END;
    SELECT ak.id INTO caller_api_key_id FROM public.api_keys AS ak WHERE ak.key_hash = p_key_hash FOR NO KEY UPDATE;
  END IF;

  IF caller_api_key_id IS NULL THEN
    answer_status := 'unknown_key';
  ELSIF call_kind = 'replay' THEN
    SELECT wks.last_key_event_id, wks.max_purged_key_event_id, wks.last_cve_event_id
      INTO caller_last_key_event_id, caller_max_purged_key_event_id, caller_last_cve_event_id
      FROM public.watchlist_key_state AS wks
     WHERE wks.api_key_id = caller_api_key_id;
    IF p_replay_cursor BETWEEN coalesce(caller_max_purged_key_event_id, 0)
                           AND coalesce(caller_last_key_event_id, 0) THEN
      answer_after_cursor := p_replay_cursor;
    ELSE
      answer_status := 'cursor_invalid';
    END IF;
  ELSE
    SELECT wks.last_key_event_id, wks.max_purged_key_event_id, wks.last_cve_event_id
      INTO caller_last_key_event_id, caller_max_purged_key_event_id, caller_last_cve_event_id
      FROM public.watchlist_key_state AS wks
     WHERE wks.api_key_id = caller_api_key_id FOR UPDATE;
    IF FOUND THEN
      SELECT wec.previous_cursor, wec.delivered_cursor INTO cursor_previous, cursor_delivered
        FROM public.watchlist_event_cursor AS wec
       WHERE wec.api_key_id = caller_api_key_id FOR UPDATE;
    END IF;
    IF cursor_delivered IS NULL THEN
      answer_status := 'no_position';
    END IF;
  END IF;

  IF answer_status <> 'ok' THEN
    events_status := answer_status;
    has_more := false;
    attribution := '[]'::jsonb;
    RETURN NEXT;
    RETURN;
  END IF;

  IF call_kind = 'normal' THEN
    SELECT scan.scanned_event_count, scan.scan_end_event_id, scan.page_event_ids, scan.page_item_ids, scan.page_pending_flags,
           scan.page_affects_versions, scan.is_page_full
      INTO scanned_event_count, scan_end_event_id, page_event_ids, page_item_ids, page_pending_flags, page_affects_versions,
           is_page_full
      FROM api.fn_watchlist_event_scan(caller_api_key_id, caller_last_cve_event_id, api.fn_watchlist_event_max_id(), p_event_row_count,
                                       p_scan_row_count, p_pair_row_count) AS scan;
    page_event_count := (SELECT count(DISTINCT page_event.event_id) FROM unnest(page_event_ids) AS page_event (event_id));
    IF is_page_full AND page_event_count = 0 THEN
      RAISE EXCEPTION 'fn_watchlist_events refuses the page after key event %: its first event has more pairs than the bound %',
                      caller_last_key_event_id, p_pair_row_count
        USING ERRCODE = 'program_limit_exceeded';
    END IF;
    WITH page_pair AS (
      SELECT pair.event_id, pair.item_id, pair.is_pending, pair.affects_version,
             caller_last_key_event_id + dense_rank() OVER (ORDER BY pair.event_id) AS key_event_id
        FROM unnest(page_event_ids, page_item_ids, page_pending_flags, page_affects_versions)
             AS pair (event_id, item_id, is_pending, affects_version)),
    numbered_pending_ref AS (
      UPDATE public.watchlist_event_ref AS wer
         SET key_event_id = pp.key_event_id
        FROM page_pair AS pp
       WHERE pp.is_pending AND wer.item_id = pp.item_id AND wer.event_id = pp.event_id)
    INSERT INTO public.watchlist_event_ref (api_key_id, item_id, event_id, key_event_id, affects_version)
    SELECT caller_api_key_id, pp.item_id, pp.event_id, pp.key_event_id, pp.affects_version
      FROM page_pair AS pp
     WHERE NOT pp.is_pending;

    UPDATE public.watchlist_key_state AS wks
       SET last_key_event_id = caller_last_key_event_id + page_event_count,
           last_cve_event_id = CASE WHEN is_page_full
                                    THEN least(scan_end_event_id, page_event_ids[cardinality(page_event_ids)])
                                    ELSE scan_end_event_id
                               END
     WHERE wks.api_key_id = caller_api_key_id;
    UPDATE public.watchlist_event_cursor AS wec
       SET previous_cursor = cursor_delivered, delivered_cursor = caller_last_key_event_id + page_event_count
     WHERE wec.api_key_id = caller_api_key_id;
    answer_after_cursor := cursor_delivered;
    answer_next_cursor := caller_last_key_event_id + page_event_count;
    answer_has_more := is_page_full
                       OR scanned_event_count = p_scan_row_count
                       OR EXISTS (SELECT 1 FROM public.watchlist_event_ref AS wer
                                   WHERE wer.api_key_id = caller_api_key_id AND wer.key_event_id IS NULL);

  ELSIF call_kind = 'repeat' THEN
    answer_after_cursor := cursor_previous;
    answer_next_cursor := cursor_delivered;

  ELSE
    SELECT max(numbered_event.key_event_id) INTO answer_next_cursor
      FROM (SELECT key_event.key_event_id,
                   sum(key_event.pair_count) OVER (ORDER BY key_event.key_event_id) AS running_pair_count
              FROM (SELECT wer.key_event_id, count(*) AS pair_count
                      FROM public.watchlist_event_ref AS wer
                     WHERE wer.api_key_id = caller_api_key_id AND wer.key_event_id > p_replay_cursor
                     GROUP BY wer.key_event_id
                     ORDER BY wer.key_event_id
                     LIMIT p_event_row_count) AS key_event) AS numbered_event
     WHERE numbered_event.running_pair_count <= p_pair_row_count;
    IF answer_next_cursor IS NULL
       AND EXISTS (SELECT 1 FROM public.watchlist_event_ref AS wer
                    WHERE wer.api_key_id = caller_api_key_id AND wer.key_event_id > p_replay_cursor) THEN
      RAISE EXCEPTION 'fn_watchlist_events refuses the replay after key event %: its first event has more pairs than the bound %',
                      p_replay_cursor, p_pair_row_count
        USING ERRCODE = 'program_limit_exceeded';
    END IF;
    answer_next_cursor := coalesce(answer_next_cursor, p_replay_cursor);
  END IF;

  IF call_kind <> 'normal' THEN
    answer_has_more := EXISTS (SELECT 1 FROM public.watchlist_event_ref AS wer
                                WHERE wer.api_key_id = caller_api_key_id AND wer.key_event_id > answer_next_cursor)
                       OR EXISTS (SELECT 1 FROM public.watchlist_event_ref AS wer
                                   WHERE wer.api_key_id = caller_api_key_id AND wer.key_event_id IS NULL)
                       OR EXISTS (SELECT 1 FROM public.cve_change_event AS cce
                                   WHERE cce.event_id > caller_last_cve_event_id)
                       OR EXISTS (SELECT 1 FROM public.package_advisory_change_event AS pae
                                   WHERE pae.event_id > caller_last_cve_event_id)
                       OR EXISTS (SELECT 1 FROM public.eol_change_event AS ece
                                   WHERE ece.event_id > caller_last_cve_event_id);
  END IF;

  RETURN QUERY
    SELECT answer_status                     AS events_status,
           answer_next_cursor                AS next_cursor,
           answer_has_more                   AS has_more,
           wer.item_id                       AS item_id,
           wer.item_endpoint_name            AS item_endpoint_name,
           wer.item_cve_id                   AS item_cve_id,
           wer.item_vendor                   AS item_vendor,
           wer.item_product                  AS item_product,
           wer.item_severity                 AS item_severity,
           wer.item_cwe_id                   AS item_cwe_id,
           wer.item_min_cvss                 AS item_min_cvss,
           wer.item_min_epss                 AS item_min_epss,
           wer.item_in_kev                   AS item_in_kev,
           wer.item_known_ransomware         AS item_known_ransomware,
           wer.item_has_nuclei_template      AS item_has_nuclei_template,
           wer.item_product_has_cves         AS item_product_has_cves,
           wer.item_domain_name              AS item_domain_name,
           wer.item_ecosystem                AS item_ecosystem,
           wer.item_package_name             AS item_package_name,
           wer.item_version                  AS item_version,
           wer.item_ip_address               AS item_ip_address,
           wer.event_rank                    AS event_rank,
           wer.is_first_row_of_event         AS is_first_row_of_event,
           wer.event_type                    AS event_type,
           wer.changed_at                    AS changed_at,
           wer.cve_id                        AS cve_id,
           wer.previous_value                AS previous_value,
           wer.current_value                 AS current_value,
           wer.vendor                        AS vendor,
           wer.product                       AS product,
           wer.degraded_email_check_id       AS degraded_email_check_id,
           wer.previous_domain_value         AS previous_domain_value,
           wer.current_domain_value          AS current_domain_value,
           wer.is_first_event_of_cve         AS is_first_event_of_cve,
           wer.risk_score                    AS risk_score,
           wer.risk_label                    AS risk_label,
           wer.in_kev                        AS in_kev,
           wer.kev_patch_deadline            AS kev_patch_deadline,
           wer.kev_known_ransomware          AS kev_known_ransomware,
           wer.has_metasploit                AS has_metasploit,
           wer.poc_count                     AS poc_count,
           wer.is_first_event_of_domain      AS is_first_event_of_domain,
           wer.registered_domain             AS registered_domain,
           wer.dns_presence_value            AS dns_presence_value,
           wer.ns_value                      AS ns_value,
           wer.mx_value                      AS mx_value,
           wer.ip_address_reachability_value AS ip_address_reachability_value,
           wer.cname_takeover_value          AS cname_takeover_value,
           wer.email_auth_value              AS email_auth_value,
           wer.advisory_id                   AS advisory_id,
           wer.fixed_version                 AS fixed_version,
           wer.previous_ip_value             AS previous_ip_value,
           wer.current_ip_value              AS current_ip_value,
           wer.drop_list_time                AS drop_list_time,
           wer.drop_copyright                AS drop_copyright,
           wer.eol_product                   AS eol_product,
           wer.eol_cycle                     AS eol_cycle,
           wer.eol_date                      AS eol_date,
           wer.previous_eol_date             AS previous_eol_date,
           wer.affects_version               AS affects_version,
           wer.is_first_event_of_advisory    AS is_first_event_of_advisory,
           wer.advisory_source               AS advisory_source,
           wer.advisory_aliases              AS advisory_aliases,
           wer.advisory_cve_facts            AS advisory_cve_facts,
           wer.attribution                   AS attribution
      FROM api.fn_watchlist_event_rows(caller_api_key_id, answer_after_cursor, answer_next_cursor) AS wer
     ORDER BY wer.item_id, wer.event_rank;
  IF NOT FOUND THEN
    events_status := answer_status;
    next_cursor   := answer_next_cursor;
    has_more      := answer_has_more;
    attribution   := '[]'::jsonb;
    RETURN NEXT;
  END IF;
END
$$;

CREATE FUNCTION api.fn_watchlist_event_ref_purge(p_event_ids bigint[], p_is_scanned_after_last_cve_event_id boolean)
  RETURNS integer
  LANGUAGE plpgsql VOLATILE STRICT SECURITY INVOKER
  SET search_path = pg_catalog
AS $$
DECLARE
  purged_ref_count integer;
BEGIN
  PERFORM 1
     FROM public.watchlist_key_state AS wks
    WHERE wks.api_key_id IN (SELECT wer.api_key_id FROM public.watchlist_event_ref AS wer WHERE wer.event_id = ANY (p_event_ids))
       OR (p_is_scanned_after_last_cve_event_id
           AND wks.last_cve_event_id < (SELECT max(picked.event_id) FROM unnest(p_event_ids) AS picked (event_id)))
    ORDER BY wks.api_key_id
     FOR UPDATE;

  WITH purged_ref AS (
    DELETE FROM public.watchlist_event_ref AS wer
     WHERE wer.event_id = ANY (p_event_ids)
    RETURNING wer.api_key_id, wer.key_event_id),
  lost AS (
    SELECT pr.api_key_id, max(pr.key_event_id) AS max_key_event_id
      FROM purged_ref AS pr
     GROUP BY pr.api_key_id),
  raised AS (
    UPDATE public.watchlist_key_state AS wks
       SET max_purged_key_event_id = lost.max_key_event_id
      FROM lost
     WHERE wks.api_key_id = lost.api_key_id
       AND wks.max_purged_key_event_id < lost.max_key_event_id)
  SELECT count(*)::integer INTO purged_ref_count FROM purged_ref;
  RETURN purged_ref_count;
END
$$;

CREATE FUNCTION api.fn_watchlist_purge(p_key_row_count integer)
  RETURNS integer
  LANGUAGE plpgsql VOLATILE STRICT SECURITY DEFINER
  SET search_path = pg_catalog
AS $$
DECLARE
  expired_key_ids integer[];
BEGIN
  expired_key_ids := ARRAY(SELECT ak.id
                             FROM public.api_keys AS ak
                            WHERE ak.expires_at < now() - interval '30 days'
                              AND (EXISTS (SELECT 1 FROM public.watchlist_item AS wi WHERE wi.api_key_id = ak.id)
                                   OR EXISTS (SELECT 1 FROM public.watchlist_event_cursor AS wec WHERE wec.api_key_id = ak.id))
                            ORDER BY ak.id
                            LIMIT p_key_row_count);

  PERFORM 1
     FROM public.watchlist_key_state AS wks
    WHERE wks.api_key_id = ANY (expired_key_ids)
    ORDER BY wks.api_key_id
     FOR UPDATE;

  UPDATE public.watchlist_key_state AS wks
     SET max_purged_key_event_id = wks.last_key_event_id
   WHERE wks.api_key_id = ANY (expired_key_ids);
  DELETE FROM public.watchlist_item AS wi WHERE wi.api_key_id = ANY (expired_key_ids);
  DELETE FROM public.watchlist_event_cursor AS wec WHERE wec.api_key_id = ANY (expired_key_ids);
  RETURN cardinality(expired_key_ids);
END
$$;
