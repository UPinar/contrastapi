ALTER DEFAULT PRIVILEGES FOR ROLE "contrastapi-owner" REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
GRANT USAGE ON SCHEMA api TO "contrastapi-api", "contrastapi-web";
DO $$
BEGIN
  EXECUTE format('REVOKE TEMPORARY ON DATABASE %I FROM PUBLIC', current_database());
  EXECUTE format('GRANT TEMPORARY ON DATABASE %I TO "contrastapi-owner"', current_database());
  EXECUTE format('GRANT CONNECT ON DATABASE %I TO "contrastapi-api", "contrastapi-sync", "contrastapi-web"', current_database());
END
$$;
DO $$
DECLARE
  api_role_functions text[] := ARRAY[
    'api.fn_api_key_state',
    'api.fn_asn_lookup',
    'api.fn_billing_claim',
    'api.fn_billing_event_purge',
    'api.fn_billing_event_record',
    'api.fn_billing_lemonsqueezy_clear_expiry',
    'api.fn_billing_lemonsqueezy_order_paid',
    'api.fn_billing_lemonsqueezy_revoke',
    'api.fn_billing_lemonsqueezy_set_expiry',
    'api.fn_billing_nowpayments_order_paid',
    'api.fn_connection_role_state',
    'api.fn_cpe_search',
    'api.fn_cpe_search_match_count',
    'api.fn_cve_change_event_purge',
    'api.fn_cve_exploit_exploitdb',
    'api.fn_cve_exploit_exploitdb_summary',
    'api.fn_cve_exploit_github',
    'api.fn_cve_exploit_github_summary',
    'api.fn_cve_exploit_metasploit',
    'api.fn_cve_exploit_metasploit_summary',
    'api.fn_cve_exploit_nvd_refs',
    'api.fn_cve_ghsa_advisory',
    'api.fn_cve_leading',
    'api.fn_cve_leading_match_count',
    'api.fn_cve_lookup',
    'api.fn_cve_products',
    'api.fn_cve_risk_breakdown',
    'api.fn_cve_search',
    'api.fn_cve_search_match_count',
    'api.fn_cve_triage',
    'api.fn_cve_triage_bulk',
    'api.fn_cve_triage_match_count',
    'api.fn_cwe_lookup',
    'api.fn_d3fend_for_attack',
    'api.fn_domain_change_event_purge',
    'api.fn_domain_watch_claim',
    'api.fn_domain_watch_purge_unwatched',
    'api.fn_domain_watch_record_ct',
    'api.fn_domain_watch_record_dns',
    'api.fn_domain_watch_record_headers',
    'api.fn_domain_watch_record_rdap_whois',
    'api.fn_domain_watch_record_tls',
    'api.fn_driver_lookup',
    'api.fn_email_disposable_domain',
    'api.fn_eol_change_event_purge',
    'api.fn_health',
    'api.fn_ip_asn_prefix',
    'api.fn_ip_change_event_purge',
    'api.fn_ip_lookup',
    'api.fn_ip_watch_write_values',
    'api.fn_kev_lookup',
    'api.fn_package_advisory_change_event_purge',
    'api.fn_package_check',
    'api.fn_package_check_bulk',
    'api.fn_package_check_bulk_weigh',
    'api.fn_package_check_eol',
    'api.fn_product_exposure',
    'api.fn_product_exposure_eol',
    'api.fn_schema_version',
    'api.fn_ssl_blacklist_certificate',
    'api.fn_target_throttle_charge',
    'api.fn_target_throttle_load',
    'api.fn_target_throttle_purge',
    'api.fn_credit_budget_charge',
    'api.fn_credit_budget_purge',
    'api.fn_credit_budget_used',
    'api.fn_upstream_cache_get',
    'api.fn_upstream_cache_purge',
    'api.fn_upstream_cache_put',
    'api.fn_upstream_feed_status',
    'api.fn_upstream_hold_remaining_seconds',
    'api.fn_upstream_hold_set',
    'api.fn_upstream_quota_mark_exhausted',
    'api.fn_upstream_quota_purge',
    'api.fn_upstream_quota_reserve',
    'api.fn_vendor_key_apply',
    'api.fn_vendor_key_link_open',
    'api.fn_vendor_key_link_purge',
    'api.fn_vendor_key_link_read',
    'api.fn_vendor_key_purge',
    'api.fn_vendor_key_read',
    'api.fn_watchlist_clear',
    'api.fn_watchlist_edit_cert_search',
    'api.fn_watchlist_edit_cve_exploit',
    'api.fn_watchlist_edit_cve_lookup',
    'api.fn_watchlist_edit_cve_search',
    'api.fn_watchlist_edit_dns_lookup',
    'api.fn_watchlist_edit_headers_check',
    'api.fn_watchlist_edit_ip_lookup',
    'api.fn_watchlist_edit_kev_lookup',
    'api.fn_watchlist_edit_package_check',
    'api.fn_watchlist_edit_product_exposure',
    'api.fn_watchlist_edit_ssl_check',
    'api.fn_watchlist_edit_whois_lookup',
    'api.fn_watchlist_events',
    'api.fn_watchlist_list',
    'api.fn_watchlist_package_list_edit',
    'api.fn_watchlist_purge',
    'api.fn_x402_payment_mark_pending',
    'api.fn_x402_payment_mark_settled',
    'api.fn_x402_payment_purge',
    'api.fn_x402_payment_release',
    'api.fn_x402_payment_reserve'
  ];
  web_role_functions text[] := ARRAY[
    'api.fn_cve_exploit_exploitdb',
    'api.fn_cve_exploit_exploitdb_summary',
    'api.fn_cve_ghsa_advisory',
    'api.fn_cve_lookup',
    'api.fn_cwe_lookup',
    'api.fn_kev_lookup',
    'api.fn_schema_version'
  ];
  sync_role_functions text[] := '{}';
  trigger_definer_functions text[] := '{}';
  listed_function  record;
  registered_pair  record;
  audited_schemas  text[];
  schema_name      text;
  function_oid     oid;
  found_count      integer;
  offender         text;
BEGIN
  SELECT array_agg(n.nspname ORDER BY n.nspname) INTO audited_schemas
    FROM pg_namespace AS n
   WHERE n.nspname NOT LIKE 'pg\_%'
     AND n.nspname <> 'information_schema';
  FOREACH schema_name IN ARRAY audited_schemas LOOP
    EXECUTE format('REVOKE ALL ON ALL FUNCTIONS IN SCHEMA %I FROM PUBLIC', schema_name);
  END LOOP;

  api_role_functions := api_role_functions
    || coalesce((SELECT array_agg(rfg.function_name ORDER BY rfg.function_name)
                   FROM public.role_function_grant AS rfg
                  WHERE rfg.role_name = 'contrastapi-api'), '{}');
  web_role_functions := web_role_functions
    || coalesce((SELECT array_agg(rfg.function_name ORDER BY rfg.function_name)
                   FROM public.role_function_grant AS rfg
                  WHERE rfg.role_name = 'contrastapi-web'), '{}');
  sync_role_functions := sync_role_functions
    || coalesce((SELECT array_agg(rfg.function_name ORDER BY rfg.function_name)
                   FROM public.role_function_grant AS rfg
                  WHERE rfg.role_name = 'contrastapi-sync'), '{}');

  FOR listed_function IN
    SELECT f.function_name, 'contrastapi-api'::text AS role_name FROM unnest(api_role_functions) AS f (function_name)
    UNION ALL
    SELECT f.function_name, 'contrastapi-web' FROM unnest(web_role_functions) AS f (function_name)
    UNION ALL
    SELECT f.function_name, 'contrastapi-sync' FROM unnest(sync_role_functions) AS f (function_name)
    UNION ALL
    SELECT f.function_name, NULL FROM unnest(trigger_definer_functions) AS f (function_name)
  LOOP
    SELECT p.oid, count(*) OVER () INTO function_oid, found_count
      FROM pg_proc AS p
      JOIN pg_namespace AS n ON n.oid = p.pronamespace
     WHERE n.nspname = split_part(listed_function.function_name, '.', 1)
       AND p.proname = split_part(listed_function.function_name, '.', 2);
    IF NOT FOUND OR found_count <> 1 THEN
      RAISE EXCEPTION 'grants.sql: % resolves to % functions, not one', listed_function.function_name, coalesce(found_count, 0);
    END IF;
    IF listed_function.function_name LIKE 'public.%' THEN
      EXECUTE format('ALTER FUNCTION %s SECURITY DEFINER', function_oid::regprocedure);
    END IF;
    IF listed_function.role_name IS NOT NULL THEN
      EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO %I', function_oid::regprocedure, listed_function.role_name);
    END IF;
  END LOOP;

  FOR registered_pair IN
    SELECT DISTINCT rfg.role_name, split_part(rfg.function_name, '.', 1) AS schema_name
      FROM public.role_function_grant AS rfg
  LOOP
    EXECUTE format('GRANT USAGE ON SCHEMA %I TO %I', registered_pair.schema_name, registered_pair.role_name);
  END LOOP;

  SELECT p.oid::regprocedure::text INTO offender
    FROM pg_proc AS p
    JOIN pg_namespace AS n ON n.oid = p.pronamespace
   WHERE n.nspname = ANY (audited_schemas)
     AND p.proowner <> (SELECT r.oid FROM pg_roles AS r WHERE r.rolname = 'contrastapi-owner')
     AND NOT EXISTS (SELECT 1 FROM pg_depend AS d
                      WHERE d.classid = 'pg_proc'::regclass AND d.objid = p.oid AND d.deptype = 'e')
   LIMIT 1;
  IF offender IS NOT NULL THEN
    RAISE EXCEPTION 'grants.sql: % is not owned by contrastapi-owner', offender;
  END IF;

  SELECT p.oid::regprocedure::text INTO offender
    FROM pg_proc AS p
    JOIN pg_namespace AS n ON n.oid = p.pronamespace
   WHERE n.nspname = ANY (audited_schemas)
     AND (n.nspname || '.' || p.proname) = ANY (api_role_functions || web_role_functions || sync_role_functions || trigger_definer_functions)
     AND (NOT p.prosecdef OR p.proconfig IS NULL OR NOT 'search_path=pg_catalog' = ANY (p.proconfig))
   LIMIT 1;
  IF offender IS NOT NULL THEN
    RAISE EXCEPTION 'grants.sql: % is listed but is not SECURITY DEFINER with search_path pg_catalog', offender;
  END IF;

  SELECT p.oid::regprocedure::text INTO offender
    FROM pg_proc AS p
    JOIN pg_namespace AS n ON n.oid = p.pronamespace
   WHERE n.nspname = ANY (audited_schemas)
     AND NOT (n.nspname || '.' || p.proname) = ANY (api_role_functions || web_role_functions || sync_role_functions || trigger_definer_functions)
     AND p.prosecdef
   LIMIT 1;
  IF offender IS NOT NULL THEN
    RAISE EXCEPTION 'grants.sql: % is SECURITY DEFINER but in no list', offender;
  END IF;

  IF (SELECT r.rolsuper FROM pg_roles AS r WHERE r.rolname = 'contrastapi-owner') THEN
    RAISE EXCEPTION 'grants.sql: contrastapi-owner is a superuser';
  END IF;

  SELECT r.rolname INTO offender
    FROM pg_roles AS r
   WHERE r.rolname IN ('contrastapi-api', 'contrastapi-sync', 'contrastapi-web')
     AND (r.rolbypassrls OR pg_has_role(r.oid, 'contrastapi-owner', 'MEMBER'))
   LIMIT 1;
  IF offender IS NOT NULL THEN
    RAISE EXCEPTION 'grants.sql: % is a superuser, bypasses row security or is a member of contrastapi-owner', offender;
  END IF;

  SELECT r.rolname INTO offender
    FROM pg_roles AS r
   WHERE r.rolname IN ('contrastapi-api', 'contrastapi-sync', 'contrastapi-web')
     AND has_database_privilege(r.oid, current_database(), 'TEMPORARY')
   LIMIT 1;
  IF offender IS NOT NULL THEN
    RAISE EXCEPTION 'grants.sql: % holds TEMPORARY on this database', offender;
  END IF;

  IF (SELECT r.rolcanlogin FROM pg_roles AS r WHERE r.rolname = 'contrastapi-owner') THEN
    RAISE EXCEPTION 'grants.sql: contrastapi-owner can log in';
  END IF;

  SELECT r.rolname INTO offender
    FROM pg_roles AS r
   WHERE r.rolname IN ('contrastapi-owner', 'contrastapi-api', 'contrastapi-sync', 'contrastapi-web')
     AND (r.rolcreaterole OR r.rolcreatedb OR r.rolreplication OR r.rolbypassrls)
   LIMIT 1;
  IF offender IS NOT NULL THEN
    RAISE EXCEPTION 'grants.sql: % holds CREATEROLE, CREATEDB, REPLICATION or BYPASSRLS', offender;
  END IF;

  SELECT r.rolname || ' is a member of ' || pg_get_userbyid(m.roleid) INTO offender
    FROM pg_auth_members AS m
    JOIN pg_roles AS r ON r.oid = m.member
   WHERE r.rolname IN ('contrastapi-api', 'contrastapi-sync', 'contrastapi-web')
   LIMIT 1;
  IF offender IS NOT NULL THEN
    RAISE EXCEPTION 'grants.sql: %', offender;
  END IF;

  SELECT r.rolname || ' owns ' || n.nspname || '.' || c.relname INTO offender
    FROM pg_class AS c
    JOIN pg_namespace AS n ON n.oid = c.relnamespace
    JOIN pg_roles AS r ON r.oid = c.relowner
   WHERE n.nspname = ANY (audited_schemas)
     AND r.rolname IN ('contrastapi-api', 'contrastapi-sync', 'contrastapi-web')
   LIMIT 1;
  IF offender IS NOT NULL THEN
    RAISE EXCEPTION 'grants.sql: %', offender;
  END IF;

  SELECT r.rolname || ' holds a privilege on ' || n.nspname || '.' || c.relname INTO offender
    FROM pg_class AS c
    JOIN pg_namespace AS n ON n.oid = c.relnamespace
   CROSS JOIN pg_roles AS r
   WHERE n.nspname = ANY (audited_schemas)
     AND c.relkind IN ('r', 'p', 'm', 'v', 'f', 'S')
     AND r.rolname IN ('contrastapi-api', 'contrastapi-sync', 'contrastapi-web')
     AND NOT EXISTS (SELECT 1 FROM pg_depend AS d
                      WHERE d.classid = 'pg_class'::regclass AND d.objid = c.oid AND d.deptype = 'e')
     AND (EXISTS (SELECT 1 FROM aclexplode(c.relacl) AS a WHERE a.grantee IN (0, r.oid))
          OR EXISTS (SELECT 1
                       FROM pg_attribute AS col
                      CROSS JOIN LATERAL aclexplode(col.attacl) AS a
                      WHERE col.attrelid = c.oid AND a.grantee IN (0, r.oid)))
   LIMIT 1;
  IF offender IS NOT NULL THEN
    RAISE EXCEPTION 'grants.sql: %', offender;
  END IF;

  SELECT r.rolname || ' may create in ' || n.nspname INTO offender
    FROM pg_namespace AS n
   CROSS JOIN pg_roles AS r
   WHERE n.nspname = ANY (audited_schemas)
     AND r.rolname IN ('contrastapi-api', 'contrastapi-sync', 'contrastapi-web')
     AND has_schema_privilege(r.oid, n.oid, 'CREATE')
   LIMIT 1;
  IF offender IS NOT NULL THEN
    RAISE EXCEPTION 'grants.sql: %', offender;
  END IF;

  SELECT r.rolname || ' may use the schema ' || n.nspname INTO offender
    FROM pg_namespace AS n
   CROSS JOIN pg_roles AS r
   WHERE n.nspname = ANY (audited_schemas)
     AND n.nspname <> 'public'
     AND r.rolname IN ('contrastapi-api', 'contrastapi-sync', 'contrastapi-web')
     AND has_schema_privilege(r.oid, n.oid, 'USAGE')
     AND NOT (n.nspname = 'api' AND r.rolname IN ('contrastapi-api', 'contrastapi-web'))
     AND NOT (n.nspname <> 'api'
              AND EXISTS (SELECT 1 FROM public.role_function_grant AS rfg
                           WHERE rfg.role_name = r.rolname
                             AND split_part(rfg.function_name, '.', 1) = n.nspname))
   LIMIT 1;
  IF offender IS NOT NULL THEN
    RAISE EXCEPTION 'grants.sql: %', offender;
  END IF;

  SELECT r.rolname || ' may call ' || n.nspname || '.' || p.proname INTO offender
    FROM pg_proc AS p
    JOIN pg_namespace AS n ON n.oid = p.pronamespace
   CROSS JOIN pg_roles AS r
   WHERE n.nspname = ANY (audited_schemas)
     AND r.rolname IN ('contrastapi-api', 'contrastapi-sync', 'contrastapi-web')
     AND has_function_privilege(r.oid, p.oid, 'EXECUTE')
     AND NOT (n.nspname || '.' || p.proname) = ANY (CASE r.rolname
                                                      WHEN 'contrastapi-api' THEN api_role_functions
                                                      WHEN 'contrastapi-web' THEN web_role_functions
                                                      ELSE sync_role_functions
                                                    END)
   LIMIT 1;
  IF offender IS NOT NULL THEN
    RAISE EXCEPTION 'grants.sql: %, which is not in its list', offender;
  END IF;
END
$$;
