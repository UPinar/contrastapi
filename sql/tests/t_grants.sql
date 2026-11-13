CREATE TEMP TABLE t_grants_role_function (role_name text, function_name text);
INSERT INTO t_grants_role_function (role_name, function_name) VALUES
  ('contrastapi-api', 'api.fn_api_key_state'),
  ('contrastapi-api', 'api.fn_asn_lookup'),
  ('contrastapi-api', 'api.fn_billing_claim'),
  ('contrastapi-api', 'api.fn_billing_event_purge'),
  ('contrastapi-api', 'api.fn_billing_event_record'),
  ('contrastapi-api', 'api.fn_billing_lemonsqueezy_clear_expiry'),
  ('contrastapi-api', 'api.fn_billing_lemonsqueezy_order_paid'),
  ('contrastapi-api', 'api.fn_billing_lemonsqueezy_revoke'),
  ('contrastapi-api', 'api.fn_billing_lemonsqueezy_set_expiry'),
  ('contrastapi-api', 'api.fn_billing_nowpayments_order_paid'),
  ('contrastapi-api', 'api.fn_connection_role_state'),
  ('contrastapi-api', 'api.fn_cpe_search'),
  ('contrastapi-api', 'api.fn_cpe_search_match_count'),
  ('contrastapi-api', 'api.fn_cve_change_event_purge'),
  ('contrastapi-api', 'api.fn_cve_exploit_exploitdb'),
  ('contrastapi-api', 'api.fn_cve_exploit_exploitdb_summary'),
  ('contrastapi-api', 'api.fn_cve_exploit_github'),
  ('contrastapi-api', 'api.fn_cve_exploit_github_summary'),
  ('contrastapi-api', 'api.fn_cve_exploit_metasploit'),
  ('contrastapi-api', 'api.fn_cve_exploit_metasploit_summary'),
  ('contrastapi-api', 'api.fn_cve_exploit_nvd_refs'),
  ('contrastapi-api', 'api.fn_cve_ghsa_advisory'),
  ('contrastapi-api', 'api.fn_cve_leading'),
  ('contrastapi-api', 'api.fn_cve_leading_match_count'),
  ('contrastapi-api', 'api.fn_cve_lookup'),
  ('contrastapi-api', 'api.fn_cve_products'),
  ('contrastapi-api', 'api.fn_cve_risk_breakdown'),
  ('contrastapi-api', 'api.fn_cve_search'),
  ('contrastapi-api', 'api.fn_cve_search_match_count'),
  ('contrastapi-api', 'api.fn_cve_triage'),
  ('contrastapi-api', 'api.fn_cve_triage_bulk'),
  ('contrastapi-api', 'api.fn_cve_triage_match_count'),
  ('contrastapi-api', 'api.fn_cwe_lookup'),
  ('contrastapi-api', 'api.fn_d3fend_for_attack'), -- gitleaks:allow
  ('contrastapi-api', 'api.fn_domain_change_event_purge'),
  ('contrastapi-api', 'api.fn_domain_watch_claim'),
  ('contrastapi-api', 'api.fn_domain_watch_purge_unwatched'),
  ('contrastapi-api', 'api.fn_domain_watch_record_ct'),
  ('contrastapi-api', 'api.fn_domain_watch_record_dns'),
  ('contrastapi-api', 'api.fn_domain_watch_record_headers'),
  ('contrastapi-api', 'api.fn_domain_watch_record_rdap_whois'),
  ('contrastapi-api', 'api.fn_domain_watch_record_tls'),
  ('contrastapi-api', 'api.fn_driver_lookup'),
  ('contrastapi-api', 'api.fn_email_disposable_domain'),
  ('contrastapi-api', 'api.fn_eol_change_event_purge'),
  ('contrastapi-api', 'api.fn_health'),
  ('contrastapi-api', 'api.fn_ip_asn_prefix'),
  ('contrastapi-api', 'api.fn_ip_change_event_purge'),
  ('contrastapi-api', 'api.fn_ip_lookup'),
  ('contrastapi-api', 'api.fn_ip_watch_write_values'),
  ('contrastapi-api', 'api.fn_kev_lookup'),
  ('contrastapi-api', 'api.fn_package_advisory_change_event_purge'),
  ('contrastapi-api', 'api.fn_package_check'),
  ('contrastapi-api', 'api.fn_package_check_bulk'),
  ('contrastapi-api', 'api.fn_package_check_bulk_weigh'),
  ('contrastapi-api', 'api.fn_package_check_eol'),
  ('contrastapi-api', 'api.fn_product_exposure'),
  ('contrastapi-api', 'api.fn_product_exposure_eol'),
  ('contrastapi-api', 'api.fn_schema_version'),
  ('contrastapi-api', 'api.fn_ssl_blacklist_certificate'),
  ('contrastapi-api', 'api.fn_target_throttle_charge'),
  ('contrastapi-api', 'api.fn_target_throttle_load'),
  ('contrastapi-api', 'api.fn_target_throttle_purge'),
  ('contrastapi-api', 'api.fn_credit_budget_charge'),
  ('contrastapi-api', 'api.fn_credit_budget_purge'),
  ('contrastapi-api', 'api.fn_credit_budget_used'),
  ('contrastapi-api', 'api.fn_upstream_cache_get'),
  ('contrastapi-api', 'api.fn_upstream_cache_purge'),
  ('contrastapi-api', 'api.fn_upstream_cache_put'),
  ('contrastapi-api', 'api.fn_upstream_feed_status'),
  ('contrastapi-api', 'api.fn_upstream_hold_remaining_seconds'),
  ('contrastapi-api', 'api.fn_upstream_hold_set'),
  ('contrastapi-api', 'api.fn_upstream_quota_mark_exhausted'),
  ('contrastapi-api', 'api.fn_upstream_quota_purge'),
  ('contrastapi-api', 'api.fn_upstream_quota_reserve'),
  ('contrastapi-api', 'api.fn_vendor_key_apply'),
  ('contrastapi-api', 'api.fn_vendor_key_link_open'),
  ('contrastapi-api', 'api.fn_vendor_key_link_purge'),
  ('contrastapi-api', 'api.fn_vendor_key_link_read'),
  ('contrastapi-api', 'api.fn_vendor_key_purge'),
  ('contrastapi-api', 'api.fn_vendor_key_read'),
  ('contrastapi-api', 'api.fn_watchlist_clear'),
  ('contrastapi-api', 'api.fn_watchlist_edit_cert_search'),
  ('contrastapi-api', 'api.fn_watchlist_edit_cve_exploit'),
  ('contrastapi-api', 'api.fn_watchlist_edit_cve_lookup'),
  ('contrastapi-api', 'api.fn_watchlist_edit_cve_search'),
  ('contrastapi-api', 'api.fn_watchlist_edit_dns_lookup'),
  ('contrastapi-api', 'api.fn_watchlist_edit_headers_check'),
  ('contrastapi-api', 'api.fn_watchlist_edit_ip_lookup'),
  ('contrastapi-api', 'api.fn_watchlist_edit_kev_lookup'),
  ('contrastapi-api', 'api.fn_watchlist_edit_package_check'),
  ('contrastapi-api', 'api.fn_watchlist_edit_product_exposure'),
  ('contrastapi-api', 'api.fn_watchlist_edit_ssl_check'),
  ('contrastapi-api', 'api.fn_watchlist_edit_whois_lookup'),
  ('contrastapi-api', 'api.fn_watchlist_events'),
  ('contrastapi-api', 'api.fn_watchlist_list'),
  ('contrastapi-api', 'api.fn_watchlist_package_list_edit'),
  ('contrastapi-api', 'api.fn_watchlist_purge'),
  ('contrastapi-api', 'api.fn_x402_payment_mark_pending'),
  ('contrastapi-api', 'api.fn_x402_payment_mark_settled'),
  ('contrastapi-api', 'api.fn_x402_payment_purge'),
  ('contrastapi-api', 'api.fn_x402_payment_release'),
  ('contrastapi-api', 'api.fn_x402_payment_reserve'),
  ('contrastapi-web', 'api.fn_cve_exploit_exploitdb'),
  ('contrastapi-web', 'api.fn_cve_exploit_exploitdb_summary'),
  ('contrastapi-web', 'api.fn_cve_ghsa_advisory'),
  ('contrastapi-web', 'api.fn_cve_lookup'),
  ('contrastapi-web', 'api.fn_cwe_lookup'),
  ('contrastapi-web', 'api.fn_kev_lookup'),
  ('contrastapi-web', 'api.fn_schema_version');

DO $$
DECLARE
  offender text;
BEGIN
  SELECT n.nspname || '.' || p.proname INTO offender
    FROM pg_proc AS p JOIN pg_namespace AS n ON n.oid = p.pronamespace
   WHERE n.nspname IN ('api', 'web', 'public') AND p.prosecdef
  EXCEPT
  SELECT rf.function_name FROM t_grants_role_function AS rf
   ORDER BY 1 LIMIT 1;
  ASSERT offender IS NULL, coalesce(offender, '') || ' is SECURITY DEFINER but in no list';
  SELECT rf.function_name INTO offender FROM t_grants_role_function AS rf
  EXCEPT
  SELECT n.nspname || '.' || p.proname
    FROM pg_proc AS p JOIN pg_namespace AS n ON n.oid = p.pronamespace
   WHERE n.nspname IN ('api', 'web', 'public') AND p.prosecdef
   ORDER BY 1 LIMIT 1;
  ASSERT offender IS NULL, coalesce(offender, '') || ' is listed but is not SECURITY DEFINER';
  SELECT n.nspname || '.' || p.proname INTO offender
    FROM pg_proc AS p JOIN pg_namespace AS n ON n.oid = p.pronamespace
   WHERE (n.nspname || '.' || p.proname) IN (SELECT rf.function_name FROM t_grants_role_function AS rf)
     AND NOT 'search_path=pg_catalog' = ANY (coalesce(p.proconfig, '{}'))
   ORDER BY 1 LIMIT 1;
  ASSERT offender IS NULL, coalesce(offender, '') || ' is listed but does not set search_path to pg_catalog';
END
$$;

DO $$
DECLARE
  offender text;
BEGIN
  SELECT p.oid::regprocedure::text INTO offender
    FROM pg_proc AS p JOIN pg_namespace AS n ON n.oid = p.pronamespace
   WHERE n.nspname IN ('api', 'web', 'public')
     AND p.proowner <> (SELECT r.oid FROM pg_roles AS r WHERE r.rolname = 'contrastapi-owner')
     AND NOT EXISTS (SELECT 1 FROM pg_depend AS d
                      WHERE d.classid = 'pg_proc'::regclass AND d.objid = p.oid AND d.deptype = 'e')
   ORDER BY 1 LIMIT 1;
  ASSERT offender IS NULL, coalesce(offender, '') || ' is not owned by contrastapi-owner';
  ASSERT (SELECT NOT r.rolsuper AND NOT r.rolcanlogin FROM pg_roles AS r WHERE r.rolname = 'contrastapi-owner'),
         'contrastapi-owner is no superuser and cannot log in';
  ASSERT (SELECT count(*) FROM pg_roles AS r
           WHERE r.rolname IN ('contrastapi-api', 'contrastapi-web', 'contrastapi-sync') AND NOT r.rolsuper) = 3,
         'the three login roles exist and none is a superuser';
END
$$;

DO $$
DECLARE
  offender text;
BEGIN
  SELECT p.oid::regprocedure::text INTO offender
    FROM pg_proc AS p JOIN pg_namespace AS n ON n.oid = p.pronamespace
   WHERE n.nspname IN ('api', 'web', 'public') AND has_function_privilege('public', p.oid, 'EXECUTE')
   ORDER BY 1 LIMIT 1;
  ASSERT offender IS NULL, 'PUBLIC may call ' || coalesce(offender, '');
END
$$;

DO $$
DECLARE
  login_role text;
  offender   text;
BEGIN
  FOREACH login_role IN ARRAY ARRAY['contrastapi-api', 'contrastapi-web', 'contrastapi-sync'] LOOP
    SELECT n.nspname || '.' || p.proname INTO offender
      FROM pg_proc AS p JOIN pg_namespace AS n ON n.oid = p.pronamespace
     WHERE n.nspname IN ('api', 'web', 'public') AND has_function_privilege(login_role, p.oid, 'EXECUTE')
    EXCEPT
    SELECT rf.function_name FROM t_grants_role_function AS rf WHERE rf.role_name = login_role
     ORDER BY 1 LIMIT 1;
    ASSERT offender IS NULL, login_role || ' may call ' || coalesce(offender, '') || ', which is not in its list';
    SELECT rf.function_name INTO offender FROM t_grants_role_function AS rf WHERE rf.role_name = login_role
    EXCEPT
    SELECT n.nspname || '.' || p.proname
      FROM pg_proc AS p JOIN pg_namespace AS n ON n.oid = p.pronamespace
     WHERE n.nspname IN ('api', 'web', 'public') AND has_function_privilege(login_role, p.oid, 'EXECUTE')
     ORDER BY 1 LIMIT 1;
    ASSERT offender IS NULL, login_role || ' may not call ' || coalesce(offender, '') || ', which is in its list';
  END LOOP;
  ASSERT NOT has_function_privilege('contrastapi-web', 'api.fn_api_key_state(text)'::regprocedure, 'EXECUTE'),
         'contrastapi-web may not call api.fn_api_key_state';
  ASSERT NOT has_function_privilege('contrastapi-sync',
                                    'api.fn_cve_lookup(text[], integer, integer, integer, integer, integer)'::regprocedure, 'EXECUTE'),
         'contrastapi-sync may not call api.fn_cve_lookup';
END
$$;

DO $$
DECLARE
  offender text;
BEGIN
  SELECT r.role_name || ' ' || pr.privilege_name || ' ' || c.oid::regclass::text INTO offender
    FROM pg_class AS c
    JOIN pg_namespace AS n ON n.oid = c.relnamespace
   CROSS JOIN unnest(ARRAY['contrastapi-api', 'contrastapi-web', 'contrastapi-sync']) AS r (role_name)
   CROSS JOIN unnest(ARRAY['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER']) AS pr (privilege_name)
   WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'm')
     AND has_table_privilege(r.role_name, c.oid, pr.privilege_name)
   ORDER BY 1 LIMIT 1;
  ASSERT offender IS NULL, 'a login role holds a table privilege: ' || coalesce(offender, '');
  ASSERT (SELECT count(*) FROM pg_class AS c
           WHERE c.relnamespace = 'public'::regnamespace AND c.relkind = 'm' AND c.relname = 'cpe_product_index') = 1,
         'the check above covers the materialized view cpe_product_index';
END
$$;

DO $$
DECLARE
  offender text;
BEGIN
  ASSERT has_schema_privilege('contrastapi-api', 'api', 'USAGE'), 'contrastapi-api may use the schema api';
  ASSERT has_schema_privilege('contrastapi-web', 'api', 'USAGE'), 'contrastapi-web may use the schema api';
  ASSERT NOT has_schema_privilege('contrastapi-sync', 'api', 'USAGE'), 'contrastapi-sync may not use the schema api';
  SELECT r.role_name || ' may use the schema ' || n.nspname INTO offender
    FROM pg_namespace AS n
   CROSS JOIN unnest(ARRAY['contrastapi-api', 'contrastapi-web', 'contrastapi-sync']) AS r (role_name)
   WHERE n.nspname NOT IN ('api', 'public', 'information_schema') AND n.nspname NOT LIKE 'pg\_%'
     AND has_schema_privilege(r.role_name, n.oid, 'USAGE')
   ORDER BY 1 LIMIT 1;
  ASSERT offender IS NULL, coalesce(offender, '') || ', which holds no registered function of it';
END
$$;

DO $$
DECLARE
  is_refused boolean;
BEGIN
  SET LOCAL ROLE "contrastapi-web";
  PERFORM api.fn_schema_version();
  RESET ROLE;

  is_refused := false;
  SET LOCAL ROLE "contrastapi-web";
  BEGIN
    PERFORM 1 FROM public.api_keys;
  EXCEPTION WHEN insufficient_privilege THEN
    is_refused := true;
  END;
  RESET ROLE;
  ASSERT is_refused, 'contrastapi-web may not read public.api_keys';

  is_refused := false;
  SET LOCAL ROLE "contrastapi-web";
  BEGIN
    PERFORM api.fn_api_key_state(repeat('0', 64));
  EXCEPTION WHEN insufficient_privilege THEN
    is_refused := true;
  END;
  RESET ROLE;
  ASSERT is_refused, 'contrastapi-web may not call api.fn_api_key_state';
END
$$;

DO $$
DECLARE
  is_refused boolean := false;
BEGIN
  SET LOCAL ROLE "contrastapi-sync";
  BEGIN
    PERFORM 1 FROM public.cves;
  EXCEPTION WHEN insufficient_privilege THEN
    is_refused := true;
  END;
  RESET ROLE;
  ASSERT is_refused, 'contrastapi-sync may not read public.cves';
END
$$;

CREATE TEMP VIEW t_connection_role_state_call AS SELECT * FROM api.fn_connection_role_state();

DO $$
DECLARE
  state record;
BEGIN
  ASSERT (SELECT array_agg(a.attname::text || ' ' || format_type(a.atttypid, a.atttypmod) ORDER BY a.attnum)
            FROM pg_attribute AS a
           WHERE a.attrelid = 't_connection_role_state_call'::regclass AND a.attnum > 0)
         = ARRAY['is_superuser boolean', 'is_owner_member boolean'],
         'the call answers two boolean columns, is_superuser and is_owner_member';
  ASSERT (SELECT count(*) FROM t_connection_role_state_call) = 1, 'api.fn_connection_role_state answers one row';

  SELECT * INTO state FROM api.fn_connection_role_state();
  ASSERT state.is_superuser, 'the test superuser is a superuser';

  SET LOCAL SESSION AUTHORIZATION "contrastapi-api";
  SELECT * INTO state FROM api.fn_connection_role_state();
  RESET SESSION AUTHORIZATION;
  ASSERT NOT state.is_superuser AND NOT state.is_owner_member,
         'contrastapi-api is no superuser and no member of contrastapi-owner';

  SET LOCAL SESSION AUTHORIZATION "contrastapi-owner";
  SELECT * INTO state FROM api.fn_connection_role_state();
  RESET SESSION AUTHORIZATION;
  ASSERT NOT state.is_superuser AND state.is_owner_member,
         'contrastapi-owner is no superuser and is a member of itself';
END
$$;

DO $$
DECLARE
  login_role text;
  offender   text;
BEGIN
  SELECT r.role_name || ' ' || c.oid::regclass::text INTO offender
    FROM pg_class AS c
   CROSS JOIN unnest(ARRAY['contrastapi-api', 'contrastapi-web', 'contrastapi-sync']) AS r (role_name)
   WHERE c.relnamespace = 'public'::regnamespace AND c.relkind IN ('r', 'p', 'm', 'v', 'f')
     AND has_any_column_privilege(r.role_name, c.oid, 'SELECT, INSERT, UPDATE, REFERENCES')
     AND NOT EXISTS (SELECT 1 FROM pg_depend AS d
                      WHERE d.classid = 'pg_class'::regclass AND d.objid = c.oid AND d.deptype = 'e')
   ORDER BY 1 LIMIT 1;
  ASSERT offender IS NULL, 'a login role holds a column or view privilege: ' || coalesce(offender, '');
  SELECT r.role_name || ' ' || c.oid::regclass::text INTO offender
    FROM pg_class AS c
   CROSS JOIN unnest(ARRAY['contrastapi-api', 'contrastapi-web', 'contrastapi-sync']) AS r (role_name)
   WHERE c.relnamespace = 'public'::regnamespace AND c.relkind = 'S'
     AND has_sequence_privilege(r.role_name, c.oid, 'USAGE, SELECT, UPDATE')
   ORDER BY 1 LIMIT 1;
  ASSERT offender IS NULL, 'a login role holds a sequence privilege: ' || coalesce(offender, '');
  FOREACH login_role IN ARRAY ARRAY['contrastapi-api', 'contrastapi-web', 'contrastapi-sync'] LOOP
    ASSERT NOT has_schema_privilege(login_role, 'api', 'CREATE'), login_role || ' may not create in api';
    ASSERT NOT has_schema_privilege(login_role, 'public', 'CREATE'), login_role || ' may not create in public';
    ASSERT NOT pg_has_role(login_role, 'contrastapi-owner', 'MEMBER'), login_role || ' is no member of contrastapi-owner';
  END LOOP;
END
$$;

DO $$
DECLARE
  role_row record;
  actual   pg_roles;
BEGIN
  FOR role_row IN SELECT * FROM (VALUES
      ('contrastapi-owner', false, -1), ('contrastapi-api', true, 24),
      ('contrastapi-sync', true, 4), ('contrastapi-web', true, 8)) AS t (role_name, can_login, connection_limit)
  LOOP
    SELECT * INTO actual FROM pg_roles AS r WHERE r.rolname = role_row.role_name;
    ASSERT actual.rolcanlogin = role_row.can_login, role_row.role_name || ' login';
    ASSERT actual.rolconnlimit = role_row.connection_limit, role_row.role_name || ' connection limit';
    ASSERT NOT (actual.rolsuper OR actual.rolcreatedb OR actual.rolcreaterole OR actual.rolreplication OR actual.rolbypassrls),
           role_row.role_name || ' holds no attribute beyond login';
  END LOOP;
  ASSERT (SELECT r.rolconfig @> ARRAY['statement_timeout=5s', 'idle_in_transaction_session_timeout=10s', 'default_transaction_read_only=on']
            FROM pg_roles AS r WHERE r.rolname = 'contrastapi-web'),
         'contrastapi-web has its timeout, its idle timeout and read-only transactions';
  ASSERT (SELECT count(*) FROM pg_default_acl AS d
           WHERE d.defaclrole = 'contrastapi-owner'::regrole AND d.defaclobjtype = 'f'
             AND NOT EXISTS (SELECT 1 FROM aclexplode(d.defaclacl) AS a WHERE a.grantee = 0)) = 1,
         'the default privileges of the owner give PUBLIC no EXECUTE';
END
$$;

DO $$
DECLARE
  login_role text;
  is_refused boolean;
BEGIN
  ASSERT has_database_privilege('contrastapi-owner', current_database(), 'TEMPORARY'), 'the owner holds TEMPORARY';
  FOREACH login_role IN ARRAY ARRAY['contrastapi-api', 'contrastapi-web', 'contrastapi-sync'] LOOP
    ASSERT NOT has_database_privilege(login_role, current_database(), 'TEMPORARY'), login_role || ' holds no TEMPORARY';
    ASSERT has_database_privilege(login_role, current_database(), 'CONNECT'), login_role || ' may connect';

    is_refused := false;
    EXECUTE format('SET LOCAL ROLE %I', login_role);
    BEGIN
      CREATE TEMP TABLE t_grants_refused (a integer);
    EXCEPTION WHEN insufficient_privilege THEN
      is_refused := true;
    END;
    RESET ROLE;
    ASSERT is_refused, login_role || ' may not create a temporary table';

    is_refused := false;
    EXECUTE format('SET LOCAL ROLE %I', login_role);
    BEGIN
      CREATE FUNCTION pg_temp.t_grants_refused() RETURNS integer LANGUAGE sql RETURN 1;
    EXCEPTION WHEN insufficient_privilege THEN
      is_refused := true;
    END;
    RESET ROLE;
    ASSERT is_refused, login_role || ' may not create a temporary function';
  END LOOP;
END
$$;

\set t_grants_text `cat sql/grants.sql`
SELECT set_config('t_grants.text', :'t_grants_text', true) AS t_grants_text_set \gset
DO $$
DECLARE
  case_row record;
  message  text;
BEGIN
  FOR case_row IN SELECT * FROM (VALUES
      ('CREATE FUNCTION api.fn_health(integer) RETURNS integer LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog RETURN 1', 'resolves to 2 functions'),
      ('ALTER FUNCTION api.fn_cwe_lookup(text) RENAME TO fn_cwe_lookup_gone', 'resolves to 0 functions'),
      ('ALTER FUNCTION api.fn_schema_version() OWNER TO "contrastapi-api"', 'not owned by'),
      ('ALTER FUNCTION api.fn_schema_version() SECURITY INVOKER', 'not SECURITY DEFINER'),
      ('ALTER FUNCTION api.fn_schema_version() RESET search_path', 'not SECURITY DEFINER'),
      ('ALTER FUNCTION api.fn_schema_version() SET search_path = public', 'not SECURITY DEFINER'),
      ('ALTER FUNCTION api.fn_schema_version() SET search_path = pg_catalog, public', 'not SECURITY DEFINER'),
      ('ALTER FUNCTION api.fn_billing_delete_key(text, text) SECURITY DEFINER', 'in no list'),
      ('CREATE SCHEMA web AUTHORIZATION "contrastapi-owner"; CREATE FUNCTION web.fn_t_grants_drift() RETURNS integer LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog RETURN 1; ALTER FUNCTION web.fn_t_grants_drift() OWNER TO "contrastapi-owner"', 'web.fn_t_grants_drift() is SECURITY DEFINER but in no list'),
      ('ALTER ROLE "contrastapi-owner" SUPERUSER', 'contrastapi-owner is a superuser'),
      ('ALTER ROLE "contrastapi-web" SUPERUSER', 'contrastapi-web is a superuser'),
      ('ALTER ROLE "contrastapi-api" BYPASSRLS', 'contrastapi-api is a superuser'),
      ('GRANT "contrastapi-owner" TO "contrastapi-sync"', 'contrastapi-sync is a superuser'),
      ('GRANT "contrastapi-owner" TO "contrastapi-web" WITH INHERIT FALSE', 'contrastapi-web is a superuser'),
      (format('GRANT TEMPORARY ON DATABASE %I TO "contrastapi-sync"', current_database()), 'contrastapi-sync holds TEMPORARY'),
      (format('GRANT TEMPORARY ON DATABASE %I TO "contrastapi-web"', current_database()), 'contrastapi-web holds TEMPORARY'),
      (format('GRANT TEMPORARY ON DATABASE %I TO "contrastapi-api"', current_database()), 'contrastapi-api holds TEMPORARY'),
      ('ALTER ROLE "contrastapi-owner" LOGIN', 'contrastapi-owner can log in'),
      ('ALTER ROLE "contrastapi-owner" CREATEROLE', 'contrastapi-owner holds CREATEROLE'),
      ('ALTER ROLE "contrastapi-owner" BYPASSRLS', 'contrastapi-owner holds CREATEROLE'),
      ('ALTER ROLE "contrastapi-api" CREATEROLE', 'contrastapi-api holds CREATEROLE'),
      ('ALTER ROLE "contrastapi-web" CREATEDB', 'contrastapi-web holds CREATEROLE'),
      ('ALTER ROLE "contrastapi-sync" REPLICATION', 'contrastapi-sync holds CREATEROLE'),
      ('GRANT pg_read_all_data TO "contrastapi-api"', 'contrastapi-api is a member of pg_read_all_data'),
      ('GRANT pg_write_all_data TO "contrastapi-web"', 'contrastapi-web is a member of pg_write_all_data'),
      ('GRANT "contrastapi-api" TO "contrastapi-sync"', 'contrastapi-sync is a member of contrastapi-api'),
      ('ALTER TABLE public.api_keys OWNER TO "contrastapi-api"', 'contrastapi-api owns public.api_keys'),
      ('ALTER MATERIALIZED VIEW public.cpe_product_index OWNER TO "contrastapi-sync"', 'contrastapi-sync owns public.cpe_product_index'),
      ('ALTER TABLE public.cwes OWNER TO "contrastapi-web"', 'contrastapi-web owns public.cwes'),
      ('CREATE TABLE api.t_grants_drift (a integer); ALTER TABLE api.t_grants_drift OWNER TO "contrastapi-api"', 'contrastapi-api owns api.t_grants_drift'),
      ('CREATE TABLE api.t_grants_drift (a integer); GRANT SELECT ON api.t_grants_drift TO "contrastapi-api"', 'contrastapi-api holds a privilege on api.t_grants_drift'),
      ('CREATE VIEW public.t_grants_drift AS SELECT 1 AS a; GRANT SELECT ON public.t_grants_drift TO "contrastapi-web"', 'contrastapi-web holds a privilege on public.t_grants_drift'),
      ('CREATE TABLE public.t_grants_drift (a integer) PARTITION BY RANGE (a); GRANT SELECT ON public.t_grants_drift TO "contrastapi-web"', 'contrastapi-web holds a privilege on public.t_grants_drift'),
      ('CREATE FOREIGN DATA WRAPPER t_grants_fdw; CREATE SERVER t_grants_server FOREIGN DATA WRAPPER t_grants_fdw; CREATE FOREIGN TABLE public.t_grants_drift (a integer) SERVER t_grants_server; GRANT SELECT ON public.t_grants_drift TO "contrastapi-web"', 'contrastapi-web holds a privilege on public.t_grants_drift'),
      ('GRANT SELECT (cve_id) ON public.cves TO PUBLIC', 'holds a privilege on public.cves'),
      ('GRANT SELECT ON public.api_keys TO "contrastapi-web"', 'contrastapi-web holds a privilege on public.api_keys'),
      ('GRANT TRUNCATE ON public.cves TO "contrastapi-sync"', 'contrastapi-sync holds a privilege on public.cves'),
      ('GRANT SELECT ON public.cpe_product_index TO "contrastapi-api"', 'contrastapi-api holds a privilege on public.cpe_product_index'),
      ('GRANT SELECT ON public.api_keys TO PUBLIC', 'holds a privilege on public.api_keys'),
      ('GRANT SELECT (cve_id) ON public.cves TO "contrastapi-web"', 'contrastapi-web holds a privilege on public.cves'),
      ('GRANT USAGE ON SEQUENCE ' || (SELECT c.oid::regclass::text FROM pg_class AS c WHERE c.relkind = 'S' AND c.relnamespace = 'public'::regnamespace ORDER BY 1 LIMIT 1) || ' TO "contrastapi-api"', 'contrastapi-api holds a privilege on'),
      ('GRANT CREATE ON SCHEMA api TO "contrastapi-api"', 'contrastapi-api may create in api'),
      ('GRANT CREATE ON SCHEMA public TO "contrastapi-sync"', 'contrastapi-sync may create in public'),
      ('GRANT CREATE ON SCHEMA public TO PUBLIC', 'may create in public'),
      ('GRANT EXECUTE ON FUNCTION api.fn_api_key_state(text) TO "contrastapi-web"', 'contrastapi-web may call api.fn_api_key_state'),
      ('GRANT USAGE ON SCHEMA api TO "contrastapi-sync"', 'contrastapi-sync may use the schema api'),
      ('GRANT SELECT ON public.role_function_grant TO "contrastapi-web"', 'contrastapi-web holds a privilege on public.role_function_grant'),
      ('GRANT EXECUTE ON FUNCTION api.fn_billing_delete_key(text, text) TO "contrastapi-api"', 'contrastapi-api may call api.fn_billing_delete_key'),
      ('CREATE SCHEMA t_grants_drift_schema; CREATE FUNCTION t_grants_drift_schema.fn_t_grants_drift() RETURNS integer LANGUAGE sql RETURN 1', 't_grants_drift_schema.fn_t_grants_drift() is not owned by contrastapi-owner'),
      ('CREATE SCHEMA t_grants_drift_schema; CREATE TABLE t_grants_drift_schema.t_grants_drift (a integer); ALTER TABLE t_grants_drift_schema.t_grants_drift OWNER TO "contrastapi-web"', 'contrastapi-web owns t_grants_drift_schema.t_grants_drift'),
      ('CREATE SCHEMA t_grants_drift_schema; CREATE TABLE t_grants_drift_schema.t_grants_drift (a integer); GRANT SELECT ON t_grants_drift_schema.t_grants_drift TO "contrastapi-api"', 'contrastapi-api holds a privilege on t_grants_drift_schema.t_grants_drift'),
      ('CREATE SCHEMA t_grants_drift_schema; GRANT CREATE ON SCHEMA t_grants_drift_schema TO "contrastapi-sync"', 'contrastapi-sync may create in t_grants_drift_schema'))
      AS t (statement_text, needle)
  LOOP
    message := NULL;
    BEGIN
      EXECUTE case_row.statement_text;
      EXECUTE current_setting('t_grants.text');
    EXCEPTION WHEN raise_exception THEN
      message := SQLERRM;
    END;
    ASSERT message LIKE '%' || case_row.needle || '%', case_row.statement_text || ' -> ' || coalesce(message, 'no refusal');
  END LOOP;
END
$$;

DO $$
DECLARE
  login_role text;
BEGIN
  EXECUTE format('GRANT TEMPORARY ON DATABASE %I TO PUBLIC', current_database());
  EXECUTE format('REVOKE CONNECT ON DATABASE %I FROM PUBLIC', current_database());
  FOREACH login_role IN ARRAY ARRAY['contrastapi-api', 'contrastapi-web', 'contrastapi-sync'] LOOP
    EXECUTE format('REVOKE CONNECT ON DATABASE %I FROM %I', current_database(), login_role);
  END LOOP;
  EXECUTE current_setting('t_grants.text');
  ASSERT NOT has_database_privilege('contrastapi-sync', current_database(), 'TEMPORARY'), 'the apply takes TEMPORARY from PUBLIC';
  FOREACH login_role IN ARRAY ARRAY['contrastapi-api', 'contrastapi-web', 'contrastapi-sync'] LOOP
    ASSERT has_database_privilege(login_role, current_database(), 'CONNECT'), 'the apply gives CONNECT to ' || login_role;
  END LOOP;
END
$$;

DO $$
BEGIN
  ASSERT NOT EXISTS (SELECT 1 FROM pg_namespace AS n WHERE n.nspname = 'web'), 'R7 the test database has no schema web';
  EXECUTE current_setting('t_grants.text');
  ASSERT has_function_privilege('contrastapi-web', 'api.fn_schema_version()'::regprocedure, 'EXECUTE'),
         'R7 the apply without web gives contrastapi-web its api function';
END
$$;

DO $$
DECLARE
  refused_row record;
  is_refused  boolean;
BEGIN
  FOR refused_row IN SELECT * FROM (VALUES
      ('contrastapi-owner', 'api.fn_health'),
      ('contrastapi-api', 't_grants_outside_a.outside_alpha'),
      ('contrastapi-web', 'fn_outside_alpha'),
      ('contrastapi-sync', 'public.fn_Outside_Alpha'),
      ('contrastapi-web', 'api.fn_credit_budget_charge'),
      ('contrastapi-web', 'public.fn_osv_version_sortable')) AS t (role_name, function_name)
  LOOP
    is_refused := false;
    BEGIN
      INSERT INTO public.role_function_grant (role_name, function_name) VALUES (refused_row.role_name, refused_row.function_name);
    EXCEPTION WHEN check_violation THEN
      is_refused := true;
    END;
    ASSERT is_refused, 'R6 the registry refuses ' || refused_row.role_name || ' with ' || refused_row.function_name;
  END LOOP;
  ASSERT (SELECT count(*) FROM public.role_function_grant) = 0, 'R6 no refused row stayed';
END
$$;

DO $$
BEGIN
  CREATE SCHEMA t_grants_outside_a AUTHORIZATION "contrastapi-owner";
  CREATE SCHEMA t_grants_outside_b AUTHORIZATION "contrastapi-owner";
  SET LOCAL ROLE "contrastapi-owner";
  CREATE FUNCTION t_grants_outside_a.fn_outside_alpha(p_count integer) RETURNS integer
    LANGUAGE sql IMMUTABLE SECURITY DEFINER SET search_path = pg_catalog RETURN p_count + 7;
  RESET ROLE;
  CREATE FUNCTION t_grants_outside_b.fn_outside_beta(p_label text) RETURNS text
    LANGUAGE sql IMMUTABLE SECURITY DEFINER SET search_path = pg_catalog RETURN p_label || '-beta';
  ALTER FUNCTION t_grants_outside_b.fn_outside_beta(text) OWNER TO "contrastapi-owner";
  INSERT INTO public.role_function_grant (role_name, function_name) VALUES
    ('contrastapi-web', 't_grants_outside_a.fn_outside_alpha'),
    ('contrastapi-api', 't_grants_outside_b.fn_outside_beta');
END
$$;

DO $$
DECLARE
  answer integer;
BEGIN
  EXECUTE current_setting('t_grants.text');
  ASSERT has_function_privilege('contrastapi-web', 't_grants_outside_a.fn_outside_alpha(integer)'::regprocedure, 'EXECUTE'),
         'R1 contrastapi-web may call its registered fn_outside_alpha';
  ASSERT has_function_privilege('contrastapi-api', 't_grants_outside_b.fn_outside_beta(text)'::regprocedure, 'EXECUTE'),
         'R1 contrastapi-api may call its registered fn_outside_beta';
  ASSERT NOT has_function_privilege('contrastapi-sync', 't_grants_outside_a.fn_outside_alpha(integer)'::regprocedure, 'EXECUTE'),
         'R1 contrastapi-sync may not call fn_outside_alpha';
  ASSERT NOT has_function_privilege('contrastapi-sync', 't_grants_outside_b.fn_outside_beta(text)'::regprocedure, 'EXECUTE'),
         'R1 contrastapi-sync may not call fn_outside_beta';
  ASSERT NOT has_function_privilege('public', 't_grants_outside_a.fn_outside_alpha(integer)'::regprocedure, 'EXECUTE'),
         'R1 PUBLIC may not call fn_outside_alpha';
  ASSERT NOT has_function_privilege('public', 't_grants_outside_b.fn_outside_beta(text)'::regprocedure, 'EXECUTE'),
         'R1 PUBLIC may not call fn_outside_beta';
  SET LOCAL ROLE "contrastapi-web";
  answer := t_grants_outside_a.fn_outside_alpha(35);
  RESET ROLE;
  ASSERT answer = 42, 'R1 contrastapi-web runs fn_outside_alpha and gets its answer';
  SET LOCAL ROLE "contrastapi-api";
  ASSERT t_grants_outside_b.fn_outside_beta('r1') = 'r1-beta', 'R1 contrastapi-api runs fn_outside_beta';
  RESET ROLE;
END
$$;

DO $$
DECLARE
  message text;
BEGIN
  BEGIN
    DELETE FROM public.role_function_grant AS rfg WHERE rfg.function_name = 't_grants_outside_a.fn_outside_alpha';
    EXECUTE current_setting('t_grants.text');
  EXCEPTION WHEN raise_exception THEN
    message := SQLERRM;
  END;
  ASSERT message LIKE '%t_grants_outside_a.fn_outside_alpha(integer) is SECURITY DEFINER but in no list%',
         'R2 an unregistered function stops the apply -> ' || coalesce(message, 'no refusal');
  ASSERT (SELECT count(*) FROM public.role_function_grant) = 2, 'R2 the sub-block put the row back';
END
$$;

DO $$
DECLARE
  message text;
BEGIN
  BEGIN
    INSERT INTO public.role_function_grant (role_name, function_name) VALUES ('contrastapi-web', 't_grants_outside_a.fn_outside_missing');
    EXECUTE current_setting('t_grants.text');
  EXCEPTION WHEN raise_exception THEN
    message := SQLERRM;
  END;
  ASSERT message LIKE '%t_grants_outside_a.fn_outside_missing resolves to 0 functions%',
         'R3 a registered name with no function stops the apply -> ' || coalesce(message, 'no refusal');
END
$$;

DO $$
DECLARE
  grant_row record;
  message   text;
BEGIN
  ASSERT has_schema_privilege('contrastapi-web', 't_grants_outside_a', 'USAGE'), 'R4 contrastapi-web may use the schema of fn_outside_alpha';
  ASSERT has_schema_privilege('contrastapi-api', 't_grants_outside_b', 'USAGE'), 'R4 contrastapi-api may use the schema of fn_outside_beta';
  ASSERT NOT has_schema_privilege('contrastapi-web', 't_grants_outside_b', 'USAGE'), 'R4 contrastapi-web may not use the schema of fn_outside_beta';
  ASSERT NOT has_schema_privilege('contrastapi-api', 't_grants_outside_a', 'USAGE'), 'R4 contrastapi-api may not use the schema of fn_outside_alpha';
  ASSERT NOT has_schema_privilege('contrastapi-sync', 't_grants_outside_a', 'USAGE'), 'R4 contrastapi-sync may not use the schema of fn_outside_alpha';
  ASSERT NOT has_schema_privilege('contrastapi-sync', 't_grants_outside_b', 'USAGE'), 'R4 contrastapi-sync may not use the schema of fn_outside_beta';
  FOR grant_row IN SELECT * FROM (VALUES
      ('GRANT USAGE ON SCHEMA t_grants_outside_a TO "contrastapi-api"', 'contrastapi-api may use the schema t_grants_outside_a'),
      ('GRANT USAGE ON SCHEMA t_grants_outside_b TO "contrastapi-sync"', 'contrastapi-sync may use the schema t_grants_outside_b'),
      ('GRANT EXECUTE ON FUNCTION t_grants_outside_b.fn_outside_beta(text) TO "contrastapi-web"', 'contrastapi-web may call t_grants_outside_b.fn_outside_beta, which is not in its list'))
      AS t (statement_text, needle)
  LOOP
    message := NULL;
    BEGIN
      EXECUTE grant_row.statement_text;
      EXECUTE current_setting('t_grants.text');
    EXCEPTION WHEN raise_exception THEN
      message := SQLERRM;
    END;
    ASSERT message LIKE '%' || grant_row.needle || '%', 'R4 ' || grant_row.statement_text || ' -> ' || coalesce(message, 'no refusal');
  END LOOP;
END
$$;

DO $$
DECLARE
  is_refused boolean := false;
BEGIN
  ASSERT NOT has_function_privilege('contrastapi-api', 't_grants_outside_a.fn_outside_alpha(integer)'::regprocedure, 'EXECUTE'),
         'R5 the row of contrastapi-web gives contrastapi-api no EXECUTE on fn_outside_alpha';
  ASSERT NOT has_function_privilege('contrastapi-web', 't_grants_outside_b.fn_outside_beta(text)'::regprocedure, 'EXECUTE'),
         'R5 the row of contrastapi-api gives contrastapi-web no EXECUTE on fn_outside_beta';
  SET LOCAL ROLE "contrastapi-api";
  BEGIN
    PERFORM t_grants_outside_a.fn_outside_alpha(35);
  EXCEPTION WHEN insufficient_privilege THEN
    is_refused := true;
  END;
  RESET ROLE;
  ASSERT is_refused, 'R5 contrastapi-api is refused fn_outside_alpha';
  is_refused := false;
  SET LOCAL ROLE "contrastapi-web";
  BEGIN
    PERFORM t_grants_outside_b.fn_outside_beta('r5');
  EXCEPTION WHEN insufficient_privilege THEN
    is_refused := true;
  END;
  RESET ROLE;
  ASSERT is_refused, 'R5 contrastapi-web is refused fn_outside_beta';
END
$$;

DO $$
BEGIN
  DELETE FROM public.role_function_grant;
  DROP SCHEMA t_grants_outside_a CASCADE;
  DROP SCHEMA t_grants_outside_b CASCADE;
  EXECUTE current_setting('t_grants.text');
END
$$;
