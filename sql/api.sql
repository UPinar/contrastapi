\set ON_ERROR_STOP on
SELECT current_setting('search_path') AS api_saved_search_path \gset
SET LOCAL search_path = pg_catalog;
DO $$
BEGIN
  IF current_setting('search_path') <> 'pg_catalog' THEN
    RAISE EXCEPTION 'api.sql must run inside a transaction';
  END IF;
END
$$;
DO $$
DECLARE
  missing_role text;
BEGIN
  SELECT r.role_name INTO missing_role
    FROM unnest(ARRAY['contrastapi-owner', 'contrastapi-api', 'contrastapi-web', 'contrastapi-sync']) AS r (role_name)
   WHERE NOT EXISTS (SELECT 1 FROM pg_roles AS pr WHERE pr.rolname = r.role_name)
   LIMIT 1;
  IF missing_role IS NOT NULL THEN
    RAISE EXCEPTION 'the role % is missing: run sql/roles.sql once as a superuser', missing_role;
  END IF;
END
$$;
DROP SCHEMA IF EXISTS api CASCADE;
CREATE SCHEMA api AUTHORIZATION "contrastapi-owner";
SET LOCAL ROLE "contrastapi-owner";

\ir fn_schema_version.sql
\ir fn_connection_role_state.sql
\ir fn_api_key_state.sql
\ir fn_vendor_key.sql
\ir fn_billing.sql
\ir fn_credit_budget_purge.sql
\ir fn_credit_budget_check.sql
\ir fn_cve_risk_score.sql
\ir fn_upstream_feed_status.sql
\ir fn_current_window_start.sql
\ir fn_upstream_quota.sql
\ir fn_upstream_hold.sql
\ir fn_upstream_cache.sql
\ir fn_target_throttle.sql
\ir fn_x402.sql
\ir fn_cve_products.sql
\ir fn_cve_lookup.sql
\ir fn_cve_ghsa_advisory.sql
\ir fn_cve_exploit.sql
\ir fn_kev_lookup.sql
\ir fn_cwe_lookup.sql
\ir fn_cve_risk_breakdown.sql
\ir fn_health.sql
\ir fn_cve_triage_bulk.sql
\ir fn_product_exposure.sql
\ir fn_cve_change_event.sql
\ir fn_domain_watch.sql
\ir fn_package_advisory_change_event.sql
\ir fn_eol_change_event.sql
\ir fn_package_check.sql
\ir fn_ip_watch.sql
\ir fn_watchlist.sql
\ir fn_cve_list_from_where.sql
\ir fn_cve_search.sql
\ir fn_cve_leading.sql
\ir fn_cve_triage.sql
\ir fn_cpe_search.sql
\ir fn_d3fend_for_attack.sql
\ir fn_driver_lookup.sql
\ir fn_ip_lookup.sql
\ir fn_email_address_check.sql
\ir fn_asn_lookup.sql
\ir fn_ssl_check.sql

RESET ROLE;
\ir grants.sql
SELECT set_config('search_path', :'api_saved_search_path', true) AS api_restored_search_path \gset
