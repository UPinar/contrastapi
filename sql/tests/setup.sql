\set ON_ERROR_STOP on
BEGIN;
SET jit = off;
GRANT CREATE ON SCHEMA public TO "contrastapi-owner";
SET LOCAL ROLE "contrastapi-owner";
\ir ../../schema.sql
CREATE FUNCTION public.t_shadow_multiply(double precision, integer) RETURNS double precision
  LANGUAGE sql IMMUTABLE RETURN 999;
CREATE OPERATOR public.* (LEFTARG = double precision, RIGHTARG = integer,
                          FUNCTION = public.t_shadow_multiply);
CREATE FUNCTION public.width_bucket(double precision, double precision[]) RETURNS integer
  LANGUAGE sql IMMUTABLE RETURN 3;
RESET ROLE;
CREATE EXTENSION pg_stat_statements;
\ir ../api.sql
DROP OPERATOR public.* (double precision, integer);
DROP FUNCTION public.t_shadow_multiply(double precision, integer);
DROP FUNCTION public.width_bucket(double precision, double precision[]);
CREATE FUNCTION pg_temp.t_watchlist_edit(p_key_hash                   text,
                                         p_action                     text,
                                         p_endpoint_name              text,
                                         p_cve_id                     text,
                                         p_vendor                     text,
                                         p_product                    text,
                                         p_severity                   text,
                                         p_cwe_id                     text,
                                         p_min_cvss                   real,
                                         p_min_epss                   real,
                                         p_in_kev                     boolean,
                                         p_known_ransomware           boolean,
                                         p_has_nuclei_template        boolean,
                                         p_is_cleared                 boolean,
                                         p_item_max_count             integer,
                                         p_domain_name                text,
                                         p_registered_domain          text,
                                         p_domain_name_max_count      integer,
                                         p_ecosystem                  text,
                                         p_package_name               text,
                                         p_version                    text,
                                         p_package_item_max_count     integer,
                                         p_package_item_base_weight   integer,
                                         p_package_weight_budget      integer,
                                         p_listed_versions_per_weight integer)
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
  LANGUAGE plpgsql VOLATILE
AS $$
BEGIN
  IF p_is_cleared AND p_action IS NOT NULL THEN
    RAISE EXCEPTION 't_watchlist_edit: a clear takes no action, got %', p_action;
  END IF;
  IF p_is_cleared THEN
    RETURN QUERY SELECT * FROM api.fn_watchlist_clear(p_key_hash);
    RETURN;
  END IF;
  IF p_action IS NULL THEN
    RETURN QUERY SELECT * FROM api.fn_watchlist_list(p_key_hash);
    RETURN;
  END IF;
  IF p_endpoint_name = 'cve_lookup' THEN
    RETURN QUERY SELECT e.edit_status, e.endpoint_name, e.cve_id, NULL::text, NULL::text, NULL::text, NULL::text, NULL::real, NULL::real, NULL::boolean, NULL::boolean, NULL::boolean, NULL::boolean, NULL::text, NULL::text, NULL::text, NULL::text, NULL::text, e.item_count, e.package_item_count
                   FROM api.fn_watchlist_edit_cve_lookup(p_key_hash, p_action, p_cve_id, p_item_max_count) AS e;
  ELSIF p_endpoint_name = 'kev_lookup' THEN
    RETURN QUERY SELECT e.edit_status, e.endpoint_name, e.cve_id, NULL::text, NULL::text, NULL::text, NULL::text, NULL::real, NULL::real, NULL::boolean, NULL::boolean, NULL::boolean, NULL::boolean, NULL::text, NULL::text, NULL::text, NULL::text, NULL::text, e.item_count, e.package_item_count
                   FROM api.fn_watchlist_edit_kev_lookup(p_key_hash, p_action, p_cve_id, p_item_max_count) AS e;
  ELSIF p_endpoint_name = 'cve_exploit' THEN
    RETURN QUERY SELECT e.edit_status, e.endpoint_name, e.cve_id, NULL::text, NULL::text, NULL::text, NULL::text, NULL::real, NULL::real, NULL::boolean, NULL::boolean, NULL::boolean, NULL::boolean, NULL::text, NULL::text, NULL::text, NULL::text, NULL::text, e.item_count, e.package_item_count
                   FROM api.fn_watchlist_edit_cve_exploit(p_key_hash, p_action, p_cve_id, p_item_max_count) AS e;
  ELSIF p_endpoint_name = 'product_exposure' THEN
    RETURN QUERY SELECT e.edit_status, e.endpoint_name, NULL::text, e.vendor, e.product, NULL::text, NULL::text, NULL::real, NULL::real, NULL::boolean, NULL::boolean, NULL::boolean, e.product_has_cves, NULL::text, NULL::text, NULL::text, e.version, NULL::text, e.item_count, e.package_item_count
                   FROM api.fn_watchlist_edit_product_exposure(p_key_hash, p_action, p_vendor, p_product, p_version, p_item_max_count) AS e;
  ELSIF p_endpoint_name = 'cve_search' THEN
    RETURN QUERY SELECT e.edit_status, e.endpoint_name, NULL::text, e.vendor, e.product, e.severity, e.cwe_id, e.min_cvss, e.min_epss, e.in_kev, e.known_ransomware, e.has_nuclei_template, NULL::boolean, NULL::text, NULL::text, NULL::text, NULL::text, NULL::text, e.item_count, e.package_item_count
                   FROM api.fn_watchlist_edit_cve_search(p_key_hash, p_action, p_vendor, p_product, p_severity, p_cwe_id, p_min_cvss, p_min_epss, p_in_kev, p_known_ransomware, p_has_nuclei_template, p_item_max_count) AS e;
  ELSIF p_endpoint_name = 'dns_lookup' THEN
    RETURN QUERY SELECT e.edit_status, e.endpoint_name, NULL::text, NULL::text, NULL::text, NULL::text, NULL::text, NULL::real, NULL::real, NULL::boolean, NULL::boolean, NULL::boolean, NULL::boolean, e.domain_name, NULL::text, NULL::text, NULL::text, NULL::text, e.item_count, e.package_item_count
                   FROM api.fn_watchlist_edit_dns_lookup(p_key_hash, p_action, p_domain_name, p_registered_domain, p_item_max_count, p_domain_name_max_count) AS e;
  ELSIF p_endpoint_name = 'ssl_check' THEN
    RETURN QUERY SELECT e.edit_status, e.endpoint_name, NULL::text, NULL::text, NULL::text, NULL::text, NULL::text, NULL::real, NULL::real, NULL::boolean, NULL::boolean, NULL::boolean, NULL::boolean, e.domain_name, NULL::text, NULL::text, NULL::text, NULL::text, e.item_count, e.package_item_count
                   FROM api.fn_watchlist_edit_ssl_check(p_key_hash, p_action, p_domain_name, p_registered_domain, p_item_max_count, p_domain_name_max_count) AS e;
  ELSIF p_endpoint_name = 'whois_lookup' THEN
    RETURN QUERY SELECT e.edit_status, e.endpoint_name, NULL::text, NULL::text, NULL::text, NULL::text, NULL::text, NULL::real, NULL::real, NULL::boolean, NULL::boolean, NULL::boolean, NULL::boolean, e.domain_name, NULL::text, NULL::text, NULL::text, NULL::text, e.item_count, e.package_item_count
                   FROM api.fn_watchlist_edit_whois_lookup(p_key_hash, p_action, p_domain_name, p_registered_domain, p_item_max_count, p_domain_name_max_count) AS e;
  ELSIF p_endpoint_name = 'headers_check' THEN
    RETURN QUERY SELECT e.edit_status, e.endpoint_name, NULL::text, NULL::text, NULL::text, NULL::text, NULL::text, NULL::real, NULL::real, NULL::boolean, NULL::boolean, NULL::boolean, NULL::boolean, e.domain_name, NULL::text, NULL::text, NULL::text, NULL::text, e.item_count, e.package_item_count
                   FROM api.fn_watchlist_edit_headers_check(p_key_hash, p_action, p_domain_name, p_registered_domain, p_item_max_count, p_domain_name_max_count) AS e;
  ELSIF p_endpoint_name = 'cert_search' THEN
    RETURN QUERY SELECT e.edit_status, e.endpoint_name, NULL::text, NULL::text, NULL::text, NULL::text, NULL::text, NULL::real, NULL::real, NULL::boolean, NULL::boolean, NULL::boolean, NULL::boolean, e.domain_name, NULL::text, NULL::text, NULL::text, NULL::text, e.item_count, e.package_item_count
                   FROM api.fn_watchlist_edit_cert_search(p_key_hash, p_action, p_domain_name, p_registered_domain, p_item_max_count, p_domain_name_max_count) AS e;
  ELSIF p_endpoint_name = 'package_check' THEN
    RETURN QUERY SELECT e.edit_status, e.endpoint_name, NULL::text, NULL::text, NULL::text, NULL::text, NULL::text, NULL::real, NULL::real, NULL::boolean, NULL::boolean, NULL::boolean, NULL::boolean, NULL::text, e.ecosystem, e.package_name, e.version, NULL::text, e.item_count, e.package_item_count
                   FROM api.fn_watchlist_edit_package_check(p_key_hash, p_action, p_ecosystem, p_package_name, p_version, p_package_item_max_count, p_package_item_base_weight, p_package_weight_budget, p_listed_versions_per_weight) AS e;
  ELSE
    RAISE EXCEPTION 't_watchlist_edit: no edit function for endpoint %', p_endpoint_name;
  END IF;
END
$$;
