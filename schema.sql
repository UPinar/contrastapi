CREATE TABLE api_keys (
  id         SERIAL      PRIMARY KEY,
  key_hash   TEXT        NOT NULL UNIQUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  active     BOOLEAN     NOT NULL DEFAULT TRUE,
  expires_at TIMESTAMPTZ,
  CONSTRAINT api_keys_key_hash_format CHECK (key_hash ~ '^[0-9a-f]{64}$')
);

CREATE TABLE credit_budget (
  ip_hash      TEXT        NOT NULL,
  has_key      BOOLEAN     NOT NULL,
  credit_count INTEGER     NOT NULL DEFAULT 0,
  window_start TIMESTAMPTZ NOT NULL DEFAULT DATE_TRUNC('hour', NOW()),
  PRIMARY KEY (ip_hash, has_key)
);

CREATE TABLE role_function_grant (
  role_name     TEXT NOT NULL,
  function_name TEXT NOT NULL,
  PRIMARY KEY (role_name, function_name),
  CONSTRAINT role_function_grant_role_known CHECK (role_name IN ('contrastapi-api', 'contrastapi-web', 'contrastapi-sync')),
  CONSTRAINT role_function_grant_function_name_format CHECK (function_name ~ '^[a-z_]+\.fn_[a-z0-9_]+$'),
  CONSTRAINT role_function_grant_function_outside_core CHECK (split_part(function_name, '.', 1) NOT IN ('api', 'public'))
);

CREATE TABLE vendor_key (
  api_key_id  INTEGER     NOT NULL REFERENCES api_keys(id) ON DELETE CASCADE,
  vendor_name TEXT        NOT NULL,
  sealed_hex  TEXT        NOT NULL,
  saved_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (api_key_id, vendor_name),
  CONSTRAINT vendor_key_vendor_name_known CHECK (vendor_name IN ('shodan', 'abuseipdb')),
  CONSTRAINT vendor_key_sealed_hex_format CHECK (sealed_hex ~ '^([0-9a-f]{2}){30,157}$')
);

CREATE TABLE vendor_key_link (
  link_hash       TEXT        PRIMARY KEY,
  api_key_id      INTEGER     NOT NULL REFERENCES api_keys(id) ON DELETE CASCADE,
  key_fingerprint TEXT        NOT NULL,
  expires_at      TIMESTAMPTZ NOT NULL,
  CONSTRAINT vendor_key_link_link_hash_format       CHECK (link_hash ~ '^[0-9a-f]{64}$'),
  CONSTRAINT vendor_key_link_key_fingerprint_format CHECK (key_fingerprint ~ '^[0-9a-f]{32}$')
);
CREATE INDEX idx_vendor_key_link_api_key_id ON vendor_key_link(api_key_id);
CREATE INDEX idx_vendor_key_link_expires_at ON vendor_key_link(expires_at);

CREATE TABLE billing_orders (
  billing_order_id          BIGINT      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  provider                  TEXT        NOT NULL,
  provider_order_ref        TEXT        NOT NULL,
  provider_subscription_ref TEXT,
  provider_updated_at       TIMESTAMPTZ,
  order_id                  TEXT        UNIQUE,
  status                    TEXT        NOT NULL,
  claimable_until           TIMESTAMPTZ,
  claimed_at                TIMESTAMPTZ,
  expires_at                TIMESTAMPTZ,
  api_key_id                INTEGER     REFERENCES api_keys(id),
  created_at                TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT billing_orders_provider_known            CHECK (provider IN ('lemonsqueezy', 'nowpayments', 'manual')),
  CONSTRAINT billing_orders_provider_order_ref_unique UNIQUE (provider, provider_order_ref),
  CONSTRAINT billing_orders_provider_order_ref_length CHECK (octet_length(provider_order_ref) BETWEEN 1 AND 128),
  CONSTRAINT billing_orders_lemonsqueezy_ref_format   CHECK (provider <> 'lemonsqueezy' OR (provider_order_ref ~ '^[1-9][0-9]{0,18}$'
                                                             AND (provider_subscription_ref IS NULL OR provider_subscription_ref ~ '^[1-9][0-9]{0,18}$'))),
  CONSTRAINT billing_orders_order_id_format           CHECK (order_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'),
  CONSTRAINT billing_orders_status_known              CHECK (status IN ('paid', 'claimed', 'regenerating', 'revoked')),
  CONSTRAINT billing_orders_claimable_has_claim       CHECK (status NOT IN ('paid', 'regenerating') OR (order_id IS NOT NULL AND claimable_until IS NOT NULL)),
  CONSTRAINT billing_orders_paid_has_no_key           CHECK (status <> 'paid' OR (api_key_id IS NULL AND claimed_at IS NULL)),
  CONSTRAINT billing_orders_claimed_has_key           CHECK (status NOT IN ('claimed', 'regenerating') OR (api_key_id IS NOT NULL AND claimed_at IS NOT NULL))
);
CREATE INDEX idx_billing_orders_api_key_id ON billing_orders(api_key_id);

CREATE TABLE billing_events (
  provider                  TEXT        NOT NULL,
  provider_event_ref        TEXT        NOT NULL,
  event_name                TEXT        NOT NULL,
  provider_order_ref        TEXT,
  provider_subscription_ref TEXT,
  received_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
  billing_action            TEXT        NOT NULL,
  provider_updated_at       TIMESTAMPTZ,
  expires_at                TIMESTAMPTZ,
  PRIMARY KEY (provider, provider_event_ref),
  CONSTRAINT billing_events_provider_known            CHECK (provider IN ('lemonsqueezy', 'nowpayments', 'manual')),
  CONSTRAINT billing_events_billing_action_known      CHECK (billing_action IN ('order_paid', 'set_expiry', 'clear_expiry', 'revoke', 'record')),
  CONSTRAINT billing_events_updated_at_by_action      CHECK ((billing_action IN ('set_expiry', 'clear_expiry')) = (provider_updated_at IS NOT NULL)),
  CONSTRAINT billing_events_expires_at_by_action      CHECK ((billing_action = 'set_expiry') = (expires_at IS NOT NULL)),
  CONSTRAINT billing_events_event_name_format         CHECK (event_name ~ '^[a-z_]{1,64}$'),
  CONSTRAINT billing_events_provider_event_ref_length CHECK (octet_length(provider_event_ref) BETWEEN 1 AND 128),
  CONSTRAINT billing_events_lemonsqueezy_ref_format   CHECK (provider <> 'lemonsqueezy' OR (
               provider_event_ref ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
               AND (provider_order_ref IS NULL OR provider_order_ref ~ '^[1-9][0-9]{0,18}$')
               AND (provider_subscription_ref IS NULL OR provider_subscription_ref ~ '^[1-9][0-9]{0,18}$')))
);
CREATE INDEX idx_billing_events_received_at ON billing_events(received_at);

CREATE TABLE upstream_quota (
  source_name        TEXT        NOT NULL,
  window_seconds     INTEGER     NOT NULL,
  window_start       TIMESTAMPTZ NOT NULL,
  granted_call_count INTEGER     NOT NULL,
  refused_call_count INTEGER     NOT NULL,
  PRIMARY KEY (source_name, window_seconds, window_start),
  CONSTRAINT upstream_quota_window_seconds     CHECK (window_seconds IN (10, 60, 3600, 86400)),
  CONSTRAINT upstream_quota_counts             CHECK (granted_call_count >= 0 AND refused_call_count >= 0),
  CONSTRAINT upstream_quota_source_name_format CHECK (source_name ~ '^[a-z][a-z0-9_]{0,31}$')
);

CREATE TABLE upstream_hold (
  hold_name  TEXT        PRIMARY KEY,
  held_until TIMESTAMPTZ NOT NULL,
  CONSTRAINT upstream_hold_hold_name_format CHECK (hold_name ~ '^[a-z][a-z0-9_]{0,31}(:[a-z0-9.-]{1,253})?$')
);

CREATE UNLOGGED TABLE upstream_cache (
  cache_key  TEXT        PRIMARY KEY,
  body       TEXT        NOT NULL,
  is_error   BOOLEAN     NOT NULL,
  fetched_at TIMESTAMPTZ NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  CONSTRAINT upstream_cache_key_length          CHECK (octet_length(cache_key) BETWEEN 1 AND 512),
  CONSTRAINT upstream_cache_body_length         CHECK (octet_length(body) <= 1048576),
  CONSTRAINT upstream_cache_expires_after_fetch CHECK (expires_at > fetched_at)
);
CREATE INDEX idx_upstream_cache_expires_at ON upstream_cache(expires_at);

CREATE TABLE target_throttle (
  throttle_rule_name TEXT        NOT NULL,
  target_name        TEXT        NOT NULL,
  window_seconds     INTEGER     NOT NULL,
  window_start       TIMESTAMPTZ NOT NULL,
  charged_unit_count INTEGER     NOT NULL,
  PRIMARY KEY (throttle_rule_name, target_name),
  CONSTRAINT target_throttle_window_seconds            CHECK (window_seconds IN (60, 3600)),
  CONSTRAINT target_throttle_charged_unit_count        CHECK (charged_unit_count >= 0),
  CONSTRAINT target_throttle_throttle_rule_name_format CHECK (throttle_rule_name ~ '^[a-z][a-z0-9_]{0,31}$'),
  CONSTRAINT target_throttle_target_name_length        CHECK (octet_length(target_name) BETWEEN 1 AND 253)
);

CREATE TABLE x402_payment (
  message_hash TEXT        PRIMARY KEY,
  source_hash  TEXT        NOT NULL,
  status       TEXT        NOT NULL,
  signature    TEXT,
  reserved_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT x402_payment_message_hash_format    CHECK (message_hash ~ '^[0-9a-f]{64}$'),
  CONSTRAINT x402_payment_source_hash_format     CHECK (source_hash ~ '^[0-9a-f]{64}$'),
  CONSTRAINT x402_payment_status_known           CHECK (status IN ('reserved', 'settled', 'pending', 'released')),
  CONSTRAINT x402_payment_signature_only_pending CHECK (signature IS NULL OR status = 'pending'),
  CONSTRAINT x402_payment_signature_format       CHECK (signature ~ '^[1-9A-HJ-NP-Za-km-z]{64,88}$')
);
CREATE INDEX idx_x402_payment_source_hash_reserved_at ON x402_payment(source_hash, reserved_at);
CREATE INDEX idx_x402_payment_reserved_at ON x402_payment(reserved_at);

CREATE TABLE cves (
  cve_id                  TEXT        PRIMARY KEY,
  cve_description         TEXT        NOT NULL DEFAULT '',
  severity                TEXT        NOT NULL DEFAULT 'UNKNOWN',
  cvss_v3                 REAL        NOT NULL DEFAULT 0.0,
  cvss_v3_vector          TEXT        NOT NULL DEFAULT '',
  cvss_v4                 REAL        NOT NULL DEFAULT 0.0,
  cvss_v4_vector          TEXT        NOT NULL DEFAULT '',
  published_time          DATE        NOT NULL DEFAULT CURRENT_DATE,
  epss_score              REAL        NOT NULL DEFAULT 0.0,
  epss_percentile         REAL        NOT NULL DEFAULT 0.0,
  cwe_id                  TEXT        NOT NULL DEFAULT '',
  cwes                    JSONB       NOT NULL DEFAULT '[]',
  in_kev                  BOOLEAN     NOT NULL DEFAULT FALSE,
  kev_date_added          TEXT        NOT NULL DEFAULT '',
  affected_products       JSONB       NOT NULL DEFAULT '[]',
  refs                    JSONB       NOT NULL DEFAULT '[]',
  vulnerability_status    TEXT        NOT NULL DEFAULT '',
  cve_tags                JSONB       NOT NULL DEFAULT '[]',
  poc_count               INTEGER     NOT NULL DEFAULT 0,
  vendor_advisory_count   INTEGER     NOT NULL DEFAULT 0,
  patch_count             INTEGER     NOT NULL DEFAULT 0,
  has_metasploit          BOOLEAN     NOT NULL DEFAULT FALSE,
  has_nuclei_template     BOOLEAN     NOT NULL DEFAULT FALSE,
  ssvc_exploitation       TEXT,
  ssvc_automatable        TEXT,
  ssvc_technical_impact   TEXT,
  ssvc_version            TEXT,
  ssvc_scored_at          TIMESTAMPTZ,
  cvss_v3_source          TEXT        NOT NULL DEFAULT '',
  cvss_v4_source          TEXT        NOT NULL DEFAULT '',
  cwe_source              TEXT        NOT NULL DEFAULT '',
  exploit_ref_count       INTEGER     NOT NULL DEFAULT 0,
  has_exploitdb           BOOLEAN     NOT NULL DEFAULT FALSE,
  epss_level              SMALLINT    NOT NULL DEFAULT 0,
  nvd_last_modified_at    TIMESTAMPTZ,
  CONSTRAINT cves_cve_id_format CHECK (cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,15}$'),
  CONSTRAINT cves_cvss_v3_range CHECK (cvss_v3 >= 0 AND cvss_v3 <= 10),
  CONSTRAINT cves_cvss_v4_range CHECK (cvss_v4 >= 0 AND cvss_v4 <= 10),
  CONSTRAINT cves_epss_level_range CHECK (epss_level BETWEEN 0 AND 7),
  CONSTRAINT cves_ssvc_exploitation_known     CHECK (ssvc_exploitation IN ('none', 'poc', 'active')),
  CONSTRAINT cves_ssvc_automatable_known      CHECK (ssvc_automatable IN ('no', 'yes')),
  CONSTRAINT cves_ssvc_technical_impact_known CHECK (ssvc_technical_impact IN ('partial', 'total')),
  CONSTRAINT cves_ssvc_version_known          CHECK (ssvc_version IN ('2.0.3')),
  CONSTRAINT cves_cvss_v3_source_known        CHECK (cvss_v3_source IN ('', 'nvd', 'cna', 'adp', 'other')),
  CONSTRAINT cves_cvss_v4_source_known        CHECK (cvss_v4_source IN ('', 'nvd', 'cna', 'adp', 'other')),
  CONSTRAINT cves_cwe_source_known            CHECK (cwe_source     IN ('', 'nvd', 'cna', 'adp', 'other')),
  CONSTRAINT cves_ssvc_all_or_none CHECK (num_nulls(ssvc_exploitation, ssvc_automatable, ssvc_technical_impact, ssvc_version) IN (0, 4)),
  CONSTRAINT cves_ssvc_scored_at_needs_values CHECK (ssvc_scored_at IS NULL OR ssvc_version IS NOT NULL),
  CONSTRAINT cves_refs_objects CHECK (
    CASE WHEN jsonb_typeof(refs) = 'array'
         THEN NOT jsonb_path_exists(refs, 'strict $[*] ? (@.type() != "object")')
         ELSE false END)
);

CREATE INDEX idx_cves_severity       ON cves(severity) INCLUDE (vulnerability_status);
CREATE INDEX idx_cves_published_time ON cves(published_time) INCLUDE (vulnerability_status);
CREATE INDEX idx_cves_epss           ON cves(epss_score) INCLUDE (vulnerability_status);
CREATE INDEX idx_cves_kev            ON cves(cve_id) WHERE in_kev = true;
CREATE INDEX idx_cves_not_rejected ON cves (cve_id) WHERE vulnerability_status <> 'Rejected';
CREATE INDEX idx_cves_cwe_id         ON cves(cwe_id) INCLUDE (vulnerability_status, in_kev, cvss_v3, epss_score);
CREATE INDEX idx_cves_poc_count      ON cves(poc_count);
CREATE INDEX idx_cves_nuclei_published ON cves (published_time DESC, cve_id) INCLUDE (severity, vulnerability_status) WHERE has_nuclei_template;

CREATE FUNCTION public.fn_cve_ref_is_exploit(p_ref jsonb) RETURNS boolean
  LANGUAGE sql IMMUTABLE SECURITY INVOKER
  RETURN coalesce(p_ref -> 'tags' @> '["Exploit"]'
                  OR p_ref ->> 'url' ~* '^https?://(www\.)?(exploit-db\.com/exploits/[0-9]+|(packetstormsecurity\.(com|org|net)|packetstorm\.news)/(files/(view/|id/)?[0-9]+|[0-9]{4}-exploits/.))',
                  false);

CREATE FUNCTION fn_cves_update_ref_counts()
RETURNS TRIGGER LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
  NEW.poc_count := (
    SELECT COUNT(*) FROM jsonb_array_elements(NEW.refs) AS r
    WHERE r->'tags' @> '["Exploit"]'
  );
  NEW.exploit_ref_count := (
    SELECT COUNT(*) FROM jsonb_array_elements(NEW.refs) AS r
    WHERE public.fn_cve_ref_is_exploit(r)
  );
  NEW.vendor_advisory_count := (
    SELECT COUNT(*) FROM jsonb_array_elements(NEW.refs) AS r
    WHERE r->'tags' @> '["Vendor Advisory"]'
  );
  NEW.patch_count := (
    SELECT COUNT(*) FROM jsonb_array_elements(NEW.refs) AS r
    WHERE r->'tags' @> '["Patch"]'
  );
  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_cves_ref_counts
  BEFORE INSERT OR UPDATE OF refs ON cves
  FOR EACH ROW EXECUTE FUNCTION fn_cves_update_ref_counts();

CREATE FUNCTION public.fn_cves_set_has_metasploit()
RETURNS TRIGGER LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
  NEW.has_metasploit := EXISTS (
    SELECT 1 FROM public.metasploit_modules AS mm WHERE mm.cve_id = NEW.cve_id
  );
  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_cves_has_metasploit
  BEFORE INSERT ON cves
  FOR EACH ROW EXECUTE FUNCTION public.fn_cves_set_has_metasploit();

CREATE FUNCTION public.fn_cves_set_has_nuclei_template()
RETURNS TRIGGER LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
  NEW.has_nuclei_template := EXISTS (
    SELECT 1 FROM public.nuclei_templates AS nt WHERE nt.cve_id = NEW.cve_id
  );
  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_cves_has_nuclei_template
  BEFORE INSERT ON cves
  FOR EACH ROW EXECUTE FUNCTION public.fn_cves_set_has_nuclei_template();

CREATE FUNCTION public.fn_cves_set_has_exploitdb()
RETURNS TRIGGER LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
  NEW.has_exploitdb := EXISTS (
    SELECT 1 FROM public.exploitdb_entries AS ee WHERE ee.cve_id = NEW.cve_id
  );
  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_cves_has_exploitdb
  BEFORE INSERT ON cves
  FOR EACH ROW EXECUTE FUNCTION public.fn_cves_set_has_exploitdb();

CREATE FUNCTION public.fn_epss_level_scores() RETURNS numeric[]
  LANGUAGE sql IMMUTABLE SECURITY INVOKER
  RETURN ARRAY[0.05, 0.1, 0.2, 0.3, 0.5, 0.7, 0.9];

CREATE FUNCTION public.fn_epss_score_is_held(p_was_held boolean, p_score real, p_threshold numeric) RETURNS boolean
  LANGUAGE sql IMMUTABLE SECURITY INVOKER
  RETURN p_score::numeric >= p_threshold OR (p_was_held AND p_score::numeric >= 0.8 * p_threshold);

CREATE FUNCTION public.fn_epss_level_next(p_previous_level smallint, p_score real) RETURNS smallint
  LANGUAGE sql IMMUTABLE SECURITY INVOKER
  SET search_path = pg_catalog
  RETURN (SELECT (count(*) FILTER (WHERE public.fn_epss_score_is_held(lv.level <= p_previous_level, p_score, lv.score)))::smallint
            FROM unnest(public.fn_epss_level_scores()) WITH ORDINALITY AS lv (score, level));

CREATE FUNCTION public.fn_cves_set_epss_level()
RETURNS TRIGGER LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    NEW.epss_level := public.fn_epss_level_next(0::smallint, NEW.epss_score);
  ELSE
    NEW.epss_level := public.fn_epss_level_next(OLD.epss_level, NEW.epss_score);
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_cves_epss_level
  BEFORE INSERT OR UPDATE OF epss_score ON cves
  FOR EACH ROW EXECUTE FUNCTION public.fn_cves_set_epss_level();

CREATE TABLE kev_details (
  cve_id               TEXT    PRIMARY KEY REFERENCES cves(cve_id),
  vendor_project       TEXT    NOT NULL DEFAULT '',
  product              TEXT    NOT NULL DEFAULT '',
  patch_deadline       TEXT    NOT NULL DEFAULT '',
  required_action      TEXT    NOT NULL DEFAULT '',
  known_ransomware_use BOOLEAN NOT NULL DEFAULT FALSE,
  vulnerability_name   TEXT    NOT NULL DEFAULT '',
  short_description    TEXT    NOT NULL DEFAULT '',
  notes                TEXT    NOT NULL DEFAULT '',
  cwes                 JSONB   NOT NULL DEFAULT '[]',
  date_removed         TEXT    NOT NULL DEFAULT '',
  updated_at           TEXT    NOT NULL DEFAULT ''
);

CREATE TABLE cve_products (
  id             SERIAL  PRIMARY KEY,
  cve_id         TEXT    NOT NULL REFERENCES cves(cve_id),
  vendor         TEXT    NOT NULL DEFAULT '',
  product        TEXT    NOT NULL DEFAULT '',
  is_vulnerable  BOOLEAN NOT NULL DEFAULT FALSE,
  product_source TEXT    NOT NULL DEFAULT 'nvd',
  CONSTRAINT cve_products_product_source_known CHECK (product_source IN ('nvd', 'cna', 'cna_cpe'))
);

CREATE INDEX idx_products_cve_id  ON cve_products(cve_id);
CREATE INDEX idx_products_vendor  ON cve_products(vendor);
CREATE INDEX idx_products_product ON cve_products(product);
CREATE INDEX idx_products_vulnerable_pair ON cve_products (vendor, product, cve_id) WHERE is_vulnerable;

CREATE FUNCTION public.fn_cve_product_name_max_bytes() RETURNS integer
  LANGUAGE sql IMMUTABLE SECURITY INVOKER
  SET search_path = pg_catalog
  RETURN 128;

CREATE MATERIALIZED VIEW cpe_product_index AS
  SELECT cp.vendor                                                                                      AS vendor,
         cp.product                                                                                     AS product,
         count(DISTINCT cp.cve_id) FILTER (WHERE cp.is_vulnerable)                                      AS vulnerable_cve_count,
         jsonb_agg(DISTINCT cp.product_source ORDER BY cp.product_source)                               AS product_named_by,
         lower(translate(regexp_replace(cp.vendor || ' ' || cp.product, '\\(.)', '\1', 'g'), '_', ' ')) AS search_key
    FROM cve_products AS cp
   WHERE cp.vendor <> '' AND cp.product <> ''
     AND octet_length(cp.vendor) <= public.fn_cve_product_name_max_bytes()
     AND octet_length(cp.product) <= public.fn_cve_product_name_max_bytes()
   GROUP BY cp.vendor, cp.product;

CREATE UNIQUE INDEX idx_cpe_product_index_vendor_product ON cpe_product_index(vendor, product);

CREATE TABLE cwes (
  cwe_id               TEXT         PRIMARY KEY,
  cwe_name             TEXT         NOT NULL  DEFAULT '',
  cwe_description      TEXT         NOT NULL  DEFAULT '',
  extended_description TEXT         NOT NULL  DEFAULT '',
  abstract_type        TEXT         NOT NULL  DEFAULT '',
  cwe_status           TEXT         NOT NULL  DEFAULT '',
  likelihood           TEXT         NOT NULL  DEFAULT '',
  mitigations          JSONB        NOT NULL  DEFAULT '[]',
  examples             JSONB        NOT NULL  DEFAULT '[]',
  parent_cwe           TEXT         NOT NULL  DEFAULT '',
  updated_at           TIMESTAMPTZ
);

CREATE INDEX idx_cwes_parent ON cwes(parent_cwe);

CREATE TABLE epss_history (
  cve_id     TEXT  NOT NULL REFERENCES cves(cve_id),
  epss_date  DATE  NOT NULL,
  score      REAL  NOT NULL,
  percentile REAL  NOT NULL,
  PRIMARY KEY (cve_id, epss_date)
);

CREATE INDEX idx_epss_history_cve_id ON epss_history(cve_id);
CREATE INDEX idx_epss_history_date   ON epss_history(epss_date);

CREATE TABLE upstream_feed_sync (
  feed_name        TEXT        PRIMARY KEY,
  last_synced      TIMESTAMPTZ,
  last_status      TEXT        NOT NULL DEFAULT '',
  records_updated  INTEGER     NOT NULL DEFAULT 0,
  resume_cursor    TEXT,
  delta_window_end TIMESTAMPTZ
);

CREATE TABLE metasploit_modules (
  cve_id      TEXT    NOT NULL,
  module_name TEXT    NOT NULL,
  module_type TEXT    NOT NULL DEFAULT '',
  module_rank INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (cve_id, module_name),
  CONSTRAINT metasploit_modules_cve_id_format CHECK (cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,15}$')
);
CREATE INDEX idx_metasploit_cve ON metasploit_modules(cve_id);

CREATE FUNCTION public.fn_cves_update_has_metasploit()
RETURNS TRIGGER LANGUAGE plpgsql SET search_path = pg_catalog AS $$
DECLARE
  changed_ids text[];
BEGIN
  IF TG_OP = 'TRUNCATE' THEN
    UPDATE public.cves SET has_metasploit = false WHERE has_metasploit;
    RETURN NULL;
  ELSIF TG_OP = 'INSERT' THEN
    SELECT array_agg(n.cve_id) INTO changed_ids FROM new_rows AS n;
  ELSIF TG_OP = 'DELETE' THEN
    SELECT array_agg(o.cve_id) INTO changed_ids FROM old_rows AS o;
  ELSE
    SELECT array_agg(u.cve_id) INTO changed_ids
      FROM (SELECT o.cve_id FROM old_rows AS o
            UNION
            SELECT n.cve_id FROM new_rows AS n) AS u;
  END IF;

  UPDATE public.cves AS c
     SET has_metasploit = EXISTS (SELECT 1 FROM public.metasploit_modules AS mm WHERE mm.cve_id = c.cve_id)
   WHERE c.cve_id = ANY (changed_ids)
     AND c.has_metasploit <> EXISTS (SELECT 1 FROM public.metasploit_modules AS mm WHERE mm.cve_id = c.cve_id);
  RETURN NULL;
END;
$$;

CREATE TRIGGER trg_metasploit_modules_insert
  AFTER INSERT ON metasploit_modules
  REFERENCING NEW TABLE AS new_rows
  FOR EACH STATEMENT EXECUTE FUNCTION public.fn_cves_update_has_metasploit();

CREATE TRIGGER trg_metasploit_modules_delete
  AFTER DELETE ON metasploit_modules
  REFERENCING OLD TABLE AS old_rows
  FOR EACH STATEMENT EXECUTE FUNCTION public.fn_cves_update_has_metasploit();

CREATE TRIGGER trg_metasploit_modules_update
  AFTER UPDATE ON metasploit_modules
  REFERENCING OLD TABLE AS old_rows NEW TABLE AS new_rows
  FOR EACH STATEMENT EXECUTE FUNCTION public.fn_cves_update_has_metasploit();

CREATE TRIGGER trg_metasploit_modules_truncate
  AFTER TRUNCATE ON metasploit_modules
  FOR EACH STATEMENT EXECUTE FUNCTION public.fn_cves_update_has_metasploit();

CREATE TABLE nuclei_templates (
  template_path TEXT NOT NULL PRIMARY KEY,
  cve_id        TEXT NOT NULL,
  template_id   TEXT NOT NULL DEFAULT '',
  template_name TEXT NOT NULL DEFAULT '',
  severity      TEXT NOT NULL DEFAULT '',

  CONSTRAINT nuclei_templates_cve_id_format   CHECK (cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,15}$'),
  CONSTRAINT nuclei_templates_path_format     CHECK ( template_path ~ '^[A-Za-z0-9._/-]+\.yaml$'
                                                      AND strpos(template_path, '..') = 0
                                                      AND octet_length(template_path) <= 256),
  CONSTRAINT nuclei_templates_id_length       CHECK (octet_length(template_id) <= 64),
  CONSTRAINT nuclei_templates_name_length     CHECK (octet_length(template_name) <= 256),
  CONSTRAINT nuclei_templates_severity_known  CHECK (severity IN ('', 'info', 'low', 'medium', 'high', 'critical', 'unknown'))
);
CREATE INDEX idx_nuclei_templates_cve_id ON nuclei_templates(cve_id);

CREATE FUNCTION public.fn_cves_update_has_nuclei_template()
RETURNS TRIGGER LANGUAGE plpgsql SET search_path = pg_catalog AS $$
DECLARE
  changed_ids text[];
BEGIN
  IF TG_OP = 'TRUNCATE' THEN
    UPDATE public.cves SET has_nuclei_template = false WHERE has_nuclei_template;
    RETURN NULL;
  ELSIF TG_OP = 'INSERT' THEN
    SELECT array_agg(n.cve_id) INTO changed_ids FROM new_rows AS n;
  ELSIF TG_OP = 'DELETE' THEN
    SELECT array_agg(o.cve_id) INTO changed_ids FROM old_rows AS o;
  ELSE
    SELECT array_agg(u.cve_id) INTO changed_ids
      FROM (SELECT o.cve_id FROM old_rows AS o
            UNION
            SELECT n.cve_id FROM new_rows AS n) AS u;
  END IF;

  UPDATE public.cves AS c
     SET has_nuclei_template = EXISTS (SELECT 1 FROM public.nuclei_templates AS nt WHERE nt.cve_id = c.cve_id)
   WHERE c.cve_id = ANY (changed_ids)
     AND c.has_nuclei_template <> EXISTS (SELECT 1 FROM public.nuclei_templates AS nt WHERE nt.cve_id = c.cve_id);
  RETURN NULL;
END;
$$;

CREATE TRIGGER trg_nuclei_templates_insert
  AFTER INSERT ON nuclei_templates
  REFERENCING NEW TABLE AS new_rows
  FOR EACH STATEMENT EXECUTE FUNCTION public.fn_cves_update_has_nuclei_template();

CREATE TRIGGER trg_nuclei_templates_delete
  AFTER DELETE ON nuclei_templates
  REFERENCING OLD TABLE AS old_rows
  FOR EACH STATEMENT EXECUTE FUNCTION public.fn_cves_update_has_nuclei_template();

CREATE TRIGGER trg_nuclei_templates_update
  AFTER UPDATE ON nuclei_templates
  REFERENCING OLD TABLE AS old_rows NEW TABLE AS new_rows
  FOR EACH STATEMENT EXECUTE FUNCTION public.fn_cves_update_has_nuclei_template();

CREATE TRIGGER trg_nuclei_templates_truncate
  AFTER TRUNCATE ON nuclei_templates
  FOR EACH STATEMENT EXECUTE FUNCTION public.fn_cves_update_has_nuclei_template();

CREATE TABLE github_poc_repos (
  cve_id         TEXT    NOT NULL,
  repo_full_name TEXT    NOT NULL,
  star_count     INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (cve_id, repo_full_name),

  CONSTRAINT github_poc_repos_cve_id_format    CHECK (cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,15}$'),
  CONSTRAINT github_poc_repos_full_name_format CHECK ( repo_full_name ~ '^[A-Za-z0-9-]+/[A-Za-z0-9._-]+$'
                                                       AND split_part(repo_full_name, '/', 2) NOT IN ('.', '..')
                                                       AND octet_length(repo_full_name) <= 128),
  CONSTRAINT github_poc_repos_star_count_range CHECK (star_count >= 0)
);

CREATE TABLE exploitdb_entries (
  cve_id         TEXT    NOT NULL,
  edb_id         INTEGER NOT NULL,
  date_published DATE,
  exploit_type   TEXT    NOT NULL DEFAULT '',
  platform       TEXT    NOT NULL DEFAULT '',
  verified       BOOLEAN NOT NULL DEFAULT false,
  author         TEXT    NOT NULL DEFAULT '',
  source_url     TEXT,
  PRIMARY KEY (cve_id, edb_id),

  CONSTRAINT exploitdb_entries_cve_id_format       CHECK (cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,15}$'),
  CONSTRAINT exploitdb_entries_edb_id_range        CHECK (edb_id > 0),
  CONSTRAINT exploitdb_entries_exploit_type_format CHECK (exploit_type ~ '^[a-z]{0,16}$'),
  CONSTRAINT exploitdb_entries_platform_format     CHECK (platform ~ '^[A-Za-z0-9_.-]{0,32}$'),
  CONSTRAINT exploitdb_entries_author_visible      CHECK (author !~ '[\u0001-\u001f\u007f]' AND octet_length(author) <= 256),
  CONSTRAINT exploitdb_entries_source_url_format   CHECK (source_url IS NULL
                                                          OR (source_url ~ '^https?://[!-~]+$' AND octet_length(source_url) <= 2048))
);

CREATE FUNCTION public.fn_cves_update_has_exploitdb()
RETURNS TRIGGER LANGUAGE plpgsql SET search_path = pg_catalog AS $$
DECLARE
  changed_ids text[];
BEGIN
  IF TG_OP = 'TRUNCATE' THEN
    UPDATE public.cves SET has_exploitdb = false WHERE has_exploitdb;
    RETURN NULL;
  ELSIF TG_OP = 'INSERT' THEN
    SELECT array_agg(n.cve_id) INTO changed_ids FROM new_rows AS n;
  ELSIF TG_OP = 'DELETE' THEN
    SELECT array_agg(o.cve_id) INTO changed_ids FROM old_rows AS o;
  ELSE
    SELECT array_agg(u.cve_id) INTO changed_ids
      FROM (SELECT o.cve_id FROM old_rows AS o
            UNION
            SELECT n.cve_id FROM new_rows AS n) AS u;
  END IF;

  UPDATE public.cves AS c
     SET has_exploitdb = EXISTS (SELECT 1 FROM public.exploitdb_entries AS ee WHERE ee.cve_id = c.cve_id)
   WHERE c.cve_id = ANY (changed_ids)
     AND c.has_exploitdb <> EXISTS (SELECT 1 FROM public.exploitdb_entries AS ee WHERE ee.cve_id = c.cve_id);
  RETURN NULL;
END;
$$;

CREATE TRIGGER trg_exploitdb_entries_insert
  AFTER INSERT ON exploitdb_entries
  REFERENCING NEW TABLE AS new_rows
  FOR EACH STATEMENT EXECUTE FUNCTION public.fn_cves_update_has_exploitdb();

CREATE TRIGGER trg_exploitdb_entries_delete
  AFTER DELETE ON exploitdb_entries
  REFERENCING OLD TABLE AS old_rows
  FOR EACH STATEMENT EXECUTE FUNCTION public.fn_cves_update_has_exploitdb();

CREATE TRIGGER trg_exploitdb_entries_update
  AFTER UPDATE ON exploitdb_entries
  REFERENCING OLD TABLE AS old_rows NEW TABLE AS new_rows
  FOR EACH STATEMENT EXECUTE FUNCTION public.fn_cves_update_has_exploitdb();

CREATE TRIGGER trg_exploitdb_entries_truncate
  AFTER TRUNCATE ON exploitdb_entries
  FOR EACH STATEMENT EXECUTE FUNCTION public.fn_cves_update_has_exploitdb();

CREATE TABLE cve_change_event (
  event_id       BIGINT      GENERATED ALWAYS AS IDENTITY (SEQUENCE NAME watchlist_event_id_seq) PRIMARY KEY,
  cve_id         TEXT        NOT NULL REFERENCES cves(cve_id),
  event_type     TEXT        NOT NULL,
  changed_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  previous_value REAL,
  current_value  REAL,
  vendor         TEXT,
  product        TEXT,
  CONSTRAINT cve_change_event_type_known CHECK
    (event_type IN ('cve_added', 'kev_added', 'kev_removed', 'epss_changed', 'cvss_added', 'cvss_risk_band_changed', 'exploit_published', 'product_added',
                    'ransomware_linked', 'product_removed', 'vendor_advisory_published', 'patch_published', 'cve_disputed', 'cve_rejected',
                    'metasploit_added', 'nuclei_template_added', 'epss_level_up', 'epss_level_down', 'exploitdb_added', 'ssvc_added',
                    'ssvc_changed', 'github_poc_added', 'description_changed', 'cvss_score_changed', 'cwe_changed', 'kev_updated',
                    'ghsa_linked')),
  CONSTRAINT cve_change_event_product_pair CHECK (
    CASE WHEN event_type IN ('product_added', 'product_removed')
         THEN vendor IS NOT NULL AND product IS NOT NULL
         ELSE vendor IS NULL AND product IS NULL END)
);

CREATE INDEX idx_cve_change_event_cve_id     ON cve_change_event(cve_id, event_id);
CREATE INDEX idx_cve_change_event_changed_at ON cve_change_event(changed_at);

CREATE TABLE watchlist_item (
  item_id       BIGINT  GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  api_key_id    INTEGER NOT NULL REFERENCES api_keys(id) ON DELETE CASCADE,
  endpoint_name TEXT    NOT NULL,
  CONSTRAINT watchlist_item_endpoint_name_known CHECK
    (endpoint_name IN ('cve_lookup', 'kev_lookup', 'cve_exploit', 'product_exposure', 'cve_search', 'dns_lookup', 'ssl_check',
                       'whois_lookup', 'headers_check', 'cert_search', 'package_check', 'ip_lookup')),
  CONSTRAINT watchlist_item_key_unique          UNIQUE (item_id, api_key_id),
  CONSTRAINT watchlist_item_key_endpoint_unique UNIQUE (item_id, api_key_id, endpoint_name)
);

CREATE INDEX idx_watchlist_item_api_key_id ON watchlist_item(api_key_id, item_id);

CREATE TABLE watchlist_item_cve (
  item_id                  BIGINT  PRIMARY KEY,
  api_key_id               INTEGER NOT NULL,
  endpoint_name            TEXT    NOT NULL,
  last_event_id_before_add BIGINT  NOT NULL,
  cve_id                   TEXT,
  vendor                   TEXT,
  product                  TEXT,
  severity                 TEXT,
  cwe_id                   TEXT,
  min_cvss                 REAL,
  min_epss                 REAL,
  in_kev                   BOOLEAN,
  known_ransomware         BOOLEAN,
  has_nuclei_template      BOOLEAN,
  version                  TEXT,
  CONSTRAINT watchlist_item_cve_item_fkey FOREIGN KEY (item_id, api_key_id, endpoint_name)
    REFERENCES watchlist_item (item_id, api_key_id, endpoint_name) ON DELETE CASCADE,
  CONSTRAINT watchlist_item_cve_endpoint_name_known CHECK
    (endpoint_name IN ('cve_lookup', 'kev_lookup', 'cve_exploit', 'product_exposure', 'cve_search')),
  CONSTRAINT watchlist_item_cve_shape CHECK (
    (known_ransomware IS NULL OR known_ransomware)
    AND (has_nuclei_template IS NULL OR has_nuclei_template)
    AND CASE WHEN endpoint_name IN ('cve_lookup', 'kev_lookup', 'cve_exploit')
             THEN cve_id IS NOT NULL
                  AND num_nonnulls(vendor, product, severity, cwe_id, min_cvss, min_epss, in_kev, known_ransomware,
                                   has_nuclei_template, version) = 0
             WHEN endpoint_name = 'product_exposure'
             THEN vendor IS NOT NULL
                  AND product IS NOT NULL
                  AND num_nonnulls(cve_id, severity, cwe_id, min_cvss, min_epss, in_kev, known_ransomware, has_nuclei_template) = 0
             WHEN endpoint_name = 'cve_search'
             THEN cve_id IS NULL
                  AND version IS NULL
                  AND num_nonnulls(vendor, product, severity, cwe_id, min_cvss, min_epss, in_kev, known_ransomware,
                                   has_nuclei_template) >= 1
             ELSE false END),
  CONSTRAINT watchlist_item_cve_version_form CHECK (version ~ '^[!-~]{1,128}$')
);

CREATE UNIQUE INDEX idx_watchlist_item_cve_key_value
  ON watchlist_item_cve (api_key_id, endpoint_name, cve_id, vendor, product, severity, cwe_id, min_cvss, min_epss, in_kev, known_ransomware,
                         has_nuclei_template, version)
  NULLS NOT DISTINCT;

CREATE TABLE watchlist_key_state (
  api_key_id               INTEGER PRIMARY KEY REFERENCES api_keys(id) ON DELETE CASCADE,
  last_key_event_id        BIGINT  NOT NULL DEFAULT 0,
  max_purged_key_event_id  BIGINT  NOT NULL DEFAULT 0,
  last_cve_event_id        BIGINT  NOT NULL,
  CONSTRAINT watchlist_key_state_max_purged_key_event_id_range CHECK (max_purged_key_event_id >= 0),
  CONSTRAINT watchlist_key_state_last_cve_event_id_range       CHECK (last_cve_event_id >= 0),
  CONSTRAINT watchlist_key_state_order                         CHECK (max_purged_key_event_id <= last_key_event_id)
);

CREATE TABLE watchlist_event_cursor (
  api_key_id       INTEGER PRIMARY KEY REFERENCES api_keys(id) ON DELETE CASCADE,
  previous_cursor  BIGINT  NOT NULL,
  delivered_cursor BIGINT  NOT NULL,
  CONSTRAINT watchlist_event_cursor_order CHECK (previous_cursor <= delivered_cursor)
);

CREATE TABLE domain_watch (
  domain_name         TEXT        PRIMARY KEY,
  registered_domain   TEXT        NOT NULL,
  CONSTRAINT domain_watch_domain_name_form CHECK
    (domain_name = lower(domain_name) AND octet_length(domain_name) BETWEEN 1 AND 253),
  CONSTRAINT domain_watch_registered_domain_form CHECK
    (registered_domain = lower(registered_domain) AND octet_length(registered_domain) BETWEEN 1 AND 253)
);

CREATE INDEX idx_domain_watch_registered_domain ON domain_watch(registered_domain);

CREATE TABLE watchlist_item_domain (
  item_id           BIGINT      PRIMARY KEY,
  api_key_id        INTEGER     NOT NULL,
  endpoint_name     TEXT        NOT NULL,
  domain_name       TEXT        NOT NULL,
  registered_domain TEXT        NOT NULL,
  next_scan_at      TIMESTAMPTZ NOT NULL,
  CONSTRAINT watchlist_item_domain_item_fkey FOREIGN KEY (item_id, api_key_id, endpoint_name)
    REFERENCES watchlist_item (item_id, api_key_id, endpoint_name) ON DELETE CASCADE,
  CONSTRAINT watchlist_item_domain_domain_name_fkey FOREIGN KEY (domain_name)
    REFERENCES domain_watch (domain_name) ON DELETE RESTRICT,
  CONSTRAINT watchlist_item_domain_endpoint_name_known CHECK (endpoint_name IN ('dns_lookup', 'ssl_check', 'whois_lookup', 'headers_check',
                                                                                 'cert_search')),
  CONSTRAINT watchlist_item_domain_registered_domain_form CHECK
    (registered_domain = lower(registered_domain) AND octet_length(registered_domain) BETWEEN 1 AND 253),
  CONSTRAINT watchlist_item_domain_key_name_unique UNIQUE (api_key_id, endpoint_name, domain_name)
);

CREATE INDEX idx_watchlist_item_domain_next_scan_at ON watchlist_item_domain(endpoint_name, next_scan_at);
CREATE INDEX idx_watchlist_item_domain_name ON watchlist_item_domain(domain_name, endpoint_name);

CREATE TABLE watchlist_item_domain_value (
  item_id                BIGINT      NOT NULL REFERENCES watchlist_item_domain(item_id) ON DELETE CASCADE,
  value_kind             TEXT        NOT NULL,
  current_value          TEXT        NOT NULL,
  current_value_sha256   TEXT        NOT NULL,
  candidate_value        TEXT,
  candidate_value_sha256 TEXT,
  candidate_seen_at      TIMESTAMPTZ,
  PRIMARY KEY (item_id, value_kind),
  CONSTRAINT watchlist_item_domain_value_kind_known CHECK
    (value_kind IN ('dns_presence', 'ns', 'mx', 'ip_address_reachability', 'cname_takeover', 'email_auth', 'hosting',
                    'certificate_expiry', 'certificate_validity', 'certificate_listing', 'tls_protocol',
                    'registration_expiry', 'registrar', 'transfer_lock', 'dnssec_delegation', 'security_headers',
                    'cert_issuers')),
  CONSTRAINT watchlist_item_domain_value_current_value_sha256_form CHECK (current_value_sha256 ~ '^[0-9a-f]{64}$'),
  CONSTRAINT watchlist_item_domain_value_candidate_value_sha256_form CHECK (candidate_value_sha256 ~ '^[0-9a-f]{64}$'),
  CONSTRAINT watchlist_item_domain_value_candidate_whole CHECK
    (num_nulls(candidate_value, candidate_value_sha256, candidate_seen_at) IN (0, 3))
);

CREATE TABLE domain_change_event (
  event_id                BIGINT      PRIMARY KEY DEFAULT nextval('watchlist_event_id_seq'::regclass),
  domain_name             TEXT        NOT NULL REFERENCES domain_watch(domain_name) ON DELETE CASCADE,
  event_type              TEXT        NOT NULL,
  degraded_email_check_id TEXT,
  changed_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  previous_value          TEXT,
  current_value           TEXT,
  CONSTRAINT domain_change_event_type_known CHECK
    (event_type IN ('domain_not_found', 'domain_found', 'ns_changed', 'mx_changed', 'ip_address_not_public', 'ip_address_lost',
                    'ip_address_restored', 'cname_takeover_detected', 'cname_takeover_resolved', 'email_auth_degraded',
                    'hosting_changed', 'cert_expiring', 'cert_invalid', 'cert_listed', 'tls_downgraded',
                    'domain_expiring', 'registrar_changed', 'transfer_lock_removed', 'dnssec_disabled',
                    'security_header_removed', 'cert_unexpected')),
  CONSTRAINT domain_change_event_degraded_email_check_id_set CHECK
    ((event_type = 'email_auth_degraded') = (degraded_email_check_id IS NOT NULL)),
  CONSTRAINT domain_change_event_degraded_email_check_id_form CHECK (degraded_email_check_id ~ '^[a-z][a-z0-9_]{0,31}$')
);

CREATE INDEX idx_domain_change_event_domain_name ON domain_change_event(domain_name, event_id);
CREATE INDEX idx_domain_change_event_changed_at  ON domain_change_event(changed_at);

CREATE TABLE watchlist_event_ref (
  api_key_id        INTEGER NOT NULL,
  item_id           BIGINT  NOT NULL,
  event_id          BIGINT  NOT NULL,
  key_event_id      BIGINT,
  affects_version   BOOLEAN,
  PRIMARY KEY (item_id, event_id),
  CONSTRAINT watchlist_event_ref_item_fkey FOREIGN KEY (item_id, api_key_id)
    REFERENCES watchlist_item (item_id, api_key_id) ON DELETE CASCADE
);

CREATE INDEX idx_watchlist_event_ref_key_event_id ON watchlist_event_ref(api_key_id, key_event_id);
CREATE INDEX idx_watchlist_event_ref_pending      ON watchlist_event_ref(api_key_id, event_id) WHERE key_event_id IS NULL;
CREATE INDEX idx_watchlist_event_ref_event_id     ON watchlist_event_ref(event_id);

CREATE TABLE package_advisory_change_event (
  event_id                BIGINT      PRIMARY KEY DEFAULT nextval('watchlist_event_id_seq'::regclass),
  advisory_id             TEXT        NOT NULL,
  ecosystem               TEXT        NOT NULL,
  package_name_normalized TEXT        NOT NULL,
  package_name            TEXT        NOT NULL,
  event_type              TEXT        NOT NULL,
  fixed_version           TEXT,
  changed_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT package_advisory_change_event_type_known CHECK (event_type IN ('advisory_added', 'fix_available', 'malware_added')),
  CONSTRAINT package_advisory_change_event_fixed_version_set CHECK ((event_type = 'fix_available') = (fixed_version IS NOT NULL))
);

CREATE INDEX idx_package_advisory_change_event_package    ON package_advisory_change_event(ecosystem, package_name_normalized, event_id);
CREATE INDEX idx_package_advisory_change_event_changed_at ON package_advisory_change_event(changed_at);

CREATE TABLE eol_change_event (
  event_id          BIGINT      PRIMARY KEY DEFAULT nextval('watchlist_event_id_seq'::regclass),
  eol_product       TEXT        NOT NULL,
  cycle_name        TEXT        NOT NULL,
  event_type        TEXT        NOT NULL,
  eol_date          DATE,
  previous_eol_date DATE,
  changed_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT eol_change_event_type_known CHECK (event_type IN ('eol_approaching', 'eol_reached', 'eol_date_changed')),
  CONSTRAINT eol_change_event_eol_date_set CHECK (eol_date IS NOT NULL OR event_type = 'eol_reached'),
  CONSTRAINT eol_change_event_previous_eol_date_set CHECK ((event_type = 'eol_date_changed') = (previous_eol_date IS NOT NULL))
);

CREATE INDEX idx_eol_change_event_product    ON eol_change_event(eol_product, event_id);
CREATE INDEX idx_eol_change_event_changed_at ON eol_change_event(changed_at);

CREATE TABLE change_event_purge_state (
  event_table_name        TEXT   PRIMARY KEY,
  max_purged_event_id     BIGINT NOT NULL DEFAULT 0,
  max_unwatched_event_id  BIGINT NOT NULL DEFAULT 0,
  CONSTRAINT change_event_purge_state_event_table_name
    CHECK (event_table_name IN ('cve_change_event', 'domain_change_event', 'package_advisory_change_event', 'eol_change_event', 'ip_change_event')),
  CONSTRAINT change_event_purge_state_unwatched_domain_only
    CHECK (event_table_name = 'domain_change_event' OR max_unwatched_event_id = 0)
);

INSERT INTO change_event_purge_state (event_table_name)
VALUES ('cve_change_event'), ('domain_change_event'), ('package_advisory_change_event'), ('eol_change_event'), ('ip_change_event');

CREATE TABLE watchlist_item_ip (
  item_id       BIGINT      PRIMARY KEY,
  api_key_id    INTEGER     NOT NULL,
  endpoint_name TEXT        NOT NULL,
  ip_address    INET        NOT NULL,
  checked_at    TIMESTAMPTZ,
  CONSTRAINT watchlist_item_ip_item_fkey FOREIGN KEY (item_id, api_key_id, endpoint_name)
    REFERENCES watchlist_item (item_id, api_key_id, endpoint_name) ON DELETE CASCADE,
  CONSTRAINT watchlist_item_ip_endpoint_name_known CHECK (endpoint_name = 'ip_lookup'),
  CONSTRAINT watchlist_item_ip_ip_address_host CHECK (masklen(ip_address) = CASE family(ip_address) WHEN 4 THEN 32 ELSE 128 END),
  CONSTRAINT watchlist_item_ip_key_address_unique UNIQUE (api_key_id, ip_address)
);

CREATE INDEX idx_watchlist_item_ip_checked_at ON watchlist_item_ip(checked_at NULLS FIRST, item_id);

CREATE TABLE watchlist_item_ip_value (
  item_id           BIGINT      NOT NULL REFERENCES watchlist_item_ip(item_id) ON DELETE CASCADE,
  value_kind        TEXT        NOT NULL,
  current_value     TEXT        NOT NULL,
  candidate_value   TEXT,
  candidate_seen_at TIMESTAMPTZ,
  PRIMARY KEY (item_id, value_kind),
  CONSTRAINT watchlist_item_ip_value_kind_known CHECK (value_kind IN ('drop_listing', 'hosting')),
  CONSTRAINT watchlist_item_ip_value_candidate_whole CHECK (num_nulls(candidate_value, candidate_seen_at) IN (0, 2))
);

CREATE TABLE ip_change_event (
  event_id       BIGINT      PRIMARY KEY DEFAULT nextval('watchlist_event_id_seq'::regclass),
  ip_address     INET        NOT NULL,
  event_type     TEXT        NOT NULL,
  changed_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  previous_value TEXT,
  current_value  TEXT,
  drop_list_time TIMESTAMPTZ,
  drop_copyright TEXT,
  CONSTRAINT ip_change_event_ip_address_host CHECK (masklen(ip_address) = CASE family(ip_address) WHEN 4 THEN 32 ELSE 128 END),
  CONSTRAINT ip_change_event_type_known CHECK (event_type IN ('drop_listed', 'drop_unlisted', 'hosting_changed')),
  CONSTRAINT ip_change_event_drop_attribution_set CHECK
    (CASE WHEN event_type IN ('drop_listed', 'drop_unlisted')
          THEN drop_list_time IS NOT NULL AND drop_copyright IS NOT NULL
          ELSE drop_list_time IS NULL AND drop_copyright IS NULL END),
  CONSTRAINT ip_change_event_value_length CHECK (octet_length(previous_value) <= 4096 AND octet_length(current_value) <= 4096),
  CONSTRAINT ip_change_event_drop_copyright_length CHECK (octet_length(drop_copyright) BETWEEN 1 AND 256)
);

CREATE INDEX idx_ip_change_event_changed_at ON ip_change_event(changed_at);

CREATE TABLE domain_watch_dns_bucket (
  registered_domain   TEXT        PRIMARY KEY,
  question_allowance  REAL        NOT NULL,
  refilled_at         TIMESTAMPTZ NOT NULL
);

CREATE TABLE domain_watch_lane (
  domain_name   TEXT        NOT NULL REFERENCES domain_watch(domain_name) ON DELETE CASCADE,
  lane_name     TEXT        NOT NULL,
  claimed_until TIMESTAMPTZ,
  claimed_at    TIMESTAMPTZ,
  scanned_at    TIMESTAMPTZ,
  not_before    TIMESTAMPTZ,
  PRIMARY KEY (domain_name, lane_name),
  CONSTRAINT domain_watch_lane_name_known CHECK (lane_name IN ('dns', 'tls', 'rdap_whois', 'headers', 'ct'))
);

CREATE FUNCTION public.fn_jsonb_array_or_empty(p_value jsonb) RETURNS jsonb
  LANGUAGE sql IMMUTABLE SECURITY INVOKER
  SET search_path = pg_catalog
  RETURN CASE WHEN jsonb_typeof(p_value) = 'array' THEN p_value ELSE '[]'::jsonb END;

CREATE FUNCTION public.fn_cve_product_is_vulnerable(p_product jsonb) RETURNS boolean
  LANGUAGE sql IMMUTABLE SECURITY INVOKER
  SET search_path = pg_catalog
  RETURN CASE
           WHEN p_product ? 'is_vulnerable'
             THEN coalesce(p_product -> 'is_vulnerable' NOT IN ('false'::jsonb, 'null'::jsonb, '0'::jsonb, '""'::jsonb, '[]'::jsonb, '{}'::jsonb), true)
           WHEN p_product ? 'default_status' OR p_product ? 'versions'
             THEN coalesce(p_product ->> 'default_status' = 'affected', false)
                  OR EXISTS (SELECT 1
                               FROM jsonb_array_elements(public.fn_jsonb_array_or_empty(p_product -> 'versions')) AS version_range (original)
                              WHERE version_range.original ->> 'status' = 'affected')
           ELSE true
         END;

CREATE FUNCTION public.fn_watchlist_event_take_order_lock() RETURNS void
  LANGUAGE sql VOLATILE SECURITY INVOKER
  SET search_path = pg_catalog
  BEGIN ATOMIC
    SELECT pg_advisory_xact_lock('public.watchlist_event_id_seq'::regclass::oid::bigint);
  END;

CREATE DOMAIN attack_technique_id AS text CHECK (VALUE ~ '^T[0-9]{4}(\.[0-9]{3})?$');

CREATE TABLE d3fend_defenses (
  defense_id            TEXT   PRIMARY KEY,
  defense_label         TEXT   NOT NULL,
  defense_tactic        TEXT   NOT NULL,
  digital_artifact      TEXT   NOT NULL DEFAULT '',
  parent_defense_labels TEXT[] NOT NULL DEFAULT '{}',
  CONSTRAINT d3fend_defenses_defense_id_format          CHECK (defense_id ~ '^[A-Za-z][A-Za-z0-9-]{0,63}$'),
  CONSTRAINT d3fend_defenses_defense_label_length       CHECK (octet_length(defense_label) BETWEEN 1 AND 128),
  CONSTRAINT d3fend_defenses_defense_tactic_known       CHECK (defense_tactic IN ('Model', 'Harden', 'Detect', 'Isolate', 'Deceive', 'Evict', 'Restore')),
  CONSTRAINT d3fend_defenses_digital_artifact_length    CHECK (octet_length(digital_artifact) <= 128),
  CONSTRAINT d3fend_defenses_parent_defense_labels_list CHECK (CASE coalesce(array_ndims(parent_defense_labels), 1)
                                                                 WHEN 1 THEN array_position(parent_defense_labels, NULL) IS NULL
                                                                         AND array_position(parent_defense_labels, '') IS NULL
                                                                 ELSE false
                                                               END)
);

CREATE TABLE d3fend_attack_mappings (
  defense_id                 TEXT                NOT NULL REFERENCES d3fend_defenses(defense_id) ON DELETE CASCADE,
  attack_technique_id        attack_technique_id NOT NULL,
  attack_parent_technique_id attack_technique_id GENERATED ALWAYS AS (left(attack_technique_id, 5)) STORED,
  attack_label               TEXT                NOT NULL DEFAULT '',
  PRIMARY KEY (defense_id, attack_technique_id),
  CONSTRAINT d3fend_attack_mappings_attack_label_length CHECK (octet_length(attack_label) <= 128)
);
CREATE INDEX idx_d3fend_attack_mappings_technique ON d3fend_attack_mappings(attack_technique_id);
CREATE INDEX idx_d3fend_attack_mappings_parent    ON d3fend_attack_mappings(attack_parent_technique_id);

CREATE TABLE lol_drivers (
  driver_id            TEXT    PRIMARY KEY,
  category             TEXT    NOT NULL,
  is_verified          BOOLEAN NOT NULL DEFAULT FALSE,
  attack_technique_ids TEXT    NOT NULL DEFAULT '',
  catalog_added        TEXT    NOT NULL DEFAULT '',
  driver_description   TEXT    NOT NULL DEFAULT '',
  use_case             TEXT    NOT NULL DEFAULT '',
  privileges           TEXT    NOT NULL DEFAULT '',
  operating_system     TEXT    NOT NULL DEFAULT '',
  command              TEXT    NOT NULL DEFAULT '',
  tags                 JSONB   NOT NULL DEFAULT '[]',
  detection_rules      JSONB   NOT NULL DEFAULT '[]',
  reference_urls       JSONB   NOT NULL DEFAULT '[]',
  cve_ids              JSONB   NOT NULL DEFAULT '[]',

  CONSTRAINT lol_drivers_driver_id_format            CHECK (driver_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'),
  CONSTRAINT lol_drivers_category_known              CHECK (category IN ('vulnerable driver', 'malicious')),
  CONSTRAINT lol_drivers_attack_technique_ids_format CHECK (attack_technique_ids ~ '^(T[0-9]{4}(\.[0-9]{3})?(, T[0-9]{4}(\.[0-9]{3})?)*)?$' AND octet_length(attack_technique_ids) <= 64),
  CONSTRAINT lol_drivers_catalog_added_format        CHECK (catalog_added ~ '^([0-9]{4}-[0-9]{2}-[0-9]{2})?$'),
  CONSTRAINT lol_drivers_driver_description_length   CHECK (octet_length(driver_description) <= 2048),
  CONSTRAINT lol_drivers_use_case_length             CHECK (octet_length(use_case) <= 1024),
  CONSTRAINT lol_drivers_privileges_length           CHECK (octet_length(privileges) <= 256),
  CONSTRAINT lol_drivers_operating_system_length     CHECK (octet_length(operating_system) <= 128),
  CONSTRAINT lol_drivers_command_length              CHECK (octet_length(command) <= 512),
  CONSTRAINT lol_drivers_tags_list                   CHECK (jsonb_typeof(tags) = 'array' AND octet_length(tags::text) <= 1024),
  CONSTRAINT lol_drivers_detection_rules_list        CHECK (jsonb_typeof(detection_rules) = 'array' AND octet_length(detection_rules::text) <= 12288),
  CONSTRAINT lol_drivers_reference_urls_list         CHECK (jsonb_typeof(reference_urls) = 'array' AND octet_length(reference_urls::text) <= 2048),
  CONSTRAINT lol_drivers_lists_visible               CHECK ((tags::text || detection_rules::text || reference_urls::text) !~ '[\u007f\u200b-\u200d\u2028-\u202e\u2060\u2066-\u2069\ufeff]'),
  CONSTRAINT lol_drivers_cve_ids_list                CHECK (octet_length(cve_ids::text) <= 512),
  CONSTRAINT lol_drivers_cve_ids_format              CHECK (cve_ids::text ~ '^\[("CVE-[0-9]{4}-[0-9]{4,15}"(, "CVE-[0-9]{4}-[0-9]{4,15}")*)?\]$')
);

CREATE TABLE lol_driver_samples (
  driver_id           TEXT    NOT NULL REFERENCES lol_drivers(driver_id) ON DELETE CASCADE,
  sample_index        INTEGER NOT NULL,
  file_name           TEXT    NOT NULL DEFAULT '',
  md5                 TEXT    NOT NULL DEFAULT '',
  sha1                TEXT    NOT NULL DEFAULT '',
  sha256              TEXT    NOT NULL DEFAULT '',
  authentihash_md5    TEXT    NOT NULL DEFAULT '',
  authentihash_sha1   TEXT    NOT NULL DEFAULT '',
  authentihash_sha256 TEXT    NOT NULL DEFAULT '',
  publisher           TEXT    NOT NULL DEFAULT '',
  company             TEXT    NOT NULL DEFAULT '',
  sample_description  TEXT    NOT NULL DEFAULT '',
  original_file_name  TEXT    NOT NULL DEFAULT '',
  file_version        TEXT    NOT NULL DEFAULT '',
  product_version     TEXT    NOT NULL DEFAULT '',
  product_name        TEXT    NOT NULL DEFAULT '',
  imphash             TEXT    NOT NULL DEFAULT '',
  loads_despite_hvci  BOOLEAN,
  PRIMARY KEY (driver_id, sample_index),

  CONSTRAINT lol_driver_samples_sample_index_range         CHECK (sample_index >= 0),
  CONSTRAINT lol_driver_samples_md5_format                 CHECK (md5 ~ '^([0-9a-f]{32})?$'),
  CONSTRAINT lol_driver_samples_sha1_format                CHECK (sha1 ~ '^([0-9a-f]{40})?$'),
  CONSTRAINT lol_driver_samples_sha256_format              CHECK (sha256 ~ '^([0-9a-f]{64})?$'),
  CONSTRAINT lol_driver_samples_authentihash_md5_format    CHECK (authentihash_md5 ~ '^([0-9a-f]{32})?$'),
  CONSTRAINT lol_driver_samples_authentihash_sha1_format   CHECK (authentihash_sha1 ~ '^([0-9a-f]{40})?$'),
  CONSTRAINT lol_driver_samples_authentihash_sha256_format CHECK (authentihash_sha256 ~ '^([0-9a-f]{64})?$'),
  CONSTRAINT lol_driver_samples_file_name_length           CHECK (octet_length(file_name) <= 128),
  CONSTRAINT lol_driver_samples_publisher_length           CHECK (octet_length(publisher) <= 128),
  CONSTRAINT lol_driver_samples_company_length             CHECK (octet_length(company) <= 128),
  CONSTRAINT lol_driver_samples_sample_description_length  CHECK (octet_length(sample_description) <= 256),
  CONSTRAINT lol_driver_samples_original_file_name_length  CHECK (octet_length(original_file_name) <= 128),
  CONSTRAINT lol_driver_samples_file_version_length        CHECK (octet_length(file_version) <= 128),
  CONSTRAINT lol_driver_samples_product_version_length     CHECK (octet_length(product_version) <= 128),
  CONSTRAINT lol_driver_samples_product_name_length        CHECK (octet_length(product_name) <= 256),
  CONSTRAINT lol_driver_samples_imphash_format             CHECK (imphash ~ '^([0-9a-f]{32})?$')
);
CREATE INDEX idx_lol_driver_samples_md5                 ON lol_driver_samples(md5);
CREATE INDEX idx_lol_driver_samples_sha1                ON lol_driver_samples(sha1);
CREATE INDEX idx_lol_driver_samples_sha256              ON lol_driver_samples(sha256);
CREATE INDEX idx_lol_driver_samples_authentihash_md5    ON lol_driver_samples(authentihash_md5);
CREATE INDEX idx_lol_driver_samples_authentihash_sha1   ON lol_driver_samples(authentihash_sha1);
CREATE INDEX idx_lol_driver_samples_authentihash_sha256 ON lol_driver_samples(authentihash_sha256);

CREATE FUNCTION public.fn_osv_number_sortable(p_number text)
  RETURNS text
  LANGUAGE sql IMMUTABLE STRICT SECURITY INVOKER
  SET search_path = pg_catalog
  RETURN CASE WHEN length(ltrim(p_number, '0')) <= 99
              THEN '0' || lpad(length(ltrim(p_number, '0'))::text, 2, '0') || ltrim(p_number, '0')
         END;

CREATE FUNCTION public.fn_osv_pep440_sortable(p_version text)
  RETURNS text[]
  LANGUAGE sql IMMUTABLE SECURITY INVOKER
  SET search_path = pg_catalog
  BEGIN ATOMIC
    WITH folded_version AS (
      SELECT translate(btrim(p_version, E' \t\n\r\f\x0b'),'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz') AS version_text),
    version_part AS (
      SELECT m[1] AS epoch, m[2] AS release_text, m[3] AS pre_letter, m[4] AS pre_number,
             m[5] AS post_number_implicit, m[6] AS post_letter, m[7] AS post_number,
             m[8] AS dev_letter, m[9] AS dev_number, m[10] AS local_version
        FROM folded_version AS fv
       CROSS JOIN LATERAL regexp_match(fv.version_text,
               '^v?(?:([0-9]+)!)?([0-9]+(?:\.[0-9]+)*)'
            || '(?:[-_.]?(alpha|a|beta|b|preview|pre|c|rc)[-_.]?([0-9]+)?)?'
            || '(?:-([0-9]+)|[-_.]?(post|rev|r)[-_.]?([0-9]+)?)?'
            || '(?:[-_.]?(dev)[-_.]?([0-9]+)?)?'
            || '(?:\+([a-z0-9]+(?:[-_.][a-z0-9]+)*))?$') AS m
       WHERE m IS NOT NULL),
    release_number AS (
      SELECT r.number_text, r.number_ordinal
        FROM version_part AS vp
       CROSS JOIN LATERAL unnest(string_to_array(vp.release_text, '.')) WITH ORDINALITY AS r (number_text, number_ordinal)),
    local_segment AS (
      SELECT s.segment_text, s.segment_ordinal
        FROM version_part AS vp
       CROSS JOIN LATERAL unnest(regexp_split_to_array(vp.local_version, '[-_.]')) WITH ORDINALITY AS s (segment_text, segment_ordinal)
       WHERE vp.local_version IS NOT NULL),
    sortable_form AS (
      SELECT ARRAY[public.fn_osv_number_sortable(coalesce(vp.epoch, '0'))]
             || ARRAY(SELECT public.fn_osv_number_sortable(rn.number_text)
                        FROM release_number AS rn
                       WHERE rn.number_ordinal <= coalesce((SELECT max(last_nonzero.number_ordinal) FROM release_number AS last_nonzero WHERE ltrim(last_nonzero.number_text, '0') <> ''), 0)
                       ORDER BY rn.number_ordinal)
             || ARRAY['!',
                      CASE WHEN vp.pre_letter IS NULL AND vp.post_letter IS NULL AND vp.post_number_implicit IS NULL AND vp.dev_letter IS NOT NULL THEN '1'
                           WHEN vp.pre_letter IS NULL THEN '3'
                           ELSE '2' || CASE WHEN vp.pre_letter IN ('a', 'alpha') THEN 'a'
                                            WHEN vp.pre_letter IN ('b', 'beta')  THEN 'b'
                                            ELSE 'c'
                                       END || public.fn_osv_number_sortable(coalesce(vp.pre_number, '0'))
                      END,
                      CASE WHEN vp.post_letter IS NULL AND vp.post_number_implicit IS NULL THEN '1'
                           ELSE '2' || public.fn_osv_number_sortable(coalesce(vp.post_number_implicit, vp.post_number, '0'))
                      END,
                      CASE WHEN vp.dev_letter IS NULL THEN '3'
                           ELSE '2' || public.fn_osv_number_sortable(coalesce(vp.dev_number, '0'))
                      END,
                      CASE WHEN vp.local_version IS NULL THEN '1' ELSE '2' END]
             || ARRAY(SELECT CASE WHEN ls.segment_text ~ '^[0-9]+$' THEN '2' || public.fn_osv_number_sortable(ls.segment_text)
                                  ELSE '1' || ls.segment_text
                             END
                        FROM local_segment AS ls
                       ORDER BY ls.segment_ordinal) AS version_sortable
        FROM version_part AS vp)

    SELECT CASE WHEN array_position(sf.version_sortable, NULL) IS NULL THEN sf.version_sortable END
      FROM sortable_form AS sf;
  END;

CREATE FUNCTION public.fn_osv_maven_sortable(p_version text)
  RETURNS text[]
  LANGUAGE plpgsql IMMUTABLE SECURITY INVOKER
  SET search_path = pg_catalog
AS $$
DECLARE
  keywords         CONSTANT text[] := ARRAY['alpha', 'beta', 'milestone', 'rc', 'snapshot', '', 'sp'];
  folded_version   text;
  segments         text[];
  separators       text[];
  segment_runs     text[];
  token_prefixes   text[] := '{}';
  token_values     text[] := '{}';
  token_value      text;
  number_sortable  text;
  keyword_rank     integer;
  version_sortable text[] := '{}';
  token_count      integer;
  i                integer;
  j                integer;
BEGIN
  IF p_version IS NULL OR p_version !~ '^[0-9][0-9A-Za-z._+-]*$' OR length(p_version) > 256 THEN
    RETURN NULL;
  END IF;
  folded_version := translate(p_version, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz');
  segments := regexp_split_to_array(folded_version, '[-.]');
  separators := ARRAY(SELECT m[1] FROM regexp_matches(folded_version, '([-.])', 'g') AS m);

  FOR i IN 1 .. cardinality(segments) LOOP
    segment_runs := ARRAY(SELECT m[1] FROM regexp_matches(segments[i], '([0-9]+|[^0-9]+)', 'g') AS m);
    IF cardinality(segment_runs) = 0 THEN
      segment_runs := ARRAY[''];
    END IF;
    FOR j IN 1 .. cardinality(segment_runs) LOOP
      token_value := segment_runs[j];
      IF token_value = '' THEN
        token_value := '0';
      ELSIF token_value = 'cr' THEN
        token_value := 'rc';
      ELSIF token_value IN ('ga', 'final', 'release') THEN
        token_value := '';
      ELSIF j < cardinality(segment_runs) AND token_value IN ('a', 'b', 'm') THEN
        token_value := CASE token_value WHEN 'a' THEN 'alpha' WHEN 'b' THEN 'beta' ELSE 'milestone' END;
      ELSIF token_value ~ '^[0-9]+$' THEN
        token_value := coalesce(nullif(ltrim(token_value, '0'), ''), '0');
      END IF;
      token_prefixes := token_prefixes || CASE WHEN j > 1 THEN '-' WHEN i = 1 THEN '' ELSE separators[i - 1] END;
      token_values := token_values || token_value;
    END LOOP;
  END LOOP;

  token_count := cardinality(token_values);
  i := token_count;
  WHILE i > 1 LOOP
    IF token_values[i] IN ('0', '') THEN
      token_prefixes := token_prefixes[1:i - 1] || token_prefixes[i + 1:token_count];
      token_values := token_values[1:i - 1] || token_values[i + 1:token_count];
      token_count := token_count - 1;
      i := i - 1;
      CONTINUE;
    END IF;
    WHILE i >= 1 AND token_prefixes[i] <> '-' LOOP
      i := i - 1;
    END LOOP;
    i := i - 1;
  END LOOP;

  FOR i IN 1 .. token_count LOOP
    token_value := token_values[i];
    IF token_value ~ '^[0-9]+$' THEN
      number_sortable := public.fn_osv_number_sortable(token_value);
      IF number_sortable IS NULL THEN
        RETURN NULL;
      END IF;
      IF i = 1 THEN
        version_sortable := version_sortable || ('2' || number_sortable);
      ELSIF token_prefixes[i] = '-' THEN
        version_sortable := version_sortable || ('7' || number_sortable);
      ELSIF token_value <> '0' THEN
        version_sortable := version_sortable || ('8' || number_sortable);
      ELSE
        j := i + 1;
        WHILE j <= token_count AND token_prefixes[j] = '.' AND token_values[j] = '0' LOOP
          j := j + 1;
        END LOOP;
        keyword_rank := array_position(keywords, token_values[j]) - 1;
        version_sortable := version_sortable || CASE WHEN keyword_rank <= 5 THEN '3' ELSE '8' || number_sortable END;
      END IF;
    ELSE
      keyword_rank := array_position(keywords, token_value) - 1;
      IF token_prefixes[i] = '.' THEN
        IF keyword_rank IS NULL AND left(token_value, 1) = '+' THEN
          RETURN NULL;
        END IF;
        version_sortable := version_sortable || CASE WHEN keyword_rank <= 5 THEN '1' || keyword_rank WHEN keyword_rank = 6 THEN '50' ELSE '51' || token_value END;
      ELSE
        IF keyword_rank = 5 THEN
          RETURN NULL;
        END IF;
        version_sortable := version_sortable || CASE WHEN keyword_rank <= 4 THEN '2' || keyword_rank WHEN keyword_rank = 6 THEN '60' ELSE '61' || token_value END;
      END IF;
    END IF;
  END LOOP;
  RETURN version_sortable || '4'::text;
END;
$$;

CREATE FUNCTION public.fn_osv_maven_order_is_uncertain(p_version_sortable text[], p_bound_sortable text[])
  RETURNS boolean
  LANGUAGE plpgsql IMMUTABLE SECURITY INVOKER
  SET search_path = pg_catalog
AS $$
DECLARE
  i             integer := 1;
  version_token text;
  bound_token   text;
BEGIN
  IF p_version_sortable IS NULL OR p_bound_sortable IS NULL THEN
    RETURN false;
  END IF;
  LOOP
    version_token := p_version_sortable[i];
    bound_token := p_bound_sortable[i];
    IF version_token IS NULL OR bound_token IS NULL THEN
      RETURN false;
    END IF;
    EXIT WHEN NOT (version_token = bound_token OR (version_token IN ('3', '8000') AND bound_token IN ('3', '8000')));
    i := i + 1;
  END LOOP;
  IF i = 1 OR version_token = '4' OR bound_token = '4' THEN
    RETURN false;
  END IF;
  RETURN (version_token = '3' AND left(bound_token, 1) IN ('5', '6', '7')) OR (bound_token = '3' AND left(version_token, 1) IN ('5', '6', '7'))
      OR (left(version_token, 1) = '2' AND left(bound_token, 1) = '5') OR (left(bound_token, 1) = '2' AND left(version_token, 1) = '5');
END;
$$;

CREATE FUNCTION public.fn_osv_nuget_sortable(p_version text)
  RETURNS text[]
  LANGUAGE sql IMMUTABLE SECURITY INVOKER
  SET search_path = pg_catalog
  BEGIN ATOMIC
    WITH parsed_version AS (
      SELECT regexp_match(p_version, '^v?([0-9]+)(?:\.([0-9]+))?(?:\.([0-9]+))?(?:\.([0-9]+))?'
                                     '(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$') AS part
    ),
    prerelease_identifier AS (
      SELECT identifier.identifier_ordinal,
             CASE WHEN identifier.identifier_text ~ '^(0|[1-9][0-9]*)$' THEN '1' || public.fn_osv_number_sortable(identifier.identifier_text)
                  WHEN identifier.identifier_text ~ '^[0-9]+$' OR identifier.identifier_text ~ '^-[0-9]+$' THEN NULL
                  ELSE '2' || translate(identifier.identifier_text, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')
             END AS key_part
        FROM parsed_version
       CROSS JOIN LATERAL unnest(string_to_array(parsed_version.part[5], '.')) WITH ORDINALITY AS identifier (identifier_text, identifier_ordinal)
    ),
    sortable_form AS (
      SELECT ARRAY[public.fn_osv_number_sortable(parsed_version.part[1]),
                   public.fn_osv_number_sortable(coalesce(parsed_version.part[2], '0')),
                   public.fn_osv_number_sortable(coalesce(parsed_version.part[3], '0')),
                   public.fn_osv_number_sortable(coalesce(parsed_version.part[4], '0'))]
             || CASE WHEN parsed_version.part[5] IS NULL THEN ARRAY['2']
                     ELSE '1'::text || ARRAY(SELECT prerelease_identifier.key_part FROM prerelease_identifier ORDER BY prerelease_identifier.identifier_ordinal)
                END AS version_sortable
        FROM parsed_version
       WHERE parsed_version.part IS NOT NULL
    )
    SELECT sortable_form.version_sortable FROM sortable_form WHERE array_position(sortable_form.version_sortable, NULL) IS NULL;
  END;

CREATE FUNCTION public.fn_osv_rubygems_sortable(p_version text)
  RETURNS text[]
  LANGUAGE plpgsql IMMUTABLE SECURITY INVOKER
  SET search_path = pg_catalog
AS $$
DECLARE
  segments            text[];
  release_segments    text[];
  prerelease_segments text[];
  prerelease_start    integer;
  version_sortable    text[] := '{}';
  j                   integer;
BEGIN
  IF p_version IS NULL OR p_version !~ '^[0-9]+(\.[0-9A-Za-z]+)*$' OR length(p_version) > 256 THEN
    RETURN NULL;
  END IF;
  segments := ARRAY(SELECT run.run_text[1]
                  FROM regexp_matches(p_version, '([0-9]+|[A-Za-z]+)', 'g') WITH ORDINALITY AS run (run_text, run_ordinal)
                 ORDER BY run.run_ordinal);
  prerelease_start := coalesce((SELECT min(s.segment_ordinal) FROM unnest(segments) WITH ORDINALITY AS s (segment_text, segment_ordinal) WHERE s.segment_text ~ '^[A-Za-z]'),
                       cardinality(segments) + 1);
  release_segments := segments[1:prerelease_start - 1];
  prerelease_segments := segments[prerelease_start:];
  WHILE cardinality(release_segments) > 0 AND release_segments[cardinality(release_segments)] ~ '^0+$' LOOP
    release_segments := release_segments[1:cardinality(release_segments) - 1];
  END LOOP;
  WHILE cardinality(prerelease_segments) > 0 AND prerelease_segments[cardinality(prerelease_segments)] ~ '^0+$' LOOP
    prerelease_segments := prerelease_segments[1:cardinality(prerelease_segments) - 1];
  END LOOP;
  segments := release_segments || prerelease_segments;
  FOR i IN 1 .. coalesce(cardinality(segments), 0) LOOP
    IF segments[i] ~ '^[A-Za-z]' THEN
      version_sortable := version_sortable || ('1' || segments[i]);
    ELSIF segments[i] ~ '^0+$' THEN
      j := i + 1;
      WHILE segments[j] ~ '^0+$' LOOP
        j := j + 1;
      END LOOP;
      version_sortable := version_sortable || CASE WHEN segments[j] ~ '^[A-Za-z]' THEN '2' ELSE '4' END;
    ELSIF length(ltrim(segments[i], '0')) > 99 THEN
      RETURN NULL;
    ELSE
      version_sortable := version_sortable || ('5' || public.fn_osv_number_sortable(segments[i]));
    END IF;
  END LOOP;
  RETURN version_sortable || '3'::text;
END;
$$;

CREATE FUNCTION public.fn_osv_packagist_sortable(p_version text)
  RETURNS text[]
  LANGUAGE sql IMMUTABLE SECURITY INVOKER
  SET search_path = pg_catalog
  BEGIN ATOMIC
    WITH parsed_version AS (
      SELECT regexp_match(p_version, '^v?([0-9]{1,5})\.([0-9]+)\.([0-9]+)'
                                     '(?:[-._]?(alpha|beta|a|b|RC|rc|pl|p)(?:[.-]?([0-9]+))?|(-dev))?$') AS part
    ),
    sortable_form AS (
      SELECT ARRAY[public.fn_osv_number_sortable(parsed_version.part[1]),
                   public.fn_osv_number_sortable(parsed_version.part[2]),
                   public.fn_osv_number_sortable(parsed_version.part[3]),
                   CASE WHEN parsed_version.part[6] IS NOT NULL THEN '1'
                        WHEN parsed_version.part[4] IS NULL THEN '5'
                        WHEN parsed_version.part[4] IN ('alpha', 'a') THEN '2'
                        WHEN parsed_version.part[4] IN ('beta', 'b') THEN '3'
                        WHEN parsed_version.part[4] IN ('RC', 'rc') THEN '4'
                        ELSE '6' END]
             || CASE WHEN parsed_version.part[5] IS NULL THEN '{}'::text[] ELSE ARRAY[public.fn_osv_number_sortable(parsed_version.part[5])] END AS version_sortable
        FROM parsed_version
       WHERE parsed_version.part IS NOT NULL
    )
    SELECT sortable_form.version_sortable FROM sortable_form WHERE array_position(sortable_form.version_sortable, NULL) IS NULL;
  END;

CREATE FUNCTION public.fn_osv_semver_sortable(p_ecosystem text, p_version text)
  RETURNS text[]
  LANGUAGE sql IMMUTABLE SECURITY INVOKER
  SET search_path = pg_catalog
  BEGIN ATOMIC
    WITH parsed_version AS (
      SELECT regexp_match(CASE WHEN p_ecosystem = 'Go' THEN regexp_replace(p_version, '^v', '') ELSE p_version END,
                          '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$') AS part
       WHERE p_ecosystem IN ('npm', 'Go', 'crates.io', 'SwiftURL')),
    identifier AS (
      SELECT i.identifier_ordinal, i.identifier_text, i.identifier_ordinal = 4 AS is_marker
        FROM parsed_version AS pv
       CROSS JOIN LATERAL unnest(ARRAY[pv.part[1], pv.part[2], pv.part[3], CASE WHEN pv.part[4] IS NULL THEN 'b_release' ELSE 'a_prerelease' END]
                                 || coalesce(string_to_array(substr(pv.part[4], 2), '.'), '{}')) WITH ORDINALITY AS i (identifier_text, identifier_ordinal)
       WHERE pv.part IS NOT NULL),
    encoded AS (
      SELECT i.identifier_ordinal,
             CASE WHEN i.is_marker                                                     THEN i.identifier_text
                  WHEN i.identifier_text !~ '^[0-9]+$'                                 THEN '1' || i.identifier_text
                  WHEN i.identifier_text ~ '^0[0-9]' OR length(i.identifier_text) > 99 THEN NULL
                  ELSE '0' || lpad(length(ltrim(i.identifier_text, '0'))::text, 2, '0') || ltrim(i.identifier_text, '0')
             END AS key_part
        FROM identifier AS i)

    SELECT CASE WHEN count(*) = 0 OR bool_or(e.key_part IS NULL) THEN NULL
                ELSE array_agg(e.key_part ORDER BY e.identifier_ordinal)
           END
      FROM encoded AS e;
  END;

CREATE FUNCTION public.fn_osv_version_sortable(p_ecosystem text, p_version text)
  RETURNS text[]
  LANGUAGE plpgsql IMMUTABLE SECURITY INVOKER
  SET search_path = pg_catalog
AS $$
BEGIN
  IF p_ecosystem = 'PyPI' THEN
    RETURN public.fn_osv_pep440_sortable(p_version);
  ELSIF p_ecosystem = 'Maven' THEN
    RETURN public.fn_osv_maven_sortable(p_version);
  ELSIF p_ecosystem = 'NuGet' THEN
    RETURN public.fn_osv_nuget_sortable(p_version);
  ELSIF p_ecosystem = 'RubyGems' THEN
    RETURN public.fn_osv_rubygems_sortable(p_version);
  ELSIF p_ecosystem = 'Packagist' THEN
    RETURN public.fn_osv_packagist_sortable(p_version);
  END IF;
  RETURN public.fn_osv_semver_sortable(p_ecosystem, p_version);
END;
$$;

CREATE FUNCTION public.fn_osv_normalize_package_name(p_ecosystem text, p_package_name text) RETURNS text
  LANGUAGE sql IMMUTABLE SECURITY INVOKER
  SET search_path = pg_catalog
  RETURN CASE WHEN p_ecosystem = 'PyPI'                         THEN lower(regexp_replace(p_package_name, '[-_.]+', '-', 'g'))
              WHEN p_ecosystem IN ('npm', 'NuGet', 'Packagist') THEN lower(p_package_name)
              ELSE p_package_name
         END;

CREATE TABLE osv_advisories (
  advisory_id    TEXT        PRIMARY KEY,
  source         TEXT        NOT NULL,
  license        TEXT        NOT NULL,
  summary        TEXT        NOT NULL DEFAULT '',
  aliases        TEXT[]      NOT NULL DEFAULT '{}',
  published_time TIMESTAMPTZ NOT NULL,
  modified_time  TIMESTAMPTZ NOT NULL,

  CONSTRAINT osv_advisories_advisory_id_format CHECK (advisory_id ~ '^(GHSA|GO|PYSEC|RUSTSEC|MAL)-[0-9A-Za-z-]{1,40}$'),
  CONSTRAINT osv_advisories_source_known       CHECK ((source = 'ghsa'    AND advisory_id LIKE 'GHSA-%')
                                                   OR (source = 'go'      AND advisory_id LIKE 'GO-%')
                                                   OR (source = 'pysec'   AND advisory_id LIKE 'PYSEC-%')
                                                   OR (source = 'rustsec' AND advisory_id LIKE 'RUSTSEC-%')
                                                   OR (source = 'mal'     AND advisory_id LIKE 'MAL-%')),
  CONSTRAINT osv_advisories_license_known      CHECK ((source IN ('ghsa', 'go', 'pysec') AND license = 'CC-BY-4.0')
                                                   OR (source = 'rustsec' AND license IN ('CC0-1.0', 'CC-BY-4.0'))
                                                   OR (source = 'mal'     AND license = 'Apache-2.0')),
  CONSTRAINT osv_advisories_summary_length     CHECK (octet_length(summary) <= 1024),
  CONSTRAINT osv_advisories_summary_visible    CHECK (summary !~ '[\u0001-\u001f\u007f\u200b-\u200d\u2028-\u202e\u2060\u2066-\u2069\ufeff]'),
  CONSTRAINT osv_advisories_aliases_list       CHECK (cardinality(aliases) <= 64
                                                      AND array_position(aliases, NULL) IS NULL
                                                      AND array_to_string(aliases, ' ') ~ '^([!-~]{1,64}( [!-~]{1,64})*)?$'
                                                      AND cardinality(string_to_array(array_to_string(aliases, ' '), ' ')) = cardinality(aliases))
);

CREATE INDEX idx_osv_advisories_aliases ON osv_advisories USING gin (aliases);

CREATE TABLE osv_affected (
  advisory_id               TEXT    NOT NULL REFERENCES osv_advisories(advisory_id) ON DELETE CASCADE,
  affected_index            INTEGER NOT NULL,
  ecosystem                 TEXT    NOT NULL,
  package_name              TEXT    NOT NULL,
  package_name_normalized   TEXT    NOT NULL GENERATED ALWAYS AS (public.fn_osv_normalize_package_name(ecosystem, package_name)) STORED,
  version_ranges            JSONB   NOT NULL DEFAULT '[]',
  listed_versions           TEXT[]  NOT NULL DEFAULT '{}',
  listed_versions_sortable  TEXT[]  NOT NULL DEFAULT '{}',
  is_unaffected_provable    BOOLEAN NOT NULL DEFAULT false,
  PRIMARY KEY (advisory_id, affected_index),

  CONSTRAINT osv_affected_affected_index_range CHECK (affected_index >= 0),
  CONSTRAINT osv_affected_ecosystem_known      CHECK (ecosystem IN ('npm', 'PyPI', 'Maven', 'Go', 'NuGet', 'RubyGems', 'crates.io', 'Packagist', 'SwiftURL')),
  CONSTRAINT osv_affected_package_name_format  CHECK (package_name !~ '[\u0001-\u0020\u007f]' AND octet_length(package_name) BETWEEN 1 AND 256),
  CONSTRAINT osv_affected_version_ranges_list  CHECK (jsonb_typeof(version_ranges) = 'array' AND octet_length(version_ranges::text) <= 8192)
);
CREATE INDEX idx_osv_affected_package ON osv_affected(ecosystem, package_name_normalized);

CREATE TABLE watchlist_item_package (
  item_id                  BIGINT  PRIMARY KEY,
  api_key_id               INTEGER NOT NULL,
  endpoint_name            TEXT    NOT NULL,
  last_event_id_before_add BIGINT  NOT NULL,
  ecosystem                TEXT    NOT NULL,
  package_name             TEXT    NOT NULL,
  package_name_normalized  TEXT    NOT NULL GENERATED ALWAYS AS (public.fn_osv_normalize_package_name(ecosystem, package_name)) STORED,
  version                  TEXT,
  CONSTRAINT watchlist_item_package_item_fkey FOREIGN KEY (item_id, api_key_id, endpoint_name)
    REFERENCES watchlist_item (item_id, api_key_id, endpoint_name) ON DELETE CASCADE,
  CONSTRAINT watchlist_item_package_endpoint_name_known CHECK (endpoint_name = 'package_check'),
  CONSTRAINT watchlist_item_package_ecosystem_known     CHECK (ecosystem IN ('npm', 'PyPI', 'Maven', 'Go', 'NuGet', 'RubyGems', 'crates.io',
                                                                             'Packagist', 'SwiftURL')),
  CONSTRAINT watchlist_item_package_package_name_format CHECK (package_name !~ '[\u0001-\u0020\u007f]' AND octet_length(package_name) BETWEEN 1 AND 256),
  CONSTRAINT watchlist_item_package_version_form        CHECK (version ~ '^[!-~]{1,128}$'),
  CONSTRAINT watchlist_item_package_key_package_unique  UNIQUE NULLS NOT DISTINCT (api_key_id, ecosystem, package_name_normalized, version)
);

CREATE TABLE osv_affected_version_intervals (
  advisory_id                 TEXT    NOT NULL,
  affected_index              INTEGER NOT NULL,
  interval_index              INTEGER NOT NULL,
  introduced_version_sortable TEXT[]  COLLATE "C",
  upper_version_sortable      TEXT[]  COLLATE "C",
  upper_event                 TEXT,
  fixed_version               TEXT,
  PRIMARY KEY (advisory_id, affected_index, interval_index),
  FOREIGN KEY (advisory_id, affected_index) REFERENCES osv_affected(advisory_id, affected_index) ON DELETE CASCADE,

  CONSTRAINT osv_affected_version_intervals_upper_event_known CHECK (upper_event IN ('fixed', 'last_affected')),
  CONSTRAINT osv_affected_version_intervals_upper_complete    CHECK ((upper_event IS NULL) = (upper_version_sortable IS NULL)),
  CONSTRAINT osv_affected_version_intervals_fixed_version_format CHECK ((upper_event IS NOT DISTINCT FROM 'fixed') = (fixed_version IS NOT NULL)
                                                                AND fixed_version ~ '^[!-~]{1,128}$')
);

CREATE TABLE ip_asn (
  asn       BIGINT  PRIMARY KEY,
  asn_name  TEXT    NOT NULL,
  country   TEXT,

  CONSTRAINT ip_asn_asn_range       CHECK (asn BETWEEN 1 AND 4294967295),
  CONSTRAINT ip_asn_asn_name_format CHECK (octet_length(asn_name) BETWEEN 1 AND 256 AND asn_name !~ '[\u0001-\u001f\u007f-\u009f]'),
  CONSTRAINT ip_asn_country_format  CHECK (country ~ '^[A-Z]{2}$')
);

CREATE TABLE ip_asn_prefix (
  prefix  CIDR    PRIMARY KEY,
  asn     BIGINT  NOT NULL REFERENCES ip_asn (asn)
);
CREATE INDEX idx_ip_asn_prefix_prefix ON ip_asn_prefix USING gist (prefix inet_ops);
CREATE INDEX idx_ip_asn_prefix_asn ON ip_asn_prefix (asn, prefix);

CREATE TABLE ip_geo_prefix (
  prefix    CIDR  PRIMARY KEY,
  country   TEXT  NOT NULL,

  CONSTRAINT ip_geo_prefix_country_format CHECK (country ~ '^[A-Z]{2}$')
);
CREATE INDEX idx_ip_geo_prefix_prefix ON ip_geo_prefix USING gist (prefix inet_ops);

CREATE TABLE ip_cloud_range (
  provider    TEXT          NOT NULL,
  service     TEXT          NOT NULL,
  prefix      CIDR          NOT NULL,
  is_cdn      BOOLEAN       NOT NULL,
  synced_at   TIMESTAMPTZ   NOT NULL,
  PRIMARY KEY (provider, service, prefix),

  CONSTRAINT ip_cloud_range_provider_known CHECK (provider IN ('aws', 'google', 'azure', 'cloudflare', 'fastly', 'bunny', 'gcore')),
  CONSTRAINT ip_cloud_range_service_format CHECK (service ~ '^[a-z][a-z0-9_]{0,31}$'),
  CONSTRAINT ip_cloud_range_prefix_min_len CHECK (masklen(prefix) >= CASE family(prefix) WHEN 4 THEN 8 ELSE 24 END)
);
CREATE INDEX idx_ip_cloud_range_prefix ON ip_cloud_range USING gist (prefix inet_ops);

CREATE TABLE ip_tor_exit (
  ip_address  INET  PRIMARY KEY,

  CONSTRAINT ip_tor_exit_ip_address_host CHECK (masklen(ip_address) = CASE family(ip_address) WHEN 4 THEN 32 ELSE 128 END)
);

CREATE TABLE ip_drop_list_prefix (
  prefix              CIDR          PRIMARY KEY,
  listing_id          TEXT          NOT NULL,
  regional_registry   TEXT          NOT NULL,
  list_time           TIMESTAMPTZ   NOT NULL,
  copyright           TEXT          NOT NULL,

  CONSTRAINT ip_drop_list_prefix_listing_id_format        CHECK (listing_id ~ '^SBL[0-9]{1,10}$'),
  CONSTRAINT ip_drop_list_prefix_regional_registry_format CHECK (regional_registry ~ '^[a-z]{1,16}$'),
  CONSTRAINT ip_drop_list_prefix_copyright_format         CHECK (octet_length(copyright) BETWEEN 1 AND 256 AND copyright !~ '[\u0001-\u001f\u007f-\u009f]')
);
CREATE INDEX idx_ip_drop_list_prefix_prefix ON ip_drop_list_prefix USING gist (prefix inet_ops);

CREATE TABLE email_disposable_domain (
  domain  TEXT  PRIMARY KEY,

  CONSTRAINT email_disposable_domain_domain_format CHECK (octet_length(domain) <= 253 AND domain ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$')
);

CREATE TABLE ssl_blacklist_certificate (
  sha1            TEXT          PRIMARY KEY,
  listing_reason  TEXT          NOT NULL,
  listing_time    TIMESTAMPTZ   NOT NULL,

  CONSTRAINT ssl_blacklist_certificate_sha1_format           CHECK (sha1 ~ '^[0-9a-f]{40}$'),
  CONSTRAINT ssl_blacklist_certificate_listing_reason_format CHECK (listing_reason ~ '^[A-Za-z0-9 &.()/_-]{1,128}$')
);

CREATE TABLE eol_product (
  product_name   TEXT   PRIMARY KEY,
  product_label  TEXT   NOT NULL,
  url            TEXT   NOT NULL,

  CONSTRAINT eol_product_name_length  CHECK (octet_length(product_name) BETWEEN 1 AND 64),
  CONSTRAINT eol_product_label_length CHECK (octet_length(product_label) BETWEEN 1 AND 128),
  CONSTRAINT eol_product_url_format   CHECK (url LIKE 'https://%' AND octet_length(url) <= 256)
);

CREATE TABLE eol_cycle (
  eol_product                 TEXT      NOT NULL REFERENCES eol_product (product_name) ON DELETE CASCADE,
  cycle_name                  TEXT      NOT NULL,
  release_date                DATE      NOT NULL,
  eol_date                    DATE,
  is_eol                      BOOLEAN   NOT NULL,
  is_maintained               BOOLEAN   NOT NULL,
  is_lts                      BOOLEAN   NOT NULL,
  latest_version              TEXT,
  approaching_fired_eol_date  DATE,
  is_reached_fired            BOOLEAN NOT NULL DEFAULT false,

  PRIMARY KEY (eol_product, cycle_name),
  CONSTRAINT eol_cycle_name_length           CHECK (octet_length(cycle_name) BETWEEN 1 AND 100),
  CONSTRAINT eol_cycle_latest_version_length CHECK (octet_length(latest_version) BETWEEN 1 AND 100)
);

CREATE TABLE eol_product_cpe (
  vendor       TEXT   NOT NULL,
  product      TEXT   NOT NULL,
  eol_product  TEXT   NOT NULL,
  series       TEXT,
  source       TEXT   NOT NULL,

  PRIMARY KEY (vendor, product, eol_product, source),
  CONSTRAINT eol_product_cpe_source             CHECK (source IN ('endoflife', 'manual')),
  CONSTRAINT eol_product_cpe_series_manual_only CHECK (series IS NULL OR source = 'manual'),
  CONSTRAINT eol_product_cpe_pair_length        CHECK (octet_length(vendor) BETWEEN 1 AND 128 AND octet_length(product) BETWEEN 1 AND 128)
);

CREATE TABLE eol_product_package (
  ecosystem                TEXT   NOT NULL,
  package_name             TEXT   NOT NULL,
  package_name_normalized  TEXT   NOT NULL GENERATED ALWAYS AS (public.fn_osv_normalize_package_name(ecosystem, package_name)) STORED,
  eol_product              TEXT   NOT NULL REFERENCES eol_product (product_name) ON DELETE CASCADE,

  PRIMARY KEY (ecosystem, package_name_normalized, eol_product),
  CONSTRAINT eol_product_package_ecosystem_known     CHECK (ecosystem IN ('npm', 'PyPI', 'Maven', 'Go', 'NuGet', 'RubyGems', 'crates.io', 'Packagist', 'SwiftURL')),
  CONSTRAINT eol_product_package_package_name_format CHECK (package_name !~ '[\u0001-\u0020\u007f]' AND octet_length(package_name) BETWEEN 1 AND 256)
);

CREATE FUNCTION public.fn_eol_cycle_is_in_series(p_series text, p_cycle text) RETURNS boolean
  LANGUAGE sql IMMUTABLE SECURITY INVOKER
  RETURN p_cycle = p_series
         OR (left(p_cycle, length(p_series) + 1) = p_series || '-'
             AND substr(p_cycle, length(p_series) + 2) ~ '^(w|e|lts|iot)(-(w|e|lts|iot))*$');

CREATE FUNCTION public.fn_eol_cycle_is_reached(p_eol_date date, p_is_eol boolean) RETURNS boolean
  LANGUAGE sql STABLE SECURITY INVOKER
  RETURN CASE WHEN p_eol_date IS NOT NULL THEN p_eol_date <= current_date ELSE p_is_eol END;

CREATE FUNCTION public.fn_eol_date_is_approaching(p_eol_date date) RETURNS boolean
  LANGUAGE sql STABLE SECURITY INVOKER
  RETURN p_eol_date BETWEEN current_date AND current_date + 90;

CREATE FUNCTION public.fn_eol_product_cpe_pick(p_vendor text, p_product text)
  RETURNS TABLE (eol_product text,
                 series      text)
  LANGUAGE sql STABLE SECURITY INVOKER
  SET search_path = pg_catalog
  BEGIN ATOMIC
    SELECT epc.eol_product AS eol_product,
           epc.series      AS series
      FROM public.eol_product_cpe AS epc
      JOIN public.eol_product AS ep ON ep.product_name = epc.eol_product
     WHERE epc.vendor = p_vendor AND epc.product = p_product
     ORDER BY CASE epc.source WHEN 'endoflife' THEN 0 ELSE 1 END, epc.eol_product
     LIMIT 1;
  END;

CREATE FUNCTION public.fn_eol_product_package_pick(p_ecosystem text, p_package_name_normalized text)
  RETURNS TABLE (eol_product text)
  LANGUAGE sql STABLE SECURITY INVOKER
  SET search_path = pg_catalog
  BEGIN ATOMIC
    SELECT epp.eol_product AS eol_product
      FROM public.eol_product_package AS epp
     WHERE epp.ecosystem = p_ecosystem AND epp.package_name_normalized = p_package_name_normalized
     ORDER BY epp.eol_product
     LIMIT 1;
  END;

CREATE FUNCTION public.fn_eol_pick_series(p_eol_product text, p_series text, p_version text) RETURNS text
  LANGUAGE sql STABLE SECURITY INVOKER
  SET search_path = pg_catalog
  BEGIN ATOMIC
    SELECT coalesce(p_series,
                    (SELECT version.name
                      WHERE EXISTS (SELECT 1 FROM public.eol_cycle AS ec
                                     WHERE ec.eol_product = p_eol_product AND public.fn_eol_cycle_is_in_series(version.name, ec.cycle_name))),
                    (SELECT ec.cycle_name
                       FROM public.eol_cycle AS ec
                      WHERE ec.eol_product = p_eol_product AND left(version.name, length(ec.cycle_name) + 1) = ec.cycle_name || '.'
                      ORDER BY length(ec.cycle_name) DESC
                      LIMIT 1)) AS series
      FROM (SELECT CASE WHEN left(p_version, 1) = 'v' THEN substr(p_version, 2) ELSE p_version END) AS version (name);
  END;
