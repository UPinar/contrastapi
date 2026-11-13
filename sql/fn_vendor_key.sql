CREATE FUNCTION api.fn_vendor_key_fingerprint(p_key_hash text) RETURNS text
  LANGUAGE sql STABLE STRICT SECURITY INVOKER
  RETURN left(encode(sha256(convert_to(p_key_hash, 'UTF8')), 'hex'), 32);

CREATE FUNCTION api.fn_vendor_key_read(p_key_hash text)
  RETURNS TABLE (api_key_id           integer,
                 key_fingerprint      text,
                 shodan_sealed_hex    text,
                 abuseipdb_sealed_hex text)
  LANGUAGE sql STABLE SECURITY DEFINER
  SET search_path = pg_catalog
  BEGIN ATOMIC
    SELECT ak.id                                      AS api_key_id,
           api.fn_vendor_key_fingerprint(ak.key_hash) AS key_fingerprint,
           vk1.sealed_hex                             AS shodan_sealed_hex,
           vk2.sealed_hex                             AS abuseipdb_sealed_hex
      FROM (VALUES (1)) AS one_row (n)
      LEFT JOIN public.api_keys AS ak ON ak.key_hash = p_key_hash AND api.fn_api_key_is_active(ak.active, ak.expires_at)
      LEFT JOIN public.vendor_key AS vk1 ON vk1.api_key_id = ak.id AND vk1.vendor_name = 'shodan'
      LEFT JOIN public.vendor_key AS vk2 ON vk2.api_key_id = ak.id AND vk2.vendor_name = 'abuseipdb';
  END;

CREATE FUNCTION api.fn_vendor_key_link_open(p_api_key_id integer, p_link_hash text, p_link_lifetime_seconds integer) RETURNS bigint
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER
  SET search_path = pg_catalog
AS $$
DECLARE
  link_expires_at timestamptz;
BEGIN
  IF p_link_lifetime_seconds IS NULL OR p_link_lifetime_seconds < 1 THEN
    RAISE EXCEPTION 'api.fn_vendor_key_link_open takes a lifetime of at least one second';
  END IF;

  INSERT INTO public.vendor_key_link AS vkl (link_hash, api_key_id, key_fingerprint, expires_at)
  SELECT p_link_hash, ak.id, api.fn_vendor_key_fingerprint(ak.key_hash), now() + make_interval(secs => p_link_lifetime_seconds)
    FROM public.api_keys AS ak
   WHERE ak.id = p_api_key_id AND api.fn_api_key_is_active(ak.active, ak.expires_at)
  RETURNING vkl.expires_at INTO link_expires_at;
  RETURN floor(extract(epoch FROM link_expires_at))::bigint;
END
$$;

CREATE FUNCTION api.fn_vendor_key_link_read(p_link_hash text)
  RETURNS TABLE (link_state           text,
                 api_key_id           integer,
                 link_expires_at      bigint,
                 shodan_sealed_hex    text,
                 abuseipdb_sealed_hex text)
  LANGUAGE sql STABLE SECURITY DEFINER
  SET search_path = pg_catalog
  BEGIN ATOMIC
    SELECT link_check.link_state                                                                               AS link_state,
           CASE WHEN link_check.link_state = 'open' THEN vkl.api_key_id END                                    AS api_key_id,
           CASE WHEN link_check.link_state = 'open' THEN floor(extract(epoch FROM vkl.expires_at))::bigint END AS link_expires_at,
           vk1.sealed_hex                                                                                      AS shodan_sealed_hex,
           vk2.sealed_hex                                                                                      AS abuseipdb_sealed_hex
      FROM (VALUES (1)) AS one_row (n)
      LEFT JOIN public.vendor_key_link AS vkl ON vkl.link_hash = p_link_hash
      LEFT JOIN public.api_keys AS ak ON ak.id = vkl.api_key_id
      CROSS JOIN LATERAL (SELECT CASE WHEN ak.id IS NULL OR NOT api.fn_api_key_is_active(ak.active, ak.expires_at)
                                        OR api.fn_vendor_key_fingerprint(ak.key_hash) <> vkl.key_fingerprint THEN 'invalid'
                                      WHEN vkl.expires_at <= now() THEN 'expired'
                                      ELSE 'open' END) AS link_check (link_state)
      LEFT JOIN public.vendor_key AS vk1 ON link_check.link_state = 'open' AND vk1.api_key_id = vkl.api_key_id AND vk1.vendor_name = 'shodan'
      LEFT JOIN public.vendor_key AS vk2 ON link_check.link_state = 'open' AND vk2.api_key_id = vkl.api_key_id AND vk2.vendor_name = 'abuseipdb';
  END;

CREATE FUNCTION api.fn_vendor_key_apply(p_api_key_id           integer,
                                        p_link_hash            text,
                                        p_key_fingerprint      text,
                                        p_is_link_spent        boolean,
                                        p_shodan_sealed_hex    text,
                                        p_is_shodan_deleted    boolean,
                                        p_abuseipdb_sealed_hex text,
                                        p_is_abuseipdb_deleted boolean)
  RETURNS text
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER
  SET search_path = pg_catalog
AS $$
DECLARE
  is_key_active        boolean;
  key_fingerprint      text;
  link_api_key_id      integer;
  link_key_fingerprint text;
  link_expires_at      timestamptz;
BEGIN
  IF p_is_link_spent IS NULL OR p_is_shodan_deleted IS NULL OR p_is_abuseipdb_deleted IS NULL THEN
    RAISE EXCEPTION 'api.fn_vendor_key_apply takes no NULL flag';
  END IF;
  IF p_is_link_spent AND p_link_hash IS NULL THEN
    RAISE EXCEPTION 'api.fn_vendor_key_apply spends no link on the API-key way';
  END IF;
  IF p_link_hash IS NOT NULL AND p_key_fingerprint IS NOT NULL THEN
    RAISE EXCEPTION 'api.fn_vendor_key_apply takes a link hash or a key fingerprint, not both';
  END IF;
  IF (p_shodan_sealed_hex IS NOT NULL AND p_is_shodan_deleted) OR (p_abuseipdb_sealed_hex IS NOT NULL AND p_is_abuseipdb_deleted) THEN
    RAISE EXCEPTION 'api.fn_vendor_key_apply takes a sealed text or a delete flag for one vendor, not both';
  END IF;

  SELECT api.fn_api_key_is_active(ak.active, ak.expires_at), api.fn_vendor_key_fingerprint(ak.key_hash) INTO is_key_active, key_fingerprint
    FROM public.api_keys AS ak
   WHERE ak.id = p_api_key_id
     FOR UPDATE;

  IF p_link_hash IS NULL THEN
    IF is_key_active IS NOT TRUE OR key_fingerprint IS DISTINCT FROM p_key_fingerprint THEN
      RETURN 'inactive';
    END IF;
  ELSE
    SELECT vkl.api_key_id, vkl.key_fingerprint, vkl.expires_at INTO link_api_key_id, link_key_fingerprint, link_expires_at
      FROM public.vendor_key_link AS vkl
     WHERE vkl.link_hash = p_link_hash
       FOR UPDATE;
    IF NOT FOUND OR link_api_key_id <> p_api_key_id OR is_key_active IS NOT TRUE OR key_fingerprint <> link_key_fingerprint THEN
      RETURN 'invalid';
    END IF;
    IF link_expires_at <= now() THEN
      RETURN 'expired';
    END IF;
  END IF;

  INSERT INTO public.vendor_key (api_key_id, vendor_name, sealed_hex)
  SELECT p_api_key_id, saved.vendor_name, saved.sealed_hex
    FROM (VALUES ('shodan', p_shodan_sealed_hex), ('abuseipdb', p_abuseipdb_sealed_hex)) AS saved (vendor_name, sealed_hex)
   WHERE saved.sealed_hex IS NOT NULL
      ON CONFLICT (api_key_id, vendor_name) DO UPDATE SET sealed_hex = EXCLUDED.sealed_hex, saved_at = now();
  DELETE FROM public.vendor_key AS vk
   USING (VALUES ('shodan', p_is_shodan_deleted), ('abuseipdb', p_is_abuseipdb_deleted)) AS deleted (vendor_name, is_deleted)
   WHERE vk.api_key_id = p_api_key_id AND vk.vendor_name = deleted.vendor_name AND deleted.is_deleted;

  IF p_is_link_spent THEN
    DELETE FROM public.vendor_key_link AS vkl WHERE vkl.link_hash = p_link_hash;
  END IF;
  RETURN 'applied';
END
$$;

CREATE FUNCTION api.fn_vendor_key_purge(p_key_row_count integer) RETURNS integer
  LANGUAGE sql VOLATILE STRICT SECURITY DEFINER
  SET search_path = pg_catalog
  BEGIN ATOMIC
    WITH expired_key AS (
      SELECT ak.id
        FROM public.api_keys AS ak
       WHERE ak.expires_at < now() - interval '30 days'
         AND EXISTS (SELECT 1 FROM public.vendor_key AS vk WHERE vk.api_key_id = ak.id)
       ORDER BY ak.id
       LIMIT p_key_row_count),
    purged AS (
      DELETE FROM public.vendor_key AS vk
       WHERE vk.api_key_id IN (SELECT expired_key.id FROM expired_key)
      RETURNING vk.api_key_id)
    SELECT count(DISTINCT purged.api_key_id)::integer FROM purged;
  END;

CREATE FUNCTION api.fn_vendor_key_link_purge(p_link_row_count integer) RETURNS integer
  LANGUAGE sql VOLATILE STRICT SECURITY DEFINER
  SET search_path = pg_catalog
  BEGIN ATOMIC
    WITH purged AS (
      DELETE FROM public.vendor_key_link AS vkl
       WHERE vkl.ctid = ANY (ARRAY(SELECT ended.ctid FROM public.vendor_key_link AS ended
                                   WHERE ended.expires_at < now()
                                   LIMIT p_link_row_count))
      RETURNING 1)
    SELECT count(*)::integer FROM purged;
  END;
