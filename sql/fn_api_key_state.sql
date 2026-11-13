CREATE FUNCTION api.fn_api_key_is_active(p_active boolean, p_expires_at timestamptz) RETURNS boolean
  LANGUAGE sql STABLE SECURITY INVOKER
  SET search_path = pg_catalog
  RETURN p_active AND (p_expires_at IS NULL OR p_expires_at > now());

CREATE FUNCTION api.fn_api_key_state(p_key_hash text)
  RETURNS TABLE (api_key_state  text,
                 key_expires_at bigint)
  LANGUAGE sql STABLE SECURITY DEFINER
  SET search_path = pg_catalog
  BEGIN ATOMIC
    SELECT CASE WHEN ak.id IS NULL THEN 'unknown' WHEN api.fn_api_key_is_active(ak.active, ak.expires_at) THEN 'active' ELSE 'inactive' END AS api_key_state,
           floor(extract(epoch FROM ak.expires_at))::bigint                                                                                  AS key_expires_at
      FROM (VALUES (1)) AS one_row (n)
      LEFT JOIN public.api_keys AS ak ON ak.key_hash = p_key_hash;
  END;

CREATE FUNCTION api.fn_api_key_revoke(p_key_hash text)
  RETURNS boolean
  LANGUAGE sql VOLATILE STRICT SECURITY INVOKER
  SET search_path = pg_catalog
  BEGIN ATOMIC
    WITH revoked AS (
      UPDATE public.api_keys AS ak
         SET active     = false,
             expires_at = least(ak.expires_at, now())
       WHERE ak.key_hash = p_key_hash
      RETURNING 1
    )
    SELECT EXISTS (SELECT FROM revoked);
  END;

