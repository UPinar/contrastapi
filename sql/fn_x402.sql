CREATE FUNCTION api.fn_x402_payment_reserve(p_message_hash text, p_source_hash text)
  RETURNS TABLE (reserve_answer text,
                 signature      text)
  LANGUAGE sql VOLATILE SECURITY DEFINER
  SET search_path = pg_catalog
  BEGIN ATOMIC
    SELECT pg_advisory_xact_lock(hashtext('x402_payment'), hashtext(p_source_hash));
    WITH found AS (
      SELECT xp.status, xp.signature
        FROM public.x402_payment AS xp
       WHERE xp.message_hash = p_message_hash),
    source_check AS (
      SELECT EXISTS (SELECT 1 FROM public.x402_payment AS other
                      WHERE other.source_hash = p_source_hash
                        AND other.status IN ('reserved', 'pending')
                        AND other.reserved_at > now() - interval '150 seconds') AS is_source_busy),
    taken AS (
      INSERT INTO public.x402_payment AS xp (message_hash, source_hash, status)
      SELECT p_message_hash, p_source_hash, 'reserved'
        FROM source_check
       WHERE NOT source_check.is_source_busy
      ON CONFLICT (message_hash) DO UPDATE
         SET status      = 'reserved',
             reserved_at = now()
       WHERE xp.status = 'released'
      RETURNING 1)
    SELECT CASE WHEN EXISTS (SELECT FROM taken) THEN 'reserved' WHEN found.status = 'settled' THEN 'settled' WHEN found.status = 'pending' THEN 'pending' WHEN found.status = 'reserved' THEN 'in_flight' ELSE 'source_busy' END AS reserve_answer,
           found.signature                                                                                                                                                                                                       AS signature
      FROM (VALUES (1)) AS one_row (n)
      LEFT JOIN found ON true;
  END;

CREATE FUNCTION api.fn_x402_payment_mark_settled(p_message_hash text) RETURNS boolean
  LANGUAGE sql VOLATILE SECURITY DEFINER
  SET search_path = pg_catalog
  BEGIN ATOMIC
    WITH settled AS (
      UPDATE public.x402_payment AS xp
         SET status    = 'settled',
             signature = NULL
       WHERE xp.message_hash = p_message_hash
         AND xp.status IN ('reserved', 'pending')
      RETURNING 1)
    SELECT EXISTS (SELECT FROM settled);
  END;

CREATE FUNCTION api.fn_x402_payment_mark_pending(p_message_hash text, p_signature text) RETURNS boolean
  LANGUAGE sql VOLATILE SECURITY DEFINER
  SET search_path = pg_catalog
  BEGIN ATOMIC
    WITH pended AS (
      UPDATE public.x402_payment AS xp
         SET status    = 'pending',
             signature = p_signature
       WHERE xp.message_hash = p_message_hash
         AND xp.status = 'reserved'
      RETURNING 1)
    SELECT EXISTS (SELECT FROM pended);
  END;

CREATE FUNCTION api.fn_x402_payment_release(p_message_hash text) RETURNS boolean
  LANGUAGE sql VOLATILE SECURITY DEFINER
  SET search_path = pg_catalog
  BEGIN ATOMIC
    WITH released AS (
      UPDATE public.x402_payment AS xp
         SET status    = 'released',
             signature = NULL
       WHERE xp.message_hash = p_message_hash
         AND xp.status IN ('reserved', 'pending')
      RETURNING 1)
    SELECT EXISTS (SELECT FROM released);
  END;

CREATE FUNCTION api.fn_x402_payment_purge(p_payment_row_count integer) RETURNS integer
  LANGUAGE sql VOLATILE STRICT SECURITY DEFINER
  SET search_path = pg_catalog
  BEGIN ATOMIC
    WITH purged AS (
      DELETE FROM public.x402_payment AS xp
       WHERE xp.ctid = ANY (ARRAY(SELECT aged.ctid FROM public.x402_payment AS aged
                                   WHERE aged.reserved_at < now() - interval '1 hour'
                                   LIMIT p_payment_row_count))
      RETURNING 1)
    SELECT count(*)::integer FROM purged;
  END;
