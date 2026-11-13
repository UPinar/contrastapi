CREATE FUNCTION api.fn_billing_lemonsqueezy_order_paid(p_provider_event_ref text,
                                                       p_order_id           text,
                                                       p_provider_order_ref text)
  RETURNS text
  LANGUAGE sql VOLATILE STRICT SECURITY DEFINER
  SET search_path = pg_catalog
  BEGIN ATOMIC
    SELECT pg_advisory_xact_lock(hashtext('lemonsqueezy'), hashtext(p_provider_order_ref));
    WITH taken_event AS (
      INSERT INTO public.billing_events (provider, provider_event_ref, event_name, provider_order_ref, billing_action)
      VALUES ('lemonsqueezy', p_provider_event_ref, 'order_created', p_provider_order_ref, 'order_paid')
      ON CONFLICT DO NOTHING
      RETURNING 1
    ), written_order AS (
      INSERT INTO public.billing_orders (provider, provider_order_ref, provider_subscription_ref, provider_updated_at, order_id, status,
                                         claimable_until, expires_at)
      SELECT 'lemonsqueezy', p_provider_order_ref, first_subscription.provider_subscription_ref, last_expiry.provider_updated_at, p_order_id,
             CASE WHEN ended.is_revoked THEN 'revoked' ELSE 'paid' END,
             now() + interval '24 hours',
             CASE WHEN ended.is_revoked THEN least(last_expiry.expires_at, now()) ELSE last_expiry.expires_at END
        FROM taken_event
       CROSS JOIN LATERAL (SELECT EXISTS (SELECT FROM public.billing_events AS be
                                           WHERE be.provider = 'lemonsqueezy' AND be.provider_order_ref = p_provider_order_ref
                                             AND be.billing_action = 'revoke')) AS ended (is_revoked)
        LEFT JOIN LATERAL (SELECT be.provider_updated_at, be.expires_at
                             FROM public.billing_events AS be
                            WHERE be.provider = 'lemonsqueezy' AND be.provider_order_ref = p_provider_order_ref
                              AND be.billing_action IN ('set_expiry', 'clear_expiry')
                            ORDER BY be.provider_updated_at DESC, be.received_at DESC, be.provider_event_ref DESC
                            LIMIT 1) AS last_expiry ON true
        LEFT JOIN LATERAL (SELECT be.provider_subscription_ref
                             FROM public.billing_events AS be
                            WHERE be.provider = 'lemonsqueezy' AND be.provider_order_ref = p_provider_order_ref
                              AND be.billing_action IN ('set_expiry', 'clear_expiry')
                            ORDER BY be.received_at, be.provider_event_ref
                            LIMIT 1) AS first_subscription ON true
      ON CONFLICT DO NOTHING
      RETURNING 1
    )
    SELECT CASE WHEN NOT EXISTS (SELECT FROM taken_event) THEN 'duplicate'
                WHEN EXISTS (SELECT FROM written_order)   THEN 'applied'
                ELSE 'exists' END;
  END;

CREATE FUNCTION api.fn_billing_nowpayments_order_paid(p_event_ref  text,
                                                      p_event_name text,
                                                      p_order_id   uuid,
                                                      p_order_ref  text)
  RETURNS text
  LANGUAGE sql VOLATILE STRICT SECURITY DEFINER
  SET search_path = pg_catalog
  BEGIN ATOMIC
    SELECT pg_advisory_xact_lock(hashtext('nowpayments'), hashtext(p_order_ref));
    WITH taken_event AS (
      INSERT INTO public.billing_events (provider, provider_event_ref, event_name, provider_order_ref, billing_action)
      VALUES ('nowpayments', p_event_ref, p_event_name, p_order_ref, 'order_paid')
      ON CONFLICT DO NOTHING
      RETURNING 1
    ), written_order AS (
      INSERT INTO public.billing_orders (provider, provider_order_ref, order_id, status, claimable_until, expires_at)
      SELECT 'nowpayments', p_order_ref, p_order_id::text, 'paid', now() + interval '24 hours', now() + interval '30 days'
        FROM taken_event
      ON CONFLICT DO NOTHING
      RETURNING 1
    )
    SELECT CASE WHEN NOT EXISTS (SELECT FROM taken_event) THEN 'duplicate'
                WHEN EXISTS (SELECT FROM written_order)   THEN 'applied'
                ELSE 'exists' END;
  END;

CREATE FUNCTION api.fn_billing_lemonsqueezy_set_expiry(p_provider_event_ref        text,
                                                       p_provider_order_ref        text,
                                                       p_provider_subscription_ref text,
                                                       p_provider_updated_at       bigint,
                                                       p_expires_at                bigint)
  RETURNS text
  LANGUAGE plpgsql VOLATILE STRICT SECURITY DEFINER
  SET search_path = pg_catalog
AS $$
DECLARE
  order_api_key_id    integer;
  locked_order        public.billing_orders;
BEGIN
  PERFORM pg_advisory_xact_lock(hashtext('lemonsqueezy'), hashtext(p_provider_order_ref));

  INSERT INTO public.billing_events (provider, provider_event_ref, event_name, provider_order_ref, provider_subscription_ref,
                                     billing_action, provider_updated_at, expires_at)
  VALUES ('lemonsqueezy', p_provider_event_ref, 'subscription_cancelled', p_provider_order_ref, p_provider_subscription_ref,
          'set_expiry', to_timestamp(p_provider_updated_at), to_timestamp(p_expires_at))
  ON CONFLICT DO NOTHING;
  IF NOT FOUND THEN
    RETURN 'duplicate';
  END IF;

  SELECT bo.api_key_id INTO order_api_key_id
    FROM public.billing_orders AS bo
   WHERE bo.provider = 'lemonsqueezy' AND bo.provider_order_ref = p_provider_order_ref;
  IF NOT FOUND THEN
    RETURN 'unknown';
  END IF;
  PERFORM FROM public.api_keys AS ak WHERE ak.id = order_api_key_id FOR UPDATE;

  SELECT * INTO locked_order
    FROM public.billing_orders AS bo
   WHERE bo.provider = 'lemonsqueezy' AND bo.provider_order_ref = p_provider_order_ref
     FOR UPDATE;
  IF locked_order.status = 'revoked' THEN
    RETURN 'revoked';
  END IF;
  IF to_timestamp(p_provider_updated_at) < locked_order.provider_updated_at THEN
    RETURN 'stale';
  END IF;

  UPDATE public.billing_orders AS bo
     SET expires_at                = to_timestamp(p_expires_at),
         provider_updated_at       = to_timestamp(p_provider_updated_at),
         provider_subscription_ref = coalesce(bo.provider_subscription_ref, p_provider_subscription_ref)
   WHERE bo.billing_order_id = locked_order.billing_order_id;
  UPDATE public.api_keys AS ak
     SET expires_at = to_timestamp(p_expires_at)
   WHERE ak.id = locked_order.api_key_id AND ak.active;
  RETURN 'applied';
END
$$;

CREATE FUNCTION api.fn_billing_lemonsqueezy_clear_expiry(p_provider_event_ref        text,
                                                         p_provider_order_ref        text,
                                                         p_provider_subscription_ref text,
                                                         p_provider_updated_at       bigint)
  RETURNS text
  LANGUAGE plpgsql VOLATILE STRICT SECURITY DEFINER
  SET search_path = pg_catalog
AS $$
DECLARE
  order_api_key_id    integer;
  locked_order        public.billing_orders;
BEGIN
  PERFORM pg_advisory_xact_lock(hashtext('lemonsqueezy'), hashtext(p_provider_order_ref));

  INSERT INTO public.billing_events (provider, provider_event_ref, event_name, provider_order_ref, provider_subscription_ref,
                                     billing_action, provider_updated_at)
  VALUES ('lemonsqueezy', p_provider_event_ref, 'subscription_resumed', p_provider_order_ref, p_provider_subscription_ref,
          'clear_expiry', to_timestamp(p_provider_updated_at))
  ON CONFLICT DO NOTHING;
  IF NOT FOUND THEN
    RETURN 'duplicate';
  END IF;

  SELECT bo.api_key_id INTO order_api_key_id
    FROM public.billing_orders AS bo
   WHERE bo.provider = 'lemonsqueezy' AND bo.provider_order_ref = p_provider_order_ref;
  IF NOT FOUND THEN
    RETURN 'unknown';
  END IF;
  PERFORM FROM public.api_keys AS ak WHERE ak.id = order_api_key_id FOR UPDATE;

  SELECT * INTO locked_order
    FROM public.billing_orders AS bo
   WHERE bo.provider = 'lemonsqueezy' AND bo.provider_order_ref = p_provider_order_ref
     FOR UPDATE;
  IF locked_order.status = 'revoked' THEN
    RETURN 'revoked';
  END IF;
  IF to_timestamp(p_provider_updated_at) < locked_order.provider_updated_at THEN
    RETURN 'stale';
  END IF;

  UPDATE public.billing_orders AS bo
     SET expires_at                = NULL,
         provider_updated_at       = to_timestamp(p_provider_updated_at),
         provider_subscription_ref = coalesce(bo.provider_subscription_ref, p_provider_subscription_ref)
   WHERE bo.billing_order_id = locked_order.billing_order_id;
  UPDATE public.api_keys AS ak
     SET expires_at = NULL
   WHERE ak.id = locked_order.api_key_id AND ak.active;
  RETURN 'applied';
END
$$;

CREATE FUNCTION api.fn_billing_lemonsqueezy_revoke(p_provider_event_ref text,
                                                   p_event_name         text,
                                                   p_provider_order_ref text)
  RETURNS text
  LANGUAGE plpgsql VOLATILE STRICT SECURITY DEFINER
  SET search_path = pg_catalog
AS $$
DECLARE
  order_api_key_id integer;
  locked_order        public.billing_orders;
  order_key_hash      text;
BEGIN
  PERFORM pg_advisory_xact_lock(hashtext('lemonsqueezy'), hashtext(p_provider_order_ref));

  INSERT INTO public.billing_events (provider, provider_event_ref, event_name, provider_order_ref, billing_action)
  VALUES ('lemonsqueezy', p_provider_event_ref, p_event_name, p_provider_order_ref, 'revoke')
  ON CONFLICT DO NOTHING;
  IF NOT FOUND THEN
    RETURN 'duplicate';
  END IF;

  SELECT bo.api_key_id INTO order_api_key_id
    FROM public.billing_orders AS bo
   WHERE bo.provider = 'lemonsqueezy' AND bo.provider_order_ref = p_provider_order_ref;
  IF NOT FOUND THEN
    RETURN 'unknown';
  END IF;
  PERFORM FROM public.api_keys AS ak WHERE ak.id = order_api_key_id FOR UPDATE;

  SELECT * INTO locked_order
    FROM public.billing_orders AS bo
   WHERE bo.provider = 'lemonsqueezy' AND bo.provider_order_ref = p_provider_order_ref
     FOR UPDATE;
  IF locked_order.status = 'revoked' THEN
    RETURN 'revoked';
  END IF;

  UPDATE public.billing_orders AS bo
     SET status     = 'revoked',
         expires_at = least(bo.expires_at, now())
   WHERE bo.billing_order_id = locked_order.billing_order_id;
  SELECT ak.key_hash INTO order_key_hash FROM public.api_keys AS ak WHERE ak.id = locked_order.api_key_id FOR UPDATE;
  IF FOUND THEN
    PERFORM api.fn_api_key_revoke(order_key_hash);
  END IF;
  RETURN 'applied';
END
$$;

CREATE FUNCTION api.fn_billing_event_record(p_provider                  text,
                                            p_provider_event_ref        text,
                                            p_event_name                text,
                                            p_provider_order_ref        text,
                                            p_provider_subscription_ref text)
  RETURNS text
  LANGUAGE sql VOLATILE SECURITY DEFINER
  SET search_path = pg_catalog
  BEGIN ATOMIC
    WITH taken_event AS (
      INSERT INTO public.billing_events (provider, provider_event_ref, event_name, provider_order_ref, provider_subscription_ref, billing_action)
      VALUES (p_provider, p_provider_event_ref, p_event_name, p_provider_order_ref, p_provider_subscription_ref, 'record')
      ON CONFLICT DO NOTHING
      RETURNING 1
    )
    SELECT CASE WHEN EXISTS (SELECT FROM taken_event) THEN 'applied' ELSE 'duplicate' END;
  END;

CREATE FUNCTION api.fn_billing_claim(p_order_id text,
                                     p_key_hash text)
  RETURNS text
  LANGUAGE plpgsql VOLATILE STRICT SECURITY DEFINER
  SET search_path = pg_catalog
AS $$
DECLARE
  order_api_key_id    integer;
  locked_order        public.billing_orders;
  new_api_key_id      integer;
BEGIN
  SELECT bo.api_key_id INTO order_api_key_id FROM public.billing_orders AS bo WHERE bo.order_id = p_order_id;
  IF NOT FOUND THEN
    RETURN 'unknown';
  END IF;
  PERFORM FROM public.api_keys AS ak WHERE ak.id = order_api_key_id FOR UPDATE;

  SELECT * INTO locked_order FROM public.billing_orders AS bo WHERE bo.order_id = p_order_id FOR UPDATE;
  IF NOT FOUND THEN
    RETURN 'unknown';
  END IF;
  IF locked_order.status = 'revoked' THEN
    RETURN 'revoked';
  ELSIF locked_order.status = 'claimed' THEN
    RETURN 'already_claimed';
  END IF;
  IF locked_order.claimable_until <= now() THEN
    RETURN 'lapsed';
  END IF;

  IF locked_order.status = 'paid' THEN
    INSERT INTO public.api_keys (key_hash, expires_at)
    VALUES (p_key_hash, locked_order.expires_at)
    RETURNING id INTO new_api_key_id;
    UPDATE public.billing_orders AS bo
       SET status     = 'claimed',
           claimed_at = now(),
           api_key_id = new_api_key_id
     WHERE bo.billing_order_id = locked_order.billing_order_id;
  ELSE
    UPDATE public.api_keys AS ak
       SET key_hash = p_key_hash
     WHERE ak.id = locked_order.api_key_id;
    UPDATE public.billing_orders AS bo
       SET status     = 'claimed',
           claimed_at = now()
     WHERE bo.billing_order_id = locked_order.billing_order_id;
  END IF;
  RETURN 'claimed';
END
$$;

CREATE FUNCTION api.fn_billing_regenerate_key(p_provider           text,
                                              p_provider_order_ref text)
  RETURNS TABLE (regenerate_status text,
                 claim_order_id    text)
  LANGUAGE plpgsql VOLATILE STRICT SECURITY INVOKER
  SET search_path = pg_catalog
AS $$
DECLARE
  order_api_key_id    integer;
  locked_order        public.billing_orders;
  order_key           public.api_keys;
BEGIN
  SELECT bo.api_key_id INTO order_api_key_id
    FROM public.billing_orders AS bo
   WHERE bo.provider = p_provider AND bo.provider_order_ref = p_provider_order_ref;
  IF NOT FOUND THEN
    regenerate_status := 'unknown';
    RETURN NEXT;
    RETURN;
  END IF;
  PERFORM FROM public.api_keys AS ak WHERE ak.id = order_api_key_id FOR UPDATE;

  SELECT * INTO locked_order
    FROM public.billing_orders AS bo
   WHERE bo.provider = p_provider AND bo.provider_order_ref = p_provider_order_ref
     FOR UPDATE;
  IF locked_order.status = 'paid' THEN
    UPDATE public.billing_orders AS bo
       SET order_id        = gen_random_uuid()::text,
           claimable_until = now() + interval '24 hours'
     WHERE bo.billing_order_id = locked_order.billing_order_id
    RETURNING 'reopened', bo.order_id INTO regenerate_status, claim_order_id;
    RETURN NEXT;
    RETURN;
  ELSIF locked_order.status = 'revoked' THEN
    regenerate_status := 'revoked';
    RETURN NEXT;
    RETURN;
  END IF;
  SELECT * INTO order_key FROM public.api_keys AS ak WHERE ak.id = locked_order.api_key_id FOR UPDATE;
  IF NOT api.fn_api_key_is_active(order_key.active, order_key.expires_at) THEN
    regenerate_status := 'inactive';
    RETURN NEXT;
    RETURN;
  END IF;

  UPDATE public.api_keys AS ak
     SET key_hash = encode(sha256(convert_to(gen_random_uuid()::text, 'UTF8')), 'hex')
   WHERE ak.id = order_key.id;
  UPDATE public.billing_orders AS bo
     SET status          = 'regenerating',
         order_id        = gen_random_uuid()::text,
         claimable_until = now() + interval '24 hours'
   WHERE bo.billing_order_id = locked_order.billing_order_id
  RETURNING 'regenerating', bo.order_id INTO regenerate_status, claim_order_id;
  RETURN NEXT;
END
$$;

CREATE FUNCTION api.fn_billing_delete_key(p_provider           text,
                                          p_provider_order_ref text)
  RETURNS text
  LANGUAGE plpgsql VOLATILE STRICT SECURITY INVOKER
  SET search_path = pg_catalog
AS $$
DECLARE
  order_api_key_id    integer;
  locked_order        public.billing_orders;
BEGIN
  PERFORM pg_advisory_xact_lock(hashtext(p_provider), hashtext(p_provider_order_ref));

  SELECT bo.api_key_id INTO order_api_key_id
    FROM public.billing_orders AS bo
   WHERE bo.provider = p_provider AND bo.provider_order_ref = p_provider_order_ref;
  IF NOT FOUND THEN
    RETURN 'unknown';
  END IF;
  PERFORM FROM public.api_keys AS ak WHERE ak.id = order_api_key_id FOR UPDATE;

  SELECT * INTO locked_order
    FROM public.billing_orders AS bo
   WHERE bo.provider = p_provider AND bo.provider_order_ref = p_provider_order_ref
     FOR UPDATE;
  IF locked_order.api_key_id IS NULL THEN
    RETURN 'no_key';
  END IF;

  UPDATE public.billing_orders AS bo
     SET status     = 'revoked',
         api_key_id = NULL,
         claimed_at = NULL,
         expires_at = least(bo.expires_at, now())
   WHERE bo.billing_order_id = locked_order.billing_order_id;
  DELETE FROM public.api_keys AS ak WHERE ak.id = locked_order.api_key_id;
  RETURN 'deleted';
END
$$;

CREATE FUNCTION api.fn_billing_manual_key_grant(p_provider_order_ref text,
                                                p_key_hash           text)
  RETURNS text
  LANGUAGE plpgsql VOLATILE STRICT SECURITY INVOKER
  SET search_path = pg_catalog
AS $$
DECLARE
  granted_api_key_id integer;
BEGIN
  PERFORM pg_advisory_xact_lock(hashtext('manual'), hashtext(p_provider_order_ref));
  IF EXISTS (SELECT FROM public.billing_orders AS bo
              WHERE bo.provider = 'manual' AND bo.provider_order_ref = p_provider_order_ref) THEN
    RETURN 'exists';
  END IF;

  INSERT INTO public.api_keys (key_hash) VALUES (p_key_hash) RETURNING id INTO granted_api_key_id;
  INSERT INTO public.billing_orders (provider, provider_order_ref, status, claimed_at, api_key_id)
    VALUES ('manual', p_provider_order_ref, 'claimed', now(), granted_api_key_id);
  RETURN 'granted';
END
$$;

CREATE FUNCTION api.fn_billing_event_purge(p_event_row_count integer) RETURNS integer
  LANGUAGE sql VOLATILE STRICT SECURITY DEFINER
  SET search_path = pg_catalog
  BEGIN ATOMIC
    WITH purged AS (
      DELETE FROM public.billing_events AS be
       WHERE be.ctid = ANY (ARRAY(SELECT aged.ctid FROM public.billing_events AS aged
                                   WHERE aged.received_at < now() - interval '365 days'
                                     AND (aged.provider_order_ref IS NULL
                                          OR EXISTS (SELECT FROM public.billing_orders AS bo
                                                      WHERE bo.provider = aged.provider
                                                        AND bo.provider_order_ref = aged.provider_order_ref
                                                        AND (aged.billing_action NOT IN ('set_expiry', 'clear_expiry')
                                                             OR aged.provider_updated_at < bo.provider_updated_at)))
                                   LIMIT p_event_row_count))
      RETURNING 1)
    SELECT count(*)::integer FROM purged;
  END;
