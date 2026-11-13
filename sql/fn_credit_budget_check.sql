CREATE FUNCTION api.fn_credit_budget_used(p_ip_hash text, p_has_key boolean)
  RETURNS TABLE (credit_count   integer,
                 window_expired boolean)
  LANGUAGE sql STABLE SECURITY DEFINER
  SET search_path = pg_catalog
  BEGIN ATOMIC
    SELECT cb.credit_count                             AS credit_count,
           cb.window_start < date_trunc('hour', now()) AS window_expired
      FROM public.credit_budget AS cb
     WHERE cb.ip_hash = p_ip_hash AND cb.has_key = p_has_key;
  END;

CREATE FUNCTION api.fn_credit_budget_charge(p_ip_hash             text,
                                           p_has_key              boolean,
                                           p_charged_credit_count integer,
                                           p_credit_limit         integer)
  RETURNS TABLE (credit_count integer)
  LANGUAGE sql VOLATILE SECURITY DEFINER
  SET search_path = pg_catalog
  BEGIN ATOMIC
    WITH charged AS (
      INSERT INTO public.credit_budget AS cb (ip_hash, has_key, credit_count, window_start)
      VALUES (p_ip_hash, p_has_key, p_charged_credit_count, date_trunc('hour', now()))
      ON CONFLICT (ip_hash, has_key) DO UPDATE
         SET credit_count  = CASE WHEN cb.window_start < date_trunc('hour', now())
                                 THEN p_charged_credit_count
                                 ELSE cb.credit_count + p_charged_credit_count END,
             window_start = date_trunc('hour', now())
       WHERE (CASE WHEN cb.window_start < date_trunc('hour', now()) THEN 0
                   ELSE cb.credit_count END) + p_charged_credit_count <= p_credit_limit
      RETURNING cb.credit_count)
    SELECT charged.credit_count AS credit_count FROM charged;
  END;
