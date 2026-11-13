CREATE FUNCTION api.fn_credit_budget_purge(p_credit_budget_row_count integer) RETURNS integer
  LANGUAGE sql VOLATILE STRICT SECURITY DEFINER
  SET search_path = pg_catalog
  BEGIN ATOMIC
    WITH purged AS (
      DELETE FROM public.credit_budget AS cb
       WHERE cb.ctid = ANY (ARRAY(SELECT expired.ctid FROM public.credit_budget AS expired
                                   WHERE expired.window_start < date_trunc('hour', now())
                                   LIMIT p_credit_budget_row_count))
      RETURNING 1)
    SELECT count(*)::integer FROM purged;
  END;
