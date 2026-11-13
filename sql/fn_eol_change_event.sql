CREATE FUNCTION api.fn_eol_change_event_max_id() RETURNS bigint
  LANGUAGE sql STABLE SECURITY INVOKER
  SET search_path = pg_catalog
  RETURN (SELECT greatest(ps.max_purged_event_id,
                          (SELECT max(ece.event_id) FROM public.eol_change_event AS ece))
            FROM public.change_event_purge_state AS ps
           WHERE ps.event_table_name = 'eol_change_event');

CREATE FUNCTION api.fn_eol_change_event_purge(p_event_row_count integer) RETURNS integer
  LANGUAGE plpgsql VOLATILE STRICT SECURITY DEFINER
  SET search_path = pg_catalog
AS $$
DECLARE
  picked_event_ids   bigint[];
  purged_event_count integer;
BEGIN
  picked_event_ids := ARRAY(SELECT ece.event_id
                              FROM public.eol_change_event AS ece
                             WHERE ece.changed_at < now() - interval '90 days'
                             ORDER BY ece.event_id
                             LIMIT p_event_row_count);

  PERFORM api.fn_watchlist_event_ref_purge(picked_event_ids, true);

  WITH purged AS (
    DELETE FROM public.eol_change_event AS ece
     WHERE ece.event_id = ANY (picked_event_ids)
    RETURNING ece.event_id),
  deleted AS (
    SELECT max(p.event_id) AS max_event_id FROM purged AS p),
  raised AS (
    UPDATE public.change_event_purge_state AS ps
       SET max_purged_event_id = deleted.max_event_id
      FROM deleted
     WHERE ps.event_table_name = 'eol_change_event'
       AND ps.max_purged_event_id < deleted.max_event_id)
  SELECT count(*)::integer INTO purged_event_count FROM purged;
  RETURN purged_event_count;
END
$$;
