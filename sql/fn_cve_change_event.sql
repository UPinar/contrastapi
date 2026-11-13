CREATE FUNCTION api.fn_cve_change_event_max_id() RETURNS bigint
  LANGUAGE sql STABLE SECURITY INVOKER
  SET search_path = pg_catalog
  RETURN (SELECT greatest(ps.max_purged_event_id,
                          (SELECT max(cce.event_id) FROM public.cve_change_event AS cce))
            FROM public.change_event_purge_state AS ps
           WHERE ps.event_table_name = 'cve_change_event');

CREATE FUNCTION api.fn_cve_change_event_scan(p_cursor bigint, p_event_row_count integer)
  RETURNS TABLE (is_cursor_valid       boolean,
                 last_scanned_event_id bigint,
                 may_have_more_events  boolean)
  LANGUAGE sql STABLE STRICT SECURITY INVOKER
  SET search_path = pg_catalog
  BEGIN ATOMIC
    SELECT p_cursor BETWEEN ps.max_purged_event_id AND api.fn_cve_change_event_max_id() AS is_cursor_valid,
           coalesce(scanned.last_event_id, p_cursor)                                    AS last_scanned_event_id,
           scanned.event_count = p_event_row_count                                      AS may_have_more_events
      FROM public.change_event_purge_state AS ps
      CROSS JOIN LATERAL (SELECT max(page_event.event_id) AS last_event_id, count(*) AS event_count
                            FROM (SELECT cce.event_id
                                    FROM public.cve_change_event AS cce
                                   WHERE cce.event_id > p_cursor
                                   ORDER BY cce.event_id
                                   LIMIT p_event_row_count) AS page_event) AS scanned
     WHERE ps.event_table_name = 'cve_change_event';
  END;

CREATE FUNCTION api.fn_cve_change_event_purge(p_event_row_count integer) RETURNS integer
  LANGUAGE plpgsql VOLATILE STRICT SECURITY DEFINER
  SET search_path = pg_catalog
AS $$
DECLARE
  picked_event_ids   bigint[];
  purged_event_count integer;
BEGIN
  picked_event_ids := ARRAY(SELECT cce.event_id
                              FROM public.cve_change_event AS cce
                             WHERE cce.changed_at < now() - interval '90 days'
                             ORDER BY cce.event_id
                             LIMIT p_event_row_count);

  PERFORM api.fn_watchlist_event_ref_purge(picked_event_ids, true);

  WITH purged AS (
    DELETE FROM public.cve_change_event AS cce
     WHERE cce.event_id = ANY (picked_event_ids)
    RETURNING cce.event_id),
  deleted AS (
    SELECT max(p.event_id) AS max_event_id FROM purged AS p),
  raised AS (
    UPDATE public.change_event_purge_state AS ps
       SET max_purged_event_id = deleted.max_event_id
      FROM deleted
     WHERE ps.event_table_name = 'cve_change_event'
       AND ps.max_purged_event_id < deleted.max_event_id)
  SELECT count(*)::integer INTO purged_event_count FROM purged;
  RETURN purged_event_count;
END
$$;
