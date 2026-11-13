CREATE FUNCTION api.fn_ip_watch_write_values(p_item_row_count integer)
  RETURNS integer
  LANGUAGE plpgsql VOLATILE STRICT SECURITY DEFINER
  SET search_path = pg_catalog
AS $$
DECLARE
  newest_list_synced_at      timestamptz;
  is_drop_list_on            boolean;
  newest_drop_list_time      timestamptz;
  newest_drop_copyright      text;
  taken_item_ids             bigint[];
  taken_api_key_ids          integer[];
  taken_ip_addresses         inet[];
  taken_index                integer;
  drop_value                 text;
  hosting_value              text;
  stored                     public.watchlist_item_ip_value%ROWTYPE;
  transition_item_ids        bigint[]  := '{}';
  transition_api_key_ids     integer[] := '{}';
  transition_ip_addresses    inet[]    := '{}';
  transition_event_types     text[]    := '{}';
  transition_previous_values text[]    := '{}';
  transition_current_values  text[]    := '{}';
BEGIN
  SELECT max(ufs.last_synced) INTO newest_list_synced_at
    FROM public.upstream_feed_sync AS ufs
   WHERE ufs.feed_name IN ('drop_list', 'iptoasn', 'cloud_ranges')
     AND ufs.last_status = 'ok';
  SELECT idlp.list_time, idlp.copyright INTO newest_drop_list_time, newest_drop_copyright
    FROM public.ip_drop_list_prefix AS idlp
   ORDER BY idlp.list_time DESC, idlp.copyright
   LIMIT 1;
  is_drop_list_on := FOUND;

  SELECT coalesce(array_agg(taken.item_id ORDER BY taken.checked_at NULLS FIRST, taken.item_id), '{}'),
         coalesce(array_agg(taken.api_key_id ORDER BY taken.checked_at NULLS FIRST, taken.item_id), '{}'),
         coalesce(array_agg(taken.ip_address ORDER BY taken.checked_at NULLS FIRST, taken.item_id), '{}')
    INTO taken_item_ids, taken_api_key_ids, taken_ip_addresses
    FROM (SELECT wii.item_id, wii.api_key_id, wii.ip_address, wii.checked_at
            FROM public.watchlist_item_ip AS wii
            JOIN public.watchlist_item AS wi ON wi.item_id = wii.item_id
            JOIN public.api_keys AS ak ON ak.id = wii.api_key_id
           WHERE (wii.checked_at IS NULL OR wii.checked_at < newest_list_synced_at)
             AND api.fn_api_key_is_active(ak.active, ak.expires_at)
           ORDER BY wii.checked_at NULLS FIRST, wii.item_id
           LIMIT p_item_row_count
             FOR NO KEY UPDATE OF wii, wi SKIP LOCKED) AS taken;

  FOR taken_index IN 1 .. cardinality(taken_item_ids) LOOP
    IF is_drop_list_on THEN
      SELECT coalesce(string_agg(idlp.prefix::text || ' ' || idlp.listing_id, E'\n' ORDER BY idlp.prefix, idlp.listing_id), '')
        INTO drop_value
        FROM public.ip_drop_list_prefix AS idlp
       WHERE idlp.prefix >>= taken_ip_addresses[taken_index];
    ELSE
      drop_value := NULL;
    END IF;

    IF octet_length(drop_value) <= 4096 THEN
      SELECT * INTO stored FROM public.watchlist_item_ip_value AS wiiv
       WHERE wiiv.item_id = taken_item_ids[taken_index] AND wiiv.value_kind = 'drop_listing';
      IF NOT FOUND THEN
        INSERT INTO public.watchlist_item_ip_value (item_id, value_kind, current_value)
        VALUES (taken_item_ids[taken_index], 'drop_listing', drop_value);
        IF drop_value <> '' THEN
          transition_item_ids        := transition_item_ids || taken_item_ids[taken_index];
          transition_api_key_ids     := transition_api_key_ids || taken_api_key_ids[taken_index];
          transition_ip_addresses    := transition_ip_addresses || taken_ip_addresses[taken_index];
          transition_event_types     := transition_event_types || 'drop_listed'::text;
          transition_previous_values := transition_previous_values || NULL::text;
          transition_current_values  := transition_current_values || drop_value;
        END IF;
      ELSIF drop_value <> stored.current_value THEN
        UPDATE public.watchlist_item_ip_value AS wiiv
           SET current_value = drop_value
         WHERE wiiv.item_id = taken_item_ids[taken_index] AND wiiv.value_kind = 'drop_listing';
        IF stored.current_value = '' OR drop_value = '' THEN
          transition_item_ids        := transition_item_ids || taken_item_ids[taken_index];
          transition_api_key_ids     := transition_api_key_ids || taken_api_key_ids[taken_index];
          transition_ip_addresses    := transition_ip_addresses || taken_ip_addresses[taken_index];
          transition_event_types     := transition_event_types || CASE WHEN drop_value = '' THEN 'drop_unlisted' ELSE 'drop_listed' END;
          transition_previous_values := transition_previous_values || stored.current_value;
          transition_current_values  := transition_current_values || drop_value;
        END IF;
      END IF;
    END IF;

    hosting_value := api.fn_ip_hosting_classes(ARRAY[taken_ip_addresses[taken_index]]);
    IF hosting_value IS NOT NULL THEN
      SELECT * INTO stored FROM public.watchlist_item_ip_value AS wiiv
       WHERE wiiv.item_id = taken_item_ids[taken_index] AND wiiv.value_kind = 'hosting';
      IF NOT FOUND THEN
        INSERT INTO public.watchlist_item_ip_value (item_id, value_kind, current_value)
        VALUES (taken_item_ids[taken_index], 'hosting', hosting_value);
      ELSIF hosting_value = stored.current_value THEN
        UPDATE public.watchlist_item_ip_value AS wiiv
           SET candidate_value = NULL, candidate_seen_at = NULL
         WHERE wiiv.item_id = taken_item_ids[taken_index] AND wiiv.value_kind = 'hosting';
      ELSIF hosting_value = stored.candidate_value THEN
        UPDATE public.watchlist_item_ip_value AS wiiv
           SET current_value = hosting_value, candidate_value = NULL, candidate_seen_at = NULL
         WHERE wiiv.item_id = taken_item_ids[taken_index] AND wiiv.value_kind = 'hosting';
        transition_item_ids        := transition_item_ids || taken_item_ids[taken_index];
        transition_api_key_ids     := transition_api_key_ids || taken_api_key_ids[taken_index];
        transition_ip_addresses    := transition_ip_addresses || taken_ip_addresses[taken_index];
        transition_event_types     := transition_event_types || 'hosting_changed'::text;
        transition_previous_values := transition_previous_values || stored.current_value;
        transition_current_values  := transition_current_values || hosting_value;
      ELSE
        UPDATE public.watchlist_item_ip_value AS wiiv
           SET candidate_value = hosting_value, candidate_seen_at = now()
         WHERE wiiv.item_id = taken_item_ids[taken_index] AND wiiv.value_kind = 'hosting';
      END IF;
    END IF;
  END LOOP;

  UPDATE public.watchlist_item_ip AS wii
     SET checked_at = greatest(now(), newest_list_synced_at)
   WHERE wii.item_id = ANY (taken_item_ids);

  IF cardinality(transition_item_ids) > 0 THEN
    PERFORM public.fn_watchlist_event_take_order_lock();
    WITH transition AS (
      SELECT t.item_id, t.api_key_id, t.ip_address, t.event_type, t.previous_value, t.current_value, t.transition_number
        FROM unnest(transition_item_ids, transition_api_key_ids, transition_ip_addresses, transition_event_types,
                    transition_previous_values, transition_current_values)
             WITH ORDINALITY AS t (item_id, api_key_id, ip_address, event_type, previous_value, current_value, transition_number)),
    shared_event AS (
      SELECT tr.ip_address, tr.event_type, tr.previous_value, tr.current_value, min(tr.transition_number) AS first_transition_number
        FROM transition AS tr
       GROUP BY tr.ip_address, tr.event_type, tr.previous_value, tr.current_value),
    inserted AS (
      INSERT INTO public.ip_change_event AS ice (ip_address, event_type, previous_value, current_value, drop_list_time, drop_copyright)
      SELECT se.ip_address, se.event_type, se.previous_value, se.current_value,
             CASE WHEN se.event_type <> 'hosting_changed' THEN newest_drop_list_time END,
             CASE WHEN se.event_type <> 'hosting_changed' THEN newest_drop_copyright END
        FROM shared_event AS se
       ORDER BY se.first_transition_number
      RETURNING ice.event_id, ice.ip_address, ice.event_type, ice.previous_value, ice.current_value)
    INSERT INTO public.watchlist_event_ref (api_key_id, item_id, event_id)
    SELECT tr.api_key_id, tr.item_id, ins.event_id
      FROM transition AS tr
      JOIN inserted AS ins ON ins.ip_address = tr.ip_address
                          AND ins.event_type = tr.event_type
                          AND ins.previous_value IS NOT DISTINCT FROM tr.previous_value
                          AND ins.current_value = tr.current_value;
  END IF;

  RETURN cardinality(taken_item_ids);
END
$$;

CREATE FUNCTION api.fn_ip_change_event_max_id() RETURNS bigint
  LANGUAGE sql STABLE SECURITY INVOKER
  SET search_path = pg_catalog
  RETURN (SELECT greatest(ps.max_purged_event_id, (SELECT max(ice.event_id) FROM public.ip_change_event AS ice))
            FROM public.change_event_purge_state AS ps
           WHERE ps.event_table_name = 'ip_change_event');

CREATE FUNCTION api.fn_ip_change_event_purge(p_event_row_count integer) RETURNS integer
  LANGUAGE plpgsql VOLATILE STRICT SECURITY DEFINER
  SET search_path = pg_catalog
AS $$
DECLARE
  picked_event_ids   bigint[];
  purged_event_count integer;
BEGIN
  picked_event_ids := ARRAY(SELECT ice.event_id
                              FROM public.ip_change_event AS ice
                             WHERE ice.changed_at < now() - interval '90 days'
                             ORDER BY ice.event_id
                             LIMIT p_event_row_count);

  PERFORM api.fn_watchlist_event_ref_purge(picked_event_ids, false);

  WITH purged AS (
    DELETE FROM public.ip_change_event AS ice
     WHERE ice.event_id = ANY (picked_event_ids)
    RETURNING ice.event_id),
  deleted AS (
    SELECT max(p.event_id) AS max_event_id FROM purged AS p),
  raised AS (
    UPDATE public.change_event_purge_state AS ps
       SET max_purged_event_id = deleted.max_event_id
      FROM deleted
     WHERE ps.event_table_name = 'ip_change_event'
       AND ps.max_purged_event_id < deleted.max_event_id)
  SELECT count(*)::integer INTO purged_event_count FROM purged;
  RETURN purged_event_count;
END
$$;
