CREATE FUNCTION api.fn_driver_lookup(p_file_hashes text[], p_match_row_count integer, p_is_command_included boolean)
  RETURNS TABLE (file_hash          text,
                 match_count        integer,
                 driver_feed_loaded boolean,
                 matches            jsonb)
  LANGUAGE sql STABLE STRICT SECURITY DEFINER
  SET search_path = pg_catalog
  BEGIN ATOMIC
    WITH queried_hash AS (
      SELECT lower(q.file_hash) AS file_hash, q.position
        FROM unnest(p_file_hashes) WITH ORDINALITY AS q (file_hash, position)),
    matched_sample AS (
      SELECT qh.position,
             lds.driver_id,
             lds.sample_index,
             row_number() OVER (PARTITION BY qh.position ORDER BY lds.driver_id, lds.sample_index) AS match_position,
             array_remove(ARRAY[CASE WHEN lds.md5                 = qh.file_hash THEN 'md5'                 END,
                                CASE WHEN lds.sha1                = qh.file_hash THEN 'sha1'                END,
                                CASE WHEN lds.sha256              = qh.file_hash THEN 'sha256'              END,
                                CASE WHEN lds.authentihash_md5    = qh.file_hash THEN 'authentihash_md5'    END,
                                CASE WHEN lds.authentihash_sha1   = qh.file_hash THEN 'authentihash_sha1'   END,
                                CASE WHEN lds.authentihash_sha256 = qh.file_hash THEN 'authentihash_sha256' END], NULL) AS matched_on
        FROM queried_hash AS qh
        JOIN public.lol_driver_samples AS lds
          ON qh.file_hash IN (lds.md5, lds.sha1, lds.sha256, lds.authentihash_md5, lds.authentihash_sha1, lds.authentihash_sha256)
       WHERE qh.file_hash <> ''),
    match_element AS (
      SELECT ms.position,
             ms.match_position,
             jsonb_build_object(
               'driver_id',            ld.driver_id,
               'category',             ld.category,
               'verified',             ld.is_verified,
               'attack_technique_ids', nullif(ld.attack_technique_ids, ''),
               'cve_ids',              ld.cve_ids,
               'catalog_added',        nullif(ld.catalog_added, ''),
               'description',          nullif(ld.driver_description, ''),
               'use_case',             nullif(ld.use_case, ''),
               'privileges',           nullif(ld.privileges, ''),
               'operating_system',     nullif(ld.operating_system, ''),
               'command',              CASE WHEN p_is_command_included THEN nullif(ld.command, '') END,
               'tags',                 ld.tags,
               'matched_on',           to_jsonb(ms.matched_on),
               'matched_driver_file',  jsonb_build_object(
                 'file_name',          nullif(lds.file_name, ''),
                 'original_file_name', nullif(lds.original_file_name, ''),
                 'md5',                nullif(lds.md5, ''),
                 'sha1',               nullif(lds.sha1, ''),
                 'sha256',             nullif(lds.sha256, ''),
                 'authentihash',       jsonb_build_object(
                   'md5',    nullif(lds.authentihash_md5, ''),
                   'sha1',   nullif(lds.authentihash_sha1, ''),
                   'sha256', nullif(lds.authentihash_sha256, '')),
                 'imphash',            nullif(lds.imphash, ''),
                 'publisher',          nullif(lds.publisher, ''),
                 'company',            nullif(lds.company, ''),
                 'product_name',       nullif(lds.product_name, ''),
                 'product_version',    nullif(lds.product_version, ''),
                 'file_version',       nullif(lds.file_version, ''),
                 'description',        nullif(lds.sample_description, ''),
                 'loads_despite_hvci', lds.loads_despite_hvci),
               'detection_rules',      ld.detection_rules,
               'references',           ld.reference_urls,
               'source_url',           'https://www.loldrivers.io/drivers/' || ld.driver_id || '/') AS element
        FROM matched_sample AS ms
        JOIN public.lol_drivers AS ld ON ld.driver_id = ms.driver_id
        JOIN public.lol_driver_samples AS lds ON lds.driver_id = ms.driver_id AND lds.sample_index = ms.sample_index)
        
    SELECT qh.file_hash                              AS file_hash,
           match_stats.match_count                   AS match_count,
           EXISTS (SELECT 1 FROM public.lol_drivers) AS driver_feed_loaded,
           match_list.matches                        AS matches
      FROM queried_hash AS qh
     CROSS JOIN LATERAL (
       SELECT count(*)::integer
         FROM matched_sample AS ms
        WHERE ms.position = qh.position) AS match_stats (match_count)
     CROSS JOIN LATERAL (
       SELECT COALESCE(jsonb_agg(me.element ORDER BY me.match_position), '[]'::jsonb)
         FROM match_element AS me
        WHERE me.position = qh.position
          AND me.match_position <= p_match_row_count) AS match_list (matches)
     ORDER BY qh.position;
  END;
