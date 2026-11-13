CREATE FUNCTION api.fn_kev_lookup(p_cve_id text)
  RETURNS TABLE (cve_id               text,
                 vendor_project       text,
                 product              text,
                 patch_deadline       text,
                 required_action      text,
                 known_ransomware_use boolean,
                 vulnerability_name   text,
                 short_description    text,
                 kev_date_added       text,
                 date_removed         text,
                 cwes                 jsonb,
                 notes                text,
                 in_kev               boolean)
  LANGUAGE sql STABLE SECURITY DEFINER
  SET search_path = pg_catalog
  BEGIN ATOMIC
    SELECT kd.cve_id               AS cve_id,
           kd.vendor_project       AS vendor_project,
           kd.product              AS product,
           kd.patch_deadline       AS patch_deadline,
           kd.required_action      AS required_action,
           kd.known_ransomware_use AS known_ransomware_use,
           kd.vulnerability_name   AS vulnerability_name,
           kd.short_description    AS short_description,
           c.kev_date_added        AS kev_date_added,
           kd.date_removed         AS date_removed,
           kd.cwes                 AS cwes,
           kd.notes                AS notes,
           c.in_kev                AS in_kev
      FROM public.kev_details AS kd
      JOIN public.cves AS c ON c.cve_id = kd.cve_id
     WHERE kd.cve_id = p_cve_id;
  END;
