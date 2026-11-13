CREATE FUNCTION api.fn_d3fend_for_attack(p_attack_technique_id text)
  RETURNS TABLE (defense_id            text,
                 defense_label         text,
                 defense_tactic        text,
                 digital_artifact      text,
                 parent_defense_labels jsonb,
                 attack_technique_ids  jsonb,
                 attack_techniques     jsonb)
  LANGUAGE sql STABLE STRICT SECURITY DEFINER
  SET search_path = pg_catalog
  BEGIN ATOMIC
    WITH matched_mapping AS (
      SELECT dam.defense_id, dam.attack_technique_id, dam.attack_parent_technique_id, dam.attack_label
        FROM public.d3fend_attack_mappings AS dam
       WHERE p_attack_technique_id IN (dam.attack_technique_id, dam.attack_parent_technique_id)),
    matched_attack_technique AS (
      SELECT mm.attack_technique_id                                         AS attack_technique_id,
             nullif(mm.attack_parent_technique_id, mm.attack_technique_id)  AS subtechnique_of,
             min(nullif(mm.attack_label, ''))                               AS attack_label
        FROM matched_mapping AS mm
       GROUP BY mm.attack_technique_id, mm.attack_parent_technique_id)
    SELECT dd.defense_id                                                                                           AS defense_id,
           dd.defense_label                                                                                        AS defense_label,
           dd.defense_tactic                                                                                       AS defense_tactic,
           dd.digital_artifact                                                                                     AS digital_artifact,
           to_jsonb(dd.parent_defense_labels)                                                                      AS parent_defense_labels,
           to_jsonb(array_agg(mm.attack_technique_id ORDER BY mm.attack_technique_id))                             AS attack_technique_ids,
           (SELECT to_jsonb(array_agg(mat ORDER BY mat.attack_technique_id)) FROM matched_attack_technique AS mat) AS attack_techniques
      FROM matched_mapping AS mm
      JOIN public.d3fend_defenses AS dd ON dd.defense_id = mm.defense_id
     GROUP BY dd.defense_id
     ORDER BY dd.defense_label, dd.defense_id;
  END;
