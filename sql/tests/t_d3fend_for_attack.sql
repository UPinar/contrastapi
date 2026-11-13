INSERT INTO d3fend_defenses (defense_id, defense_label, defense_tactic, digital_artifact, parent_defense_labels) VALUES
  ('DefB',   'Aardvark', 'Detect', 'Artifact B', '{Zeta Parent,Alpha Parent}'),
  ('DefA2',  'Alpha',    'Model',  '',           '{}'),
  ('DefA',   'Alpha',    'Harden', '',           '{Gamma Parent}'),
  ('DefSib', 'Sibling',  'Evict',  '',           '{}');
INSERT INTO d3fend_attack_mappings (defense_id, attack_technique_id, attack_label) VALUES
  ('DefB',   'T1055.012', 'Process Hollowing'),
  ('DefB',   'T1055.001', 'Dynamic-link Library Injection'),
  ('DefA2',  'T1055.012', 'Process Hollowing (old)'),
  ('DefA2',  'T1055.001', ''),
  ('DefA',   'T1055.004', ''),
  ('DefA',   'T1055',     'Process Injection'),
  ('DefSib', 'T1056.012', 'Sibling Sub'),
  ('DefSib', 'T1056',     'Sibling');

CREATE TEMP VIEW t_d3fend_for_attack_call AS SELECT * FROM api.fn_d3fend_for_attack('T1055');

DO $$
BEGIN
  ASSERT (SELECT array_agg(attname::text ORDER BY attnum) FROM pg_attribute
          WHERE attrelid = 't_d3fend_for_attack_call'::regclass AND attnum > 0)
         = ARRAY['defense_id', 'defense_label', 'defense_tactic', 'digital_artifact', 'parent_defense_labels',
                 'attack_technique_ids', 'attack_techniques'],
         'api.fn_d3fend_for_attack answers the 7 columns db_D3FENDFORATTACK reads, in its order';
  ASSERT (SELECT array_agg(format_type(atttypid, atttypmod) ORDER BY attnum) FROM pg_attribute
          WHERE attrelid = 't_d3fend_for_attack_call'::regclass AND attnum > 0)
         = ARRAY['text', 'text', 'text', 'text', 'jsonb', 'jsonb', 'jsonb'],
         'the four defense columns are text and the three lists are jsonb';
  ASSERT (SELECT array_agg(row(c.defense_id, c.defense_label, c.defense_tactic, c.digital_artifact, c.parent_defense_labels,
                              c.attack_technique_ids)::text)
            FROM t_d3fend_for_attack_call AS c)
         = ARRAY[row('DefB',  'Aardvark', 'Detect', 'Artifact B', '["Zeta Parent", "Alpha Parent"]', '["T1055.001", "T1055.012"]')::text,
                 row('DefA',  'Alpha',    'Harden', '',           '["Gamma Parent"]',               '["T1055", "T1055.004"]')::text,
                 row('DefA2', 'Alpha',    'Model',  '',           '[]',                             '["T1055.001", "T1055.012"]')::text],
         'T1055 answers each defense of the technique and of its sub-techniques, by defense_label and then defense_id, '
         'each with its own columns, its parents in their order, and the ids it matched through in id order';
  ASSERT (SELECT bool_and(c.attack_techniques =
            '[{"attack_technique_id":"T1055","subtechnique_of":null,"attack_label":"Process Injection"},'
            '{"attack_technique_id":"T1055.001","subtechnique_of":"T1055","attack_label":"Dynamic-link Library Injection"},'
            '{"attack_technique_id":"T1055.004","subtechnique_of":"T1055","attack_label":null},'
            '{"attack_technique_id":"T1055.012","subtechnique_of":"T1055","attack_label":"Process Hollowing"}]')
            FROM t_d3fend_for_attack_call AS c),
         'every row repeats each matched id once, in id order; a label one mapping gives wins over an empty one, the smaller of two names wins, '
         'and an id whose every label is empty has null';
  ASSERT (SELECT array_agg(row(c.defense_id, c.attack_technique_ids, c.attack_techniques)::text)
            FROM api.fn_d3fend_for_attack('T1055.012') AS c)
         = ARRAY[row('DefB',  '["T1055.012"]', '[{"attack_label": "Process Hollowing", "subtechnique_of": "T1055", "attack_technique_id": "T1055.012"}]')::text,
                 row('DefA2', '["T1055.012"]', '[{"attack_label": "Process Hollowing", "subtechnique_of": "T1055", "attack_technique_id": "T1055.012"}]')::text],
         'a sub-technique id matches only itself, not its parent technique or a sibling sub-technique';
  ASSERT (SELECT array_agg(c.defense_id) FROM api.fn_d3fend_for_attack('T1056') AS c) = ARRAY['DefSib'],
         'T1056 matches its own defense and none of T1055';
  ASSERT (SELECT count(*) FROM api.fn_d3fend_for_attack('T9999')) = 0,
         'an id with no defense answers no row';
  ASSERT (SELECT count(*) FROM api.fn_d3fend_for_attack(NULL)) = 0,
         'api.fn_d3fend_for_attack is STRICT, so a NULL id answers no row';
  ASSERT (SELECT array_agg(dam.attack_parent_technique_id::text ORDER BY dam.defense_id, dam.attack_technique_id)
            FROM d3fend_attack_mappings AS dam WHERE dam.defense_id = 'DefB')
         = ARRAY['T1055', 'T1055'],
         'attack_parent_technique_id is the technique of a sub-technique';
END
$$;

PREPARE t_d3fend_for_attack_query AS SELECT * FROM api.fn_d3fend_for_attack($1);
CREATE TEMP TABLE t_d3fend_for_attack_answer AS EXECUTE t_d3fend_for_attack_query('T1055.001');
DEALLOCATE t_d3fend_for_attack_query;

DO $$
BEGIN
  ASSERT (SELECT array_agg(defense_id) FROM t_d3fend_for_attack_answer) = ARRAY['DefB', 'DefA2'],
         'the query db_D3FENDFORATTACK sends answers the defenses of its id';
  ASSERT (SELECT p.prosecdef AND p.proisstrict AND p.provolatile = 's' AND p.proconfig = ARRAY['search_path=pg_catalog']
            FROM pg_proc AS p WHERE p.oid = 'api.fn_d3fend_for_attack(text)'::regprocedure),
         'api.fn_d3fend_for_attack is SECURITY DEFINER, STRICT, STABLE and sets search_path to pg_catalog';
END
$$;
