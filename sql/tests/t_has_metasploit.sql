INSERT INTO cves (cve_id) VALUES ('CVE-0000-0001'), ('CVE-0000-0002'), ('CVE-0000-0003');

CREATE TEMP VIEW t_has_metasploit_flags AS
  SELECT cve_id, has_metasploit FROM cves WHERE cve_id LIKE 'CVE-0000-%';

DO $$
BEGIN
  ASSERT (SELECT count(*) FROM t_has_metasploit_flags WHERE has_metasploit) = 0,
         'a cves row with no module starts false';

  INSERT INTO metasploit_modules (cve_id, module_name) VALUES ('CVE-0000-0001', 'm1');
  ASSERT (SELECT has_metasploit FROM t_has_metasploit_flags WHERE cve_id = 'CVE-0000-0001'),
         'an inserted module sets the flag';
  ASSERT NOT (SELECT has_metasploit FROM t_has_metasploit_flags WHERE cve_id = 'CVE-0000-0002'),
         'an inserted module leaves another cve_id false';

  INSERT INTO metasploit_modules (cve_id, module_name) VALUES ('CVE-0000-0001', 'm2');
  ASSERT (SELECT has_metasploit FROM t_has_metasploit_flags WHERE cve_id = 'CVE-0000-0001'),
         'a second module keeps the flag';

  DELETE FROM metasploit_modules WHERE cve_id = 'CVE-0000-0001' AND module_name = 'm1';
  ASSERT (SELECT has_metasploit FROM t_has_metasploit_flags WHERE cve_id = 'CVE-0000-0001'),
         'deleting one of two modules keeps the flag';

  DELETE FROM metasploit_modules WHERE cve_id = 'CVE-0000-0001';
  ASSERT NOT (SELECT has_metasploit FROM t_has_metasploit_flags WHERE cve_id = 'CVE-0000-0001'),
         'deleting the last module clears the flag';
END
$$;

DO $$
BEGIN
  INSERT INTO metasploit_modules (cve_id, module_name) VALUES ('CVE-0000-0004', 'm1');
  ASSERT NOT EXISTS (SELECT 1 FROM cves WHERE cve_id = 'CVE-0000-0004'),
         'a module with no cves row adds no cves row';

  INSERT INTO cves (cve_id) VALUES ('CVE-0000-0007');
  ASSERT NOT (SELECT has_metasploit FROM t_has_metasploit_flags WHERE cve_id = 'CVE-0000-0007'),
         'a new cves row starts false while only another cve_id has a module';

  INSERT INTO cves (cve_id) VALUES ('CVE-0000-0004');
  ASSERT (SELECT has_metasploit FROM t_has_metasploit_flags WHERE cve_id = 'CVE-0000-0004'),
         'a cves row that comes after its module starts true';

  INSERT INTO cves (cve_id, cve_description, refs)
  VALUES ('CVE-0000-0004', 'upserted', '[{"url": "u", "tags": ["Exploit"]}]')
  ON CONFLICT (cve_id) DO UPDATE SET
    cve_description = EXCLUDED.cve_description,
    refs            = EXCLUDED.refs;
  ASSERT (SELECT has_metasploit AND cve_description = 'upserted' AND poc_count = 1
          FROM cves WHERE cve_id = 'CVE-0000-0004'),
         'an upsert of the cves row keeps the flag and still counts its refs';
END
$$;

DO $$
BEGIN
  INSERT INTO metasploit_modules (cve_id, module_name) VALUES ('CVE-0000-0004', 'm2');
  UPDATE metasploit_modules SET cve_id = 'CVE-0000-0002'
   WHERE cve_id = 'CVE-0000-0004' AND module_name = 'm1';
  ASSERT (SELECT has_metasploit FROM t_has_metasploit_flags WHERE cve_id = 'CVE-0000-0002'),
         'a module moved to a cve_id sets its flag';
  ASSERT (SELECT has_metasploit FROM t_has_metasploit_flags WHERE cve_id = 'CVE-0000-0004'),
         'the old cve_id keeps its flag while it has another module';

  UPDATE metasploit_modules SET cve_id = 'CVE-0000-0002' WHERE cve_id = 'CVE-0000-0004';
  ASSERT NOT (SELECT has_metasploit FROM t_has_metasploit_flags WHERE cve_id = 'CVE-0000-0004'),
         'moving the last module away clears the old cve_id';
  ASSERT (SELECT has_metasploit FROM t_has_metasploit_flags WHERE cve_id = 'CVE-0000-0002'),
         'the new cve_id keeps its flag';

  UPDATE metasploit_modules SET module_rank = 600 WHERE cve_id = 'CVE-0000-0002';
  ASSERT (SELECT has_metasploit FROM t_has_metasploit_flags WHERE cve_id = 'CVE-0000-0002'),
         'an UPDATE that keeps the cve_id keeps the flag';
END
$$;

DO $$
BEGIN
  TRUNCATE metasploit_modules;
  ASSERT (SELECT count(*) FROM t_has_metasploit_flags WHERE has_metasploit) = 0,
         'a TRUNCATE clears every flag';
END
$$;

DO $$
DECLARE
  saved_search_path text := current_setting('search_path');
BEGIN
  PERFORM set_config('search_path', 'pg_catalog', true);
  INSERT INTO public.metasploit_modules (cve_id, module_name) VALUES ('CVE-0000-0006', 'm1');
  INSERT INTO public.cves (cve_id) VALUES ('CVE-0000-0006');
  INSERT INTO public.metasploit_modules (cve_id, module_name) VALUES ('CVE-0000-0003', 'm1');
  PERFORM set_config('search_path', saved_search_path, true);
  ASSERT (SELECT array_agg(cve_id ORDER BY cve_id) FROM t_has_metasploit_flags WHERE has_metasploit)
         = ARRAY['CVE-0000-0003', 'CVE-0000-0006'],
         'the triggers work with search_path set to pg_catalog';
END
$$;

CREATE FUNCTION public.t_shadow_array_agg_step(text[], text) RETURNS text[]
  LANGUAGE sql IMMUTABLE RETURN '{}'::text[];
CREATE AGGREGATE public.array_agg(text) (SFUNC = public.t_shadow_array_agg_step,
                                         STYPE = text[], INITCOND = '{}');
DO $$
BEGIN
  INSERT INTO metasploit_modules (cve_id, module_name) VALUES ('CVE-0000-0007', 'm1');
  ASSERT (SELECT has_metasploit FROM t_has_metasploit_flags WHERE cve_id = 'CVE-0000-0007'),
         'the triggers call the built-in array_agg while public holds a closer match';
END
$$;
DROP AGGREGATE public.array_agg(text);
DROP FUNCTION public.t_shadow_array_agg_step(text[], text);
