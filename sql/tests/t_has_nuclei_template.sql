INSERT INTO cves (cve_id) VALUES ('CVE-0000-2001'), ('CVE-0000-2002'), ('CVE-0000-2003');

CREATE TEMP VIEW t_has_nuclei_template_flags AS
  SELECT cve_id, has_nuclei_template FROM cves WHERE cve_id LIKE 'CVE-0000-2%';

DO $$
BEGIN
  ASSERT (SELECT count(*) FROM t_has_nuclei_template_flags WHERE has_nuclei_template) = 0,
         'a cves row with no template starts false';

  INSERT INTO nuclei_templates (template_path, cve_id) VALUES ('http/a.yaml', 'CVE-0000-2001');
  ASSERT (SELECT has_nuclei_template FROM t_has_nuclei_template_flags WHERE cve_id = 'CVE-0000-2001'),
         'an inserted template sets the flag';
  ASSERT NOT (SELECT has_nuclei_template FROM t_has_nuclei_template_flags WHERE cve_id = 'CVE-0000-2002'),
         'an inserted template leaves another cve_id false';

  INSERT INTO nuclei_templates (template_path, cve_id) VALUES ('network/a.yaml', 'CVE-0000-2001');
  DELETE FROM nuclei_templates WHERE template_path = 'http/a.yaml';
  ASSERT (SELECT has_nuclei_template FROM t_has_nuclei_template_flags WHERE cve_id = 'CVE-0000-2001'),
         'deleting one of two templates keeps the flag';

  DELETE FROM nuclei_templates WHERE cve_id = 'CVE-0000-2001';
  ASSERT NOT (SELECT has_nuclei_template FROM t_has_nuclei_template_flags WHERE cve_id = 'CVE-0000-2001'),
         'deleting the last template clears the flag';
END
$$;

SAVEPOINT t_has_nuclei_template_untouched;
UPDATE cves SET has_nuclei_template = true WHERE cve_id = 'CVE-0000-2003';
DO $$
BEGIN
  INSERT INTO nuclei_templates (template_path, cve_id) VALUES ('http/u.yaml', 'CVE-0000-2002');
  ASSERT (SELECT has_nuclei_template FROM t_has_nuclei_template_flags WHERE cve_id = 'CVE-0000-2003'),
         'a template of another cve_id leaves a row it did not touch as it was';
END
$$;
ROLLBACK TO SAVEPOINT t_has_nuclei_template_untouched;

DO $$
BEGIN
  INSERT INTO nuclei_templates (template_path, cve_id) VALUES ('http/b.yaml', 'CVE-0000-2004');
  ASSERT NOT EXISTS (SELECT 1 FROM cves WHERE cve_id = 'CVE-0000-2004'),
         'a template with no cves row adds no cves row';

  INSERT INTO cves (cve_id) VALUES ('CVE-0000-2007');
  ASSERT NOT (SELECT has_nuclei_template FROM t_has_nuclei_template_flags WHERE cve_id = 'CVE-0000-2007'),
         'a new cves row starts false while only another cve_id has a template';

  INSERT INTO cves (cve_id) VALUES ('CVE-0000-2004');
  ASSERT (SELECT has_nuclei_template FROM t_has_nuclei_template_flags WHERE cve_id = 'CVE-0000-2004'),
         'a cves row that comes after its template starts true';

  INSERT INTO cves (cve_id, cve_description) VALUES ('CVE-0000-2004', 'upserted')
  ON CONFLICT (cve_id) DO UPDATE SET cve_description = EXCLUDED.cve_description;
  ASSERT (SELECT has_nuclei_template AND cve_description = 'upserted' FROM cves WHERE cve_id = 'CVE-0000-2004'),
         'an upsert of the cves row keeps the flag';
END
$$;

DO $$
BEGIN
  UPDATE nuclei_templates SET cve_id = 'CVE-0000-2002' WHERE template_path = 'http/b.yaml';
  ASSERT (SELECT has_nuclei_template FROM t_has_nuclei_template_flags WHERE cve_id = 'CVE-0000-2002'),
         'a template moved to a cve_id sets its flag';
  ASSERT NOT (SELECT has_nuclei_template FROM t_has_nuclei_template_flags WHERE cve_id = 'CVE-0000-2004'),
         'moving the last template away clears the old cve_id';

  UPDATE nuclei_templates SET severity = 'high' WHERE template_path = 'http/b.yaml';
  ASSERT (SELECT has_nuclei_template FROM t_has_nuclei_template_flags WHERE cve_id = 'CVE-0000-2002'),
         'an UPDATE that keeps the cve_id keeps the flag';

  TRUNCATE nuclei_templates;
  ASSERT (SELECT count(*) FROM t_has_nuclei_template_flags WHERE has_nuclei_template) = 0,
         'a TRUNCATE clears every flag';
END
$$;

DO $$
DECLARE
  bad              record;
  fired_constraint text;
BEGIN
  FOR bad IN
    SELECT * FROM (VALUES
      ('http/x.yaml', 'cve-0000-2001', '', '', '', 'nuclei_templates_cve_id_format'),
      ('http/x.yml',  'CVE-0000-2001', '', '', '', 'nuclei_templates_path_format'),
      ('http/../x.yaml', 'CVE-0000-2001', '', '', '', 'nuclei_templates_path_format'),
      ('http/x y.yaml', 'CVE-0000-2001', '', '', '', 'nuclei_templates_path_format'),
      ('http/' || repeat('a', 247) || '.yaml', 'CVE-0000-2001', '', '', '', 'nuclei_templates_path_format'),
      ('http/x.yaml', 'CVE-0000-2001', repeat('i', 65), '', '', 'nuclei_templates_id_length'),
      ('http/x.yaml', 'CVE-0000-2001', '', repeat('n', 257), '', 'nuclei_templates_name_length'),
      ('http/x.yaml', 'CVE-0000-2001', '', '', 'severe', 'nuclei_templates_severity_known'))
      AS v (template_path, cve_id, template_id, template_name, severity, constraint_name)
  LOOP
    BEGIN
      INSERT INTO nuclei_templates (template_path, cve_id, template_id, template_name, severity)
      VALUES (bad.template_path, bad.cve_id, bad.template_id, bad.template_name, bad.severity);
      ASSERT false, bad.constraint_name || ' refuses its row';
    EXCEPTION WHEN check_violation THEN
      GET STACKED DIAGNOSTICS fired_constraint = CONSTRAINT_NAME;
      ASSERT fired_constraint = bad.constraint_name, bad.constraint_name || ' refuses its row, not ' || fired_constraint;
    END;
  END LOOP;
END
$$;

DO $$
BEGIN
  INSERT INTO nuclei_templates (template_path, cve_id, template_id, template_name, severity) VALUES
    ('http/' || repeat('a', 246) || '.yaml', 'CVE-0000-2001', repeat('i', 64), repeat('n', 256), 'info'),
    ('http/s1.yaml', 'CVE-0000-2001', '', '', ''),
    ('http/s2.yaml', 'CVE-0000-2001', '', '', 'low'),
    ('http/s3.yaml', 'CVE-0000-2001', '', '', 'medium'),
    ('http/s4.yaml', 'CVE-0000-2001', '', '', 'high'),
    ('http/s5.yaml', 'CVE-0000-2001', '', '', 'critical'),
    ('http/s6.yaml', 'CVE-0000-2001', '', '', 'unknown');
  ASSERT (SELECT max(octet_length(template_path)) FROM nuclei_templates) = 256,
         'a 256-byte path is accepted';
  TRUNCATE nuclei_templates;
END
$$;

DO $$
DECLARE
  saved_search_path text := current_setting('search_path');
BEGIN
  PERFORM set_config('search_path', 'pg_catalog', true);
  INSERT INTO public.nuclei_templates (template_path, cve_id) VALUES ('http/2006.yaml', 'CVE-0000-2006');
  INSERT INTO public.cves (cve_id) VALUES ('CVE-0000-2006');
  INSERT INTO public.nuclei_templates (template_path, cve_id) VALUES ('http/2003.yaml', 'CVE-0000-2003');
  PERFORM set_config('search_path', saved_search_path, true);
  ASSERT (SELECT array_agg(cve_id ORDER BY cve_id) FROM t_has_nuclei_template_flags WHERE has_nuclei_template)
         = ARRAY['CVE-0000-2003', 'CVE-0000-2006'],
         'the triggers work with search_path set to pg_catalog';
  TRUNCATE nuclei_templates;
END
$$;
