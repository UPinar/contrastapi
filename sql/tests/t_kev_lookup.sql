INSERT INTO cves (cve_id, in_kev, kev_date_added) VALUES
  ('CVE-2001-0011', true,  '2001-02-01'),
  ('CVE-2001-0012', false, '2001-02-02'),
  ('CVE-2001-0013', false, '');
INSERT INTO kev_details (cve_id, vendor_project, product, patch_deadline, required_action,
                         known_ransomware_use, vulnerability_name, short_description, notes,
                         cwes, date_removed) VALUES
  ('CVE-2001-0011', 'Vendor', 'Product', '2001-02-15', 'Apply updates', true, 'Name',
   'Short', 'https://a.example ; https://b.example', '["CWE-79"]', ''),
  ('CVE-2001-0012', 'Vendor', 'Product', '2001-02-16', 'Apply updates', false, 'Name',
   'Short', '', '[]', '2001-03-01');

CREATE TEMP VIEW t_kev_lookup_call AS SELECT * FROM api.fn_kev_lookup('CVE-2001-0011');

DO $$
BEGIN
  ASSERT (SELECT array_agg(attname::text ORDER BY attnum) FROM pg_attribute
          WHERE attrelid = 't_kev_lookup_call'::regclass AND attnum > 0)
         = ARRAY['cve_id', 'vendor_project', 'product', 'patch_deadline', 'required_action',
                 'known_ransomware_use', 'vulnerability_name', 'short_description',
                 'kev_date_added', 'date_removed', 'cwes', 'notes', 'in_kev'],
         'api.fn_kev_lookup answers the 13 columns db_KEVLOOKUP reads, in its order';
  ASSERT (SELECT array_agg(format_type(atttypid, atttypmod) ORDER BY attnum) FROM pg_attribute
          WHERE attrelid = 't_kev_lookup_call'::regclass AND attnum > 0)
         = ARRAY['text', 'text', 'text', 'text', 'text', 'boolean', 'text', 'text', 'text',
                 'text', 'jsonb', 'text', 'boolean'],
         'each column keeps the type of the column it reads';
  ASSERT (SELECT row(cve_id, vendor_project, product, patch_deadline, required_action,
                     known_ransomware_use, vulnerability_name, short_description,
                     kev_date_added, date_removed, cwes, notes, in_kev)::text
            FROM t_kev_lookup_call)
         = row('CVE-2001-0011', 'Vendor', 'Product', '2001-02-15', 'Apply updates', true,
               'Name', 'Short', '2001-02-01', '', '["CWE-79"]'::jsonb,
               'https://a.example ; https://b.example', true)::text,
         'each column holds its own value, with kev_date_added and in_kev from cves';
  ASSERT (SELECT NOT in_kev AND date_removed = '2001-03-01' FROM api.fn_kev_lookup('CVE-2001-0012')),
         'a CVE that left KEV answers its entry, with in_kev false';
  ASSERT (SELECT count(*) FROM api.fn_kev_lookup('CVE-2001-0013')) = 0,
         'a CVE with no KEV entry answers no row';
END
$$;

PREPARE t_kev_lookup_query AS SELECT * FROM api.fn_kev_lookup($1);
CREATE TEMP TABLE t_kev_lookup_answer AS EXECUTE t_kev_lookup_query('CVE-2001-0011');
DEALLOCATE t_kev_lookup_query;

DO $$
BEGIN
  ASSERT (SELECT array_agg(cve_id) FROM t_kev_lookup_answer) = ARRAY['CVE-2001-0011'],
         'the query db_KEVLOOKUP sends answers the row of its id';
  ASSERT (SELECT prosecdef AND provolatile = 's' FROM pg_proc
          WHERE oid = 'api.fn_kev_lookup(text)'::regprocedure),
         'api.fn_kev_lookup is SECURITY DEFINER and STABLE';
  ASSERT (SELECT proconfig FROM pg_proc WHERE oid = 'api.fn_kev_lookup(text)'::regprocedure)
         = ARRAY['search_path=pg_catalog'],
         'api.fn_kev_lookup sets search_path to pg_catalog';
END
$$;
