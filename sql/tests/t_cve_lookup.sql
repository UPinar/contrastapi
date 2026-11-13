INSERT INTO cves (cve_id, cve_description, cvss_v3, cvss_v3_vector, in_kev, refs) VALUES
  ('CVE-2001-0001', 'in KEV, known ransomware', 9.8, 'CVSS:3.1/AV:N', true,
   '[{"url": "https://a.example", "tags": ["Exploit"]}, {"url": "https://b.example", "tags": ["Vendor Advisory"]}]'),
  ('CVE-2001-0002', 'left KEV', 7.5, 'CVSS:3.1/AV:N', false, '[]'),
  ('CVE-2001-0003', 'never in KEV', 5.0, 'CVSS:3.1/AV:N', false, '[]'),
  ('CVE-2001-0004', 'in KEV, no known ransomware', 6.1, 'CVSS:3.1/AV:N', true, '[]'),
  ('CVE-2001-0010', 'in KEV, no kev_details row yet', 6.1, 'CVSS:3.1/AV:N', true, '[]');
INSERT INTO kev_details (cve_id, known_ransomware_use) VALUES
  ('CVE-2001-0001', true), ('CVE-2001-0002', true), ('CVE-2001-0004', false);
INSERT INTO epss_history (cve_id, epss_date, score, percentile) VALUES
  ('CVE-2001-0001', '2001-03-01', 0.1, 0.2),
  ('CVE-2001-0001', '2001-03-03', 0.5, 0.6),
  ('CVE-2001-0001', '2001-03-02', 0.3, 0.4);
INSERT INTO metasploit_modules (cve_id, module_name) VALUES
  ('CVE-2001-0001', 'm1'), ('CVE-2001-0001', 'm2');
INSERT INTO nuclei_templates (template_path, cve_id, template_id, template_name, severity) VALUES
  ('network/cves/2001/CVE-2001-0001.yaml', 'CVE-2001-0001', 'CVE-2001-0001-alt', 'Net check', 'high'),
  ('http/cves/2001/CVE-2001-0001.yaml',    'CVE-2001-0001', 'CVE-2001-0001',     'Web check', 'critical'),
  ('javascript/cves/2001/CVE-2001-0001.yaml', 'CVE-2001-0001', 'CVE-2001-0001-js', 'JS check', 'medium'),
  ('http/cves/2001/CVE-2001-0099.yaml',    'CVE-2001-0099', 'CVE-2001-0099',     'Orphan',    'low');
DO $$
BEGIN
  ASSERT (SELECT count(*) FROM api.fn_cve_lookup(ARRAY['CVE-2001-0099'], 30, 5, 20, 10, 20)) = 0,
         'a CVE with a Nuclei template and no cves row answers no row';
END
$$;
UPDATE cves SET ssvc_exploitation = 'active', ssvc_automatable = 'no', ssvc_technical_impact = 'total',
                ssvc_version = '2.0.3', ssvc_scored_at = '2024-04-17 17:05:13+03'
 WHERE cve_id = 'CVE-2001-0001';
UPDATE cves SET ssvc_exploitation = 'poc', ssvc_automatable = 'yes', ssvc_technical_impact = 'partial',
                ssvc_version = '2.0.3'
 WHERE cve_id = 'CVE-2001-0002';
UPDATE cves SET cve_tags = '["disputed"]' WHERE cve_id = 'CVE-2001-0001';
UPDATE cves SET cvss_v3_source = 'nvd', cvss_v4_source = 'cna', cwe_source = 'adp' WHERE cve_id = 'CVE-2001-0001';

CREATE TEMP VIEW t_cve_lookup_call AS SELECT * FROM api.fn_cve_lookup(ARRAY['CVE-2001-0001'], 30, 5, 20, 10, 20);

DO $$
BEGIN
  ASSERT (SELECT array_agg(attname::text ORDER BY attnum) FROM pg_attribute
          WHERE attrelid = 't_cve_lookup_call'::regclass AND attnum > 0)
         = ARRAY['cve_id', 'cve_description', 'severity', 'cvss_v3', 'cvss_v3_vector',
                 'published_time', 'epss_score', 'epss_percentile', 'cwe_id', 'cwes', 'in_kev',
                 'kev_date_added', 'vulnerability_status', 'poc_count', 'vendor_advisory_count',
                 'cve_tags', 'metasploit_module_count', 'affected_products', 'refs', 'epss_trend',
                 'ransomware_campaign', 'cvss_v4', 'cvss_v4_vector', 'ssvc_exploitation',
                 'ssvc_automatable', 'ssvc_technical_impact', 'ssvc_version', 'ssvc_scored_at',
                 'metasploit_feed_loaded', 'nuclei_template_count', 'nuclei_template_feed_loaded',
                 'nuclei_templates', 'cvss_v3_source', 'cvss_v4_source', 'cwe_source',
                 'affected_product_count', 'product_count_by_vendor', 'ref_count'],
         'api.fn_cve_lookup answers the 38 columns db_CVELOOKUP reads, in its order';
  ASSERT (SELECT array_agg(format_type(atttypid, atttypmod) ORDER BY attnum) FROM pg_attribute
          WHERE attrelid = 't_cve_lookup_call'::regclass AND attnum > 0)
         = ARRAY['text', 'text', 'text', 'real', 'text', 'date', 'real', 'real', 'text', 'jsonb',
                 'boolean', 'text', 'text', 'integer', 'integer', 'jsonb', 'integer', 'jsonb',
                 'jsonb', 'jsonb', 'text', 'real', 'text', 'text', 'text', 'text', 'text', 'text',
                 'boolean', 'integer', 'boolean', 'jsonb', 'text', 'text', 'text',
                 'integer', 'jsonb', 'integer'],
         'each cves column keeps its type, ssvc_scored_at is text, cve_tags, epss_trend and nuclei_templates are jsonb, the feed and template columns are boolean, integer and boolean, the three source columns are text, affected_product_count and ref_count are integer, and product_count_by_vendor is jsonb';
  ASSERT (SELECT ROW(cvss_v3_source, cvss_v4_source, cwe_source) FROM t_cve_lookup_call) = ROW('nvd'::text, 'cna'::text, 'adp'::text),
         'each source column holds its own cves value';
  ASSERT (SELECT ROW(cvss_v3_source, cvss_v4_source, cwe_source) FROM api.fn_cve_lookup(ARRAY['CVE-2001-0003'], 30, 5, 20, 10, 20)) = ROW(''::text, ''::text, ''::text),
         'a CVE with no class answers the empty string in each source column';
  ASSERT (SELECT array_agg(cve_id ORDER BY ord) FROM
            (SELECT cve_id, row_number() OVER () AS ord
               FROM api.fn_cve_lookup(ARRAY['CVE-2001-0003', 'CVE-2001-0001', 'CVE-2001-0009', 'CVE-2001-0003'], 30, 5, 20, 10, 20)) AS rows)
         = ARRAY['CVE-2001-0003', 'CVE-2001-0001'],
         'the rows come in the order of the ids, an unknown id answers no row, and a repeated id answers one row';
  ASSERT (SELECT json_array_length(epss_trend::json) FROM api.fn_cve_lookup(ARRAY['CVE-2001-0001'], 2, 5, 20, 10, 20)) = 2,
         'the trend holds at most p_epss_trend_row_count days';
  ASSERT (SELECT epss_trend::json->0->>'epss_date' FROM t_cve_lookup_call) = '2001-03-03',
         'the trend starts with the newest day';
  ASSERT (SELECT array_agg(k ORDER BY k) FROM t_cve_lookup_call, jsonb_object_keys(epss_trend->0) AS k)
         = ARRAY['epss_date', 'percentile', 'score'],
         'each trend element has the keys epss_date, percentile and score, and no other';
  ASSERT (SELECT epss_trend -> 0 FROM t_cve_lookup_call)
         = '{"epss_date": "2001-03-03", "score": 0.5, "percentile": 0.6}'::jsonb,
         'the newest trend element carries the score and the percentile of its day';
  ASSERT (SELECT cve_tags FROM t_cve_lookup_call) = '["disputed"]'::jsonb,
         'cve_tags answers the tags of the row';
  ASSERT (SELECT epss_trend FROM api.fn_cve_lookup(ARRAY['CVE-2001-0003'], 30, 5, 20, 10, 20)) = '[]',
         'a CVE with no EPSS history answers an empty trend';
  ASSERT (SELECT metasploit_module_count = 2 AND poc_count = 1 AND vendor_advisory_count = 1 FROM t_cve_lookup_call),
         'metasploit_module_count counts the modules, and the PoC and advisory counts come from refs';
  ASSERT (SELECT metasploit_module_count FROM api.fn_cve_lookup(ARRAY['CVE-2001-0003'], 30, 5, 20, 10, 20)) = 0,
         'a CVE with no module answers a metasploit_module_count of 0';
  ASSERT (SELECT metasploit_feed_loaded FROM api.fn_cve_lookup(ARRAY['CVE-2001-0003'], 30, 5, 20, 10, 20)),
         'a CVE with no module answers a loaded feed while metasploit_modules holds a module';
  ASSERT (SELECT ransomware_campaign FROM t_cve_lookup_call) = 'Known',
         'a KEV CVE with known ransomware use answers Known';
  ASSERT (SELECT ransomware_campaign FROM api.fn_cve_lookup(ARRAY['CVE-2001-0004'], 30, 5, 20, 10, 20)) = 'Unknown',
         'a KEV CVE without known ransomware use answers Unknown';
  ASSERT (SELECT ransomware_campaign IS NULL FROM api.fn_cve_lookup(ARRAY['CVE-2001-0002'], 30, 5, 20, 10, 20)),
         'a CVE that left KEV answers NULL, though its kev_details row stays';
  ASSERT (SELECT ransomware_campaign IS NULL FROM api.fn_cve_lookup(ARRAY['CVE-2001-0003'], 30, 5, 20, 10, 20)),
         'a CVE outside KEV answers NULL';
  ASSERT (SELECT ransomware_campaign IS NULL FROM api.fn_cve_lookup(ARRAY['CVE-2001-0010'], 30, 5, 20, 10, 20)),
         'a KEV CVE with no kev_details row answers NULL, not the row of another CVE';
  ASSERT (SELECT count(*) FROM api.fn_cve_lookup(ARRAY['CVE-2001-0001'], NULL, 5, 20, 10, 20)) = 0,
         'a NULL row limit answers no row';
  ASSERT (SELECT count(*) FROM api.fn_cve_lookup(NULL, 30, 5, 20, 10, 20)) = 0,
         'a NULL id list answers no row';
  ASSERT (SELECT count(*) FROM api.fn_cve_lookup(ARRAY['CVE-2001-0001'], 30, 5, NULL, 10, 20)) = 0,
         'a NULL product row limit answers no row';
  ASSERT (SELECT count(*) FROM api.fn_cve_lookup(ARRAY['CVE-2001-0001'], 30, 5, 20, NULL, 20)) = 0,
         'a NULL vendor row limit answers no row';
  ASSERT (SELECT count(*) FROM api.fn_cve_lookup(ARRAY['CVE-2001-0001'], 30, 5, 20, 10, NULL)) = 0,
         'a NULL reference row limit answers no row';
END
$$;

DO $$
DECLARE
  saved_time_zone text := current_setting('TimeZone');
BEGIN
  PERFORM set_config('TimeZone', 'Europe/Istanbul', true);
  ASSERT (SELECT ssvc_exploitation = 'active' AND ssvc_automatable = 'no' AND ssvc_technical_impact = 'total'
                 AND ssvc_version = '2.0.3'
            FROM t_cve_lookup_call),
         'each ssvc_ column answers the value of its own cves column';
  ASSERT (SELECT ssvc_scored_at FROM t_cve_lookup_call) = '2024-04-17T14:05:13Z',
         'ssvc_scored_at answers the time in UTC, as YYYY-MM-DDTHH:MI:SSZ, in an Istanbul session too';
  ASSERT (SELECT ssvc_exploitation = 'poc' AND ssvc_automatable = 'yes' AND ssvc_technical_impact = 'partial'
                 AND ssvc_version = '2.0.3' AND ssvc_scored_at IS NULL
            FROM api.fn_cve_lookup(ARRAY['CVE-2001-0002'], 30, 5, 20, 10, 20)),
         'an assessment with no time answers its values and a NULL ssvc_scored_at';
  ASSERT (SELECT num_nulls(ssvc_exploitation, ssvc_automatable, ssvc_technical_impact, ssvc_version, ssvc_scored_at) = 5
            FROM api.fn_cve_lookup(ARRAY['CVE-2001-0003'], 30, 5, 20, 10, 20)),
         'a CVE with no assessment answers NULL in the five ssvc_ columns';
  PERFORM set_config('TimeZone', saved_time_zone, true);
END
$$;

DO $$
BEGIN
  ASSERT (SELECT nuclei_template_count FROM t_cve_lookup_call) = 3,
         'nuclei_template_count counts every template of the CVE';
  ASSERT (SELECT array_agg(template ->> 'template_path' ORDER BY ord)
            FROM api.fn_cve_lookup(ARRAY['CVE-2001-0001'], 30, 2, 20, 10, 20) AS lookup,
                 json_array_elements(lookup.nuclei_templates::json) WITH ORDINALITY AS t (template, ord))
         = ARRAY['http/cves/2001/CVE-2001-0001.yaml', 'javascript/cves/2001/CVE-2001-0001.yaml'],
         'the list holds at most p_nuclei_template_row_count templates, in template_path order';
  ASSERT (SELECT nuclei_template_count FROM api.fn_cve_lookup(ARRAY['CVE-2001-0001'], 30, 2, 20, 10, 20)) = 3,
         'the count is not cut by the row limit of the list';
  ASSERT (SELECT array_agg(k ORDER BY k) FROM t_cve_lookup_call, jsonb_object_keys(nuclei_templates -> 0) AS k)
         = ARRAY['name', 'severity', 'template_id', 'template_path', 'url'],
         'each template has the keys name, severity, template_id, template_path and url, and no other';
  ASSERT (SELECT nuclei_templates::json -> 0 ->> 'template_id' = 'CVE-2001-0001'
                 AND nuclei_templates::json -> 0 ->> 'name' = 'Web check'
                 AND nuclei_templates::json -> 0 ->> 'severity' = 'critical'
            FROM t_cve_lookup_call),
         'each key holds the value of its own column';
  ASSERT (SELECT nuclei_templates::json -> 0 ->> 'url' FROM t_cve_lookup_call)
         = 'https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2001/CVE-2001-0001.yaml',
         'url is the GitHub link of the template path';
  ASSERT (SELECT nuclei_template_count = 0 AND nuclei_templates = '[]' AND nuclei_template_feed_loaded
            FROM api.fn_cve_lookup(ARRAY['CVE-2001-0003'], 30, 5, 20, 10, 20)),
         'a CVE with no template answers 0, an empty list and a loaded feed';
  ASSERT (SELECT count(*) FROM api.fn_cve_lookup(ARRAY['CVE-2001-0001'], 30, NULL, 20, 10, 20)) = 0,
         'a NULL template row limit answers no row';
END
$$;

SAVEPOINT t_cve_lookup_products_and_refs;
INSERT INTO cves (cve_id, affected_products, refs) VALUES
  ('CVE-2001-0005',
   '[{"vendor": "b", "product": "p1", "is_vulnerable": false, "version_start_including": null},
     {"vendor": "c", "product": "p2", "is_vulnerable": true, "version_end_excluding": "2.0"},
     {"vendor": "b", "product": "p3", "is_vulnerable": true, "version_end_including": null},
     {"vendor": "", "product": "p4", "is_vulnerable": true},
     {"vendor": "b", "product": "p5", "is_vulnerable": true},
     {"vendor": "a", "product": "p6", "is_vulnerable": true}]',
   '[{"url": "https://r3.example", "tags": [], "source": "nvd"},
     {"url": "https://r2.example", "tags": ["Patch"], "source": "cna"},
     {"url": "https://r4.example", "tags": [], "source": "nvd"},
     {"url": "https://r1.example", "tags": ["exploit"], "source": "nvd"},
     {"url": "https://Rz.example", "tags": [], "source": "nvd"},
     {"url": "https://r1.example", "tags": ["Patch"], "source": "nvd"}]'),
  ('CVE-2001-0006', '[7]', '[]');

DO $$
BEGIN
  ASSERT (SELECT affected_products FROM api.fn_cve_lookup(ARRAY['CVE-2001-0005'], 30, 5, 3, 10, 20))
         = (SELECT affected_products FROM api.fn_cve_products('CVE-2001-0005', NULL, NULL, 3, 0)),
         'affected_products is the first page of api.fn_cve_products, with no filter';
  ASSERT (SELECT affected_products FROM api.fn_cve_lookup(ARRAY['CVE-2001-0005'], 30, 5, 3, 10, 20))
         = '[{"vendor": "", "product": "p4", "is_vulnerable": true},
             {"vendor": "a", "product": "p6", "is_vulnerable": true},
             {"vendor": "b", "product": "p3", "is_vulnerable": true}]'::jsonb,
         'the page holds at most p_product_row_count elements, the vulnerable ones first by vendor, with no null bound';
  ASSERT (SELECT affected_product_count FROM api.fn_cve_lookup(ARRAY['CVE-2001-0005'], 30, 5, 2, 10, 20)) = 6,
         'affected_product_count counts every element, not only the page';
  ASSERT (SELECT product_count_by_vendor FROM api.fn_cve_lookup(ARRAY['CVE-2001-0005'], 30, 5, 20, 10, 20))
         = '{"a": 1, "b": 3, "c": 1}'::jsonb,
         'product_count_by_vendor counts the elements of each vendor, and leaves out the empty vendor';
  ASSERT (SELECT product_count_by_vendor FROM api.fn_cve_lookup(ARRAY['CVE-2001-0005'], 30, 5, 20, 2, 20))
         = '{"a": 1, "b": 3}'::jsonb,
         'p_vendor_row_count keeps the vendors with the most elements, and a tie goes to the vendor that sorts first';
  ASSERT (SELECT product_count_by_vendor FROM api.fn_cve_lookup(ARRAY['CVE-2001-0003'], 30, 5, 20, 10, 20)) = '{}'::jsonb,
         'a CVE with no affected product answers an empty vendor object';
  ASSERT (SELECT refs FROM api.fn_cve_lookup(ARRAY['CVE-2001-0005'], 30, 5, 20, 10, 2))
         = '[{"url": "https://Rz.example", "tags": []}, {"url": "https://r1.example", "tags": ["Patch"]}]'::jsonb,
         'p_ref_row_count cuts the sorted references, not the references of the array';
  ASSERT (SELECT refs FROM api.fn_cve_lookup(ARRAY['CVE-2001-0005'], 30, 5, 20, 10, 3))
         = '[{"url": "https://Rz.example", "tags": []}, {"url": "https://r1.example", "tags": ["Patch"]},
             {"url": "https://r1.example", "tags": ["exploit"]}]'::jsonb,
         'refs holds the first p_ref_row_count references by url, each without its source key';
  ASSERT (SELECT ref_count FROM api.fn_cve_lookup(ARRAY['CVE-2001-0005'], 30, 5, 20, 10, 3)) = 6,
         'ref_count counts every reference, not only the listed ones';
  ASSERT (SELECT refs = '[]' AND ref_count = 0 FROM api.fn_cve_lookup(ARRAY['CVE-2001-0003'], 30, 5, 20, 10, 20)),
         'a CVE with no reference answers an empty list and a count of 0';
  ASSERT (SELECT row(affected_products, affected_product_count, product_count_by_vendor)::text
            FROM api.fn_cve_lookup(ARRAY['CVE-2001-0006'], 30, 5, 20, 10, 20))
         = row('[7]'::jsonb, 1, '{}'::jsonb)::text,
         'an affected product that is not an object stays as cves holds it, and fails no call';
END
$$;
ROLLBACK TO SAVEPOINT t_cve_lookup_products_and_refs;

SAVEPOINT t_cve_lookup_empty_nuclei;
DELETE FROM nuclei_templates;
DO $$
BEGIN
  ASSERT (SELECT array_agg(row(nuclei_template_count, nuclei_template_feed_loaded, nuclei_templates)::text)
            FROM api.fn_cve_lookup(ARRAY['CVE-2001-0001'], 30, 5, 20, 10, 20))
         = ARRAY[row(0, false, '[]')::text],
         'an empty nuclei_templates table answers a count of 0, a feed that is not loaded and an empty list';
END
$$;
ROLLBACK TO SAVEPOINT t_cve_lookup_empty_nuclei;

SAVEPOINT t_cve_lookup_longest_nuclei;
INSERT INTO cves (cve_id) VALUES ('CVE-2001-0077');
INSERT INTO nuclei_templates (template_path, cve_id, template_id, template_name, severity)
SELECT 'http/' || repeat('a', 245) || n || '.yaml', 'CVE-2001-0077', repeat(chr(1), 64), repeat(chr(1), 256), 'critical'
  FROM generate_series(1, 5) AS n;
DO $$
BEGIN
  ASSERT (SELECT octet_length(c.nuclei_templates::text) FROM api.fn_cve_lookup(ARRAY['CVE-2001-0077'], 30, 5, 20, 10, 20) AS c) = 12920,
         format('the longest values give a nuclei_templates text of 12920 bytes for 5 templates, measured %s',
                (SELECT octet_length(c.nuclei_templates::text) FROM api.fn_cve_lookup(ARRAY['CVE-2001-0077'], 30, 5, 20, 10, 20) AS c));
END
$$;
ROLLBACK TO SAVEPOINT t_cve_lookup_longest_nuclei;

SAVEPOINT t_cve_lookup_empty_metasploit;
DELETE FROM metasploit_modules;
DO $$
BEGIN
  ASSERT (SELECT array_agg(row(metasploit_module_count, metasploit_feed_loaded)::text)
            FROM api.fn_cve_lookup(ARRAY['CVE-2001-0001'], 30, 5, 20, 10, 20))
         = ARRAY[row(0, false)::text],
         'an empty metasploit_modules table answers a count of 0 and a feed that is not loaded';
END
$$;
ROLLBACK TO SAVEPOINT t_cve_lookup_empty_metasploit;

PREPARE t_cve_lookup_query AS SELECT * FROM api.fn_cve_lookup(ARRAY[$1], $2, $3, $4, $5, $6);
CREATE TEMP TABLE t_cve_lookup_answer AS EXECUTE t_cve_lookup_query('CVE-2001-0001', '30', '5', '20', '10', '20');
DEALLOCATE t_cve_lookup_query;

DO $$
BEGIN
  ASSERT (SELECT array_agg(cve_id) FROM t_cve_lookup_answer) = ARRAY['CVE-2001-0001'],
         'the query db_CVELOOKUP sends answers the row of its id';
END
$$;

PREPARE t_cve_lookup_bulk_query AS SELECT * FROM api.fn_cve_lookup($1, $2, $3, $4, $5, $6);
CREATE TEMP TABLE t_cve_lookup_bulk_answer AS
  EXECUTE t_cve_lookup_bulk_query('{CVE-2001-0003,CVE-2001-0001,CVE-2001-0009}', '30', '5', '20', '10', '20');
DEALLOCATE t_cve_lookup_bulk_query;

DO $$
BEGIN
  ASSERT (SELECT array_agg(cve_id ORDER BY ctid) FROM t_cve_lookup_bulk_answer)
         = ARRAY['CVE-2001-0003', 'CVE-2001-0001'],
         'the query db_CVELOOKUPBULK sends answers the rows of its ids, in their order';
END
$$;

DO $$
BEGIN
  ASSERT (SELECT prosecdef AND provolatile = 's' AND proisstrict FROM pg_proc
          WHERE oid = 'api.fn_cve_lookup(text[], integer, integer, integer, integer, integer)'::regprocedure),
         'api.fn_cve_lookup is SECURITY DEFINER, STABLE and STRICT';
  ASSERT (SELECT proconfig FROM pg_proc
          WHERE oid = 'api.fn_cve_lookup(text[], integer, integer, integer, integer, integer)'::regprocedure)
         = ARRAY['search_path=pg_catalog'],
         'api.fn_cve_lookup sets search_path to pg_catalog';
END
$$;
