SAVEPOINT t_cve_products_rows;
INSERT INTO cves (cve_id, affected_products) VALUES
  ('CVE-2008-0001',
   '[{"vendor": "acme", "product": "alpha", "is_vulnerable": false, "product_source": "nvd",
      "version_start_including": null, "version_start_excluding": null,
      "version_end_including": null, "version_end_excluding": null},
     {"vendor": "acme", "product": "beta", "product_source": "cna", "default_status": null,
      "versions": [{"version": "1.0", "status": "affected"}]},
     {"vendor": "zeta", "product": "alpha", "is_vulnerable": true, "product_source": "nvd",
      "version_start_including": "1.0", "version_start_excluding": null,
      "version_end_including": null, "version_end_excluding": "2.0"},
     {"product": "gamma", "is_vulnerable": true, "product_source": "nvd"},
     {"vendor": "acme", "product": "alpha", "is_vulnerable": true, "product_source": "nvd",
      "version_start_including": null, "version_start_excluding": "3.0",
      "version_end_including": "4.0", "version_end_excluding": null}]'),
  ('CVE-2008-0002', '[]'),
  ('CVE-2008-0003', '{"vendor": "acme"}'),
  ('CVE-2008-0004', '[5, {"vendor": "acme", "product": "delta", "is_vulnerable": true, "version_end_including": null}]'),
  ('CVE-2008-0005',
   '[{"vendor": "acme", "product": "eta", "is_vulnerable": true, "version_end_excluding": "a.0"},
     {"vendor": "acme", "product": "eta", "is_vulnerable": true, "version_end_excluding": "B.0"},
     {"vendor": "Bolt", "product": "eta", "is_vulnerable": true},
     {"vendor": "acme", "product": "Eta", "is_vulnerable": true}]'),
  ('CVE-2008-0006', '[{"vendor": "acme", "product": "theta"}, {"vendor": "Bolt", "product": "iota"}]');

CREATE TEMP VIEW t_cve_products_call AS SELECT * FROM api.fn_cve_products('CVE-2008-0001', NULL, NULL, 20, 0);

DO $$
BEGIN
  ASSERT (SELECT array_agg(attname::text ORDER BY attnum) FROM pg_attribute
          WHERE attrelid = 't_cve_products_call'::regclass AND attnum > 0)
         = ARRAY['affected_product_count', 'listed_product_count', 'affected_products'],
         'api.fn_cve_products answers the 3 columns db_CVEPRODUCTS reads, in its order';
  ASSERT (SELECT array_agg(format_type(atttypid, atttypmod) ORDER BY attnum) FROM pg_attribute
          WHERE attrelid = 't_cve_products_call'::regclass AND attnum > 0)
         = ARRAY['integer', 'integer', 'jsonb'],
         'the two counts are integer and the page is jsonb';
  ASSERT (SELECT count(*) FROM t_cve_products_call) = 1,
         'a CVE that cves holds answers one row';
  ASSERT (SELECT count(*) FROM api.fn_cve_products('CVE-2008-0009', NULL, NULL, 20, 0)) = 0,
         'an unknown CVE answers no row';
  ASSERT (SELECT count(*) FROM api.fn_cve_products(NULL, NULL, NULL, 20, 0)) = 0,
         'a NULL id answers no row';
  ASSERT (SELECT count(*) FROM api.fn_cve_products('CVE-2008-0001', NULL, NULL, NULL, 0)) = 0,
         'a NULL row count answers no row';
  ASSERT (SELECT count(*) FROM api.fn_cve_products('CVE-2008-0001', NULL, NULL, 20, NULL)) = 0,
         'a NULL offset answers no row';
END
$$;

DO $$
BEGIN
  ASSERT (SELECT affected_product_count = 5 AND listed_product_count = 5 FROM t_cve_products_call),
         'with no filter, the count and the page hold every element';
  ASSERT (SELECT array_agg(item ->> 'vendor' || '/' || (item ->> 'product') ORDER BY ord)
            FROM t_cve_products_call, jsonb_array_elements(affected_products) WITH ORDINALITY AS t (item, ord))
         = ARRAY['acme/alpha', 'acme/beta', 'zeta/alpha', NULL, 'acme/alpha'],
         'the vulnerable elements come first, and each group sorts by vendor and product, an element with no vendor last';
  ASSERT (SELECT array_agg(item ->> 'vendor' || '/' || (item ->> 'product') || '/' || coalesce(item ->> 'version_end_excluding', '-') ORDER BY ord)
            FROM api.fn_cve_products('CVE-2008-0005', NULL, NULL, 20, 0) AS products,
                 jsonb_array_elements(products.affected_products) WITH ORDINALITY AS t (item, ord))
         = ARRAY['Bolt/eta/-', 'acme/Eta/-', 'acme/eta/B.0', 'acme/eta/a.0'],
         'the sort compares bytes, and two elements of one vendor and product sort by their text';
  ASSERT (SELECT array_agg(item ->> 'vendor' || '/' || (item ->> 'product') || '/' || coalesce(item ->> 'version_end_excluding', '-') ORDER BY ord)
            FROM api.fn_cve_products('CVE-2008-0005', NULL, NULL, 2, 1) AS products,
                 jsonb_array_elements(products.affected_products) WITH ORDINALITY AS t (item, ord))
         = ARRAY['acme/Eta/-', 'acme/eta/B.0'],
         'the row count and the offset cut the sorted elements, not the elements of the array';
  ASSERT (SELECT affected_products -> 4 FROM t_cve_products_call)
         = '{"vendor": "acme", "product": "alpha", "is_vulnerable": false, "product_source": "nvd"}'::jsonb,
         'an element whose four bounds are null leaves out all four';
  ASSERT (SELECT affected_products -> 2 FROM t_cve_products_call)
         = '{"vendor": "zeta", "product": "alpha", "is_vulnerable": true, "product_source": "nvd",
             "version_start_including": "1.0", "version_end_excluding": "2.0"}'::jsonb,
         'a bound that holds a value stays, and each null bound goes';
  ASSERT (SELECT affected_products -> 0 FROM t_cve_products_call)
         = '{"vendor": "acme", "product": "alpha", "is_vulnerable": true, "product_source": "nvd",
             "version_start_excluding": "3.0", "version_end_including": "4.0"}'::jsonb,
         'the other two bounds stay when they hold a value';
  ASSERT (SELECT affected_products -> 1 FROM t_cve_products_call)
         = '{"vendor": "acme", "product": "beta", "product_source": "cna", "default_status": null,
             "versions": [{"version": "1.0", "status": "affected"}]}'::jsonb,
         'a null default_status stays, and so do the versions of a CNA element';
  ASSERT (SELECT row(affected_product_count, listed_product_count, affected_products)::text
            FROM api.fn_cve_products('CVE-2008-0002', NULL, NULL, 20, 0))
         = row(0, 0, '[]'::jsonb)::text,
         'a CVE with no element answers two counts of 0 and an empty page';
  ASSERT (SELECT row(affected_product_count, listed_product_count, affected_products)::text
            FROM api.fn_cve_products('CVE-2008-0003', NULL, NULL, 20, 0))
         = row(0, 0, '[]'::jsonb)::text,
         'a stored value that is not an array holds no element';
  ASSERT (SELECT row(affected_product_count, affected_products)::text
            FROM api.fn_cve_products('CVE-2008-0004', NULL, NULL, 20, 0))
         = row(2, '[{"vendor": "acme", "product": "delta", "is_vulnerable": true}, 5]'::jsonb)::text,
         'an element that is not an object stays as cves holds it, and fails no call';
END
$$;

DO $$
BEGIN
  ASSERT (SELECT row(affected_product_count, listed_product_count)::text
            FROM api.fn_cve_products('CVE-2008-0001', 'acme', NULL, 20, 0))
         = row(3, 3)::text,
         'the vendor filter keeps the elements of that vendor';
  ASSERT (SELECT array_agg(item ->> 'vendor' ORDER BY ord)
            FROM api.fn_cve_products('CVE-2008-0001', NULL, 'alpha', 20, 0) AS products,
                 jsonb_array_elements(products.affected_products) WITH ORDINALITY AS t (item, ord))
         = ARRAY['acme', 'zeta', 'acme'],
         'the product filter keeps the elements of that product, whatever their vendor';
  ASSERT (SELECT row(affected_product_count, affected_products -> 0 ->> 'product')::text
            FROM api.fn_cve_products('CVE-2008-0001', 'acme', 'alpha', 20, 0))
         = row(2, 'alpha')::text,
         'the two filters keep the elements that match both';
  ASSERT (SELECT row(affected_product_count, listed_product_count, affected_products)::text
            FROM api.fn_cve_products('CVE-2008-0001', 'ACME', NULL, 20, 0))
         = row(0, 0, '[]'::jsonb)::text,
         'the filter compares the name as cves holds it, so another case matches nothing';
  ASSERT (SELECT row(affected_product_count, listed_product_count)::text
            FROM api.fn_cve_products('CVE-2008-0005', NULL, 'eta', 20, 0))
         = row(3, 3)::text,
         'the product filter compares the name as cves holds it too, so it does not keep Eta';
  ASSERT (SELECT row(affected_product_count, listed_product_count)::text
            FROM api.fn_cve_products('CVE-2008-0001', NULL, NULL, 2, 0))
         = row(5, 2)::text,
         'the page holds at most p_product_row_count elements, and the count is not cut';
  ASSERT (SELECT array_agg(item ->> 'product' ORDER BY ord)
            FROM api.fn_cve_products('CVE-2008-0001', NULL, NULL, 2, 2) AS products,
                 jsonb_array_elements(products.affected_products) WITH ORDINALITY AS t (item, ord))
         = ARRAY['alpha', 'gamma'],
         'the offset skips the elements of the pages before it';
  ASSERT (SELECT row(affected_product_count, listed_product_count, affected_products)::text
            FROM api.fn_cve_products('CVE-2008-0001', NULL, NULL, 20, 5))
         = row(5, 0, '[]'::jsonb)::text,
         'an offset past the last element answers the count and an empty page';
END
$$;

PREPARE t_cve_products_query AS SELECT * FROM api.fn_cve_products($1, $2, $3, $4, $5);
CREATE TEMP TABLE t_cve_products_answer AS EXECUTE t_cve_products_query('CVE-2008-0001', 'acme', NULL, '1', '1');
DEALLOCATE t_cve_products_query;

DO $$
BEGIN
  ASSERT (SELECT row(affected_product_count, listed_product_count, affected_products -> 0 ->> 'product')::text
            FROM t_cve_products_answer)
         = row(3, 1, 'beta')::text,
         'the query db_CVEPRODUCTS sends answers the page of its filters';
END
$$;

DO $$
BEGIN
  ASSERT (SELECT prosecdef AND provolatile = 's' AND NOT proisstrict FROM pg_proc
          WHERE oid = 'api.fn_cve_products(text, text, text, integer, integer)'::regprocedure),
         'api.fn_cve_products is SECURITY DEFINER, STABLE and not STRICT';
  ASSERT (SELECT proconfig FROM pg_proc
          WHERE oid = 'api.fn_cve_products(text, text, text, integer, integer)'::regprocedure)
         = ARRAY['search_path=pg_catalog'],
         'api.fn_cve_products sets search_path to pg_catalog';
END
$$;

DO $$
BEGIN
  ASSERT (SELECT product_count_by_vendor FROM api.fn_cve_lookup(ARRAY['CVE-2008-0005'], 30, 5, 20, 10, 20))
         = '{"acme": 3, "Bolt": 1}'::jsonb,
         'product_count_by_vendor counts elements, so two elements of one product count twice';
  ASSERT (SELECT product_count_by_vendor FROM api.fn_cve_lookup(ARRAY['CVE-2008-0006'], 30, 5, 20, 1, 20))
         = '{"Bolt": 1}'::jsonb,
         'a tie on the count goes to the vendor whose bytes sort first';
  ASSERT (SELECT row(affected_product_count, product_count_by_vendor)::text
            FROM api.fn_cve_lookup(ARRAY['CVE-2008-0003'], 30, 5, 20, 10, 20))
         = row(0, '{}'::jsonb)::text,
         'a stored value that is not an array fails no lookup, and counts no vendor';
END
$$;
ROLLBACK TO SAVEPOINT t_cve_products_rows;
