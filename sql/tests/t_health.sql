CREATE TEMP VIEW t_health_call AS SELECT * FROM api.fn_health();

DO $$
BEGIN
  ASSERT (SELECT array_agg(attname::text ORDER BY attnum) FROM pg_attribute
          WHERE attrelid = 't_health_call'::regclass AND attnum > 0)
         = ARRAY['cve_count', 'nvd_last_cve_id', 'nvd_last_published_time', 'kev_count',
                 'kev_last_cve_id', 'kev_last_date_added', 'cwe_count', 'cwe_last_id',
                 'cwe_last_updated_at'],
         'api.fn_health answers the nine columns db_HEALTH reads, in its order';
  ASSERT (SELECT array_agg(format_type(atttypid, atttypmod) ORDER BY attnum) FROM pg_attribute
          WHERE attrelid = 't_health_call'::regclass AND attnum > 0)
         = ARRAY['bigint', 'text', 'date', 'bigint', 'text', 'text', 'bigint', 'text',
                 'timestamp with time zone'],
         'the counts are bigint, and each newest-row column keeps the type of its table column';
END
$$;

SAVEPOINT t_health_tables;
TRUNCATE cves, kev_details, cwes, cve_products, epss_history, metasploit_modules CASCADE;

DO $$
BEGIN
  ASSERT (SELECT count(*) FROM api.fn_health()) = 1,
         'empty tables still answer one row';
  ASSERT (SELECT cve_count = 0 AND kev_count = 0 AND cwe_count = 0 FROM api.fn_health()),
         'empty tables answer counts of 0';
  ASSERT (SELECT nvd_last_cve_id IS NULL AND nvd_last_published_time IS NULL
             AND kev_last_cve_id IS NULL AND kev_last_date_added IS NULL
             AND cwe_last_id IS NULL AND cwe_last_updated_at IS NULL FROM api.fn_health()),
         'an empty table answers NULL for its newest row';
END
$$;

INSERT INTO cves (cve_id, published_time, kev_date_added) VALUES
  ('CVE-2001-0041', '2099-01-02', '2099-02-02'),
  ('CVE-2001-0042', '2099-01-02', '2099-02-02'),
  ('CVE-2001-0043', '2099-01-01', '2099-02-01'),
  ('CVE-2001-0044', '2099-01-01', '2099-02-04'),
  ('CVE-2001-0045', '2098-01-01', '');
INSERT INTO kev_details (cve_id) VALUES
  ('CVE-2001-0041'), ('CVE-2001-0042'), ('CVE-2001-0043'), ('CVE-2001-0045');
INSERT INTO cwes (cwe_id, updated_at) VALUES
  ('CWE-2041', '2099-01-01 00:00:00+00'),
  ('CWE-2042', '2099-01-01 00:00:00+00'),
  ('CWE-2043', '2098-01-01 00:00:00+00');

DO $$
BEGIN
  ASSERT (SELECT cve_count = 5 AND kev_count = 4 AND cwe_count = 3 FROM api.fn_health()),
         'each count counts the rows of its table';
  ASSERT (SELECT nvd_last_cve_id = 'CVE-2001-0042' AND nvd_last_published_time = '2099-01-02'
            FROM api.fn_health()),
         'the newest CVE has the latest published_time, and the larger id wins a tie';
  ASSERT (SELECT kev_last_cve_id = 'CVE-2001-0042' AND kev_last_date_added = '2099-02-02'
            FROM api.fn_health()),
         'the newest KEV entry has the latest kev_date_added, and the larger id wins a tie';
  ASSERT (SELECT cwe_last_id = 'CWE-2042' AND cwe_last_updated_at = '2099-01-01 00:00:00+00'
            FROM api.fn_health()),
         'the newest CWE has the latest updated_at, and the larger id wins a tie';
END
$$;

DELETE FROM kev_details WHERE cve_id <> 'CVE-2001-0045';

DO $$
BEGIN
  ASSERT (SELECT kev_count = 1 AND kev_last_cve_id IS NULL AND kev_last_date_added IS NULL
            FROM api.fn_health()),
         'a KEV entry with no kev_date_added answers NULL for the newest KEV row';
END
$$;

INSERT INTO cwes (cwe_id, updated_at) VALUES ('CWE-2040', NULL);

DO $$
BEGIN
  ASSERT (SELECT cwe_last_id = 'CWE-2040' AND cwe_last_updated_at IS NULL FROM api.fn_health()),
         'a CWE with no updated_at counts as the newest CWE';
END
$$;

ROLLBACK TO SAVEPOINT t_health_tables;

PREPARE t_health_query AS SELECT * FROM api.fn_health();
CREATE TEMP TABLE t_health_answer AS EXECUTE t_health_query;
DEALLOCATE t_health_query;

DO $$
BEGIN
  ASSERT (SELECT count(*) FROM t_health_answer) = 1,
         'the query db_HEALTH sends answers one row';
  ASSERT (SELECT prosecdef AND provolatile = 's' FROM pg_proc
          WHERE oid = 'api.fn_health()'::regprocedure),
         'api.fn_health is SECURITY DEFINER and STABLE';
  ASSERT (SELECT proconfig FROM pg_proc WHERE oid = 'api.fn_health()'::regprocedure)
         = ARRAY['search_path=pg_catalog'],
         'api.fn_health sets search_path to pg_catalog';
END
$$;
