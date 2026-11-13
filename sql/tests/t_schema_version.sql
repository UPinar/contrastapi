CREATE TEMP VIEW t_schema_version_call AS SELECT api.fn_schema_version() AS schema_version;

DO $$
BEGIN
  ASSERT (SELECT array_agg(attname::text || ' ' || format_type(atttypid, atttypmod) ORDER BY attnum)
            FROM pg_attribute
           WHERE attrelid = 't_schema_version_call'::regclass AND attnum > 0)
         = ARRAY['schema_version integer'],
         'the call db.c sends answers one integer column, schema_version';
  ASSERT (SELECT count(*) FROM t_schema_version_call) = 1,
         'api.fn_schema_version() answers one row';
  ASSERT (SELECT schema_version FROM t_schema_version_call) > 0,
         'api.fn_schema_version() answers a version above 0';
END
$$;
