CREATE FUNCTION api.fn_schema_version() RETURNS integer
  LANGUAGE sql IMMUTABLE SECURITY DEFINER
  SET search_path = pg_catalog
  RETURN 79;
