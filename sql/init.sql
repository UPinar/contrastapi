\set ON_ERROR_STOP on
BEGIN;
GRANT CREATE ON SCHEMA public TO "contrastapi-owner";
SET LOCAL ROLE "contrastapi-owner";
\ir ../schema.sql
RESET ROLE;
\ir api.sql
COMMIT;
