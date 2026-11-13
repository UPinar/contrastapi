\set ON_ERROR_STOP on
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'contrastapi-owner') THEN
    CREATE ROLE "contrastapi-owner" NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'contrastapi-api') THEN
    CREATE ROLE "contrastapi-api" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 24;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'contrastapi-sync') THEN
    CREATE ROLE "contrastapi-sync" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 4;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'contrastapi-web') THEN
    CREATE ROLE "contrastapi-web" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 8;
  END IF;
END
$$;
ALTER ROLE "contrastapi-web" SET statement_timeout = '5s';
ALTER ROLE "contrastapi-web" SET idle_in_transaction_session_timeout = '10s';
ALTER ROLE "contrastapi-web" SET default_transaction_read_only = on;
