-- qfc-server-wallet local-dev Postgres init script
--
-- Postgres' official image already creates the user/db given the
-- POSTGRES_USER / POSTGRES_PASSWORD / POSTGRES_DB env vars, so the
-- only thing left for us to do here is:
--   1. Make sure the role has CREATE on the schema (it does by default
--      on the db it owns, but stating it explicitly keeps things
--      obvious to operators).
--   2. Add any schemas / extensions the M2 P2 audit layer needs.
--
-- The actual table DDL lives in qfc-audit (sqlx migrations) so it can
-- be unit-tested by the migrations harness, not embedded here.

-- The bootstrap role is the same user the app connects as.
ALTER ROLE qfc WITH CREATEDB;

-- Useful extensions for the audit + wallet registry layer:
--   - pgcrypto: gen_random_uuid() for tests and ad-hoc queries
--   - btree_gin: indexes on JSONB filter columns (audit search)
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS btree_gin;

-- Schema namespace for app tables (qfc-audit migrations create the
-- actual tables when the app starts). Keeping it separate from
-- `public` makes it easy to drop just the app data with `DROP SCHEMA
-- qfc CASCADE` without nuking extensions.
CREATE SCHEMA IF NOT EXISTS qfc AUTHORIZATION qfc;

-- Mark this script as run for diagnostics.
DO $$ BEGIN
  RAISE NOTICE 'qfc-server-wallet postgres-init/01-create.sql complete';
END $$;
