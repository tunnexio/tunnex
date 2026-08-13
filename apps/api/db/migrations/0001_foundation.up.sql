-- 0001 foundation — schema conventions every later migration inherits.
-- See db/migrations/README.md for the full rationale.
--
--   * Primary keys: UUIDv7 via uuid_generate_v7() (time-ordered, index-friendly).
--   * Timestamps:   timestamptz everywhere; created_at + updated_at on every table.
--   * Multi-tenancy: tenant-owned tables carry org_id NOT NULL and lead their
--                    composite indexes with org_id.
--
-- This migration creates no domain tables (those arrive in S1.1); it establishes
-- the shared helpers those tables rely on.

-- UUIDv7 generator. Native uuidv7() ships in PostgreSQL 18; until we require
-- that, we provide our own. Built entirely on core functions (gen_random_uuid
-- is core since PG13) so no extension is required.
--
-- Method: start from a v4 UUID (correct variant bits already set), overlay the
-- first 6 bytes with the current unix-millisecond timestamp, then set the
-- version nibble to 7. Verified to emit version=7, variant in {8,9,a,b}, and a
-- monotonic millisecond prefix.
CREATE OR REPLACE FUNCTION uuid_generate_v7()
RETURNS uuid
AS $$
  SELECT encode(
    set_bit(
      set_bit(
        overlay(
          uuid_send(gen_random_uuid())
          PLACING substring(int8send(floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint) FROM 3)
          FROM 1 FOR 6
        ),
        52, 1
      ),
      53, 1
    ),
    'hex')::uuid;
$$ LANGUAGE sql VOLATILE;

COMMENT ON FUNCTION uuid_generate_v7() IS
  'Time-ordered UUIDv7 generator (convention: use as PRIMARY KEY DEFAULT).';

-- Trigger function to maintain updated_at. Attach per table in later migrations:
--   CREATE TRIGGER set_updated_at BEFORE UPDATE ON <table>
--     FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS trigger
AS $$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION set_updated_at() IS
  'BEFORE UPDATE trigger helper: stamps updated_at = now() on every row update.';
