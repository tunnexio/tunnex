-- Restore the live-only (partial) slug uniqueness from 0002.
DROP INDEX IF EXISTS organizations_slug_key;
CREATE UNIQUE INDEX organizations_slug_key ON organizations (slug) WHERE deleted_at IS NULL;
