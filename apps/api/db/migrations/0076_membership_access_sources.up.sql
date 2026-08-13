-- Org-scoped access provenance for directory-sync deprovisioning.
ALTER TABLE memberships ADD COLUMN access_revoked_at timestamptz;
ALTER TABLE idp_sync_configs ADD COLUMN delegated_admin_email text;
CREATE TABLE membership_access_sources (
    org_id uuid NOT NULL,
    user_id uuid NOT NULL,
    source_type text NOT NULL CHECK (source_type IN ('manual', 'idp_sync')),
    source_key text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, user_id, source_type, source_key),
    FOREIGN KEY (org_id, user_id) REFERENCES memberships(org_id, user_id) ON DELETE CASCADE
);
CREATE INDEX membership_access_sources_lookup_idx ON membership_access_sources (org_id, user_id);
INSERT INTO membership_access_sources (org_id, user_id, source_type, source_key)
SELECT org_id, user_id, 'manual', 'legacy' FROM memberships;
CREATE OR REPLACE FUNCTION membership_access_source_on_insert() RETURNS trigger AS $$
BEGIN
  INSERT INTO membership_access_sources (org_id, user_id, source_type, source_key)
  VALUES (NEW.org_id, NEW.user_id, 'manual', 'legacy') ON CONFLICT DO NOTHING;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER memberships_access_source_on_insert
AFTER INSERT OR UPDATE OF role ON memberships
FOR EACH ROW EXECUTE FUNCTION membership_access_source_on_insert();
