DROP TRIGGER IF EXISTS memberships_access_source_on_insert ON memberships;
DROP FUNCTION IF EXISTS membership_access_source_on_insert();
DROP TABLE IF EXISTS membership_access_sources;
ALTER TABLE memberships DROP COLUMN IF EXISTS access_revoked_at;
ALTER TABLE idp_sync_configs DROP COLUMN IF EXISTS delegated_admin_email;
