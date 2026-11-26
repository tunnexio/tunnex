ALTER TABLE users DROP COLUMN IF EXISTS deactivated_by_org_id;
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_deactivation_source_check;
ALTER TABLE users DROP COLUMN IF EXISTS deactivation_source;
ALTER TABLE memberships DROP CONSTRAINT IF EXISTS memberships_access_revoked_source_check;
ALTER TABLE memberships DROP COLUMN IF EXISTS access_revoked_source;
