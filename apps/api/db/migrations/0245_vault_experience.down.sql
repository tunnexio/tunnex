-- Removing the purge does not restore anything it already deleted (that was the point).
DROP TRIGGER vault_purge_personal_on_membership_revoke ON memberships;
DROP TRIGGER vault_purge_personal_on_membership_delete ON memberships;
DROP FUNCTION vault_purge_on_membership_revoke();
DROP FUNCTION vault_purge_on_membership_delete();
DROP FUNCTION vault_purge_personal_entries(uuid, uuid, text);
DROP INDEX vault_quick_requests_created;
ALTER TABLE vault_entries DROP COLUMN revision;
