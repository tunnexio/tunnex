-- RBAC-0 (docs/RBAC-0-people-management-security.md D3): record WHO removed access, so reactivation
-- can reverse only its own act. Additive and nullable; no role or status is rewritten.

-- Org-scoped revocation: which authority set memberships.access_revoked_at.
ALTER TABLE memberships ADD COLUMN access_revoked_source text NULL;
ALTER TABLE memberships ADD CONSTRAINT memberships_access_revoked_source_check
    CHECK (access_revoked_source IS NULL OR access_revoked_source IN ('member_admin', 'idp_sync'));
-- Directory sync was the only writer of access_revoked_at before this migration.
UPDATE memberships SET access_revoked_source = 'idp_sync'
WHERE access_revoked_at IS NOT NULL AND access_revoked_source IS NULL;

-- Account-wide deactivation: which authority, from which organization.
ALTER TABLE users ADD COLUMN deactivation_source text NULL;
ALTER TABLE users ADD CONSTRAINT users_deactivation_source_check
    CHECK (deactivation_source IS NULL OR deactivation_source IN ('member_admin', 'idp_sync'));
ALTER TABLE users ADD COLUMN deactivated_by_org_id uuid NULL REFERENCES organizations (id) ON DELETE SET NULL;

-- Backfill from the latest user.deactivated audit row (idp-sync is a named system actor). Users with no
-- such row stay NULL (legacy, unknown provenance) and follow the legacy rule in the service.
UPDATE users u
SET deactivation_source = CASE WHEN latest.actor_system = 'idp-sync' THEN 'idp_sync' ELSE 'member_admin' END,
    deactivated_by_org_id = latest.org_id
FROM (
    SELECT DISTINCT ON (a.target_id) a.target_id, a.actor_system, a.org_id
    FROM audit_logs a
    WHERE a.action = 'user.deactivated' AND a.target_type = 'user'
    ORDER BY a.target_id, a.created_at DESC
) latest
WHERE u.status = 'deactivated' AND u.deactivation_source IS NULL AND latest.target_id = u.id::text;
