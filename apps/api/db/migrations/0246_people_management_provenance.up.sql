-- RBAC-0 (docs/RBAC-0-people-management-security.md D3): record WHO removed access, so reactivation can
-- reverse only its own act. Additive: two SIDE TABLES, deliberately not new columns on `users` or
-- `memberships` — those rows are read with expanded `SELECT *` by code that also runs against pinned older
-- schemas (rolling upgrades and the version-pinned integration suites), so their shape must not change.
-- No role or status is rewritten.

-- Org-scoped revocation: which authority set memberships.access_revoked_at. Meaningful only while the
-- membership is revoked.
CREATE TABLE membership_revocation_sources (
    org_id     uuid NOT NULL,
    user_id    uuid NOT NULL,
    source     text NOT NULL CHECK (source IN ('member_admin', 'idp_sync')),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, user_id),
    FOREIGN KEY (org_id, user_id) REFERENCES memberships (org_id, user_id) ON DELETE CASCADE
);
-- Directory sync was the only writer of access_revoked_at before this migration.
INSERT INTO membership_revocation_sources (org_id, user_id, source)
SELECT org_id, user_id, 'idp_sync' FROM memberships WHERE access_revoked_at IS NOT NULL
ON CONFLICT DO NOTHING;

-- Account-wide deactivation: which authority, from which organization. Meaningful only while the user
-- is deactivated.
CREATE TABLE user_deactivations (
    user_id    uuid PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    source     text NOT NULL CHECK (source IN ('member_admin', 'idp_sync')),
    org_id     uuid NULL REFERENCES organizations (id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
-- Backfill from the latest user.deactivated audit row (idp-sync is a named system actor). Users with no
-- such row get no provenance (legacy, unknown) and follow the legacy rule in the service.
INSERT INTO user_deactivations (user_id, source, org_id)
SELECT u.id, CASE WHEN latest.actor_system = 'idp-sync' THEN 'idp_sync' ELSE 'member_admin' END, latest.org_id
FROM users u
JOIN (
    SELECT DISTINCT ON (a.target_id) a.target_id, a.actor_system, a.org_id
    FROM audit_logs a
    WHERE a.action = 'user.deactivated' AND a.target_type = 'user'
    ORDER BY a.target_id, a.created_at DESC
) latest ON latest.target_id = u.id::text
WHERE u.status = 'deactivated'
ON CONFLICT DO NOTHING;
