-- name: UpsertMembership :one
-- Idempotent on (org_id, user_id), and it SETS the role. ⛔ RBAC-0 D1: only for callers whose authority
-- is "set this person's role" — org creation, bootstrap, the deployment-administrator grant. A JOIN
-- (invite accept, SSO JIT) must use InsertMembershipIfAbsent: an upsert there let an invite or login
-- rewrite an existing member's roles, including demoting the sole owner.
INSERT INTO memberships (org_id, user_id, role)
VALUES ($1, $2, $3)
ON CONFLICT (org_id, user_id) DO UPDATE
    SET role = EXCLUDED.role
RETURNING *;

-- name: InsertMembershipIfAbsent :one
-- RBAC-0 D1: the JOIN form. Never touches an existing row (active or revoked); no row returned means the
-- person already has a membership and the caller must refuse rather than change it.
INSERT INTO memberships (org_id, user_id, role)
VALUES ($1, $2, $3)
ON CONFLICT (org_id, user_id) DO NOTHING
RETURNING *;

-- name: ListMembershipsByUser :many
-- lint:cross-org — intentionally spans orgs: a user's memberships across all
-- their organizations (used to resolve which orgs a principal belongs to).
SELECT * FROM memberships
WHERE user_id = $1 AND access_revoked_at IS NULL
ORDER BY created_at;

-- name: ListMembershipsByOrg :many
SELECT * FROM memberships
WHERE org_id = $1 AND access_revoked_at IS NULL
ORDER BY created_at;

-- name: ListOrgMembersWithUser :many
-- The org roster for the Users page: membership joined to the user record so the
-- UI has name/email/status/verified in one query. Soft-deleted users are
-- excluded (their membership row survives a soft-delete); deactivated members
-- stay on the roster (status carries that).
-- ⛔ AND IT CARRIES WHAT DEACTIVATING THIS PERSON WOULD STOP (D23). A machine credential dies with its
-- owner's deactivation — that is the whole point of the ownership binding — and until this column existed
-- nothing in the product could tell an operator that BEFORE they clicked. A routine offboarding took down
-- a GitOps pipeline and the two acts were never connected.
--
-- ⚠ COUNTED ACROSS EVERY ORGANIZATION. Since RBAC-0 deactivation is account-wide only for a person in no
-- other organization; for anyone else it is org-scoped, so this count is an UPPER bound (the dialog says
-- "up to") — over-stating the blast radius is the safe direction on the screen that exists to state it.
SELECT m.user_id, m.role, m.roles, m.created_at AS joined_at,
       u.email, u.name,
       -- RBAC-0 D3: status is PER ORGANIZATION. A membership whose access was revoked here reads as
       -- deactivated even when the account is active elsewhere; it used to read "active".
       (CASE WHEN m.access_revoked_at IS NOT NULL THEN 'deactivated' ELSE u.status END)::text AS status,
       -- Who removed access, relative to THIS org: organization | directory | other_organization | ''.
       (CASE
          WHEN m.access_revoked_at IS NOT NULL THEN
            CASE WHEN rs.source = 'member_admin' THEN 'organization' ELSE 'directory' END
          WHEN u.status = 'deactivated' THEN
            CASE
              WHEN ud.source = 'idp_sync' AND ud.org_id = m.org_id THEN 'directory'
              WHEN ud.source = 'idp_sync' THEN 'other_organization'
              WHEN ud.org_id = m.org_id THEN 'organization'
              WHEN ud.org_id IS NOT NULL THEN 'other_organization'
              ELSE ''
            END
          ELSE ''
        END)::text AS deactivated_by,
       (u.email_verified_at IS NOT NULL)::boolean AS email_verified,
       (SELECT count(*) FROM machine_credentials mc
         WHERE mc.user_id = m.user_id AND mc.revoked_at IS NULL)::bigint AS machine_credentials,
       (SELECT count(DISTINCT ap.device_id)
          FROM group_members gm
          JOIN memberships delegated_m
            ON delegated_m.org_id = gm.org_id AND delegated_m.user_id = gm.user_id
          JOIN agent_profiles ap ON ap.managing_group_id = gm.group_id
          JOIN devices d ON d.id = ap.device_id AND d.org_id = gm.org_id
         WHERE gm.user_id = m.user_id
           AND delegated_m.access_revoked_at IS NULL
           AND d.deleted_at IS NULL)::bigint AS managed_agent_delegations
FROM memberships m
JOIN users u ON u.id = m.user_id
LEFT JOIN membership_revocation_sources rs ON rs.org_id = m.org_id AND rs.user_id = m.user_id
LEFT JOIN user_deactivations ud ON ud.user_id = m.user_id
WHERE m.org_id = $1 AND u.deleted_at IS NULL
ORDER BY m.created_at;

-- name: GetMembership :one
SELECT * FROM memberships
WHERE org_id = $1 AND user_id = $2 AND access_revoked_at IS NULL;

-- name: GetMembershipIncludingRevoked :one
SELECT * FROM memberships
WHERE org_id = $1 AND user_id = $2;

-- name: ListAccessSources :many
SELECT source_type, source_key FROM membership_access_sources
WHERE org_id = $1 AND user_id = $2
ORDER BY source_type, source_key;

-- name: RevokeMembershipAccess :execrows
-- RBAC-0 D3: the source records which authority removed access, so only that authority restores it.
WITH revoked AS (
    UPDATE memberships mr SET access_revoked_at = now()
    WHERE mr.org_id = sqlc.arg(org_id) AND mr.user_id = sqlc.arg(user_id) AND mr.access_revoked_at IS NULL
    RETURNING mr.org_id AS revoked_org_id, mr.user_id AS revoked_user_id
)
INSERT INTO membership_revocation_sources (org_id, user_id, source)
SELECT revoked_org_id, revoked_user_id, sqlc.arg(source)::text FROM revoked
ON CONFLICT (org_id, user_id) DO UPDATE SET source = EXCLUDED.source, created_at = now();

-- name: RestoreMembershipAccess :execrows
-- Restores ONLY a revocation made by the named source; another authority's revocation is left alone.
WITH owned AS (
    DELETE FROM membership_revocation_sources s
    USING memberships m
    WHERE s.org_id = sqlc.arg(org_id) AND s.user_id = sqlc.arg(user_id) AND s.source = sqlc.arg(source)::text
      AND m.org_id = s.org_id AND m.user_id = s.user_id AND m.access_revoked_at IS NOT NULL
    RETURNING s.org_id, s.user_id
)
UPDATE memberships SET access_revoked_at = NULL
FROM owned WHERE memberships.org_id = owned.org_id AND memberships.user_id = owned.user_id;

-- name: GetMembershipRevocationSource :one
-- The authority that revoked this membership ('' when none is recorded). Read only while revoked.
SELECT COALESCE((SELECT source FROM membership_revocation_sources s
                 WHERE s.org_id = sqlc.arg(org_id) AND s.user_id = sqlc.arg(user_id)), '')::text AS source;

-- name: CountOtherActiveMemberships :one
-- lint:cross-org — RBAC-0 D3: does this person have access to any OTHER live organization? Decides
-- whether a deactivation may be account-wide (no) or must stay scoped to the acting org (yes).
SELECT count(*) FROM memberships m
JOIN organizations o ON o.id = m.org_id AND o.deleted_at IS NULL
WHERE m.user_id = sqlc.arg(user_id) AND m.org_id <> sqlc.arg(org_id) AND m.access_revoked_at IS NULL;

-- name: ChangeMemberRole :one
UPDATE memberships
SET role = $3
WHERE org_id = $1 AND user_id = $2
RETURNING *;

-- name: ChangeMemberRoles :one
UPDATE memberships SET roles = sqlc.arg(roles)::text[]
WHERE org_id = sqlc.arg(org_id) AND user_id = sqlc.arg(user_id)
RETURNING *;

-- name: LockMembershipOrganization :one
SELECT id FROM organizations WHERE id = $1 AND deleted_at IS NULL FOR UPDATE;

-- name: RemoveMember :execrows
DELETE FROM memberships
WHERE org_id = $1 AND user_id = $2;

-- name: CountOwners :one
-- RBAC-0 D6: ACTIVE owners only — membership not revoked, account active and not deleted. A deactivated
-- or revoked owner cannot administer the org, so it must not satisfy the last-owner guard.
SELECT count(*) FROM memberships m
JOIN users u ON u.id = m.user_id
WHERE m.org_id = $1 AND m.role = 'owner' AND m.access_revoked_at IS NULL
  AND u.status = 'active' AND u.deleted_at IS NULL;

-- name: CountOrgsWhereSoleOwner :one
-- lint:cross-org — spans a user's orgs to protect the last-owner invariant on
-- global deactivation; each row's org_id is used in the correlated subquery.
-- Same ACTIVE-owner definition as CountOwners (RBAC-0 D6).
SELECT count(*) FROM memberships m
WHERE m.user_id = $1 AND m.role = 'owner' AND m.access_revoked_at IS NULL
  AND (SELECT count(*) FROM memberships o JOIN users ou ON ou.id = o.user_id
        WHERE o.org_id = m.org_id AND o.role = 'owner' AND o.access_revoked_at IS NULL
          AND ou.status = 'active' AND ou.deleted_at IS NULL) = 1;

-- RBAC-1 Helpdesk ceiling. The roles of the person who owns a device in this organization (no row when the
-- device or the owner's active membership is gone).
-- name: GetDeviceOwnerMembershipRoles :one
SELECT m.role, m.roles FROM devices d
JOIN memberships m ON m.org_id = d.org_id AND m.user_id = d.user_id AND m.access_revoked_at IS NULL
WHERE d.org_id = $1 AND d.id = $2;

-- RBAC-1 Helpdesk ceiling for gateway-level device actions: does any device homed on this gateway belong
-- to a person holding one of the given roles?
-- name: NodeHasDeviceOwnedByRoles :one
SELECT EXISTS (
    SELECT 1 FROM devices d
    JOIN memberships m ON m.org_id = d.org_id AND m.user_id = d.user_id
    WHERE d.org_id = $1 AND d.node_id = $2 AND d.deleted_at IS NULL
      AND COALESCE(m.roles, ARRAY[m.role]) && sqlc.arg(roles)::text[]
);
