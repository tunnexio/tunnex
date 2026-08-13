-- name: CreateOrganization :one
INSERT INTO organizations (name, slug)
VALUES ($1, $2)
RETURNING *;

-- name: GetOrganizationByID :one
SELECT * FROM organizations
WHERE id = $1 AND deleted_at IS NULL;

-- name: GetOrganizationBySlug :one
SELECT * FROM organizations
WHERE slug = $1 AND deleted_at IS NULL;

-- name: ListOrganizations :many
-- Admin/system listing of all orgs; user-facing listing uses
-- ListOrganizationsForUser (membership-scoped).
SELECT * FROM organizations
WHERE deleted_at IS NULL
ORDER BY created_at;

-- name: ListOrganizationsForUser :many
SELECT o.* FROM organizations o
JOIN memberships m ON m.org_id = o.id
WHERE m.user_id = $1 AND o.deleted_at IS NULL
ORDER BY o.created_at;

-- name: CountOrganizations :one
SELECT count(*) FROM organizations
WHERE deleted_at IS NULL;

-- name: UpdateOrganizationName :one
-- Slug is immutable after creation (S1.2); only name is updatable here.
UPDATE organizations
SET name = $2
WHERE id = $1 AND deleted_at IS NULL
RETURNING *;

-- name: SoftDeleteOrganization :execrows
UPDATE organizations
SET deleted_at = now()
WHERE id = $1 AND deleted_at IS NULL;

-- name: UpsertOrganization :one
-- Used by the seed with a fixed id; idempotent. Also clears deleted_at so
-- re-seeding restores a previously soft-deleted demo org to a clean live state.
INSERT INTO organizations (id, name, slug)
VALUES ($1, $2, $3)
ON CONFLICT (id) DO UPDATE
    SET name = EXCLUDED.name, slug = EXCLUDED.slug, deleted_at = NULL
RETURNING *;

-- name: UpdateOrgPoolCidr :one
-- Resize the org tunnel pool. The service refuses a shrink that would orphan
-- live allocations (checked in Go before calling this); this just persists it.
UPDATE organizations
SET pool_cidr = $2
WHERE id = $1 AND deleted_at IS NULL
RETURNING *;

-- name: CountMembersByOrg :one
-- Org roster size. Joins users to exclude soft-deleted accounts (whose
-- membership row survives a soft-delete); deactivated members are still on the
-- roster, so they are intentionally counted.
SELECT count(*) FROM memberships m
JOIN users u ON u.id = m.user_id
WHERE m.org_id = $1 AND u.deleted_at IS NULL;

-- name: CountActiveDevicesByOrg :one
SELECT count(*) FROM devices WHERE org_id = $1 AND status = 'active' AND deleted_at IS NULL;

-- name: CountActiveNodesByOrg :one
SELECT count(*) FROM nodes WHERE org_id = $1 AND status = 'active';

-- name: CountOnlineDevicesByOrg :one
-- "Seen recently": last handshake within the window ($2 = now - OnlineWindow),
-- an S3.6-style online approximation. The boundary is inclusive (>=) to match
-- deviceOnline's `time.Since(h) <= threshold`. Requires an ACTIVE owner too: a
-- deactivated user's peers are offboarded from the data plane (they fall out of
-- the node's desired state) even though the device row stays 'active', so
-- counting them as "online" would be dishonest.
SELECT count(*) FROM devices d
JOIN device_status ds ON ds.device_id = d.id
JOIN users u ON u.id = d.user_id
WHERE d.org_id = $1 AND d.status = 'active' AND d.deleted_at IS NULL
  AND u.status = 'active' AND u.deleted_at IS NULL
  AND ds.last_handshake_at >= $2;

-- name: SetOrgOVPNEnabled :one
-- D-S9.5-OPTIN org opt-in toggle (the admin flip is 4d; the column + gate land in 4b). Flipping OFF
-- is a full sweep at the agent tier (server stopped, tun leaves, CCD swept) — issued client certs
-- SURVIVE (disable is not revocation).
UPDATE organizations SET ovpn_enabled = $2, updated_at = now()
WHERE id = $1 AND deleted_at IS NULL
RETURNING *;

-- name: ListOVPNEnabledOrgs :many
-- S9.1 Slice 5: orgs with OpenVPN enabled — the scheduled CRL refresh regenerates each org's CRL well
-- inside CRLValidity so no CRL ever EXPIRES (an expired CRL can fail-OPEN, silently un-revoking a fleet).
SELECT id FROM organizations WHERE ovpn_enabled = true AND deleted_at IS NULL;

-- name: CountOrganizationsEver :one
-- lint:allow-deleted
-- ⛔ INCLUDES SOFT-DELETED ROWS, DELIBERATELY, AND THAT IS THE WHOLE POINT.
--
-- This answers "has this deployment ever been set up", which is a DIFFERENT question from
-- CountOrganizations' "how many exist now". The bootstrap window — the one moment a stranger may create
-- the first organization — must key on the former. Keyed on the latter, deleting every organization
-- REOPENS setup, and the next person to reach the URL becomes owner of the deployment.
SELECT count(*) FROM organizations;

-- name: CountOrgResources :one
-- ⛔ WHAT MUST BE GONE BEFORE AN ORGANIZATION MAY BE DELETED (S12.8).
--
-- Deleting an org is a SOFT delete — the row gets `deleted_at` and nothing else happens. So every gateway,
-- device, site, cluster and machine credential it owned keeps existing, keeps its address pool slot, and in
-- the gateway's case KEEPS CARRYING TRAFFIC on a customer's server, now belonging to an organization no
-- screen will ever show again. That is not a deletion, it is an abandonment.
--
-- ⚠ ONE QUERY, NOT FIVE ROUND TRIPS: the operator is told everything blocking them at once. A preflight
-- that reveals one blocker per attempt is a guessing game with a destructive verb at the end of it.
--
-- ⚠ LIVE ROWS ONLY, matching what each table means by gone: nodes/machine credentials use `revoked_at`,
-- devices use `deleted_at`, sites and clusters have neither and are counted whole.
SELECT
  (SELECT count(*) FROM nodes n WHERE n.org_id = $1 AND n.revoked_at IS NULL)::bigint AS gateways,
  (SELECT count(*) FROM devices d WHERE d.org_id = $1 AND d.deleted_at IS NULL)::bigint AS devices,
  (SELECT count(*) FROM sites s WHERE s.org_id = $1)::bigint AS sites,
  (SELECT count(*) FROM k8s_clusters k WHERE k.org_id = $1)::bigint AS clusters,
  (SELECT count(*) FROM machine_credentials m WHERE m.org_id = $1 AND m.revoked_at IS NULL)::bigint AS machine_credentials;
