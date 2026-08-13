-- S7.5.2 IdP-group sync. Enterprise. All tenant-scoped by org_id.
-- The reconciler reads the desired membership from a DirectoryProvider (Graph/etc.) and drives
-- these to converge group_members(origin='idp_sync') — NEVER touching manual rows (disjoint by D1).

-- ── sync configs (per org, per provider) ─────────────────────────────────────────
-- name: GetIdpSyncConfig :one
SELECT * FROM idp_sync_configs
WHERE org_id = $1 AND provider = $2;

-- name: ListEnabledIdpSyncConfigs :many
-- The poller's work-list: every org/provider with sync turned on. Deliberately CROSS-ORG — the
-- background poller iterates all tenants; each config is reconciled org-scoped downstream.
-- lint:cross-org
SELECT * FROM idp_sync_configs
WHERE enabled = true
ORDER BY org_id, provider;

-- name: RecordIdpSyncResult :exec
-- One stamp for all three poll outcomes (the two-tier health, D2):
--   success  → ok=true,  advance_clock=true  (last_sync_at = now; error cleared)
--   transient→ ok=false, advance_clock=false (last_sync_at FROZEN at the last good sync — the
--              staleness the escalation tier measures; a Graph outage must NOT reset that clock)
--   gone     → ok=false, advance_clock=true  (fetch itself succeeded, so data is fresh: immediate
--              tier only, never escalates — a stable known-bad mapping, not a worsening outage)
-- advance_clock also drives whether last_sync_error is cleared vs set.
UPDATE idp_sync_configs
SET last_sync_ok    = $3,
    last_sync_error = $4,
    last_sync_at    = CASE WHEN $5::boolean THEN $6 ELSE last_sync_at END,
    updated_at      = $6
WHERE org_id = $1 AND provider = $2;

-- name: UpsertIdpSyncConfig :one
-- Connect / update a provider credential. The secret is pre-sealed (AES-GCM) by the caller;
-- plaintext never reaches SQL. On re-set, credentials update but the sync-health columns are
-- left intact (a credential rotation shouldn't fake a green health).
INSERT INTO idp_sync_configs (org_id, provider, client_id, secret_sealed, tenant_id, delegated_admin_email, enabled)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (org_id, provider) DO UPDATE
    SET client_id = EXCLUDED.client_id,
        secret_sealed = EXCLUDED.secret_sealed,
        tenant_id = EXCLUDED.tenant_id,
        delegated_admin_email = EXCLUDED.delegated_admin_email,
        enabled = EXCLUDED.enabled,
        updated_at = now()
RETURNING *;

-- ── group mapping (create / bind / unbind) ───────────────────────────────────────
-- name: CreateIdpSyncGroup :one
-- Create a fresh Tunnex group already bound to an IdP group (origin='idp_sync').
INSERT INTO user_groups (org_id, name, description, origin, idp_provider, idp_group_id)
VALUES ($1, $2, '', 'idp_sync', $3, $4)
RETURNING *;

-- name: BindGroupToIdp :one
-- Flip an EXISTING manual group to idp_sync. The WHERE origin='manual' clause makes a re-bind of
-- an already-synced group a no-row (the app layer maps that + the not-empty check to a 409). The
-- disjointness (D1) and the not-empty rule are enforced above this; this only flips a clean group.
UPDATE user_groups
SET origin = 'idp_sync', idp_provider = $3, idp_group_id = $4, updated_at = now()
WHERE id = $1 AND org_id = $2 AND origin = 'manual'
RETURNING *;

-- name: UnbindIdpGroup :one
-- Revert an idp_sync group to a plain (empty) manual group. Members are cleared separately.
UPDATE user_groups
SET origin = 'manual', idp_provider = NULL, idp_group_id = NULL, updated_at = now()
WHERE id = $1 AND org_id = $2 AND origin = 'idp_sync'
RETURNING *;

-- name: CountGroupMembers :one
-- Any origin — the refuse-unless-empty guard (D1) must see a hand-added member too.
SELECT count(*) FROM group_members WHERE org_id = $1 AND group_id = $2;

-- name: DeleteGroupMembersByGroup :execrows
-- Clear a group's membership (used on un-map, after the origin flip back to manual).
DELETE FROM group_members WHERE org_id = $1 AND group_id = $2;

-- ── idp_sync groups (the mappings to reconcile) ──────────────────────────────────
-- name: ListIdpSyncGroups :many
-- Every Tunnex group bound to an IdP group for this org+provider — the units the reconciler
-- walks. origin/shape is schema-guaranteed (0026), so idp_provider/idp_group_id are non-null.
SELECT id, idp_group_id
FROM user_groups
WHERE org_id = $1 AND origin = 'idp_sync' AND idp_provider = $2
ORDER BY id;

-- ── idp-origin membership (the reconcile target) ─────────────────────────────────
-- name: ListIdpGroupMembers :many
-- Current idp-origin members of one group (user id + recorded directory external id). Filtered to
-- origin='idp_sync' so a hand-added row could never appear here and get computed into a removal
-- (belt over disjoint). The external id lets a later removal resolve delete-vs-moved (D3 sweep).
SELECT user_id, idp_external_id
FROM group_members
WHERE org_id = $1 AND group_id = $2 AND origin = 'idp_sync'
ORDER BY user_id;

-- name: AddIdpGroupMember :execrows
-- Idempotent add of a synced member, recording the directory external id. Explicit origin='idp_sync'.
-- Returns rows-affected: 0 on conflict = already present → the caller reports didChange=false and
-- skips BOTH the audit and the org-wide re-push.
INSERT INTO group_members (org_id, group_id, user_id, origin, idp_external_id)
VALUES ($1, $2, $3, 'idp_sync', $4)
ON CONFLICT (group_id, user_id) DO NOTHING;

-- name: AddIdpAccessSource :exec
INSERT INTO membership_access_sources (org_id, user_id, source_type, source_key)
VALUES ($1, $2, 'idp_sync', $3)
ON CONFLICT DO NOTHING;

-- name: RemoveIdpAccessSource :exec
DELETE FROM membership_access_sources
WHERE org_id = $1 AND user_id = $2 AND source_type = 'idp_sync' AND source_key = $3;

-- name: CountAccessSources :one
SELECT count(*) FROM membership_access_sources WHERE org_id = $1 AND user_id = $2;

-- name: RestoreMembershipAfterIdpGrant :exec
UPDATE memberships SET access_revoked_at = NULL WHERE org_id = $1 AND user_id = $2;

-- name: RemoveIdpGroupMember :execrows
-- Remove a synced member — scoped to origin='idp_sync' so the reconcile can NEVER delete a
-- manual membership even if one somehow shared the (group,user) key.
DELETE FROM group_members
WHERE org_id = $1 AND group_id = $2 AND user_id = $3 AND origin = 'idp_sync';

-- ── directory email → Tunnex org user ────────────────────────────────────────────
-- name: GetOrgUserByEmail :one
-- Resolve a directory member's email to a Tunnex user that BELONGS to this org (membership
-- join). A directory member with no matching org user is skipped by the reconciler (sync grants
-- access to existing users; it does not JIT-provision — that's S2.5). Case-insensitive: the
-- provider already lower-cases; users.email is stored lower-cased.
SELECT u.id, u.status
FROM users u
JOIN memberships m ON m.user_id = u.id AND m.org_id = $1
WHERE u.email = $2 AND u.deleted_at IS NULL;
