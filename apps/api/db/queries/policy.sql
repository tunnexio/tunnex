-- Zero Trust policy model (S7.1). Enterprise feature; model-only (no data plane).
-- All tenant tables scope by org_id (tenant-lint). Policy objects are hard-deleted
-- (FK ON DELETE CASCADE), so there is no deleted_at filter here.

-- ── user_groups (the rule SUBJECT) ──────────────────────────────────────────────
-- name: CreateUserGroup :one
INSERT INTO user_groups (org_id, name, description)
VALUES ($1, $2, $3)
RETURNING *;

-- name: GetUserGroup :one
SELECT * FROM user_groups
WHERE id = $1 AND org_id = $2;

-- name: ListUserGroupsByOrg :many
-- Membership is unique per (group_id, user_id), but keep this aggregate
-- duplicate-safe if a future bounded list enriches it with another join.
SELECT g.*, count(DISTINCT u.id)::bigint AS member_count
FROM user_groups g
LEFT JOIN group_members gm
  ON gm.org_id = g.org_id AND gm.group_id = g.id
LEFT JOIN users u
  ON u.id = gm.user_id AND u.deleted_at IS NULL
WHERE g.org_id = $1
GROUP BY g.id
ORDER BY g.name;

-- name: UpdateUserGroup :one
UPDATE user_groups
SET name = $3, description = $4
WHERE id = $1 AND org_id = $2
RETURNING *;

-- name: DeleteUserGroup :execrows
DELETE FROM user_groups
WHERE id = $1 AND org_id = $2;

-- ── group_members ───────────────────────────────────────────────────────────────
-- name: AddGroupMember :execrows
-- Returns rows-affected: 0 on ON CONFLICT (already a member) so the caller can skip
-- the audit event for a no-op re-add (idempotent, still 204).
INSERT INTO group_members (org_id, group_id, user_id)
VALUES ($1, $2, $3)
ON CONFLICT (group_id, user_id) DO NOTHING;

-- name: RemoveGroupMember :execrows
DELETE FROM group_members
WHERE org_id = $1 AND group_id = $2 AND user_id = $3;

-- name: ListGroupMembers :many
SELECT u.id, u.email, u.name, gm.created_at
FROM group_members gm
JOIN users u ON u.id = gm.user_id
WHERE gm.org_id = $1 AND gm.group_id = $2 AND u.deleted_at IS NULL
ORDER BY u.email;

-- name: ListGroupMembershipsByOrg :many
-- Compiler input: every (group, user) pair in the org.
SELECT group_id, user_id
FROM group_members
WHERE org_id = $1
ORDER BY group_id, user_id;

-- ── resources (static destinations) ─────────────────────────────────────────────
-- name: CreateResource :one
-- ⚠ `label` is a free-text OPERATOR NOTE (S15.3). It is NOT read by the compiler — CanonicalHash sees
-- cidr, protocol and the port bounds only — so it cannot desync an artifact or bump RequiredVersion.
INSERT INTO resources (org_id, name, cidr, protocol, port_low, port_high, label)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING *;

-- name: GetResource :one
SELECT * FROM resources
WHERE id = $1 AND org_id = $2;

-- name: ListResourcesByOrg :many
SELECT * FROM resources
WHERE org_id = $1
ORDER BY name;

-- name: UpdateResource :one
UPDATE resources
SET name = $3, cidr = $4, protocol = $5, port_low = $6, port_high = $7, label = $8
WHERE id = $1 AND org_id = $2
RETURNING *;

-- name: DeleteResource :execrows
DELETE FROM resources
WHERE id = $1 AND org_id = $2;

-- ── policy_rules (allow grants) ─────────────────────────────────────────────────
-- name: GetFQDNResourceForPolicy :one
-- A policy destination may only name a resource owned by this organization.
SELECT id FROM fqdn_resources
WHERE id = $1 AND org_id = $2;

-- name: CreatePolicyRule :one
-- S7.5.4: src_kind ∈ {group,user}; S8.2: +site; S8.7: +cidr (exactly one of src_group_id/src_user_id/
-- src_site_id/src_cidr, CHECK-enforced). expires_at NULL = permanent, set = a temporary grant. S8.1: dst_kind
-- ∈ {resource,group,site}; S10.3: +k8s_service (exactly one of dst_resource_id/dst_group_id/dst_site_id/
-- dst_k8s_service_id, CHECK-enforced).
INSERT INTO policy_rules (org_id, src_kind, src_group_id, src_user_id, src_site_id, src_cidr, src_device_id, dst_kind, dst_resource_id, dst_group_id, dst_site_id, dst_k8s_service_id, dst_fqdn_resource_id, expires_at, managed_by_machine)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
RETURNING *;

-- name: CreateAgentJITPolicyRule :one
-- F10's approval path must remain executable against the historical 0098
-- schema. It deliberately names only the agent-access identity and destination
-- columns that existed before 0113; JIT does not support FQDN destinations or
-- machine ownership. Returning only the immutable rule ID prevents a later
-- policy_rules projection from making an old-schema approval depend on new
-- columns.
INSERT INTO policy_rules (org_id, src_kind, src_device_id, dst_kind, dst_resource_id, dst_group_id, dst_site_id, dst_k8s_service_id, expires_at)
VALUES ($1, 'agent', $2, $3, $4, $5, $6, $7, $8)
RETURNING id;

-- name: ListPolicyRulesByOrg :many
-- Admin LIST — every rule incl. expired ones (the UI shows a lapsed grant distinctly).
-- 0113 added dst_fqdn_resource_id.  This LIST is also used by the historical
-- 0109 agent-template route contract, so referencing the physical column
-- directly would make an otherwise valid legacy policy inventory fail.  JSONB
-- row extraction returns NULL when the additive key is absent, while retaining
-- the current FQDN destination when it exists.
SELECT p.id, p.org_id, p.src_group_id, p.dst_kind, p.dst_resource_id,
       p.dst_group_id, p.created_at, p.src_kind, p.src_user_id, p.expires_at,
       p.dst_site_id, p.src_site_id, p.src_cidr, p.disabled,
       p.dst_k8s_service_id, p.managed_by_machine, p.src_device_id,
       p.dst_k8s_cluster_id, p.src_agent_group_id,
       NULLIF(to_jsonb(p) ->> 'dst_fqdn_resource_id', '')::uuid AS dst_fqdn_resource_id
FROM policy_rules p
WHERE p.org_id = $1
ORDER BY p.created_at;

-- name: ListActivePolicyRulesForOrg :many
-- COMPILER INPUT — excludes EXPIRED temporary grants (the expiry correctness backstop:
-- an expired rule stops compiling on the next recompile REGARDLESS of the sweeper). The
-- pure compiler stays clockless; this query applies now() at snapshot-build time.
-- Keep the compiler's ordinary policy projection readable on schema 0109 as
-- well. The additive FQDN destination is extracted only when present; the
-- FQDN-aware compiler later fail-closes unless its full current contract is
-- available and enabled.
SELECT p.id, p.org_id, p.src_group_id, p.dst_kind, p.dst_resource_id,
       p.dst_group_id, p.created_at, p.src_kind, p.src_user_id, p.expires_at,
       p.dst_site_id, p.src_site_id, p.src_cidr, p.disabled,
       p.dst_k8s_service_id, p.managed_by_machine, p.src_device_id,
       p.dst_k8s_cluster_id, p.src_agent_group_id,
       NULLIF(to_jsonb(p) ->> 'dst_fqdn_resource_id', '')::uuid AS dst_fqdn_resource_id
FROM policy_rules p
WHERE p.org_id = $1 AND (p.expires_at IS NULL OR p.expires_at > now())
ORDER BY p.created_at, p.id;

-- name: ListApprovedK8sClusterScopeExpansions :many
-- S20.4 compiler input. One row lowers an active scope rule to one ordinary
-- exact k8s_service destination. The selected report is the latest eligible
-- snapshot for the exact current connector generation; an older still-fresh
-- report must not retain a Service omitted by a newer snapshot. Every
-- approval identity is rejoined to the current UID attribution and exact
-- protocol/port child. Missing opt-in, stale inventory, moved ownership,
-- malformed over-limit state, or an identity mismatch therefore yields zero
-- rows rather than a wildcard or a guessed sibling port.
WITH eligible_reports AS (
    SELECT DISTINCT ON (report.org_id, report.cluster_id)
           report.id, report.org_id, report.site_id, report.cluster_id,
           report.connector_node_id, report.replay_state_id,
           report.replay_sequence
    FROM k8s_service_inventory_reports report
    JOIN k8s_service_uid_observation_replay_states replay
      ON replay.id=report.replay_state_id AND replay.org_id=report.org_id
     AND replay.site_id=report.site_id AND replay.cluster_id=report.cluster_id
     AND replay.connector_node_id=report.connector_node_id
     AND replay.sequence=report.replay_sequence
    JOIN k8s_clusters cluster
      ON cluster.id=report.cluster_id AND cluster.org_id=report.org_id
     AND cluster.site_id=report.site_id
    JOIN nodes reporter
      ON reporter.id=report.connector_node_id AND reporter.org_id=report.org_id
     AND reporter.site_id=report.site_id AND reporter.status='active'
     AND reporter.revoked_at IS NULL
    WHERE report.org_id=$1 AND report.fresh_until>now()
      AND (
        (cluster.connector_pool_id IS NULL
         AND cluster.connector_node_id=report.connector_node_id
         AND report.promotion_generation=0)
        OR
        (cluster.connector_node_id IS NULL AND EXISTS (
            SELECT 1
            FROM k8s_connector_pools pool
            JOIN k8s_connector_pool_members member
              ON member.pool_id=pool.id AND member.org_id=pool.org_id
             AND member.site_id=pool.site_id AND member.node_id=pool.active_node_id
            WHERE pool.id=cluster.connector_pool_id
              AND pool.org_id=cluster.org_id AND pool.site_id=cluster.site_id
              AND pool.cluster_id=cluster.id
              AND pool.active_node_id=report.connector_node_id
              AND pool.generation=report.promotion_generation
              AND pool.generation>0
        ))
      )
    ORDER BY report.org_id,report.cluster_id,report.replay_sequence DESC,
             report.received_at DESC,report.id DESC
)
SELECT DISTINCT rule.id AS policy_rule_id, child.id AS service_child_id
FROM policy_rules rule
JOIN k8s_cluster_scope_grants scope
  ON scope.rule_id=rule.id AND scope.org_id=rule.org_id
 AND scope.cluster_id=rule.dst_k8s_cluster_id AND scope.active
JOIN k8s_cluster_scope_settings setting
  ON setting.org_id=scope.org_id AND setting.enabled
JOIN k8s_cluster_scope_memberships membership
  ON membership.rule_id=scope.rule_id AND membership.org_id=scope.org_id
 AND membership.cluster_id=scope.cluster_id AND membership.status='approved'
JOIN k8s_services child
  ON child.id=membership.service_child_id AND child.org_id=membership.org_id
 AND child.cluster_id=membership.cluster_id AND child.deleted_at IS NULL
 AND child.namespace=membership.namespace AND child.protocol=membership.protocol
 AND child.port_low=membership.port_low AND child.port_high=membership.port_high
JOIN k8s_service_identities identity
  ON identity.id=child.identity_id AND identity.org_id=child.org_id
 AND identity.cluster_id=child.cluster_id AND identity.namespace=child.namespace
 AND identity.name=child.name AND identity.deleted_at IS NULL
JOIN eligible_reports report
  ON report.org_id=scope.org_id AND report.cluster_id=scope.cluster_id
JOIN k8s_service_inventory_items inventory
  ON inventory.report_id=report.id AND inventory.org_id=report.org_id
 AND inventory.cluster_id=report.cluster_id
 AND inventory.namespace=membership.namespace AND inventory.service=identity.name
 AND inventory.service_uid=membership.service_uid
JOIN k8s_service_inventory_ports inventory_port
  ON inventory_port.report_id=inventory.report_id
 AND inventory_port.inventory_ref=inventory.inventory_ref
 AND inventory_port.protocol=membership.protocol
 AND inventory_port.service_port=membership.port_low
JOIN k8s_service_uid_observation_ledgers ledger
  ON ledger.org_id=scope.org_id AND ledger.cluster_id=scope.cluster_id
JOIN k8s_service_uid_observation_current current_uid
  ON current_uid.ledger_id=ledger.id AND current_uid.org_id=ledger.org_id
 AND current_uid.namespace=membership.namespace AND current_uid.service=identity.name
 AND current_uid.uid=membership.service_uid AND current_uid.state='live'
 AND current_uid.replay_sequence=report.replay_sequence
JOIN k8s_service_uid_observation_current_attributions attribution
  ON attribution.ledger_id=current_uid.ledger_id
 AND attribution.org_id=current_uid.org_id
 AND attribution.namespace=current_uid.namespace
 AND attribution.service=current_uid.service
 AND attribution.replay_state_id=report.replay_state_id
 AND attribution.replay_sequence=report.replay_sequence
WHERE rule.org_id=$1 AND rule.dst_kind='k8s_cluster_scope'
  AND NOT rule.disabled AND (rule.expires_at IS NULL OR rule.expires_at>now())
  AND (SELECT count(*) FROM k8s_cluster_scope_memberships bounded
       WHERE bounded.rule_id=scope.rule_id)<=500
  AND (SELECT count(*) FROM k8s_cluster_scope_grants active_scope
       WHERE active_scope.org_id=scope.org_id
         AND active_scope.cluster_id=scope.cluster_id
         AND active_scope.active)<=20
ORDER BY rule.id,child.id;

-- name: DeletePolicyRule :execrows
DELETE FROM policy_rules
WHERE id = $1 AND org_id = $2;

-- name: SetPolicyRuleEnabled :one
-- F3: toggle a rule's disabled flag. RETURNING * so the API echoes the new state; the caller (mutate)
-- recompiles + pushes — disabling changes the compiled artifact's CONTENT (in-hash, ordinary push).
UPDATE policy_rules SET disabled = $3
WHERE id = $1 AND org_id = $2
RETURNING *;

-- name: ExtendPolicyRule :one
-- S7.5.4: move a temporary grant's window IN PLACE (never delete+recreate — that would
-- churn the /32 out+back and cause a spurious push). The `expires_at > now()` predicate
-- is the LAPSE GUARD: a grant that has already expired matches 0 rows, so extend and the
-- expiry sweeper compose deterministically on the row lock — a grant lapsing mid-extend
-- resolves to extended-OR-(0 rows -> 409 grant_lapsed), never torn. Only a TEMPORARY
-- (expires_at NOT NULL), still-LIVE grant can be extended.
UPDATE policy_rules
SET expires_at = sqlc.arg(new_expires_at)
WHERE id = $1 AND org_id = $2 AND expires_at IS NOT NULL AND expires_at > now()
RETURNING *;

-- name: DeleteExpiredGrants :many
-- The expiry sweeper (S7.5.4 story-end AMENDMENT — delete-on-sweep, replaced linger). A
-- lapsed temporary grant is DELETED (not lingered), returning id+org for the same-tx
-- grant_expired audit + the org-wide push. STATELESS — no window/`last` cursor: every
-- currently-expired grant is deleted each tick, so a failed or interrupted (downtime) tick
-- simply leaves rows for the NEXT tick to delete+audit (closes the window-skip + downtime-
-- audit-gap by construction). Composes with ExtendPolicyRule on the row lock: a grant an
-- extend rescued (expires_at moved to the future) no longer matches expires_at <= now().
DELETE FROM policy_rules
WHERE expires_at IS NOT NULL AND expires_at <= now()
  AND NOT EXISTS (
      SELECT 1 FROM agent_access_requests ar
      WHERE ar.org_id=policy_rules.org_id
        AND ar.policy_rule_id=policy_rules.id
        AND ar.state='approved'
  )
RETURNING id, org_id;

-- ── compiler inputs ─────────────────────────────────────────────────────────────
-- name: ListActiveDevicesForOrg :many
-- Every active device whose owner is an active, CURRENT org member, org-wide (all
-- nodes) — the compiler resolves group destinations to these devices' /32s and keys
-- allows by src /32. The memberships join is load-bearing: a removed member's device
-- must not participate in policy (as a source OR a destination) even if the device
-- itself was never revoked. NOT health_blocked (S7.5.3): a health-blocked device's
-- /32 leaves the compiled allow-sets (source AND destination) the same way.
SELECT d.id, d.user_id, d.node_id, d.assigned_ip, d.kind,
       ars.applied_revision AS agent_config_revision
FROM devices d
JOIN users u ON u.id = d.user_id
JOIN memberships mem ON mem.org_id = d.org_id AND mem.user_id = d.user_id
LEFT JOIN agent_runtime_state ars ON ars.device_id = d.id AND d.kind = 'agent'
WHERE d.org_id = $1
  AND d.status = 'active' AND NOT d.health_blocked AND d.deleted_at IS NULL
  AND u.status = 'active' AND u.deleted_at IS NULL
  AND d.assigned_ip IS NOT NULL AND d.assigned_ip <> ''
ORDER BY d.assigned_ip;

-- ── org enforcement mode ────────────────────────────────────────────────────────
-- name: SetOrgZeroTrustMode :one
UPDATE organizations
SET zero_trust_mode = $2
WHERE id = $1 AND deleted_at IS NULL
RETURNING *;

-- name: GetPolicyRuleForUpdate :one
-- Row-locking read (S7.5.4): ExtendGrant reads the CURRENT window (for the old->new audit +
-- disambiguation) under FOR UPDATE, so the expiry sweeper's DELETE can't interleave between
-- the read and the UPDATE — extend and sweep serialize on this lock (extended-or-terminal,
-- never torn, and old_expires_at is the true pre-update value).
SELECT * FROM policy_rules WHERE id = $1 AND org_id = $2 FOR UPDATE;

-- name: GetPolicyRuleForOrg :one
-- Resolve one rule (org-scoped) — S7.5.1 ingest enriches an allow event's kernel-stamped
-- rule_id into the grant's destination (resource/group) it named, captured AT EVENT TIME so
-- it survives a later rule delete. Returns no rows if the rule was already deleted.
SELECT * FROM policy_rules WHERE id = $1 AND org_id = $2;
