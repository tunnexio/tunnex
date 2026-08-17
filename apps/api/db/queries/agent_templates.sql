-- name: ListActiveAgentGroupMembersForOrg :many
-- Compiler input only: inactive/deleted/non-agent devices must never expand an
-- agent-group source. Suspension keeps the membership row but contributes no
-- source until the canonical device becomes active again.
SELECT m.agent_group_id, m.device_id
FROM agent_group_members m
JOIN agent_groups g
  ON g.id = m.agent_group_id AND g.org_id = m.org_id
JOIN devices d
  ON d.id = m.device_id AND d.org_id = m.org_id
WHERE m.org_id = $1
  AND g.archived_at IS NULL
  AND d.kind = 'agent'
  AND d.status = 'active'
  AND d.deleted_at IS NULL
ORDER BY m.agent_group_id, m.device_id;

-- name: CreateAgentGroup :one
INSERT INTO agent_groups (org_id, name, description)
VALUES ($1, $2, $3)
RETURNING *;

-- name: ListAgentGroups :many
SELECT * FROM agent_groups
WHERE org_id = $1 AND archived_at IS NULL
ORDER BY lower(name), id;

-- name: GetAgentGroup :one
SELECT * FROM agent_groups
WHERE id = $1 AND org_id = $2 AND archived_at IS NULL;

-- name: GetAgentGroupForUpdate :one
SELECT * FROM agent_groups
WHERE id = $1 AND org_id = $2 AND archived_at IS NULL
FOR UPDATE;

-- name: AddAgentGroupMember :execrows
INSERT INTO agent_group_members (org_id, agent_group_id, device_id, created_by_user_id)
VALUES ($1, $2, $3, $4)
ON CONFLICT (agent_group_id, device_id) DO NOTHING;

-- name: RemoveAgentGroupMember :execrows
DELETE FROM agent_group_members
WHERE org_id = $1 AND agent_group_id = $2 AND device_id = $3;

-- name: RemoveAgentGroupMembershipsForDevice :execrows
DELETE FROM agent_group_members
WHERE org_id = $1 AND device_id = $2;

-- name: ListAgentGroupMembers :many
SELECT d.id, d.name, d.status, d.node_id, d.assigned_ip, m.created_at
FROM agent_group_members m
JOIN devices d ON d.id = m.device_id AND d.org_id = m.org_id
WHERE m.org_id = $1 AND m.agent_group_id = $2
  AND d.kind = 'agent' AND d.deleted_at IS NULL
ORDER BY lower(d.name), d.id;

-- name: CreateAgentPolicyTemplate :one
INSERT INTO agent_policy_templates (org_id, name, description)
VALUES ($1, $2, $3)
RETURNING *;

-- name: ListAgentPolicyTemplates :many
SELECT * FROM agent_policy_templates
WHERE org_id = $1 AND archived_at IS NULL
ORDER BY lower(name), id;

-- name: GetAgentPolicyTemplateForUpdate :one
SELECT * FROM agent_policy_templates
WHERE id = $1 AND org_id = $2 AND archived_at IS NULL
FOR UPDATE;

-- name: GetAgentPolicyTemplate :one
SELECT * FROM agent_policy_templates
WHERE id = $1 AND org_id = $2 AND archived_at IS NULL;

-- name: NextAgentPolicyTemplateVersion :one
SELECT coalesce(max(version), 0)::bigint + 1 AS version
FROM agent_policy_template_versions
WHERE org_id = $1 AND template_id = $2;

-- name: CreateAgentPolicyTemplateVersion :one
INSERT INTO agent_policy_template_versions
    (org_id, template_id, version, created_by_user_id)
VALUES ($1, $2, $3, $4)
RETURNING *;

-- name: CreateAgentPolicyTemplateVersionItem :one
INSERT INTO agent_policy_template_version_items
    (org_id, template_version_id, ordinal, dst_kind,
     dst_resource_id, dst_group_id, dst_site_id, dst_k8s_service_id)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING *;

-- name: GetAgentPolicyTemplateVersion :one
SELECT v.*
FROM agent_policy_template_versions v
JOIN agent_policy_templates t
  ON t.id = v.template_id AND t.org_id = v.org_id
WHERE v.id = $1 AND v.org_id = $2 AND t.archived_at IS NULL;

-- name: ListAgentPolicyTemplateVersions :many
SELECT v.*
FROM agent_policy_template_versions v
JOIN agent_policy_templates t
  ON t.id = v.template_id AND t.org_id = v.org_id
WHERE v.org_id = $1 AND v.template_id = $2 AND t.archived_at IS NULL
ORDER BY v.version DESC, v.id;

-- name: ListAgentPolicyTemplateVersionItems :many
SELECT * FROM agent_policy_template_version_items
WHERE org_id = $1 AND template_version_id = $2
ORDER BY ordinal, id;

-- name: GetActiveAgentPolicyTemplateAssignmentForUpdate :one
SELECT * FROM agent_policy_template_assignments
WHERE org_id = $1 AND agent_group_id = $2 AND template_id = $3
  AND state = 'active'
FOR UPDATE;

-- name: GetActiveAgentPolicyTemplateAssignment :one
SELECT * FROM agent_policy_template_assignments
WHERE org_id = $1 AND agent_group_id = $2 AND template_id = $3
  AND state = 'active';

-- name: ListAgentPolicyTemplateRuleBindings :many
SELECT b.*, r.src_agent_group_id, r.dst_kind, r.dst_resource_id,
       r.dst_group_id, r.dst_site_id, r.dst_k8s_service_id
FROM agent_policy_template_rule_bindings b
JOIN policy_rules r ON r.id = b.policy_rule_id AND r.org_id = b.org_id
WHERE b.org_id = $1 AND b.assignment_id = $2
ORDER BY b.template_version_item_id, b.policy_rule_id;

-- name: ListAgentTemplateManagedRuleIDs :many
SELECT DISTINCT policy_rule_id
FROM agent_policy_template_rule_bindings
WHERE org_id = $1
ORDER BY policy_rule_id;

-- Destination delete guards. Immutable template versions keep their exact
-- destination identity, so each owning service refuses before its normal
-- cascade/soft-delete could silently change reusable policy meaning.
-- name: CountAgentPolicyTemplateResourceReferences :one
SELECT count(DISTINCT template_version_id)
FROM agent_policy_template_version_items
WHERE org_id = $1 AND dst_resource_id = $2;

-- name: CountAgentPolicyTemplateGroupReferences :one
SELECT count(DISTINCT template_version_id)
FROM agent_policy_template_version_items
WHERE org_id = $1 AND dst_group_id = $2;

-- name: CountAgentPolicyTemplateSiteReferences :one
SELECT count(DISTINCT template_version_id)
FROM agent_policy_template_version_items
WHERE org_id = $1 AND dst_site_id = $2;

-- name: IsAgentTemplateManagedRule :one
SELECT EXISTS (
  SELECT 1
  FROM agent_policy_template_rule_bindings
  WHERE org_id = $1 AND policy_rule_id = $2
);
