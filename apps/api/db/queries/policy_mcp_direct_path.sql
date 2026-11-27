-- AI-SEC-2: inputs the policy snapshot needs to close an agent's direct path to
-- an MCP endpoint assigned to it. The compiler stays pure; these reads carry the
-- gating facts (gateway capability, runtime capability, grace date).

-- name: MCPDirectPathSchemaPresent :one
-- The control plane also runs against a schema that has not been migrated to
-- 0249; there the feature has no data and the snapshot must not name the table.
SELECT (to_regclass('organization_mcp_direct_path_grace') IS NOT NULL)::boolean AS present;

-- name: ListMCPDirectPathInputsForOrg :many
-- One row per agent device and MCP endpoint it inherits from a group's active
-- profile assignment (the same join as ListAgentMCPProfilesForDevice), with the
-- device's gateway capabilities, whether its runtime already forwards through
-- the gateway, and whether the organization is still inside its grace period.
-- No grace row means no grace. The clock is PostgreSQL's.
SELECT d.id AS device_id,
       p.endpoint,
       n.capabilities AS node_capabilities,
       (rs.mcp_gateway_capable_at IS NOT NULL)::boolean AS runtime_gateway_capable,
       (g.grace_until IS NOT NULL AND g.grace_until > now())::boolean AS grace_open
FROM agent_mcp_profile_assignments a
JOIN agent_mcp_profiles p
  ON p.id = a.profile_id AND p.org_id = a.org_id
JOIN agent_group_members m
  ON m.agent_group_id = a.agent_group_id AND m.org_id = a.org_id
JOIN devices d
  ON d.id = m.device_id AND d.org_id = m.org_id
JOIN nodes n
  ON n.id = d.node_id AND n.org_id = d.org_id
LEFT JOIN agent_runtime_state rs ON rs.device_id = d.id
LEFT JOIN organization_mcp_direct_path_grace g ON g.org_id = a.org_id
WHERE a.org_id = sqlc.arg(org_id)
  AND a.state = 'active'
  AND d.kind = 'agent'
  AND d.status = 'active'
  AND d.deleted_at IS NULL
ORDER BY d.id, p.id;

-- name: ListOrganizationsWithMCPDirectPathGraceEndedBetween :many
-- Organizations whose grace date went by in (after_time, until_time]. The grace
-- sweep pushes each of them once so the deny is compiled when the date passes.
SELECT org_id
FROM organization_mcp_direct_path_grace
WHERE grace_until > sqlc.arg(after_time)
  AND grace_until <= sqlc.arg(until_time)
ORDER BY org_id;
