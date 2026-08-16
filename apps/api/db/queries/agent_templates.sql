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
