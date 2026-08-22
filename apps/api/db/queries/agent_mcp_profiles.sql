-- name: ListAgentMCPProfilesForDevice :many
SELECT p.id, p.org_id, p.name, p.endpoint
FROM agent_mcp_profiles p
JOIN agent_mcp_profile_assignments a
  ON a.profile_id = p.id AND a.org_id = p.org_id
JOIN agent_group_members m
  ON m.agent_group_id = a.agent_group_id AND m.org_id = a.org_id
WHERE p.org_id = $1 AND m.device_id = $2
ORDER BY p.id;
-- name: CreateAgentMCPProfile :one
INSERT INTO agent_mcp_profiles (org_id, name, endpoint)
VALUES ($1, $2, $3)
RETURNING *;

-- name: ListAgentMCPProfiles :many
SELECT * FROM agent_mcp_profiles WHERE org_id = $1 ORDER BY lower(name), id;

-- name: GetAgentMCPProfile :one
SELECT * FROM agent_mcp_profiles WHERE id = $1 AND org_id = $2;

-- name: AssignAgentMCPProfile :one
INSERT INTO agent_mcp_profile_assignments (org_id, profile_id, agent_group_id)
VALUES ($1, $2, $3)
RETURNING *;

-- name: ListAgentMCPProfileAssignments :many
SELECT a.*, p.name AS profile_name, p.endpoint, g.name AS group_name
FROM agent_mcp_profile_assignments a
JOIN agent_mcp_profiles p ON p.id = a.profile_id AND p.org_id = a.org_id
JOIN agent_groups g ON g.id = a.agent_group_id AND g.org_id = a.org_id
WHERE a.org_id = $1
ORDER BY a.assigned_at DESC, a.id DESC;
