-- AI-SEC-2: gateway-enforced MCP. Device identity comes from tunnel evidence the
-- gateway observed (source address + WireGuard key) and from the gateway's own
-- mTLS identity (organization + node), never from anything the caller sent.

-- name: ResolveAgentDeviceByTunnelEvidence :one
-- The sibling of the AI Gateway VPN resolver for agent devices: an active agent
-- with exactly this key and address, homed on the calling gateway. No
-- membership join and no AI Gateway gate.
SELECT d.id, d.org_id, d.node_id, d.user_id, d.name
FROM devices d
WHERE d.org_id = sqlc.arg(org_id)
  AND d.node_id = sqlc.arg(node_id)
  AND d.public_key = sqlc.arg(public_key)
  AND d.assigned_ip = sqlc.arg(assigned_ip)
  AND d.transport = 'wireguard'
  AND d.kind = 'agent'
  AND d.status = 'active'
  AND d.deleted_at IS NULL
  AND NOT d.health_blocked;

-- name: GetOrganizationMCPDirectPathGrace :one
-- No row means no grace: the direct path closes as soon as the gateway can enforce.
SELECT grace_until
FROM organization_mcp_direct_path_grace
WHERE org_id = sqlc.arg(org_id);

-- name: InsertAgentMCPToolActivity :one
INSERT INTO agent_mcp_tool_activity (
    org_id, device_id, node_id, endpoint, server_name, method, tool_name,
    arguments_digest, decision, reason, policy_version, approval_request_id, result_status
) VALUES (
    sqlc.arg(org_id), sqlc.arg(device_id), sqlc.narg(node_id), sqlc.arg(endpoint), sqlc.arg(server_name),
    sqlc.arg(method), sqlc.arg(tool_name), sqlc.narg(arguments_digest), sqlc.arg(decision), sqlc.arg(reason),
    sqlc.narg(policy_version), sqlc.narg(approval_request_id), sqlc.arg(result_status)
)
RETURNING id, org_id, device_id, node_id, endpoint, server_name, method, tool_name, arguments_digest,
          decision, reason, policy_version, approval_request_id, result_status, upstream_http_status,
          occurred_at, completed_at, created_at;

-- name: CompleteAgentMCPToolActivity :execrows
-- Closes an allowed call once, and only for the gateway that was given it.
UPDATE agent_mcp_tool_activity
SET result_status = sqlc.arg(result_status),
    upstream_http_status = sqlc.narg(upstream_http_status),
    completed_at = now()
WHERE id = sqlc.arg(id)
  AND org_id = sqlc.arg(org_id)
  AND node_id = sqlc.arg(node_id)
  AND decision = 'allow'
  AND result_status = 'pending';

-- name: ListAgentMCPToolActivity :many
-- Newest first for one agent. Keyset: pass the last row's occurred_at and id.
SELECT a.id, a.org_id, a.device_id, a.node_id, a.endpoint, a.server_name, a.method, a.tool_name,
       a.arguments_digest, a.decision, a.reason, a.policy_version, a.approval_request_id, a.result_status,
       a.upstream_http_status, a.occurred_at, a.completed_at, a.created_at
FROM agent_mcp_tool_activity a
JOIN devices d ON d.id = a.device_id
WHERE a.org_id = sqlc.arg(org_id)
  AND a.device_id = sqlc.arg(device_id)
  AND d.org_id = sqlc.arg(org_id)
  AND d.kind = 'agent'
  AND d.deleted_at IS NULL
  AND (sqlc.narg(before_occurred_at)::timestamptz IS NULL
       OR (a.occurred_at, a.id) < (sqlc.narg(before_occurred_at)::timestamptz, sqlc.narg(before_id)::uuid))
ORDER BY a.occurred_at DESC, a.id DESC
LIMIT sqlc.arg(page_limit);

-- name: DeleteAgentMCPToolActivityBatch :execrows
-- Retention sweep: one bounded batch of rows older than the cutoff.
WITH doomed AS (
    SELECT a.id
    FROM agent_mcp_tool_activity a
    WHERE a.org_id = sqlc.arg(org_id)
      AND a.created_at < sqlc.arg(cutoff)
    ORDER BY a.created_at
    LIMIT sqlc.arg(batch_limit)
    FOR UPDATE SKIP LOCKED
)
DELETE FROM agent_mcp_tool_activity a
USING doomed
WHERE a.id = doomed.id;

-- name: ListOrganizationsWithAgentMCPToolActivity :many
SELECT DISTINCT a.org_id
FROM agent_mcp_tool_activity a
ORDER BY a.org_id;

-- name: GetAgentMCPToolActivityRetention :one
-- No row means the application default (30 days).
SELECT org_id, retention_days, updated_by_user_id, created_at, updated_at
FROM agent_mcp_tool_activity_retention_settings
WHERE org_id = sqlc.arg(org_id);

-- name: UpsertAgentMCPToolActivityRetention :one
INSERT INTO agent_mcp_tool_activity_retention_settings (org_id, retention_days, updated_by_user_id)
VALUES (sqlc.arg(org_id), sqlc.arg(retention_days), sqlc.narg(updated_by_user_id))
ON CONFLICT (org_id) DO UPDATE
SET retention_days = EXCLUDED.retention_days, updated_by_user_id = EXCLUDED.updated_by_user_id
RETURNING org_id, retention_days, updated_by_user_id, created_at, updated_at;
