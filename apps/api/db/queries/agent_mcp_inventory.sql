-- name: UpsertAgentMCPInventory :one
INSERT INTO agent_mcp_inventory (device_id, snapshot, observed_at)
SELECT d.id, sqlc.arg(snapshot)::jsonb, sqlc.arg(observed_at)
FROM devices d
WHERE d.id = sqlc.arg(device_id)
  AND d.org_id = sqlc.arg(org_id)
  AND d.kind = 'agent'
  AND d.deleted_at IS NULL
ON CONFLICT (device_id) DO UPDATE
SET snapshot = EXCLUDED.snapshot, observed_at = EXCLUDED.observed_at
-- AI-SEC-2: once the gateway has observed this device, a list reported by the
-- agent host never replaces it. No row is returned in that case.
WHERE agent_mcp_inventory.source = 'agent'
RETURNING device_id, snapshot, observed_at, created_at, updated_at, source;

-- name: MergeAgentMCPInventoryOAuthDiscovery :execrows
-- AI-SEC-2: for a gateway-observed device the agent host may still refresh the
-- OAuth discovery metadata an administrator starts consent from. Nothing else
-- in the snapshot, and neither its time nor its source, changes.
UPDATE agent_mcp_inventory i
SET snapshot = jsonb_set(i.snapshot, '{oauth_discovery}', sqlc.arg(oauth_discovery)::jsonb, true)
FROM devices d
WHERE d.id = i.device_id
  AND i.device_id = sqlc.arg(device_id)
  AND d.org_id = sqlc.arg(org_id)
  AND d.kind = 'agent'
  AND d.deleted_at IS NULL
  AND i.source = 'gateway';

-- name: GetAgentMCPInventory :one
SELECT i.device_id, i.snapshot, i.observed_at, i.created_at, i.updated_at, i.source
FROM agent_mcp_inventory i
JOIN devices d ON d.id = i.device_id
WHERE i.device_id = sqlc.arg(device_id)
  AND d.org_id = sqlc.arg(org_id)
  AND d.kind = 'agent'
  AND d.deleted_at IS NULL;

-- name: UpsertGatewayAgentMCPInventory :one
-- AI-SEC-2: the gateway observed this device's MCP server. The row becomes
-- gateway-sourced and stays so; the control plane computes every hash in the
-- snapshot itself and never stores one a caller reported. The device must be an
-- active agent homed on the reporting gateway.
INSERT INTO agent_mcp_inventory (device_id, snapshot, observed_at, source)
SELECT d.id, sqlc.arg(snapshot)::jsonb, sqlc.arg(observed_at), 'gateway'
FROM devices d
WHERE d.id = sqlc.arg(device_id)
  AND d.org_id = sqlc.arg(org_id)
  AND d.node_id = sqlc.arg(node_id)
  AND d.kind = 'agent'
  AND d.deleted_at IS NULL
ON CONFLICT (device_id) DO UPDATE
SET snapshot = EXCLUDED.snapshot, observed_at = EXCLUDED.observed_at, source = 'gateway'
RETURNING device_id, snapshot, observed_at, created_at, updated_at, source;
