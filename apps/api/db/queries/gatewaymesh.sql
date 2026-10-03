-- name: ListCrossGatewayGateways :many
-- Organization-scoped network carriers, including gateways with no site.
-- Agent devices are subjects; enrolled agent nodes are not gateway carriers.
SELECT id, wg_public_key, endpoint FROM nodes
WHERE org_id = $1 AND status = 'active'
  AND COALESCE(enrolled_kind, 'gateway') = 'gateway'
  AND wg_public_key ~ '^[A-Za-z0-9+/]{43}=$'
ORDER BY id;

-- name: ListCrossGatewayClients :many
-- Same owner/membership/posture boundary as active peers and policy subjects.
-- Intentionally includes human and agent devices, with either client transport.
SELECT d.node_id, d.assigned_ip, d.transport
FROM devices d
JOIN users u ON u.id = d.user_id
JOIN memberships m ON m.org_id = d.org_id AND m.user_id = d.user_id
WHERE d.org_id = $1 AND d.status = 'active' AND NOT d.health_blocked
  AND d.deleted_at IS NULL AND u.status = 'active' AND u.deleted_at IS NULL
  AND m.access_revoked_at IS NULL
  AND d.assigned_ip IS NOT NULL AND d.assigned_ip <> ''
  AND (d.transport = 'openvpn' OR d.public_key ~ '^[A-Za-z0-9+/]{43}=$')
ORDER BY d.assigned_ip;

-- name: SetOrgCrossGatewayClientsEnabled :one
UPDATE organizations SET cross_gateway_clients_enabled = $2, updated_at = now()
WHERE id = $1 AND deleted_at IS NULL
RETURNING *;

-- name: ListCrossGatewayIPv6Pool :many
-- Read the already allocated organization pool; never allocate during topology reads.
SELECT pool_cidr FROM org_ipv6_pools WHERE org_id = $1;

-- name: GetCrossGatewaySettingForUpdate :one
-- Serialize the old/new audit transition with concurrent setting changes.
SELECT cross_gateway_clients_enabled FROM organizations
WHERE id = $1 AND deleted_at IS NULL FOR UPDATE;
