-- name: ShareConnectivityEligibility :one
-- Match the WireGuard roster's active owner/membership/posture/key gates.
-- Device serialization plus shared eligibility locks keep the snapshot stable
-- until commit. No caller-supplied owner or gateway determines the binding.
SELECT d.id AS device_id, d.org_id, d.user_id AS owner_id, d.node_id AS gateway_id,
       d.public_key AS device_public_key, n.wg_public_key AS gateway_public_key
FROM devices d
JOIN nodes n ON n.id = d.node_id AND n.org_id = d.org_id
JOIN users u ON u.id = d.user_id
JOIN memberships m ON m.org_id = d.org_id AND m.user_id = d.user_id
JOIN organizations o ON o.id = d.org_id
JOIN connectivity_profiles p ON p.org_id = d.org_id
WHERE d.id = sqlc.arg(device_id) AND d.org_id = sqlc.arg(org_id)
  AND d.status = 'active' AND d.deleted_at IS NULL AND NOT d.health_blocked
  AND d.transport = 'wireguard' AND d.assigned_ip IS NOT NULL
  AND d.public_key ~ '^[A-Za-z0-9+/]{43}=$'
  AND n.status = 'active' AND u.status = 'active' AND u.deleted_at IS NULL
  AND o.deleted_at IS NULL AND p.enabled
FOR SHARE OF d, n, u, m, o, p;


-- name: ShareConnectivitySession :one
SELECT * FROM connectivity_sessions
WHERE org_id = sqlc.arg(org_id) AND device_id = sqlc.arg(device_id)
FOR SHARE;
