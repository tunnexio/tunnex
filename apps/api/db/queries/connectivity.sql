-- name: LockConnectivityEligibility :one
-- Match the WireGuard roster's active owner/membership/posture/key gates.
-- Device serialization plus shared eligibility locks keep the snapshot stable
-- until commit. No caller-supplied owner or gateway determines the binding.
SELECT d.id AS device_id, d.org_id, d.user_id AS owner_id, d.node_id AS gateway_id
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
FOR UPDATE OF d FOR SHARE OF n, u, m, o, p;

-- name: ConnectivityWallClock :one
SELECT clock_timestamp()::timestamptz AS now;

-- name: GetConnectivitySession :one
SELECT * FROM connectivity_sessions
WHERE org_id = sqlc.arg(org_id) AND device_id = sqlc.arg(device_id)
FOR UPDATE;

-- name: ReplaceConnectivitySession :one
-- Caller holds canonical device/eligibility locks. Keep generation monotonic
-- even when the previous session was revoked or expired.
INSERT INTO connectivity_sessions
    (device_id, org_id, owner_id, gateway_id, session_id, generation, created_at, expires_at)
VALUES (sqlc.arg(device_id), sqlc.arg(org_id), sqlc.arg(owner_id), sqlc.arg(gateway_id),
    sqlc.arg(session_id), 1, sqlc.arg(created_at), sqlc.arg(expires_at))
ON CONFLICT (device_id) DO UPDATE SET
    org_id = EXCLUDED.org_id, owner_id = EXCLUDED.owner_id, gateway_id = EXCLUDED.gateway_id,
    session_id = EXCLUDED.session_id, generation = connectivity_sessions.generation + 1,
    created_at = EXCLUDED.created_at, expires_at = EXCLUDED.expires_at, revoked = false,
    device_sequence = 0, gateway_sequence = 0, device_payload = '{}', gateway_payload = '{}'
WHERE connectivity_sessions.org_id = EXCLUDED.org_id
  AND connectivity_sessions.generation < 9223372036854775807
RETURNING *;

-- name: SaveConnectivitySnapshot :one
UPDATE connectivity_sessions SET
    device_sequence = sqlc.arg(device_sequence), gateway_sequence = sqlc.arg(gateway_sequence),
    device_payload = sqlc.arg(device_payload), gateway_payload = sqlc.arg(gateway_payload),
    revoked = sqlc.arg(revoked)
WHERE org_id = sqlc.arg(org_id) AND device_id = sqlc.arg(device_id)
  AND session_id = sqlc.arg(session_id) AND generation = sqlc.arg(generation)
RETURNING *;
