-- name: EnsureConnectivityProfile :exec
INSERT INTO connectivity_profiles(org_id) VALUES(sqlc.arg(org_id)) ON CONFLICT(org_id) DO NOTHING;

-- name: LockConnectivityProfile :one
SELECT * FROM connectivity_profiles WHERE org_id=sqlc.arg(org_id) FOR UPDATE;

-- name: ReadConnectivityProfile :one
SELECT * FROM connectivity_profiles WHERE org_id=sqlc.arg(org_id) FOR SHARE;

-- name: SaveConnectivityProfile :one
UPDATE connectivity_profiles SET relay_url=sqlc.arg(relay_url),secret_sealed=sqlc.narg(secret_sealed),
    enabled=sqlc.arg(enabled),revision=revision+1
WHERE org_id=sqlc.arg(org_id) AND revision=sqlc.arg(expected_revision)
RETURNING *;

-- name: RevokeOrgConnectivitySessions :exec
UPDATE connectivity_sessions SET revoked=true,device_payload='{}',gateway_payload='{}'
WHERE org_id=sqlc.arg(org_id);
