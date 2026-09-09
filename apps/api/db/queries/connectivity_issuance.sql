-- name: EnsureConnectivityIssuanceLock :exec
INSERT INTO connectivity_issuance_locks(org_id) VALUES($1) ON CONFLICT DO NOTHING;

-- name: HasConnectivityIssuance :one
SELECT EXISTS(SELECT 1 FROM connectivity_issuances
WHERE session_id=sqlc.arg(session_id) AND org_id=sqlc.arg(org_id));

-- name: LockConnectivityIssuance :one
SELECT org_id FROM connectivity_issuance_locks WHERE org_id=$1 FOR UPDATE;

-- name: PruneConnectivityIssuances :exec
DELETE FROM connectivity_issuances WHERE org_id=sqlc.arg(org_id)
AND issued_at <= sqlc.arg(cutoff)::timestamptz;

-- name: CountConnectivityIssuances :one
SELECT count(*) AS organization_count,
count(*) FILTER (WHERE owner_id=sqlc.arg(owner_id)) AS owner_count,
count(*) FILTER (WHERE device_id=sqlc.arg(device_id)) AS device_count
FROM connectivity_issuances WHERE org_id=sqlc.arg(org_id);

-- name: RecordConnectivityIssuance :exec
INSERT INTO connectivity_issuances(session_id, org_id, owner_id, device_id, issued_at)
VALUES ($1,$2,$3,$4,$5);
