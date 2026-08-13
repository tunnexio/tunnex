-- S7.5.3 device health (posture v1). Facts are CLIENT-REPORTED (not attested);
-- evaluation is server-side, continuous (on every report), and enforcement rides
-- the existing exclude-then-push machinery via devices.health_blocked.

-- name: GetDeviceHealth :one
-- lint:cross-org — keyed by device_id; the caller authorized the device via its
-- org (GetDevice) before reading its health snapshot.
SELECT * FROM device_health WHERE device_id = $1;

-- name: UpsertDeviceHealth :one
-- lint:cross-org — keyed by device_id; ownership + org checked by the service
-- (GetDevice + owner match) in the same transaction. Snapshot-only (v1): the
-- latest report replaces the prior one; reported_at is the SERVER clock that
-- staleness (D4) is measured against.
INSERT INTO device_health (device_id, platform, os_version, disk_encrypted,
                           evaluated_state, failed_checks, collected_at, reported_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, now())
ON CONFLICT (device_id) DO UPDATE
SET platform        = EXCLUDED.platform,
    os_version      = EXCLUDED.os_version,
    disk_encrypted  = EXCLUDED.disk_encrypted,
    evaluated_state = EXCLUDED.evaluated_state,
    failed_checks   = EXCLUDED.failed_checks,
    collected_at    = EXCLUDED.collected_at,
    reported_at     = now()
RETURNING *;

-- name: SetDeviceHealthBlocked :one
-- lint:cross-org — keyed by device_id inside the report/sweep transaction (org
-- already authorized). Flips the ORTHOGONAL enforcement flag (D7); returns the
-- row so the caller sees org/node for the push.
UPDATE devices SET health_blocked = $2, updated_at = now()
WHERE id = $1 AND deleted_at IS NULL
RETURNING *;

-- name: ListOrgHealthChecks :many
SELECT * FROM org_health_checks WHERE org_id = $1 ORDER BY check_kind;

-- name: UpsertOrgHealthCheck :one
-- Opt-in a check (or change its mode/param). A row's existence IS the opt-in
-- (no row = off — the unlock-then-opt-in convention, default-off by construction).
INSERT INTO org_health_checks (org_id, check_kind, mode, param)
VALUES ($1, $2, $3, $4)
ON CONFLICT (org_id, check_kind) DO UPDATE
SET mode = EXCLUDED.mode, param = EXCLUDED.param, updated_at = now()
RETURNING *;

-- name: DeleteOrgHealthCheck :execrows
-- Turn a check OFF (delete the opt-in row).
DELETE FROM org_health_checks WHERE org_id = $1 AND check_kind = $2;

-- name: ListDeviceHealthForOrg :many
-- The org's reporting devices with their latest facts — the blast-radius input
-- (D4): on enabling a check, count how many devices' LAST report would fail it
-- (best-effort, post-commit; the config write itself never blocks anything).
SELECT dh.*
FROM device_health dh
JOIN devices d ON d.id = dh.device_id
WHERE d.org_id = $1 AND d.status IN ('active', 'pending') AND d.deleted_at IS NULL;

-- name: ClearStaleHealthBlocks :many
-- lint:cross-org — the staleness sweep (D4: a report gone quiet past the TTL is
-- ABSENCE, and absence never blocks — only a FRESH positive non-compliant report
-- gates). System-wide by design: clears health_blocked wherever the backing
-- report has gone stale, returning the affected devices for auditing + org push.
UPDATE devices d
SET health_blocked = false, updated_at = now()
FROM device_health dh
WHERE dh.device_id = d.id
  AND d.health_blocked
  AND d.deleted_at IS NULL
  AND dh.reported_at < now() - sqlc.arg(ttl)::interval
RETURNING d.id, d.org_id;

-- name: ClearAllHealthBlocks :many
-- lint:cross-org — the DOWNGRADE-RELEASE sweep (the enforcement mirror of
-- unlock-then-opt-in): when the device-health feature is OFF (open build), NO
-- device may remain posture-blocked — disabling a feature must RELEASE its
-- enforcement, not petrify it. Unconditional (no TTL): every health_blocked
-- device is freed. Returns the affected devices for auditing + org push. Runs at
-- open-build boot; idempotent (no blocks -> no rows).
UPDATE devices
SET health_blocked = false, updated_at = now()
WHERE health_blocked AND deleted_at IS NULL
RETURNING id, org_id;
