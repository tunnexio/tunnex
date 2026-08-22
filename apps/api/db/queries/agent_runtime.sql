-- name: EnsureAgentRuntimeState :one
-- The org join is the tenant boundary; device ids are globally unique, but a
-- runtime bootstrap must never turn knowledge of another org's UUID into state.
INSERT INTO agent_runtime_state (device_id, route_fingerprint)
SELECT d.id, $3
FROM devices d
WHERE d.id = $1
  AND d.org_id = $2
  AND d.kind = 'agent'
  AND d.deleted_at IS NULL
ON CONFLICT (device_id) DO UPDATE SET device_id = EXCLUDED.device_id
RETURNING device_id, desired_revision, applied_revision,
          last_attempted_revision, client_version, last_seen_at,
          last_error_code, last_error_revision, route_fingerprint, created_at, updated_at;

-- name: RefreshAgentRuntimeRouteFingerprint :one
-- A route-set change is desired state, not an imperative host command. Advance
-- only when the fingerprint changes, so concurrent polls coalesce safely.
UPDATE agent_runtime_state ars
SET desired_revision = CASE
        WHEN ars.route_fingerprint IS DISTINCT FROM $3 THEN ars.desired_revision + 1
        ELSE ars.desired_revision
    END,
    route_fingerprint = $3,
    updated_at = now()
FROM devices d
WHERE ars.device_id = $1
  AND d.id = ars.device_id
  AND d.org_id = $2
  AND d.kind = 'agent'
  AND d.deleted_at IS NULL
RETURNING ars.device_id, ars.desired_revision, ars.applied_revision,
          ars.last_attempted_revision, ars.client_version, ars.last_seen_at,
          ars.last_error_code, ars.last_error_revision, ars.route_fingerprint,
          ars.created_at, ars.updated_at;

-- name: GetAgentRuntimeState :one
SELECT ars.device_id, ars.desired_revision, ars.applied_revision,
       ars.last_attempted_revision, ars.client_version, ars.last_seen_at,
       ars.last_error_code, ars.last_error_revision, ars.route_fingerprint, ars.created_at, ars.updated_at
FROM agent_runtime_state ars
JOIN devices d ON d.id = ars.device_id
WHERE ars.device_id = $1
  AND d.org_id = $2
  AND d.kind = 'agent'
  AND d.deleted_at IS NULL;

-- name: BumpAgentDesiredRevision :one
UPDATE agent_runtime_state ars
SET desired_revision = ars.desired_revision + 1,
    updated_at = now()
FROM devices d
WHERE ars.device_id = $1
  AND d.id = ars.device_id
  AND d.org_id = $2
  AND d.kind = 'agent'
  AND d.deleted_at IS NULL
RETURNING ars.device_id, ars.desired_revision, ars.applied_revision,
          ars.last_attempted_revision, ars.client_version, ars.last_seen_at,
          ars.last_error_code, ars.last_error_revision, ars.route_fingerprint, ars.created_at, ars.updated_at;

-- name: ReportAgentRuntimeState :one
-- Inputs:
--   $3 applied_revision       last revision installed successfully
--   $4 attempted_revision     revision this report concerns
--   $5 client_version         bounded by the table constraint
--   $6 error_code             empty means the attempted revision succeeded
--
-- Reports may arrive out of order. Monotonic maxima prevent a stale poll from
-- rolling back success, and an error at or below an already-applied revision is
-- cleared rather than resurrected.
WITH previous AS MATERIALIZED (
    SELECT ars.device_id, ars.applied_revision AS previous_applied_revision
    FROM agent_runtime_state ars
    WHERE ars.device_id = $1
    FOR UPDATE OF ars
)
UPDATE agent_runtime_state ars
SET applied_revision = GREATEST(ars.applied_revision, $3),
    last_attempted_revision = GREATEST(ars.last_attempted_revision, $4),
    client_version = $5,
    last_seen_at = now(),
    last_error_code = CASE
        WHEN $4 < ars.last_attempted_revision THEN ars.last_error_code
        WHEN $4 <= GREATEST(ars.applied_revision, $3) THEN NULL
        WHEN sqlc.arg(error_code)::text = '' THEN NULL
        ELSE sqlc.arg(error_code)::text
    END,
    last_error_revision = CASE
        WHEN $4 < ars.last_attempted_revision THEN ars.last_error_revision
        WHEN $4 <= GREATEST(ars.applied_revision, $3) THEN NULL
        WHEN sqlc.arg(error_code)::text = '' THEN NULL
        ELSE $4
    END,
    updated_at = now()
FROM devices d, previous p
WHERE ars.device_id = $1
  AND p.device_id = ars.device_id
  AND d.id = ars.device_id
  AND d.org_id = $2
  AND d.kind = 'agent'
  AND d.deleted_at IS NULL
  AND $3 >= 0
  AND $4 >= $3
  AND $4 <= ars.desired_revision
  AND (sqlc.arg(error_code)::text <> '' OR $3 = $4)
RETURNING ars.device_id, ars.desired_revision, ars.applied_revision,
          ars.last_attempted_revision, ars.client_version, ars.last_seen_at,
          ars.last_error_code, ars.last_error_revision, ars.created_at, ars.updated_at,
          d.node_id, ars.applied_revision > p.previous_applied_revision AS applied_changed;
