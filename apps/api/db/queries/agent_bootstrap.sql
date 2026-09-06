-- name: CreateAgentBootstrapToken :one
INSERT INTO agent_bootstrap_tokens (org_id, gateway_node_id, agent_name, token_hash, expires_at, issued_by)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: GetAgentBootstrapToken :one
-- lint:cross-org — the public redemption credential is an unguessable hash; org is learned from the token row.
SELECT * FROM agent_bootstrap_tokens
WHERE token_hash = $1 AND consumed_at IS NULL AND expires_at > now();

-- name: ConsumeAgentBootstrapToken :one
-- lint:cross-org — the token hash is the public endpoint's credential and the row is locked before creation.
UPDATE agent_bootstrap_tokens
SET consumed_at = now(), consumed_device_id = $2
WHERE token_hash = $1 AND consumed_at IS NULL AND expires_at > now()
RETURNING *;

-- name: CreateAgentRuntimeCredential :one
INSERT INTO agent_runtime_credentials (org_id, device_id, token_hash)
VALUES ($1, $2, $3)
RETURNING *;

-- name: GetAgentRuntimeCredential :one
-- lint:cross-org — F04's bearer hash is the credential; the returned row supplies its org/device binding.
SELECT * FROM agent_runtime_credentials
WHERE token_hash = $1 AND revoked_at IS NULL AND state = 'current';

-- name: RequestAgentRuntimeCredentialRotation :one
UPDATE agent_runtime_credentials current
SET rotation_requested_at = now(), rotation_deadline = $3,
    rotation_requested_by = $4
FROM devices d
WHERE current.org_id = $1 AND current.device_id = $2
  AND current.state = 'current' AND current.revoked_at IS NULL
  AND d.id = current.device_id AND d.org_id = current.org_id
  AND d.kind = 'agent' AND d.status = 'active' AND d.deleted_at IS NULL
  AND NOT EXISTS (
    SELECT 1 FROM agent_runtime_credentials candidate
    WHERE candidate.device_id = current.device_id
      AND candidate.state = 'candidate'
  )
RETURNING current.*;

-- name: ExpireAgentRuntimeCredentialRotation :exec
WITH expired_candidate AS (
  UPDATE agent_runtime_credentials candidate
  SET state = 'revoked', revoked_at = COALESCE(revoked_at, now()),
      terminal_at = COALESCE(terminal_at, now()), candidate_expires_at = NULL
  WHERE candidate.org_id = $1 AND candidate.device_id = $2
    AND candidate.state = 'candidate' AND candidate.candidate_expires_at <= statement_timestamp()
  RETURNING 1
)
SELECT count(*) FROM expired_candidate;

-- name: GetAgentRuntimeCredentialRotation :one
SELECT current.device_id, current.revision,
  current.rotation_requested_at, current.rotation_deadline,
  CAST(candidate.id IS NOT NULL AS boolean) AS candidate_pending
FROM agent_runtime_credentials current
JOIN devices d ON d.id = current.device_id AND d.org_id = current.org_id
LEFT JOIN agent_runtime_credentials candidate
  ON candidate.device_id = current.device_id AND candidate.state = 'candidate'
WHERE current.org_id = $1 AND current.device_id = $2
  AND current.state = 'current' AND current.revoked_at IS NULL
  AND d.kind = 'agent' AND d.deleted_at IS NULL;

-- name: RequestAgentWireGuardRotation :one
INSERT INTO agent_wireguard_rotations (
  device_id, org_id, current_revision, requested_revision, state,
  requested_at, deadline, requested_by
)
SELECT d.id, d.org_id, 1, 2, 'requested', now(), $3, $4
FROM devices d
WHERE d.id = $2 AND d.org_id = $1 AND d.kind = 'agent'
  AND d.status = 'active' AND d.deleted_at IS NULL
ON CONFLICT (device_id) DO UPDATE
SET requested_revision = agent_wireguard_rotations.current_revision + 1,
    state = 'requested', candidate_public_key = NULL,
    requested_at = now(), deadline = EXCLUDED.deadline,
    requested_by = EXCLUDED.requested_by, staged_at = NULL,
    updated_at = now()
WHERE agent_wireguard_rotations.org_id = EXCLUDED.org_id
  AND (agent_wireguard_rotations.state = 'current'
       OR agent_wireguard_rotations.deadline <= now())
RETURNING agent_wireguard_rotations.*;

-- name: GetAgentWireGuardRotation :one
SELECT r.* FROM agent_wireguard_rotations r
JOIN devices d ON d.id = r.device_id AND d.org_id = r.org_id
WHERE r.org_id = $1 AND r.device_id = $2
  AND d.kind = 'agent' AND d.deleted_at IS NULL;

-- name: TryLockAgentWireGuardRotation :one
-- An operator request already owns the device row. A reporting gateway may
-- own this rotation row while awaiting that device; never wait in reverse
-- order. Missing rows permit first rotation, 55P03 is retryable contention.
SELECT device_id FROM agent_wireguard_rotations
WHERE org_id = $1 AND device_id = $2
FOR UPDATE NOWAIT;

-- name: ExpireAgentWireGuardRotation :exec
UPDATE agent_wireguard_rotations
SET state = 'current', requested_revision = NULL,
    candidate_public_key = NULL, requested_at = NULL, deadline = NULL,
    requested_by = NULL, staged_at = NULL, updated_at = now()
WHERE org_id = $1 AND device_id = $2 AND state <> 'current'
  AND deadline <= now();

-- name: PrepareAgentWireGuardCandidate :one
UPDATE agent_wireguard_rotations r
SET state = 'prepared', candidate_public_key = $3, updated_at = now()
FROM devices d
WHERE r.org_id = $1 AND r.device_id = $2
  AND d.id = r.device_id AND d.org_id = r.org_id
  AND d.kind = 'agent' AND d.status = 'active' AND d.deleted_at IS NULL
  AND r.requested_revision = $4 AND r.deadline > now()
  AND r.state IN ('requested', 'prepared')
  AND (r.candidate_public_key IS NULL OR r.candidate_public_key = $3)
  AND $3 ~ '^[A-Za-z0-9+/]{43}=$' AND $3 <> d.public_key
  AND NOT EXISTS (
    SELECT 1 FROM devices collision
    WHERE collision.node_id = d.node_id AND collision.public_key = $3
      AND collision.id <> d.id AND collision.deleted_at IS NULL
  )
RETURNING r.*;

-- name: PrepareAgentRuntimeCredentialCandidate :one
WITH current_credential AS (
  SELECT current.* FROM agent_runtime_credentials current
  WHERE current.org_id = $1 AND current.device_id = $2
    AND current.state = 'current' AND current.revoked_at IS NULL
    AND current.rotation_requested_at IS NOT NULL
    AND current.rotation_deadline > statement_timestamp()
    AND $4 = current.revision + 1
  FOR UPDATE
), prepared AS (
  INSERT INTO agent_runtime_credentials (
    org_id, device_id, token_hash, revision, state, candidate_expires_at
  )
  SELECT org_id, device_id, $3, $4, 'candidate', rotation_deadline
  FROM current_credential
  ON CONFLICT (device_id) WHERE state = 'candidate'
  DO UPDATE SET token_hash = agent_runtime_credentials.token_hash
  WHERE agent_runtime_credentials.revision = EXCLUDED.revision
    AND agent_runtime_credentials.token_hash = EXCLUDED.token_hash
    AND agent_runtime_credentials.candidate_expires_at > statement_timestamp()
  RETURNING agent_runtime_credentials.*
)
SELECT * FROM prepared;

-- name: LookupAgentRuntimeCredentialBinding :one
-- lint:cross-org — the bearer hash supplies only the locking scope, never authentication.
-- Do not lock a credential before its device: device lifecycle triggers take
-- those locks in device -> credential order. Re-read below AFTER the device lock.
SELECT org_id, device_id FROM agent_runtime_credentials WHERE token_hash = $1;

-- name: AuthenticateAgentRuntimeCredential :one
-- Call only inside the device-locked transaction. This separate statement gets
-- a fresh READ COMMITTED snapshot after a lock wait; it does not promote.
SELECT * FROM agent_runtime_credentials
WHERE org_id = $1 AND device_id = $2 AND token_hash = $3
  AND revoked_at IS NULL
  AND (state = 'current'
    OR (state = 'candidate' AND candidate_expires_at > statement_timestamp()))
FOR UPDATE;

-- name: DemoteAgentRuntimeCredentialPredecessor :one
-- Explicitly finish demotion before promotion. A single multi-row UPDATE can
-- visit the candidate first and violate the immediate one-current index.
UPDATE agent_runtime_credentials
SET state = 'superseded', revoked_at = statement_timestamp(),
    terminal_at = statement_timestamp(), candidate_expires_at = NULL,
    rotation_requested_at = NULL, rotation_deadline = NULL,
    rotation_requested_by = NULL
WHERE org_id = $1 AND device_id = $2 AND revision = $3
  AND state = 'current' AND revoked_at IS NULL
RETURNING *;

-- name: PromoteAgentRuntimeCredentialCandidate :one
-- Exact successor only; a refusal MUST roll back the preceding demotion.
UPDATE agent_runtime_credentials
SET state = 'current', revoked_at = NULL, activated_at = statement_timestamp(),
    terminal_at = NULL, candidate_expires_at = NULL,
    rotation_requested_at = NULL, rotation_deadline = NULL,
    rotation_requested_by = NULL
WHERE org_id = $1 AND device_id = $2 AND id = $3 AND token_hash = $4
  AND revision = $5 AND state = 'candidate' AND revoked_at IS NULL
  AND candidate_expires_at > statement_timestamp()
RETURNING *;
