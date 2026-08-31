-- S20.5/D13a lifecycle-claim protocol. Every query is org-scoped. The token
-- credential itself is never selected by these operator endpoints; only the
-- temporarily sealed response is read by the exact remint transaction.

-- name: CreateLifecycleJoinToken :one
INSERT INTO node_join_tokens (
    org_id, node_name, token_hash, expires_at, issued_by, enrols_kind,
    lifecycle_claim, lifecycle_generation, lifecycle_request_id,
    lifecycle_token_sealed
)
VALUES (
    sqlc.arg(org_id), sqlc.arg(node_name), sqlc.arg(token_hash), sqlc.arg(expires_at),
    sqlc.arg(issued_by), 'gateway', sqlc.arg(lifecycle_claim),
    1, sqlc.arg(lifecycle_request_id), sqlc.arg(lifecycle_token_sealed)
)
ON CONFLICT (lifecycle_claim) WHERE lifecycle_claim IS NOT NULL DO NOTHING
RETURNING *;

-- name: CreateAbortedLifecycleJoinToken :one
-- Generation zero is a credentialless, permanently expired tombstone. The
-- random hash has no disclosed preimage and exists only because the legacy
-- token table keeps token_hash NOT NULL/unique during the mixed-version
-- compatibility window.
INSERT INTO node_join_tokens (
    org_id, node_name, token_hash, expires_at, issued_by, enrols_kind,
    lifecycle_claim, lifecycle_generation, lifecycle_request_id,
    lifecycle_token_sealed, lifecycle_aborted_at
)
VALUES (
    sqlc.arg(org_id), sqlc.arg(node_name), sqlc.arg(token_hash),
    TIMESTAMPTZ 'epoch', sqlc.arg(issued_by), 'gateway',
    sqlc.arg(lifecycle_claim), 0, sqlc.arg(lifecycle_request_id),
    NULL, now()
)
ON CONFLICT (lifecycle_claim) WHERE lifecycle_claim IS NOT NULL DO NOTHING
RETURNING *;

-- name: GetLifecycleJoinTokenForOrg :one
SELECT * FROM node_join_tokens
WHERE org_id = sqlc.arg(org_id) AND lifecycle_claim = sqlc.arg(lifecycle_claim);

-- name: LockLifecycleJoinTokenForOrg :one
SELECT * FROM node_join_tokens
WHERE org_id = sqlc.arg(org_id) AND lifecycle_claim = sqlc.arg(lifecycle_claim)
FOR UPDATE;

-- name: RemintLifecycleJoinToken :one
UPDATE node_join_tokens
SET token_hash = sqlc.arg(token_hash),
    expires_at = sqlc.arg(expires_at),
    lifecycle_generation = lifecycle_generation + 1,
    lifecycle_request_id = sqlc.arg(lifecycle_request_id),
    lifecycle_token_sealed = sqlc.arg(lifecycle_token_sealed),
    lifecycle_acknowledged_at = NULL
WHERE id = sqlc.arg(id)
  AND org_id = sqlc.arg(org_id)
  AND lifecycle_claim = sqlc.arg(lifecycle_claim)
  AND lifecycle_generation = sqlc.arg(expected_generation)
  AND consumed_at IS NULL
  AND lifecycle_aborted_at IS NULL
  AND expires_at <= sqlc.arg(server_time)
RETURNING *;

-- name: AcknowledgeLifecycleJoinToken :execrows
UPDATE node_join_tokens
SET lifecycle_token_sealed = NULL,
    lifecycle_acknowledged_at = now()
WHERE org_id = sqlc.arg(org_id)
  AND lifecycle_claim = sqlc.arg(lifecycle_claim)
  AND lifecycle_generation = sqlc.arg(expected_generation)
  AND lifecycle_request_id = sqlc.arg(lifecycle_request_id)
  AND consumed_at IS NULL
  AND lifecycle_aborted_at IS NULL
  AND lifecycle_token_sealed IS NOT NULL;

-- name: AbortLifecycleJoinToken :execrows
UPDATE node_join_tokens
SET lifecycle_token_sealed = NULL,
    lifecycle_aborted_at = now(),
    expires_at = LEAST(expires_at, now())
WHERE org_id = sqlc.arg(org_id)
  AND lifecycle_claim = sqlc.arg(lifecycle_claim)
  AND lifecycle_generation = sqlc.arg(expected_generation)
  AND lifecycle_request_id = sqlc.arg(lifecycle_request_id)
  AND lifecycle_aborted_at IS NULL;

-- name: GetNodeByLifecycleClaimForOrg :one
SELECT * FROM nodes
WHERE org_id = sqlc.arg(org_id) AND lifecycle_claim = sqlc.arg(lifecycle_claim);

-- name: LockNodeByLifecycleClaimForOrg :one
SELECT * FROM nodes
WHERE org_id = sqlc.arg(org_id) AND lifecycle_claim = sqlc.arg(lifecycle_claim)
FOR UPDATE;

-- D13h install-operation epochs. The caller always locks the lifecycle token
-- first; every operation mutation follows that same token -> operation order.

-- name: GetLifecycleDatabaseTime :one
SELECT clock_timestamp()::timestamptz;

-- name: GetLifecycleInstallOperationForOrg :one
SELECT * FROM node_lifecycle_install_operations
WHERE org_id = sqlc.arg(org_id)
  AND lifecycle_claim = sqlc.arg(lifecycle_claim)
  AND operation_id = sqlc.arg(operation_id);

-- name: GetLatestLifecycleInstallOperationForOrg :one
SELECT * FROM node_lifecycle_install_operations
WHERE org_id = sqlc.arg(org_id)
  AND lifecycle_claim = sqlc.arg(lifecycle_claim)
ORDER BY epoch DESC
LIMIT 1;

-- name: LockLatestLifecycleInstallOperationForOrg :one
SELECT * FROM node_lifecycle_install_operations
WHERE org_id = sqlc.arg(org_id)
  AND lifecycle_claim = sqlc.arg(lifecycle_claim)
ORDER BY epoch DESC
LIMIT 1
FOR UPDATE;

-- name: CreateLifecycleInstallOperation :one
WITH server_clock AS MATERIALIZED (
    SELECT clock_timestamp()::timestamptz AS now_at
)
INSERT INTO node_lifecycle_install_operations (
    operation_id, token_id, org_id, lifecycle_claim,
    lifecycle_generation, lifecycle_request_id, epoch,
    release_namespace, release_name, install_intent_digest,
    requested_duration_seconds, not_after, heartbeat_at
)
SELECT
    sqlc.arg(operation_id), token.id, token.org_id, token.lifecycle_claim,
    token.lifecycle_generation, token.lifecycle_request_id, sqlc.arg(epoch),
    sqlc.arg(release_namespace), sqlc.arg(release_name), sqlc.arg(install_intent_digest),
    sqlc.arg(requested_duration_seconds),
    LEAST(token.expires_at, server_clock.now_at + make_interval(secs => sqlc.arg(requested_duration_seconds)::integer)),
    server_clock.now_at
FROM node_join_tokens token
CROSS JOIN server_clock
WHERE token.id = sqlc.arg(token_id)
  AND token.org_id = sqlc.arg(org_id)
  AND token.lifecycle_claim = sqlc.arg(lifecycle_claim)
  AND token.lifecycle_generation = sqlc.arg(expected_generation)
  AND token.lifecycle_request_id = sqlc.arg(lifecycle_request_id)
  AND token.lifecycle_acknowledged_at IS NOT NULL
  AND token.lifecycle_aborted_at IS NULL
  AND token.consumed_at IS NULL
  AND token.expires_at > server_clock.now_at
ON CONFLICT DO NOTHING
RETURNING *;

-- name: HeartbeatLifecycleInstallOperation :one
WITH server_clock AS MATERIALIZED (
    SELECT clock_timestamp()::timestamptz AS now_at
)
UPDATE node_lifecycle_install_operations
SET heartbeat_at = GREATEST(heartbeat_at, (SELECT now_at FROM server_clock))
WHERE org_id = sqlc.arg(org_id)
  AND lifecycle_claim = sqlc.arg(lifecycle_claim)
  AND lifecycle_generation = sqlc.arg(expected_generation)
  AND lifecycle_request_id = sqlc.arg(lifecycle_request_id)
  AND operation_id = sqlc.arg(operation_id)
  AND epoch = sqlc.arg(expected_epoch)
  AND state = 'active'
  AND not_after > (SELECT now_at FROM server_clock)
RETURNING *;

-- name: RequestAbortLifecycleInstallOperation :one
WITH server_clock AS MATERIALIZED (
    SELECT clock_timestamp()::timestamptz AS now_at
)
UPDATE node_lifecycle_install_operations
SET abort_requested_at = (SELECT now_at FROM server_clock)
WHERE org_id = sqlc.arg(org_id)
  AND lifecycle_claim = sqlc.arg(lifecycle_claim)
  AND lifecycle_generation = sqlc.arg(expected_generation)
  AND lifecycle_request_id = sqlc.arg(lifecycle_request_id)
  AND operation_id = sqlc.arg(operation_id)
  AND epoch = sqlc.arg(expected_epoch)
  AND state IN ('active', 'released')
  AND abort_requested_at IS NULL
RETURNING *;

-- name: ReleaseLifecycleInstallOperation :one
WITH server_clock AS MATERIALIZED (
    SELECT clock_timestamp()::timestamptz AS now_at
)
UPDATE node_lifecycle_install_operations
SET state = 'released', released_at = (SELECT now_at FROM server_clock)
WHERE org_id = sqlc.arg(org_id)
  AND lifecycle_claim = sqlc.arg(lifecycle_claim)
  AND lifecycle_generation = sqlc.arg(expected_generation)
  AND lifecycle_request_id = sqlc.arg(lifecycle_request_id)
  AND operation_id = sqlc.arg(operation_id)
  AND epoch = sqlc.arg(expected_epoch)
  AND state = 'active'
RETURNING *;

-- name: CompleteLifecycleInstallOperation :one
WITH server_clock AS MATERIALIZED (
    SELECT clock_timestamp()::timestamptz AS now_at
)
UPDATE node_lifecycle_install_operations operation
SET state = 'completed', completed_at = (SELECT now_at FROM server_clock)
WHERE operation.org_id = sqlc.arg(org_id)
  AND operation.lifecycle_claim = sqlc.arg(lifecycle_claim)
  AND operation.lifecycle_generation = sqlc.arg(expected_generation)
  AND operation.lifecycle_request_id = sqlc.arg(lifecycle_request_id)
  AND operation.operation_id = sqlc.arg(operation_id)
  AND operation.epoch = sqlc.arg(expected_epoch)
  AND operation.state = 'active'
  AND operation.abort_requested_at IS NULL
  AND operation.not_after > (SELECT now_at FROM server_clock)
  AND EXISTS (
      SELECT 1
      FROM node_join_tokens token
      JOIN nodes node
        ON node.id = token.consumed_node_id
       AND node.org_id = token.org_id
       AND node.lifecycle_claim = token.lifecycle_claim
       AND node.name = token.node_name
      WHERE token.id = operation.token_id
        AND token.org_id = operation.org_id
        AND token.lifecycle_claim = operation.lifecycle_claim
        AND token.lifecycle_generation = operation.lifecycle_generation
        AND token.lifecycle_request_id = operation.lifecycle_request_id
        AND token.consumed_at IS NOT NULL
        AND token.lifecycle_aborted_at IS NULL
        AND node.status = 'active'
  )
RETURNING operation.*;

-- name: TakeOverLifecycleInstallOperationForAbort :one
WITH server_clock AS MATERIALIZED (
    SELECT clock_timestamp()::timestamptz AS now_at
)
UPDATE node_lifecycle_install_operations
SET state = 'taken_over', epoch = epoch + 1,
    released_at = NULL, taken_over_at = (SELECT now_at FROM server_clock)
WHERE org_id = sqlc.arg(org_id)
  AND lifecycle_claim = sqlc.arg(lifecycle_claim)
  AND lifecycle_generation = sqlc.arg(expected_generation)
  AND lifecycle_request_id = sqlc.arg(lifecycle_request_id)
  AND operation_id = sqlc.arg(operation_id)
  AND epoch = sqlc.arg(expected_epoch)
  AND abort_requested_at IS NOT NULL
  AND (state = 'released' OR (state = 'active' AND not_after <= (SELECT now_at FROM server_clock)))
RETURNING *;

-- name: MarkLifecycleInstallOperationAborted :one
WITH server_clock AS MATERIALIZED (
    SELECT clock_timestamp()::timestamptz AS now_at
)
UPDATE node_lifecycle_install_operations
SET state = 'aborted', aborted_at = (SELECT now_at FROM server_clock)
WHERE org_id = sqlc.arg(org_id)
  AND lifecycle_claim = sqlc.arg(lifecycle_claim)
  AND lifecycle_generation = sqlc.arg(expected_generation)
  AND lifecycle_request_id = sqlc.arg(lifecycle_request_id)
  AND operation_id = sqlc.arg(operation_id)
  AND epoch = sqlc.arg(expected_epoch)
  AND state = 'taken_over'
  AND abort_requested_at IS NOT NULL
RETURNING *;
