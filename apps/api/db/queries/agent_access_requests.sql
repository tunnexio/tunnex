-- F10 approval-gated temporary access workflow.

-- name: CreateAgentAccessRequest :one
INSERT INTO agent_access_requests (
  org_id, device_id, dst_kind, dst_resource_id, dst_group_id, dst_site_id,
  dst_k8s_service_id, reason, requested_duration_seconds, requested_by_user_id
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
RETURNING *;

-- name: GetAgentAccessRequest :one
SELECT * FROM agent_access_requests
WHERE id=$1 AND org_id=$2;

-- name: GetAgentAccessRequestForUpdate :one
SELECT * FROM agent_access_requests
WHERE id=$1 AND org_id=$2
FOR UPDATE;

-- name: ListAgentAccessRequests :many
SELECT * FROM agent_access_requests
WHERE org_id=$1
  AND (sqlc.narg('state')::text IS NULL OR state=sqlc.narg('state'))
  AND (sqlc.narg('device_id')::uuid IS NULL OR device_id=sqlc.narg('device_id'))
  AND (sqlc.narg('before_requested_at')::timestamptz IS NULL
       OR (requested_at, id) < (sqlc.narg('before_requested_at')::timestamptz,
                               sqlc.narg('before_id')::uuid))
ORDER BY requested_at DESC, id DESC
LIMIT sqlc.arg('page_size');

-- name: ListAgentAccessRequestsForActor :many
SELECT ar.*
FROM agent_access_requests ar
JOIN devices d ON d.id=ar.device_id AND d.org_id=ar.org_id
JOIN agent_profiles ap ON ap.device_id=d.id
WHERE ar.org_id=$1
  AND (sqlc.narg('state')::text IS NULL OR ar.state=sqlc.narg('state'))
  AND (sqlc.narg('device_id')::uuid IS NULL OR ar.device_id=sqlc.narg('device_id'))
  AND (sqlc.narg('before_requested_at')::timestamptz IS NULL
       OR (ar.requested_at, ar.id) < (sqlc.narg('before_requested_at')::timestamptz,
                                     sqlc.narg('before_id')::uuid))
  AND (
      ar.requested_by_user_id=sqlc.arg('actor_id')::uuid
      OR
      d.user_id=sqlc.arg('actor_id')::uuid
      OR EXISTS (
          SELECT 1
          FROM group_members gm
          JOIN memberships m ON m.org_id=gm.org_id AND m.user_id=gm.user_id
          JOIN users u ON u.id=gm.user_id
          WHERE gm.org_id=d.org_id
            AND gm.group_id=ap.managing_group_id
            AND gm.user_id=sqlc.arg('actor_id')::uuid
            AND m.access_revoked_at IS NULL
            AND u.status='active'
            AND u.deleted_at IS NULL
      )
  )
ORDER BY ar.requested_at DESC, ar.id DESC
LIMIT sqlc.arg('page_size');

-- name: InsertAgentAccessRequestEvent :one
INSERT INTO agent_access_request_events (
  org_id, request_id, state, actor_user_id, actor_system, metadata
) VALUES ($1,$2,$3,$4,$5,$6)
RETURNING *;

-- name: ListAgentAccessRequestEvents :many
SELECT * FROM agent_access_request_events
WHERE org_id=$1 AND request_id=$2
ORDER BY created_at, id;

-- name: GetAgentAccessOperation :one
SELECT o.org_id, o.request_id, o.operation, o.idempotency_key,
       o.parameter_hash, o.created_at
FROM agent_access_request_operations o
WHERE o.org_id=$1 AND o.operation=$2 AND o.idempotency_key=$3;

-- name: InsertAgentAccessOperation :execrows
INSERT INTO agent_access_request_operations (
  org_id, request_id, operation, idempotency_key, parameter_hash
) VALUES ($1,$2,$3,$4,$5)
ON CONFLICT (org_id, operation, idempotency_key) DO NOTHING;

-- name: ApproveAgentAccessRequest :one
UPDATE agent_access_requests
SET state='approved', approved_by_user_id=$3, approved_at=$4,
    approved_expires_at=$5, policy_rule_id=$6
WHERE id=$1 AND org_id=$2 AND state='pending'
RETURNING *;

-- name: RejectAgentAccessRequest :one
UPDATE agent_access_requests
SET state='rejected', rejected_by_user_id=$3, rejected_at=$4,
    rejection_reason=$5
WHERE id=$1 AND org_id=$2 AND state='pending'
RETURNING *;

-- name: CancelAgentAccessRequest :one
UPDATE agent_access_requests
SET state='cancelled', cancelled_by_user_id=$3, cancelled_at=$4
WHERE id=$1 AND org_id=$2 AND state='pending'
RETURNING *;

-- name: RevokeAgentAccessRequest :one
UPDATE agent_access_requests
SET state='revoked', revoked_by_user_id=$3, revoked_at=$4
WHERE id=$1 AND org_id=$2 AND state='approved'
RETURNING *;

-- name: ListDueAgentAccessRequestsForUpdate :many
-- lint:cross-org — the scheduler-leader expiry sweep intentionally scans every
-- organization; each returned row still carries org_id for same-tx mutation,
-- audit and one push per affected tenant.
SELECT * FROM agent_access_requests
WHERE state='approved' AND approved_expires_at <= now()
ORDER BY approved_expires_at, id
FOR UPDATE SKIP LOCKED;

-- name: ExpireAgentAccessRequest :one
UPDATE agent_access_requests
SET state='expired'
WHERE id=$1 AND org_id=$2 AND state='approved' AND approved_expires_at <= now()
RETURNING *;

-- name: GetAgentAccessRequestByPolicyRule :one
SELECT * FROM agent_access_requests
WHERE org_id=$1 AND policy_rule_id=$2;

-- name: ListAgentAccessManagedRules :many
SELECT policy_rule_id, id AS request_id
FROM agent_access_requests
WHERE org_id=$1 AND policy_rule_id IS NOT NULL
ORDER BY policy_rule_id;

-- name: CountLiveAgentAccessRequests :one
SELECT count(*) FROM agent_access_requests
WHERE org_id=$1 AND state IN ('pending','approved');

-- name: CountLiveAgentAccessRequestsByDevice :one
SELECT count(*) FROM agent_access_requests
WHERE org_id=$1 AND device_id=$2 AND state IN ('pending','approved');

-- name: CountAgentAccessRequestsRequestedByActor :one
SELECT count(*) FROM agent_access_requests
WHERE org_id=$1 AND requested_by_user_id=$2;

-- name: CountLiveAgentAccessRequestsByDestination :one
SELECT count(*) FROM agent_access_requests
WHERE org_id=$1 AND state IN ('pending','approved')
  AND (
      (dst_kind='resource' AND dst_resource_id=sqlc.narg('dst_resource_id')::uuid)
      OR (dst_kind='group' AND dst_group_id=sqlc.narg('dst_group_id')::uuid)
      OR (dst_kind='site' AND dst_site_id=sqlc.narg('dst_site_id')::uuid)
      OR (dst_kind='k8s_service' AND dst_k8s_service_id=sqlc.narg('dst_k8s_service_id')::uuid)
  );

-- Destructive destination paths lock the canonical row before counting live
-- workflow references. The create trigger takes FOR KEY SHARE on the same row,
-- closing the count/delete race without retaining a permanent history FK.
-- name: LockAgentAccessResourceDestination :one
SELECT id FROM resources WHERE id=$1 AND org_id=$2 FOR UPDATE;

-- name: LockAgentAccessGroupDestination :one
SELECT id FROM user_groups WHERE id=$1 AND org_id=$2 FOR UPDATE;

-- name: LockAgentAccessSiteDestination :one
SELECT id FROM sites WHERE id=$1 AND org_id=$2 FOR UPDATE;

-- name: LockAgentAccessK8sServiceDestination :one
SELECT id FROM k8s_services WHERE id=$1 AND org_id=$2 AND deleted_at IS NULL FOR UPDATE;

-- name: LockAgentAccessK8sClusterDestinations :many
SELECT id FROM k8s_services WHERE org_id=$1 AND cluster_id=$2 FOR UPDATE;

-- name: CountLiveAgentAccessRequestsByK8sCluster :one
SELECT count(*)
FROM agent_access_requests ar
JOIN k8s_services ks ON ks.id=ar.dst_k8s_service_id AND ks.org_id=ar.org_id
WHERE ar.org_id=$1 AND ks.cluster_id=$2 AND ar.state IN ('pending','approved');

-- name: ListLiveAgentAccessRequestsByDeviceForUpdate :many
SELECT * FROM agent_access_requests
WHERE org_id=$1 AND device_id=$2 AND state IN ('pending','approved')
ORDER BY requested_at, id
FOR UPDATE;
