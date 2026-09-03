-- name: InsertAccessEvent :exec
-- The id is app-generated (uuid v7), and seq comes from BumpOrgFlowSeq (a per-org
-- locked counter), so it is unique by construction. This is a PLAIN insert (NO
-- `ON CONFLICT DO NOTHING`): the (org_id, seq) unique index is a FAIL-LOUD backstop, so an
-- impossible collision errors the batch (agent -> next-report gap) rather than SILENTLY
-- dropping audit rows (review #1). No replay path re-inserts: a failed batch rolls the tx
-- (and the counter bump) back, so a retry re-reserves a fresh range.
INSERT INTO access_events (
    id, org_id, seq, node_id, occurred_at, decision, rule_id,
    src_device_id, src_user_id, src_ip, dst_ip, dst_resource_id, dst_group_id,
    protocol, dst_port, deny_count, window_end, created_at,
    policy_hash, policy_version, src_config_revision, src_kind, decision_reason
) VALUES (
    $1, $2, $3, $4, $5, $6, $7,
    $8, $9, $10, $11, $12, $13,
    $14, $15, $16, $17, $18,
    $19, $20, $21, $22, $23
);

-- name: InsertAccessEventBatch :batchexec
-- The hot ingest path (review fold-2 #6): pipeline a whole batch's inserts in ONE round trip
-- instead of N sequential Execs, so the process-global ingest mutex is held for far less time.
-- Same plain insert as InsertAccessEvent (seq is unique via the counter; the unique index is
-- the fail-LOUD backstop).
INSERT INTO access_events (
    id, org_id, seq, node_id, occurred_at, decision, rule_id,
    src_device_id, src_user_id, src_ip, dst_ip, dst_resource_id, dst_group_id,
    protocol, dst_port, deny_count, window_end, created_at,
    policy_hash, policy_version, src_config_revision, src_kind, decision_reason
) VALUES (
    $1, $2, $3, $4, $5, $6, $7,
    $8, $9, $10, $11, $12, $13,
    $14, $15, $16, $17, $18,
    $19, $20, $21, $22, $23
);

-- name: BumpOrgFlowSeq :one
-- Atomically reserve `n` seq values for an org and return the NEW high-water. The UPDATE
-- takes a ROW LOCK on the org, serializing concurrent same-org ingest so two batches can
-- never derive colliding seq (review #1). flow_seq lives on organizations and is NEVER swept,
-- so seq is monotonic + sweep-proof (review #6). The batch's seqs are (returned-n+1)..returned.
UPDATE organizations SET flow_seq = flow_seq + sqlc.arg(n)::bigint
WHERE id = sqlc.arg(org_id) AND deleted_at IS NULL
RETURNING flow_seq;

-- name: ListAccessEvents :many
-- Keyset page, newest-first, scoped by org. Expanded (created_at, id) < (cursor) predicate
-- (row-value form confuses sqlc's type inference for the id cursor). First page passes a
-- far-future created_at + a max uuid so the whole feed is < the cursor. Uses
-- access_events_org_created_id_idx.
SELECT * FROM access_events
WHERE org_id = $1
  AND (created_at < sqlc.arg(before_created_at)
       OR (created_at = sqlc.arg(before_created_at) AND id < sqlc.arg(before_id)))
ORDER BY created_at DESC, id DESC
LIMIT sqlc.arg(page_limit);

-- name: ListAccessEventsByAgent :many
SELECT * FROM access_events
WHERE org_id = $1
  AND src_kind = 'agent'
  AND src_device_id = sqlc.arg(src_agent_id)
  AND (created_at < sqlc.arg(before_created_at)
       OR (created_at = sqlc.arg(before_created_at) AND id < sqlc.arg(before_id)))
ORDER BY created_at DESC, id DESC
LIMIT sqlc.arg(page_limit);

-- name: ListAccessDenies :many
-- The security-focused feed: deny + deny_aggregate + terminated only, same keyset shape.
SELECT * FROM access_events
WHERE org_id = $1
  AND decision <> 'allow'
  AND (created_at < sqlc.arg(before_created_at)
       OR (created_at = sqlc.arg(before_created_at) AND id < sqlc.arg(before_id)))
ORDER BY created_at DESC, id DESC
LIMIT sqlc.arg(page_limit);

-- name: ListAccessDeniesByAgent :many
SELECT * FROM access_events
WHERE org_id = $1
  AND src_kind = 'agent'
  AND src_device_id = sqlc.arg(src_agent_id)
  AND decision <> 'allow'
  AND (created_at < sqlc.arg(before_created_at)
       OR (created_at = sqlc.arg(before_created_at) AND id < sqlc.arg(before_id)))
ORDER BY created_at DESC, id DESC
LIMIT sqlc.arg(page_limit);

-- name: LockLiveAccessEventRetentionOrganization :one
-- Settings are user-facing configuration and may only change for a live tenant.
SELECT id FROM organizations
WHERE id=sqlc.arg(org_id) AND deleted_at IS NULL
FOR UPDATE;

-- name: LockAccessEventRetentionOrganization :one
-- lint:allow-deleted — retention must continue draining events for a soft-deleted
-- tenant. The row lock serializes scheduled/manual claims for that tenant.
SELECT id FROM organizations
WHERE id=sqlc.arg(org_id)
FOR UPDATE;

-- name: GetAccessEventRetentionSettings :one
SELECT * FROM access_event_retention_settings
WHERE org_id=sqlc.arg(org_id);

-- name: GetAccessEventRetentionSettingsForUpdate :one
SELECT * FROM access_event_retention_settings
WHERE org_id=sqlc.arg(org_id)
FOR UPDATE;

-- name: InsertAccessEventRetentionSettings :one
INSERT INTO access_event_retention_settings (
    org_id,retention_days,cleanup_interval_minutes,revision,updated_by_user_id
) VALUES (
    sqlc.arg(org_id),sqlc.arg(retention_days),sqlc.arg(cleanup_interval_minutes),1,
    sqlc.arg(updated_by_user_id)
)
RETURNING *;

-- name: UpdateAccessEventRetentionSettings :one
UPDATE access_event_retention_settings
SET retention_days=sqlc.arg(retention_days),
    cleanup_interval_minutes=sqlc.arg(cleanup_interval_minutes),
    revision=sqlc.arg(revision),
    updated_by_user_id=sqlc.arg(updated_by_user_id)
WHERE org_id=sqlc.arg(org_id)
RETURNING *;

-- name: ListDueAccessEventRetentionOrganizations :many
-- lint:cross-org — the elected retention scheduler enumerates only tenants
-- holding events. Soft-deleted tenants remain eligible so their event history
-- cannot strand disk indefinitely. A latest successful run with more_pending
-- is immediately eligible for the next bounded continuation.
SELECT event_org.org_id
FROM (SELECT DISTINCT org_id FROM access_events) AS event_org
LEFT JOIN access_event_retention_settings AS setting
       ON setting.org_id=event_org.org_id
LEFT JOIN LATERAL (
    SELECT run.status,run.completed_at,run.more_pending
    FROM access_event_retention_runs AS run
    WHERE run.org_id=event_org.org_id AND run.status <> 'running'
    ORDER BY run.started_at DESC,run.id DESC
    LIMIT 1
) AS latest ON true
WHERE NOT EXISTS (
    SELECT 1 FROM access_event_retention_runs AS active
    WHERE active.org_id=event_org.org_id
      AND active.status='running'
      AND active.lease_expires_at > sqlc.arg(now_at)
)
  AND (
    latest.completed_at IS NULL
    OR (latest.status='succeeded' AND latest.more_pending)
    OR EXISTS (
        SELECT 1 FROM access_event_retention_runs AS expired
        WHERE expired.org_id=event_org.org_id
          AND expired.status='running'
          AND expired.lease_expires_at <= sqlc.arg(now_at)
    )
    OR latest.completed_at
       + COALESCE(setting.cleanup_interval_minutes,
                  sqlc.arg(default_interval_minutes)::integer) * interval '1 minute'
       <= sqlc.arg(now_at)
  )
ORDER BY latest.completed_at NULLS FIRST,event_org.org_id
LIMIT sqlc.arg(org_limit);

-- name: IsAccessEventRetentionDue :one
SELECT EXISTS (
    SELECT 1 FROM access_events AS event
    WHERE event.org_id=sqlc.arg(org_id)
)
AND NOT EXISTS (
    SELECT 1 FROM access_event_retention_runs AS active
    WHERE active.org_id=sqlc.arg(org_id)
      AND active.status='running'
      AND active.lease_expires_at > sqlc.arg(now_at)
)
AND COALESCE((
    SELECT (latest.status='succeeded' AND latest.more_pending)
       OR latest.completed_at
          + sqlc.arg(cleanup_interval_minutes)::integer * interval '1 minute'
          <= sqlc.arg(now_at)
    FROM access_event_retention_runs AS latest
    WHERE latest.org_id=sqlc.arg(org_id) AND latest.status <> 'running'
    ORDER BY latest.started_at DESC,latest.id DESC
    LIMIT 1
),true) AS due;

-- name: ExpireAccessEventRetentionRun :one
UPDATE access_event_retention_runs
SET status='failed',completed_at=sqlc.arg(completed_at),lease_expires_at=NULL,
    more_pending=true,error_code='lease_expired'
WHERE org_id=sqlc.arg(org_id)
  AND status='running'
  AND lease_expires_at <= sqlc.arg(completed_at)
RETURNING *;

-- name: InsertScheduledAccessEventRetentionRun :one
INSERT INTO access_event_retention_runs (
    org_id,trigger_kind,status,retention_days,cleanup_interval_minutes,
    settings_revision,row_cap,batch_size,max_batches,cutoff_at,started_at,
    lease_expires_at
) VALUES (
    sqlc.arg(org_id),'scheduled','running',sqlc.arg(retention_days),
    sqlc.arg(cleanup_interval_minutes),sqlc.arg(settings_revision),
    sqlc.arg(row_cap),sqlc.arg(batch_size),sqlc.arg(max_batches),
    sqlc.arg(cutoff_at),sqlc.arg(started_at),sqlc.arg(lease_expires_at)
)
RETURNING *;

-- name: InsertManualAccessEventRetentionRun :one
INSERT INTO access_event_retention_runs (
    org_id,trigger_kind,status,manual_idempotency_key,requested_by_user_id,
    retention_days,cleanup_interval_minutes,settings_revision,row_cap,
    batch_size,max_batches,cutoff_at,started_at,lease_expires_at
) VALUES (
    sqlc.arg(org_id),'manual','running',sqlc.arg(manual_idempotency_key),
    sqlc.arg(requested_by_user_id),sqlc.arg(retention_days),
    sqlc.arg(cleanup_interval_minutes),sqlc.arg(settings_revision),
    sqlc.arg(row_cap),sqlc.arg(batch_size),sqlc.arg(max_batches),
    sqlc.arg(cutoff_at),sqlc.arg(started_at),sqlc.arg(lease_expires_at)
)
RETURNING *;

-- name: GetManualAccessEventRetentionRun :one
SELECT * FROM access_event_retention_runs
WHERE org_id=sqlc.arg(org_id)
  AND manual_idempotency_key=sqlc.arg(manual_idempotency_key);

-- name: GetRunningAccessEventRetentionRun :one
SELECT * FROM access_event_retention_runs
WHERE org_id=sqlc.arg(org_id) AND status='running'
LIMIT 1;

-- name: GetLatestAccessEventRetentionRun :one
SELECT * FROM access_event_retention_runs
WHERE org_id=sqlc.arg(org_id)
ORDER BY started_at DESC,id DESC
LIMIT 1;

-- name: RenewAccessEventRetentionRunLease :execrows
UPDATE access_event_retention_runs
SET lease_expires_at=sqlc.arg(lease_expires_at)
WHERE id=sqlc.arg(id) AND org_id=sqlc.arg(org_id) AND status='running';

-- name: FinalizeAccessEventRetentionRunSuccess :one
UPDATE access_event_retention_runs
SET status='succeeded',completed_at=sqlc.arg(completed_at),lease_expires_at=NULL,
    deleted_rows=sqlc.arg(deleted_rows),batches=sqlc.arg(batches),
    more_pending=sqlc.arg(more_pending),error_code=NULL
WHERE id=sqlc.arg(id) AND org_id=sqlc.arg(org_id) AND status='running'
RETURNING *;

-- name: FinalizeAccessEventRetentionRunFailure :one
UPDATE access_event_retention_runs
SET status='failed',completed_at=sqlc.arg(completed_at),lease_expires_at=NULL,
    deleted_rows=sqlc.arg(deleted_rows),batches=sqlc.arg(batches),
    more_pending=true,error_code=sqlc.arg(error_code)
WHERE id=sqlc.arg(id) AND org_id=sqlc.arg(org_id) AND status='running'
RETURNING *;

-- name: PruneAccessEventsByAgeBatch :execrows
-- Tenant-scoped, oldest-first and bounded. created_at is trusted control-plane
-- ingest time; agent occurred_at can never extend retention.
WITH doomed AS (
    SELECT event.id
    FROM access_events AS event
    WHERE event.org_id=sqlc.arg(org_id)
      AND event.created_at < sqlc.arg(older_than)
    ORDER BY event.created_at,event.id
    LIMIT sqlc.arg(batch_limit)
    FOR UPDATE SKIP LOCKED
)
DELETE FROM access_events AS target
USING doomed
WHERE target.org_id=sqlc.arg(org_id) AND target.id=doomed.id;

-- name: PruneAccessEventsOverCapBatch :execrows
-- Find the first row beyond the protected newest window, then remove at most
-- one oldest batch through that boundary. Recomputing the boundary each batch
-- stays correct while ingestion remains append-only and concurrent.
WITH boundary AS (
    SELECT event.created_at,event.id
    FROM access_events AS event
    WHERE event.org_id=sqlc.arg(org_id)
    ORDER BY event.created_at DESC,event.id DESC
    OFFSET sqlc.arg(keep_newest)
    LIMIT 1
), doomed AS (
    SELECT event.id
    FROM access_events AS event
    CROSS JOIN boundary
    WHERE event.org_id=sqlc.arg(org_id)
      AND (event.created_at < boundary.created_at
        OR (event.created_at=boundary.created_at AND event.id <= boundary.id))
    ORDER BY event.created_at,event.id
    LIMIT sqlc.arg(batch_limit)
    FOR UPDATE OF event SKIP LOCKED
)
DELETE FROM access_events AS target
USING doomed
WHERE target.org_id=sqlc.arg(org_id) AND target.id=doomed.id;

-- name: AccessEventRetentionMorePending :one
SELECT EXISTS (
    SELECT 1 FROM access_events AS event
    WHERE event.org_id=sqlc.arg(org_id)
      AND event.created_at < sqlc.arg(older_than)
) OR EXISTS (
    SELECT 1 FROM access_events AS event
    WHERE event.org_id=sqlc.arg(org_id)
    ORDER BY event.created_at DESC,event.id DESC
    OFFSET sqlc.arg(keep_newest)
    LIMIT 1
) AS more_pending;
