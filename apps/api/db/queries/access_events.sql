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

-- name: InsertAccessEventBatch :copyfrom
-- COPY the whole report as one PostgreSQL statement. Besides avoiding one round trip per
-- row, this is important to retention accounting: the statement-level transition-table
-- trigger advances access_event_retention_state once for the complete logical batch.
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

-- name: ListAccessEventsByDevice :many
-- src_device_id is the verified, immutable event-row attribution. Do not join
-- the live device roster: deleted devices remain valid historical filters.
SELECT * FROM access_events
WHERE org_id = $1
  AND src_device_id = sqlc.arg(src_device_id)
  AND (created_at < sqlc.arg(before_created_at)
       OR (created_at = sqlc.arg(before_created_at) AND id < sqlc.arg(before_id)))
ORDER BY created_at DESC, id DESC
LIMIT sqlc.arg(page_limit);

-- name: ListAccessEventsByUser :many
-- src_user_id is the owner resolved and persisted at ingest, not a live
-- ownership join and not proof that the human initiated the traffic.
SELECT * FROM access_events
WHERE org_id = $1
  AND src_user_id = sqlc.arg(src_user_id)
  AND (created_at < sqlc.arg(before_created_at)
       OR (created_at = sqlc.arg(before_created_at) AND id < sqlc.arg(before_id)))
ORDER BY created_at DESC, id DESC
LIMIT sqlc.arg(page_limit);

-- name: ListAccessDenies :many
-- The security-focused feed: deny + deny_aggregate + terminated + gap, same keyset shape.
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

-- name: ListAccessDeniesByDevice :many
SELECT * FROM access_events
WHERE org_id = $1
  AND src_device_id = sqlc.arg(src_device_id)
  AND decision <> 'allow'
  AND (created_at < sqlc.arg(before_created_at)
       OR (created_at = sqlc.arg(before_created_at) AND id < sqlc.arg(before_id)))
ORDER BY created_at DESC, id DESC
LIMIT sqlc.arg(page_limit);

-- name: ListAccessDeniesByUser :many
SELECT * FROM access_events
WHERE org_id = $1
  AND src_user_id = sqlc.arg(src_user_id)
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
-- lint:allow-deleted — retention intentionally drains evidence for soft-deleted tenants.
-- with policy-eligible events. Soft-deleted tenants remain eligible so their
-- event history cannot strand disk indefinitely. Expired claims are still
-- enumerated after their final eligible row disappears so they can be durably
-- failed before a successor is considered.
WITH db_clock AS MATERIALIZED (
    SELECT statement_timestamp() AS now_at
)
SELECT organization.id AS org_id
FROM organizations AS organization
CROSS JOIN db_clock
LEFT JOIN access_event_retention_state AS retention_state
       ON retention_state.org_id=organization.id
LEFT JOIN access_event_retention_settings AS setting
       ON setting.org_id=organization.id
LEFT JOIN LATERAL (
    SELECT run.status,run.completed_at,run.more_pending
    FROM access_event_retention_runs AS run
    WHERE run.org_id=organization.id AND run.status <> 'running'
    ORDER BY run.started_at DESC,run.id DESC
    LIMIT 1
) AS latest ON true
WHERE NOT EXISTS (
    SELECT 1 FROM access_event_retention_runs AS active
    WHERE active.org_id=organization.id
      AND active.status='running'
      AND active.lease_expires_at > db_clock.now_at
)
  AND (
    EXISTS (
        SELECT 1 FROM access_event_retention_runs AS expired
        WHERE expired.org_id=organization.id
          AND expired.status='running'
          AND expired.lease_expires_at <= db_clock.now_at
    )
    OR (
        CASE
            WHEN COALESCE(retention_state.retained_rows,0)
                 > sqlc.arg(default_row_cap)::integer THEN true
            WHEN COALESCE(retention_state.retained_rows,0) > 0 THEN EXISTS (
                SELECT 1 FROM access_events AS old_event
                WHERE old_event.org_id=organization.id
                  AND old_event.created_at
                      < db_clock.now_at
                          - COALESCE(setting.retention_days,
                                     sqlc.arg(default_retention_days)::integer)
                            * interval '24 hours'
            )
            ELSE false
        END
        AND (
            latest.completed_at IS NULL
            OR (latest.status='succeeded' AND latest.more_pending)
            OR latest.completed_at
               + COALESCE(setting.cleanup_interval_minutes,
                          sqlc.arg(default_interval_minutes)::integer)
                 * interval '1 minute'
               <= db_clock.now_at
        )
    )
  )
ORDER BY latest.completed_at NULLS FIRST,organization.id
LIMIT sqlc.arg(org_limit);

-- name: IsAccessEventRetentionDue :one
WITH db_clock AS MATERIALIZED (
    SELECT statement_timestamp() AS now_at
)
SELECT (
    CASE
    WHEN COALESCE((
        SELECT state.retained_rows
        FROM access_event_retention_state AS state
        WHERE state.org_id=sqlc.arg(org_id)
    ),0) > sqlc.arg(row_cap)::integer THEN true
    WHEN COALESCE((
        SELECT state.retained_rows
        FROM access_event_retention_state AS state
        WHERE state.org_id=sqlc.arg(org_id)
    ),0) > 0 THEN EXISTS (
        SELECT 1 FROM access_events AS old_event
        WHERE old_event.org_id=sqlc.arg(org_id)
          AND old_event.created_at
              < db_clock.now_at
                  - sqlc.arg(retention_days)::integer * interval '24 hours'
    )
    ELSE false
    END
)
AND NOT EXISTS (
    SELECT 1 FROM access_event_retention_runs AS active
    WHERE active.org_id=sqlc.arg(org_id)
      AND active.status='running'
      AND active.lease_expires_at > db_clock.now_at
)
AND COALESCE((
    SELECT (latest.status='succeeded' AND latest.more_pending)
       OR latest.completed_at
          + sqlc.arg(cleanup_interval_minutes)::integer * interval '1 minute'
          <= db_clock.now_at
    FROM access_event_retention_runs AS latest
    WHERE latest.org_id=sqlc.arg(org_id) AND latest.status <> 'running'
    ORDER BY latest.started_at DESC,latest.id DESC
    LIMIT 1
),true) AS due
FROM db_clock;

-- name: ExpireAccessEventRetentionRun :one
UPDATE access_event_retention_runs
SET status='failed',completed_at=GREATEST(clock_timestamp(),started_at),lease_expires_at=NULL,
    more_pending=true,error_code='lease_expired'
WHERE org_id=sqlc.arg(org_id)
  AND status='running'
  AND lease_expires_at <= clock_timestamp()
RETURNING *;

-- name: InsertScheduledAccessEventRetentionRun :one
WITH db_clock AS MATERIALIZED (
    SELECT statement_timestamp() AS now_at
)
INSERT INTO access_event_retention_runs (
    org_id,trigger_kind,status,retention_days,cleanup_interval_minutes,
    settings_revision,row_cap,batch_size,max_batches,cutoff_at,started_at,
    lease_expires_at
) SELECT
    sqlc.arg(org_id),'scheduled','running',sqlc.arg(retention_days),
    sqlc.arg(cleanup_interval_minutes),sqlc.arg(settings_revision),
    sqlc.arg(row_cap),sqlc.arg(batch_size),sqlc.arg(max_batches),
    db_clock.now_at - sqlc.arg(retention_days)::integer * interval '24 hours',
    db_clock.now_at,db_clock.now_at + interval '15 minutes'
FROM db_clock
RETURNING *;

-- name: InsertManualAccessEventRetentionRun :one
WITH db_clock AS MATERIALIZED (
    SELECT statement_timestamp() AS now_at
)
INSERT INTO access_event_retention_runs (
    org_id,trigger_kind,status,manual_idempotency_key,requested_by_user_id,
    retention_days,cleanup_interval_minutes,settings_revision,row_cap,
    batch_size,max_batches,cutoff_at,started_at,lease_expires_at
) SELECT
    sqlc.arg(org_id),'manual','running',sqlc.arg(manual_idempotency_key),
    sqlc.arg(requested_by_user_id),sqlc.arg(retention_days),
    sqlc.arg(cleanup_interval_minutes),sqlc.arg(settings_revision),
    sqlc.arg(row_cap),sqlc.arg(batch_size),sqlc.arg(max_batches),
    db_clock.now_at - sqlc.arg(retention_days)::integer * interval '24 hours',
    db_clock.now_at,db_clock.now_at + interval '15 minutes'
FROM db_clock
RETURNING *;

-- name: GetManualAccessEventRetentionRun :one
SELECT * FROM access_event_retention_runs
WHERE org_id=sqlc.arg(org_id)
  AND manual_idempotency_key=sqlc.arg(manual_idempotency_key);

-- name: PruneAccessEventRetentionRunHistory :execrows
-- Bound automatic scheduler history without weakening manual idempotency:
-- manual runs and running claims are never candidates.
WITH obsolete AS (
    SELECT run.id
    FROM access_event_retention_runs AS run
    WHERE run.org_id=sqlc.arg(org_id)
      AND run.trigger_kind='scheduled'
      AND run.status <> 'running'
    ORDER BY run.started_at DESC,run.id DESC
    LIMIT sqlc.arg(delete_limit)::integer
    OFFSET sqlc.arg(keep_terminal)::integer
    FOR UPDATE SKIP LOCKED
)
DELETE FROM access_event_retention_runs AS target
USING obsolete
WHERE target.org_id=sqlc.arg(org_id) AND target.id=obsolete.id;

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
SET lease_expires_at=clock_timestamp() + interval '15 minutes'
WHERE id=sqlc.arg(id) AND org_id=sqlc.arg(org_id) AND status='running'
  AND lease_expires_at > clock_timestamp();

-- name: FinalizeAccessEventRetentionRunSuccess :one
UPDATE access_event_retention_runs
SET status='succeeded',completed_at=GREATEST(clock_timestamp(),started_at),lease_expires_at=NULL,
    more_pending=sqlc.arg(more_pending),error_code=NULL
WHERE id=sqlc.arg(id) AND org_id=sqlc.arg(org_id) AND status='running'
  AND lease_expires_at > clock_timestamp()
RETURNING *;

-- name: FinalizeAccessEventRetentionRunFailure :one
UPDATE access_event_retention_runs
SET status='failed',completed_at=GREATEST(clock_timestamp(),started_at),lease_expires_at=NULL,
    more_pending=true,error_code=sqlc.arg(error_code)
WHERE id=sqlc.arg(id) AND org_id=sqlc.arg(org_id) AND status='running'
  AND lease_expires_at > clock_timestamp()
RETURNING *;

-- name: PruneAccessEventRetentionBatch :one
-- The security-definer function is the only authorized DELETE path. It locks
-- the exact live run, verifies its snapshot against the current effective
-- policy, derives age/cap eligibility, and commits deletion counters atomically.
SELECT access_event_retention_prune_batch(sqlc.arg(run_id));

-- name: AccessEventRetentionMorePending :one
SELECT (EXISTS (
    SELECT 1 FROM access_events AS event
    WHERE event.org_id=sqlc.arg(org_id)
      AND event.created_at < sqlc.arg(older_than)
) OR COALESCE((
    SELECT state.retained_rows
    FROM access_event_retention_state AS state
    WHERE state.org_id=sqlc.arg(org_id)
),0) > sqlc.arg(keep_newest)::integer) AS more_pending;
