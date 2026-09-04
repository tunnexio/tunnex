-- audit_logs is append-only for ordinary callers. The only deletion seam is the
-- bounded security-definer retention function introduced in migration 0129.

-- name: InsertAuditLog :one
INSERT INTO audit_logs (org_id, actor_user_id, action, target_type, target_id, metadata)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: InsertSystemAuditLog :one
-- Append a system/service-initiated audit row: actor_user_id is NULL and the actor is NAMED in
-- actor_system (e.g. 'idp-sync'). The metadata carries the CAUSE. Used when no human initiated
-- the action (S7.5.2 idp-sync deprovisioning).
INSERT INTO audit_logs (org_id, actor_system, action, target_type, target_id, metadata)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: ListAuditLogsByOrg :many
-- Org-scoped audit feed with optional filters (actor / action / date range) and
-- KEYSET pagination on (created_at, id) DESC. Every filter + cursor param is
-- nullable, so the S4.3 dashboard passes none (latest N). The cursor is written
-- as a ROW-VALUE comparison so it plans against (org_id, created_at DESC, id DESC)
-- rather than an OR-expansion the planner can't use.
SELECT * FROM audit_logs
WHERE org_id = $1
  AND (sqlc.narg('actor')::uuid IS NULL OR actor_user_id = sqlc.narg('actor'))
  AND (sqlc.narg('action')::text IS NULL OR action = sqlc.narg('action'))
  AND (sqlc.narg('from_ts')::timestamptz IS NULL OR created_at >= sqlc.narg('from_ts'))
  AND (sqlc.narg('to_ts')::timestamptz IS NULL OR created_at <= sqlc.narg('to_ts'))
  AND (sqlc.narg('cursor_ts')::timestamptz IS NULL OR (created_at, id) < (sqlc.narg('cursor_ts'), sqlc.narg('cursor_id')::uuid))
ORDER BY created_at DESC, id DESC
LIMIT sqlc.arg('lim');

-- name: LockLiveAuditLogRetentionOrganization :one
-- Settings are user-facing configuration and may only change for a live tenant.
SELECT id FROM organizations
WHERE id=sqlc.arg(org_id) AND deleted_at IS NULL
FOR UPDATE;

-- name: LockAuditLogRetentionOrganization :one
-- lint:allow-deleted — a persisted bounded policy keeps draining evidence for
-- a soft-deleted tenant. The row lock serializes scheduled/manual claims.
SELECT id FROM organizations
WHERE id=sqlc.arg(org_id)
FOR UPDATE;

-- name: GetAuditLogRetentionSettings :one
SELECT * FROM audit_log_retention_settings
WHERE org_id=sqlc.arg(org_id);

-- name: GetAuditLogRetentionSettingsForUpdate :one
SELECT * FROM audit_log_retention_settings
WHERE org_id=sqlc.arg(org_id)
FOR UPDATE;

-- name: InsertAuditLogRetentionSettings :one
INSERT INTO audit_log_retention_settings (
    org_id,retention_days,cleanup_interval_minutes,revision,updated_by_user_id
) VALUES (
    sqlc.arg(org_id),sqlc.narg(retention_days),sqlc.arg(cleanup_interval_minutes),1,
    sqlc.arg(updated_by_user_id)
)
RETURNING *;

-- name: UpdateAuditLogRetentionSettings :one
UPDATE audit_log_retention_settings
SET retention_days=sqlc.narg(retention_days),
    cleanup_interval_minutes=sqlc.arg(cleanup_interval_minutes),
    revision=sqlc.arg(revision),
    updated_by_user_id=sqlc.arg(updated_by_user_id)
WHERE org_id=sqlc.arg(org_id)
RETURNING *;

-- name: ListDueAuditLogRetentionOrganizations :many
-- lint:cross-org — new claims require an explicitly persisted bounded policy
-- and eligible evidence. Expired claims are still enumerated for recovery even
-- after the final eligible row is gone or the policy returns to Forever.
SELECT setting.org_id
FROM audit_log_retention_settings setting
WHERE NOT EXISTS (
      SELECT 1 FROM audit_log_retention_runs active
      WHERE active.org_id=setting.org_id
        AND active.status='running'
        AND active.lease_expires_at > statement_timestamp()
  )
  AND (
      -- Expired claims must be reclaimed even after their final batch removed
      -- the last eligible row or the policy switched back to Forever.
      EXISTS (
          SELECT 1 FROM audit_log_retention_runs expired
          WHERE expired.org_id=setting.org_id
            AND expired.status='running'
            AND expired.lease_expires_at <= statement_timestamp()
      )
      OR (
          setting.retention_days IS NOT NULL
          AND EXISTS (
              SELECT 1
              FROM audit_logs audit
              WHERE audit.org_id=setting.org_id
                AND audit.created_at
                    < statement_timestamp()
                        - setting.retention_days * interval '24 hours'
                AND NOT EXISTS (
                    SELECT 1 FROM k8s_connector_handoff_operations operation
                    WHERE operation.cas_audit_id=audit.id
                      AND operation.org_id=audit.org_id
                )
          )
          AND COALESCE((
              SELECT (latest.status='succeeded' AND latest.more_pending)
                 OR latest.completed_at
                    + setting.cleanup_interval_minutes * interval '1 minute'
                    <= statement_timestamp()
              FROM audit_log_retention_runs latest
              WHERE latest.org_id=setting.org_id AND latest.status <> 'running'
              ORDER BY latest.started_at DESC,latest.id DESC
              LIMIT 1
          ),true)
      )
  )
ORDER BY (
    SELECT latest.completed_at
    FROM audit_log_retention_runs latest
    WHERE latest.org_id=setting.org_id AND latest.status <> 'running'
    ORDER BY latest.started_at DESC,latest.id DESC
    LIMIT 1
) NULLS FIRST,setting.org_id
LIMIT sqlc.arg(org_limit);

-- name: IsAuditLogRetentionDue :one
SELECT EXISTS (
    SELECT 1
    FROM audit_log_retention_settings setting
    JOIN audit_logs audit ON audit.org_id=setting.org_id
    WHERE setting.org_id=sqlc.arg(org_id)
      AND setting.retention_days IS NOT NULL
      AND audit.created_at
          < statement_timestamp()
              - setting.retention_days * interval '24 hours'
      AND NOT EXISTS (
          SELECT 1 FROM k8s_connector_handoff_operations operation
          WHERE operation.cas_audit_id=audit.id
            AND operation.org_id=audit.org_id
      )
)
AND NOT EXISTS (
    SELECT 1 FROM audit_log_retention_runs active
    WHERE active.org_id=sqlc.arg(org_id)
      AND active.status='running'
      AND active.lease_expires_at > statement_timestamp()
)
AND COALESCE((
    SELECT (latest.status='succeeded' AND latest.more_pending)
       OR latest.completed_at
          + sqlc.arg(cleanup_interval_minutes)::integer * interval '1 minute'
          <= statement_timestamp()
    FROM audit_log_retention_runs latest
    WHERE latest.org_id=sqlc.arg(org_id) AND latest.status <> 'running'
    ORDER BY latest.started_at DESC,latest.id DESC
    LIMIT 1
),true) AS due;

-- name: ExpireAuditLogRetentionRun :one
UPDATE audit_log_retention_runs
SET status='failed',completed_at=GREATEST(clock_timestamp(),started_at),lease_expires_at=NULL,
    more_pending=true,error_code='lease_expired'
WHERE org_id=sqlc.arg(org_id)
  AND status='running'
  AND lease_expires_at <= clock_timestamp()
RETURNING *;

-- name: InsertScheduledAuditLogRetentionRun :one
INSERT INTO audit_log_retention_runs (
    org_id,trigger_kind,status,retention_days,cleanup_interval_minutes,
    settings_revision,batch_size,max_batches,cutoff_at,started_at,
    lease_expires_at
) VALUES (
    sqlc.arg(org_id),'scheduled','running',sqlc.arg(retention_days),
    sqlc.arg(cleanup_interval_minutes),sqlc.arg(settings_revision),
    sqlc.arg(batch_size),sqlc.arg(max_batches),
    statement_timestamp() - sqlc.arg(retention_days)::integer * interval '24 hours',
    statement_timestamp(),statement_timestamp() + interval '15 minutes'
)
RETURNING *;

-- name: InsertManualAuditLogRetentionRun :one
INSERT INTO audit_log_retention_runs (
    org_id,trigger_kind,status,manual_idempotency_key,requested_by_user_id,
    retention_days,cleanup_interval_minutes,settings_revision,batch_size,
    max_batches,cutoff_at,started_at,lease_expires_at
) VALUES (
    sqlc.arg(org_id),'manual','running',sqlc.arg(manual_idempotency_key),
    sqlc.arg(requested_by_user_id),sqlc.arg(retention_days),
    sqlc.arg(cleanup_interval_minutes),sqlc.arg(settings_revision),
    sqlc.arg(batch_size),sqlc.arg(max_batches),
    statement_timestamp() - sqlc.arg(retention_days)::integer * interval '24 hours',
    statement_timestamp(),statement_timestamp() + interval '15 minutes'
)
RETURNING *;

-- name: GetManualAuditLogRetentionRun :one
SELECT * FROM audit_log_retention_runs
WHERE org_id=sqlc.arg(org_id)
  AND manual_idempotency_key=sqlc.arg(manual_idempotency_key);

-- name: PruneAuditLogRetentionRunHistory :execrows
-- Bound automatic scheduler history without weakening manual idempotency:
-- manual runs and running claims are never candidates.
WITH obsolete AS (
    SELECT run.id
    FROM audit_log_retention_runs run
    WHERE run.org_id=sqlc.arg(org_id)
      AND run.trigger_kind='scheduled'
      AND run.status <> 'running'
    ORDER BY run.started_at DESC,run.id DESC
    LIMIT sqlc.arg(delete_limit)::integer
    OFFSET sqlc.arg(keep_terminal)::integer
    FOR UPDATE SKIP LOCKED
)
DELETE FROM audit_log_retention_runs target
USING obsolete
WHERE target.org_id=sqlc.arg(org_id) AND target.id=obsolete.id;

-- name: GetRunningAuditLogRetentionRun :one
SELECT * FROM audit_log_retention_runs
WHERE org_id=sqlc.arg(org_id) AND status='running'
LIMIT 1;

-- name: GetLatestAuditLogRetentionRun :one
SELECT * FROM audit_log_retention_runs
WHERE org_id=sqlc.arg(org_id)
ORDER BY started_at DESC,id DESC
LIMIT 1;

-- name: RenewAuditLogRetentionRunLease :execrows
UPDATE audit_log_retention_runs
SET lease_expires_at=clock_timestamp() + interval '15 minutes'
WHERE id=sqlc.arg(id) AND org_id=sqlc.arg(org_id) AND status='running'
  AND lease_expires_at > clock_timestamp();

-- name: FinalizeAuditLogRetentionRunSuccess :one
UPDATE audit_log_retention_runs
SET status='succeeded',completed_at=GREATEST(clock_timestamp(),started_at),lease_expires_at=NULL,
    more_pending=sqlc.arg(more_pending),error_code=NULL
WHERE id=sqlc.arg(id) AND org_id=sqlc.arg(org_id) AND status='running'
  AND lease_expires_at > clock_timestamp()
RETURNING *;

-- name: FinalizeAuditLogRetentionRunFailure :one
UPDATE audit_log_retention_runs
SET status='failed',completed_at=GREATEST(clock_timestamp(),started_at),lease_expires_at=NULL,
    more_pending=true,error_code=sqlc.arg(error_code)
WHERE id=sqlc.arg(id) AND org_id=sqlc.arg(org_id) AND status='running'
  AND lease_expires_at > clock_timestamp()
RETURNING *;

-- name: PruneAuditLogsByAgeBatch :one
-- This security-definer function is the only authorized DELETE path. Its SQL
-- body locks the exact unexpired durable run and derives tenant/cutoff from it.
SELECT audit_log_retention_prune_batch(
    sqlc.arg(run_id)
);

-- name: AuditLogRetentionMorePending :one
SELECT EXISTS (
    SELECT 1 FROM audit_logs audit
    WHERE audit.org_id=sqlc.arg(org_id)
      AND audit.created_at < sqlc.arg(older_than)
      AND NOT EXISTS (
          SELECT 1 FROM k8s_connector_handoff_operations operation
          WHERE operation.cas_audit_id=audit.id
            AND operation.org_id=audit.org_id
      )
) AS more_pending;
