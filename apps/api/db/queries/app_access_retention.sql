-- Fixed App Access retention has no public/manual cleanup API or caller cutoff.
-- name: ListDueAppAccessRetentionOrganizations :many
-- lint:cross-org — the leader enumerates only fixed-policy work or expired claims.
-- lint:allow-deleted — soft-deleted organizations keep their fixed evidence policy.
SELECT o.id FROM organizations o
WHERE EXISTS(SELECT 1 FROM app_access_retention_runs r WHERE r.org_id=o.id AND r.status='running' AND r.lease_expires_at<=statement_timestamp())
 OR (app_access_retention_has_work(o.id,statement_timestamp()-interval '2160 hours',statement_timestamp()-interval '8760 hours')
  AND NOT EXISTS(SELECT 1 FROM app_access_retention_runs r WHERE r.org_id=o.id AND r.status='running')
  AND COALESCE((SELECT r.started_at<=statement_timestamp()-interval '1 hour' OR (r.status='succeeded' AND r.more_pending) OR COALESCE(r.error_code='lease_expired',false)
   FROM app_access_retention_runs r WHERE r.org_id=o.id ORDER BY r.started_at DESC,r.id DESC LIMIT 1),true))
ORDER BY o.id LIMIT sqlc.arg(page_limit);

-- name: ExpireAppAccessRetentionRun :execrows
UPDATE app_access_retention_runs SET status='failed',error_code='lease_expired',more_pending=true,completed_at=clock_timestamp(),lease_expires_at=NULL
WHERE org_id=sqlc.arg(org_id) AND status='running' AND lease_expires_at<=clock_timestamp();

-- name: IsAppAccessRetentionDue :one
SELECT (app_access_retention_has_work(sqlc.arg(org_id)::uuid,statement_timestamp()-interval '2160 hours',statement_timestamp()-interval '8760 hours')
 AND NOT EXISTS(SELECT 1 FROM app_access_retention_runs r WHERE r.org_id=sqlc.arg(org_id) AND r.status='running')
 AND COALESCE((SELECT r.started_at<=statement_timestamp()-interval '1 hour' OR (r.status='succeeded' AND r.more_pending) OR COALESCE(r.error_code='lease_expired',false)
  FROM app_access_retention_runs r WHERE r.org_id=sqlc.arg(org_id) ORDER BY r.started_at DESC,r.id DESC LIMIT 1),true))::boolean AS due;

-- name: CreateAppAccessRetentionRun :one
WITH moment AS (SELECT clock_timestamp() AS value)
INSERT INTO app_access_retention_runs(org_id,started_at,grant_cutoff_at,audit_cutoff_at,lease_expires_at)
SELECT sqlc.arg(org_id),value,value-interval '2160 hours',value-interval '8760 hours',value+interval '15 minutes' FROM moment RETURNING *;

-- name: RenewAppAccessRetentionRun :execrows
UPDATE app_access_retention_runs SET lease_expires_at=clock_timestamp()+interval '15 minutes'
WHERE org_id=sqlc.arg(org_id) AND id=sqlc.arg(id) AND status='running' AND lease_expires_at>clock_timestamp();

-- name: PruneAppAccessRetentionBatch :one
SELECT app_access_retention_prune_batch(sqlc.arg(run_id)::uuid)::bigint AS deleted;

-- name: AppAccessRetentionMorePending :one
SELECT app_access_retention_has_work(sqlc.arg(org_id)::uuid,sqlc.arg(grant_cutoff)::timestamptz,sqlc.arg(audit_cutoff)::timestamptz)::boolean AS more_pending;

-- name: FinalizeAppAccessRetentionSuccess :one
UPDATE app_access_retention_runs SET status='succeeded',more_pending=sqlc.arg(more_pending),completed_at=clock_timestamp(),lease_expires_at=NULL
WHERE org_id=sqlc.arg(org_id) AND id=sqlc.arg(id) AND status='running' AND lease_expires_at>clock_timestamp() RETURNING *;

-- name: FinalizeAppAccessRetentionFailure :one
UPDATE app_access_retention_runs SET status='failed',error_code=sqlc.arg(error_code)::text,completed_at=clock_timestamp(),lease_expires_at=NULL
WHERE org_id=sqlc.arg(org_id) AND id=sqlc.arg(id) AND status='running' AND lease_expires_at>clock_timestamp() RETURNING *;
