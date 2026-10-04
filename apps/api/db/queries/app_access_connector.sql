-- name: LockAppAccessGateway :one
SELECT n.id,n.org_id,n.cert_serial,n.status,n.enrolled_kind,n.cert_not_after FROM nodes n JOIN organizations o ON o.id=n.org_id AND o.deleted_at IS NULL WHERE n.org_id=$1 AND n.id=$2 FOR SHARE OF n;

-- name: GetAppAccessGatewayRuntime :one
SELECT r.* FROM app_access_gateway_runtime r JOIN organizations o ON o.id=r.org_id AND o.deleted_at IS NULL WHERE r.org_id=$1 AND r.gateway_id=$2;

-- name: LockAppAccessGatewayRuntime :one
SELECT * FROM app_access_gateway_runtime WHERE org_id=$1 AND gateway_id=$2 FOR UPDATE;

-- name: ReportAppAccessGatewayRuntime :one
INSERT INTO app_access_gateway_runtime(org_id,gateway_id,capability_version,reported_cert_serial) VALUES($1,$2,$3,$4)
ON CONFLICT(org_id,gateway_id) DO UPDATE SET capability_version=EXCLUDED.capability_version,reported_cert_serial=EXCLUDED.reported_cert_serial,reported_at=now() RETURNING *;

-- name: WithdrawStaleAppAccessAssignments :exec
UPDATE app_access_connector_assignments a SET withdrawn_at=now() WHERE a.org_id=$1 AND a.gateway_id=$2 AND a.withdrawn_at IS NULL AND NOT EXISTS(
 SELECT 1 FROM app_access_applications app JOIN app_access_revisions r ON r.org_id=app.org_id AND r.app_id=app.id AND r.revision=app.draft_revision
 WHERE app.org_id=a.org_id AND app.id=a.app_id AND r.revision=a.revision AND r.digest=a.digest AND r.gateway_id=a.gateway_id);

-- name: WithdrawGatewayAppAccessAssignments :exec
UPDATE app_access_connector_assignments SET withdrawn_at=now() WHERE org_id=$1 AND gateway_id=$2 AND withdrawn_at IS NULL;

-- name: WithdrawInvalidAppAccessChecks :exec
UPDATE app_access_origin_checks c SET status='withdrawn',error_code='assignment_changed',completed_at=now() WHERE c.org_id=$1 AND c.gateway_id=$2 AND c.status IN ('queued','running') AND EXISTS(SELECT 1 FROM app_access_connector_assignments a WHERE a.generation=c.generation AND a.withdrawn_at IS NOT NULL);

-- name: ExpireAppAccessChecks :exec
UPDATE app_access_origin_checks SET status='expired',error_code='deadline_exceeded',completed_at=now() WHERE org_id=$1 AND gateway_id=$2 AND status IN ('queued','running') AND deadline<=now();

-- name: CurrentAppAccessAssignment :one
SELECT * FROM app_access_connector_assignments WHERE org_id=$1 AND app_id=$2 AND withdrawn_at IS NULL;

-- name: CreateAppAccessAssignment :one
INSERT INTO app_access_connector_assignments(org_id,app_id,gateway_id,revision,digest) VALUES($1,$2,$3,$4,$5) RETURNING *;

-- name: AppAccessGatewayWorkCounts :one
SELECT (SELECT count(*) FROM app_access_connector_assignments a WHERE a.org_id=$1 AND a.gateway_id=$2 AND a.withdrawn_at IS NULL)::bigint AS assignments,
 count(*) FILTER(WHERE status='running')::bigint AS running, count(*) FILTER(WHERE status='queued')::bigint AS queued,
 count(*) FILTER(WHERE created_at>now()-interval '1 minute')::bigint AS recent FROM app_access_origin_checks WHERE org_id=$1 AND gateway_id=$2;

-- name: PendingAppAccessCheck :one
SELECT * FROM app_access_origin_checks WHERE org_id=$1 AND app_id=$2 AND generation=$3 AND status IN ('queued','running') AND deadline>now() ORDER BY created_at DESC LIMIT 1;

-- name: CreateAppAccessCheck :one
INSERT INTO app_access_origin_checks(org_id,app_id,gateway_id,revision,digest,generation) VALUES($1,$2,$3,$4,$5,$6) RETURNING *;

-- name: GetAppAccessCheck :one
SELECT c.* FROM app_access_origin_checks c JOIN organizations o ON o.id=c.org_id AND o.deleted_at IS NULL WHERE c.org_id=$1 AND c.app_id=$2 AND c.id=$3;

-- name: LockAppAccessCheck :one
SELECT * FROM app_access_origin_checks WHERE org_id=$1 AND id=$2 FOR UPDATE;

-- name: ClaimAppAccessChecks :exec
UPDATE app_access_origin_checks SET status='running' WHERE id IN(SELECT c.id FROM app_access_origin_checks c WHERE c.org_id=$1 AND c.gateway_id=$2 AND c.status='queued' AND c.deadline>now() ORDER BY c.created_at,c.id LIMIT $3 FOR UPDATE SKIP LOCKED);

-- name: RunningAppAccessChecks :many
SELECT * FROM app_access_origin_checks WHERE org_id=$1 AND gateway_id=$2 AND status='running' AND deadline>now() ORDER BY created_at,id LIMIT 8;

-- name: ListGatewayAppAccessAssignments :many
SELECT a.*,r.origin_url,r.allowed_destination_cidrs,r.origin_ca_pem,r.origin_ca_digest FROM app_access_connector_assignments a JOIN app_access_revisions r ON r.org_id=a.org_id AND r.app_id=a.app_id AND r.revision=a.revision WHERE a.org_id=$1 AND a.gateway_id=$2 AND a.withdrawn_at IS NULL ORDER BY a.created_at,a.generation LIMIT 64;

-- name: GetAppAccessAssignmentGeneration :one
SELECT * FROM app_access_connector_assignments WHERE org_id=$1 AND generation=$2;

-- name: CompleteAppAccessCheck :one
UPDATE app_access_origin_checks SET status=$3,dns_status=$4,connect_status=$5,tls_status=$6,error_code=$7,completed_at=now(),completed_cert_serial=$8 WHERE org_id=$1 AND id=$2 AND status='running' AND deadline>now() RETURNING *;

-- name: ReportAppAccessApplied :exec
UPDATE app_access_connector_assignments SET applied_status=$3,applied_error_code=$4,applied_at=now() WHERE org_id=$1 AND generation=$2;

-- name: PruneAppAccessCheckHistory :exec
DELETE FROM app_access_origin_checks target WHERE target.org_id=$1 AND target.app_id=$2 AND target.status NOT IN('queued','running') AND target.id IN(SELECT c.id FROM app_access_origin_checks c WHERE c.org_id=$1 AND c.app_id=$2 AND c.status NOT IN('queued','running') ORDER BY c.created_at DESC,c.id DESC OFFSET 64) AND NOT EXISTS(SELECT 1 FROM app_access_publication_operations op WHERE op.org_id=target.org_id AND op.app_id=target.app_id AND op.origin_check_id=target.id);

-- name: PruneAppAccessAssignmentHistory :exec
DELETE FROM app_access_connector_assignments a WHERE a.org_id=$1 AND a.app_id=$2 AND a.withdrawn_at IS NOT NULL
 AND a.generation IN(SELECT old.generation FROM app_access_connector_assignments old WHERE old.org_id=$1 AND old.app_id=$2 AND old.withdrawn_at IS NOT NULL ORDER BY old.created_at DESC,old.generation DESC OFFSET 64)
 AND NOT EXISTS(SELECT 1 FROM app_access_origin_checks c WHERE c.generation=a.generation);

-- name: WithdrawAppAccessApplicationAssignment :exec
UPDATE app_access_connector_assignments SET withdrawn_at=now() WHERE org_id=$1 AND app_id=$2 AND withdrawn_at IS NULL;

-- name: FinalizeAppAccessApplicationChecks :exec
UPDATE app_access_origin_checks c SET
 status=CASE WHEN c.deadline<=now() THEN 'expired' ELSE 'withdrawn' END,
 error_code=CASE WHEN c.deadline<=now() THEN 'deadline_exceeded' ELSE 'assignment_changed' END,
 completed_at=now()
WHERE c.org_id=$1 AND c.app_id=$2 AND c.status IN('queued','running')
 AND (c.deadline<=now() OR EXISTS(SELECT 1 FROM app_access_connector_assignments a WHERE a.generation=c.generation AND a.withdrawn_at IS NOT NULL));
