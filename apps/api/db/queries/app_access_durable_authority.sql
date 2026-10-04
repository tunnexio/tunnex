-- name: GetAppAccessInstallationAuthority :one
-- lint:cross-org -- Installation UUID is global restore authority, never a body-selected tenant.
SELECT * FROM app_access_installation_authority WHERE singleton=true;

-- name: LockAppAccessInstallationAuthority :one
-- lint:cross-org -- Offline installation recovery serializes its generation change.
SELECT * FROM app_access_installation_authority WHERE singleton=true FOR UPDATE;

-- name: RotateAppAccessInstallationAuthority :one
-- lint:cross-org -- Offline listeners-stopped recovery CAS; database UUID alone does not detect rollback of its own backup.
UPDATE app_access_installation_authority SET generation=uuid_generate_v7(),version=version+1,changed_at=now(),recovery_completed_at=NULL WHERE singleton=true AND version=sqlc.arg(expected_version) RETURNING *;

-- name: ConfirmAppAccessInstallationRecovery :one
-- lint:cross-org -- Only post-commit monotonic withdrawal wait may confirm this exact recovery generation/version.
UPDATE app_access_installation_authority SET recovery_completed_at=now() WHERE singleton=true AND generation=sqlc.arg(expected_generation) AND version=sqlc.arg(expected_version) AND recovery_completed_at IS NULL RETURNING *;

-- name: InsertAppAccessSessionRevocation :one
INSERT INTO app_access_session_revocations(org_id,app_id,user_id,live_user_id,session_id,installation_generation,absolute_expires_at,actor_user_id,actor_user_snapshot,actor_system,reason)
SELECT sqlc.arg(org_id),sqlc.arg(app_id),sqlc.arg(user_id),sqlc.narg(live_user_id),sqlc.arg(session_id),sqlc.arg(installation_generation),sqlc.arg(absolute_expires_at),sqlc.narg(actor_user_id),sqlc.narg(actor_user_snapshot),sqlc.narg(actor_system),sqlc.arg(reason)
WHERE EXISTS(SELECT 1 FROM organizations o WHERE o.id=sqlc.arg(org_id) AND o.deleted_at IS NULL)
ON CONFLICT(org_id,app_id,user_id,session_id,installation_generation) DO UPDATE SET id=app_access_session_revocations.id RETURNING *;

-- name: AppAccessSessionRevoked :one
SELECT EXISTS(SELECT 1 FROM app_access_session_revocations r WHERE r.org_id=sqlc.arg(org_id) AND r.app_id=sqlc.arg(app_id) AND r.user_id=sqlc.arg(user_id) AND r.session_id=sqlc.arg(session_id) AND r.installation_generation=sqlc.arg(installation_generation));

-- name: InsertAppAccessEvent :one
INSERT INTO app_access_events(org_id,app_id,installation_generation,revision,serving_generation,user_id,gateway_id,proxy_id,session_id,stream_id,correlation_id,event_kind,outcome,reason,dropped_count)
SELECT sqlc.arg(org_id),sqlc.arg(app_id),sqlc.arg(installation_generation),sqlc.narg(revision),sqlc.narg(serving_generation),sqlc.narg(user_id),sqlc.narg(gateway_id),sqlc.narg(proxy_id),sqlc.narg(session_id),sqlc.narg(stream_id),sqlc.narg(correlation_id),sqlc.arg(event_kind),sqlc.arg(outcome),sqlc.arg(reason),sqlc.arg(dropped_count)
WHERE EXISTS(SELECT 1 FROM organizations o WHERE o.id=sqlc.arg(org_id) AND o.deleted_at IS NULL) RETURNING *;

-- name: ListAppAccessEvents :many
SELECT e.* FROM app_access_events e JOIN organizations o ON o.id=e.org_id AND o.deleted_at IS NULL
WHERE e.org_id=sqlc.arg(org_id) AND e.created_at>=now()-interval '30 days' AND (sqlc.narg(app_id)::uuid IS NULL OR e.app_id=sqlc.narg(app_id))
 AND (sqlc.narg(user_id)::uuid IS NULL OR e.user_id=sqlc.narg(user_id)) AND (sqlc.narg(session_id)::uuid IS NULL OR e.session_id=sqlc.narg(session_id))
 AND (sqlc.narg(before_time)::timestamptz IS NULL OR (e.created_at,e.id)<(sqlc.narg(before_time),sqlc.narg(before_id)::uuid))
ORDER BY e.created_at DESC,e.id DESC LIMIT LEAST(GREATEST(sqlc.arg(page_limit)::integer,0),100);

-- name: PruneAppAccessEvents :execrows
WITH cutoff AS (
 SELECT boundary.created_at,boundary.id FROM app_access_events boundary WHERE boundary.org_id=sqlc.arg(org_id)
 ORDER BY boundary.created_at DESC,boundary.id DESC OFFSET LEAST(GREATEST(sqlc.arg(retained_rows)::integer,1),10000)-1 LIMIT 1
)
DELETE FROM app_access_events e WHERE e.org_id=sqlc.arg(org_id) AND e.id IN(
 SELECT candidate.id FROM app_access_events candidate WHERE candidate.org_id=sqlc.arg(org_id)
 AND (candidate.created_at<sqlc.arg(before_time)::timestamptz OR EXISTS(SELECT 1 FROM cutoff c WHERE (candidate.created_at,candidate.id)<(c.created_at,c.id)))
 ORDER BY candidate.created_at,candidate.id LIMIT LEAST(GREATEST(sqlc.arg(batch_limit)::integer,0),500));

-- name: GetAppAccessSessionRevocation :one
SELECT * FROM app_access_session_revocations WHERE org_id=sqlc.arg(org_id) AND app_id=sqlc.arg(app_id) AND user_id=sqlc.arg(user_id) AND session_id=sqlc.arg(session_id) AND installation_generation=sqlc.arg(installation_generation);

-- name: RevokeAllAppAccessProxyCredentials :execrows
-- lint:cross-org -- Offline installation recovery revokes the dedicated AppProxy family only; no operator or gateway credentials are touched.
UPDATE app_access_proxy_credentials SET revoked_at=now(),version=version+1 WHERE revoked_at IS NULL;

-- name: CancelAllAppAccessPublicationOperations :execrows
-- lint:cross-org -- Offline installation recovery withdraws all pending publication work and invalidates its proxy readiness claims.
UPDATE app_access_publication_operations SET status='cancelled',error_code='assignment_changed',completed_at=now(),version=version+1,proxy_credential_id=NULL,proxy_credential_version=NULL,proxy_instance_token_hash=NULL,claimed_at=NULL WHERE status IN('queued','checking');

-- name: DisableAllAppAccessServingPublications :execrows
-- lint:cross-org -- Offline installation recovery advances every retained serving pointer and clears withdrawal proof before the full monotonic wait.
UPDATE app_access_serving_publications SET state='disabled',authority_version=authority_version+1,updated_at=now(),withdrawal_confirmed_at=NULL,withdrawal_confirmed_authority_version=NULL,withdrawal_confirmed_generation=NULL;

-- name: AdvanceAllUserAppAuthEpoch :execrows
-- lint:allow-deleted -- Recovery must advance inactive and soft-deleted accounts too; restored stale parents must not revive if an account is later restored.
-- lint:cross-org -- Offline installation recovery invalidates restored native parents and password-verified MFA challenges for all accounts, including inactive accounts.
UPDATE users SET app_auth_epoch=app_auth_epoch+1;

-- name: GetAppAccessSessionRevocationForUser :one
SELECT r.* FROM app_access_session_revocations r JOIN organizations o ON o.id=r.org_id AND o.deleted_at IS NULL
WHERE r.org_id=sqlc.arg(org_id) AND r.user_id=sqlc.arg(user_id) AND r.session_id=sqlc.arg(session_id) ORDER BY r.revoked_at DESC,r.id DESC LIMIT 1;

-- name: GetAppAccessSessionRevocationForApplication :one
SELECT r.* FROM app_access_session_revocations r JOIN organizations o ON o.id=r.org_id AND o.deleted_at IS NULL
WHERE r.org_id=sqlc.arg(org_id) AND r.app_id=sqlc.arg(app_id) AND r.session_id=sqlc.arg(session_id) ORDER BY r.revoked_at DESC,r.id DESC LIMIT 1;

-- name: TryInsertAppAccessSessionRevocation :execrows
INSERT INTO app_access_session_revocations(org_id,app_id,user_id,live_user_id,session_id,installation_generation,absolute_expires_at,actor_user_id,actor_user_snapshot,actor_system,reason)
SELECT sqlc.arg(org_id),sqlc.arg(app_id),sqlc.arg(user_id),sqlc.narg(live_user_id),sqlc.arg(session_id),sqlc.arg(installation_generation),sqlc.arg(absolute_expires_at),sqlc.narg(actor_user_id),sqlc.narg(actor_user_snapshot),sqlc.narg(actor_system),sqlc.arg(reason)
WHERE EXISTS(SELECT 1 FROM organizations o WHERE o.id=sqlc.arg(org_id) AND o.deleted_at IS NULL)
ON CONFLICT(org_id,app_id,user_id,session_id,installation_generation) DO NOTHING;


-- name: ListAppAccessEventRetentionOrganizations :many
-- lint:cross-org -- Bounded installation retention worker enumerates tenant IDs only; each prune then uses exact org scope.
SELECT DISTINCT org_id FROM app_access_events WHERE org_id>sqlc.arg(after_org_id)::uuid ORDER BY org_id LIMIT LEAST(GREATEST(sqlc.arg(page_limit)::integer,0),64);
