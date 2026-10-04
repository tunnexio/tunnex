-- name: GetAppAccessPublicationOperation :one
SELECT op.* FROM app_access_publication_operations op JOIN organizations o ON o.id=op.org_id AND o.deleted_at IS NULL WHERE op.org_id=sqlc.arg(org_id) AND op.app_id=sqlc.arg(app_id) AND op.id=sqlc.arg(operation_id);

-- name: LockAppAccessPublicationOperation :one
SELECT op.* FROM app_access_publication_operations op JOIN organizations o ON o.id=op.org_id AND o.deleted_at IS NULL WHERE op.org_id=sqlc.arg(org_id) AND op.app_id=sqlc.arg(app_id) AND op.id=sqlc.arg(operation_id) FOR UPDATE OF op;

-- name: GetAppAccessPublicationOperationByKey :one
SELECT op.* FROM app_access_publication_operations op JOIN organizations o ON o.id=op.org_id AND o.deleted_at IS NULL WHERE op.org_id=sqlc.arg(org_id) AND op.app_id=sqlc.arg(app_id) AND op.idempotency_key=sqlc.arg(idempotency_key);

-- name: LastAppAccessPublicationOperation :one
SELECT op.* FROM app_access_publication_operations op JOIN organizations o ON o.id=op.org_id AND o.deleted_at IS NULL WHERE op.org_id=sqlc.arg(org_id) AND op.app_id=sqlc.arg(app_id) ORDER BY op.created_at DESC,op.id DESC LIMIT 1;

-- name: PendingAppAccessPublicationOperation :one
SELECT op.* FROM app_access_publication_operations op JOIN organizations o ON o.id=op.org_id AND o.deleted_at IS NULL WHERE op.org_id=sqlc.arg(org_id) AND op.app_id=sqlc.arg(app_id) AND op.status IN('queued','checking') AND op.deadline>now();

-- name: CreateAppAccessPublicationOperation :one
INSERT INTO app_access_publication_operations(org_id,app_id,actor_user_id,idempotency_key,reviewed_app_version,expected_app_version,revision,digest,origin_check_id,gateway_id,hostname,expected_active_authority_version,authority_version,gateway_cert_serial,deadline)
VALUES(sqlc.arg(org_id),sqlc.arg(app_id),sqlc.arg(actor_user_id),sqlc.arg(idempotency_key),sqlc.arg(reviewed_app_version),sqlc.arg(expected_app_version),sqlc.arg(revision),sqlc.arg(digest),sqlc.arg(origin_check_id),sqlc.arg(gateway_id),sqlc.arg(hostname),sqlc.arg(expected_active_authority_version),sqlc.arg(expected_active_authority_version)::bigint+1,sqlc.arg(gateway_cert_serial),LEAST(sqlc.arg(deadline)::timestamptz,now()+interval '60 seconds')) RETURNING *;

-- name: ExpireAppAccessPublicationOperations :exec
UPDATE app_access_publication_operations SET status='expired',error_code='deadline_exceeded',completed_at=now(),version=version+1 WHERE org_id=sqlc.arg(org_id) AND app_id=sqlc.arg(app_id) AND status IN('queued','checking') AND deadline<=now();

-- name: CancelAppAccessPublicationOperations :execrows
UPDATE app_access_publication_operations SET status='cancelled',error_code='assignment_changed',completed_at=now(),version=version+1 WHERE org_id=sqlc.arg(org_id) AND app_id=sqlc.arg(app_id) AND status IN('queued','checking');

-- name: CancelAppAccessPublicationOperation :one
UPDATE app_access_publication_operations SET status='cancelled',error_code='assignment_changed',completed_at=now(),version=version+1 WHERE org_id=sqlc.arg(org_id) AND app_id=sqlc.arg(app_id) AND id=sqlc.arg(operation_id) AND version=sqlc.arg(expected_version) AND status IN('queued','checking') RETURNING *;

-- name: LockAppAccessServingPublication :one
SELECT p.* FROM app_access_serving_publications p JOIN organizations o ON o.id=p.org_id AND o.deleted_at IS NULL WHERE p.org_id=sqlc.arg(org_id) AND p.app_id=sqlc.arg(app_id) FOR UPDATE OF p;

-- name: GetAppAccessServingPublication :one
SELECT p.* FROM app_access_serving_publications p JOIN organizations o ON o.id=p.org_id AND o.deleted_at IS NULL WHERE p.org_id=sqlc.arg(org_id) AND p.app_id=sqlc.arg(app_id);

-- name: DisableAppAccessServingPublication :execrows
UPDATE app_access_serving_publications SET state='disabled',authority_version=authority_version+1,updated_at=now(),withdrawal_confirmed_at=NULL,withdrawal_confirmed_authority_version=NULL,withdrawal_confirmed_generation=NULL WHERE org_id=sqlc.arg(org_id) AND app_id=sqlc.arg(app_id) AND (state<>'disabled' OR withdrawal_confirmed_at IS NULL);

-- name: ArchiveAppAccessApplication :execrows
UPDATE app_access_applications app SET state='archived',version=app.version+1,updated_at=now() WHERE app.org_id=sqlc.arg(org_id) AND app.id=sqlc.arg(app_id) AND app.version=sqlc.arg(expected_version) AND app.state='draft' AND EXISTS(SELECT 1 FROM app_access_serving_publications p WHERE p.org_id=app.org_id AND p.app_id=app.id AND p.state='disabled' AND p.withdrawal_confirmed_at IS NOT NULL AND p.withdrawal_confirmed_authority_version=p.authority_version AND p.withdrawal_confirmed_generation=p.generation) AND NOT EXISTS(SELECT 1 FROM app_access_publication_operations op WHERE op.org_id=app.org_id AND op.app_id=app.id AND op.status IN('queued','checking')) AND EXISTS(SELECT 1 FROM organizations o WHERE o.id=sqlc.arg(org_id) AND o.deleted_at IS NULL);

-- name: ReportAppAccessBrowserGatewayRuntime :one
INSERT INTO app_access_browser_gateway_runtime(org_id,gateway_id,capability_version,reported_cert_serial) VALUES(sqlc.arg(org_id),sqlc.arg(gateway_id),sqlc.arg(capability_version),sqlc.arg(reported_cert_serial))
ON CONFLICT(org_id,gateway_id) DO UPDATE SET capability_version=EXCLUDED.capability_version,reported_cert_serial=EXCLUDED.reported_cert_serial,reported_at=now() RETURNING *;

-- name: GetAppAccessBrowserGatewayRuntime :one
SELECT r.* FROM app_access_browser_gateway_runtime r JOIN organizations o ON o.id=r.org_id AND o.deleted_at IS NULL WHERE r.org_id=sqlc.arg(org_id) AND r.gateway_id=sqlc.arg(gateway_id);

-- name: ListAppAccessReadinessCandidates :many
-- lint:cross-org -- Dedicated installation proxy derives tenants from persisted pending operations; human/body identifiers do not select work.
SELECT op.*,r.origin_url,r.allowed_destination_cidrs,r.origin_ca_pem,r.origin_ca_digest FROM app_access_publication_operations op
JOIN organizations o ON o.id=op.org_id AND o.deleted_at IS NULL
JOIN app_access_settings s ON s.org_id=op.org_id AND s.enabled
JOIN app_access_revisions r ON r.org_id=op.org_id AND r.app_id=op.app_id AND r.revision=op.revision AND r.digest=op.digest AND r.gateway_id=op.gateway_id AND r.public_hostname=op.hostname
WHERE op.deadline>now() AND (op.status='queued' OR (op.status='checking' AND op.proxy_credential_id=sqlc.arg(proxy_credential_id) AND op.proxy_credential_version=sqlc.arg(proxy_credential_version)))
ORDER BY op.created_at,op.id LIMIT LEAST(GREATEST(sqlc.arg(page_limit)::integer,0),8);

-- name: GetAppAccessReadinessOperationByID :one
-- lint:cross-org -- Dedicated proxy derives immutable tenant/binding from server-issued operation ID before validating body tuple and claimed ownership.
SELECT op.* FROM app_access_publication_operations op JOIN organizations o ON o.id=op.org_id AND o.deleted_at IS NULL WHERE op.id=sqlc.arg(operation_id);

-- name: ClaimAppAccessPublicationReadiness :one
UPDATE app_access_publication_operations SET status='checking',proxy_credential_id=sqlc.arg(proxy_credential_id),proxy_credential_version=sqlc.arg(proxy_credential_version),proxy_instance_token_hash=sqlc.arg(proxy_instance_token_hash),claimed_at=now(),version=version+1
WHERE org_id=sqlc.arg(org_id) AND app_id=sqlc.arg(app_id) AND id=sqlc.arg(operation_id) AND version=sqlc.arg(expected_version) AND status='queued' AND deadline>now() RETURNING *;

-- name: CompleteAppAccessPublicationReadiness :one
UPDATE app_access_publication_operations SET public_dns_status=sqlc.arg(public_dns_status),public_tls_status=sqlc.arg(public_tls_status),connector_dns_status=sqlc.arg(connector_dns_status),connector_connect_status=sqlc.arg(connector_connect_status),connector_tls_status=sqlc.arg(connector_tls_status),error_code=sqlc.arg(error_code),status=sqlc.arg(status),origin_proof_completed_at=now(),public_proof_completed_at=now(),completed_at=CASE WHEN sqlc.arg(status)::text='failed' THEN now() ELSE NULL END,version=version+1
WHERE org_id=sqlc.arg(org_id) AND app_id=sqlc.arg(app_id) AND id=sqlc.arg(operation_id) AND version=sqlc.arg(expected_version) AND readiness_request_id=sqlc.arg(readiness_request_id)
 AND proxy_credential_id=sqlc.arg(proxy_credential_id) AND proxy_credential_version=sqlc.arg(proxy_credential_version) AND proxy_instance_token_hash=sqlc.arg(proxy_instance_token_hash)
 AND gateway_cert_serial=sqlc.arg(gateway_cert_serial) AND status='checking' AND deadline>now() AND origin_proof_completed_at IS NULL AND sqlc.arg(status)::text IN('checking','failed') RETURNING *;

-- name: MarkAppAccessPublicationActivated :one
UPDATE app_access_publication_operations SET status='activated',completed_at=now(),version=version+1 WHERE org_id=sqlc.arg(org_id) AND app_id=sqlc.arg(app_id) AND id=sqlc.arg(operation_id) AND version=sqlc.arg(expected_version) AND status='checking' AND deadline>now() RETURNING *;

-- name: ActivateAppAccessServingPublication :execrows
INSERT INTO app_access_serving_publications(org_id,app_id,gateway_id,revision,digest,hostname,generation,purpose,authority_version,state)
SELECT op.org_id,op.app_id,op.gateway_id,op.revision,op.digest,op.hostname,op.generation,op.purpose,op.authority_version,'active'
FROM app_access_publication_operations op
JOIN organizations o ON o.id=op.org_id AND o.deleted_at IS NULL
JOIN app_access_settings setting ON setting.org_id=op.org_id AND setting.enabled
JOIN app_access_applications app ON app.org_id=op.org_id AND app.id=op.app_id AND app.state='draft' AND app.version=op.expected_app_version AND app.draft_revision=op.revision
JOIN app_access_hostnames h ON h.hostname=op.hostname AND h.org_id=op.org_id AND h.app_id=op.app_id AND (to_jsonb(h)->>'released_at') IS NULL
JOIN app_access_revisions r ON r.org_id=op.org_id AND r.app_id=op.app_id AND r.gateway_id=op.gateway_id AND r.revision=op.revision AND r.digest=op.digest AND r.public_hostname=op.hostname
JOIN nodes n ON n.org_id=op.org_id AND n.id=op.gateway_id AND n.status='active' AND n.enrolled_kind='gateway' AND n.cert_serial=op.gateway_cert_serial AND n.cert_not_after>now()
JOIN app_access_browser_gateway_runtime runtime ON runtime.org_id=op.org_id AND runtime.gateway_id=op.gateway_id AND runtime.capability_version=1 AND runtime.reported_cert_serial=n.cert_serial AND runtime.reported_at>now()-interval '30 seconds'
JOIN app_access_origin_checks c ON c.org_id=op.org_id AND c.app_id=op.app_id AND c.id=op.origin_check_id AND c.gateway_id=op.gateway_id AND c.revision=op.revision AND c.digest=op.digest AND c.purpose='origin_check' AND c.status='succeeded' AND c.completed_cert_serial=n.cert_serial AND c.completed_at>now()-interval '5 minutes'
JOIN app_access_proxy_credentials proxy ON proxy.id=op.proxy_credential_id AND proxy.version=op.proxy_credential_version AND proxy.revoked_at IS NULL
WHERE op.org_id=sqlc.arg(org_id) AND op.app_id=sqlc.arg(app_id) AND op.id=sqlc.arg(operation_id) AND op.version=sqlc.arg(expected_version) AND op.status='checking' AND op.deadline>now()
 AND op.public_dns_status='passed' AND op.public_tls_status='passed' AND op.connector_dns_status='passed' AND op.connector_connect_status='passed' AND op.connector_tls_status=CASE WHEN r.origin_url LIKE 'https://%' THEN 'passed' ELSE 'skipped' END AND op.error_code=''
 AND op.origin_proof_completed_at>now()-interval '10 seconds' AND op.public_proof_completed_at>now()-interval '10 seconds'
 AND COALESCE((SELECT current.authority_version FROM app_access_serving_publications current WHERE current.org_id=op.org_id AND current.app_id=op.app_id),0)=op.expected_active_authority_version
ON CONFLICT(org_id,app_id) DO UPDATE SET gateway_id=EXCLUDED.gateway_id,revision=EXCLUDED.revision,digest=EXCLUDED.digest,hostname=EXCLUDED.hostname,generation=EXCLUDED.generation,purpose=EXCLUDED.purpose,authority_version=EXCLUDED.authority_version,state='active',updated_at=now(),withdrawal_confirmed_at=NULL,withdrawal_confirmed_authority_version=NULL,withdrawal_confirmed_generation=NULL
WHERE app_access_serving_publications.authority_version=EXCLUDED.authority_version-1;

-- name: ListGatewayAppAccessBrowserAssignments :many
SELECT p.app_id,p.gateway_id,p.revision,p.digest,p.hostname,p.generation,p.purpose,p.authority_version,r.origin_url,r.allowed_destination_cidrs,r.origin_ca_pem,r.origin_ca_digest,'active'::text AS stage,NULL::uuid AS operation_id,NULL::uuid AS readiness_request_id,NULL::timestamptz AS deadline FROM app_access_serving_publications p
JOIN organizations o ON o.id=p.org_id AND o.deleted_at IS NULL
JOIN app_access_applications app ON app.org_id=p.org_id AND app.id=p.app_id AND app.state='draft'
JOIN app_access_revisions r ON r.org_id=p.org_id AND r.app_id=p.app_id AND r.gateway_id=p.gateway_id AND r.revision=p.revision AND r.digest=p.digest AND r.public_hostname=p.hostname
WHERE p.org_id=sqlc.arg(org_id) AND p.gateway_id=sqlc.arg(gateway_id) AND p.state='active'
UNION ALL
SELECT op.app_id,op.gateway_id,op.revision,op.digest,op.hostname,op.generation,op.purpose,op.authority_version,r.origin_url,r.allowed_destination_cidrs,r.origin_ca_pem,r.origin_ca_digest,'pending'::text AS stage,op.id AS operation_id,op.readiness_request_id,op.deadline FROM app_access_publication_operations op
JOIN organizations o ON o.id=op.org_id AND o.deleted_at IS NULL
JOIN app_access_applications app ON app.org_id=op.org_id AND app.id=op.app_id AND app.state='draft'
JOIN app_access_revisions r ON r.org_id=op.org_id AND r.app_id=op.app_id AND r.gateway_id=op.gateway_id AND r.revision=op.revision AND r.digest=op.digest AND r.public_hostname=op.hostname
WHERE op.org_id=sqlc.arg(org_id) AND op.gateway_id=sqlc.arg(gateway_id) AND op.status IN('queued','checking') AND op.deadline>now()
ORDER BY app_id,generation LIMIT 64;

-- name: ConfirmAppAccessPublicationWithdrawal :one
-- Only the service's post-commit monotonic wait may call this; wall-clock age is not withdrawal proof.
UPDATE app_access_serving_publications SET withdrawal_confirmed_at=now(),withdrawal_confirmed_authority_version=authority_version,withdrawal_confirmed_generation=generation
WHERE org_id=sqlc.arg(org_id) AND app_id=sqlc.arg(app_id) AND state='disabled' AND authority_version=sqlc.arg(expected_authority_version) AND generation=sqlc.arg(expected_generation)
 AND EXISTS(SELECT 1 FROM organizations o WHERE o.id=sqlc.arg(org_id) AND o.deleted_at IS NULL) RETURNING *;

-- name: CreateDisabledAppAccessPublicationFromOperation :execrows
INSERT INTO app_access_serving_publications(org_id,app_id,gateway_id,revision,digest,hostname,generation,purpose,authority_version,state)
SELECT op.org_id,op.app_id,op.gateway_id,op.revision,op.digest,op.hostname,op.generation,op.purpose,op.authority_version,'disabled'
FROM app_access_publication_operations op JOIN organizations o ON o.id=op.org_id AND o.deleted_at IS NULL
WHERE op.org_id=sqlc.arg(org_id) AND op.app_id=sqlc.arg(app_id) AND op.id=sqlc.arg(operation_id) AND op.status='cancelled' AND op.expected_active_authority_version=0
ON CONFLICT(org_id,app_id) DO NOTHING;

-- name: CreateDisabledAppAccessPublicationFromDraft :execrows
INSERT INTO app_access_serving_publications(org_id,app_id,gateway_id,revision,digest,hostname,authority_version,state)
SELECT app.org_id,app.id,r.gateway_id,r.revision,r.digest,r.public_hostname,1,'disabled'
FROM app_access_applications app JOIN organizations o ON o.id=app.org_id AND o.deleted_at IS NULL
JOIN app_access_revisions r ON r.org_id=app.org_id AND r.app_id=app.id AND r.revision=app.draft_revision
WHERE app.org_id=sqlc.arg(org_id) AND app.id=sqlc.arg(app_id) AND app.version=sqlc.arg(expected_app_version) AND app.state='draft'
ON CONFLICT(org_id,app_id) DO NOTHING;

-- name: AppAccessBrowserGatewayWorkCount :one
SELECT ((SELECT count(*) FROM app_access_serving_publications p WHERE p.org_id=sqlc.arg(org_id) AND p.gateway_id=sqlc.arg(gateway_id) AND p.state='active')+
(SELECT count(*) FROM app_access_publication_operations op WHERE op.org_id=sqlc.arg(org_id) AND op.gateway_id=sqlc.arg(gateway_id) AND op.status IN('queued','checking') AND op.deadline>now()))::bigint;

-- name: FailAppAccessPublicationOperation :one
UPDATE app_access_publication_operations SET status='failed',error_code=sqlc.arg(error_code),completed_at=now(),version=version+1
WHERE org_id=sqlc.arg(org_id) AND app_id=sqlc.arg(app_id) AND id=sqlc.arg(operation_id) AND version=sqlc.arg(expected_version) AND status IN('queued','checking') RETURNING *;

-- name: CountClaimedAppAccessReadiness :one
-- lint:cross-org -- Dedicated installation proxy's bounded outstanding readiness claims span only its own current credential version.
SELECT count(*)::bigint FROM app_access_publication_operations op
WHERE op.proxy_credential_id=sqlc.arg(proxy_credential_id) AND op.proxy_credential_version=sqlc.arg(proxy_credential_version)
 AND op.status='checking' AND op.deadline>now();

-- name: ListClaimedAppAccessReadiness :many
-- lint:cross-org -- Dedicated installation proxy's own current credential version identifies admitted outstanding work; stored operations derive tenant scope.
SELECT op.* FROM app_access_publication_operations op JOIN organizations o ON o.id=op.org_id AND o.deleted_at IS NULL
WHERE op.proxy_credential_id=sqlc.arg(proxy_credential_id) AND op.proxy_credential_version=sqlc.arg(proxy_credential_version)
 AND op.status='checking' AND op.deadline>now() ORDER BY op.claimed_at,op.id LIMIT 8;

-- name: GetPreviouslyActivatedAppAccessRevision :one
SELECT r.* FROM app_access_revisions r JOIN organizations o ON o.id=r.org_id AND o.deleted_at IS NULL
WHERE r.org_id=sqlc.arg(org_id) AND r.app_id=sqlc.arg(app_id) AND r.revision=sqlc.arg(revision)
 AND EXISTS(SELECT 1 FROM app_access_publication_operations op WHERE op.org_id=r.org_id AND op.app_id=r.app_id AND op.revision=r.revision AND op.digest=r.digest AND op.status='activated');

-- name: ListPreviouslyActivatedAppAccessRevisions :many
SELECT r.revision,r.digest,r.name,r.public_hostname AS hostname,r.gateway_id,max(op.completed_at)::timestamptz AS activated_at
FROM app_access_publication_operations op JOIN organizations o ON o.id=op.org_id AND o.deleted_at IS NULL
JOIN app_access_revisions r ON r.org_id=op.org_id AND r.app_id=op.app_id AND r.revision=op.revision AND r.digest=op.digest
WHERE op.org_id=sqlc.arg(org_id) AND op.app_id=sqlc.arg(app_id) AND op.status='activated'
GROUP BY r.revision,r.digest,r.name,r.public_hostname,r.gateway_id ORDER BY r.revision DESC LIMIT LEAST(GREATEST(sqlc.arg(page_limit)::integer,0),50);

-- name: AdvanceAppAccessApplicationAuthorityVersion :one
UPDATE app_access_applications app SET version=app.version+1,updated_at=now()
WHERE app.org_id=sqlc.arg(org_id) AND app.id=sqlc.arg(app_id) AND app.version=sqlc.arg(expected_version) AND app.state='draft'
 AND EXISTS(SELECT 1 FROM organizations o WHERE o.id=sqlc.arg(org_id) AND o.deleted_at IS NULL) RETURNING app.version;

-- name: ClearAppAccessPublicationWithdrawalConfirmation :exec
UPDATE app_access_serving_publications SET withdrawal_confirmed_at=NULL,withdrawal_confirmed_authority_version=NULL,withdrawal_confirmed_generation=NULL
WHERE org_id=sqlc.arg(org_id) AND app_id=sqlc.arg(app_id) AND state='disabled';

-- name: GetAppAccessServingPublicationLabel :one
SELECT r.name FROM app_access_serving_publications p JOIN organizations o ON o.id=p.org_id AND o.deleted_at IS NULL
JOIN app_access_revisions r ON r.org_id=p.org_id AND r.app_id=p.app_id AND r.revision=p.revision AND r.digest=p.digest AND r.gateway_id=p.gateway_id
WHERE p.org_id=sqlc.arg(org_id) AND p.app_id=sqlc.arg(app_id);

-- name: AppAccessPublicationMatchingUserCount :one
SELECT count(*)::bigint FROM (
 SELECT u.id FROM users u JOIN memberships m ON m.user_id=u.id AND m.org_id=sqlc.arg(org_id)
 JOIN organizations o ON o.id=m.org_id AND o.deleted_at IS NULL
 JOIN app_access_applications a ON a.org_id=m.org_id AND a.id=sqlc.arg(app_id)
 WHERE u.deleted_at IS NULL AND u.status='active' AND u.email_verified_at IS NOT NULL AND NOT u.must_change_password AND m.access_revoked_at IS NULL
 AND (CASE WHEN cardinality(m.roles)>0 THEN m.roles ELSE ARRAY[m.role] END) && sqlc.arg(eligible_roles)::text[]
 AND EXISTS(SELECT 1 FROM app_access_grants g WHERE g.org_id=m.org_id AND g.app_id=a.id AND g.enabled AND g.revoked_at IS NULL
 AND (g.starts_at IS NULL OR g.starts_at<=sqlc.arg(evaluated_at)::timestamptz) AND (g.expires_at IS NULL OR sqlc.arg(evaluated_at)::timestamptz<g.expires_at)
 AND ((g.subject_kind='user' AND g.user_id=u.id) OR (g.subject_kind='group' AND EXISTS(
 SELECT 1 FROM group_members gm JOIN user_groups ug ON ug.id=gm.group_id AND ug.org_id=gm.org_id WHERE gm.org_id=g.org_id AND gm.group_id=g.group_id AND gm.user_id=u.id))))
 ORDER BY u.id LIMIT 1001
) matching;
