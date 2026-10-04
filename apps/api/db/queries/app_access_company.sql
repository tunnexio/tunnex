-- name: LockAppAccessCompanyActor :one
SELECT u.id,u.name,u.email,m.role,m.roles
FROM users u JOIN memberships m ON m.user_id=u.id
JOIN organizations o ON o.id=m.org_id AND o.deleted_at IS NULL
WHERE m.org_id=$1 AND u.id=$2 AND m.access_revoked_at IS NULL
 AND u.status='active' AND u.deleted_at IS NULL AND u.email_verified_at IS NOT NULL
 AND (NOT u.must_change_password OR u.password_hash IS NULL)
FOR SHARE OF m,u;

-- name: GetAppAccessManagement :one
SELECT a.id,a.version,a.state,a.catalog_visible,a.app_admin_user_id,
 COALESCE(u.name,'')::text AS admin_name,COALESCE(u.email,'')::text AS admin_email,
 COALESCE(m.access_revoked_at IS NULL AND m.user_id IS NOT NULL AND u.status='active' AND u.deleted_at IS NULL,false)::boolean AS admin_available
FROM app_access_applications a
JOIN organizations o ON o.id=a.org_id AND o.deleted_at IS NULL
LEFT JOIN memberships m ON m.org_id=a.org_id AND m.user_id=a.app_admin_user_id
LEFT JOIN users u ON u.id=m.user_id
WHERE a.org_id=$1 AND a.id=$2;

-- name: UpdateAppAccessManagement :execrows
UPDATE app_access_applications SET catalog_visible=sqlc.arg(catalog_visible),
 app_admin_user_id=sqlc.narg(app_admin_user_id),version=version+1,updated_at=now()
WHERE org_id=sqlc.arg(org_id) AND id=sqlc.arg(app_id) AND version=sqlc.arg(expected_version) AND state='draft';

-- name: AppAccessCompanyAppPublished :one
SELECT r.name FROM app_access_applications a
 JOIN app_access_serving_publications p ON p.org_id=a.org_id AND p.app_id=a.id AND p.state='active' AND p.purpose='browser_proxy'
 JOIN app_access_revisions r ON r.org_id=p.org_id AND r.app_id=p.app_id AND r.revision=p.revision AND r.digest=p.digest AND r.gateway_id=p.gateway_id AND r.public_hostname=p.hostname
 WHERE a.org_id=$1 AND a.id=$2 AND a.state='draft' AND a.catalog_visible;

-- name: ListAppAccessCompanyCandidates :many
SELECT a.id,r.name,r.description,branding.icon,branding.icon_data_url,p.hostname,a.require_mfa,
 EXISTS(SELECT 1 FROM app_access_grants g
 WHERE g.org_id=a.org_id AND g.app_id=a.id AND g.enabled AND g.revoked_at IS NULL
 AND (g.starts_at IS NULL OR g.starts_at<=sqlc.arg(evaluated_at)::timestamptz)
 AND (g.expires_at IS NULL OR sqlc.arg(evaluated_at)::timestamptz<g.expires_at)
 AND ((g.subject_kind='user' AND g.user_id=sqlc.arg(user_id)) OR (g.subject_kind='group' AND EXISTS(
 SELECT 1 FROM group_members gm JOIN user_groups ug ON ug.id=gm.group_id AND ug.org_id=gm.org_id
 WHERE gm.org_id=a.org_id AND gm.group_id=g.group_id AND gm.user_id=sqlc.arg(user_id)))))::boolean AS access_granted
FROM app_access_applications a
JOIN organizations o ON o.id=a.org_id AND o.deleted_at IS NULL
JOIN app_access_settings setting ON setting.org_id=a.org_id AND setting.enabled
JOIN app_access_serving_publications p ON p.org_id=a.org_id AND p.app_id=a.id AND p.state='active' AND p.purpose='browser_proxy'
JOIN app_access_revisions r ON r.org_id=p.org_id AND r.app_id=p.app_id AND r.revision=p.revision AND r.digest=p.digest AND r.gateway_id=p.gateway_id AND r.public_hostname=p.hostname
JOIN app_access_revisions branding ON branding.org_id=a.org_id AND branding.app_id=a.id AND branding.revision=a.draft_revision
JOIN nodes n ON n.org_id=a.org_id AND n.id=p.gateway_id AND n.status='active' AND n.enrolled_kind='gateway' AND n.cert_not_after>sqlc.arg(evaluated_at)::timestamptz
WHERE a.org_id=sqlc.arg(org_id) AND a.state='draft' AND a.catalog_visible
 AND (sqlc.arg(search)::text='' OR r.name ILIKE '%'||sqlc.arg(search)::text||'%' OR r.description ILIKE '%'||sqlc.arg(search)::text||'%')
ORDER BY lower(r.name),a.id LIMIT sqlc.arg(page_limit) OFFSET sqlc.arg(page_offset);

-- name: ListManagedAppAccessApps :many
SELECT a.id,r.name,r.description,r.icon,r.icon_data_url,
 (SELECT count(*) FROM app_access_requests rq WHERE rq.org_id=a.org_id AND rq.app_id=a.id AND rq.status='pending')::bigint AS pending_count
FROM app_access_applications a
JOIN organizations o ON o.id=a.org_id AND o.deleted_at IS NULL
JOIN app_access_revisions r ON r.org_id=a.org_id AND r.app_id=a.id AND r.revision=a.draft_revision
WHERE a.org_id=sqlc.arg(org_id) AND (sqlc.arg(global_grant)::boolean OR a.app_admin_user_id=sqlc.arg(actor_id))
 AND (sqlc.narg(app_id)::uuid IS NULL OR a.id=sqlc.narg(app_id))
 AND (a.state='draft' OR EXISTS(SELECT 1 FROM app_access_requests rq WHERE rq.org_id=a.org_id AND rq.app_id=a.id AND rq.status='pending'))
ORDER BY lower(r.name),a.id LIMIT sqlc.arg(page_limit) OFFSET sqlc.arg(page_offset);

-- name: GetAppAccessRequest :one
SELECT rq.*,
 COALESCE(m.user_id IS NOT NULL AND m.access_revoked_at IS NULL AND u.status='active' AND u.deleted_at IS NULL,false)::boolean AS requester_available
FROM app_access_requests rq
JOIN organizations o ON o.id=rq.org_id AND o.deleted_at IS NULL
JOIN app_access_applications a ON a.org_id=rq.org_id AND a.id=rq.app_id
LEFT JOIN memberships m ON m.org_id=rq.org_id AND m.user_id=rq.requester_membership_user_id
LEFT JOIN users u ON u.id=m.user_id
WHERE rq.org_id=$1 AND rq.id=$2;

-- name: LockAppAccessRequest :one
SELECT * FROM app_access_requests WHERE org_id=$1 AND id=$2 FOR UPDATE;

-- name: LatestOwnAppAccessRequest :one
SELECT id FROM app_access_requests WHERE org_id=$1 AND app_id=$2 AND requester_user_id=$3 ORDER BY created_at DESC,id DESC LIMIT 1;

-- name: PendingOwnAppAccessRequest :one
SELECT id FROM app_access_requests WHERE org_id=$1 AND app_id=$2 AND requester_user_id=$3 AND status='pending';

-- name: CreateAppAccessRequest :one
INSERT INTO app_access_requests(org_id,app_id,requester_user_id,requester_membership_user_id,requester_name,requester_email,reason,app_name)
VALUES($1,$2,$3,$3,$4,$5,$6,$7) RETURNING *;

-- name: DecideAppAccessRequest :execrows
UPDATE app_access_requests SET status=sqlc.arg(status),decision_reason=sqlc.arg(decision_reason),
 decided_by=sqlc.arg(decided_by),decided_at=now(),grant_id=sqlc.narg(grant_id),version=version+1
WHERE org_id=sqlc.arg(org_id) AND id=sqlc.arg(id) AND status='pending' AND version=sqlc.arg(expected_version);

-- name: ListAppAccessRequestIDs :many
SELECT rq.id FROM app_access_requests rq
JOIN app_access_applications a ON a.org_id=rq.org_id AND a.id=rq.app_id
WHERE rq.org_id=sqlc.arg(org_id)
 AND ((sqlc.arg(own)::boolean AND rq.requester_user_id=sqlc.arg(actor_id))
 OR (NOT sqlc.arg(own)::boolean AND (sqlc.arg(global_grant)::boolean OR a.app_admin_user_id=sqlc.arg(actor_id))))
 AND (sqlc.arg(status)::text='' OR rq.status=sqlc.arg(status))
 AND (sqlc.narg(app_id)::uuid IS NULL OR rq.app_id=sqlc.narg(app_id))
ORDER BY rq.created_at DESC,rq.id DESC LIMIT sqlc.arg(page_limit) OFFSET sqlc.arg(page_offset);

-- name: CountPendingAppAccessRequests :one
SELECT count(*)::bigint FROM app_access_requests rq
JOIN app_access_applications a ON a.org_id=rq.org_id AND a.id=rq.app_id
WHERE rq.org_id=sqlc.arg(org_id) AND rq.status='pending'
 AND ((sqlc.arg(own)::boolean AND rq.requester_user_id=sqlc.arg(actor_id))
 OR (NOT sqlc.arg(own)::boolean AND (sqlc.arg(global_grant)::boolean OR a.app_admin_user_id=sqlc.arg(actor_id))))
 AND (sqlc.narg(app_id)::uuid IS NULL OR rq.app_id=sqlc.narg(app_id));

-- name: ListAppAccessGrantUserSubjects :many
SELECT u.id,u.name,u.email FROM users u JOIN memberships m ON m.user_id=u.id
WHERE m.org_id=sqlc.arg(org_id) AND m.access_revoked_at IS NULL AND u.status='active' AND u.deleted_at IS NULL
 AND (sqlc.arg(search)::text='' OR u.name ILIKE '%'||sqlc.arg(search)::text||'%' OR u.email ILIKE '%'||sqlc.arg(search)::text||'%')
ORDER BY lower(u.name),u.id LIMIT sqlc.arg(page_limit) OFFSET sqlc.arg(page_offset);

-- name: ListAppAccessGrantGroupSubjects :many
SELECT id,name FROM user_groups WHERE org_id=sqlc.arg(org_id)
 AND (sqlc.arg(search)::text='' OR name ILIKE '%'||sqlc.arg(search)::text||'%')
ORDER BY lower(name),id LIMIT sqlc.arg(page_limit) OFFSET sqlc.arg(page_offset);

-- name: GetCurrentAppAccessUserGrant :one
SELECT * FROM app_access_grants WHERE org_id=$1 AND app_id=$2 AND subject_kind='user' AND subject_id=$3 AND revoked_at IS NULL FOR UPDATE;

-- name: LockAppAccessGrantUserDirectory :one
-- lint:allow-deleted -- Lock only the same-org directory identity before FK cleanup; this query grants no subject eligibility or read projection.
-- Lock unavailable subjects too: directory deletion must finish before the app
-- and grant rows are locked; this does not make the subject eligible for access.
SELECT u.id FROM users u JOIN memberships m ON m.user_id=u.id
WHERE m.org_id=$1 AND u.id=$2 FOR SHARE OF m,u;
