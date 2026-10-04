-- name: GetAppAccessSettings :one
SELECT live_org.id AS org_id, COALESCE(setting.enabled,false)::boolean AS enabled, COALESCE(setting.version,1)::bigint AS version FROM organizations live_org LEFT JOIN app_access_settings setting ON setting.org_id=live_org.id WHERE live_org.id=$1 AND live_org.deleted_at IS NULL;

-- name: GetAppAccessApplication :one
SELECT id,org_id,version,draft_revision,state,created_at,updated_at FROM app_access_applications WHERE org_id = $1 AND app_access_applications.id = $2 AND EXISTS(SELECT 1 FROM organizations live_org WHERE live_org.id=$1 AND live_org.deleted_at IS NULL);

-- name: GetAppAccessRevision :one
SELECT * FROM app_access_revisions WHERE org_id = $1 AND app_id = $2 AND revision = $3 AND EXISTS(SELECT 1 FROM organizations live_org WHERE live_org.id=$1 AND live_org.deleted_at IS NULL);

-- name: EnsureAppAccessSettings :exec
INSERT INTO app_access_settings(org_id) VALUES($1) ON CONFLICT DO NOTHING;

-- name: UpdateAppAccessSettings :execrows
UPDATE app_access_settings SET enabled=$2,version=version+1 WHERE org_id=$1 AND version=$3;

-- name: LockAppAccessSettings :one
SELECT enabled FROM app_access_settings WHERE org_id=$1 FOR SHARE;

-- name: AppAccessOrganizationExists :one
SELECT EXISTS(SELECT 1 FROM organizations live_org WHERE live_org.id=$1 AND live_org.deleted_at IS NULL);

-- name: AppAccessGatewayExists :one
SELECT EXISTS(SELECT 1 FROM nodes WHERE org_id=$1 AND id=$2 AND status='active' AND enrolled_kind='gateway');

-- name: CreateAppAccessApplication :one
INSERT INTO app_access_applications(org_id) VALUES($1) RETURNING id;

-- name: ReserveAppAccessHostname :exec
INSERT INTO app_access_hostnames(hostname,org_id,app_id) VALUES($1,$2,$3) ON CONFLICT DO NOTHING;

-- name: OwnsAppAccessHostname :one
-- JSON projection preserves historical pre-release schema qualification.
SELECT app_id=$2 AND org_id=$3 FROM app_access_hostnames h WHERE hostname=$1 AND (to_jsonb(h)->>'released_at') IS NULL;

-- name: InsertAppAccessRevision :exec
INSERT INTO app_access_revisions(org_id,app_id,revision,name,description,icon,origin_url,gateway_id,public_hostname,idle_timeout_seconds,absolute_timeout_seconds,digest,allowed_destination_cidrs,origin_ca_pem,origin_ca_digest,icon_data_url) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16);

-- name: LockAppAccessApplication :one
SELECT version FROM app_access_applications WHERE org_id=$1 AND id=$2 FOR UPDATE;

-- name: AdvanceAppAccessDraft :exec
UPDATE app_access_applications SET version=version+1,draft_revision=version+1,updated_at=now() WHERE org_id=$1 AND id=$2 AND state='draft';

-- name: ListAppAccessApplicationIDs :many
SELECT a.id FROM app_access_applications a JOIN app_access_revisions r ON r.org_id=a.org_id AND r.app_id=a.id AND r.revision=a.draft_revision WHERE a.org_id=$1 AND EXISTS(SELECT 1 FROM organizations live_org WHERE live_org.id=$1 AND live_org.deleted_at IS NULL) AND strpos(lower(r.name),lower(sqlc.arg(search)::text))>0 AND (a.state<>'archived' OR sqlc.arg(publication_state)::text='archived') AND (sqlc.arg(publication_state)::text='' OR sqlc.arg(publication_state)::text=CASE WHEN a.state='archived' THEN 'archived' WHEN EXISTS(SELECT 1 FROM app_access_serving_publications p WHERE p.org_id=a.org_id AND p.app_id=a.id AND p.state='active') THEN 'published' WHEN EXISTS(SELECT 1 FROM app_access_serving_publications p WHERE p.org_id=a.org_id AND p.app_id=a.id AND p.state='disabled') THEN 'disabled' ELSE 'unpublished' END) ORDER BY a.created_at,a.id LIMIT sqlc.arg(page_limit) OFFSET sqlc.arg(page_offset);

-- name: LockActiveAppAccessOrganization :one
SELECT id FROM organizations WHERE id=$1 AND deleted_at IS NULL FOR SHARE;

-- name: GetAppAccessMFAPolicy :one
-- JSON projection keeps historical pre-policy schema reads compatible; writes require migration 176.
SELECT COALESCE((to_jsonb(a)->>'require_mfa')::boolean,false)::boolean AS require_mfa
FROM app_access_applications a JOIN organizations o ON o.id=a.org_id AND o.deleted_at IS NULL
WHERE a.org_id=$1 AND a.id=$2;

-- name: UpdateAppAccessMFAPolicy :execrows
UPDATE app_access_applications SET require_mfa=sqlc.arg(require_mfa),version=version+1,updated_at=now()
WHERE org_id=sqlc.arg(org_id) AND id=sqlc.arg(id) AND version=sqlc.arg(expected_version) AND state='draft';
