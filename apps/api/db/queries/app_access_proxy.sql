-- name: CreateAppAccessProxyCredential :one
INSERT INTO app_access_proxy_credentials(name,token_hash)VALUES($1,$2)RETURNING *;

-- name: AuthenticateAppAccessProxyCredential :one
-- lint:cross-org -- Installation-wide dedicated proxy identity; no tenant authority is stored here.
SELECT * FROM app_access_proxy_credentials WHERE token_hash=$1 AND revoked_at IS NULL;

-- name: CurrentAppAccessProxyCredential :one
-- lint:cross-org -- Installation-wide dedicated proxy identity, rechecked before every internal port.
SELECT * FROM app_access_proxy_credentials WHERE id=$1 AND version=$2 AND revoked_at IS NULL;

-- name: LockAppAccessProxyCredential :one
-- lint:cross-org -- Operator-local provisioning of installation-wide service credentials.
SELECT * FROM app_access_proxy_credentials WHERE id=$1 FOR UPDATE;

-- name: RevokeAppAccessProxyCredential :one
-- lint:cross-org -- Operator-local revocation of installation-wide service credentials.
UPDATE app_access_proxy_credentials SET version=version+1,revoked_at=now()WHERE id=$1 AND revoked_at IS NULL RETURNING *;

-- name: LookupAppAccessServingRoute :one
-- lint:cross-org -- Dedicated authenticated proxy derives tenant from globally unique exact publication hostname; live org and exact revision/gateway/host joins constrain projection.
SELECT p.*,r.origin_url,r.allowed_destination_cidrs,r.origin_ca_pem,r.origin_ca_digest
FROM app_access_serving_publications p
JOIN organizations o ON o.id=p.org_id AND o.deleted_at IS NULL
JOIN app_access_applications live_app ON live_app.org_id=p.org_id AND live_app.id=p.app_id AND live_app.state='draft'
JOIN app_access_hostnames h ON h.hostname=p.hostname AND h.org_id=p.org_id AND h.app_id=p.app_id AND (to_jsonb(h)->>'released_at') IS NULL
JOIN app_access_revisions r ON r.org_id=p.org_id AND r.app_id=p.app_id AND r.gateway_id=p.gateway_id AND r.revision=p.revision AND r.digest=p.digest AND r.public_hostname=p.hostname
JOIN nodes n ON n.org_id=p.org_id AND n.id=p.gateway_id AND n.status='active' AND n.enrolled_kind='gateway' AND n.cert_not_after>now()
WHERE p.hostname=$1 AND p.state='active' AND p.purpose='browser_proxy';

-- name: GetAppAccessServingApplicationHostname :one
SELECT p.hostname FROM app_access_serving_publications p
JOIN app_access_applications a ON a.org_id=p.org_id AND a.id=p.app_id AND a.state='draft'
JOIN app_access_hostnames h ON h.hostname=p.hostname AND h.org_id=p.org_id AND h.app_id=p.app_id AND (to_jsonb(h)->>'released_at') IS NULL
WHERE p.org_id = sqlc.arg(org_id) AND p.app_id = sqlc.arg(app_id)
 AND p.state = 'active' AND p.purpose = 'browser_proxy'
 AND EXISTS(SELECT 1 FROM organizations o WHERE o.id=p.org_id AND o.deleted_at IS NULL);

-- name: ListMyAppAccessPublishedCandidates :many
-- Publication and explicit current grants are filtered before paging. Only saved
-- branding comes from the latest draft; names, routes and access stay published.
SELECT p.app_id, p.gateway_id, p.revision, p.digest, p.hostname, p.generation, p.authority_version,
 r.name, r.description, branding.icon, branding.icon_data_url
FROM app_access_serving_publications p
JOIN organizations o ON o.id=p.org_id AND o.deleted_at IS NULL
JOIN app_access_settings setting ON setting.org_id=p.org_id AND setting.enabled
JOIN app_access_revisions r ON r.org_id=p.org_id AND r.app_id=p.app_id AND r.gateway_id=p.gateway_id AND r.revision=p.revision AND r.digest=p.digest AND r.public_hostname=p.hostname
JOIN app_access_applications a ON a.org_id=p.org_id AND a.id=p.app_id AND a.state='draft'
JOIN app_access_revisions branding ON branding.org_id=a.org_id AND branding.app_id=a.id AND branding.revision=a.draft_revision
JOIN nodes n ON n.org_id=p.org_id AND n.id=p.gateway_id AND n.status='active' AND n.enrolled_kind='gateway' AND n.cert_not_after>sqlc.arg(evaluated_at)::timestamptz
JOIN memberships m ON m.org_id=p.org_id AND m.user_id=sqlc.arg(user_id) AND m.access_revoked_at IS NULL
JOIN users u ON u.id=m.user_id AND u.status='active' AND u.deleted_at IS NULL AND u.email_verified_at IS NOT NULL AND (NOT u.must_change_password OR u.password_hash IS NULL)
WHERE p.org_id=sqlc.arg(org_id) AND p.state='active' AND p.purpose='browser_proxy'
 AND (CASE WHEN cardinality(m.roles)>0 THEN m.roles ELSE ARRAY[m.role] END) && sqlc.arg(eligible_roles)::text[]
 AND (sqlc.arg(search)::text='' OR r.name ILIKE '%'||sqlc.arg(search)::text||'%' OR r.description ILIKE '%'||sqlc.arg(search)::text||'%')
 AND EXISTS(SELECT 1 FROM app_access_grants g
 WHERE g.org_id=p.org_id AND g.app_id=p.app_id AND g.enabled AND g.revoked_at IS NULL
 AND (g.starts_at IS NULL OR g.starts_at<=sqlc.arg(evaluated_at)::timestamptz)
 AND (g.expires_at IS NULL OR sqlc.arg(evaluated_at)::timestamptz<g.expires_at)
 AND ((g.subject_kind='user' AND g.user_id=u.id) OR (g.subject_kind='group' AND EXISTS(
 SELECT 1 FROM group_members gm JOIN user_groups ug ON ug.id=gm.group_id AND ug.org_id=gm.org_id
 WHERE gm.org_id=p.org_id AND gm.group_id=g.group_id AND gm.user_id=u.id))))
ORDER BY lower(r.name),p.app_id LIMIT sqlc.arg(page_limit) OFFSET sqlc.arg(page_offset);
