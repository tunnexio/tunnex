-- name: GetAppAccessGrant :one
SELECT * FROM app_access_grants WHERE app_access_grants.org_id=$1 AND app_access_grants.id=$2 AND EXISTS(SELECT 1 FROM organizations live_org WHERE live_org.id=$1 AND live_org.deleted_at IS NULL);

-- name: LockAppAccessGrant :one
SELECT * FROM app_access_grants WHERE app_access_grants.org_id=$1 AND app_access_grants.id=$2 AND EXISTS(SELECT 1 FROM organizations live_org WHERE live_org.id=$1 AND live_org.deleted_at IS NULL) FOR UPDATE;

-- name: ListAppAccessGrants :many
SELECT * FROM app_access_grants WHERE app_access_grants.org_id=sqlc.arg(org_id) AND EXISTS(SELECT 1 FROM organizations live_org WHERE live_org.id=sqlc.arg(org_id) AND live_org.deleted_at IS NULL)
 AND (sqlc.narg(app_id)::uuid IS NULL OR app_id=sqlc.narg(app_id))
 AND (sqlc.arg(subject_kind)::text='' OR subject_kind=sqlc.arg(subject_kind))
 AND (sqlc.narg(subject_id)::uuid IS NULL OR subject_id=sqlc.narg(subject_id))
 ORDER BY created_at,id LIMIT sqlc.arg(page_limit) OFFSET sqlc.arg(page_offset);


-- name: ListFilteredAppAccessGrants :many
-- Search and status are resolved in this same statement before pagination.
SELECT sqlc.embed(g), r.name AS app_label, eligibility.available AS subject_available
FROM app_access_grants g
JOIN organizations o ON o.id=g.org_id AND o.deleted_at IS NULL
JOIN app_access_applications a ON a.org_id=g.org_id AND a.id=g.app_id
JOIN app_access_revisions r ON r.org_id=a.org_id AND r.app_id=a.id AND r.revision=a.draft_revision
CROSS JOIN LATERAL (
 SELECT ((g.subject_kind='user' AND EXISTS(
  SELECT 1 FROM users u JOIN memberships m ON m.user_id=u.id
  WHERE m.org_id=g.org_id AND u.id=g.user_id AND u.status='active'
   AND u.deleted_at IS NULL AND m.access_revoked_at IS NULL))
 OR (g.subject_kind='group' AND EXISTS(
  SELECT 1 FROM user_groups ug WHERE ug.org_id=g.org_id AND ug.id=g.group_id)))::boolean AS available
) eligibility
CROSS JOIN LATERAL (SELECT CASE
   WHEN g.revoked_at IS NOT NULL THEN 'revoked'
   WHEN NOT eligibility.available THEN 'subject_unavailable'
   WHEN NOT g.enabled THEN 'disabled'
   WHEN g.starts_at IS NOT NULL AND sqlc.arg(evaluated_at)::timestamptz<g.starts_at THEN 'scheduled'
   WHEN g.expires_at IS NOT NULL AND sqlc.arg(evaluated_at)::timestamptz>=g.expires_at THEN 'expired'
   ELSE 'active'
  END::text AS status) computed
WHERE g.org_id=sqlc.arg(org_id)
 AND (sqlc.narg(app_id)::uuid IS NULL OR g.app_id=sqlc.narg(app_id))
 AND (sqlc.arg(subject_kind)::text='' OR g.subject_kind=sqlc.arg(subject_kind))
 AND (sqlc.narg(subject_id)::uuid IS NULL OR g.subject_id=sqlc.narg(subject_id))
 AND (sqlc.arg(search)::text=''
  OR strpos(lower(g.subject_label),lower(sqlc.arg(search)::text))>0
  OR strpos(lower(r.name),lower(sqlc.arg(search)::text))>0
  OR (g.subject_kind='user' AND EXISTS(
   SELECT 1 FROM users u JOIN memberships m ON m.user_id=u.id
   WHERE m.org_id=g.org_id AND u.id=g.user_id AND u.deleted_at IS NULL
    AND (strpos(lower(u.name),lower(sqlc.arg(search)::text))>0 OR strpos(lower(u.email::text),lower(sqlc.arg(search)::text))>0)))
  OR (g.subject_kind='group' AND EXISTS(
   SELECT 1 FROM user_groups ug WHERE ug.org_id=g.org_id AND ug.id=g.group_id
    AND strpos(lower(ug.name),lower(sqlc.arg(search)::text))>0)))

 AND (sqlc.arg(status)::text='' OR computed.status=sqlc.arg(status)::text)
 AND (sqlc.arg(view)::text='' OR
      (sqlc.arg(view)::text='current' AND (sqlc.arg(status)::text<>'' OR computed.status IN ('active','disabled'))) OR
      (sqlc.arg(view)::text='history' AND computed.status IN ('revoked','expired')))
ORDER BY g.created_at,g.id LIMIT sqlc.arg(page_limit) OFFSET sqlc.arg(page_offset);

-- name: LockAppAccessUserSubject :one
SELECT u.name,u.email FROM memberships m JOIN users u ON u.id=m.user_id
WHERE m.org_id=$1 AND m.user_id=$2 AND m.access_revoked_at IS NULL AND u.status='active' AND u.deleted_at IS NULL FOR SHARE OF m,u;

-- name: LockAppAccessGroupSubject :one
SELECT name FROM user_groups WHERE org_id=$1 AND id=$2 FOR SHARE;

-- name: CreateAppAccessGrant :one
INSERT INTO app_access_grants(org_id,app_id,subject_kind,subject_id,subject_label,user_id,group_id,enabled,starts_at,expires_at)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *;

-- name: UpdateAppAccessGrant :one
UPDATE app_access_grants SET enabled=$3,starts_at=$4,expires_at=$5,version=version+1,updated_at=now() WHERE org_id=$1 AND id=$2 RETURNING *;

-- name: RevokeAppAccessGrant :one
UPDATE app_access_grants SET enabled=false,revoked_at=now(),version=version+1,updated_at=now() WHERE org_id=$1 AND id=$2 RETURNING *;

-- name: AppAccessEvaluationUser :one
SELECT u.email_verified_at,u.must_change_password,u.status,m.access_revoked_at,m.role,m.roles FROM users u JOIN memberships m ON m.user_id=u.id
WHERE m.org_id=$1 AND u.id=$2 AND u.deleted_at IS NULL;

-- name: MatchingAppAccessGrants :many
SELECT g.id,g.expires_at FROM app_access_grants g
JOIN organizations o ON o.id=g.org_id AND o.deleted_at IS NULL
JOIN memberships m ON m.org_id=g.org_id AND m.user_id=sqlc.arg(user_id) AND m.access_revoked_at IS NULL
JOIN users u ON u.id=m.user_id AND u.status='active' AND u.deleted_at IS NULL
WHERE g.org_id=sqlc.arg(org_id) AND g.app_id=sqlc.arg(app_id) AND g.enabled AND g.revoked_at IS NULL
 AND (g.starts_at IS NULL OR g.starts_at<=sqlc.arg(evaluated_at)::timestamptz)
 AND (g.expires_at IS NULL OR sqlc.arg(evaluated_at)::timestamptz<g.expires_at)
 AND ((g.subject_kind='user' AND g.user_id=u.id) OR (g.subject_kind='group' AND EXISTS(
 SELECT 1 FROM group_members gm JOIN user_groups ug ON ug.id=gm.group_id AND ug.org_id=gm.org_id
 WHERE gm.org_id=g.org_id AND gm.group_id=g.group_id AND gm.user_id=u.id))) ORDER BY g.id;

-- name: AppAccessGrantSubjectAvailable :one
SELECT (g.subject_kind='user' AND EXISTS(SELECT 1 FROM users u JOIN memberships m ON m.user_id=u.id WHERE m.org_id=g.org_id AND u.id=g.user_id AND u.status='active' AND u.deleted_at IS NULL AND m.access_revoked_at IS NULL)) OR (g.subject_kind='group' AND EXISTS(SELECT 1 FROM user_groups ug WHERE ug.org_id=g.org_id AND ug.id=g.group_id))
FROM app_access_grants g WHERE g.org_id=$1 AND g.id=$2 AND EXISTS(SELECT 1 FROM organizations live_org WHERE live_org.id=$1 AND live_org.deleted_at IS NULL);

-- name: AppAccessRevokeImpact :one
WITH selected AS (
 SELECT g.* FROM app_access_grants g JOIN organizations o ON o.id=g.org_id AND o.deleted_at IS NULL
 WHERE g.org_id=sqlc.arg(org_id) AND g.id=sqlc.arg(grant_id)
), eligible AS (
 SELECT u.id FROM users u JOIN memberships m ON m.user_id=u.id AND m.org_id=sqlc.arg(org_id)
 WHERE u.deleted_at IS NULL AND u.status='active' AND u.email_verified_at IS NOT NULL AND NOT u.must_change_password AND m.access_revoked_at IS NULL
 AND (CASE WHEN cardinality(m.roles)>0 THEN m.roles ELSE ARRAY[m.role] END) && sqlc.arg(eligible_roles)::text[]
), affected AS (
 SELECT u.id FROM eligible u CROSS JOIN selected s WHERE s.enabled AND s.revoked_at IS NULL
 AND (s.starts_at IS NULL OR s.starts_at<=sqlc.arg(evaluated_at)::timestamptz)
 AND (s.expires_at IS NULL OR sqlc.arg(evaluated_at)::timestamptz<s.expires_at)
 AND ((s.subject_kind='user' AND s.user_id=u.id) OR (s.subject_kind='group' AND EXISTS(
 SELECT 1 FROM group_members gm JOIN user_groups ug ON ug.id=gm.group_id AND ug.org_id=gm.org_id WHERE gm.org_id=s.org_id AND gm.group_id=s.group_id AND gm.user_id=u.id)))
)
SELECT COALESCE((SELECT version FROM selected),0)::bigint AS grant_version, count(*)::bigint AS matching_user_count, count(*) FILTER(WHERE NOT EXISTS(
 SELECT 1 FROM app_access_grants g CROSS JOIN selected s
 WHERE g.org_id=s.org_id AND g.app_id=s.app_id AND g.id<>s.id AND g.enabled AND g.revoked_at IS NULL
 AND (g.starts_at IS NULL OR g.starts_at<=sqlc.arg(evaluated_at)::timestamptz)
 AND (g.expires_at IS NULL OR sqlc.arg(evaluated_at)::timestamptz<g.expires_at)
 AND ((g.subject_kind='user' AND g.user_id=affected.id) OR (g.subject_kind='group' AND EXISTS(
 SELECT 1 FROM group_members gm JOIN user_groups ug ON ug.id=gm.group_id AND ug.org_id=gm.org_id WHERE gm.org_id=g.org_id AND gm.group_id=g.group_id AND gm.user_id=affected.id)))
))::bigint AS users_losing_grant_match_count FROM affected;
