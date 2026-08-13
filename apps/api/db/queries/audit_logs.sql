-- audit_logs is append-only: there are intentionally NO update or delete queries
-- here, and the DB enforces it (see 0002 triggers).

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
