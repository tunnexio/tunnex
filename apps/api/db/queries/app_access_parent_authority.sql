-- name: CASUserPasswordRehash :execrows
-- lint:cross-org — verified native login has no organization context.
UPDATE users SET password_hash = sqlc.arg(new_hash)
WHERE id = sqlc.arg(user_id) AND deleted_at IS NULL
 AND password_hash = sqlc.arg(expected_hash) AND app_auth_epoch = sqlc.arg(expected_epoch);

-- name: SetUserPasswordAndBumpAppAuthEpoch :one
-- lint:cross-org — native reset credential is user scoped.
UPDATE users SET password_hash = sqlc.arg(new_hash), app_auth_epoch = app_auth_epoch + 1
WHERE id = sqlc.arg(user_id) AND deleted_at IS NULL RETURNING *;

-- name: ChangePasswordCASAndBumpAppAuthEpoch :one
-- lint:cross-org — native password verification is user scoped.
UPDATE users SET password_hash = sqlc.arg(new_hash), app_auth_epoch = app_auth_epoch + 1
WHERE id = sqlc.arg(user_id) AND deleted_at IS NULL
 AND password_hash = sqlc.arg(expected_hash) AND app_auth_epoch = sqlc.arg(expected_epoch) RETURNING *;

-- name: CreateMfaChallengeWithAuthority :execrows
-- lint:cross-org — verified native password login challenge precedes organization selection.
INSERT INTO mfa_challenges (user_id, token_hash, expires_at, verified_app_auth_epoch)
SELECT u.id, sqlc.arg(token_hash), sqlc.arg(expires_at)::timestamptz, u.app_auth_epoch
FROM users u WHERE u.id = sqlc.arg(user_id) AND u.deleted_at IS NULL AND u.status = 'active'
 AND u.app_auth_epoch = sqlc.arg(verified_epoch);

-- name: RecordAppParentLogout :exec
-- lint:cross-org — exact native parent session logout is user scoped.
INSERT INTO app_access_parent_logout_tombstones (parent_hash, user_id, parent_expires_at)
VALUES (sqlc.arg(parent_hash), sqlc.arg(user_id), sqlc.arg(parent_expires_at))
ON CONFLICT (parent_hash) DO UPDATE SET parent_expires_at = GREATEST(app_access_parent_logout_tombstones.parent_expires_at, EXCLUDED.parent_expires_at);

-- name: IsAppParentLogoutRevoked :one
-- lint:cross-org — exact hashed native parent token independently establishes its revocation lookup.
SELECT EXISTS(SELECT 1 FROM app_access_parent_logout_tombstones WHERE parent_hash = sqlc.arg(parent_hash));
