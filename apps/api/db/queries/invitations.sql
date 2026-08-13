-- name: CreateInvitation :one
INSERT INTO invitations (org_id, email, role, token_hash, expires_at, invited_by_user_id)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: GetInvitationByTokenHash :one
-- lint:cross-org — the token hash IS the authorization key; lookup is by token,
-- not org. Callers must still check expires_at/accepted_at/revoked_at (single-use).
SELECT * FROM invitations
WHERE token_hash = $1;

-- name: AcceptInvitation :one
-- lint:cross-org — authorized by the invitation id obtained via its token, not
-- by org scope. Single-use: only transitions a pending, unexpired invite.
UPDATE invitations
SET accepted_at = now()
WHERE id = $1
  AND accepted_at IS NULL
  AND revoked_at IS NULL
  AND expires_at > now()
RETURNING *;

-- name: RevokeInvitationByOrgEmail :execrows
UPDATE invitations
SET revoked_at = now()
WHERE org_id = $1 AND email = $2 AND accepted_at IS NULL AND revoked_at IS NULL;

-- name: SupersedePendingInvites :exec
-- When a user joins an org another way (e.g. domain-capture JIT), pending
-- invites for that (org, email) become moot — revoke them so they can't be
-- accepted into a second membership attempt.
UPDATE invitations
SET revoked_at = now()
WHERE org_id = $1 AND email = $2 AND accepted_at IS NULL AND revoked_at IS NULL;

-- name: ListInvitations :many
-- ⛔ LEFT JOIN, NOT JOIN. invitations.invited_by_user_id is ON DELETE SET NULL, so the inviter
-- can be gone — and an inner join would silently DROP those rows, hiding outstanding invitations
-- precisely because the person who sent them left. That is the failure this endpoint exists to
-- end, so it must not be reintroduced by the join.
-- ⛔ COALESCE, NOT A BARE CAST. `u.email::text` makes sqlc type the column NON-NULLABLE (*string),
-- but a LEFT JOIN against a deleted inviter yields NULL and the scan fails with
-- "cannot scan NULL into *string" — a 500 on the whole list. Caught on the review stack by the
-- fixture row seeded for exactly this case; without that row it would have shipped and broken the
-- first time an inviter was deleted, which is the one moment the list matters most.
SELECT i.*, COALESCE(u.email::text, '')::text AS invited_by_email
FROM invitations i
-- ⛔ `deleted_at IS NULL` ON THE JOIN, caught by TestQueriesScopeDeletedAt. A SOFT-deleted inviter
-- must read the same as a HARD-deleted one: the column is ON DELETE SET NULL, so a hard delete
-- already yields NULL here and the panel renders "account deleted". Without this filter the two
-- kinds of deletion would render differently for no reason a user could explain — and the soft
-- one would keep publishing the address of an account we were asked to remove.
LEFT JOIN users u ON u.id = i.invited_by_user_id AND u.deleted_at IS NULL
WHERE i.org_id = $1
ORDER BY i.created_at DESC;
