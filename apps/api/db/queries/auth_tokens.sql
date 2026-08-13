-- name: CreateAuthToken :one
INSERT INTO auth_tokens (user_id, purpose, token_hash, expires_at)
VALUES ($1, $2, $3, $4)
RETURNING *;

-- name: ConsumeAuthToken :one
-- Single-use + purpose-bound: only matches an unconsumed, unexpired token of the
-- given purpose. A reset token therefore cannot be consumed as a verification
-- token and vice-versa.
UPDATE auth_tokens
SET consumed_at = now()
WHERE token_hash = $1
  AND purpose = $2
  AND consumed_at IS NULL
  AND expires_at > now()
RETURNING *;

-- name: InvalidateUserTokens :exec
-- Consume all outstanding tokens of a purpose for a user (e.g. before issuing a
-- new password-reset token, so only the latest is valid).
UPDATE auth_tokens
SET consumed_at = now()
WHERE user_id = $1 AND purpose = $2 AND consumed_at IS NULL;
