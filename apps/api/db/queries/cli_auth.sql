-- CLI credential flow (S5.1). All secrets arrive here PRE-HASHED (sha-256); the
-- raw token/code never reaches SQL. Consumption is a single atomic UPDATE so a
-- code can never be redeemed twice (no check-then-consume window).

-- name: CreateCliCredential :one
INSERT INTO cli_credentials (user_id, name, token_hash, fingerprint, expires_at)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: GetActiveCliCredentialByHash :one
-- Active = not revoked and not expired. Expired/revoked rows fail auth closed.
SELECT * FROM cli_credentials
WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > now();

-- name: GetCliCredentialByHash :one
-- Any state (auth needs to distinguish "expired" from "unknown" for the CLI's
-- credential_expired UX line).
SELECT * FROM cli_credentials WHERE token_hash = $1;

-- name: TouchCliCredentialUsed :exec
UPDATE cli_credentials SET last_used_at = now() WHERE id = $1;

-- name: ListCliCredentialsForUser :many
SELECT * FROM cli_credentials
WHERE user_id = $1 AND revoked_at IS NULL
ORDER BY created_at DESC;

-- name: RevokeCliCredential :execrows
-- Self-scoped: the WHERE user_id makes another user's credential unreachable
-- (idempotent 204 semantics; no existence leak).
UPDATE cli_credentials SET revoked_at = now()
WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL;

-- name: RevokeAllCliCredentialsForUser :exec
-- The SWEEP: password reset and account deactivation kill every live CLI
-- credential exactly like they kill sessions (a surviving credential would be a
-- back door around the sweep).
UPDATE cli_credentials SET revoked_at = now()
WHERE user_id = $1 AND revoked_at IS NULL;

-- name: CreateCliAuthCode :one
INSERT INTO cli_auth_codes (user_id, code_hash, redirect_uri, code_challenge, expires_at)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: ConsumeCliAuthCode :one
-- Atomic single-use consume; returns the row only on the FIRST valid redemption.
UPDATE cli_auth_codes SET consumed_at = now()
WHERE code_hash = $1 AND consumed_at IS NULL AND expires_at > now()
RETURNING *;

-- name: CreateCliDeviceCode :one
INSERT INTO cli_device_codes (device_code_hash, user_code_hash, expires_at)
VALUES ($1, $2, $3)
RETURNING *;

-- name: ApproveCliDeviceCode :execrows
-- The browser leg binds the human's identity to the pending device code.
UPDATE cli_device_codes SET user_id = $2, approved_at = now()
WHERE user_code_hash = $1 AND approved_at IS NULL AND consumed_at IS NULL AND expires_at > now();

-- name: GetCliDeviceCodeByDeviceHash :one
SELECT * FROM cli_device_codes
WHERE device_code_hash = $1 AND consumed_at IS NULL AND expires_at > now();

-- name: ConsumeCliDeviceCode :one
-- Atomic single-use consume of an APPROVED device code.
UPDATE cli_device_codes SET consumed_at = now()
WHERE device_code_hash = $1 AND approved_at IS NOT NULL AND consumed_at IS NULL AND expires_at > now()
RETURNING *;
