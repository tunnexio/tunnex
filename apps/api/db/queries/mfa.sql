-- S7.5.5 MFA / TOTP queries. Auth-plane; enrollment OPEN, enforce enterprise (app layer).
-- The user_totp / user_recovery_codes / mfa_challenges tables are USER-scoped credentials (like a
-- user's password), NOT org tenant data — every query below is `-- lint:cross-org` by design.

-- ── user_totp (verify-before-arm + replay guard) ──────────────────────────────────
-- name: UpsertUnconfirmedTOTP :exec
-- lint:cross-org — user-scoped credential (keyed by user, not org).
-- Start/RE-start enrollment: store a fresh SEALED secret, unconfirmed. Re-generating before
-- confirming replaces the old secret and clears the replay clock — an unconfirmed secret never
-- gates login, so overwriting it is safe.
INSERT INTO user_totp (user_id, secret_enc, confirmed, last_used_timestep, created_at, confirmed_at)
VALUES ($1, $2, false, NULL, now(), NULL)
ON CONFLICT (user_id) DO UPDATE
SET secret_enc = EXCLUDED.secret_enc, confirmed = false, last_used_timestep = NULL,
    created_at = now(), confirmed_at = NULL;

-- name: GetTOTP :one
-- lint:cross-org — user-scoped credential.
SELECT * FROM user_totp WHERE user_id = $1;

-- name: GetConfirmedTOTPForUpdate :one
-- lint:cross-org — user-scoped credential.
-- Verify path: read the CONFIRMED secret + replay clock under a row lock, so the replay-guard
-- read+update can't interleave with a concurrent verify.
SELECT * FROM user_totp WHERE user_id = $1 AND confirmed FOR UPDATE;

-- name: ConfirmTOTP :execrows
-- lint:cross-org — user-scoped credential.
-- Arm enrollment: only an UNCONFIRMED row flips to confirmed, stamping the confirming code's
-- timestep as the replay clock so the very first login can't replay the confirmation code.
UPDATE user_totp
SET confirmed = true, confirmed_at = now(), last_used_timestep = sqlc.arg(last_used_timestep)
WHERE user_id = $1 AND NOT confirmed;

-- name: SetTOTPLastTimestep :exec
-- lint:cross-org — user-scoped credential.
-- Replay guard: advance the last-accepted timestep after a successful verify.
UPDATE user_totp SET last_used_timestep = $2 WHERE user_id = $1;

-- name: DeleteTOTP :execrows
-- lint:cross-org — user-scoped credential.
-- Disenroll (self re-enroll clears via upsert; explicit delete for self-disenroll + admin-reset).
DELETE FROM user_totp WHERE user_id = $1;

-- ── user_recovery_codes (single-use, hashed) ──────────────────────────────────────
-- name: InsertRecoveryCode :exec
-- lint:cross-org — user-scoped credential.
INSERT INTO user_recovery_codes (user_id, code_hash) VALUES ($1, $2);

-- name: ConsumeRecoveryCode :one
-- lint:cross-org — user-scoped credential.
-- Atomic single-use: only an UNUSED code for THIS user is burned; returns its id on success,
-- 0 rows if already used / not found (no which-code oracle to the caller).
UPDATE user_recovery_codes
SET used_at = now()
WHERE user_id = $1 AND code_hash = $2 AND used_at IS NULL
RETURNING id;

-- name: CountUnusedRecoveryCodes :one
-- lint:cross-org — user-scoped credential.
SELECT count(*) FROM user_recovery_codes WHERE user_id = $1 AND used_at IS NULL;

-- name: DeleteRecoveryCodesForUser :exec
-- lint:cross-org — user-scoped credential.
DELETE FROM user_recovery_codes WHERE user_id = $1;

-- ── mfa_challenges (the login second-step token — NOT a session) ───────────────────
-- name: CreateMfaChallenge :exec
-- lint:cross-org — user-scoped login challenge (pre-session, no org context).
INSERT INTO mfa_challenges (user_id, token_hash, expires_at) VALUES ($1, $2, $3);

-- name: GetMfaChallengeForUpdate :one
-- lint:cross-org — user-scoped login challenge; the token itself is the credential.
-- Verify path: fetch a LIVE challenge under a row lock (attempt-count + burn serialize here).
SELECT * FROM mfa_challenges WHERE token_hash = $1 AND expires_at > now() FOR UPDATE;

-- name: IncrementMfaChallengeAttempts :one
-- lint:cross-org — user-scoped login challenge.
UPDATE mfa_challenges SET attempts = attempts + 1 WHERE id = $1 RETURNING attempts;

-- name: DeleteMfaChallenge :exec
-- lint:cross-org — user-scoped login challenge.
-- Burn — on SUCCESS or on cap exhaustion (a token never survives its own resolution).
DELETE FROM mfa_challenges WHERE id = $1;

-- name: DeleteExpiredMfaChallenges :exec
-- lint:cross-org — user-scoped login challenge (GC, ledgered to S11).
DELETE FROM mfa_challenges WHERE expires_at <= now();

-- name: DeleteMfaChallengesForUser :exec
-- lint:cross-org — user-scoped login challenges. Full MFA revocation (disenroll / admin-reset) burns
-- the target's outstanding challenges too — a challenge is claimed state; revocation releases it, so
-- a mid-login target gets a clean "sign in again", not attempts-to-exhaustion (finding #6).
DELETE FROM mfa_challenges WHERE user_id = $1;

-- ── org_mfa (enforce flag — slice 2 logic; org-scoped) ─────────────────────────────
-- name: GetOrgMfa :one
SELECT * FROM org_mfa WHERE org_id = $1;

-- name: UpsertOrgMfaEnforce :exec
INSERT INTO org_mfa (org_id, enforce, updated_at) VALUES ($1, $2, now())
ON CONFLICT (org_id) DO UPDATE SET enforce = EXCLUDED.enforce, updated_at = now();

-- name: UserInEnforcingOrg :one
-- lint:cross-org — spans a user's orgs by design: does ANY org the user belongs to enforce MFA?
-- The D8/D5 enforcement predicate (local-auth users only; SSO is exempt at the login seam).
SELECT EXISTS (
    SELECT 1 FROM org_mfa om
    JOIN memberships m ON m.org_id = om.org_id
    WHERE m.user_id = $1 AND om.enforce
);
