-- Machine credentials (S10.2): an org-scoped, NON-USER principal for the GitOps operator. Mirror of the
-- cli_credentials pattern — sha256 hash storage, fingerprint-only display, revoke-severs-on-next-request.
-- The raw token NEVER reaches SQL. Revoke is org-scoped (a caller can only revoke its own org's creds).

-- name: CreateMachineCredential :one
INSERT INTO machine_credentials (org_id, name, role, token_hash, fingerprint)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: GetMachineCredentialByHash :one
-- lint:cross-org — an auth lookup by the secret HASH; the row resolves the org (the hash IS the credential).
-- Returns the row regardless of revoked state — the auth path applies the NO-ORACLE check (revoked /
-- unknown are indistinguishable at the wire), exactly like the CLI credential path.
SELECT * FROM machine_credentials WHERE token_hash = $1;

-- name: TouchMachineCredentialUsed :exec
-- lint:cross-org — best-effort telemetry keyed by the credential id resolved from the hash lookup above.
UPDATE machine_credentials SET last_used_at = now() WHERE id = $1;

-- name: ListMachineCredentialsForOrg :many
-- ⛔ owner_email IS RESOLVED HERE, FROM `users` AND NOT FROM `memberships` (S15.1, D22 ruled).
--
-- The field was on the DTO, documented as "resolved from owner_user_id for display", and NEVER POPULATED —
-- the web resolved it from the member roster it already fetches. That is correct until the owner LEAVES THE
-- ORG, at which point the roster cannot name them and the accountability screen goes blank on precisely the
-- row accountability exists for.
--
-- ⚠ LEFT JOIN ON `users`, WHICH SURVIVES BOTH LOSSES THE ROSTER DOES NOT: membership deletion (nothing pins
-- it) and deactivation. The FK is ON DELETE RESTRICT, so an assigned credential cannot outlive its user row —
-- the recorded identity is always recoverable, and the LEFT JOIN is for the NULL owner, not for a missing user.
-- lint:allow-deleted — DELIBERATE, AND IT IS THE RULING (D22), NOT A BYPASS.
-- The lint's default is right for every query that ACTS on a user. This one does not act; it RESOLVES A
-- RECORDED IDENTITY for display. Filtering `u.deleted_at IS NULL` here would blank the owner of a credential
-- whose owner was soft-deleted — the exact failure D22 was ruled to end, arrived at from a different
-- direction: the roster could not name a departed member, and `deleted_at` scoping cannot name a deleted one.
-- ⚠ A screen whose purpose is accountability must not lose the name at the moment accountability matters.
SELECT mc.*, u.email AS owner_email
FROM machine_credentials mc
LEFT JOIN users u ON u.id = mc.user_id
WHERE mc.org_id = $1 AND mc.revoked_at IS NULL
ORDER BY mc.created_at DESC;

-- name: RevokeMachineCredential :execrows
-- Org-scoped + idempotent (already-revoked returns 0 rows). Revocation severs on the very next request
-- (the auth path re-reads the row every time — no session cache).
UPDATE machine_credentials SET revoked_at = now()
WHERE id = $1 AND org_id = $2 AND revoked_at IS NULL;

-- name: AssignMachineCredentialOwner :execrows
-- S15.1 (D14/D19 step 2) — an admin NAMES the owner. There is no created_by on this table, so the minting
-- user is not recoverable from the row: the admin is CHOOSING, not confirming, and nothing here guesses.
--
-- ⛔ THE OWNER MUST BE IN THE CREDENTIAL'S ORG, ENFORCED IN THE STATEMENT. A cross-org owner would attribute a
-- machine principal to someone who cannot see it. The EXISTS is org-scoped both ways — credential and user —
-- so a mismatched pair updates zero rows rather than succeeding quietly.
UPDATE machine_credentials mc
SET user_id = $3
WHERE mc.id = $1
  AND mc.org_id = $2
  AND mc.revoked_at IS NULL
  -- ⚠ MEMBERSHIP IS RELATIONAL — `users` has NO org_id (measured, not assumed; the first draft of this
  -- statement joined a column that does not exist and would have matched nothing). Org scoping goes through
  -- `memberships`, and the user must still be live.
  -- ⛔ AND VERIFIED (D21). Enforced IN THE STATEMENT, not only in the handler's pre-check: a client-side
  -- filter is a presentation decision, and the pre-check can be raced by a verification being revoked
  -- between read and write. This is the authorization decision, so it lives where the write happens.
  AND EXISTS (
      SELECT 1 FROM memberships m
      JOIN users u ON u.id = m.user_id
      WHERE m.user_id = $3 AND m.org_id = $2
        AND u.deleted_at IS NULL AND u.status = 'active'
        AND u.email_verified_at IS NOT NULL
  );


-- name: GetOrgMemberVerification :one
-- S15.1 / D21 — is this user eligible to be named as an accountable owner?
--
-- ⛔ RULED NO FOR UNVERIFIED ACCOUNTS. Ownership is an ACCOUNTABILITY CLAIM, and an account that cannot
-- perform org mutations (requireVerifiedUser gates those) cannot be held accountable for what a credential
-- does. Nameable-but-unable-to-act is a contradiction the screen would render as fact.
--
-- ⚠ THIS EXISTS FOR THE MESSAGE, NOT FOR THE TRUTH. The refusal is enforced in the UPDATE statement itself,
-- which cannot be raced; this read only lets the handler say WHICH precondition failed instead of returning
-- an undifferentiated not-found. No oracle is created: the caller holds machine:manage and can already read
-- every member's email_verified from the roster.
--
-- No row = not a live member of this org (already the AssignOwner failure mode).
SELECT (u.email_verified_at IS NOT NULL)::boolean AS email_verified
FROM memberships m
JOIN users u ON u.id = m.user_id
WHERE m.org_id = $1 AND m.user_id = $2
  AND u.deleted_at IS NULL AND u.status = 'active';

-- name: GetMachineOwnerStanding :one
-- ⛔ D23 (RULED): IS THE OWNER DEACTIVATED? Nothing else.
--
-- D14 bound machine credentials to a human so accountability exists; the binding was checked at REST and
-- never at USE, so a credential outlived its owner's deactivation indefinitely. This is the arm that ends
-- that, and it is deliberately the ONLY one:
--
--   ⛔ REMOVED-FROM-ORG IS NOT A REACHABLE STATE. The exposed offboarding is DEACTIVATION, which preserves
--     the membership row and its role; `RemoveMember` hard-deletes but has no HTTP endpoint. A check for a
--     state nothing can produce is dormant machinery — it never fires, so it is never proven, and it reads
--     as protection that has been tested.
--   ⛔ UNVERIFIED IS UNREACHABLE FOR THIS SUBJECT. An operator credential is minted by someone already
--     inside, so the invite-to-verify window does not exist for them — and a machine is exempt from the
--     human email gate by construction anyway.
--
-- ⚠ NO ROW = REFUSE, and that is fail-closed rather than a second check: users are read `deleted_at IS
-- NULL` everywhere, so a soft-deleted owner simply is not here, and "we could not confirm the owner is
-- active" must never resolve to "carry on".
SELECT (u.status = 'active')::boolean AS active
FROM users u
WHERE u.id = $1 AND u.deleted_at IS NULL;

-- name: CountLiveMachineCredentialsOwnedBy :one
-- lint:cross-org — deliberately spans organizations: deactivation is a DEPLOYMENT-wide act on a person,
-- so every credential they own stops, wherever it lives. Counting one org would under-report the blast
-- radius on the screen that exists to state it.
--
-- ⛔ THIS IS THE WARNING'S NUMBER. Deactivating someone now stops every GitOps operator they own, at that
-- moment, and nothing else in the product would have said so.
SELECT count(*) FROM machine_credentials
WHERE user_id = $1 AND revoked_at IS NULL;
