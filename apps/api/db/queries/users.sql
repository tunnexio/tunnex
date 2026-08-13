-- name: GetUserByEmail :one
SELECT * FROM users
WHERE email = $1 AND deleted_at IS NULL;

-- name: GetUserByID :one
SELECT * FROM users
WHERE id = $1 AND deleted_at IS NULL;

-- name: UpsertUser :one
-- Used by the seed with a fixed id; idempotent.
--
-- ⛔ cp_admin IS STATED EXPLICITLY, AND IT IS A FIXTURE'S JOB TO STATE IT. It is a DEPLOYMENT fact —
-- who may bring an organization into existence — and leaving it to the column DEFAULT made the seed silent
-- about a security property it is responsible for.
--
-- ⚠ AND THE OMISSION WAS INVISIBLE ON ANY RIG THAT ALREADY HAD DATA. Migration 0073 backfills the
-- capability for existing owners, so a developer's rig grants it retroactively while every FRESH install
-- runs migrate (matching no rows, since there are no users yet) and then seeds a demo owner with the
-- column at DEFAULT false — unable to create anything, with no "+ New" in the switcher and no walk.
INSERT INTO users (id, email, name, cp_admin)
VALUES ($1, $2, $3, $4)
ON CONFLICT (id) DO UPDATE
    SET email = EXCLUDED.email, name = EXCLUDED.name,
        cp_admin = EXCLUDED.cp_admin
RETURNING *;

-- name: CreateUser :one
INSERT INTO users (email, name, password_hash)
VALUES ($1, $2, $3)
RETURNING *;

-- name: SetUserPassword :exec
UPDATE users
SET password_hash = $2
WHERE id = $1 AND deleted_at IS NULL;

-- name: MarkEmailVerified :exec
UPDATE users
SET email_verified_at = now()
WHERE id = $1 AND deleted_at IS NULL AND email_verified_at IS NULL;

-- name: SetUserStatus :exec
UPDATE users
SET status = $2
WHERE id = $1 AND deleted_at IS NULL;

-- name: UserIsCPAdmin :one
SELECT cp_admin FROM users WHERE id = $1 AND deleted_at IS NULL;

-- name: GrantCPAdmin :exec
-- ⚠ Used ONCE, at bootstrap, inside the same transaction that creates the first organization.
-- ⛔ `deleted_at IS NULL` IS NOT BOILERPLATE HERE — the lint asked and the answer is a real filter, not an
-- annotation. Granting deployment-level authority to a soft-deleted account would arm an identity that is
-- meant to be gone, and a later undelete would restore it silently holding a capability nobody granted it.
UPDATE users SET cp_admin = true, updated_at = now()
WHERE id = $1 AND deleted_at IS NULL;

-- name: SetCPAdmin :execrows
-- The deployment-administrator capability, both directions (S12.11).
--
-- ⛔ GrantCPAdmin IS NOT THIS QUERY WITH A PARAMETER. That one is the BOOTSTRAP grant: it runs inside the
-- transaction that creates the first organization, is unconditional, and can only ever grant. This one is an
-- operator ACT on another account, and the caller must be able to tell "no such live user" from "changed
-- nothing" — hence :execrows, and hence a separate name rather than a shared statement whose two callers
-- would have to agree about what zero rows means.
UPDATE users SET cp_admin = $2, updated_at = now()
WHERE id = $1 AND deleted_at IS NULL;

-- name: CountCPAdmins :one
-- ⛔ THE LAST-HOLDER GUARD READS THIS, so it counts only accounts that can actually SIGN IN and use the
-- capability: soft-deleted rows are excluded (a deleted holder recovers nothing) and so are deactivated
-- ones (SessionAuth 401s them, so they cannot exercise it either). Counting either would let the deployment
-- reach a state where the guard says a holder exists and no human can log in — the exact unrecoverable
-- state it exists to prevent.
SELECT count(*) FROM users
WHERE cp_admin = true AND deleted_at IS NULL AND status = 'active';

-- name: CountUsers :one
-- lint:allow-deleted
-- ⛔ INCLUDES SOFT-DELETED ROWS. The bootstrap condition is "has this deployment ever had a user", not
-- "does it have one now" — otherwise deleting every account reopens admin minting, which is the same
-- re-open CountOrganizationsEver exists to prevent.
SELECT count(*) FROM users;

-- name: CreateBootstrapAdmin :one
INSERT INTO users (email, name, password_hash, email_verified_at, cp_admin, must_change_password)
VALUES ($1, $2, $3, now(), true, true)
RETURNING *;

-- name: ClearMustChangePassword :exec
UPDATE users SET must_change_password = false, updated_at = now()
WHERE id = $1 AND deleted_at IS NULL;

