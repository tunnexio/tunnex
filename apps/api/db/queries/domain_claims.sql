-- name: CreateDomainClaim :one
INSERT INTO domain_claims (org_id, domain, verification_token)
VALUES ($1, $2, $3)
RETURNING *;

-- name: GetDomainClaim :one
SELECT * FROM domain_claims
WHERE org_id = $1 AND domain = $2;

-- name: ListDomainClaims :many
SELECT * FROM domain_claims
WHERE org_id = $1
ORDER BY created_at;

-- name: MarkDomainVerified :one
UPDATE domain_claims
SET verified_at = now(), last_checked_at = now()
WHERE org_id = $1 AND domain = $2
RETURNING *;

-- name: TouchDomainCheckedAt :exec
UPDATE domain_claims
SET last_checked_at = now()
WHERE org_id = $1 AND domain = $2;

-- name: SuspendDomainClaim :exec
-- Verification loss: clear verified_at so the domain stops capturing (the claim
-- is NOT deleted — the org keeps its pending claim and can re-verify).
UPDATE domain_claims
SET verified_at = NULL, last_checked_at = now()
WHERE org_id = $1 AND domain = $2;

-- name: GetVerifiedClaimForDomain :one
-- lint:cross-org — JIT resolves the capturing org from an email domain before an
-- org context exists; org_id is a column on the returned row. Only verified
-- claims are returned (partial unique index guarantees at most one).
SELECT * FROM domain_claims
WHERE domain = $1 AND verified_at IS NOT NULL;
