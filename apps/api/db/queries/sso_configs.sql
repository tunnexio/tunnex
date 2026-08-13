-- name: UpsertSSOConfig :one
INSERT INTO sso_configs (org_id, provider, client_id, client_secret_sealed, secret_fingerprint, tenant_id, enabled)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (org_id, provider) DO UPDATE
    SET client_id = EXCLUDED.client_id,
        client_secret_sealed = EXCLUDED.client_secret_sealed,
        secret_fingerprint = EXCLUDED.secret_fingerprint,
        tenant_id = EXCLUDED.tenant_id,
        enabled = EXCLUDED.enabled
RETURNING *;

-- name: GetSSOConfig :one
SELECT * FROM sso_configs
WHERE org_id = $1 AND provider = $2;

-- name: GetEnabledSSOConfigByProvider :one
-- lint:cross-org — SSO callback resolves the config by (provider, client_id)
-- before an org context exists; org_id is a column on the returned row.
SELECT * FROM sso_configs
WHERE provider = $1 AND client_id = $2 AND enabled = true;
