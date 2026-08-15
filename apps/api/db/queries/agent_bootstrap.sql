-- name: CreateAgentBootstrapToken :one
INSERT INTO agent_bootstrap_tokens (org_id, gateway_node_id, agent_name, token_hash, expires_at, issued_by)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: GetAgentBootstrapToken :one
-- lint:cross-org — the public redemption credential is an unguessable hash; org is learned from the token row.
SELECT * FROM agent_bootstrap_tokens
WHERE token_hash = $1 AND consumed_at IS NULL AND expires_at > now();

-- name: ConsumeAgentBootstrapToken :one
-- lint:cross-org — the token hash is the public endpoint's credential and the row is locked before creation.
UPDATE agent_bootstrap_tokens
SET consumed_at = now(), consumed_device_id = $2
WHERE token_hash = $1 AND consumed_at IS NULL AND expires_at > now()
RETURNING *;

-- name: CreateAgentRuntimeCredential :one
INSERT INTO agent_runtime_credentials (org_id, device_id, token_hash)
VALUES ($1, $2, $3)
RETURNING *;

-- name: GetAgentRuntimeCredential :one
-- lint:cross-org — F04's bearer hash is the credential; the returned row supplies its org/device binding.
SELECT * FROM agent_runtime_credentials
WHERE token_hash = $1 AND revoked_at IS NULL;
