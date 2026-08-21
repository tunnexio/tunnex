-- name: UpsertAgentMCPOAuthConnection :one
INSERT INTO agent_mcp_oauth_connections (org_id, device_id, endpoint, protected_resource, issuer, scopes, client_id, client_secret_sealed, client_secret_fingerprint, state)
SELECT sqlc.arg(org_id), d.id, sqlc.arg(endpoint), sqlc.arg(protected_resource), sqlc.arg(issuer), sqlc.arg(scopes)::jsonb, sqlc.arg(client_id), sqlc.narg(client_secret_sealed), sqlc.narg(client_secret_fingerprint), sqlc.arg(state)
FROM devices d WHERE d.id=sqlc.arg(device_id) AND d.org_id=sqlc.arg(org_id) AND d.kind='agent' AND d.deleted_at IS NULL
ON CONFLICT (device_id, endpoint) DO UPDATE SET protected_resource=EXCLUDED.protected_resource, issuer=EXCLUDED.issuer, scopes=EXCLUDED.scopes, client_id=EXCLUDED.client_id, client_secret_sealed=COALESCE(EXCLUDED.client_secret_sealed, agent_mcp_oauth_connections.client_secret_sealed), client_secret_fingerprint=COALESCE(EXCLUDED.client_secret_fingerprint, agent_mcp_oauth_connections.client_secret_fingerprint), state=EXCLUDED.state, failure_code=NULL
RETURNING *;

-- name: GetAgentMCPOAuthConnection :one
SELECT * FROM agent_mcp_oauth_connections WHERE id=sqlc.arg(id) AND org_id=sqlc.arg(org_id) AND device_id=sqlc.arg(device_id);

-- name: ListAgentMCPOAuthConnections :many
SELECT id, org_id, device_id, endpoint, protected_resource, issuer, scopes, client_id, client_secret_fingerprint, token_expires_at, state, failure_code, connected_by_user_id, connected_at, created_at, updated_at
FROM agent_mcp_oauth_connections WHERE org_id=sqlc.arg(org_id) AND device_id=sqlc.arg(device_id) ORDER BY created_at;

-- name: ConnectAgentMCPOAuthConnection :execrows
UPDATE agent_mcp_oauth_connections SET access_token_sealed=sqlc.arg(access_token_sealed), refresh_token_sealed=sqlc.narg(refresh_token_sealed), token_expires_at=sqlc.narg(token_expires_at), state='connected', failure_code=NULL, connected_by_user_id=sqlc.arg(connected_by_user_id), connected_at=now()
WHERE id=sqlc.arg(id) AND org_id=sqlc.arg(org_id);
