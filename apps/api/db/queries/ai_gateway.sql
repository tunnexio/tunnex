-- name: GetAIGatewaySettings :one
SELECT ai_gateway_enabled, ai_gateway_revision FROM organizations WHERE id=$1 AND deleted_at IS NULL;

-- name: SetAIGatewayEnabled :one
UPDATE organizations SET ai_gateway_enabled=$2,
 ai_gateway_revision=ai_gateway_revision+CASE WHEN ai_gateway_enabled IS DISTINCT FROM $2 THEN 1 ELSE 0 END
WHERE id=$1 AND deleted_at IS NULL RETURNING ai_gateway_enabled,ai_gateway_revision;

-- name: CountLiveAICredentials :one
SELECT count(*) FROM ai_gateway_credentials WHERE org_id=$1 AND device_id=$2
 AND runtime_revision=$3 AND revoked_at IS NULL AND expires_at>statement_timestamp();
