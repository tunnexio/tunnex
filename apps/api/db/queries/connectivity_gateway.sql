-- name: ListGatewayConnectivityKeys :many
-- Candidate IDs only; caller must reauthorize each row through Store.Read.
SELECT device_id, session_id, generation
FROM connectivity_sessions
WHERE org_id = sqlc.arg(org_id) AND gateway_id = sqlc.arg(gateway_id)
  AND device_id > sqlc.arg(after_device_id) AND NOT revoked
  AND expires_at > clock_timestamp()
ORDER BY device_id
LIMIT 64;
