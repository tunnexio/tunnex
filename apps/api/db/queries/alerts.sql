-- name: CreateAlertDestination :one
INSERT INTO alert_destinations (
    org_id, kind, name, endpoint_sealed, endpoint_fingerprint, endpoint_host,
    allow_private, severity_floor, cooldown_seconds, quiet_hours_start,
    quiet_hours_end, quiet_hours_timezone, created_by_user_id
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13
)
RETURNING *;

-- name: ListAlertDestinations :many
SELECT * FROM alert_destinations
WHERE org_id = $1
ORDER BY archived_at NULLS FIRST, created_at, id;

-- name: AddAlertSubscription :one
INSERT INTO alert_subscriptions (org_id, destination_id, event_key)
VALUES ($1, $2, $3)
ON CONFLICT (destination_id, event_key) DO NOTHING
RETURNING *;

-- name: ListAlertSubscriptions :many
SELECT * FROM alert_subscriptions
WHERE org_id = $1 AND destination_id = $2
ORDER BY event_key;

-- name: ListAlertDestinationsForEvent :many
SELECT d.*
FROM alert_destinations d
JOIN alert_subscriptions s
  ON s.org_id = d.org_id AND s.destination_id = d.id
WHERE d.org_id = $1
  AND d.archived_at IS NULL
  AND s.event_key = $2
  AND CASE d.severity_floor
        WHEN 'info' THEN 0
        WHEN 'warning' THEN 1
        WHEN 'critical' THEN 2
      END <= CASE $3
               WHEN 'info' THEN 0
               WHEN 'warning' THEN 1
               WHEN 'critical' THEN 2
             END
ORDER BY d.created_at, d.id;

-- name: CreateAlertDelivery :one
INSERT INTO alert_deliveries (
    org_id, destination_id, event_key, severity, dedup_key, payload,
    next_attempt_at, suppressed_count
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING *;

-- name: ListDueAlertDeliveries :many
-- lint:cross-org — the leader-gated dispatcher intentionally claims due
-- deliveries across all tenants. It never exposes this query to a human route.
SELECT * FROM alert_deliveries
WHERE state = 'pending' AND next_attempt_at <= $1
ORDER BY next_attempt_at, id
LIMIT $2
FOR UPDATE SKIP LOCKED;

-- name: CreateAlertDeliveryAttempt :one
INSERT INTO alert_delivery_attempts (
    org_id, delivery_id, attempt, outcome, response_status, error
) VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;
