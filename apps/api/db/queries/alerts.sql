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

-- name: GetAlertDeliveryCooldownForUpdate :one
SELECT * FROM alert_delivery_cooldowns
WHERE org_id = $1 AND destination_id = $2 AND event_key = $3 AND dedup_key = $4
FOR UPDATE;

-- name: CreateAlertDeliveryCooldown :one
INSERT INTO alert_delivery_cooldowns (
    org_id, destination_id, event_key, dedup_key, next_eligible_at
) VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: IncrementAlertDeliveryCooldown :one
UPDATE alert_delivery_cooldowns
SET suppressed_count = suppressed_count + 1
WHERE org_id = $1 AND destination_id = $2 AND event_key = $3 AND dedup_key = $4
RETURNING *;

-- name: ReserveAlertDeliveryCooldown :one
UPDATE alert_delivery_cooldowns
SET next_eligible_at = $5, suppressed_count = 0
WHERE org_id = $1 AND destination_id = $2 AND event_key = $3 AND dedup_key = $4
RETURNING *;

-- name: ListDueAlertDeliveries :many
-- lint:cross-org — the leader-gated dispatcher intentionally claims due
-- deliveries across all tenants. It never exposes this query to a human route.
SELECT * FROM alert_deliveries
WHERE state = 'pending' AND next_attempt_at <= $1
ORDER BY next_attempt_at, id
LIMIT $2
FOR UPDATE SKIP LOCKED;

-- name: ClaimDueAlertDeliveries :many
-- lint:cross-org — the leader-gated dispatcher claims only its bounded due
-- batch, atomically moving each delivery out of the pending queue.
WITH due AS (
    SELECT alert_deliveries.id
    FROM alert_deliveries
    WHERE alert_deliveries.state = 'pending' AND alert_deliveries.next_attempt_at <= $1
    ORDER BY alert_deliveries.next_attempt_at, alert_deliveries.id
    LIMIT $2
    FOR UPDATE SKIP LOCKED
)
UPDATE alert_deliveries d
SET state = 'delivering', attempts = d.attempts + 1
FROM due
WHERE d.id = due.id
RETURNING d.*;

-- name: RecoverStaleAlertDeliveries :execrows
-- lint:cross-org — the leader-gated dispatcher requeues stale claims across
-- every tenant; no human route can call this query.
-- A delivery is claimed before outbound I/O. If that worker dies, a later
-- leader requeues only claims older than the bounded dispatcher lease.
UPDATE alert_deliveries
SET state = 'pending', next_attempt_at = $1, last_error = 'delivery worker lease expired'
WHERE state = 'delivering' AND updated_at < $2;

-- name: GetAlertDestinationForDelivery :one
SELECT d.*
FROM alert_destinations d
JOIN alert_deliveries l
  ON l.org_id = d.org_id AND l.destination_id = d.id
WHERE l.id = $1 AND l.org_id = $2 AND d.archived_at IS NULL;

-- name: FinishAlertDelivery :one
UPDATE alert_deliveries
SET state = $3,
    next_attempt_at = $4,
    last_error = $5,
    sent_at = CASE WHEN $3 = 'sent' THEN now() ELSE sent_at END,
    failed_at = CASE WHEN $3 = 'failed' THEN now() ELSE failed_at END
WHERE id = $1 AND org_id = $2 AND state = 'delivering'
RETURNING *;

-- name: CreateAlertDeliveryAttempt :one
INSERT INTO alert_delivery_attempts (
    org_id, delivery_id, attempt, outcome, response_status, error
) VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;
