package alerts

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
)

// OutboxStore is the narrow persistence seam for event producers. The
// dispatcher owns retry state; this store atomically reserves the destination
// condition cooldown before adding a durable delivery request.
type OutboxStore interface {
	GetOrganizationByID(context.Context, uuid.UUID) (sqlc.Organization, error)
	ListAlertDestinationsForEvent(context.Context, sqlc.ListAlertDestinationsForEventParams) ([]sqlc.AlertDestination, error)
	Enqueue(context.Context, sqlc.AlertDestination, Event, []byte, time.Time) error
}

// OccurrenceStore records the canonical product condition independently of
// outbound-notification opt-in. Delivery destinations are optional; the alert
// centre must still be able to show a truthful active or resolved condition.
type OccurrenceStore interface {
	ObserveOccurrence(context.Context, Event, time.Time) error
	ListFiringOccurrences(context.Context, uuid.UUID, []EventKey) ([]Event, error)
}

type OutboxPublisher struct {
	store       OutboxStore
	occurrences OccurrenceStore
	now         func() time.Time
}

func NewOutboxPublisher(store OutboxStore) *OutboxPublisher {
	p := &OutboxPublisher{store: store, now: time.Now}
	if occurrences, ok := store.(OccurrenceStore); ok {
		p.occurrences = occurrences
	}
	return p
}

func (p *OutboxPublisher) Publish(ctx context.Context, event Event) error {
	// Legacy F11 producers predate condition lifecycle and emit delivery-only
	// notifications without resource identity. Recording those as occurrences
	// would create active alerts that can never be reconciled. New shared-alert
	// producers opt into lifecycle tracking with a resource or explicit state.
	trackOccurrence := event.Resource != nil || event.State != ""
	event = event.normalized()
	if err := event.Validate(); err != nil {
		return err
	}
	if p == nil || p.store == nil {
		return fmt.Errorf("alert outbox publisher is not configured")
	}
	now := p.now().UTC()
	if trackOccurrence && p.occurrences != nil {
		if err := p.occurrences.ObserveOccurrence(ctx, event, now); err != nil {
			return fmt.Errorf("record alert occurrence: %w", err)
		}
	}
	org, err := p.store.GetOrganizationByID(ctx, event.OrgID)
	if err != nil {
		return err
	}
	if !org.AlertingEnabled {
		return nil
	}
	destinations, err := p.store.ListAlertDestinationsForEvent(ctx, sqlc.ListAlertDestinationsForEventParams{
		OrgID: event.OrgID, EventKey: string(event.Key), SeverityFloor: string(event.Severity),
	})
	if err != nil {
		return err
	}
	payload, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal alert event: %w", err)
	}
	for _, destination := range destinations {
		if err := p.store.Enqueue(ctx, destination, event, payload, now); err != nil {
			return err
		}
	}
	return nil
}

func (p *OutboxPublisher) ListFiringOccurrences(ctx context.Context, orgID uuid.UUID, keys []EventKey) ([]Event, error) {
	if p == nil || p.occurrences == nil {
		return nil, fmt.Errorf("alert occurrence store is not configured")
	}
	return p.occurrences.ListFiringOccurrences(ctx, orgID, keys)
}

func (s *PostgresOutbox) ObserveOccurrence(ctx context.Context, event Event, observedAt time.Time) error {
	fields, err := json.Marshal(event.Fields)
	if err != nil {
		return fmt.Errorf("marshal alert occurrence fields: %w", err)
	}
	resourceType, resourceID, resourceName := "", "", ""
	if event.Resource != nil {
		resourceType, resourceID, resourceName = event.Resource.Type, event.Resource.ID, event.Resource.Name
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO alert_occurrences (
			org_id,event_key,dedup_key,resource_type,resource_id,resource_name,
			severity,subject,fields,state,first_observed_at,last_observed_at,resolved_at,occurrence_count
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$11,
			CASE WHEN $10='resolved' THEN $11 ELSE NULL END,
			CASE WHEN $10='firing' THEN 1 ELSE 0 END)
		ON CONFLICT (org_id,event_key,dedup_key) DO UPDATE SET
			resource_type=EXCLUDED.resource_type,
			resource_id=EXCLUDED.resource_id,
			resource_name=EXCLUDED.resource_name,
			severity=EXCLUDED.severity,
			subject=EXCLUDED.subject,
			fields=EXCLUDED.fields,
			state=EXCLUDED.state,
			last_observed_at=EXCLUDED.last_observed_at,
			resolved_at=CASE WHEN EXCLUDED.state='resolved' THEN EXCLUDED.last_observed_at ELSE NULL END,
			occurrence_count=alert_occurrences.occurrence_count + CASE WHEN EXCLUDED.state='firing' THEN 1 ELSE 0 END
		WHERE EXCLUDED.last_observed_at >= alert_occurrences.last_observed_at`,
		event.OrgID, string(event.Key), event.DedupKey, resourceType, resourceID, resourceName,
		string(event.Severity), event.Subject, fields, string(event.State), observedAt)
	return err
}

func (s *PostgresOutbox) ListFiringOccurrences(ctx context.Context, orgID uuid.UUID, keys []EventKey) ([]Event, error) {
	keyValues := make([]string, len(keys))
	for i, key := range keys {
		keyValues[i] = string(key)
	}
	rows, err := s.pool.Query(ctx, `
		SELECT event_key,dedup_key,resource_type,resource_id,resource_name,severity,subject,fields
		FROM alert_occurrences
		WHERE org_id=$1 AND state='firing' AND event_key=ANY($2::text[])
		ORDER BY event_key,dedup_key`, orgID, keyValues)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var event Event
		var resourceType, resourceID, resourceName string
		var fields []byte
		if err := rows.Scan(&event.Key, &event.DedupKey, &resourceType, &resourceID, &resourceName,
			&event.Severity, &event.Subject, &fields); err != nil {
			return nil, err
		}
		event.OrgID = orgID
		event.State = EventStateFiring
		if resourceType != "" {
			event.Resource = &ResourceRef{Type: resourceType, ID: resourceID, Name: resourceName}
		}
		if err := json.Unmarshal(fields, &event.Fields); err != nil {
			return nil, fmt.Errorf("decode alert occurrence fields: %w", err)
		}
		out = append(out, event)
	}
	return out, rows.Err()
}

// PostgresOutbox keeps the cooldown reservation and delivery creation in one
// transaction. A transaction-scoped advisory lock serializes the first write
// for one destination/condition key before the cooldown row exists.
type PostgresOutbox struct {
	pool *pgxpool.Pool
	q    *sqlc.Queries
}

func NewPostgresOutbox(pool *pgxpool.Pool) *PostgresOutbox {
	return &PostgresOutbox{pool: pool, q: sqlc.New(pool)}
}

func (s *PostgresOutbox) GetOrganizationByID(ctx context.Context, orgID uuid.UUID) (sqlc.Organization, error) {
	return s.q.GetOrganizationByID(ctx, orgID)
}

func (s *PostgresOutbox) ListAlertDestinationsForEvent(ctx context.Context, params sqlc.ListAlertDestinationsForEventParams) ([]sqlc.AlertDestination, error) {
	return s.q.ListAlertDestinationsForEvent(ctx, params)
}

func (s *PostgresOutbox) Enqueue(ctx context.Context, destination sqlc.AlertDestination, event Event, payload []byte, now time.Time) error {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	q := s.q.WithTx(tx)
	cooldownKey := occurrenceCooldownKey(event)
	lockKey := event.OrgID.String() + "|" + destination.ID.String() + "|" + string(event.Key) + "|" + cooldownKey
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, lockKey); err != nil {
		return err
	}
	key := sqlc.GetAlertDeliveryCooldownForUpdateParams{
		OrgID: event.OrgID, DestinationID: destination.ID, EventKey: string(event.Key), DedupKey: cooldownKey,
	}
	cooldown, err := q.GetAlertDeliveryCooldownForUpdate(ctx, key)
	if errors.Is(err, pgx.ErrNoRows) {
		if _, err := q.CreateAlertDeliveryCooldown(ctx, sqlc.CreateAlertDeliveryCooldownParams{
			OrgID: event.OrgID, DestinationID: destination.ID, EventKey: string(event.Key), DedupKey: cooldownKey,
			NextEligibleAt: now,
		}); err != nil {
			return err
		}
		cooldown, err = q.GetAlertDeliveryCooldownForUpdate(ctx, key)
	}
	if err != nil {
		return err
	}
	if now.Before(cooldown.NextEligibleAt) {
		if _, err := q.IncrementAlertDeliveryCooldown(ctx, sqlc.IncrementAlertDeliveryCooldownParams(key)); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}
	if _, err := q.ReserveAlertDeliveryCooldown(ctx, sqlc.ReserveAlertDeliveryCooldownParams{
		OrgID: event.OrgID, DestinationID: destination.ID, EventKey: string(event.Key), DedupKey: cooldownKey,
		NextEligibleAt: now.Add(time.Duration(destination.CooldownSeconds) * time.Second),
	}); err != nil {
		return err
	}
	if _, err := q.CreateAlertDelivery(ctx, sqlc.CreateAlertDeliveryParams{
		OrgID: event.OrgID, DestinationID: destination.ID, EventKey: string(event.Key), Severity: string(event.Severity),
		DedupKey: event.DedupKey, Payload: payload, NextAttemptAt: now, SuppressedCount: cooldown.SuppressedCount,
	}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func occurrenceCooldownKey(event Event) string {
	if event.State == EventStateResolved {
		return event.DedupKey + ":resolved"
	}
	return event.DedupKey
}
