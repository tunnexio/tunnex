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

type OutboxPublisher struct {
	store OutboxStore
	now   func() time.Time
}

func NewOutboxPublisher(store OutboxStore) *OutboxPublisher {
	return &OutboxPublisher{store: store, now: time.Now}
}

func (p *OutboxPublisher) Publish(ctx context.Context, event Event) error {
	if err := event.Validate(); err != nil {
		return err
	}
	if p == nil || p.store == nil {
		return fmt.Errorf("alert outbox publisher is not configured")
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
		if err := p.store.Enqueue(ctx, destination, event, payload, p.now().UTC()); err != nil {
			return err
		}
	}
	return nil
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
	lockKey := event.OrgID.String() + "|" + destination.ID.String() + "|" + string(event.Key) + "|" + event.DedupKey
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, lockKey); err != nil {
		return err
	}
	key := sqlc.GetAlertDeliveryCooldownForUpdateParams{
		OrgID: event.OrgID, DestinationID: destination.ID, EventKey: string(event.Key), DedupKey: event.DedupKey,
	}
	cooldown, err := q.GetAlertDeliveryCooldownForUpdate(ctx, key)
	if errors.Is(err, pgx.ErrNoRows) {
		if _, err := q.CreateAlertDeliveryCooldown(ctx, sqlc.CreateAlertDeliveryCooldownParams{
			OrgID: event.OrgID, DestinationID: destination.ID, EventKey: string(event.Key), DedupKey: event.DedupKey,
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
		OrgID: event.OrgID, DestinationID: destination.ID, EventKey: string(event.Key), DedupKey: event.DedupKey,
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
