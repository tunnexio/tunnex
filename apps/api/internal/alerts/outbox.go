package alerts

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
)

// OutboxStore is the narrow persistence seam for event producers. The
// dispatcher owns retry and cooldown state; publishing only makes a durable,
// tenant-scoped delivery request for each eligible destination.
type OutboxStore interface {
	GetOrganizationByID(context.Context, uuid.UUID) (sqlc.Organization, error)
	ListAlertDestinationsForEvent(context.Context, sqlc.ListAlertDestinationsForEventParams) ([]sqlc.AlertDestination, error)
	CreateAlertDelivery(context.Context, sqlc.CreateAlertDeliveryParams) (sqlc.AlertDelivery, error)
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
		if _, err := p.store.CreateAlertDelivery(ctx, sqlc.CreateAlertDeliveryParams{
			OrgID: event.OrgID, DestinationID: destination.ID, EventKey: string(event.Key),
			Severity: string(event.Severity), DedupKey: event.DedupKey, Payload: payload,
			NextAttemptAt: p.now().UTC(),
		}); err != nil {
			return err
		}
	}
	return nil
}
