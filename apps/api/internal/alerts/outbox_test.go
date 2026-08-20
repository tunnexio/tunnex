package alerts

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
)

type outboxStore struct {
	org          sqlc.Organization
	destinations []sqlc.AlertDestination
	created      []sqlc.CreateAlertDeliveryParams
}

func (s *outboxStore) GetOrganizationByID(_ context.Context, _ uuid.UUID) (sqlc.Organization, error) {
	return s.org, nil
}

func (s *outboxStore) ListAlertDestinationsForEvent(_ context.Context, _ sqlc.ListAlertDestinationsForEventParams) ([]sqlc.AlertDestination, error) {
	return s.destinations, nil
}

func (s *outboxStore) CreateAlertDelivery(_ context.Context, params sqlc.CreateAlertDeliveryParams) (sqlc.AlertDelivery, error) {
	s.created = append(s.created, params)
	return sqlc.AlertDelivery{}, nil
}

func TestOutboxPublisherRequiresExplicitOrgOptIn(t *testing.T) {
	t.Parallel()
	store := &outboxStore{destinations: []sqlc.AlertDestination{{ID: uuid.New()}}}
	publisher := NewOutboxPublisher(store)
	if err := publisher.Publish(context.Background(), testEvent()); err != nil {
		t.Fatal(err)
	}
	if len(store.created) != 0 {
		t.Fatalf("created %d deliveries while alerting was disabled", len(store.created))
	}
}

func TestOutboxPublisherQueuesEachEligibleDestination(t *testing.T) {
	t.Parallel()
	store := &outboxStore{
		org:          sqlc.Organization{AlertingEnabled: true},
		destinations: []sqlc.AlertDestination{{ID: uuid.New()}, {ID: uuid.New()}},
	}
	publisher := NewOutboxPublisher(store)
	now := time.Date(2026, time.August, 20, 12, 0, 0, 0, time.UTC)
	publisher.now = func() time.Time { return now }
	event := testEvent()
	if err := publisher.Publish(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	if len(store.created) != 2 {
		t.Fatalf("created %d deliveries, want 2", len(store.created))
	}
	for _, created := range store.created {
		if created.OrgID != event.OrgID || created.EventKey != string(event.Key) || created.Severity != string(event.Severity) || created.DedupKey != event.DedupKey {
			t.Fatalf("delivery did not preserve event fields: %#v", created)
		}
		if !created.NextAttemptAt.Equal(now) {
			t.Fatalf("next attempt=%s, want %s", created.NextAttemptAt, now)
		}
		var payload Event
		if err := json.Unmarshal(created.Payload, &payload); err != nil {
			t.Fatalf("payload was not event JSON: %v", err)
		}
		if payload.Subject != event.Subject || payload.Fields["agent_id"] != "a-1" {
			t.Fatalf("payload=%#v, want event payload", payload)
		}
	}
}

func testEvent() Event {
	return Event{
		OrgID: uuid.New(), Key: EventAgentOffline, Severity: SeverityWarning,
		DedupKey: "agent:a-1:offline", Subject: "Agent a-1 is offline",
		Fields: map[string]string{"agent_id": "a-1"},
	}
}
