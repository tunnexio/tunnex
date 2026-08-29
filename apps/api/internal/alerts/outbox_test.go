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
	observed     []Event
}

func (s *outboxStore) ObserveOccurrence(_ context.Context, event Event, _ time.Time) error {
	s.observed = append(s.observed, event)
	return nil
}

func (s *outboxStore) ListFiringOccurrences(_ context.Context, _ uuid.UUID, _ []EventKey) ([]Event, error) {
	return append([]Event(nil), s.observed...), nil
}

func (s *outboxStore) GetOrganizationByID(_ context.Context, _ uuid.UUID) (sqlc.Organization, error) {
	return s.org, nil
}

func (s *outboxStore) ListAlertDestinationsForEvent(_ context.Context, _ sqlc.ListAlertDestinationsForEventParams) ([]sqlc.AlertDestination, error) {
	return s.destinations, nil
}

func (s *outboxStore) Enqueue(_ context.Context, destination sqlc.AlertDestination, event Event, payload []byte, now time.Time) error {
	s.created = append(s.created, sqlc.CreateAlertDeliveryParams{
		OrgID: event.OrgID, DestinationID: destination.ID, EventKey: string(event.Key), Severity: string(event.Severity),
		DedupKey: event.DedupKey, Payload: payload, NextAttemptAt: now,
	})
	return nil
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
	if len(store.observed) != 0 {
		t.Fatalf("occurrences=%#v, want legacy delivery-only event excluded", store.observed)
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
	event.Resource = &ResourceRef{Type: "agent", ID: "a-1", Name: "a-1"}
	if err := publisher.Publish(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	if len(store.created) != 2 {
		t.Fatalf("created %d deliveries, want 2", len(store.created))
	}
	if len(store.observed) != 1 {
		t.Fatalf("observed %d occurrences, want one independent of destination count", len(store.observed))
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

func TestOutboxPublisherTracksExplicitLifecycleWithoutDeliveryOptIn(t *testing.T) {
	t.Parallel()
	store := &outboxStore{}
	publisher := NewOutboxPublisher(store)
	event := testEvent()
	event.Resource = &ResourceRef{Type: "gateway", ID: "g-1", Name: "edge"}
	if err := publisher.Publish(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	if len(store.observed) != 1 || store.observed[0].State != EventStateFiring {
		t.Fatalf("occurrences=%#v, want normalized firing condition", store.observed)
	}
}

func testEvent() Event {
	return Event{
		OrgID: uuid.New(), Key: EventAgentOffline, Severity: SeverityWarning,
		DedupKey: "agent:a-1:offline", Subject: "Agent a-1 is offline",
		Fields: map[string]string{"agent_id": "a-1"},
	}
}

func TestResolvedOccurrenceUsesIndependentDeliveryCooldown(t *testing.T) {
	t.Parallel()
	event := testEvent()
	if got := occurrenceCooldownKey(event.normalized()); got != event.DedupKey {
		t.Fatalf("firing cooldown key=%q", got)
	}
	event.State = EventStateResolved
	if got := occurrenceCooldownKey(event); got != event.DedupKey+":resolved" {
		t.Fatalf("resolved cooldown key=%q", got)
	}
}
