package alerts

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

type conditionStore struct {
	offline, denies, expiry, rotations []Condition
}

func (s conditionStore) OfflineAgents(context.Context) ([]Condition, error)  { return s.offline, nil }
func (s conditionStore) DenialSpikes(context.Context) ([]Condition, error)   { return s.denies, nil }
func (s conditionStore) ExpiringAccess(context.Context) ([]Condition, error) { return s.expiry, nil }
func (s conditionStore) FailedRotations(context.Context) ([]Condition, error) {
	return s.rotations, nil
}

type recordedPublisher struct{ events []Event }

func (p *recordedPublisher) Publish(_ context.Context, event Event) error {
	p.events = append(p.events, event)
	return event.Validate()
}

func TestConditionScannerPublishesEachBoundedCondition(t *testing.T) {
	t.Parallel()
	condition := func(reason string) Condition {
		return Condition{OrgID: uuid.New(), DeviceID: uuid.New(), Name: "build-agent", Count: 20, Deadline: time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC), Reason: reason}
	}
	store := conditionStore{offline: []Condition{condition("offline")}, denies: []Condition{condition("denial-spike")}, expiry: []Condition{condition("request-1")}, rotations: []Condition{condition("wireguard")}}
	publisher := &recordedPublisher{}
	if err := NewConditionScanner(store, publisher).RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(publisher.events) != 4 {
		t.Fatalf("published %d events, want 4", len(publisher.events))
	}
	keys := map[EventKey]bool{}
	for _, event := range publisher.events {
		keys[event.Key] = true
	}
	for _, key := range []EventKey{EventAgentOffline, EventAgentDenialSpike, EventAgentAccessExpiring, EventAgentRotationFailed} {
		if !keys[key] {
			t.Fatalf("missing %s from %#v", key, keys)
		}
	}
	offline := publisher.events[0]
	if offline.Fields["threshold_seconds"] != "60" || offline.Subject != "Agent build-agent has been offline for at least one minute" {
		t.Fatalf("offline event = %#v, want one-minute threshold", offline)
	}
}

func TestConditionScannerIsNoopForEmptyObservations(t *testing.T) {
	t.Parallel()
	publisher := &recordedPublisher{}
	if err := NewConditionScanner(conditionStore{}, publisher).RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(publisher.events) != 0 {
		t.Fatalf("published %#v for empty conditions", publisher.events)
	}
}
