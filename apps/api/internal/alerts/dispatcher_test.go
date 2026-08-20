package alerts

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
)

type dispatchStore struct {
	claimed  []sqlc.AlertDelivery
	finished []sqlc.FinishAlertDeliveryParams
	attempts []sqlc.CreateAlertDeliveryAttemptParams
}

func (s *dispatchStore) ClaimDueAlertDeliveries(_ context.Context, _ sqlc.ClaimDueAlertDeliveriesParams) ([]sqlc.AlertDelivery, error) {
	return s.claimed, nil
}

func (s *dispatchStore) GetAlertDestinationForDelivery(_ context.Context, params sqlc.GetAlertDestinationForDeliveryParams) (sqlc.AlertDestination, error) {
	return sqlc.AlertDestination{ID: params.ID, OrgID: params.OrgID, Kind: "webhook"}, nil
}

func (s *dispatchStore) FinishAlertDelivery(_ context.Context, params sqlc.FinishAlertDeliveryParams) (sqlc.AlertDelivery, error) {
	s.finished = append(s.finished, params)
	return sqlc.AlertDelivery{}, nil
}

func (s *dispatchStore) CreateAlertDeliveryAttempt(_ context.Context, params sqlc.CreateAlertDeliveryAttemptParams) (sqlc.AlertDeliveryAttempt, error) {
	s.attempts = append(s.attempts, params)
	return sqlc.AlertDeliveryAttempt{}, nil
}

type sender struct{ err error }

func (s sender) Send(_ context.Context, _ sqlc.AlertDestination, _ []byte) (int32, error) {
	return 202, s.err
}

func TestRetryAfterHasFiveBoundedAttempts(t *testing.T) {
	t.Parallel()
	for attempt, want := range map[int32]time.Duration{1: time.Minute, 2: 2 * time.Minute, 3: 4 * time.Minute, 4: 8 * time.Minute} {
		got, ok := RetryAfter(attempt)
		if !ok || got != want {
			t.Fatalf("attempt %d retry=(%s,%t), want (%s,true)", attempt, got, ok, want)
		}
	}
	if _, ok := RetryAfter(MaxAttempts); ok {
		t.Fatal("fifth attempt must be terminal")
	}
}

func TestDispatcherMarksSuccessfulDeliverySent(t *testing.T) {
	t.Parallel()
	store := &dispatchStore{claimed: []sqlc.AlertDelivery{testDelivery(1)}}
	dispatcher := NewDispatcher(store, sender{})
	now := time.Date(2026, time.August, 20, 12, 0, 0, 0, time.UTC)
	dispatcher.now = func() time.Time { return now }
	if err := dispatcher.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(store.finished) != 1 || store.finished[0].State != "sent" || !store.finished[0].NextAttemptAt.Equal(now) {
		t.Fatalf("finished=%#v, want sent at now", store.finished)
	}
	if len(store.attempts) != 1 || store.attempts[0].Outcome != "sent" || store.attempts[0].Error != nil {
		t.Fatalf("attempts=%#v, want successful history", store.attempts)
	}
}

func TestDispatcherSchedulesThenDeadLettersFailures(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.August, 20, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		attempt int32
		state   string
		next    time.Time
	}{
		{1, "pending", now.Add(time.Minute)},
		{MaxAttempts, "failed", now},
	} {
		t.Run(tc.state, func(t *testing.T) {
			store := &dispatchStore{claimed: []sqlc.AlertDelivery{testDelivery(tc.attempt)}}
			dispatcher := NewDispatcher(store, sender{err: errors.New("destination unavailable")})
			dispatcher.now = func() time.Time { return now }
			if err := dispatcher.RunOnce(context.Background()); err != nil {
				t.Fatal(err)
			}
			got := store.finished[0]
			if got.State != tc.state || !got.NextAttemptAt.Equal(tc.next) || got.LastError == nil {
				t.Fatalf("finish=%#v, want state=%s next=%s error", got, tc.state, tc.next)
			}
			if store.attempts[0].Outcome != "failed" || store.attempts[0].Attempt != tc.attempt {
				t.Fatalf("attempt=%#v, want failed attempt %d", store.attempts[0], tc.attempt)
			}
		})
	}
}

func testDelivery(attempt int32) sqlc.AlertDelivery {
	return sqlc.AlertDelivery{ID: uuid.New(), OrgID: uuid.New(), DestinationID: uuid.New(), Attempts: attempt, Payload: []byte(`{"event":"agent.offline"}`)}
}
