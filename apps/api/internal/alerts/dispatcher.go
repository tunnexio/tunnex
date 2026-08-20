package alerts

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
)

const (
	MaxAttempts = 5
	BatchSize   = 1
	ClaimLease  = time.Minute
)

// RetryAfter returns the fixed F11 retry delays after a failed attempt. A
// fifth failure is terminal and therefore has no next retry time.
func RetryAfter(attempt int32) (time.Duration, bool) {
	switch attempt {
	case 1:
		return time.Minute, true
	case 2:
		return 2 * time.Minute, true
	case 3:
		return 4 * time.Minute, true
	case 4:
		return 8 * time.Minute, true
	default:
		return 0, false
	}
}

type DispatchStore interface {
	RecoverStaleAlertDeliveries(context.Context, sqlc.RecoverStaleAlertDeliveriesParams) (int64, error)
	ClaimDueAlertDeliveries(context.Context, sqlc.ClaimDueAlertDeliveriesParams) ([]sqlc.AlertDelivery, error)
	GetAlertDestinationForDelivery(context.Context, sqlc.GetAlertDestinationForDeliveryParams) (sqlc.AlertDestination, error)
	FinishAlertDeliveryWithAttempt(context.Context, sqlc.FinishAlertDeliveryWithAttemptParams) (sqlc.AlertDeliveryAttempt, error)
}

// Sender performs the only outbound operation in the dispatcher. Its concrete
// implementation is the safedial client; a sender never receives a database
// handle or a plaintext secret outside the duration of one request.
type Sender interface {
	Send(context.Context, sqlc.AlertDestination, []byte) (status int32, err error)
}

type Dispatcher struct {
	store  DispatchStore
	sender Sender
	now    func() time.Time
}

func NewDispatcher(store DispatchStore, sender Sender) *Dispatcher {
	return &Dispatcher{store: store, sender: sender, now: time.Now}
}

// RunOnce claims a bounded batch. Claiming moves rows out of pending before
// any network I/O, so two scheduler replicas cannot send the same claimed row.
// A crash after the claim is recovered by the future lease/recovery slice; this
// slice keeps the mutation and retry outcomes explicit and durable.
func (d *Dispatcher) RunOnce(ctx context.Context) error {
	if d == nil || d.store == nil || d.sender == nil {
		return errors.New("alert dispatcher is not configured")
	}
	now := d.now().UTC()
	if _, err := d.store.RecoverStaleAlertDeliveries(ctx, sqlc.RecoverStaleAlertDeliveriesParams{
		NextAttemptAt: now, StaleBefore: now.Add(-ClaimLease), MaxAttempts: MaxAttempts,
	}); err != nil {
		return err
	}
	claimed, err := d.store.ClaimDueAlertDeliveries(ctx, sqlc.ClaimDueAlertDeliveriesParams{
		NextAttemptAt: now, Limit: BatchSize,
	})
	if err != nil {
		return err
	}
	for _, delivery := range claimed {
		if err := d.deliverOne(ctx, delivery); err != nil {
			return err
		}
	}
	return nil
}

func (d *Dispatcher) deliverOne(ctx context.Context, delivery sqlc.AlertDelivery) error {
	destination, err := d.store.GetAlertDestinationForDelivery(ctx, sqlc.GetAlertDestinationForDeliveryParams{
		ID: delivery.ID, OrgID: delivery.OrgID,
	})
	if err == nil {
		status, sendErr := d.sender.Send(ctx, destination, delivery.Payload)
		err = sendErr
		var responseStatus *int32
		if status > 0 {
			responseStatus = &status
		}
		if err == nil {
			return d.finish(ctx, delivery, "sent", d.now().UTC(), nil, "sent", responseStatus)
		}
		message := "alert delivery " + deliveryFailureCode(err, status)
		state := "pending"
		next := d.now().UTC()
		if after, retry := RetryAfter(delivery.Attempts); retry {
			next = next.Add(after)
		} else {
			state = "failed"
		}
		outcome := "retryable_failure"
		if state == "failed" {
			outcome = "terminal_failure"
		}
		return d.finish(ctx, delivery, state, next, &message, outcome, responseStatus)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	message := "alert delivery unavailable"
	return d.finish(ctx, delivery, "failed", d.now().UTC(), &message, "terminal_failure", nil)
}

func (d *Dispatcher) finish(ctx context.Context, delivery sqlc.AlertDelivery, state string, next time.Time, message *string, outcome string, responseStatus *int32) error {
	_, err := d.store.FinishAlertDeliveryWithAttempt(ctx, sqlc.FinishAlertDeliveryWithAttemptParams{
		DeliveryID: delivery.ID, OrgID: delivery.OrgID, DeliveryState: state,
		NextAttemptAt: next, LastError: message, Attempt: delivery.Attempts,
		Outcome: outcome, ResponseStatus: responseStatus,
	})
	return err
}
