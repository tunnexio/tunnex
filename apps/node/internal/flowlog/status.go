package flowlog

import (
	"sync/atomic"
	"time"
)

// State is the bounded, operator-facing state of the gateway's flow observer.
// It deliberately describes the collection substrate rather than traffic: an
// active observer with no events is a healthy, idle gateway, not a failure.
type State string

const (
	StateActive        State = "active"
	StateDisabled      State = "disabled"
	StateSourceError   State = "source_error"
	StateDeliveryError State = "delivery_error"
)

// Bounded returns a closed-catalogue state for the wire. Unknown internal
// values fail toward source_error rather than claiming collection is disabled
// by an operator. Delivery errors are separate from NFLOG source failures so
// operators know which side of the observer pipeline is unhealthy.
func (s State) Bounded() State {
	switch s {
	case StateActive, StateDisabled, StateSourceError, StateDeliveryError:
		return s
	default:
		return StateSourceError
	}
}

// Status is the concurrency-safe flow-observer heartbeat shared by the NFLOG
// pump, drain loop, and the node's periodic control-plane report. Timestamps are
// Unix nanoseconds so readers never observe a torn time.Time.
type Status struct {
	sourceState        atomic.Uint32
	deliveryError      atomic.Bool
	lastObservedNanos  atomic.Int64
	lastDeliveredNanos atomic.Int64
}

const (
	stateCodeDisabled uint32 = iota
	stateCodeActive
	stateCodeSourceError
)

// NewStatus creates a status tracker in one of the bounded states.
func NewStatus(state State) *Status {
	s := &Status{}
	s.SetState(state)
	return s
}

// SetState records a bounded state. An unknown value is a source error, never
// an implicit disablement.
func (s *Status) SetState(state State) {
	if s == nil {
		return
	}
	switch state.Bounded() {
	case StateActive:
		s.sourceState.Store(stateCodeActive)
		s.deliveryError.Store(false)
	case StateSourceError:
		s.sourceState.Store(stateCodeSourceError)
	case StateDeliveryError:
		s.sourceState.Store(stateCodeActive)
		s.deliveryError.Store(true)
	default:
		s.sourceState.Store(stateCodeDisabled)
		s.deliveryError.Store(false)
	}
}

// RecordObserved marks the newest flow record accepted from the NFLOG source.
func (s *Status) RecordObserved(at time.Time) {
	if s != nil && !at.IsZero() {
		s.lastObservedNanos.Store(at.UTC().UnixNano())
	}
}

// RecordDelivered marks a successful flow-event report, including a report
// carrying only a gap marker after earlier loss.
func (s *Status) RecordDelivered(at time.Time) {
	if s != nil && !at.IsZero() {
		s.lastDeliveredNanos.Store(at.UTC().UnixNano())
		s.deliveryError.Store(false)
	}
}

// RecordDeliveryFailure marks only the report side unhealthy. It cannot mask a
// concurrent/earlier NFLOG source failure; Snapshot gives source_error priority.
func (s *Status) RecordDeliveryFailure() {
	if s != nil {
		s.deliveryError.Store(true)
	}
}

// Snapshot is one read-only heartbeat view for /agent/report.
type Snapshot struct {
	State           State
	LastObservedAt  time.Time
	LastDeliveredAt time.Time
}

// Snapshot returns a concurrency-safe view. Zero timestamps mean no event has
// yet been observed or no report has yet succeeded.
func (s *Status) Snapshot() Snapshot {
	if s == nil {
		return Snapshot{State: StateSourceError}
	}
	state := StateDisabled
	switch s.sourceState.Load() {
	case stateCodeActive:
		state = StateActive
	case stateCodeSourceError:
		state = StateSourceError
	}
	if state == StateActive && s.deliveryError.Load() {
		state = StateDeliveryError
	}
	return Snapshot{
		State:           state,
		LastObservedAt:  timeFromNanos(s.lastObservedNanos.Load()),
		LastDeliveredAt: timeFromNanos(s.lastDeliveredNanos.Load()),
	}
}

func timeFromNanos(nanos int64) time.Time {
	if nanos == 0 {
		return time.Time{}
	}
	return time.Unix(0, nanos).UTC()
}
