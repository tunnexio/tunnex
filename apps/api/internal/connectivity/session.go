// Package connectivity defines the internal signaling authorization contract.
// It performs no authentication, persistence, credential issuance or forwarding.
package connectivity

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

// ErrDenied deliberately does not reveal which binding or eligibility failed.
var ErrDenied = errors.New("connectivity session denied")

type Side uint8

const (
	DeviceSide Side = iota + 1
	GatewaySide
)

// Principal must be constructed from authenticated server context, not JSON.
// A device-side principal identifies its owning user; the device is checked
// against current server-derived ownership in Snapshot.
type Principal struct {
	Side             Side
	OrgID, SubjectID uuid.UUID
}

type Binding struct {
	SessionID, OrgID, OwnerID, DeviceID, GatewayID uuid.UUID
	Generation                                     uint64
}

func (b Binding) valid() bool {
	return b.SessionID != uuid.Nil && b.OrgID != uuid.Nil && b.OwnerID != uuid.Nil &&
		b.DeviceID != uuid.Nil && b.GatewayID != uuid.Nil && b.Generation > 0
}

// Snapshot is current authoritative state, reloaded in the same transaction as
// a signaling operation. Unknown/zero state denies. Callers must invalidate or
// supersede the generation when any binding changes.
type Snapshot struct {
	Current                                                     Binding
	OptedIn, OwnerActiveMember, DeviceEligible, GatewayEligible bool
}

// Session is immutable input/output to the reducer, not a concurrent store.
// The durable caller must atomically compare-and-swap both sequence counters.
type Session struct {
	Binding                         Binding
	CreatedAt, ExpiresAt            time.Time
	Revoked                         bool
	DeviceSequence, GatewaySequence uint64
}

func (s Session) Authorize(p Principal, current Snapshot, now time.Time) error {
	if !s.Binding.valid() || current.Current != s.Binding || !current.OptedIn ||
		!current.OwnerActiveMember || !current.DeviceEligible || !current.GatewayEligible ||
		s.Revoked || now.IsZero() || s.CreatedAt.IsZero() || now.Before(s.CreatedAt) ||
		!s.ExpiresAt.After(s.CreatedAt) || !now.Before(s.ExpiresAt) || p.OrgID != s.Binding.OrgID {
		return ErrDenied
	}
	switch p.Side {
	case DeviceSide:
		if p.SubjectID == s.Binding.OwnerID {
			return nil
		}
	case GatewaySide:
		if p.SubjectID == s.Binding.GatewayID {
			return nil
		}
	}
	return ErrDenied
}

// Accept advances exactly one side by one message. Reads also require Authorize.
// Repeated, skipped and wrapped sequence numbers deny without changing state.
func (s Session) Accept(p Principal, current Snapshot, now time.Time, sequence uint64) (Session, error) {
	if err := s.Authorize(p, current, now); err != nil {
		return s, err
	}
	last := &s.DeviceSequence
	if p.Side == GatewaySide {
		last = &s.GatewaySequence
	}
	if sequence == 0 || *last == ^uint64(0) || sequence != *last+1 {
		return s, ErrDenied
	}
	*last = sequence
	return s, nil
}
