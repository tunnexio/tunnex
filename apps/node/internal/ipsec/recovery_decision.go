package ipsec

import (
	"time"

	"github.com/google/uuid"
)

// Recovery decisions are inactive advice only. They neither select a route nor
// authorize traffic. All times are elapsed readings from one qualified process
// clock; wall-clock timestamps cannot be supplied to this reducer.
type recoveryEpoch struct {
	Binding    Binding
	PolicyHash string
	DeliveryID uuid.UUID
	Namespace  string
	Tunnels    [2]uuid.UUID
}

type recoveryObservation struct {
	Epoch      recoveryEpoch
	Current    uint8
	Status     [2]string
	Authorized bool
	At         time.Duration
}

type recoveryAdvice struct {
	Refuse bool
	Target uint8
}

type recoveryDecision struct {
	epoch           recoveryEpoch
	current         uint8
	seen            bool
	lastAt, lastNow time.Duration
	firstDown       time.Duration
	consecutive     uint8
}

func validRecoveryEpoch(e recoveryEpoch) bool {
	b := e.Binding
	return b.OrgID != uuid.Nil && b.GatewayID != uuid.Nil && b.ConnectionID != uuid.Nil &&
		b.DesiredRevision > 0 && b.ConfigurationRevision > 0 && ((e.PolicyHash == "" && b.PolicyRevision > 0) || (validDigest(e.PolicyHash) && b.PolicyRevision == 0)) &&
		e.DeliveryID != uuid.Nil && validKernelNamespace(e.Namespace) &&
		e.Tunnels[0] != uuid.Nil && e.Tunnels[1] != uuid.Nil && e.Tunnels[0] != e.Tunnels[1]
}

func (r *recoveryDecision) observe(expected recoveryEpoch, now time.Duration, o recoveryObservation) recoveryAdvice {
	refuse := recoveryAdvice{Refuse: true}
	if r == nil {
		return refuse
	}
	reset := func() recoveryAdvice { *r = recoveryDecision{}; return refuse }
	if !validRecoveryEpoch(expected) || o.Epoch != expected || !o.Authorized ||
		o.Current < 1 || o.Current > 2 || now < 0 || o.At < 0 || o.At > now || now-o.At > 5*time.Second {
		return reset()
	}
	for _, status := range o.Status {
		if status != "up" && status != "down" {
			return reset()
		}
	}
	// A clock discontinuity invalidates evidence even if the caller also changed
	// the epoch. No previous recommendation is carried through a reset.
	if r.seen && now < r.lastNow {
		return reset()
	}
	if r.epoch != expected || r.current != o.Current {
		*r = recoveryDecision{}
	}
	if r.seen && (o.At <= r.lastAt || o.At-r.lastAt > 10*time.Second || now-r.lastNow > 10*time.Second) {
		return reset()
	}
	r.epoch, r.current, r.seen = expected, o.Current, true
	r.lastAt, r.lastNow = o.At, now
	current := int(o.Current) - 1
	if o.Status[current] == "up" {
		r.consecutive, r.firstDown = 0, 0
		return recoveryAdvice{}
	}
	if o.Status[1-current] != "up" {
		r.consecutive, r.firstDown = 0, 0
		return refuse
	}
	if r.consecutive == 0 {
		r.firstDown = o.At
	}
	if r.consecutive < 3 {
		r.consecutive++
	}
	if r.consecutive >= 3 && o.At-r.firstDown >= 10*time.Second {
		refuse.Target = 3 - o.Current
	}
	return refuse
}
