package ipsec

import (
	"github.com/google/uuid"
	"testing"
	"time"
)

func recoveryFixture() (recoveryEpoch, recoveryObservation) {
	e := recoveryEpoch{Binding: daemonFixture().Binding, DeliveryID: uuid.New(), Namespace: "net:[4026531992]", Tunnels: [2]uuid.UUID{uuid.New(), uuid.New()}}
	return e, recoveryObservation{Epoch: e, Current: 1, Status: [2]string{"down", "up"}, Authorized: true}
}
func TestRecoverySustainedEvidenceAndNoFailback(t *testing.T) {
	e, o := recoveryFixture()
	var r recoveryDecision
	for i, at := range []time.Duration{0, 5 * time.Second, 10 * time.Second} {
		o.At = at
		got := r.observe(e, at, o)
		if !got.Refuse || (i < 2 && got.Target != 0) || (i == 2 && got.Target != 2) {
			t.Fatalf("unexpected decision %+v at %v", got, at)
		}
	}
	o.At = 15 * time.Second
	o.Current = 2
	o.Status = [2]string{"up", "up"}
	if got := r.observe(e, o.At, o); got.Refuse || got.Target != 0 {
		t.Fatal("healthy alternate caused failback", got)
	}
}
func TestRecoveryResetsUnsafeEvidence(t *testing.T) {
	for _, kind := range []string{"unknown", "unauthorized", "stale", "future", "duplicate", "regression", "gap", "epoch", "malformed"} {
		t.Run(kind, func(t *testing.T) {
			e, o := recoveryFixture()
			var r recoveryDecision
			r.observe(e, 0, o)
			o.At = 5 * time.Second
			r.observe(e, o.At, o)
			bad := o
			now := 10 * time.Second
			bad.At = now
			switch kind {
			case "unknown":
				bad.Status[0] = "unknown"
			case "unauthorized":
				bad.Authorized = false
			case "stale":
				bad.At = 3 * time.Second
			case "future":
				bad.At = 11 * time.Second
			case "duplicate":
				bad.At = 5 * time.Second
			case "regression":
				bad.At = 4 * time.Second
			case "gap":
				now = 16 * time.Second
				bad.At = now
			case "epoch":
				bad.Epoch.DeliveryID = uuid.New()
			case "malformed":
				bad.Status[0] = "invalid"
			}
			if got := r.observe(e, now, bad); !got.Refuse || got.Target != 0 {
				t.Fatal("unsafe observation accepted", got)
			}
			o.At = now + time.Second
			if got := r.observe(e, o.At, o); got.Target != 0 {
				t.Fatal("unsafe history retained")
			}
		})
	}
}
func TestRecoveryEpochAndSelectionChanges(t *testing.T) {
	e, o := recoveryFixture()
	var r recoveryDecision
	r.observe(e, 0, o)
	o.At = 5 * time.Second
	r.observe(e, o.At, o)
	e.Binding.PolicyRevision++
	o.Epoch = e
	o.At = 10 * time.Second
	if got := r.observe(e, o.At, o); got.Target != 0 {
		t.Fatal("old policy history reused")
	}
	o.Current = 2
	o.Status = [2]string{"up", "down"}
	o.At = 15 * time.Second
	if got := r.observe(e, o.At, o); got.Target != 0 {
		t.Fatal("old selection history reused")
	}
	o.At = 20 * time.Second
	r.observe(e, o.At, o)
	o.At = 25 * time.Second
	if got := r.observe(e, o.At, o); got.Target != 1 || !got.Refuse {
		t.Fatal("reverse recovery missing", got)
	}
}

func TestRecoveryRefusesInvalidCoordinates(t *testing.T) {
	for _, kind := range []string{"org", "gateway", "connection", "revision", "delivery", "namespace", "tunnel", "duplicate tunnels", "zero slot", "invalid slot", "negative clock"} {
		t.Run(kind, func(t *testing.T) {
			e, o := recoveryFixture()
			switch kind {
			case "org":
				e.Binding.OrgID = uuid.Nil
			case "gateway":
				e.Binding.GatewayID = uuid.Nil
			case "connection":
				e.Binding.ConnectionID = uuid.Nil
			case "revision":
				e.Binding.PolicyRevision = 0
			case "delivery":
				e.DeliveryID = uuid.Nil
			case "namespace":
				e.Namespace = "invalid"
			case "tunnel":
				e.Tunnels[0] = uuid.Nil
			case "duplicate tunnels":
				e.Tunnels[1] = e.Tunnels[0]
			case "zero slot":
				o.Current = 0
			case "invalid slot":
				o.Current = 3
			case "negative clock":
				o.At = -time.Second
			}
			o.Epoch = e
			var r recoveryDecision
			if got := r.observe(e, o.At, o); !got.Refuse || got.Target != 0 {
				t.Fatal("invalid coordinates accepted", got)
			}
		})
	}
}
func TestRecoveryRapidSamplesCannotBypassHoldDown(t *testing.T) {
	e, o := recoveryFixture()
	var r recoveryDecision
	for i := 0; i < 10; i++ {
		o.At = time.Duration(i) * time.Millisecond
		if got := r.observe(e, o.At, o); got.Target != 0 || !got.Refuse {
			t.Fatal("rapid samples bypassed hold-down", got)
		}
	}
	o.At = 10 * time.Second
	if got := r.observe(e, o.At, o); got.Target != 2 {
		t.Fatal("elapsed hold-down never completes", got)
	}
}
func TestRecoveryHealthyPrimaryResetsPendingSwitch(t *testing.T) {
	e, o := recoveryFixture()
	var r recoveryDecision
	r.observe(e, 0, o)
	o.At = 5 * time.Second
	r.observe(e, o.At, o)
	o.At = 10 * time.Second
	o.Status = [2]string{"up", "up"}
	if got := r.observe(e, o.At, o); got.Refuse || got.Target != 0 {
		t.Fatal("healthy primary not retained", got)
	}
	o.At = 15 * time.Second
	o.Status = [2]string{"down", "up"}
	if got := r.observe(e, o.At, o); got.Target != 0 || !got.Refuse {
		t.Fatal("old failure history reused", got)
	}
}

func TestRecoveryRejectsClockRegressionDespiteNewSample(t *testing.T) {
	e, o := recoveryFixture()
	var r recoveryDecision
	o.At = 5 * time.Second
	r.observe(e, 10*time.Second, o)
	o.At = 6 * time.Second
	if got := r.observe(e, 9*time.Second, o); !got.Refuse || got.Target != 0 {
		t.Fatal("regressing clock accepted", got)
	}
	o.At = 10 * time.Second
	r.observe(e, 10*time.Second, o)
	o.At = 16 * time.Second
	if got := r.observe(e, 16*time.Second, o); got.Target != 0 {
		t.Fatal("clock discontinuity retained candidate history", got)
	}
}

func TestRecoveryAlternateLossRestartsHoldDown(t *testing.T) {
	e, o := recoveryFixture()
	var r recoveryDecision
	r.observe(e, 0, o)
	o.At = 5 * time.Second
	r.observe(e, o.At, o)
	o.At = 10 * time.Second
	o.Status = [2]string{"down", "down"}
	if got := r.observe(e, o.At, o); !got.Refuse || got.Target != 0 {
		t.Fatal("both down accepted", got)
	}
	o.Status = [2]string{"down", "up"}
	for i, at := range []time.Duration{15 * time.Second, 20 * time.Second, 25 * time.Second} {
		o.At = at
		got := r.observe(e, o.At, o)
		if !got.Refuse || (i < 2 && got.Target != 0) || (i == 2 && got.Target != 2) {
			t.Fatal("alternate loss did not restart hold-down", got)
		}
	}
}
