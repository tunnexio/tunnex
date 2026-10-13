package ipsec

import (
	"testing"
	"time"
)

func TestFreshSelectedUpAfterHistoryGapCounterexample(t *testing.T) {
	e, o := recoveryFixture()
	o.Status = [2]string{"up", "up"}
	var r recoveryDecision
	if a := r.observe(e, 0, o); a.Refuse {
		t.Fatal("initial healthy refused")
	}
	o.At = 20 * time.Second
	if a := r.observe(e, o.At, o); a.Refuse || a.Target != 0 {
		t.Fatalf("fresh lawful currentUp refused solely due old history: %+v", a)
	}
}
func TestFreshUpGapApplyRecoveryCounterexample(t *testing.T) {
	r := newRecoveryTestRig(t)
	r.status = [2]string{"up", "up"}
	if err := r.apply(); err != nil {
		t.Fatal("initial healthy", err)
	}
	r.events = nil
	r.now = 20 * time.Second
	if err := r.apply(); err != nil {
		t.Fatalf("fresh samebinding lease+currentUp refused after20s schedulinggap: %v events=%v", err, r.events)
	}
	for _, e := range r.events {
		if e == "deny" || e == "switch" {
			t.Fatalf("healthy schedulinggap withdrew or switched: %v", r.events)
		}
	}
}
func TestHistoryGapStillResetsDownEvidence(t *testing.T) {
	e, o := recoveryFixture()
	var r recoveryDecision
	for _, at := range []time.Duration{0, 5 * time.Second} {
		o.At = at
		_ = r.observe(e, at, o)
	}
	o.At = 25 * time.Second
	a := r.observe(e, o.At, o)
	if !a.Refuse || a.Target != 0 {
		t.Fatal("gap reused sustainedDown history", a)
	}
	o.At = 26 * time.Second
	if a = r.observe(e, o.At, o); a.Target != 0 {
		t.Fatal("immediate postgap failover", a)
	}
}
func TestFreshUpGapStaleCurrentStillRefuses(t *testing.T) {
	e, o := recoveryFixture()
	o.Status = [2]string{"up", "up"}
	var r recoveryDecision
	_ = r.observe(e, 0, o)
	o.At = 10 * time.Second
	if a := r.observe(e, 20*time.Second, o); !a.Refuse || a.Target != 0 {
		t.Fatal("stale current observation allowed", a)
	}
}
func TestFreshUpRepeatedThirtyTwoSecondGaps(t *testing.T) {
	r := newRecoveryTestRig(t)
	r.status = [2]string{"up", "up"}
	for _, at := range []time.Duration{0, 32 * time.Second, 64 * time.Second, 96 * time.Second} {
		r.now = at
		r.events = nil
		if err := r.apply(); err != nil {
			t.Fatalf("freshUp at%v refused:%v", at, err)
		}
		if at > 0 {
			for _, x := range r.events {
				if x == "deny" || x == "switch" {
					t.Fatalf("freshUp historygap changedauthority:%v", r.events)
				}
			}
		}
	}
}
func TestGapDownStartsFreshThreeSampleEvidence(t *testing.T) {
	e, o := recoveryFixture()
	var r recoveryDecision
	o.Status = [2]string{"up", "up"}
	_ = r.observe(e, 0, o)
	o.Status = [2]string{"down", "up"}
	for i, at := range []time.Duration{32 * time.Second, 37 * time.Second, 42 * time.Second} {
		o.At = at
		a := r.observe(e, at, o)
		if !a.Refuse || (i < 2 && a.Target != 0) || (i == 2 && a.Target != 2) {
			t.Fatalf("postgap sample%d at%v advice%+v", i, at, a)
		}
	}
}
