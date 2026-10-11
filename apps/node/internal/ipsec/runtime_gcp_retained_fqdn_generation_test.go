package ipsec

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"
)

// This is a negative control for the proposed retained-resource cause, not a
// reproduction of the live failure. Native IO is the existing modeled rig.
func TestGCPBaselineRetainedFQDNRefreshDoesNotWithdrawClassic(t *testing.T) {
	r := newRenewalCycleRigInput(t, true, gcpMaintenanceRestoredClassic)
	id := r.entries[1].Allocation.ConnectionID
	before := r.c.active[id]
	for _, g := range before.Grants {
		if g.FQDNManaged {
			t.Fatal("baseline fixture unexpectedly marked")
		}
	}
	_, _, p := fqdnRuntimeFixture(t)
	p.NodeID = r.c.config.GatewayID.String()
	p.Allow = p.Allow[:0]
	s := &RuntimeFQDNPolicySource{}
	s.CommittedPolicy(p)
	s.Attach(r.c)
	r.c.config.FQDNPolicy = s
	deadline := before.Authority.deadline
	for _, generation := range []string{strings.Repeat("a", 64), strings.Repeat("b", 64), ""} {
		p.FQDNGenerations[0].Generation = generation
		if generation == "" {
			p.FQDNGenerations[0].Answers = nil
		}
		if err := s.BeforePolicy(context.Background(), p); err != nil {
			t.Fatal(err)
		}
		s.CommittedPolicy(p)
		if !r.c.fqdnGrantsCurrent(before.Grants) {
			t.Fatal("ungranted retained resource invalidated baseline")
		}
		if err := r.c.installActive(context.Background(), r.entries); err != nil {
			t.Fatal(err)
		}
		after, ok := r.c.active[id]
		if !ok || r.applicationDenied[id] {
			t.Fatal("retained generation removed Classic baseline authority")
		}
		if after.Authority != before.Authority || after.Authority.deadline != deadline || !reflect.DeepEqual(after.Grants, before.Grants) {
			t.Fatal("baseline identity or original authority changed")
		}
		if _, err := after.Authority.RemainingForApply(after.Identity, 5*time.Second); err != nil {
			t.Fatal(err)
		}
	}
}

// Reproduces the documented fail-closed publication shape, not a product bug:
// one Classic proof failure removes that candidate while HA renews successfully.
func TestGCPMaintenanceTransientClassicProofPublishesPrefixOnlyWithoutApplyError(t *testing.T) {
	r := newRenewalCycleRigInput(t, true, gcpMaintenanceRestoredClassic)
	id := r.entries[1].Allocation.ConnectionID
	before := r.c.active[id]
	remaining, err := before.Authority.RemainingForApply(before.Identity, 5*time.Second)
	if err != nil || remaining < 50*time.Second {
		t.Fatal("fixture must retain long original lease", remaining, err)
	}
	originalProve := r.c.prove
	failed := false
	r.c.prove = func(ctx context.Context, e RuntimeJournalEntry, env RuntimeEnvironment) error {
		if e.Allocation.ConnectionID == id && !failed {
			failed = true
			return ErrRuntimeController
		}
		return originalProve(ctx, e, env)
	}
	r.phase = "maintenance"
	results, err := r.c.maintainIPsecRuntime(context.Background(), r.materials, maintenanceAuthority(r), func() bool { return true })
	if err != nil || !failed || len(results) != 1 {
		t.Fatalf("results=%d failed=%t err=%v", len(results), failed, err)
	}
	if _, ok := r.c.active[id]; ok || !r.applicationDenied[id] {
		t.Fatal("failed Classic proof must retract Classic in actual rendered guard")
	}
	if _, ok := r.c.active[r.entries[0].Allocation.ConnectionID]; !ok {
		t.Fatal("unaffected HA authority removed")
	}
	if _, err := before.Authority.RemainingForApply(before.Identity, 5*time.Second); err != nil {
		t.Fatal("old lease unexpectedly expired; this model is proof withdrawal", err)
	}
}
