package idpsync

import (
	"context"
	"github.com/google/uuid"
	"testing"
	"time"

	"github.com/tunnexio/tunnex/apps/api/internal/licence"
)

// ⛔ THE REACHABILITY TEST, AND IT EXISTS BECAUSE ITS ABSENCE IS THE ENTIRE DEFECT S12.1 SLICE 9 FIXED.
//
// `lapsed_licence_test.go` has proven the gate's BEHAVIOUR correct since S7.5.2: three reds, the security
// half asserted from both sides, comments explaining the ruling. Every one of them passed. And in
// production `WithProvisioningGate` was never called, so `mayProvision()` saw a nil predicate and returned
// true forever — a paid capability given away underneath a green suite that described gating it in detail.
//
// > ## ⛔ **A TEST THAT INJECTS THE GATE PROVES THE GATE. IT PROVES NOTHING ABOUT WHETHER ANYTHING INJECTS IT.**
//
// (docs/laws.md: unit tests prove behaviour, not reachability — name the trigger and check it can
// CO-OCCUR with the gate.) This asserts the predicate the SERVICE hands over, not one a test supplies.
func TestTheServiceSuppliesARealPredicate(t *testing.T) {
	if (&Service{now: time.Now}).mayProvision() {
		t.Fatal("an unwired manager must refuse new directory grants")
	}
	valid := licence.NewTestManager("starter", time.Now().Add(time.Hour))
	if !(&Service{now: time.Now, licence: valid}).mayProvision() {
		t.Error("a valid Starter licence was refused directory sync")
	}
	// ⭐ Community has never been entitled to directory sync, licence or no licence.
	community := &licence.Manager{}
	if (&Service{now: time.Now, licence: community}).mayProvision() {
		t.Error("⛔ IDP SYNC IS FREE. An unlicensed deployment provisions members from a directory")
	}
	// ⭐ And the ladder: a lapsed Starter falls to Community, so provisioning stops — while its removals,
	// which have no seam to gate, keep running. That asymmetry is D1.
	lapsed := licence.NewTestManager("starter", time.Now().Add(-100*24*time.Hour))
	if (&Service{now: time.Now, licence: lapsed}).mayProvision() {
		t.Error("⛔ a fully lapsed licence still provisions new members")
	}
}

func TestProvisioningStopsAtExpiryWithoutWaitingForGrace(t *testing.T) {
	now := time.Unix(1800000000, 0)
	for _, tc := range []struct {
		name   string
		expiry time.Time
		want   bool
	}{
		{"active", now.Add(time.Second), true},
		{"exact expiry", now, false},
		{"inside grace", now.Add(-time.Hour), false},
		{"past grace", now.Add(-100 * 24 * time.Hour), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &Service{now: func() time.Time { return now }, licence: licence.NewTestManager("starter", tc.expiry)}
			if got := s.mayProvision(); got != tc.want {
				t.Fatalf("mayProvision = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestServiceLicenceGateKeepsRevocationsAtExpiry(t *testing.T) {
	now := time.Unix(1800000000, 0)
	for _, tier := range []string{"trial", "starter"} {
		for _, active := range []bool{true, false} {
			name := tier + "/expired"
			expiry := now
			if active {
				name = tier + "/active"
				expiry = now.Add(time.Hour)
			}
			t.Run(name, func(t *testing.T) {
				svc := &Service{now: func() time.Time { return now }, licence: licence.NewTestManager(tier, expiry)}
				st := baseStore()
				st.current[grp] = []uuid.UUID{uBob}
				p := &fakeProvider{members: []DirectoryMember{
					{ExternalID: "alice", Email: "alice@acme.com", Status: StatusActive},
					{ExternalID: "bob", Email: "bob@acme.com", Status: StatusDisabled},
				}}
				d := &fakeDeprov{}
				r := NewReconciler(p, st, d, svc.now).WithProvisioningGate(svc.mayProvision)
				if err := r.ReconcileConfig(context.Background(), org, "microsoft"); err != nil {
					t.Fatal(err)
				}
				if (len(st.added) == 1) != active {
					t.Fatalf("unexpected additions: %+v", st.added)
				}
				if len(st.removed) != 1 || st.removed[0].user != uBob || len(d.deactivated) != 1 || d.deactivated[0] != uBob {
					t.Fatal("licence state blocked revocation")
				}
			})
		}
	}
}

func TestExpiryBetweenGrantsStopsFurtherAdditions(t *testing.T) {
	st := baseStore()
	p := &fakeProvider{members: []DirectoryMember{
		{ExternalID: "alice", Email: "alice@acme.com", Status: StatusActive},
		{ExternalID: "bob", Email: "bob@acme.com", Status: StatusActive},
	}}
	checks := 0
	r := NewReconciler(p, st, &fakeDeprov{}, time.Now).WithProvisioningGate(func() bool { checks++; return checks == 1 })
	if err := r.ReconcileConfig(context.Background(), org, "microsoft"); err != nil {
		t.Fatal(err)
	}
	if len(st.added) != 1 {
		t.Fatalf("expiry between grants: got %d grants, want 1", len(st.added))
	}
}
