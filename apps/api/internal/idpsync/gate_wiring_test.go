package idpsync

import (
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
	if !(&Service{now: time.Now}).mayProvision() {
		t.Fatal("⛔ an unwired manager stopped provisioning — every deployment without a licence just lost " +
			"directory sync, including the ones entitled to it")
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
