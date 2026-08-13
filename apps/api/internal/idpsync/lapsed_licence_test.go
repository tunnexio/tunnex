package idpsync

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// ⭐ D1, FOUNDER-RULED: A LICENCE MAY STOP GRANTING ACCESS. IT MUST NEVER STOP REMOVING IT.
//
// On a lapsed licence the reconciler keeps running and applies ONLY removals and deprovisions. Joiners stop
// being provisioned — the capability the customer was paying for. Leavers still lose access, because that
// is not a feature being sold, it is the product not leaking access.
//
// ⛔ WHAT THIS IS GUARDING AGAINST IS THE OBVIOUS IMPLEMENTATION, WHICH LOOKS LIKE THE CONVENTION.
// "Downgrade releases enforcement" (devices/health.go:260, ReleaseAllHealthBlocks) is a law about
// RESTRICTIONS. Sync is a REVOCATION MECHANISM. Releasing it is also more permissive, and that is the
// fail-open: membership freezes at the last sync and a directory-removed person keeps access indefinitely.
// See docs/laws.md.
//
// Three reds, and the SECOND is the whole ruling — without it this is a refactor.

// lapsed builds a reconciler whose licence no longer entitles provisioning.
func runGated(t *testing.T, p DirectoryProvider, s *fakeStore, d *fakeDeprov, licensed bool) {
	t.Helper()
	r := NewReconciler(p, s, d, func() time.Time { return time.Unix(1700000000, 0) }).
		WithProvisioningGate(func() bool { return licensed })
	if err := r.ReconcileConfig(context.Background(), org, "microsoft"); err != nil {
		t.Logf("ReconcileConfig returned: %v", err)
	}
}

// RED 1 — ON A LAPSED LICENCE, A DIRECTORY REMOVAL STILL STRIPS THE MEMBERSHIP.
//
// This is the security half. If it fails, a person removed from the customer's directory keeps working
// access to the fabric for as long as the licence stays lapsed, and no surface says so.
func TestLapsedLicence_DirectoryRemovalStillStripsMembership(t *testing.T) {
	s := baseStore()
	s.current[grp] = []uuid.UUID{uAli, uBob} // both currently synced in
	p := &fakeProvider{members: []DirectoryMember{
		{ExternalID: "x1", Email: "alice@acme.com", Status: StatusActive}, // bob removed upstream
	}}
	runGated(t, p, s, &fakeDeprov{}, false)

	if len(s.removed) != 1 || s.removed[0].user != uBob {
		t.Fatalf("⛔ A LAPSED LICENCE STOPPED A REVOCATION. Bob was removed from the directory and kept his "+
			"membership: want bob removed, got %+v", s.removed)
	}
}

// RED 1b — the deprovision sweep also survives a lapse.
//
// A member DISABLED in the directory gets the full org-wide sweep, not merely a group removal. Removal and
// sweep are separate blocks in converge(), so proving one says nothing about the other — a gate placed one
// block too low would pass RED 1 and still strand a disabled account with live sessions and credentials.
func TestLapsedLicence_DisabledMemberIsStillSwept(t *testing.T) {
	s := baseStore()
	s.current[grp] = []uuid.UUID{uAli}
	p := &fakeProvider{members: []DirectoryMember{
		{ExternalID: "x1", Email: "alice@acme.com", Status: StatusDisabled},
	}}
	d := &fakeDeprov{}
	runGated(t, p, s, d, false)

	if len(d.deactivated) != 1 || d.deactivated[0] != uAli {
		t.Fatalf("⛔ A LAPSED LICENCE STOPPED THE DEPROVISION SWEEP: want alice swept, got %+v", d.deactivated)
	}
}

// ⭐ RED 2 — ON A LAPSED LICENCE, A DIRECTORY ADDITION DOES NOT PROVISION.
//
// THIS IS THE WHOLE RULING. Without it, (e) is a refactor: the reconciler would keep doing everything it
// did before and the licence would gate nothing. It is also the half that is easy to lose in a later
// edit — a removed `if r.mayProvision()` leaves every other test in this package green.
func TestLapsedLicence_DirectoryAdditionDoesNotProvision(t *testing.T) {
	s := baseStore()
	p := &fakeProvider{members: []DirectoryMember{
		{ExternalID: "x1", Email: "alice@acme.com", Status: StatusActive},
		{ExternalID: "x2", Email: "bob@acme.com", Status: StatusActive},
	}}
	runGated(t, p, s, &fakeDeprov{}, false)

	if len(s.added) != 0 {
		t.Fatalf("⛔ A LAPSED LICENCE PROVISIONED NEW MEMBERS — the gate is not gating, and the Enterprise "+
			"tier's IdP-sync row is unenforced: want 0 adds, got %+v", s.added)
	}
}

// RED 3 — A VALID LICENCE STILL DOES BOTH.
//
// The negative half, and it is not ceremony: "gate everything" and "gate the additive half" are
// indistinguishable from RED 1 and RED 2 alone. A reconciler that had simply stopped provisioning
// altogether — the refactor-shaped bug — passes both of those and fails only here.
func TestValidLicence_StillProvisionsAndStillRemoves(t *testing.T) {
	s := baseStore()
	s.current[grp] = []uuid.UUID{uBob} // bob is in, and is about to drop out of the directory
	p := &fakeProvider{members: []DirectoryMember{
		{ExternalID: "x1", Email: "alice@acme.com", Status: StatusActive}, // alice is new
	}}
	runGated(t, p, s, &fakeDeprov{}, true)

	if len(s.added) != 1 || s.added[0].user != uAli {
		t.Fatalf("a VALID licence must still provision: want alice added, got %+v", s.added)
	}
	if len(s.removed) != 1 || s.removed[0].user != uBob {
		t.Fatalf("a VALID licence must still remove: want bob removed, got %+v", s.removed)
	}
}

// ⚠ AND THE FAIL-STATIC PROPERTY IS UNTOUCHED BY THE GATE.
//
// The desired-set computation is SHARED between the additive and subtractive halves. A gate placed above it
// — or one that let converge() run on a failed fetch — would make removals derivable from an EMPTY member
// set, which strips every member of every synced group on the first directory outage. That is the failure
// this whole subsystem was designed against, and the gate is exactly the kind of edit that could reintroduce
// it, so it is re-proven here on the LAPSED path specifically rather than trusted from the licensed one.
func TestLapsedLicence_TransientFetchStillRemovesNobody(t *testing.T) {
	s := baseStore()
	s.current[grp] = []uuid.UUID{uAli, uBob}
	p := &fakeProvider{listErr: errors.New("graph 503 service unavailable")}
	d := &fakeDeprov{}
	runGated(t, p, s, d, false)

	if len(s.removed) != 0 || len(d.deactivated) != 0 {
		t.Fatalf("⛔ FAIL-STATIC BROKEN ON THE LAPSED PATH: a failed fetch removed %+v and swept %+v",
			s.removed, d.deactivated)
	}
	if len(s.added) != 0 {
		t.Errorf("want no adds either, got %+v", s.added)
	}
}

// ⛔ THE COPY MUST NOT READ AS A FAULT — founder-ruled, and it is a security requirement wearing
// copywriting clothes.
//
// An operator who reads "IdP sync: error" does the obvious remedial thing: disconnects the credential or
// re-enters it. The deprovision half stops with it, and the fail-open D1 exists to close reopens — caused
// by the wording, on a deployment that was behaving correctly.
//
// So the words are pinned. This is a spelling test in form and a fail-open guard in substance.
func TestPausedProvisioningCopyDoesNotReadAsAFault(t *testing.T) {
	title, body := DescribeProvisioning(ProvisioningPaused)
	if title == "" || body == "" {
		t.Fatal("the paused state must SAY something — silence is the thing the founder ruled against: the " +
			"customer is entitled to know their deployment is still calling their IdP on a lapsed licence")
	}
	text := strings.ToLower(title + " " + body)

	// Fault vocabulary. Each of these invites the operator to go and fix something that is not broken.
	for _, w := range []string{"error", "failed", "failure", "broken", "unavailable", "cannot", "problem", "unable"} {
		if strings.Contains(text, w) {
			t.Errorf("⛔ the copy contains fault vocabulary %q — an operator reading this as an error "+
				"disconnects the credential, which STOPS DEPROVISIONING and reopens the exact fail-open "+
				"D1 closed:\n  %s\n  %s", w, title, body)
		}
	}

	// And the three facts the founder required it to carry.
	for _, want := range []struct{ frag, why string }{
		{"licence has lapsed", "the operator must learn WHY, or 'partially licensed' is a riddle"},
		{"no longer being added", "the capability that stopped must be named, or renewal has no motive"},
		{"removals are still being applied", "⛔ the SECURITY half — without it the operator cannot know " +
			"leavers still lose access, and may go looking for another way to revoke them"},
	} {
		if !strings.Contains(text, want.frag) {
			t.Errorf("the copy must state %q — %s\ngot: %s", want.frag, want.why, body)
		}
	}

	// ⚠ And nothing at all on the licensed path: a permanent "provisioning is working" banner trains the
	// reader to stop seeing the line that matters when it changes.
	if tl, bd := DescribeProvisioning(ProvisioningActive); tl != "" || bd != "" {
		t.Errorf("the ACTIVE state must say nothing, got %q / %q", tl, bd)
	}
}
