package ipsec

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// Use an applied marked-static owner and a separately nonce-qualified candidate;
// this tests advisory adoption only, after the caller's native commit fences.
func committedRecoveryPolicyFixture(t *testing.T) (*recoveryTestRig, uuid.UUID, runtimeActive, runtimeActive) {
	t.Helper()
	r := newRecoveryTestRigTransport(t, true, uuid.New())
	r.status = [2]string{"up", "up"}
	r.now = 5 * time.Second
	if err := r.apply(); err != nil {
		t.Fatal(err)
	}
	id := r.m.Manifest.ConnectionID
	old := r.c.active[id]
	if !runtimeDesktopEntrySupported(old.Entry) {
		t.Fatal("marked static fixture required")
	}
	next := old
	next.Identity.PolicyHash = strings.Repeat("b", 64)
	if next.Identity.PolicyHash == old.Identity.PolicyHash {
		next.Identity.PolicyHash = strings.Repeat("c", 64)
	}
	next.Authority = NewPermitLeaseAuthority()
	req, err := next.Authority.Begin(next.Identity)
	if err != nil {
		t.Fatal(err)
	}
	if err = next.Authority.Accept(PermitLeaseResponse{PermitLeaseRequest: req, TTLMillis: 60000}); err != nil {
		t.Fatal(err)
	}
	h := r.c.recoveryHistory[id]
	if h == nil || !h.seen {
		t.Fatal("applied owner lacks native advice")
	}
	h.consecutive, h.firstDown = 2, time.Second
	r.c.recoveryReportClocks = map[uuid.UUID]runtimeRecoveryReportClock{id: {epoch: h.epoch, current: h.current, sequence: 1, returned: 5 * time.Second}}
	r.now = 10 * time.Second
	return r, id, old, next
}

func TestCommittedRecoveryPolicyAdviceKeepsNativeClockAndResetsHold(t *testing.T) {
	r, id, old, next := committedRecoveryPolicyFixture(t)
	prior := *r.c.recoveryHistory[id]
	events, switches := len(r.events), r.switches
	entries, _ := r.c.journal.Entries()
	oldDeadline, newDeadline := old.Authority.deadline, next.Authority.deadline
	if err := r.c.resetCommittedRecoveryPolicyAdvice(map[uuid.UUID]runtimeActive{id: next}, map[uuid.UUID]runtimeActive{id: old}); err != nil {
		t.Fatal(err)
	}
	got := r.c.recoveryHistory[id]
	if got.epoch != recoveryReportEpoch(next) || got.current != prior.current || got.lastAt != prior.lastAt || got.lastNow != prior.lastNow || !got.seen || got.consecutive != 0 || got.firstDown != 0 {
		t.Fatal("epoch adoption minted time or retained old failover hold", got, prior)
	}
	if _, present := r.c.recoveryReportClocks[id]; present {
		t.Fatal("prior policy report clock survived")
	}
	after, _ := r.c.journal.Entries()
	if !reflect.DeepEqual(entries, after) || !reflect.DeepEqual(r.c.active[id], old) || old.Authority.deadline != oldDeadline || next.Authority.deadline != newDeadline || len(r.events) != events || r.switches != switches {
		t.Fatal("advice reset changed native state, authority or active policy")
	}
	// A next genuine down sample must start a new hold; old two-sample evidence
	// cannot authorize a failover under the newly committed policy epoch.
	observation := recoveryObservation{Epoch: got.epoch, Current: got.current, Status: [2]string{"down", "up"}, Authorized: true, At: 10 * time.Second}
	if got.current == 2 {
		observation.Status = [2]string{"up", "down"}
	}
	advice := got.observe(got.epoch, 10*time.Second, observation)
	if advice.Target != 0 || got.consecutive != 1 || got.firstDown != 10*time.Second {
		t.Fatal("old failover evidence crossed policy epoch", advice, got)
	}
}

func TestCommittedRecoveryPolicyAdviceMissingRemainsMissing(t *testing.T) {
	r, id, old, next := committedRecoveryPolicyFixture(t)
	delete(r.c.recoveryHistory, id)
	if err := r.c.resetCommittedRecoveryPolicyAdvice(map[uuid.UUID]runtimeActive{id: next}, map[uuid.UUID]runtimeActive{id: old}); err != nil {
		t.Fatal(err)
	}
	if r.c.recoveryHistory[id] != nil {
		t.Fatal("policy adoption invented native observation")
	}
	if _, ok := r.c.recoveryReportClock(next); ok {
		t.Fatal("old report clock became a current report")
	}
}

func TestCommittedRecoveryPolicyAdviceRejectsForeignMetadataAtomically(t *testing.T) {
	for _, kind := range []string{"foreign_epoch", "selected_slot", "backwards_clock", "same_authority", "nil_authority", "binding", "delivery", "entry", "environment", "invalid_hash"} {
		t.Run(kind, func(t *testing.T) {
			r, id, old, next := committedRecoveryPolicyFixture(t)
			switch kind {
			case "foreign_epoch":
				r.c.recoveryHistory[id].epoch.DeliveryID = uuid.New()
			case "selected_slot":
				r.c.recoveryHistory[id].current = 3 - selectedRuntimeSlot(old.Entry)
			case "backwards_clock":
				r.now = r.c.recoveryHistory[id].lastNow - time.Nanosecond
			case "same_authority":
				next.Authority = old.Authority
			case "nil_authority":
				next.Authority = nil
			case "binding":
				next.Identity.Binding.DesiredRevision++
			case "delivery":
				next.Identity.DeliveryID = uuid.New()
			case "entry":
				next.Entry.OwnershipDigest = strings.Repeat("e", 64)
			case "environment":
				next.Environment.Namespace = "net:[4026533999]"
			case "invalid_hash":
				next.Identity.PolicyHash = "invalid"
			}
			pointer := r.c.recoveryHistory[id]
			before := *pointer
			clock := r.c.recoveryReportClocks[id]
			if err := r.c.resetCommittedRecoveryPolicyAdvice(map[uuid.UUID]runtimeActive{id: next}, map[uuid.UUID]runtimeActive{id: old}); err == nil {
				t.Fatal("foreign metadata accepted")
			}
			if r.c.recoveryHistory[id] != pointer || *pointer != before || r.c.recoveryReportClocks[id] != clock {
				t.Fatal("failed adoption partially changed advice")
			}
		})
	}
}

func TestCommittedRecoveryPolicyAdviceValidatesAllOwnersBeforeWriting(t *testing.T) {
	r, first, old, next := committedRecoveryPolicyFixture(t)
	other, second, oldOther, nextOther := committedRecoveryPolicyFixture(t)
	r.c.recoveryHistory[second] = other.c.recoveryHistory[second]
	r.c.recoveryReportClocks[second] = other.c.recoveryReportClocks[second]
	nextOther.Identity.Binding.DesiredRevision++
	pointers := map[uuid.UUID]*recoveryDecision{first: r.c.recoveryHistory[first], second: r.c.recoveryHistory[second]}
	values := map[uuid.UUID]recoveryDecision{first: *pointers[first], second: *pointers[second]}
	clocks := map[uuid.UUID]runtimeRecoveryReportClock{first: r.c.recoveryReportClocks[first], second: r.c.recoveryReportClocks[second]}
	if err := r.c.resetCommittedRecoveryPolicyAdvice(map[uuid.UUID]runtimeActive{first: next, second: nextOther}, map[uuid.UUID]runtimeActive{first: old, second: oldOther}); err == nil {
		t.Fatal("one invalid owner accepted")
	}
	for id, pointer := range pointers {
		if r.c.recoveryHistory[id] != pointer || *pointer != values[id] || r.c.recoveryReportClocks[id] != clocks[id] {
			t.Fatal("multi-owner adoption changed state before all validation", id)
		}
	}
}
