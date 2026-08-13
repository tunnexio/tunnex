package nodes

import (
	"os"
	"strings"
	"testing"
)

// ⛔ THE RULE IS TESTED SEPARATELY FROM ITS ARMING, AND THAT SEPARATION IS THE POINT.
//
// While `enrolmentRefusalArmed` is false, every test that reaches the refusal through
// `RefuseUnownedEnrolment` asserts that `false` is `false`. It would pass with the rule inverted, deleted,
// or replaced by `return false` — and it would hand the commit that ARMS the refusal a test suite that had
// never once exercised what it is about to switch on.
//
// This is the tautological-guard law in its natural habitat: a guard whose test cannot fail is not a test.

func TestRefusalRuleBothDirections(t *testing.T) {
	// The rule itself, reachable without the constant.
	if !RefusalWouldFire(false) {
		t.Fatal("an enrolment with NO owner must fire the refusal")
	}
	// ⛔ THE SECOND HALF IS WHY THE FIRST MEANS ANYTHING. A rule that refused everything would pass above.
	if RefusalWouldFire(true) {
		t.Fatal("an enrolment WITH an owner must NOT fire the refusal")
	}
}

// TestRefusalIsArmed — ⭐ THE ASSERTION THAT HAS NEVER RUN UNTIL NOW, AND THAT WAS THE DESIGN.
//
// While the constant was false, this file's other test exercised the RULE (`RefusalWouldFire`) and the gate
// (`RefuseUnownedEnrolment`) returned false for every input — so nothing here had ever asserted the armed
// path. That separation is precisely what made arming a boolean flip over a proven implementation instead
// of a leap of faith, and this is where it pays.
//
// ⛔ THE LICENCE IS THE D14 RESTORE PROOF, DISCHARGED ON THE WIRE at EPIC 15 walk Leg 1
// (`walk-artifacts/EPIC-15-leg1-leg4.md`): 401 refused → 204 assign → 200 authenticates, same token, same
// call, with a control proving the flip was ownership and not the endpoint.
func TestRefusalIsArmed(t *testing.T) {
	if !EnrolmentRefusalArmed() {
		t.Fatal("the enrolment refusal is ARMED as of the D14 restore proof's discharge (EPIC 15 walk Leg 1). " +
			"If this is being disarmed, say why in the commit — a refusal that goes back to sleep needs a " +
			"reason as explicit as the one that woke it.")
	}
}

// TestArmedGateRefusesUnownedAndAdmitsOwned — ⛔ BOTH DIRECTIONS THROUGH THE GATE, NOT THE RULE.
//
// The rule is tested separately above. This is the GATE — arming composed with the rule — and it is the
// thing that now actually runs in production.
//
// ⚠ THE SECOND HALF IS WHY THE FIRST MEANS ANYTHING. An armed gate that refused EVERYTHING would pass the
// refusal assertion and would brick every enrolment in the product, including every owned one. That is a
// worse outcome than the defect the refusal exists to prevent, and it is one boolean away at all times.
func TestArmedGateRefusesUnownedAndAdmitsOwned(t *testing.T) {
	if !RefuseUnownedEnrolment(false) {
		t.Fatal("ARMED: an enrolment with NO owner must be REFUSED")
	}
	if RefuseUnownedEnrolment(true) {
		t.Fatal("ARMED: an enrolment WITH an owner must still SUCCEED — a gate that refuses everything is " +
			"not a guard, it is an outage")
	}
}

// ⛔ AND THE GATE MUST BE CALLED, WHICH IS A DIFFERENT CLAIM FROM THE GATE BEING CORRECT.
//
// Arming `enrolmentRefusalArmed` changed nothing on its own: `RefuseUnownedEnrolment` had **zero call
// sites**. A guard that is armed, tested in both directions, mutation-proven — and never invoked — is the
// dormant-machinery law wearing a passing test suite.
//
// > **THE WHO-READS-THIS PROBE APPLIES TO GUARDS, NOT ONLY TO CHANNEL FIELDS.** Name the caller and cite the
// > line, or the guard is decoration.
//
// This test reads the enrolment path's source and fails if the call disappears — a rename or a refactor that
// drops it is caught here rather than by an unowned agent appearing in production.
func TestEnrolmentPathActuallyCallsTheGate(t *testing.T) {
	b, err := os.ReadFile("service.go")
	if err != nil {
		t.Fatalf("read service.go: %v", err)
	}
	src := string(b)
	if !strings.Contains(src, "RefuseUnownedEnrolment(") {
		t.Fatal("the enrolment path does not call RefuseUnownedEnrolment — the refusal is armed and " +
			"UNREACHABLE, which is worse than unarmed: the constant claims a protection nothing applies")
	}
	// ⚠ AND IT MUST BE INSIDE Enroll, not merely somewhere in the file. A call in an unrelated function
	// would satisfy the check above while leaving enrolment ungated.
	enroll := src[strings.Index(src, "func (s *Service) Enroll("):]
	if end := strings.Index(enroll, "\nfunc "); end > 0 {
		enroll = enroll[:end]
	}
	if !strings.Contains(enroll, "RefuseUnownedEnrolment(") {
		t.Fatal("RefuseUnownedEnrolment is called, but NOT inside Enroll — the gate is on a path that " +
			"enrolment does not take")
	}
}
