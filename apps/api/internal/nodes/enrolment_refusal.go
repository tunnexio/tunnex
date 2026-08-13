package nodes

// The enrolment refusal — D25(B). BUILT, TESTED, AND DELIBERATELY UNARMED.
//
// ⛔ WHY IT IS NOT A CONFIG FLAG.
//
// A flag that an operator can switch off is the grandfather clause D14 refused: the moment an unowned agent
// is inconvenient, the refusal gets disabled in an environment variable and nobody ever turns it back on.
// **A build-time constant is a FACT about the binary.** Flipping it is one line, in a commit, with its own
// red — visible in a diff, attributable to a person, and reviewable. There is no runtime path to `false`.
//
// ⛔ WHY IT SHIPS UNARMED AT ALL.
//
// Slice 2 ships a refusal whose CURE has never been watched working. S15.1 proved that an unowned machine
// credential is REFUSED — reds, mutations, and a 422 on the wire — and it never proved that assigning an
// owner brings one BACK (`docs/S15.0-decisions.md` §15, still owed).
//
// > **A REFUSAL PROVEN AND A CURE UNPROVEN IS ACCEPTABLE ON A PIPELINE AND NOT ON A DATA PLANE.** A refused
// > GitOps operator fails a build. A refused agent fails a tunnel — and the first demonstration that an
// > owner can be assigned back would be on a gateway that will not come up.
//
// So the refusal exists, is exercised by tests in both directions, and returns `false` at the one place that
// matters until the proof is discharged: one credential, three states, on the wire — refused → assigned →
// authenticates.
//
// ⛔ ARMED 2026-08-04, AND THE LICENCE IS A MEASUREMENT, NOT A DECISION TO SHIP IT.
//
// The gate was the D14 restore proof (`docs/S15.0-decisions.md` §15). It was **discharged on the wire** at
// EPIC 15 walk Leg 1 (`walk-artifacts/EPIC-15-leg1-leg4.md`): one credential, three states, in order —
// **401 refused → 204 assign through the picker's endpoint → 200 authenticates**, same token, same call.
// Non-vacuous (three org-scoped endpoints returning real data), and controlled (a second credential left
// UNOWNED returns 401 on those same three, so the flip was ownership and not the endpoint).
//
// > **A REFUSAL SHIPPED UNARMED BECAUSE ITS CURE WAS UNPROVEN DOES NOT STAY UNARMED ONCE THE CURE IS
// > PROVEN.** Leaving it would be the dormant-machinery law in exactly the case that law was written for:
// > machinery that exists, is correct, is tested, and does nothing.
//
// ⚠ AND UNARMED WAS NOT UNBUILT — that was the point. The rule shipped with tests and mutation evidence, so
// arming it is a boolean flip over a proven implementation rather than a leap of faith. This is the payoff
// of having built it early.
const enrolmentRefusalArmed = true

// RefuseUnownedEnrolment reports whether an enrolment with no resolvable owner must be refused.
//
// ⛔ THE ARMING CHECK IS FIRST AND THE PREDICATE IS SECOND, DELIBERATELY. Written the other way round, a
// test that exercises the predicate would silently be testing the constant instead — and would keep passing
// if the predicate were later broken. Here the predicate is a pure function of its input (`RefusalWouldFire`)
// and the arming is a separate, visible gate over it.
func RefuseUnownedEnrolment(hasOwner bool) bool {
	if !enrolmentRefusalArmed {
		return false
	}
	return RefusalWouldFire(hasOwner)
}

// RefusalWouldFire is the refusal's actual rule, independent of whether it is armed.
//
// ⚠ EXPORTED SO THE RULE CAN BE TESTED WITHOUT THE CONSTANT. A test that could only reach the rule through
// `RefuseUnownedEnrolment` would, while unarmed, assert nothing about the rule at all — it would assert that
// `false` is `false`, pass forever, and give a future arming commit no safety net whatsoever.
func RefusalWouldFire(hasOwner bool) bool {
	return !hasOwner
}

// EnrolmentRefusalArmed exposes the constant for tests and for the surface that tells an operator the truth
// about what this build does.
//
// ⚠ A SURFACE THAT CLAIMED "UNOWNED AGENTS ARE REFUSED" WHILE THIS IS FALSE WOULD BE THE WORSE FAILURE — a
// security claim the binary does not implement. The flag is readable so the copy can match the build.
func EnrolmentRefusalArmed() bool { return enrolmentRefusalArmed }
