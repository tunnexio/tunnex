package licence

import (
	"strings"
	"testing"
	"time"
)

// ⛔ THE GRACE LADDER, AND THE ASSERTIONS THAT MATTER ARE THE NEGATIVE ONES.
//
//	valid  → everything
//	expired (0–90 days) → paid capabilities STILL WORK. Only new principals are refused.
//	lapsed  (90 days +) → paid capabilities stop. The VPN still does not.
//
// ⚠ A ladder is easy to test in the direction that reads well ("expired refuses!") and that direction is
// the half that cannot cause an outage. The half that CAN is "expired must not stop anything", and it is
// the half a plausible refactor breaks — collapse StateExpired into StateLapsed and every "it refuses"
// test still passes while every paying customer's SSO dies on the expiry date.

const (
	graceExp    = 1_700_000_000 // the expiry instant used throughout
	oneDay      = 24 * 60 * 60
	graceLength = 90 * oneDay
)

func at(offsetSeconds int64) time.Time { return time.Unix(graceExp+offsetSeconds, 0) }

// ⭐ THE LOAD-BEARING ONE. During grace a customer keeps every capability they paid for.
func TestExpiredStopsNothingAtAll(t *testing.T) {
	m := withClaims("growth", at(0))
	for _, when := range []int64{1, oneDay, 30 * oneDay, graceLength - 1} {
		now := at(when)
		if got := m.Evaluate(now).State; got != StateExpired {
			t.Fatalf("+%ds: state = %v, want StateExpired", when, got)
		}
		if !m.Has(FeatSSO, now) {
			t.Errorf("+%ds: SSO STOPPED DURING GRACE — a paying customer was locked out on their "+
				"expiry date, which is the exact outage grace exists to prevent", when)
		}
		if !m.Has(FeatIdpSync, now) || !m.Has(FeatMultiOrg, now) {
			t.Errorf("+%ds: a gated capability stopped during grace", when)
		}
		if c := m.GatewayCeilingNow(now); c == nil || *c != 20 {
			t.Errorf("+%ds: gateway ceiling = %v, want the Growth band (20) — grace must not "+
				"retroactively shrink a band under running gateways", when, c)
		}
	}
}

// ⛔ AND THE ONE THING GRACE DOES CHANGE: growth stops.
func TestExpiredRefusesNewPrincipals(t *testing.T) {
	m := withClaims("growth", at(0))
	if !m.AllowsNewPrincipals(at(-1)) {
		t.Fatal("a valid licence must allow enrolment")
	}
	for _, when := range []int64{1, 30 * oneDay, graceLength - 1, graceLength + 1, 400 * oneDay} {
		if m.AllowsNewPrincipals(at(when)) {
			t.Errorf("+%ds after expiry: a new principal was allowed", when)
		}
	}
}

// ⚠ THE ONE STATE THAT IS NOT ON THE LADDER AT ALL. No licence is not a lapsed licence — Community is a
// product, not a punishment, and a deployment that never had a key must never be told one expired.
func TestUnlicensedIsNotOnTheLadder(t *testing.T) {
	m := &Manager{}
	if !m.AllowsNewPrincipals(at(0)) {
		t.Fatal("⛔ COMMUNITY CANNOT ENROL A DEVICE. The free tier was just turned off for everyone " +
			"who never bought anything — the exact opposite of the model")
	}
}

// ⛔ AFTER GRACE: gated capabilities stop, the tier falls to Community — and that is the ONLY thing that
// changes. Nothing here touches a running tunnel, and nothing can: the manager has no data-plane reach.
func TestLapsedFallsToCommunityAndNoFurther(t *testing.T) {
	m := withClaims("growth", at(0))
	now := at(graceLength + oneDay)
	st := m.Evaluate(now)
	if st.State != StateLapsed {
		t.Fatalf("state = %v, want StateLapsed", st.State)
	}
	if st.Tier != TierCommunity {
		t.Fatalf("lapsed tier = %v, want Community", st.Tier)
	}
	if m.Has(FeatSSO, now) {
		t.Error("SSO survived the full grace period — the gate never closes")
	}
	if c := m.GatewayCeilingNow(now); c == nil || *c != 1 {
		t.Errorf("lapsed gateway ceiling = %v, want the Community band (1)", c)
	}
	// ⭐ THE BOUNDARY, ASSERTED FROM BOTH SIDES — one second earlier is still grace. An off-by-one in the
	// comparison is a customer losing SSO 90 days before they were told they would.
	if m.Evaluate(at(graceLength-1)).State != StateExpired {
		t.Error("the last second of grace is not grace")
	}
}

// ⭐ THE REFUSAL TEXT IS PRODUCT, NOT PLUMBING. An operator meets it at the worst possible moment and it
// must answer their only real question — "is my fleet down?" — before it says no to anything.
func TestRefusalReassuresBeforeItRefuses(t *testing.T) {
	msg := withClaims("growth", at(0)).NewPrincipalRefusal(at(oneDay))
	for _, want := range []string{"keeps working", "nothing has stopped", "renewed"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the refusal never says %q — an operator reading it cannot tell whether their "+
				"running gateways are affected:\n%s", want, msg)
		}
	}
	// ⛔ THE DATE, NOT THE WORD. "expired" alone is unactionable; the date tells them whether this is a
	// renewal they forgot or a clock that is wrong.
	if !strings.Contains(msg, "2023") {
		t.Errorf("the refusal does not name the expiry date:\n%s", msg)
	}
}
