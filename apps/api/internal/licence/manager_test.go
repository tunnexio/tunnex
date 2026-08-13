package licence

import (
	"testing"
	"time"
)

// ⛔ THE ZERO VALUE IS COMMUNITY, AND IT IS USABLE. This is the fail-open default, asserted first because it
// is what every deployment that upgrades into this code gets before anyone pastes a key.
func TestNoLicenceIsCommunityNotRefused(t *testing.T) {
	var m Manager
	st := m.Evaluate(time.Now())
	if st.State != StateUnlicensed || st.Tier != TierCommunity {
		t.Fatalf("an absent licence must be Community, got state=%v tier=%v", st.State, st.Tier)
	}
	// ⚠ WHAT COMMUNITY KEEPS — a deployment must not lose what it can keep.
	if gw := m.GatewayCeilingNow(time.Now()); gw == nil || *gw != 1 {
		t.Errorf("Community must keep exactly one gateway, got %v", gw)
	}
	// ...and what it loses, which the product must SAY rather than fail silently.
	for _, f := range []Feature{FeatSSO, FeatIdpSync, FeatMultiGateway, FeatMultiOrg} {
		if m.Has(f, time.Now()) {
			t.Errorf("%q must NOT be granted without a licence", f)
		}
	}
}

func withClaims(tier string, exp time.Time) *Manager {
	m := &Manager{}
	m.claims = &Claims{Version: 1, Tier: tier, Band: tier, ExpiresAt: exp.Unix()}
	return m
}

// ⛔ THE VERDICT IS EVALUATED PER READ, NOT CACHED AT LOAD. Settings change on write; a licence expires on
// TIME. The same manager, unmodified, must answer differently as the clock moves — a verdict computed once
// is wrong from the first second after expiry.
func TestTheVerdictFollowsTheClockNotTheLoad(t *testing.T) {
	exp := time.Unix(2_000_000_000, 0)
	m := withClaims("scale", exp)

	if st := m.Evaluate(exp.Add(-time.Hour)); st.State != StateValid {
		t.Errorf("before expiry: want valid, got %v", st.State)
	}
	// ⛔ EXPIRED IS NOT LAPSED — nothing stops, the entitlement is unchanged.
	if st := m.Evaluate(exp.Add(time.Hour)); st.State != StateExpired || st.Tier != TierScale {
		t.Errorf("inside grace: want expired AND still Scale, got state=%v tier=%v", st.State, st.Tier)
	}
	if st := m.Evaluate(exp.Add(GracePeriod - time.Hour)); st.Tier != TierScale {
		t.Error("the last hour of grace must still grant the licensed tier")
	}
	// After grace the gated capabilities stop — expressed as falling back to Community, not as a refusal.
	st := m.Evaluate(exp.Add(GracePeriod + time.Hour))
	if st.State != StateLapsed || st.Tier != TierCommunity {
		t.Errorf("after grace: want lapsed AND Community, got state=%v tier=%v", st.State, st.Tier)
	}
	// ⚠ AND THE MANAGER WAS NEVER MUTATED between those calls. If it had cached a verdict, the first
	// answer would have persisted.
	if m.Evaluate(exp.Add(-time.Hour)).State != StateValid {
		t.Error("⛔ the verdict was cached — going back in time must yield the earlier answer")
	}
}

// ⚠ AN UNKNOWN TIER IS COMMUNITY, NOT EVERYTHING. A licence naming a tier this build does not know is one
// it cannot honour; reading it generously would let a future tier name grant more than this build can
// enforce.
func TestUnknownTierReadsAsCommunity(t *testing.T) {
	m := withClaims("platinum", time.Unix(4_000_000_000, 0))
	st := m.Evaluate(time.Unix(2_000_000_000, 0))
	if st.Tier != TierCommunity {
		t.Fatalf("unknown tier must read as Community, got %v", st.Tier)
	}
	if m.Has(FeatSSO, time.Unix(2_000_000_000, 0)) {
		t.Error("an unknown tier must grant nothing")
	}
}

// ⚠ Keys minted before `tier` existed carry none. They are valid, and read as Community — exactly what they
// could do when they were signed. Never a defect, and never more than was attested.
func TestPreTierKeyReadsAsCommunity(t *testing.T) {
	m := withClaims("", time.Unix(4_000_000_000, 0))
	if got := m.Evaluate(time.Unix(2_000_000_000, 0)).Tier; got != TierCommunity {
		t.Fatalf("a key with no tier must read as Community, got %v", got)
	}
}

func TestCeilingsFollowTheTier(t *testing.T) {
	now := time.Unix(2_000_000_000, 0)
	exp := time.Unix(4_000_000_000, 0)
	for _, tc := range []struct {
		tier string
		want *int
	}{
		{"trial", ptr(2)}, {"starter", ptr(5)}, {"growth", ptr(20)}, {"scale", nil},
	} {
		got := withClaims(tc.tier, exp).GatewayCeilingNow(now)
		if (got == nil) != (tc.want == nil) || (got != nil && *got != *tc.want) {
			t.Errorf("%s: gateway ceiling = %v, want %v", tc.tier, got, tc.want)
		}
	}
}

// ⛔ A BAD PASTE MUST NOT DOWNGRADE A WORKING DEPLOYMENT.
func TestFailedInstallLeavesTheExistingLicenceAlone(t *testing.T) {
	m := withClaims("scale", time.Unix(4_000_000_000, 0))
	if _, err := m.Install(TrustedKeys, "tnxl_garbage"); err != nil {
		t.Fatalf("a malformed key is a refusal, not an error: %v", err)
	}
	if got := m.Evaluate(time.Unix(2_000_000_000, 0)).Tier; got != TierScale {
		t.Fatalf("⛔ a rejected paste replaced a working licence — got %v", got)
	}
}

// The clock is instrumentation, never a gate.
func TestBackwardClockIsReportedAndChangesNothing(t *testing.T) {
	m := withClaims("scale", time.Unix(4_000_000_000, 0))
	base := time.Unix(2_000_000_000, 0)
	m.Evaluate(base)
	st := m.Evaluate(base.Add(-48 * time.Hour))
	if !st.ClockWentBackwards {
		t.Fatal("a 48-hour backward jump must be reported")
	}
	if st.State != StateValid || st.Tier != TierScale {
		t.Error("⛔ the clock jump changed the verdict — it must REPORT, never refuse")
	}
}
