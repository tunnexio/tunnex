package nodes

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/tunnexio/tunnex/apps/api/internal/licence"
)

// ⛔ THE GATEWAY CEILING IS ENFORCED IMMEDIATELY — no warning window, no grandfathering.
//
// FOUNDER-RULED, and the reason is what makes it safe: THERE ARE NO CUSTOMERS. The licence mechanism has
// never shipped, the site says BETA, and no deployment exists outside the founder's rig. A migration story
// protects existing deployments from a change they did not ask for; there are none, so there is nothing to
// protect.
//
// ⚠ THIS RULING HAS AN EXPIRY CONDITION, AND IT IS NOT A PERMANENT POLICY. The first real deployment makes
// this same change a BREAKING one, and grandfathering becomes the right answer. Anyone reading "we enforce
// immediately" as standing policy is reading it out of the only context that justified it.

func TestTheBandsAreTheFoundersNumbers(t *testing.T) {
	for _, tc := range []struct {
		tier licence.Tier
		want string
	}{
		{licence.TierCommunity, "1"},
		{licence.TierTrial, "2"},
		{licence.TierStarter, "5"},
		{licence.TierGrowth, "20"},
		{licence.TierScale, "unlimited"},
	} {
		got := "unlimited"
		if c, _ := licence.GatewayCeilingFor(tc.tier); c != nil {
			got = itoa(*c)
		}
		if got != tc.want {
			t.Errorf("%s: ceiling = %s, want %s", tc.tier, got, tc.want)
		}
	}
}

// ⭐ THE REFUSAL IS THE FEATURE. It is the first thing a real customer meets, and a bare failure looks like
// a broken install rather than a licence boundary. This asserts the message carries what an operator needs
// to ACT: which band, what the ceiling is, how many exist, that nothing running is affected, and the two
// ways out.
func TestTheRefusalIsLegible(t *testing.T) {
	s := &Service{}
	msg := s.ceilingRefusal(licence.TierCommunity, 1, 1)

	for _, want := range []struct{ frag, why string }{
		{"community", "the operator must learn WHICH band they are on"},
		{"1 gateway", "…and what the ceiling IS, or they cannot tell whether it is wrong"},
		{"already enrolled", "…and how many they have, so the arithmetic is theirs to check"},
		{"Nothing running is affected", "⛔ THE FEAR THIS ANSWERS: an operator who reads a licence refusal " +
			"assumes their live gateways are next. Saying so is the difference between a boundary and an outage"},
		{"upgrade the licence", "a way out"},
		{"revoke a gateway", "the OTHER way out — one that costs nothing and needs no purchase"},
	} {
		if !strings.Contains(strings.ToLower(msg), strings.ToLower(want.frag)) {
			t.Errorf("the refusal must mention %q — %s\n\ngot: %s", want.frag, want.why, msg)
		}
	}
	// ⚠ And it must not read as a fault: this is correct behaviour.
	for _, bad := range []string{"error", "failed", "unexpected"} {
		if strings.Contains(strings.ToLower(msg), bad) {
			t.Errorf("the refusal contains fault vocabulary %q — a licence boundary is not a malfunction", bad)
		}
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

// ⚠ A Service with no licence manager behaves as Community rather than refusing everything — the fail-open
// default, asserted so nobody "fixes" the nil check into an error.
func TestNoManagerMeansCommunityNotRefusal(t *testing.T) {
	s := &Service{}
	if got := s.effectiveTier(time.Now()); got != licence.TierCommunity {
		t.Fatalf("a Service without a licence manager must be Community, got %v", got)
	}
}

// ⛔ THE PAID CEILING WAS LIFTABLE BY CLICKING "+ New" (founder-found).
//
// The enrolment check counted `CountLiveNodesForOrg`. Starter allows 5 gateways and UNLIMITED
// organizations, so the real ceiling was 5 × however many organizations the customer created — using the
// product's own header control, with no exploit and no API misuse. Growth was 20 × N. Community and trial
// looked safe only because their ORG ceiling happens to be 1, which is two numbers agreeing rather than a
// boundary.
//
// > ## ⛔ **A CEILING SCOPED MORE NARROWLY THAN THE THING THAT GRANTS IT IS NOT A CEILING.**
//
// ⚠ THIS TEST READS THE QUERY THE CHECK USES, because that is where the defect lived — not in the numbers,
// which were right, and not in the message, which was honest. A behavioural version needs two orgs and a
// live database; this one fails on the same line the bug was on and runs everywhere.
func TestTheGatewayCeilingCountsTheWholeDeployment(t *testing.T) {
	src, err := os.ReadFile("service.go")
	if err != nil {
		t.Fatal(err)
	}
	body := funcSource(string(src), "func (s *Service) checkGatewayCeiling(")
	if body == "" {
		t.Fatal("⛔ checkGatewayCeiling not found — this guard has stopped guarding anything")
	}
	if strings.Contains(body, "CountLiveNodesForOrg") {
		t.Error("⛔ THE LICENCE CEILING IS COUNTING ONE ORGANIZATION AGAIN. Starter allows 5 gateways and " +
			"UNLIMITED organizations, so a per-org count makes the paid ceiling 5 × N — liftable by the " +
			"'+ New' button in the product's own header. Count the deployment: CountLiveNodes.")
	}
	if !strings.Contains(body, "CountLiveNodes(ctx)") {
		t.Error("⛔ the ceiling check no longer reads the deployment-wide count")
	}

	// ⚠ AND THE COMBINATION THAT MADE IT EXPLOITABLE IS PINNED, not just the code. If a future band ever
	// gets a finite gateway ceiling AND an unlimited org ceiling, a per-org count would be catastrophic
	// again — this states which bands are in that shape so nobody has to re-derive it.
	multipliable := 0
	for _, tier := range []licence.Tier{
		licence.TierCommunity, licence.TierTrial, licence.TierStarter, licence.TierGrowth, licence.TierScale,
	} {
		gw, _ := licence.GatewayCeilingFor(tier)
		orgs, _ := licence.OrgCeilingFor(tier)
		if gw != nil && orgs == nil {
			multipliable++
		}
	}
	if multipliable == 0 {
		t.Error("⚠ no band has a finite gateway ceiling with unlimited organizations — if that is now " +
			"true by design, this guard is checking nothing and the reason should be written down")
	}
}

// funcSource returns a function's source up to its closing brace at column 0.
func funcSource(src, prefix string) string {
	i := strings.Index(src, prefix)
	if i < 0 {
		return ""
	}
	rest := src[i:]
	if j := strings.Index(rest, "\n}\n"); j > 0 {
		return rest[:j]
	}
	return rest
}
