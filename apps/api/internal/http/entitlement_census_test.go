package http

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/tunnexio/tunnex/apps/api/internal/licence"
)

// ⛔ THE ENTITLEMENT CENSUS — what replaced `test-editions`.
//
// `make test-editions` proved a COMPILE-TIME property: paid code was ABSENT from the open binary. Not "the
// endpoint refuses" — the function was not in the artifact. The compiler enforced it and no test had to
// remember. S12.1 retired that permanently: one binary, every capability present, gated by a runtime
// boolean. A boolean someone forgets to check is a capability given away silently, and the compiler will
// never mention it.
//
// > **A COMPILE-TIME GUARANTEE FAILS LOUDLY AND FOR FREE. A RUNTIME ONE FAILS SILENTLY UNLESS SOMETHING
// > COUNTS IT. THIS IS THE SOMETHING.**
//
// ⚠ THE SUBJECT MOVED ONCE ALREADY, AND THAT IS THE INTERESTING PART. This census used to enumerate
// `*_wire_open.go` stubs — the build-tag boundary. S12.1 deleted them, and the census's own vacuity floor
// fired ("found no capability seam at all") rather than passing over an empty set. That floor is why the
// move was noticed instead of the census silently becoming a no-op (docs/laws.md: a census whose subject
// is a proxy drifts out from under it silently).

// Tier is which side of the commercial boundary a capability sits on.
type Tier int

const (
	Community Tier = iota
	Enterprise
)

type disposition struct {
	tier   Tier
	reason string
}

// ⛔ TIERS MIRRORS internal/licence/entitlements.go BY HAND.
//
// Deriving it would make the census compare the map to itself — it would pass for every possible map,
// including one that gave SSO away. The independent restatement IS the mechanism: a check must be able to
// DISAGREE with the thing it checks, and derivation removes that ability while looking like rigour.
var TIERS = map[string]disposition{
	"multi_gateway": {Enterprise, "more than one gateway. Community 1 · trial 2 · Starter 5 · Growth 20 · Scale unlimited"},
	"multi_org":     {Enterprise, "more than one organization"},
	"sso":           {Enterprise, "SSO/OIDC — Google and Microsoft Entra"},
	"idp_sync": {Enterprise, "IdP directory sync. ⚠ Its DEPROVISION half is NOT gated: a licence may stop " +
		"granting access, it must never stop removing it"},
}

// capabilitySeams derives the census's input FROM THE TIER MAP AT RUNTIME, so a feature someone adds is in
// scope the moment it exists — never a hardcoded list that silently stops covering.
func capabilitySeams() map[string]string {
	found := map[string]string{}
	for _, f := range licence.AllFeatures() {
		found[string(f)] = "internal/licence/entitlements.go"
	}
	return found
}

// ⛔ THE VACUITY FLOOR. Without it, a census over an empty input set reports a clean bill of health forever
// — which is exactly what would have happened when the old subject was deleted.
func TestCensusInputIsNotEmpty(t *testing.T) {
	if len(capabilitySeams()) == 0 {
		t.Fatal("⛔ the census has NO INPUT — it would pass over an empty set forever")
	}
}

// ⛔ SET EQUALITY, BOTH DIRECTIONS. One-sided lets TIERS accumulate rulings for capabilities that no longer
// exist, and a stale ruling reads exactly like a live one.
func TestEveryPaidCapabilityHasATierRuling(t *testing.T) {
	seams := capabilitySeams()

	var undispositioned []string
	for capability, where := range seams {
		if _, ok := TIERS[capability]; !ok {
			undispositioned = append(undispositioned, fmt.Sprintf("  %s\t(%s)", capability, where))
		}
	}
	sort.Strings(undispositioned)
	if len(undispositioned) > 0 {
		t.Errorf("⛔ CAPABILITY WITH NO TIER RULING — it exists in the entitlement map and nobody has "+
			"decided whether customers get it:\n%s\n\nAdd it to TIERS with a reason. A capability that is "+
			"gated by accident is given away, or withheld, by accident.", strings.Join(undispositioned, "\n"))
	}

	var stale []string
	for capability := range TIERS {
		if _, ok := seams[capability]; !ok {
			stale = append(stale, "  "+capability)
		}
	}
	sort.Strings(stale)
	if len(stale) > 0 {
		t.Errorf("⚠ TIER RULING FOR A CAPABILITY THAT NO LONGER EXISTS — the map describes code that is "+
			"gone, and a stale ruling is indistinguishable from a live one:\n%s", strings.Join(stale, "\n"))
	}
}

// ⛔ THE MODEL'S HEADLINE, ASSERTED RATHER THAN TRUSTED: "gated — four, and only four".
//
// ⭐ FOUR NOW. `multi_gateway` became real in S12.1 — the story the founder actually asked for. It was
// three while the gateway limit existed only in prose.
func TestTheFourGatesAreExactlyFour(t *testing.T) {
	var ent []string
	for capability, d := range TIERS {
		if d.tier == Enterprise {
			ent = append(ent, capability)
		}
	}
	sort.Strings(ent)
	want := []string{"idp_sync", "multi_gateway", "multi_org", "sso"}
	if strings.Join(ent, ",") != strings.Join(want, ",") {
		t.Errorf("the Enterprise tier is %v; expected %v.\n\nIf a capability MOVED tiers that is a product "+
			"decision, and docs/S12.1-licensing-decisions.md must move with it.", ent, want)
	}
}

// ⭐ AND THE HALF THAT MATTERS COMMERCIALLY: everything else is Community, deliberately.
func TestCommunityKeepsTheProduct(t *testing.T) {
	for _, f := range licence.AllFeatures() {
		if licence.Has(licence.TierCommunity, f) {
			t.Errorf("%q is granted to Community but is dispositioned Enterprise — the entitlement map and "+
				"this census disagree about who pays for it", f)
		}
	}
	// The Zero Trust engine, agents, Kubernetes, posture, approval, MFA enforcement and the audit log are
	// NOT Features at all — being ungated is HOW they are free. A new Feature constant naming one of them
	// would be the moat being reversed without anyone saying so.
	for _, f := range licence.AllFeatures() {
		for _, forbidden := range []string{"policy", "zero_trust", "agent", "kubernetes", "posture", "audit", "mfa"} {
			if strings.Contains(string(f), forbidden) {
				t.Errorf("⛔ %q GATES A COMMUNITY CAPABILITY. The moat is the free tier's generosity, not "+
					"Enterprise's length — a thinner Community loses to NetBird's free self-hosted edition.", f)
			}
		}
	}
}
