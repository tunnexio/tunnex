package policy

import (
	"os"
	"strings"
	"testing"
)

// TestSelfSiteRefusalIsCrossField — the guard that had no equivalent anywhere in this function.
//
// ⛔ EVERY OTHER CHECK IN CreatePolicyRule VALIDATES ONE SIDE. Twenty of them, all of the shape "does this
// side carry its own id" — and not one reads `src_kind` and `dst_kind` together or asks whether they name the
// same thing. That absence is what let the form offer a site reaching itself.
//
// > **A SITE CANNOT REACH ITSELF THROUGH ITS OWN GATEWAY.** Two hosts on one LAN are switched locally; their
// > traffic never enters that gateway's forward chain, so the compiler emits an allow that CANNOT MATCH.
//
// This is a source-reading test for the same reason `TestEnrolmentPathActuallyCallsTheGate` is: the rule is
// one comparison, and what actually needs pinning is that it is REACHED, on the path all three callers take.
func TestSelfSiteRefusalIsCrossField(t *testing.T) {
	b, err := os.ReadFile("service.go")
	if err != nil {
		t.Fatalf("read service.go: %v", err)
	}
	src := string(b)

	i := strings.Index(src, "func (s *Service) CreatePolicyRule(")
	if i < 0 {
		t.Fatal("CreatePolicyRule not found — if it was renamed, carry this guard with it")
	}
	fn := src[i:]
	if end := strings.Index(fn[1:], "\nfunc "); end > 0 {
		fn = fn[:end]
	}

	// ⛔ THE SITE-TO-ITSELF COMPARISON, INSIDE THE CREATE PATH. A check living anywhere else in the file
	// would satisfy a naive "contains" test while leaving creation ungated.
	if !strings.Contains(fn, "*in.SrcSiteID == *in.DstSiteID") {
		t.Fatal("CreatePolicyRule does not refuse a site reaching itself — the compiler emits an allow " +
			"that cannot match, and the rule renders `active` while enforcing nothing")
	}
	// ⛔ AND ITS NARROWED TWIN. `src_kind=cidr` is a site source narrowed to a prefix, so a CIDR inside the
	// destination site's own subnet is the identical impossible rule wearing a different kind. Refusing only
	// the site form would leave the same rule creatable one dropdown over.
	if !strings.Contains(fn, "sub.Cidr.Contains(src.Addr())") {
		t.Fatal("the cidr-inside-the-destination-site case is unguarded — the same impossible rule, " +
			"reachable by choosing CIDR instead of Site as the source kind")
	}
	if !strings.Contains(fn, "invalid_rule_self_site") {
		t.Fatal("the refusal must carry its own error code — folding it into invalid_request tells the " +
			"caller their fields are malformed when the fields are fine and the PAIR is not")
	}

	// ⚠ AND THE REFUSAL MUST NOT HAVE EATEN THE WARN-NOT-REFUSE CASES. A CIDR in NO site is the OUTSIDE
	// RANGES surface: it self-clears the moment a range is declared, and turning it into a creation refusal
	// would impose an ordering dependency the S8.7 ruling exists to prevent. If this ever grows into a
	// general "the cidr must resolve to a site" check, that convention is gone.
	if strings.Contains(fn, "src_cidr must be inside") || strings.Contains(fn, "cidr_outside_ranges") {
		t.Fatal("a CIDR outside every site subnet must still be CREATABLE — it warns and self-clears; " +
			"refusing it trades a self-clearing warning for a permanent obstruction")
	}

	// ⛔ A DIFFERENT SITE MUST STILL BE ALLOWED, and this is the half that stops the guard from becoming an
	// outage. Site-to-site transit is S8.2's whole subject and is proven on the wire; a refusal that keyed
	// off `dst_kind == "site"` alone rather than off the IDs BEING EQUAL would delete that feature while
	// passing every assertion above.
	if strings.Contains(fn, `srcKind == "site" && in.DstKind == "site" {`) {
		t.Fatal("the refusal must compare the site IDs, not merely detect a site-to-site rule — " +
			"site-to-site transit is a shipped, wire-proven feature")
	}
}
