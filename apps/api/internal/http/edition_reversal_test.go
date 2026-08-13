package http

import (
	"strings"
	"testing"

	"github.com/tunnexio/tunnex/apps/api/internal/licence"
)

// ⛔ THE BUILD-TAG EDITION SPLIT IS REVERSED, AND ITS GUARDS ARE REWRITTEN RATHER THAN DELETED.
//
// `policy_edition_open_test.go` and `sso_edition_open_test.go` asserted that the OPEN BUILD returned
// 403 edition_required for Zero Trust and SSO. That was the old ruling, enforced by tests — and deleting
// them to make the build green would have retired an invariant as a side effect of a ruling change, with
// nothing left recording that it existed (docs/laws.md: census what ENFORCES a ruling, not only what
// states it; a reversed ruling should leave a NARROWER guard behind it, not an absence).
//
// What replaces them is narrower and still mechanical: the tier map is now the boundary, and this asserts
// which side of it each capability sits on.
func TestZeroTrustIsCommunity(t *testing.T) {
	// ⭐ The whole strategy in one assertion. If a future edit puts the policy engine behind a feature, the
	// moat argument has been reversed without anyone saying so.
	for _, f := range licence.AllFeatures() {
		if strings.Contains(string(f), "policy") || strings.Contains(string(f), "zero_trust") {
			t.Errorf("⛔ %q GATES THE ZERO TRUST ENGINE. It is Community by founder ruling — the moat is "+
				"the free tier's generosity, not Enterprise's length, and a thinner Community loses to "+
				"NetBird's free self-hosted edition.", f)
		}
	}
	if licence.Has(licence.TierCommunity, licence.FeatSSO) {
		t.Error("SSO must NOT be Community — it is one of the four paid gates")
	}
}

// ⛔ TestPaidCapabilitiesAreNotYetEnforced LIVED HERE, AND IT IS GONE BECAUSE ITS PREMISE IS NOW FALSE.
//
// It said, in a t.Log: "SSO and IdP sync are wired unconditionally until the LicenseManager slice lands.
// DO NOT RELEASE." That was true and honest for six slices, and it could never have stopped anything — a
// t.Log does not fail a build, and a comment does not fail a build. The gap would have closed when someone
// remembered, or not.
//
// ⚠ IT WAS REPLACED, NOT DELETED, AND THE REPLACEMENT IS enforcement_census_test.go — which asks the same
// question mechanically, of every capability, and FAILS. Deleting a tripwire because the thing it watched
// for got fixed retires the invariant with it (docs/laws.md: census what ENFORCES a ruling, not only what
// states it; a reversed ruling should leave a NARROWER guard behind it, not an absence).
