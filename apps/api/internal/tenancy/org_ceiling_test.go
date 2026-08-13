package tenancy

import (
	"strings"
	"testing"

	"github.com/tunnexio/tunnex/apps/api/internal/licence"
)

// ⛔ THE ORGANIZATION CEILING — AT CREATION ONLY (S12.1 slice 5).
//
// It replaces a COMPILE-TIME constant. `enterprise.Unlimited` was a build-tag const, so in the enterprise
// binary the check was ELIMINATED — the branch was not present, rather than present-and-false. With one
// binary the question is a runtime one and has to be asked every time.

func TestOrgCeilingsAreTheRuledNumbers(t *testing.T) {
	for _, tc := range []struct {
		tier licence.Tier
		want string
	}{
		{licence.TierCommunity, "1"},
		{licence.TierTrial, "1"},
		{licence.TierStarter, "unlimited"},
		{licence.TierGrowth, "unlimited"},
		{licence.TierScale, "unlimited"},
	} {
		got := "unlimited"
		if c, _ := licence.OrgCeilingFor(tc.tier); c != nil {
			got = itoa(*c)
		}
		if got != tc.want {
			t.Errorf("%s: org ceiling = %s, want %s", tc.tier, got, tc.want)
		}
	}
}

// ⚠ A Service with no licence manager is COMMUNITY, not a refusal — the fail-open default.
func TestNoManagerMeansCommunity(t *testing.T) {
	s := &Service{}
	if c, _ := licence.OrgCeilingFor(s.effectiveTier()); c == nil || *c != 1 {
		t.Fatalf("a Service without a manager must get Community's ceiling of 1, got %v", c)
	}
}

// ⭐ THE REFUSAL IS LEGIBLE, and ⛔ THE ERROR CODE IS LOAD-BEARING BEYOND THIS PACKAGE.
//
// apps/web's CreateOrg funnel branches on `org_limit_reached` to swap the form for an invitation-only
// card. Changing the code would silently break a shipped flow that no test in this repo covers — so the
// code is asserted here, where the person changing it will be.
func TestOrgRefusalIsLegibleAndKeepsItsCode(t *testing.T) {
	s := &Service{}
	msg := s.orgRefusal(licence.TierCommunity, 1, 1)
	for _, want := range []string{"community", "1 organization", "already exist", "Nothing existing is affected", "upgrade the licence"} {
		if !strings.Contains(strings.ToLower(msg), strings.ToLower(want)) {
			t.Errorf("the refusal must mention %q\ngot: %s", want, msg)
		}
	}
	for _, bad := range []string{"error", "failed"} {
		if strings.Contains(strings.ToLower(msg), bad) {
			t.Errorf("fault vocabulary %q — a licence boundary is not a malfunction", bad)
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
