package licence

import (
	"testing"
	"time"
)

func TestAppAccessTierAndLapse(t *testing.T) {
	if FeatAppAccess != "app_access" {
		t.Fatal("named capability changed")
	}
	for _, tier := range []Tier{TierCommunity, "unknown"} {
		if Has(tier, FeatAppAccess) {
			t.Fatalf("unexpected grant to %s", tier)
		}
	}
	for _, tier := range []Tier{TierTrial, TierStarter, TierGrowth, TierScale} {
		if !Has(tier, FeatAppAccess) {
			t.Fatalf("missing grant to %s", tier)
		}
	}
	exp := time.Unix(2_000_000_000, 0)
	m := NewTestManager("trial", exp)
	if !m.Has(FeatAppAccess, exp.Add(-time.Minute)) || !m.Has(FeatAppAccess, exp.Add(time.Hour)) {
		t.Fatal("valid/grace entitlement denied")
	}
	if m.Has(FeatAppAccess, exp.Add(GracePeriod+time.Second)) {
		t.Fatal("lapsed entitlement accepted")
	}
}
