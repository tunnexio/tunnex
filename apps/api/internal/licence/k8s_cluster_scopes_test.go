package licence

import "testing"

func TestK8sClusterScopesRequireEntitlementAndRemainTrialEvaluable(t *testing.T) {
	if FeatK8sClusterScopes != "k8s_cluster_scopes" {
		t.Fatalf("feature name drifted: %q", FeatK8sClusterScopes)
	}
	if Has(TierCommunity, FeatK8sClusterScopes) {
		t.Fatal("Community must not unlock approval-gated cluster scopes")
	}
	for _, tier := range []Tier{TierTrial, TierStarter, TierGrowth, TierScale} {
		if !Has(tier, FeatK8sClusterScopes) {
			t.Fatalf("%s must unlock cluster scopes; organization opt-in remains separate", tier)
		}
	}
}
