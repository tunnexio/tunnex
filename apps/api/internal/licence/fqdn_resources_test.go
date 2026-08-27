package licence

import "testing"

func TestFQDNResourcesIsNamedOneBinaryFeature(t *testing.T) {
	if FeatFQDNResources != "fqdn_resources" {
		t.Fatal("feature name changed")
	}
	if Has(TierCommunity, FeatFQDNResources) {
		t.Fatal("community must not unlock FQDN enforcement")
	}
	if !Has(TierGrowth, FeatFQDNResources) {
		t.Fatal("growth must unlock FQDN enforcement capability")
	}
}
