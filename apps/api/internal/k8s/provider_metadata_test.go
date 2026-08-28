package k8s

import "testing"

func TestProviderPlatformPairsAreExactAndLegacyUnknownIsExplicit(t *testing.T) {
	for _, pair := range [][2]string{{"aws", "eks"}, {"azure", "aks"}, {"gcp", "gke_standard"}, {"self_managed", "kubernetes"}} {
		if !validProviderPlatform(pair[0], pair[1], false) {
			t.Fatalf("supported pair rejected: %v", pair)
		}
	}
	for _, pair := range [][2]string{{"aws", "aks"}, {"gcp", "kubernetes"}, {"unknown", "eks"}, {"", ""}, {"aws", ""}} {
		if validProviderPlatform(pair[0], pair[1], true) {
			t.Fatalf("invalid/partial pair accepted: %v", pair)
		}
	}
	if !validProviderPlatform("unknown", "unknown", true) {
		t.Fatal("legacy callers must retain explicit unknown/unknown compatibility")
	}
	if validProviderPlatform("unknown", "unknown", false) {
		t.Fatal("metadata correction must require a truthful supported pair")
	}
}
