package db_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestK8sClusterProviderMetadataMigrationContract(t *testing.T) {
	up, err := os.ReadFile("migrations/0124_k8s_cluster_provider_metadata.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := os.ReadFile("migrations/0124_k8s_cluster_provider_metadata.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	upSQL, downSQL := string(up), string(down)
	for _, want := range []string{
		"ADD COLUMN provider text NOT NULL DEFAULT 'unknown'",
		"ADD COLUMN platform text NOT NULL DEFAULT 'unknown'",
		"provider='aws' AND platform='eks'",
		"provider='azure' AND platform='aks'",
		"provider='gcp' AND platform='gke_standard'",
		"provider='self_managed' AND platform='kubernetes'",
	} {
		if !strings.Contains(upSQL, want) {
			t.Fatalf("0124 up missing %q", want)
		}
	}
	if strings.Contains(upSQL, "UPDATE k8s_clusters") {
		t.Fatal("0124 must not infer metadata for existing clusters")
	}
	if !strings.Contains(downSQL, "0124 rollback refused") {
		t.Fatal("0124 down must refuse lossy metadata contraction")
	}
}

func TestK8sClusterProviderMetadataMigrationOrder(t *testing.T) {
	for _, direction := range []string{"up", "down"} {
		matches, err := filepath.Glob(filepath.Join("migrations", "0124_*."+direction+".sql"))
		if err != nil {
			t.Fatal(err)
		}
		if len(matches) != 1 || filepath.Base(matches[0]) != "0124_k8s_cluster_provider_metadata."+direction+".sql" {
			t.Fatalf("0124 %s migration must be unique and ordered after 0123, found %v", direction, matches)
		}
	}
}
