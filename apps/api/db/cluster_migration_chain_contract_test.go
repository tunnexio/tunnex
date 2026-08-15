package db_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// TestClusterMigrationChainIsCollisionFree protects the shared migration
// boundary: cluster work owns 0079-0087, while the AI-agent work starts at
// 0088. This is a source contract; PostgreSQL up/down behavior is covered by
// the opt-in integration tests in this package.
func TestClusterMigrationChainIsCollisionFree(t *testing.T) {
	cluster := map[int]string{
		79: "0079_k8s_connector_pool",
		80: "0080_k8s_service_port_exposures",
		81: "0081_pool_vip_ownership_delivery",
		82: "0082_k8s_connector_handoff_operations",
		83: "0083_k8s_connector_pool_health_history",
		84: "0084_k8s_service_uid_observations",
		85: "0085_pool_vip_ownership_handoff_provenance",
		86: "0086_k8s_cluster_scope_approvals",
		87: "0087_k8s_cluster_scope_membership_origin",
	}
	for version := 79; version <= 87; version++ {
		base := filepath.Join("migrations", cluster[version])
		for _, direction := range []string{"up", "down"} {
			path := base + "." + direction + ".sql"
			contents, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("cluster migration %d missing %s: %v", version, direction, err)
			}
			if len(contents) == 0 {
				t.Fatalf("cluster migration %d %s is empty", version, direction)
			}
		}
	}
	for version := 88; version <= 93; version++ {
		matches, err := filepath.Glob(filepath.Join("migrations", fmt.Sprintf("%04d_*.up.sql", version)))
		if err != nil {
			t.Fatal(err)
		}
		if len(matches) != 1 {
			t.Fatalf("AI migration boundary %d must have exactly one up migration, found %v", version, matches)
		}
	}
}
