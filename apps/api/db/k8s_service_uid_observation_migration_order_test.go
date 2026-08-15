package db_test

import (
	"os"
	"strings"
	"testing"
)

// TestK8sServiceUIDObservationMigrationConsolidationOrder records the only
// supported order without copying P1 migrations into this P2 worktree.
func TestK8sServiceUIDObservationMigrationConsolidationOrder(t *testing.T) {
	const migration = "migrations/0084_k8s_service_uid_observations.up.sql"
	b, err := os.ReadFile(migration)
	if err != nil {
		t.Fatalf("read %s: %v", migration, err)
	}
	sql := string(b)
	for _, want := range []string{
		"P1 0079 connector pools, P2 0080",
		"P2 0081 ownership delivery, P1 0082 handoff",
		"operations, and P1 0083 health",
		"P1 0079 owns nodes_id_org_site_key and k8s_clusters_id_org_site_key",
		"REFERENCES k8s_clusters (id, org_id, site_id)",
		"REFERENCES nodes (id, org_id, site_id)",
		"FOREIGN KEY (connector_node_id, org_id, site_id)",
	} {
		if !strings.Contains(sql, want) {
			t.Fatalf("%s must document/enforce consolidation prerequisite %q", migration, want)
		}
	}
	for _, forbidden := range []string{
		"ADD CONSTRAINT nodes_id_org_site_",
		"ADD CONSTRAINT k8s_clusters_id_org_site_",
	} {
		if strings.Contains(sql, forbidden) {
			t.Fatalf("%s must reuse P1 0079 composite keys, not add %q", migration, forbidden)
		}
	}
}
