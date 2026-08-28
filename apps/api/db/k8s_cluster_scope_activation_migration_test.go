package db_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestK8sClusterScopeActivationMigrationContract(t *testing.T) {
	up, err := os.ReadFile("migrations/0123_k8s_cluster_scope_activation.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := os.ReadFile("migrations/0123_k8s_cluster_scope_activation.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	upSQL, downSQL := string(up), string(down)
	for _, want := range []string{
		"CREATE TABLE k8s_cluster_scope_settings",
		"enabled         boolean NOT NULL DEFAULT false",
		"CREATE TABLE k8s_service_inventory_reports",
		"service_count       integer NOT NULL CHECK (service_count BETWEEN 0 AND 500)",
		"CREATE TABLE k8s_service_inventory_items",
		"inventory_ref   uuid NOT NULL DEFAULT uuid_generate_v7()",
		"CREATE TABLE k8s_service_inventory_ports",
		"port_count      integer NOT NULL CHECK (port_count BETWEEN 1 AND 32)",
		"CREATE TABLE k8s_cluster_scope_initial_candidates",
		"inventory_report_id uuid NOT NULL",
		"FOREIGN KEY (inventory_report_id, org_id, cluster_id)",
		"REFERENCES k8s_service_inventory_reports (id, org_id, cluster_id) ON DELETE RESTRICT",
		"k8s_cluster_scope_initial_candidates_inventory_report_idx",
		"CHECK (initial_candidate_count BETWEEN 0 AND 500)",
		"REFERENCES k8s_clusters (id) ON DELETE RESTRICT",
		"k8s_service_inventory_require_current_reporter",
		"k8s_service_inventory_require_current_uid",
	} {
		if !strings.Contains(upSQL, want) {
			t.Fatalf("0123 up missing %q", want)
		}
	}
	if strings.Contains(upSQL, "INSERT INTO k8s_cluster_scope_settings") || strings.Contains(upSQL, "UPDATE organizations") {
		t.Fatal("0123 must not opt in existing organizations")
	}
	for _, want := range []string{
		"IF EXISTS (SELECT 1 FROM k8s_cluster_scope_settings)",
		"OR EXISTS (SELECT 1 FROM k8s_cluster_scope_grants)",
		"0123 rollback refused",
		"CHECK (initial_candidate_count BETWEEN 0 AND 100)",
		"REFERENCES k8s_clusters (id) ON DELETE CASCADE",
	} {
		if !strings.Contains(downSQL, want) {
			t.Fatalf("0123 down missing %q", want)
		}
	}
}

func TestK8sClusterScopeActivationMigrationOrder(t *testing.T) {
	for _, direction := range []string{"up", "down"} {
		matches, err := filepath.Glob(filepath.Join("migrations", "0123_*."+direction+".sql"))
		if err != nil {
			t.Fatal(err)
		}
		if len(matches) != 1 || filepath.Base(matches[0]) != "0123_k8s_cluster_scope_activation."+direction+".sql" {
			t.Fatalf("0123 %s migration must be unique and ordered after 0122, found %v", direction, matches)
		}
		if _, err := os.Stat(filepath.Join("migrations", "0122_k8s_connector_ha_activation."+direction+".sql")); err != nil {
			t.Fatalf("0123 predecessor 0122 %s missing: %v", direction, err)
		}
	}
}
