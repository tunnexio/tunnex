package db_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestK8sServiceInventoryRetentionMigrationContract(t *testing.T) {
	up, err := os.ReadFile("migrations/0123_k8s_service_inventory_retention.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := os.ReadFile("migrations/0123_k8s_service_inventory_retention.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	upSQL, downSQL := string(up), string(down)
	for _, want := range []string{
		"retain_unreferenced <> 20",
		"row_number() OVER",
		"ORDER BY report.received_at DESC,report.id DESC",
		"k8s_service_inventory_retention_authorizations",
		"SECURITY DEFINER SET search_path=public,pg_temp",
		"REVOKE ALL ON FUNCTION k8s_service_inventory_retention_authorized(uuid) FROM PUBLIC",
		"REVOKE ALL ON FUNCTION k8s_service_inventory_prune(uuid,uuid,integer) FROM PUBLIC",
		"k8s_service_inventory_snapshot_is_immutable",
	} {
		if !strings.Contains(upSQL, want) {
			t.Fatalf("0123 up missing %q", want)
		}
	}
	for _, forbidden := range []string{"ADD COLUMN", "SET NOT NULL", "DROP COLUMN", "k8s_cluster_scope_initial_candidate_require_inventory_report"} {
		if strings.Contains(upSQL, forbidden) || strings.Contains(downSQL, forbidden) {
			t.Fatalf("0123 must remain retention-only; found %q", forbidden)
		}
	}
}

func TestK8sServiceInventoryRetentionMigrationOrder(t *testing.T) {
	for _, direction := range []string{"up", "down"} {
		matches, err := filepath.Glob(filepath.Join("migrations", "0123_*."+direction+".sql"))
		if err != nil {
			t.Fatal(err)
		}
		if len(matches) != 1 || filepath.Base(matches[0]) != "0123_k8s_service_inventory_retention."+direction+".sql" {
			t.Fatalf("0123 %s migration must be unique and ordered after 0122, found %v", direction, matches)
		}
	}
}
