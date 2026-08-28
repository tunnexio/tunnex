package db_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestK8sServiceUIDPoolConnectorSelectionMigrationContract(t *testing.T) {
	up, err := os.ReadFile("migrations/0119_k8s_service_uid_pool_connector_selection.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := os.ReadFile("migrations/0119_k8s_service_uid_pool_connector_selection.down.sql")
	if err != nil {
		t.Fatal(err)
	}

	upSQL, downSQL := string(up), string(down)
	for _, want := range []string{
		"CREATE OR REPLACE FUNCTION k8s_service_uid_observation_require_selected_connector()",
		"c.connector_pool_id IS NULL",
		"c.connector_node_id = NEW.connector_node_id",
		"p.id = c.connector_pool_id",
		"p.org_id = c.org_id",
		"p.site_id = c.site_id",
		"p.cluster_id = c.id",
		"p.active_node_id = NEW.connector_node_id",
		"p.generation > 0",
		"m.node_id = p.active_node_id",
		"n.status = 'active'",
		"n.revoked_at IS NULL",
		"n.wg_public_key ~ '^[A-Za-z0-9+/]{43}=$'",
		"btrim(n.endpoint) <> ''",
		"BEFORE UPDATE OF sequence, digest",
	} {
		if !strings.Contains(upSQL, want) {
			t.Fatalf("0119 up missing %q", want)
		}
	}
	for _, forbidden := range []string{"ALTER TABLE", "DROP TABLE", "DROP COLUMN"} {
		if strings.Contains(upSQL, forbidden) {
			t.Fatalf("0119 up must remain an expand-only predicate change; found %q", forbidden)
		}
	}
	for _, want := range []string{
		"DROP TRIGGER k8s_service_uid_observation_require_selected_connector_before_progress",
		"CREATE OR REPLACE FUNCTION k8s_service_uid_observation_require_selected_connector()",
		"c.connector_node_id = NEW.connector_node_id",
	} {
		if !strings.Contains(downSQL, want) {
			t.Fatalf("0119 down missing legacy restoration %q", want)
		}
	}
	if strings.Contains(downSQL, "k8s_connector_pools") || strings.Contains(downSQL, "DELETE FROM") {
		t.Fatal("0119 down must restore 0084 semantics without deleting observation data")
	}

	// 0084 is released history. The fix belongs only to 0119.
	legacy, err := os.ReadFile("migrations/0084_k8s_service_uid_observations.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	legacySQL := string(legacy)
	if !strings.Contains(legacySQL, "AND c.connector_node_id = NEW.connector_node_id") || strings.Contains(legacySQL, "FROM k8s_connector_pools") {
		t.Fatal("0084 selected-connector predicate must remain its released legacy-only contract")
	}
}

func TestK8sServiceUIDPoolConnectorSelectionMigrationOrder(t *testing.T) {
	for _, direction := range []string{"up", "down"} {
		matches, err := filepath.Glob(filepath.Join("migrations", "0119_*."+direction+".sql"))
		if err != nil {
			t.Fatal(err)
		}
		if len(matches) != 1 || filepath.Base(matches[0]) != "0119_k8s_service_uid_pool_connector_selection."+direction+".sql" {
			t.Fatalf("0119 %s migration must be unique and ordered after 0118, found %v", direction, matches)
		}
		if _, err := os.Stat(filepath.Join("migrations", "0118_fqdn_resolver_profiles."+direction+".sql")); err != nil {
			t.Fatalf("0119 predecessor 0118 %s missing: %v", direction, err)
		}
	}
}
