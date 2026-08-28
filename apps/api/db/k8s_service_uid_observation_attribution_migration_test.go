package db_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestK8sServiceUIDObservationAttributionMigrationContract(t *testing.T) {
	up, err := os.ReadFile("migrations/0119_k8s_service_uid_observation_attribution.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := os.ReadFile("migrations/0119_k8s_service_uid_observation_attribution.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	upSQL, downSQL := string(up), string(down)
	for _, want := range []string{
		"CREATE TABLE k8s_service_uid_observation_current_attributions",
		"FOREIGN KEY (ledger_id, namespace, service)",
		"FOREIGN KEY (replay_state_id, org_id)",
		"k8s_service_uid_observation_invalidate_current_attribution_after_write",
		"current_uid.replay_sequence=NEW.replay_sequence",
		"r.sequence = NEW.replay_sequence",
		"c.connector_node_id=r.connector_node_id",
		"p.active_node_id=r.connector_node_id",
		"p.generation > 0",
		"n.status='active' AND n.revoked_at IS NULL",
		"FOR SHARE OF current_uid,l,r,c,p,m,n",
		"replay.connector_node_id=NEW.active_node_id",
	} {
		if !strings.Contains(upSQL, want) {
			t.Fatalf("0119 up missing %q", want)
		}
	}
	if strings.Contains(upSQL, "UPDATE k8s_service_uid_observation_current SET") || strings.Contains(upSQL, "DELETE FROM k8s_service_uid_observation_current ") {
		t.Fatal("0119 up must preserve every existing current observation")
	}
	for _, want := range []string{
		"IF EXISTS (SELECT 1 FROM k8s_service_uid_observation_current_attributions)",
		"cannot remove Kubernetes Service UID attribution",
		"DROP TABLE k8s_service_uid_observation_current_attributions",
		"CREATE OR REPLACE FUNCTION pool_vip_ownership_handoff_provenance_require_child_scope()",
	} {
		if !strings.Contains(downSQL, want) {
			t.Fatalf("0119 down missing %q", want)
		}
	}
	if strings.Contains(downSQL, "DELETE FROM k8s_service_uid_observation_current") {
		t.Fatal("0119 down must never delete observation data")
	}
}

func TestK8sServiceUIDObservationAttributionMigrationOrder(t *testing.T) {
	for _, direction := range []string{"up", "down"} {
		matches, err := filepath.Glob(filepath.Join("migrations", "0119_*."+direction+".sql"))
		if err != nil {
			t.Fatal(err)
		}
		if len(matches) != 1 || filepath.Base(matches[0]) != "0119_k8s_service_uid_observation_attribution."+direction+".sql" {
			t.Fatalf("0119 %s migration must be unique and ordered after 0118, found %v", direction, matches)
		}
		if _, err := os.Stat(filepath.Join("migrations", "0118_pool_vip_ownership_delivery_v3."+direction+".sql")); err != nil {
			t.Fatalf("0119 predecessor 0118 %s missing: %v", direction, err)
		}
	}
}
