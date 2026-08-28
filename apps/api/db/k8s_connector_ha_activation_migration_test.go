package db_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestK8sConnectorHAActivationMigrationContract(t *testing.T) {
	up, err := os.ReadFile("migrations/0122_k8s_connector_ha_activation.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := os.ReadFile("migrations/0122_k8s_connector_ha_activation.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	upSQL, downSQL := string(up), string(down)
	for _, want := range []string{
		"CREATE TABLE k8s_ha_settings",
		"enabled             boolean NOT NULL DEFAULT false",
		"CREATE TABLE k8s_connector_pool_ha_transitions",
		"requested_mode IN ('legacy','fenced_ha')",
		"actual_mode IN ('legacy','bootstrap_pending','fenced_ha','drain_pending','blocked')",
		"actual_mode <> 'fenced_ha' OR (achieved_authority_revision IS NOT NULL AND membership_epoch IS NOT NULL)",
		"CREATE TABLE k8s_base_authority_node_states",
		"CREATE TABLE k8s_base_authority_deliveries",
		"CHECK (wire_version = 1)",
		"CREATE TABLE k8s_base_authority_delivery_pools",
		"kind IN ('classification','unfence')",
		"disposition IN ('arm_fence','maintain_fence')",
		"CREATE TABLE k8s_base_authority_ack_receipts",
		"k8s_base_authority_ack_delivery_exact_fk",
		"k8s_ha_actor_require_org_membership",
		"ON DELETE RESTRICT",
	} {
		if !strings.Contains(upSQL, want) {
			t.Fatalf("0122 up missing %q", want)
		}
	}
	if strings.Contains(upSQL, "INSERT INTO k8s_ha_settings") || strings.Contains(upSQL, "UPDATE organizations") {
		t.Fatal("0122 must not opt in or infer HA state for legacy organizations")
	}
	for _, want := range []string{
		"LOCK TABLE k8s_base_authority_ack_receipts",
		"IN ACCESS EXCLUSIVE MODE",
		"IF EXISTS (SELECT 1 FROM k8s_ha_settings)",
		"cannot roll back 0122: Kubernetes connector HA state exists",
		"DROP TABLE k8s_base_authority_ack_receipts",
		"DROP FUNCTION k8s_ha_actor_require_org_membership()",
	} {
		if !strings.Contains(downSQL, want) {
			t.Fatalf("0122 down missing %q", want)
		}
	}
}

func TestK8sConnectorHAActivationMigrationOrder(t *testing.T) {
	for _, direction := range []string{"up", "down"} {
		matches, err := filepath.Glob(filepath.Join("migrations", "0122_*."+direction+".sql"))
		if err != nil {
			t.Fatal(err)
		}
		if len(matches) != 1 || filepath.Base(matches[0]) != "0122_k8s_connector_ha_activation."+direction+".sql" {
			t.Fatalf("0122 %s migration must be unique and ordered after 0121, found %v", direction, matches)
		}
		if _, err := os.Stat(filepath.Join("migrations", "0121_k8s_service_uid_observation_attribution."+direction+".sql")); err != nil {
			t.Fatalf("0122 predecessor 0121 %s missing: %v", direction, err)
		}
	}
}
