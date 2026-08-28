package db_test

import (
	"os"
	"strings"
	"testing"
)

func TestPoolVIPOwnershipDeliveryV3MigrationContract(t *testing.T) {
	up, err := os.ReadFile("migrations/0118_pool_vip_ownership_delivery_v3.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := os.ReadFile("migrations/0118_pool_vip_ownership_delivery_v3.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"wire_version IN (1, 2, 3)",
		"ADD COLUMN ownership_manifest jsonb NOT NULL DEFAULT '{}'::jsonb",
		"ADD COLUMN applied_manifest jsonb",
		"octet_length(ownership_manifest::text) <= 12288",
		"role = 'withdrawal' AND prior_lease_epoch > 0",
		"CHECK (wire_version IN (2, 3))",
		"NEW.wire_version=3 AND a.applied_manifest=d.ownership_manifest",
		"ALTER TABLE pool_vip_ownership_handoff_provenance_capabilities",
		"DROP CONSTRAINT pool_vip_ownership_handoff_provenance_capabi_wire_version_check",
		"ADD CONSTRAINT pool_vip_handoff_provenance_caps_wire_version_check",
		"d.wire_version=NEW.wire_version",
		"pool_vip_ownership_handoff_provenance_require_child_scope",
		"pool_vip_ownership_ack_manifest_matches_wire_version_before_write",
		"delivery_wire_version = 3 AND NEW.applied_manifest IS NULL",
	} {
		if !strings.Contains(string(up), want) {
			t.Fatalf("0118 up missing %q", want)
		}
	}
	if !strings.Contains(string(down), "cannot remove ownership delivery v3 while v3 provenance exists") ||
		!strings.Contains(string(down), "wire_version IN (1, 2)") ||
		!strings.Contains(string(down), "CHECK (wire_version = 2)") ||
		!strings.Contains(string(down), "DROP CONSTRAINT pool_vip_handoff_provenance_caps_wire_version_check") ||
		!strings.Contains(string(down), "ADD CONSTRAINT pool_vip_ownership_handoff_provenance_capabi_wire_version_check") ||
		!strings.Contains(string(down), "pool_vip_ownership_handoff_provenance_capabilities WHERE wire_version = 3") ||
		!strings.Contains(string(down), "d.wire_version=2") ||
		!strings.Contains(string(down), "DROP FUNCTION pool_vip_ownership_ack_manifest_matches_wire_version()") {
		t.Fatal("0118 down must refuse data loss and restore the v1/v2 contract")
	}
}
