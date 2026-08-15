package db_test

import (
	"os"
	"strings"
	"testing"
)

// TestPoolVIPOwnershipDeliveryMigrationConsolidationOrder records the one
// supported consolidation order. 0081 intentionally depends on P1's 0079
// composite pool/member contract; it must not be transplanted before 0079.
func TestPoolVIPOwnershipDeliveryMigrationConsolidationOrder(t *testing.T) {
	const migration = "migrations/0081_pool_vip_ownership_delivery.up.sql"
	b, err := os.ReadFile(migration)
	if err != nil {
		t.Fatalf("read %s: %v", migration, err)
	}
	sql := string(b)

	for _, want := range []string{
		"P1 0079 connector pools, P2 0080 Service-port",
		"this P2 0081 delivery ledger, then P1 0082 handoff operations",
		"REFERENCES k8s_connector_pools (id, org_id, site_id, cluster_id)",
		"REFERENCES k8s_connector_pool_members (pool_id, org_id, site_id, node_id)",
		"jsonb_array_length(owned_routes) <= 512",
		"octet_length(owned_routes::text) <= 12288",
	} {
		if !strings.Contains(sql, want) {
			t.Fatalf("%s must document/enforce consolidation prerequisite %q", migration, want)
		}
	}
}
