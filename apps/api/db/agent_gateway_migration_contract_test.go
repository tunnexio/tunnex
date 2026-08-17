package db_test

import (
	"os"
	"strings"
	"testing"
)

// TestAgentGatewayCardinalityMigrationContract pins F02's deliberately narrow
// schema change: remove only the one-live-agent-per-gateway index. Device IDs,
// WireGuard keys, and org-scoped tunnel addresses remain independently unique.
func TestAgentGatewayCardinalityMigrationContract(t *testing.T) {
	up, err := os.ReadFile("migrations/0089_multi_agent_per_gateway.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := os.ReadFile("migrations/0089_multi_agent_per_gateway.down.sql")
	if err != nil {
		t.Fatal(err)
	}

	upSQL, downSQL := string(up), string(down)
	if !strings.Contains(upSQL, "DROP INDEX IF EXISTS devices_agent_node_key") {
		t.Fatal("0089 up must remove the 0067 one-live-agent-per-gateway index")
	}
	for _, forbidden := range []string{
		"devices_org_ip_key",
		"devices_node_pubkey_key",
		"ALTER TABLE devices",
		"ALTER TABLE organizations",
	} {
		if strings.Contains(upSQL, forbidden) {
			t.Fatalf("0089 up must not weaken identity/allocation or invent quota schema; found %q", forbidden)
		}
	}
	for _, required := range []string{
		"multiple live agents are present on one gateway",
		"CREATE UNIQUE INDEX devices_agent_node_key ON devices (node_id)",
		"WHERE kind = 'agent' AND deleted_at IS NULL",
	} {
		if !strings.Contains(downSQL, required) {
			t.Fatalf("0089 down is missing safe rollback contract %q", required)
		}
	}
}
