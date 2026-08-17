package db_test

import (
	"os"
	"strings"
	"testing"
)

func TestAgentAccessEventAttributionMigrationContract(t *testing.T) {
	up, err := os.ReadFile("migrations/0096_agent_access_event_attribution.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := os.ReadFile("migrations/0096_agent_access_event_attribution.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"policy_hash text", "policy_version integer", "src_config_revision bigint", "src_kind text", "decision_reason text", "WHERE src_kind = 'agent'"} {
		if !strings.Contains(string(up), want) {
			t.Fatalf("0096 up missing %q", want)
		}
	}
	for _, want := range []string{"cannot roll back 0096", "policy_hash IS NOT NULL", "DROP COLUMN policy_hash"} {
		if !strings.Contains(string(down), want) {
			t.Fatalf("0096 down missing preservation guard %q", want)
		}
	}
}
