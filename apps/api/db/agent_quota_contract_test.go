package db_test

import (
	"os"
	"strings"
	"testing"
)

func TestAgentIdentityQuotaMigrationIsNullableAndReversible(t *testing.T) {
	up, err := os.ReadFile("migrations/0092_agent_identity_quota.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := os.ReadFile("migrations/0092_agent_identity_quota.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	upSQL, downSQL := strings.ToLower(string(up)), strings.ToLower(string(down))
	for _, want := range []string{"add column max_agent_identities integer", "is null", ">= 0"} {
		if !strings.Contains(upSQL, want) {
			t.Errorf("quota up migration missing %q", want)
		}
	}
	if !strings.Contains(downSQL, "drop column if exists max_agent_identities") {
		t.Fatal("quota down must remove only the nullable setting")
	}
	if strings.Contains(downSQL, "delete") || strings.Contains(downSQL, "truncate") {
		t.Fatal("quota down must preserve device data")
	}
}

func TestAgentIdentityQuotaCountsOnlyOrgLiveAgentStates(t *testing.T) {
	q, err := os.ReadFile("queries/devices.sql")
	if err != nil {
		t.Fatal(err)
	}
	s := strings.ToLower(string(q))
	for _, want := range []string{
		"countagentidentitiesforquota",
		"org_id = $1",
		"kind = 'agent'",
		"status in ('pending', 'active', 'suspended')",
		"deleted_at is null",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("quota count query contract missing %q", want)
		}
	}
}
