package db_test

import (
	"os"
	"strings"
	"testing"
)

func TestAgentRuntimeSyncSchemaIsAgentOnlyAndSecretFree(t *testing.T) {
	up, err := os.ReadFile("migrations/0091_agent_runtime_sync.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	s := strings.ToLower(string(up))
	for _, want := range []string{
		"create table agent_runtime_state",
		"desired_revision",
		"applied_revision",
		"last_attempted_revision",
		"client_version",
		"last_seen_at",
		"last_error_code",
		"kind = 'agent'",
		"deleted_at is null",
		"deferrable initially deferred",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("0091 up migration missing %q", want)
		}
	}
	for _, forbidden := range []string{"private_key", "token_hash", "access_token", "bearer_token"} {
		if strings.Contains(s, forbidden) {
			t.Errorf("runtime state must not store secret material: found %q", forbidden)
		}
	}
}

func TestAgentRuntimeQueriesAreOrgScopedAndMonotonic(t *testing.T) {
	q, err := os.ReadFile("queries/agent_runtime.sql")
	if err != nil {
		t.Fatal(err)
	}
	s := strings.ToLower(string(q))
	for _, want := range []string{
		"d.org_id = $2",
		"d.kind = 'agent'",
		"greatest(ars.applied_revision, $3)",
		"greatest(ars.last_attempted_revision, $4)",
		"$4 <= ars.desired_revision",
		"$3 = $4",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("agent runtime query contract missing %q", want)
		}
	}
	if got := strings.Count(s, "d.org_id = $2"); got != 4 {
		t.Fatalf("every runtime query must be org scoped: got %d/4", got)
	}
}

func TestAgentRuntimeOptInIsDefaultOffAndRollbackRefusesLiveEnablement(t *testing.T) {
	up, err := os.ReadFile("migrations/0093_agent_runtime_opt_in.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := os.ReadFile("migrations/0093_agent_runtime_opt_in.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	upSQL := strings.ToLower(string(up))
	for _, want := range []string{"managed_agent_runtime_enabled", "not null", "default false"} {
		if !strings.Contains(upSQL, want) {
			t.Errorf("0093 up migration missing %q", want)
		}
	}
	downSQL := strings.ToLower(string(down))
	for _, want := range []string{"managed_agent_runtime_enabled = true", "rollback refused", "drop column"} {
		if !strings.Contains(downSQL, want) {
			t.Errorf("0093 down migration missing %q", want)
		}
	}
}
