package db_test

import (
	"os"
	"strings"
	"testing"
)

func TestAgentJITAccessMigrationContract(t *testing.T) {
	upBytes, err := os.ReadFile("migrations/0098_agent_jit_access.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	downBytes, err := os.ReadFile("migrations/0098_agent_jit_access.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	up, down := string(upBytes), string(downBytes)

	for _, want := range []string{
		"agent_jit_access_enabled boolean NOT NULL DEFAULT false",
		"CREATE TABLE agent_access_requests",
		"requested_duration_seconds BETWEEN 300 AND 86400",
		"CREATE TABLE agent_access_request_events",
		"agent_access_request_events_prevent_mutation",
		"agent_access_request_events_no_truncate",
		"CREATE TABLE agent_access_request_operations",
		"PRIMARY KEY (org_id, operation, idempotency_key)",
		"agent_access_requests_due_idx",
		"agent_access_request_require_managed_agent",
	} {
		if !strings.Contains(up, want) {
			t.Fatalf("0098 up missing %q", want)
		}
	}
	for _, want := range []string{
		"cannot roll back 0098: agent JIT access state exists",
		"EXISTS (SELECT 1 FROM agent_access_request_operations)",
		"EXISTS (SELECT 1 FROM agent_access_request_events)",
		"EXISTS (SELECT 1 FROM agent_access_requests)",
		"ALTER TABLE organizations DROP COLUMN agent_jit_access_enabled",
	} {
		if !strings.Contains(down, want) {
			t.Fatalf("0098 down missing %q", want)
		}
	}
}
