package db_test

import (
	"os"
	"strings"
	"testing"
)

func TestAgentDelegatedRBACMigrationContract(t *testing.T) {
	up, err := os.ReadFile("migrations/0095_agent_delegated_rbac.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := os.ReadFile("migrations/0095_agent_delegated_rbac.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"CREATE TRIGGER set_updated_at",
		"managing_group_id uuid NULL REFERENCES user_groups (id) ON DELETE SET NULL",
		"agent_profiles_managing_group_same_org",
		"DEFERRABLE INITIALLY IMMEDIATE",
		"device_org <> group_org",
	} {
		if !strings.Contains(string(up), required) {
			t.Fatalf("0095 up missing %q", required)
		}
	}
	for _, required := range []string{
		"managing_group_id IS NOT NULL",
		"cannot roll back 0095",
		"DROP COLUMN managing_group_id",
	} {
		if !strings.Contains(string(down), required) {
			t.Fatalf("0095 down missing preservation guard %q", required)
		}
	}
	queries, err := os.ReadFile("queries/devices.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"AND d.deleted_at IS NULL",
		"FOR UPDATE OF m, u",
	} {
		if !strings.Contains(string(queries), required) {
			t.Fatalf("F06 device queries missing %q", required)
		}
	}
}
