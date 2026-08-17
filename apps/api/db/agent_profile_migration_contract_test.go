package db

import (
	"os"
	"strings"
	"testing"
)

func TestAgentProfileMigrationContract(t *testing.T) {
	up, err := os.ReadFile("migrations/0088_agent_profiles.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := os.ReadFile("migrations/0088_agent_profiles.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	upSQL, downSQL := string(up), string(down)
	for _, required := range []string{"CREATE TABLE agent_profiles", "device_id   uuid PRIMARY KEY", "kind = 'agent'", "INSERT INTO agent_profiles (device_id)", "status IN ('active', 'pending', 'suspended', 'revoked')", "suspended_agent_only"} {
		if !strings.Contains(upSQL, required) {
			t.Errorf("0088 up missing %q", required)
		}
	}
	if strings.Contains(upSQL, "'enrolled'") {
		t.Fatal("0088 must not persist an enrolled status; pending is canonical awaiting approval")
	}
	for _, canonical := range []string{"d.user_id", "d.status", "device_status"} {
		if !strings.Contains(upSQL+" "+mustReadQuery(t), canonical) {
			t.Errorf("F01 must retain canonical %s", canonical)
		}
	}
	if strings.Contains(upSQL, "UPDATE devices") {
		t.Fatal("0088 must not rewrite existing device identity or lifecycle rows")
	}
	for _, required := range []string{"suspended agent/device rows", "agent profile metadata would be lost", "DROP TABLE IF EXISTS agent_profiles", "DROP FUNCTION IF EXISTS ensure_agent_profile_device"} {
		if !strings.Contains(downSQL, required) {
			t.Errorf("0088 down missing %q", required)
		}
	}
}

func TestAgentProfileGeneratedStatusContract(t *testing.T) {
	for _, path := range []string{
		"../internal/api/api.gen.go",
		"../../cli/internal/api/api.gen.go",
		"../../../packages/shared/src/api.d.ts",
	} {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		s := string(b)
		if strings.Contains(s, "AgentProfileStatusEnrolled") || strings.Contains(s, "UpdateAgentProfileRequestStatusEnrolled") {
			t.Fatalf("generated %s exposes enrolled in the F01 profile contract", path)
		}
	}
}

func mustReadQuery(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("queries/devices.sql")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
