package db_test

import (
	"os"
	"strings"
	"testing"
)

func TestAgentCredentialRotationMigrationContract(t *testing.T) {
	up, err := os.ReadFile("migrations/0094_agent_credential_rotation.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := os.ReadFile("migrations/0094_agent_credential_rotation.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	upText, downText := string(up), string(down)
	for _, required := range []string{
		"revision bigint NOT NULL DEFAULT 1", "state IN ('current', 'candidate', 'superseded', 'revoked')",
		"agent_runtime_credentials_one_current_key",
		"agent_runtime_credentials_one_candidate_key", "rotation_deadline",
		"devices_f05_runtime_credential_lifecycle", "NEW.status = 'revoked'",
		"f05_bound_runtime_credential_history", "position > 10",
	} {
		if !strings.Contains(upText, required) {
			t.Fatalf("0094 up missing %q", required)
		}
	}
	for _, required := range []string{
		"refusing to roll back 0094", "revision <> 1", "state <> 'current'",
		"rotation_requested_at IS NOT NULL", "DROP TRIGGER devices_f05_runtime_credential_lifecycle",
	} {
		if !strings.Contains(downText, required) {
			t.Fatalf("0094 down missing preservation guard %q", required)
		}
	}
	if strings.Contains(upText, "plaintext") || strings.Contains(upText, "private_key") {
		t.Fatal("credential rotation schema must remain hash-only")
	}
}

func TestAgentCredentialRotationQueryContract(t *testing.T) {
	source, err := os.ReadFile("queries/agent_bootstrap.sql")
	if err != nil {
		t.Fatal(err)
	}
	s := string(source)
	for _, required := range []string{
		"PrepareAgentRuntimeCredentialCandidate", "current.rotation_deadline > now()",
		"agent_runtime_credentials.token_hash = EXCLUDED.token_hash", "AuthenticateAgentRuntimeCredential",
		"ELSE 'superseded'", "credential.id = matched.id THEN 'current'",
	} {
		if !strings.Contains(s, required) {
			t.Fatalf("rotation query contract missing %q", required)
		}
	}
}
