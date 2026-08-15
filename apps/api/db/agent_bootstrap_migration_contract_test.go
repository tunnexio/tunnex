package db_test

import (
	"os"
	"strings"
	"testing"
)

func TestAgentBootstrapMigrationStoresOnlyHashesAndBindsGateway(t *testing.T) {
	b, err := os.ReadFile("migrations/0090_agent_bootstrap_tokens.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{
		"nodes_org_id_id_f03_key UNIQUE (org_id, id)",
		"devices_org_id_id_f03_key UNIQUE (org_id, id)",
		"FOREIGN KEY (org_id, gateway_node_id) REFERENCES nodes (org_id, id)",
		"FOREIGN KEY (org_id, device_id) REFERENCES devices (org_id, id)",
		"CHECK (octet_length(token_hash) = 32)",
		"CHECK (expires_at > created_at)",
		"consumed_at >= created_at",
		"f03_runtime_credential_agent_only",
		"kind = 'agent'",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("0090 missing %q", want)
		}
	}
	if strings.Contains(s, "raw_token") || strings.Contains(s, "plaintext") {
		t.Fatal("0090 must not persist reusable plaintext secrets")
	}
}

func TestAgentBootstrapDownRefusesLiveCredentials(t *testing.T) {
	b, err := os.ReadFile("migrations/0090_agent_bootstrap_tokens.down.sql")
	if err != nil { t.Fatal(err) }
	s := string(b)
	if !strings.Contains(s, "refusing to roll back 0090 while bootstrap credentials exist") {
		t.Fatal("0090 down must refuse to delete live bootstrap/runtime credentials")
	}
	if !strings.Contains(s, "agent_runtime_credentials LIMIT 1") || !strings.Contains(s, "agent_bootstrap_tokens LIMIT 1") {
		t.Fatal("0090 down must inspect both credential tables before dropping them")
	}
}
