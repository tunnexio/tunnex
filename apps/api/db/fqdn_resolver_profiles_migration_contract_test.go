package db

import (
	"os"
	"strings"
	"testing"
)

func TestFQDNResolverProfilesMigrationContract(t *testing.T) {
	up, err := os.ReadFile("migrations/0118_fqdn_resolver_profiles.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	source := string(up)
	for _, required := range []string{
		"CREATE TABLE fqdn_resolver_context_profiles",
		"UNIQUE (config_id, suffix)",
		"CREATE TABLE fqdn_resolver_context_profile_endpoints",
		"Existing flat configurations become an explicit legacy catch-all profile",
		"resolver_profile_id uuid NULL",
		"resolver_match_suffix text NULL",
		"fqdn_generation_resolver_profile_fk",
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("0118 up missing %q", required)
		}
	}
	down, err := os.ReadFile("migrations/0118_fqdn_resolver_profiles.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(down), "refusing rollback: FQDN resolver profile provenance exists") {
		t.Fatal("0118 down must refuse resolver-profile provenance loss")
	}
}
