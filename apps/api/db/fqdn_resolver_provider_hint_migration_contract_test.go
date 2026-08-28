package db

import (
	"os"
	"strings"
	"testing"
)

func TestFQDNResolverProviderHintMigrationContract(t *testing.T) {
	up, err := os.ReadFile("migrations/0117_fqdn_resolver_provider_hint.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"ADD COLUMN provider_hint text NULL",
		"'aws', 'azure', 'google_cloud', 'on_premises'",
	} {
		if !strings.Contains(string(up), required) {
			t.Fatalf("0117 up missing %q", required)
		}
	}
	down, err := os.ReadFile("migrations/0117_fqdn_resolver_provider_hint.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(down), "cannot roll back FQDN resolver provider metadata after it has been recorded") {
		t.Fatal("0117 down must refuse recorded provider metadata loss")
	}
}
