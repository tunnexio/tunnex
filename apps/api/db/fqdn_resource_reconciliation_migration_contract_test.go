package db_test

import (
	"os"
	"strings"
	"testing"
)

func TestFQDNResourceReconciliationMigrationContract(t *testing.T) {
	up, err := os.ReadFile("migrations/0112_fqdn_resource_reconciliation.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := os.ReadFile("migrations/0112_fqdn_resource_reconciliation.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"fqdn_resources_enabled boolean NOT NULL DEFAULT false",
		"ADD COLUMN resolver_site_id uuid",
		"fqdn_resources_resolver_context_pair",
		"fqdn_resolver_context_is_selected",
		"n.site_id = NEW.resolver_site_id",
		"CREATE TABLE fqdn_resource_rule_references",
		"ON DELETE RESTRICT",
	} {
		if !strings.Contains(string(up), want) {
			t.Fatalf("0112 up missing %q", want)
		}
	}
	if !strings.Contains(string(down), "cannot roll back 0112: FQDN reconciliation data exists") {
		t.Fatal("0112 down must refuse reconciliation data loss")
	}
}
