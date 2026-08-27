package db_test

import (
	"os"
	"strings"
	"testing"
)

func TestFQDNPolicyDestinationMigrationContract(t *testing.T) {
	up, err := os.ReadFile("migrations/0113_fqdn_policy_destination_contract.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := os.ReadFile("migrations/0113_fqdn_policy_destination_contract.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"ADD COLUMN dst_fqdn_resource_id uuid", "dst_kind IN ('resource', 'group', 'site', 'k8s_service', 'fqdn_resource')",
		"FOREIGN KEY (dst_fqdn_resource_id, org_id)", "REFERENCES fqdn_resources (id, org_id) ON DELETE RESTRICT",
		"fqdn_policy_rule_reference_mirror", "fqdn_generation_published_immutable",
		"port_low IS NOT NULL AND port_high IS NOT NULL", "resources_ports_complete_check", "fqdn_resources_ports_complete_check",
	} {
		if !strings.Contains(string(up), want) {
			t.Fatalf("0113 up missing %q", want)
		}
	}
	if strings.Contains(string(up), "DROP TABLE fqdn_resource_rule_references") {
		t.Fatal("0113 must retain the old reference reader for the rolling-upgrade compatibility window")
	}
	if !strings.Contains(string(down), "cannot roll back 0113: FQDN policy destination or published generation data exists") {
		t.Fatal("0113 down must refuse to erase FQDN policy or publication history")
	}
}
