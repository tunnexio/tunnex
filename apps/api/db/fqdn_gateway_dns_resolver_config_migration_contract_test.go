package db

import (
	"os"
	"strings"
	"testing"
)

func TestFQDNGatewayDNSResolverConfigMailboxMigrationContract(t *testing.T) {
	up, err := os.ReadFile("migrations/0116_fqdn_gateway_dns_resolver_config.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"resolver_config_id", "resolver_config_version", "resolver_endpoints",
		"fqdn_gateway_dns_requests_resolver_config_fk",
		"REFERENCES fqdn_resolver_context_configs(id, org_id)",
		"jsonb_array_length(resolver_endpoints) BETWEEN 1 AND 8",
	} {
		if !strings.Contains(string(up), required) {
			t.Fatalf("0116 up missing %q", required)
		}
	}
	down, err := os.ReadFile("migrations/0116_fqdn_gateway_dns_resolver_config.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(down), "cannot roll back FQDN gateway DNS resolver config binding after mailbox work exists") {
		t.Fatal("0116 down must refuse resolver snapshot provenance loss")
	}
}
