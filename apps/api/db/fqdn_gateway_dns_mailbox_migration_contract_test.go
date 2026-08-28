package db

import (
	"os"
	"strings"
	"testing"
)

func TestFQDNGatewayDNSMailboxMigrationContract(t *testing.T) {
	up, err := os.ReadFile("migrations/0114_fqdn_gateway_dns_mailbox.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"CREATE TABLE fqdn_gateway_dns_requests", "protocol_version", "request_id", "org_id", "resource_id", "site_id", "gateway_id", "record_types", "deadline", "state IN ('pending','completed','expired')", "ON DELETE RESTRICT", "fqdn_gateway_dns_requests_pending_gateway_idx",
	} {
		if !strings.Contains(string(up), required) {
			t.Fatalf("0114 up missing %q", required)
		}
	}
	down, err := os.ReadFile("migrations/0114_fqdn_gateway_dns_mailbox.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(down), "cannot roll back 0114: durable FQDN gateway DNS mailbox rows exist") {
		t.Fatal("0114 down must refuse lifecycle-history loss")
	}
}
