package db_test

import (
	"os"
	"strings"
	"testing"
)

func TestFQDNResolverContextEndpointsMigrationContract(t *testing.T) {
	up, err := os.ReadFile("migrations/0115_fqdn_resolver_context_endpoints.up.sql")
	if err != nil { t.Fatal(err) }
	down, err := os.ReadFile("migrations/0115_fqdn_resolver_context_endpoints.down.sql")
	if err != nil { t.Fatal(err) }
	for _, want := range []string{
		"CREATE TABLE fqdn_resolver_context_configs",
		"CREATE TABLE fqdn_resolver_context_endpoints",
		"fqdn_resolver_context_configs_one_active",
		"fqdn_resolver_config_require_endpoint",
		"fqdn_resolver_config_context_is_selected",
		"ADD COLUMN resolver_config_id uuid",
		"ON DELETE RESTRICT",
	} {
		if !strings.Contains(string(up), want) { t.Fatalf("0115 up missing %q", want) }
	}
	if !strings.Contains(string(down), "refusing to roll back 0115") {
		t.Fatal("0115 down must refuse resolver configuration/history loss")
	}
}
