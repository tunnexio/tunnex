package nodepolicy_test

import (
	"encoding/json"
	"testing"

	"github.com/tunnexio/tunnex/apps/node/internal/nodepolicy"
)

// Keep this fixture and its independently derived digest identical to the
// policyspec twin; packet grants cannot drift from the resolver declaration.
func TestPrivateDNSCanonicalHashGoldenAndRevocation(t *testing.T) {
	wire := `{"version":11,"node_id":"node-dns","mode":"enforcing","mesh":false,"allow":[{"src_ip":"10.99.0.2","dst_cidr":"10.85.2.24/32","protocol":"udp","port_low":53,"port_high":53},{"src_ip":"10.99.0.2","dst_cidr":"10.85.2.24/32","protocol":"tcp","port_low":53,"port_high":53}],"dns_resolver_profiles":[{"context_config_id":"11111111-1111-4111-8111-111111111111","context_config_version":4,"profile_id":"22222222-2222-4222-8222-222222222222","zone_suffixes":["s2s-qa.tunnex.test"],"endpoints":[{"address":"10.85.2.24","port":53,"transport":"udp"}],"ipsec_path":{"connection_id":"33333333-3333-4333-8333-333333333333","configuration_revision":7,"source_address":"10.84.2.254"},"allowed_sources":["10.99.0.2/32"]}]}`
	var c nodepolicy.Compiled
	if err := json.Unmarshal([]byte(wire), &c); err != nil {
		t.Fatal(err)
	}
	if got := nodepolicy.CanonicalHash(&c); got != "68994dbc4014" {
		t.Fatal("private DNS cross-module hash drift", got)
	}
	original := nodepolicy.CanonicalHash(&c)
	c.DNSResolverProfiles[0].AllowedSources = nil
	if nodepolicy.CanonicalHash(&c) == original {
		t.Fatal("client DNS revocation did not alter hashed declaration")
	}
	c.DNSResolverProfiles[0].IPsecPath.ConfigurationRevision++
	if nodepolicy.CanonicalHash(&c) == original {
		t.Fatal("new connection revision retained old DNS identity")
	}
}
