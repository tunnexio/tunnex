package nodepolicy

import (
	"encoding/json"
	"testing"
)

func TestStaticCNAMECompletionWireAndHash(t *testing.T) {
	if MaxSupportedVersion != 14 {
		t.Fatal("static completion capability missing")
	}
	wire := `{"version":14,"node_id":"node-dns","mode":"enforcing","mesh":false,"allow":[],"dns_resolver_profiles":[{"context_config_id":"11111111-1111-4111-8111-111111111111","context_config_version":4,"profile_id":"22222222-2222-4222-8222-222222222222","zone_suffixes":["office.test"],"endpoints":[{"address":"1.1.1.1","port":53,"transport":"tcp"}],"ipsec_path":{"connection_id":"","configuration_revision":0,"source_address":""},"allowed_sources":["10.99.0.2/32"],"static_records":[{"name":"app.office.test","type":"CNAME","value":"outside.example","ttl":300}]}]}`
	var c Compiled
	if err := json.Unmarshal([]byte(wire), &c); err != nil {
		t.Fatal(err)
	}
	if len(c.DNSResolverProfiles) != 1 || len(c.DNSResolverProfiles[0].Endpoints) != 1 || c.DNSResolverProfiles[0].Endpoints[0].Transport != "tcp" {
		t.Fatal("completion endpoint lost")
	}
	before := CanonicalHash(&c)
	c.DNSResolverProfiles[0].Endpoints = nil
	if CanonicalHash(&c) == before {
		t.Fatal("completion withdrawal hash blind")
	}
}
