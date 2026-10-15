package policyspec

import (
	"encoding/json"
	"testing"
)

func TestStaticLANDNSCanonicalWireAndRevocation(t *testing.T) {
	wire := `{"version":12,"node_id":"node-dns","mode":"enforcing","mesh":false,"allow":[],"dns_resolver_profiles":[{"context_config_id":"11111111-1111-4111-8111-111111111111","context_config_version":4,"profile_id":"22222222-2222-4222-8222-222222222222","zone_suffixes":["office.test"],"endpoints":[],"ipsec_path":{"connection_id":"","configuration_revision":0,"source_address":""},"allowed_sources":["10.99.0.2/32"],"static_records":[{"name":"app.office.test","type":"A","value":"10.20.0.80","ttl":300}],"lan_listener":{"address":"192.168.1.39","interface":"eth0","allowed_sources":["192.168.1.0/24"]}}]}`
	var c Compiled
	if err := json.Unmarshal([]byte(wire), &c); err != nil {
		t.Fatal(err)
	}
	if got := CanonicalHash(c); got != "0d0a1d32be36" {
		t.Fatal("DNS contract hash mismatch", got)
	}
	original := CanonicalHash(c)
	c.DNSResolverProfiles[0].StaticRecords[0].Value = "10.20.0.90"
	if CanonicalHash(c) == original {
		t.Fatal("static answer omitted from enforcement hash")
	}
	changed := CanonicalHash(c)
	c.DNSResolverProfiles[0].LANListener.AllowedSources = nil
	if CanonicalHash(c) == changed {
		t.Fatal("LAN source revocation omitted from enforcement hash")
	}
}
func TestStaticLANDNSRequiresV12OnlyWhenUsed(t *testing.T) {
	for _, p := range []DNSResolverProfile{{StaticRecords: []DNSStaticRecord{{Name: "app.office.test", Type: "A", Value: "10.0.0.1", TTL: 300}}}, {LANListener: &DNSLANListener{Address: "192.168.1.39", Interface: "eth0"}}} {
		if RequiredVersion(Compiled{DNSResolverProfiles: []DNSResolverProfile{p}}) != 12 {
			t.Fatal("older agent can silently ignore DNS authority")
		}
	}
	if RequiredVersion(Compiled{DNSResolverProfiles: []DNSResolverProfile{{ContextConfigID: "existing"}}}) != 11 {
		t.Fatal("unchanged IPsec-only DNS requires new protocol")
	}
}

func TestLANPublicDNSRequiresV13AndChangesHash(t *testing.T) {
	c := Compiled{Version: 12, DNSResolverProfiles: []DNSResolverProfile{{StaticRecords: []DNSStaticRecord{{Name: "old.test", Type: "A", Value: "10.0.0.1"}}}, {LANListener: &DNSLANListener{Address: "192.168.1.39", Interface: "eth0", AllowedSources: []string{"192.168.1.0/24"}}}}}
	before := CanonicalHash(c)
	c.DNSResolverProfiles[1].LANListener.DefaultUpstreams = []string{"1.1.1.1"}
	if RequiredVersion(c) != 13 {
		t.Fatal("public defaults accepted by v12 gateway")
	}
	if CanonicalHash(c) == before {
		t.Fatal("public DNS authorization omitted from hash")
	}
	c.DNSResolverProfiles[1].LANListener.DefaultUpstreams = nil
	if RequiredVersion(c) != 12 || CanonicalHash(c) != before {
		t.Fatal("private-only compatibility changed")
	}
}
