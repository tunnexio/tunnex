package ownershiplease

import (
	"encoding/json"
	"testing"

	"github.com/tunnexio/tunnex/apps/node/internal/nodepolicy"
	"github.com/tunnexio/tunnex/apps/node/internal/reconcile"
)

func TestProjectorPreservesWirePolicyHash(t *testing.T) {
	for _, raw := range []string{
		`{"version":11,"node_id":"gateway","mode":"enforcing","mesh":false,"allow":[{"src_ip":"10.70.0.0/24","dst_cidr":"10.80.0.10/32","protocol":"tcp","port_low":8080,"port_high":8080}],"dns_resolver_profiles":[{"context_config_id":"context","context_config_version":2,"profile_id":"profile","zone_suffixes":["example.test"],"endpoints":[{"address":"10.81.0.2","port":53,"transport":"udp"}],"ipsec_path":{"connection_id":"classic","configuration_revision":1,"source_address":"10.99.0.1"},"allowed_sources":[]}]}`,
		`{"version":11,"node_id":"gateway","mode":"enforcing","mesh":false,"allow":[],"dns_resolver_profiles":[{"zone_suffixes":[],"endpoints":[],"allowed_sources":[]}]}`,
		`{"version":11,"node_id":"gateway","mode":"enforcing","mesh":false,"allow":null,"dns_resolver_profiles":[{"zone_suffixes":null,"endpoints":null,"allowed_sources":null}]}`,
		`{"version":9,"node_id":"gateway","mode":"enforcing","mesh":false,"allow":[],"fqdn_generations":[{"answers":[]}]}`,
	} {
		var policy nodepolicy.Compiled
		if err := json.Unmarshal([]byte(raw), &policy); err != nil {
			t.Fatal(err)
		}
		p := NewProjector()
		if err := p.UpdateBase(reconcile.DesiredState{Policy: &policy}); err != nil {
			t.Fatal(err)
		}
		got, found, err := p.Snapshot()
		if err != nil || !found {
			t.Fatalf("snapshot: found=%v err=%v", found, err)
		}
		if before, after := nodepolicy.CanonicalHash(&policy), nodepolicy.CanonicalHash(got.Policy); before != after {
			t.Fatalf("wire hash changed by pure projection: %s -> %s", before, after)
		}
		base, _ := p.Base()
		if nodepolicy.CanonicalHash(base.Policy) != nodepolicy.CanonicalHash(&policy) {
			t.Fatal("stored base changed policy hash")
		}
	}
}

func TestProjectorPolicySlicesAreIndependent(t *testing.T) {
	policy := &nodepolicy.Compiled{Version: 11, NodeID: "gateway", Mode: "enforcing", DNSResolverProfiles: []nodepolicy.DNSResolverProfile{{AllowedSources: []string{"10.99.0.2/32"}, ZoneSuffixes: []string{"example.test"}, Endpoints: []nodepolicy.DNSResolverEndpoint{{Address: "10.81.0.2"}}}}, FQDNGenerations: []nodepolicy.FQDNGeneration{{Answers: []string{"10.81.0.10"}}}}
	p := NewProjector()
	if err := p.UpdateBase(reconcile.DesiredState{Policy: policy}); err != nil {
		t.Fatal(err)
	}
	want := nodepolicy.CanonicalHash(policy)
	policy.DNSResolverProfiles[0].AllowedSources[0] = "10.99.0.3/32"
	got, _, err := p.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if nodepolicy.CanonicalHash(got.Policy) != want {
		t.Fatal("input alias changed baseline")
	}
	got.Policy.DNSResolverProfiles[0].ZoneSuffixes[0] = "changed.test"
	got.Policy.DNSResolverProfiles[0].Endpoints[0].Address = "10.81.0.3"
	got.Policy.FQDNGenerations[0].Answers[0] = "10.81.0.11"
	again, _, err := p.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if nodepolicy.CanonicalHash(again.Policy) != want {
		t.Fatal("output alias changed baseline")
	}
}
