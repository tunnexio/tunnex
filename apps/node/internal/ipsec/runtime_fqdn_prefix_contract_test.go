package ipsec

import (
	"encoding/json"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/node/internal/nodepolicy"
	"net/netip"
	"testing"
)

// The ordinary API activeFQDNGeneration wire emits canonical host prefixes.
func TestRuntimeFQDNProducerPrefixWireContract(t *testing.T) {
	for _, answer := range []string{"10.81.0.10/32", "10.81.0.10", "10.81.0.0/24", "10.81.0.10/032", "10.81.0.11/32"} {
		t.Run(answer, func(t *testing.T) {
			_, g, p := fqdnRuntimeFixture(t)
			g.Destination = netip.MustParsePrefix("10.81.0.10/32")
			p.Allow[0].DstCIDR = g.Destination.String()
			p.FQDNGenerations[0].Answers = []string{answer}
			wire, e := json.Marshal(p)
			if e != nil {
				t.Fatal(e)
			}
			decoded := *p
			if e = json.Unmarshal(wire, &decoded); e != nil {
				t.Fatal(e)
			}
			s := &RuntimeFQDNPolicySource{}
			s.CommittedPolicy(&decoded)
			if got, want := s.view.Load().matches(g), answer == g.Destination.String(); got != want {
				t.Fatalf("answer %q accepted=%v want=%v", answer, got, want)
			}
		})
	}
}

// Ordinary policy and runtime grant are actual synthetic API compiler outputs.
// Only the resolver profile is test-owned, since the producer fixture omits it.
func TestRuntimeFQDNActualOrdinaryProducerJSON(t *testing.T) {
	const raw = `{
  "binding": {
    "configuration_revision": 1,
    "connection_id": "eb788e34-ec3f-4651-aac3-4e9d663b6cd8",
    "node_id": "3a24a19b-d154-49f1-97b9-db6a6a6422aa",
    "org_id": "1832f07a-cb91-4995-86b4-85271a04463b",
    "site_id": "501c08f0-3065-4868-8ba2-68a717356f51"
  },
  "ordinary": {
    "version": 9,
    "node_id": "3a24a19b-d154-49f1-97b9-db6a6a6422aa",
    "mode": "enforcing",
    "mesh": false,
    "allow": [
      {
        "src_ip": "10.84.2.0/24",
        "dst_cidr": "10.85.1.20/32",
        "protocol": "tcp",
        "port_low": 443,
        "port_high": 443,
        "rule_id": "a9f56875-5da1-49e3-bacd-97ace6495ce6"
      },
      {
        "src_ip": "10.84.2.10/32",
        "dst_cidr": "10.85.1.10/32",
        "protocol": "tcp",
        "port_low": 8081,
        "port_high": 8081,
        "rule_id": "b68f6e82-3103-4a98-880c-d308c9c254cb",
        "fqdn_managed": true
      }
    ],
    "fqdn_generations": [
      {
        "resource_id": "4abe0c26-4cac-4e08-8bb2-e8fd25fbec03",
        "name": "app.corp.example",
        "generation": "86218ce75aa1d25c90432530db726d9d62b103f64552788918d6f77df8c90152",
        "resolver_config_id": "1cfeedf8-281f-4d84-b470-5793dd7fbfa6",
        "resolver_config_version": 3,
        "answers": [
          "10.85.1.10/32"
        ]
      }
    ]
  },
  "runtime_fqdn_grant": {
    "source": "10.84.2.10/32",
    "destination": "10.85.1.10/32",
    "protocol": "tcp",
    "port_low": 8081,
    "port_high": 8081,
    "rule_id": "b68f6e82-3103-4a98-880c-d308c9c254cb",
    "fqdn_managed": true,
    "resource_id": "4abe0c26-4cac-4e08-8bb2-e8fd25fbec03",
    "name": "app.corp.example",
    "generation": "86218ce75aa1d25c90432530db726d9d62b103f64552788918d6f77df8c90152",
    "resolver_config_id": "1cfeedf8-281f-4d84-b470-5793dd7fbfa6",
    "resolver_config_version": 3,
    "selected_site_id": "501c08f0-3065-4868-8ba2-68a717356f51",
    "selected_gateway_id": "3a24a19b-d154-49f1-97b9-db6a6a6422aa",
    "resolver_profile_id": "a3daaeec-781c-4f3d-8ac1-7767f7ff4d25",
    "resolver_match_suffix": "corp.example",
    "connection_id": "eb788e34-ec3f-4651-aac3-4e9d663b6cd8",
    "configuration_revision": 1
  },
  "scope": "synthetic actual policy.Compile producer; no live authority"
}
`
	var v struct {
		Ordinary nodepolicy.Compiled `json:"ordinary"`
		Grant    RuntimeFQDNGrant    `json:"runtime_fqdn_grant"`
	}
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		t.Fatal(err)
	}
	f := v.Grant
	g := GuardGrant{Source: netip.MustParsePrefix(f.Source), Destination: netip.MustParsePrefix(f.Destination), Protocol: GuardProtocol(f.Protocol), PortLow: f.PortLow, PortHigh: f.PortHigh, FQDNManaged: true, FQDN: FQDNGrantBinding{ResourceID: uuid.MustParse(f.ResourceID), ResolverConfigID: uuid.MustParse(f.ResolverConfigID), SelectedSiteID: uuid.MustParse(f.SelectedSiteID), SelectedGatewayID: uuid.MustParse(f.SelectedGatewayID), ResolverProfileID: uuid.MustParse(f.ResolverProfileID), ConnectionID: uuid.MustParse(f.ConnectionID), RuleID: uuid.MustParse(f.RuleID), Name: f.Name, Generation: f.Generation, ResolverMatchSuffix: f.ResolverMatchSuffix, ResolverConfigVersion: f.ResolverConfigVersion, ConfigurationRevision: f.ConfigurationRevision}}
	v.Ordinary.DNSResolverProfiles = []nodepolicy.DNSResolverProfile{{ContextConfigID: f.ResolverConfigID, ContextConfigVersion: f.ResolverConfigVersion, ProfileID: f.ResolverProfileID, ZoneSuffixes: []string{f.ResolverMatchSuffix}, IPsecPath: nodepolicy.DNSResolverIPsecPath{ConnectionID: f.ConnectionID, ConfigurationRevision: f.ConfigurationRevision}}}
	s := &RuntimeFQDNPolicySource{}
	s.CommittedPolicy(&v.Ordinary)
	if !s.view.Load().matches(g) {
		t.Fatal("actual ordinary producer host-prefix answer refused")
	}
}
