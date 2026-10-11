package ipsec

import (
	"github.com/google/uuid"
	"strings"
	"testing"
)

func runtimeFQDNPolicyFixture() (RuntimePolicy, RuntimePolicyInput) {
	in := RuntimePolicyInput{OrgID: uuid.New(), SiteID: uuid.New(), NodeID: uuid.New(), ConnectionID: uuid.New(), ConfigurationRevision: 1, FQDNPolicyVersion: 1, Config: StaticConfig{LocalPrefixes: []string{"10.84.2.0/24"}, RemotePrefixes: []string{"10.85.0.0/16"}}}
	g := RuntimeFQDNGrant{RuntimeGrant: RuntimeGrant{Source: "10.84.2.10/32", Destination: "10.85.1.10/32", Protocol: "tcp", PortLow: 8081, PortHigh: 8081, RuleID: uuid.NewString()}, FQDNManaged: true, ResourceID: uuid.NewString(), Name: "app.corp.example", Generation: strings.Repeat("a", 64), ResolverConfigID: uuid.NewString(), ResolverConfigVersion: 3, SelectedSiteID: in.SiteID.String(), SelectedGatewayID: in.NodeID.String(), ResolverProfileID: uuid.NewString(), ResolverMatchSuffix: "corp.example", ConnectionID: in.ConnectionID.String(), ConfigurationRevision: 1}
	return RuntimePolicy{FQDNPolicyVersion: 1, FQDNGrants: []RuntimeFQDNGrant{g}}, in
}
func TestRuntimeFQDNPolicyRequiresExactCurrentProvenance(t *testing.T) {
	p, in := runtimeFQDNPolicyFixture()
	if !validRuntimeFQDNPolicy(p, in) {
		t.Fatal("exact policy refused")
	}
	mutations := map[string]func(*RuntimePolicy, *RuntimePolicyInput){"missing capability": func(_ *RuntimePolicy, in *RuntimePolicyInput) { in.FQDNPolicyVersion = 0 }, "wrong version": func(p *RuntimePolicy, _ *RuntimePolicyInput) { p.FQDNPolicyVersion = 2 }, "unmarked": func(p *RuntimePolicy, _ *RuntimePolicyInput) { p.FQDNGrants[0].FQDNManaged = false }, "foreign connection": func(p *RuntimePolicy, _ *RuntimePolicyInput) { p.FQDNGrants[0].ConnectionID = uuid.NewString() }, "foreign Site": func(p *RuntimePolicy, _ *RuntimePolicyInput) { p.FQDNGrants[0].SelectedSiteID = uuid.NewString() }, "foreign gateway": func(p *RuntimePolicy, _ *RuntimePolicyInput) { p.FQDNGrants[0].SelectedGatewayID = uuid.NewString() }, "stale config": func(p *RuntimePolicy, _ *RuntimePolicyInput) { p.FQDNGrants[0].ConfigurationRevision = 2 }, "missing generation": func(p *RuntimePolicy, _ *RuntimePolicyInput) { p.FQDNGrants[0].Generation = "" }, "missing profile": func(p *RuntimePolicy, _ *RuntimePolicyInput) { p.FQDNGrants[0].ResolverProfileID = uuid.Nil.String() }, "noncanonical name": func(p *RuntimePolicy, _ *RuntimePolicyInput) { p.FQDNGrants[0].Name = "APP.corp.example" }, "unmatched suffix": func(p *RuntimePolicy, _ *RuntimePolicyInput) { p.FQDNGrants[0].ResolverMatchSuffix = "foreign.example" }, "outside local WG": func(p *RuntimePolicy, _ *RuntimePolicyInput) { p.FQDNGrants[0].Source = "10.99.0.2/32" }, "outside remote": func(p *RuntimePolicy, _ *RuntimePolicyInput) { p.FQDNGrants[0].Destination = "10.86.1.10/32" }, "widened answer": func(p *RuntimePolicy, _ *RuntimePolicyInput) { p.FQDNGrants[0].Destination = "10.85.1.0/24" }, "protected answer": func(p *RuntimePolicy, in *RuntimePolicyInput) {
		p.FQDNGrants[0].Destination = "169.254.169.254/32"
		in.Config.RemotePrefixes = []string{"169.254.0.0/16"}
	}, "duplicate": func(p *RuntimePolicy, _ *RuntimePolicyInput) { p.FQDNGrants = append(p.FQDNGrants, p.FQDNGrants[0]) }, "invalid ports": func(p *RuntimePolicy, _ *RuntimePolicyInput) { p.FQDNGrants[0].PortLow = 8082 }, "false any": func(p *RuntimePolicy, _ *RuntimePolicyInput) { p.FQDNGrants[0].Protocol = "any" }, "empty versioned": func(p *RuntimePolicy, _ *RuntimePolicyInput) { p.FQDNGrants = nil }}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			p, in := runtimeFQDNPolicyFixture()
			mutate(&p, &in)
			if validRuntimeFQDNPolicy(p, in) {
				t.Fatal("invalid policy accepted")
			}
		})
	}
	if !validRuntimeFQDNPolicy(RuntimePolicy{}, RuntimePolicyInput{}) {
		t.Fatal("legacy empty field refused")
	}
}
