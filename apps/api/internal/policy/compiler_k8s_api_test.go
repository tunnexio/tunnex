package policy_test

import (
	"testing"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/internal/policy"
	"github.com/tunnexio/tunnex/apps/api/internal/policyspec"
)

// K8N-3 stage 1: a rule whose destination is a cluster's Kubernetes API (dst_kind='k8s_api').

var (
	apiEndpoint = uuid.MustParse("00000000-0000-0000-0000-0000000a91a9")
	deviceAlice = uuid.MustParse("00000000-0000-0000-0000-0000000de71c")
)

// apiEndpointOn is one cluster API endpoint whose API access is on: address 100.64.0.7, DNS 100.64.0.2,
// served by the cluster's gateway nodeB.
func apiEndpointOn() policy.ExposedService {
	return policy.ExposedService{ID: apiEndpoint, VIP: "100.64.0.7", DNSVIP: "100.64.0.2", Protocol: "tcp", PortLow: 443, PortHigh: 443, ConnectorNodeID: nodeB}
}

// k8sAPIBase: Alice (a member of gAdmins) has a device on nodeA; rule grants the cluster's API.
func k8sAPIBase(rule policy.Rule, endpoints []policy.ExposedService) policy.Snapshot {
	rule.DstKind, rule.DstK8sAPIEndpointID = "k8s_api", apiEndpoint
	return policy.Snapshot{
		Mode:         policy.ModeEnforcing,
		APIEndpoints: endpoints,
		Rules:        []policy.Rule{rule},
		Memberships:  []policy.Membership{{GroupID: gAdmins, UserID: uAlice}},
		Devices:      []policy.Device{{ID: deviceAlice, UserID: uAlice, NodeID: nodeA, AssignedIP: "10.99.0.10", Kind: "human"}},
	}
}

func apiEntries(entries []policyspec.AllowEntry) (api, dns []policyspec.AllowEntry) {
	for _, entry := range entries {
		switch entry.DstCIDR {
		case "100.64.0.7/32":
			api = append(api, entry)
		case "100.64.0.2/32":
			dns = append(dns, entry)
		}
	}
	return api, dns
}

// The rule yields the API's address on TCP 443 and the cluster's DNS address, on the device's gateway AND
// on the cluster's gateway, for a group and for a single person.
func TestK8sAPIRuleGrantsTCP443AndDNSOnBothGateways(t *testing.T) {
	ruleID := uuid.New()
	for name, rule := range map[string]policy.Rule{
		"group":  {ID: ruleID, SrcKind: "group", SrcGroupID: gAdmins},
		"person": {ID: ruleID, SrcKind: "user", SrcUserID: uAlice},
	} {
		t.Run(name, func(t *testing.T) {
			compiled := policy.Compile(k8sAPIBase(rule, []policy.ExposedService{apiEndpointOn()}))
			for _, node := range []uuid.UUID{nodeA, nodeB} {
				artifact, ok := compiled[node]
				if !ok {
					t.Fatalf("gateway %s must receive an artifact", node)
				}
				api, dns := apiEntries(artifact.Allow)
				if len(api) != 1 || api[0].SrcIP != "10.99.0.10" || api[0].Protocol != policyspec.ProtoTCP || api[0].PortLow != 443 || api[0].PortHigh != 443 ||
					api[0].RuleID != ruleID.String() || api[0].SrcDeviceID != deviceAlice.String() {
					t.Fatalf("gateway %s: want exactly TCP 443 to the API address attributed to the rule, got %+v", node, api)
				}
				if len(dns) != 2 {
					t.Fatalf("gateway %s: want the cluster's DNS address on UDP and TCP 53, got %+v", node, dns)
				}
				for _, entry := range dns {
					if entry.PortLow != 53 || entry.PortHigh != 53 || (entry.Protocol != policyspec.ProtoUDP && entry.Protocol != policyspec.ProtoTCP) {
						t.Fatalf("gateway %s: DNS entry = %+v", node, entry)
					}
				}
				if len(artifact.Allow) != 3 {
					t.Fatalf("gateway %s: the rule must grant nothing else, got %+v", node, artifact.Allow)
				}
				if artifact.Mesh {
					t.Fatalf("gateway %s: an enforcing artifact must be default deny", node)
				}
			}
		})
	}
}

// Default deny: with API access on and no rule, nothing reaches the API address.
func TestK8sAPIWithoutARuleIsDenied(t *testing.T) {
	snap := k8sAPIBase(policy.Rule{SrcKind: "group", SrcGroupID: gAdmins}, []policy.ExposedService{apiEndpointOn()})
	snap.Rules = nil
	compiled := policy.Compile(snap)
	for _, node := range []uuid.UUID{nodeA, nodeB} {
		if a := allowsFor(compiled, node); len(a) != 0 {
			t.Fatalf("no rule must mean no path on %s, got %+v", node, a)
		}
	}
	if _, ok := compiled[nodeB]; !ok {
		t.Fatal("the cluster's gateway still receives a (deny-all) artifact for an API-only cluster")
	}
}

// API access off (or the cluster gone): the endpoint is absent from the snapshot and the rule, which is
// kept, compiles to nothing. So does a disabled rule, and a rule of another person.
func TestK8sAPIRuleCompilesToNothingWhenItShould(t *testing.T) {
	group := policy.Rule{SrcKind: "group", SrcGroupID: gAdmins}
	cases := map[string]policy.Snapshot{
		"API access off":       k8sAPIBase(group, nil),
		"another endpoint":     k8sAPIBase(group, []policy.ExposedService{{ID: uuid.New(), VIP: "100.64.0.7", DNSVIP: "100.64.0.2", Protocol: "tcp", PortLow: 443, PortHigh: 443, ConnectorNodeID: nodeB}}),
		"endpoint without VIP": k8sAPIBase(group, []policy.ExposedService{{ID: apiEndpoint, DNSVIP: "100.64.0.2", Protocol: "tcp", PortLow: 443, PortHigh: 443, ConnectorNodeID: nodeB}}),
		"rule disabled":        k8sAPIBase(policy.Rule{SrcKind: "group", SrcGroupID: gAdmins, Disabled: true}, []policy.ExposedService{apiEndpointOn()}),
		"someone else's rule":  k8sAPIBase(policy.Rule{SrcKind: "user", SrcUserID: uBob}, []policy.ExposedService{apiEndpointOn()}),
		"unresolved pool":      k8sAPIBase(group, []policy.ExposedService{{ID: apiEndpoint, VIP: "100.64.0.7", DNSVIP: "100.64.0.2", Protocol: "tcp", PortLow: 443, PortHigh: 443, PoolBound: true}}),
	}
	for name, snap := range cases {
		t.Run(name, func(t *testing.T) {
			compiled := policy.Compile(snap)
			for _, node := range []uuid.UUID{nodeA, nodeB} {
				if a := allowsFor(compiled, node); len(a) != 0 {
					t.Fatalf("must compile to nothing on %s, got %+v", node, a)
				}
			}
		})
	}
}

// Founder ruling 2026-11-23: people and groups only. A site, an address range, an agent or an agent group
// as the source compiles to nothing even if such a row existed, and an AI agent's device gets nothing from
// a rule that grants its owner.
func TestK8sAPIRuleIsForPeopleAndGroupsOnly(t *testing.T) {
	site, agentDevice, agentGroup := uuid.New(), uuid.New(), uuid.New()
	withSite := func(snap policy.Snapshot) policy.Snapshot {
		snap.SiteSubnets = []policy.SiteSubnet{{SiteID: site, CIDR: "10.20.0.0/24"}}
		snap.SiteNodes = []policy.SiteNode{{SiteID: site, NodeID: nodeA}}
		return snap
	}
	cases := map[string]policy.Snapshot{
		"site source":  withSite(k8sAPIBase(policy.Rule{SrcKind: "site", SrcSiteID: site}, []policy.ExposedService{apiEndpointOn()})),
		"range source": withSite(k8sAPIBase(policy.Rule{SrcKind: "cidr", SrcCIDR: "10.20.0.7/32"}, []policy.ExposedService{apiEndpointOn()})),
	}
	agent := k8sAPIBase(policy.Rule{SrcKind: "agent", SrcDeviceID: agentDevice}, []policy.ExposedService{apiEndpointOn()})
	agent.Devices = append(agent.Devices, policy.Device{ID: agentDevice, UserID: uAlice, NodeID: nodeA, AssignedIP: "10.99.0.20", Kind: "agent"})
	cases["agent source"] = agent
	group := k8sAPIBase(policy.Rule{SrcKind: "agent_group", SrcAgentGroupID: agentGroup}, []policy.ExposedService{apiEndpointOn()})
	group.Devices = append(group.Devices, policy.Device{ID: agentDevice, UserID: uAlice, NodeID: nodeA, AssignedIP: "10.99.0.20", Kind: "agent"})
	group.AgentGroupMemberships = []policy.AgentGroupMembership{{GroupID: agentGroup, DeviceID: agentDevice}}
	cases["agent group source"] = group
	for name, snap := range cases {
		t.Run(name, func(t *testing.T) {
			compiled := policy.Compile(snap)
			for node, artifact := range compiled {
				if api, dns := apiEntries(artifact.Allow); len(api) != 0 || len(dns) != 0 {
					t.Fatalf("a %s must never reach the cluster API (node %s): %+v", name, node, artifact.Allow)
				}
			}
		})
	}

	// A person's rule: their own device is granted, an AI agent they own is not.
	owned := k8sAPIBase(policy.Rule{SrcKind: "user", SrcUserID: uAlice}, []policy.ExposedService{apiEndpointOn()})
	owned.Devices = append(owned.Devices, policy.Device{ID: agentDevice, UserID: uAlice, NodeID: nodeA, AssignedIP: "10.99.0.20", Kind: "agent"})
	a := allowsFor(policy.Compile(owned), nodeA)
	if !hasAllow(a, "10.99.0.10", "100.64.0.7/32") {
		t.Fatalf("the person's own device must be granted, got %+v", a)
	}
	for _, entry := range a {
		if entry.SrcIP == "10.99.0.20" {
			t.Fatalf("an AI agent owned by a granted person reached the cluster API: %+v", entry)
		}
	}
}

// The two Kubernetes destination kinds never cross: a k8s_service rule cannot resolve to a cluster's API
// endpoint, and a k8s_api rule cannot resolve to an exposed Service, even when the ids are equal.
func TestK8sAPIAndK8sServiceRulesNeverCross(t *testing.T) {
	service := policy.Snapshot{
		Mode:         policy.ModeEnforcing,
		APIEndpoints: []policy.ExposedService{apiEndpointOn()},
		Rules:        []policy.Rule{{SrcKind: "group", SrcGroupID: gAdmins, DstKind: "k8s_service", DstK8sServiceID: apiEndpoint}},
		Memberships:  []policy.Membership{{GroupID: gAdmins, UserID: uAlice}},
		Devices:      []policy.Device{{ID: deviceAlice, UserID: uAlice, NodeID: nodeA, AssignedIP: "10.99.0.10", Kind: "human"}},
	}
	if a := allowsFor(policy.Compile(service), nodeA); len(a) != 0 {
		t.Fatalf("a k8s_service rule reached a cluster API endpoint: %+v", a)
	}
	api := k8sAPIBase(policy.Rule{SrcKind: "group", SrcGroupID: gAdmins}, nil)
	api.ExposedServices = []policy.ExposedService{{ID: apiEndpoint, VIP: "100.64.0.5", Protocol: "tcp", PortLow: 80, PortHigh: 80}}
	if a := allowsFor(policy.Compile(api), nodeA); len(a) != 0 {
		t.Fatalf("a k8s_api rule reached an exposed Service: %+v", a)
	}
}

// Open mesh (enforcement off): the artifact is the blanket mesh, so an enabled API address is reachable by
// every device with no rule at all. The dashboard says so before enabling; this is why.
func TestK8sAPIUnderOpenMeshIsReachableWithoutARule(t *testing.T) {
	snap := k8sAPIBase(policy.Rule{SrcKind: "group", SrcGroupID: gAdmins}, []policy.ExposedService{apiEndpointOn()})
	snap.Mode, snap.Rules = policy.ModeOff, nil
	compiled := policy.Compile(snap)
	for _, node := range []uuid.UUID{nodeA, nodeB} {
		if artifact, ok := compiled[node]; !ok || !artifact.Mesh || len(artifact.Allow) != 0 {
			t.Fatalf("open mesh: %s must carry the blanket mesh artifact, got %+v", node, artifact)
		}
	}
}

// The artifact a k8s_api rule produces needs no newer wire version than a k8s_service rule's: older
// gateways still serve it.
func TestK8sAPIRuleNeedsNoNewArtifactVersion(t *testing.T) {
	apiArtifact := policy.Compile(k8sAPIBase(policy.Rule{SrcKind: "group", SrcGroupID: gAdmins}, []policy.ExposedService{apiEndpointOn()}))[nodeA]
	serviceArtifact := policy.Compile(k8sBase(svcA, []policy.ExposedService{{ID: svcA, VIP: "100.64.0.7", DNSVIP: "100.64.0.2", Protocol: "tcp", PortLow: 443, PortHigh: 443, ConnectorNodeID: nodeB}}))[nodeA]
	if apiArtifact.Version != serviceArtifact.Version {
		t.Fatalf("a k8s_api rule changed the artifact version: %d, a k8s_service rule gives %d", apiArtifact.Version, serviceArtifact.Version)
	}
	if policyspec.CanonicalHash(apiArtifact) != policyspec.CanonicalHash(serviceArtifact) {
		t.Fatal("the same address, port and DNS grant must hash the same whichever kind produced it")
	}
}
