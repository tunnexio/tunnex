package policy

import (
	"github.com/google/uuid"
	"testing"
)

func TestSandboxCannotInheritLegacySubjectGrants(t *testing.T) {
	owner, group, agentGroup, peer := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	rules := []Rule{
		{SrcKind: "user", SrcUserID: owner},
		{SrcKind: "group", SrcGroupID: group},
		{SrcGroupID: group},
		{SrcKind: "agent", SrcDeviceID: peer},
		{SrcKind: "agent_group", SrcAgentGroupID: agentGroup},
	}
	for _, rule := range rules {
		d := Device{ID: peer, UserID: owner, Kind: "sandbox"}
		if ruleMatchesDevice(rule, d, map[uuid.UUID]bool{group: true}, map[uuid.UUID]bool{agentGroup: true}) {
			t.Fatalf("sandbox inherited %q grant", rule.SrcKind)
		}
		d.Kind = "agent"
		if !ruleMatchesDevice(rule, d, map[uuid.UUID]bool{group: true}, map[uuid.UUID]bool{agentGroup: true}) {
			t.Fatalf("existing agent behavior changed for %q", rule.SrcKind)
		}
	}
}

func TestSandboxExcludedFromHumanGroupDestinations(t *testing.T) {
	node, owner, other, group, peer := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	s := Snapshot{
		Mode: ModeEnforcing,
		Devices: []Device{
			{ID: peer, UserID: owner, NodeID: node, AssignedIP: "10.99.0.4", Kind: "sandbox"},
			{ID: uuid.New(), UserID: other, NodeID: node, AssignedIP: "10.99.0.5", Kind: "human"},
		},
		Memberships: []Membership{{UserID: owner, GroupID: group}},
		Rules:       []Rule{{ID: uuid.New(), SrcKind: "user", SrcUserID: other, DstKind: "group", DstGroupID: group}},
	}
	for _, compiled := range Compile(s) {
		for _, allow := range compiled.Allow {
			if allow.DstCIDR == "10.99.0.4/32" {
				t.Fatal("sandbox inherited human destination-group membership")
			}
		}
	}
}

func TestSandboxLegacyGrantsCompileToNoAllows(t *testing.T) {
	node, owner, group, agentGroup, peer, resource := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	s := Snapshot{Mode: ModeEnforcing,
		Devices:     []Device{{ID: peer, UserID: owner, NodeID: node, AssignedIP: "10.99.0.4", Kind: "sandbox"}},
		Memberships: []Membership{{UserID: owner, GroupID: group}},
		Resources:   []Resource{{ID: resource, CIDR: "192.168.10.0/24", Protocol: "tcp", PortLow: 22, PortHigh: 22}},
	}
	for _, r := range []Rule{{SrcKind: "user", SrcUserID: owner}, {SrcKind: "group", SrcGroupID: group}, {SrcKind: "agent", SrcDeviceID: peer}, {SrcKind: "agent_group", SrcAgentGroupID: agentGroup}} {
		r.ID = uuid.New()
		r.DstKind = "resource"
		r.DstResourceID = resource
		s.Rules = append(s.Rules, r)
	}
	for _, c := range Compile(s) {
		if len(c.Allow) != 0 {
			t.Fatalf("sandbox got legacy allows: %+v", c.Allow)
		}
	}
	s.Devices[0].Kind = "agent"
	if len(Compile(s)[node].Allow) == 0 {
		t.Fatal("existing managed agent lost owner access")
	}
}
