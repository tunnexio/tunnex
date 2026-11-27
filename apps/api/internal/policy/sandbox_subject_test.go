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
	}
}

// AI-SEC-1: an agent is its own principal. It is reached by rules that name it
// or one of its agent groups, never by a rule written for the person who
// enrolled it or for that person's groups.
func TestAgentMatchesOnlyAgentSubjects(t *testing.T) {
	owner, group, agentGroup, agent := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	d := Device{ID: agent, UserID: owner, Kind: "agent"}
	ownerGroups, agentGroups := map[uuid.UUID]bool{group: true}, map[uuid.UUID]bool{agentGroup: true}
	for _, rule := range []Rule{{SrcKind: "user", SrcUserID: owner}, {SrcKind: "group", SrcGroupID: group}, {SrcGroupID: group}} {
		if ruleMatchesDevice(rule, d, ownerGroups, agentGroups) {
			t.Fatalf("agent inherited its owner's %q grant", rule.SrcKind)
		}
	}
	for _, rule := range []Rule{{SrcKind: "agent", SrcDeviceID: agent}, {SrcKind: "agent_group", SrcAgentGroupID: agentGroup}} {
		if !ruleMatchesDevice(rule, d, ownerGroups, agentGroups) {
			t.Fatalf("agent lost its own %q grant", rule.SrcKind)
		}
	}
	human := Device{ID: uuid.New(), UserID: owner, Kind: "human"}
	for _, rule := range []Rule{{SrcKind: "user", SrcUserID: owner}, {SrcKind: "group", SrcGroupID: group}, {SrcGroupID: group}} {
		if !ruleMatchesDevice(rule, human, ownerGroups, agentGroups) {
			t.Fatalf("a person's device lost its %q grant", rule.SrcKind)
		}
	}
}

func TestAgentOwnerGrantsCompileToNoAllows(t *testing.T) {
	node, owner, group, agent, resource := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	s := Snapshot{Mode: ModeEnforcing,
		Devices: []Device{
			{ID: uuid.New(), UserID: owner, NodeID: node, AssignedIP: "10.99.0.3", Kind: "human"},
			{ID: agent, UserID: owner, NodeID: node, AssignedIP: "10.99.0.4", Kind: "agent"},
		},
		Memberships: []Membership{{UserID: owner, GroupID: group}},
		Resources:   []Resource{{ID: resource, CIDR: "192.168.10.0/24", Protocol: "tcp", PortLow: 22, PortHigh: 22}},
		Rules: []Rule{
			{ID: uuid.New(), SrcKind: "user", SrcUserID: owner, DstKind: "resource", DstResourceID: resource},
			{ID: uuid.New(), SrcKind: "group", SrcGroupID: group, DstKind: "resource", DstResourceID: resource},
		},
	}
	human, agentAllows := 0, 0
	for _, compiled := range Compile(s) {
		for _, allow := range compiled.Allow {
			switch allow.SrcIP {
			case "10.99.0.3":
				human++
			case "10.99.0.4":
				agentAllows++
			}
		}
	}
	if human == 0 {
		t.Fatal("the owner's own device must keep its grant")
	}
	if agentAllows != 0 {
		t.Fatalf("agent received %d allows from its owner's rules", agentAllows)
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
