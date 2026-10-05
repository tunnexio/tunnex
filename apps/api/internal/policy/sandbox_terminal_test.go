package policy

import (
	"testing"

	"github.com/google/uuid"
)

func TestSandboxTerminalGrantIsCreatorHumanOnlyAndWithdrawn(t *testing.T) {
	creator, other, sandboxNode, clientNode := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	sandbox, human, agent, sibling, foreign := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	s := Snapshot{Mode: ModeEnforcing, Devices: []Device{
		{ID: sandbox, Kind: "sandbox", UserID: creator, NodeID: sandboxNode, AssignedIP: "10.99.0.4"},
		{ID: human, Kind: "human", UserID: creator, NodeID: clientNode, AssignedIP: "10.99.0.2"},
		{ID: agent, Kind: "agent", UserID: creator, NodeID: clientNode, AssignedIP: "10.99.0.3"},
		{ID: sibling, Kind: "sandbox", UserID: creator, NodeID: clientNode, AssignedIP: "10.99.0.5"},
		{ID: foreign, Kind: "human", UserID: other, NodeID: clientNode, AssignedIP: "10.99.0.6"},
	}, Sandboxes: []SandboxProjection{{SandboxID: uuid.New(), DeviceID: sandbox, CreatorID: creator}}}
	compiled := Compile(s)
	for _, node := range []uuid.UUID{clientNode, sandboxNode} {
		allows := compiled[node].Allow
		if len(allows) != 1 || allows[0].SrcDeviceID != human.String() || allows[0].SrcIP != "10.99.0.2" || allows[0].DstCIDR != "10.99.0.4/32" || allows[0].Protocol != "tcp" || allows[0].PortLow != 22 || allows[0].PortHigh != 22 {
			t.Fatal("terminal grant widened or wrong placement", allows)
		}
	}
	s.Sandboxes = nil
	for _, artifact := range Compile(s) {
		if len(artifact.Allow) != 0 {
			t.Fatal("withdrawn projection retains terminal access")
		}
	}
	// Persisted/public source kinds cannot manufacture compiler-owned management.
	s.Rules = []Rule{{ID: uuid.New(), SrcKind: "sandbox_terminal", SrcDeviceID: human, DstKind: "resource", DstResourceID: sandbox}}
	s.Resources = []Resource{{ID: sandbox, CIDR: "10.99.0.4/32", Protocol: "tcp", PortLow: 22, PortHigh: 22}}
	for _, artifact := range Compile(s) {
		if len(artifact.Allow) != 0 {
			t.Fatal("untrusted terminal rule accepted")
		}
	}
}

func TestSandboxTerminalPinExcludesOtherOwnerDevices(t *testing.T) {
	creator, node, sandbox, mac, otherMac := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	s := Snapshot{Mode: ModeEnforcing, Devices: []Device{
		{ID: sandbox, Kind: "sandbox", UserID: creator, NodeID: node, AssignedIP: "10.99.0.10"},
		{ID: mac, Kind: "human", UserID: creator, NodeID: node, AssignedIP: "10.99.0.5"},
		{ID: otherMac, Kind: "human", UserID: creator, NodeID: node, AssignedIP: "10.99.0.6"},
	}, Sandboxes: []SandboxProjection{{SandboxID: uuid.New(), DeviceID: sandbox, CreatorID: creator, TerminalDeviceID: mac}}}
	allows := Compile(s)[node].Allow
	if len(allows) != 1 || allows[0].SrcDeviceID != mac.String() || allows[0].DstCIDR != "10.99.0.10/32" || allows[0].Protocol != "tcp" || allows[0].PortLow != 22 || allows[0].PortHigh != 22 {
		t.Fatal("terminal pin widened", allows)
	}
	s.Sandboxes[0].TerminalDeviceID = uuid.New()
	if len(Compile(s)[node].Allow) != 0 {
		t.Fatal("missing pinned device fell back to all owner devices")
	}
	s.Sandboxes[0].TerminalDeviceID = mac
	s.Devices[1].UserID = uuid.New()
	if len(Compile(s)[node].Allow) != 0 {
		t.Fatal("transferred device retained creator grant")
	}
}

func TestSandboxLocalTerminalPlacementAndGatewayMoves(t *testing.T) {
	creator, local, remote, peer, mac, site := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	s := Snapshot{Mode: ModeEnforcing, ActiveHub: remote,
		Devices:     []Device{{ID: peer, Kind: "sandbox", UserID: creator, NodeID: local, AssignedIP: "10.99.0.10"}, {ID: mac, Kind: "human", UserID: creator, NodeID: local, AssignedIP: "10.99.0.5"}},
		SiteSubnets: []SiteSubnet{{SiteID: site, CIDR: "10.99.0.0/24"}}, SiteNodes: []SiteNode{{SiteID: site, NodeID: remote}},
		Sandboxes: []SandboxProjection{{SandboxID: uuid.New(), DeviceID: peer, CreatorID: creator, TerminalDeviceID: mac, LocalTerminalGatewayID: local}},
	}
	compiled := Compile(s)
	if len(compiled[local].Allow) != 1 || len(compiled[remote].Allow) != 0 {
		t.Fatalf("local terminal leaked into remote site or hub: %+v", compiled)
	}
	for _, index := range []int{0, 1} {
		s.Devices[index].NodeID = remote
		for _, artifact := range Compile(s) {
			if len(artifact.Allow) != 0 {
				t.Fatal("gateway move retained local grant", artifact.Allow)
			}
		}
		s.Devices[index].NodeID = local
	}
	s.Sandboxes[0].TerminalDeviceID = uuid.Nil
	for _, artifact := range Compile(s) {
		if len(artifact.Allow) != 0 {
			t.Fatal("missing terminal pin widened local grant")
		}
	}
}
