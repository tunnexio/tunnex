package policy

import (
	"encoding/json"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxscope"
	"testing"
)

func TestSandboxProjectionBoundedAndWithdrawn(t *testing.T) {
	node, creator, peer, resA, resB := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	a := sandboxscope.Scope{CIDR: "10.1.0.0/16", Protocol: "tcp", PortLow: 22, PortHigh: 22}
	s := Snapshot{Mode: ModeEnforcing,
		Devices:   []Device{{ID: peer, UserID: creator, NodeID: node, AssignedIP: "10.99.0.4", Kind: "sandbox"}},
		Resources: []Resource{{ID: resA, CIDR: a.CIDR, Protocol: a.Protocol, PortLow: 22, PortHigh: 22}, {ID: resB, CIDR: "10.2.0.0/16", Protocol: "any"}},
		Rules:     []Rule{{ID: uuid.New(), SrcKind: "user", SrcUserID: creator, DstKind: "resource", DstResourceID: resA}, {ID: uuid.New(), SrcKind: "user", SrcUserID: creator, DstKind: "resource", DstResourceID: resB}},
		Sandboxes: []SandboxProjection{{SandboxID: uuid.New(), DeviceID: peer, CreatorID: creator, Requested: []sandboxscope.Scope{a}, TemplateCap: []sandboxscope.Scope{{CIDR: "10.0.0.0/8", Protocol: "any"}}}},
	}
	before, _ := json.Marshal(s)
	got := Compile(s)[node].Allow
	if len(got) != 1 || got[0].DstCIDR != a.CIDR || got[0].PortLow != 22 || got[0].PortHigh != 22 {
		t.Fatalf("unbounded grants: %+v", got)
	}
	second, _ := json.Marshal(Compile(s))
	first, _ := json.Marshal(Compile(s))
	if string(first) != string(second) {
		t.Fatal("unstable projection")
	}
	after, _ := json.Marshal(s)
	if string(before) != string(after) {
		t.Fatal("snapshot mutated")
	}
	s.Rules[0].Disabled = true
	if len(Compile(s)[node].Allow) != 0 {
		t.Fatal("revoked entitlement retained")
	}
	s.Rules[0].Disabled = false
	s.Sandboxes[0].TemplateCap = nil
	if len(Compile(s)[node].Allow) != 0 {
		t.Fatal("removed template cap retained")
	}
	s.Sandboxes[0].TemplateCap = []sandboxscope.Scope{a}
	s.Sandboxes[0].CreatorID = uuid.New()
	if len(Compile(s)[node].Allow) != 0 {
		t.Fatal("spoofed creator matched")
	}
	s.Sandboxes[0].CreatorID = creator
	s.Sandboxes = append(s.Sandboxes, s.Sandboxes[0])
	if len(Compile(s)[node].Allow) != 0 {
		t.Fatal("ambiguous binding matched")
	}
}
