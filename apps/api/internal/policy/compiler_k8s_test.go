package policy_test

import (
	"testing"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/internal/policy"
	"github.com/tunnexio/tunnex/apps/api/internal/policyspec"
)

var (
	svcA = uuid.MustParse("00000000-0000-0000-0000-00000000a5a5")
	svcB = uuid.MustParse("00000000-0000-0000-0000-00000000b5b5")
)

// base builds an enforcing snapshot: Alice (gAdmins member) on nodeA with a device, and a rule granting
// gAdmins -> the K8s Service `dst`. ExposedServices is supplied by the caller (to model VIP changes /
// deletion / reuse). SiteID is Nil so placement is device-node-only (the resolution is what these reds test).
func k8sBase(dst uuid.UUID, exposed []policy.ExposedService) policy.Snapshot {
	return policy.Snapshot{
		Mode:            policy.ModeEnforcing,
		ExposedServices: exposed,
		Rules:           []policy.Rule{{SrcGroupID: gAdmins, DstKind: "k8s_service", DstK8sServiceID: dst}},
		Memberships:     []policy.Membership{{GroupID: gAdmins, UserID: uAlice}},
		Devices:         []policy.Device{{UserID: uAlice, NodeID: nodeA, AssignedIP: "10.99.0.10"}},
	}
}

// A grant to a K8s Service resolves to the Service's CURRENT VIP/32 (mirrors device-source -> resource).
func TestK8sServiceResolvesToCurrentVIP(t *testing.T) {
	snap := k8sBase(svcA, []policy.ExposedService{{ID: svcA, VIP: "100.64.0.5", Protocol: "tcp", PortLow: 80, PortHigh: 80}})
	a := allowsFor(policy.Compile(snap), nodeA)
	if !hasAllow(a, "10.99.0.10", "100.64.0.5/32") {
		t.Fatalf("grant must resolve to the Service's current VIP/32, got %+v", a)
	}
}

// Reassignment-trap (a): the SAME Service identity with a NEW VIP -> the grant FOLLOWS to the new address
// (the compiler resolves id -> current VIP, never a snapshotted one). The easy half.
func TestK8sServiceGrantFollowsVIPChange(t *testing.T) {
	snap := k8sBase(svcA, []policy.ExposedService{{ID: svcA, VIP: "100.64.0.9", Protocol: "tcp"}})
	a := allowsFor(policy.Compile(snap), nodeA)
	if hasAllow(a, "10.99.0.10", "100.64.0.5/32") {
		t.Fatal("grant must NOT keep the old VIP after reassignment")
	}
	if !hasAllow(a, "10.99.0.10", "100.64.0.9/32") {
		t.Fatalf("grant must follow the Service identity to its new VIP, got %+v", a)
	}
}

// A selected connector has no enrolled desktop device, but it is still an enforcement point for the
// service VIP's final hop. It must therefore receive an artifact rather than panicking in add().
func TestK8sServiceSelectedConnectorReceivesGrant(t *testing.T) {
	snap := k8sBase(svcA, []policy.ExposedService{{
		ID:              svcA,
		VIP:             "100.64.0.5",
		Protocol:        "tcp",
		PortLow:         80,
		PortHigh:        80,
		ConnectorNodeID: nodeB,
	}})
	compiled := policy.Compile(snap)
	if _, ok := compiled[nodeB]; !ok {
		t.Fatal("selected connector must receive a compiled artifact")
	}
	if a := allowsFor(compiled, nodeB); !hasAllow(a, "10.99.0.10", "100.64.0.5/32") {
		t.Fatalf("selected connector must enforce the service VIP grant, got %+v", a)
	}
}

func TestK8sPoolBoundServiceRequiresResolvedGeneration(t *testing.T) {
	for name, svc := range map[string]policy.ExposedService{
		"missing active":     {ID: svcA, VIP: "100.64.0.5", PoolBound: true, ConnectorGeneration: 2},
		"missing generation": {ID: svcA, VIP: "100.64.0.5", PoolBound: true, ConnectorNodeID: nodeB},
	} {
		t.Run(name, func(t *testing.T) {
			compiled := policy.Compile(k8sBase(svcA, []policy.ExposedService{svc}))
			if a := allowsFor(compiled, nodeA); len(a) != 0 {
				t.Fatalf("unresolved pool-bound Service must compile to nothing, got %+v", a)
			}
			if _, ok := compiled[nodeB]; ok {
				t.Fatal("unresolved pool-bound Service must not create a connector artifact")
			}
		})
	}

	resolved := policy.ExposedService{
		ID: svcA, VIP: "100.64.0.5", PoolBound: true,
		ConnectorNodeID: nodeB, ConnectorGeneration: 2,
	}
	compiled := policy.Compile(k8sBase(svcA, []policy.ExposedService{resolved}))
	for _, node := range []uuid.UUID{nodeA, nodeB} {
		if a := allowsFor(compiled, node); !hasAllow(a, "10.99.0.10", "100.64.0.5/32") {
			t.Fatalf("resolved pool-bound Service must compile on node %s, got %+v", node, a)
		}
	}
}

func TestK8sServiceGrantAlsoAllowsItsPrivateDNSVIP(t *testing.T) {
	snap := k8sBase(svcA, []policy.ExposedService{{
		ID: svcA, VIP: "100.64.0.5", DNSVIP: "100.64.0.2", Protocol: "tcp", PortLow: 80, PortHigh: 80,
		ConnectorNodeID: nodeB,
	}})
	compiled := policy.Compile(snap)
	for _, node := range []uuid.UUID{nodeA, nodeB} {
		entries := allowsFor(compiled, node)
		for _, proto := range []policyspec.Protocol{policyspec.ProtoUDP, policyspec.ProtoTCP} {
			found := false
			for _, entry := range entries {
				if entry.SrcIP == "10.99.0.10" && entry.DstCIDR == "100.64.0.2/32" && entry.Protocol == proto && entry.PortLow == 53 && entry.PortHigh == 53 {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("node %s missing %s DNS allow for the granted Service: %+v", node, proto, entries)
			}
		}
	}
}

// Reassignment-trap (b) — THE ONE THAT MATTERS: a DIFFERENT Service (svcB) that inherits a freed VIP does
// NOT inherit svcA's grant. The rule references svcA (now deleted/absent); svcB holds the old VIP. The grant
// keys on identity, so it compiles to NOTHING — the reused VIP is not silently re-granted to the new Service.
func TestReusedVIPDoesNotInheritGrant(t *testing.T) {
	// svcA deleted (absent from ExposedServices); svcB is a NEW Service that got svcA's old VIP 100.64.0.5.
	snap := k8sBase(svcA, []policy.ExposedService{{ID: svcB, VIP: "100.64.0.5", Protocol: "tcp"}})
	a := allowsFor(policy.Compile(snap), nodeA)
	if len(a) != 0 {
		t.Fatalf("a grant to a DELETED Service must not follow its freed VIP onto a different Service, got %+v", a)
	}
	if hasAllow(a, "10.99.0.10", "100.64.0.5/32") {
		t.Fatal("the reused VIP was silently re-granted — identity binding leaked")
	}
}

// Compile-to-nothing (condition 3): a rule pointing at a soft-deleted / absent Service produces ZERO
// AllowEntries — not an error, not a blanket. (The visible "rule points at a vanished Service" warn surface
// belongs in the API/web slice — noted in docs/S10.3-decisions.md.)
func TestK8sServiceDeletedCompilesToNothing(t *testing.T) {
	snap := k8sBase(svcA, nil) // no exposed Services at all
	if a := allowsFor(policy.Compile(snap), nodeA); len(a) != 0 {
		t.Fatalf("a grant to a vanished Service must compile to nothing, got %+v", a)
	}
}
