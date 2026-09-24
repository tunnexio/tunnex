package policy

import (
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/ipsec"
	"testing"
)

func TestIPsecRuntimePolicyExplicitGrantOnly(t *testing.T) {
	org, site, node, conn, res := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	input := ipsec.RuntimePolicyInput{OrgID: org, NodeID: node, SiteID: site, ConnectionID: conn, Config: ipsec.StaticConfig{LocalPrefixes: []string{"10.10.0.0/24"}, RemotePrefixes: []string{"10.20.0.0/24"}}}
	snapshot := Snapshot{Mode: ModeEnforcing, SiteNodes: []SiteNode{{SiteID: site, NodeID: node}}, SiteSubnets: []SiteSubnet{{SiteID: site, CIDR: "10.10.0.0/24"}}, Resources: []Resource{{ID: res, CIDR: "10.10.0.5/32", Protocol: "tcp", PortLow: 443, PortHigh: 443}}, Rules: []Rule{{ID: uuid.New(), SrcKind: "cidr", SrcCIDR: "10.20.0.9/32", DstKind: "resource", DstResourceID: res}}}
	policy, err := compileIPsecRuntimePolicy(snapshot, input)
	if err != nil || len(policy.Hash) != 64 || len(policy.Grants) != 1 {
		t.Fatalf("explicit projection missing %+v %v", policy, err)
	}
	if policy.Grants[0].Source != "10.20.0.9/32" || policy.Grants[0].Destination != "10.10.0.5/32" || policy.Grants[0].PortLow != 443 {
		t.Fatal("grant widened")
	}
	snapshot.Rules[0].Disabled = true
	revoked, err := compileIPsecRuntimePolicy(snapshot, input)
	if err != nil || len(revoked.Grants) != 0 || revoked.Hash == policy.Hash {
		t.Fatal("revocation not reflected")
	}
	snapshot.Rules[0].Disabled = false
	snapshot.Mode = "mesh"
	mesh, err := compileIPsecRuntimePolicy(snapshot, input)
	if err != nil || len(mesh.Grants) != 0 {
		t.Fatal("mesh created authority")
	}
	snapshot.Mode = ModeEnforcing
	snapshot.Rules[0].SrcKind = "group"
	group, err := compileIPsecRuntimePolicy(snapshot, input)
	if err != nil || len(group.Grants) != 0 {
		t.Fatal("group widening")
	}
}

func TestIPsecRuntimePolicyLocalSourceUsesAssignedGateway(t *testing.T) {
	site, node, other, res := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	input := ipsec.RuntimePolicyInput{OrgID: uuid.New(), NodeID: node, SiteID: site, ConnectionID: uuid.New(), Config: ipsec.StaticConfig{LocalPrefixes: []string{"10.10.0.0/24"}, RemotePrefixes: []string{"10.20.0.0/24"}}}
	snap := Snapshot{Mode: ModeEnforcing, SiteNodes: []SiteNode{{SiteID: site, NodeID: node}, {SiteID: site, NodeID: other}}, SiteSubnets: []SiteSubnet{{SiteID: site, CIDR: "10.10.0.0/24"}}, Resources: []Resource{{ID: res, CIDR: "10.20.0.5/32", Protocol: "tcp", PortLow: 443, PortHigh: 443}}, Rules: []Rule{{ID: uuid.New(), SrcKind: "site", SrcSiteID: site, DstKind: "resource", DstResourceID: res}}}
	p, err := compileIPsecRuntimePolicy(snap, input)
	if err != nil || len(p.Grants) != 1 {
		t.Fatalf("assigned gateway lost local grant: %+v %v", p, err)
	}
	snap.SiteNodes = snap.SiteNodes[1:]
	if _, err := compileIPsecRuntimePolicy(snap, input); err == nil {
		t.Fatal("missing assignment accepted")
	}
}
