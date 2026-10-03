package nodes

import (
	"testing"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/gatewaymesh"
	"github.com/tunnexio/tunnex/apps/api/internal/policyspec"
)

func TestCrossGatewayArtifactForSitelessGatewayPreservesEnforcement(t *testing.T) {
	a, b := uuid.New(), uuid.New()
	graph, err := gatewaymesh.Build(true, []gatewaymesh.Gateway{{ID: a, PublicKey: "a", Endpoint: "a.example:51820"}, {ID: b, PublicKey: "b"}}, []gatewaymesh.Client{{NodeID: a, Address: "10.99.0.2"}, {NodeID: b, Address: "10.99.0.3"}}, []uuid.UUID{a})
	if err != nil {
		t.Fatal(err)
	}
	topo := siteTopology{poolCIDR: "10.99.0.0/24", clientGraph: graph}
	base := &policyspec.Compiled{NodeID: a.String(), Mode: "enforcing", Mesh: false, Allow: []policyspec.AllowEntry{{SrcIP: "10.99.0.2", DstCIDR: "10.99.0.3/32", Protocol: "tcp", PortLow: 443, PortHigh: 443}}}
	final := (&Service{}).finalizeArtifact(topo, sqlc.Node{ID: a}, base)
	if final.Mesh || len(final.Allow) != 1 || final.Allow[0].PortLow != 443 || len(final.Routes) != 1 || final.Routes[0].DstCIDR != "10.99.0.3/32" || final.PoolCIDR != "10.99.0.0/24" || final.Version != 10 || !final.CrossGatewayClients {
		t.Fatalf("siteless graph or enforcement lost: %+v", final)
	}
	off := (&Service{}).finalizeArtifact(siteTopology{}, sqlc.Node{ID: a}, &policyspec.Compiled{Mode: "enforcing"})
	if len(off.Routes) != 0 || off.Mesh || off.CrossGatewayClients {
		t.Fatal("default introduced routes or mesh")
	}
}
