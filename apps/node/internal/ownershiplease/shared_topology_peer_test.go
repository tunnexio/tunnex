package ownershiplease

import (
	"github.com/tunnexio/tunnex/apps/node/internal/reconcile"
	"reflect"
	"testing"
)

func TestSharedTopologyPeerFencePreservesOrdinaryRouteAndDevice(t *testing.T) {
	base := reconcile.DesiredState{Peers: []reconcile.Peer{
		{PublicKey: projectorPeerA, AllowedIPs: []string{"10.99.0.2/32"}},
		{PublicKey: projectorPeerB, AllowedIPs: []string{"10.99.0.0/24", "172.31.0.0/16"}},
	}}
	fences := map[string]PoolFence{"pool": {Suppressed: PoolOwnedBaseFields{WGPeers: []WGPeerOwnership{{PublicKey: projectorPeerB, AllowedIPs: []string{"10.99.0.0/24"}}}}}}
	got := filterFencedBase(base, fences)
	if len(got.Peers) != 2 || !reflect.DeepEqual(got.Peers[0].AllowedIPs, []string{"10.99.0.2/32"}) || !reflect.DeepEqual(got.Peers[1].AllowedIPs, []string{"172.31.0.0/16"}) {
		t.Fatalf("pool fence changed unrelated peer ownership: %+v", got.Peers)
	}
	if len(base.Peers[1].AllowedIPs) != 2 {
		t.Fatal("filter mutated raw base")
	}
}
