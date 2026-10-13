package ipsec

import (
	"context"
	"github.com/google/uuid"
	"net/netip"
	"reflect"
	"testing"
)

// A complete independently disjoint B snapshot changes SPI during rekey;
// A's two owned pairs and selectors remain byte-for-byte identical.
func TestStaticHealthyPeerSurvivesUnrelatedNamespaceRekey(t *testing.T) {
	e, d, k, x := runtimeProofFixture()
	b, bd, bk, bx := runtimeProofFixture()
	// B owns distinct interface IDs/names (UUID-derived fixture), indexes,
	// remote prefix and exact daemon/kernel SPI pairs in the same namespace.
	remote := netip.MustParsePrefix("10.30.0.0/24")
	for i := range b.Engines {
		b.Observed[i].InterfaceIndex += 100
		bk.Links[i].Index += 100
		b.Engines[i].RemotePrefixes = []netip.Prefix{remote}
		b.Allocation.Tunnels[i].RemotePrefixes = []netip.Prefix{remote}
		bd.SAs[i].Children[0].RemotePrefixes = []netip.Prefix{remote}
		bd.SAs[i].Children[0].SPIIn += 1000
		bd.SAs[i].Children[0].SPIOut += 1000
	}
	for i := range bx.States {
		bx.States[i].SPI += 1000
	}
	for i := range bx.Policies {
		if bx.Policies[i].Direction == "out" {
			bx.Policies[i].Destination = remote
		} else {
			bx.Policies[i].Source = remote
		}
	}
	for i := range bk.Routes {
		bk.Routes[i].Destination = remote
		bk.Routes[i].OutputInterface += 100
	}
	d.SAs = append(d.SAs, bd.SAs...)
	k.Links = append(k.Links, bk.Links...)
	k.Routes = append(k.Routes, bk.Routes...)
	x.States = append(x.States, bx.States...)
	x.Policies = append(x.Policies, bx.Policies...)
	if runtimeInventoryMatches(e, d, k, x) != nil || runtimeInventoryMatches(b, d, k, x) != nil {
		t.Fatal("two complete owned baselines refused")
	}
	before := runtimeTunnelStatuses(e, d, k, x)
	if before != [2]string{"up", "up"} {
		t.Fatal("disjoint baseline is not independently healthy", before)
	}
	calls := 0
	var currentD DaemonInventory
	readers := runtimeStatusReaders{daemon: func(context.Context) (DaemonInventory, error) {
		calls++
		currentD = d
		currentD.SAs = append([]DaemonIKE(nil), d.SAs...)
		if calls == 2 {
			sa := currentD.SAs[2]
			sa.Children = append([]DaemonChild(nil), sa.Children...)
			sa.Children[0].SPIOut++
			currentD.SAs[2] = sa
		}
		return currentD, nil
	}, kernel: func(context.Context) (KernelInventory, error) { return k, nil }, xfrm: func(context.Context) (XFRMInventory, error) {
		v := x
		v.States = append([]XFRMState(nil), x.States...)
		if calls == 2 {
			v.States[4].SPI++
		}
		if runtimeInventoryMatches(e, currentD, k, v) != nil || runtimeInventoryMatches(b, currentD, k, v) != nil {
			t.Fatal("owned complete per-pass proof failed")
		}
		if got := runtimeTunnelStatuses(e, currentD, k, v); got != before {
			t.Fatal("A ownership changed", got)
		}
		return v, nil
	}, alive: func() bool { return true }}
	if got := runtimeObservedStatuses(context.Background(), e, readers); got != before {
		t.Fatalf("healthy A withdrawn by unrelated B rekey: got %v, want %v", got, before)
	}
}

func TestStaticForeignOwnedSPIStillRefused(t *testing.T) {
	e, d, k, x := runtimeProofFixture()
	x.States[0].SPI++
	if got := runtimeTunnelStatuses(e, d, k, x); got[0] != "unknown" {
		t.Fatal("mismatched owned SPI accepted", got)
	}
}

func TestStaticSelectedUnknownUsesGlobalRefusal(t *testing.T) {
	r := newRecoveryTestRig(t)
	entries, err := r.c.journal.Entries()
	if err != nil {
		t.Fatal(err)
	}
	e := entries[0]
	authority, identity, err := r.c.recoveryLease(context.Background(), e, r.m.Policy.Hash)
	if err != nil {
		t.Fatal(err)
	}
	r.c.active = map[uuid.UUID]runtimeActive{e.Allocation.ConnectionID: {Entry: e, Environment: r.env, Authority: authority, Identity: identity}}
	// Keep independent ownership proof good, then make the later installation
	// health read unknown; this isolates the global refusal branch itself.
	r.c.prove = func(context.Context, RuntimeJournalEntry, RuntimeEnvironment) error { return nil }
	r.status = [2]string{"unknown", "up"}
	if err := r.c.installActive(context.Background(), entries); err == nil {
		t.Fatal("unknown selected peer unexpectedly accepted")
	}
	if len(r.events) == 0 || r.events[len(r.events)-1] != "deny" {
		t.Fatal("global refusal was not installed", r.events)
	}
}

func TestStaticOverlapArtifactsRemainRefused(t *testing.T) {
	for _, kind := range []string{"reqid", "ifid", "route"} {
		t.Run(kind, func(t *testing.T) {
			e, d, k, x := runtimeProofFixture()
			switch kind {
			case "reqid":
				s := x.States[0]
				s.IfID += 100
				s.SPI += 100
				x.States = append(x.States, s)
			case "ifid":
				s := x.States[0]
				s.ReqID += 100
				s.SPI += 100
				x.States = append(x.States, s)
			case "route":
				r := k.Routes[0]
				r.OutputInterface += 100
				k.Routes = append(k.Routes, r)
			}
			if runtimeInventoryMatches(e, d, k, x) == nil {
				t.Fatal("overlapping unknown artifact accepted", kind)
			}
		})
	}
}

func TestConnectionSnapshotRetainsEveryTargetCollision(t *testing.T) {
	e, _, k, x := runtimeProofFixture()
	for _, kind := range []string{"spi", "reqid", "ifid", "nat", "route", "name", "index"} {
		t.Run(kind, func(t *testing.T) {
			xx := x
			xx.States = append([]XFRMState(nil), x.States...)
			kk := k
			kk.Links = append([]KernelLink(nil), k.Links...)
			kk.Routes = append([]KernelRoute(nil), k.Routes...)
			switch kind {
			case "spi":
				xx.States[0].SPI++
			case "reqid":
				xx.States[0].ReqID++
			case "ifid":
				xx.States[0].IfID++
			case "nat":
				xx.States[0].Encapsulation.DestinationPort++
			case "route":
				kk.Routes[0].Metric++
			case "name":
				kk.Links[0].Name = "foreign"
			case "index":
				kk.Links[0].Index++
			}
			if reflect.DeepEqual(connectionXFRMSnapshot(e, x), connectionXFRMSnapshot(e, xx)) && reflect.DeepEqual(connectionKernelSnapshot(e, k), connectionKernelSnapshot(e, kk)) {
				t.Fatal("target collision vanished", kind)
			}
		})
	}
}
