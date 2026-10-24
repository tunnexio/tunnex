package ipsec

import (
	"context"
	"testing"
	"time"
)

// Model healthy complete host inventories, not an injected Up/report/sequence.
// The production two-snapshot classifier and durable report serializer still
// run. Virtual cost is charged only on the synchronous reader branch so the
// parallel daemon reader cannot race the test's monotonic clock.
func installFQDNCadenceStatusReaders(t *testing.T, r *renewalCycleRig, check func()) {
	t.Helper()
	d := DaemonInventory{}
	k := KernelInventory{Namespace: r.entries[0].Allocation.Namespace}
	x := XFRMInventory{Namespace: r.entries[0].Allocation.Namespace}
	for ei, e := range r.entries {
		for i, tunnel := range e.Engines[:e.Allocation.activeTunnelCount()] {
			own := e.Observed[i]
			k.Links = append(k.Links, KernelLink{Name: own.InterfaceName, Index: own.InterfaceIndex, XFRMID: own.XFRMID, Up: true})
			key := uint32(1000 + ei*10 + i)
			child := DaemonChild{Name: engineName(tunnel), UniqueID: uint64(key), ReqID: tunnel.ReqID, IfIDIn: tunnel.XFRMID, IfIDOut: tunnel.XFRMID, SPIIn: key, SPIOut: key + 10000, Installed: true, LocalPrefixes: engineTransportPrefixes(tunnel, true), RemotePrefixes: engineTransportPrefixes(tunnel, false)}
			d.SAs = append(d.SAs, DaemonIKE{Name: engineName(tunnel), UniqueID: uint64(key), Established: true, LocalAddress: tunnel.LocalAddress, RemoteAddress: tunnel.RemoteAddress, Children: []DaemonChild{child}})
			x.States = append(x.States, XFRMState{Source: tunnel.LocalAddress, Destination: tunnel.RemoteAddress, SPI: child.SPIOut, ReqID: tunnel.ReqID, IfID: tunnel.XFRMID}, XFRMState{Source: tunnel.RemoteAddress, Destination: tunnel.LocalAddress, SPI: child.SPIIn, ReqID: tunnel.ReqID, IfID: tunnel.XFRMID})
			for _, local := range child.LocalPrefixes {
				for _, remote := range child.RemotePrefixes {
					for _, direction := range []string{"in", "fwd", "out"} {
						p := XFRMPolicy{Source: remote, Destination: local, Direction: direction, ReqID: tunnel.ReqID, IfID: tunnel.XFRMID, TemplateSource: tunnel.RemoteAddress, TemplateDestination: tunnel.LocalAddress}
						if direction == "out" {
							p.Source, p.Destination, p.TemplateSource, p.TemplateDestination = local, remote, tunnel.LocalAddress, tunnel.RemoteAddress
						}
						x.Policies = append(x.Policies, p)
					}
				}
			}
		}
	}
	for _, e := range r.entries {
		if got := runtimeTunnelStatuses(e, d, k, x); got != [2]string{"up", "up"} {
			t.Fatalf("healthy fixture must pass real ownership classifier: %v", got)
		}
	}
	r.c.config.IPPath = "/usr/bin/true"
	r.c.config.Daemon = &DaemonClient{}
	r.c.statusReaders = &runtimeStatusReaders{
		daemon: func(context.Context) (DaemonInventory, error) { return d, nil },
		kernel: func(context.Context) (KernelInventory, error) {
			r.charge("status_native", 800*time.Millisecond)
			if check != nil {
				check()
			}
			return k, nil
		},
		xfrm:  func(context.Context) (XFRMInventory, error) { return x, nil },
		alive: r.c.config.DaemonAlive,
	}
}

func TestFQDNCadenceStatusFixtureSerializedHealthyAndUnknown(t *testing.T) {
	for _, broken := range []bool{false, true} {
		t.Run(map[bool]string{false: "healthy", true: "missing_xfrm"}[broken], func(t *testing.T) {
			r, _ := fqdnMultiOwnerCadenceRig(t)
			installFQDNCadenceStatusReaders(t, r, nil)
			if broken {
				r.c.statusReaders.xfrm = func(context.Context) (XFRMInventory, error) { return XFRMInventory{Namespace: r.entries[0].Allocation.Namespace}, nil }
			}
			for _, a := range r.c.active {
				if a.Entry.ContractVersion != 2 {
					continue
				}
				report, err := runtimeFQDNFollowupReport(a.Delivery)
				if err != nil {
					t.Fatal(err)
				}
				before := *r.now
				report, err = r.c.observeIPsecStatusLocked(context.Background(), a.Delivery, report, false, true)
				if err != nil || report.RecoveryVersion == nil || report.SelectionSequence == nil || *report.SelectionSequence == 0 {
					t.Fatal("serialized envelope", err, report)
				}
				if *r.now-before < 1600*time.Millisecond {
					t.Fatal("real reader costs omitted")
				}
				if broken {
					if report.Tunnels[0].Status == "up" || report.Tunnels[1].Status == "up" || report.ActiveSlot != nil {
						t.Fatal("missing native evidence fabricated Up", report)
					}
				} else if report.Tunnels[0].Status != "up" || report.Tunnels[1].Status != "up" || report.ActiveSlot == nil || *report.ActiveSlot != int(selectedRuntimeSlot(a.Entry)) {
					t.Fatal("healthy native report or active slot missing", report)
				}
			}
		})
	}
}
