package ipsec

import (
	"context"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
)

func azureSchedulerBGPProofFixture(t *testing.T, profile string) (RuntimeJournalEntry, DaemonInventory, KernelInventory, XFRMInventory) {
	m := azureMaterialFixture(profile)
	e, _, _ := runtimeMaterialEntry(m, m.Manifest.OrgID, m.Manifest.NodeID, "net:[4026531992]")
	d := DaemonInventory{}
	k := KernelInventory{Namespace: e.Allocation.Namespace}
	x := XFRMInventory{Namespace: e.Allocation.Namespace}
	for i, t := range e.Engines[:e.Allocation.activeTunnelCount()] {
		own := Ownership{Namespace: e.Allocation.Namespace, InterfaceName: e.Allocation.Tunnels[i].Name, InterfaceIndex: 10 + i, XFRMID: t.XFRMID}
		e.Observed[i] = own
		k.Links = append(k.Links, KernelLink{Name: own.InterfaceName, Index: own.InterfaceIndex, XFRMID: own.XFRMID, Up: true})
		child := DaemonChild{Name: engineName(t), UniqueID: uint64(i + 1), ReqID: t.ReqID, IfIDIn: t.XFRMID, IfIDOut: t.XFRMID, SPIIn: uint32(100 + i), SPIOut: uint32(200 + i), Installed: true, LocalPrefixes: engineTransportPrefixes(t, true), RemotePrefixes: engineTransportPrefixes(t, false)}
		d.Connections = append(d.Connections, engineName(t))
		d.SharedKeys = append(d.SharedKeys, engineName(t))
		d.SAs = append(d.SAs, DaemonIKE{Name: engineName(t), UniqueID: uint64(i + 1), Established: true, LocalAddress: t.LocalAddress, RemoteAddress: t.RemoteAddress, Children: []DaemonChild{child}})
		x.States = append(x.States, XFRMState{Source: t.LocalAddress, Destination: t.RemoteAddress, SPI: child.SPIOut, ReqID: t.ReqID, IfID: t.XFRMID}, XFRMState{Source: t.RemoteAddress, Destination: t.LocalAddress, SPI: child.SPIIn, ReqID: t.ReqID, IfID: t.XFRMID})
		for _, l := range engineTransportPrefixes(t, true) {
			for _, r := range engineTransportPrefixes(t, false) {
				for _, dir := range []string{"in", "fwd", "out"} {
					p := XFRMPolicy{Source: r, Destination: l, Direction: dir, ReqID: t.ReqID, IfID: t.XFRMID, TemplateSource: t.RemoteAddress, TemplateDestination: t.LocalAddress}
					if dir == "out" {
						p.Source, p.Destination, p.TemplateSource, p.TemplateDestination = l, r, t.LocalAddress, t.RemoteAddress
					}
					x.Policies = append(x.Policies, p)
				}
			}
		}
	}
	for _, r := range e.Engines[0].RemotePrefixes {
		k.Routes = append(k.Routes, KernelRoute{Kind: 1, RouteTuple: RouteTuple{Destination: r, Table: 254, Protocol: 242, Metric: 50001, OutputInterface: 10}})
	}
	e.BGPRoutes = &RuntimeBGPRoutes{Sequence: 1, Stage: "completed", Owned: []RuntimeBGPRouteTuple{routeTupleFixture(e, 1)}, Target: []RuntimeBGPRouteTuple{routeTupleFixture(e, 1)}}
	return e, d, k, x
}

func azureSchedulerRouteFixture(e RuntimeJournalEntry) *recoveryKernelFixture {
	f := newRecoveryKernelFixture()
	f.p = e.Allocation
	f.owned = e.Observed
	for i, t := range e.Allocation.Tunnels[:e.Allocation.activeTunnelCount()] {
		f.routes[i] = map[string]bool{netip.PrefixFrom(t.BGP.Peer, 32).String(): true}
	}
	if e.Allocation.activeTunnelCount() == 1 {
		f.deleted[1] = true
		f.routes[1] = map[string]bool{}
	}
	for _, r := range bgpRouteUnion(e.BGPRoutes) {
		f.routes[r.Slot-1][r.Prefix.String()] = true
	}
	return f
}
func azureSchedulerRouteReader(f *recoveryKernelFixture) *KernelApplier {
	a := f.applier()
	a.run = func(ctx context.Context, args ...string) ([]byte, error) {
		b, err := f.run(ctx, args...)
		if err != nil {
			return b, err
		}
		if strings.Contains(strings.Join(args, " "), "addr show") {
			var rows []map[string]any
			if json.Unmarshal(b, &rows) != nil {
				return nil, ErrKernelApply
			}
			for _, row := range rows {
				for _, v := range row["addr_info"].([]any) {
					v.(map[string]any)["prefixlen"] = 32
				}
			}
			return json.Marshal(rows)
		}
		return b, nil
	}
	return a
}
func TestAzureSchedulerBGPContractNativeProof(t *testing.T) {
	for _, profile := range []string{AzureActiveActiveBGPProfile, AzureActiveStandbyBGPProfile} {
		t.Run(profile, func(t *testing.T) {
			e, d, k, x := azureSchedulerBGPProofFixture(t, profile)
			f := azureSchedulerRouteFixture(e)
			if runtimeInventoryMatches(e, d, k, x) == nil {
				t.Fatal("static validator unexpectedly admitted BGP")
			}
			if azureSchedulerNativeProof(context.Background(), e, d, k, x, azureSchedulerRouteReader(f)) != nil {
				t.Fatal("valid BGP contract refused")
			}
			if f.mutations != 0 {
				t.Fatal("proof mutated kernel")
			}
		})
	}
}
func TestAzureSchedulerBGPContractRefusals(t *testing.T) {
	for name, mutate := range map[string]func(*RuntimeJournalEntry, *DaemonInventory, *XFRMInventory, *recoveryKernelFixture){
		"missing route": func(e *RuntimeJournalEntry, _ *DaemonInventory, _ *XFRMInventory, f *recoveryKernelFixture) {
			delete(f.routes[0], e.BGPRoutes.Owned[0].Prefix.String())
		},
		"wrong metric": func(_ *RuntimeJournalEntry, _ *DaemonInventory, _ *XFRMInventory, f *recoveryKernelFixture) {
			f.badMetric = true
		},
		"wrong child": func(_ *RuntimeJournalEntry, d *DaemonInventory, _ *XFRMInventory, _ *recoveryKernelFixture) {
			d.SAs[0].Children[0].Installed = false
		},
		"wrong SPI": func(_ *RuntimeJournalEntry, _ *DaemonInventory, x *XFRMInventory, _ *recoveryKernelFixture) {
			x.States[0].SPI++
		},
		"inactive cardinality": func(_ *RuntimeJournalEntry, d *DaemonInventory, _ *XFRMInventory, _ *recoveryKernelFixture) {
			d.SAs = append(d.SAs, d.SAs[0])
		},
		"inactive route slot": func(e *RuntimeJournalEntry, _ *DaemonInventory, _ *XFRMInventory, _ *recoveryKernelFixture) {
			e.BGPRoutes.Owned[0].Slot = 2
		},
		"pending routes": func(e *RuntimeJournalEntry, _ *DaemonInventory, _ *XFRMInventory, _ *recoveryKernelFixture) {
			e.BGPRoutes.Stage = "pending"
		},
	} {
		t.Run(name, func(t *testing.T) {
			e, d, k, x := azureSchedulerBGPProofFixture(t, AzureActiveStandbyBGPProfile)
			f := azureSchedulerRouteFixture(e)
			mutate(&e, &d, &x, f)
			if azureSchedulerNativeProof(context.Background(), e, d, k, x, azureSchedulerRouteReader(f)) == nil {
				t.Fatal("invalid proof admitted")
			}
			if f.mutations != 0 {
				t.Fatal("mutated")
			}
		})
	}
}

func TestAzureSchedulerStaticProofUnchanged(t *testing.T) {
	e, d, k, x := runtimeProofFixture()
	if azureSchedulerNativeProof(context.Background(), e, d, k, x, nil) != nil {
		t.Fatal("static proof changed")
	}
	k.Routes = nil
	if azureSchedulerNativeProof(context.Background(), e, d, k, x, nil) == nil {
		t.Fatal("static missing routes admitted")
	}
}
