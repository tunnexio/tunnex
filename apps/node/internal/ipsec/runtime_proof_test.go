package ipsec

import (
	"net/netip"
	"testing"
)

func runtimeProofFixture() (RuntimeJournalEntry, DaemonInventory, KernelInventory, XFRMInventory) {
	m := runtimeMaterialFixture()
	e, _, _ := runtimeMaterialEntry(m, m.Manifest.OrgID, m.Manifest.NodeID, "net:[4026531992]")
	d := DaemonInventory{}
	k := KernelInventory{Namespace: e.Allocation.Namespace}
	x := XFRMInventory{Namespace: e.Allocation.Namespace}
	for i, t := range e.Engines {
		own := Ownership{Namespace: e.Allocation.Namespace, InterfaceName: e.Allocation.Tunnels[i].Name, InterfaceIndex: 10 + i, XFRMID: t.XFRMID}
		e.Observed[i] = own
		k.Links = append(k.Links, KernelLink{Name: own.InterfaceName, Index: own.InterfaceIndex, XFRMID: own.XFRMID, Up: true})
		child := DaemonChild{Name: engineName(t), UniqueID: uint64(i + 1), ReqID: t.ReqID, IfIDIn: t.XFRMID, IfIDOut: t.XFRMID, SPIIn: uint32(100 + i), SPIOut: uint32(200 + i), Installed: true, LocalPrefixes: t.LocalPrefixes, RemotePrefixes: t.RemotePrefixes}
		d.SAs = append(d.SAs, DaemonIKE{Name: engineName(t), UniqueID: uint64(i + 1), Established: true, LocalAddress: t.LocalAddress, RemoteAddress: t.RemoteAddress, Children: []DaemonChild{child}})
		x.States = append(x.States, XFRMState{Source: t.LocalAddress, Destination: t.RemoteAddress, SPI: child.SPIOut, ReqID: t.ReqID, IfID: t.XFRMID}, XFRMState{Source: t.RemoteAddress, Destination: t.LocalAddress, SPI: child.SPIIn, ReqID: t.ReqID, IfID: t.XFRMID})
		for _, l := range t.LocalPrefixes {
			for _, r := range t.RemotePrefixes {
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
	return e, d, k, x
}
func TestRuntimeProofIndependentOwnershipRefusals(t *testing.T) {
	e, d, k, x := runtimeProofFixture()
	if runtimeInventoryMatches(e, d, k, x) != nil {
		t.Fatal("valid independent tuples refused")
	}
	cases := map[string]func(*DaemonInventory, *KernelInventory, *XFRMInventory){
		"wrong template SPI": func(_ *DaemonInventory, _ *KernelInventory, x *XFRMInventory) { x.Policies[0].TemplateSPI = 4294967295 },
		"missing state":      func(_ *DaemonInventory, _ *KernelInventory, x *XFRMInventory) { x.States = x.States[1:] },
		"missing route":      func(_ *DaemonInventory, k *KernelInventory, _ *XFRMInventory) { k.Routes = nil },
		"foreign reqid":      func(_ *DaemonInventory, _ *KernelInventory, x *XFRMInventory) { x.States[0].IfID++ },
		"expanded policy": func(_ *DaemonInventory, _ *KernelInventory, x *XFRMInventory) {
			p := x.Policies[0]
			p.Source = netip.MustParsePrefix("0.0.0.0/0")
			x.Policies = append(x.Policies, p)
		},
		"unestablished": func(d *DaemonInventory, _ *KernelInventory, _ *XFRMInventory) { d.SAs[0].Established = false },
		"wrong SPI":     func(d *DaemonInventory, _ *KernelInventory, _ *XFRMInventory) { d.SAs[0].Children[0].SPIOut++ },
		"extra route": func(_ *DaemonInventory, k *KernelInventory, _ *XFRMInventory) {
			k.Routes = append(k.Routes, k.Routes[0])
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			e, d, k, x := runtimeProofFixture()
			mutate(&d, &k, &x)
			if runtimeInventoryMatches(e, d, k, x) == nil {
				t.Fatal("invalid observed tuple accepted")
			}
		})
	}
}

func TestRuntimeMissingJournalRequiresExactAbsence(t *testing.T) {
	e, d, k, x := runtimeProofFixture()
	emptyD := DaemonInventory{}
	emptyK := KernelInventory{Namespace: e.Allocation.Namespace}
	emptyX := XFRMInventory{Namespace: e.Allocation.Namespace}
	if !runtimeObjectsAbsent(e, emptyD, emptyK, emptyX) {
		t.Fatal("complete absence refused")
	}
	if runtimeObjectsAbsent(e, d, emptyK, emptyX) || runtimeObjectsAbsent(e, emptyD, k, emptyX) || runtimeObjectsAbsent(e, emptyD, emptyK, x) {
		t.Fatal("existing matching object accepted as absent")
	}
	foreign := DaemonInventory{Connections: []string{engineName(e.Engines[0])}}
	if runtimeObjectsAbsent(e, foreign, emptyK, emptyX) {
		t.Fatal("foreign daemon configuration adopted")
	}
}

func TestRuntimeMissingJournalRefusesOrphanReservedRoute(t *testing.T) {
	e, _, _, _ := runtimeProofFixture()
	k := KernelInventory{Namespace: e.Allocation.Namespace, Routes: []KernelRoute{{RouteTuple: RouteTuple{Destination: e.Engines[0].RemotePrefixes[0], Table: 254, Protocol: 242, Metric: 50001, OutputInterface: 900}}}}
	x := XFRMInventory{Namespace: e.Allocation.Namespace}
	if runtimeObjectsAbsent(e, DaemonInventory{}, k, x) {
		t.Fatal("orphan reserved route acknowledged absent")
	}
}

func TestRuntimeAddressRoutesBindExactAssignedTunnel(t *testing.T) {
	e, d, k, x := runtimeProofFixture()
	address := e.Allocation.Tunnels[0].InsideAddress.Addr()
	local := KernelRoute{Kind: 2, RouteTuple: RouteTuple{Destination: netip.PrefixFrom(address, 32), Table: 255, Protocol: 2, OutputInterface: e.Observed[0].InterfaceIndex}, Scope: 254, PreferredSource: address}
	k.Routes = append(k.Routes, local)
	if runtimeInventoryMatches(e, d, k, x) != nil {
		t.Fatal("assigned local address route refused")
	}
	k.Routes[len(k.Routes)-1].PreferredSource = address.Next()
	if runtimeInventoryMatches(e, d, k, x) == nil {
		t.Fatal("foreign local address accepted")
	}
	k.Routes[len(k.Routes)-1] = local
	k.Routes[len(k.Routes)-1].OutputInterface = 900
	if runtimeInventoryMatches(e, d, k, x) != nil {
		t.Fatal("unrelated typed address observation confused with this ownership")
	}
	k.Routes[0].Kind = 2
	if runtimeInventoryMatches(e, d, k, x) == nil {
		t.Fatal("local route stood in for remote unicast")
	}
}
