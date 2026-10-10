package ipsec

import (
	"context"
	"net/netip"
	"reflect"
	"testing"
)

func bgpRouteWriterFixture(t *testing.T) (RuntimeJournalEntry, *recoveryKernelFixture, *RuntimeJournal) {
	t.Helper()
	return bgpRouteWriterEntryFixture(t, bgpEntryFixture(t))
}
func bgpRouteWriterEntryFixture(t *testing.T, e RuntimeJournalEntry) (RuntimeJournalEntry, *recoveryKernelFixture, *RuntimeJournal) {
	t.Helper()
	f := newRecoveryKernelFixture()
	f.p = e.Allocation
	for i, p := range f.p.Tunnels {
		f.owned[i] = Ownership{Namespace: f.p.Namespace, InterfaceName: p.Name, InterfaceIndex: 10 + i, XFRMID: p.XFRMID}
		f.routes[i] = map[string]bool{netip.PrefixFrom(p.BGP.Peer, 32).String(): true}
	}
	e.Observed = f.owned
	j, err := OpenRuntimeJournal(journalDir(t), e.Engines[0].Binding.GatewayID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { j.Close() })
	for _, phase := range []RuntimePhase{RuntimeReserved, RuntimeApplying, RuntimeApplied} {
		e.Phase = phase
		if err = j.Save([]RuntimeJournalEntry{e}); err != nil {
			t.Fatal(err)
		}
	}
	return e, f, j
}
func routeTupleFixture(e RuntimeJournalEntry, slot uint8) RuntimeBGPRouteTuple {
	return RuntimeBGPRouteTuple{Prefix: e.Allocation.Tunnels[0].RemotePrefixes[0], Slot: slot, InterfaceIndex: e.Observed[slot-1].InterfaceIndex, Table: 254, Protocol: 242, Metric: 50000 + uint32(slot)}
}
func TestBGPRoutesDurableOwnedWriter(t *testing.T) {
	e, f, j := bgpRouteWriterFixture(t)
	r := routeTupleFixture(e, 2)
	if err := ReconcileBGPRoutes(context.Background(), j, f.applier(), e.DeliveryID.String(), []RuntimeBGPRouteTuple{r}); err != nil {
		t.Fatal(err)
	}
	entries, _ := j.Entries()
	if entries[0].BGPRoutes.Stage != "completed" || !reflect.DeepEqual(entries[0].BGPRoutes.Owned, []RuntimeBGPRouteTuple{r}) || !f.routes[1][r.Prefix.String()] || f.routes[0][r.Prefix.String()] {
		t.Fatal("wrong owned best tuple")
	}
	if err := ReconcileBGPRoutes(context.Background(), j, f.applier(), e.DeliveryID.String(), nil); err != nil {
		t.Fatal(err)
	}
	if f.routes[1][r.Prefix.String()] {
		t.Fatal("withdrawal left owned route")
	}
}
func TestBGPRoutesForeignAndFailureRemainClosed(t *testing.T) {
	for _, foreign := range []bool{false, true} {
		t.Run(map[bool]string{false: "mutation-failure", true: "foreign-no-adoption"}[foreign], func(t *testing.T) {
			e, f, j := bgpRouteWriterFixture(t)
			r := routeTupleFixture(e, 1)
			if foreign {
				f.routes[0][r.Prefix.String()] = true
			} else {
				f.failAt = 1
			}
			err := ReconcileBGPRoutes(context.Background(), j, f.applier(), e.DeliveryID.String(), []RuntimeBGPRouteTuple{r})
			if err == nil {
				t.Fatal("failure accepted")
			}
			entries, _ := j.Entries()
			if foreign {
				if f.mutations != 0 || entries[0].BGPRoutes != nil {
					t.Fatal("foreign route adopted")
				}
			} else {
				if entries[0].BGPRoutes == nil || entries[0].BGPRoutes.Stage != "pending" {
					t.Fatal("cleanup obligation forgotten")
				}
			}
		})
	}
}

func TestBGPMoveFailurePreservesDurableUnion(t *testing.T) {
	e, f, j := bgpRouteWriterFixture(t)
	first := routeTupleFixture(e, 1)
	second := routeTupleFixture(e, 2)
	if err := ReconcileBGPRoutes(context.Background(), j, f.applier(), e.DeliveryID.String(), []RuntimeBGPRouteTuple{first}); err != nil {
		t.Fatal(err)
	}
	f.failAt = f.mutations + 2
	if err := ReconcileBGPRoutes(context.Background(), j, f.applier(), e.DeliveryID.String(), []RuntimeBGPRouteTuple{second}); err == nil {
		t.Fatal("failed move accepted")
	}
	if f.routes[0][first.Prefix.String()] || f.routes[1][first.Prefix.String()] {
		t.Fatal("unexpected route after failed add")
	}
	dir := j.dir
	j.Close()
	reopened, err := OpenRuntimeJournal(dir, e.Engines[0].Binding.GatewayID)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	entries, err := reopened.Entries()
	if err != nil {
		t.Fatal(err)
	}
	s := entries[0].BGPRoutes
	if s.Stage != "pending" || !reflect.DeepEqual(s.Owned, []RuntimeBGPRouteTuple{first}) || !reflect.DeepEqual(s.Target, []RuntimeBGPRouteTuple{second}) || len(bgpRouteUnion(s)) != 2 {
		t.Fatal("pending union lost across reopen")
	}
	for _, change := range []func(*RuntimeJournalEntry){func(e *RuntimeJournalEntry) { e.BGPRoutes.Sequence-- }, func(e *RuntimeJournalEntry) { e.BGPRoutes.Owned = []RuntimeBGPRouteTuple{} }, func(e *RuntimeJournalEntry) { e.BGPRoutes.Target = []RuntimeBGPRouteTuple{} }, func(e *RuntimeJournalEntry) { e.Observed[0].InterfaceIndex++ }} {
		modified, _ := reopened.Entries()
		change(&modified[0])
		if err = reopened.Save(modified); err == nil {
			t.Fatal("pending cleanup obligation rewritten")
		}
	}
}
func TestBGPFinalReadbackFailureRetainsIntent(t *testing.T) {
	e, f, j := bgpRouteWriterFixture(t)
	r := routeTupleFixture(e, 1)
	a := f.applier()
	base := a.run
	a.run = func(ctx context.Context, args ...string) ([]byte, error) {
		raw, err := base(ctx, args...)
		if f.mutations > 0 && len(args) > 3 && args[0] == "-j" && args[2] == "link" {
			return []byte(`[]`), nil
		}
		return raw, err
	}
	if err := ReconcileBGPRoutes(context.Background(), j, a, e.DeliveryID.String(), []RuntimeBGPRouteTuple{r}); err == nil {
		t.Fatal("unproved mutation accepted")
	}
	entries, _ := j.Entries()
	if entries[0].BGPRoutes.Stage != "pending" || !f.routes[0][r.Prefix.String()] {
		t.Fatal("installed duty forgotten on readback failure")
	}
}
func TestBGPJournalPerPeerLimitAllowsDisjointUnion(t *testing.T) {
	e := bgpEntryFixture(t)
	e.BGP.MaximumPrefixes = 1
	extra := netip.MustParsePrefix("10.30.0.0/24")
	for i := range e.Allocation.Tunnels {
		e.Allocation.Tunnels[i].RemotePrefixes = append(e.Allocation.Tunnels[i].RemotePrefixes, extra)
		e.Engines[i].RemotePrefixes = append(e.Engines[i].RemotePrefixes, extra)
		e.Observed[i] = Ownership{Namespace: e.Allocation.Namespace, InterfaceName: e.Allocation.Tunnels[i].Name, XFRMID: e.Allocation.Tunnels[i].XFRMID, InterfaceIndex: 10 + i}
	}
	first := routeTupleFixture(e, 1)
	second := routeTupleFixture(e, 2)
	second.Prefix = extra
	e.BGPRoutes = &RuntimeBGPRoutes{Sequence: 1, Stage: "pending", Owned: []RuntimeBGPRouteTuple{}, Target: []RuntimeBGPRouteTuple{first, second}}
	if !validBGPRoutes(e) {
		t.Fatal("approved disjoint union incorrectly restricted to per-peer limit")
	}
	e.BGPRoutes.Target = append(e.BGPRoutes.Target, RuntimeBGPRouteTuple{Prefix: netip.MustParsePrefix("10.40.0.0/24"), Slot: 2, InterfaceIndex: 11, Table: 254, Protocol: 242, Metric: 50002})
	if validBGPRoutes(e) {
		t.Fatal("unapproved prefix admitted")
	}
}
func TestBGPKnownLinkdownWithdrawsOnlyLostTuple(t *testing.T) {
	e, f, j := bgpRouteWriterFixture(t)
	first := routeTupleFixture(e, 1)
	second := routeTupleFixture(e, 2)
	if err := ReconcileBGPRoutes(context.Background(), j, f.applier(), e.DeliveryID.String(), []RuntimeBGPRouteTuple{first}); err != nil {
		t.Fatal(err)
	}
	f.down = 0
	if err := ReconcileBGPRoutes(context.Background(), j, f.applier(), e.DeliveryID.String(), []RuntimeBGPRouteTuple{second}); err != nil {
		t.Fatal("known lost link blocked healthy alternate", err)
	}
	if f.routes[0][first.Prefix.String()] || !f.routes[1][first.Prefix.String()] || f.down != 0 {
		t.Fatal("lost route retained, healthy alternate missing, or interface repaired")
	}
}
func TestBGPDownTargetCannotInstall(t *testing.T) {
	e, f, j := bgpRouteWriterFixture(t)
	f.down = 0
	r := routeTupleFixture(e, 1)
	before := f.mutations
	if err := ReconcileBGPRoutes(context.Background(), j, f.applier(), e.DeliveryID.String(), []RuntimeBGPRouteTuple{r}); err == nil {
		t.Fatal("lost interface installed new prefix")
	}
	if f.mutations != before || f.routes[0][r.Prefix.String()] {
		t.Fatal("lost target mutated")
	}
}
