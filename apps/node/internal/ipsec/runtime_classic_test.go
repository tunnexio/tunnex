package ipsec

import (
	"context"
	"github.com/google/uuid"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func classicEntryFixture(t *testing.T) RuntimeJournalEntry {
	t.Helper()
	m := classicMaterialFixture()
	e, _, err := runtimeMaterialEntry(m, m.Manifest.OrgID, m.Manifest.NodeID, "net:[4026531992]")
	if err != nil {
		t.Fatal(err)
	}
	return e
}
func classicProofFixture(t *testing.T) (RuntimeJournalEntry, DaemonInventory, KernelInventory, XFRMInventory) {
	e := classicEntryFixture(t)
	engine := e.Engines[0]
	own := Ownership{Namespace: e.Allocation.Namespace, InterfaceName: e.Allocation.Tunnels[0].Name, InterfaceIndex: 10, XFRMID: engine.XFRMID}
	e.Observed[0] = own
	k := KernelInventory{Namespace: e.Allocation.Namespace, Links: []KernelLink{{Name: own.InterfaceName, Index: 10, XFRMID: own.XFRMID, Up: true}}}
	child := DaemonChild{Name: engineName(engine), UniqueID: 1, ReqID: engine.ReqID, IfIDIn: engine.XFRMID, IfIDOut: engine.XFRMID, SPIIn: 100, SPIOut: 200, Installed: true, LocalPrefixes: engineTransportPrefixes(engine, true), RemotePrefixes: engineTransportPrefixes(engine, false)}
	d := DaemonInventory{SAs: []DaemonIKE{{Name: engineName(engine), UniqueID: 1, Established: true, LocalAddress: engine.LocalAddress, RemoteAddress: engine.RemoteAddress, Children: []DaemonChild{child}}}}
	x := XFRMInventory{Namespace: e.Allocation.Namespace, States: []XFRMState{{Source: engine.LocalAddress, Destination: engine.RemoteAddress, SPI: 200, ReqID: engine.ReqID, IfID: engine.XFRMID}, {Source: engine.RemoteAddress, Destination: engine.LocalAddress, SPI: 100, ReqID: engine.ReqID, IfID: engine.XFRMID}}}
	all := netip.MustParsePrefix("0.0.0.0/0")
	for _, dir := range []string{"in", "fwd", "out"} {
		p := XFRMPolicy{Source: all, Destination: all, Direction: dir, ReqID: engine.ReqID, IfID: engine.XFRMID, TemplateSource: engine.RemoteAddress, TemplateDestination: engine.LocalAddress}
		if dir == "out" {
			p.TemplateSource, p.TemplateDestination = engine.LocalAddress, engine.RemoteAddress
		}
		x.Policies = append(x.Policies, p)
	}
	for _, r := range engine.RemotePrefixes {
		k.Routes = append(k.Routes, KernelRoute{Kind: 1, RouteTuple: RouteTuple{Destination: r, Table: 254, Protocol: 242, Metric: 50001, OutputInterface: 10}})
	}
	address := e.Allocation.Tunnels[0].InsideAddress.Addr()
	k.Routes = append(k.Routes, KernelRoute{Kind: 2, RouteTuple: RouteTuple{Destination: netip.PrefixFrom(address, 32), Table: 255, Protocol: 2, OutputInterface: 10}, Scope: 254, PreferredSource: address})
	return e, d, k, x
}
func TestClassicProofRequiresActualSingleTunnel(t *testing.T) {
	e, d, k, x := classicProofFixture(t)
	if selectedRuntimeSlot(e) != 1 || runtimeInventoryMatches(e, d, k, x) != nil {
		t.Fatal("single tunnel proof refused")
	}
	if got := runtimeTunnelStatuses(e, d, k, x); got != ([2]string{"up", "unknown"}) {
		t.Fatal("fabricated inactive observation", got)
	}
	if runtimeInventoryMatches(e, DaemonInventory{}, k, x) == nil {
		t.Fatal("applied intent substituted for actual SA")
	}
	k.Routes = k.Routes[1:]
	if runtimeInventoryMatches(e, d, k, x) == nil {
		t.Fatal("missing remote route accepted")
	}
	e, d, k, x = classicProofFixture(t)
	x.States[0].SPI++
	if runtimeInventoryMatches(e, d, k, x) == nil {
		t.Fatal("foreign SPI accepted")
	}
}
func TestClassicJournalLifecycleAndInactiveRefusal(t *testing.T) {
	e := classicEntryFixture(t)
	owner := e.Engines[0].Binding.GatewayID
	if validJournalPayload(runtimeJournalPayload{Version: 9, OwnerID: owner, Entries: []RuntimeJournalEntry{e}}) {
		t.Fatal("legacy journal accepted Classic")
	}
	j, err := OpenRuntimeJournal(journalDir(t), owner)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	if err = j.Save([]RuntimeJournalEntry{e}); err != nil {
		t.Fatal("reserve", err)
	}
	e.Phase = RuntimeApplying
	if err = j.Save([]RuntimeJournalEntry{e}); err != nil {
		t.Fatal("applying", err)
	}
	e.Phase = RuntimeApplied
	if err = j.Save([]RuntimeJournalEntry{e}); err != nil {
		t.Fatal("applied", err)
	}
	e.CleanupID = uuid.New()
	e.CleanupDesiredRevision = e.Engines[0].Binding.DesiredRevision + 1
	e.CoveredDeliveryRevision = e.Engines[0].Binding.DesiredRevision
	e.Phase = RuntimeCleanupPending
	if err = j.Save([]RuntimeJournalEntry{e}); err != nil {
		t.Fatal("cleanup", err)
	}
	e.Phase = RuntimeRetainedRefusal
	if err = j.Save([]RuntimeJournalEntry{e}); err != nil {
		t.Fatal("retained refusal", err)
	}
	for name, mutate := range map[string]func(*RuntimeJournalEntry){"engine": func(e *RuntimeJournalEntry) { e.Engines[1] = e.Engines[0] }, "ownership": func(e *RuntimeJournalEntry) { e.Observed[1].InterfaceIndex = 42 }, "allocation": func(e *RuntimeJournalEntry) { e.Allocation.Tunnels[1] = e.Allocation.Tunnels[0] }, "contract": func(e *RuntimeJournalEntry) { e.ContractVersion = 0 }, "cloud address": func(e *RuntimeJournalEntry) {
		e.Allocation.Tunnels[0].InsideAddress = netip.MustParsePrefix("169.254.1.1/30")
	}} {
		t.Run(name, func(t *testing.T) {
			bad := e
			mutate(&bad)
			if validJournalPayload(runtimeJournalPayload{Version: 10, OwnerID: owner, Entries: []RuntimeJournalEntry{bad}}) {
				t.Fatal("inactive or mixed tuple accepted")
			}
		})
	}
}
func TestClassicGuardMaintainsGrantAndSpoofBoundaries(t *testing.T) {
	e, _, _, _ := classicProofFixture(t)
	g := GuardConnection{TunnelCount: 1, ID: e.Allocation.ConnectionID, Local: e.Engines[0].LocalPrefixes, Remote: e.Engines[0].RemotePrefixes, Tunnels: e.Observed, LocalIngressIndices: []int{2}, PermittedInterfaceIndices: []int{10}, ReplyIngressIndices: []int{10}, PermitFor: 30 * time.Second, EncryptedEgress: []GuardEncryptedEgress{{TunnelInterfaceIndex: 10, ReqID: e.Engines[0].ReqID, Peer: e.Engines[0].RemoteAddress, UnderlayInterfaceIndex: 2}}, TunnelMTUs: []GuardTunnelMTU{{InterfaceIndex: 10, MTU: 1382}}, Grants: []GuardGrant{{Source: e.Engines[0].LocalPrefixes[0], Destination: e.Engines[0].RemotePrefixes[0], Protocol: GuardTCP, PortLow: 443, PortHigh: 443}}}
	intent := GuardIntent{Namespace: e.Allocation.Namespace, OwnerID: e.Engines[0].Binding.GatewayID, Revision: 1, Connections: []GuardConnection{g}}
	manifest, err := RenderGuard(intent)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(manifest.NFT, "meta oif 0") || strings.Contains(manifest.NFT, "meta iif 0") || !strings.Contains(manifest.NFT, "counter drop") || !strings.Contains(manifest.NFT, "443") {
		t.Fatal("single guard missing boundaries")
	}
	intent.Connections[0].Tunnels[1] = e.Observed[0]
	if _, err = RenderGuard(intent); err == nil {
		t.Fatal("hidden inactive interface accepted")
	}
}
func TestClassicLeaseExpiryKeepsPermanentRefusal(t *testing.T) {
	e, _, _, _ := classicProofFixture(t)
	e.Phase = RuntimeReserved
	j, err := OpenRuntimeJournal(journalDir(t), e.Engines[0].Binding.GatewayID)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	if err = j.Save([]RuntimeJournalEntry{e}); err != nil {
		t.Fatal(err)
	}
	e.Phase = RuntimeApplying
	if err = j.Save([]RuntimeJournalEntry{e}); err != nil {
		t.Fatal(err)
	}
	e.Phase = RuntimeApplied
	if err = j.Save([]RuntimeJournalEntry{e}); err != nil {
		t.Fatal(err)
	}
	authority := NewPermitLeaseAuthority()
	elapsed := time.Duration(0)
	authority.elapsed = func() time.Duration { return elapsed }
	identity := PermitLeaseIdentity{DeliveryID: e.DeliveryID, Binding: e.Engines[0].Binding, PolicyHash: strings.Repeat("b", 64)}
	identity.Binding.PolicyRevision = 0
	r, err := authority.Begin(identity)
	if err != nil {
		t.Fatal(err)
	}
	if err = authority.Accept(PermitLeaseResponse{PermitLeaseRequest: r, TTLMillis: 60000}); err != nil {
		t.Fatal(err)
	}
	var captured []GuardIntent
	c := &RuntimeController{config: RuntimeControllerConfig{GatewayID: e.Engines[0].Binding.GatewayID, OrgID: e.Engines[0].Binding.OrgID, DaemonAlive: func() bool { return true }}, journal: j, namespace: func() (string, error) { return e.Allocation.Namespace, nil }, prove: func(context.Context, RuntimeJournalEntry, RuntimeEnvironment) error { return nil }, qualification: testRuntimeQualification(e.Allocation.Namespace), replace: func(_ context.Context, g GuardIntent) (GuardManifest, error) {
		captured = append(captured, g)
		return RenderGuard(g)
	}, active: map[uuid.UUID]runtimeActive{e.Allocation.ConnectionID: {Entry: e, Identity: identity, Authority: authority, Environment: RuntimeEnvironment{Namespace: e.Allocation.Namespace, LocalIngressIndices: []int{2}, Underlays: [2]RuntimeUnderlay{{InterfaceIndex: 2, LocalAddress: e.Engines[0].LocalAddress, OuterMTU: 1500}}}}}}
	c.recoveryObserve = func(context.Context, RuntimeJournalEntry) [2]string { return [2]string{"up", "unknown"} }
	elapsed = 10 * time.Second
	if err = c.installActive(context.Background(), []RuntimeJournalEntry{e}); err != nil {
		t.Fatal(err)
	}
	if captured[0].Connections[0].TunnelCount != 1 || captured[0].Connections[0].PermitFor != 45*time.Second {
		t.Fatal("single permit requires nonexistent peer or extends lease")
	}
	elapsed = 60 * time.Second
	if err = c.installActive(context.Background(), []RuntimeJournalEntry{e}); err != nil {
		t.Fatal(err)
	}
	if !captured[1].Connections[0].PrefixOnly || len(c.active) != 0 {
		t.Fatal("expiry retained authority")
	}
}
func TestClassicStatusDoesNotInventInactiveTunnel(t *testing.T) {
	m := classicMaterialFixture()
	report, err := (*RuntimeController)(nil).ObserveIPsecStatus(context.Background(), m.RuntimeDelivery)
	if err != nil || report.TransportVersion == nil || report.TunnelCount == nil || report.Tunnels[0].Status != "unknown" || report.Tunnels[1] != (RuntimeTunnelStatus{}) {
		t.Fatal("honest single-slot status refused", err)
	}
}
