package ipsec

import (
	"context"
	"github.com/google/uuid"
	bgpengine "github.com/tunnexio/tunnex/apps/node/internal/bgp"
	"net/netip"
	"strings"
	"testing"
	"time"
)

type bgpSessionFixture struct {
	alive                         func() bool
	observationError, routesError bool
	routes                        []bgpengine.LearnedRoute
	close                         func()
	closed                        bool
	status                        *bgpengine.Status
}

func (p *bgpSessionFixture) Alive() bool {
	if p.alive != nil {
		return p.alive()
	}
	return !p.closed
}
func (p *bgpSessionFixture) Close() error {
	p.closed = true
	if p.close != nil {
		p.close()
	}
	return nil
}
func (p *bgpSessionFixture) Observe(context.Context) (bgpengine.Status, error) {
	if p.observationError {
		return bgpengine.Status{}, ErrRuntimeController
	}
	if p.status != nil {
		return *p.status, nil
	}
	return bgpengine.Status{Peers: [2]bgpengine.PeerStatus{{Slot: 1, State: "established"}, {Slot: 2, State: "established"}}}, nil
}
func (p *bgpSessionFixture) ObserveRoutes(context.Context, bgpengine.Status) ([]bgpengine.LearnedRoute, error) {
	if p.routesError {
		return nil, ErrRuntimeController
	}
	return p.routes, nil
}
func bgpControllerFixture(t *testing.T, installed bool) (*RuntimeController, *recoveryKernelFixture, *bgpSessionFixture, *bool) {
	t.Helper()
	return bgpControllerEntryFixture(t, installed, bgpEntryFixture(t))
}
func bgpControllerEntryFixture(t *testing.T, installed bool, initial RuntimeJournalEntry) (*RuntimeController, *recoveryKernelFixture, *bgpSessionFixture, *bool) {
	t.Helper()
	e, f, j := bgpRouteWriterEntryFixture(t, initial)
	routes := []RuntimeBGPRouteTuple{}
	if installed {
		routes = append(routes, routeTupleFixture(e, 1))
	}
	if err := ReconcileBGPRoutes(context.Background(), j, f.applier(), e.DeliveryID.String(), routes); err != nil {
		t.Fatal(err)
	}
	entries, _ := j.Entries()
	e = entries[0]
	a := NewPermitLeaseAuthority()
	identity := PermitLeaseIdentity{DeliveryID: e.DeliveryID, Binding: e.Engines[0].Binding, PolicyHash: strings.Repeat("b", 64)}
	request, err := a.Begin(identity)
	if err != nil {
		t.Fatal(err)
	}
	if err = a.Accept(PermitLeaseResponse{PermitLeaseRequest: request, TTLMillis: 60000}); err != nil {
		t.Fatal(err)
	}
	denied := false
	p := &bgpSessionFixture{}
	p.close = func() {
		if !denied {
			t.Fatal("daemon close occurred before verified application denial")
		}
	}
	c := &RuntimeController{started: true, journal: j, kernel: f.applier(), qualification: testRuntimeQualification(e.Allocation.Namespace), namespace: func() (string, error) { return e.Allocation.Namespace, nil }, config: RuntimeControllerConfig{OrgID: e.Engines[0].Binding.OrgID, GatewayID: e.Engines[0].Binding.GatewayID, DaemonAlive: func() bool { return true }}, prove: func(context.Context, RuntimeJournalEntry, RuntimeEnvironment) error { return nil }, recoveryObserve: func(context.Context, RuntimeJournalEntry) [2]string { return [2]string{"up", "up"} }, bgpProcesses: map[uuid.UUID]runtimeBGPSession{e.DeliveryID: p}, active: map[uuid.UUID]runtimeActive{e.Allocation.ConnectionID: {Entry: e, Identity: identity, Authority: a, Environment: RuntimeEnvironment{Namespace: e.Allocation.Namespace, Underlays: [2]RuntimeUnderlay{{InterfaceIndex: 2, OuterMTU: 1500, LocalAddress: netip.MustParseAddr("192.0.2.1")}, {InterfaceIndex: 2, OuterMTU: 1500, LocalAddress: netip.MustParseAddr("192.0.2.1")}}}, Grants: []GuardGrant{{Source: netip.MustParsePrefix("10.10.0.0/24"), Destination: e.Allocation.Tunnels[0].RemotePrefixes[0], Protocol: GuardTCP, PortLow: 18080, PortHigh: 18080, HostOrigin: true}}}}}
	c.replace = func(_ context.Context, in GuardIntent) (GuardManifest, error) {
		for _, g := range in.Connections {
			if len(g.Grants) == 0 {
				denied = true
			}
		}
		return GuardManifest{}, nil
	}
	return c, f, p, &denied
}
func TestBGPControllerObservationErrorsWithdrawBeforeClose(t *testing.T) {
	for _, installed := range []bool{false, true} {
		for _, routeError := range []bool{false, true} {
			t.Run(strings.Join([]string{map[bool]string{false: "empty", true: "installed"}[installed], map[bool]string{false: "summary", true: "rib"}[routeError]}, "-"), func(t *testing.T) {
				c, f, p, denied := bgpControllerFixture(t, installed)
				p.routesError = routeError
				p.observationError = !routeError
				entries, _ := c.journal.Entries()
				prefix := entries[0].Allocation.Tunnels[0].RemotePrefixes[0].String()
				if err := c.reconcileActiveBGP(context.Background(), entries); err != nil {
					t.Fatal(err)
				}
				if !*denied || !p.closed || len(c.active) != 0 || f.routes[0][prefix] {
					t.Fatal("invalid observation retained grant, session or route")
				}
			})
		}
	}
}
func TestBGPControllerGuardWithdrawalFailureNeverMutates(t *testing.T) {
	c, f, p, _ := bgpControllerFixture(t, false)
	entries, _ := c.journal.Entries()
	p.routes = []bgpengine.LearnedRoute{{Prefix: entries[0].Allocation.Tunnels[0].RemotePrefixes[0], Slot: 1}}
	before := f.mutations
	c.replace = func(context.Context, GuardIntent) (GuardManifest, error) { return GuardManifest{}, ErrGuardReadback }
	if err := c.reconcileActiveBGP(context.Background(), entries); err == nil {
		t.Fatal("unproved denial accepted")
	}
	if f.mutations != before || len(c.active) != 0 {
		t.Fatal("mutation or grant restoration after denied guard failure")
	}
}

func TestBGPControllerPrefixLimitKeepsTrackedSession(t *testing.T) {
	c, f, p, denied := bgpControllerFixture(t, true)
	entries, _ := c.journal.Entries()
	original := entries[0]
	p.status = &bgpengine.Status{Peers: [2]bgpengine.PeerStatus{{Slot: 1, State: "idle"}, {Slot: 2, State: "idle"}}}
	for i := 0; i < 3; i++ {
		entries, _ = c.journal.Entries()
		if err := c.reconcileActiveBGP(context.Background(), entries); err != nil {
			t.Fatal(err)
		}
		latest, _ := c.journal.Entries()
		if p.closed || c.bgpProcesses[original.DeliveryID] != p || f.routes[0][original.Allocation.Tunnels[0].RemotePrefixes[0].String()] || len(latest[0].BGPRoutes.Owned) != 0 {
			t.Fatal("limit shutdown churned session or retained route")
		}
	}
	if !*denied {
		t.Fatal("old route authority withdrawn without guard denial")
	}
}

func TestBGPControllerHealthyTunnelGuardSurvivesOtherDown(t *testing.T) {
	for _, down := range []int{0, 1} {
		t.Run([]string{"slot1-down", "slot2-down"}[down], func(t *testing.T) {
			c, _, p, _ := bgpControllerFixture(t, false)
			entries, _ := c.journal.Entries()
			id := entries[0].Allocation.ConnectionID
			active := c.active[id]
			for i := range active.Entry.Engines {
				active.Entry.Engines[i].ReqID = active.Entry.Engines[i].XFRMID
			}
			c.active[id] = active
			c.recoveryObserve = func(context.Context, RuntimeJournalEntry) [2]string {
				states := [2]string{"up", "up"}
				states[down] = "down"
				return states
			}
			var rendered GuardManifest
			var g GuardConnection
			c.replace = func(_ context.Context, in GuardIntent) (GuardManifest, error) {
				var err error
				g = in.Connections[0]
				rendered, err = RenderGuard(in)
				return rendered, err
			}
			if err := c.installActive(context.Background(), entries); err != nil {
				t.Fatal(err)
			}
			if p.closed || len(c.active) != 1 {
				t.Fatal("healthy session authority discarded")
			}
			if len(g.PermittedInterfaceIndices) != 1 || g.PermittedInterfaceIndices[0] != active.Entry.Observed[1-down].InterfaceIndex || len(g.EncryptedEgress) != 1 || g.EncryptedEgress[0].ReqID != active.Entry.Engines[1-down].ReqID {
				t.Fatal("permit was not confined to healthy tunnel")
			}
			peer := active.Entry.Allocation.Tunnels[down].BGP.Peer.String()
			for _, line := range strings.Split(rendered.NFT, "\n") {
				if strings.Contains(line, peer) && strings.Contains(line, "counter accept") {
					t.Fatal("down peer gained control permit")
				}
			}
			if !strings.Contains(rendered.NFT, "ip daddr "+peer+"/32 counter drop") {
				t.Fatal("down peer denial lost")
			}
			for _, bad := range []int{-1, 99, active.Entry.Observed[down].InterfaceIndex} {
				invalid := g
				invalid.BGPPeers = append([]GuardBGPPeer(nil), g.BGPPeers...)
				for i := range invalid.BGPPeers {
					if invalid.BGPPeers[i].Remote.String() == peer {
						invalid.BGPPeers[i].InterfaceIndex = bad
					}
				}
				if _, err := RenderGuard(GuardIntent{Namespace: rendered.Namespace, OwnerID: rendered.OwnerID, Revision: rendered.Revision, Connections: []GuardConnection{invalid}}); err == nil {
					t.Fatal("foreign or unpermitted positive peer accepted", bad)
				}
			}
			c.recoveryObserve = func(context.Context, RuntimeJournalEntry) [2]string { return [2]string{"up", "unknown"} }
			if _, err := c.bgpGuard(context.Background(), active, 30*time.Second); err == nil {
				t.Fatal("unknown child granted authority")
			}

		})
	}
}
