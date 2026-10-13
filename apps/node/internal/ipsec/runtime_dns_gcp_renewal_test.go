package ipsec

import (
	"context"
	"net/netip"
	"testing"
)

// Provider-shaped contracts and real guard parser; independent native inventories
// are modeled by the existing owner-view fixture. This is not cloud packet proof.
func TestDNSOwnerGCPBenignGuardRenewal(t *testing.T) {
	for _, profile := range []string{GCPClassicStaticProfile, GCPHABGPProfile} {
		t.Run(profile, func(t *testing.T) {
			for _, phase := range []string{"initial", "final", "churn", "withdraw", "grants", "budget", "cancel", "lease", "native"} {
				t.Run(phase, func(t *testing.T) {
					m := classicMaterialFixture()
					if profile == GCPHABGPProfile {
						m = gcpMaterialFixture()
					}
					m.Policy.DNSResolverGrants = dnsMaterialFixture().Policy.DNSResolverGrants
					m.Policy.DNSResolverGrants[0].ConnectionID = m.Manifest.ConnectionID
					m.Policy.DNSResolverGrants[0].ConfigurationRevision = m.Manifest.ConfigurationRevision
					f := newDNSOwnerProfileFixture(t, m, nil)
					if profile == GCPHABGPProfile {
						a := f.c.active[m.Manifest.ConnectionID]
						tuple := routeTupleFixture(a.Entry, 1)
						a.Entry.BGPRoutes = &RuntimeBGPRoutes{Sequence: 1, Stage: "completed", Owned: []RuntimeBGPRouteTuple{tuple}, Target: []RuntimeBGPRouteTuple{tuple}}
						f.c.active[m.Manifest.ConnectionID] = a
						f.publish(t)
					}
					if _, err := f.prove(context.Background()); err != nil {
						t.Fatalf("baseline provider proof refused %v slot=%d classic=%v guard=%d native=%d source=%d", err, selectedRuntimeSlot(f.c.active[m.Manifest.ConnectionID].Entry), validClassicJournal(f.c.active[m.Manifest.ConnectionID].Entry), f.guardReads.Load(), f.nativeProofs.Load(), f.sourceReads.Load())
					}
					f.sourceReads.Store(0)
					renew := func() {
						a := f.c.active[m.Manifest.ConnectionID]
						i := guardFixture()
						i.OwnerID = m.Manifest.NodeID
						i.Revision = f.manifest.Revision + 1
						i.Connections[0].ID = m.Manifest.ConnectionID
						i.Connections[0].Tunnels = a.Entry.Observed
						if a.Entry.Allocation.activeTunnelCount() == 1 {
							i.Connections[0].TunnelCount = 1
						}
						i.Connections[0].Grants = a.Grants
						i.Connections[0].ReplyIngressIndices = []int{10}
						i.Connections[0].EncryptedEgress = []GuardEncryptedEgress{{TunnelInterfaceIndex: 10, ReqID: a.Entry.Engines[0].ReqID, Peer: a.Entry.Engines[0].RemoteAddress, UnderlayInterfaceIndex: 2}}
						var err error
						f.manifest, err = RenderGuard(i)
						if err != nil {
							t.Fatal(err)
						}
						f.observed.Store(f.manifest.ExpectedJSON)
						f.publish(t)
					}
					reader := f.c.guard.reader
					original := reader.run
					calls := 0
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					reader.run = func(ctx context.Context, args ...string) ([]byte, error) {
						calls++
						if phase != "final" && calls == 1 || phase == "final" && calls == 2 || phase == "churn" && calls == 2 || phase == "budget" && calls == 3 {
							renew()
						}
						if calls == 1 {
							switch phase {
							case "withdraw":
								f.c.withdrawDNSOwnerView(m.Manifest.ConnectionID)
							case "grants":
								a := f.c.active[m.Manifest.ConnectionID]
								a.Grants = nil
								f.c.active[m.Manifest.ConnectionID] = a
								f.c.reconcileDNSOwnerView()
							case "cancel":
								cancel()
							case "lease":
								f.c.active[m.Manifest.ConnectionID].Authority.Invalidate()
							case "native":
								f.observed.Store(`{"nftables":[]}`)
							}
						}
						return original(ctx, args...)
					}
					if phase == "final" || phase == "budget" {
						v := f.c.dnsView.Load()
						copyV := *v
						source := copyV.observer.source
						copyV.observer.source = func(addr netip.Addr, indices []int) (int, error) {
							if f.sourceReads.Load() == 0 {
								renew()
							}
							return source(addr, indices)
						}
						f.c.dnsView.Store(&copyV)
					}
					_, err := f.prove(ctx)
					if phase != "initial" && phase != "final" {
						if err == nil {
							t.Fatal("unsafe renewal accepted", phase)
						}
						return
					}
					if err != nil {
						t.Fatal("benign committed guard renewal refused", err)
					}

					if calls < 2 || calls > 3 {
						t.Fatalf("unbounded or absent full guard revalidation: %d", calls)
					}
				})
			}
		})
	}
}
