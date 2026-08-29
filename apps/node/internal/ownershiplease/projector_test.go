package ownershiplease

import (
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/tunnexio/tunnex/apps/node/internal/fqdnrpc"
	"github.com/tunnexio/tunnex/apps/node/internal/nodepolicy"
	"github.com/tunnexio/tunnex/apps/node/internal/reconcile"
)

const (
	projectorPeerA = "qz/uIHKyeTmf08TjUpwbMLlBr78PS+fKYl33OGdZU+M="
	projectorPeerB = "ZzN444nzLsFjGeLNmSE9lzuvLAWI7mGMU2Z3fLroWnc="
)

func TestProjectorPreservesV9BaseAndAddsOnlyServingOwnership(t *testing.T) {
	base := projectorBase()
	wantBase := cloneDesiredState(base)
	p := NewProjector()
	if err := p.UpdateBase(base); err != nil {
		t.Fatal(err)
	}
	// Retained caller memory cannot rewrite the stored baseline.
	base.Peers[0].AllowedIPs[0] = "192.0.2.1/32"
	base.Policy.Allow[0].DstCIDR = "192.0.2.0/24"
	base.Policy.FQDNGenerations[0].Answers[0] = "192.0.2.9/32"
	base.DNSResolveRequest.ResolverEndpoints[0].Address = "192.0.2.53"

	if err := p.SetOwnership(projectorOwnership()); err != nil {
		t.Fatal(err)
	}
	got, found, err := p.Snapshot()
	if err != nil || !found {
		t.Fatalf("effective snapshot found=%v err=%v", found, err)
	}
	if got.Version != wantBase.Version || got.ProtocolVersion != wantBase.ProtocolVersion || got.NodeID != wantBase.NodeID ||
		!reflect.DeepEqual(got.Policy.Allow, wantBase.Policy.Allow) || !reflect.DeepEqual(got.Policy.Subjects, wantBase.Policy.Subjects) ||
		!reflect.DeepEqual(got.Policy.FQDNGenerations, wantBase.Policy.FQDNGenerations) || !reflect.DeepEqual(got.Policy.DNSForwards, wantBase.Policy.DNSForwards) ||
		!reflect.DeepEqual(got.Policy.LocalSubnets, wantBase.Policy.LocalSubnets) || got.Policy.PoolCIDR != wantBase.Policy.PoolCIDR ||
		!reflect.DeepEqual(got.OVPNClients, wantBase.OVPNClients) || !reflect.DeepEqual(got.OVPNServer, wantBase.OVPNServer) ||
		!reflect.DeepEqual(got.DNSResolveRequest, wantBase.DNSResolveRequest) {
		t.Fatalf("ordinary S21/v9 desired state changed: got=%+v want=%+v", got, wantBase)
	}
	if len(got.Peers) != 2 || !reflect.DeepEqual(got.Peers[0].AllowedIPs, []string{"10.99.0.2/32", "10.44.0.0/16", "100.64.0.2/32"}) ||
		!reflect.DeepEqual(got.Peers[1], wantBase.Peers[1]) {
		t.Fatalf("peer-specific ownership was not projected exactly: %+v", got.Peers)
	}
	if len(got.Policy.Routes) != 3 || got.Policy.Routes[0].DstCIDR != "172.16.0.0/16" ||
		len(got.Policy.VIPMappings) != 2 || got.Policy.VIPMappings[0].ServiceID != "77777777-7777-7777-7777-777777777777" ||
		len(got.Policy.K8sDNSZones) != 2 || got.Policy.K8sDNSZones[0].Zone != "site.example" {
		t.Fatalf("ownership union lost base or overlay state: %+v", got.Policy)
	}

	// Returned slices and pointers are snapshots, not handles into projector state.
	got.Peers[0].AllowedIPs[0] = "198.51.100.1/32"
	got.Policy.FQDNGenerations[0].Answers[0] = "198.51.100.2/32"
	again, _, err := p.Snapshot()
	if err != nil || again.Peers[0].AllowedIPs[0] != "10.99.0.2/32" || again.Policy.FQDNGenerations[0].Answers[0] != "8.8.8.8/32" {
		t.Fatalf("snapshot mutation escaped into projector: state=%+v err=%v", again, err)
	}
}

func TestProjectorWithdrawalRevealsNewestBaseWithoutGlobalClear(t *testing.T) {
	p := NewProjector()
	base := projectorBase()
	if err := p.UpdateBase(base); err != nil {
		t.Fatal(err)
	}
	if err := p.SetOwnership(projectorOwnership()); err != nil {
		t.Fatal(err)
	}
	newest := projectorBase()
	newest.Version = 99
	newest.Policy.Allow[0].RuleID = "newest-rule"
	newest.Policy.DNSForwards[0].ResolverIP = "10.0.0.54"
	if err := p.UpdateBase(newest); err != nil {
		t.Fatal(err)
	}
	if err := p.SetOwnership(EffectiveOwnership{}); err != nil {
		t.Fatal(err)
	}
	got, found, err := p.Snapshot()
	if err != nil || !found || !reflect.DeepEqual(got, newest) {
		t.Fatalf("withdrawal must reveal latest ordinary base: found=%v err=%v got=%+v want=%+v", found, err, got, newest)
	}
}

func TestProjectorKeepsNewestConflictingBaseForFailClosedWithdrawal(t *testing.T) {
	p := NewProjector()
	if err := p.UpdateBase(projectorBase()); err != nil {
		t.Fatal(err)
	}
	if err := p.SetOwnership(projectorOwnership()); err != nil {
		t.Fatal(err)
	}
	newest := projectorBase()
	newest.Version = 100
	newest.Policy.Routes = append(newest.Policy.Routes, nodepolicy.Route{DstCIDR: "10.44.1.0/24"})
	if err := p.UpdateBase(newest); !errors.Is(err, ErrOwnershipCollision) {
		t.Fatalf("conflicting newest base err=%v", err)
	}
	if _, found, err := p.Snapshot(); !found || !errors.Is(err, ErrOwnershipCollision) {
		t.Fatalf("active conflict must remain visible: found=%v err=%v", found, err)
	}
	if err := p.SetOwnership(EffectiveOwnership{}); err != nil {
		t.Fatal(err)
	}
	got, found, err := p.Snapshot()
	if err != nil || !found || !reflect.DeepEqual(got, newest) {
		t.Fatalf("withdrawal did not reveal newest conflicting base: found=%v err=%v got=%+v", found, err, got)
	}
}

func TestProjectorRejectsMissingPeerAndOwnershipCollisions(t *testing.T) {
	tests := map[string]func(*reconcile.DesiredState, *EffectiveOwnership){
		"missing exact peer": func(_ *reconcile.DesiredState, own *EffectiveOwnership) {
			own.WGPeers[0].PublicKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
		},
		"base peer prefix": func(base *reconcile.DesiredState, _ *EffectiveOwnership) {
			base.Peers[1].AllowedIPs = []string{"10.44.1.0/24"}
		},
		"base route prefix": func(base *reconcile.DesiredState, _ *EffectiveOwnership) {
			base.Policy.Routes = append(base.Policy.Routes, nodepolicy.Route{DstCIDR: "10.44.1.0/24"})
		},
		"owned route prefix": func(_ *reconcile.DesiredState, own *EffectiveOwnership) {
			own.Routes = append(own.Routes, "10.44.1.0/24")
		},
		"service ID": func(base *reconcile.DesiredState, own *EffectiveOwnership) {
			base.Policy.VIPMappings[0].ServiceID = own.VIPMappings[0].ServiceID
		},
		"VIP": func(base *reconcile.DesiredState, own *EffectiveOwnership) {
			base.Policy.VIPMappings[0].VIP = own.VIPMappings[0].VIP
		},
		"DNS name": func(base *reconcile.DesiredState, own *EffectiveOwnership) {
			base.Policy.VIPMappings[0].DNSName = own.VIPMappings[0].DNSName
		},
		"DNS listen VIP": func(base *reconcile.DesiredState, own *EffectiveOwnership) {
			base.Policy.K8sDNSZones[0].ListenVIP = own.DNSZones[0].ListenVIP
		},
		"DNS zone": func(base *reconcile.DesiredState, own *EffectiveOwnership) {
			base.Policy.K8sDNSZones[0].Zone = own.DNSZones[0].Zone
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			base, own := projectorBase(), projectorOwnership()
			mutate(&base, &own)
			p := NewProjector()
			if err := p.UpdateBase(base); err != nil {
				t.Fatal(err)
			}
			err := p.SetOwnership(own)
			if name == "missing exact peer" {
				if !errors.Is(err, ErrOwnershipPeerMissing) {
					t.Fatalf("missing peer err=%v", err)
				}
			} else if !errors.Is(err, ErrOwnershipCollision) {
				t.Fatalf("collision err=%v", err)
			}
			got, found, snapshotErr := p.Snapshot()
			if snapshotErr != nil || !found || !reflect.DeepEqual(got, base) {
				t.Fatalf("rejected overlay changed base: found=%v err=%v got=%+v", found, snapshotErr, got)
			}
		})
	}
}

func TestProjectorRejectsOverlappingOwnedPeerPrefixesAndKeepsPriorLease(t *testing.T) {
	p := NewProjector()
	if err := p.UpdateBase(projectorBase()); err != nil {
		t.Fatal(err)
	}
	good := projectorOwnership()
	if err := p.SetOwnership(good); err != nil {
		t.Fatal(err)
	}
	bad := cloneEffective(good)
	bad.WGPeers = append(bad.WGPeers, WGPeerOwnership{PublicKey: projectorPeerB, AllowedIPs: []string{"10.44.1.0/24"}})
	if err := p.SetOwnership(bad); !errors.Is(err, ErrOwnershipCollision) {
		t.Fatalf("overlapping owned prefixes err=%v", err)
	}
	got, _, err := p.Snapshot()
	if err != nil || len(got.Peers[1].AllowedIPs) != 1 || len(got.Peers[0].AllowedIPs) != 3 {
		t.Fatalf("failed candidate replaced prior active lease: state=%+v err=%v", got, err)
	}
}

func TestProjectorRequiresBaseAndPolicyBeforeServing(t *testing.T) {
	p := NewProjector()
	if _, found, err := p.Snapshot(); err != nil || found {
		t.Fatalf("empty projector found=%v err=%v", found, err)
	}
	if err := p.SetOwnership(projectorOwnership()); !errors.Is(err, ErrBaseDesiredUnavailable) {
		t.Fatalf("ownership without base err=%v", err)
	}
	base := projectorBase()
	base.Policy = nil
	if err := p.UpdateBase(base); err != nil {
		t.Fatal(err)
	}
	if err := p.SetOwnership(projectorOwnership()); !errors.Is(err, ErrBasePolicyUnavailable) {
		t.Fatalf("ownership without policy err=%v", err)
	}
}

func TestProjectorConcurrentSnapshotsAreRaceSafe(t *testing.T) {
	p := NewProjector()
	if err := p.UpdateBase(projectorBase()); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 96)
	for worker := 0; worker < 6; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < 16; i++ {
				switch worker % 3 {
				case 0:
					base := projectorBase()
					base.Version = uint64(i + 1)
					errs <- p.UpdateBase(base)
				case 1:
					_, _, err := p.Snapshot()
					errs <- err
				case 2:
					if i%2 == 0 {
						errs <- p.SetOwnership(projectorOwnership())
					} else {
						errs <- p.SetOwnership(EffectiveOwnership{})
					}
				}
			}
		}(worker)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
}

func projectorBase() reconcile.DesiredState {
	revision := int64(41)
	return reconcile.DesiredState{
		ProtocolVersion: 9, NodeID: "99999999-9999-9999-9999-999999999999", InterfaceAddress: "10.99.0.1/24", MTU: 1380, ListenPort: 51820, Version: 17,
		Peers: []reconcile.Peer{
			{PublicKey: projectorPeerA, AllowedIPs: []string{"10.99.0.2/32"}, Endpoint: "198.51.100.1:51820", SiteLink: true, PersistentKeepalive: 25},
			{PublicKey: projectorPeerB, AllowedIPs: []string{"10.99.0.3/32"}, Endpoint: "198.51.100.2:51820"},
		},
		Policy: &nodepolicy.Compiled{
			Version: 9, NodeID: "99999999-9999-9999-9999-999999999999", Mode: nodepolicy.ModeEnforcing,
			Allow:    []nodepolicy.AllowEntry{{SrcIP: "10.99.0.2/32", DstCIDR: "8.8.8.8/32", Protocol: "tcp", PortLow: 443, PortHigh: 443, RuleID: "normal-rule", SrcDeviceID: "device-a", FQDNManaged: true}},
			Subjects: []nodepolicy.SubjectAttribution{{SrcIP: "10.99.0.2", DeviceID: "device-a", Kind: "agent", ConfigRevision: &revision}},
			Routes:   []nodepolicy.Route{{DstCIDR: "172.16.0.0/16"}}, LocalSubnets: []string{"192.168.1.0/24"},
			DNSForwards: []nodepolicy.DNSForward{{Domain: "corp.example", ResolverIP: "10.0.0.53"}}, PoolCIDR: "10.99.0.0/24",
			VIPMappings:     []nodepolicy.VIPMapping{{ServiceID: "77777777-7777-7777-7777-777777777777", VIP: "100.64.1.10", Namespace: "legacy", Service: "web", ServiceCIDR: "10.97.0.0/16", Protocol: "tcp", PortLow: 80, PortHigh: 80, DNSName: "web.legacy.svc.site.example"}},
			K8sDNSZones:     []nodepolicy.K8sDNSZone{{ListenVIP: "100.64.1.2", Zone: "site.example"}},
			FQDNGenerations: []nodepolicy.FQDNGeneration{{ResourceID: "resource-a", Name: "api.example.com", Generation: "g1", Answers: []string{"8.8.8.8/32"}}},
		},
		OVPNEnabled: true, OVPNClients: []reconcile.OVPNClient{{CommonName: "alice", IP: "10.99.0.20", FullTunnel: true}},
		OVPNServer:        &reconcile.OVPNServerMaterial{CA: "ca", Cert: "cert", Key: "key", CRL: "crl"},
		DNSResolveRequest: &fqdnrpc.Request{Version: 1, RequestID: "request-a", OrgID: "org-a", ResourceID: "resource-a", SiteID: "site-a", GatewayID: "gateway-a", Hostname: "api.example.com", RecordTypes: []fqdnrpc.RecordType{fqdnrpc.RecordA}, Deadline: time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC), ResolverConfigID: "resolver-a", ResolverConfigVersion: 3, ResolverEndpoints: []fqdnrpc.ResolverEndpoint{{Address: "10.0.0.53", Port: 53, Transport: "udp"}}},
	}
}

func projectorOwnership() EffectiveOwnership {
	return EffectiveOwnership{
		OrgID: "11111111-1111-1111-1111-111111111111", SiteID: "22222222-2222-2222-2222-222222222222",
		ClusterID: "33333333-3333-3333-3333-333333333333", PoolID: "44444444-4444-4444-4444-444444444444",
		ConnectorNodeID: "55555555-5555-5555-5555-555555555555", ManifestIdentity: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		PromotionGeneration: 4, ManifestRevision: 9, LeaseEpoch: 7,
		Routes:      []string{"10.44.0.0/16", "100.64.0.2/32"},
		WGPeers:     []WGPeerOwnership{{PublicKey: projectorPeerA, AllowedIPs: []string{"10.44.0.0/16", "100.64.0.2/32"}}},
		VIPMappings: []nodepolicy.VIPMapping{{ServiceID: "66666666-6666-6666-6666-666666666666", VIP: "100.64.0.10", Namespace: "default", Service: "api", ServiceCIDR: "10.96.0.0/12", Protocol: "tcp", PortLow: 443, PortHigh: 443, DNSName: "api.default.svc.cluster.example"}},
		DNSZones:    []nodepolicy.K8sDNSZone{{ListenVIP: "100.64.0.2", Zone: "cluster.example"}},
	}
}
