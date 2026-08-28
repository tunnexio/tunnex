package ownershiplease

import (
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/tunnexio/tunnex/apps/node/internal/control"
	"github.com/tunnexio/tunnex/apps/node/internal/nodepolicy"
)

func TestV3DeliveryAdapterServingPreparedAndWithdrawal(t *testing.T) {
	now := time.Date(2026, 8, 28, 10, 0, 0, 0, time.UTC)
	tests := []struct {
		name    string
		role    string
		serving bool
	}{
		{name: "serving", role: nodepolicy.PoolVIPOwnershipServing, serving: true},
		{name: "prepared non-serving", role: nodepolicy.PoolVIPOwnershipPreparedNonServing},
		{name: "withdrawal", role: nodepolicy.PoolVIPOwnershipWithdrawal},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			domain := &fakeDomainSurface{}
			coordinator := newTestCoordinator(t, filepath.Join(t.TempDir(), "fences.json"), domain)
			if err := coordinator.UpdateBase(t.Context(), projectorBase(), BaseAuthority{}); err != nil {
				t.Fatal(err)
			}
			stateStore := NewFileStateStore(filepath.Join(t.TempDir(), "ownership.json"))
			lifecycle := lifecycleAt(t, coordinator, stateStore, &now)
			adapter, err := NewV3DeliveryAdapter(lifecycle, coordinator)
			if err != nil {
				t.Fatal(err)
			}
			envelope := v3AdapterEnvelope(t, tc.role, now)
			if err := adapter.ApplyPoolVIPOwnershipV3(t.Context(), envelope); err != nil {
				t.Fatal(err)
			}
			actual, err := adapter.ReadPoolVIPOwnershipV3(t.Context(), envelope)
			if err != nil || !reflect.DeepEqual(actual, cloneV3Manifest(envelope.Manifest)) {
				t.Fatalf("role %q readback=%+v err=%v", tc.role, actual, err)
			}

			_, found, err := stateStore.Load(t.Context())
			if err != nil || found != tc.serving {
				t.Fatalf("role %q durable serving state found=%v err=%v", tc.role, found, err)
			}
			owned := effectiveFromV3(envelope)
			if tc.serving != containsOwnership(domain.applied, owned) {
				t.Fatalf("role %q applied ownership=%+v", tc.role, domain.applied)
			}
		})
	}
}

func TestV3DeliveryAdapterReplayUsesFreshFullDomainReadback(t *testing.T) {
	now := time.Date(2026, 8, 28, 10, 0, 0, 0, time.UTC)
	domain := &fakeDomainSurface{}
	coordinator := newTestCoordinator(t, filepath.Join(t.TempDir(), "fences.json"), domain)
	if err := coordinator.UpdateBase(t.Context(), projectorBase(), BaseAuthority{}); err != nil {
		t.Fatal(err)
	}
	lifecycle := lifecycleAt(t, coordinator, NewFileStateStore(filepath.Join(t.TempDir(), "ownership.json")), &now)
	adapter, err := NewV3DeliveryAdapter(lifecycle, coordinator)
	if err != nil {
		t.Fatal(err)
	}
	envelope := v3AdapterEnvelope(t, nodepolicy.PoolVIPOwnershipServing, now)
	if err := adapter.ApplyPoolVIPOwnershipV3(t.Context(), envelope); err != nil {
		t.Fatal(err)
	}

	first, err := adapter.ReadPoolVIPOwnershipV3(t.Context(), envelope)
	if err != nil {
		t.Fatal(err)
	}
	first.Routes[0] = "192.0.2.0/24"
	first.WGPeers[0].AllowedIPs[0] = "192.0.2.0/24"
	first.Services[0].VIP = "192.0.2.10"
	second, err := adapter.ReadPoolVIPOwnershipV3(t.Context(), envelope)
	if err != nil || !reflect.DeepEqual(second, envelope.Manifest) {
		t.Fatalf("replay returned aliased or stale manifest: got=%+v err=%v", second, err)
	}

	domain.mutate = func(actual *AppliedDomainState) { actual.Routes = nil }
	if _, err := adapter.ReadPoolVIPOwnershipV3(t.Context(), envelope); !errors.Is(err, ErrDomainReadbackMismatch) {
		t.Fatalf("replay must fail when fresh substrate proof changes: %v", err)
	}
	if _, err := adapter.ReadPoolVIPOwnershipV3(t.Context(), envelope); err != nil {
		t.Fatalf("failed replay proof must not corrupt active state: %v", err)
	}
}

func v3AdapterEnvelope(t *testing.T, role string, now time.Time) control.PoolVIPOwnershipDeliveryEnvelopeV3 {
	t.Helper()
	own := projectorOwnership()
	manifest := control.PoolVIPOwnershipManifestV3{
		Version: nodepolicy.PoolVIPOwnershipManifestVersion,
		OrgID:   own.OrgID, SiteID: own.SiteID, ClusterID: own.ClusterID, PoolID: own.PoolID,
		ConnectorNodeID: own.ConnectorNodeID, Role: role, PromotionGeneration: own.PromotionGeneration,
		ManifestRevision: own.ManifestRevision, LeaseEpoch: own.LeaseEpoch, LeaseExpiresAt: now.Add(time.Minute),
		DNSZone: "cluster.example", DNSVIP: "100.64.0.2", HandoffOwnerID: "88888888-8888-8888-8888-888888888888",
	}
	switch role {
	case nodepolicy.PoolVIPOwnershipServing:
		manifest.RouteIntent = "serving"
		for _, peer := range own.WGPeers {
			manifest.WGPeers = append(manifest.WGPeers, control.PoolVIPOwnershipWGPeerV3{PublicKey: peer.PublicKey, AllowedIPs: append([]string(nil), peer.AllowedIPs...)})
		}
		manifest.Routes = append([]string(nil), own.Routes...)
		for _, mapping := range own.VIPMappings {
			manifest.Services = append(manifest.Services, control.PoolVIPOwnershipServiceV3{
				ServiceID: mapping.ServiceID, VIP: mapping.VIP, Namespace: mapping.Namespace, Service: mapping.Service,
				ServiceCIDR: mapping.ServiceCIDR, DNSName: mapping.DNSName, Protocol: mapping.Protocol, Port: mapping.PortLow,
			})
		}
	case nodepolicy.PoolVIPOwnershipPreparedNonServing:
		manifest.RouteIntent = "non_serving"
	case nodepolicy.PoolVIPOwnershipWithdrawal:
		manifest.RouteIntent = "withdrawal"
	default:
		t.Fatalf("unsupported test role %q", role)
	}
	policyManifest := nodepolicy.PoolVIPOwnershipManifest{
		Version: manifest.Version, OrgID: manifest.OrgID, SiteID: manifest.SiteID, ClusterID: manifest.ClusterID,
		PoolID: manifest.PoolID, ConnectorNodeID: manifest.ConnectorNodeID, Role: manifest.Role,
		PromotionGeneration: manifest.PromotionGeneration, ManifestRevision: manifest.ManifestRevision, LeaseEpoch: manifest.LeaseEpoch,
		LeaseExpiresAt: manifest.LeaseExpiresAt, DNSZone: manifest.DNSZone, DNSVIP: manifest.DNSVIP,
		HandoffOwnerID: manifest.HandoffOwnerID, RouteIntent: manifest.RouteIntent, Routes: append([]string(nil), manifest.Routes...),
	}
	for _, peer := range manifest.WGPeers {
		policyManifest.WGPeers = append(policyManifest.WGPeers, nodepolicy.PoolVIPOwnershipWGPeer{PublicKey: peer.PublicKey, AllowedIPs: append([]string(nil), peer.AllowedIPs...)})
	}
	for _, service := range manifest.Services {
		policyManifest.Services = append(policyManifest.Services, nodepolicy.PoolVIPOwnershipService{
			ServiceID: service.ServiceID, VIP: service.VIP, Namespace: service.Namespace, Service: service.Service,
			ServiceCIDR: service.ServiceCIDR, DNSName: service.DNSName, Protocol: service.Protocol, Port: service.Port,
		})
	}
	identity, err := nodepolicy.PoolVIPOwnershipManifestIdentity(policyManifest)
	if err != nil {
		t.Fatal(err)
	}
	phase := "serve"
	priorLeaseEpoch := uint64(0)
	if role == nodepolicy.PoolVIPOwnershipPreparedNonServing {
		phase = "prepare"
	}
	if role == nodepolicy.PoolVIPOwnershipWithdrawal {
		phase = "withdraw"
		priorLeaseEpoch = own.LeaseEpoch - 1
	}
	routeDigest, err := control.PoolVIPOwnershipOwnedRouteDigest(manifest.Routes)
	if err != nil {
		t.Fatal(err)
	}
	vipDigest := ""
	if role == nodepolicy.PoolVIPOwnershipServing {
		mappings := make([]nodepolicy.VIPMapping, len(manifest.Services))
		for i, service := range manifest.Services {
			mappings[i] = nodepolicy.VIPMapping{
				ServiceID: service.ServiceID, VIP: service.VIP, Namespace: service.Namespace, Service: service.Service,
				ServiceCIDR: service.ServiceCIDR, DNSName: service.DNSName, Protocol: service.Protocol, PortLow: service.Port, PortHigh: service.Port,
			}
		}
		vipDigest = nodepolicy.VIPMapDigest(mappings)
	}
	envelope := control.PoolVIPOwnershipDeliveryEnvelopeV3{
		PoolVIPOwnershipDeliveryEnvelope: control.PoolVIPOwnershipDeliveryEnvelope{
			Version: control.PoolVIPOwnershipDeliveryHandoffVersion,
			OrgID:   manifest.OrgID, SiteID: manifest.SiteID, ClusterID: manifest.ClusterID, PoolID: manifest.PoolID,
			ConnectorNodeID: manifest.ConnectorNodeID, TargetNodeID: manifest.ConnectorNodeID, OperationID: manifest.HandoffOwnerID,
			ManifestIdentity: identity, Role: role, PromotionGeneration: manifest.PromotionGeneration,
			ManifestRevision: manifest.ManifestRevision, LeaseEpoch: manifest.LeaseEpoch, DeliveryPhase: phase,
			DeliveryID:    "99999999-9999-9999-9999-999999999999",
			DeliveryNonce: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		},
		ExpiresAt: manifest.LeaseExpiresAt, Manifest: manifest, PriorLeaseEpoch: priorLeaseEpoch,
		ExpectedRouteDigest: routeDigest, ExpectedVIPMapDigest: vipDigest,
	}
	if err := control.ValidatePoolVIPOwnershipDeliveryEnvelopeV3(envelope); err != nil {
		t.Fatalf("invalid v3 adapter test envelope: %v", err)
	}
	return envelope
}
