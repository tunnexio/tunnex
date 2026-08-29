package ownershiplease

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/tunnexio/tunnex/apps/node/internal/nodepolicy"
	"github.com/tunnexio/tunnex/apps/node/internal/reconcile"
)

type fakeWGReadbackOwner struct {
	value reconcile.WGBackendReadback
	err   error
	calls int
}

func (f *fakeWGReadbackOwner) Readback(context.Context) (reconcile.WGBackendReadback, error) {
	f.calls++
	if f.err != nil {
		return reconcile.WGBackendReadback{}, f.err
	}
	return f.value, nil
}

func TestProductionWGReadbackSurfaceReplacesDesiredEchoWithActual(t *testing.T) {
	domain := &fakeDomainSurface{applied: AppliedDomainState{
		WGPeers:     []WGAppliedPeer{{PublicKey: "desired-echo", AllowedIPs: []string{"192.0.2.0/24"}}},
		Routes:      []string{"192.0.2.0/24"},
		ReturnRules: []reconcile.ReturnRule{{Priority: 100, Destination: "192.0.2.0/24", Lookup: "main"}},
		VIPMappings: []nodepolicy.VIPMapping{{ServiceID: "service-a", VIP: "100.64.0.10"}},
	}}
	wg := &fakeWGReadbackOwner{value: reconcile.WGBackendReadback{
		Peers:        []reconcile.Peer{{PublicKey: "actual-peer", AllowedIPs: []string{"100.64.0.0/24"}}},
		Routes:       []string{"100.64.0.0/24"},
		RouteDetails: []reconcile.OwnedRoute{{Family: "ipv4", Destination: "100.64.0.0/24", Device: "wg0", Protocol: "static", Metric: 8021}},
		ReturnRules:  []reconcile.ReturnRule{{Priority: 100, Destination: "10.99.0.0/24", Lookup: "main"}},
	}}
	surface, err := NewProductionWGReadbackSurface(domain, wg)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := surface.Readback(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(actual.WGPeers, []WGAppliedPeer{{PublicKey: "actual-peer", AllowedIPs: []string{"100.64.0.0/24"}}}) ||
		!reflect.DeepEqual(actual.Routes, wg.value.Routes) || !reflect.DeepEqual(actual.ReturnRules, wg.value.ReturnRules) {
		t.Fatalf("WG domain was not replaced with reconcile-owned actual state: %+v", actual)
	}
	if !reflect.DeepEqual(actual.VIPMappings, domain.applied.VIPMappings) {
		t.Fatalf("non-WG domains must remain delegated: %+v", actual.VIPMappings)
	}
	actual.WGPeers[0].AllowedIPs[0] = "203.0.113.0/24"
	actual.Routes[0] = "203.0.113.0/24"
	if wg.value.Peers[0].AllowedIPs[0] != "100.64.0.0/24" || wg.value.Routes[0] != "100.64.0.0/24" {
		t.Fatal("production readback returned aliases into the WG owner's snapshot")
	}
}

func TestProductionWGReadbackSurfaceRejectsDestinationOnlyRouteProof(t *testing.T) {
	wg := &fakeWGReadbackOwner{value: reconcile.WGBackendReadback{Routes: []string{"100.64.0.0/24"}}}
	surface, err := NewProductionWGReadbackSurface(&fakeDomainSurface{}, wg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := surface.Readback(t.Context()); err == nil {
		t.Fatal("destination-only route readback must fail closed")
	}
}

func TestProductionWGReadbackSurfaceFailsClosedOnBackendReadError(t *testing.T) {
	readErr := errors.New("WG enumeration failed")
	wg := &fakeWGReadbackOwner{err: readErr}
	surface, err := NewProductionWGReadbackSurface(&fakeDomainSurface{}, wg)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := surface.Readback(t.Context())
	if !errors.Is(err, readErr) || !reflect.DeepEqual(actual, AppliedDomainState{}) || wg.calls != 1 {
		t.Fatalf("readback error must return no desired echo: actual=%+v err=%v calls=%d", actual, err, wg.calls)
	}
}

func TestProductionWGReadbackEmergencyWithdrawalAcceptsAbsentInterface(t *testing.T) {
	domain := &emergencyDomain{}
	wg := &fakeWGReadbackOwner{err: reconcile.ErrWGInterfaceAbsent}
	surface, err := NewProductionWGReadbackSurface(domain, wg)
	if err != nil {
		t.Fatal(err)
	}
	emergency, ok := surface.(EmergencyDomainSurface)
	if !ok {
		t.Fatal("production surface must expose emergency withdrawal")
	}
	fences := []PoolFence{{}}
	if err := emergency.EmergencyWithdraw(t.Context(), fences); err != nil {
		t.Fatalf("missing interface is already withdrawn: %v", err)
	}
	if !reflect.DeepEqual(domain.fences, fences) {
		t.Fatalf("downstream withdrawal was skipped: got %+v want %+v", domain.fences, fences)
	}
}

func TestProductionWGReadbackEmergencyWithdrawalAcceptsRawAbsentDeviceError(t *testing.T) {
	domain := &emergencyDomain{}
	wg := &fakeWGReadbackOwner{err: errors.New(`ip -o -4 addr show dev wg0: Device "wg0" does not exist`)}
	surface, err := NewProductionWGReadbackSurface(domain, wg)
	if err != nil {
		t.Fatal(err)
	}
	emergency := surface.(EmergencyDomainSurface)
	if err := emergency.EmergencyWithdraw(t.Context(), []PoolFence{{}}); err != nil {
		t.Fatalf("raw missing-device error is already withdrawn: %v", err)
	}
	if len(domain.fences) != 1 {
		t.Fatal("downstream withdrawal was skipped")
	}
}

func TestCoordinatorProductionWGReadbackRejectsUnappliedOwnershipAndCompensates(t *testing.T) {
	ctx := t.Context()
	base := projectorBase()
	backend := reconcile.NewMemBackend()
	if err := backend.Configure(ctx, reconcile.InterfaceConfig{Address: base.InterfaceAddress}); err != nil {
		t.Fatal(err)
	}
	if err := backend.ApplyPeers(ctx, base.Peers); err != nil {
		t.Fatal(err)
	}
	var routes []string
	for _, route := range base.Policy.Routes {
		routes = append(routes, route.DstCIDR)
	}
	if err := backend.ApplyRoutes(ctx, routes, ""); err != nil {
		t.Fatal(err)
	}
	domain := &fakeDomainSurface{}
	coordinator, err := NewCoordinatorWithProductionWGReadback(
		NewProjector(), domain, backend, NewFileFenceStore(filepath.Join(t.TempDir(), "fences.json")),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.UpdateBase(ctx, base, BaseAuthority{}); err != nil {
		t.Fatal(err)
	}
	actual, err := coordinator.ApplyAndReadback(ctx, projectorOwnership())
	if !errors.Is(err, ErrDomainReadbackMismatch) || !isZeroEffective(actual) {
		t.Fatalf("unapplied WG ownership must never ACK: actual=%+v err=%v", actual, err)
	}
	if containsOwnership(domain.applied, projectorOwnership()) {
		t.Fatalf("failed actual WG proof did not compensate to non-serving: %+v", domain.applied)
	}
}

func TestExpectedReturnRulesRequireConfiguredRouteIntersection(t *testing.T) {
	desired := projectorBase()
	desired.InterfaceAddress = "10.99.0.1/24, fd00::1/64"
	desired.Policy.Routes = append(desired.Policy.Routes,
		nodepolicy.Route{DstCIDR: "10.99.0.0/24"},
		nodepolicy.Route{DstCIDR: "fd00::/64"},
		nodepolicy.Route{DstCIDR: "198.51.100.0/24"},
	)
	want := []reconcile.ReturnRule{
		{Priority: 100, Destination: "10.99.0.0/24", Lookup: "main"},
		{Priority: 100, Destination: "fd00::/64", Lookup: "main"},
	}
	if got := canonicalDomainState(expectedDomainState(desired)).ReturnRules; !reflect.DeepEqual(got, want) {
		t.Fatalf("return rules=%+v want configured-route intersections only %+v", got, want)
	}
}

func TestProductionWGReadbackCompositionRejectsMissingDependencies(t *testing.T) {
	if _, err := NewProductionWGReadbackSurface(nil, &fakeWGReadbackOwner{}); !errors.Is(err, ErrProductionAdapterUnavailable) {
		t.Fatalf("nil domain must fail closed: %v", err)
	}
	if _, err := NewProductionWGReadbackSurface(&fakeDomainSurface{}, nil); !errors.Is(err, ErrProductionAdapterUnavailable) {
		t.Fatalf("nil WG owner must fail closed: %v", err)
	}
}
