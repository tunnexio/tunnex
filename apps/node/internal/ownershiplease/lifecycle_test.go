package ownershiplease

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tunnexio/tunnex/apps/node/internal/nodepolicy"
)

type fakeAtomicDataplane struct {
	calls      []EffectiveOwnership
	mutate     func(*EffectiveOwnership)
	afterApply func(EffectiveOwnership)
	err        error
}

func (f *fakeAtomicDataplane) ApplyAndReadback(_ context.Context, desired EffectiveOwnership) (EffectiveOwnership, error) {
	f.calls = append(f.calls, cloneEffective(desired))
	if f.err != nil {
		return EffectiveOwnership{}, f.err
	}
	actual := cloneEffective(desired)
	if f.afterApply != nil {
		f.afterApply(cloneEffective(desired))
	}
	if f.mutate != nil && !isZeroEffective(desired) {
		f.mutate(&actual)
	}
	return actual, nil
}

func TestServingLeaseRechecksExpiryAfterSlowApply(t *testing.T) {
	now := time.Date(2026, 8, 28, 10, 0, 0, 0, time.UTC)
	grant := testGrant(now)
	dataplane := &fakeAtomicDataplane{}
	dataplane.afterApply = func(desired EffectiveOwnership) {
		if !isZeroEffective(desired) {
			now = grant.LeaseExpiresAt
		}
	}
	lifecycle := lifecycleAt(t, dataplane, NewFileStateStore(filepath.Join(t.TempDir(), "ownership.json")), &now)
	if err := lifecycle.InstallServingLease(t.Context(), grant); !errors.Is(err, ErrLeaseExpired) {
		t.Fatalf("post-apply expiry error=%v", err)
	}
	if len(dataplane.calls) != 2 || !isZeroEffective(dataplane.calls[1]) {
		t.Fatalf("lease that expires during apply must withdraw before ACK: %+v", dataplane.calls)
	}
}

func TestServingLeaseRechecksBackwardClockAfterApply(t *testing.T) {
	now := time.Date(2026, 8, 28, 10, 0, 0, 0, time.UTC)
	grant := testGrant(now)
	dataplane := &fakeAtomicDataplane{}
	dataplane.afterApply = func(desired EffectiveOwnership) {
		if !isZeroEffective(desired) {
			now = now.Add(-time.Second)
		}
	}
	lifecycle := lifecycleAt(t, dataplane, NewFileStateStore(filepath.Join(t.TempDir(), "ownership.json")), &now)
	if err := lifecycle.InstallServingLease(t.Context(), grant); !errors.Is(err, ErrClockMovedBackward) {
		t.Fatalf("post-apply backward-clock error=%v", err)
	}
	if len(dataplane.calls) != 2 || !isZeroEffective(dataplane.calls[1]) {
		t.Fatalf("backward clock during apply must withdraw before ACK: %+v", dataplane.calls)
	}
}

func cloneEffective(value EffectiveOwnership) EffectiveOwnership {
	b, _ := json.Marshal(value)
	var out EffectiveOwnership
	_ = json.Unmarshal(b, &out)
	return out
}

func testGrant(now time.Time) Grant {
	return Grant{
		LeaseExpiresAt: now.Add(time.Minute),
		Effective: EffectiveOwnership{
			OrgID: "11111111-1111-1111-1111-111111111111", SiteID: "22222222-2222-2222-2222-222222222222",
			ClusterID: "33333333-3333-3333-3333-333333333333", PoolID: "44444444-4444-4444-4444-444444444444",
			ConnectorNodeID: "55555555-5555-5555-5555-555555555555", ManifestIdentity: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			PromotionGeneration: 4, ManifestRevision: 9, LeaseEpoch: 7,
			Routes: []string{"100.64.0.0/24"}, WGPeers: []WGPeerOwnership{{PublicKey: "qz/uIHKyeTmf08TjUpwbMLlBr78PS+fKYl33OGdZU+M=", AllowedIPs: []string{"100.64.0.0/24"}}},
			VIPMappings: []nodepolicy.VIPMapping{{
				ServiceID: "66666666-6666-6666-6666-666666666666", VIP: "100.64.0.5", Namespace: "prod", Service: "api",
				ServiceCIDR: "10.96.0.0/12", Protocol: "tcp", PortLow: 443, PortHigh: 443, DNSName: "api.prod.svc.cluster.example",
			}},
			DNSZones: []nodepolicy.K8sDNSZone{{ListenVIP: "100.64.0.2", Zone: "cluster.example"}},
		},
	}
}

func lifecycleAt(t *testing.T, dataplane AtomicDataplane, store StateStore, now *time.Time) *Lifecycle {
	t.Helper()
	lifecycle := New(dataplane, store)
	lifecycle.setClock(func() time.Time { return *now })
	return lifecycle
}

func TestStartupReconcileRestoresOnlyUnexpiredDurableLease(t *testing.T) {
	now := time.Date(2026, 8, 28, 10, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "ownership.json")
	store := NewFileStateStore(path)
	firstDataplane := &fakeAtomicDataplane{}
	first := lifecycleAt(t, firstDataplane, store, &now)
	grant := testGrant(now)
	if err := first.InstallServingLease(t.Context(), grant); err != nil {
		t.Fatal(err)
	}

	restartedDataplane := &fakeAtomicDataplane{}
	restarted := lifecycleAt(t, restartedDataplane, NewFileStateStore(path), &now)
	if err := restarted.StartupReconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(restartedDataplane.calls) != 1 {
		t.Fatalf("startup applies once, got %d calls", len(restartedDataplane.calls))
	}
	got := restartedDataplane.calls[0]
	if len(got.Routes) != 1 || len(got.WGPeers) != 1 || len(got.VIPMappings) != 1 || len(got.DNSZones) != 1 {
		t.Fatalf("startup did not atomically restore every ownership surface: %+v", got)
	}
}

func TestDisconnectedLeaseExpiryWithdrawsEveryOwnershipSurface(t *testing.T) {
	now := time.Date(2026, 8, 28, 10, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "ownership.json")
	dataplane := &fakeAtomicDataplane{}
	lifecycle := lifecycleAt(t, dataplane, NewFileStateStore(path), &now)
	grant := testGrant(now)
	if err := lifecycle.InstallServingLease(t.Context(), grant); err != nil {
		t.Fatal(err)
	}
	// No CP renewal arrives. The watchdog alone owns deadline withdrawal.
	now = grant.LeaseExpiresAt
	if err := lifecycle.Check(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(dataplane.calls) != 2 || !isZeroEffective(dataplane.calls[1]) {
		t.Fatalf("expiry must atomically withdraw routes, AllowedIPs, VIP/DNAT, and DNS: %+v", dataplane.calls)
	}
	if _, found, err := NewFileStateStore(path).Load(t.Context()); err != nil || found {
		t.Fatalf("expired lease must be cleared after withdrawal: found=%v err=%v", found, err)
	}
}

func TestBackwardClockWithdrawsImmediately(t *testing.T) {
	now := time.Date(2026, 8, 28, 10, 0, 0, 0, time.UTC)
	dataplane := &fakeAtomicDataplane{}
	lifecycle := lifecycleAt(t, dataplane, NewFileStateStore(filepath.Join(t.TempDir(), "ownership.json")), &now)
	if err := lifecycle.InstallServingLease(t.Context(), testGrant(now)); err != nil {
		t.Fatal(err)
	}
	now = now.Add(-time.Second)
	err := lifecycle.Check(t.Context())
	if !errors.Is(err, ErrClockMovedBackward) {
		t.Fatalf("backward clock error = %v", err)
	}
	if len(dataplane.calls) != 2 || !isZeroEffective(dataplane.calls[1]) {
		t.Fatalf("backward clock must immediately withdraw, calls=%+v", dataplane.calls)
	}
}

func TestCorruptStartupStateWithdrawsImmediately(t *testing.T) {
	now := time.Date(2026, 8, 28, 10, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "ownership.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"state":`), 0600); err != nil {
		t.Fatal(err)
	}
	dataplane := &fakeAtomicDataplane{}
	lifecycle := lifecycleAt(t, dataplane, NewFileStateStore(path), &now)
	err := lifecycle.StartupReconcile(t.Context())
	if !errors.Is(err, ErrCorruptState) {
		t.Fatalf("corrupt state error = %v", err)
	}
	if len(dataplane.calls) != 1 || !isZeroEffective(dataplane.calls[0]) {
		t.Fatalf("corrupt state must immediately withdraw the ownership overlay: %+v", dataplane.calls)
	}
}

func TestAtomicReadbackCoversEveryOwnershipSurface(t *testing.T) {
	tests := map[string]func(*EffectiveOwnership){
		"routes":                func(v *EffectiveOwnership) { v.Routes = nil },
		"wireguard_allowed_ips": func(v *EffectiveOwnership) { v.WGPeers = nil },
		"vip_dnat":              func(v *EffectiveOwnership) { v.VIPMappings[0].VIP = "100.64.0.99" },
		"dns":                   func(v *EffectiveOwnership) { v.DNSZones[0].Zone = "other.example" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			now := time.Date(2026, 8, 28, 10, 0, 0, 0, time.UTC)
			dataplane := &fakeAtomicDataplane{mutate: mutate}
			path := filepath.Join(t.TempDir(), "ownership.json")
			lifecycle := lifecycleAt(t, dataplane, NewFileStateStore(path), &now)
			err := lifecycle.InstallServingLease(t.Context(), testGrant(now))
			if !errors.Is(err, ErrReadbackMismatch) {
				t.Fatalf("readback mismatch error = %v", err)
			}
			if len(dataplane.calls) != 2 || !isZeroEffective(dataplane.calls[1]) {
				t.Fatalf("partial readback must trigger overlay withdrawal: %+v", dataplane.calls)
			}
			if _, found, loadErr := NewFileStateStore(path).Load(t.Context()); loadErr != nil || found {
				t.Fatalf("mismatched apply must not persist authority: found=%v err=%v", found, loadErr)
			}
		})
	}
}

func TestServingLeaseRejectsNoncanonicalDataplanePrefixes(t *testing.T) {
	tests := map[string]func(*Grant){
		"route":        func(g *Grant) { g.Effective.Routes[0] = "100.64.0.1/24" },
		"allowed IP":   func(g *Grant) { g.Effective.WGPeers[0].AllowedIPs[0] = "100.64.0.1/24" },
		"service CIDR": func(g *Grant) { g.Effective.VIPMappings[0].ServiceCIDR = "10.96.0.1/12" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			now := time.Date(2026, 8, 28, 10, 0, 0, 0, time.UTC)
			grant := testGrant(now)
			mutate(&grant)
			dataplane := &fakeAtomicDataplane{}
			lifecycle := lifecycleAt(t, dataplane, NewFileStateStore(filepath.Join(t.TempDir(), "ownership.json")), &now)
			if err := lifecycle.InstallServingLease(t.Context(), grant); err == nil {
				t.Fatal("noncanonical prefix must reject")
			}
			if len(dataplane.calls) != 1 || !isZeroEffective(dataplane.calls[0]) {
				t.Fatalf("invalid serving candidate must withdraw overlay: %+v", dataplane.calls)
			}
		})
	}
}

func TestExpiredStartupStateWithdrawsInsteadOfReapplying(t *testing.T) {
	now := time.Date(2026, 8, 28, 10, 2, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "ownership.json")
	grantTime := now.Add(-2 * time.Minute)
	grant := testGrant(grantTime)
	store := NewFileStateStore(path)
	if err := store.Save(t.Context(), State{Version: StateVersion, Grant: grant, LastWallTime: grantTime}); err != nil {
		t.Fatal(err)
	}
	dataplane := &fakeAtomicDataplane{}
	lifecycle := lifecycleAt(t, dataplane, NewFileStateStore(path), &now)
	if err := lifecycle.StartupReconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(dataplane.calls) != 1 || !isZeroEffective(dataplane.calls[0]) {
		t.Fatalf("expired startup state must withdraw without a serving reapply: %+v", dataplane.calls)
	}
}
