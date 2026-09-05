package ownershiplease

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/tunnexio/tunnex/apps/node/internal/nodepolicy"
	"github.com/tunnexio/tunnex/apps/node/internal/reconcile"
)

type fakeDomainSurface struct {
	mu          sync.Mutex
	stages      []Stage
	applied     AppliedDomainState
	failStage   Stage
	failOnce    bool
	readbackErr error
	mutate      func(*AppliedDomainState)
	inApply     bool
	concurrent  bool
}

type cancellationAwareDomain struct{ fakeDomainSurface }

func (f *cancellationAwareDomain) ApplyStage(ctx context.Context, stage Stage, desired reconcile.DesiredState) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return f.fakeDomainSurface.ApplyStage(ctx, stage, desired)
}

type emergencyDomain struct {
	fakeDomainSurface
	fences []PoolFence
}

type failingFenceStore struct {
	fences []PoolFence
	fail   bool
}

func (s *failingFenceStore) LoadFences(context.Context) ([]PoolFence, error) {
	return append([]PoolFence(nil), s.fences...), nil
}

func (s *failingFenceStore) SaveFences(_ context.Context, fences []PoolFence) error {
	if s.fail {
		return errors.New("injected durable rename failure")
	}
	s.fences = append([]PoolFence(nil), fences...)
	return nil
}

func (f *emergencyDomain) EmergencyWithdraw(_ context.Context, fences []PoolFence) error {
	f.fences = append([]PoolFence(nil), fences...)
	f.applied = AppliedDomainState{}
	return nil
}

func (f *fakeDomainSurface) ApplyStage(_ context.Context, stage Stage, desired reconcile.DesiredState) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.inApply {
		f.concurrent = true
	}
	f.inApply = true
	defer func() { f.inApply = false }()
	f.stages = append(f.stages, stage)
	if stage == f.failStage {
		if !f.failOnce {
			return errors.New("injected stage failure")
		}
		f.failStage = ""
		return errors.New("injected one-shot stage failure")
	}
	want := expectedDomainState(desired)
	switch stage {
	case StageDNS:
		f.applied.DNSZones = want.DNSZones
		f.applied.DNSAnswers = want.DNSAnswers
		f.applied.DNSVIPs = want.DNSVIPs
		f.applied.DNSListeners = want.DNSListeners
	case StageDNAT:
		f.applied.VIPMappings = want.VIPMappings
	case StageOVPN:
		f.applied.OVPN = want.OVPN
	case StageRoutes:
		f.applied.Routes = want.Routes
		f.applied.ReturnRules = want.ReturnRules
	case StageWireGuard:
		f.applied.WGPeers = want.WGPeers
	default:
		return errors.New("unknown stage")
	}
	return nil
}

func (f *fakeDomainSurface) Readback(context.Context) (AppliedDomainState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.readbackErr != nil {
		return AppliedDomainState{}, f.readbackErr
	}
	actual := cloneAppliedDomainState(f.applied)
	if f.mutate != nil {
		mutate := f.mutate
		f.mutate = nil
		mutate(&actual)
	}
	return actual, nil
}

func cloneAppliedDomainState(value AppliedDomainState) AppliedDomainState {
	return cloneDomainState(value)
}

func legacyBaseWithOwnership() reconcile.DesiredState {
	base := projectorBase()
	own := projectorOwnership()
	base.Policy.Routes = append(base.Policy.Routes, nodepolicy.Route{DstCIDR: own.Routes[0]}, nodepolicy.Route{DstCIDR: own.Routes[1]})
	base.Peers[0].AllowedIPs = append(base.Peers[0].AllowedIPs, own.WGPeers[0].AllowedIPs...)
	base.Policy.VIPMappings = append(base.Policy.VIPMappings, own.VIPMappings...)
	base.Policy.K8sDNSZones = append(base.Policy.K8sDNSZones, own.DNSZones...)
	return base
}

func newTestCoordinator(t *testing.T, path string, domain *fakeDomainSurface) *Coordinator {
	t.Helper()
	return NewCoordinator(NewProjector(), domain, NewFileFenceStore(path))
}

func TestCoordinatorAdoptsExactLegacyDuplicatesAndWithdrawsInReverse(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fences.json")
	domain := &fakeDomainSurface{}
	coordinator := newTestCoordinator(t, path, domain)
	base := legacyBaseWithOwnership()
	if err := coordinator.UpdateBase(t.Context(), base, BaseAuthority{}); err != nil {
		t.Fatal(err)
	}
	own := projectorOwnership()
	actual, err := coordinator.ApplyAndReadback(t.Context(), own)
	if err != nil || !reflect.DeepEqual(actual, own) {
		t.Fatalf("activation actual=%+v err=%v", actual, err)
	}
	if !reflect.DeepEqual(domain.stages, activationOrder) {
		t.Fatalf("activation order=%v want=%v", domain.stages, activationOrder)
	}
	active := cloneAppliedDomainState(domain.applied)
	if count(active.Routes, own.Routes[0]) != 1 || appliedPeerPrefixCount(active.WGPeers, own.WGPeers[0].PublicKey, own.WGPeers[0].AllowedIPs[0]) != 1 {
		t.Fatalf("exact legacy adoption duplicated ownership: %+v", active)
	}

	domain.stages = nil
	if _, err := coordinator.ApplyAndReadback(t.Context(), EffectiveOwnership{}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(domain.stages, withdrawalOrder) {
		t.Fatalf("withdrawal order=%v want=%v", domain.stages, withdrawalOrder)
	}
	if containsOwnership(domain.applied, own) {
		t.Fatalf("withdrawal revealed fenced legacy ownership: %+v", domain.applied)
	}
	if !contains(domain.applied.Routes, "172.16.0.0/16") || len(domain.applied.VIPMappings) != 1 || domain.applied.VIPMappings[0].ServiceID != "77777777-7777-7777-7777-777777777777" {
		t.Fatalf("withdrawal removed unrelated base state: %+v", domain.applied)
	}
}

func TestCoordinatorFenceSurvivesRestartUntilExplicitCPUnfence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fences.json")
	base := legacyBaseWithOwnership()
	own := projectorOwnership()
	firstDomain := &fakeDomainSurface{}
	first := newTestCoordinator(t, path, firstDomain)
	if err := first.UpdateBase(t.Context(), base, BaseAuthority{}); err != nil {
		t.Fatal(err)
	}
	if _, err := first.ApplyAndReadback(t.Context(), own); err != nil {
		t.Fatal(err)
	}
	if _, err := first.ApplyAndReadback(t.Context(), EffectiveOwnership{}); err != nil {
		t.Fatal(err)
	}

	restartedDomain := &fakeDomainSurface{}
	restarted := newTestCoordinator(t, path, restartedDomain)
	if err := restarted.UpdateBase(t.Context(), base, BaseAuthority{}); err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.ApplyAndReadback(t.Context(), EffectiveOwnership{}); err != nil {
		t.Fatal(err)
	}
	if containsOwnership(restartedDomain.applied, own) {
		t.Fatalf("restart revealed fenced generation-1 ownership: %+v", restartedDomain.applied)
	}

	scope := PoolScope{OrgID: own.OrgID, SiteID: own.SiteID, ClusterID: own.ClusterID, PoolID: own.PoolID}
	hash, err := baseStateHash(base)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.UpdateBase(t.Context(), base, BaseAuthority{BaseVersion: base.Version, BaseHash: hash, UnfencedPools: []PoolScope{scope}}); err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.ApplyAndReadback(t.Context(), EffectiveOwnership{}); err != nil {
		t.Fatal(err)
	}
	if !containsOwnership(restartedDomain.applied, own) {
		t.Fatalf("explicit CP unfence did not reveal authoritative base: %+v", restartedDomain.applied)
	}
	fences, err := NewFileFenceStore(path).LoadFences(t.Context())
	if err != nil || len(fences) != 1 || fences[0].ReleasedAtBaseVersion != base.Version || fences[0].ReleasedAtBaseHash != hash {
		t.Fatalf("explicit unfence was not durable: fences=%+v err=%v", fences, err)
	}
}

func TestCoordinatorUnfenceRequiresInactiveExactBaseBinding(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fences.json")
	base := legacyBaseWithOwnership()
	own := projectorOwnership()
	coordinator := newTestCoordinator(t, path, &fakeDomainSurface{})
	if err := coordinator.UpdateBase(t.Context(), base, BaseAuthority{}); err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.ApplyAndReadback(t.Context(), own); err != nil {
		t.Fatal(err)
	}
	hash, _ := baseStateHash(base)
	scope := PoolScope{OrgID: own.OrgID, SiteID: own.SiteID, ClusterID: own.ClusterID, PoolID: own.PoolID}
	if err := coordinator.UpdateBase(t.Context(), base, BaseAuthority{BaseVersion: base.Version, BaseHash: hash, UnfencedPools: []PoolScope{scope}}); err == nil {
		t.Fatal("active ownership must reject unfence")
	}
	if _, err := coordinator.ApplyAndReadback(t.Context(), EffectiveOwnership{}); err != nil {
		t.Fatal(err)
	}
	if err := coordinator.UpdateBase(t.Context(), base, BaseAuthority{BaseVersion: base.Version, BaseHash: strings.Repeat("0", 64), UnfencedPools: []PoolScope{scope}}); err == nil {
		t.Fatal("unfence with a stale/mismatched base hash must fail closed")
	}
	fences, err := NewFileFenceStore(path).LoadFences(t.Context())
	if err != nil || len(fences) != 1 || fences[0].ReleasedAtBaseVersion != 0 {
		t.Fatalf("rejected unfence changed durable fence: fences=%+v err=%v", fences, err)
	}
}

func TestCoordinatorUnfencePersistenceFailureDoesNotExposeOrMutateBase(t *testing.T) {
	base := legacyBaseWithOwnership()
	own := projectorOwnership()
	store := &failingFenceStore{}
	domain := &fakeDomainSurface{}
	coordinator := NewCoordinator(NewProjector(), domain, store)
	if err := coordinator.UpdateBase(t.Context(), base, BaseAuthority{}); err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.ApplyAndReadback(t.Context(), own); err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.ApplyAndReadback(t.Context(), EffectiveOwnership{}); err != nil {
		t.Fatal(err)
	}
	hash, _ := baseStateHash(base)
	scope := PoolScope{OrgID: own.OrgID, SiteID: own.SiteID, ClusterID: own.ClusterID, PoolID: own.PoolID}
	store.fail = true
	if err := coordinator.UpdateBase(t.Context(), base, BaseAuthority{BaseVersion: base.Version, BaseHash: hash, UnfencedPools: []PoolScope{scope}}); err == nil {
		t.Fatal("durable unfence failure must fail closed")
	}
	if len(store.fences) != 1 || store.fences[0].ReleasedAtBaseVersion != 0 {
		t.Fatalf("failed atomic save changed durable fence: %+v", store.fences)
	}
	store.fail = false
	if _, err := coordinator.ApplyAndReadback(t.Context(), EffectiveOwnership{}); err != nil {
		t.Fatal(err)
	}
	if containsOwnership(domain.applied, own) {
		t.Fatalf("failed unfence exposed base ownership: %+v", domain.applied)
	}
}

func TestCoordinatorFenceAccumulatesManifestRevisionsUntilUnfence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fences.json")
	firstOwnership := projectorOwnership()
	secondOwnership := cloneEffective(firstOwnership)
	secondOwnership.ManifestIdentity = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	secondOwnership.ManifestRevision++
	secondOwnership.LeaseEpoch++
	secondOwnership.Routes = []string{"10.45.0.0/16", "100.64.0.3/32"}
	secondOwnership.WGPeers[0].AllowedIPs = append([]string(nil), secondOwnership.Routes...)
	secondOwnership.VIPMappings[0] = nodepolicy.VIPMapping{ServiceID: firstOwnership.VIPMappings[0].ServiceID, VIP: "100.64.0.11", Namespace: "default", Service: "api-v2", ServiceCIDR: "10.96.0.0/12", Protocol: "tcp", PortLow: 8443, PortHigh: 8443, DNSName: "api-v2.default.svc.cluster-v2.example"}
	secondOwnership.DNSZones[0] = nodepolicy.K8sDNSZone{ListenVIP: "100.64.0.3", Zone: "cluster-v2.example"}

	firstBase := legacyBaseWithOwnership()
	secondBase := projectorBase()
	for _, route := range secondOwnership.Routes {
		secondBase.Policy.Routes = append(secondBase.Policy.Routes, nodepolicy.Route{DstCIDR: route})
	}
	secondBase.Peers[0].AllowedIPs = append(secondBase.Peers[0].AllowedIPs, secondOwnership.WGPeers[0].AllowedIPs...)
	secondBase.Policy.VIPMappings = append(secondBase.Policy.VIPMappings, secondOwnership.VIPMappings...)
	secondBase.Policy.K8sDNSZones = append(secondBase.Policy.K8sDNSZones, secondOwnership.DNSZones...)

	domain := &fakeDomainSurface{}
	coordinator := newTestCoordinator(t, path, domain)
	if err := coordinator.UpdateBase(t.Context(), firstBase, BaseAuthority{}); err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.ApplyAndReadback(t.Context(), firstOwnership); err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.ApplyAndReadback(t.Context(), EffectiveOwnership{}); err != nil {
		t.Fatal(err)
	}
	scope := PoolScope{OrgID: secondOwnership.OrgID, SiteID: secondOwnership.SiteID, ClusterID: secondOwnership.ClusterID, PoolID: secondOwnership.PoolID}
	if err := coordinator.UpdateBase(t.Context(), secondBase, BaseAuthority{Classifications: []PoolClassification{{Scope: scope, Ownership: secondOwnership}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.ApplyAndReadback(t.Context(), secondOwnership); err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.ApplyAndReadback(t.Context(), EffectiveOwnership{}); err != nil {
		t.Fatal(err)
	}
	if containsOwnership(domain.applied, firstOwnership) || containsOwnership(domain.applied, secondOwnership) {
		t.Fatalf("withdrawal revealed a prior manifest revision: %+v", domain.applied)
	}
	fences, err := NewFileFenceStore(path).LoadFences(t.Context())
	if err != nil || len(fences) != 1 || len(fences[0].Suppressed.Routes) != 4 || len(fences[0].Suppressed.VIPMappings) != 2 {
		t.Fatalf("manifest revisions were not durably accumulated: fences=%+v err=%v", fences, err)
	}

	// Even if the ordinary base later rolls back to the first generation, the
	// accumulated tombstone still suppresses it after restart.
	restartedDomain := &fakeDomainSurface{}
	restarted := newTestCoordinator(t, path, restartedDomain)
	if err := restarted.UpdateBase(t.Context(), firstBase, BaseAuthority{Classifications: []PoolClassification{{Scope: scope, Ownership: firstOwnership}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.ApplyAndReadback(t.Context(), EffectiveOwnership{}); err != nil {
		t.Fatal(err)
	}
	if containsOwnership(restartedDomain.applied, firstOwnership) {
		t.Fatalf("accumulated tombstone lost the first manifest revision after restart: %+v", restartedDomain.applied)
	}
}

func TestCoordinatorCompensatesPartialActivationToFencedNonServing(t *testing.T) {
	domain := &fakeDomainSurface{failStage: StageRoutes, failOnce: true}
	coordinator := newTestCoordinator(t, filepath.Join(t.TempDir(), "fences.json"), domain)
	if err := coordinator.UpdateBase(t.Context(), legacyBaseWithOwnership(), BaseAuthority{}); err != nil {
		t.Fatal(err)
	}
	_, err := coordinator.ApplyAndReadback(t.Context(), projectorOwnership())
	if err == nil {
		t.Fatal("partial activation must fail")
	}
	wantOrder := append(append([]Stage(nil), activationOrder[:4]...), withdrawalOrder...)
	if !reflect.DeepEqual(domain.stages, wantOrder) {
		t.Fatalf("partial activation/compensation order=%v want=%v", domain.stages, wantOrder)
	}
	if containsOwnership(domain.applied, projectorOwnership()) {
		t.Fatalf("compensation did not reach fenced non-serving state: %+v", domain.applied)
	}
}

func TestCoordinatorWithdrawalRecoveryOutlivesCancelledRequest(t *testing.T) {
	domain := &cancellationAwareDomain{}
	coordinator := NewCoordinator(NewProjector(), domain, NewFileFenceStore(filepath.Join(t.TempDir(), "fences.json")))
	if err := coordinator.UpdateBase(t.Context(), projectorBase(), BaseAuthority{}); err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.ApplyAndReadback(t.Context(), projectorOwnership()); err != nil {
		t.Fatal(err)
	}
	domain.stages = nil
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := coordinator.ApplyAndReadback(cancelled, EffectiveOwnership{}); err != nil {
		t.Fatalf("independent bounded recovery should complete withdrawal: %v", err)
	}
	if !reflect.DeepEqual(domain.stages, withdrawalOrder) {
		t.Fatalf("recovery did not attempt every reverse stage: got=%v want=%v", domain.stages, withdrawalOrder)
	}
}

func TestCoordinatorWithdrawalFailureStillAttemptsEveryReverseStage(t *testing.T) {
	domain := &fakeDomainSurface{}
	coordinator := newTestCoordinator(t, filepath.Join(t.TempDir(), "fences.json"), domain)
	if err := coordinator.UpdateBase(t.Context(), projectorBase(), BaseAuthority{}); err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.ApplyAndReadback(t.Context(), projectorOwnership()); err != nil {
		t.Fatal(err)
	}
	domain.stages = nil
	domain.failStage = StageRoutes
	domain.failOnce = true
	if _, err := coordinator.ApplyAndReadback(t.Context(), EffectiveOwnership{}); err != nil {
		t.Fatalf("complete recovery sweep should heal one-shot reverse failure: %v", err)
	}
	for _, stage := range withdrawalOrder {
		if !containsStage(domain.stages, stage) {
			t.Fatalf("reverse failure skipped stage %s: calls=%v", stage, domain.stages)
		}
	}
}

func TestCoordinatorStartupEmergencyWithdrawalUsesDurableFenceWithoutBase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fences.json")
	fence, err := fenceFor(projectorOwnership())
	if err != nil {
		t.Fatal(err)
	}
	store := NewFileFenceStore(path)
	if err := store.SaveFences(t.Context(), []PoolFence{fence}); err != nil {
		t.Fatal(err)
	}
	domain := &emergencyDomain{fakeDomainSurface: fakeDomainSurface{applied: expectedDomainState(legacyBaseWithOwnership())}}
	coordinator := NewCoordinator(NewProjector(), domain, store)
	if actual, err := coordinator.ApplyAndReadback(t.Context(), EffectiveOwnership{}); err != nil || !isZeroEffective(actual) {
		t.Fatalf("emergency withdrawal actual=%+v err=%v", actual, err)
	}
	if len(domain.fences) != 1 || domain.fences[0].Scope != fence.Scope || !reflect.DeepEqual(domain.applied, AppliedDomainState{}) {
		t.Fatalf("durable emergency classification was not withdrawn: fences=%+v applied=%+v", domain.fences, domain.applied)
	}
}

func TestCoordinatorUpdateBaseAndSnapshotFiltersArmedFenceBeforeNormalReconcile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fences.json")
	base := legacyBaseWithOwnership()
	own := projectorOwnership()
	first := newTestCoordinator(t, path, &fakeDomainSurface{})
	if err := first.UpdateBase(t.Context(), base, BaseAuthority{}); err != nil {
		t.Fatal(err)
	}
	if _, err := first.ApplyAndReadback(t.Context(), own); err != nil {
		t.Fatal(err)
	}
	if _, err := first.ApplyAndReadback(t.Context(), EffectiveOwnership{}); err != nil {
		t.Fatal(err)
	}

	raw := cloneDesiredState(base)
	restarted := newTestCoordinator(t, path, &fakeDomainSurface{})
	snapshot, err := restarted.UpdateBaseAndSnapshot(t.Context(), raw, BaseAuthority{})
	if err != nil {
		t.Fatal(err)
	}
	if contains(routeCIDRs(snapshot.Policy.Routes), own.Routes[0]) {
		t.Fatalf("fenced route escaped into normal reconcile snapshot: %+v", snapshot.Policy.Routes)
	}
	if contains(snapshot.Peers[0].AllowedIPs, own.WGPeers[0].AllowedIPs[0]) ||
		containsVIPMapping(snapshot.Policy.VIPMappings, own.VIPMappings[0]) ||
		containsDNSZone(snapshot.Policy.K8sDNSZones, own.DNSZones[0]) {
		t.Fatalf("fenced Kubernetes state escaped into normal reconcile snapshot: %+v", snapshot)
	}
	if !contains(snapshot.Peers[0].AllowedIPs, "10.99.0.2/32") || !contains(routeCIDRs(snapshot.Policy.Routes), "172.16.0.0/16") ||
		len(snapshot.Policy.VIPMappings) != 1 || snapshot.Policy.VIPMappings[0].ServiceID != "77777777-7777-7777-7777-777777777777" ||
		len(snapshot.Policy.K8sDNSZones) != 1 || snapshot.Policy.K8sDNSZones[0].Zone != "site.example" {
		t.Fatalf("fence filtering removed unrelated ordinary state: %+v", snapshot)
	}
	if !reflect.DeepEqual(raw, base) {
		t.Fatal("snapshot filtering mutated the caller's authoritative base")
	}
}

func TestCoordinatorScopeCompleteClassificationSuppressesChangedBaseValues(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fences.json")
	domain := &fakeDomainSurface{}
	coordinator := newTestCoordinator(t, path, domain)
	base := legacyBaseWithOwnership()
	own := projectorOwnership()
	if err := coordinator.UpdateBase(t.Context(), base, BaseAuthority{}); err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.ApplyAndReadback(t.Context(), own); err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.ApplyAndReadback(t.Context(), EffectiveOwnership{}); err != nil {
		t.Fatal(err)
	}
	changed := cloneEffective(own)
	changed.ManifestRevision++
	changed.LeaseEpoch++
	changed.Routes = []string{"10.45.0.0/16", "100.64.0.9/32"}
	changed.WGPeers[0].AllowedIPs = append([]string(nil), changed.Routes...)
	changed.VIPMappings[0].VIP = "100.64.0.19"
	changed.DNSZones[0].ListenVIP = "100.64.0.9"
	changedBase := projectorBase()
	for _, route := range changed.Routes {
		changedBase.Policy.Routes = append(changedBase.Policy.Routes, nodepolicy.Route{DstCIDR: route})
	}
	changedBase.Peers[0].AllowedIPs = append(changedBase.Peers[0].AllowedIPs, changed.WGPeers[0].AllowedIPs...)
	changedBase.Policy.VIPMappings = append(changedBase.Policy.VIPMappings, changed.VIPMappings...)
	changedBase.Policy.K8sDNSZones = append(changedBase.Policy.K8sDNSZones, changed.DNSZones...)
	scope := PoolScope{OrgID: own.OrgID, SiteID: own.SiteID, ClusterID: own.ClusterID, PoolID: own.PoolID}
	if err := coordinator.UpdateBase(t.Context(), changedBase, BaseAuthority{Classifications: []PoolClassification{{Scope: scope, Ownership: changed}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.ApplyAndReadback(t.Context(), EffectiveOwnership{}); err != nil {
		t.Fatal(err)
	}
	if containsOwnership(domain.applied, changed) {
		t.Fatalf("changed scope-classified values leaked through armed fence: %+v", domain.applied)
	}
}

func TestCoordinatorFullDomainReadbackMismatchCompensatesAndNeverACKs(t *testing.T) {
	tests := map[string]func(*AppliedDomainState){
		"WireGuard": func(actual *AppliedDomainState) { actual.WGPeers = nil },
		"routes":    func(actual *AppliedDomainState) { actual.Routes = nil },
		"return rules": func(actual *AppliedDomainState) {
			actual.ReturnRules = []reconcile.ReturnRule{{Priority: 100, Destination: "10.99.0.0/24", Lookup: "main"}}
		},
		"VIP DNAT":    func(actual *AppliedDomainState) { actual.VIPMappings = nil },
		"DNS zones":   func(actual *AppliedDomainState) { actual.DNSZones = nil },
		"DNS answers": func(actual *AppliedDomainState) { actual.DNSAnswers = nil },
		"DNS VIPs":    func(actual *AppliedDomainState) { actual.DNSVIPs = nil },
		"DNS listener": func(actual *AppliedDomainState) {
			actual.DNSListeners = nil
		},
		"OpenVPN derived routes": func(actual *AppliedDomainState) { actual.OVPN.Routes = nil },
		"OpenVPN process":        func(actual *AppliedDomainState) { actual.OVPN.Serving = false },
		"OpenVPN material":       func(actual *AppliedDomainState) { actual.OVPN.ServerMaterialDigest = "" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			domain := &fakeDomainSurface{mutate: mutate}
			coordinator := newTestCoordinator(t, filepath.Join(t.TempDir(), "fences.json"), domain)
			if err := coordinator.UpdateBase(t.Context(), projectorBase(), BaseAuthority{}); err != nil {
				t.Fatal(err)
			}
			actual, err := coordinator.ApplyAndReadback(t.Context(), projectorOwnership())
			if !errors.Is(err, ErrDomainReadbackMismatch) || !isZeroEffective(actual) {
				t.Fatalf("mismatch actual=%+v err=%v", actual, err)
			}
			if containsOwnership(domain.applied, projectorOwnership()) {
				t.Fatalf("readback mismatch did not compensate: %+v", domain.applied)
			}
		})
	}
}

func TestCanonicalDomainStateCanonicalizesEmptyPeerAllowedIPs(t *testing.T) {
	withNil := canonicalDomainState(AppliedDomainState{WGPeers: []WGAppliedPeer{{PublicKey: "peer"}}})
	withEmpty := canonicalDomainState(AppliedDomainState{WGPeers: []WGAppliedPeer{{PublicKey: "peer", AllowedIPs: []string{}}}})
	if !reflect.DeepEqual(withNil, withEmpty) {
		t.Fatalf("empty peer AllowedIPs must be canonical: nil=%+v empty=%+v", withNil, withEmpty)
	}
}

func TestFileFenceStoreRejectsCorruptionAndDoesNotInferUnfence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fences.json")
	fence, err := fenceFor(projectorOwnership())
	if err != nil {
		t.Fatal(err)
	}
	store := NewFileFenceStore(path)
	if err := store.SaveFences(t.Context(), []PoolFence{fence}); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.LoadFences(t.Context())
	if err != nil || !reflect.DeepEqual(loaded, []PoolFence{fence}) {
		t.Fatalf("fence round trip=%+v err=%v", loaded, err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	b[len(b)/2] ^= 1
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFileFenceStore(path).LoadFences(t.Context()); err == nil {
		t.Fatal("corrupt fence state must not be treated as an empty/unfenced set")
	}
	domain := &fakeDomainSurface{}
	coordinator := newTestCoordinator(t, path, domain)
	if err := coordinator.UpdateBase(t.Context(), legacyBaseWithOwnership(), BaseAuthority{}); err == nil {
		t.Fatal("coordinator must refuse a base when durable fence authority is corrupt")
	}
	if len(domain.stages) != 0 {
		t.Fatalf("corrupt fence authority reached dataplane stages: %v", domain.stages)
	}
}

func TestCurrentProductionAdapterBlockersAreTyped(t *testing.T) {
	err := CurrentProductionAdapterError()
	if !errors.Is(err, ErrProductionAdapterUnavailable) {
		t.Fatalf("production blocker error=%v", err)
	}
	var detail *ProductionAdapterError
	if !errors.As(err, &detail) || len(detail.Missing) != 1 {
		t.Fatalf("production blocker detail=%+v", detail)
	}
	for _, missing := range detail.Missing {
		switch missing {
		case BlockRouteKernelReadback, BlockVIPDNATReadback, BlockDNSVIPReadback, BlockDNSForwarderReadback, BlockOVPNAppliedReadback:
			t.Fatalf("implemented owner readback is still reported missing: %+v", detail.Missing)
		}
	}
}

func count(values []string, want string) int {
	n := 0
	for _, value := range values {
		if value == want {
			n++
		}
	}
	return n
}

func contains(values []string, want string) bool { return count(values, want) > 0 }

func routeCIDRs(values []nodepolicy.Route) []string {
	out := make([]string, len(values))
	for i, value := range values {
		out[i] = value.DstCIDR
	}
	return out
}

func containsStage(values []Stage, want Stage) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func appliedPeerPrefixCount(peers []WGAppliedPeer, publicKey, prefix string) int {
	for _, peer := range peers {
		if peer.PublicKey == publicKey {
			return count(peer.AllowedIPs, prefix)
		}
	}
	return 0
}

func containsOwnership(state AppliedDomainState, own EffectiveOwnership) bool {
	for _, route := range own.Routes {
		if contains(state.Routes, route) {
			return true
		}
	}
	for _, peer := range state.WGPeers {
		for _, ownedPeer := range own.WGPeers {
			if peer.PublicKey == ownedPeer.PublicKey {
				for _, prefix := range ownedPeer.AllowedIPs {
					if contains(peer.AllowedIPs, prefix) {
						return true
					}
				}
			}
		}
	}
	for _, mapping := range state.VIPMappings {
		if containsVIPMapping(own.VIPMappings, mapping) {
			return true
		}
	}
	for _, zone := range state.DNSZones {
		if containsDNSZone(own.DNSZones, zone) {
			return true
		}
	}
	return false
}
