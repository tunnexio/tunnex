package ownershiplease

import (
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tunnexio/tunnex/apps/node/internal/nodepolicy"
	"github.com/tunnexio/tunnex/apps/node/internal/reconcile"
)

func TestPendingBaseCursorPinKeepsExactAuthorityAndAck(t *testing.T) {
	dir := t.TempDir()
	fenceStore := NewFileFenceStore(filepath.Join(dir, "fences.json"))
	authorityStore := NewFileBaseAuthorityStateStore(filepath.Join(dir, "authority.json"))
	domain := &fakeDomainSurface{}
	coordinator := NewCoordinator(NewProjector(), domain, fenceStore).WithBaseAuthorityStateStore(authorityStore)
	base := legacyBaseWithOwnership()
	base.Version = 10
	if err := coordinator.UpdateBase(t.Context(), base, authorityFor(t, base, 1, PoolClassificationArmFence)); err != nil {
		t.Fatal(err)
	}

	// The CP has already issued this immutable authority at cursor 20. A wake
	// advances the captured response cursor to 40 without changing base bytes;
	// serving cursor 20 again must not relax the node's exact binding checks.
	pendingBase := cloneDesiredState(base)
	pendingBase.Version = 20
	pending := authorityFor(t, pendingBase, 2, PoolClassificationMaintainFence)
	captured := cloneDesiredState(pendingBase)
	captured.Version = 40
	if hash, err := BaseStateHash(captured); err != nil || hash != pending.BaseHash {
		t.Fatalf("cursor-only response changed full base hash: hash=%s error=%v", hash, err)
	}
	pinned := cloneDesiredState(captured)
	pinned.Version = pending.BaseVersion
	pinned = baseWithWireAuthority(t, pinned, pending)
	if _, err := coordinator.UpdateBaseAndSnapshot(t.Context(), pinned, BaseAuthorityFromWire(pinned.KubernetesOwnershipBaseAuthority)); err != nil {
		t.Fatalf("exact pending response refused: %v", err)
	}
	if err := coordinator.ReconcileCurrent(t.Context()); err != nil {
		t.Fatal(err)
	}
	appliedAt := time.Date(2026, 9, 6, 3, 0, 0, 0, time.UTC)
	ack, ready, err := coordinator.PrepareBaseAuthorityAck(t.Context(), pinned, appliedAt)
	if err != nil || !ready || ack.AuthorityRevision != pending.AuthorityRevision || ack.BaseVersion != pending.BaseVersion || ack.BaseHash != pending.BaseHash {
		t.Fatalf("receipt did not preserve pending tuple: ack=%+v ready=%t error=%v", ack, ready, err)
	}
	_, digest, err := canonicalBaseAuthority(pinned, pending)
	if err != nil || ack.AuthorityDigest != digest {
		t.Fatalf("receipt changed immutable authority digest: digest=%s error=%v", ack.AuthorityDigest, err)
	}
	if ack.BaseVersion == captured.Version {
		t.Fatal("receipt was relabelled with the newer notification cursor")
	}
	if err := coordinator.MarkBaseAuthorityAckDelivered(t.Context(), ack); err != nil {
		t.Fatal(err)
	}
	wantFences := coordinator.projector.Fences()
	wantState, found, err := authorityStore.LoadBaseAuthorityState(t.Context())
	if err != nil || !found {
		t.Fatalf("read durable authority: found=%t error=%v", found, err)
	}
	for _, tc := range []struct {
		name   string
		change func(*reconcile.DesiredState)
	}{
		{"wrong response version", func(value *reconcile.DesiredState) { value.Version++ }},
		{"wrong authority hash", func(value *reconcile.DesiredState) {
			value.KubernetesOwnershipBaseAuthority.BaseHash = strings.Repeat("0", 64)
		}},
		{"changed base bytes", func(value *reconcile.DesiredState) { value.MTU++ }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := cloneDesiredState(pinned)
			tc.change(&bad)
			if err := coordinator.UpdateBase(t.Context(), bad, BaseAuthorityFromWire(bad.KubernetesOwnershipBaseAuthority)); !errors.Is(err, ErrBaseAuthorityInvalid) {
				t.Fatalf("mismatched pending authority error=%v", err)
			}
			if _, ready, err := coordinator.PrepareBaseAuthorityAck(t.Context(), bad, appliedAt.Add(time.Second)); !errors.Is(err, ErrBaseAuthorityInvalid) || ready {
				t.Fatalf("mismatch produced a receipt: ready=%t error=%v", ready, err)
			}
			state, found, err := authorityStore.LoadBaseAuthorityState(t.Context())
			if err != nil || !found || !reflect.DeepEqual(state, wantState) || !reflect.DeepEqual(coordinator.projector.Fences(), wantFences) {
				t.Fatalf("refused mismatch changed durable authority/fences: found=%t error=%v", found, err)
			}
		})
	}
	// Once the original receipt has landed, an ordinary response resumes the
	// current cursor without another authority or an inferred unfence.
	restored, err := coordinator.UpdateBaseAndSnapshot(t.Context(), captured, BaseAuthority{})
	if err != nil || restored.Version != captured.Version || containsOwnership(expectedDomainState(restored), projectorOwnership()) {
		t.Fatalf("current cursor did not preserve the armed fence: version=%d error=%v", restored.Version, err)
	}
}

func TestPendingBaseCursorPinConservativelyRetainsUnrelatedReleasedFence(t *testing.T) {
	dir := t.TempDir()
	fenceStore := NewFileFenceStore(filepath.Join(dir, "fences.json"))
	domain := &fakeDomainSurface{}
	coordinator := NewCoordinator(NewProjector(), domain, fenceStore).
		WithBaseAuthorityStateStore(NewFileBaseAuthorityStateStore(filepath.Join(dir, "authority.json")))
	base := legacyBaseWithOwnership()
	base.Version = 10
	other := projectorOwnership()
	other.PoolID = "88888888-8888-8888-8888-888888888888"
	other.Routes = []string{"172.16.0.0/16", "100.64.1.2/32"}
	other.WGPeers = []WGPeerOwnership{{PublicKey: projectorPeerB, AllowedIPs: append([]string(nil), other.Routes...)}}
	other.VIPMappings = append([]nodepolicy.VIPMapping(nil), base.Policy.VIPMappings[:1]...)
	other.DNSZones = append([]nodepolicy.K8sDNSZone(nil), base.Policy.K8sDNSZones[:1]...)
	base.Policy.Routes = append(base.Policy.Routes, nodepolicy.Route{DstCIDR: other.Routes[1]})
	base.Peers[1].AllowedIPs = append(base.Peers[1].AllowedIPs, other.Routes...)
	otherScope := PoolScope{OrgID: other.OrgID, SiteID: other.SiteID, ClusterID: other.ClusterID, PoolID: other.PoolID}
	arm := authorityFor(t, base, 1, PoolClassificationArmFence)
	arm.Classifications = append(arm.Classifications, PoolClassification{
		Scope: otherScope, Disposition: PoolClassificationArmFence,
		Fields: PoolOwnedBaseFields{Routes: other.Routes, WGPeers: other.WGPeers, VIPMappings: other.VIPMappings, DNSZones: other.DNSZones},
	})
	if err := coordinator.UpdateBase(t.Context(), base, arm); err != nil {
		t.Fatal(err)
	}
	releasedBase := cloneDesiredState(base)
	releasedBase.Version = 30
	release := authorityFor(t, releasedBase, 2, PoolClassificationMaintainFence)
	release.UnfencedPools = []PoolScope{otherScope}
	if err := coordinator.UpdateBase(t.Context(), releasedBase, release); err != nil {
		t.Fatalf("explicit unrelated-pool release: %v", err)
	}
	captured := cloneDesiredState(base)
	captured.Version = 40
	wantCurrent, err := coordinator.UpdateBaseAndSnapshot(t.Context(), captured, BaseAuthority{})
	if err != nil || !containsOwnership(expectedDomainState(wantCurrent), other) || containsOwnership(expectedDomainState(wantCurrent), projectorOwnership()) {
		t.Fatalf("initial released/armed projection incorrect: error=%v", err)
	}
	wantFences := coordinator.projector.Fences()

	// Deliberately place the pending cursor below the unrelated release marker.
	// This is a conservative projection edge, not permission to reset that marker
	// or to treat an earlier watch cursor as a newer explicit unfence.
	pinned := cloneDesiredState(captured)
	pinned.Version = 20
	pending := authorityFor(t, pinned, 3, PoolClassificationMaintainFence)
	pinned = baseWithWireAuthority(t, pinned, pending)
	closed, err := coordinator.UpdateBaseAndSnapshot(t.Context(), pinned, pending)
	if err != nil {
		t.Fatal(err)
	}
	if containsOwnership(expectedDomainState(closed), other) || containsOwnership(expectedDomainState(closed), projectorOwnership()) {
		t.Fatal("earlier pending cursor reopened fenced ownership")
	}
	if err := coordinator.ReconcileCurrent(t.Context()); err != nil {
		t.Fatal(err)
	}
	ack, ready, err := coordinator.PrepareBaseAuthorityAck(t.Context(), pinned, time.Date(2026, 9, 6, 3, 1, 0, 0, time.UTC))
	if err != nil || !ready || ack.BaseVersion != pinned.Version || ack.BaseHash != pending.BaseHash {
		t.Fatalf("exact closed projection receipt: ready=%t ack=%+v error=%v", ready, ack, err)
	}
	if err := coordinator.MarkBaseAuthorityAckDelivered(t.Context(), ack); err != nil {
		t.Fatal(err)
	}
	for _, fence := range coordinator.projector.Fences() {
		if fence.Scope == otherScope {
			for _, original := range wantFences {
				if original.Scope == otherScope && !reflect.DeepEqual(fence, original) {
					t.Fatal("pending cursor mutated the unrelated durable release marker")
				}
			}
		}
	}
	restored, err := coordinator.UpdateBaseAndSnapshot(t.Context(), captured, BaseAuthority{})
	if err != nil || !reflect.DeepEqual(restored, wantCurrent) {
		t.Fatalf("current ordinary cursor did not restore exact prior projection: error=%v", err)
	}
	if err := coordinator.ReconcileCurrent(t.Context()); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(domain.applied, expectedDomainState(wantCurrent)) {
		t.Fatal("current-cursor convergence failed to restore the released pool")
	}
}
