package ownershiplease

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tunnexio/tunnex/apps/node/internal/fqdnrpc"
	"github.com/tunnexio/tunnex/apps/node/internal/nodepolicy"
	"github.com/tunnexio/tunnex/apps/node/internal/reconcile"
)

func authorityFor(t *testing.T, base reconcile.DesiredState, revision uint64, disposition PoolClassificationDisposition) BaseAuthority {
	t.Helper()
	hash, err := BaseStateHash(base)
	if err != nil {
		t.Fatal(err)
	}
	own := projectorOwnership()
	return BaseAuthority{
		WireVersion: reconcile.KubernetesOwnershipBaseAuthorityWireVersion, AuthorityRevision: revision,
		NodeID: base.NodeID, OrgID: own.OrgID, SiteID: own.SiteID, BaseVersion: base.Version, BaseHash: hash,
		Classifications: []PoolClassification{{
			Scope:       PoolScope{OrgID: own.OrgID, SiteID: own.SiteID, ClusterID: own.ClusterID, PoolID: own.PoolID},
			Disposition: disposition,
			Fields: PoolOwnedBaseFields{Routes: append([]string(nil), own.Routes...), WGPeers: append([]WGPeerOwnership(nil), own.WGPeers...),
				VIPMappings: append([]nodepolicy.VIPMapping(nil), own.VIPMappings...), DNSZones: append([]nodepolicy.K8sDNSZone(nil), own.DNSZones...)},
		}},
	}
}

func baseWithWireAuthority(t *testing.T, base reconcile.DesiredState, authority BaseAuthority) reconcile.DesiredState {
	t.Helper()
	value := reconcile.KubernetesOwnershipBaseAuthority{
		WireVersion: authority.WireVersion, AuthorityRevision: authority.AuthorityRevision, NodeID: authority.NodeID,
		OrgID: authority.OrgID, SiteID: authority.SiteID, BaseVersion: authority.BaseVersion, BaseHash: authority.BaseHash,
	}
	for _, item := range authority.Classifications {
		fields := reconcile.KubernetesOwnershipPoolFields{Routes: append([]string(nil), item.Fields.Routes...), VIPMappings: append([]nodepolicy.VIPMapping(nil), item.Fields.VIPMappings...), DNSZones: append([]nodepolicy.K8sDNSZone(nil), item.Fields.DNSZones...)}
		for _, peer := range item.Fields.WGPeers {
			fields.WGPeers = append(fields.WGPeers, reconcile.KubernetesOwnershipWGPeer{PublicKey: peer.PublicKey, AllowedIPs: append([]string(nil), peer.AllowedIPs...)})
		}
		value.Classifications = append(value.Classifications, reconcile.KubernetesOwnershipPoolClassification{
			Scope:       reconcile.KubernetesOwnershipPoolScope{OrgID: item.Scope.OrgID, SiteID: item.Scope.SiteID, ClusterID: item.Scope.ClusterID, PoolID: item.Scope.PoolID},
			Disposition: reconcile.KubernetesOwnershipPoolDisposition(item.Disposition), Fields: fields,
		})
	}
	for _, scope := range authority.UnfencedPools {
		value.UnfencedPools = append(value.UnfencedPools, reconcile.KubernetesOwnershipPoolScope{OrgID: scope.OrgID, SiteID: scope.SiteID, ClusterID: scope.ClusterID, PoolID: scope.PoolID})
	}
	base.KubernetesOwnershipBaseAuthority = &value
	return base
}

func TestBaseStateHashExcludesAuthorityAndTransientDNSRequest(t *testing.T) {
	base := projectorBase()
	want, err := BaseStateHash(base)
	if err != nil {
		t.Fatal(err)
	}
	base.DNSResolveRequest = &fqdnrpc.Request{Version: 1, RequestID: "different"}
	base.KubernetesOwnershipBaseAuthority = &reconcile.KubernetesOwnershipBaseAuthority{WireVersion: 99, AuthorityRevision: 88}
	got, err := BaseStateHash(base)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("transient/security envelope changed ordinary-base hash: got=%s want=%s", got, want)
	}
	base.MTU++
	changed, err := BaseStateHash(base)
	if err != nil {
		t.Fatal(err)
	}
	if changed == want {
		t.Fatal("ordinary data-plane change did not change base hash")
	}
}

func TestBaseStateHashMatchesControlPlaneCrossRuntimeGolden(t *testing.T) {
	base := reconcile.DesiredState{ProtocolVersion: 9, NodeID: "99999999-9999-9999-9999-999999999999", InterfaceAddress: "10.99.0.1/24", MTU: 1380, ListenPort: 51820, Version: 17,
		Peers: []reconcile.Peer{}, OVPNEnabled: true, OVPNClients: []reconcile.OVPNClient{{CommonName: "alice", IP: "10.99.0.20", FullTunnel: true}}}
	got, err := BaseStateHash(base)
	if err != nil {
		t.Fatal(err)
	}
	const want = "ad039cb612f05abdf22eae00d3fe6bb5102c333ddc5fbb3a98d4b4b94e9d7e67"
	if got != want {
		t.Fatalf("base digest=%s want=%s", got, want)
	}
}

func TestBaseAuthorityFingerprintMatchesWireV1CrossRuntimeGolden(t *testing.T) {
	value := BaseAuthority{
		Present: true, WireVersion: 1, AuthorityRevision: 7,
		NodeID: "99999999-9999-9999-9999-999999999999", OrgID: "11111111-1111-1111-1111-111111111111", SiteID: "22222222-2222-2222-2222-222222222222",
		BaseVersion: 17, BaseHash: strings.Repeat("a", 64),
		Classifications: []PoolClassification{{
			Scope:       PoolScope{OrgID: "11111111-1111-1111-1111-111111111111", SiteID: "22222222-2222-2222-2222-222222222222", ClusterID: "33333333-3333-3333-3333-333333333333", PoolID: "44444444-4444-4444-4444-444444444444"},
			Disposition: PoolClassificationArmFence,
			Fields: PoolOwnedBaseFields{Routes: []string{"10.44.0.0/16", "100.64.0.2/32"}, WGPeers: []WGPeerOwnership{{PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", AllowedIPs: []string{"10.44.0.0/16", "100.64.0.2/32"}}},
				VIPMappings: []nodepolicy.VIPMapping{{ServiceID: "66666666-6666-6666-6666-666666666666", VIP: "100.64.0.10", Namespace: "default", Service: "api", ServiceCIDR: "10.96.0.0/12", Protocol: "tcp", PortLow: 443, PortHigh: 443, DNSName: "api.default.svc.cluster.example"}},
				DNSZones:    []nodepolicy.K8sDNSZone{{ListenVIP: "100.64.0.2", Zone: "cluster.example"}}},
		}},
		UnfencedPools: []PoolScope{},
	}
	got, err := baseAuthorityFingerprint(value)
	if err != nil {
		t.Fatal(err)
	}
	const want = "3869701fc1d1578083ce0e70078d40413db2516e84a9d08c2b11155303da1db2"
	if got != want {
		t.Fatalf("wire-v1 digest=%s want=%s", got, want)
	}
}

func TestCoordinatorAuthorityReplayAndStandbyFence(t *testing.T) {
	dir := t.TempDir()
	base := projectorBase()
	authority := authorityFor(t, base, 7, PoolClassificationArmFence)
	domain := &fakeDomainSurface{}
	coordinator := NewCoordinator(NewProjector(), domain, NewFileFenceStore(filepath.Join(dir, "fences.json"))).
		WithBaseAuthorityStateStore(NewFileBaseAuthorityStateStore(filepath.Join(dir, "authority.json")))
	if _, err := coordinator.UpdateBaseAndSnapshot(t.Context(), base, authority); err != nil {
		t.Fatal(err)
	}
	fences := coordinator.projector.Fences()
	if len(fences) != 1 || fences[0].Scope.PoolID != projectorOwnership().PoolID {
		t.Fatalf("standby arm did not create exact durable fence: %+v", fences)
	}
	if !reflect.DeepEqual(fences[0].Suppressed.Routes, projectorOwnership().Routes) {
		t.Fatalf("standby tombstone lost pool fields: %+v", fences[0])
	}
	if _, err := coordinator.UpdateBaseAndSnapshot(t.Context(), base, authority); err != nil {
		t.Fatalf("exact replay must be idempotent: %v", err)
	}
	stale := authority
	stale.AuthorityRevision--
	if err := coordinator.UpdateBase(t.Context(), base, stale); !errors.Is(err, ErrBaseAuthorityStale) {
		t.Fatalf("stale err=%v", err)
	}
	changed := authority
	changed.Classifications = append([]PoolClassification(nil), authority.Classifications...)
	changed.Classifications[0].Disposition = PoolClassificationMaintainFence
	if err := coordinator.UpdateBase(t.Context(), base, changed); !errors.Is(err, ErrBaseAuthorityChangedReplay) {
		t.Fatalf("changed replay err=%v", err)
	}
	newer := authority
	newer.AuthorityRevision++
	newer.Classifications = append([]PoolClassification(nil), authority.Classifications...)
	newer.Classifications[0].Disposition = PoolClassificationMaintainFence
	if err := coordinator.UpdateBase(t.Context(), base, newer); err != nil {
		t.Fatalf("newer maintain authority: %v", err)
	}
}

func TestPresentAllZeroAuthorityIsNotLegacyAbsence(t *testing.T) {
	coordinator := NewCoordinator(NewProjector(), &fakeDomainSurface{}, NewFileFenceStore(filepath.Join(t.TempDir(), "fences.json")))
	if err := coordinator.UpdateBase(t.Context(), projectorBase(), BaseAuthority{Present: true}); !errors.Is(err, ErrBaseAuthorityInvalid) {
		t.Fatalf("present malformed authority err=%v", err)
	}
}

func TestAuthorityAcceptedBeforeFencePersistenceAndNoAckOnMismatch(t *testing.T) {
	dir := t.TempDir()
	base := projectorBase()
	authority := authorityFor(t, base, 3, PoolClassificationArmFence)
	authorityStore := NewFileBaseAuthorityStateStore(filepath.Join(dir, "authority.json"))
	coordinator := NewCoordinator(NewProjector(), &fakeDomainSurface{}, &failingFenceStore{fail: true}).WithBaseAuthorityStateStore(authorityStore)
	if err := coordinator.UpdateBase(t.Context(), base, authority); err == nil {
		t.Fatal("expected injected fence persistence failure")
	}
	state, found, err := authorityStore.LoadBaseAuthorityState(t.Context())
	if err != nil || !found || state.AuthorityRevision != authority.AuthorityRevision {
		t.Fatalf("authority was not durable before fence/base apply: state=%+v found=%v err=%v", state, found, err)
	}

	goodStore := NewFileBaseAuthorityStateStore(filepath.Join(dir, "authority-2.json"))
	domain := &fakeDomainSurface{}
	coordinator = NewCoordinator(NewProjector(), domain, NewFileFenceStore(filepath.Join(dir, "fences.json"))).WithBaseAuthorityStateStore(goodStore)
	base = baseWithWireAuthority(t, base, authority)
	if _, err := coordinator.UpdateBaseAndSnapshot(t.Context(), base, authority); err != nil {
		t.Fatal(err)
	}
	if _, ready, err := coordinator.PrepareBaseAuthorityAck(t.Context(), base, time.Now()); !errors.Is(err, ErrDomainReadbackMismatch) || ready {
		t.Fatalf("unapplied readback produced receipt: ready=%v err=%v", ready, err)
	}
	state, found, err = goodStore.LoadBaseAuthorityState(t.Context())
	if err != nil || !found || state.PendingAck != nil {
		t.Fatalf("mismatch persisted ACK: state=%+v found=%v err=%v", state, found, err)
	}
}

func TestBaseAuthorityAckPersistsAndReplaysAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	fencePath := filepath.Join(dir, "fences.json")
	authorityPath := filepath.Join(dir, "authority.json")
	base := projectorBase()
	authority := authorityFor(t, base, 11, PoolClassificationArmFence)
	base = baseWithWireAuthority(t, base, authority)
	domain := &fakeDomainSurface{}
	coordinator := NewCoordinator(NewProjector(), domain, NewFileFenceStore(fencePath)).WithBaseAuthorityStateStore(NewFileBaseAuthorityStateStore(authorityPath))
	effective, err := coordinator.UpdateBaseAndSnapshot(t.Context(), base, authority)
	if err != nil {
		t.Fatal(err)
	}
	for _, stage := range activationOrder {
		if err := domain.ApplyStage(t.Context(), stage, effective); err != nil {
			t.Fatal(err)
		}
	}
	appliedAt := time.Date(2026, 8, 28, 10, 11, 12, 345, time.UTC)
	ack, ready, err := coordinator.PrepareBaseAuthorityAck(t.Context(), base, appliedAt)
	if err != nil || !ready {
		t.Fatalf("prepare ack=%+v ready=%v err=%v", ack, ready, err)
	}

	restarted := NewCoordinator(NewProjector(), domain, NewFileFenceStore(fencePath)).WithBaseAuthorityStateStore(NewFileBaseAuthorityStateStore(authorityPath))
	if _, err := restarted.UpdateBaseAndSnapshot(t.Context(), base, authority); err != nil {
		t.Fatal(err)
	}
	replayed, ready, err := restarted.PrepareBaseAuthorityAck(t.Context(), base, appliedAt.Add(time.Hour))
	if err != nil || !ready || !reflect.DeepEqual(replayed, ack) {
		t.Fatalf("restart replay=%+v want=%+v ready=%v err=%v", replayed, ack, ready, err)
	}
	if err := restarted.MarkBaseAuthorityAckDelivered(t.Context(), replayed); err != nil {
		t.Fatal(err)
	}
	state, found, err := NewFileBaseAuthorityStateStore(authorityPath).LoadBaseAuthorityState(t.Context())
	if err != nil || !found || state.PendingAck != nil {
		t.Fatalf("delivered ACK checkpoint state=%+v found=%v err=%v", state, found, err)
	}
}

func TestExplicitUnfenceRequiresNewExactAuthorityAndNoActiveLease(t *testing.T) {
	dir := t.TempDir()
	coordinator := NewCoordinator(NewProjector(), &fakeDomainSurface{}, NewFileFenceStore(filepath.Join(dir, "fences.json"))).
		WithBaseAuthorityStateStore(NewFileBaseAuthorityStateStore(filepath.Join(dir, "authority.json")))
	base := projectorBase()
	arm := authorityFor(t, base, 1, PoolClassificationArmFence)
	if err := coordinator.UpdateBase(t.Context(), base, arm); err != nil {
		t.Fatal(err)
	}
	unfenceBase := base
	unfenceBase.Version++
	hash, err := BaseStateHash(unfenceBase)
	if err != nil {
		t.Fatal(err)
	}
	scope := arm.Classifications[0].Scope
	unfence := BaseAuthority{WireVersion: reconcile.KubernetesOwnershipBaseAuthorityWireVersion, AuthorityRevision: 2,
		NodeID: unfenceBase.NodeID, OrgID: scope.OrgID, SiteID: scope.SiteID, BaseVersion: unfenceBase.Version, BaseHash: hash, UnfencedPools: []PoolScope{scope}}
	if err := coordinator.UpdateBase(t.Context(), unfenceBase, unfence); err != nil {
		t.Fatal(err)
	}
	fences := coordinator.projector.Fences()
	if len(fences) != 1 || fences[0].ReleasedAtBaseVersion != unfenceBase.Version || fences[0].ReleasedAtBaseHash != hash {
		t.Fatalf("explicit unfence was not exact/durable: %+v", fences)
	}
}

func TestFileFenceStoreReadsLegacyV1WithoutLeaseMetadataInV2Fence(t *testing.T) {
	own := projectorOwnership()
	legacy := []legacyPoolFence{{
		Version:    legacyFenceVersion,
		Scope:      PoolScope{OrgID: own.OrgID, SiteID: own.SiteID, ClusterID: own.ClusterID, PoolID: own.PoolID},
		Suppressed: own,
	}}
	payload, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(payload)
	fileBytes, err := json.Marshal(legacyFenceFile{Version: legacyFenceVersion, Fences: legacy, Checksum: hex.EncodeToString(sum[:])})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "fences.json")
	if err := os.WriteFile(path, fileBytes, 0600); err != nil {
		t.Fatal(err)
	}
	fences, err := NewFileFenceStore(path).LoadFences(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(fences) != 1 || fences[0].Version != FenceVersion || !reflect.DeepEqual(fences[0].Suppressed.Routes, own.Routes) {
		t.Fatalf("converted fences=%+v", fences)
	}
	converted, err := json.Marshal(fences[0].Suppressed)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(converted), "lease_epoch") || strings.Contains(string(converted), "connector_node_id") {
		t.Fatalf("v2 fence retained serving lease identity: %s", converted)
	}
}
