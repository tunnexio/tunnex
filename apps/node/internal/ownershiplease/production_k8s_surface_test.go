package ownershiplease

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/tunnexio/tunnex/apps/node/internal/dnsforward"
	"github.com/tunnexio/tunnex/apps/node/internal/egress"
	"github.com/tunnexio/tunnex/apps/node/internal/nodepolicy"
	"github.com/tunnexio/tunnex/apps/node/internal/ovpnserver"
	"github.com/tunnexio/tunnex/apps/node/internal/reconcile"
)

type fakeProductionEgress struct {
	policy        *nodepolicy.Compiled
	requested     []egress.K8sDNATReceipt
	dnatObserved  []string
	dnsObserved   []string
	dnsCandidates []string
	dnsErr        error
	dnatErr       error
	reconcileErr  error
	resolved      int
	emergency     int
	emergencyVIPs []string
	ovpnTun       string
}

func (f *fakeProductionEgress) EmergencyWithdrawK8s(ctx context.Context, candidates []string) error {
	f.emergency++
	f.emergencyVIPs = append([]string(nil), candidates...)
	f.policy = nil
	f.dnsObserved = nil
	f.dnatObserved = nil
	return nil
}

func TestProductionStartupWithoutLeaseOrFenceStillRunsEmergencyK8sSweep(t *testing.T) {
	fenceStore := NewFileFenceStore(filepath.Join(t.TempDir(), "fences.json"))
	egressOwner := &fakeProductionEgress{policy: productionDesired().Policy, dnsObserved: []string{"100.64.0.2"}}
	dnsOwner := &fakeProductionDNS{state: dnsforward.AppliedK8sState{
		Answers: []dnsforward.K8sEntry{{FQDN: "api.default.cluster.example", VIP: "100.64.0.10"}},
		Zones:   []string{"cluster.example"}, Listeners: []string{"100.64.0.2"},
	}}
	surface, err := NewProductionK8sSurface(&fakeDomainSurface{}, egressOwner, dnsOwner, fenceStore, "wg0")
	if err != nil {
		t.Fatal(err)
	}
	coordinator := NewCoordinator(NewProjector(), surface, fenceStore)
	lifecycle := New(coordinator, NewFileStateStore(filepath.Join(t.TempDir(), "ownership.json")))
	if err := lifecycle.StartupReconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	if egressOwner.emergency != 1 || len(egressOwner.emergencyVIPs) != 0 {
		t.Fatalf("no-fence startup emergency sweep calls=%d candidates=%v", egressOwner.emergency, egressOwner.emergencyVIPs)
	}
	if egressOwner.policy != nil || len(egressOwner.dnsObserved) != 0 || len(egressOwner.dnatObserved) != 0 {
		t.Fatalf("no-fence startup did not clear enumerable Kubernetes egress residue: %+v", egressOwner)
	}
	if dnsOwner.reconciles != 1 || len(dnsOwner.state.Answers) != 0 || len(dnsOwner.state.Zones) != 0 || len(dnsOwner.state.Listeners) != 0 {
		t.Fatalf("no-fence startup did not withdraw DNS answers/listeners: %+v", dnsOwner)
	}
}

func TestProductionStartupWithdrawsUnexpiredLeaseBeforeFirstBase(t *testing.T) {
	fenceStore := NewFileFenceStore(filepath.Join(t.TempDir(), "fences.json"))
	fence, err := fenceFor(projectorOwnership())
	if err != nil {
		t.Fatal(err)
	}
	if err := fenceStore.SaveFences(t.Context(), []PoolFence{fence}); err != nil {
		t.Fatal(err)
	}
	egOwner := &fakeProductionEgress{policy: productionDesired().Policy, dnsObserved: []string{"100.64.0.2"}}
	dnsOwner := &fakeProductionDNS{state: dnsforward.AppliedK8sState{
		Answers: []dnsforward.K8sEntry{{FQDN: "api.default.cluster.example", VIP: "100.64.0.10"}},
		Zones:   []string{"cluster.example"}, Listeners: []string{"100.64.0.2"},
	}}
	surface, err := NewProductionK8sSurface(&fakeDomainSurface{}, egOwner, dnsOwner, fenceStore, "wg0")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	leaseStore := NewFileStateStore(filepath.Join(t.TempDir(), "ownership.json"))
	if err := leaseStore.Save(t.Context(), State{Version: StateVersion, Grant: Grant{
		Effective: projectorOwnership(), LeaseExpiresAt: now.Add(time.Hour),
	}, LastWallTime: now.Add(-time.Second)}); err != nil {
		t.Fatal(err)
	}
	lifecycle := New(NewCoordinator(NewProjector(), surface, fenceStore), leaseStore)
	if err := lifecycle.StartupReconcile(t.Context()); err != nil {
		t.Fatalf("startup must recover after proven emergency withdrawal: %v", err)
	}
	if egOwner.emergency != 1 {
		t.Fatalf("startup emergency withdrawal calls=%d, want 1", egOwner.emergency)
	}
	if _, found, err := leaseStore.Load(t.Context()); err != nil || found {
		t.Fatalf("withdrawn startup lease remains durable: found=%v err=%v", found, err)
	}
}

func (f *fakeProductionEgress) SetPolicy(policy *nodepolicy.Compiled) { f.policy = policy }
func (f *fakeProductionEgress) ResolveK8sVIPs(context.Context)        { f.resolved++ }
func (f *fakeProductionEgress) ReconcileDNSVIPsWithCandidates(_ context.Context, values []string) error {
	f.dnsCandidates = append([]string(nil), values...)
	return f.dnsErr
}
func (f *fakeProductionEgress) Reconcile(context.Context) (bool, bool, error) {
	return true, true, f.reconcileErr
}
func (f *fakeProductionEgress) RequestedK8sDNATReceipts() []egress.K8sDNATReceipt {
	return append([]egress.K8sDNATReceipt(nil), f.requested...)
}
func (f *fakeProductionEgress) ReadK8sDNATReceiptDigests(context.Context) ([]string, error) {
	return append([]string(nil), f.dnatObserved...), f.dnatErr
}
func (f *fakeProductionEgress) ReadDNSVIPs(context.Context, []string) ([]string, error) {
	return append([]string(nil), f.dnsObserved...), nil
}
func (f *fakeProductionEgress) SetOVPNTun(value string) { f.ovpnTun = value }
func (f *fakeProductionEgress) AppliedOVPNTun() string  { return f.ovpnTun }
func (f *fakeProductionEgress) ReconcileOVPNTunnel(_ context.Context, value string) error {
	f.ovpnTun = value
	return f.reconcileErr
}
func (f *fakeProductionEgress) ReadAppliedOVPNTunnel(context.Context) (string, error) {
	return f.ovpnTun, nil
}

type fakeProductionDNS struct {
	state      dnsforward.AppliedK8sState
	reconciles int
}

type fakeProductionOVPN struct {
	desired                  ovpnserver.Desired
	process                  ovpnserver.ProcessState
	material                 *reconcile.OVPNServerMaterial
	stopErrWhenDesiredAbsent error
}

func (f *fakeProductionOVPN) SetDesired(value ovpnserver.Desired) { f.desired = value }
func (f *fakeProductionOVPN) WriteServerMaterial(ca, cert, key, crl string) error {
	f.material = &reconcile.OVPNServerMaterial{CA: ca, Cert: cert, Key: key, CRL: crl}
	return nil
}
func (f *fakeProductionOVPN) Reconcile(context.Context) error {
	if f.desired.PoolCIDR == "" {
		if f.stopErrWhenDesiredAbsent != nil {
			return f.stopErrWhenDesiredAbsent
		}
		f.process = ovpnserver.ProcessState{}
	} else {
		digest, _ := ovpnserver.DesiredDigest(f.desired)
		f.process = ovpnserver.ProcessState{Serving: true, AppliedDigest: "artifact-digest", DesiredDigest: digest}
	}
	return nil
}
func (f *fakeProductionOVPN) AppliedState() (ovpnserver.ProcessState, error) { return f.process, nil }
func (f *fakeProductionOVPN) TunActive() bool                                { return f.process.Serving }
func (f *fakeProductionOVPN) TunName() string                                { return ovpnserver.TunName }

func (f *fakeProductionDNS) SetK8sAnswers(entries []dnsforward.K8sEntry, zones []string) {
	f.state.Answers = append([]dnsforward.K8sEntry(nil), entries...)
	f.state.Zones = append([]string(nil), zones...)
}
func (f *fakeProductionDNS) ReconcileK8sBinds(context.Context, string) {
	f.reconciles++
	if len(f.state.Zones) == 0 {
		f.state.Listeners = nil
	}
}
func (f *fakeProductionDNS) AppliedK8sState() dnsforward.AppliedK8sState {
	out := f.state
	out.Answers = append([]dnsforward.K8sEntry(nil), f.state.Answers...)
	out.Zones = append([]string(nil), f.state.Zones...)
	out.Listeners = append([]string(nil), f.state.Listeners...)
	return out
}

func productionDesired() reconcile.DesiredState {
	desired := projectorBase()
	desired.OVPNEnabled = false
	desired.OVPNClients = nil
	desired.OVPNServer = nil
	return desired
}

func TestProductionK8sSurfaceUsesExistingOwnersAndReplacesDesiredEcho(t *testing.T) {
	desired := productionDesired()
	wantDigest := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	egressOwner := &fakeProductionEgress{
		requested:    []egress.K8sDNATReceipt{{VIP: desired.Policy.VIPMappings[0].VIP, Digest: wantDigest}},
		dnatObserved: []string{wantDigest},
		dnsObserved:  []string{desired.Policy.K8sDNSZones[0].ListenVIP},
	}
	dnsOwner := &fakeProductionDNS{}
	dnsOwner.state.Listeners = []string{desired.Policy.K8sDNSZones[0].ListenVIP, desired.InterfaceAddress[:len("10.99.0.1")]}
	delegate := &fakeDomainSurface{applied: AppliedDomainState{
		VIPMappings: []nodepolicy.VIPMapping{{VIP: "192.0.2.10"}},
		DNSVIPs:     []string{"192.0.2.2"}, DNSListeners: []string{"192.0.2.2"},
	}}
	store := NewFileFenceStore(filepath.Join(t.TempDir(), "fences.json"))
	surface, err := NewProductionK8sSurface(delegate, egressOwner, dnsOwner, store, "wg0")
	if err != nil {
		t.Fatal(err)
	}
	if err := surface.ApplyStage(t.Context(), StageDNS, desired); err != nil {
		t.Fatal(err)
	}
	if err := surface.ApplyStage(t.Context(), StageDNAT, desired); err != nil {
		t.Fatal(err)
	}
	actual, err := surface.Readback(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	want := expectedDomainState(desired)
	if !reflect.DeepEqual(canonicalDomainState(actual).VIPMappings, want.VIPMappings) ||
		!reflect.DeepEqual(canonicalDomainState(actual).DNSZones, want.DNSZones) ||
		!reflect.DeepEqual(canonicalDomainState(actual).DNSAnswers, want.DNSAnswers) ||
		!reflect.DeepEqual(canonicalDomainState(actual).DNSVIPs, want.DNSVIPs) ||
		!reflect.DeepEqual(canonicalDomainState(actual).DNSListeners, want.DNSListeners) {
		t.Fatalf("production K8s readback=%+v want K8s=%+v", actual, want)
	}
	if egressOwner.resolved != 1 || dnsOwner.reconciles != 1 || len(egressOwner.dnsCandidates) != 1 {
		t.Fatalf("existing owners were not called exactly: egress=%+v dns=%+v", egressOwner, dnsOwner)
	}
}

func TestProductionK8sSurfaceMissingOrUnexpectedKernelDNATFailsClosed(t *testing.T) {
	desired := productionDesired()
	digest := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	tests := map[string]struct {
		requested []egress.K8sDNATReceipt
		observed  []string
		wantErr   bool
	}{
		"missing":    {requested: []egress.K8sDNATReceipt{{VIP: desired.Policy.VIPMappings[0].VIP, Digest: digest}}},
		"unexpected": {observed: []string{digest}, wantErr: true},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			egressOwner := &fakeProductionEgress{requested: tc.requested, dnatObserved: tc.observed, dnsObserved: []string{desired.Policy.K8sDNSZones[0].ListenVIP}}
			dnsOwner := &fakeProductionDNS{state: dnsforward.AppliedK8sState{Listeners: []string{desired.Policy.K8sDNSZones[0].ListenVIP}}}
			surface, err := NewProductionK8sSurface(&fakeDomainSurface{}, egressOwner, dnsOwner, NewFileFenceStore(filepath.Join(t.TempDir(), "fences.json")), "wg0")
			if err != nil {
				t.Fatal(err)
			}
			if err := surface.ApplyStage(t.Context(), StageDNS, desired); err != nil {
				t.Fatal(err)
			}
			if err := surface.ApplyStage(t.Context(), StageDNAT, desired); err != nil {
				t.Fatal(err)
			}
			actual, readErr := surface.Readback(t.Context())
			if tc.wantErr {
				if readErr == nil {
					t.Fatalf("unexpected receipt returned actual=%+v", actual)
				}
				return
			}
			if readErr != nil || len(actual.VIPMappings) != 0 {
				t.Fatalf("missing receipt must omit mapping for coordinator mismatch: actual=%+v err=%v", actual, readErr)
			}
		})
	}
}

func TestProductionK8sSurfaceIncludesDurableFenceCandidatesOnWithdrawal(t *testing.T) {
	desired := productionDesired()
	fence, err := fenceFor(projectorOwnership())
	if err != nil {
		t.Fatal(err)
	}
	store := NewFileFenceStore(filepath.Join(t.TempDir(), "fences.json"))
	if err := store.SaveFences(t.Context(), []PoolFence{fence}); err != nil {
		t.Fatal(err)
	}
	desired.Policy.VIPMappings = nil
	desired.Policy.K8sDNSZones = nil
	egressOwner := &fakeProductionEgress{dnsObserved: []string{fence.Suppressed.DNSZones[0].ListenVIP}}
	dnsOwner := &fakeProductionDNS{}
	surface, err := NewProductionK8sSurface(&fakeDomainSurface{}, egressOwner, dnsOwner, store, "wg0")
	if err != nil {
		t.Fatal(err)
	}
	if err := surface.ApplyStage(t.Context(), StageDNS, desired); err != nil {
		t.Fatal(err)
	}
	if err := surface.ApplyStage(t.Context(), StageDNAT, desired); err != nil {
		t.Fatal(err)
	}
	actual, err := surface.Readback(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(egressOwner.dnsCandidates) != 1 || len(actual.DNSVIPs) != 1 {
		t.Fatalf("fenced restart residue was hidden: candidates=%v actual=%+v", egressOwner.dnsCandidates, actual)
	}
}

func TestProductionK8sSurfaceKeepsOVPNAndMissingDependenciesBlocked(t *testing.T) {
	desired := productionDesired()
	desired.OVPNEnabled = true
	surface, err := NewProductionK8sSurface(&fakeDomainSurface{}, &fakeProductionEgress{}, &fakeProductionDNS{}, NewFileFenceStore(filepath.Join(t.TempDir(), "fences.json")), "wg0")
	if err != nil {
		t.Fatal(err)
	}
	if err := surface.ApplyStage(t.Context(), StageOVPN, desired); !errors.Is(err, ErrProductionAdapterUnavailable) {
		t.Fatalf("OVPN must remain blocked: %v", err)
	}
	if _, err := NewProductionK8sSurface(nil, &fakeProductionEgress{}, &fakeProductionDNS{}, NewFileFenceStore("x"), "wg0"); !errors.Is(err, ErrProductionAdapterUnavailable) {
		t.Fatalf("nil delegate must fail closed: %v", err)
	}
}

func TestProductionOwnerSurfaceConsumesReconcileReadbackDecorator(t *testing.T) {
	desired := productionDesired()
	egressOwner := &fakeProductionEgress{}
	dnsOwner := &fakeProductionDNS{}
	wg := &fakeWGReadbackOwner{value: reconcile.WGBackendReadback{
		Peers:        []reconcile.Peer{{PublicKey: "actual-peer", AllowedIPs: []string{"100.64.0.0/24"}}},
		Routes:       []string{"100.64.0.0/24"},
		RouteDetails: []reconcile.OwnedRoute{{Family: "ipv4", Destination: "100.64.0.0/24", Device: "wg0", Protocol: "static", Metric: 8021}},
	}}
	surface, err := NewProductionOwnerSurface(&fakeDomainSurface{applied: expectedDomainState(desired)}, egressOwner, dnsOwner, wg,
		NewFileFenceStore(filepath.Join(t.TempDir(), "fences.json")), "wg0")
	if err != nil {
		t.Fatal(err)
	}
	if err := surface.ApplyStage(t.Context(), StageDNS, desired); err != nil {
		t.Fatal(err)
	}
	if err := surface.ApplyStage(t.Context(), StageDNAT, desired); err != nil {
		t.Fatal(err)
	}
	actual, err := surface.Readback(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(actual.WGPeers, []WGAppliedPeer{{PublicKey: "actual-peer", AllowedIPs: []string{"100.64.0.0/24"}}}) ||
		!reflect.DeepEqual(actual.Routes, []string{"100.64.0.0/24"}) || wg.calls != 1 {
		t.Fatalf("C3 reconcile readback was not composed: actual=%+v calls=%d", actual, wg.calls)
	}
}

func TestProductionOVPNSurfaceAppliesAndReadsExactProcessArtifact(t *testing.T) {
	desired := productionDesired()
	desired.OVPNEnabled = true
	desired.OVPNServer = &reconcile.OVPNServerMaterial{CA: "ca", Cert: "cert", Key: "key", CRL: "crl"}
	desired.Policy.VIPMappings = nil
	desired.Policy.K8sDNSZones = nil
	owner := &fakeProductionOVPN{}
	surface, err := NewProductionK8sSurfaceWithOVPN(
		&fakeDomainSurface{applied: expectedDomainState(desired)}, &fakeProductionEgress{}, &fakeProductionDNS{}, owner,
		NewFileFenceStore(filepath.Join(t.TempDir(), "fences.json")), "wg0",
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := surface.ApplyStage(t.Context(), StageOVPN, desired); err != nil {
		t.Fatal(err)
	}
	actual, err := surface.Readback(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(actual.OVPN, expectedDomainState(desired).OVPN) || owner.material == nil || owner.desired.PoolCIDR != desired.InterfaceAddress {
		t.Fatalf("OpenVPN production state=%+v material=%+v desired=%+v", actual.OVPN, owner.material, owner.desired)
	}
	owner.process = ovpnserver.ProcessState{}
	if _, err := surface.Readback(t.Context()); err == nil {
		t.Fatal("non-serving OpenVPN process must fail applied-state readback")
	}
}

func TestProductionOVPNWithdrawalStopFailureClearsLiveEgressButCannotAck(t *testing.T) {
	desired := productionDesired()
	desired.OVPNEnabled = true
	desired.OVPNServer = &reconcile.OVPNServerMaterial{CA: "ca", Cert: "cert", Key: "key", CRL: "crl"}
	egressOwner := &fakeProductionEgress{}
	owner := &fakeProductionOVPN{}
	surface, err := NewProductionK8sSurfaceWithOVPN(
		&fakeDomainSurface{}, egressOwner, &fakeProductionDNS{}, owner,
		NewFileFenceStore(filepath.Join(t.TempDir(), "fences.json")), "wg0",
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := surface.ApplyStage(t.Context(), StageOVPN, desired); err != nil {
		t.Fatal(err)
	}
	owner.stopErrWhenDesiredAbsent = errors.New("stale OpenVPN process remains alive")
	desired.OVPNEnabled = false
	desired.OVPNServer = nil
	if err := surface.ApplyStage(t.Context(), StageOVPN, desired); err == nil {
		t.Fatal("failed OpenVPN process withdrawal must refuse ownership transition")
	}
	if !owner.process.Serving || egressOwner.ovpnTun != "" {
		t.Fatalf("failed stop must retain live-process evidence but withdraw egress: process=%+v tun=%q", owner.process, egressOwner.ovpnTun)
	}
}
