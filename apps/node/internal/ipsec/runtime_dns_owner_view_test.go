package ipsec

import (
	"context"
	"encoding/json"
	"net/netip"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/node/internal/fqdnrpc"
)

type dnsOwnerViewFixture struct {
	c                                                 *RuntimeController
	material                                          RuntimeMaterial
	config                                            fqdnrpc.ResolverConfig
	manifest                                          GuardManifest
	nativeProofs, guardReads, sourceReads, routeReads atomic.Int32
	observed                                          atomic.Value
}

func newDNSOwnerViewFixture(t *testing.T, proof func(context.Context) error) *dnsOwnerViewFixture {
	t.Helper()
	return newDNSOwnerProfileFixture(t, dnsMaterialFixture(), proof)
}

func newDNSOwnerProfileFixture(t *testing.T, material RuntimeMaterial, proof func(context.Context) error) *dnsOwnerViewFixture {
	t.Helper()
	f := &dnsOwnerViewFixture{material: material}
	m := f.material
	entry, grants, err := runtimeMaterialEntry(m, m.Manifest.OrgID, m.Manifest.NodeID, "net:[4026531992]")
	if err != nil {
		t.Fatal(err)
	}
	entry.Phase = RuntimeApplied
	for i, tunnel := range entry.Allocation.Tunnels[:entry.Allocation.activeTunnelCount()] {
		entry.Observed[i] = Ownership{Namespace: entry.Allocation.Namespace, InterfaceName: tunnel.Name, InterfaceIndex: 10 + i, XFRMID: tunnel.XFRMID}
	}
	identity := PermitLeaseIdentity{PolicyHash: m.Policy.Hash, Binding: entry.Engines[0].Binding, DeliveryID: entry.DeliveryID}
	authority := dnsTestAuthority(t, identity)
	j, err := OpenRuntimeJournal(journalDir(t), m.Manifest.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { j.Close() })
	c := &RuntimeController{started: true, journal: j, qualification: testRuntimeQualification(entry.Allocation.Namespace), config: RuntimeControllerConfig{OrgID: m.Manifest.OrgID, GatewayID: m.Manifest.NodeID, DaemonAlive: func() bool { return true }}, active: map[uuid.UUID]runtimeActive{entry.Allocation.ConnectionID: {Entry: entry, Environment: RuntimeEnvironment{Namespace: entry.Allocation.Namespace, LocalIngressIndices: []int{2}}, Grants: grants, Identity: identity, Authority: authority}}}
	c.prove = func(ctx context.Context, _ RuntimeJournalEntry, _ RuntimeEnvironment) error {
		f.nativeProofs.Add(1)
		if proof != nil {
			return proof(ctx)
		}
		return nil
	}
	i := guardFixture()
	i.OwnerID = m.Manifest.NodeID
	i.Connections[0].ID = entry.Allocation.ConnectionID
	i.Connections[0].Tunnels = entry.Observed
	if entry.Allocation.activeTunnelCount() == 1 {
		i.Connections[0].TunnelCount = 1
	}
	i.Connections[0].Grants = grants
	i.Connections[0].ReplyIngressIndices = []int{10}
	i.Connections[0].EncryptedEgress = []GuardEncryptedEgress{{TunnelInterfaceIndex: 10, ReqID: entry.Engines[0].ReqID, Peer: entry.Engines[0].RemoteAddress, UnderlayInterfaceIndex: 2}}
	f.manifest, err = RenderGuard(i)
	if err != nil {
		t.Fatal(err)
	}
	f.observed.Store(f.manifest.ExpectedJSON)
	reader := &GuardReader{namespace: func() (string, error) { return entry.Allocation.Namespace, nil }, interfaces: func() ([]GuardInterface, error) {
		links := []GuardInterface{{Name: "eth0", Index: 2}}
		for _, owned := range entry.Observed[:entry.Allocation.activeTunnelCount()] {
			links = append(links, GuardInterface{Name: owned.InterfaceName, Index: owned.InterfaceIndex})
		}
		return links, nil
	}, run: func(context.Context, ...string) ([]byte, error) {
		f.guardReads.Add(1)
		return []byte(f.observed.Load().(string)), nil
	}}
	c.guard = &RuntimeGuard{reader: reader}
	f.c = c
	g := m.Policy.DNSResolverGrants[0]
	f.config = fqdnrpc.ResolverConfig{ID: g.ContextConfigID.String(), Version: g.ContextConfigVersion, ProfileID: g.ProfileID.String(), MatchedSuffix: "corp.test", Endpoints: []fqdnrpc.ResolverEndpoint{{Address: g.ResolverAddress, Port: 53, Transport: "udp"}}, IPsecPath: &fqdnrpc.IPsecPath{ConnectionID: g.ConnectionID.String(), ConfigurationRevision: g.ConfigurationRevision, SourceAddress: g.SourceAddress}}
	f.publish(t)
	return f
}
func dnsTestAuthority(t *testing.T, i PermitLeaseIdentity) *PermitLeaseAuthority {
	t.Helper()
	a := NewPermitLeaseAuthority()
	r, err := a.Begin(i)
	if err != nil {
		t.Fatal(err)
	}
	if a.Accept(PermitLeaseResponse{PermitLeaseRequest: r, TTLMillis: 60000}) != nil {
		t.Fatal("fixture lease refused")
	}
	return a
}
func (f *dnsOwnerViewFixture) publish(t *testing.T) {
	t.Helper()
	f.c.publishDNSOwnerView(f.manifest)
	v := f.c.dnsView.Load()
	if v == nil {
		t.Fatal("positive owner publication refused")
	}
	// Model only independent source/route inventories. Native guard parsing and
	// exact provenance/accepted lease remain real; no live qualification claimed.
	copied := *v
	copied.observer.source = func(source netip.Addr, allowed []int) (int, error) {
		f.sourceReads.Add(1)
		if source.String() != "10.10.0.1" || len(allowed) != 1 || allowed[0] != 2 {
			return 0, ErrRuntimeController
		}
		return 2, nil
	}
	copied.observer.route = func(_ context.Context, _ string, args ...string) ([]byte, error) {
		f.routeReads.Add(1)
		if strings.Join(args, " ") != "-j -4 route get 10.20.0.53 from 10.10.0.1" {
			return nil, ErrRuntimeController
		}
		a := v.entries[f.material.Manifest.ConnectionID].active
		return json.Marshal([]map[string]any{{"dst": "10.20.0.53", "from": "10.10.0.1", "dev": a.Entry.Observed[0].InterfaceName}})
	}
	f.c.dnsView.Store(&copied)
}
func (f *dnsOwnerViewFixture) prove(ctx context.Context) (runtimeDNSProof, error) {
	return f.c.proveResolverDNS(ctx, f.config, f.config.Endpoints[0])
}

func TestDNSOwnerViewIgnoresUnrelatedSerialOwnerWait(t *testing.T) {
	f := newDNSOwnerViewFixture(t, func(ctx context.Context) error {
		select {
		case <-time.After(80 * time.Millisecond):
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	f.c.mu.Lock()
	defer f.c.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 2500*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := f.prove(ctx); err != nil {
		t.Fatal("qualified immutable DNS path waited behind unrelated owner IO", err)
	}
	if time.Since(start) > time.Second || f.nativeProofs.Load() != 1 || f.guardReads.Load() != 1 || f.sourceReads.Load() != 2 || f.routeReads.Load() != 1 {
		t.Fatalf("missing fresh independent checks or slow path: proofs%d guard%d source%d route%d", f.nativeProofs.Load(), f.guardReads.Load(), f.sourceReads.Load(), f.routeReads.Load())
	}
}
func TestDNSOwnerViewNativeIODoesNotOccupyOwner(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	f := newDNSOwnerViewFixture(t, func(ctx context.Context) error {
		close(entered)
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	go func() { _, err := f.prove(context.Background()); done <- err }()
	<-entered
	available := f.c.mu.TryLock()
	if available {
		f.c.mu.Unlock()
	}
	close(release)
	if err := <-done; err != nil || !available {
		t.Fatalf("DNS native read monopolized owner: err%v available%v", err, available)
	}
}
func TestDNSOwnerViewConcurrentProofsDoNotSerialize(t *testing.T) {
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	done := make(chan error, 2)
	f := newDNSOwnerViewFixture(t, func(ctx context.Context) error {
		entered <- struct{}{}
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	for i := 0; i < 2; i++ {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_, err := f.prove(ctx)
			done <- err
		}()
	}
	for i := 0; i < 2; i++ {
		select {
		case <-entered:
		case <-time.After(500 * time.Millisecond):
			close(release)
			t.Fatal("DNS proofs serialized native IO")
		}
	}
	close(release)
	for i := 0; i < 2; i++ {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
}
func TestDNSOwnerViewMutationDuringNativeProofRefuses(t *testing.T) {
	cases := map[string]func(*dnsOwnerViewFixture){
		"withdraw": func(f *dnsOwnerViewFixture) { f.c.withdrawDNSOwnerView(f.material.Manifest.ConnectionID) },
		"close": func(f *dnsOwnerViewFixture) {
			if f.c.Close() != nil {
				panic("close")
			}
		},
		"grants": func(f *dnsOwnerViewFixture) {
			id := f.material.Manifest.ConnectionID
			a := f.c.active[id]
			a.Grants = nil
			f.c.active[id] = a
			f.c.reconcileDNSOwnerView()
		},
		"identity": func(f *dnsOwnerViewFixture) {
			id := f.material.Manifest.ConnectionID
			a := f.c.active[id]
			a.Identity.PolicyHash = strings.Repeat("a", 64)
			f.c.active[id] = a
			f.c.reconcileDNSOwnerView()
		},
		"environment": func(f *dnsOwnerViewFixture) {
			id := f.material.Manifest.ConnectionID
			a := f.c.active[id]
			a.Environment.Underlays[0].OuterMTU = 1400
			f.c.active[id] = a
			f.c.reconcileDNSOwnerView()
		},
		"entry": func(f *dnsOwnerViewFixture) {
			id := f.material.Manifest.ConnectionID
			a := f.c.active[id]
			a.Entry.Observed[0].InterfaceIndex++
			f.c.active[id] = a
			f.c.reconcileDNSOwnerView()
		},
		"disabled-new-revision": func(f *dnsOwnerViewFixture) {
			m := f.material
			m.DesiredRevision++
			m.Manifest.DesiredRevision++
			f.c.withdrawChangedDNSMaterial(m, f.c.active[m.Manifest.ConnectionID].Grants)
		},
		"lease-revocation": func(f *dnsOwnerViewFixture) { f.c.active[f.material.Manifest.ConnectionID].Authority.Invalidate() },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			entered := make(chan struct{})
			release := make(chan struct{})
			done := make(chan error, 1)
			f := newDNSOwnerViewFixture(t, func(context.Context) error { close(entered); <-release; return nil })
			go func() { _, err := f.prove(context.Background()); done <- err }()
			<-entered
			if name == "close" {
				change(f)
			} else {
				f.c.mu.Lock()
				change(f)
				f.c.mu.Unlock()
			}
			close(release)
			if err := <-done; err == nil {
				t.Fatal("withdrawn or changed owner epoch accepted DNS")
			}
		})
	}
}
func TestDNSOwnerViewSameIdentityRenewalPreservesOriginalDeadline(t *testing.T) {
	f := newDNSOwnerViewFixture(t, nil)
	before, err := f.prove(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	id := f.material.Manifest.ConnectionID
	original := f.c.active[id].Authority
	f.c.mu.Lock()
	a := f.c.active[id]
	a.Authority = dnsTestAuthority(t, a.Identity)
	f.c.active[id] = a
	f.publish(t)
	f.c.mu.Unlock()
	after, err := f.prove(context.Background())
	if err != nil || !sameResolverDNSProof(after, before) {
		t.Fatal("benign exact identity renewal invalidated live original proof", err)
	}
	original.Invalidate()
	if sameResolverDNSProof(after, before) {
		t.Fatal("replacement authority extended/revived original deadline")
	}
}
func TestDNSOwnerViewDeepCopiesPublishedInputs(t *testing.T) {
	f := newDNSOwnerViewFixture(t, nil)
	id := f.material.Manifest.ConnectionID
	v := f.c.dnsView.Load()
	old := v.entries[id]
	a := f.c.active[id]
	a.Entry.Engines[0].LocalPrefixes[0] = netip.MustParsePrefix("10.11.0.0/24")
	a.Environment.LocalIngressIndices[0] = 99
	a.Grants[0].PortHigh = 54
	f.c.active[id] = a
	if old.active.Entry.Engines[0].LocalPrefixes[0].String() != "10.10.0.0/24" || old.active.Environment.LocalIngressIndices[0] != 2 || old.active.Grants[0].PortHigh != 53 {
		t.Fatal("published inputs alias mutable owner data")
	}
}
func TestDNSOwnerViewDoesNotPublishWithoutNativeGuardCommit(t *testing.T) {
	f := newDNSOwnerViewFixture(t, nil)
	f.c.withdrawDNSOwnerView(uuid.Nil)
	if _, err := f.prove(context.Background()); err == nil {
		t.Fatal("active metadata alone supplied DNS authority")
	}
	f.c.publishDNSOwnerView(GuardManifest{})
	if f.c.dnsView.Load() != nil {
		t.Fatal("uncommitted missing guard supplied DNS view")
	}
}

func TestDNSOwnerViewDuringActualValidateNativeIO(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	f := newDNSOwnerViewFixture(t, func(ctx context.Context) error {
		if calls.Add(1) != 1 {
			return nil
		}
		close(entered)
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	a := f.c.active[f.material.Manifest.ConnectionID]
	f.c.namespace = func() (string, error) { return a.Entry.Allocation.Namespace, nil }
	f.c.recoveryObserve = func(context.Context, RuntimeJournalEntry) [2]string { return [2]string{"up", "up"} }
	f.c.replace = func(context.Context, GuardIntent) (GuardManifest, error) {
		return GuardManifest{}, ErrRuntimeController
	}
	reserved := a.Entry
	reserved.Phase, reserved.Observed = RuntimeReserved, [2]Ownership{}
	for _, phase := range []RuntimePhase{RuntimeReserved, RuntimeApplying, RuntimeApplied} {
		reserved.Phase = phase
		if phase != RuntimeReserved {
			reserved.Observed = a.Entry.Observed
		}
		if err := f.c.journal.Save([]RuntimeJournalEntry{reserved}); err != nil {
			t.Fatal("genuine journal fixture", phase, err)
		}
	}
	done := make(chan error, 1)
	go func() { done <- f.c.Validate(context.Background()) }()
	<-entered
	ctx, cancel := context.WithTimeout(context.Background(), 2500*time.Millisecond)
	defer cancel()
	_, err := f.prove(ctx)
	close(release)
	<-done // fixture has no kernel mutation backend; only the real owner wait is exercised.
	if err != nil || calls.Load() < 2 {
		t.Fatal("DNS queued behind production Validate native read", err)
	}
}

func TestDNSOwnerViewConcurrentCloseCannotRepublish(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	f := newDNSOwnerViewFixture(t, func(context.Context) error { close(entered); <-release; return nil })
	proofDone := make(chan error, 1)
	go func() { _, err := f.prove(context.Background()); proofDone <- err }()
	<-entered
	f.c.mu.Lock()
	closeQueued, closeDone := make(chan struct{}), make(chan error, 1)
	go func() { close(closeQueued); closeDone <- f.c.Close() }()
	<-closeQueued
	// A prior owner may finish publication before the queued Close acquires c.mu.
	f.publish(t)
	f.c.mu.Unlock()
	if err := <-closeDone; err != nil {
		t.Fatal(err)
	}
	f.c.mu.Lock()
	f.c.publishDNSOwnerView(f.manifest)
	f.c.mu.Unlock()
	close(release)
	if err := <-proofDone; err == nil || f.c.dnsView.Load() != nil {
		t.Fatal("Close resurrected an owner view", err)
	}
}

func TestDNSOwnerViewFreshNativeInputsRemainMandatory(t *testing.T) {
	for _, name := range []string{"native", "source-removed", "source-moved", "route-wan", "guard-expired", "cancelled"} {
		t.Run(name, func(t *testing.T) {
			f := newDNSOwnerViewFixture(t, nil)
			v := *f.c.dnsView.Load()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch name {
			case "native":
				observer := *v.observer.controller
				observer.prove = func(context.Context, RuntimeJournalEntry, RuntimeEnvironment) error { return ErrRuntimeController }
				v.observer.controller = &observer
			case "source-removed":
				v.observer.source = func(netip.Addr, []int) (int, error) { return 0, ErrRuntimeController }
			case "source-moved":
				var count atomic.Int32
				v.observer.source = func(netip.Addr, []int) (int, error) { return int(count.Add(1)), nil }
			case "route-wan":
				v.observer.route = func(context.Context, string, ...string) ([]byte, error) {
					return []byte(`[{"dst":"10.20.0.53","from":"10.10.0.1","dev":"eth0","gateway":"192.0.2.1"}]`), nil
				}
			case "guard-expired":
				f.observed.Store(`{"nftables":[]}`)
			case "cancelled":
				cancel()
			}
			f.c.dnsView.Store(&v)
			if _, err := f.prove(ctx); err == nil {
				t.Fatal("immutable intent supplied missing fresh native proof")
			}
		})
	}
}

func TestDNSOwnerViewLatestGuardRecheckedAfterConcurrentReplacement(t *testing.T) {
	f := newDNSOwnerViewFixture(t, nil)
	v := *f.c.dnsView.Load()
	oldSource := v.observer.source
	var reads atomic.Int32
	v.observer.source = func(source netip.Addr, allowed []int) (int, error) {
		if reads.Add(1) == 2 {
			// Simulate an unrelated owner replacing the shared table after the
			// first exact guard read. Epoch/state are identical, but native table
			// and the freshly published template must still match at completion.
			latest := *f.c.dnsView.Load()
			latest.guard.Digest = strings.Repeat("a", 64)
			f.observed.Store(`{"nftables":[]}`)
			f.c.dnsView.Store(&latest)
		}
		return oldSource(source, allowed)
	}
	f.c.dnsView.Store(&v)
	if _, err := f.prove(context.Background()); err == nil || f.guardReads.Load() != 2 {
		t.Fatal("replacement guard bypassed fresh complete readback", err, f.guardReads.Load())
	}
}

func TestDNSOwnerViewClonePreservesNestedIdentityAndEmptySlices(t *testing.T) {
	f := newDNSOwnerViewFixture(t, nil)
	a := f.c.active[f.material.Manifest.ConnectionID]
	a.Entry.RetainedGuardPredecessors = []RuntimeRetainedGuardPredecessor{}
	a.Entry.Restoration = &RuntimeRestoration{Retired: []RuntimeRetiredEpoch{{Entry: RuntimeJournalEntry{Engines: [2]EngineTunnel{{RemotePrefixes: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/24")}}}}}}}
	a.Entry.BGPRoutes = &RuntimeBGPRoutes{Owned: []RuntimeBGPRouteTuple{}, Target: []RuntimeBGPRouteTuple{}}
	copy := cloneDNSOwnerActive(a)
	if !sameDNSOwnerInputs(copy, a) {
		t.Fatal("deep copy normalized exact empty/nil identity")
	}
	a.Entry.Restoration.Retired[0].Entry.Engines[0].RemotePrefixes[0] = netip.MustParsePrefix("10.21.0.0/24")
	a.Entry.BGPRoutes.Target = append(a.Entry.BGPRoutes.Target, RuntimeBGPRouteTuple{Slot: 2})
	if copy.Entry.Restoration.Retired[0].Entry.Engines[0].RemotePrefixes[0].String() != "10.20.0.0/24" || len(copy.Entry.BGPRoutes.Target) != 0 {
		t.Fatal("nested snapshot aliases owner state")
	}
}

func TestDNSOwnerViewFinalExchangeCheckRejectsCurrentRevocation(t *testing.T) {
	f := newDNSOwnerViewFixture(t, nil)
	before, err := f.prove(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	id := f.material.Manifest.ConnectionID
	f.c.mu.Lock()
	a := f.c.active[id]
	a.Authority = dnsTestAuthority(t, a.Identity)
	f.c.active[id] = a
	f.publish(t)
	f.c.mu.Unlock()
	after, err := f.prove(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	a.Authority.Invalidate()
	if sameResolverDNSProof(after, before) {
		t.Fatal("current replaced authority revoked between final proof and response")
	}
}
func TestDNSOwnerViewFinalExchangeCheckRejectsWithdrawnEpoch(t *testing.T) {
	f := newDNSOwnerViewFixture(t, nil)
	before, err := f.prove(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	after, err := f.prove(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	f.c.mu.Lock()
	f.c.withdrawDNSOwnerView(f.material.Manifest.ConnectionID)
	f.c.mu.Unlock()
	if sameResolverDNSProof(after, before) {
		t.Fatal("withdrawn epoch accepted between final proof and response")
	}
}

func TestDNSOwnerViewCleanupWithdrawsBeforeJournalIO(t *testing.T) {
	f := newDNSOwnerViewFixture(t, nil)
	cleanup := RuntimeCleanup{RuntimeDelivery: f.material.RuntimeDelivery, RetainGuard: true, Lineage: []RuntimeDelivery{f.material.RuntimeDelivery}}
	cleanup.ID, cleanup.Kind = uuid.New(), "cleanup"
	cleanup.DesiredRevision = f.material.DesiredRevision + 1
	cleanup.CoversDeliveryRevision = f.material.DesiredRevision
	raw, err := json.Marshal(cleanup.Lineage)
	if err != nil {
		t.Fatal(err)
	}
	cleanup.OwnershipDigest = stringDigest(raw)
	if !runtimeCleanupValid(cleanup, f.material.Manifest.OrgID, f.material.Manifest.NodeID) {
		t.Fatal("invalid cleanup fixture")
	}
	// A journal refusal must not leave the old resolver view usable while the
	// explicit cleanup cannot yet finish native denial. No native mutation occurs.
	f.c.journal.mu.Lock()
	f.c.journal.poisoned = true
	f.c.journal.mu.Unlock()
	if _, err := f.c.Cleanup(context.Background(), cleanup); err == nil {
		t.Fatal("poisoned journal unexpectedly cleaned")
	}
	if _, err := f.prove(context.Background()); err == nil {
		t.Fatal("cleanup refusal retained old DNS authority view")
	}
}

func TestDNSOwnerViewOriginalLeaseExpiryCannotUseRenewedDeadline(t *testing.T) {
	f := newDNSOwnerViewFixture(t, nil)
	id := f.material.Manifest.ConnectionID
	f.c.mu.Lock()
	a := f.c.active[id]
	var elapsed atomic.Int64
	original := NewPermitLeaseAuthority()
	original.elapsed = func() time.Duration { return time.Duration(elapsed.Load()) }
	request, err := original.Begin(a.Identity)
	if err != nil {
		t.Fatal(err)
	}
	if err = original.Accept(PermitLeaseResponse{PermitLeaseRequest: request, TTLMillis: 2000}); err != nil {
		t.Fatal(err)
	}
	a.Authority = original
	f.c.active[id] = a
	f.publish(t)
	f.c.mu.Unlock()
	before, err := f.prove(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	f.c.mu.Lock()
	a.Authority = dnsTestAuthority(t, a.Identity)
	f.c.active[id] = a
	f.publish(t)
	f.c.mu.Unlock()
	after, err := f.prove(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	elapsed.Store(int64(1200 * time.Millisecond))
	if sameResolverDNSProof(after, before) {
		t.Fatal("renewal extended original minimum completion window")
	}
}

func TestDNSOwnerViewWithdrawalCannotBeReopenedForInFlightQuery(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	f := newDNSOwnerViewFixture(t, func(context.Context) error { close(entered); <-release; return nil })
	done := make(chan error, 1)
	go func() { _, err := f.prove(context.Background()); done <- err }()
	<-entered
	f.c.mu.Lock()
	f.c.withdrawDNSOwnerView(f.material.Manifest.ConnectionID)
	f.publish(t) // same intent/new native commit must receive a distinct epoch.
	f.c.mu.Unlock()
	close(release)
	if err := <-done; err == nil {
		t.Fatal("new positive publication revived a withdrawn in-flight epoch")
	}
}

func TestDNSOwnerViewDoesNotPublishForeignGuardBinding(t *testing.T) {
	for _, name := range []string{"owner", "namespace", "revision", "digest"} {
		t.Run(name, func(t *testing.T) {
			f := newDNSOwnerViewFixture(t, nil)
			g := f.manifest
			switch name {
			case "owner":
				g.OwnerID = uuid.New()
			case "namespace":
				g.Namespace = "net:[4026531993]"
			case "revision":
				g.Revision = 0
			case "digest":
				g.Digest = ""
			}
			f.c.mu.Lock()
			f.c.publishDNSOwnerView(g)
			f.c.mu.Unlock()
			if f.c.dnsView.Load() != nil {
				t.Fatal("unbound native manifest produced resolver view")
			}
		})
	}
}

// These exercise real provider-shaped material validation and immutable owner
// epochs. They do not execute native SA/source/route or Linux packet proof.
func TestDNSOwnerViewGCPProfileEpochs(t *testing.T) {
	for _, profile := range []string{GCPClassicStaticProfile, GCPHABGPProfile} {
		t.Run(profile, func(t *testing.T) {
			m := classicMaterialFixture()
			wantCount, wantContract := 1, 4
			if profile == GCPHABGPProfile {
				m = gcpMaterialFixture()
				wantCount, wantContract = 2, 3
			}
			m.Policy.DNSResolverGrants = dnsMaterialFixture().Policy.DNSResolverGrants
			m.Policy.DNSResolverGrants[0].ConnectionID = m.Manifest.ConnectionID
			m.Policy.DNSResolverGrants[0].ConfigurationRevision = m.Manifest.ConfigurationRevision
			e, grants, err := runtimeMaterialEntry(m, m.Manifest.OrgID, m.Manifest.NodeID, "net:[4026531992]")
			if err != nil {
				t.Fatal(err)
			}
			e.Phase = RuntimeApplied
			if wantCount == 2 {
				e.Observed[0].InterfaceIndex, e.Observed[1].InterfaceIndex = 10, 11
				tuple := routeTupleFixture(e, 1)
				e.BGPRoutes = &RuntimeBGPRoutes{Sequence: 1, Stage: "completed", Owned: []RuntimeBGPRouteTuple{tuple}, Target: []RuntimeBGPRouteTuple{tuple}}
				if !validBGPRoutes(e) {
					t.Fatal("initial GCP route tuple invalid")
				}
			}
			identity := PermitLeaseIdentity{PolicyHash: m.Policy.Hash, Binding: e.Engines[0].Binding, DeliveryID: e.DeliveryID}
			a := runtimeActive{Entry: e, Grants: grants, Identity: identity, Authority: dnsTestAuthority(t, identity)}
			id := m.Manifest.ConnectionID
			original := runtimeDNSOwnerEntry{active: cloneDNSOwnerActive(a), epoch: &runtimeDNSEpoch{}}
			c := &RuntimeController{active: map[uuid.UUID]runtimeActive{id: a}}
			c.dnsView.Store(&runtimeDNSOwnerView{entries: map[uuid.UUID]runtimeDNSOwnerEntry{id: original}})
			if original.active.Entry.ContractVersion != wantContract || original.active.Entry.Allocation.activeTunnelCount() != wantCount {
				t.Fatal("provider contract lost during snapshot")
			}
			if wantCount == 1 && (!reflect.DeepEqual(original.active.Entry.Allocation.Tunnels[1], KernelTunnelAllocation{}) || original.active.Entry.Observed[1] != (Ownership{})) {
				t.Fatal("Classic inactive slot populated")
			}
			if _, ok := c.currentDNSOwnerEntry(id, original); !ok {
				t.Fatal("valid profile epoch refused")
			}

			var elapsed atomic.Int64
			deadline := NewPermitLeaseAuthority()
			deadline.elapsed = func() time.Duration { return time.Duration(elapsed.Load()) }
			req, err := deadline.Begin(identity)
			if err != nil {
				t.Fatal(err)
			}
			if err = deadline.Accept(PermitLeaseResponse{PermitLeaseRequest: req, TTLMillis: 2000}); err != nil {
				t.Fatal(err)
			}
			expired := original
			expired.active.Authority = deadline
			elapsed.Store(int64(1200 * time.Millisecond))
			if _, ok := c.currentDNSOwnerEntry(id, expired); ok {
				t.Fatal("renewed profile authority extended original minimum deadline")
			}
			changed := c.active[id]
			// A newly selected BGP route slot changes immutable ownership even if the
			// policy identity and accepted deadline have not changed.
			if wantCount == 2 {
				tuple := routeTupleFixture(changed.Entry, 2)
				changed.Entry.BGPRoutes = &RuntimeBGPRoutes{Sequence: 2, Stage: "completed", Owned: []RuntimeBGPRouteTuple{tuple}, Target: []RuntimeBGPRouteTuple{tuple}}
				if !validBGPRoutes(changed.Entry) {
					t.Fatal("changed GCP route tuple invalid")
				}
			} else {
				changed.Entry.Observed[0].InterfaceIndex++
			}
			c.active[id] = changed
			c.reconcileDNSOwnerView()
			if !original.epoch.revoked.Load() {
				t.Fatal("route/interface mutation retained original query epoch")
			}
			if _, ok := c.currentDNSOwnerEntry(id, original); ok {
				t.Fatal("changed route accepted original in-flight query")
			}
		})
	}
}
