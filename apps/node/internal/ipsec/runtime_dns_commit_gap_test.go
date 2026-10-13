package ipsec

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
)

// Reuse real material admission, guard renderer/readback, candidate installation,
// publication and DNS proof. Only kernel/native inventories are test readers.
// An existing local private IPv4 address is read, never configured; no socket
// exchange occurs in this proof.
func dnsCommitGapFixture(t *testing.T) (*dnsOwnerViewFixture, []RuntimeJournalEntry, runtimeActive) {
	t.Helper()
	f := newDNSOwnerViewFixture(t, nil)
	m := f.material
	var source netip.Addr
	var sourceIndex int
	links, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, link := range links {
		if link.Flags&net.FlagUp == 0 || link.Index == 10 || link.Index == 11 {
			continue
		}
		addresses, err := link.Addrs()
		if err != nil {
			t.Fatal(err)
		}
		for _, address := range addresses {
			p, err := netip.ParsePrefix(address.String())
			if err == nil && p.Addr().Is4() && p.Addr().IsPrivate() {
				source, sourceIndex = p.Addr(), link.Index
				break
			}
		}
		if source.IsValid() {
			break
		}
	}
	if !source.IsValid() {
		t.Skip("requires an existing private local IPv4 address; no fixture configures an address")
	}
	m.Manifest.LocalPrefixes = []string{netip.PrefixFrom(source, 32).String()}
	m.Policy.DNSResolverGrants[0].SourceAddress = source.String()
	runtimeReseal(&m)
	e, grants, err := runtimeMaterialEntry(m, m.Manifest.OrgID, m.Manifest.NodeID, "net:[4026531992]")
	if err != nil {
		t.Fatal(err)
	}
	for i, tunnel := range e.Allocation.Tunnels {
		e.Observed[i] = Ownership{Namespace: e.Allocation.Namespace, InterfaceName: tunnel.Name, InterfaceIndex: 10 + i, XFRMID: tunnel.XFRMID}
	}
	if err = f.c.journal.Save([]RuntimeJournalEntry{e}); err != nil {
		t.Fatal(err)
	}
	e.Phase = RuntimeApplying
	if err = f.c.journal.Save([]RuntimeJournalEntry{e}); err != nil {
		t.Fatal(err)
	}
	e.Phase = RuntimeApplied
	if err = f.c.journal.Save([]RuntimeJournalEntry{e}); err != nil {
		t.Fatal(err)
	}
	id := m.Manifest.ConnectionID
	a := f.c.active[id]
	a.Entry, a.Grants = e, grants
	a.Environment.LocalIngressIndices = []int{sourceIndex}
	a.Environment.Underlays = [2]RuntimeUnderlay{{InterfaceIndex: 2, OuterMTU: 1500, LocalAddress: netip.MustParseAddr("192.0.2.1")}, {InterfaceIndex: 2, OuterMTU: 1500, LocalAddress: netip.MustParseAddr("192.0.2.1")}}
	f.c.active[id] = a
	f.material = m
	f.config.IPsecPath.SourceAddress = source.String()
	k := newRecoveryKernelFixture()
	k.p, k.owned = e.Allocation, e.Observed
	k.routes = [2]map[string]bool{{}, {}}
	for _, p := range e.Allocation.Tunnels[0].RemotePrefixes {
		k.routes[0][p.String()] = true
	}
	f.c.kernel = k.applier()
	f.c.namespace = func() (string, error) { return e.Allocation.Namespace, nil }
	f.c.recoveryObserve = func(context.Context, RuntimeJournalEntry) [2]string { return [2]string{"up", "up"} }
	i := guardFixture()
	i.OwnerID = m.Manifest.NodeID
	g := &i.Connections[0]
	g.ID, g.Local, g.Remote, g.Tunnels, g.Grants = id, e.Engines[0].LocalPrefixes, e.Engines[0].RemotePrefixes, e.Observed, grants
	g.LocalIngressIndices = []int{sourceIndex}
	g.ReplyIngressIndices = []int{10, 11}
	g.EncryptedEgress = []GuardEncryptedEgress{{TunnelInterfaceIndex: 10, ReqID: e.Engines[0].ReqID, Peer: e.Engines[0].RemoteAddress, UnderlayInterfaceIndex: 2}}
	g.TunnelMTUs = []GuardTunnelMTU{{InterfaceIndex: 10, MTU: 1422}, {InterfaceIndex: 11, MTU: 1422}}
	f.manifest, err = RenderGuard(i)
	if err != nil {
		t.Fatal(err)
	}
	f.observed.Store(f.manifest.ExpectedJSON)
	f.c.publishDNSOwnerView(f.manifest)
	v := *f.c.dnsView.Load()
	v.observer.source = func(got netip.Addr, _ []int) (int, error) {
		f.sourceReads.Add(1)
		if got != source {
			return 0, ErrRuntimeController
		}
		return sourceIndex, nil
	}
	v.observer.route = func(context.Context, string, ...string) ([]byte, error) {
		f.routeReads.Add(1)
		return json.Marshal([]map[string]any{{"dst": "10.20.0.53", "from": source.String(), "dev": e.Observed[0].InterfaceName}})
	}
	oldInterfaces := f.c.guard.reader.interfaces
	f.c.guard.reader.interfaces = func() ([]GuardInterface, error) {
		links, err := oldInterfaces()
		if sourceIndex != 2 {
			links = append(links, GuardInterface{Name: "fixtureSource", Index: sourceIndex})
		}
		return links, err
	}
	f.c.dnsView.Store(&v)
	return f, []RuntimeJournalEntry{e}, a
}

func TestDNSGuardWaitsForSameOwnerNativeCommitPublication(t *testing.T) {
	for _, transport := range []string{"udp", "tcp"} {
		t.Run(transport, func(t *testing.T) { testDNSGuardCommitPublication(t, transport) })
	}
}
func testDNSGuardCommitPublication(t *testing.T, transport string) {
	f, entries, old := dnsCommitGapFixture(t)
	f.config.Endpoints[0].Transport = transport
	id := f.material.Manifest.ConnectionID
	original := f.c.dnsView.Load().entries[id]
	candidate := old
	candidate.Authority = dnsTestAuthority(t, candidate.Identity)
	nativeReady, publish := make(chan struct{}), make(chan struct{})
	f.c.replace = func(ctx context.Context, in GuardIntent) (GuardManifest, error) {
		g, err := RenderGuard(in)
		if err != nil {
			return GuardManifest{}, err
		}
		f.observed.Store(g.ExpectedJSON)
		if err = f.c.guard.reader.checkConnection(ctx, g, id); err != nil {
			return GuardManifest{}, err
		}
		close(nativeReady)
		select {
		case <-publish:
			return g, nil
		case <-ctx.Done():
			return GuardManifest{}, ctx.Err()
		}
	}
	writerDone := make(chan error, 1)
	go func() {
		f.c.mu.Lock()
		defer f.c.mu.Unlock()
		writerDone <- f.c.installActiveCandidates(context.Background(), entries, map[uuid.UUID]runtimeActive{id: candidate}, map[uuid.UUID]runtimeActive{id: candidate}, map[uuid.UUID]runtimeActive{id: old}, nil)
	}()
	<-nativeReady
	// The installed complete native table differs while the immutable DNS view
	// remains old. The query has to wait for the committed positive seam.
	queryRead := make(chan struct{})
	run := f.c.guard.reader.run
	var once sync.Once
	f.c.guard.reader.run = func(ctx context.Context, args ...string) ([]byte, error) {
		raw, err := run(ctx, args...)
		once.Do(func() { close(queryRead) })
		return raw, err
	}
	queryDone := make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() { _, err := f.prove(ctx); queryDone <- err }()
	<-queryRead
	var early error
	returnedEarly := false
	select {
	case early = <-queryDone:
		returnedEarly = true
	case <-time.After(20 * time.Millisecond):
	}
	close(publish)
	if err := <-writerDone; err != nil {
		t.Fatal("original native commit failed", err)
	}
	if returnedEarly {
		t.Fatalf("same-owner native commit gap refused before publication: %v", early)
	}
	if err := <-queryDone; err != nil {
		t.Fatal("committed same-owner view still refused", err)
	}
	current := f.c.dnsView.Load().entries[id]
	if current.epoch != original.epoch || current.active.Authority != candidate.Authority || original.active.Authority == candidate.Authority || !sameDNSOwnerInputs(original.active, current.active) {
		t.Fatal("test did not preserve exact owner/original finite authority")
	}
	if f.guardReads.Load() < 3 || f.sourceReads.Load() != 2 || f.routeReads.Load() != 1 {
		t.Fatal("fresh guard/source/route proof omitted")
	}
}

func TestDNSGuardCommitWaitRetainsDenialBoundaries(t *testing.T) {
	for _, name := range []string{"replace_failure", "original_expiry", "current_expiry", "epoch_revoked", "changed_grants", "wrong_native", "cancelled", "deadline"} {
		t.Run(name, func(t *testing.T) {
			f, entries, old := dnsCommitGapFixture(t)
			id := f.material.Manifest.ConnectionID
			original := f.c.dnsView.Load().entries[id]
			candidate := old
			candidate.Authority = dnsTestAuthority(t, candidate.Identity)
			if name == "changed_grants" {
				candidate.Grants = copyDNSSlice(candidate.Grants[:1])
			}
			nativeReady, publish := make(chan struct{}), make(chan struct{})
			f.c.replace = func(ctx context.Context, in GuardIntent) (GuardManifest, error) {
				g, err := RenderGuard(in)
				if err != nil {
					return GuardManifest{}, err
				}
				f.observed.Store(g.ExpectedJSON)
				if err = f.c.guard.reader.checkConnection(ctx, g, id); err != nil {
					return GuardManifest{}, err
				}
				close(nativeReady)
				select {
				case <-publish:
				case <-ctx.Done():
					return GuardManifest{}, ctx.Err()
				}
				if name == "replace_failure" {
					return GuardManifest{}, ErrGuardReadback
				}
				if name == "wrong_native" {
					f.observed.Store(`{"nftables":[]}`)
				}
				return g, nil
			}
			writerDone := make(chan error, 1)
			go func() {
				f.c.mu.Lock()
				defer f.c.mu.Unlock()
				writerDone <- f.c.installActiveCandidates(context.Background(), entries, map[uuid.UUID]runtimeActive{id: candidate}, map[uuid.UUID]runtimeActive{id: candidate}, map[uuid.UUID]runtimeActive{id: old}, nil)
			}()
			<-nativeReady
			queryRead := make(chan struct{})
			run := f.c.guard.reader.run
			var once sync.Once
			f.c.guard.reader.run = func(ctx context.Context, args ...string) ([]byte, error) {
				raw, err := run(ctx, args...)
				once.Do(func() { close(queryRead) })
				return raw, err
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if name == "deadline" {
				cancel()
				ctx, cancel = context.WithTimeout(context.Background(), 30*time.Millisecond)
				defer cancel()
			}
			done := make(chan error, 1)
			go func() { _, err := f.prove(ctx); done <- err }()
			<-queryRead
			switch name {
			case "original_expiry":
				old.Authority.Invalidate()
			case "current_expiry":
				candidate.Authority.Invalidate()
			case "epoch_revoked":
				original.epoch.revoked.Store(true)
			case "cancelled":
				cancel()
			case "deadline":
				<-ctx.Done()
			}
			close(publish)
			<-writerDone // Success is insufficient: original/current authority and native proof still gate DNS.
			if err := <-done; err == nil {
				t.Fatal("changed, uncommitted, expired or invalid native authority accepted")
			}
			if f.sourceReads.Load() != 0 || f.routeReads.Load() != 0 {
				t.Fatal("denial was delayed until after source/route proof")
			}
			if f.c.dnsGuardCommit.Load() != nil {
				t.Fatal("finished commit token leaked")
			}
		})
	}
}

func TestDNSGuardCommitWaitRequiresExactKnownTransition(t *testing.T) {
	for _, name := range []string{"no_token", "no_deadline", "wrong_digest", "wrong_namespace", "wrong_owner", "changed_epoch", "changed_inputs", "original_expiry", "current_expiry", "no_new_publication"} {
		t.Run(name, func(t *testing.T) {
			f := newDNSOwnerViewFixture(t, nil)
			id := f.material.Manifest.ConnectionID
			previous := f.c.dnsView.Load()
			owner := previous.entries[id]
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			var token *runtimeDNSGuardCommit
			if name != "no_token" {
				token = f.c.beginDNSGuardCommit()
			}
			if token != nil {
				copied := *token.previous
				copied.entries = make(map[uuid.UUID]runtimeDNSOwnerEntry)
				for id, e := range token.previous.entries {
					copied.entries[id] = e
				}
				token.previous = &copied
				switch name {
				case "wrong_digest":
					token.previous.guard.Digest = stringDigest([]byte("foreign"))
				case "wrong_namespace":
					token.previous.guard.Namespace = "net:[4026531993]"
				case "wrong_owner":
					token.previous.guard.OwnerID = uuid.New()
				case "changed_epoch":
					e := copied.entries[id]
					e.epoch = &runtimeDNSEpoch{}
					copied.entries[id] = e
				case "changed_inputs":
					e := copied.entries[id]
					e.active.Grants = copyDNSSlice(e.active.Grants[:1])
					copied.entries[id] = e
				case "original_expiry":
					owner.active.Authority.Invalidate()
				case "current_expiry":
					current := *previous
					current.entries = make(map[uuid.UUID]runtimeDNSOwnerEntry)
					for id, e := range previous.entries {
						current.entries[id] = e
					}
					e := current.entries[id]
					e.active.Authority = dnsTestAuthority(t, e.active.Identity)
					e.active.Authority.Invalidate()
					current.entries[id] = e
					f.c.dnsView.Store(&current)
				case "no_new_publication":
					f.c.finishDNSGuardCommit(token)
					token = nil
				}
			}
			if name == "no_deadline" {
				ctx = context.Background()
			}
			start := time.Now()
			e := owner.active.Entry
			got := f.c.revalidateDNSGuardSnapshotDigest(ctx, id, owner, previous, e, e.Observed[0].InterfaceIndex, e.Engines[0].ReqID)
			if token != nil {
				f.c.finishDNSGuardCommit(token)
			}
			if got != "" || time.Since(start) > 200*time.Millisecond || f.guardReads.Load() != 0 {
				t.Fatal("unknown/mismatched/expired commit was waited on or supplied authority", name)
			}
		})
	}
}

func TestDNSGuardKnownCommitCannotWaitForSecondSupersession(t *testing.T) {
	f := newDNSOwnerViewFixture(t, nil)
	id := f.material.Manifest.ConnectionID
	previous := f.c.dnsView.Load()
	owner := previous.entries[id]
	token := f.c.beginDNSGuardCommit()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result := make(chan string, 1)
	e := owner.active.Entry
	go func() {
		result <- f.c.revalidateDNSGuardSnapshotDigest(ctx, id, owner, previous, e, e.Observed[0].InterfaceIndex, e.Engines[0].ReqID)
	}()
	// Waiter sees the first committed view, but native collection crosses another
	// independently published digest. A second transition never gets a wait.
	renewDNSDiagnosticGuard(t, f)
	token.published = f.c.dnsView.Load()
	run := f.c.guard.reader.run
	var changed atomic.Bool
	f.c.guard.reader.run = func(ctx context.Context, args ...string) ([]byte, error) {
		raw, err := run(ctx, args...)
		if changed.CompareAndSwap(false, true) {
			renewDNSDiagnosticGuard(t, f)
		}
		return raw, err
	}
	f.c.finishDNSGuardCommit(token)
	if got := <-result; got != "" || f.guardReads.Load() != 1 {
		t.Fatal("second guard supersession reused first commit token", got, f.guardReads.Load())
	}
}

// Pause exactly after the reader loads a known token, before it waits. This
// makes a completed A followed by B deterministic without scheduling sleeps.
type dnsCommitWaitGateContext struct {
	context.Context
	entered chan struct{}
	resume  chan struct{}
	once    sync.Once
}

func (c *dnsCommitWaitGateContext) Deadline() (time.Time, bool) {
	c.once.Do(func() { close(c.entered); <-c.resume })
	return c.Context.Deadline()
}
func TestDNSGuardCompletedCommitCannotAdoptSecondPublication(t *testing.T) {
	for _, second := range []string{"published", "inflight"} {
		t.Run(second, func(t *testing.T) {
			f := newDNSOwnerViewFixture(t, nil)
			id := f.material.Manifest.ConnectionID
			previous := f.c.dnsView.Load()
			owner := previous.entries[id]
			entry := owner.active.Entry
			token := f.c.beginDNSGuardCommit()
			parent, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			ctx := &dnsCommitWaitGateContext{Context: parent, entered: make(chan struct{}), resume: make(chan struct{})}
			done := make(chan string, 1)
			go func() {
				done <- f.c.revalidateDNSGuardSnapshotDigest(ctx, id, owner, previous, entry, entry.Observed[0].InterfaceIndex, entry.Engines[0].ReqID)
			}()
			<-ctx.entered
			renewDNSDiagnosticGuard(t, f)
			token.published = f.c.dnsView.Load() // exactly committed A
			f.c.finishDNSGuardCommit(token)
			var secondToken *runtimeDNSGuardCommit
			if second == "published" {
				renewDNSDiagnosticGuard(t, f)
			} else {
				secondToken = f.c.beginDNSGuardCommit()
				// Native B is known in flight, but has no committed published template.
				f.observed.Store(`{"nftables":[]}`)
			}
			close(ctx.resume)
			if got := <-done; got != "" {
				t.Fatal("completed A adopted a later B template", got)
			}
			if secondToken != nil {
				f.c.finishDNSGuardCommit(secondToken)
			}
			expectedReads := int32(0)
			if second == "inflight" {
				expectedReads = 1
			}
			if f.guardReads.Load() != expectedReads {
				t.Fatal("extra token retry/native read", f.guardReads.Load())
			}
		})
	}
}
