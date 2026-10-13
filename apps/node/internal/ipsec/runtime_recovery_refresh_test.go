package ipsec

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"net/netip"
	"reflect"
	"testing"
	"time"
)

func refreshDeniedFixture(t *testing.T, r *recoveryTestRig) *[]byte {
	t.Helper()
	entries, _ := r.c.journal.Entries()
	e := entries[0]
	m, err := RenderGuard(GuardIntent{Namespace: e.Allocation.Namespace, OwnerID: r.c.config.GatewayID, Revision: 1, Connections: []GuardConnection{{ID: e.Allocation.ConnectionID, PrefixOnly: true, Local: e.Engines[0].LocalPrefixes, Remote: e.Engines[0].RemotePrefixes}}})
	if err != nil {
		t.Fatal(err)
	}
	if r.c.journal.prepareGuard(m) != nil || r.c.journal.finishGuard(m) != nil {
		t.Fatal("guard journal")
	}
	raw := []byte(m.ExpectedJSON)
	reader := &GuardReader{namespace: r.c.namespace, interfaces: func() ([]GuardInterface, error) {
		return []GuardInterface{{Name: e.Observed[0].InterfaceName, Index: e.Observed[0].InterfaceIndex}, {Name: e.Observed[1].InterfaceName, Index: e.Observed[1].InterfaceIndex}}, nil
	}, run: func(context.Context, ...string) ([]byte, error) { return raw, nil }}
	r.c.guard = &RuntimeGuard{journal: r.c.journal, reader: reader}
	return &raw
}

type refreshLeaseFixture struct {
	requests []RuntimeLeaseRequest
	mutate   func(*RuntimeLease)
	deny     bool
	onRenew  func(context.Context)
}

func (l *refreshLeaseFixture) RenewIPsecLease(ctx context.Context, _ uuid.UUID, r RuntimeLeaseRequest) (RuntimeLease, error) {
	l.requests = append(l.requests, r)
	if l.onRenew != nil {
		l.onRenew(ctx)
	}
	if l.deny {
		return RuntimeLease{}, errors.New("revoked")
	}
	v := RuntimeLease{RuntimeLeaseRequest: r, TTLMS: 60000}
	if l.mutate != nil {
		l.mutate(&v)
	}
	return v, nil
}
func TestRecoveryRefreshInactiveFreshDownEvidence(t *testing.T) {
	r := newRecoveryTestRig(t)
	r.status = [2]string{"up", "up"}
	if err := r.apply(); err != nil {
		t.Fatal(err)
	}
	refreshDeniedFixture(t, r)
	lease := &refreshLeaseFixture{}
	r.c.client = lease
	before, _ := r.c.journal.Entries()
	events := len(r.events)
	switches := r.switches
	r.status = [2]string{"down", "up"}
	for _, at := range []time.Duration{5 * time.Second, 10 * time.Second, 15 * time.Second} {
		r.now = at
		if err := r.c.RefreshIPsecRecovery(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	h := r.c.recoveryHistory[before[0].Allocation.ConnectionID]
	if h.consecutive != 3 || h.lastNow-h.firstDown != 10*time.Second {
		t.Fatalf("fresh evidence missing: %+v", h)
	}
	after, _ := r.c.journal.Entries()
	if !reflect.DeepEqual(before, after) || r.switches != switches || len(r.events) != events {
		t.Fatal("observation mutated runtime")
	}
	if len(lease.requests) != 3 {
		t.Fatal("fresh lease missing")
	}
	seen := map[string]bool{}
	for _, q := range lease.requests {
		if seen[q.Nonce] {
			t.Fatal("nonce reused")
		}
		seen[q.Nonce] = true
	}
}
func TestRecoveryRefreshRefusesUnsafeEvidence(t *testing.T) {
	for _, kind := range []string{"nonce", "revision", "hash", "revoked", "short-lease", "no-cp", "unknown", "timing", "foreign-rule", "nonempty", "owner", "environment", "cleanup"} {
		t.Run(kind, func(t *testing.T) {
			r := newRecoveryTestRig(t)
			r.status = [2]string{"up", "up"}
			if err := r.apply(); err != nil {
				t.Fatal(err)
			}
			raw := refreshDeniedFixture(t, r)
			switches := r.switches
			id := r.m.Manifest.ConnectionID
			lease := &refreshLeaseFixture{}
			r.c.client = lease
			r.now = 5 * time.Second
			r.status = [2]string{"down", "up"}
			switch kind {
			case "nonce":
				lease.mutate = func(v *RuntimeLease) { v.Nonce = "wrong" }
			case "revision":
				lease.mutate = func(v *RuntimeLease) { v.DesiredRevision++ }
			case "hash":
				lease.mutate = func(v *RuntimeLease) { v.PolicyHash = "wrong" }
			case "revoked":
				lease.deny = true
			case "short-lease":
				lease.mutate = func(v *RuntimeLease) { v.TTLMS = 1 }
			case "no-cp":
				r.c.client = nil
			case "unknown":
				r.status = [2]string{"unknown", "up"}
			case "timing":
				r.c.recoveryObserve = func(context.Context, RuntimeJournalEntry) [2]string { r.now += 6 * time.Second; return r.status }
			case "owner":
				r.c.config.GatewayID = uuid.New()
			case "environment":
				r.c.recoveryPrepared[r.m.ID] = RuntimeEnvironment{}
			case "cleanup":
				// Journal phase validation forbids fabricating cleanup; invalidate the known
				// epoch revision instead, matching current cleanup/new-revision intake.
				r.c.recoveryHistory[id].epoch.Binding.DesiredRevision++
			case "foreign-rule", "nonempty":
				var d map[string]any
				json.Unmarshal(*raw, &d)
				items := d["nftables"].([]any)
				if kind == "foreign-rule" {
					d["nftables"] = append(items, map[string]any{"rule": map[string]any{"family": "inet", "table": "tunnex_ipsec", "chain": "output_guard", "expr": []any{map[string]any{"accept": nil}}}})
				} else {
					for _, x := range items {
						if s, ok := x.(map[string]any)["set"].(map[string]any); ok && s["name"] == guardLeaseName(id) {
							s["elem"] = []any{map[string]any{"elem": map[string]any{"val": 10, "timeout": 60}}}
						}
					}
				}
				*raw, _ = json.Marshal(d)
			}
			_ = r.c.RefreshIPsecRecovery(context.Background())
			if r.c.recoveryHistory[id] != nil {
				t.Fatal("unsafe evidence retained")
			}
			if r.switches != switches {
				t.Fatal("refresh switched route")
			}
		})
	}
}
func TestRecoveryDeniedObservationSurvivesOtherGuardFailure(t *testing.T) {
	r := newRecoveryTestRig(t)
	r.status = [2]string{"up", "up"}
	if err := r.apply(); err != nil {
		t.Fatal(err)
	}
	refreshDeniedFixture(t, r)
	switches := r.switches
	entries, _ := r.c.journal.Entries()
	target := entries[0].Allocation.ConnectionID
	other := uuid.New()
	a := r.c.active[target]
	a.Entry.Allocation.ConnectionID = other
	for i := range a.Entry.Engines {
		a.Entry.Engines[i].Binding.ConnectionID = other
	}
	a.Identity.Binding.ConnectionID = other
	a.Authority = NewPermitLeaseAuthority()
	q, _ := a.Authority.Begin(a.Identity)
	a.Authority.Accept(PermitLeaseResponse{PermitLeaseRequest: q, TTLMillis: 60000})
	r.c.active[other] = a
	entries = append(entries, a.Entry)
	r.now = 5 * time.Second
	r.status = [2]string{"down", "up"}
	r.c.prove = func(_ context.Context, e RuntimeJournalEntry, _ RuntimeEnvironment) error {
		if e.Allocation.ConnectionID == other {
			return nil
		}
		return ErrRuntimeController
	}
	r.c.recoveryObserve = func(_ context.Context, e RuntimeJournalEntry) [2]string {
		if e.Allocation.ConnectionID == other {
			return [2]string{"unknown", "unknown"}
		}
		return r.status
	}
	_, err := r.c.applyRecovery(context.Background(), r.m, entries, 0, r.env, nil)
	if err == nil {
		t.Fatal("global failure acknowledged")
	}
	h := r.c.recoveryHistory[target]
	if h == nil || h.consecutive != 1 {
		t.Fatalf("target history starved: %+v", h)
	}
	if r.switches != switches {
		t.Fatal("early switch")
	}
}
func TestRecoveryRefreshSkipsGenuinePositiveGuardWithoutAuthority(t *testing.T) {
	r := newRecoveryTestRig(t)
	r.status = [2]string{"up", "up"}
	if err := r.apply(); err != nil {
		t.Fatal(err)
	}
	entries, _ := r.c.journal.Entries()
	e := entries[0]
	g := guardFixture()
	g.OwnerID = r.c.config.GatewayID
	g.Namespace = e.Allocation.Namespace
	g.Connections[0].ID = e.Allocation.ConnectionID
	m, err := RenderGuard(g)
	if err != nil {
		t.Fatal(err)
	}
	if r.c.journal.prepareGuard(m) != nil || r.c.journal.finishGuard(m) != nil {
		t.Fatal("template")
	}
	r.c.guard = &RuntimeGuard{journal: r.c.journal, reader: &GuardReader{namespace: r.c.namespace, interfaces: func() ([]GuardInterface, error) { return nil, nil }, run: func(context.Context, ...string) ([]byte, error) { return []byte(m.ExpectedJSON), nil }}}
	lease := &refreshLeaseFixture{}
	r.c.client = lease
	r.now = 5 * time.Second
	h := *r.c.recoveryHistory[e.Allocation.ConnectionID]
	if err := r.c.RefreshIPsecRecovery(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(lease.requests) != 0 || *r.c.recoveryHistory[e.Allocation.ConnectionID] != h {
		t.Fatal("positive guard accepted as denied")
	}
}
func TestRecoveryRefreshRefusesPermissionAppearingAfterNativeRead(t *testing.T) {
	r := newRecoveryTestRig(t)
	r.status = [2]string{"up", "up"}
	if err := r.apply(); err != nil {
		t.Fatal(err)
	}
	raw := refreshDeniedFixture(t, r)
	id := r.m.Manifest.ConnectionID
	r.now = 5 * time.Second
	r.c.recoveryObserve = func(context.Context, RuntimeJournalEntry) [2]string {
		var d map[string]any
		json.Unmarshal(*raw, &d)
		for _, v := range d["nftables"].([]any) {
			if s, ok := v.(map[string]any)["set"].(map[string]any); ok && s["name"] == guardReplyLeaseName(id) {
				s["elem"] = []any{map[string]any{"elem": map[string]any{"val": 11, "timeout": 60}}}
			}
		}
		*raw, _ = json.Marshal(d)
		return [2]string{"down", "up"}
	}
	if r.c.RefreshIPsecRecovery(context.Background()) == nil || r.c.recoveryHistory[id] != nil {
		t.Fatal("postread permission accepted")
	}
}
func TestRecoveryRefreshEvidenceCannotCrossFreshMaterialPolicy(t *testing.T) {
	r := newRecoveryTestRig(t)
	r.status = [2]string{"up", "up"}
	if err := r.apply(); err != nil {
		t.Fatal(err)
	}
	refreshDeniedFixture(t, r)
	r.status = [2]string{"down", "up"}
	for _, at := range []time.Duration{5 * time.Second, 10 * time.Second, 15 * time.Second} {
		r.now = at
		if err := r.c.RefreshIPsecRecovery(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	switches := r.switches
	r.now = 16 * time.Second
	r.m.Policy.Hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	_ = r.apply()
	if r.switches != switches {
		t.Fatal("queued changed policy consumed prior evidence")
	}
	h := r.c.recoveryHistory[r.m.Manifest.ConnectionID]
	if h == nil || h.consecutive != 1 {
		t.Fatalf("new policy did not reset: %+v", h)
	}
}

func TestRecoveryRefreshThenOrdinaryApplySwitches(t *testing.T) {
	r := newRecoveryTestRig(t)
	r.status = [2]string{"up", "up"}
	if err := r.apply(); err != nil {
		t.Fatal(err)
	}
	refreshDeniedFixture(t, r)
	r.c.client = &refreshLeaseFixture{}
	before := r.switches
	r.status = [2]string{"down", "up"}
	for _, at := range []time.Duration{5 * time.Second, 10 * time.Second, 15 * time.Second} {
		r.now = at
		if err := r.c.RefreshIPsecRecovery(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if r.switches != before {
		t.Fatal("refresh mutated route")
	}
	r.now = 16 * time.Second
	if err := r.apply(); err != nil {
		t.Fatal(err)
	}
	entries, err := r.c.journal.Entries()
	if err != nil {
		t.Fatal(err)
	}
	if r.switches != before+1 || selectedRuntimeSlot(entries[0]) != 2 || entries[0].Recovery.Sequence != 1 {
		t.Fatalf("ordinary Apply did not consume evidence: switches=%d recovery=%+v", r.switches, entries[0].Recovery)
	}
}

type refreshSlowEnvironment struct {
	env     RuntimeEnvironment
	advance func()
}

func (e *refreshSlowEnvironment) Observe(context.Context, KernelAllocation, [2]EngineTunnel) (RuntimeEnvironment, error) {
	e.advance()
	return e.env, nil
}
func (e *refreshSlowEnvironment) Drain(context.Context, []RuntimeJournalEntry) error { return nil }
func TestRecoveryRefreshSharedBudgetAcrossCPAndEnvironment(t *testing.T) {
	r := newRecoveryTestRig(t)
	r.status = [2]string{"up", "up"}
	if err := r.apply(); err != nil {
		t.Fatal(err)
	}
	refreshDeniedFixture(t, r)
	r.now = 5 * time.Second
	r.status = [2]string{"down", "up"}
	r.c.client = &refreshLeaseFixture{onRenew: func(context.Context) { r.now += 3 * time.Second }}
	r.c.config.Environment = &refreshSlowEnvironment{env: r.env, advance: func() { r.now += 2 * time.Second }}
	if r.c.RefreshIPsecRecovery(context.Background()) == nil || r.c.recoveryHistory[r.m.Manifest.ConnectionID] != nil {
		t.Fatal("combined seven-second callback retained evidence")
	}
}

func TestRecoveryRefreshCancelledCPResetsEvidence(t *testing.T) {
	r := newRecoveryTestRig(t)
	r.status = [2]string{"up", "up"}
	if err := r.apply(); err != nil {
		t.Fatal(err)
	}
	refreshDeniedFixture(t, r)
	r.now = 5 * time.Second
	r.status = [2]string{"down", "up"}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r.c.client = &refreshLeaseFixture{onRenew: func(context.Context) { cancel() }}
	if r.c.RefreshIPsecRecovery(ctx) == nil || r.c.recoveryHistory[r.m.Manifest.ConnectionID] != nil {
		t.Fatal("cancelled authority retained evidence")
	}
}

// Multiple native reads must share the callback budget without losing fresh evidence.
func TestRecoveryRefreshBoundedNativeReadCost(t *testing.T) {
	r := newRecoveryTestRig(t)
	r.status = [2]string{"up", "up"}
	if err := r.apply(); err != nil {
		t.Fatal(err)
	}
	refreshDeniedFixture(t, r)
	r.c.client = &refreshLeaseFixture{}
	r.now = 5 * time.Second
	r.status = [2]string{"down", "up"}
	originalRun := r.c.guard.reader.run
	reads := 0
	r.c.guard.reader.run = func(ctx context.Context, args ...string) ([]byte, error) {
		reads++
		r.now += 1500 * time.Millisecond
		return originalRun(ctx, args...)
	}
	r.c.config.Environment = &refreshSlowEnvironment{env: r.env, advance: func() { r.now += 500 * time.Millisecond }}
	before, _ := r.c.journal.Entries()
	switches, events := r.switches, len(r.events)
	if err := r.c.RefreshIPsecRecovery(context.Background()); err != nil {
		t.Fatalf("bounded native cost starved inactive evidence: reads=%d elapsed=%v err=%v", reads, r.now-5*time.Second, err)
	}
	h := r.c.recoveryHistory[r.m.Manifest.ConnectionID]
	if h == nil || h.consecutive != 1 || reads != 2 {
		t.Fatalf("expected exact two native reads and fresh evidence: reads=%d history=%+v", reads, h)
	}
	after, _ := r.c.journal.Entries()
	if !reflect.DeepEqual(before, after) || r.switches != switches || len(r.events) != events {
		t.Fatal("read-only refresh mutated runtime")
	}
}

func TestRecoveryGuardCandidateSnapshotSeparatesPositiveProvider(t *testing.T) {
	r := newRecoveryTestRig(t)
	entries, _ := r.c.journal.Entries()
	target := entries[0]
	other := uuid.New()
	g := guardFixture()
	g.OwnerID = r.c.config.GatewayID
	g.Namespace = target.Allocation.Namespace
	positive := g.Connections[0]
	positive.ID = other
	positive.Remote = []netip.Prefix{netip.MustParsePrefix("10.111.0.0/24")}
	positive.Local = target.Engines[0].LocalPrefixes
	positive.Grants[0].Source = positive.Local[0]
	positive.Grants[0].Destination = positive.Remote[0]
	positive.Tunnels[0].InterfaceIndex, positive.Tunnels[1].InterfaceIndex = 20, 21
	positive.PermittedInterfaceIndices = []int{20}
	g.Connections = []GuardConnection{{ID: target.Allocation.ConnectionID, PrefixOnly: true, Local: target.Engines[0].LocalPrefixes, Remote: target.Engines[0].RemotePrefixes}, positive}
	m, err := RenderGuard(g)
	if err != nil {
		t.Fatal(err)
	}
	if r.c.journal.prepareGuard(m) != nil || r.c.journal.finishGuard(m) != nil {
		t.Fatal("guard")
	}
	reads := 0
	r.c.guard = &RuntimeGuard{journal: r.c.journal, reader: &GuardReader{namespace: r.c.namespace, interfaces: func() ([]GuardInterface, error) {
		return []GuardInterface{{Name: "tnxi-a", Index: 20}, {Name: "tnxi-b", Index: 21}}, nil
	}, run: func(context.Context, ...string) ([]byte, error) { reads++; return []byte(m.ExpectedJSON), nil }}}
	candidates := []RuntimeJournalEntry{target, {Allocation: KernelAllocation{Namespace: g.Namespace, ConnectionID: other}}}
	denied, err := r.c.recoveryGuardDenials(context.Background(), candidates)
	if err != nil || !denied[target.Allocation.ConnectionID] || denied[other] || reads != 1 {
		t.Fatalf("shared snapshot mixed authority or reread: denied=%v reads=%d err=%v", denied, reads, err)
	}
	for _, change := range []string{"nil", "duplicate", "namespace", "missing", "changed-links"} {
		t.Run(change, func(t *testing.T) {
			bad := append([]RuntimeJournalEntry(nil), candidates...)
			old := *r.c.guard.reader
			defer func() { *r.c.guard.reader = old }()
			switch change {
			case "nil":
				bad[1].Allocation.ConnectionID = uuid.Nil
			case "duplicate":
				bad[1] = bad[0]
			case "namespace":
				bad[1].Allocation.Namespace = "net:[2]"
			case "missing":
				bad[1].Allocation.ConnectionID = uuid.New()
			case "changed-links":
				n := 0
				r.c.guard.reader.interfaces = func() ([]GuardInterface, error) {
					n++
					index := 20
					if n > 1 {
						index = 22
					}
					return []GuardInterface{{Name: "tnxi-a", Index: index}, {Name: "tnxi-b", Index: 21}}, nil
				}
			}
			if _, err := r.c.recoveryGuardDenials(context.Background(), bad); err == nil {
				t.Fatal("unsafe candidate snapshot accepted")
			}
		})
	}
}
