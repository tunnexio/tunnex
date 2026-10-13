package ipsec

import (
	"context"
	"fmt"
	"github.com/google/uuid"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestCombinedBudgetHealthyStaticContinuity(t *testing.T) {
	c, entries, staticIDs := mixedBudgetFixture(t)
	c.prove = func(ctx context.Context, e RuntimeJournalEntry, _ RuntimeEnvironment) error {
		t.Logf("proof profile=%d ctx=%v", e.ContractVersion, ctx.Err())
		return nil
	}
	c.recoveryObserve = func(ctx context.Context, e RuntimeJournalEntry) [2]string {
		delay := 1600 * time.Millisecond
		if e.ContractVersion == 2 {
			delay = 300 * time.Millisecond
		}
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			t.Logf("observe deadline profile=%d err=%v", e.ContractVersion, ctx.Err())
			return [2]string{"unknown", "unknown"}
		}
		t.Logf("observe healthy profile=%d ctx=%v", e.ContractVersion, ctx.Err())
		return [2]string{"up", "up"}
	}
	calls := 0
	c.replace = func(ctx context.Context, in GuardIntent) (GuardManifest, error) {
		calls++
		t.Logf("replace call=%d ctx=%v", calls, ctx.Err())
		return RenderGuard(in)
	}
	for i, e := range entries {
		t.Logf("order=%d profile=%d connection=%s", i, e.ContractVersion, e.Allocation.ConnectionID)
	}
	err := c.installActive(context.Background(), entries)
	t.Logf("install err=%v replacecalls=%d active=%d", err, calls, len(c.active))
	for _, id := range staticIDs {
		if _, ok := c.active[id]; !ok {
			t.Errorf("healthy static authority removed by unrelated render budget: %s", id)
		}
	}
}

func mixedBudgetFixture(t *testing.T) (*RuntimeController, []RuntimeJournalEntry, []uuid.UUID) {
	c, _, _, _ := bgpControllerFixture(t, true)
	c.active = map[uuid.UUID]runtimeActive{}
	entries := []RuntimeJournalEntry{}
	for i := 0; i < 3; i++ {
		b, _, _, _ := bgpControllerFixture(t, true)
		for id, a := range b.active {
			a.Grants = nil
			c.bgpProcesses[a.Entry.DeliveryID] = b.bgpProcesses[a.Entry.DeliveryID]
			c.active[id] = a
			entries = append(entries, a.Entry)
		}
	}
	staticIDs := []uuid.UUID{}
	for i := 0; i < 2; i++ {
		r := newRecoveryTestRig(t)
		es, _ := r.c.journal.Entries()
		e := es[0]
		e.Allocation.Namespace = entries[0].Allocation.Namespace
		for j := range e.Observed {
			e.Observed[j].Namespace = e.Allocation.Namespace
		}
		a := NewPermitLeaseAuthority()
		id := PermitLeaseIdentity{DeliveryID: e.DeliveryID, Binding: e.Engines[0].Binding, PolicyHash: strings.Repeat("b", 64)}
		req, err := a.Begin(id)
		if err != nil {
			t.Fatal(err)
		}
		if err = a.Accept(PermitLeaseResponse{PermitLeaseRequest: req, TTLMillis: 60000}); err != nil {
			t.Fatal(err)
		}
		c.active[e.Allocation.ConnectionID] = runtimeActive{Entry: e, Authority: a, Identity: id, Environment: RuntimeEnvironment{Namespace: e.Allocation.Namespace}}
		entries = append(entries, e)
		staticIDs = append(staticIDs, e.Allocation.ConnectionID)
	}
	if len(c.active) != 5 || len(entries) != 5 {
		t.Fatal("fixture must contain exactly five distinct active entries")
	}
	for n := range entries {
		e := entries[n]
		remote := []netip.Prefix{netip.MustParsePrefix(fmt.Sprintf("10.%d.0.0/16", 85+n))}
		local := []netip.Prefix{netip.MustParsePrefix("10.84.2.0/24"), netip.MustParsePrefix("10.84.3.0/24")}
		for j := range e.Engines {
			e.Engines[j].Binding.OrgID = c.config.OrgID
			e.Engines[j].Binding.GatewayID = c.config.GatewayID
			e.Engines[j].LocalPrefixes = local
			e.Engines[j].RemotePrefixes = remote
			e.Engines[j].ReqID = uint32(100 + n*2 + j)
			e.Allocation.Tunnels[j].RemotePrefixes = remote
			e.Allocation.Tunnels[j].InsideAddress = netip.MustParsePrefix(fmt.Sprintf("169.254.%d.%d/30", n+1, j*4+1))
			if e.Allocation.BGP {
				e.Allocation.Tunnels[j].BGP.Peer = netip.MustParseAddr(fmt.Sprintf("169.254.%d.%d", n+1, j*4+2))
			}
			e.Observed[j].InterfaceIndex = 10 + n*2 + j
		}
		if e.BGPRoutes != nil {
			e.BGPRoutes.Owned = []RuntimeBGPRouteTuple{routeTupleFixture(e, 1)}
			e.BGPRoutes.Target = append([]RuntimeBGPRouteTuple{}, e.BGPRoutes.Owned...)
		}
		a := c.active[e.Allocation.ConnectionID]
		a.Entry = e
		a.Environment.Namespace = e.Allocation.Namespace
		a.Environment.Underlays = [2]RuntimeUnderlay{{InterfaceIndex: 2, OuterMTU: 1500, LocalAddress: netip.MustParseAddr("192.0.2.1")}, {InterfaceIndex: 2, OuterMTU: 1500, LocalAddress: netip.MustParseAddr("192.0.2.1")}}
		a.Identity.Binding = e.Engines[0].Binding
		a.Authority = NewPermitLeaseAuthority()
		req, err := a.Authority.Begin(a.Identity)
		if err != nil {
			t.Fatal(err)
		}
		if err = a.Authority.Accept(PermitLeaseResponse{PermitLeaseRequest: req, TTLMillis: 60000}); err != nil {
			t.Fatal(err)
		}
		c.active[e.Allocation.ConnectionID] = a
		entries[n] = e
	}
	if !validJournalPayload(runtimeJournalPayload{Version: 8, OwnerID: c.config.GatewayID, Entries: entries}) {
		t.Fatal("normalized five-entry journal invalid")
	}
	return c, entries, staticIDs
}

func TestCombinedBudgetUnknownAndForeignStaticRefuse(t *testing.T) {
	for _, mode := range []string{"unknown", "foreign-proof"} {
		t.Run(mode, func(t *testing.T) {
			c, entries, ids := mixedBudgetFixture(t)
			c.prove = func(_ context.Context, e RuntimeJournalEntry, _ RuntimeEnvironment) error {
				if mode == "foreign-proof" && e.Allocation.ConnectionID == ids[0] {
					return ErrRuntimeController
				}
				return nil
			}
			c.recoveryObserve = func(_ context.Context, e RuntimeJournalEntry) [2]string {
				if mode == "unknown" && e.Allocation.ConnectionID == ids[0] {
					return [2]string{"unknown", "up"}
				}
				return [2]string{"up", "up"}
			}
			c.replace = func(context.Context, GuardIntent) (GuardManifest, error) { return GuardManifest{}, nil }
			_ = c.installActive(context.Background(), entries)
			if _, ok := c.active[ids[0]]; ok {
				t.Fatal("unsafe static authority retained")
			}
		})
	}
}

func TestCombinedBudgetFixtureRenders(t *testing.T) {
	c, entries, _ := mixedBudgetFixture(t)
	calls := 0
	c.replace = func(_ context.Context, in GuardIntent) (GuardManifest, error) { calls++; return RenderGuard(in) }
	if err := c.installActive(context.Background(), entries); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatal("missing actual render")
	}
}

func budgetClock(t *testing.T, c *RuntimeController) *time.Duration {
	t.Helper()
	now := new(time.Duration)
	for id, a := range c.active {
		x := &PermitLeaseAuthority{elapsed: func() time.Duration { return *now }}
		req, err := x.Begin(a.Identity)
		if err != nil {
			t.Fatal(err)
		}
		if err = x.Accept(PermitLeaseResponse{PermitLeaseRequest: req, TTLMillis: 60000}); err != nil {
			t.Fatal(err)
		}
		a.Authority = x
		c.active[id] = a
	}
	return now
}
func TestCombinedBudgetLeaseExpiresDuringCollection(t *testing.T) {
	c, entries, _ := mixedBudgetFixture(t)
	now := budgetClock(t, c)
	c.recoveryObserve = func(context.Context, RuntimeJournalEntry) [2]string {
		*now += 12 * time.Second
		return [2]string{"up", "up"}
	}
	calls := 0
	c.replace = func(context.Context, GuardIntent) (GuardManifest, error) { calls++; return GuardManifest{}, nil }
	if c.installActive(context.Background(), entries) == nil || calls != 0 {
		t.Fatal("expired collection installed authority")
	}
}
func TestCombinedBudgetCommitDurationRecomputed(t *testing.T) {
	c, entries, _ := mixedBudgetFixture(t)
	now := budgetClock(t, c)
	c.recoveryObserve = func(context.Context, RuntimeJournalEntry) [2]string {
		*now += time.Second
		return [2]string{"up", "up"}
	}
	c.replace = func(ctx context.Context, in GuardIntent) (GuardManifest, error) {
		for _, g := range in.Connections {
			if g.PermitFor != 50*time.Second {
				t.Fatalf("stale duration %v", g.PermitFor)
			}
		}
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 5*time.Second {
			t.Fatal("missing bounded commit")
		}
		*now += 4 * time.Second
		return RenderGuard(in)
	}
	if err := c.installActive(context.Background(), entries); err != nil {
		t.Fatal(err)
	}
}
func TestCombinedBudgetCommitTimeout(t *testing.T) {
	c, entries, _ := mixedBudgetFixture(t)
	c.replace = func(ctx context.Context, in GuardIntent) (GuardManifest, error) {
		<-ctx.Done()
		return GuardManifest{}, ctx.Err()
	}
	start := time.Now()
	if c.installActive(context.Background(), entries) == nil {
		t.Fatal("commit timeout accepted")
	}
	if time.Since(start) > 6*time.Second {
		t.Fatal("commit exceeded bound")
	}
}
func TestCombinedBudgetParentCancellation(t *testing.T) {
	c, entries, _ := mixedBudgetFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	c.recoveryObserve = func(ctx context.Context, e RuntimeJournalEntry) [2]string { cancel(); return [2]string{"up", "up"} }
	calls := 0
	c.replace = func(_ context.Context, in GuardIntent) (GuardManifest, error) {
		for _, g := range in.Connections {
			if !g.PrefixOnly {
				calls++
			}
		}
		return GuardManifest{}, nil
	}
	if c.installActive(ctx, entries) == nil || calls != 0 {
		t.Fatal("parent cancellation installed permits")
	}
}

func TestCombinedBudgetLivenessLostDuringLaterCollection(t *testing.T) {
	for _, mode := range []string{"daemon"} {
		t.Run(mode, func(t *testing.T) {
			c, entries, _ := mixedBudgetFixture(t)
			alive := true
			c.config.DaemonAlive = func() bool { return alive }
			c.recoveryObserve = func(_ context.Context, e RuntimeJournalEntry) [2]string {
				if e.Allocation.ConnectionID == entries[4].Allocation.ConnectionID {
					if mode == "daemon" {
						alive = false
					} else {
						c.bgpProcesses[entries[0].DeliveryID].(*bgpSessionFixture).closed = true
					}
				}
				return [2]string{"up", "up"}
			}
			permits := 0
			c.replace = func(_ context.Context, in GuardIntent) (GuardManifest, error) {
				for _, g := range in.Connections {
					if !g.PrefixOnly {
						permits++
					}
				}
				return RenderGuard(in)
			}
			if c.installActive(context.Background(), entries) == nil || permits != 0 {
				t.Fatal("lost liveness committed permits")
			}
		})
	}
}

func TestCombinedBudgetFinalClockStallCannotAcquireFreshCommit(t *testing.T) {
	c, entries, _ := mixedBudgetFixture(t)
	budgetClock(t, c)
	a := c.active[entries[0].Allocation.ConnectionID]
	calls := 0
	a.Authority.elapsed = func() time.Duration {
		calls++
		if calls == 3 {
			time.Sleep(5100 * time.Millisecond)
		}
		return 0
	}
	permits := 0
	c.replace = func(_ context.Context, in GuardIntent) (GuardManifest, error) {
		for _, g := range in.Connections {
			if !g.PrefixOnly {
				permits++
			}
		}
		return RenderGuard(in)
	}
	if c.installActive(context.Background(), entries) == nil || permits != 0 {
		t.Fatal("final clock stall acquired fresh apply budget")
	}
}

func TestCombinedBudgetLivenessLostDuringFinalClockRead(t *testing.T) {
	for _, mode := range []string{"daemon", "bgp-process"} {
		t.Run(mode, func(t *testing.T) {
			c, _, _, _ := bgpControllerFixture(t, true)
			entries, _ := c.journal.Entries()
			budgetClock(t, c)
			alive := true
			c.config.DaemonAlive = func() bool { return alive }
			a := c.active[entries[0].Allocation.ConnectionID]
			calls := 0
			a.Authority.elapsed = func() time.Duration {
				calls++
				if calls == 3 {
					time.Sleep(50 * time.Millisecond)
					if mode == "daemon" {
						alive = false
					} else {
						c.bgpProcesses[entries[0].DeliveryID].(*bgpSessionFixture).closed = true
					}
				}
				return 0
			}
			permits := 0
			c.replace = func(_ context.Context, in GuardIntent) (GuardManifest, error) {
				for _, g := range in.Connections {
					if len(g.Grants) > 0 {
						permits++
					}
				}
				return RenderGuard(in)
			}
			if c.installActive(context.Background(), entries) == nil || permits != 0 {
				t.Fatal("liveness lost during final clock read committed application permits")
			}
		})
	}
}
func TestCombinedBudgetTransportOnlyBeforeBGPProcess(t *testing.T) {
	c, entries, _ := mixedBudgetFixture(t)
	c.bgpProcesses = nil
	c.replace = func(_ context.Context, in GuardIntent) (GuardManifest, error) { return RenderGuard(in) }
	if err := c.installActive(context.Background(), entries); err != nil {
		t.Fatal(err)
	}
}
func TestCombinedBudgetMissingDaemonRefusesLiveButAllowsDenial(t *testing.T) {
	for _, alive := range []func() bool{nil, func() bool { return false }} {
		c, entries, _ := mixedBudgetFixture(t)
		c.config.DaemonAlive = alive
		permits := 0
		c.replace = func(_ context.Context, in GuardIntent) (GuardManifest, error) {
			for _, g := range in.Connections {
				if !g.PrefixOnly {
					permits++
				}
			}
			return RenderGuard(in)
		}
		if c.installActive(context.Background(), entries) == nil || permits != 0 {
			t.Fatal("missing daemon allowed transport")
		}
		c.active = nil
		if err := c.installActive(context.Background(), entries); err != nil {
			t.Fatal("denial-only refused", err)
		}
	}
}
