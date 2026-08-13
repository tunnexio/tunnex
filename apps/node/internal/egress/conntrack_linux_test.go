//go:build linux

package egress

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	conntrack "github.com/florianl/go-conntrack"

	"github.com/tunnexio/tunnex/apps/node/internal/nodepolicy"
)

func ipp(s string) *net.IP  { p := net.ParseIP(s); return &p }
func u8p(v uint8) *uint8    { return &v }
func u16p(v uint16) *uint16 { return &v }

func con(src, dst string, proto uint8, dport uint16) conntrack.Con {
	return conntrack.Con{Origin: &conntrack.IPTuple{
		Src: ipp(src), Dst: ipp(dst),
		Proto: &conntrack.ProtoTuple{Number: u8p(proto), DstPort: u16p(dport)},
	}}
}

// TestMatchesTupleScoped — the INNOCENT-NEIGHBOR centerpiece (S8.7 Slice 2): the flush filter matches the
// removed grant's EXACT tuple and nothing wider. A flow differing in ANY one dimension (src, dst, proto,
// dst-port) SURVIVES — proven by survival, not by the filter's appearance. One predicate too wide is a
// self-inflicted outage on the busiest gateway.
func TestMatchesTupleScoped(t *testing.T) {
	rt, ok := tupleFromAllow(nodepolicy.AllowEntry{SrcIP: "172.31.17.64/32", DstCIDR: "10.0.0.4/32", Protocol: "tcp", PortLow: 5432, PortHigh: 5432})
	if !ok {
		t.Fatal("tuple parse")
	}
	if !matchesTuple(con("172.31.17.64", "10.0.0.4", 6, 5432), rt) {
		t.Fatal("the EXACT removed tuple must match (get flushed)")
	}
	// Each neighbor differs in ONE dimension → must NOT match → survives the flush.
	survivors := []struct {
		name     string
		src, dst string
		proto    uint8
		dport    uint16
	}{
		{"different src", "172.31.17.65", "10.0.0.4", 6, 5432},
		{"different dst", "172.31.17.64", "10.0.0.5", 6, 5432},
		{"different proto", "172.31.17.64", "10.0.0.4", 17, 5432},
		{"different dst-port", "172.31.17.64", "10.0.0.4", 6, 5433},
		// GAP-3 ruling: orig-tuple-only matching is correct. A flow whose ORIGIN runs the OTHER way (B→A,
		// B-initiated) was authorized by a DIFFERENT grant and must SURVIVE the A→B rule's flush — matching
		// the reply tuple would over-delete, violating innocent-neighbor from the opposite side. (Deleting
		// the A→B flow's conntrack entry already kills BOTH its directions — one entry, orig+reply.)
		{"reply-direction (B-initiated, own grant)", "10.0.0.4", "172.31.17.64", 6, 5432},
	}
	for _, n := range survivors {
		if matchesTuple(con(n.src, n.dst, n.proto, n.dport), rt) {
			t.Fatalf("innocent neighbor (%s) must SURVIVE the scoped flush", n.name)
		}
	}
	// A proto-any / no-port grant (a site subnet source) matches every L4 within its src/dst — but still
	// scoped to THAT src/dst; a different dst survives.
	wide, _ := tupleFromAllow(nodepolicy.AllowEntry{SrcIP: "172.31.0.0/16", DstCIDR: "10.0.0.0/24", Protocol: "any"})
	if !matchesTuple(con("172.31.9.9", "10.0.0.7", 17, 53), wide) {
		t.Fatal("a proto-any grant must match any L4 within its src/dst")
	}
	if matchesTuple(con("172.31.9.9", "10.9.9.9", 17, 53), wide) {
		t.Fatal("a different dst must survive even a proto-any grant")
	}
}

// TestRemovedTuplesDiff — the diff finds grants that LEFT the allow set (expired/deleted), keeps the ones
// that stayed. The kept neighbor is never in the removed set.
func TestRemovedTuplesDiff(t *testing.T) {
	a := nodepolicy.AllowEntry{SrcIP: "10.99.0.10", DstCIDR: "10.0.5.0/24", Protocol: "tcp", PortLow: 5432, PortHigh: 5432, RuleID: "rA"}
	b := nodepolicy.AllowEntry{SrcIP: "172.31.17.64/32", DstCIDR: "10.0.0.4/32", Protocol: "any", RuleID: "rB"}
	removed := removedTuples([]nodepolicy.AllowEntry{a, b}, []nodepolicy.AllowEntry{a}) // b left
	if len(removed) != 1 || removed[0].ruleID != "rB" {
		t.Fatalf("only the removed grant (rB) must be flushed, got %+v", removed)
	}
	// nothing removed → empty (a steady-state reconcile flushes nothing).
	if r := removedTuples([]nodepolicy.AllowEntry{a, b}, []nodepolicy.AllowEntry{a, b}); len(r) != 0 {
		t.Fatalf("an unchanged allow set must flush nothing, got %+v", r)
	}
}

// TestFlushWiringOnRemoval — D5 one-function-two-triggers: a successful enforcing apply that DROPPED a grant
// flushes EXACTLY that grant's tuple (the kept grant is not flushed); the path is identical whether the
// grant left by expiry or by manual delete (the agent only sees an absent entry). Uses the injected ctFlush.
func TestFlushWiringOnRemoval(t *testing.T) {
	var flushed [][]flowTuple
	m := &Manager{
		apply: func(context.Context, string) error { return nil }, // apply always succeeds
		now:   time.Now,
		ctFlush: func(_ context.Context, ts []flowTuple) (int, error) {
			flushed = append(flushed, ts)
			return len(ts), nil
		},
	}
	a := nodepolicy.AllowEntry{SrcIP: "10.99.0.10", DstCIDR: "10.0.5.0/24", Protocol: "tcp", PortLow: 5432, PortHigh: 5432, RuleID: "rA"}
	b := nodepolicy.AllowEntry{SrcIP: "172.31.17.64/32", DstCIDR: "10.0.0.4/32", Protocol: "any", RuleID: "rB"}
	enf := func(allow ...nodepolicy.AllowEntry) *nodepolicy.Compiled {
		return &nodepolicy.Compiled{Mode: nodepolicy.ModeEnforcing, Allow: allow}
	}
	ctx := context.Background()

	// First apply: allow {A,B}. No prior applied set → nothing removed → no flush.
	if err := m.applyAndTrack(ctx, "ruleset", enf(a, b)); err != nil {
		t.Fatalf("apply 1: %v", err)
	}
	m.drainFlush(ctx)
	if len(flushed) != 0 {
		t.Fatalf("the first apply must flush nothing, got %+v", flushed)
	}
	// Second apply: allow {A} — B's grant LEFT (expired or deleted; indistinguishable). Flush EXACTLY B.
	if err := m.applyAndTrack(ctx, "ruleset", enf(a)); err != nil {
		t.Fatalf("apply 2: %v", err)
	}
	m.drainFlush(ctx)
	if len(flushed) != 1 || len(flushed[0]) != 1 || flushed[0][0].ruleID != "rB" {
		t.Fatalf("removing B must flush EXACTLY B's tuple (A survives), got %+v", flushed)
	}
}

// TestFlushFailureSurfacedNotSilent — a flush error (e.g. CAP_NET_ADMIN absent, netlink fault) is recorded
// in flushErr (surfaced) and does NOT fail the apply — the rule removal already succeeded; lingering flows
// are degraded-not-broken, never silent.
func TestFlushFailureSurfacedNotSilent(t *testing.T) {
	boom := errors.New("conntrack open (CAP_NET_ADMIN?): operation not permitted")
	m := &Manager{
		apply:   func(context.Context, string) error { return nil },
		now:     time.Now,
		ctFlush: func(context.Context, []flowTuple) (int, error) { return 0, boom },
	}
	a := nodepolicy.AllowEntry{SrcIP: "10.99.0.10", DstCIDR: "10.0.5.0/24", Protocol: "tcp", PortLow: 5432, PortHigh: 5432, RuleID: "rA"}
	ctx := context.Background()
	if err := m.applyAndTrack(ctx, "ruleset", &nodepolicy.Compiled{Mode: nodepolicy.ModeEnforcing, Allow: []nodepolicy.AllowEntry{a}}); err != nil {
		t.Fatalf("apply 1: %v", err)
	}
	m.drainFlush(ctx)
	// Drop the grant → a flush is attempted → the flusher errors.
	if err := m.applyAndTrack(ctx, "ruleset", &nodepolicy.Compiled{Mode: nodepolicy.ModeEnforcing}); err != nil {
		t.Fatalf("apply 2 (rule removal) must SUCCEED despite a flush failure, got %v", err)
	}
	m.drainFlush(ctx)
	m.mu.Lock()
	fe := m.flushErr
	m.mu.Unlock()
	if fe == nil {
		t.Fatal("a flush failure must be SURFACED in flushErr (never silent)")
	}
	// SURFACED on the health plane: the agent reports it via ConntrackFlushFailing → conntrack_flush_unavailable.
	if !m.ConntrackFlushFailing() {
		t.Fatal("a persistent flush failure must be reported via ConntrackFlushFailing (health-plane surface)")
	}
	// RECOVERY: the next successful flush clears it (CAP restored / netlink healthy) → the kind clears.
	m.ctFlush = func(context.Context, []flowTuple) (int, error) { return 1, nil }
	if err := m.applyAndTrack(ctx, "ruleset", &nodepolicy.Compiled{Mode: nodepolicy.ModeEnforcing, Allow: []nodepolicy.AllowEntry{a}}); err != nil {
		t.Fatalf("re-add grant: %v", err)
	}
	m.drainFlush(ctx)
	if err := m.applyAndTrack(ctx, "ruleset", &nodepolicy.Compiled{Mode: nodepolicy.ModeEnforcing}); err != nil {
		t.Fatalf("re-remove grant: %v", err)
	}
	m.drainFlush(ctx)
	if m.ConntrackFlushFailing() {
		t.Fatal("a successful flush must CLEAR the failing state (recovery → kind clears)")
	}
}

// TestFamiliesOf — [11]/[17]: the flush dumps ONLY the families the removed tuples span. An all-v4 removal
// never touches IPv6 (so a v6-less kernel can't false-fail).
func TestFamiliesOf(t *testing.T) {
	v4, _ := tupleFromAllow(nodepolicy.AllowEntry{SrcIP: "10.0.0.1/32", DstCIDR: "10.0.0.2/32"})
	v6, _ := tupleFromAllow(nodepolicy.AllowEntry{SrcIP: "2001:db8::1/128", DstCIDR: "2001:db8::2/128"})
	if f := familiesOf([]flowTuple{v4}); len(f) != 1 || f[0] != conntrack.IPv4 {
		t.Fatalf("v4-only tuples → [IPv4] only, got %v", f)
	}
	if f := familiesOf([]flowTuple{v6}); len(f) != 1 || f[0] != conntrack.IPv6 {
		t.Fatalf("v6-only tuples → [IPv6] only, got %v", f)
	}
	if f := familiesOf([]flowTuple{v4, v6}); len(f) != 2 {
		t.Fatalf("mixed tuples → both families, got %v", f)
	}
}

// enfPol builds an enforcing Compiled for the flush tests.
func enfPol(allow ...nodepolicy.AllowEntry) *nodepolicy.Compiled {
	return &nodepolicy.Compiled{Mode: nodepolicy.ModeEnforcing, Allow: allow}
}

// TestPartialFlushFailureKeepsKindRaised — F2/RE5 the per-family/per-flow accounting surface: a flush that kills
// some flows but returns a (joined) error must still raise conntrack_flush_unavailable. Killing a v4 flow does
// NOT mask a v6 dump/delete failure — the standing over-report preference (annoyance heals, silence doesn't).
func TestPartialFlushFailureKeepsKindRaised(t *testing.T) {
	m := &Manager{
		apply:   func(context.Context, string) error { return nil },
		now:     time.Now,
		ctFlush: func(context.Context, []flowTuple) (int, error) { return 2, errors.New("conntrack dump ipv6: ENOBUFS") },
	}
	a := nodepolicy.AllowEntry{SrcIP: "10.99.0.10", DstCIDR: "10.0.5.0/24", Protocol: "any", RuleID: "rA"}
	ctx := context.Background()
	if err := m.applyAndTrack(ctx, "rs", enfPol(a)); err != nil {
		t.Fatalf("apply 1: %v", err)
	}
	m.drainFlush(ctx)
	if err := m.applyAndTrack(ctx, "rs", enfPol()); err != nil { // drop the grant → a flush is attempted
		t.Fatalf("apply 2: %v", err)
	}
	m.drainFlush(ctx)
	if !m.ConntrackFlushFailing() {
		t.Fatal("a flush that killed some flows but returned a joined error must KEEP the kind raised (kills never mask a partial failure)")
	}
}
