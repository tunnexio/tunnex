package helper

import (
	"errors"
	"strings"
	"testing"
)

// fakeRoutes is the routeCmd seam's stand-in: it records every (op,target) and maintains a kernel-truth
// set so a test can assert what's actually installed. failAdd makes `route add <t>` fail for t in the set;
// existsErr models the "File exists" failure a NON-idempotent add would hit on a pre-existing route.
type fakeRoutes struct {
	kernel    map[string]bool // routes "in the kernel"
	calls     []string        // "add <t>" / "del <t>" in order
	failAdd   map[string]bool // targets whose add fails (transient)
	existsErr bool            // if true, add of an already-present route errors "File exists"
}

func newFakeRoutes(pre ...string) *fakeRoutes {
	f := &fakeRoutes{kernel: map[string]bool{}, failAdd: map[string]bool{}}
	for _, t := range pre {
		f.kernel[t] = true
	}
	return f
}

func (f *fakeRoutes) cmd(add bool, target string) error {
	if add {
		f.calls = append(f.calls, "add "+target)
		if f.failAdd[target] {
			return errors.New("transient routing-socket error")
		}
		if f.existsErr && f.kernel[target] {
			return errors.New("route: writing to routing socket: File exists")
		}
		f.kernel[target] = true
		return nil
	}
	f.calls = append(f.calls, "del "+target)
	delete(f.kernel, target)
	return nil
}

func kernelSet(f *fakeRoutes) []string { return sortedKeys(f.kernel) }

// RED #1 — partial-add then retry CONVERGES: r2's add fails, but r1 stays applied so the retry re-attempts
// ONLY r2 and never re-issues `route add r1` (which would fail "File exists"). Routes converge.
func TestReconcilePartialAddThenRetryConverges(t *testing.T) {
	applied := map[string]bool{}
	f := newFakeRoutes()
	f.existsErr = true // a re-add of an already-present route WOULD fail — proves we don't re-add r1
	f.failAdd["10.2.0.0/24"] = true
	want := map[string]bool{"10.1.0.0/24": true, "10.2.0.0/24": true}

	// First reconcile: r1 succeeds, r2 fails → error naming r2, r1 belief kept.
	err := reconcileRoutes(applied, want, f.cmd)
	if err == nil || !strings.Contains(err.Error(), "10.2.0.0/24") {
		t.Fatalf("first pass must report the failed target: %v", err)
	}
	if !applied["10.1.0.0/24"] || applied["10.2.0.0/24"] {
		t.Fatalf("per-route advance: r1 kept, r2 not: %v", applied)
	}
	// The transient clears; retry. r1 must NOT be re-added (it's believed applied); only r2 is attempted.
	f.failAdd = map[string]bool{}
	f.calls = nil
	if err := reconcileRoutes(applied, want, f.cmd); err != nil {
		t.Fatalf("retry must converge, got %v", err)
	}
	for _, c := range f.calls {
		if c == "add 10.1.0.0/24" {
			t.Fatalf("retry re-added r1 (the #1 wedge — would fail File exists): %v", f.calls)
		}
	}
	if got := kernelSet(f); !eq(got, []string{"10.1.0.0/24", "10.2.0.0/24"}) {
		t.Fatalf("both routes must be in the kernel after convergence: %v", got)
	}
}

// RED #3 — a PRE-EXISTING identical route (home-LAN collision) → apply SUCCEEDS via delete-before-add,
// never fails "File exists". The user's home LAN 192.168.1.0/24 already has a route; our add of the same
// range must delete-first then add (our route wins while up), not error.
func TestReconcileDeleteBeforeAddIdempotent(t *testing.T) {
	applied := map[string]bool{}
	f := newFakeRoutes("192.168.1.0/24") // pre-existing (foreign) route
	f.existsErr = true                   // a bare add WOULD fail File exists
	want := map[string]bool{"192.168.1.0/24": true}
	if err := reconcileRoutes(applied, want, f.cmd); err != nil {
		t.Fatalf("delete-before-add must make a colliding route succeed, got %v", err)
	}
	// The sequence must be del THEN add for the colliding target.
	if !eq(f.calls, []string{"del 192.168.1.0/24", "add 192.168.1.0/24"}) {
		t.Fatalf("delete-before-add order: %v", f.calls)
	}
	if !applied["192.168.1.0/24"] {
		t.Fatalf("belief must be set after a successful add")
	}
}

// RED #4 — a poll that ADDS A (fails) and REMOVES B: the delete-sweep of B must run REGARDLESS of A's add
// failure (no early return), so B's stale route is gone even though A errored.
func TestReconcileSweepRunsDespiteAddFailure(t *testing.T) {
	applied := map[string]bool{"10.9.0.0/24": true} // B, previously applied, now de-advertised
	f := newFakeRoutes("10.9.0.0/24")
	f.failAdd["10.1.0.0/24"] = true              // A fails
	want := map[string]bool{"10.1.0.0/24": true} // A wanted, B gone
	err := reconcileRoutes(applied, want, f.cmd)
	if err == nil || !strings.Contains(err.Error(), "10.1.0.0/24") {
		t.Fatalf("A's failure must be reported: %v", err)
	}
	if f.kernel["10.9.0.0/24"] {
		t.Fatalf("B's stale route must be swept even though A's add failed (no early return): kernel=%v", kernelSet(f))
	}
	if applied["10.9.0.0/24"] {
		t.Fatalf("B's belief must be cleared: %v", applied)
	}
}

// RED — no-op when applied already equals want (idempotent steady state, ZERO commands).
func TestReconcileNoOpWhenConverged(t *testing.T) {
	applied := map[string]bool{"10.1.0.0/24": true}
	f := newFakeRoutes("10.1.0.0/24")
	if err := reconcileRoutes(applied, map[string]bool{"10.1.0.0/24": true}, f.cmd); err != nil {
		t.Fatalf("converged reconcile: %v", err)
	}
	if len(f.calls) != 0 {
		t.Fatalf("a converged reconcile must issue ZERO route commands: %v", f.calls)
	}
}

func eq(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
