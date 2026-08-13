package nodes

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Structural guards for S7.4b (advisory-read-only + single-writer). The desync signal is
// CP-owned DISPLAY detail: exactly ONE function may WRITE it, and nothing in compile/push may
// READ it — so a future refactor can't (a) add a second writer to the CP-owned column or
// (b) quietly let the advisory kind become load-bearing (the policy_degraded BOOL stays the
// sole decision signal, the S7.2 collapse un-un-collapsed). The agent (apps/node) is safe by
// ARCHITECTURE — the kind/onset are computed server-side and never sent to it; the open-build
// wall (no enterprise hash-compare linked) is the existing edition-isolation guard.

// TestDesyncSingleWriter — the two CP-only queries are invoked from exactly ONE function.
func TestDesyncSingleWriter(t *testing.T) {
	src, err := os.ReadFile("service.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{"StampNodePolicyDesyncSince(", "ClearNodePolicyDesyncSince("} {
		if !strings.Contains(string(src), q) {
			t.Fatalf("%s not found — test stale?", q)
		}
		for _, chunk := range strings.Split(string(src), "\nfunc ")[1:] {
			if !strings.Contains(chunk, q) {
				continue
			}
			header := chunk
			if i := strings.IndexByte(chunk, '\n'); i > 0 {
				header = chunk[:i]
			}
			if !strings.Contains(header, "trackDesync") {
				t.Fatalf("%s called OUTSIDE trackDesync (second writer) — in: func %s", q, header)
			}
		}
	}
}

// TestDesyncAdvisoryReadOnly — compile/push (enterprise policy) must not reference the advisory
// signal. If it ever does, the "advisory over the bool" invariant is broken (it became an input).
func TestDesyncAdvisoryReadOnly(t *testing.T) {
	forbidden := []string{"policy_desync_since", "PolicyDesyncSince", "degradedKind", "PolicyDegradedKind"}
	// ⚠ WAS `../enterprise/policy` UNTIL S12.1 SLICE 1 DISSOLVED THE ENTERPRISE TREE. The path was a proxy
	// for "the compile/push code", and the code moved out from under it. ⭐ THE VACUITY FLOOR BELOW IS THE
	// ONLY REASON THIS SURFACED AS A FAILURE RATHER THAN AS A GUARD THAT SILENTLY PASSED OVER ZERO FILES —
	// the same rescue the entitlement census's floor performed in the same slice, on the same day, for the
	// same cause (docs/laws.md: a census whose subject is a proxy drifts out from under it silently).
	dir := "../policy" // compile + push + hash comparison
	seen := false
	err := filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return err
		}
		seen = true
		b, _ := os.ReadFile(p)
		for _, f := range forbidden {
			if strings.Contains(string(b), f) {
				t.Errorf("advisory signal %q referenced in %s — compile/push must NOT read it (UI-only)", f, p)
			}
		}
		return nil
	})
	if err != nil || !seen {
		t.Fatalf("could not scan %s (walk err=%v, sawFiles=%v)", dir, err, seen)
	}
}
