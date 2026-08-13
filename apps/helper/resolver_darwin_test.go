//go:build darwin

package helper

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read %s: %v", p, err)
	}
	return string(b)
}

// TestReconcileWritesScopedResolver: a desired forward becomes /etc/resolver/<domain>
// with our ownership marker and the nameserver line.
func TestReconcileWritesScopedResolver(t *testing.T) {
	dir := t.TempDir()
	if err := reconcileResolvers(dir, []ResolverForward{{Domain: "corp.local", ResolverIP: "10.20.0.53"}}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	got := readFile(t, filepath.Join(dir, "corp.local"))
	if !strings.HasPrefix(got, resolverMarker) {
		t.Errorf("file not marked owned: %q", got)
	}
	if !strings.Contains(got, "nameserver 10.20.0.53") {
		t.Errorf("missing nameserver line: %q", got)
	}
}

// TestReconcileIdempotent: applying the same desired set twice converges — no error,
// same content, file still owned.
func TestReconcileIdempotent(t *testing.T) {
	dir := t.TempDir()
	d := []ResolverForward{{Domain: "corp.local", ResolverIP: "10.20.0.53"}}
	if err := reconcileResolvers(dir, d); err != nil {
		t.Fatalf("first: %v", err)
	}
	first := readFile(t, filepath.Join(dir, "corp.local"))
	if err := reconcileResolvers(dir, d); err != nil {
		t.Fatalf("second: %v", err)
	}
	if second := readFile(t, filepath.Join(dir, "corp.local")); second != first {
		t.Errorf("not idempotent: %q != %q", second, first)
	}
}

// TestReconcileFullSweep: switching the desired set removes the owned file no longer
// desired and writes the new one — full-sweep, not additive.
func TestReconcileFullSweep(t *testing.T) {
	dir := t.TempDir()
	if err := reconcileResolvers(dir, []ResolverForward{{Domain: "old.local", ResolverIP: "10.20.0.53"}}); err != nil {
		t.Fatalf("apply old: %v", err)
	}
	if err := reconcileResolvers(dir, []ResolverForward{{Domain: "new.local", ResolverIP: "10.30.0.53"}}); err != nil {
		t.Fatalf("apply new: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "old.local")); !os.IsNotExist(err) {
		t.Errorf("old.local not swept: err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "new.local")); err != nil {
		t.Errorf("new.local not written: %v", err)
	}
}

// TestReconcileEmptyClearsOwned: an empty desired set sweeps every owned file (the
// inert steady state on tunnel-down).
func TestReconcileEmptyClearsOwned(t *testing.T) {
	dir := t.TempDir()
	if err := reconcileResolvers(dir, []ResolverForward{{Domain: "corp.local", ResolverIP: "10.20.0.53"}}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if err := reconcileResolvers(dir, nil); err != nil {
		t.Fatalf("clear: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "corp.local")); !os.IsNotExist(err) {
		t.Errorf("owned file not cleared: err=%v", err)
	}
}

// TestReconcileInertNoOp: with nothing owned and nothing desired, reconcile does not
// even create the dir — zero files, zero behavior delta (the ruling's inert red).
func TestReconcileInertNoOp(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "resolver") // does NOT exist yet
	if err := reconcileResolvers(dir, nil); err != nil {
		t.Fatalf("inert reconcile: %v", err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("inert reconcile created the dir: err=%v", err)
	}
}

// TestReconcileNeverTouchesForeign: a foreign resolver file (no marker) is left
// untouched by a sweep, and a desired domain colliding with a foreign file is
// REFUSED (never clobbered) with nothing applied.
func TestReconcileNeverTouchesForeign(t *testing.T) {
	dir := t.TempDir()
	foreign := filepath.Join(dir, "hand.local")
	if err := os.WriteFile(foreign, []byte("nameserver 9.9.9.9\n"), 0o644); err != nil {
		t.Fatalf("seed foreign: %v", err)
	}
	// A sweep (empty desired) must leave the foreign file alone.
	if err := reconcileResolvers(dir, nil); err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if _, err := os.Stat(foreign); err != nil {
		t.Errorf("foreign file swept away: %v", err)
	}
	// Wanting the foreign domain must refuse, not overwrite.
	err := reconcileResolvers(dir, []ResolverForward{{Domain: "hand.local", ResolverIP: "10.20.0.53"}})
	if err == nil || codeOf(err) != "resolver_domain_conflict" {
		t.Errorf("want resolver_domain_conflict, got %v", err)
	}
	if got := readFile(t, foreign); got != "nameserver 9.9.9.9\n" {
		t.Errorf("foreign file was clobbered: %q", got)
	}
}

// TestReconcileAcceptsSingleLabel (F3): a single-label zone ("internal") — legitimate in homelab/SMB and
// ACCEPTED by the control plane — must install, not be rejected by the helper (the third-normalizer drift).
func TestReconcileAcceptsSingleLabel(t *testing.T) {
	dir := t.TempDir()
	if err := reconcileResolvers(dir, []ResolverForward{{Domain: "internal", ResolverIP: "10.20.0.53"}}); err != nil {
		t.Fatalf("single-label zone must install: %v", err)
	}
	got := readFile(t, filepath.Join(dir, "internal"))
	if !strings.Contains(got, "nameserver 10.20.0.53") {
		t.Errorf("single-label resolver not written: %q", got)
	}
}

// TestReconcileAcceptsUnderscoreAndUnicode (S8.4 fold R1) — the helper does PATH-SAFETY only; a domain the
// CP accepts (an AD `_msdcs.corp` SRV zone, a unicode zone) must install, and — critically now that apply is
// all-or-nothing — one such domain must NOT sink the WHOLE set.
func TestReconcileAcceptsUnderscoreAndUnicode(t *testing.T) {
	dir := t.TempDir()
	err := reconcileResolvers(dir, []ResolverForward{
		{Domain: "_msdcs.corp", ResolverIP: "10.20.0.53"},
		{Domain: "münchen.local", ResolverIP: "10.20.0.54"},
		{Domain: "corp.local", ResolverIP: "10.20.0.55"},
	})
	if err != nil {
		t.Fatalf("underscore/unicode zones must install, not sink the set: %v", err)
	}
	for _, dom := range []string{"_msdcs.corp", "münchen.local", "corp.local"} {
		if _, statErr := os.Stat(filepath.Join(dir, dom)); statErr != nil {
			t.Errorf("%q not written: %v", dom, statErr)
		}
	}
}

// TestReconcileStillRefusesTraversal (S8.4 fold R1) — the path-safety FLOOR did not regress: separators,
// traversal, and leading/trailing dots are still refused.
func TestReconcileStillRefusesTraversal(t *testing.T) {
	dir := t.TempDir()
	for _, bad := range []string{"../etc/evil", "a/b.local", ".corp.local", "a..b.local", "a\nb.local", "a\tb.local", "a\x00b.local"} {
		if err := reconcileResolvers(dir, []ResolverForward{{Domain: bad, ResolverIP: "10.0.0.1"}}); err == nil || codeOf(err) != "invalid_resolver_domain" {
			t.Errorf("path-unsafe domain %q must be refused, got %v", bad, err)
		}
	}
}

// TestReconcilePartialWriteRollsBack (F5/F6): a write failure mid-apply removes the files this apply newly
// created (all-or-nothing) so nothing is stranded, and a foreign file is untouched throughout.
func TestReconcilePartialWriteRollsBack(t *testing.T) {
	dir := t.TempDir()
	foreign := filepath.Join(dir, "hand.local")
	if err := os.WriteFile(foreign, []byte("nameserver 9.9.9.9\n"), 0o644); err != nil {
		t.Fatalf("seed foreign: %v", err)
	}
	// Force the SECOND write (sorted: a.local then b.local) to fail.
	orig := writeResolverFileFn
	calls := 0
	writeResolverFileFn = func(path string, ip netip.Addr) error {
		calls++
		if calls == 2 {
			return &ProtocolError{Code: "resolver_write_failed", Msg: "boom"}
		}
		return orig(path, ip)
	}
	defer func() { writeResolverFileFn = orig }()

	err := reconcileResolvers(dir, []ResolverForward{
		{Domain: "a.local", ResolverIP: "10.20.0.1"},
		{Domain: "b.local", ResolverIP: "10.20.0.2"},
	})
	if err == nil {
		t.Fatal("a mid-apply write failure must surface an error")
	}
	// The first (newly created) file must have been rolled back — nothing stranded.
	if _, statErr := os.Stat(filepath.Join(dir, "a.local")); !os.IsNotExist(statErr) {
		t.Errorf("partial apply stranded a.local: err=%v", statErr)
	}
	// Foreign survives.
	if got := readFile(t, foreign); got != "nameserver 9.9.9.9\n" {
		t.Errorf("foreign file disturbed: %q", got)
	}
}

// TestReconcileRejectsBadInput: a path-traversal domain or a non-IP resolver is
// refused with a typed code and NOTHING is written (validate-before-apply).
func TestReconcileRejectsBadInput(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		name string
		fwd  ResolverForward
		code string
	}{
		{"traversal", ResolverForward{Domain: "../etc/evil", ResolverIP: "10.0.0.1"}, "invalid_resolver_domain"},
		{"slash", ResolverForward{Domain: "a/b.local", ResolverIP: "10.0.0.1"}, "invalid_resolver_domain"},
		{"leadingdot", ResolverForward{Domain: ".corp.local", ResolverIP: "10.0.0.1"}, "invalid_resolver_domain"},
		{"badip", ResolverForward{Domain: "corp.local", ResolverIP: "not-an-ip"}, "invalid_resolver_ip"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := reconcileResolvers(dir, []ResolverForward{c.fwd})
			if err == nil || codeOf(err) != c.code {
				t.Errorf("want %s, got %v", c.code, err)
			}
			if ents, _ := os.ReadDir(dir); len(ents) != 0 {
				t.Errorf("bad input wrote %d files", len(ents))
			}
		})
	}
}
