package helper

import (
	"errors"
	"strings"
	"testing"
)

// fakeNrpt is the cmdRunner seam's stand-in: it returns a canned Get table and records every script it is
// asked to run, so the reconcile LOGIC is exercised on any platform without powershell.exe. failOn makes a
// script whose text contains the substring fail (to force a mid-reconcile error).
type fakeNrpt struct {
	getOut string
	calls  []string
	failOn string
}

func (f *fakeNrpt) run(script string) (string, error) {
	f.calls = append(f.calls, script)
	if f.failOn != "" && strings.Contains(script, f.failOn) {
		return "", errors.New("boom")
	}
	if script == nrptGetScript {
		return f.getOut, nil
	}
	return "", nil
}

// row builds one Get-DnsClientNrptRule output line (name<TAB>namespace<TAB>comment), CRLF-terminated to
// mirror powershell's real output.
func row(name, ns, comment string) string {
	return name + "\t" + ns + "\t" + comment + "\r\n"
}

func fwd(domain, ip string) ResolverForward { return ResolverForward{Domain: domain, ResolverIP: ip} }

// removeCalls / addNamespaces extract the effect of a reconcile from the recorded scripts.
func removeCalls(calls []string) []string {
	var out []string
	for _, c := range calls {
		if strings.HasPrefix(c, "Remove-DnsClientNrptRule") {
			out = append(out, c)
		}
	}
	return out
}
func addCalls(calls []string) []string {
	var out []string
	for _, c := range calls {
		if strings.HasPrefix(c, "Add-DnsClientNrptRule") {
			out = append(out, c)
		}
	}
	return out
}

// RED 1 — add + update + sweep: owned {.a(g-a), .c(g-c)}, desired {a, b}. Every owned rule is removed and
// the desired set added fresh (remove-then-add = idempotent full-sweep, no upsert/dup). .a is an UPDATE
// (removed then re-added with its new resolver); .c is a SWEEP (removed, not re-added); .b is an ADD.
func TestReconcileNRPTAddUpdateSweep(t *testing.T) {
	f := &fakeNrpt{getOut: row("g-a", ".a", nrptMarker) + row("g-c", ".c", nrptMarker)}
	if err := reconcileNRPT(f.run, []ResolverForward{fwd("a", "10.0.0.1"), fwd("b", "10.0.0.2")}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	rm := removeCalls(f.calls)
	if len(rm) != 2 || !contains(rm, "g-a") || !contains(rm, "g-c") {
		t.Fatalf("must remove ALL owned rules (g-a, g-c): %v", rm)
	}
	ad := addCalls(f.calls)
	if len(ad) != 2 || !contains(ad, "'.a'") || !contains(ad, "'.b'") || !contains(ad, "10.0.0.1") || !contains(ad, "10.0.0.2") {
		t.Fatalf("must add the desired set fresh (.a→10.0.0.1, .b→10.0.0.2): %v", ad)
	}
}

// RED 2 — foreign-refuse: a desired namespace already held by a FOREIGN rule (no marker) → refuse with
// nrpt_domain_conflict, NOTHING applied (no remove, no add), and the foreign rule is never touched.
func TestReconcileNRPTForeignRefuse(t *testing.T) {
	f := &fakeNrpt{getOut: row("g-foreign", ".corp.local", "")} // GPO rule, no marker
	err := reconcileNRPT(f.run, []ResolverForward{fwd("corp.local", "10.20.0.53")})
	var pe *ProtocolError
	if !errors.As(err, &pe) || pe.Code != "nrpt_domain_conflict" {
		t.Fatalf("a desired namespace colliding with a foreign rule must refuse nrpt_domain_conflict: %v", err)
	}
	if n := len(removeCalls(f.calls)) + len(addCalls(f.calls)); n != 0 {
		t.Fatalf("a conflict must apply NOTHING (no remove/add) — the GPO rule is never fought: %d calls", n)
	}
}

// RED 3 — full-sweep, foreign untouched: owned {.a, .b}, foreign {.f}, desired {a}. Both owned rules are
// removed (full-sweep, not just the undesired one), the foreign rule is NEVER removed, .a is re-added.
func TestReconcileNRPTFullSweepLeavesForeign(t *testing.T) {
	f := &fakeNrpt{getOut: row("g-a", ".a", nrptMarker) + row("g-b", ".b", nrptMarker) + row("g-f", ".f", "corp-gpo")}
	if err := reconcileNRPT(f.run, []ResolverForward{fwd("a", "10.0.0.1")}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	rm := removeCalls(f.calls)
	if !contains(rm, "g-a") || !contains(rm, "g-b") {
		t.Fatalf("full-sweep must remove ALL owned rules: %v", rm)
	}
	if contains(rm, "g-f") {
		t.Fatalf("a FOREIGN rule must NEVER be removed: %v", rm)
	}
}

// RED 4 — foreign survives sweep-to-empty (the crash-sweep / CleanStaleResolvers case, condition #4):
// reconcileNRPT(run, nil) removes every OWNED rule and NOTHING else — a planted foreign rule survives.
func TestReconcileNRPTSweepToEmptyLeavesForeign(t *testing.T) {
	f := &fakeNrpt{getOut: row("g-a", ".a", nrptMarker) + row("g-f", ".f", "")}
	if err := reconcileNRPT(f.run, nil); err != nil {
		t.Fatalf("sweep-to-empty: %v", err)
	}
	rm := removeCalls(f.calls)
	if !contains(rm, "g-a") {
		t.Fatalf("sweep-to-empty must remove the owned rule: %v", rm)
	}
	if contains(rm, "g-f") {
		t.Fatalf("the crash-sweep must NOT remove a foreign rule (condition #4): %v", rm)
	}
	if len(addCalls(f.calls)) != 0 {
		t.Fatalf("sweep-to-empty adds nothing: %v", addCalls(f.calls))
	}
}

// RED 5 — validate-first (all-or-nothing): a bad namespace fails the whole call with ZERO commands issued
// (not even the Get) — the caller keeps its last good state, nothing half-applied.
func TestReconcileNRPTValidateFirst(t *testing.T) {
	f := &fakeNrpt{getOut: ""}
	err := reconcileNRPT(f.run, []ResolverForward{fwd("ok.local", "10.0.0.1"), fwd("../evil", "10.0.0.2")})
	var pe *ProtocolError
	if !errors.As(err, &pe) || pe.Code != "invalid_resolver_domain" {
		t.Fatalf("a bad namespace must fail the whole call: %v", err)
	}
	if len(f.calls) != 0 {
		t.Fatalf("validate-first: a bad input must issue ZERO commands (not even Get): %v", f.calls)
	}
}

// RED 6 — psQuote is injection-proof: safeResolverDomain does not (and must not) forbid shell
// metacharacters, so the PowerShell binding MUST render every value as a single-quoted literal, doubling
// embedded quotes. A namespace can never become a command on the privileged SYSTEM service.
func TestPsQuoteInjectionProof(t *testing.T) {
	if got := psQuote("a'b"); got != "'a''b'" {
		t.Fatalf("psQuote must double embedded quotes: %q", got)
	}
	// A metacharacter-bearing value is fully contained in the single-quoted literal — no bare $ ; ` reaches
	// the parser. (safeResolverDomain would reject this domain's path-unsafety, but psQuote is the floor
	// regardless of what upstream allows.)
	s := nrptAddScript(".x`;calc", "10.0.0.1")
	if !strings.Contains(s, "'.x`;calc'") {
		t.Fatalf("nrptAddScript must single-quote the namespace literally: %s", s)
	}
}

// parseNrpt tolerates CRLF, blank lines, and a missing comment field (→ foreign).
func TestParseNrpt(t *testing.T) {
	out := row("g1", ".a", nrptMarker) + "\r\n" + "g2\t.b\r\n" // second row: no comment → foreign
	rules := parseNrpt(out)
	if len(rules) != 2 {
		t.Fatalf("want 2 rules, got %d: %+v", len(rules), rules)
	}
	if rules[0].comment != nrptMarker || rules[1].comment != "" {
		t.Fatalf("comment parse: %+v", rules)
	}
	if rules[0].namespace != ".a" || rules[1].namespace != ".b" {
		t.Fatalf("namespace parse: %+v", rules)
	}
}

func contains(ss []string, sub string) bool {
	for _, s := range ss {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
