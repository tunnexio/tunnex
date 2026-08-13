package helper

import (
	"fmt"
	"net/netip"
	"strings"
)

// Windows NRPT (Name Resolution Policy Table) is the platform's domain-scoped split-DNS mechanism: a rule
// binds a namespace (".corp.local" — leading dot = the zone and its subdomains) to a resolver, so ONLY
// those names go to the site's internal DNS over the tunnel, everything else to the system default. This
// is the Windows form of the macOS /etc/resolver files (S8.4b, triggered by S8.5's device-routes slice).
//
// MECHANISM: the documented PowerShell *-DnsClientNrptRule cmdlets (RULED S8.5 Slice 4), NOT the raw
// HKLM\...\DnsPolicyConfig registry schema. Rationale in docs/S8.5-decisions.md — consistent with the
// helper's proven Windows surface (posture shells PowerShell), documented over version-fragile registry,
// native -Comment owned-marker, and co-exists with GPO-managed NRPT on the SAME documented layer.
//
// This file is UNTAGGED: the reconcile LOGIC (owned-enum, foreign-refuse, remove-then-add, full-sweep) is
// unit-tested on any platform via the cmdRunner seam; the real powershell.exe binding lives in
// resolver_windows.go and the WALK proves it on iron (Windows-only, un-testable locally).

// nrptMarker is the ownership tag written as the -Comment of every rule we create. Reconcile only ever
// removes rules carrying this marker — a rule authored by a human or GPO is NEVER touched (shared-territory
// law, the Windows form of the macOS "# tunnex-managed" file marker + the DOCKER-USER "tunnex-site-fwd").
const nrptMarker = "tunnex-managed"

// cmdRunner runs one PowerShell -Command script and returns its stdout. The seam that makes the reconcile
// logic red-able off-Windows: tests inject a fake; resolver_windows.go injects the real powershell.exe.
type cmdRunner func(script string) (string, error)

// nrptRule is one parsed row of Get-DnsClientNrptRule output (flattened to one namespace per row).
type nrptRule struct {
	name      string // the rule's GUID identifier (.Name) — what Remove-DnsClientNrptRule -Name takes
	namespace string // e.g. ".corp.local"
	comment   string // ours == nrptMarker; anything else (incl. empty) is FOREIGN
}

// nrptGetScript enumerates every NRPT rule as tab-separated `name<TAB>namespace<TAB>comment` lines, one
// line PER namespace (a rule may carry several) so a multi-namespace foreign/GPO rule is fully seen. No
// user input — a constant.
const nrptGetScript = `Get-DnsClientNrptRule | ForEach-Object { $r=$_; foreach ($ns in $r.Namespace) { "$($r.Name)` + "`t" + `$ns` + "`t" + `$($r.Comment)" } }`

// psQuote wraps s as a PowerShell SINGLE-QUOTED literal, doubling any embedded quote. Single quotes
// suppress ALL interpolation ($, backtick, subexpressions), so this is injection-proof: a namespace or
// name is DATA, never code, even though safeResolverDomain does not (and should not — it's the CP's shape
// one-truth) forbid shell metacharacters like ; $ ` & |. The privileged SYSTEM service must never let a
// zone name become a command.
func psQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

func nrptAddScript(namespace, resolverIP string) string {
	return "Add-DnsClientNrptRule -Namespace " + psQuote(namespace) +
		" -NameServers " + psQuote(resolverIP) + " -Comment " + psQuote(nrptMarker)
}

func nrptRemoveScript(name string) string {
	return "Remove-DnsClientNrptRule -Name " + psQuote(name) + " -Force"
}

// parseNrpt turns nrptGetScript output into rows. Lines with fewer than 2 fields are skipped; a missing
// third field (no comment) is an empty comment (→ foreign). Namespace/comment are trimmed of surrounding
// whitespace and \r (powershell emits CRLF).
func parseNrpt(out string) []nrptRule {
	var rules []nrptRule
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) < 2 {
			continue
		}
		comment := ""
		if len(f) >= 3 {
			comment = strings.TrimSpace(f[2])
		}
		rules = append(rules, nrptRule{
			name:      strings.TrimSpace(f[0]),
			namespace: strings.TrimSpace(f[1]),
			comment:   comment,
		})
	}
	return rules
}

// nrptNamespace derives the NRPT namespace form (a leading dot = suffix match on the zone + subdomains)
// from a domain, applying the shared path-safety floor first.
func nrptNamespace(domain string) (string, error) {
	d, err := safeResolverDomain(domain)
	if err != nil {
		return "", err
	}
	return "." + d, nil
}

// reconcileNRPT makes the OWNED NRPT rules exactly match desired: refuse if any desired namespace collides
// with a FOREIGN (GPO/human) rule, else remove every owned rule and add the desired set fresh. Add-
// DnsClientNrptRule has no upsert (each call creates a rule), so remove-all-owned-then-add-desired is the
// idempotent full-sweep — no duplicate accumulation, and an update (same namespace, new resolver) is a
// remove+add. FOREIGN rules are never removed (owned-marker discipline). VALIDATE-FIRST: a bad namespace
// or resolver fails the whole call with ZERO commands issued (all-or-nothing; the caller keeps its last
// good state). The brief per-namespace resolve gap during remove→add is the accepted DNS-down≠tunnel-down
// window (the macOS overwrite-window precedent).
func reconcileNRPT(run cmdRunner, desired []ResolverForward) error {
	// Validate + normalize FIRST — before touching NRPT at all (all-or-nothing).
	want := make(map[string]netip.Addr, len(desired))
	for _, d := range desired {
		ns, err := nrptNamespace(d.Domain)
		if err != nil {
			return err
		}
		ip, err := netip.ParseAddr(strings.TrimSpace(d.ResolverIP))
		if err != nil {
			return &ProtocolError{Code: "invalid_resolver_ip", Msg: fmt.Sprintf("resolver ip %q is not an IP address", d.ResolverIP)}
		}
		want[ns] = ip
	}

	// Enumerate the current table.
	out, err := run(nrptGetScript)
	if err != nil {
		return &ProtocolError{Code: "nrpt_list_failed", Msg: err.Error()}
	}
	var owned []nrptRule         // rules we authored (comment == marker)
	foreign := map[string]bool{} // namespaces held by a rule we do NOT own
	for _, r := range parseNrpt(out) {
		if r.comment == nrptMarker {
			owned = append(owned, r)
		} else {
			foreign[r.namespace] = true
		}
	}

	// FOREIGN-REFUSE: a desired namespace already held by a foreign/GPO rule → refuse, LOGGED, with NOTHING
	// applied — never fight the GPO, never clobber a rule we don't own. Checked before any remove/add.
	for ns := range want {
		if foreign[ns] {
			return &ProtocolError{Code: "nrpt_domain_conflict", Msg: fmt.Sprintf("a foreign NRPT rule already exists for %q", ns)}
		}
	}

	// Remove every OWNED rule (full-sweep by construction) — foreign rules are untouched.
	for _, r := range owned {
		if _, err := run(nrptRemoveScript(r.name)); err != nil {
			return &ProtocolError{Code: "nrpt_remove_failed", Msg: err.Error()}
		}
	}
	// Add the desired set (deterministic order for a stable command sequence / red).
	for _, ns := range sortedKeys(want) {
		if _, err := run(nrptAddScript(ns, want[ns].String())); err != nil {
			return &ProtocolError{Code: "nrpt_add_failed", Msg: err.Error()}
		}
	}
	return nil
}
