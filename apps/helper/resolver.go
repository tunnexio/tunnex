package helper

import (
	"errors"
	"sort"
	"strings"
	"unicode"
)

// CleanStaleResolvers sweeps any owned domain-scoped resolvers left by a PRIOR process that exited without
// a graceful sweep — a helper/host restart, or an uninstall-without-relaunch (F6, mirroring the kill-switch
// SelfHeal precedent). It reconciles the owned set to EMPTY; foreign resolvers are never touched. The
// helper calls it ONCE at startup, before serving, AND the dead-man-release rider (S8.5 Slice 1) calls it
// on a crash/owner-loss. A platform without resolver support reports resolvers_unsupported, a no-op.
// (macOS: /etc/resolver files; Windows: NRPT rules — same owned-marker/full-sweep discipline, both swept.)
func CleanStaleResolvers() error {
	if err := setResolvers(nil); err != nil {
		var pe *ProtocolError
		if errors.As(err, &pe) && pe.Code == "resolvers_unsupported" {
			return nil
		}
		return err
	}
	return nil
}

// safeResolverDomain enforces the helper's OWN concern — that the domain is safe to use as a FILENAME
// (macOS /etc/resolver/<domain>) or an NRPT namespace token (Windows) — and NOTHING ELSE. Domain SHAPE
// (single-label vs dotted, label rules, allowed characters) is the control plane's one-truth
// (sites.NormalizeDomain); the helper must not reject what the CP accepted (F3). This is PATH-SAFETY ONLY:
// no separators, no traversal, no NUL/control char, no leading/trailing dot. Underscores (`_msdcs.corp`,
// `_ldap._tcp` — bog-standard Active Directory) and unicode zones are perfectly safe and NOT rejected.
// Lowercased. (Shared by the macOS resolver files and the Windows NRPT path — one floor, both platforms.)
func safeResolverDomain(raw string) (string, error) {
	d := strings.ToLower(strings.TrimSpace(strings.TrimSuffix(raw, ".")))
	if d == "" || len(d) > 253 {
		return "", &ProtocolError{Code: "invalid_resolver_domain", Msg: "domain is empty or too long"}
	}
	if strings.ContainsAny(d, "/\\") || strings.Contains(d, "..") {
		return "", &ProtocolError{Code: "invalid_resolver_domain", Msg: "domain contains a path separator or traversal"}
	}
	// The path-safety FLOOR (RR4): separators, traversal, NUL — and ANY control character (newline/tab/etc.)
	// which is never legitimate in a domain and dangerous in a filename/argument. Everything else
	// (underscores, unicode) is the CP's shape one-truth, not the helper's to second-guess.
	for _, r := range d {
		if unicode.IsControl(r) { // NUL (U+0000) is category Cc, so this covers it too
			return "", &ProtocolError{Code: "invalid_resolver_domain", Msg: "domain contains a control character"}
		}
	}
	if d[0] == '.' || d[len(d)-1] == '.' {
		return "", &ProtocolError{Code: "invalid_resolver_domain", Msg: "domain has a leading or trailing dot"}
	}
	return d, nil
}

// sortedKeys returns a map's keys in sorted order — the one keys-then-sort helper for the whole helper
// package (the resolver reconcile, the NRPT reconcile, and the route reconcile all share it, S8.5 #4).
func sortedKeys[V any](m map[string]V) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}
