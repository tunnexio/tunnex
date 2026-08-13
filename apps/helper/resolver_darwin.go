//go:build darwin

package helper

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
)

// macOS resolves a name under a domain via /etc/resolver/<domain> if such a file
// exists: its `nameserver` line names the resolver for that domain only (scoped, not
// the system default). S8.4 uses this to route a remote site's names to that site's
// internal DNS over the tunnel.
//
// resolverDir is the real macOS location; tests call reconcileResolvers with a temp dir.
const resolverDir = "/etc/resolver"

// resolverMarker is the OWNERSHIP line written as the first line of every file we
// create. Reconcile only ever reads/writes/deletes files carrying this marker — a
// resolver file a human (or another tool) placed is NEVER touched. Same discipline
// as the DOCKER-USER `tunnex-site-fwd` comment (WF-4): own-your-writes, sweep only
// your own.
const resolverMarker = "# tunnex-managed"

// setResolvers is the platform entry the Server dispatches VerbSetResolvers to.
func setResolvers(desired []ResolverForward) error {
	return reconcileResolvers(resolverDir, desired)
}

// reconcileResolvers makes the OWNED resolver files in dir exactly match desired:
// write/update each desired domain, delete owned files whose domain is not desired,
// leave foreign files alone. Full-sweep, idempotent. Validates every entry BEFORE
// writing anything — a bad domain or resolver IP fails the whole call with nothing
// half-applied (the caller keeps its last good state).
func reconcileResolvers(dir string, desired []ResolverForward) error {
	// Validate + normalize first; build the desired map keyed by safe filename.
	want := make(map[string]netip.Addr, len(desired))
	for _, d := range desired {
		dom, err := safeResolverDomain(d.Domain)
		if err != nil {
			return err
		}
		ip, err := netip.ParseAddr(strings.TrimSpace(d.ResolverIP))
		if err != nil {
			return &ProtocolError{Code: "invalid_resolver_ip", Msg: fmt.Sprintf("resolver ip %q is not an IP address", d.ResolverIP)}
		}
		want[dom] = ip
	}

	// Enumerate the current OWNED files so we can sweep the ones no longer desired.
	owned, err := ownedResolverFiles(dir)
	if err != nil {
		return err
	}

	// A desired domain whose file exists but is NOT owned is a FOREIGN file (a human's
	// or another tool's scoped resolver). Refuse — never clobber what we don't own —
	// with nothing applied, rather than silently overwrite it.
	for dom := range want {
		if _, mine := owned[dom]; mine {
			continue
		}
		if _, statErr := os.Stat(filepath.Join(dir, dom)); statErr == nil {
			return &ProtocolError{Code: "resolver_domain_conflict", Msg: fmt.Sprintf("a foreign resolver file already exists for %q", dom)}
		}
	}

	// Nothing to do AND nothing owned: don't even create the dir (inert steady state).
	if len(want) == 0 && len(owned) == 0 {
		return nil
	}
	if len(want) > 0 {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return &ProtocolError{Code: "resolver_dir_failed", Msg: err.Error()}
		}
	}

	// Write/update the desired set. On a mid-apply write failure, roll back the files this apply newly
	// CREATED (existed==false) so a partial apply strands no NEW owned file. An OVERWRITE of an
	// already-owned file is NOT rolled back — the accepted, ledgered window (S8.4 fold R5): a failed
	// mid-apply may leave an already-owned domain pointing at its NEW resolver until the next reconcile
	// tick (client re-applies the full set) or a restart (startup CleanStale) heals it. Bounded + honest;
	// not full all-or-nothing, and deliberately so — chasing atomic overwrite-rollback was the over-clever
	// path the fold reduction backed out of.
	type writeRec struct {
		path    string
		existed bool
	}
	var written []writeRec
	for _, dom := range sortedKeys(want) {
		path := filepath.Join(dir, dom)
		_, statErr := os.Stat(path)
		if err := writeResolverFileFn(path, want[dom]); err != nil {
			for _, w := range written {
				if !w.existed {
					os.Remove(w.path)
				}
			}
			return err
		}
		written = append(written, writeRec{path: path, existed: statErr == nil})
	}
	// Sweep owned files whose domain is no longer desired.
	for dom := range owned {
		if _, keep := want[dom]; keep {
			continue
		}
		if err := os.Remove(filepath.Join(dir, dom)); err != nil && !os.IsNotExist(err) {
			return &ProtocolError{Code: "resolver_remove_failed", Msg: err.Error()}
		}
	}
	return nil
}

// ownedResolverFiles returns the set of domain filenames in dir that we own (carry
// the marker). A missing dir is not an error (nothing owned). Foreign files and
// unreadable entries are skipped, never claimed.
func ownedResolverFiles(dir string) (map[string]struct{}, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]struct{}{}, nil
		}
		return nil, &ProtocolError{Code: "resolver_list_failed", Msg: err.Error()}
	}
	owned := make(map[string]struct{})
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue // unreadable → not ours to claim
		}
		if strings.HasPrefix(string(b), resolverMarker) {
			owned[e.Name()] = struct{}{}
		}
	}
	return owned, nil
}

// writeResolverFileFn is the write seam (defaults to writeResolverFile) so the partial-write rollback red
// can force a mid-apply failure without a real filesystem fault.
var writeResolverFileFn = writeResolverFile

// writeResolverFile atomically writes an owned resolver file (marker + nameserver)
// via temp-then-rename so a name lookup never sees a half-written file.
func writeResolverFile(path string, ip netip.Addr) error {
	content := resolverMarker + "\nnameserver " + ip.String() + "\n"
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tunnex-resolver-*")
	if err != nil {
		return &ProtocolError{Code: "resolver_write_failed", Msg: err.Error()}
	}
	tmpName := tmp.Name()
	if _, err := tmp.WriteString(content); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return &ProtocolError{Code: "resolver_write_failed", Msg: err.Error()}
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return &ProtocolError{Code: "resolver_write_failed", Msg: err.Error()}
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return &ProtocolError{Code: "resolver_write_failed", Msg: err.Error()}
	}
	return nil
}

// safeResolverDomain + sortedKeys moved to resolver.go (untagged) so the Windows NRPT path shares the same
// path-safety floor and key-sort — one floor, both platforms.
