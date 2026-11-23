//go:build linux

package k8snetprep

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
)

// maxFactReadAttempts bounds how often one read starts over because the chains
// it must carry are not the ones it listed first.
const maxFactReadAttempts = 3

// maxSetNamesBytes bounds the output of `ipset list -n`.
const maxSetNamesBytes = 64 << 10

// HostFactsReader is the privileged side of Decision 9. It runs only read
// commands: `iptables-nft-save -V|-t nat|-t mangle`, `ipset list -n`,
// `ipset save NAME` and `nft -j -a list chain ip nat|mangle CHAIN`.
type HostFactsReader struct {
	runNFT      NFTRunner
	runIPTables IPTablesRunner
	runIPSet    IPSetRunner
	sysModule   string

	mu sync.Mutex
	// remembered holds, per table, the chains the last read carried. They are
	// listed before the next save, so the save lies between two listings.
	remembered map[string][]string
}

// NewHostFactsReader returns a reader over the given runners; a nil runner is
// replaced by the real, closed one.
func NewHostFactsReader(nft NFTRunner, iptables IPTablesRunner, ipset IPSetRunner) *HostFactsReader {
	if nft == nil {
		nft = realFactsNFTRunner
	}
	if iptables == nil {
		iptables = realIPTablesRunner
	}
	if ipset == nil {
		ipset = realFactsIPSetRunner
	}
	return &HostFactsReader{runNFT: nft, runIPTables: iptables, runIPSet: ipset, sysModule: "/sys/module", remembered: map[string][]string{}}
}

// realFactsNFTRunner lists one chain of the ip nat or ip mangle table.
func realFactsNFTRunner(ctx context.Context, args ...string) (string, error) {
	if len(args) != 7 || strings.Join(args[:5], " ") != "-j -a list chain ip" || (args[5] != "nat" && args[5] != "mangle") || !factChainNameRE.MatchString(args[6]) {
		return "", errors.New("unsupported nft inspection")
	}
	return runBoundedRead(ctx, maxCNISnapshotBytes, "nft", args...)
}

// realFactsIPSetRunner lists the names of the kernel's sets, or one set.
func realFactsIPSetRunner(ctx context.Context, args ...string) (string, error) {
	if len(args) == 2 && args[0] == "list" && args[1] == "-n" {
		ctx, cancel := context.WithTimeout(ctx, ipsetReadTimeout)
		defer cancel()
		return runBoundedRead(ctx, maxSetNamesBytes, "ipset", "list", "-n")
	}
	return realIPSetRunner(ctx, args...)
}

type boundedBuffer struct {
	bytes.Buffer
	limit    int
	exceeded bool
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	// Keep draining after the bound so the command can exit; the output is
	// refused as a whole.
	if b.exceeded || b.Len()+len(p) > b.limit {
		b.exceeded = true
		return len(p), nil
	}
	return b.Buffer.Write(p)
}

func runBoundedRead(ctx context.Context, limit int, name string, args ...string) (string, error) {
	stdout := &boundedBuffer{limit: limit}
	stderr := &boundedBuffer{limit: 512}
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout, cmd.Stderr = stdout, stderr
	err := cmd.Run()
	if stdout.exceeded {
		return "", fmt.Errorf("%s inspection exceeds bound", name)
	}
	if err != nil {
		return "", fmt.Errorf("%s inspection: %w: %s", name, err, bounded(stderr.Buffer.String(), 120))
	}
	return stdout.Buffer.String(), nil
}

// Read performs one bounded read. It never returns an error: what could not be
// read is stated in the facts, with its reason, so the gateway can report it.
func (r *HostFactsReader) Read(ctx context.Context) HostNetFacts {
	ctx, cancel := context.WithTimeout(ctx, HostFactsReadBudget)
	defer cancel()
	r.mu.Lock()
	defer r.mu.Unlock()
	version, err := r.runIPTables(ctx, "-V")
	if err != nil || !strings.HasPrefix(strings.TrimSpace(version), "iptables-nft-save v") || !strings.Contains(version, "(nf_tables)") {
		return UnreadableHostNetFacts("explicit nft-backed iptables-nft-save is unavailable or incompatible")
	}
	var facts HostNetFacts
	facts.Mangle, _ = r.readTable(ctx, "mangle")
	switch exist, err := r.kernelSetsExist(ctx); {
	case err != nil:
		facts.NAT = unreadableTable("look for kernel sets: " + err.Error())
	case !exist:
		facts.NAT = SavedTableFacts{State: FactsNotNeeded, Reason: "the kernel has no ipset, so no NAT rule can match one"}
	default:
		facts.NAT, facts.Sets = r.readTable(ctx, "nat")
	}
	if err := facts.Validate(); err != nil {
		return UnreadableHostNetFacts(err.Error())
	}
	return facts
}

func unreadableTable(reason string) SavedTableFacts {
	return SavedTableFacts{State: FactsUnreadable, Reason: bounded(reason, maxReasonBytes)}
}

// kernelSetsExist reports whether any ipset exists. The module check comes
// first: asking a kernel that has not loaded ip_set would load it.
func (r *HostFactsReader) kernelSetsExist(ctx context.Context) (bool, error) {
	if _, err := os.Stat(filepath.Join(r.sysModule, "ip_set")); errors.Is(err, os.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	out, err := r.runIPSet(ctx, "list", "-n")
	if err != nil {
		return false, errors.New(bounded(err.Error(), 120))
	}
	return strings.TrimSpace(out) != "", nil
}

// readTable reads the saved form of one table between two listings of the
// chains it carries. For nat it also reads the candidate sets.
func (r *HostFactsReader) readTable(ctx context.Context, table string) (SavedTableFacts, []SavedSetFacts) {
	names := r.remembered[table]
	for attempt := 0; attempt < maxFactReadAttempts; attempt++ {
		before, err := r.listingDigests(ctx, table, names)
		if err != nil {
			if len(names) == 0 {
				return unreadableTable(err.Error()), nil
			}
			// A chain carried last time is gone: find the chains again.
			names, r.remembered[table] = nil, nil
			continue
		}
		text, err := r.runIPTables(ctx, "-t", table)
		if err != nil {
			return unreadableTable(fmt.Sprintf("read saved %s rules: %s", table, bounded(err.Error(), 120))), nil
		}
		lines, err := parseNFTSaveTable(text, table)
		if err != nil {
			return unreadableTable(fmt.Sprintf("read saved %s rules: %s", table, err)), nil
		}
		saved, err := parseSavedRules(text)
		if err != nil {
			return unreadableTable(fmt.Sprintf("read saved %s rules: %s", table, err)), nil
		}
		relevant := savedFactChains(table, saved)
		if len(relevant) > maxFactChains {
			return unreadableTable(fmt.Sprintf("more than %d %s chains would have to be carried", maxFactChains, table)), nil
		}
		for _, name := range relevant {
			if !factChainNameRE.MatchString(name) {
				return unreadableTable(fmt.Sprintf("a %s chain has a name that is not understood", table)), nil
			}
		}
		if !reflect.DeepEqual(relevant, names) && (len(relevant) != 0 || len(names) != 0) {
			names, r.remembered[table] = relevant, relevant
			continue
		}
		var sets []SavedSetFacts
		if table == "nat" {
			if sets, err = r.readSets(ctx, saved, relevant); err != nil {
				return unreadableTable(err.Error()), nil
			}
		}
		after, err := r.listingDigests(ctx, table, names)
		if err != nil || !reflect.DeepEqual(before, after) {
			return unreadableTable(fmt.Sprintf("%s rules changed while they were read", table)), nil
		}
		if err := ctx.Err(); err != nil {
			return unreadableTable(fmt.Sprintf("read saved %s rules: %s", table, err)), nil
		}
		facts := SavedTableFacts{State: FactsRead}
		for _, name := range relevant {
			facts.Chains = append(facts.Chains, SavedChainFacts{Name: name, Listing: after[name], Rules: lines[name]})
		}
		return facts, sets
	}
	return unreadableTable(fmt.Sprintf("%s rules kept changing while they were read", table)), nil
}

func (r *HostFactsReader) listingDigests(ctx context.Context, table string, chains []string) (map[string]string, error) {
	digests := map[string]string{}
	for _, chain := range chains {
		listing, err := r.runNFT(ctx, "-j", "-a", "list", "chain", "ip", table, chain)
		if err != nil {
			return nil, fmt.Errorf("list %s chain %s: %s", table, chain, bounded(err.Error(), 120))
		}
		snapshot, err := parseCNISnapshot(listing)
		if err != nil {
			return nil, fmt.Errorf("list %s chain %s: %w", table, chain, err)
		}
		digest, ok := snapshot.chainListingDigest(table, chain)
		if !ok {
			return nil, fmt.Errorf("list %s chain %s: chain is not in its own listing", table, chain)
		}
		digests[chain] = digest
	}
	return digests, nil
}

func (r *HostFactsReader) readSets(ctx context.Context, saved map[string][]savedRule, chains []string) ([]SavedSetFacts, error) {
	names := factSetCandidates(saved, chains)
	if len(names) > maxProofSets {
		return nil, fmt.Errorf("NAT rules name more than %d source sets", maxProofSets)
	}
	sets := make([]SavedSetFacts, 0, len(names))
	for _, name := range names {
		if !validSetName(name) {
			return nil, errors.New("NAT rule names an invalid set")
		}
		out, err := r.runIPSet(ctx, "save", name)
		switch {
		case err != nil:
			sets = append(sets, SavedSetFacts{Name: name, State: FactsUnreadable, Reason: bounded(err.Error(), 120)})
		case strings.TrimSpace(out) == "":
			sets = append(sets, SavedSetFacts{Name: name, State: FactsUnreadable, Reason: "ipset printed nothing"})
		default:
			sets = append(sets, SavedSetFacts{Name: name, State: FactsRead, Saved: out})
		}
	}
	return sets, nil
}

// chainListingDigest identifies one chain of a listing: its declaration and its
// rules with their handles, counters removed. A rule that is replaced gets a
// new handle, so equal digests mean the same rules, not merely equal ones.
func (s *cniSnapshot) chainListingDigest(table, chain string) (string, bool) {
	key := nftKey("ip", table, chain)
	view, ok := s.chains[key]
	if !ok {
		return "", false
	}
	rules := make([]nftRuleView, 0, len(s.rules[key]))
	for _, rule := range s.rules[key] {
		rule.Expr = withoutCounters(rule.Expr)
		rules = append(rules, rule)
	}
	encoded, err := json.Marshal(struct {
		Chain nftChainView
		Rules []nftRuleView
	}{view, rules})
	if err != nil {
		return "", false
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), true
}

// factChains names, in order, the chains of this listing whose saved form a
// proof can need: ip nat chains with an opaque set match, ip mangle chains
// with a MARK target. It is the listing's side of savedFactChains.
func (s *cniSnapshot) factChains(table string) []string {
	names := map[string]bool{}
	for _, list := range s.rules {
		for _, rule := range list {
			if rule.Family != "ip" || rule.Table != table {
				continue
			}
			expr := withoutCounters(rule.Expr)
			if table == "nat" && opaqueSetMatches(expr) > 0 {
				names[rule.Chain] = true
			}
			if table != "mangle" {
				continue
			}
			for _, item := range expr {
				if xt, ok := item["xt"]; ok && len(item) == 1 {
					if kind, name := xtDescriptor(xt); kind == "target" && name == "MARK" {
						names[rule.Chain] = true
					}
				}
			}
		}
	}
	return sortedNames(names)
}

// savedRulesFromFacts returns the saved rules of one table as the manager read
// them, and only if they describe the rules of this listing: every carried
// chain must have here the listing digest the manager recorded, and every
// chain of this listing that a proof can need must be carried.
func (s *cniSnapshot) savedRulesFromFacts(table string, facts SavedTableFacts) (map[string][]savedRule, error) {
	if facts.State != FactsRead {
		reason := facts.Reason
		if reason == "" {
			reason = "no reason given"
		}
		return nil, fmt.Errorf("host-posture manager did not read saved %s rules: %s", table, reason)
	}
	carried := map[string]bool{}
	var text strings.Builder
	for _, chain := range facts.Chains {
		digest, ok := s.chainListingDigest(table, chain.Name)
		if !ok || digest != chain.Listing {
			return nil, fmt.Errorf("%s chain %s changed after the host-posture manager read it", table, chain.Name)
		}
		carried[chain.Name] = true
		for _, rule := range chain.Rules {
			text.WriteString(rule)
			text.WriteByte('\n')
		}
	}
	for _, name := range s.factChains(table) {
		if !carried[name] {
			return nil, fmt.Errorf("host-posture facts do not carry %s chain %s", table, name)
		}
	}
	saved, err := parseSavedRules(text.String())
	if err != nil {
		return nil, err
	}
	for name := range carried {
		if saved[name] == nil {
			saved[name] = []savedRule{}
		}
	}
	return saved, nil
}

// UseHostFacts makes the observed proof take the saved mangle and NAT rule
// text and the set members from source instead of running iptables-nft-save
// and ipset for them. It is set once, before the first Reconcile. The checks
// of the registered AWS mechanism still use the iptables runner.
func (r *Reconciler) UseHostFacts(source HostFactsSource) { r.hostFacts = source }

// takeHostFacts takes the facts once per observation.
func (r *Reconciler) takeHostFacts(ctx context.Context, taken **HostNetFacts) (*HostNetFacts, error) {
	if *taken != nil {
		return *taken, nil
	}
	if err := operationContextErr(ctx); err != nil {
		return nil, err
	}
	facts, err := r.hostFacts(ctx)
	if err != nil {
		return nil, fmt.Errorf("host-posture facts: %w", err)
	}
	if err := facts.Validate(); err != nil {
		return nil, fmt.Errorf("host-posture facts: %w", err)
	}
	if err := operationContextErr(ctx); err != nil {
		return nil, err
	}
	*taken = &facts
	return *taken, nil
}

// natSetFactsFromHostFacts is readNATSetFacts without a command: the saved NAT
// rules and the members of exactly the sets the proof depends on, from facts.
func (r *Reconciler) natSetFactsFromHostFacts(s *cniSnapshot, facts *HostNetFacts, cidr string) (*natSetFacts, error) {
	tunnel, err := netip.ParsePrefix(cidr)
	if err != nil {
		return nil, errors.New("invalid IPv4 tunnel CIDR")
	}
	saved, err := s.savedRulesFromFacts("nat", facts.NAT)
	if err != nil {
		return nil, err
	}
	chains, rules := s.observedNATInput()
	names, err := setsNeededForProof(chains, rules, "POSTROUTING", tunnel, r.iface, observedHandledChains, saved)
	if err != nil {
		return nil, err
	}
	out := &natSetFacts{saved: saved, members: map[string][]netip.Prefix{}}
	for _, name := range names {
		var set *SavedSetFacts
		for i := range facts.Sets {
			if facts.Sets[i].Name == name {
				set = &facts.Sets[i]
			}
		}
		if set == nil {
			return nil, fmt.Errorf("host-posture facts do not carry set %s", name)
		}
		if set.State != FactsRead {
			return nil, fmt.Errorf("read set %s: %s", name, bounded(set.Reason, 120))
		}
		members, err := parseIPSetSave(name, set.Saved)
		if err != nil {
			return nil, err
		}
		out.members[name] = members
	}
	return out, nil
}
