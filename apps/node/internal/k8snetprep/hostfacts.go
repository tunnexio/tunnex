package k8snetprep

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

// K8N-1, Decision 9: the gateway container cannot run iptables-nft-save on a
// node whose rules carry `set` matches (it needs NET_RAW), so in Kubernetes the
// privileged host-posture manager reads the saved rule text and the set
// members and hands them over as facts. The gateway still decides: it knows
// the tunnel range, runs the same parsers and the same proofs, and binds every
// fact to its own nft listing.

// Fact states. A table or set that was not read carries the reason.
const (
	FactsRead       = "read"
	FactsNotNeeded  = "not_needed"
	FactsUnreadable = "unreadable"
)

const (
	// MaxHostNetFactsBytes bounds the rule text and set listings of one
	// HostNetFacts. Facts that do not fit are published as unreadable.
	MaxHostNetFactsBytes = 192 << 10
	// HostFactsReadBudget bounds one read of the manager.
	HostFactsReadBudget = 3 * time.Second

	maxFactChains     = 64
	maxFactChainRules = 1024
	factDigestHexLen  = 64
)

// factChainNameRE is the only shape of chain name the reader passes to nft or
// carries. It is nft's own unquoted identifier, so no name needs quoting.
var factChainNameRE = regexp.MustCompile(`^[A-Za-z_.][A-Za-z0-9_.-]{0,63}$`)

// HostNetFacts is what the nft listing hides about the ip nat and ip mangle
// tables: rule text as iptables-nft-save prints it, and kernel set members as
// ipset prints them. It holds no verdict and nothing secret.
type HostNetFacts struct {
	NAT    SavedTableFacts `json:"nat"`
	Mangle SavedTableFacts `json:"mangle"`
	Sets   []SavedSetFacts `json:"sets,omitempty"`
	// LegacyIPTables says whether the node has IPv4 iptables-legacy tables.
	// Their rules run beside nf_tables and no nft listing shows them, so a
	// node with any is not ready (K8N review, finding 5). Required: facts that
	// do not say are refused.
	LegacyIPTables LegacyTablesFacts `json:"legacy_iptables"`
}

// LegacyTablesFacts is what /proc/net/ip_tables_names listed in the node's
// network namespace, or why it could not be read.
type LegacyTablesFacts struct {
	State  string   `json:"state"`
	Reason string   `json:"reason,omitempty"`
	Tables []string `json:"tables,omitempty"`
}

// maxLegacyTables bounds the table names carried; the kernel has five.
const maxLegacyTables = 16

// legacyTableNameRE is the shape of an x_tables table name (XT_TABLE_MAXNAMELEN 32).
var legacyTableNameRE = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,31}$`)

func (l LegacyTablesFacts) validate() error {
	if len(l.Reason) > maxReasonBytes || len(l.Tables) > maxLegacyTables {
		return errors.New("host facts for legacy iptables exceed bound")
	}
	switch l.State {
	case FactsRead:
		if l.Reason != "" {
			return errors.New("host facts for legacy iptables are inconsistent")
		}
		for _, name := range l.Tables {
			if !legacyTableNameRE.MatchString(name) {
				return errors.New("host facts name an invalid legacy iptables table")
			}
		}
	case FactsUnreadable:
		if l.Reason == "" || len(l.Tables) != 0 {
			return errors.New("host facts for legacy iptables are inconsistent")
		}
	case "":
		return errors.New("host facts do not say whether the node has iptables-legacy tables")
	default:
		return errors.New("host facts for legacy iptables have an unknown state")
	}
	return nil
}

// LegacyRefusal is nil only when the facts say the node has no IPv4
// iptables-legacy table. Anything else refuses the node: a legacy table's
// rules, a masquerade among them, are invisible to every proof here.
func (l LegacyTablesFacts) LegacyRefusal() error {
	switch {
	case l.State == FactsRead && len(l.Tables) == 0:
		return nil
	case l.State == FactsRead:
		return fmt.Errorf("node has iptables-legacy tables (%s), whose rules no nft listing shows; remove them or move their rules to iptables-nft", strings.Join(l.Tables, ", "))
	case l.State == FactsUnreadable:
		return fmt.Errorf("could not tell whether the node has iptables-legacy tables: %s", bounded(l.Reason, 120))
	default:
		return errors.New("host facts do not say whether the node has iptables-legacy tables")
	}
}

// ParseLegacyTableNames reads /proc/net/ip_tables_names: one table name per
// line, empty when no legacy table exists in that network namespace.
func ParseLegacyTableNames(text string) LegacyTablesFacts {
	names := strings.Fields(text)
	if len(names) > maxLegacyTables {
		return LegacyTablesFacts{State: FactsUnreadable, Reason: "ip_tables_names lists more tables than expected"}
	}
	for _, name := range names {
		if !legacyTableNameRE.MatchString(name) {
			return LegacyTablesFacts{State: FactsUnreadable, Reason: "ip_tables_names lists a name that is not understood"}
		}
	}
	sort.Strings(names)
	return LegacyTablesFacts{State: FactsRead, Tables: names}
}

// SavedTableFacts carries the chains of one table a proof can need: NAT chains
// with a `set` match, mangle chains with a MARK target.
type SavedTableFacts struct {
	State  string            `json:"state"`
	Reason string            `json:"reason,omitempty"`
	Chains []SavedChainFacts `json:"chains,omitempty"`
}

// SavedChainFacts is one chain's `-A` lines in rule order, and the digest of
// the nft listing of that chain, which was the same before and after the lines
// were read.
type SavedChainFacts struct {
	Name    string   `json:"name"`
	Listing string   `json:"listing"`
	Rules   []string `json:"rules"`
}

// SavedSetFacts is what `ipset save NAME` printed, or why it could not be read.
type SavedSetFacts struct {
	Name   string `json:"name"`
	State  string `json:"state"`
	Reason string `json:"reason,omitempty"`
	Saved  string `json:"saved,omitempty"`
}

// HostFactsSource returns the current facts, or the reason there are none. It
// is called between the two nft listings of one observation.
type HostFactsSource func(context.Context) (HostNetFacts, error)

// UnreadableHostNetFacts is the facts value of a read that failed as a whole.
func UnreadableHostNetFacts(reason string) HostNetFacts {
	table := SavedTableFacts{State: FactsUnreadable, Reason: bounded(reason, maxReasonBytes)}
	return HostNetFacts{NAT: table, Mangle: table, LegacyIPTables: LegacyTablesFacts{State: FactsUnreadable, Reason: table.Reason}}
}

// Validate refuses facts that are malformed or exceed a bound. It says nothing
// about whether they prove anything.
func (f HostNetFacts) Validate() error {
	total := 0
	for _, table := range []struct {
		name  string
		facts SavedTableFacts
	}{{"nat", f.NAT}, {"mangle", f.Mangle}} {
		size, err := table.facts.validate(table.name)
		if err != nil {
			return err
		}
		total += size
	}
	if err := f.LegacyIPTables.validate(); err != nil {
		return err
	}
	if len(f.Sets) > maxProofSets {
		return errors.New("host facts carry too many sets")
	}
	if len(f.Sets) != 0 && f.NAT.State != FactsRead {
		return errors.New("host facts carry sets without saved nat rules")
	}
	if !sort.SliceIsSorted(f.Sets, func(i, k int) bool { return f.Sets[i].Name < f.Sets[k].Name }) {
		return errors.New("host facts sets are not in order")
	}
	for i, set := range f.Sets {
		if !validSetName(set.Name) || (i > 0 && f.Sets[i-1].Name == set.Name) {
			return errors.New("host facts name an invalid or repeated set")
		}
		if len(set.Reason) > maxReasonBytes || len(set.Saved) > maxSetSaveBytes {
			return fmt.Errorf("host facts for set %s exceed bound", set.Name)
		}
		switch set.State {
		case FactsRead:
			if set.Reason != "" || set.Saved == "" {
				return fmt.Errorf("host facts for set %s are inconsistent", set.Name)
			}
		case FactsUnreadable:
			if set.Reason == "" || set.Saved != "" {
				return fmt.Errorf("host facts for set %s are inconsistent", set.Name)
			}
		default:
			return fmt.Errorf("host facts for set %s have an unknown state", set.Name)
		}
		total += len(set.Saved)
	}
	if total > MaxHostNetFactsBytes {
		return errors.New("host facts exceed bound")
	}
	return nil
}

func (t SavedTableFacts) validate(table string) (int, error) {
	if len(t.Reason) > maxReasonBytes {
		return 0, fmt.Errorf("host facts for %s carry an oversized reason", table)
	}
	switch t.State {
	case FactsRead:
		if t.Reason != "" {
			return 0, fmt.Errorf("host facts for %s are inconsistent", table)
		}
	case FactsNotNeeded, FactsUnreadable:
		if t.Reason == "" || len(t.Chains) != 0 {
			return 0, fmt.Errorf("host facts for %s are inconsistent", table)
		}
	default:
		return 0, fmt.Errorf("host facts for %s have an unknown state", table)
	}
	if len(t.Chains) > maxFactChains {
		return 0, fmt.Errorf("host facts for %s carry too many chains", table)
	}
	total := 0
	for i, chain := range t.Chains {
		if !factChainNameRE.MatchString(chain.Name) || (i > 0 && t.Chains[i-1].Name >= chain.Name) {
			return 0, fmt.Errorf("host facts for %s name an invalid, repeated or unordered chain", table)
		}
		if !validFactDigest(chain.Listing) {
			return 0, fmt.Errorf("host facts for %s chain %s lack a listing digest", table, chain.Name)
		}
		if len(chain.Rules) > maxFactChainRules {
			return 0, fmt.Errorf("host facts for %s chain %s carry too many rules", table, chain.Name)
		}
		for _, rule := range chain.Rules {
			if len(rule) > maxSavedRuleBytes || strings.ContainsAny(rule, "\r\n\x00") || !strings.HasPrefix(rule, "-A "+chain.Name+" ") {
				return 0, fmt.Errorf("host facts for %s chain %s carry a line that is not one of its rules", table, chain.Name)
			}
			total += len(rule)
		}
	}
	return total, nil
}

func validFactDigest(value string) bool {
	if len(value) != factDigestHexLen {
		return false
	}
	for _, char := range value {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}

// factSetCandidates names the sets whose members can decide a proof for some
// tunnel range: those of non-negated, source-only matches on source-NAT rules.
// It does not depend on the tunnel range, so the manager, which never learns
// that range, reads a superset of what setsNeededForProof asks for.
func factSetCandidates(saved map[string][]savedRule, chains []string) []string {
	names := map[string]bool{}
	for _, chain := range chains {
		for _, rule := range saved[chain] {
			if rule.Target != "MASQUERADE" && rule.Target != "SNAT" {
				continue
			}
			for _, match := range rule.Sets {
				if !match.Negated && len(match.Dirs) == 1 && match.Dirs[0] == "src" {
					names[match.Name] = true
				}
			}
		}
	}
	return sortedNames(names)
}

// savedFactChains names, in order, the chains of one saved table that a proof
// can need: for nat those with a set match, for mangle those with a MARK target.
func savedFactChains(table string, saved map[string][]savedRule) []string {
	names := map[string]bool{}
	for chain, rules := range saved {
		for _, rule := range rules {
			if (table == "nat" && len(rule.Sets) > 0) || (table == "mangle" && rule.Target == "MARK") {
				names[chain] = true
			}
		}
	}
	return sortedNames(names)
}
