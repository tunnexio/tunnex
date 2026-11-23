package k8snetprep

import (
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"sort"
	"strconv"
	"strings"
)

// ObservedAdapterName is the adapter reported when the node has no registered
// CNI masquerade mechanism to edit, and the live NAT rules were instead proved
// unable to source-NAT traffic bound for the tunnel range.
const ObservedAdapterName = "observed_cni"

// ReasonObservedNoTunnelSourceNAT is the bounded reason carried by a ready
// observed adapter.
const ReasonObservedNoTunnelSourceNAT = "node NAT rules cannot rewrite traffic to the tunnel range"

const maxObservedChainDepth = 8

// maxProofSets bounds how many kernel sets one proof may ask to read.
const maxProofSets = 16

// errSetFactsNeeded marks a refusal that exists only because a source-NAT rule
// is conditioned on a kernel set the nft listing cannot describe. The caller
// may read those facts (natSetFacts) and prove again; without them the rule
// stays refused.
var errSetFactsNeeded = errors.New("set match not read")

// natSetFacts is what the nft listing cannot say about `-m set` matches: the
// saved form of every NAT rule (from iptables-nft-save) and the members of the
// sets the proof depends on (from ipset). Both are read by the caller; the
// proof itself runs no command.
type natSetFacts struct {
	saved   map[string][]savedRule
	members map[string][]netip.Prefix
}

// observedReadyReason is the bounded reason of a ready observed adapter. When
// kernel sets carried the proof it names them, so an operator can see why a
// masquerade rule was accepted.
func observedReadyReason(proofSets []string) string {
	if len(proofSets) == 0 {
		return ReasonObservedNoTunnelSourceNAT
	}
	const shown = 3
	names := proofSets
	more := ""
	if len(names) > shown {
		more = fmt.Sprintf(" and %d more", len(names)-shown)
		names = names[:shown]
	}
	return bounded(ReasonObservedNoTunnelSourceNAT+"; masquerade sources are limited by sets outside it: "+strings.Join(names, ", ")+more, maxReasonBytes)
}

// kubeMarks are the packet-mark bits Kubernetes components reserve to select
// their own NAT rules: kube-proxy masquerade (0x4000) and drop (0x8000), and
// the CNI portmap plugin's host-port masquerade (0x2000). Tunnex never sets
// them, and it delivers to pod addresses directly, so traffic bound for the
// tunnel range does not carry them.
var kubeMarks = map[float64]bool{0x2000: true, 0x4000: true, 0x8000: true}

type observedNAT struct {
	chains  map[string]bool
	rules   map[string][][]map[string]any
	handled map[string]bool
	tunnel  netip.Prefix
	active  map[string]bool

	// facts is nil when no set facts were read. collect makes the walk gather
	// the sets it would need (needed) instead of judging their members.
	facts   *natSetFacts
	collect bool
	paired  map[string]bool
	needed  map[string]bool
	proof   map[string]bool
}

// proveNoTunnelSourceNAT walks every rule reachable from base (the ip nat
// POSTROUTING chain) and returns nil only when no source-NAT statement can
// apply to a packet whose destination is inside tunnel, except for traffic a
// rule positively limits to a source range outside the tunnel (pod-originated
// traffic, which a CNI may legitimately masquerade).
//
// rules holds each chain's rules with counters already removed. handled names
// chains another adapter owns and proves separately. The analysis is
// deliberately small: any statement or jump target it does not understand is
// an error, never an assumption.
func proveNoTunnelSourceNAT(chains map[string]bool, rules map[string][][]map[string]any, base string, tunnel netip.Prefix, handled map[string]bool) error {
	_, err := proveNoTunnelSourceNATWithSets(chains, rules, base, tunnel, handled, nil)
	return err
}

// proveNoTunnelSourceNATWithSets is the same walk, given the set facts read
// beside the nft listing. A source-NAT rule behind opaque `set` matches is then
// accepted exactly when it pairs with its saved form and that form carries a
// non-negated, source-only match on a set whose every member is outside
// tunnel. It returns the sorted names of the sets that carried the proof.
//
// With facts nil such a rule is refused with errSetFactsNeeded. A rule that
// does not pair, a needed set that was not read, and a set overlapping tunnel
// are errors.
func proveNoTunnelSourceNATWithSets(chains map[string]bool, rules map[string][][]map[string]any, base string, tunnel netip.Prefix, handled map[string]bool, facts *natSetFacts) ([]string, error) {
	o, err := newObservedNAT(chains, rules, tunnel, handled)
	if err != nil {
		return nil, err
	}
	o.facts = facts
	if _, err := o.walk(base, 0); err != nil {
		return nil, err
	}
	return sortedNames(o.proof), nil
}

// setsNeededForProof runs the walk without judging membership and returns the
// sorted names of exactly the sets whose members the proof depends on: those
// of non-negated, source-only matches on source-NAT rules that tunnel-bound
// traffic can reach from base. Every other refusal of the walk, including a
// rule that does not pair with saved, is returned as an error.
func setsNeededForProof(chains map[string]bool, rules map[string][][]map[string]any, base string, tunnel netip.Prefix, handled map[string]bool, saved map[string][]savedRule) ([]string, error) {
	o, err := newObservedNAT(chains, rules, tunnel, handled)
	if err != nil {
		return nil, err
	}
	o.facts, o.collect = &natSetFacts{saved: saved}, true
	if _, err := o.walk(base, 0); err != nil {
		return nil, err
	}
	if len(o.needed) > maxProofSets {
		return nil, errors.New("NAT rules depend on too many sets")
	}
	return sortedNames(o.needed), nil
}

func newObservedNAT(chains map[string]bool, rules map[string][][]map[string]any, tunnel netip.Prefix, handled map[string]bool) (*observedNAT, error) {
	if !tunnel.IsValid() || !tunnel.Addr().Is4() {
		return nil, errors.New("invalid IPv4 tunnel range")
	}
	return &observedNAT{chains: chains, rules: rules, handled: handled, tunnel: tunnel.Masked(), active: map[string]bool{},
		paired: map[string]bool{}, needed: map[string]bool{}, proof: map[string]bool{}}, nil
}

func sortedNames(set map[string]bool) []string {
	names := make([]string, 0, len(set))
	for name := range set {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// walk reports whether tunnel-bound traffic certainly leaves the hook inside
// this chain (accept or drop), so the caller's later rules never see it.
func (o *observedNAT) walk(chain string, depth int) (bool, error) {
	if depth > maxObservedChainDepth || o.active[chain] {
		return false, fmt.Errorf("NAT chain %s is nested too deeply or loops", chain)
	}
	if !o.chains[chain] {
		return false, fmt.Errorf("NAT rule jumps to unknown chain %s", chain)
	}
	o.active[chain] = true
	defer delete(o.active, chain)
	for n, rule := range o.rules[chain] {
		view, err := o.read(chain, rule)
		if err != nil {
			return false, err
		}
		if view.cannotMatch {
			continue
		}
		switch view.verdict {
		case "noop":
		case "return":
			if view.certain {
				return false, nil
			}
		case "accept", "drop":
			if view.certain {
				return true, nil
			}
		case "jump", "goto":
			if o.handled[view.target] {
				continue
			}
			done, err := o.walk(view.target, depth+1)
			if err != nil {
				return false, err
			}
			if view.certain && (done || view.verdict == "goto") {
				return done, nil
			}
		case "nat":
			if view.sourceLimited {
				continue
			}
			if err := o.proveBySets(chain, n); err != nil {
				return false, err
			}
		}
	}
	return false, nil
}

// proveBySets decides a source-NAT rule that no readable nft condition limits.
// It returns nil only when the rule's saved form limits the source to a set
// that lies outside the tunnel range.
func (o *observedNAT) proveBySets(chain string, n int) error {
	refused := fmt.Errorf("NAT chain %s can rewrite the source of traffic to the tunnel range %s", chain, o.tunnel)
	if opaqueSetMatches(o.rules[chain][n]) == 0 {
		return refused
	}
	if o.facts == nil {
		return fmt.Errorf("%w: %w", refused, errSetFactsNeeded)
	}
	if err := o.pair(chain); err != nil {
		return err
	}
	matches := o.facts.saved[chain][n].Sets
	candidates := 0
	for _, match := range matches {
		if match.Negated || len(match.Dirs) != 1 || match.Dirs[0] != "src" {
			continue
		}
		candidates++
		if o.collect {
			o.needed[match.Name] = true
			continue
		}
		if _, read := o.facts.members[match.Name]; !read {
			return fmt.Errorf("NAT chain %s depends on set %s, which was not read", chain, match.Name)
		}
	}
	if candidates == 0 {
		// Only negated or destination set matches: nothing limits the source.
		return refused
	}
	if o.collect {
		return nil
	}
	ok, proof := setsLimitSourceOutside(matches, o.facts.members, o.tunnel)
	if !ok {
		for _, match := range matches {
			if !match.Negated && len(match.Dirs) == 1 && match.Dirs[0] == "src" {
				return fmt.Errorf("NAT chain %s masquerades sources in set %s, which overlaps the tunnel range %s", chain, match.Name, o.tunnel)
			}
		}
		return refused
	}
	for _, name := range proof {
		o.proof[name] = true
	}
	return nil
}

// pair checks that the saved text describes the same chain as the nft
// listing: the same number of rules, and for rule N of both the same number of
// set matches and the same target. Only then may set match K of saved rule N be
// read as the K-th opaque set match of nft rule N.
func (o *observedNAT) pair(chain string) error {
	if o.paired[chain] {
		return nil
	}
	rules, saved := o.rules[chain], o.facts.saved[chain]
	if len(rules) != len(saved) {
		return fmt.Errorf("NAT chain %s has %d rules but %d saved rules; its set matches cannot be read", chain, len(rules), len(saved))
	}
	for n, rule := range rules {
		if opaqueSetMatches(rule) != len(saved[n].Sets) || ruleTarget(rule) != saved[n].Target {
			return fmt.Errorf("NAT chain %s rule %d does not pair with its saved rule; its set matches cannot be read", chain, n+1)
		}
	}
	o.paired[chain] = true
	return nil
}

// opaqueSetMatches counts the `-m set` matches nft shows without their content.
func opaqueSetMatches(exprs []map[string]any) int {
	count := 0
	for _, expr := range exprs {
		if xt, ok := expr["xt"]; ok && len(expr) == 1 {
			if kind, name := xtDescriptor(xt); kind == "match" && name == "set" {
				count++
			}
		}
	}
	return count
}

// ruleTarget names what a rule ends in, in the vocabulary iptables-nft-save
// uses after -j or -g. It is empty for a rule with no target.
func ruleTarget(exprs []map[string]any) string {
	if len(exprs) == 0 {
		return ""
	}
	last := exprs[len(exprs)-1]
	if len(last) != 1 {
		return ""
	}
	if xt, ok := last["xt"]; ok {
		if kind, name := xtDescriptor(xt); kind == "target" {
			return name
		}
		return ""
	}
	for key, name := range map[string]string{"return": "RETURN", "accept": "ACCEPT", "drop": "DROP", "masquerade": "MASQUERADE", "snat": "SNAT"} {
		if hasKey(last, key) {
			return name
		}
	}
	for _, verdict := range []string{"jump", "goto"} {
		if body, ok := last[verdict].(map[string]any); ok {
			target, _ := body["target"].(string)
			return target
		}
	}
	return ""
}

type observedRule struct {
	verdict       string
	target        string
	cannotMatch   bool
	certain       bool
	sourceLimited bool
}

func (o *observedNAT) read(chain string, exprs []map[string]any) (observedRule, error) {
	view := observedRule{certain: true}
	for i, expr := range exprs {
		last := i == len(exprs)-1
		if len(expr) != 1 {
			return view, fmt.Errorf("NAT chain %s has an unreadable statement", chain)
		}
		if xt, ok := expr["xt"]; ok {
			kind, name := xtDescriptor(xt)
			switch {
			case kind == "match" && name == "comment":
			case kind == "match" && name != "":
				// An extension match can only narrow the rule.
				view.certain = false
			case kind == "target" && last && (name == "MASQUERADE" || name == "SNAT"):
				view.verdict = "nat"
			case kind == "target" && last && name == "MARK":
				view.verdict = "noop"
			default:
				// Untyped (older nft), misplaced, or unknown: not readable.
				return view, fmt.Errorf("NAT chain %s has an extension that is not understood", chain)
			}
			continue
		}
		if match, ok := expr["match"].(map[string]any); ok {
			o.readMatch(match, &view)
			continue
		}
		if !last {
			if _, ok := expr["mangle"]; ok {
				continue
			}
			return view, fmt.Errorf("NAT chain %s has a statement before the end of a rule that is not understood", chain)
		}
		switch {
		case hasKey(expr, "return"):
			view.verdict = "return"
		case hasKey(expr, "accept"):
			view.verdict = "accept"
		case hasKey(expr, "drop"):
			view.verdict = "drop"
		case hasKey(expr, "masquerade"), hasKey(expr, "snat"):
			view.verdict = "nat"
		case hasKey(expr, "mangle"):
			view.verdict = "noop"
		case hasKey(expr, "jump"), hasKey(expr, "goto"):
			verdict := "jump"
			if hasKey(expr, "goto") {
				verdict = "goto"
			}
			body, _ := expr[verdict].(map[string]any)
			target, ok := body["target"].(string)
			if !ok || len(body) != 1 || target == "" {
				return view, fmt.Errorf("NAT chain %s has an unreadable jump", chain)
			}
			view.verdict, view.target = verdict, target
		default:
			return view, fmt.Errorf("NAT chain %s has a statement that is not understood", chain)
		}
	}
	if view.verdict == "" {
		// A rule with only conditions (a bare counter) does nothing.
		view.verdict = "noop"
	}
	return view, nil
}

func (o *observedNAT) readMatch(match map[string]any, view *observedRule) {
	op, _ := match["op"].(string)
	if len(match) != 3 || (op != "==" && op != "!=") {
		view.certain = false
		return
	}
	if direction, ok := ipAddressField(match["left"]); ok {
		prefix, ok := matchPrefix(match["right"])
		if !ok {
			view.certain = false
			return
		}
		inside := prefix.Bits() <= o.tunnel.Bits() && prefix.Contains(o.tunnel.Addr())
		overlaps := prefix.Overlaps(o.tunnel)
		switch {
		case direction == "daddr" && op == "==":
			if !overlaps {
				view.cannotMatch = true
			} else if !inside {
				view.certain = false
			}
		case direction == "daddr" && op == "!=":
			if inside {
				view.cannotMatch = true
			} else if overlaps {
				view.certain = false
			}
		case direction == "saddr" && op == "==":
			view.certain = false
			if !overlaps {
				view.sourceLimited = true
			}
		default:
			view.certain = false
		}
		return
	}
	if mask, ok := markMask(match["left"]); ok {
		right, isNumber := match["right"].(float64)
		if isNumber && right == mask && kubeMarks[mask] {
			if op == "==" {
				view.cannotMatch = true
			}
			// "!=" on a reserved mark is always true for tunnel-bound traffic.
			return
		}
	}
	view.certain = false
}

func hasKey(expr map[string]any, key string) bool {
	_, ok := expr[key]
	return ok
}

func xtDescriptor(value any) (string, string) {
	body, ok := value.(map[string]any)
	if !ok || len(body) != 2 {
		return "", ""
	}
	kind, _ := body["type"].(string)
	name, _ := body["name"].(string)
	return kind, name
}

func ipAddressField(left any) (string, bool) {
	for _, direction := range []string{"saddr", "daddr"} {
		if reflect.DeepEqual(left, map[string]any{"payload": map[string]any{"protocol": "ip", "field": direction}}) {
			return direction, true
		}
	}
	return "", false
}

func matchPrefix(right any) (netip.Prefix, bool) {
	if address, ok := right.(string); ok {
		addr, err := netip.ParseAddr(address)
		if err != nil || !addr.Is4() {
			return netip.Prefix{}, false
		}
		return netip.PrefixFrom(addr, 32), true
	}
	object, ok := right.(map[string]any)
	if !ok || len(object) != 1 {
		return netip.Prefix{}, false
	}
	body, ok := object["prefix"].(map[string]any)
	if !ok || len(body) != 2 {
		return netip.Prefix{}, false
	}
	addr, ok := body["addr"].(string)
	bits, bitsOK := body["len"].(float64)
	if !ok || !bitsOK || bits < 0 || bits > 32 || bits != float64(int(bits)) {
		return netip.Prefix{}, false
	}
	prefix, err := netip.ParsePrefix(addr + "/" + strconv.Itoa(int(bits)))
	if err != nil || !prefix.Addr().Is4() {
		return netip.Prefix{}, false
	}
	return prefix.Masked(), true
}

// markMask reads `meta mark & MASK` and returns MASK.
func markMask(left any) (float64, bool) {
	body, ok := left.(map[string]any)
	if !ok || len(body) != 1 {
		return 0, false
	}
	operands, ok := body["&"].([]any)
	if !ok || len(operands) != 2 || !reflect.DeepEqual(operands[0], map[string]any{"meta": map[string]any{"key": "mark"}}) {
		return 0, false
	}
	mask, ok := operands[1].(float64)
	return mask, ok && mask > 0
}
