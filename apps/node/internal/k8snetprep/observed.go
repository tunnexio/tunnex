package k8snetprep

import (
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"regexp"
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

// exactInterfaceNameRE is an interface name with no wildcard, as nft prints an
// exact `oifname` comparison.
var exactInterfaceNameRE = regexp.MustCompile(`^[A-Za-z0-9._-]{1,15}$`)

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
//
// That last sentence is an assumption, not something read from the node, for
// every hook a packet passes before NAT POSTROUTING. What is enforced: nothing
// reachable from `ip mangle POSTROUTING` (proveCannotSetReservedMarks) and
// nothing tunnel-bound traffic can reach inside the NAT walk itself
// (proveMarkTarget, nativeMarkStatement) can set one. What is not: marks set
// earlier, in PREROUTING, OUTPUT or FORWARD. kube-proxy sets 0x4000 there on
// Service traffic, so a Service endpoint inside the tunnel range breaks the
// assumption; see docs/K8N-1-calico.md, "Assumption A1".
var kubeMarks = map[float64]bool{0x2000: true, 0x4000: true, 0x8000: true}

type observedNAT struct {
	chains  map[string]bool
	rules   map[string][][]map[string]any
	handled map[string]bool
	tunnel  netip.Prefix
	egress  string
	// tunnels holds egress and every other interface through which traffic
	// enters a tunnel on this node. It is empty when egress is.
	tunnels map[string]bool
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
	_, err := proveNoTunnelSourceNATWithSets(chains, rules, base, tunnel, "", handled, nil)
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
//
// egress, when not empty, is the interface through which traffic enters the
// tunnel (the WireGuard interface). The traffic the proof protects is then
// traffic for tunnel that leaves through egress, the same scope as the rules
// this package owns (`ip daddr TUNNEL oifname EGRESS return`): a rule that
// requires another exact output interface cannot apply to it. With egress
// empty an output-interface condition excuses nothing.
//
// alsoTunnel names every other interface through which traffic enters a
// tunnel on this node (the OpenVPN server's, when it serves). Devices behind
// any of them draw from the same range, so a rule bound to one of them is not
// excused either: a rule is excused only when the exact name it requires is
// none of the tunnel interfaces.
func proveNoTunnelSourceNATWithSets(chains map[string]bool, rules map[string][][]map[string]any, base string, tunnel netip.Prefix, egress string, handled map[string]bool, facts *natSetFacts, alsoTunnel ...string) ([]string, error) {
	o, err := newObservedNAT(chains, rules, tunnel, egress, handled, alsoTunnel)
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
func setsNeededForProof(chains map[string]bool, rules map[string][][]map[string]any, base string, tunnel netip.Prefix, egress string, handled map[string]bool, saved map[string][]savedRule, alsoTunnel ...string) ([]string, error) {
	o, err := newObservedNAT(chains, rules, tunnel, egress, handled, alsoTunnel)
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

// maxTunnelInterfaces bounds how many tunnel interfaces one proof may be told.
const maxTunnelInterfaces = 16

func newObservedNAT(chains map[string]bool, rules map[string][][]map[string]any, tunnel netip.Prefix, egress string, handled map[string]bool, alsoTunnel []string) (*observedNAT, error) {
	if !tunnel.IsValid() || !tunnel.Addr().Is4() {
		return nil, errors.New("invalid IPv4 tunnel range")
	}
	if len(alsoTunnel) > maxTunnelInterfaces {
		return nil, errors.New("too many tunnel interfaces")
	}
	if egress != "" && !exactInterfaceNameRE.MatchString(egress) {
		return nil, errors.New("invalid tunnel interface name")
	}
	tunnels := map[string]bool{}
	if egress != "" {
		tunnels[egress] = true
	}
	for _, name := range alsoTunnel {
		// A name that could not be an interface is never dropped: the caller
		// meant an interface this proof would otherwise excuse rules for.
		if !exactInterfaceNameRE.MatchString(name) {
			return nil, errors.New("invalid tunnel interface name")
		}
		if egress != "" {
			tunnels[name] = true
		}
	}
	return &observedNAT{chains: chains, rules: rules, handled: handled, tunnel: tunnel.Masked(), egress: egress, tunnels: tunnels, active: map[string]bool{},
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
		case "mark":
			if err := o.proveMarkTarget(chain, n); err != nil {
				return false, err
			}
		}
	}
	return false, nil
}

// natMarkNotReadError refuses a MARK target that tunnel-bound traffic can
// reach inside the NAT table while its value is not at hand. Like a set
// match, the value is only in the saved rule text, so the caller may read
// that text and prove again.
type natMarkNotReadError struct{ chain string }

func (e *natMarkNotReadError) Error() string {
	return fmt.Sprintf("NAT chain %s sets a mark whose value was not read", e.chain)
}

func (e *natMarkNotReadError) Is(target error) bool { return target == errSetFactsNeeded }

// proveMarkTarget decides an iptables MARK target that tunnel-bound traffic
// can reach on its way through the NAT table. The walk relies on that traffic
// carrying no Kubernetes mark (kubeMarks) when it meets a rule that tests
// one, so a mark set here, before such a rule, is accepted only when its
// saved value is read and leaves those bits alone, exactly as for the mangle
// hook (proveCannotSetReservedMarks). The nft listing does not show the value.
func (o *observedNAT) proveMarkTarget(chain string, n int) error {
	if o.facts == nil {
		return &natMarkNotReadError{chain: chain}
	}
	if _, carried := o.facts.saved[chain]; !carried {
		// The saved text at hand does not hold this chain (the host-posture
		// manager carries NAT chains for their set matches only).
		return fmt.Errorf("NAT chain %s sets a mark whose value was not read: its saved rules are not at hand", chain)
	}
	if err := o.pair(chain); err != nil {
		return err
	}
	changed, ok := savedMarkChange(o.facts.saved[chain][n].Args)
	if !ok {
		return fmt.Errorf("NAT chain %s has a MARK target that is not understood", chain)
	}
	if changed&reservedMarkBits != 0 {
		return fmt.Errorf("NAT chain %s can set a Kubernetes mark that selects a masquerade", chain)
	}
	return nil
}

// nativeMarkStatement reads an nft `mangle` statement found in the NAT table.
// The only one accepted is `meta mark set VALUE` where VALUE cannot turn on a
// Kubernetes mark bit that was off. Every other mangle statement (`ip saddr
// set`, `ip daddr set`, `ct mark set`, `meta priority set`, ...) rewrites
// something this walk does not model and is refused.
func nativeMarkStatement(statement any) error {
	body, ok := statement.(map[string]any)
	if !ok || len(body) != 2 || !reflect.DeepEqual(body["key"], map[string]any{"meta": map[string]any{"key": "mark"}}) {
		return errors.New("rewrites a packet field with a statement that is not understood")
	}
	value, present := body["value"]
	if !present {
		return errors.New("sets a mark to a value that is not understood")
	}
	turnsOn, ok := markBitsTurnedOn(value, 0)
	if !ok {
		return errors.New("sets a mark to a value that is not understood")
	}
	if turnsOn&reservedMarkBits != 0 {
		return errors.New("can set a Kubernetes mark that selects a masquerade")
	}
	return nil
}

// maxMarkValueDepth bounds the nesting of a mark value (`mark & M | C` is 2).
const maxMarkValueDepth = 4

// markBitsTurnedOn returns every bit that the value of a `meta mark set`
// statement can have set where the packet's mark had it clear:
//
//	N                 every bit of N
//	meta mark         none (the old mark)
//	A | B, A ^ B      what A or B can turn on
//	A & B             only what both can turn on
//
// Anything else (ct mark, a map, numgen, a shift, a hash, a negative or
// fractional number) is not understood.
func markBitsTurnedOn(value any, depth int) (uint32, bool) {
	if depth > maxMarkValueDepth {
		return 0, false
	}
	if number, ok := value.(float64); ok {
		if number < 0 || number > float64(^uint32(0)) || number != float64(uint32(number)) {
			return 0, false
		}
		return uint32(number), true
	}
	object, ok := value.(map[string]any)
	if !ok || len(object) != 1 {
		return 0, false
	}
	if reflect.DeepEqual(object, map[string]any{"meta": map[string]any{"key": "mark"}}) {
		return 0, true
	}
	for _, operator := range []string{"|", "^", "&"} {
		operands, ok := object[operator].([]any)
		if !ok {
			continue
		}
		if len(operands) != 2 {
			return 0, false
		}
		left, leftOK := markBitsTurnedOn(operands[0], depth+1)
		right, rightOK := markBitsTurnedOn(operands[1], depth+1)
		if !leftOK || !rightOK {
			return 0, false
		}
		if operator == "&" {
			return left & right, true
		}
		return left | right, true
	}
	return 0, false
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
				// Its value is not in the listing: the walk reads it from the
				// saved rule, if tunnel-bound traffic can reach the rule.
				view.verdict = "mark"
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
		if statement, ok := expr["mangle"]; ok {
			// Decided here, whatever the rule's conditions say: a statement
			// takes effect before the conditions that follow it in the same
			// rule, so a rule may set a mark and then match on it.
			if err := nativeMarkStatement(statement); err != nil {
				return view, fmt.Errorf("NAT chain %s %w", chain, err)
			}
			continue
		}
		if !last {
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
	if reflect.DeepEqual(match["left"], map[string]any{"meta": map[string]any{"key": "oifname"}}) {
		// `oifname == "tunl0"`: the rule applies only to packets leaving
		// through that one interface. Traffic entering a tunnel leaves
		// through one of the tunnel interfaces, so a rule bound to an exact
		// name that is none of them never sees it. A wildcard ("tunl*"), a
		// set of names, "!=" and an unknown egress prove nothing.
		name, isName := match["right"].(string)
		if op == "==" && isName && o.egress != "" && exactInterfaceNameRE.MatchString(name) && !o.tunnels[name] {
			view.cannotMatch = true
			return
		}
		view.certain = false
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
