package k8snetprep

import (
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"strconv"
)

// ObservedAdapterName is the adapter reported when the node has no registered
// CNI masquerade mechanism to edit, and the live NAT rules were instead proved
// unable to source-NAT traffic bound for the tunnel range.
const ObservedAdapterName = "observed_cni"

// ReasonObservedNoTunnelSourceNAT is the bounded reason carried by a ready
// observed adapter.
const ReasonObservedNoTunnelSourceNAT = "node NAT rules cannot rewrite traffic to the tunnel range"

const maxObservedChainDepth = 8

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
	if !tunnel.IsValid() || !tunnel.Addr().Is4() {
		return errors.New("invalid IPv4 tunnel range")
	}
	o := &observedNAT{chains: chains, rules: rules, handled: handled, tunnel: tunnel.Masked(), active: map[string]bool{}}
	_, err := o.walk(base, 0)
	return err
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
	for _, rule := range o.rules[chain] {
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
			if !view.sourceLimited {
				return false, fmt.Errorf("NAT chain %s can rewrite the source of traffic to the tunnel range %s", chain, o.tunnel)
			}
		}
	}
	return false, nil
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
