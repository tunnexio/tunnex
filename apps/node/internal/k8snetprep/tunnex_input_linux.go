//go:build linux

package k8snetprep

import (
	"errors"
	"reflect"
	"slices"
)

// knownTunnexHooks are the hooks the egress renderer declares in `ip tunnex`
// and `ip6 tunnex`: the DNAT, the source NAT, the access chain and the input
// chain (K8N-7). A chain on any other hook in those tables is refused.
var knownTunnexHooks = map[string]bool{"prerouting": true, "postrouting": true, "forward": true, "input": true}

// validateTunnexInput proves the input hook of the gateway's own tables
// (K8N-7). In `ip tunnex` and `ip6 tunnex` the only chain on the input hook is
// `input`: filter, priority 0, policy accept, holding exactly one of:
//
//   - the running chain: the reply accept (`iifname <tunnels> ct direction
//     reply ct state established,related accept`), the DNS listener in UDP and
//     TCP and, in IPv4 only and each at most once, the AI VPN listener and
//     then the MCP gateway listener (`iifname <wg> fib daddr . iif type local
//     <proto> dport <port> accept`), then the tunnel drop (`iifname <tunnels>
//     drop`), in that order, each under its marker;
//   - the stopped chain: one tunnel drop under the stopped marker.
//
// Both tunnel sets are the same and cover the WireGuard interface and every
// other tunnel interface the agent currently owns. A missing input chain, or
// an empty one, is accepted here: the manager's marker-only table, a table
// left by a release without the chain and the gateway before its first apply
// have none, and a release that does not declare the chain leaves it empty
// (policy accept, no rule) after its own `flush table`. Neither can drop or
// accept anything. The egress manager's kernel readback (ReadAppliedOVPNTunnel)
// requires the chain.
func (s *cniSnapshot) validateTunnexInput(iface string) error {
	tunnels := append([]string{iface}, s.tunnelIfaces...)
	for key, chain := range s.chains {
		if chain.Table != "tunnex" || (chain.Family != "ip" && chain.Family != "ip6") {
			continue
		}
		if chain.Hook == "" {
			if chain.Name == "input" {
				return errors.New("Tunnex input chain is not the registered input hook")
			}
			continue
		}
		if !knownTunnexHooks[chain.Hook] {
			return errors.New("unknown Tunnex hook")
		}
		if chain.Hook != "input" {
			continue
		}
		if chain.Name != "input" || chain.Type != "filter" || chain.Priority != 0 || chain.Policy != "accept" {
			return errors.New("Tunnex input hook is not the exact registered chain")
		}
		if err := validateTunnexInputRules(chain.Family, s.rules[key], iface, tunnels); err != nil {
			return err
		}
	}
	return nil
}

func validateTunnexInputRules(family string, rules []nftRuleView, iface string, tunnels []string) error {
	if len(rules) == 0 {
		return nil
	}
	if len(rules) == 1 && rules[0].Comment == StoppedTunnelDropRuleComment {
		_, err := tunnexInputDrop(withoutCounters(rules[0].Expr), tunnels)
		return err
	}
	want := []string{InputReplyRuleComment, InputDNSRuleComment, InputDNSRuleComment}
	listeners := [][2]any{{"udp", float64(InputDNSPort)}, {"tcp", float64(InputDNSPort)}}
	// The optional IPv4 listeners, in the renderer's order, each named by its marker at its position.
	if family == "ip" {
		for _, optional := range []struct {
			comment string
			port    int
		}{{InputAIVPNRuleComment, InputAIVPNPort}, {InputMCPGatewayRuleComment, InputMCPGatewayPort}} {
			if len(want) < len(rules) && rules[len(want)].Comment == optional.comment {
				want = append(want, optional.comment)
				listeners = append(listeners, [2]any{"tcp", float64(optional.port)})
			}
		}
	}
	want = append(want, InputTunnelDropRuleComment)
	if len(rules) != len(want) {
		return errors.New("Tunnex input chain does not hold exactly the registered rules")
	}
	for i, rule := range rules {
		if rule.Comment != want[i] {
			return errors.New("Tunnex input chain does not hold exactly the registered rules")
		}
	}
	reply, err := tunnexInputReply(withoutCounters(rules[0].Expr), tunnels)
	if err != nil {
		return err
	}
	for i, listener := range listeners {
		if !tunnexInputListener(withoutCounters(rules[1+i].Expr), iface, listener[0], listener[1]) {
			return errors.New("Tunnex input listener is not the exact registered accept")
		}
	}
	drop, err := tunnexInputDrop(withoutCounters(rules[len(rules)-1].Expr), tunnels)
	if err != nil {
		return err
	}
	if !slices.Equal(reply, drop) {
		return errors.New("Tunnex input reply and drop name different tunnels")
	}
	return nil
}

// tunnexInputReply accepts `iifname <tunnels> ct direction reply ct state
// established,related accept` and returns the interface set.
func tunnexInputReply(expr []map[string]any, tunnels []string) ([]string, error) {
	if len(expr) != 4 || !reflect.DeepEqual(expr[3], map[string]any{"accept": nil}) {
		return nil, errors.New("Tunnex input reply accept is not exact")
	}
	direction, ok := nftMatch(expr[1], "==", map[string]any{"ct": map[string]any{"key": "direction"}})
	if !ok || direction != "reply" {
		return nil, errors.New("Tunnex input reply accept is not limited to replies")
	}
	state, ok := nftMatch(expr[2], "in", map[string]any{"ct": map[string]any{"key": "state"}})
	if !ok || !reflect.DeepEqual(state, []any{"established", "related"}) {
		return nil, errors.New("Tunnex input reply accept is not limited to established and related")
	}
	return tunnexInputIngress(expr[0], tunnels)
}

// tunnexInputListener matches `iifname <wg> fib daddr . iif type local
// <proto> dport <port> accept` exactly.
func tunnexInputListener(expr []map[string]any, iface string, proto, port any) bool {
	if len(expr) != 4 || !reflect.DeepEqual(expr[3], map[string]any{"accept": nil}) {
		return false
	}
	ingress, ok := nftNamedInterfaceMatch(expr[0], "==", "iifname")
	if !ok || ingress != iface {
		return false
	}
	local, ok := nftMatch(expr[1], "==", map[string]any{"fib": map[string]any{"result": "type", "flags": []any{"daddr", "iif"}}})
	if !ok || local != "local" {
		return false
	}
	dport, ok := nftMatch(expr[2], "==", map[string]any{"payload": map[string]any{"protocol": proto, "field": "dport"}})
	return ok && dport == port
}

// tunnexInputDrop accepts `iifname <tunnels> drop` and returns the set.
func tunnexInputDrop(expr []map[string]any, tunnels []string) ([]string, error) {
	if len(expr) != 2 || !reflect.DeepEqual(expr[1], map[string]any{"drop": nil}) {
		return nil, errors.New("Tunnex input tunnel drop is not exact")
	}
	return tunnexInputIngress(expr[0], tunnels)
}

// tunnexInputIngress reads `iifname "x"` or `iifname { ... }` and requires it
// to name every current tunnel interface, each valid name once.
func tunnexInputIngress(expr map[string]any, tunnels []string) ([]string, error) {
	right, ok := nftMatch(expr, "==", map[string]any{"meta": map[string]any{"key": "iifname"}})
	if !ok {
		return nil, errors.New("Tunnex input rule is not limited to tunnel ingress")
	}
	var names []string
	switch value := right.(type) {
	case string:
		names = []string{value}
	case map[string]any:
		members, ok := value["set"].([]any)
		if len(value) != 1 || !ok || len(members) == 0 || len(members) > 16 {
			return nil, errors.New("Tunnex input interface set is unsupported")
		}
		for _, member := range members {
			name, ok := member.(string)
			if !ok {
				return nil, errors.New("Tunnex input interface set is invalid")
			}
			names = append(names, name)
		}
	default:
		return nil, errors.New("Tunnex input rule is not limited to tunnel ingress")
	}
	seen := map[string]bool{}
	for _, name := range names {
		if !interfaceNameRE.MatchString(name) || seen[name] {
			return nil, errors.New("Tunnex input interface set is invalid")
		}
		seen[name] = true
	}
	for _, tunnel := range tunnels {
		if !seen[tunnel] {
			return nil, errors.New("Tunnex input rule leaves a tunnel interface open")
		}
	}
	slices.Sort(names)
	return names, nil
}
