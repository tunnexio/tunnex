//go:build linux

package k8snetprep

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
)

// K8N-2, the guard and the proof. The rule check reads NAT and mangle rules.
// Cilium can masquerade in eBPF, where there is no rule to read, so on a
// Cilium node a passing rule check says nothing about that masquerade (seen on
// a real node: docs/K8N-2-cilium.md, "Live capture"). A node that shows Cilium
// is therefore ready only when Cilium's own report, read by the host-posture
// manager, proves that its masquerade cannot rewrite tunnel traffic:
//
//   - the agent does not masquerade IPv4, or
//   - it masquerades with iptables rules, which the rule check has just read
//     and accepted, or
//   - it masquerades in eBPF and the tunnel range lies inside its
//     native-routing range or inside one entry of its ip-masq-agent map.
//
// Without that report, or with one that is missing, stale, damaged or not
// understood, the node is refused, whatever mode Cilium is in.

// realLinkNames lists the names of the network devices in this process's
// network namespace (the host's). It reads only, and needs no privilege.
func realLinkNames() ([]string, error) {
	links, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(links))
	for _, link := range links {
		names = append(names, link.Name)
	}
	return names, nil
}

// detectCilium says whether the node shows a trace of Cilium and names the
// first one found. It fails when it cannot tell. Two signals are read:
//
//   - the names of the node's network devices (cilium_host, cilium_net, ...);
//   - the names of every IPv4 iptables chain in the listing the rule check has
//     already read (CILIUM_POST_nat, CILIUM_POST_mangle, ...).
//
// Cilium's pinned maps are not read here: the gateway container does not see
// the host's /sys/fs/bpf. The device names cover a Cilium that was told to
// install no iptables rules.
func (r *Reconciler) detectCilium(snapshot *cniSnapshot) (string, error) {
	if snapshot == nil {
		return "", errors.New("Cilium detection has no rule listing to read")
	}
	list := r.listLinks
	if list == nil {
		list = realLinkNames
	}
	links, err := list()
	if err != nil {
		return "", fmt.Errorf("Cilium detection could not list network devices: %w", err)
	}
	if len(links) == 0 {
		// Every network namespace has at least the loopback device.
		return "", errors.New("Cilium detection listed no network devices")
	}
	var chains []string
	for _, chain := range snapshot.chains {
		if chain.Family == "ip" {
			chains = append(chains, chain.Name)
		}
	}
	sort.Strings(links)
	sort.Strings(chains)
	for _, name := range links {
		if ciliumPresent([]string{name}, nil, nil) {
			return "network device " + bounded(name, 32), nil
		}
	}
	for _, name := range chains {
		if ciliumPresent(nil, []string{name}, nil) {
			return "iptables chain " + bounded(name, 32), nil
		}
	}
	return "", nil
}

// proveCilium runs after the rule check has passed. On a node without Cilium
// it returns nothing. On a node that shows Cilium it returns the ready
// cilium_masquerade adapter, or the refusal. It reads the manager's facts once
// and writes nothing.
//
// A node shows Cilium when this process sees a trace of it, or when the
// manager's receipt carries a `cilium` section: the manager sees the agent's
// socket and pinned maps, which the gateway does not (K8N review, finding 6).
// With a facts source the receipt is therefore read on every observation, and
// one that cannot be read refuses the node, Cilium or not.
func (r *Reconciler) proveCilium(ctx context.Context, snapshot *cniSnapshot, tunnel netip.Prefix) (*ComponentStatus, error) {
	found, err := r.detectCilium(snapshot)
	if err != nil {
		return nil, err
	}
	if found == "" && r.ciliumFacts == nil {
		return nil, nil
	}
	var reason string
	if found == "" {
		if err := operationContextErr(ctx); err != nil {
			return nil, err
		}
		facts, factsErr := r.ciliumFacts(ctx)
		if factsErr != nil {
			return nil, fmt.Errorf("could not tell whether the host-posture manager saw Cilium: %s", bounded(factsErr.Error(), 120))
		}
		if facts == nil {
			return nil, nil
		}
		found = "a cilium section in the host-posture receipt"
		reason, err = decideCiliumMasquerade(facts, tunnel)
	} else {
		reason, err = r.decideCilium(ctx, tunnel)
	}
	if err != nil {
		if errors.Is(err, errCiliumNotVerified) {
			// Say what made this a Cilium node, when there is room for it.
			if withTrace := fmt.Sprintf("%s (found %s)", err, found); len(withTrace) <= maxReasonBytes {
				return nil, fmt.Errorf("%w (found %s)", err, found)
			}
		}
		return nil, err
	}
	return &ComponentStatus{Name: CiliumAdapterName, State: StateReady, Reason: reason}, nil
}

func (r *Reconciler) decideCilium(ctx context.Context, tunnel netip.Prefix) (string, error) {
	if r.ciliumFacts == nil {
		return "", ciliumNotVerified("no host-posture facts source is configured")
	}
	if err := operationContextErr(ctx); err != nil {
		return "", err
	}
	facts, err := r.ciliumFacts(ctx)
	if err != nil {
		return "", ciliumNotVerified(err.Error())
	}
	if err := operationContextErr(ctx); err != nil {
		return "", err
	}
	return decideCiliumMasquerade(facts, tunnel)
}
