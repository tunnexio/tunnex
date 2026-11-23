//go:build linux

package k8snetprep

import (
	"errors"
	"fmt"
	"net"
	"sort"
)

// K8N-2, the guard. The rule check reads NAT and mangle rules. Cilium can
// masquerade in eBPF, where there is no rule to read, so on a Cilium node a
// passing rule check says nothing about that masquerade (seen on a real node:
// docs/K8N-2-cilium.md, "Live capture"). Until the gateway is given Cilium's
// own report and can run proveCiliumNoTunnelMasquerade, a node that shows
// Cilium is refused, whatever mode Cilium is in.

// ReasonCiliumNotVerified starts the refusal of a node that shows Cilium.
const ReasonCiliumNotVerified = "Cilium runs on this node and its eBPF masquerade cannot be verified yet (K8N-2); the gateway is not ready on Cilium nodes"

// errCiliumNotVerified lets callers and tests tell this refusal from others.
var errCiliumNotVerified = errors.New(ReasonCiliumNotVerified)

// realLinkNames lists the names of the network devices in the gateway's
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

// refuseCilium returns an error when the node shows a trace of Cilium, and
// also when it cannot tell. Two signals are read:
//
//   - the names of the node's network devices (cilium_host, cilium_net, ...);
//   - the names of every IPv4 iptables chain in the listing the rule check has
//     already read (CILIUM_POST_nat, CILIUM_POST_mangle, ...).
//
// Cilium's pinned maps are not read: the gateway container does not see the
// host's /sys/fs/bpf. The device names cover a Cilium that was told to install
// no iptables rules.
func (r *Reconciler) refuseCilium(snapshot *cniSnapshot) error {
	if snapshot == nil {
		return errors.New("Cilium detection has no rule listing to read")
	}
	list := r.listLinks
	if list == nil {
		list = realLinkNames
	}
	links, err := list()
	if err != nil {
		return fmt.Errorf("Cilium detection could not list network devices: %w", err)
	}
	if len(links) == 0 {
		// Every network namespace has at least the loopback device.
		return errors.New("Cilium detection listed no network devices")
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
			return fmt.Errorf("%w (found network device %s)", errCiliumNotVerified, bounded(name, 32))
		}
	}
	for _, name := range chains {
		if ciliumPresent(nil, []string{name}, nil) {
			return fmt.Errorf("%w (found iptables chain %s)", errCiliumNotVerified, bounded(name, 32))
		}
	}
	return nil
}
