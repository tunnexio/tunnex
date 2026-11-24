//go:build linux

package k8snetprep

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
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
//     native-routing range or inside one entry of its ip-masq-agent map;
//
// and, in every case, the agent reports Legacy host routing, so traffic
// between pods and the tunnel passes Tunnex's forward chain (K8N-6).
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
	found, _, err := r.detectCiliumWithLinks(snapshot)
	return found, err
}

// detectCiliumWithLinks is detectCilium that also returns the device names it
// read, sorted, so that the eBPF dataplane guard reads the same list.
func (r *Reconciler) detectCiliumWithLinks(snapshot *cniSnapshot) (string, []string, error) {
	if snapshot == nil {
		return "", nil, errors.New("Cilium detection has no rule listing to read")
	}
	list := r.listLinks
	if list == nil {
		list = realLinkNames
	}
	links, err := list()
	if err != nil {
		return "", nil, fmt.Errorf("Cilium detection could not list network devices: %w", err)
	}
	if len(links) == 0 {
		// Every network namespace has at least the loopback device.
		return "", nil, errors.New("Cilium detection listed no network devices")
	}
	var chains []string
	for _, chain := range snapshot.chains {
		if chain.Family == "ip" {
			chains = append(chains, chain.Name)
		}
	}
	links = append([]string(nil), links...)
	sort.Strings(links)
	sort.Strings(chains)
	for _, name := range links {
		if ciliumPresent([]string{name}, nil, nil) {
			return "network device " + bounded(name, 32), links, nil
		}
	}
	for _, name := range chains {
		if ciliumPresent(nil, []string{name}, nil) {
			return "iptables chain " + bounded(name, 32), links, nil
		}
	}
	return "", links, nil
}

// Calico's eBPF dataplane, like Cilium's BPF host routing, runs its own
// programs on the node's devices and pods, and Tunnex has no proof that they
// leave traffic between pods and the tunnel to its forward chain. It was refused before only because Felix in BPF mode
// keeps a mark-matched MASQUERADE in cali-POSTROUTING ("BPF loopback SNAT")
// that the NAT walk cannot prove. That refusal is an accident of a rule; this
// one is on purpose. Two signals, both read from what the gateway already has
// (Calico v3.31.2 source, felix):
//
//   - the network devices bpfin.cali and bpfout.cali
//     (dataplane/linux/dataplanedefs), which Felix creates in BPF mode unless
//     host-networked NAT is off (the default, connect-time load balancing for
//     TCP only, leaves it on);
//   - the raw-table chains cali-untracked-policy and cali-untracked-flows,
//     which Felix renders only in BPF mode (rules/static.go,
//     StaticBPFModeRawChains; dataplane/linux/int_dataplane.go,
//     setUpIptablesBPF). The name is matched inside a longer one too, in case
//     a backend prefixes it.
//
// The captured Calico node (iptables dataplane) shows neither.
var (
	calicoEBPFDevices = []string{"bpfin.cali", "bpfout.cali"}
	calicoEBPFChains  = []string{"cali-untracked-policy", "cali-untracked-flows"}
)

// ReasonCalicoEBPF starts the refusal of a node that runs Calico's eBPF
// dataplane.
const ReasonCalicoEBPF = "Calico's eBPF dataplane runs on this node and is not supported: Tunnex cannot prove that its programs leave tunnel traffic to Tunnex's access rules. Use Calico's iptables dataplane"

// detectCalicoEBPF names the first signal of Calico's eBPF dataplane among the
// sorted device names and the listing's chains, or returns "".
func detectCalicoEBPF(links []string, snapshot *cniSnapshot) string {
	for _, name := range links {
		for _, device := range calicoEBPFDevices {
			if name == device {
				return "network device " + name
			}
		}
	}
	if snapshot == nil {
		return ""
	}
	var chains []string
	for _, chain := range snapshot.chains {
		chains = append(chains, chain.Name)
	}
	sort.Strings(chains)
	for _, name := range chains {
		for _, marker := range calicoEBPFChains {
			if strings.Contains(name, marker) {
				return "chain " + bounded(name, 48)
			}
		}
	}
	return ""
}

// proveCilium runs after the rule check has passed. It first refuses a node
// that runs Calico's eBPF dataplane (detectCalicoEBPF). On a node without
// Cilium it then returns nothing. On a node that shows Cilium it returns the ready
// cilium_masquerade adapter, or the refusal. It reads the manager's facts once
// and writes nothing.
//
// A node shows Cilium when this process sees a trace of it, or when the
// manager's receipt carries a `cilium` section: the manager sees the agent's
// socket and pinned maps, which the gateway does not (K8N review, finding 6).
// With a facts source the receipt is therefore read on every observation, and
// one that cannot be read refuses the node, Cilium or not.
func (r *Reconciler) proveCilium(ctx context.Context, snapshot *cniSnapshot, tunnel netip.Prefix) (*ComponentStatus, error) {
	found, links, err := r.detectCiliumWithLinks(snapshot)
	if err != nil {
		return nil, err
	}
	// Calico's eBPF dataplane is refused on every node, Cilium or not, before
	// anything else is read.
	if calico := detectCalicoEBPF(links, snapshot); calico != "" {
		return nil, fmt.Errorf("%s (found %s)", ReasonCalicoEBPF, calico)
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
