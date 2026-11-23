//go:build linux

package k8snetprep

import (
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

// Today's rule check (hook coverage, mangle mark proof, NAT rule walk) on the
// captured Cilium 1.20.5 nodes; cilium_live_test.go says what the captures are.

func liveCiliumKernel(t *testing.T, prefix string) (*calicoTestKernel, *Reconciler) {
	t.Helper()
	f := &calicoTestKernel{
		awsTestKernel: &awsTestKernel{
			save:       string(ciliumLiveRead(t, prefix+"iptables-nft-save-nat.txt")),
			saveMangle: string(ciliumLiveRead(t, prefix+"iptables-nft-save-mangle.txt")),
			version:    "iptables-nft-save v1.8.13 (nf_tables)",
			next:       1 << 20,
		},
		sets: map[string]string{},
	}
	if err := json.Unmarshal(ciliumLiveRead(t, prefix+"nft-ruleset.json"), &f.doc); err != nil {
		t.Fatal(err)
	}
	r := awsTestReconciler(t, f.awsTestKernel, ScopeIPMasqAndAWS)
	r.runIPSet = f.ipset
	return f, r
}

// The rule check alone (hook coverage, mangle mark proof, NAT rule walk)
// passes on all three real nodes: with eBPF masquerade Cilium's NAT and mangle
// chains are empty, and in iptables mode the walk accepts the real rules (the
// masquerade is limited to the node's pod range as its source, the exception
// it also grants Flannel, and both SNAT rules are bound to the exact output
// interface cilium_host). On the configuration A node that pass is false: a
// pod's packet to 100.96.0.5 was seen leaving wg0 rewritten to the node's
// address.
func TestCiliumLiveNodesPassTheRuleCheckAlone(t *testing.T) {
	for _, prefix := range []string{ciliumLiveA, ciliumLiveB, ciliumLiveC} {
		s, err := parseCNISnapshot(string(ciliumLiveRead(t, prefix+"nft-ruleset.json")))
		if err != nil {
			t.Fatal(err)
		}
		if err := s.validateHookCoverage("wg0", "100.96.0.0/24"); err != nil {
			t.Errorf("%s: %v", prefix, err)
		}
	}
}

// So the guard refuses every node that shows Cilium, in every mode, until the
// gateway can read Cilium's own report. The whole reconcile on each real
// capture is refused with that reason, names what it found, reports no ready
// adapter and writes nothing. The test container has no Cilium device, so the
// chains in the capture carry the detection here.
func TestCiliumLiveNodesAreRefusedByTheGuard(t *testing.T) {
	for _, prefix := range []string{ciliumLiveA, ciliumLiveB, ciliumLiveC} {
		for _, tunnel := range []string{"100.96.0.0/24", "10.244.200.0/24"} {
			f, r := liveCiliumKernel(t, prefix)
			status, err := r.Reconcile(t.Context(), tunnel)
			if !errors.Is(err, errCiliumNotVerified) {
				t.Fatalf("%s %s: %+v %v", prefix, tunnel, status, err)
			}
			if !strings.HasPrefix(err.Error(), ReasonCiliumNotVerified) || !strings.Contains(err.Error(), "found iptables chain CILIUM_") {
				t.Errorf("%s: reason %q", prefix, err)
			}
			if len(err.Error()) > maxReasonBytes {
				t.Errorf("reason is %d bytes", len(err.Error()))
			}
			if status.Host.State != StateBlocked || status.Host.Reason != err.Error() {
				t.Errorf("%s: host = %+v", prefix, status.Host)
			}
			for _, adapter := range status.Adapters {
				if adapter.State != StateBlocked || adapter.Name == ObservedAdapterName {
					t.Errorf("%s: adapter = %+v", prefix, adapter)
				}
			}
			if len(f.mutations) != 0 {
				t.Errorf("%s: refusal mutated: %v", prefix, f.mutations)
			}
		}
	}
}

// The real device names alone are enough: a Cilium told to install no iptables
// rules leaves no chain, but its devices remain.
func TestCiliumGuardDetectsDevicesWithoutChains(t *testing.T) {
	var links []string
	for _, name := range strings.Fields(string(ciliumLiveRead(t, ciliumLiveA+"links.txt"))) {
		name, _, _ = strings.Cut(name, "@")
		links = append(links, name)
	}
	_, r := liveFlannelKernel(t)
	r.listLinks = func() ([]string, error) { return links, nil }
	status, err := r.Reconcile(t.Context(), "100.96.0.0/24")
	if !errors.Is(err, errCiliumNotVerified) || !strings.Contains(err.Error(), "found network device cilium_host") {
		t.Fatalf("%+v %v", status, err)
	}
}

// A node with no Cilium signal is unaffected, and a node whose devices cannot
// be listed is not assumed free of Cilium.
func TestCiliumGuardWithoutCilium(t *testing.T) {
	f, r := liveFlannelKernel(t)
	r.listLinks = func() ([]string, error) { return []string{"lo", "eth0", "flannel.1", "cni0", "wg0"}, nil }
	status, err := r.Reconcile(t.Context(), "100.96.0.0/24")
	if err != nil || status.Adapters[0].Name != ObservedAdapterName || status.Adapters[0].State != StateReady {
		t.Fatalf("node without Cilium: %+v %v", status, err)
	}
	if len(f.mutations) != 0 {
		t.Fatalf("mutations: %v", f.mutations)
	}
	// Names that merely contain the word are not Cilium's.
	r.listLinks = func() ([]string, error) { return []string{"lo", "mycilium_0", "Cilium_host"}, nil }
	if _, err := r.Reconcile(t.Context(), "100.96.0.0/24"); err != nil {
		t.Fatalf("unrelated device names refused: %v", err)
	}
	for name, list := range map[string]func() ([]string, error){
		"error": func() ([]string, error) { return nil, errors.New("netlink: permission denied") },
		"empty": func() ([]string, error) { return nil, nil },
	} {
		_, r := liveFlannelKernel(t)
		r.listLinks = list
		status, err := r.Reconcile(t.Context(), "100.96.0.0/24")
		if err == nil || errors.Is(err, errCiliumNotVerified) || !strings.Contains(err.Error(), "Cilium detection") {
			t.Errorf("%s: %+v %v", name, status, err)
		}
		for _, adapter := range status.Adapters {
			if adapter.State == StateReady {
				t.Errorf("%s: ready adapter %+v", name, adapter)
			}
		}
	}
	if err := (&Reconciler{}).refuseCilium(nil); err == nil {
		t.Error("no listing accepted")
	}
	// The real device list of the test host is readable and shows no Cilium.
	if links, err := realLinkNames(); err != nil || len(links) == 0 || ciliumPresent(links, nil, nil) {
		t.Errorf("real devices: %v %v", links, err)
	}
}

func liveFlannelKernel(t *testing.T) (*calicoTestKernel, *Reconciler) {
	t.Helper()
	f := &calicoTestKernel{awsTestKernel: &awsTestKernel{version: "iptables-nft-save v1.8.13 (nf_tables)", next: 1 << 20}, sets: map[string]string{}}
	if err := json.Unmarshal(ciliumLiveRead(t, "testdata/k3s-flannel-nat.json"), &f.doc); err != nil {
		t.Fatal(err)
	}
	r := awsTestReconciler(t, f.awsTestKernel, ScopeIPMasqAndAWS)
	r.runIPSet = f.ipset
	return f, r
}

// Configuration C, iptables masquerade. The real CILIUM_POST_nat holds:
//
//	-s 10.244.0.0/24 -m set --match-set cilium_node_set_v4 dst -j ACCEPT
//	-s 10.244.0.0/24 ! -d 10.244.0.0/16 ! -o cilium_+ -j MASQUERADE
//	-m mark --mark 0xa00/0xe00 -j ACCEPT
//	-s 127.0.0.1/32 -o cilium_host -j SNAT
//	-o cilium_host -m mark --mark 0xf00/0xf00 -m conntrack --ctstate DNAT -j SNAT
//
// What the walk refuses on it, for when the guard gives way to the reader.
func TestCiliumLiveIPTablesNodeRefusals(t *testing.T) {
	s, err := parseCNISnapshot(string(ciliumLiveRead(t, ciliumLiveC+"nft-ruleset.json")))
	if err != nil {
		t.Fatal(err)
	}
	chains, rules := s.observedNATInput()
	walk := func(tunnel, egress string) error {
		_, err := proveNoTunnelSourceNATWithSets(chains, rules, "POSTROUTING", netip.MustParsePrefix(tunnel), egress, observedHandledChains, nil)
		return err
	}
	if err := walk("100.96.0.0/24", "wg0"); err != nil {
		t.Fatalf("accepted case: %v", err)
	}
	// A tunnel range inside 10.244.0.0/16 is excluded by the rule's own
	// `! -d 10.244.0.0/16`, even when it is the node's pod range.
	for _, tunnel := range []string{"10.244.0.0/24", "10.244.200.0/24"} {
		if err := walk(tunnel, "wg0"); err != nil {
			t.Errorf("%s: %v", tunnel, err)
		}
	}
	// A wider range that contains the node's pod range and reaches outside
	// 10.244.0.0/16: neither the source limit nor the destination excludes it.
	for _, tunnel := range []string{"10.0.0.0/8", "10.240.0.0/12"} {
		if err := walk(tunnel, "wg0"); err == nil || !strings.Contains(err.Error(), "CILIUM_POST_nat") {
			t.Errorf("%s: %v", tunnel, err)
		}
	}
	// The two SNAT rules are excused only by their output interface.
	for _, egress := range []string{"", "cilium_host"} {
		if err := walk("100.96.0.0/24", egress); err == nil || !strings.Contains(err.Error(), "CILIUM_POST_nat") {
			t.Errorf("egress %q: %v", egress, err)
		}
	}
}
