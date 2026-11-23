//go:build linux

package k8snetprep

import (
	"encoding/json"
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

// With eBPF masquerade Cilium's NAT and mangle chains are empty, so the rule
// check has nothing to refuse and reports the node ready as observed_cni, for
// any tunnel range. On the configuration A node that is exactly the case the
// paper calls the false "ready": a pod's packet to 100.96.0.5 was seen leaving
// wg0 rewritten to the node's address. Only the Cilium proof refuses it, so
// the guard that makes that proof mandatory on a Cilium node must be wired
// before a Cilium node may be reported ready.
func TestCiliumLiveBPFNodePassesTheRuleCheckAndIsRefusedOnlyByTheCiliumProof(t *testing.T) {
	_, r := liveCiliumKernel(t, ciliumLiveA)
	status, err := r.Reconcile(t.Context(), "100.96.0.0/24")
	if err != nil {
		t.Fatalf("rule check on the real eBPF node: %v", err)
	}
	if adapter := status.Adapters[0]; adapter.Name != ObservedAdapterName || adapter.State != StateReady {
		t.Fatalf("adapter = %+v", adapter)
	}
	masq, err := parseCiliumStatus(ciliumLiveFile(t, "healthz.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := proveCiliumNoTunnelMasquerade(ciliumObservation{Masquerade: masq}, netip.MustParsePrefix("100.96.0.0/24")); err == nil {
		t.Fatal("the Cilium proof accepted the node as well")
	}
	// The detection the guard will use sees this node from its NAT chains.
	s, err := parseCNISnapshot(string(ciliumLiveFile(t, "nft-ruleset.json")))
	if err != nil {
		t.Fatal(err)
	}
	chains, _ := s.observedNATInput()
	if !ciliumPresent(nil, sortedNames(chains), nil) {
		t.Fatal("Cilium not detected from the NAT chains the rule check already reads")
	}
}

// Configuration C, iptables masquerade. The real CILIUM_POST_nat holds:
//
//	-s 10.244.0.0/24 -m set --match-set cilium_node_set_v4 dst -j ACCEPT
//	-s 10.244.0.0/24 ! -d 10.244.0.0/16 ! -o cilium_+ -j MASQUERADE
//	-m mark --mark 0xa00/0xe00 -j ACCEPT
//	-s 127.0.0.1/32 -o cilium_host -j SNAT
//	-o cilium_host -m mark --mark 0xf00/0xf00 -m conntrack --ctstate DNAT -j SNAT
//
// The walk accepts it: the masquerade is limited to the node's pod range as
// its source (the exception it also grants Flannel), and both SNAT rules are
// bound to the exact output interface cilium_host.
func TestCiliumLiveIPTablesNodeIsAcceptedByTheRuleWalk(t *testing.T) {
	f, r := liveCiliumKernel(t, ciliumLiveC)
	status, err := r.Reconcile(t.Context(), "100.96.0.0/24")
	if err != nil {
		t.Fatalf("real iptables-mode node was refused: %+v %v", status, err)
	}
	if adapter := status.Adapters[0]; adapter.Name != ObservedAdapterName || adapter.State != StateReady || adapter.Reason != ReasonObservedNoTunnelSourceNAT {
		t.Fatalf("adapter = %+v", adapter)
	}
	if len(f.mutations) != 0 || len(f.setReads) != 0 {
		t.Fatalf("mutations %v, set reads %v", f.mutations, f.setReads)
	}
}

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
