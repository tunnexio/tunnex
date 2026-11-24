//go:build linux

package k8snetprep

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"
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

// constantCiliumFacts is a facts source that always has the same section, and
// counts how often the reconciler asked for it.
func constantCiliumFacts(facts *CiliumFacts, calls *int) CiliumFactsSource {
	return func(context.Context) (*CiliumFacts, error) {
		if calls != nil {
			*calls++
		}
		return facts, nil
	}
}

func wantCiliumRefusal(t *testing.T, name string, f *calicoTestKernel, status ReconcileStatus, err error, want string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("%s: status %+v, error %v, want %q", name, status, err, want)
	}
	if status.Host.State != StateBlocked || status.Host.Reason != bounded(err.Error(), maxReasonBytes) {
		t.Errorf("%s: host = %+v", name, status.Host)
	}
	for _, adapter := range status.Adapters {
		if adapter.State != StateBlocked || adapter.Name == ObservedAdapterName || adapter.Name == CiliumAdapterName {
			t.Errorf("%s: adapter = %+v", name, adapter)
		}
	}
	if len(f.mutations) != 0 {
		t.Errorf("%s: refusal mutated: %v", name, f.mutations)
	}
}

// The whole reconcile on the real captures, with the section the manager
// would publish for each. The test container has no Cilium device, so the
// chains in the capture carry the detection here.
//
//	A  eBPF masquerade, ip-masq-agent off: refused, and the customer is told
//	   what to add; ready only for a range inside the native-routing range.
//	B  eBPF masquerade, the range in the ip-masq-agent map: ready, proved by
//	   the map entry.
//	B, then the ip-masq-agent turned off: refused again.
//	C  iptables masquerade: the rule walk decides, and it accepts the real
//	   rules.
func TestCiliumLiveNodesReconcileOnTheManagersFacts(t *testing.T) {
	for name, tc := range map[string]struct {
		prefix string
		facts  *CiliumFacts
		tunnel string
		// reason is the ready cilium_masquerade reason; refuse is the refusal.
		reason string
		refuse string
	}{
		"A":                   {prefix: ciliumLiveA, facts: ciliumFactsA(t), tunnel: "100.96.0.0/24", refuse: ciliumWantEnable},
		"A, native routing":   {prefix: ciliumLiveA, facts: ciliumFactsA(t), tunnel: "10.244.200.0/24", reason: "tunnel range is inside Cilium's native-routing range 10.244.0.0/16"},
		"B":                   {prefix: ciliumLiveB, facts: ciliumFactsB(t), tunnel: "100.96.0.0/24", reason: "tunnel range is inside Cilium ip-masq-agent range 100.96.0.0/24"},
		"B, range not listed": {prefix: ciliumLiveB, facts: ciliumFactsB(t), tunnel: "100.96.1.0/24", refuse: ciliumWantAdd},
		// Review finding 1: with the ip-masq-agent on the reported range is no proof.
		"B, reported range only": {prefix: ciliumLiveB, facts: ciliumFactsB(t), tunnel: "10.244.200.0/24", refuse: ciliumWantList},
		"B then off":             {prefix: ciliumLiveA, facts: ciliumFactsBThenOff(t), tunnel: "100.96.0.0/24", refuse: ciliumWantEnable},
		"C":                      {prefix: ciliumLiveC, facts: ciliumFactsC(t), tunnel: "100.96.0.0/24", reason: ReasonCiliumIPTablesMasquerade},
		"C, inside pod routing":  {prefix: ciliumLiveC, facts: ciliumFactsC(t), tunnel: "10.244.200.0/24", reason: ReasonCiliumIPTablesMasquerade},
	} {
		f, r := liveCiliumKernel(t, tc.prefix)
		calls := 0
		r.UseCiliumFacts(constantCiliumFacts(tc.facts, &calls))
		status, err := r.Reconcile(t.Context(), tc.tunnel)
		if calls != 1 {
			t.Errorf("%s: the facts were taken %d times", name, calls)
		}
		if tc.refuse != "" {
			wantCiliumRefusal(t, name, f, status, err, tc.refuse)
			if err.Error() != tc.refuse || !errors.Is(err, errCiliumTunnelMasqueraded) {
				t.Errorf("%s: refusal = %q", name, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %+v %v", name, status, err)
			continue
		}
		want := []ComponentStatus{
			{Name: ObservedAdapterName, State: StateReady, Reason: ReasonObservedNoTunnelSourceNAT},
			{Name: CiliumAdapterName, State: StateReady, Reason: tc.reason},
			{Name: ipMasqAdapterName, State: StateNotApplicable, Reason: "exact chain absent"},
			{Name: awsAdapterName, State: StateNotApplicable, Reason: "exact chain absent"},
		}
		if status.Host.State != StateReady || !reflect.DeepEqual(status.Adapters, want) {
			t.Errorf("%s: status = %+v", name, status)
		}
		if len(f.mutations) != 0 {
			t.Errorf("%s: mutations: %v", name, f.mutations)
		}
	}
}

// Review finding 1, on the whole reconcile. The captured B node runs eBPF
// masquerade with the ip-masq-agent on and reports the native-routing range
// 10.244.0.0/16. A tunnel range inside that range is not ready on the report:
// with the ip-masq-agent on, Cilium applies the range only when it was set
// explicitly, and the report reads the same when it was not (the node's pod
// range, or a range the IPAM detected, which the program then does not
// exclude). The gateway is ready only once an entry of the live map contains
// the tunnel range, and it writes nothing while refused.
func TestCiliumLiveNodeWithIPMasqAgentOnIsNotReadyOnTheReportedRange(t *testing.T) {
	const tunnel = "10.244.200.0/24"
	f, r := liveCiliumKernel(t, ciliumLiveB)
	r.UseCiliumFacts(constantCiliumFacts(ciliumFactsB(t), nil))
	status, err := r.Reconcile(t.Context(), tunnel)
	wantCiliumRefusal(t, "reported range only", f, status, err, ciliumWantList)
	if err.Error() != ciliumWantList || !errors.Is(err, errCiliumTunnelMasqueraded) || errors.Is(err, errCiliumNotVerified) {
		t.Fatalf("refusal = %q", err)
	}
	if len(status.Host.Reason) > maxReasonBytes || status.Host.Reason != ciliumWantList {
		t.Fatalf("the customer does not read the whole instruction: %q", status.Host.Reason)
	}

	// The same rules and the same range with the ip-masq-agent off: there the
	// reported range is what the program was compiled with.
	f, r = liveCiliumKernel(t, ciliumLiveB)
	r.UseCiliumFacts(constantCiliumFacts(ciliumFactsA(t), nil))
	status, err = r.Reconcile(t.Context(), tunnel)
	if err != nil || len(status.Adapters) < 2 || status.Adapters[1] != (ComponentStatus{Name: CiliumAdapterName, State: StateReady, Reason: "tunnel range is inside Cilium's native-routing range 10.244.0.0/16"}) {
		t.Fatalf("ip-masq-agent off: %+v %v", status, err)
	}

	// The customer follows the instruction: the range is in the live map.
	listed := ciliumFactsB(t)
	listed.IPMasqMap.Text = string(ciliumIPMasqDump("100.96.0.0/24", tunnel))
	f, r = liveCiliumKernel(t, ciliumLiveB)
	r.UseCiliumFacts(constantCiliumFacts(listed, nil))
	status, err = r.Reconcile(t.Context(), tunnel)
	if err != nil || len(status.Adapters) < 2 || status.Adapters[1] != (ComponentStatus{Name: CiliumAdapterName, State: StateReady, Reason: "tunnel range is inside Cilium ip-masq-agent range " + tunnel}) {
		t.Fatalf("range listed: %+v %v", status, err)
	}
	if len(f.mutations) != 0 {
		t.Fatalf("mutations: %v", f.mutations)
	}
}

// In iptables mode the Cilium proof only says who decides. A tunnel range the
// walk refuses stays refused by the walk, naming Cilium's chain, and the
// manager's facts are not even asked for.
func TestCiliumLiveIPTablesNodeIsRefusedByTheWalkNotByTheFacts(t *testing.T) {
	for _, tunnel := range []string{"10.0.0.0/8", "10.240.0.0/12"} {
		f, r := liveCiliumKernel(t, ciliumLiveC)
		calls := 0
		r.UseCiliumFacts(constantCiliumFacts(ciliumFactsC(t), &calls))
		status, err := r.Reconcile(t.Context(), tunnel)
		wantCiliumRefusal(t, tunnel, f, status, err, "CILIUM_POST_nat")
		if errors.Is(err, errCiliumNotVerified) || errors.Is(err, errCiliumTunnelMasqueraded) || calls != 0 {
			t.Errorf("%s: %v, facts taken %d times", tunnel, err, calls)
		}
	}
	// The same node reported as eBPF mode would need the eBPF proof: the mode
	// comes from the agent, never from the look of the rules.
	f, r := liveCiliumKernel(t, ciliumLiveC)
	r.UseCiliumFacts(constantCiliumFacts(ciliumFactsA(t), nil))
	status, err := r.Reconcile(t.Context(), "100.96.0.0/24")
	wantCiliumRefusal(t, "C rules, eBPF report", f, status, err, ciliumWantEnable)
}

// A node that shows Cilium is refused whenever the reader's section is not
// there to decide on: no source, no receipt, a receipt without the section, or
// a section that says the agent could not be read. All modes, both ranges.
func TestCiliumLiveNodesAreRefusedWithoutUsableFacts(t *testing.T) {
	unread := UnreadableCiliumFacts("/var/run/cilium is not mounted in the host-posture manager; set cilium.enabled=true on the tunnex-host-posture chart")
	for name, tc := range map[string]struct {
		source CiliumFactsSource
		want   string
	}{
		"no source": {want: "Cilium masquerade on this node is not verified: no host-posture facts source is configured (found iptables chain CILIUM_"},
		"no receipt": {
			source: func(context.Context) (*CiliumFacts, error) { return nil, errors.New("host facts receipt is missing") },
			want:   "Cilium masquerade on this node is not verified: host facts receipt is missing (found iptables chain CILIUM_",
		},
		"stale receipt": {
			source: func(context.Context) (*CiliumFacts, error) {
				return nil, errors.New("host facts receipt is stale or from the future")
			},
			want: "Cilium masquerade on this node is not verified: host facts receipt is stale or from the future (found iptables chain CILIUM_",
		},
		"receipt without the section": {
			source: constantCiliumFacts(nil, nil),
			want:   "Cilium masquerade on this node is not verified: the host-posture manager published no Cilium facts (found iptables chain CILIUM_",
		},
		"agent not readable": {
			source: constantCiliumFacts(unread, nil),
			want:   "Cilium masquerade on this node is not verified: the host-posture manager could not read the Cilium agent status: /var/run/cilium is not mounted in the host-posture manager; set cilium.enabled=true on the tunnex-host-posture chart",
		},
	} {
		for _, prefix := range []string{ciliumLiveA, ciliumLiveB, ciliumLiveC} {
			for _, tunnel := range []string{"100.96.0.0/24", "10.244.200.0/24"} {
				f, r := liveCiliumKernel(t, prefix)
				r.UseCiliumFacts(tc.source)
				status, err := r.Reconcile(t.Context(), tunnel)
				wantCiliumRefusal(t, name+" "+prefix, f, status, err, tc.want)
				if !errors.Is(err, errCiliumNotVerified) || !strings.HasPrefix(err.Error(), ReasonCiliumNotVerified+": ") {
					t.Errorf("%s: %v", name, err)
				}
				if len(status.Host.Reason) > maxReasonBytes {
					t.Errorf("%s: reason is %d bytes", name, len(status.Host.Reason))
				}
			}
		}
	}
}

// The real device names alone are enough: a Cilium told to install no iptables
// rules leaves no chain, but its devices remain. Such a node needs the same
// proof.
func TestCiliumGuardDetectsDevicesWithoutChains(t *testing.T) {
	var links []string
	for _, name := range strings.Fields(string(ciliumLiveRead(t, ciliumLiveA+"links.txt"))) {
		name, _, _ = strings.Cut(name, "@")
		links = append(links, name)
	}
	f, r := liveFlannelKernel(t)
	r.listLinks = func() ([]string, error) { return links, nil }
	status, err := r.Reconcile(t.Context(), "100.96.0.0/24")
	wantCiliumRefusal(t, "no source", f, status, err, "no host-posture facts source is configured (found network device cilium_host)")
	if !errors.Is(err, errCiliumNotVerified) {
		t.Fatalf("%v", err)
	}
	r.UseCiliumFacts(constantCiliumFacts(ciliumFactsA(t), nil))
	status, err = r.Reconcile(t.Context(), "100.96.0.0/24")
	wantCiliumRefusal(t, "A facts", f, status, err, ciliumWantEnable)
	r.UseCiliumFacts(constantCiliumFacts(ciliumFactsB(t), nil))
	status, err = r.Reconcile(t.Context(), "100.96.0.0/24")
	if err != nil || len(status.Adapters) < 2 || status.Adapters[1].Name != CiliumAdapterName || status.Adapters[1].State != StateReady {
		t.Fatalf("B facts: %+v %v", status, err)
	}
}

// A node with no Cilium signal on either side is unaffected: it reports no
// cilium_masquerade adapter. Its facts source is asked once per reconcile
// (K8N review, finding 6: the manager may have seen Cilium where the gateway
// cannot) and has no section for it. A node whose devices cannot be listed
// is not assumed free of Cilium.
func TestCiliumGuardWithoutCilium(t *testing.T) {
	f, r := liveFlannelKernel(t)
	calls := 0
	r.UseCiliumFacts(func(context.Context) (*CiliumFacts, error) {
		calls++
		return nil, nil
	})
	r.listLinks = func() ([]string, error) { return []string{"lo", "eth0", "flannel.1", "cni0", "wg0"}, nil }
	status, err := r.Reconcile(t.Context(), "100.96.0.0/24")
	if err != nil || status.Adapters[0].Name != ObservedAdapterName || status.Adapters[0].State != StateReady {
		t.Fatalf("node without Cilium: %+v %v", status, err)
	}
	for _, adapter := range status.Adapters {
		if adapter.Name == CiliumAdapterName {
			t.Fatalf("a node without Cilium reports %+v", adapter)
		}
	}
	if len(f.mutations) != 0 || calls != 1 {
		t.Fatalf("mutations: %v, facts taken %d times", f.mutations, calls)
	}
	// Names that merely contain the word are not Cilium's.
	r.listLinks = func() ([]string, error) { return []string{"lo", "mycilium_0", "Cilium_host"}, nil }
	if _, err := r.Reconcile(t.Context(), "100.96.0.0/24"); err != nil || calls != 2 {
		t.Fatalf("unrelated device names refused: %v", err)
	}
	for name, list := range map[string]func() ([]string, error){
		"error": func() ([]string, error) { return nil, errors.New("netlink: permission denied") },
		"empty": func() ([]string, error) { return nil, nil },
	} {
		_, r := liveFlannelKernel(t)
		r.UseCiliumFacts(constantCiliumFacts(ciliumFactsB(t), nil))
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
	if _, err := (&Reconciler{}).detectCilium(nil); err == nil {
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
// What the walk refuses on it.
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

// Review finding 6. The gateway sees neither a cilium_ device nor a CILIUM_
// chain (Cilium told to install no rules, devices it does not name so), but
// the manager saw the agent's socket and pinned maps and published a `cilium`
// section. Before the fix the gateway never asked and the node was ready on
// the rule walk alone; now the section is decided as on any Cilium node.
func TestGatewayRunsTheCiliumDecisionOnAReceiptSectionAlone(t *testing.T) {
	const tunnel = "100.96.0.0/24"
	noTrace := func() ([]string, error) { return []string{"lo", "eth0", "wg0"}, nil }

	f, r := liveFlannelKernel(t)
	r.listLinks = noTrace
	r.UseCiliumFacts(constantCiliumFacts(ciliumFactsA(t), nil))
	status, err := r.Reconcile(t.Context(), tunnel)
	wantCiliumRefusal(t, "A section, no trace", f, status, err, ciliumWantEnable)

	_, r = liveFlannelKernel(t)
	r.listLinks = noTrace
	r.UseCiliumFacts(constantCiliumFacts(ciliumFactsB(t), nil))
	status, err = r.Reconcile(t.Context(), tunnel)
	if err != nil || len(status.Adapters) < 2 || status.Adapters[1].Name != CiliumAdapterName || status.Adapters[1].State != StateReady {
		t.Fatalf("B section, no trace: %+v %v", status, err)
	}

	// A section the manager could not read refuses, naming where Cilium was seen.
	f, r = liveFlannelKernel(t)
	r.listLinks = noTrace
	r.UseCiliumFacts(constantCiliumFacts(UnreadableCiliumFacts("Cilium agent status: dial unix: connection refused"), nil))
	status, err = r.Reconcile(t.Context(), tunnel)
	if err == nil || !strings.Contains(err.Error(), "found a cilium section in the host-posture receipt") {
		t.Fatalf("unreadable section: %+v %v", status, err)
	}

	// A receipt that cannot be taken: whether the manager saw Cilium is unknown.
	_, r = liveFlannelKernel(t)
	r.listLinks = noTrace
	r.UseCiliumFacts(func(context.Context) (*CiliumFacts, error) {
		return nil, errors.New("host facts receipt is stale or from the future")
	})
	if status, err := r.Reconcile(t.Context(), tunnel); err == nil || err.Error() != "could not tell whether the host-posture manager saw Cilium: host facts receipt is stale or from the future" {
		t.Fatalf("receipt not taken: %+v %v", status, err)
	}
}
