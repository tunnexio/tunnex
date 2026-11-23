package k8snetprep

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"testing"
)

// The `cilium` section of the host-facts receipt and the gateway's decision on
// it, on the captures of cilium_live_test.go. The section is built here by
// hand from the captured files; cilium_reader_linux_test.go shows that the
// real reader builds the same one.

func ciliumFactsFromCapture(t *testing.T, statusFile, pinsFile, dumpFile string) *CiliumFacts {
	t.Helper()
	status, err := reduceCiliumStatus(ciliumLiveRead(t, statusFile))
	if err != nil {
		t.Fatal(err)
	}
	facts := &CiliumFacts{Status: CiliumTextFact{State: FactsRead, Text: status}, PinnedMaps: CiliumPinFacts{State: FactsRead}}
	for _, name := range strings.Fields(string(ciliumLiveRead(t, pinsFile))) {
		facts.PinnedMaps.Total++
		if strings.HasPrefix(name, ciliumEgressGatewayPinPrefix) {
			facts.PinnedMaps.EgressGateway = append(facts.PinnedMaps.EgressGateway, name)
		}
	}
	sort.Strings(facts.PinnedMaps.EgressGateway)
	masq, err := parseCiliumStatus([]byte(status))
	if err != nil {
		t.Fatal(err)
	}
	if masq.IPMasqAgent {
		facts.IPMasqMap = CiliumTextFact{State: FactsRead, Text: strings.TrimSpace(string(ciliumLiveRead(t, dumpFile)))}
	} else {
		facts.IPMasqMap = CiliumTextFact{State: FactsNotNeeded, Reason: "the agent reports that its ip-masq-agent is off"}
	}
	if err := facts.Validate(); err != nil {
		t.Fatal(err)
	}
	return facts
}

func ciliumFactsA(t *testing.T) *CiliumFacts {
	return ciliumFactsFromCapture(t, ciliumLiveA+"healthz.json", ciliumLiveA+"pinned-maps.txt", "")
}

func ciliumFactsB(t *testing.T) *CiliumFacts {
	return ciliumFactsFromCapture(t, ciliumLiveB+"healthz.json", ciliumLiveB+"pinned-maps.txt", ciliumLiveB+"ipmasq-v4.bpftool.json")
}

// After the ip-masq-agent was turned off again and the agent restarted, the
// status was as in A and the pin was gone. Only the pin list of that state was
// captured.
func ciliumFactsBThenOff(t *testing.T) *CiliumFacts {
	return ciliumFactsFromCapture(t, ciliumLiveA+"healthz.json", "testdata/cilium-1.20.5-kind-B-then-ipmasq-off.pinned-maps.txt", "")
}

func ciliumFactsC(t *testing.T) *CiliumFacts {
	return ciliumFactsFromCapture(t, ciliumLiveC+"healthz.json", ciliumLiveC+"pinned-maps.txt", "")
}

// What the customer reads when the tunnel range is not excluded.
const (
	ciliumWantEnable = "Cilium eBPF masquerade would rewrite traffic to the tunnel range 100.96.0.0/24. Enable Cilium's ip-masq-agent (Helm ipMasqAgent.enabled=true) with 100.96.0.0/24 in nonMasqueradeCIDRs, then restart the Cilium agents"
	ciliumWantAdd    = "Cilium eBPF masquerade would rewrite traffic to the tunnel range 100.96.1.0/24. Add 100.96.1.0/24 to nonMasqueradeCIDRs in the ip-masq-agent ConfigMap (namespace kube-system, key config); no restart is needed, allow about a minute"
	// The ip-masq-agent is on and the range is only inside the range the agent
	// reports: the customer is told why that is not enough and what to add.
	ciliumWantList = "Cilium's ip-masq-agent is on: its reported native-routing range 10.244.0.0/16 does not prove 10.244.200.0/24 is not masqueraded. Add 10.244.200.0/24 to nonMasqueradeCIDRs in the ip-masq-agent ConfigMap (kube-system, key config)"
)

func TestCiliumFactsDecisionOnTheRealCaptures(t *testing.T) {
	for name, tc := range map[string]struct {
		facts  *CiliumFacts
		tunnel string
		reason string
		refuse string
	}{
		"A, range outside every exclusion": {facts: ciliumFactsA(t), tunnel: "100.96.0.0/24", refuse: ciliumWantEnable},
		"A, range inside native routing":   {facts: ciliumFactsA(t), tunnel: "10.244.200.0/24", reason: "tunnel range is inside Cilium's native-routing range 10.244.0.0/16"},
		"B, range listed":                  {facts: ciliumFactsB(t), tunnel: "100.96.0.0/24", reason: "tunnel range is inside Cilium ip-masq-agent range 100.96.0.0/24"},
		// Review finding 1: with the ip-masq-agent on, the reported range is
		// not a proof. (Before the fix this case was ready.)
		"B, range inside the reported native-routing range only": {facts: ciliumFactsB(t), tunnel: "10.244.200.0/24", refuse: ciliumWantList},
		"B, another range":    {facts: ciliumFactsB(t), tunnel: "100.96.1.0/24", refuse: ciliumWantAdd},
		"B then off":          {facts: ciliumFactsBThenOff(t), tunnel: "100.96.0.0/24", refuse: ciliumWantEnable},
		"C, the walk decides": {facts: ciliumFactsC(t), tunnel: "100.96.0.0/24", reason: ReasonCiliumIPTablesMasquerade},
	} {
		reason, err := decideCiliumMasquerade(tc.facts, netip.MustParsePrefix(tc.tunnel))
		if tc.refuse != "" {
			if err == nil || err.Error() != tc.refuse || !errors.Is(err, errCiliumTunnelMasqueraded) || errors.Is(err, errCiliumNotVerified) {
				t.Errorf("%s: reason = %q, err = %v", name, reason, err)
			}
			continue
		}
		if err != nil || reason != tc.reason {
			t.Errorf("%s: reason = %q, err = %v", name, reason, err)
		}
	}
}

// A range covered by two entries together is not excluded: one entry must
// contain it. The customer is told to add the range itself.
func TestCiliumFactsRangeSplitOverTwoEntriesIsRefused(t *testing.T) {
	facts := ciliumFactsB(t)
	facts.IPMasqMap.Text = `[{"key":["0x19","0x00","0x00","0x00","0x64","0x60","0x00","0x00"],"value":["0x00"]},{"key":["0x19","0x00","0x00","0x00","0x64","0x60","0x00","0x80"],"value":["0x00"]}]`
	_, err := decideCiliumMasquerade(facts, netip.MustParsePrefix("100.96.0.0/24"))
	if err == nil || !strings.Contains(err.Error(), "Add 100.96.0.0/24 to nonMasqueradeCIDRs") {
		t.Fatalf("err = %v", err)
	}
	if reason, err := decideCiliumMasquerade(facts, netip.MustParsePrefix("100.96.0.0/25")); err != nil || reason != "tunnel range is inside Cilium ip-masq-agent range 100.96.0.0/25" {
		t.Fatalf("one half: %q %v", reason, err)
	}
}

func TestCiliumFactsThatProveNothingAreRefused(t *testing.T) {
	withStatus := func(base *CiliumFacts, masquerading string) *CiliumFacts {
		out := *base
		out.Status.Text = `{"masquerading":` + masquerading + `}`
		return &out
	}
	unreadable := CiliumTextFact{State: FactsUnreadable, Reason: "/var/run/cilium is not mounted in the host-posture manager; set cilium.enabled=true on the tunnex-host-posture chart"}
	for name, tc := range map[string]struct {
		facts *CiliumFacts
		want  string
		// definitive marks a refusal that is not "could not be verified".
		definitive bool
	}{
		"no section": {facts: nil, want: "the host-posture manager published no Cilium facts"},
		"whole read failed": {
			facts: UnreadableCiliumFacts("read Cilium facts: context deadline exceeded"),
			want:  "could not read the Cilium agent status: read Cilium facts: context deadline exceeded",
		},
		"socket not mounted": {
			facts: &CiliumFacts{Status: unreadable, PinnedMaps: CiliumPinFacts{State: FactsUnreadable, Reason: "no pinned maps"}, IPMasqMap: CiliumTextFact{State: FactsUnreadable, Reason: "the agent status was not read"}},
			want:  "could not read the Cilium agent status: /var/run/cilium is not mounted in the host-posture manager; set cilium.enabled=true on the tunnex-host-posture chart",
		},
		"status without a masquerading section": {
			facts: func() *CiliumFacts { f := *ciliumFactsA(t); f.Status.Text = `{}`; return &f }(),
			want:  "Cilium status has no masquerading section",
		},
		"status that is not JSON": {
			facts: func() *CiliumFacts { f := *ciliumFactsA(t); f.Status.Text = `masquerading: BPF`; return &f }(),
			want:  "Cilium status is not a JSON object",
		},
		"unknown field in the masquerading report": {
			facts: withStatus(ciliumFactsA(t), `{"enabled":true,"enabledProtocols":{"ipv4":true},"mode":"BPF","snat-exclusion-cidr-v4":"10.244.0.0/16","egress-masquerade":"auto"}`),
			want:  "Cilium masquerading status is not understood",
		},
		"unknown mode": {
			facts: withStatus(ciliumFactsA(t), `{"enabled":true,"enabledProtocols":{"ipv4":true},"mode":"XDP","snat-exclusion-cidr-v4":"10.244.0.0/16"}`),
			want:  "Cilium masquerading mode is not understood",
		},
		"stale masquerading report": {
			facts: func() *CiliumFacts {
				f := *ciliumFactsA(t)
				f.Status.Text = strings.TrimSuffix(f.Status.Text, "}") + `,"stale":{"masquerading":"2026-11-23T10:00:00Z"}}`
				return &f
			}(),
			want: "Cilium masquerading status is stale",
		},
		"pinned maps not listed, eBPF mode": {
			facts: func() *CiliumFacts {
				f := *ciliumFactsB(t)
				f.PinnedMaps = CiliumPinFacts{State: FactsUnreadable, Reason: "list pinned maps: permission denied"}
				return &f
			}(),
			want: "could not list Cilium's pinned maps: list pinned maps: permission denied",
		},
		"egress gateway": {
			facts: func() *CiliumFacts {
				f := *ciliumFactsB(t)
				f.PinnedMaps.EgressGateway = []string{"cilium_egress_gw_policy_v4", "cilium_egress_gw_policy_v4_v2"}
				f.PinnedMaps.Total += 2
				return &f
			}(),
			want:       "Cilium egress gateway is enabled; its policies are applied before any masquerade exclusion and are not read",
			definitive: true,
		},
		"ip-masq-agent on, map not read": {
			facts: func() *CiliumFacts {
				f := *ciliumFactsB(t)
				f.IPMasqMap = CiliumTextFact{State: FactsUnreadable, Reason: "bpftool: bpf obj get (/sys/fs/bpf/tc/globals/cilium_ipmasq_v4): No such file or directory"}
				return &f
			}(),
			want: "could not read the ip-masq-agent map: bpftool: bpf obj get (/sys/fs/bpf/tc/globals/cilium_ipmasq_v4): No such file or directory",
		},
		"ip-masq-agent on, map said to be not needed": {
			facts: func() *CiliumFacts {
				f := *ciliumFactsB(t)
				f.IPMasqMap = CiliumTextFact{State: FactsNotNeeded, Reason: "the agent reports that its ip-masq-agent is off"}
				return &f
			}(),
			want: "the ip-masq-agent map fact contradicts the agent status",
		},
		"ip-masq-agent off, map carried": {
			facts: func() *CiliumFacts { f := *ciliumFactsA(t); f.IPMasqMap = ciliumFactsB(t).IPMasqMap; return &f }(),
			want:  "the ip-masq-agent map fact contradicts the agent status",
		},
		"bpftool's error object carried as the map": {
			facts: func() *CiliumFacts {
				f := *ciliumFactsB(t)
				f.IPMasqMap.Text = strings.TrimSpace(string(ciliumLiveRead(t, ciliumLiveA+"ipmasq-v4.bpftool.json")))
				return &f
			}(),
			want: "BPF map dump is not a JSON array",
		},
		"map key of another size": {
			facts: func() *CiliumFacts {
				f := *ciliumFactsB(t)
				f.IPMasqMap.Text = `[{"key":["0x18","0x00","0x00","0x00"],"value":["0x00"]}]`
				return &f
			}(),
			want: "BPF map dump has a key that is not understood",
		},
		"section with an unknown state": {
			facts: func() *CiliumFacts { f := *ciliumFactsA(t); f.Status.State = "partial"; return &f }(),
			want:  "host facts for Cilium status have an unknown state",
		},
	} {
		for _, tunnel := range []string{"100.96.0.0/24", "10.244.200.0/24"} {
			reason, err := decideCiliumMasquerade(tc.facts, netip.MustParsePrefix(tunnel))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("%s, %s: reason = %q, err = %v", name, tunnel, reason, err)
				continue
			}
			if errors.Is(err, errCiliumNotVerified) == tc.definitive || errors.Is(err, errCiliumTunnelMasqueraded) {
				t.Errorf("%s: wrong kind of refusal: %v", name, err)
			}
			if !tc.definitive && !strings.HasPrefix(err.Error(), ReasonCiliumNotVerified+": ") {
				t.Errorf("%s: refusal does not start with the common reason: %v", name, err)
			}
			if len(err.Error()) > maxReasonBytes+len(ReasonCiliumNotVerified)+2 {
				t.Errorf("%s: refusal is %d bytes", name, len(err.Error()))
			}
		}
	}
}

// In iptables mode Cilium's eBPF facts decide nothing, so an unlisted pin
// directory does not refuse; the rule walk has to pass on its own.
func TestCiliumFactsIPTablesModeNeedsNoPinnedMaps(t *testing.T) {
	facts := ciliumFactsC(t)
	facts.PinnedMaps = CiliumPinFacts{State: FactsUnreadable, Reason: "no pinned maps at /sys/fs/bpf/tc/globals"}
	if reason, err := decideCiliumMasquerade(facts, netip.MustParsePrefix("100.96.0.0/24")); err != nil || reason != ReasonCiliumIPTablesMasquerade {
		t.Fatalf("reason = %q, err = %v", reason, err)
	}
}

func TestCiliumFactsMasqueradeOff(t *testing.T) {
	facts := ciliumFactsA(t)
	facts.Status.Text = `{"masquerading":{"enabledProtocols":{}}}`
	if reason, err := decideCiliumMasquerade(facts, netip.MustParsePrefix("100.96.0.0/24")); err != nil || reason != ReasonCiliumMasqueradeOff {
		t.Fatalf("reason = %q, err = %v", reason, err)
	}
}

// The customer-facing refusals fit the reason bound for the longest range that
// can be written, so the instruction is never cut.
func TestCiliumInstructionsFitTheReasonBound(t *testing.T) {
	tunnel := netip.MustParsePrefix("100.100.100.100/32")
	for _, agent := range []bool{false, true} {
		notExcluded := &ciliumTunnelNotExcludedError{Tunnel: tunnel, Exclusion: netip.MustParsePrefix("192.168.100.0/24"), IPMasqAgent: agent}
		reason := fmt.Sprintf("%s %s. %s", ReasonCiliumTunnelMasqueraded, tunnel, ciliumInstruction(notExcluded))
		if len(reason) > maxReasonBytes {
			t.Errorf("ip-masq-agent %v: %d bytes: %s", agent, len(reason), reason)
		}
		if bounded(reason, maxReasonBytes) != reason || strings.Count(reason, tunnel.String()) != 2 {
			t.Errorf("reason = %q", reason)
		}
	}
}

// The refusal of review finding 1 fits the bound for the longest two ranges
// that can be written, names the range to add twice and the reported range
// once, and is of the kind the customer can lift.
func TestCiliumReportedRangeRefusalFitsTheReasonBound(t *testing.T) {
	tunnel, reported := netip.MustParsePrefix("100.100.100.100/32"), netip.MustParsePrefix("100.100.100.100/31")
	err := ciliumNotExcludedReason(&ciliumTunnelNotExcludedError{Tunnel: tunnel, Exclusion: reported, IPMasqAgent: true, InsideReported: true})
	reason := err.Error()
	if len(reason) > maxReasonBytes || bounded(reason, maxReasonBytes) != reason {
		t.Fatalf("%d bytes: %s", len(reason), reason)
	}
	if strings.Count(reason, tunnel.String()) != 2 || strings.Count(reason, reported.String()) != 1 || !strings.HasPrefix(reason, ReasonCiliumReportedRangeNotProof+" ") {
		t.Fatalf("reason = %q", reason)
	}
	if !errors.Is(err, errCiliumTunnelMasqueraded) || errors.Is(err, errCiliumNotVerified) {
		t.Fatalf("wrong kind of refusal: %v", err)
	}
	// Outside the reported range the unchanged instruction is given.
	plain := ciliumNotExcludedReason(&ciliumTunnelNotExcludedError{Tunnel: tunnel, Exclusion: reported, IPMasqAgent: true})
	if !strings.HasPrefix(plain.Error(), ReasonCiliumTunnelMasqueraded+" ") || !errors.Is(plain, errCiliumTunnelMasqueraded) {
		t.Fatalf("plain refusal = %v", plain)
	}
}

// Review finding 1 on the receipt: the reported range decides only with the
// ip-masq-agent off. With it on, a tunnel range inside that range is refused
// until an entry of the dumped map contains it, whatever else the map holds.
func TestCiliumFactsReportedRangeIsNotAProofWithTheIPMasqAgentOn(t *testing.T) {
	tunnel := netip.MustParsePrefix("10.244.200.0/24")
	if reason, err := decideCiliumMasquerade(ciliumFactsA(t), tunnel); err != nil || reason != "tunnel range is inside Cilium's native-routing range 10.244.0.0/16" {
		t.Fatalf("ip-masq-agent off: reason = %q, err = %v", reason, err)
	}
	for name, dump := range map[string]string{
		"the captured map (100.96.0.0/24)": ciliumFactsB(t).IPMasqMap.Text,
		"an empty map":                     `[]`,
		"an entry for half of the range":   string(ciliumIPMasqDump("10.244.200.0/25")),
		"an entry beside the range":        string(ciliumIPMasqDump("10.244.201.0/24", "10.245.0.0/16")),
	} {
		facts := ciliumFactsB(t)
		facts.IPMasqMap.Text = dump
		reason, err := decideCiliumMasquerade(facts, tunnel)
		if err == nil || err.Error() != ciliumWantList || reason != "" || !errors.Is(err, errCiliumTunnelMasqueraded) || errors.Is(err, errCiliumNotVerified) {
			t.Errorf("%s: reason = %q, err = %v", name, reason, err)
		}
	}
	// The map could not be read: not verified, and never the reported range.
	facts := ciliumFactsB(t)
	facts.IPMasqMap = CiliumTextFact{State: FactsUnreadable, Reason: "bpftool: permission denied"}
	if _, err := decideCiliumMasquerade(facts, tunnel); err == nil || !errors.Is(err, errCiliumNotVerified) {
		t.Fatalf("map unreadable: %v", err)
	}
	for _, listed := range []string{"10.244.200.0/24", "10.244.0.0/16", "10.0.0.0/8"} {
		facts := ciliumFactsB(t)
		facts.IPMasqMap.Text = string(ciliumIPMasqDump("100.96.0.0/24", listed))
		if reason, err := decideCiliumMasquerade(facts, tunnel); err != nil || reason != "tunnel range is inside Cilium ip-masq-agent range "+listed {
			t.Errorf("listed as %s: reason = %q, err = %v", listed, reason, err)
		}
	}
}

func TestReduceCiliumStatusCarriesOnlyWhatTheProofReads(t *testing.T) {
	for _, prefix := range []string{ciliumLiveA, ciliumLiveB, ciliumLiveC} {
		raw := ciliumLiveRead(t, prefix+"healthz.json")
		reduced, err := reduceCiliumStatus(raw)
		if err != nil {
			t.Fatal(err)
		}
		if len(reduced) > 400 || !strings.HasPrefix(reduced, `{"masquerading":{`) || strings.Contains(reduced, "controllers") || strings.ContainsAny(reduced, " \n") {
			t.Errorf("%s: reduced status = %s", prefix, reduced)
		}
		// The reduced status reads exactly as the full one.
		full, fullErr := parseCiliumStatus(raw)
		short, shortErr := parseCiliumStatus([]byte(reduced))
		if fullErr != nil || shortErr != nil || full != short {
			t.Errorf("%s: full %+v %v, reduced %+v %v", prefix, full, fullErr, short, shortErr)
		}
	}
	if reduced, err := reduceCiliumStatus([]byte(`{"masquerading":{"mode":"BPF"}, "stale": {"masquerading": "x"}, "cilium":{"state":"Ok"}}`)); err != nil || reduced != `{"masquerading":{"mode":"BPF"},"stale":{"masquerading":"x"}}` {
		t.Errorf("stale is not carried: %q %v", reduced, err)
	}
	if reduced, err := reduceCiliumStatus([]byte(`{"cilium":{"state":"Ok"}}`)); err != nil || reduced != `{}` {
		t.Errorf("status without the section: %q %v", reduced, err)
	}
	for name, raw := range map[string]string{
		"not an object":  `["masquerading"]`,
		"null":           `null`,
		"trailing data":  `{"masquerading":{}} {}`,
		"empty":          ``,
		"oversized part": `{"masquerading":{"mode":"` + strings.Repeat("B", MaxCiliumStatusFactBytes) + `"}}`,
	} {
		if reduced, err := reduceCiliumStatus([]byte(raw)); err == nil {
			t.Errorf("%s: accepted as %q", name, reduced)
		}
	}
	if _, err := reduceCiliumStatus(make([]byte, maxCiliumStatusBytes+1)); err == nil {
		t.Error("oversized status accepted")
	}
}

func TestCiliumFactsValidate(t *testing.T) {
	if err := UnreadableCiliumFacts("").Validate(); err != nil {
		t.Fatalf("unreadable facts are not valid: %v", err)
	}
	if facts := UnreadableCiliumFacts(strings.Repeat("r", 4*maxReasonBytes)); facts.Validate() != nil || len(facts.Status.Reason) != maxReasonBytes {
		t.Fatal("an oversized reason is not bounded")
	}
	for name, mutate := range map[string]func(*CiliumFacts){
		"status read without text":         func(f *CiliumFacts) { f.Status.Text = "" },
		"status read with a reason":        func(f *CiliumFacts) { f.Status.Reason = "x" },
		"status not needed":                func(f *CiliumFacts) { f.Status = CiliumTextFact{State: FactsNotNeeded, Reason: "x"} },
		"status unreadable without reason": func(f *CiliumFacts) { f.Status = CiliumTextFact{State: FactsUnreadable} },
		"status unreadable with text":      func(f *CiliumFacts) { f.Status = CiliumTextFact{State: FactsUnreadable, Reason: "x", Text: "{}"} },
		"status over its bound":            func(f *CiliumFacts) { f.Status.Text = strings.Repeat("x", MaxCiliumStatusFactBytes+1) },
		"map over its bound":               func(f *CiliumFacts) { f.IPMasqMap.Text = strings.Repeat("x", MaxCiliumMapFactBytes+1) },
		"map with an oversized reason": func(f *CiliumFacts) {
			f.IPMasqMap = CiliumTextFact{State: FactsUnreadable, Reason: strings.Repeat("x", maxReasonBytes+1)}
		},
		"map with an empty state":        func(f *CiliumFacts) { f.IPMasqMap.State = "" },
		"pins with an unknown state":     func(f *CiliumFacts) { f.PinnedMaps.State = FactsNotNeeded },
		"pins read with a reason":        func(f *CiliumFacts) { f.PinnedMaps.Reason = "x" },
		"pins unreadable without reason": func(f *CiliumFacts) { f.PinnedMaps = CiliumPinFacts{State: FactsUnreadable} },
		"pins unreadable with a count":   func(f *CiliumFacts) { f.PinnedMaps = CiliumPinFacts{State: FactsUnreadable, Reason: "x", Total: 1} },
		"pins with an oversized reason":  func(f *CiliumFacts) { f.PinnedMaps.Reason = strings.Repeat("x", maxReasonBytes+1) },
		"more egress maps than maps": func(f *CiliumFacts) {
			f.PinnedMaps.Total, f.PinnedMaps.EgressGateway = 0, []string{"cilium_egress_gw_policy_v4"}
		},
		"egress map of another name": func(f *CiliumFacts) { f.PinnedMaps.EgressGateway = []string{"cilium_egresscall_policy"} },
		"egress map with a path":     func(f *CiliumFacts) { f.PinnedMaps.EgressGateway = []string{"cilium_egress_gw_policy_v4/../x"} },
		"egress maps repeated": func(f *CiliumFacts) {
			f.PinnedMaps.EgressGateway = []string{"cilium_egress_gw_policy_v4", "cilium_egress_gw_policy_v4"}
		},
		"egress maps out of order": func(f *CiliumFacts) {
			f.PinnedMaps.EgressGateway = []string{"cilium_egress_gw_policy_v4_v2", "cilium_egress_gw_policy_v4"}
		},
		"too many egress maps": func(f *CiliumFacts) {
			for i := 0; i <= maxCiliumEgressPins; i++ {
				f.PinnedMaps.EgressGateway = append(f.PinnedMaps.EgressGateway, fmt.Sprintf("cilium_egress_gw_policy_v4_%02d", i))
			}
		},
	} {
		facts := *ciliumFactsB(t)
		mutate(&facts)
		if err := facts.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestCiliumFactsSummaryIsBounded(t *testing.T) {
	if got, want := ciliumFactsB(t).Summary(), "status=read; pinned_maps=read egress_gateway=0; ip_masq_map=read"; got != want {
		t.Errorf("summary = %q", got)
	}
	if got := UnreadableCiliumFacts(strings.Repeat("r", maxReasonBytes)).Summary(); len(got) > maxReasonBytes || !strings.HasPrefix(got, "status=unreadable (rrr") {
		t.Errorf("summary = %q", got)
	}
}
