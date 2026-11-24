package k8snetprep

import (
	"net/netip"
	"os"
	"strings"
	"testing"
)

// The fixtures named cilium-1.20.5-kind-* are captured, not written: one kind
// node (kind v0.31.0, kindest/node v1.35.0, kernel 6.8.0-117-generic, arm64)
// running Cilium 1.20.5 installed by Helm with kube-proxy replacement and
// native routing (ipv4NativeRoutingCIDR 10.244.0.0/16), read on 2026-11-23
// from a separate privileged pod with read-only host mounts of
// /var/run/cilium and /sys/fs/bpf. Three configurations:
//
//	A-bpf         bpf.masquerade=true, ip-masq-agent off
//	B-bpf-ipmasq  bpf.masquerade=true, ip-masq-agent on, nonMasqueradeCIDRs
//	              [100.96.0.0/24], masqLinkLocal true
//	C-iptables    bpf.masquerade=false (iptables masquerade)
//
// See docs/K8N-2-cilium.md, "Live capture". A and B report BPF host routing,
// C reports Legacy.
//
// Two more were captured on 2026-11-24 for the host routing decision (same
// kind, node image and kernel; Cilium 1.20.5 with K8N-6's values: eBPF
// masquerade, ip-masq-agent on with nonMasqueradeCIDRs [10.99.0.0/24],
// masqLinkLocal true), read from a privileged pod with the same read-only
// host mounts:
//
//	hostlegacy-ipmasq  bpf.hostLegacyRouting=true: host routing Legacy, the
//	                   configuration Tunnex accepts (before the test wg0
//	                   existed, as A)
//	hostbpf-ipmasq     the same with bpf.hostLegacyRouting=false: host
//	                   routing BPF, refused (wg0 up and among the devices)
//
// See docs/K8N-2-cilium.md, "Host routing — decision, 2026-11-24".

const (
	ciliumLiveA = "testdata/cilium-1.20.5-kind-A-bpf."
	ciliumLiveB = "testdata/cilium-1.20.5-kind-B-bpf-ipmasq."
	ciliumLiveC = "testdata/cilium-1.20.5-kind-C-iptables."

	ciliumLiveLegacy  = "testdata/cilium-1.20.5-kind-hostlegacy-ipmasq."
	ciliumLiveBPFHost = "testdata/cilium-1.20.5-kind-hostbpf-ipmasq."
)

func ciliumLiveFile(t *testing.T, name string) []byte {
	t.Helper()
	return ciliumLiveRead(t, ciliumLiveA+name)
}

func ciliumLiveRead(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func ciliumLiveLines(t *testing.T, name string) []string {
	t.Helper()
	return strings.Fields(string(ciliumLiveFile(t, name)))
}

func TestCiliumLiveBPFMasqueradeStatusIsRead(t *testing.T) {
	masq, err := parseCiliumStatus(ciliumLiveFile(t, "healthz.json"))
	if err != nil {
		t.Fatalf("parseCiliumStatus on the captured status: %v", err)
	}
	want := ciliumMasquerade{Mode: ciliumMasqBPF, Exclusion: netip.MustParsePrefix("10.244.0.0/16")}
	if masq != want {
		t.Fatalf("masquerade = %+v, want %+v", masq, want)
	}
}

func TestCiliumLiveNodeIsDetected(t *testing.T) {
	links := ciliumLiveLines(t, "links.txt")
	maps := ciliumLiveLines(t, "pinned-maps.txt")
	var chains []string
	for _, line := range strings.Split(string(ciliumLiveFile(t, "iptables-nft-save-nat.txt")), "\n") {
		if strings.HasPrefix(line, ":") {
			chains = append(chains, strings.Fields(line[1:])[0])
		}
	}
	// Each kind of trace alone must be enough.
	for name, present := range map[string]bool{
		"links":  ciliumPresent(links, nil, nil),
		"chains": ciliumPresent(nil, chains, nil),
		"maps":   ciliumPresent(nil, nil, maps),
	} {
		if !present {
			t.Errorf("Cilium not detected from the captured %s", name)
		}
	}
	// The node pins cilium_egresscall_policy, which is not an egress-gateway
	// policy map; the egress gateway is off here.
	if ciliumEgressGatewayPinned(maps) {
		t.Fatal("egress gateway reported on a node where it is off")
	}
	for _, name := range maps {
		if name == "cilium_ipmasq_v4" {
			t.Fatal("ip-masq-agent map pinned although the ip-masq-agent is off")
		}
	}
}

// With the ip-masq-agent off the map is not pinned and bpftool prints an error
// object, not an array. That is never an empty map.
func TestCiliumLiveMissingIPMasqMapIsNotAnEmptyMap(t *testing.T) {
	if _, err := parseCiliumIPMasqDump(ciliumLiveFile(t, "ipmasq-v4.bpftool.json")); err == nil {
		t.Fatal("bpftool's error output was read as a map")
	}
}

func TestCiliumLiveBPFMasqueradeProof(t *testing.T) {
	masq, err := parseCiliumStatus(ciliumLiveFile(t, "healthz.json"))
	if err != nil {
		t.Fatal(err)
	}
	obs := ciliumObservation{Masquerade: masq, EgressGateway: ciliumEgressGatewayPinned(ciliumLiveLines(t, "pinned-maps.txt"))}

	// On this node a pod's packet to 100.96.0.5 was seen leaving wg0 with the
	// node's wg0 address as its source: the refusal below is a real rewrite.
	_, err = proveCiliumNoTunnelMasquerade(obs, netip.MustParsePrefix("100.96.0.0/24"))
	if err == nil {
		t.Fatal("a tunnel range outside every exclusion was accepted")
	}
	for _, want := range []string{"100.96.0.0/24", "10.244.0.0/16", "ip-masq-agent is off"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal %q does not name %q", err, want)
		}
	}

	reason, err := proveCiliumNoTunnelMasquerade(obs, netip.MustParsePrefix("10.244.200.0/24"))
	if err != nil || reason != "tunnel range is inside Cilium's native-routing range 10.244.0.0/16" {
		t.Fatalf("inside the native-routing range: reason = %q, err = %v", reason, err)
	}
}

// Configuration B: the ip-masq-agent is on and the device range is listed. The
// real map key is the prefix length as a little-endian 32-bit number followed
// by the address: 0x18 0x00 0x00 0x00 0x64 0x60 0x00 0x00 is 100.96.0.0/24.
// The real dump has no "formatted" member. On this node a pod's packet to
// 100.96.0.5 left wg0 with the pod's own address.
func TestCiliumLiveIPMasqAgentRangeIsProved(t *testing.T) {
	masq, err := parseCiliumStatus(ciliumLiveRead(t, ciliumLiveB+"healthz.json"))
	if err != nil {
		t.Fatalf("parseCiliumStatus on the captured status: %v", err)
	}
	want := ciliumMasquerade{Mode: ciliumMasqBPF, Exclusion: netip.MustParsePrefix("10.244.0.0/16"), IPMasqAgent: true}
	if masq != want {
		t.Fatalf("masquerade = %+v, want %+v", masq, want)
	}
	dump := ciliumLiveRead(t, ciliumLiveB+"ipmasq-v4.bpftool.json")
	if strings.TrimSpace(string(dump)) != `[{"key":["0x18","0x00","0x00","0x00","0x64","0x60","0x00","0x00"],"value":["0x00"]}]` {
		t.Fatal("the captured dump is not the one this test describes")
	}
	members, err := parseCiliumIPMasqDump(dump)
	if err != nil {
		t.Fatalf("parseCiliumIPMasqDump on the captured dump: %v", err)
	}
	if len(members) != 1 || members[0] != netip.MustParsePrefix("100.96.0.0/24") {
		t.Fatalf("members = %v", members)
	}
	maps := strings.Fields(string(ciliumLiveRead(t, ciliumLiveB+"pinned-maps.txt")))
	pinned := false
	for _, name := range maps {
		pinned = pinned || name == "cilium_ipmasq_v4"
	}
	if !pinned {
		t.Fatal("cilium_ipmasq_v4 is not in the captured pin list")
	}
	obs := ciliumObservation{Masquerade: masq, NonMasquerade: members, NonMasqueradeRead: true, EgressGateway: ciliumEgressGatewayPinned(maps)}
	reason, err := proveCiliumNoTunnelMasquerade(obs, netip.MustParsePrefix("100.96.0.0/24"))
	if err != nil || reason != "tunnel range is inside Cilium ip-masq-agent range 100.96.0.0/24" {
		t.Fatalf("listed range: reason = %q, err = %v", reason, err)
	}
	for _, tunnel := range []string{"100.96.1.0/24", "100.96.0.0/23", "100.64.0.0/10"} {
		if _, err := proveCiliumNoTunnelMasquerade(obs, netip.MustParsePrefix(tunnel)); err == nil {
			t.Errorf("%s is not inside the listed range but was accepted", tunnel)
		}
	}
	// Review finding 1. The status of this node reports 10.244.0.0/16, and on
	// this node that range was set explicitly, so the datapath does exclude
	// it. The status does not say so, and with the ip-masq-agent on an
	// unset option means no exclusion at all: the report is not accepted.
	_, err = proveCiliumNoTunnelMasquerade(obs, netip.MustParsePrefix("10.244.200.0/24"))
	if err == nil || !strings.Contains(err.Error(), "is applied only when it is set explicitly") {
		t.Fatalf("inside the reported range only, ip-masq-agent on: %v", err)
	}
	// The same node with the map unread stays refused.
	obs.NonMasquerade, obs.NonMasqueradeRead = nil, false
	if _, err := proveCiliumNoTunnelMasquerade(obs, netip.MustParsePrefix("100.96.0.0/24")); err == nil {
		t.Fatal("accepted without the map")
	}
}

// After the ip-masq-agent was turned off again and the agent restarted, the
// pin was gone (and the pod's packet was masqueraded again).
func TestCiliumLiveIPMasqMapIsUnpinnedWhenTurnedOff(t *testing.T) {
	for _, name := range strings.Fields(string(ciliumLiveRead(t, "testdata/cilium-1.20.5-kind-B-then-ipmasq-off.pinned-maps.txt"))) {
		if name == "cilium_ipmasq_v4" {
			t.Fatal("the capture taken after turning the ip-masq-agent off still lists the map")
		}
	}
}

// Configuration C: the agent masquerades with iptables rules. The Cilium proof
// says so and decides nothing; the rule walk must pass on its own
// (cilium_live_linux_test.go).
func TestCiliumLiveIPTablesModeDefersToTheRuleWalk(t *testing.T) {
	masq, err := parseCiliumStatus(ciliumLiveRead(t, ciliumLiveC+"healthz.json"))
	if err != nil {
		t.Fatalf("parseCiliumStatus on the captured status: %v", err)
	}
	want := ciliumMasquerade{Mode: ciliumMasqIPTables, Exclusion: netip.MustParsePrefix("10.244.0.0/16")}
	if masq != want {
		t.Fatalf("masquerade = %+v, want %+v", masq, want)
	}
	for _, tunnel := range []string{"100.96.0.0/24", "10.244.200.0/24"} {
		reason, err := proveCiliumNoTunnelMasquerade(ciliumObservation{Masquerade: masq}, netip.MustParsePrefix(tunnel))
		if err != nil || reason != ReasonCiliumIPTablesMasquerade {
			t.Fatalf("%s: reason = %q, err = %v", tunnel, reason, err)
		}
	}
}
