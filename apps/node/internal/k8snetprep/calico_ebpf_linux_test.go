//go:build linux

package k8snetprep

import (
	"encoding/json"
	"strings"
	"testing"
)

// K8N-6 follow-up: Calico's eBPF dataplane is refused on purpose. Before, a
// node running it was refused only because Felix in BPF mode keeps a
// mark-matched MASQUERADE ("BPF loopback SNAT") in cali-POSTROUTING that the
// NAT walk cannot prove. That is still the refusal a real node shows first;
// these tests show the node stays refused when the walk would pass.
//
// calico-v3.31.2-kind-ebpf.* were captured on 2026-11-24 from a one-node kind
// cluster (kind v0.31.0, kindest/node v1.35.0, kernel 6.8.0-117-generic,
// arm64) running Calico v3.31.2 from its unchanged calico.yaml, switched to
// the eBPF dataplane (FelixConfiguration bpfEnabled, with connect-time load
// balancing off: Felix could not attach it on this kernel), read from a
// privileged pod in the node's network namespace (nft 1.1.6,
// iptables-nft-save 1.8.13). Felix created its devices and chains; on this
// kernel it could not load its tc programs, so nothing was attached
// (walk-artifacts/k8n6-cilium-host-routing-20261124/out/calico-ebpf-*).

const liveCalicoEBPF = "testdata/calico-v3.31.2-kind-ebpf."

func calicoEBPFLinks(t *testing.T) []string {
	t.Helper()
	return strings.Fields(string(ciliumLiveRead(t, liveCalicoEBPF+"links.txt")))
}

func calicoSnapshotOf(t *testing.T, path string) *cniSnapshot {
	t.Helper()
	s, err := parseCNISnapshot(string(ciliumLiveRead(t, path)))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// Both signals are in the capture, and neither is on any other captured node.
func TestDetectCalicoEBPFOnTheCaptures(t *testing.T) {
	ebpf := calicoSnapshotOf(t, liveCalicoEBPF+"nft.json")
	plainLinks := []string{"lo", "eth0", "tunl0", "wg0"}
	for name, tc := range map[string]struct {
		links    []string
		snapshot *cniSnapshot
		want     string
	}{
		"eBPF capture, its devices":       {calicoEBPFLinks(t), ebpf, "network device bpfin.cali"},
		"eBPF capture, its chains alone":  {plainLinks, ebpf, "chain cali-untracked-policy"},
		"eBPF capture, its devices alone": {calicoEBPFLinks(t), nil, "network device bpfin.cali"},
		"iptables-mode Calico capture":    {plainLinks, calicoSnapshotOf(t, liveCalico+"nft.json"), ""},
		"Cilium, legacy host routing":     {strings.Fields(string(ciliumLiveRead(t, ciliumLiveLegacy+"links.txt"))), calicoSnapshotOf(t, ciliumLiveLegacy+"nft-ruleset.json"), ""},
		"Cilium A":                        {strings.Fields(string(ciliumLiveRead(t, ciliumLiveA+"links.txt"))), calicoSnapshotOf(t, ciliumLiveA+"nft-ruleset.json"), ""},
		"Cilium C":                        {strings.Fields(string(ciliumLiveRead(t, ciliumLiveC+"links.txt"))), calicoSnapshotOf(t, ciliumLiveC+"nft-ruleset.json"), ""},
		// A device name that only resembles Felix's is not it.
		"similar names": {[]string{"bpfin.calico", "xbpfout.cali", "bpfin"}, nil, ""},
	} {
		if got := detectCalicoEBPF(tc.links, tc.snapshot); got != tc.want {
			t.Errorf("%s: %q, want %q", name, got, tc.want)
		}
	}
	// The capture also holds the rule that refused such a node by accident.
	if save := string(ciliumLiveRead(t, liveCalicoEBPF+"iptables-nft-save.txt")); !strings.Contains(save, `"BPF loopback SNAT" -m mark --mark 0x3600000/0x3f00000 -j MASQUERADE`) {
		t.Fatal("the capture lacks Felix's BPF loopback SNAT rule")
	}
}

func wantCalicoEBPFRefusal(t *testing.T, name string, f *calicoTestKernel, status ReconcileStatus, err error, found string) {
	t.Helper()
	want := ReasonCalicoEBPF + " (found " + found + ")"
	if err == nil || err.Error() != want || len(want) > maxReasonBytes {
		t.Fatalf("%s: status %+v, error %v, want %q", name, status, err, want)
	}
	if status.Host.State != StateBlocked || status.Host.Reason != want {
		t.Errorf("%s: host = %+v", name, status.Host)
	}
	for _, adapter := range status.Adapters {
		if adapter.State != StateBlocked {
			t.Errorf("%s: adapter = %+v", name, adapter)
		}
	}
	if len(f.mutations) != 0 {
		t.Errorf("%s: refusal mutated: %v", name, f.mutations)
	}
}

// The whole reconcile on the captured iptables-mode Calico node, which is
// ready, with one eBPF signal added at a time. The walk passes on its rules
// (there is no BPF loopback SNAT rule in them), so only the explicit check
// can refuse it.
func TestCalicoEBPFNodeIsRefusedOnPurpose(t *testing.T) {
	// The baseline: ready.
	f, r := liveCalicoKernel(t)
	r.listLinks = func() ([]string, error) { return []string{"lo", "eth0", "tunl0", "wg0"}, nil }
	if status, err := r.Reconcile(t.Context(), "100.96.0.0/24"); err != nil || status.Adapters[0].Name != ObservedAdapterName || status.Adapters[0].State != StateReady {
		t.Fatalf("captured Calico node was refused: %+v %v", status, err)
	}

	// Felix's devices, as the eBPF capture listed them.
	f, r = liveCalicoKernel(t)
	links := calicoEBPFLinks(t)
	for i := range links {
		links[i], _, _ = strings.Cut(links[i], "@")
	}
	r.listLinks = func() ([]string, error) { return links, nil }
	status, err := r.Reconcile(t.Context(), "100.96.0.0/24")
	wantCalicoEBPFRefusal(t, "devices", f, status, err, "network device bpfin.cali")

	// Felix's BPF-mode raw chain, added to the listing.
	f, r = liveCalicoKernel(t)
	r.listLinks = func() ([]string, error) { return []string{"lo", "eth0", "tunl0", "wg0"}, nil }
	chain, err := json.Marshal(map[string]any{"chain": map[string]any{"family": "ip", "table": "raw", "name": "cali-untracked-policy", "handle": 999999}})
	if err != nil {
		t.Fatal(err)
	}
	var entry map[string]json.RawMessage
	if err := json.Unmarshal(chain, &entry); err != nil {
		t.Fatal(err)
	}
	f.doc.NFTables = append(f.doc.NFTables, entry)
	status, err = r.Reconcile(t.Context(), "100.96.0.0/24")
	wantCalicoEBPFRefusal(t, "raw chain", f, status, err, "chain cali-untracked-policy")

	// A Cilium facts source does not change it: Calico's eBPF dataplane is
	// refused before any Cilium fact is read.
	f, r = liveCalicoKernel(t)
	r.listLinks = func() ([]string, error) { return links, nil }
	calls := 0
	r.UseCiliumFacts(constantCiliumFacts(nil, &calls))
	status, err = r.Reconcile(t.Context(), "100.96.0.0/24")
	wantCalicoEBPFRefusal(t, "with a facts source", f, status, err, "network device bpfin.cali")
	if calls != 0 {
		t.Fatalf("Cilium facts were read %d times", calls)
	}
}
