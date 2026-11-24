//go:build linux

package k8snetprep_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tunnexio/tunnex/apps/node/internal/hostposture"
	"github.com/tunnexio/tunnex/apps/node/internal/k8snetprep"
)

// K8N-2, end to end: the real host-posture manager, with the real netfilter
// reader and the real Cilium reader, publishes into a real state directory,
// and a real gateway reconciler decides from that directory alone.
//
// The node is the captured Cilium 1.20.5 one (testdata/README.md) in its three
// configurations. Only the Kubernetes API, the manager's kernel mutations and
// the four reads of the Cilium reader (devices, agent status, pin directory,
// bpftool) are replaced; the last four answer from the captured files.

const (
	ciliumE2ENode = "cilium-worker"
	ciliumA       = "testdata/cilium-1.20.5-kind-A-bpf."
	ciliumB       = "testdata/cilium-1.20.5-kind-B-bpf-ipmasq."
	ciliumC       = "testdata/cilium-1.20.5-kind-C-iptables."

	ciliumAbsentMap = `{"error":"bpf obj get (/sys/fs/bpf/tc/globals/cilium_ipmasq_v4): No such file or directory"}`
	ciliumEnable    = "Cilium eBPF masquerade would rewrite traffic to the tunnel range 100.96.0.0/24. Enable Cilium's ip-masq-agent (Helm ipMasqAgent.enabled=true) with 100.96.0.0/24 in nonMasqueradeCIDRs, then restart the Cilium agents"
)

func ciliumFixture(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// ciliumAgent is what the Cilium reader finds on the node. The test changes it
// between passes, as the customer changes Cilium.
type ciliumAgent struct {
	links   []string
	status  string
	pins    []string
	dump    string
	dumpErr error
	ran     []string
}

func (a *ciliumAgent) configure(t *testing.T, prefix string) {
	t.Helper()
	a.status = ciliumFixture(t, prefix+"healthz.json")
	a.pins = strings.Fields(ciliumFixture(t, prefix+"pinned-maps.txt"))
	a.links = nil
	for _, name := range strings.Fields(ciliumFixture(t, prefix+"links.txt")) {
		name, _, _ = strings.Cut(name, "@")
		a.links = append(a.links, name)
	}
	a.dump, a.dumpErr = ciliumAbsentMap, errors.New("bpftool inspection: exit status 255: ")
	if prefix == ciliumB {
		a.dump, a.dumpErr = ciliumFixture(t, prefix+"ipmasq-v4.bpftool.json"), nil
	}
}

func (a *ciliumAgent) reader() *k8snetprep.CiliumFactsReader {
	return k8snetprep.NewCiliumFactsReader(
		func() ([]string, error) { return a.links, nil },
		func(context.Context) ([]byte, error) {
			a.ran = append(a.ran, "GET /v1/healthz")
			return []byte(a.status), nil
		},
		func(context.Context) ([]string, error) { a.ran = append(a.ran, "list pins"); return a.pins, nil },
		func(_ context.Context, args ...string) (string, error) {
			a.ran = append(a.ran, "bpftool "+strings.Join(args, " "))
			return a.dump, a.dumpErr
		},
	)
}

func newCapturedCiliumRules(t *testing.T, prefix string) *capturedNode {
	t.Helper()
	var doc struct {
		NFTables []nftEntry `json:"nftables"`
	}
	if err := json.Unmarshal([]byte(ciliumFixture(t, prefix+"nft-ruleset.json")), &doc); err != nil {
		t.Fatal(err)
	}
	node := &capturedNode{
		t: t, entries: doc.NFTables,
		nat: ciliumFixture(t, prefix+"iptables-nft-save-nat.txt"), mangle: ciliumFixture(t, prefix+"iptables-nft-save-mangle.txt"),
		sets: map[string]string{},
	}
	if prefix == ciliumC {
		node.sets["cilium_node_set_v4"] = ciliumFixture(t, prefix+"ipset-cilium_node_set_v4.txt")
	}
	return node
}

type ciliumE2E struct {
	t        *testing.T
	rules    *capturedNode
	agent    *ciliumAgent
	manager  *hostposture.Manager
	gateway  *k8snetprep.Reconciler
	stateDir string
}

func newCiliumE2E(t *testing.T, prefix string) *ciliumE2E {
	t.Helper()
	e := &ciliumE2E{t: t, rules: newCapturedCiliumRules(t, prefix), agent: &ciliumAgent{}, stateDir: filepath.Join(t.TempDir(), "v1")}
	e.agent.configure(t, prefix)
	netfilter := k8snetprep.NewHostFactsReader(e.rules.managerNFT, e.rules.managerIPTables, e.rules.managerIPSet)
	sysModule := t.TempDir()
	if len(e.rules.sets) > 0 {
		if err := os.Mkdir(filepath.Join(sysModule, "ip_set"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	netfilter.SetSysModuleForTest(sysModule)
	netfilter.SetProcNetForTest(e2eNoLegacyProcNet(t))
	e.manager = newE2EManager(t, e.stateDir, ciliumE2ENode, e2eOwnerUID, netfilter)
	e.manager.SetCiliumFactsReader(e.agent.reader())
	e.gateway = newE2EGateway(t, e.stateDir, ciliumE2ENode, e2eOwnerUID, e.rules.gatewayNFT, e.rules.gatewayDenied("iptables-nft-save"))
	e.gateway.SetIPSetRunnerForTest(e.rules.gatewayDenied("ipset"))
	return e
}

func (e *ciliumE2E) pass() {
	e.t.Helper()
	if err := e.manager.ReconcileOnce(e.t.Context()); err != nil {
		e.t.Fatalf("manager pass: %v", err)
	}
}

// admit lets the gateway earn its authority: it has to see two advancing
// heartbeats of the manager that name it as the owner.
func (e *ciliumE2E) admit() {
	e.t.Helper()
	e.pass()
	e.refused("100.96.0.0/24", "awaits two advancing exact-owner heartbeats")
	e.pass()
}

func (e *ciliumE2E) receiptPath() string { return filepath.Join(e.stateDir, "host-facts.json") }

func (e *ciliumE2E) ready(tunnel, reason string) {
	e.t.Helper()
	status, err := e.gateway.Reconcile(e.t.Context(), tunnel)
	if err != nil {
		e.t.Fatalf("gateway was refused for %s: %+v %v", tunnel, status, err)
	}
	if status.Host.State != k8snetprep.StateReady || len(status.Adapters) < 2 ||
		status.Adapters[0].Name != k8snetprep.ObservedAdapterName || status.Adapters[0].State != k8snetprep.StateReady ||
		status.Adapters[1].Name != k8snetprep.CiliumAdapterName || status.Adapters[1].State != k8snetprep.StateReady || status.Adapters[1].Reason != reason {
		e.t.Fatalf("status = %+v, want cilium_masquerade ready with %q", status, reason)
	}
}

func (e *ciliumE2E) refused(tunnel, want string) {
	e.t.Helper()
	status, err := e.gateway.Reconcile(e.t.Context(), tunnel)
	if err == nil || !strings.Contains(err.Error(), want) {
		e.t.Fatalf("for %s: status %+v, error %v, want %q", tunnel, status, err, want)
	}
	if status.Host.State != k8snetprep.StateBlocked || len(status.Host.Reason) > 240 {
		e.t.Fatalf("refusal does not carry a bounded reason: %+v", status)
	}
	for _, adapter := range status.Adapters {
		if adapter.State == k8snetprep.StateReady {
			e.t.Fatalf("refused gateway reports a ready adapter: %+v", status)
		}
	}
}

// The customer's path on one node: eBPF masquerade with the device range not
// excluded (A), then the range added to the ip-masq-agent list (B), then the
// ip-masq-agent turned off again. The gateway and the manager are never
// restarted; the gateway follows what each pass of the manager publishes.
func TestCapturedCiliumNodeFollowsTheIPMasqAgentThroughTheReceipt(t *testing.T) {
	e := newCiliumE2E(t, ciliumA)

	// Before the manager has run there is nothing to trust.
	if _, err := e.gateway.Reconcile(t.Context(), "100.96.0.0/24"); err == nil {
		t.Fatal("gateway became ready with no manager")
	}
	e.admit()

	// A: refused, with the instruction; ready for a range inside the
	// native-routing range.
	e.refused("100.96.0.0/24", ciliumEnable)
	e.ready("10.244.200.0/24", "tunnel range is inside Cilium's native-routing range 10.244.0.0/16")
	if strings.Contains(strings.Join(e.agent.ran, "\n"), "bpftool") {
		t.Fatalf("the map was dumped although the agent reports the ip-masq-agent off: %v", e.agent.ran)
	}

	// B: the customer enables the ip-masq-agent with the range. Until the
	// manager's next pass the gateway still sees A.
	e.agent.configure(t, ciliumB)
	e.refused("100.96.0.0/24", ciliumEnable)
	e.pass()
	e.ready("100.96.0.0/24", "tunnel range is inside Cilium ip-masq-agent range 100.96.0.0/24")
	e.refused("100.96.1.0/24", "Add 100.96.1.0/24 to nonMasqueradeCIDRs in the ip-masq-agent ConfigMap (namespace kube-system, key config); no restart is needed, allow about a minute")
	// Review finding 1: the range that was ready on the agent's report a
	// moment ago is not ready on it now. With the ip-masq-agent on the report
	// is no proof, and the customer is told to list the range.
	e.refused("10.244.200.0/24", "Cilium's ip-masq-agent is on: its reported native-routing range 10.244.0.0/16 does not prove 10.244.200.0/24 is not masqueraded. Add 10.244.200.0/24 to nonMasqueradeCIDRs in the ip-masq-agent ConfigMap (kube-system, key config)")

	// What is on disk: a public, bounded file. The whole 12 KiB status is not
	// in it, the tunnel range and the owner are not in it.
	body, err := os.ReadFile(e.receiptPath())
	if err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(e.receiptPath())
	if info.Mode().Perm() != 0o644 || len(body) > 2<<10 {
		t.Fatalf("receipt mode %v, %d bytes", info.Mode(), len(body))
	}
	for _, want := range []string{`"contract":"tunnex-host-posture-facts/v1"`, `"node_name":"` + ciliumE2ENode + `"`, `"cilium":{"status":{"state":"read"`, `\"mode\":\"BPF\"`, `\"ip-masq-agent\":true`, `"pinned_maps":{"state":"read","total":47}`, `\"0x18\",\"0x00\",\"0x00\",\"0x00\",\"0x64\",\"0x60\",\"0x00\",\"0x00\"`} {
		if !bytes.Contains(body, []byte(want)) {
			t.Errorf("receipt lacks %q", want)
		}
	}
	for _, unwanted := range []string{e2eOwnerUID, "100.96.0.0/24", "controllers", "kube-proxy-replacement", "cilium_lxc", "verdict", "ready"} {
		if bytes.Contains(body, []byte(unwanted)) {
			t.Errorf("receipt carries %q: %s", unwanted, body)
		}
	}

	// The list changes without an agent restart: the range is taken out.
	e.agent.dump = "[]"
	e.pass()
	e.refused("100.96.0.0/24", "Add 100.96.0.0/24 to nonMasqueradeCIDRs")
	e.agent.configure(t, ciliumB)
	e.pass()
	e.ready("100.96.0.0/24", "tunnel range is inside Cilium ip-masq-agent range 100.96.0.0/24")

	// The pin disappears while the agent still reports the ip-masq-agent on.
	// bpftool's error is a read error, never an empty map.
	e.agent.dump, e.agent.dumpErr = ciliumAbsentMap, errors.New("bpftool inspection: exit status 255: ")
	e.pass()
	e.refused("100.96.0.0/24", "Cilium masquerade on this node is not verified: the host-posture manager could not read the ip-masq-agent map: bpftool: bpf obj get (/sys/fs/bpf/tc/globals/cilium_ipmasq_v4): No such file or directory")

	// B, then the ip-masq-agent off and the agent restarted: as A, refused.
	e.agent.configure(t, ciliumA)
	e.agent.pins = strings.Fields(ciliumFixture(t, "testdata/cilium-1.20.5-kind-B-then-ipmasq-off.pinned-maps.txt"))
	e.pass()
	e.refused("100.96.0.0/24", ciliumEnable)

	// An egress gateway is enabled on a node that would otherwise be ready.
	e.agent.configure(t, ciliumB)
	e.agent.pins = append(e.agent.pins, "cilium_egress_gw_policy_v4")
	e.pass()
	e.refused("100.96.0.0/24", "Cilium egress gateway is enabled; its policies are applied before any masquerade exclusion and are not read")
	e.refused("10.244.200.0/24", "Cilium egress gateway is enabled")

	// A Cilium release adds a field to its masquerading report.
	e.agent.configure(t, ciliumB)
	e.agent.status = strings.Replace(e.agent.status, `"masquerading":{`, `"masquerading":{"egress-masquerade-interfaces":"eth+",`, 1)
	if !strings.Contains(e.agent.status, "egress-masquerade-interfaces") {
		t.Fatal("the captured status has no masquerading object to extend")
	}
	e.pass()
	e.refused("100.96.0.0/24", "Cilium masquerade on this node is not verified: Cilium masquerading status is not understood")

	// Nothing above made the gateway run anything but its own listing, and the
	// manager's Cilium reader issued only its three reads.
	for _, command := range e.rules.gatewayRan {
		if command != "nft -j -a list ruleset" {
			t.Fatalf("gateway ran %q", command)
		}
	}
	for _, command := range e.agent.ran {
		if command != "GET /v1/healthz" && command != "list pins" && command != "bpftool --json map dump pinned /sys/fs/bpf/tc/globals/cilium_ipmasq_v4" {
			t.Fatalf("Cilium reader ran %q", command)
		}
	}
}

// Configuration C: the agent reports iptables masquerade, and the rule walk
// decides on the real rules, as it does on any other node.
func TestCapturedCiliumIPTablesNodeIsDecidedByTheRuleWalk(t *testing.T) {
	e := newCiliumE2E(t, ciliumC)
	e.admit()
	e.ready("100.96.0.0/24", k8snetprep.ReasonCiliumIPTablesMasquerade)
	e.ready("10.244.200.0/24", k8snetprep.ReasonCiliumIPTablesMasquerade)
	// A range that contains the node's pod range and reaches outside the
	// native-routing range: the walk refuses, naming Cilium's chain.
	e.refused("10.0.0.0/8", "CILIUM_POST_nat")
	if strings.Contains(strings.Join(e.agent.ran, "\n"), "bpftool") {
		t.Fatalf("the map was dumped in iptables mode: %v", e.agent.ran)
	}
	for _, command := range e.rules.gatewayRan {
		if strings.HasPrefix(command, "DENIED") {
			t.Fatalf("gateway tried %q", command)
		}
	}
	// The agent is switched to eBPF masquerade: the same rules no longer
	// carry the node.
	e.agent.configure(t, ciliumA)
	e.pass()
	e.refused("100.96.0.0/24", ciliumEnable)
}

// A missing, stale, earlier, damaged, edited or foreign receipt, and a manager
// that stopped, each leave a Cilium node not ready and say which.
func TestCapturedCiliumNodeRefusesAReceiptThatDoesNotHold(t *testing.T) {
	e := newCiliumE2E(t, ciliumB)
	e.admit()
	const tunnel = "100.96.0.0/24"
	const proved = "tunnel range is inside Cilium ip-masq-agent range 100.96.0.0/24"
	// The receipt is taken before the rules are proved (K8N review, findings 5
	// and 6), so a receipt that does not hold refuses there, Cilium or not.
	const notVerified = "host-posture facts: "
	e.ready(tunnel, proved)

	if err := os.Remove(e.receiptPath()); err != nil {
		t.Fatal(err)
	}
	e.refused(tunnel, notVerified+"host facts receipt is missing")
	e.pass()
	e.ready(tunnel, proved)

	earlier, err := os.ReadFile(e.receiptPath())
	if err != nil {
		t.Fatal(err)
	}
	e.pass()
	current, err := os.ReadFile(e.receiptPath())
	if err != nil {
		t.Fatal(err)
	}
	rewrite := func(content []byte) {
		t.Helper()
		if err := os.WriteFile(e.receiptPath(), content, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// The receipt of an earlier pass.
	rewrite(earlier)
	e.refused(tunnel, notVerified+"host facts receipt does not belong to the live heartbeat")
	// Truncated.
	rewrite(current[:len(current)/2])
	e.refused(tunnel, notVerified+"read host facts receipt")
	// Edited: a wider range written into the map, the mode rewritten, the
	// section taken out.
	for name, edited := range map[string][]byte{
		"wider range": bytes.Replace(current, []byte(`\"0x18\"`), []byte(`\"0x08\"`), 1),
		"mode":        bytes.Replace(current, []byte(`\"mode\":\"BPF\"`), []byte(`\"mode\":\"iptables\"`), 1),
		"agent flag":  bytes.Replace(current, []byte(`\"ip-masq-agent\":true,`), nil, 1),
	} {
		if bytes.Equal(edited, current) {
			t.Fatalf("%s: the edit changed nothing", name)
		}
		rewrite(edited)
		e.refused(tunnel, notVerified+"host facts receipt is damaged: its digest does not match")
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(current, &doc); err != nil {
		t.Fatal(err)
	}
	delete(doc, "cilium")
	without, _ := json.Marshal(doc)
	rewrite(without)
	e.refused(tunnel, notVerified+"host facts receipt is damaged")
	// Oversized.
	rewrite(append(append([]byte{}, current...), bytes.Repeat([]byte(" "), 256<<10)...))
	e.refused(tunnel, "not a bounded regular file")

	// A receipt sealed on another node, by another manager, for a Cilium that
	// excludes the range.
	other := newCiliumE2E(t, ciliumB)
	otherManager := newE2EManager(t, other.stateDir, "another-worker", e2eOwnerUID, k8snetprep.NewHostFactsReader(other.rules.managerNFT, other.rules.managerIPTables, other.rules.managerIPSet))
	otherManager.SetCiliumFactsReader(other.agent.reader())
	if err := otherManager.ReconcileOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	foreign, err := os.ReadFile(other.receiptPath())
	if err != nil {
		t.Fatal(err)
	}
	rewrite(foreign)
	e.refused(tunnel, notVerified+"host facts receipt is from another node")

	rewrite(current)
	e.ready(tunnel, proved)

	// A manager from before K8N-2 publishes the receipt without the section.
	e.manager.SetCiliumFactsReader(nil)
	e.pass()
	e.refused(tunnel, "Cilium masquerade on this node is not verified: the host-posture manager published no Cilium facts (found iptables chain CILIUM_")
	e.manager.SetCiliumFactsReader(e.agent.reader())
	e.pass()
	e.ready(tunnel, proved)
}

// The live halves run the same two parties on a real Cilium node, each in its
// own pod: see docs/K8N-2-cilium.md, "Live check". They are skipped unless
// asked for, and they change nothing on the node but the state directory they
// are given.
//
//	TUNNEX_TEST_CILIUM_LIVE=manager|gateway
//	TUNNEX_TEST_HOST_FACTS_STATE_DIR, _NODE, _OWNER_UID
//	TUNNEX_TEST_HOST_FACTS_SECONDS  how long to run (both roles)
//	gateway: TUNNEX_TEST_HOST_FACTS_TUNNEL, a comma-separated list of ranges
//
// Both log only when what they see changes, with the wall-clock time, so the
// two logs can be laid beside the time a change was made in the cluster.
func liveCiliumEnv(t *testing.T, role string) (stateDir, node, ownerUID string, run time.Duration) {
	t.Helper()
	if os.Getenv("TUNNEX_TEST_CILIUM_LIVE") != role {
		t.Skip("live Cilium " + role + " not requested")
	}
	stateDir, node, ownerUID = os.Getenv("TUNNEX_TEST_HOST_FACTS_STATE_DIR"), os.Getenv("TUNNEX_TEST_HOST_FACTS_NODE"), os.Getenv("TUNNEX_TEST_HOST_FACTS_OWNER_UID")
	if stateDir == "" || node == "" || ownerUID == "" {
		t.Fatal("state directory, node and owner UID are required")
	}
	seconds := 60
	if value := os.Getenv("TUNNEX_TEST_HOST_FACTS_SECONDS"); value != "" {
		if _, err := fmt.Sscanf(value, "%d", &seconds); err != nil {
			t.Fatal(err)
		}
	}
	return stateDir, node, ownerUID, time.Duration(seconds) * time.Second
}

func liveStamp() string { return time.Now().UTC().Format("15:04:05.000") }

func TestLiveCiliumManager(t *testing.T) {
	stateDir, node, ownerUID, run := liveCiliumEnv(t, "manager")
	// The real readers with the real, closed runners.
	manager := newE2EManager(t, stateDir, node, ownerUID, k8snetprep.NewHostFactsReader(nil, nil, nil))
	manager.SetCiliumFactsReader(k8snetprep.NewCiliumFactsReader(nil, nil, nil, nil))
	store, err := hostposture.OpenStore(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(run)
	last := ""
	var slowest time.Duration
	passes := 0
	for pass := 1; time.Now().Before(deadline); pass++ {
		started := time.Now()
		if err := manager.ReconcileOnce(t.Context()); err != nil {
			t.Fatalf("pass %d: %v", pass, err)
		}
		took := time.Since(started)
		if took > slowest {
			slowest = took
		}
		passes = pass
		receipt, err := store.LoadHostFacts()
		if err != nil {
			t.Fatalf("pass %d: %v", pass, err)
		}
		encoded, _ := json.Marshal(struct {
			Cilium    *k8snetprep.CiliumFacts `json:"cilium"`
			Netfilter k8snetprep.HostNetFacts `json:"netfilter"`
		}{receipt.Cilium, receipt.Netfilter})
		if string(encoded) != last {
			last = string(encoded)
			info, _ := os.Stat(filepath.Join(stateDir, "host-facts.json"))
			fmt.Printf("%s MANAGER pass %d took %s, sequence %d, receipt %d bytes: %s\n", liveStamp(), pass, took.Round(time.Millisecond), receipt.Sequence, info.Size(), encoded)
		}
		time.Sleep(hostposture.DefaultReconcileInterval)
	}
	fmt.Printf("%s MANAGER done: %d passes, slowest %s\n", liveStamp(), passes, slowest.Round(time.Millisecond))
}

func TestLiveCiliumGateway(t *testing.T) {
	stateDir, node, ownerUID, run := liveCiliumEnv(t, "gateway")
	tunnels := strings.Split(os.Getenv("TUNNEX_TEST_HOST_FACTS_TUNNEL"), ",")
	if len(tunnels) == 0 || tunnels[0] == "" {
		t.Fatal("at least one tunnel range is required")
	}
	// One reconciler per range, as one gateway has one range. Real nft; the
	// real iptables-nft-save and ipset runners, which this container cannot
	// use and which the facts path must not need.
	gateways := map[string]*k8snetprep.Reconciler{}
	for _, tunnel := range tunnels {
		gateways[tunnel] = newE2EGateway(t, stateDir, node, ownerUID, nil, nil)
	}
	last := map[string]string{}
	deadline := time.Now().Add(run)
	for time.Now().Before(deadline) {
		for _, tunnel := range tunnels {
			status, err := gateways[tunnel].Reconcile(t.Context(), tunnel)
			state := "READY"
			detail, _ := json.Marshal(status.Adapters)
			if err != nil {
				state, detail = "NOT READY", []byte(status.Host.Reason)
			}
			line := fmt.Sprintf("%s %s: %s", tunnel, state, detail)
			if line != last[tunnel] {
				last[tunnel] = line
				fmt.Printf("%s GATEWAY %s\n", liveStamp(), line)
			}
		}
		time.Sleep(time.Second)
	}
}
