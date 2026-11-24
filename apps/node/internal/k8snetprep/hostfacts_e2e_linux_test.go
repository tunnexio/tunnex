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

// K8N-1, Decision 9, end to end: the real host-posture manager publishes what
// it read into a real state directory, and a real gateway reconciler, whose
// own iptables-nft-save and ipset fail as they do without NET_RAW, becomes
// ready from that directory alone.
//
// The node is the captured Calico v3.31.2 one (testdata/README.md). Only the
// Kubernetes API and the kernel mutations of the manager are replaced.

const (
	e2eNode     = "calico-worker"
	e2eOwnerUID = "11111111-2222-3333-4444-555555555555"
	e2eMasqSet  = "cali40masq-ipam-pools"
)

type nftEntry = map[string]json.RawMessage

// capturedNode is the node both parties look at.
type capturedNode struct {
	t       *testing.T
	entries []nftEntry
	nat     string
	mangle  string
	sets    map[string]string

	managerRan []string
	gatewayRan []string
}

func captured(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile("testdata/calico-v3.31.2-kind." + name)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func newCapturedNode(t *testing.T) *capturedNode {
	t.Helper()
	var doc struct {
		NFTables []nftEntry `json:"nftables"`
	}
	if err := json.Unmarshal([]byte(captured(t, "nft.json")), &doc); err != nil {
		t.Fatal(err)
	}
	return &capturedNode{
		t: t, entries: doc.NFTables,
		nat: captured(t, "iptables-nft-save.txt"), mangle: captured(t, "iptables-nft-save-mangle.txt"),
		sets: map[string]string{e2eMasqSet: captured(t, "ipset-"+e2eMasqSet+".txt")},
	}
}

func (n *capturedNode) listing(keep func(nftEntry) bool) string {
	out := []nftEntry{}
	for _, entry := range n.entries {
		if keep == nil || keep(entry) {
			out = append(out, entry)
		}
	}
	encoded, err := json.Marshal(map[string]any{"nftables": out})
	if err != nil {
		n.t.Fatal(err)
	}
	return string(encoded)
}

type nftName struct {
	Family string `json:"family"`
	Table  string `json:"table"`
	Name   string `json:"name"`
	Chain  string `json:"chain"`
}

// The manager's commands: every one succeeds, as in the privileged container.
func (n *capturedNode) managerNFT(_ context.Context, args ...string) (string, error) {
	n.managerRan = append(n.managerRan, "nft "+strings.Join(args, " "))
	if strings.Join(args, " ") == "-j -a list tables" {
		return n.listing(func(entry nftEntry) bool { _, ok := entry["table"]; return ok }), nil
	}
	if len(args) != 7 || strings.Join(args[:5], " ") != "-j -a list chain ip" {
		return "", errors.New("manager ran an nft command that is not a table or chain listing")
	}
	found := false
	out := n.listing(func(entry nftEntry) bool {
		var name nftName
		if raw, ok := entry["chain"]; ok && json.Unmarshal(raw, &name) == nil && name.Family == "ip" && name.Table == args[5] && name.Name == args[6] {
			found = true
			return true
		}
		if raw, ok := entry["rule"]; ok && json.Unmarshal(raw, &name) == nil && name.Family == "ip" && name.Table == args[5] && name.Chain == args[6] {
			return true
		}
		return false
	})
	if !found {
		return "", errors.New("exit status 1: Error: No such file or directory")
	}
	return out, nil
}

func (n *capturedNode) managerIPTables(_ context.Context, args ...string) (string, error) {
	n.managerRan = append(n.managerRan, "iptables-nft-save "+strings.Join(args, " "))
	switch strings.Join(args, " ") {
	case "-V":
		return "iptables-nft-save v1.8.13 (nf_tables)\n", nil
	case "-t nat":
		return n.nat, nil
	case "-t mangle":
		return n.mangle, nil
	}
	return "", errors.New("unexpected iptables-nft-save command")
}

func (n *capturedNode) managerIPSet(_ context.Context, args ...string) (string, error) {
	n.managerRan = append(n.managerRan, "ipset "+strings.Join(args, " "))
	if strings.Join(args, " ") == "list -n" {
		names := ""
		for name := range n.sets {
			names += name + "\n"
		}
		return names, nil
	}
	if len(args) == 2 && args[0] == "save" {
		if out, ok := n.sets[args[1]]; ok {
			return out, nil
		}
		return "", errors.New("exit status 1: The set with the given name does not exist")
	}
	return "", errors.New("unexpected ipset command")
}

// The gateway's commands: nft lists; everything else fails as on the real node
// without NET_RAW, and is recorded so the test can show it was never tried.
func (n *capturedNode) gatewayNFT(_ context.Context, args ...string) (string, error) {
	n.gatewayRan = append(n.gatewayRan, "nft "+strings.Join(args, " "))
	if strings.Join(args, " ") != "-j -a list ruleset" {
		return "", errors.New("gateway ran an nft command that is not the ruleset listing")
	}
	return n.listing(nil), nil
}

func (n *capturedNode) gatewayDenied(tool string) func(context.Context, ...string) (string, error) {
	return func(_ context.Context, args ...string) (string, error) {
		n.gatewayRan = append(n.gatewayRan, "DENIED "+tool+" "+strings.Join(args, " "))
		return "", errors.New("exit status 1: Can't open socket to ipset.")
	}
}

// replaceRule gives one rule of a chain a new handle, as a controller does
// when it writes the same rule again.
func (n *capturedNode) replaceRule(table, chain string) {
	for i, entry := range n.entries {
		raw, ok := entry["rule"]
		if !ok {
			continue
		}
		var rule map[string]any
		if err := json.Unmarshal(raw, &rule); err != nil {
			n.t.Fatal(err)
		}
		if rule["table"] == table && rule["chain"] == chain {
			rule["handle"] = rule["handle"].(float64) + 100000
			encoded, _ := json.Marshal(rule)
			n.entries[i] = nftEntry{"rule": encoded}
			return
		}
	}
	n.t.Fatalf("no rule in %s %s", table, chain)
}

// recreateTable gives one ip table a new handle and leaves every chain and rule
// handle as it was, which is what deleting a table and building it again the
// same way produces.
func (n *capturedNode) recreateTable(name string) {
	for i, entry := range n.entries {
		raw, ok := entry["table"]
		if !ok {
			continue
		}
		var table map[string]any
		if err := json.Unmarshal(raw, &table); err != nil {
			n.t.Fatal(err)
		}
		if table["family"] == "ip" && table["name"] == name {
			table["handle"] = table["handle"].(float64) + 1000
			encoded, _ := json.Marshal(table)
			n.entries[i] = nftEntry{"table": encoded}
			return
		}
	}
	n.t.Fatalf("no ip %s table", name)
}

type oneOwner struct{ uid string }

func (o oneOwner) List(context.Context, string, int) ([]hostposture.Owner, error) {
	return []hostposture.Owner{{UID: o.uid, Namespace: "tunnex-system", Name: "gw-a"}}, nil
}

// inertKernel records the manager's journal steps and touches no host state.
type inertKernel struct{}

func (inertKernel) CaptureBaseline(context.Context, string) ([]hostposture.SysctlReceipt, error) {
	return []hostposture.SysctlReceipt{
		{Key: "net/ipv4/ip_forward", Original: "1", Desired: "1"},
		{Key: "net/ipv4/conf/all/rp_filter", Original: "0", Desired: "0"},
		{Key: "net/ipv4/conf/default/rp_filter", Original: "0", Desired: "0"},
	}, nil
}

func (inertKernel) Prepare(_ context.Context, journal *hostposture.Journal, _ func(*hostposture.Journal) error) error {
	if journal.State == hostposture.StateActive {
		return nil
	}
	wg := &journal.Artifacts.WireGuard
	wg.StagingIfIndex, wg.IfIndex, wg.Phase = 41, 41, hostposture.WireGuardPhaseCommitted
	return nil
}
func (inertKernel) Enforce(context.Context, hostposture.Journal) error { return nil }
func (inertKernel) RestoreAndCleanup(_ context.Context, journal *hostposture.Journal) error {
	for i := range journal.Sysctls {
		journal.Sysctls[i].Restored = true
	}
	return nil
}

func newE2EManager(t *testing.T, stateDir, node, ownerUID string, reader hostposture.HostFactsReader) *hostposture.Manager {
	t.Helper()
	store, err := hostposture.NewStore(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := hostposture.NewManager(hostposture.Config{
		NodeName: node, ManagerUID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
	}, oneOwner{ownerUID}, inertKernel{}, store, nil)
	if err != nil {
		t.Fatal(err)
	}
	manager.SetHostFactsReader(reader)
	return manager
}

// newE2EGateway builds the reconciler exactly as the agent does in Kubernetes
// mode: authority and facts both come from the read-only state directory.
func newE2EGateway(t *testing.T, stateDir, node, ownerUID string, nft k8snetprep.NFTRunner, iptables k8snetprep.IPTablesRunner) *k8snetprep.Reconciler {
	t.Helper()
	store, err := hostposture.OpenStore(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	r := k8snetprep.NewWithAWS("wg0", nft, iptables, func(ctx context.Context) (k8snetprep.AuthorityGrant, func(), error) {
		return store.AcquireCNIAuthority(ctx, node, ownerUID, time.Now())
	})
	r.UseHostFacts(func(context.Context) (k8snetprep.HostNetFacts, error) {
		return store.HostNetFacts(node, time.Now())
	})
	r.UseCiliumFacts(func(context.Context) (*k8snetprep.CiliumFacts, error) {
		return store.CiliumFacts(node, time.Now())
	})
	// The rp_filter read-back is not what this test is about.
	procSys := t.TempDir()
	path := filepath.Join(procSys, "net", "ipv4", "conf", "wg0", "rp_filter")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("0"), 0o600); err != nil {
		t.Fatal(err)
	}
	r.SetProcSysForTest(procSys)
	return r
}

func TestCapturedCalicoNodeBecomesReadyThroughTheHostFactsReceipt(t *testing.T) {
	node := newCapturedNode(t)
	stateDir := filepath.Join(t.TempDir(), "v1")
	reader := k8snetprep.NewHostFactsReader(node.managerNFT, node.managerIPTables, node.managerIPSet)
	sysModule := t.TempDir()
	if err := os.Mkdir(filepath.Join(sysModule, "ip_set"), 0o755); err != nil {
		t.Fatal(err)
	}
	reader.SetSysModuleForTest(sysModule)
	reader.SetProcNetForTest(e2eNoLegacyProcNet(t))
	manager := newE2EManager(t, stateDir, e2eNode, e2eOwnerUID, reader)
	gateway := newE2EGateway(t, stateDir, e2eNode, e2eOwnerUID, node.gatewayNFT, node.gatewayDenied("iptables-nft-save"))
	gateway.SetIPSetRunnerForTest(node.gatewayDenied("ipset"))
	receiptPath := filepath.Join(stateDir, "host-facts.json")

	pass := func() {
		t.Helper()
		if err := manager.ReconcileOnce(t.Context()); err != nil {
			t.Fatalf("manager pass: %v", err)
		}
	}
	ready := func(tunnel string) k8snetprep.ReconcileStatus {
		t.Helper()
		status, err := gateway.Reconcile(t.Context(), tunnel)
		if err != nil {
			t.Fatalf("gateway was refused for %s: %+v %v", tunnel, status, err)
		}
		adapter := status.Adapters[0]
		want := k8snetprep.ReasonObservedNoTunnelSourceNAT + "; masquerade sources are limited by sets outside it: " + e2eMasqSet
		if status.Host.State != k8snetprep.StateReady || adapter.Name != k8snetprep.ObservedAdapterName || adapter.State != k8snetprep.StateReady || adapter.Reason != want {
			t.Fatalf("status = %+v", status)
		}
		return status
	}
	refused := func(tunnel, want string) {
		t.Helper()
		status, err := gateway.Reconcile(t.Context(), tunnel)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("for %s: status %+v, error %v, want %q", tunnel, status, err, want)
		}
		if status.Host.State != k8snetprep.StateBlocked || !strings.Contains(status.Host.Reason, want) {
			t.Fatalf("refusal does not carry its reason: %+v", status)
		}
		for _, adapter := range status.Adapters {
			if adapter.State == k8snetprep.StateReady {
				t.Fatalf("refused gateway reports a ready adapter: %+v", status)
			}
		}
	}

	// Before the manager has run there is nothing to trust.
	if _, err := gateway.Reconcile(t.Context(), "100.96.0.0/24"); err == nil {
		t.Fatal("gateway became ready with no manager")
	}
	pass()
	// One heartbeat is not yet authority; the receipt alone admits nothing.
	refused("100.96.0.0/24", "awaits two advancing exact-owner heartbeats")
	pass()

	ready("100.96.0.0/24")
	refused("192.168.7.0/24", "masquerades sources in set "+e2eMasqSet+", which overlaps the tunnel range 192.168.7.0/24")
	refused("192.168.0.0/16", "overlaps the tunnel range")

	// The gateway ran nothing but its own listings, two around every take.
	for _, command := range node.gatewayRan {
		if command != "nft -j -a list ruleset" {
			t.Fatalf("gateway ran %q; all: %v", command, node.gatewayRan)
		}
	}
	// The manager never listed the whole ruleset and read exactly one set.
	for _, command := range node.managerRan {
		if strings.Contains(command, "list ruleset") || (strings.HasPrefix(command, "ipset save ") && command != "ipset save "+e2eMasqSet) {
			t.Fatalf("manager ran %q", command)
		}
	}

	// What is on disk: a public, bounded file with rule text and set members.
	body, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(receiptPath)
	if info.Mode().Perm() != 0o644 || len(body) > 8<<10 {
		t.Fatalf("receipt mode %v, %d bytes", info.Mode(), len(body))
	}
	for _, want := range []string{`"contract":"tunnex-host-posture-facts/v1"`, `"node_name":"` + e2eNode + `"`, "--match-set cali40masq-ipam-pools src", "--set-xmark 0x0/0x1b0000", "add cali40masq-ipam-pools 192.168.0.0/16"} {
		if !bytes.Contains(body, []byte(want)) {
			t.Errorf("receipt lacks %q", want)
		}
	}
	if bytes.Contains(body, []byte(e2eOwnerUID)) || bytes.Contains(body, []byte("100.96.0.0")) || bytes.Contains(body, []byte("KUBE-SVC")) {
		t.Errorf("receipt carries more than the facts: %s", body)
	}

	// Missing receipt: not ready, and the reason says so.
	if err := os.Remove(receiptPath); err != nil {
		t.Fatal(err)
	}
	refused("100.96.0.0/24", "host-posture facts: host facts receipt is missing")
	pass()
	ready("100.96.0.0/24")

	// The receipt of an earlier pass is not the receipt of the live heartbeat.
	earlier, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	pass()
	current, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	rewrite := func(content []byte) {
		t.Helper()
		if err := os.WriteFile(receiptPath, content, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	rewrite(earlier)
	refused("100.96.0.0/24", "host facts receipt does not belong to the live heartbeat")

	// Truncated, edited, oversized.
	rewrite(current[:len(current)/2])
	refused("100.96.0.0/24", "host-posture facts: read host facts receipt")
	rewrite(bytes.Replace(current, []byte("add cali40masq-ipam-pools 192.168.0.0/16"), []byte("add cali40masq-ipam-pools 192.168.0.0/24"), 1))
	refused("100.96.0.0/24", "host facts receipt is damaged")
	rewrite(bytes.Replace(current, []byte("cali40masq-ipam-pools src"), []byte("cali40masq-ipam-pools dst"), 1))
	refused("100.96.0.0/24", "host facts receipt is damaged")
	rewrite(append(append([]byte{}, current...), bytes.Repeat([]byte(" "), 256<<10)...))
	refused("100.96.0.0/24", "not a bounded regular file")

	// A receipt sealed for another node, by another manager, in its own directory.
	otherDir := filepath.Join(t.TempDir(), "v1")
	other := newE2EManager(t, otherDir, "another-worker", e2eOwnerUID, reader)
	if err := other.ReconcileOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	foreign, err := os.ReadFile(filepath.Join(otherDir, "host-facts.json"))
	if err != nil {
		t.Fatal(err)
	}
	rewrite(foreign)
	refused("100.96.0.0/24", "host facts receipt is from another node")

	rewrite(current)
	ready("100.96.0.0/24")

	// Calico writes its masquerade rule again after the manager's read: the
	// same words under a new handle. The gateway refuses until the next pass.
	node.replaceRule("nat", "cali-nat-outgoing")
	refused("100.96.0.0/24", "nat chain cali-nat-outgoing changed after the host-posture manager read it")
	pass()
	ready("100.96.0.0/24")

	// The mangle table is deleted and built again exactly as it was: every
	// chain and rule handle repeats, only the table's own handle is new.
	node.recreateTable("mangle")
	refused("100.96.0.0/24", "mangle chain cali-POSTROUTING changed after the host-posture manager read it")
	pass()
	ready("100.96.0.0/24")

	// A pool that covers the device range appears: the next pass carries it,
	// and the gateway refuses and names the set.
	node.sets[e2eMasqSet] += "add " + e2eMasqSet + " 100.64.0.0/10\n"
	pass()
	refused("100.96.0.0/24", "masquerades sources in set "+e2eMasqSet+", which overlaps the tunnel range 100.96.0.0/24")

	// Nothing above ever made the gateway try what it cannot run.
	for _, command := range node.gatewayRan {
		if strings.HasPrefix(command, "DENIED") {
			t.Fatalf("gateway tried %q", command)
		}
	}
}

// The live halves below run the same two parties on a real node, each in its
// own pod: see docs/K8N-1-calico.md, Decision 9. They are skipped unless asked
// for, and they change nothing on the node but the state directory they are
// given.
//
//	TUNNEX_TEST_HOST_FACTS_LIVE=manager|gateway
//	TUNNEX_TEST_HOST_FACTS_STATE_DIR, _NODE, _OWNER_UID
//	manager: TUNNEX_TEST_HOST_FACTS_SECONDS (how long to keep publishing)
//	gateway: TUNNEX_TEST_HOST_FACTS_TUNNEL, TUNNEX_TEST_HOST_FACTS_WANT
//	         ("ready", or a part of the refusal that is expected)
func liveHostFactsEnv(t *testing.T, role string) (stateDir, node, ownerUID string) {
	t.Helper()
	if os.Getenv("TUNNEX_TEST_HOST_FACTS_LIVE") != role {
		t.Skip("live host-facts " + role + " not requested")
	}
	stateDir, node, ownerUID = os.Getenv("TUNNEX_TEST_HOST_FACTS_STATE_DIR"), os.Getenv("TUNNEX_TEST_HOST_FACTS_NODE"), os.Getenv("TUNNEX_TEST_HOST_FACTS_OWNER_UID")
	if stateDir == "" || node == "" || ownerUID == "" {
		t.Fatal("state directory, node and owner UID are required")
	}
	return stateDir, node, ownerUID
}

func TestLiveHostFactsManager(t *testing.T) {
	stateDir, node, ownerUID := liveHostFactsEnv(t, "manager")
	seconds := 60
	if _, err := fmt.Sscanf(os.Getenv("TUNNEX_TEST_HOST_FACTS_SECONDS"), "%d", &seconds); err != nil && os.Getenv("TUNNEX_TEST_HOST_FACTS_SECONDS") != "" {
		t.Fatal(err)
	}
	// The real reader with the real, closed runners.
	manager := newE2EManager(t, stateDir, node, ownerUID, k8snetprep.NewHostFactsReader(nil, nil, nil))
	store, err := hostposture.OpenStore(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Duration(seconds) * time.Second)
	last := ""
	for pass := 1; time.Now().Before(deadline); pass++ {
		started := time.Now()
		if err := manager.ReconcileOnce(t.Context()); err != nil {
			t.Fatalf("pass %d: %v", pass, err)
		}
		receipt, err := store.LoadHostFacts()
		if err != nil {
			t.Fatalf("pass %d: %v", pass, err)
		}
		encoded, _ := json.Marshal(receipt.Netfilter)
		if string(encoded) != last {
			last = string(encoded)
			t.Logf("pass %d took %s, sequence %d, facts: %s", pass, time.Since(started).Round(time.Millisecond), receipt.Sequence, encoded)
		}
		time.Sleep(hostposture.DefaultReconcileInterval)
	}
}

func TestLiveHostFactsGateway(t *testing.T) {
	stateDir, node, ownerUID := liveHostFactsEnv(t, "gateway")
	tunnel, want := os.Getenv("TUNNEX_TEST_HOST_FACTS_TUNNEL"), os.Getenv("TUNNEX_TEST_HOST_FACTS_WANT")
	if tunnel == "" || want == "" {
		t.Fatal("tunnel range and expectation are required")
	}
	// Real nft, and the real iptables-nft-save and ipset runners, which this
	// container cannot use and which the facts path must not need.
	gateway := newE2EGateway(t, stateDir, node, ownerUID, nil, nil)
	var status k8snetprep.ReconcileStatus
	var err error
	for attempt := 0; attempt < 40; attempt++ {
		status, err = gateway.Reconcile(t.Context(), tunnel)
		// Authority needs two advancing heartbeats; wait for those only.
		if err == nil || !strings.Contains(err.Error(), "CNI authority") {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	encoded, _ := json.Marshal(status)
	t.Logf("tunnel %s: error=%v status=%s", tunnel, err, encoded)
	if want == "ready" {
		if err != nil || len(status.Adapters) == 0 || status.Adapters[0].Name != k8snetprep.ObservedAdapterName || status.Adapters[0].State != k8snetprep.StateReady {
			t.Fatalf("gateway is not ready for %s", tunnel)
		}
		return
	}
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("gateway was not refused with %q for %s", want, tunnel)
	}
}

// e2eNoLegacyProcNet is a /proc/net of a node whose ip_tables module is not
// loaded: no ip_tables_names, so no iptables-legacy table.
func e2eNoLegacyProcNet(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "dev"), []byte("Inter-|   Receive\n"), 0o444); err != nil {
		t.Fatal(err)
	}
	return dir
}
