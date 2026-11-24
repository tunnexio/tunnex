//go:build linux

package egress

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tunnexio/tunnex/apps/node/internal/hostposture"
	"github.com/tunnexio/tunnex/apps/node/internal/k8snetprep"
	"github.com/tunnexio/tunnex/apps/node/internal/nodepolicy"
)

// TestCiliumServiceReachKernel is the opt-in helper of K8N-6 (docs/K8N-6-cilium-service-reach.md). It
// loads the REAL Manager rendering for a gateway whose compiled policy is enforcing and EMPTY (no access
// rule) into the network namespace it runs in, through real `nft -f`, and leaves it there for probes run
// from outside the test. It is meant to run on a disposable kind node, in a privileged container that
// shares the node's network namespace, with a WireGuard interface `wg0` already up:
//
//	TUNNEX_TEST_F10_KERNEL=1 TUNNEX_TEST_F10_OUT=<dir> ./egress.test -test.run '^TestCiliumServiceReachKernel$' -test.v
//
// It never removes what it loaded; the probes need the table in force. With TUNNEX_TEST_F10_OUT it writes
// the rendered ruleset and the kernel's JSON listing, which is how
// walk-artifacts/k8n6-cilium-service-reach-20261124/k8n6-cilium-service-reach.{rendered.nft,nft-ruleset.json} were produced.
func TestCiliumServiceReachKernel(t *testing.T) {
	if os.Getenv("TUNNEX_TEST_F10_KERNEL") != "1" {
		t.Skip("opt in on a disposable node: it replaces the ip/ip6 tunnex tables of this network namespace")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()

	m := New("wg0")
	m.SetKubernetesMode(true)
	m.SetKubernetesCNIAuthority(func(context.Context) (k8snetprep.AuthorityGrant, func(), error) {
		return k8snetprep.AuthorityGrant{Scope: k8snetprep.ScopeIPMasqAndAWS, NotAfter: time.Now().Add(k8snetprep.CNIOperationBudget)}, func() {}, nil
	}, nil, nil)
	// Enforcing, no access rule. Never nil: nil is the legacy mesh, which accepts everything from wg0.
	policy := &nodepolicy.Compiled{Version: 7, NodeID: "k8n6-gateway", Mode: "enforcing", Mesh: false}
	m.SetPolicy(policy)

	// Reconcile applies the table before the host/CNI check runs, so a refusal of that check (expected
	// here: no host-posture receipt is configured) leaves the table in force. It is recorded, not fatal.
	_, _, reconcileErr := m.Reconcile(ctx)
	t.Logf("F10_RECONCILE err=%v k8s_netprep_ready=%v", reconcileErr, m.K8sNetPrepReady())

	forward, err := nftRun(ctx, "-a", "list", "chain", "ip", "tunnex", "forward")
	if err != nil {
		t.Fatalf("the tunnex forward chain is not in the kernel: %v", err)
	}
	if !strings.Contains(forward, "policy drop") || !strings.Contains(forward, "tunnex_default_drop") {
		t.Fatalf("not the enforcing default-deny chain:\n%s", forward)
	}
	for _, line := range strings.Split(forward, "\n") {
		if strings.Contains(line, `iifname "wg0"`) && strings.Contains(line, "accept") {
			t.Fatalf("an accept for traffic from wg0 is in the chain of an empty policy: %s\n%s", line, forward)
		}
	}
	t.Logf("F10_FORWARD_CHAIN\n%s", forward)

	if dir := os.Getenv("TUNNEX_TEST_F10_OUT"); dir != "" {
		subnet, err := m.observeWGSubnet(ctx)
		if err != nil {
			t.Fatal(err)
		}
		listing, err := nftRun(ctx, "-j", "-a", "list", "ruleset")
		if err != nil {
			t.Fatal(err)
		}
		for file, content := range map[string]string{
			"k8n6-cilium-service-reach.rendered.nft":     m.rulesetWith(subnet, policy),
			"k8n6-cilium-service-reach.nft-ruleset.json": listing,
		} {
			if err := os.WriteFile(filepath.Join(dir, file), []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	t.Log("F10_EMPTY_POLICY_TABLE_IN_FORCE")
}

// TestCiliumHostRoutingGrantKernel is the opt-in helper of the K8N-6 follow-up (docs/K8N-2-cilium.md, "Host
// routing — decision, 2026-11-24"). It drives the REAL Manager, in Kubernetes mode, with:
//
//   - the real CNI authority, host facts and Cilium facts of a host-posture state directory, as the agent wires
//     them (the receipt is published by a real host-posture manager running beside it, for example
//     k8snetprep's TestLiveCiliumManager), so K8sNetPrepReady is the real decision on the live node;
//   - a compiled policy that grants one device one exposed Service: an access rule for the Service's VIP and
//     the VIP mapping, DNATed by the Manager to the one ready endpoint given here (the endpoint list stands in
//     for the EndpointSlice watch, which needs the API server).
//
// It reconciles every two seconds for TUNNEX_TEST_HR_SECONDS and logs each change of readiness with the
// wall-clock time. Like TestCiliumServiceReachKernel it leaves the table in force for probes run from
// outside. It is skipped unless opted in:
//
//	TUNNEX_TEST_HR_KERNEL=1
//	TUNNEX_TEST_HR_STATE_DIR, _NODE, _OWNER_UID  the host-posture state directory and its identity
//	TUNNEX_TEST_HR_DEVICE                         the device's tunnel address, e.g. 10.99.0.2
//	TUNNEX_TEST_HR_VIP, _SERVICE, _PORT, _TARGET  e.g. 10.98.0.10, default/web-cip, 80, 10.244.0.35:8080
//	TUNNEX_TEST_HR_SECONDS                        how long to keep reconciling (default 30)
//	TUNNEX_TEST_HR_OUT                            optional: write the rendered ruleset and the kernel listing
func TestCiliumHostRoutingGrantKernel(t *testing.T) {
	if os.Getenv("TUNNEX_TEST_HR_KERNEL") != "1" {
		t.Skip("opt in on a disposable node: it replaces the ip/ip6 tunnex tables of this network namespace")
	}
	env := func(name string) string {
		value := os.Getenv("TUNNEX_TEST_HR_" + name)
		if value == "" && name != "OUT" && name != "SECONDS" {
			t.Fatalf("TUNNEX_TEST_HR_%s is required", name)
		}
		return value
	}
	stateDir, node, owner := env("STATE_DIR"), env("NODE"), env("OWNER_UID")
	device, vip, service, target := env("DEVICE"), env("VIP"), env("SERVICE"), env("TARGET")
	port, err := strconv.Atoi(env("PORT"))
	if err != nil {
		t.Fatal(err)
	}
	namespace, name, ok := strings.Cut(service, "/")
	if !ok {
		t.Fatal("TUNNEX_TEST_HR_SERVICE is namespace/name")
	}
	targetIP, targetPortText, ok := strings.Cut(target, ":")
	targetPort, perr := strconv.Atoi(targetPortText)
	if !ok || perr != nil {
		t.Fatal("TUNNEX_TEST_HR_TARGET is ip:port")
	}
	seconds := 30
	if value := env("SECONDS"); value != "" {
		if seconds, err = strconv.Atoi(value); err != nil {
			t.Fatal(err)
		}
	}

	store, err := hostposture.OpenStore(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	m := New("wg0")
	m.SetKubernetesMode(true)
	m.SetKubernetesCNIAuthority(func(ctx context.Context) (k8snetprep.AuthorityGrant, func(), error) {
		return store.AcquireCNIAuthority(ctx, node, owner, time.Now())
	}, func(context.Context) (k8snetprep.HostNetFacts, error) {
		return store.HostNetFacts(node, time.Now())
	}, func(context.Context) (*k8snetprep.CiliumFacts, error) {
		return store.CiliumFacts(node, time.Now())
	})
	m.SetEndpointSource(&fakeSource{m: map[string]fakeEntry{
		namespace + "/" + name: {ok: true, targets: []k8sTarget{{ip: targetIP, port: targetPort}}},
	}})
	policy := &nodepolicy.Compiled{
		Version: 7, NodeID: "k8n6-gateway", Mode: nodepolicy.ModeEnforcing,
		Allow: []nodepolicy.AllowEntry{{SrcIP: device, DstCIDR: vip + "/32", Protocol: "tcp", PortLow: port, PortHigh: port}},
		VIPMappings: []nodepolicy.VIPMapping{{VIP: vip, Namespace: namespace, Service: name, Protocol: "tcp", PortLow: port, PortHigh: port}},
	}
	m.SetPolicy(policy)

	last := ""
	deadline := time.Now().Add(time.Duration(seconds) * time.Second)
	for first := true; first || time.Now().Before(deadline); first = false {
		ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
		m.ResolveK8sVIPs(ctx)
		_, _, reconcileErr := m.Reconcile(ctx)
		cancel()
		summary := ""
		if p := m.k8sNetPrepStatus.Load(); p != nil {
			summary = *p
		}
		resolved := 0
		if p := m.resolvedVIPs.Load(); p != nil {
			resolved = len(*p)
		}
		line := fmt.Sprintf("ready=%v resolved_vips=%d reconcile_err=%v status=%s", m.K8sNetPrepReady(), resolved, reconcileErr, summary)
		if line != last {
			last = line
			fmt.Printf("%s HR_GATEWAY %s\n", time.Now().UTC().Format("15:04:05.000"), line)
		}
		time.Sleep(2 * time.Second)
	}

	ctx := t.Context()
	forward, err := nftRun(ctx, "-a", "list", "chain", "ip", "tunnex", "forward")
	if err != nil {
		t.Fatalf("the tunnex forward chain is not in the kernel: %v", err)
	}
	t.Logf("HR_FORWARD_CHAIN\n%s", forward)
	if dir := os.Getenv("TUNNEX_TEST_HR_OUT"); dir != "" {
		subnet, err := m.observeWGSubnet(ctx)
		if err != nil {
			t.Fatal(err)
		}
		listing, err := nftRun(ctx, "-j", "-a", "list", "ruleset")
		if err != nil {
			t.Fatal(err)
		}
		for file, content := range map[string]string{
			"k8n6-host-routing-grant.rendered.nft":     m.rulesetWith(subnet, policy),
			"k8n6-host-routing-grant.nft-ruleset.json": listing,
		} {
			if err := os.WriteFile(filepath.Join(dir, file), []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	t.Log("HR_GRANT_TABLE_IN_FORCE")
}
