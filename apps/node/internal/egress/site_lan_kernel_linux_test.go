//go:build linux

package egress

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tunnexio/tunnex/apps/node/internal/k8snetprep"
)

// TestSiteLANMasqueradeKernel is the opt-in witness for K8N-5 item 4: SSI-8's site-LAN masquerade on an
// in-cluster gateway. It runs only in a disposable PRIVILEGED Linux container (it creates network
// namespaces and writes sysctls):
//
//	TUNNEX_TEST_SITE_LAN_KERNEL=1 go test ./internal/egress -run '^TestSiteLANMasqueradeKernel$' -v
//
// The real Manager renders through real `nft -f`; the real ownership check (k8snetprep, as wired by
// SetKubernetesCNIAuthority) reads that kernel's `nft -j -a list ruleset`; real packets cross real
// conntrack NAT. A gateway "process" is one run of this test binary in the gateway's namespace, so a
// restart is a new process that finds the previous one's table.
//
// What it is not: a cluster. wg0 is a veth, not WireGuard; the remote site host sits directly on it; the
// pod is a listener in a namespace whose only return route is the host-posture route to the device
// range; there is no CNI, no control plane.
//
// With TUNNEX_TEST_SITE_LAN_OUT=<dir> the first start writes the rendered ruleset and the kernel's JSON
// listing; that is how k8snetprep/testdata/k8n5-site-lan.{rendered.nft,nft-ruleset.json} were produced.
func TestSiteLANMasqueradeKernel(t *testing.T) {
	if os.Getenv("TUNNEX_TEST_SITE_LAN_KERNEL") != "1" {
		t.Skip("opt in inside a disposable privileged Linux container")
	}
	switch phase := os.Getenv("TUNNEX_TEST_SITE_LAN_PHASE"); phase {
	case "":
	case "serve":
		siteLANKernelServe(t)
		return
	case "call":
		siteLANKernelCall(t)
		return
	default:
		siteLANKernelGateway(t, phase)
		return
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 120*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "unshare", "--mount", "--net", "--propagation", "private", "sh", "-eu", "-c", siteLANKernelFixture, "fixture", executable)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("isolated witness failed: %v\n%s", err, out)
	}
	for _, proof := range []string{
		"WITHOUT_THE_RULE_THE_POD_CANNOT_ANSWER",
		"FIRST_START_ACCEPTED",
		"POD_ANSWERS_THE_REMOTE_SITE_VIA_NODE_ADDRESS",
		"RESTART_OVER_LEFTOVER_RULE_ACCEPTED",
		"POD_ANSWERS_AFTER_RESTART",
		"NEAR_MISSES_STILL_REFUSED",
		"OPENVPN_SET_FORM_ACCEPTED",
		"POD_ANSWERS_WITH_OPENVPN_SET",
		"RULE_GONE_WITH_PRESERVE_SOURCE",
		"POD_CANNOT_ANSWER_WITH_PRESERVE_SOURCE",
		"NO_RULE_LEFT_AFTER_SHUTDOWN",
	} {
		if !strings.Contains(string(out), proof) {
			t.Fatalf("missing proof %s\n%s", proof, out)
		}
	}
	t.Logf("isolated evidence:\n%s", out)
}

func siteLANKernelGateway(t *testing.T, phase string) {
	ctx := t.Context()
	nft := func(args ...string) string {
		t.Helper()
		out, err := nftRun(ctx, args...)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	natRules := func() string { return nft("-a", "list", "chain", "ip", "tunnex", "postrouting") }

	m := New("wg0")
	m.SetKubernetesMode(true)
	m.SetKubernetesCNIAuthority(func(context.Context) (k8snetprep.AuthorityGrant, func(), error) {
		return k8snetprep.AuthorityGrant{Scope: k8snetprep.ScopeIPMasqAndAWS, NotAfter: time.Now().Add(k8snetprep.CNIOperationBudget)}, func() {}, nil
	}, kernelTestHostFacts, nil)
	policy := siteLANPolicy()
	if phase == "preserve-source" {
		policy.SiteLANMasquerade = false
	}
	m.SetPolicy(policy)

	// The order of a real start, as in TestK8sAPIReturnPathKernel: desired_state_startup_base, then
	// ownership_startup_withdraw (the OpenVPN stage, fatal on error: the crash loop), then its DNAT stage.
	start := func(tun string) {
		t.Helper()
		m.ResolveK8sVIPs(ctx)
		if _, _, err := m.Reconcile(ctx); err != nil {
			t.Fatalf("desired_state_startup_base, egress pass: %v", err)
		}
		if err := m.ReconcileOVPNTunnel(ctx, tun); err != nil {
			t.Fatalf("ownership_startup_withdraw: reconcile OpenVPN tunnel-ingress rules: %v", err)
		}
		m.ResolveK8sVIPs(ctx)
		if _, _, err := m.Reconcile(ctx); err != nil {
			t.Fatalf("ownership_startup_withdraw: reconcile Kubernetes VIP DNAT: %v", err)
		}
		if !m.K8sNetPrepReady() {
			t.Fatal("the gateway is not ready after a clean start")
		}
	}
	save := func(name string) {
		dir := os.Getenv("TUNNEX_TEST_SITE_LAN_OUT")
		if dir == "" {
			return
		}
		subnet, err := m.observeWGSubnet(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for file, content := range map[string]string{
			name + ".rendered.nft":     m.rulesetWith(subnet, policy),
			name + ".nft-ruleset.json": nft("-j", "-a", "list", "ruleset"),
		} {
			if err := os.WriteFile(filepath.Join(dir, file), []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}

	switch phase {
	case "without-rule":
		// The same table minus the site-LAN line: what a site on preserve_source gets.
		if err := ensureIPForward(); err != nil {
			t.Fatal(err)
		}
		var kept []string
		for _, line := range strings.Split(m.rulesetWith(siteLANTunnel, policy), "\n") {
			if !strings.Contains(line, k8snetprep.SiteLANMasqueradeRuleComment) {
				kept = append(kept, line)
			}
		}
		if err := nftApply(ctx, strings.Join(kept, "\n")); err != nil {
			t.Fatal(err)
		}
	case "first-start":
		start("")
		if rules := natRules(); !strings.Contains(rules, siteLANRule) {
			t.Fatalf("the kernel does not hold the rule as rendered:\n%s", rules)
		}
		save("k8n5-site-lan")
		t.Logf("kernel:\n%s", natRules())
	case "restart":
		leftover := natRules()
		if !strings.Contains(leftover, siteLANRule) {
			t.Fatalf("no leftover rule to restart over:\n%s", leftover)
		}
		// The ownership check alone, on the leftover table, before this process has loaded anything.
		if err := m.ReconcileK8sNetPrep(ctx); err != nil || !m.K8sNetPrepReady() {
			t.Fatalf("the ownership check refused the leftover table: ready=%v err=%v\n%s", m.K8sNetPrepReady(), err, leftover)
		}
		start("")
	case "refuse-near-miss":
		start("")
		marker := k8snetprep.SiteLANMasqueradeRuleComment
		for reason, rule := range map[string][]string{
			"Tunnex site-LAN masquerade does not match one IPv4 source range":   {"ip", "daddr", "10.50.0.0/24", "oifname", "!=", "wg0", "masquerade", "comment", marker},
			"Tunnex site-LAN masquerade is not the exact registered masquerade": {"ip", "saddr", "10.51.0.0/24", "oifname", "!=", "wg0", "masquerade", "random", "comment", marker},
			"Tunnex NAT could bind traffic returning to WireGuard":              {"ip", "saddr", "10.51.0.0/24", "oifname", "!=", "eth0", "masquerade", "comment", marker},
			"Tunnex site-LAN masquerade matches every source":                   {"ip", "saddr", "0.0.0.0/0", "oifname", "!=", "wg0", "masquerade", "comment", marker},
			"Tunnex site-LAN masquerade is duplicated":                          {"ip", "saddr", "10.50.0.0/24", "oifname", "!=", "wg0", "masquerade", "comment", marker},
			"unknown Tunnex source-NAT rule":                                    {"ip", "saddr", "10.99.0.2", "ip", "daddr", "10.60.0.0/24", "counter", "return", "comment", "tunnex_ipsec_desktop_no_snat"},
		} {
			nft(append([]string{"add", "rule", "ip", "tunnex", "postrouting"}, rule...)...)
			err := m.ReconcileK8sNetPrep(ctx)
			if err == nil || !strings.Contains(err.Error(), reason) || m.K8sNetPrepReady() {
				t.Fatalf("a near-miss was not refused as %q: ready=%v err=%v\n%s", reason, m.K8sNetPrepReady(), err, natRules())
			}
			// The next egress pass replaces the table; the foreign rule does not outlive it.
			if _, _, err := m.Reconcile(ctx); err != nil || !m.K8sNetPrepReady() {
				t.Fatalf("the egress pass did not restore the table: ready=%v err=%v", m.K8sNetPrepReady(), err)
			}
		}
	case "openvpn":
		start("tun0")
		want := `ip saddr 10.50.0.0/24 oifname != { "wg0", "tun0" } masquerade comment "tunnex_site_lan_masquerade"`
		if rules := natRules(); !strings.Contains(rules, want) {
			t.Fatalf("the kernel does not hold the set form:\n%s", rules)
		}
	case "preserve-source":
		start("")
		if rules := natRules(); strings.Contains(rules, k8snetprep.SiteLANMasqueradeRuleComment) {
			t.Fatalf("the rule outlived the option:\n%s", rules)
		}
	case "shutdown":
		start("")
		m.Teardown(ctx)
		if table := nft("list", "table", "ip", "tunnex"); strings.Contains(table, "masquerade") || strings.Contains(table, k8snetprep.SiteLANMasqueradeRuleComment) {
			t.Fatalf("shutdown left a NAT rule:\n%s", table)
		}
	default:
		t.Fatalf("unknown phase %q", phase)
	}
	fmt.Printf("PHASE_DONE %s\n", phase)
}

// siteLANKernelServe answers every connection with the address it came from.
func siteLANKernelServe(t *testing.T) {
	listener, err := net.Listen("tcp4", os.Getenv("TUNNEX_TEST_SITE_LAN_ADDR"))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := os.WriteFile(os.Getenv("TUNNEX_TEST_SITE_LAN_READY"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(110 * time.Second)
		listener.Close()
	}()
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
		fmt.Fprintf(conn, "ANSWER from=%s\n", host)
		conn.Close()
	}
}

// siteLANKernelCall is the remote site host: one call, two seconds.
func siteLANKernelCall(t *testing.T) {
	address := os.Getenv("TUNNEX_TEST_SITE_LAN_ADDR")
	conn, err := net.DialTimeout("tcp4", address, 2*time.Second)
	if err != nil {
		t.Fatalf("CALL_FAILED %s: %v", address, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("CALL_FAILED %s: %v", address, err)
	}
	fmt.Printf("CALL_OK %s %s", address, line)
}

const siteLANKernelFixture = `
testbin=$1
run='^TestSiteLANMasqueradeKernel$'
for ns in tnx-gw tnx-site tnx-pod; do
  ip netns add "$ns"
  ip -n "$ns" link set lo up
done
# The site link: a veth between the remote site host and the gateway's wg0.
ip link add tunnel-gw type veth peer name tunnel-site
ip link set tunnel-gw netns tnx-gw
ip -n tnx-gw link set tunnel-gw name wg0
ip link set tunnel-site netns tnx-site
ip -n tnx-site link set tunnel-site name eth0
# The node network: the gateway node and the pod's node.
ip link add gw-node type veth peer name pod-node
ip link set gw-node netns tnx-gw
ip -n tnx-gw link set gw-node name eth0
ip link set pod-node netns tnx-pod
ip -n tnx-pod link set pod-node name eth0
for pair in 'tnx-gw wg0' 'tnx-gw eth0' 'tnx-site eth0' 'tnx-pod eth0'; do
  set -- $pair
  ip -n "$1" link set "$2" up
done
ip -n tnx-gw addr add 100.65.0.2/32 dev wg0
ip -n tnx-gw route add 10.50.0.0/24 dev wg0
ip -n tnx-gw addr add 10.70.0.6/24 dev eth0
ip -n tnx-site addr add 10.50.0.5/32 dev eth0
ip -n tnx-site route add 100.65.0.2/32 dev eth0
ip -n tnx-site route add default via 100.65.0.2 dev eth0
# The pod's node carries the host-posture return route to the DEVICE range only, as every node does.
# It has no route to the remote site range.
ip -n tnx-pod addr add 10.70.0.9/24 dev eth0
ip -n tnx-pod route add 10.99.0.0/24 via 10.70.0.6
for ns in tnx-gw tnx-site tnx-pod; do
  ip netns exec "$ns" sh -c 'for f in /proc/sys/net/ipv4/conf/*/rp_filter; do echo 0 > "$f"; done'
done
rm -f /tmp/site-pod.ready
ip netns exec tnx-pod env TUNNEX_TEST_SITE_LAN_PHASE=serve TUNNEX_TEST_SITE_LAN_ADDR=10.70.0.9:80 TUNNEX_TEST_SITE_LAN_READY=/tmp/site-pod.ready "$testbin" -test.run "$run" >/dev/null 2>&1 &
pod_pid=$!
trap 'kill $pod_pid 2>/dev/null || true' EXIT
for i in $(seq 1 40); do [ -e /tmp/site-pod.ready ] && break; sleep 0.25; done
[ -e /tmp/site-pod.ready ] || { echo "the pod did not start"; exit 1; }
gw() { ip netns exec tnx-gw env TUNNEX_TEST_SITE_LAN_PHASE="$1" "$testbin" -test.run "$run" -test.v; }
call() { ip netns exec tnx-site env TUNNEX_TEST_SITE_LAN_PHASE=call TUNNEX_TEST_SITE_LAN_ADDR=10.70.0.9:80 "$testbin" -test.run "$run" > /tmp/site-call.out 2>&1; }
answered_via_node() { call && grep -q 'ANSWER from=10.70.0.6' /tmp/site-call.out; }

# 1. The same table without the rule: the pod cannot route its answer to the remote site.
gw without-rule
if call; then echo "the pod answered without the rule"; exit 1; fi
echo WITHOUT_THE_RULE_THE_POD_CANNOT_ANSWER

# 2. First start with the rule, through the startup order that crash-looped.
gw first-start
echo FIRST_START_ACCEPTED
answered_via_node
echo POD_ANSWERS_THE_REMOTE_SITE_VIA_NODE_ADDRESS

# 3. Restart: a new process over the table the previous one left.
gw restart
echo RESTART_OVER_LEFTOVER_RULE_ACCEPTED
answered_via_node
echo POD_ANSWERS_AFTER_RESTART

# 4. Near-misses written into the live chain.
gw refuse-near-miss
echo NEAR_MISSES_STILL_REFUSED

# 5. OpenVPN co-terminated: the exclusion is a set.
ip -n tnx-gw link add tun0 type dummy
ip -n tnx-gw link set tun0 up
gw openvpn
echo OPENVPN_SET_FORM_ACCEPTED
answered_via_node
echo POD_ANSWERS_WITH_OPENVPN_SET
ip -n tnx-gw link del tun0

# 6. The site goes back to preserve_source.
gw preserve-source
echo RULE_GONE_WITH_PRESERVE_SOURCE
if call; then echo "the pod still answered with preserve_source"; exit 1; fi
echo POD_CANNOT_ANSWER_WITH_PRESERVE_SOURCE

# 7. Normal stop.
gw shutdown
echo NO_RULE_LEFT_AFTER_SHUTDOWN
`
