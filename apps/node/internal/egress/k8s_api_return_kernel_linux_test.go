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

// TestK8sAPIReturnPathKernel is the opt-in witness for K8N-3, "Return path for the API server". It runs
// only in a disposable PRIVILEGED Linux container (it creates network namespaces and writes sysctls):
//
//	TUNNEX_TEST_K8S_API_RETURN_KERNEL=1 go test ./internal/egress -run '^TestK8sAPIReturnPathKernel$' -v
//
// What it is: the real Manager rendering through real `nft -f`, the real ownership check
// (k8snetprep, as wired by SetKubernetesCNIAuthority) reading that kernel's `nft -j -a list ruleset`,
// and real packets through real conntrack NAT. A gateway "process" is one run of this test binary inside
// the gateway's namespace, so a restart is a new process that finds the previous one's table.
//
// What it is not: a cluster. wg0 is a veth, not WireGuard; the "API server" is a TCP listener in a
// namespace that has no route to the device's range; the node has no CNI rules; there is no TLS, no
// kubectl, no control plane. It does not replace the GKE walk.
//
// With TUNNEX_TEST_K8S_API_RETURN_OUT=<dir> the gateway phases also write the rendered ruleset and the
// kernel's JSON listing; that is how k8snetprep/testdata/k8n3-api-return*.{rendered.nft,nft-ruleset.json}
// were produced.
func TestK8sAPIReturnPathKernel(t *testing.T) {
	if os.Getenv("TUNNEX_TEST_K8S_API_RETURN_KERNEL") != "1" {
		t.Skip("opt in inside a disposable privileged Linux container")
	}
	switch phase := os.Getenv("TUNNEX_TEST_K8S_API_RETURN_PHASE"); phase {
	case "":
	case "serve":
		apiReturnKernelServe(t)
		return
	case "call":
		apiReturnKernelCall(t)
		return
	default:
		apiReturnKernelGateway(t, phase)
		return
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 120*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "unshare", "--mount", "--net", "--propagation", "private", "sh", "-eu", "-c", apiReturnKernelFixture, "fixture", executable)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("isolated witness failed: %v\n%s", err, out)
	}
	for _, proof := range []string{
		"BEFORE_FIX_REQUEST_REACHES_API_SERVER_AS_DEVICE",
		"BEFORE_FIX_API_CALL_TIMES_OUT",
		"FIRST_START_ACCEPTED",
		"API_ANSWER_RETURNS_VIA_NODE_ADDRESS",
		"SERVICE_KEEPS_DEVICE_SOURCE",
		"RESTART_OVER_LEFTOVER_RULE_ACCEPTED",
		"API_ANSWER_RETURNS_AFTER_RESTART",
		"UNKNOWN_RULES_STILL_REFUSED",
		"OPENVPN_SET_FORM_ACCEPTED",
		"API_ANSWER_RETURNS_WITH_OPENVPN_SET",
		"RULE_GONE_AFTER_API_ACCESS_OFF",
		"API_ADDRESS_NO_LONGER_ANSWERS_AFTER_API_ACCESS_OFF",
		"SERVICE_STILL_ANSWERS_AFTER_API_ACCESS_OFF",
		"NO_RULE_LEFT_AFTER_SHUTDOWN",
	} {
		if !strings.Contains(string(out), proof) {
			t.Fatalf("missing proof %s\n%s", proof, out)
		}
	}
	t.Logf("isolated evidence:\n%s", out)
}

// apiReturnKernelGateway is one gateway process in the gateway's namespace.
func apiReturnKernelGateway(t *testing.T, phase string) {
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
	}, nil, nil)
	m.SetEndpointSource(apiReturnEndpoints())
	policy := apiReturnPolicy(phase != "api-access-off")
	m.SetPolicy(policy)

	// The order of a real start. Step 1 is desired_state_startup_base (its error is only logged in the
	// agent; here it must not exist). Step 2 is ownership_startup_withdraw: the OpenVPN stage re-applies
	// the table and its error is fatal to the process. That is where the first attempt crash-looped.
	// Step 3 is the DNAT stage that follows it.
	start := func(tun string) {
		t.Helper()
		m.ResolveK8sVIPs(ctx)
		if err := m.ReconcileDNSVIPs(ctx); err != nil {
			t.Fatalf("desired_state_startup_base, DNS addresses: %v", err)
		}
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
		dir := os.Getenv("TUNNEX_TEST_K8S_API_RETURN_OUT")
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
	case "before-fix":
		// What a build without the return rule loads: the same table, minus that one line.
		m.ResolveK8sVIPs(ctx)
		if err := ensureIPForward(); err != nil {
			t.Fatal(err)
		}
		var kept []string
		for _, line := range strings.Split(m.rulesetWith(apiReturnTunnel, policy), "\n") {
			if !strings.Contains(line, k8snetprep.APIReturnRuleComment) {
				kept = append(kept, line)
			}
		}
		if err := nftApply(ctx, strings.Join(kept, "\n")); err != nil {
			t.Fatal(err)
		}
		if rules := natRules(); strings.Contains(rules, k8snetprep.APIReturnRuleComment) || !strings.Contains(rules, "ip saddr 100.65.0.2") {
			t.Fatalf("not the table of a build without the rule:\n%s", rules)
		}
	case "first-start":
		start("")
		if rules := natRules(); !strings.Contains(rules, apiReturnAPIRule) {
			t.Fatalf("the kernel does not hold the rule as rendered:\n%s", rules)
		}
		save("k8n3-api-return")
		t.Logf("kernel:\n%s", natRules())
	case "restart":
		// A new process. The previous one's table is still in the kernel, return rule included.
		leftover := natRules()
		if !strings.Contains(leftover, apiReturnAPIRule) {
			t.Fatalf("no leftover rule to restart over:\n%s", leftover)
		}
		// The ownership check alone, on the leftover table, before this process has loaded anything.
		if err := m.ReconcileK8sNetPrep(ctx); err != nil || !m.K8sNetPrepReady() {
			t.Fatalf("the ownership check refused the leftover table: ready=%v err=%v\n%s", m.K8sNetPrepReady(), err, leftover)
		}
		start("")
		t.Logf("kernel after restart:\n%s", natRules())
	case "refuse-unknown":
		start("")
		for reason, rule := range map[string][]string{
			"unknown Tunnex source-NAT rule":                                      {"ip", "daddr", "203.0.113.9", "oifname", "!=", "wg0", "masquerade", "random"},
			"Tunnex source-NAT CIDR differs from current tunnel":                  {"ct", "original", "ip", "daddr", "100.65.0.4", "oifname", "!=", "wg0", "masquerade"},
			"Tunnex API return rule does not match one original IPv4 destination": {"ct", "original", "ip", "daddr", "100.65.0.0/24", "oifname", "!=", "wg0", "masquerade", "comment", k8snetprep.APIReturnRuleComment},
			"Tunnex NAT could bind traffic returning to WireGuard":                {"ct", "original", "ip", "daddr", "100.65.0.7", "oifname", "!=", "eth0", "masquerade", "comment", k8snetprep.APIReturnRuleComment},
		} {
			nft(append([]string{"add", "rule", "ip", "tunnex", "postrouting"}, rule...)...)
			err := m.ReconcileK8sNetPrep(ctx)
			if err == nil || !strings.Contains(err.Error(), reason) || m.K8sNetPrepReady() {
				t.Fatalf("a foreign rule was not refused as %q: ready=%v err=%v\n%s", reason, m.K8sNetPrepReady(), err, natRules())
			}
			// The next egress pass replaces the table; the foreign rule does not outlive it.
			if _, _, err := m.Reconcile(ctx); err != nil || !m.K8sNetPrepReady() {
				t.Fatalf("the egress pass did not restore the table: ready=%v err=%v", m.K8sNetPrepReady(), err)
			}
		}
	case "openvpn":
		start("tun0")
		want := `ct original ip daddr 100.65.0.4 oifname != { "wg0", "tun0" } masquerade comment "tunnex_k8s_api_return"`
		if rules := natRules(); !strings.Contains(rules, want) {
			t.Fatalf("the kernel does not hold the set form:\n%s", rules)
		}
		save("k8n3-api-return-openvpn")
		t.Logf("kernel with OpenVPN:\n%s", natRules())
	case "api-access-off":
		if leftover := natRules(); !strings.Contains(leftover, k8snetprep.APIReturnRuleComment) {
			t.Fatalf("no rule to remove:\n%s", leftover)
		}
		start("")
		if rules := natRules(); strings.Contains(rules, k8snetprep.APIReturnRuleComment) || strings.Contains(rules, "ct original") {
			t.Fatalf("the rule outlived the mapping:\n%s", rules)
		}
		t.Logf("kernel after API access is off:\n%s", natRules())
	case "shutdown":
		start("")
		m.Teardown(ctx)
		// The stop state (K8N-5): the NAT chains are gone, `forward` drops only tunnel traffic under
		// policy accept, and the marker rule is written back. No rule of the previous process is left,
		// the return rule included.
		table := nft("list", "table", "ip", "tunnex")
		for _, left := range []string{"masquerade", "dnat to", "ct original", "ct state", "policy drop", "chain postrouting", k8snetprep.APIReturnRuleComment} {
			if strings.Contains(table, left) {
				t.Fatalf("shutdown left a %q rule:\n%s", left, table)
			}
		}
		if !strings.Contains(table, "tunnex_host_posture_v1") {
			t.Fatalf("shutdown removed the ownership marker:\n%s", table)
		}
		t.Logf("kernel after shutdown:\n%s", table)
	default:
		t.Fatalf("unknown phase %q", phase)
	}
}

// apiReturnKernelServe answers every connection with the address it came from.
func apiReturnKernelServe(t *testing.T) {
	listener, err := net.Listen("tcp4", os.Getenv("TUNNEX_TEST_K8S_API_RETURN_ADDR"))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := os.WriteFile(os.Getenv("TUNNEX_TEST_K8S_API_RETURN_READY"), nil, 0o644); err != nil {
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

// apiReturnKernelCall is the device: one call, two seconds.
func apiReturnKernelCall(t *testing.T) {
	address := os.Getenv("TUNNEX_TEST_K8S_API_RETURN_ADDR")
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

const apiReturnKernelFixture = `
testbin=$1
run='^TestK8sAPIReturnPathKernel$'
for ns in tnx-gw tnx-dev tnx-api tnx-pod; do
  ip netns add "$ns"
  ip -n "$ns" link set lo up
done
# The tunnel: a veth between the device and the gateway's wg0.
ip link add tunnel-gw type veth peer name tunnel-dev
ip link set tunnel-gw netns tnx-gw
ip -n tnx-gw link set tunnel-gw name wg0
ip -n tnx-gw link set wg0 up
ip link set tunnel-dev netns tnx-dev
ip -n tnx-dev link set tunnel-dev name eth0
ip -n tnx-dev link set eth0 up
# The node network: the gateway node, the managed control plane and one other node.
ip link add br-node type bridge
ip link set br-node up
for pair in 'tnx-gw eth0 gw-br' 'tnx-api eth0 api-br' 'tnx-pod eth0 pod-br'; do
  set -- $pair
  ip link add "$3" type veth peer name fixture-peer
  ip link set fixture-peer netns "$1"
  ip -n "$1" link set fixture-peer name "$2"
  ip -n "$1" link set "$2" up
  ip link set "$3" master br-node
  ip link set "$3" up
done
ip -n tnx-gw addr add 100.65.0.2/32 dev wg0
ip -n tnx-gw addr add 10.70.0.6/24 dev eth0
ip -n tnx-gw route add 10.99.0.0/24 dev wg0
ip -n tnx-dev addr add 10.99.0.2/32 dev eth0
ip -n tnx-dev route add 100.65.0.2/32 dev eth0
ip -n tnx-dev route add default via 100.65.0.2 dev eth0
# The control plane is on the node network and has NO route to the tunnel range.
ip -n tnx-api addr add 10.70.0.3/24 dev eth0
# The other node carries the host-posture return route, as every node of the cluster does.
ip -n tnx-pod addr add 10.70.0.9/24 dev eth0
ip -n tnx-pod route add 10.99.0.0/24 via 10.70.0.6
for ns in tnx-gw tnx-dev tnx-api tnx-pod; do
  ip netns exec "$ns" sh -c 'for f in /proc/sys/net/ipv4/conf/*/rp_filter; do echo 0 > "$f"; done'
done
# Witness on the control plane: who the request appears to come from.
ip netns exec tnx-api nft -f - <<'EOF'
table ip witness {
  counter from_device { }
  counter from_node { }
  chain input {
    type filter hook input priority 0; policy accept;
    ip saddr 10.99.0.2 tcp dport 443 counter name from_device
    ip saddr 10.70.0.6 tcp dport 443 counter name from_node
  }
}
EOF
seen() { ip netns exec tnx-api nft list counter ip witness "$1" | grep -q 'packets [1-9]'; }
serve() {
  rm -f "$3"
  ip netns exec "$1" env TUNNEX_TEST_K8S_API_RETURN_PHASE=serve TUNNEX_TEST_K8S_API_RETURN_ADDR="$2" TUNNEX_TEST_K8S_API_RETURN_READY="$3" "$testbin" -test.run "$run" >/dev/null 2>&1 &
  for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    [ -e "$3" ] && return 0
    sleep 0.25
  done
  echo "listener $2 did not start"; exit 1
}
serve tnx-api 10.70.0.3:443 /tmp/tnx-api.ready
api_pid=$!
serve tnx-pod 10.70.0.9:80 /tmp/tnx-pod.ready
pod_pid=$!
trap 'kill $api_pid $pod_pid 2>/dev/null || true' EXIT
gw() { ip netns exec tnx-gw env TUNNEX_TEST_K8S_API_RETURN_PHASE="$1" "$testbin" -test.run "$run" -test.v; }
call() { ip netns exec tnx-dev env TUNNEX_TEST_K8S_API_RETURN_PHASE=call TUNNEX_TEST_K8S_API_RETURN_ADDR="$1" "$testbin" -test.run "$run"; }

# 1. The table of a build without the return rule: what was seen on GKE.
gw before-fix
if call 100.65.0.4:443; then echo "the call returned without the rule"; exit 1; fi
seen from_device
if seen from_node; then exit 1; fi
echo BEFORE_FIX_REQUEST_REACHES_API_SERVER_AS_DEVICE
echo BEFORE_FIX_API_CALL_TIMES_OUT

# 2. First start of a gateway that renders the rule.
gw first-start
echo FIRST_START_ACCEPTED
call 100.65.0.4:443 | tee /tmp/call.out
grep -q 'ANSWER from=10.70.0.6' /tmp/call.out
seen from_node
echo API_ANSWER_RETURNS_VIA_NODE_ADDRESS
call 100.65.0.3:80 | tee /tmp/call.out
grep -q 'ANSWER from=10.99.0.2' /tmp/call.out
echo SERVICE_KEEPS_DEVICE_SOURCE

# 3. Restart: a new process over the table the previous one left.
gw restart
echo RESTART_OVER_LEFTOVER_RULE_ACCEPTED
call 100.65.0.4:443 | tee /tmp/call.out
grep -q 'ANSWER from=10.70.0.6' /tmp/call.out
echo API_ANSWER_RETURNS_AFTER_RESTART

# 4. Rules the check must still refuse, written into the live chain.
gw refuse-unknown
echo UNKNOWN_RULES_STILL_REFUSED

# 5. OpenVPN co-terminated: the exclusion is a set.
ip -n tnx-gw link add tun0 type dummy
ip -n tnx-gw link set tun0 up
gw openvpn
echo OPENVPN_SET_FORM_ACCEPTED
call 100.65.0.4:443 | tee /tmp/call.out
grep -q 'ANSWER from=10.70.0.6' /tmp/call.out
echo API_ANSWER_RETURNS_WITH_OPENVPN_SET

# 6. API access turned off: a new process whose policy has no mapping for default/kubernetes.
gw api-access-off
echo RULE_GONE_AFTER_API_ACCESS_OFF
if call 100.65.0.4:443; then echo "the API address still answers"; exit 1; fi
echo API_ADDRESS_NO_LONGER_ANSWERS_AFTER_API_ACCESS_OFF
call 100.65.0.3:80 | tee /tmp/call.out
grep -q 'ANSWER from=10.99.0.2' /tmp/call.out
echo SERVICE_STILL_ANSWERS_AFTER_API_ACCESS_OFF

# 7. Normal stop.
gw shutdown
echo NO_RULE_LEFT_AFTER_SHUTDOWN
`
