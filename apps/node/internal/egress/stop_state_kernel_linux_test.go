//go:build linux

package egress

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/tunnexio/tunnex/apps/node/internal/hostposture"
	"github.com/tunnexio/tunnex/apps/node/internal/k8snetprep"
)

// TestGatewayStopStateKernel is the opt-in witness for K8N-5, "what a stopped gateway leaves on its
// node". It runs only in a disposable PRIVILEGED Linux container (it creates network namespaces and
// writes sysctls):
//
//	TUNNEX_TEST_STOP_STATE_KERNEL=1 go test ./internal/egress -run '^TestGatewayStopStateKernel$' -v
//
// The gateway's namespace is a router: plain traffic from a pod on one side to a pod on the other
// crosses its forward hook, as pod and Service traffic crosses a node's. The witness checks that
// traffic and the tunnel before a start, while a gateway runs, after each stop path and after a kill.
// A gateway "process" is one run of this test binary inside that namespace, with the real Manager and
// real `nft -f`.
//
// What it is not: a cluster. wg0 is a veth, not WireGuard; there is no CNI, no kube-proxy, no
// host-posture manager process (its table delete is replayed with the same nft command).
func TestGatewayStopStateKernel(t *testing.T) {
	if os.Getenv("TUNNEX_TEST_STOP_STATE_KERNEL") != "1" {
		t.Skip("opt in inside a disposable privileged Linux container")
	}
	switch phase := os.Getenv("TUNNEX_TEST_STOP_STATE_PHASE"); phase {
	case "":
	case "serve":
		stopStateServe(t)
		return
	case "call":
		stopStateCall(t)
		return
	default:
		stopStateGateway(t, phase)
		return
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 180*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "unshare", "--mount", "--net", "--propagation", "private", "sh", "-eu", "-c", stopStateFixture, "fixture", executable)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("isolated witness failed: %v\n%s", err, out)
	}
	for _, proof := range []string{
		"BEFORE_START_NATIVE_FORWARD_PASSES",
		"BEFORE_START_NO_SERVICE_PATH",
		"RUNNING_NATIVE_FORWARD_PASSES",
		"RUNNING_SERVICE_ANSWERS_THROUGH_TUNNEL",
		"RUNNING_UNGRANTED_TUNNEL_PATH_DROPPED",
		"KILL_LEAVES_RUNNING_TABLE",
		"KILL_NATIVE_FORWARD_PASSES",
		"RELEASED_STOP_LEAVES_FORWARD_DROP_POLICY",
		"RELEASED_STOP_DROPS_NATIVE_FORWARD",
		"RESTART_OVER_RELEASED_STOP_READY",
		"NATIVE_FORWARD_PASSES_AFTER_RESTART_OVER_RELEASED_STOP",
		"NORMAL_STOP_LEAVES_NO_DROP_POLICY",
		"NORMAL_STOP_KEEPS_EXACT_POSTURE_MARKER",
		"NORMAL_STOP_NATIVE_FORWARD_PASSES",
		"NORMAL_STOP_TUNNEL_CLOSED_BY_GUARD",
		"RESTART_OVER_STOP_READY",
		"SERVICE_ANSWERS_AFTER_RESTART_OVER_STOP",
		"EMERGENCY_WITHDRAW_KEEPS_PASSTHROUGH",
		"EMERGENCY_NATIVE_FORWARD_PASSES",
		"EMERGENCY_SERVICE_WITHDRAWN",
		"MANAGER_CLEANUP_LEAVES_NO_TABLE",
		"MANAGER_CLEANUP_NATIVE_FORWARD_PASSES",
		"CONTROL_DIRECT_TUNNEL_PATH_OPEN_WITHOUT_TABLE",
		"RELEASED_STOP_RECREATES_ORPHAN_TABLE_IN_RACE",
		"STOP_IN_RACE_WITH_MANAGER_CLEANUP_RECREATES_NOTHING",
	} {
		if !strings.Contains(string(out), proof) {
			t.Fatalf("missing proof %s\n%s", proof, out)
		}
	}
	t.Logf("isolated evidence:\n%s", out)
}

// stopStateGateway is one gateway process in the gateway's namespace.
func stopStateGateway(t *testing.T, phase string) {
	ctx := t.Context()
	nft := func(args ...string) string {
		t.Helper()
		out, err := nftRun(ctx, args...)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	m := New("wg0")
	m.SetKubernetesMode(true)
	m.SetKubernetesCNIAuthority(func(context.Context) (k8snetprep.AuthorityGrant, func(), error) {
		return k8snetprep.AuthorityGrant{Scope: k8snetprep.ScopeIPMasqAndAWS, NotAfter: time.Now().Add(k8snetprep.CNIOperationBudget)}, func() {}, nil
	}, nil, nil)
	m.SetEndpointSource(apiReturnEndpoints())
	m.SetPolicy(apiReturnPolicy(false))
	// The order of a real start, as in TestK8sAPIReturnPathKernel.
	start := func() {
		t.Helper()
		m.ResolveK8sVIPs(ctx)
		if err := m.ReconcileDNSVIPs(ctx); err != nil {
			t.Fatalf("startup DNS addresses: %v", err)
		}
		if _, _, err := m.Reconcile(ctx); err != nil {
			t.Fatalf("startup egress pass: %v", err)
		}
		if err := m.ReconcileOVPNTunnel(ctx, ""); err != nil {
			t.Fatalf("startup OpenVPN stage: %v", err)
		}
		m.ResolveK8sVIPs(ctx)
		if _, _, err := m.Reconcile(ctx); err != nil {
			t.Fatalf("startup DNAT pass: %v", err)
		}
		if !m.K8sNetPrepReady() {
			t.Fatal("the gateway is not ready after a start")
		}
	}
	markersExact := func() {
		t.Helper()
		for _, family := range []string{"ip", "ip6"} {
			if err := hostposture.ValidateNFTMarkerChain(nft("-a", "list", "chain", family, "tunnex", "tunnex_posture_owner"), hostposture.NFTMarkerComment); err != nil {
				t.Fatalf("%s posture marker is not what the manager accepts: %v", family, err)
			}
		}
	}
	deleteTables := func() {
		t.Helper()
		nft("delete", "table", "ip", "tunnex")
		nft("delete", "table", "ip6", "tunnex")
	}
	tunnexTables := func() string {
		var kept []string
		for _, line := range strings.Split(nft("list", "tables"), "\n") {
			if strings.Contains(line, " tunnex") {
				kept = append(kept, line)
			}
		}
		return strings.Join(kept, "\n")
	}

	switch phase {
	case "start":
		start()
		fmt.Println("GATEWAY_READY")
	case "hold":
		start()
		if err := os.WriteFile(os.Getenv("TUNNEX_TEST_STOP_STATE_READY"), nil, 0o644); err != nil {
			t.Fatal(err)
		}
		time.Sleep(90 * time.Second) // killed with SIGKILL long before this
	case "stop-released":
		start()
		if err := nftApply(ctx, releasedStopRuleset); err != nil {
			t.Fatal(err)
		}
		ruleset := nft("list", "ruleset")
		if !strings.Contains(ruleset, "hook forward priority filter; policy drop;") {
			t.Fatalf("the released stop text did not leave the drop policy:\n%s", ruleset)
		}
		fmt.Printf("kernel after the released stop:\n%s", ruleset)
	case "stop":
		start()
		m.Teardown(ctx)
		ruleset := nft("list", "ruleset")
		if strings.Contains(ruleset, "policy drop") {
			t.Fatalf("the stop left a drop policy:\n%s", ruleset)
		}
		for _, left := range []string{"masquerade", "dnat to", "ct state", "chain prerouting", "chain postrouting", k8snetprep.APIReturnRuleComment} {
			if strings.Contains(ruleset, left) {
				t.Fatalf("the stop left %q:\n%s", left, ruleset)
			}
		}
		markersExact()
		fmt.Printf("kernel after the stop:\n%s", ruleset)
	case "emergency":
		start()
		if err := m.EmergencyWithdrawK8s(ctx, nil); err != nil {
			t.Fatalf("emergency withdraw: %v", err)
		}
		table := nft("list", "table", "ip", "tunnex")
		if strings.Contains(table, "dnat to") || !strings.Contains(table, "tunnex_native_forward_passthrough") {
			t.Fatalf("unexpected table after the emergency withdraw:\n%s", table)
		}
		fmt.Printf("kernel after the emergency withdraw:\n%s", table)
	case "emergency-then-pass":
		start()
		if err := m.EmergencyWithdrawK8s(ctx, nil); err != nil {
			t.Fatalf("emergency withdraw: %v", err)
		}
		if _, _, err := m.Reconcile(ctx); err != nil {
			t.Fatalf("egress pass after the emergency withdraw: %v", err)
		}
		fmt.Printf("forward chain after an egress pass that follows the emergency withdraw:\n%s", nft("list", "chain", "ip", "tunnex", "forward"))
	case "race-released":
		// The manager deletes the table between the gateway's marker check and its apply.
		start()
		markersExact()
		deleteTables()
		if err := nftApply(ctx, releasedStopRuleset); err != nil {
			t.Fatal(err)
		}
		if tables := tunnexTables(); tables == "" {
			t.Fatal("the released stop text did not recreate the table")
		} else {
			fmt.Printf("tables after the released stop raced the manager's delete:\n%s\n", tables)
		}
		deleteTables()
	case "race-stop":
		start()
		apply := m.apply
		m.apply = func(ctx context.Context, ruleset string) error {
			if strings.HasPrefix(ruleset, "flush table ip tunnex\n") {
				deleteTables()
			}
			err := apply(ctx, ruleset)
			fmt.Printf("stop apply after the manager's delete: %v\n", err)
			return err
		}
		m.Teardown(ctx)
		if tables := tunnexTables(); tables != "" {
			t.Fatalf("the stop recreated a table the manager deleted:\n%s", tables)
		}
	default:
		t.Fatalf("unknown phase %q", phase)
	}
}

// stopStateServe answers every connection with the address it came from, until it is killed.
func stopStateServe(t *testing.T) {
	listener, err := net.Listen("tcp4", os.Getenv("TUNNEX_TEST_STOP_STATE_ADDR"))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := os.WriteFile(os.Getenv("TUNNEX_TEST_STOP_STATE_READY"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
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

// stopStateCall is one connection, two seconds.
func stopStateCall(t *testing.T) {
	address := os.Getenv("TUNNEX_TEST_STOP_STATE_ADDR")
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

const stopStateFixture = `
testbin=$1
run='^TestGatewayStopStateKernel$'
for ns in tnx-gw tnx-dev tnx-poda tnx-podb; do
  ip netns add "$ns"
  ip -n "$ns" link set lo up
done
# The tunnel: a veth between the device and the gateway's wg0.
ip link add tunnel-gw type veth peer name tunnel-dev
ip link set tunnel-gw netns tnx-gw
ip -n tnx-gw link set tunnel-gw name wg0
ip link set tunnel-dev netns tnx-dev
ip -n tnx-dev link set tunnel-dev name eth0
# The node's two other sides: pod B (the Service's endpoint) and pod A (a plain client).
ip link add gw-b type veth peer name podb-gw
ip link set gw-b netns tnx-gw
ip -n tnx-gw link set gw-b name eth0
ip link set podb-gw netns tnx-podb
ip -n tnx-podb link set podb-gw name eth0
ip link add gw-a type veth peer name poda-gw
ip link set gw-a netns tnx-gw
ip -n tnx-gw link set gw-a name eth1
ip link set poda-gw netns tnx-poda
ip -n tnx-poda link set poda-gw name eth0
for pair in 'tnx-gw wg0' 'tnx-gw eth0' 'tnx-gw eth1' 'tnx-dev eth0' 'tnx-podb eth0' 'tnx-poda eth0'; do
  set -- $pair
  ip -n "$1" link set "$2" up
done
ip -n tnx-gw addr add 100.65.0.2/32 dev wg0
ip -n tnx-gw route add 10.99.0.0/24 dev wg0
ip -n tnx-gw addr add 10.70.0.6/24 dev eth0
ip -n tnx-gw addr add 10.80.0.1/24 dev eth1
ip -n tnx-dev addr add 10.99.0.2/32 dev eth0
ip -n tnx-dev route add 100.65.0.2/32 dev eth0
ip -n tnx-dev route add default via 100.65.0.2 dev eth0
ip -n tnx-podb addr add 10.70.0.9/24 dev eth0
ip -n tnx-podb route add default via 10.70.0.6
ip -n tnx-poda addr add 10.80.0.5/24 dev eth0
ip -n tnx-poda route add default via 10.80.0.1
for ns in tnx-gw tnx-dev tnx-poda tnx-podb; do
  ip netns exec "$ns" sh -c 'for f in /proc/sys/net/ipv4/conf/*/rp_filter; do echo 0 > "$f"; done'
done
# A node forwards before any gateway runs.
ip netns exec tnx-gw sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'

rm -f /tmp/stop-podb.ready
ip netns exec tnx-podb env TUNNEX_TEST_STOP_STATE_PHASE=serve TUNNEX_TEST_STOP_STATE_ADDR=10.70.0.9:80 TUNNEX_TEST_STOP_STATE_READY=/tmp/stop-podb.ready "$testbin" -test.run "$run" >/dev/null 2>&1 &
podb_pid=$!
trap 'kill -9 $podb_pid 2>/dev/null || true' EXIT
for i in $(seq 1 40); do [ -e /tmp/stop-podb.ready ] && break; sleep 0.25; done
[ -e /tmp/stop-podb.ready ] || { echo "pod B did not start"; exit 1; }

gw() { ip netns exec tnx-gw env TUNNEX_TEST_STOP_STATE_PHASE="$1" "$testbin" -test.run "$run" -test.v; }
call() { ip netns exec "$1" env TUNNEX_TEST_STOP_STATE_PHASE=call TUNNEX_TEST_STOP_STATE_ADDR="$2" "$testbin" -test.run "$run"; }
# Plain traffic across the node: pod A to pod B. It must arrive from pod A itself (no NAT).
native() { call tnx-poda 10.70.0.9:80 > /tmp/native.out 2>&1 && grep -q 'ANSWER from=10.80.0.5' /tmp/native.out; }
# The exposed Service through the tunnel: device to the Service's VIP.
service() { call tnx-dev 100.65.0.3:80 > /tmp/service.out 2>&1 && grep -q 'ANSWER from=10.99.0.2' /tmp/service.out; }
# A tunnel path no rule grants: device straight to pod B's address.
direct() { call tnx-dev 10.70.0.9:80 > /tmp/direct.out 2>&1; }
no_tunnex_hook_drop() { ! ip netns exec tnx-gw nft list ruleset | grep -q 'policy drop'; }

echo "== 1. before any gateway"
if ip netns exec tnx-gw nft list tables | grep -q tunnex; then exit 1; fi
native
echo BEFORE_START_NATIVE_FORWARD_PASSES
if service; then echo "the Service answered before a gateway ran"; exit 1; fi
echo BEFORE_START_NO_SERVICE_PATH

echo "== 2. a running gateway, then SIGKILL"
rm -f /tmp/stop-hold.ready
ip netns exec tnx-gw env TUNNEX_TEST_STOP_STATE_PHASE=hold TUNNEX_TEST_STOP_STATE_READY=/tmp/stop-hold.ready "$testbin" -test.run "$run" >/tmp/hold.out 2>&1 &
hold_pid=$!
for i in $(seq 1 120); do [ -e /tmp/stop-hold.ready ] && break; sleep 0.25; done
[ -e /tmp/stop-hold.ready ] || { cat /tmp/hold.out; echo "the gateway did not start"; exit 1; }
native
echo RUNNING_NATIVE_FORWARD_PASSES
service
echo RUNNING_SERVICE_ANSWERS_THROUGH_TUNNEL
if direct; then echo "an ungranted tunnel path is open while running"; exit 1; fi
echo RUNNING_UNGRANTED_TUNNEL_PATH_DROPPED
kill -9 "$hold_pid"
wait "$hold_pid" 2>/dev/null || true
ip netns exec tnx-gw nft list table ip tunnex | tee /tmp/kill.table
grep -q 'tunnex_native_forward_passthrough' /tmp/kill.table
grep -q 'dnat to 10.70.0.9:80' /tmp/kill.table
echo KILL_LEAVES_RUNNING_TABLE
native
echo KILL_NATIVE_FORWARD_PASSES

echo "== 3. the stop as released (v0.1.44, origin/main)"
gw stop-released
echo RELEASED_STOP_LEAVES_FORWARD_DROP_POLICY
if native; then echo "plain traffic passed the released stop state"; exit 1; fi
cat /tmp/native.out
echo RELEASED_STOP_DROPS_NATIVE_FORWARD

echo "== 4. a new process over the released stop state"
gw start | grep -q GATEWAY_READY
echo RESTART_OVER_RELEASED_STOP_READY
native
service
echo NATIVE_FORWARD_PASSES_AFTER_RESTART_OVER_RELEASED_STOP

echo "== 5. the normal stop, fixed"
gw stop
no_tunnex_hook_drop
echo NORMAL_STOP_LEAVES_NO_DROP_POLICY
echo NORMAL_STOP_KEEPS_EXACT_POSTURE_MARKER
native
echo NORMAL_STOP_NATIVE_FORWARD_PASSES
if direct; then echo "the tunnel is open after the stop"; exit 1; fi
ip netns exec tnx-gw nft list chain ip tunnex forward | tee /tmp/guard.out
grep -q 'iifname "wg0" counter packets [1-9].* drop comment "tunnex_stopped_tunnel_drop"' /tmp/guard.out
echo NORMAL_STOP_TUNNEL_CLOSED_BY_GUARD

echo "== 6. a new process over the stop state"
gw start | grep -q GATEWAY_READY
echo RESTART_OVER_STOP_READY
service
native
echo SERVICE_ANSWERS_AFTER_RESTART_OVER_STOP

echo "== 7. emergency withdraw (the process goes on)"
gw emergency
echo EMERGENCY_WITHDRAW_KEEPS_PASSTHROUGH
native
echo EMERGENCY_NATIVE_FORWARD_PASSES
if service; then echo "the Service still answers after the emergency withdraw"; exit 1; fi
echo EMERGENCY_SERVICE_WITHDRAWN
gw emergency-then-pass
if direct; then echo OBSERVED_TUNNEL_OPEN_TO_UNGRANTED_DESTINATION_AFTER_EMERGENCY_AND_PASS; else echo OBSERVED_TUNNEL_STAYS_CLOSED_AFTER_EMERGENCY_AND_PASS; fi

echo "== 8. a stop, then the manager's last-owner cleanup"
gw stop >/dev/null
ip netns exec tnx-gw nft delete table ip tunnex
ip netns exec tnx-gw nft delete table ip6 tunnex
if ip netns exec tnx-gw nft list tables | grep -q tunnex; then exit 1; fi
echo MANAGER_CLEANUP_LEAVES_NO_TABLE
native
echo MANAGER_CLEANUP_NATIVE_FORWARD_PASSES
# The manager also removes wg0. Before it does, the direct path is open: the guard is what closed it.
direct
echo CONTROL_DIRECT_TUNNEL_PATH_OPEN_WITHOUT_TABLE

echo "== 9. a stop racing the manager's delete"
gw race-released
echo RELEASED_STOP_RECREATES_ORPHAN_TABLE_IN_RACE
gw race-stop
if ip netns exec tnx-gw nft list tables | grep -q tunnex; then exit 1; fi
echo STOP_IN_RACE_WITH_MANAGER_CLEANUP_RECREATES_NOTHING
native
`
