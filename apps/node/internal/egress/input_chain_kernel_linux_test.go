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
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/tunnexio/tunnex/apps/node/internal/hostposture"
	"github.com/tunnexio/tunnex/apps/node/internal/k8snetprep"
	"github.com/tunnexio/tunnex/apps/node/internal/nodepolicy"
)

// TestGatewayInputChainKernel is the opt-in witness for K8N-7: a device connected to an in-cluster
// gateway must not reach the gateway node's own services. It runs only in a disposable PRIVILEGED Linux
// container (it creates network namespaces and writes sysctls):
//
//	TUNNEX_TEST_INPUT_CHAIN_KERNEL=1 go test ./internal/egress -run '^TestGatewayInputChainKernel$' -v
//
// The gateway's namespace is the node. A stand-in kubelet listens on the wildcard address at 10250, a
// stand-in host DNS on the node's own address at TCP 53, and a stand-in for the gateway's DNS
// forwarder on UDP and TCP 53 of every wg0 address (the tunnel address, a cluster DNS VIP, the IPv6
// tunnel address), bound to wg0 with SO_BINDTODEVICE as the forwarder binds. A device namespace sits
// behind wg0; a host on the node network sits behind eth0. A gateway "process" is one run of this test
// binary inside the node namespace, with the real Manager, the real ownership check and real `nft -f`.
//
// What it is not: a cluster. wg0 is a veth, not WireGuard, so IPv6 neighbour discovery would cross the
// input hook; static neighbour entries stand in for WireGuard's lack of it. There is no kubelet, no DNS
// forwarder, no CNI, no host-posture manager process (its table delete is replayed with nft).
//
// With TUNNEX_TEST_INPUT_CHAIN_OUT=<dir> the gateway phases write the rendered ruleset and the
// kernel's JSON listing; that is how k8snetprep/testdata/k8n7-input*.{rendered.nft,nft-ruleset.json}
// were produced.
func TestGatewayInputChainKernel(t *testing.T) {
	if os.Getenv("TUNNEX_TEST_INPUT_CHAIN_KERNEL") != "1" {
		t.Skip("opt in inside a disposable privileged Linux container")
	}
	switch phase := os.Getenv("TUNNEX_TEST_INPUT_CHAIN_PHASE"); phase {
	case "":
	case "serve":
		inputChainServe(t)
		return
	case "probe":
		inputChainProbe(t)
		return
	default:
		inputChainGateway(t, phase)
		return
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 240*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "unshare", "--mount", "--net", "--propagation", "private", "sh", "-eu", "-c", inputChainFixture, "fixture", executable)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("isolated witness failed: %v\n%s", err, out)
	}
	for _, proof := range []string{
		"RELEASED_DEVICE_REACHES_KUBELET_VIA_TUNNEL_ADDRESS",
		"RELEASED_DEVICE_REACHES_KUBELET_VIA_NODE_ADDRESS",
		"FIRST_START_READY",
		"RUNNING_NODE_CLOSED_TO_DEVICE",
		"RUNNING_DNS_OPEN_TO_DEVICE",
		"RUNNING_NODE_OPENED_CONNECTION_GETS_REPLY",
		"RUNNING_NODE_NETWORK_UNTOUCHED",
		"RUNNING_INPUT_DROP_COUNTED",
		"STOPPED_NODE_CLOSED_TO_DEVICE",
		"STOPPED_DNS_CLOSED_TO_DEVICE",
		"STOPPED_NODE_NETWORK_UNTOUCHED",
		"RESTART_OVER_STOPPED_TABLE_ACCEPTED",
		"RESTART_NODE_CLOSED_TO_DEVICE",
		"RESTART_DNS_OPEN_TO_DEVICE",
		"RESTART_NODE_OPENED_CONNECTION_GETS_REPLY",
		"RESTART_NODE_NETWORK_UNTOUCHED",
		"RESTART_OVER_RUNNING_TABLE_ACCEPTED",
		"RESTART_OVER_RELEASED_TABLE_ACCEPTED",
		"NEAR_MISSES_STILL_REFUSED",
		"OPENVPN_SET_FORM_ACCEPTED",
		"OPENVPN_NODE_CLOSED_TO_DEVICE",
		"KILL_LEAVES_NODE_CLOSED",
		"MANAGER_DELETE_IS_THE_CONTROL",
	} {
		if !strings.Contains(string(out), proof) {
			t.Fatalf("missing proof %s\n%s", proof, out)
		}
	}
	t.Logf("isolated evidence:\n%s", out)
}

func inputChainGateway(t *testing.T, phase string) {
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
	}, kernelTestHostFacts, nil)
	// An enforcing policy whose one grant covers the node network, the gateway node's own address
	// included, on the kubelet port. It reaches other nodes through forward; it must not open this one.
	policy := &nodepolicy.Compiled{Version: 15, Mode: nodepolicy.ModeEnforcing, Allow: []nodepolicy.AllowEntry{
		{SrcIP: "10.99.0.2", DstCIDR: "10.70.0.0/24", Protocol: "tcp", PortLow: 10250, PortHigh: 10250},
	}}
	m.SetPolicy(policy)
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
		if _, err := m.ReadAppliedOVPNTunnel(ctx); err != nil {
			t.Fatalf("the ownership readback of the tunnel set refused: %v", err)
		}
	}
	markers := func() {
		t.Helper()
		for _, family := range []string{"ip", "ip6"} {
			if err := hostposture.ValidateNFTMarkerChain(nft("-a", "list", "chain", family, "tunnex", "tunnex_posture_owner"), hostposture.NFTMarkerComment); err != nil {
				t.Fatalf("%s: the manager's marker check refused the table: %v", family, err)
			}
		}
	}
	save := func(name string, rendered bool) {
		dir := os.Getenv("TUNNEX_TEST_INPUT_CHAIN_OUT")
		if dir == "" {
			return
		}
		files := map[string]string{name + ".nft-ruleset.json": nft("-j", "-a", "list", "ruleset")}
		if rendered {
			subnet, err := m.observeWGSubnet(ctx)
			if err != nil {
				t.Fatal(err)
			}
			files[name+".rendered.nft"] = m.rulesetWith(subnet, policy)
		}
		for file, content := range files {
			if err := os.WriteFile(filepath.Join(dir, file), []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	input := func(family string) string { return nft("list", "chain", family, "tunnex", "input") }

	switch phase {
	case "released":
		// The released table: the same text with no input chain, as v0.1.44 renders it.
		if err := ensureIPForward(); err != nil {
			t.Fatal(err)
		}
		rs := m.rulesetWith("100.65.0.2/32", policy)
		v4, v6 := inputChains(t, rs)
		if err := nftApply(ctx, strings.Replace(strings.Replace(rs, v4, "", 1), v6, "", 1)); err != nil {
			t.Fatal(err)
		}
	case "first-start", "restart-over-running", "restart-over-released":
		if phase != "first-start" {
			// The ownership check alone, on the leftover table, before this process has loaded anything.
			if err := m.ReconcileK8sNetPrep(ctx); err != nil || !m.K8sNetPrepReady() {
				t.Fatalf("the ownership check refused the leftover table: ready=%v err=%v", m.K8sNetPrepReady(), err)
			}
		}
		start("")
		markers()
		for _, family := range []string{"ip", "ip6"} {
			if got := input(family); !strings.Contains(got, `iifname "wg0" counter packets`) || !strings.Contains(got, "tunnex_input_tunnel_drop") {
				t.Fatalf("%s: the kernel does not hold the input chain:\n%s", family, got)
			}
		}
		if phase == "first-start" {
			save("k8n7-input", true)
		}
		t.Logf("kernel ip tunnex input:\n%s", input("ip"))
	case "count":
		for _, family := range []string{"ip", "ip6"} {
			got := input(family)
			if !inputDropCountedRE.MatchString(got) {
				t.Fatalf("%s: the input drop counted nothing:\n%s", family, got)
			}
			t.Logf("kernel %s tunnex input after the probes:\n%s", family, got)
		}
	case "stop":
		start("")
		m.Teardown(ctx)
		markers()
		for _, family := range []string{"ip", "ip6"} {
			got := input(family)
			if !strings.Contains(got, "policy accept;") || !strings.Contains(got, `iifname "wg0" counter packets 0 bytes 0 drop comment "tunnex_stopped_tunnel_drop"`) ||
				strings.Count(got, "comment") != 1 {
				t.Fatalf("%s: the stopped input chain is not the one tunnel drop:\n%s", family, got)
			}
		}
		save("k8n7-input-stopped", false)
		t.Logf("kernel ip tunnex input after the stop:\n%s", input("ip"))
	case "restart-over-stopped":
		if err := m.ReconcileK8sNetPrep(ctx); err != nil || !m.K8sNetPrepReady() {
			t.Fatalf("the ownership check refused the stopped table: ready=%v err=%v", m.K8sNetPrepReady(), err)
		}
		start("")
		markers()
	case "refuse-near-miss":
		start("")
		for reason, rule := range map[string][]string{
			"Tunnex input chain does not hold exactly the registered rules": {"insert", "rule", "ip", "tunnex", "input", "iifname", "wg0", "tcp", "dport", "10250", "accept"},
			"Tunnex input listener is not the exact registered accept":      {"insert", "rule", "ip", "tunnex", "input", "position", "0", "iifname", "wg0", "tcp", "dport", "10250", "accept", "comment", "x"},
			"Tunnex input hook is not the exact registered chain":           {"add", "chain", "ip", "tunnex", "input_extra", "{", "type", "filter", "hook", "input", "priority", "0", ";", "policy", "accept", ";", "}"},
			"unknown Tunnex hook": {"add", "chain", "ip6", "tunnex", "output", "{", "type", "filter", "hook", "output", "priority", "0", ";", "policy", "accept", ";", "}"},
			"Tunnex input chain does not hold exactly the registered rules ip6": {"add", "rule", "ip6", "tunnex", "input", "iifname", "wg0", "accept"},
		} {
			reason = strings.TrimSuffix(reason, " ip6")
			if rule[0] == "insert" && rule[5] == "position" {
				// Replace the UDP DNS listener with a kubelet accept under the DNS marker.
				listing := nft("-a", "list", "chain", "ip", "tunnex", "input")
				handle := ""
				for _, line := range strings.Split(listing, "\n") {
					if strings.Contains(line, "udp dport 53") {
						handle = line[strings.LastIndex(line, " ")+1:]
					}
				}
				nft("replace", "rule", "ip", "tunnex", "input", "handle", handle, "iifname", "wg0", "fib", "daddr", ".", "iif", "type", "local", "udp", "dport", "10250", "counter", "accept", "comment", k8snetprep.InputDNSRuleComment)
			} else {
				nft(rule...)
			}
			err := m.ReconcileK8sNetPrep(ctx)
			if err == nil || !strings.Contains(err.Error(), reason) || m.K8sNetPrepReady() {
				t.Fatalf("a near-miss was not refused as %q: ready=%v err=%v\n%s", reason, m.K8sNetPrepReady(), err, nft("list", "table", "ip", "tunnex"))
			}
			// The next egress pass replaces the table's rules; an extra chain is the operator's to remove.
			for _, extra := range [][]string{{"ip", "input_extra"}, {"ip6", "output"}} {
				_, _ = nftRun(ctx, "delete", "chain", extra[0], "tunnex", extra[1])
			}
			if _, _, err := m.Reconcile(ctx); err != nil || !m.K8sNetPrepReady() {
				t.Fatalf("the egress pass did not restore the table: ready=%v err=%v", m.K8sNetPrepReady(), err)
			}
		}
	case "openvpn":
		start("tun0")
		for _, family := range []string{"ip", "ip6"} {
			if got := input(family); strings.Count(got, `iifname { "wg0", "tun0" }`) != 2 {
				t.Fatalf("%s: the input chain does not close both tunnels:\n%s", family, got)
			}
		}
		save("k8n7-input-openvpn", false)
	case "kill":
		start("")
		// SIGKILL: no Teardown. The full table, input chain included, stays.
		os.Exit(0)
	case "manager-delete":
		markers()
		nft("delete", "table", "ip", "tunnex")
		nft("delete", "table", "ip6", "tunnex")
	default:
		t.Fatalf("unknown phase %q", phase)
	}
	fmt.Printf("PHASE_DONE %s\n", phase)
}

var inputDropCountedRE = regexp.MustCompile(`iifname "wg0" counter packets [1-9][0-9]* bytes [0-9]+ drop comment "tunnex_input_tunnel_drop"`)

// inputChainServe listens on every "proto/address[/device]" in TUNNEX_TEST_INPUT_CHAIN_LISTEN and
// answers each connection or datagram with the address it came from.
func inputChainServe(t *testing.T) {
	for _, spec := range strings.Split(os.Getenv("TUNNEX_TEST_INPUT_CHAIN_LISTEN"), ",") {
		parts := strings.SplitN(spec, "/", 3)
		config := net.ListenConfig{}
		if len(parts) == 3 {
			device := parts[2]
			config.Control = func(_, _ string, raw syscall.RawConn) error {
				var bindErr error
				if err := raw.Control(func(fd uintptr) {
					bindErr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, device)
				}); err != nil {
					return err
				}
				return bindErr
			}
		}
		switch parts[0] {
		case "tcp":
			listener, err := config.Listen(context.Background(), "tcp", parts[1])
			if err != nil {
				t.Fatalf("listen %s: %v", spec, err)
			}
			go func() {
				for {
					conn, err := listener.Accept()
					if err != nil {
						return
					}
					host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
					fmt.Fprintf(conn, "ANSWER from=%s\n", host)
					conn.Close()
				}
			}()
		case "udp":
			packet, err := config.ListenPacket(context.Background(), "udp", parts[1])
			if err != nil {
				t.Fatalf("listen %s: %v", spec, err)
			}
			go func() {
				buf := make([]byte, 512)
				for {
					_, from, err := packet.ReadFrom(buf)
					if err != nil {
						return
					}
					host, _, _ := net.SplitHostPort(from.String())
					_, _ = packet.WriteTo([]byte("ANSWER from="+host+"\n"), from)
				}
			}()
		default:
			t.Fatalf("bad listen spec %q", spec)
		}
	}
	if err := os.WriteFile(os.Getenv("TUNNEX_TEST_INPUT_CHAIN_READY"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	time.Sleep(220 * time.Second)
}

// inputChainProbe makes one call ("tcp" or "udp" to TUNNEX_TEST_INPUT_CHAIN_ADDR) and succeeds only
// on an answer within 1.5 seconds.
func inputChainProbe(t *testing.T) {
	proto, address := os.Getenv("TUNNEX_TEST_INPUT_CHAIN_PROTO"), os.Getenv("TUNNEX_TEST_INPUT_CHAIN_ADDR")
	conn, err := net.DialTimeout(proto, address, 1500*time.Millisecond)
	if err != nil {
		t.Fatalf("PROBE_FAILED %s %s: %v", proto, address, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(1500 * time.Millisecond))
	if proto == "udp" {
		if _, err := conn.Write([]byte("q")); err != nil {
			t.Fatalf("PROBE_FAILED %s %s: %v", proto, address, err)
		}
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("PROBE_FAILED %s %s: %v", proto, address, err)
	}
	fmt.Printf("PROBE_OPEN %s %s %s", proto, address, line)
}

const inputChainFixture = `
testbin=$1
run='^TestGatewayInputChainKernel$'
for ns in tnx-gw tnx-dev tnx-host; do
  ip netns add "$ns"
  ip -n "$ns" link set lo up
done
# The tunnel: a veth between the device and the gateway node's wg0.
ip link add tunnel-gw type veth peer name tunnel-dev
ip link set tunnel-gw netns tnx-gw
ip -n tnx-gw link set tunnel-gw name wg0
ip link set tunnel-dev netns tnx-dev
ip -n tnx-dev link set tunnel-dev name eth0
# The node network: the gateway node and another host on it.
ip link add gw-node type veth peer name host-node
ip link set gw-node netns tnx-gw
ip -n tnx-gw link set gw-node name eth0
ip link set host-node netns tnx-host
ip -n tnx-host link set host-node name eth0
for pair in 'tnx-gw wg0' 'tnx-gw eth0' 'tnx-dev eth0' 'tnx-host eth0'; do
  set -- $pair
  ip -n "$1" link set "$2" up
done
# The gateway node: its tunnel address, a cluster DNS VIP on wg0 (as ReconcileDNSVIPs assigns it), its
# own address on the node network, and the device range behind wg0. IPv6 the same.
ip -n tnx-gw addr add 100.65.0.2/32 dev wg0
ip -n tnx-gw addr add 100.64.0.53/32 dev wg0 label wg0:tnxk8s
ip -n tnx-gw route add 10.99.0.0/24 dev wg0
ip -n tnx-gw -6 addr add fd00:65::2/128 dev wg0 nodad
ip -n tnx-gw -6 route add fd00:99::/64 dev wg0
ip -n tnx-gw addr add 10.70.0.6/24 dev eth0
ip -n tnx-gw -6 addr add fd70::6/64 dev eth0 nodad
# The device: everything through the gateway.
ip -n tnx-dev addr add 10.99.0.2/32 dev eth0
ip -n tnx-dev route add 100.65.0.2/32 dev eth0
ip -n tnx-dev route add default via 100.65.0.2 dev eth0
ip -n tnx-dev -6 addr add fd00:99::2/128 dev eth0 nodad
ip -n tnx-dev -6 route add fd00:65::2/128 dev eth0
ip -n tnx-dev -6 route add default via fd00:65::2 dev eth0
# WireGuard has no neighbour discovery; the veth needs it, and it would cross the input hook.
gwmac=$(ip -n tnx-gw -o link show wg0 | sed -n 's/.*link\/ether \([0-9a-f:]*\).*/\1/p')
devmac=$(ip -n tnx-dev -o link show eth0 | sed -n 's/.*link\/ether \([0-9a-f:]*\).*/\1/p')
ip -n tnx-dev -6 neigh add fd00:65::2 lladdr "$gwmac" dev eth0 nud permanent
ip -n tnx-gw -6 neigh add fd00:99::2 lladdr "$devmac" dev wg0 nud permanent
# The other host on the node network.
ip -n tnx-host addr add 10.70.0.9/24 dev eth0
ip -n tnx-host -6 addr add fd70::9/64 dev eth0 nodad
for ns in tnx-gw tnx-dev tnx-host; do
  ip netns exec "$ns" sh -c 'for f in /proc/sys/net/ipv4/conf/*/rp_filter; do echo 0 > "$f"; done'
done
pids=""
trap 'kill $pids 2>/dev/null || true' EXIT
serve() {
  rm -f /tmp/input-"$1".ready
  ip netns exec "$2" env TUNNEX_TEST_INPUT_CHAIN_PHASE=serve TUNNEX_TEST_INPUT_CHAIN_LISTEN="$3" TUNNEX_TEST_INPUT_CHAIN_READY=/tmp/input-"$1".ready "$testbin" -test.run "$run" > /tmp/input-"$1".log 2>&1 &
  pids="$pids $!"
  for i in $(seq 1 40); do [ -e /tmp/input-"$1".ready ] && return 0; sleep 0.25; done
  echo "the $1 stand-in did not start"; cat /tmp/input-"$1".log; exit 1
}
# On the node: the kubelet (wildcard, both families), a host DNS on the node's own address, and the
# gateway's DNS forwarder on every wg0 address, bound to wg0.
serve kubelet tnx-gw 'tcp/:10250'
serve hostdns tnx-gw 'tcp/10.70.0.6:53'
serve dns tnx-gw 'udp/100.65.0.2:53/wg0,tcp/100.65.0.2:53/wg0,udp/100.64.0.53:53/wg0,tcp/100.64.0.53:53/wg0,udp/[fd00:65::2]:53/wg0,tcp/[fd00:65::2]:53/wg0'
# On the device: a service the node opens a connection to.
serve device tnx-dev 'tcp/:7000'

gw() { ip netns exec tnx-gw env TUNNEX_TEST_INPUT_CHAIN_PHASE="$1" "$testbin" -test.run "$run" -test.v > /tmp/input-gw.log 2>&1 || { cat /tmp/input-gw.log; return 1; }; grep -E 'kernel|PHASE_DONE|^[[:space:]]+(table|chain|type|iifname|})' /tmp/input-gw.log || true; }
probe() { ip netns exec "$1" env TUNNEX_TEST_INPUT_CHAIN_PHASE=probe TUNNEX_TEST_INPUT_CHAIN_PROTO="$2" TUNNEX_TEST_INPUT_CHAIN_ADDR="$3" "$testbin" -test.run "$run" > /tmp/input-probe.out 2>&1; }
open() { if probe "$@"; then grep PROBE_OPEN /tmp/input-probe.out; else echo "UNEXPECTED_CLOSED $*"; cat /tmp/input-probe.out; exit 1; fi; }
closed() { if probe "$@"; then echo "UNEXPECTED_OPEN $*"; cat /tmp/input-probe.out; exit 1; else echo "closed: $*"; fi; }
node_closed() {
  closed tnx-dev tcp 100.65.0.2:10250
  closed tnx-dev tcp 10.70.0.6:10250
  closed tnx-dev tcp '[fd00:65::2]:10250'
  closed tnx-dev tcp '[fd70::6]:10250'
  closed tnx-dev tcp 10.70.0.6:53
}
dns_open() {
  open tnx-dev udp 100.65.0.2:53
  open tnx-dev tcp 100.65.0.2:53
  open tnx-dev udp 100.64.0.53:53
  open tnx-dev tcp 100.64.0.53:53
  open tnx-dev udp '[fd00:65::2]:53'
  open tnx-dev tcp '[fd00:65::2]:53'
}
dns_closed() {
  closed tnx-dev udp 100.65.0.2:53
  closed tnx-dev tcp 100.64.0.53:53
  closed tnx-dev udp '[fd00:65::2]:53'
}
node_network() {
  open tnx-host tcp 10.70.0.6:10250
  open tnx-host tcp '[fd70::6]:10250'
  open tnx-host tcp 10.70.0.6:53
}
reply() {
  open tnx-gw tcp 10.99.0.2:7000
  open tnx-gw tcp '[fd00:99::2]:7000'
}

# 1. The control: the released table (no input chain) lets the device reach the node's kubelet.
gw released
open tnx-dev tcp 100.65.0.2:10250
echo RELEASED_DEVICE_REACHES_KUBELET_VIA_TUNNEL_ADDRESS
open tnx-dev tcp 10.70.0.6:10250
echo RELEASED_DEVICE_REACHES_KUBELET_VIA_NODE_ADDRESS

# 2. First start, over the released table (an upgrade).
gw first-start
echo FIRST_START_READY
node_closed
echo RUNNING_NODE_CLOSED_TO_DEVICE
dns_open
echo RUNNING_DNS_OPEN_TO_DEVICE
reply
echo RUNNING_NODE_OPENED_CONNECTION_GETS_REPLY
node_network
echo RUNNING_NODE_NETWORK_UNTOUCHED
gw count
echo RUNNING_INPUT_DROP_COUNTED

# 3. Normal stop.
gw stop
node_closed
echo STOPPED_NODE_CLOSED_TO_DEVICE
dns_closed
echo STOPPED_DNS_CLOSED_TO_DEVICE
node_network
echo STOPPED_NODE_NETWORK_UNTOUCHED

# 4. Restart over the stopped table.
gw restart-over-stopped
echo RESTART_OVER_STOPPED_TABLE_ACCEPTED
node_closed
echo RESTART_NODE_CLOSED_TO_DEVICE
dns_open
echo RESTART_DNS_OPEN_TO_DEVICE
reply
echo RESTART_NODE_OPENED_CONNECTION_GETS_REPLY
node_network
echo RESTART_NODE_NETWORK_UNTOUCHED

# 5. Restart over a running table, and over the released one (an upgrade from v0.1.44).
gw restart-over-running
echo RESTART_OVER_RUNNING_TABLE_ACCEPTED
gw released
gw restart-over-released
node_closed
echo RESTART_OVER_RELEASED_TABLE_ACCEPTED

# 6. Near-misses written into the live chains.
gw refuse-near-miss
node_closed
echo NEAR_MISSES_STILL_REFUSED

# 7. OpenVPN co-terminated: tun0 is closed too.
ip -n tnx-gw link add tun0 type dummy
ip -n tnx-gw link set tun0 up
gw openvpn
echo OPENVPN_SET_FORM_ACCEPTED
node_closed
dns_open
echo OPENVPN_NODE_CLOSED_TO_DEVICE
ip -n tnx-gw link del tun0

# 8. Kill: the running table stays.
gw kill
node_closed
dns_open
echo KILL_LEAVES_NODE_CLOSED

# 9. The manager's last-owner delete removes the table: the node is open again. It is the input chain
#    that closes it. (The manager also removes wg0 then; it is kept here to show the control.)
gw stop
gw manager-delete
open tnx-dev tcp 100.65.0.2:10250
echo MANAGER_DELETE_IS_THE_CONTROL
`
