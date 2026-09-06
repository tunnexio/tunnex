//go:build linux

package k8snetprep

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// This opt-in witness runs only in a disposable Linux container with namespace
// capabilities. The outer child isolates mount propagation and networking
// before creating fixture namespaces. wg0 is a veth: this proves real netfilter
// ingress/egress and NAT behavior, not WireGuard authentication or AWS live HA.
func TestAWSTransitKernelPackets(t *testing.T) {
	if os.Getenv("TUNNEX_TEST_AWS_TRANSIT_KERNEL") != "1" {
		t.Skip("opt in inside a disposable Linux namespace-capable container")
	}
	if phase := os.Getenv("TUNNEX_TEST_AWS_TRANSIT_PHASE"); phase != "" {
		nft := func(ctx context.Context, args ...string) (string, error) {
			out, err := exec.CommandContext(ctx, "nft", args...).CombinedOutput()
			return string(out), err
		}
		r := NewWithAWS("wg0", nft, nil, func(context.Context) (AuthorityGrant, func(), error) {
			scope := ScopeIPMasqAndAWSTransit
			if phase == "legacy" {
				scope = ScopeIPMasqAndAWS
			}
			return AuthorityGrant{Scope: scope, NotAfter: time.Now().Add(5 * time.Second)}, func() {}, nil
		})
		before, err := r.readOwnedCNISnapshot(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if phase == "withdraw" {
			_, err = r.Withdraw(t.Context())
		} else {
			_, err = r.Reconcile(t.Context(), "10.99.0.0/24")
		}
		if err != nil {
			t.Fatal(err)
		}
		after, err := r.readOwnedCNISnapshot(t.Context())
		if err != nil || transitForeignFingerprint(before) != transitForeignFingerprint(after) {
			t.Fatalf("foreign rules changed: %v", err)
		}
		t.Logf("production %s exact native/compat readback passed", phase)
		return
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "unshare", "--mount", "--net", "--propagation", "private", "sh", "-eu", "-c", awsTransitPacketFixture, "fixture", executable)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("isolated packet witness failed: %v\n%s", err, out)
	}
	for _, proof := range []string{"LEGACY_TRANSIT_FAIL", "TRANSIT_SOURCE_PRESERVED", "RETURN_SOURCE_PRESERVED", "NON_WG_INGRESS_SNAT", "ORDINARY_EGRESS_SNAT", "POLICY_DENY_PRESERVED", "WITHDRAWAL_RESTORES_SNAT"} {
		if !strings.Contains(string(out), proof) {
			t.Fatalf("missing proof %s\n%s", proof, out)
		}
	}
	t.Logf("isolated packet evidence:\n%s", out)
}

func transitForeignFingerprint(snapshot *cniSnapshot) string {
	copy := &cniSnapshot{chains: snapshot.chains, rules: map[string][]nftRuleView{}}
	for key, rules := range snapshot.rules {
		for _, rule := range rules {
			if rule.Comment != AWSOwnedRuleComment && rule.Comment != AWSTransitOwnedRuleComment {
				copy.rules[key] = append(copy.rules[key], rule)
			}
		}
	}
	return copy.fingerprint()
}

const awsTransitPacketFixture = `
testbin=$1
for ns in tnx-router tnx-client tnx-service tnx-egress tnx-pod; do
  ip netns add "$ns"
  ip -n "$ns" link set lo up
done
ip link add br-test type bridge
ip link set br-test up
for pair in 'tnx-router wg0 r-bridge' 'tnx-client eth0 c-bridge' 'tnx-service eth0 s-bridge'; do
  set -- $pair
  ip link add "$3" type veth peer name fixture-peer
  ip link set fixture-peer netns "$1"
  ip -n "$1" link set fixture-peer name "$2"
  ip -n "$1" link set "$2" up
  ip link set "$3" master br-test
  ip link set "$3" up
done
ip link add ext-router type veth peer name ext-peer
ip link set ext-router netns tnx-router
ip -n tnx-router link set ext-router name eth0
ip -n tnx-router link set eth0 up
ip link set ext-peer netns tnx-egress
ip -n tnx-egress link set ext-peer name eth0
ip -n tnx-egress link set eth0 up
ip link add pod-router type veth peer name pod-peer
ip link set pod-router netns tnx-router
ip -n tnx-router link set pod-router name pod0
ip -n tnx-router link set pod0 up
ip link set pod-peer netns tnx-pod
ip -n tnx-pod link set pod-peer name eth0
ip -n tnx-pod link set eth0 up
ip -n tnx-router addr add 10.99.0.1/24 dev wg0
ip -n tnx-router addr add 100.96.0.1/24 dev wg0
ip -n tnx-router addr add 192.0.2.1/24 dev eth0
ip -n tnx-router addr add 198.51.100.1/24 dev eth0
ip -n tnx-router addr add 10.98.0.1/24 dev pod0
ip -n tnx-router route add 10.99.0.3/32 dev pod0
ip -n tnx-client addr add 10.99.0.2/24 dev eth0
ip -n tnx-client route add default via 10.99.0.1
ip -n tnx-service addr add 100.96.0.3/24 dev eth0
ip -n tnx-service route add default via 100.96.0.1
ip -n tnx-egress addr add 198.51.100.2/24 dev eth0
ip -n tnx-egress route add default via 198.51.100.1
ip -n tnx-pod addr add 10.99.0.3/32 dev eth0
ip -n tnx-pod route add 10.98.0.1/32 dev eth0
ip -n tnx-pod route add default via 10.98.0.1
ip netns exec tnx-router sysctl -qw net.ipv4.ip_forward=1
for ns in tnx-router tnx-client tnx-service tnx-egress tnx-pod; do
  ip netns exec "$ns" sh -c 'for f in /proc/sys/net/ipv4/conf/*/rp_filter /proc/sys/net/ipv4/conf/*/send_redirects /proc/sys/net/ipv4/conf/*/accept_redirects; do echo 0 > "$f"; done'
done
ipt() { ip netns exec tnx-router iptables-nft "$@"; }
ipt -t nat -N KUBE-POSTROUTING
ipt -t nat -N AWS-SNAT-CHAIN-0
ipt -t nat -A POSTROUTING -m comment --comment 'kubernetes postrouting rules' -j KUBE-POSTROUTING
ipt -t nat -A POSTROUTING -m comment --comment 'AWS SNAT CHAIN' -j AWS-SNAT-CHAIN-0
ipt -t nat -A KUBE-POSTROUTING -m mark ! --mark 0x4000/0x4000 -j RETURN
ipt -t nat -A KUBE-POSTROUTING -j MARK --set-xmark 0x4000/0x0
ipt -t nat -A KUBE-POSTROUTING -m comment --comment 'kubernetes service traffic requiring SNAT' -j MASQUERADE --random-fully
ipt -t nat -A AWS-SNAT-CHAIN-0 -d 192.0.2.0/24 -m comment --comment 'AWS SNAT CHAIN' -j RETURN
ipt -t nat -A AWS-SNAT-CHAIN-0 ! -o vlan+ -m comment --comment 'AWS, SNAT' -m addrtype ! --dst-type LOCAL -j SNAT --to-source 192.0.2.1 --random-fully
phase() { ip netns exec tnx-router env TUNNEX_TEST_AWS_TRANSIT_PHASE="$1" "$testbin" -test.run '^TestAWSTransitKernelPackets$' -test.v; }
# Receiver policy makes successful probes witnesses of the observed source.
sipt() { ip netns exec tnx-service iptables-nft "$@"; }
sipt -A INPUT -p icmp --icmp-type echo-request -s 10.99.0.2 -j ACCEPT
sipt -A INPUT -p icmp --icmp-type echo-request -j DROP
phase legacy
if ip netns exec tnx-client ping -c 1 -W 1 100.96.0.3; then exit 1; fi
echo LEGACY_TRANSIT_FAIL
phase transit
ip netns exec tnx-client ping -c 1 -W 2 100.96.0.3
echo TRANSIT_SOURCE_PRESERVED
# Reverse initiated flow must also retain Service source at the client.
ip netns exec tnx-client iptables-nft -A INPUT -p icmp --icmp-type echo-request ! -s 100.96.0.3 -j DROP
ip netns exec tnx-service ping -c 1 -W 2 10.99.0.2
echo RETURN_SOURCE_PRESERVED
# Same pool source arriving on pod0 is not exempted.
sipt -I INPUT 1 -p icmp --icmp-type echo-request -s 192.0.2.1 -j ACCEPT
ip netns exec tnx-pod ping -c 1 -W 2 100.96.0.3
echo NON_WG_INGRESS_SNAT
ip netns exec tnx-egress iptables-nft -A INPUT -p icmp --icmp-type echo-request ! -s 192.0.2.1 -j DROP
ip netns exec tnx-client ping -c 1 -W 2 198.51.100.2
echo ORDINARY_EGRESS_SNAT
# An independent forwarding denial must not be bypassed by NAT RETURN.
ipt -I FORWARD 1 -s 10.99.0.2 -d 100.96.0.3 -j DROP
if ip netns exec tnx-client ping -c 1 -W 1 100.96.0.3; then exit 1; fi
echo POLICY_DENY_PRESERVED
ipt -D FORWARD -s 10.99.0.2 -d 100.96.0.3 -j DROP
phase withdraw
# The first rule accepts only the SNAT source; deny every other source before
# the earlier client-source acceptance, without depending on xt deletion match.
sipt -I INPUT 2 -p icmp --icmp-type echo-request -j DROP
ip netns exec tnx-client ping -c 1 -W 2 100.96.0.3
echo WITHDRAWAL_RESTORES_SNAT
`
