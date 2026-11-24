#!/bin/sh
# probe.sh <label> <url-or-host:port> ; device is netns tnxdev
# Copied from walk-artifacts/k8n6-cilium-service-reach-20261124/probe.sh; this copy also prints the
# tunnex forward verdict lines of the trace.
label=$1; target=$2; lxc=${LXC:-lxc14fcf69d02cb}
nft add table ip f10trace 2>/dev/null
nft 'flush table ip f10trace'
nft 'add chain ip f10trace pre { type filter hook prerouting priority -350; policy accept; }'
nft 'add rule ip f10trace pre iifname "wg0" ip saddr 10.99.0.2 meta nftrace set 1'
conntrack -F >/dev/null 2>&1
fwd() { nft list chain ip tunnex forward | grep -oE 'counter packets [0-9]+ bytes [0-9]+ (accept|drop)? ?comment "[a-z_]+"' | sed 's/ bytes [0-9]*//'; }
echo "=== $label: $target"
echo "--- tunnex forward counters before"; fwd
timeout 6 nft monitor trace > /tmp/trace.$$ 2>&1 &
timeout 6 tcpdump -nli wg0 -c 6 'tcp' > /tmp/wg0.$$ 2>/dev/null &
timeout 6 tcpdump -nli $lxc -c 6 'tcp' > /tmp/lxc.$$ 2>/dev/null &
sleep 1
ip netns exec tnxdev curl -sS -m 3 -o /tmp/body.$$ -w 'http_code=%{http_code}\n' "$target" 2>&1 | sed 's/^/curl: /'
echo "body: $(cat /tmp/body.$$ 2>/dev/null)"
sleep 5
echo "--- tunnex forward counters after"; fwd
echo "--- tcpdump wg0 (before tc ingress)"; head -4 /tmp/wg0.$$
echo "--- tcpdump $lxc (pod side)"; head -4 /tmp/lxc.$$
echo "--- nft monitor trace (prerouting priority -350, iifname wg0 saddr 10.99.0.2)"; grep -E 'trace id' /tmp/trace.$$ | head -3; echo "(tunnex/filter verdict lines:)"; grep -E 'ip tunnex|ip filter FORWARD|ip filter INPUT|ip nat PREROUTING' /tmp/trace.$$ | head -6; echo "(tunnex forward verdicts:)"; grep -E 'ip tunnex forward (rule|policy)' /tmp/trace.$$ | head -3; echo "trace lines: $(grep -c 'trace id' /tmp/trace.$$)"
echo "--- netfilter conntrack for 10.99.0.2"; conntrack -L -s 10.99.0.2 2>&1 | head -3
rm -f /tmp/*.$$
