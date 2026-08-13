#!/usr/bin/env bash
# S7.2 box-proof spokes — run device A + B as WireGuard peers INSIDE the gateway VM,
# each in its own network namespace. Removes all client-side variables (host firewalls,
# NAT hairpin, remote machines) so every proof is deterministic + locally timeable.
#
#   ./s72-spokes.sh up   A.conf B.conf     # A.conf/B.conf = configs downloaded from the dashboard
#   ./s72-spokes.sh ping                   # A -> B and B -> A (proves reachability)
#   ./s72-spokes.sh a <cmd...>             # run a command in spoke A's namespace (e.g. ping / curl / nc)
#   ./s72-spokes.sh b <cmd...>
#   ./s72-spokes.sh down
#
# Needs: root, wireguard-tools + iproute2 on the HOST (sudo apt-get install -y wireguard-tools).
# The WG endpoint is overridden to the VM's own primary IP:51820 (the container publishes it) —
# NOT the config's public endpoint, because a cloud VM usually can't hairpin to its own public IP.
set -euo pipefail

NS_A=s72a; NS_B=s72b
VETH_HP=s72a-h; VETH_BP=s72b-h
HOST_IP="$(ip route get 1.1.1.1 2>/dev/null | grep -oP 'src \K\S+' | head -1)"
GW_PORT=51820

need_root() { [ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }; }

# parse_conf <file> <field>  — field = PrivateKey | Address | PeerPublicKey
parse_conf() {
	local f=$1 field=$2
	case "$field" in
	PrivateKey)    grep -iE '^\s*PrivateKey'  "$f" | head -1 | cut -d= -f2- | tr -d ' ' ;;
	Address)       grep -iE '^\s*Address'     "$f" | head -1 | cut -d= -f2- | tr -d ' ' | cut -d, -f1 ;;
	PeerPublicKey) awk '/^\[Peer\]/{p=1} p&&/^[[:space:]]*PublicKey/{print; exit}' "$f" | cut -d= -f2- | tr -d ' ' ;;
	esac
}

setup_spoke() {
	local ns=$1 veth=$2 hostside=$3 nsIP=$4 conf=$5
	local priv addr gwpub tunIP
	priv="$(parse_conf "$conf" PrivateKey)"
	addr="$(parse_conf "$conf" Address)"                 # e.g. 10.99.0.2/32
	gwpub="$(parse_conf "$conf" PeerPublicKey)"
	tunIP="${addr%%/*}"
	[ -n "$priv" ] && [ -n "$gwpub" ] && [ -n "$addr" ] || { echo "!! could not parse $conf"; exit 1; }

	ip netns add "$ns"
	ip link add "$veth" type veth peer name "${veth}n"
	ip link set "${veth}n" netns "$ns"
	ip addr add "${hostside}/30" dev "$veth"; ip link set "$veth" up
	ip netns exec "$ns" ip addr add "${nsIP}/30" dev "${veth}n"
	ip netns exec "$ns" ip link set "${veth}n" up
	ip netns exec "$ns" ip link set lo up
	ip netns exec "$ns" ip route add default via "$hostside"

	# WG in the namespace, endpoint overridden to the VM's own IP:51820 (avoids hairpin).
	ip netns exec "$ns" ip link add wg0 type wireguard
	ip netns exec "$ns" wg set wg0 private-key <(printf '%s' "$priv") \
		peer "$gwpub" endpoint "${HOST_IP}:${GW_PORT}" allowed-ips 10.99.0.0/24 persistent-keepalive 15
	ip netns exec "$ns" ip addr add "$addr" dev wg0
	ip netns exec "$ns" ip link set wg0 up
	ip netns exec "$ns" ip route add 10.99.0.0/24 dev wg0
	echo "   $ns: $tunIP  (gw peer ${gwpub:0:8}…, endpoint ${HOST_IP}:${GW_PORT})"
}

case "${1:-}" in
up)
	need_root; A="${2:?A.conf}"; B="${3:?B.conf}"
	[ -n "$HOST_IP" ] || { echo "could not derive HOST_IP"; exit 1; }
	sysctl -qw net.ipv4.ip_forward=1
	# NAT the veth subnets out so the namespaces reach the host-published :51820.
	nft list table ip s72nat >/dev/null 2>&1 || nft -f - <<-EOF
		add table ip s72nat
		add chain ip s72nat post { type nat hook postrouting priority srcnat; policy accept; }
		add rule ip s72nat post ip saddr 10.200.0.0/24 masquerade
	EOF
	echo ">> bringing up spokes (host ${HOST_IP}):"
	setup_spoke "$NS_A" "$VETH_HP" 10.200.0.1 10.200.0.2 "$A"
	setup_spoke "$NS_B" "$VETH_BP" 10.200.0.5 10.200.0.6 "$B"
	sleep 2
	echo ">> handshakes:"; ip netns exec "$NS_A" wg show wg0 latest-handshakes; ip netns exec "$NS_B" wg show wg0 latest-handshakes
	echo ">> try: sudo $0 ping"
	;;
ping)
	need_root
	bIP="$(ip netns exec "$NS_B" ip -4 -o addr show wg0 | grep -oP 'inet \K[0-9.]+')"
	aIP="$(ip netns exec "$NS_A" ip -4 -o addr show wg0 | grep -oP 'inet \K[0-9.]+')"
	echo "== A($aIP) -> B($bIP) =="; ip netns exec "$NS_A" ping -c3 -W2 "$bIP" || true
	echo "== B($bIP) -> A($aIP) =="; ip netns exec "$NS_B" ping -c3 -W2 "$aIP" || true
	;;
a) need_root; shift; ip netns exec "$NS_A" "$@" ;;
b) need_root; shift; ip netns exec "$NS_B" "$@" ;;
down)
	need_root
	ip netns del "$NS_A" 2>/dev/null || true; ip netns del "$NS_B" 2>/dev/null || true
	ip link del "$VETH_HP" 2>/dev/null || true; ip link del "$VETH_BP" 2>/dev/null || true
	nft delete table ip s72nat 2>/dev/null || true
	echo ">> spokes torn down"
	;;
*) echo "usage: $0 up A.conf B.conf | ping | a <cmd> | b <cmd> | down"; exit 1 ;;
esac
