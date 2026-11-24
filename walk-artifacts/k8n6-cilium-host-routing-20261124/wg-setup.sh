set -eu
umask 077
mkdir -p /root/wg
wg genkey > /root/wg/gw.key; wg pubkey < /root/wg/gw.key > /root/wg/gw.pub
wg genkey > /root/wg/dev.key; wg pubkey < /root/wg/dev.key > /root/wg/dev.pub
ip netns add tnxdev
ip -n tnxdev link set lo up
# Gateway side, in the node's network namespace.
ip link add wg0 type wireguard
wg set wg0 listen-port 51820 private-key /root/wg/gw.key peer "$(cat /root/wg/dev.pub)" allowed-ips 10.99.0.2/32 endpoint 127.0.0.1:51821
ip addr add 10.99.0.1/24 dev wg0
ip link set wg0 up
# Device side: created here so its UDP socket stays in the node namespace, then moved.
ip link add wgdev type wireguard
wg set wgdev listen-port 51821 private-key /root/wg/dev.key peer "$(cat /root/wg/gw.pub)" allowed-ips 0.0.0.0/0 endpoint 127.0.0.1:51820 persistent-keepalive 5
ip link set wgdev netns tnxdev
ip -n tnxdev addr add 10.99.0.2/32 dev wgdev
ip -n tnxdev link set wgdev up
ip -n tnxdev route add default dev wgdev
