#!/bin/sh
# podtodev.sh <label>: the web pod opens a TCP connection to the device (10.99.0.2:8000). HR_DIR as probe-all.sh.
cfg=$1; d=${HR_DIR:-.}; o=$d/out/probe-$cfg-pod-to-device.txt
K="kubectl --kubeconfig $d/kubeconfig"
$K -n kube-system exec tools -- sh -c '(ip netns exec tnxdev timeout 30 socat TCP-LISTEN:8000,fork,reuseaddr SYSTEM:"echo DEVICE_ANSWER" >/dev/null 2>&1 &); nft add table ip f10trace; nft flush table ip f10trace; nft "add chain ip f10trace pre { type filter hook prerouting priority -350; policy accept; }"; nft "add rule ip f10trace pre ip daddr 10.99.0.2 tcp dport 8000 meta nftrace set 1"'
B=$($K -n kube-system exec tools -- sh -c 'nft list chain ip tunnex forward | grep -oE "packets [0-9]+ bytes [0-9]+ (drop )?comment \"tunnex_(default_drop|ct_invalid_drop)\""')
( $K -n kube-system exec tools -- timeout 8 tcpdump -nli wg0 -c 4 'tcp port 8000' > $o.wg0 2>/dev/null & ); ( $K -n kube-system exec tools -- timeout 8 nft monitor trace > $o.trace 2>&1 & ); sleep 1
POD=$($K get pod -l app=web -o name)
R=$($K exec $POD -- /agnhost connect 10.99.0.2:8000 --timeout 3s 2>&1; echo "exit=$?")
sleep 7
Af=$($K -n kube-system exec tools -- sh -c 'nft list chain ip tunnex forward | grep -oE "packets [0-9]+ bytes [0-9]+ (drop )?comment \"tunnex_(default_drop|ct_invalid_drop)\""')
{ echo "=== $cfg: pod web -> device 10.99.0.2:8000"; echo "agnhost connect: $R"; echo "tunnex counters before:"; echo "$B"; echo "tunnex counters after:"; echo "$Af"; echo "--- tcpdump wg0"; cat $o.wg0; echo "--- nft trace (prerouting -350, daddr 10.99.0.2 dport 8000), tunnex lines:"; grep -E 'ip tunnex' $o.trace | head -4; echo "trace lines: $(grep -c 'trace id' $o.trace)"; } > $o; rm $o.wg0 $o.trace; cat $o
