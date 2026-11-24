cfg=$1; o=${F10_DIR:-.}/out/probe-$cfg-pod-to-device.txt
docker exec k8n-f10-tools sh -c '(ip netns exec tnxdev timeout 30 socat TCP-LISTEN:8000,fork,reuseaddr SYSTEM:"echo DEVICE_ANSWER" >/dev/null 2>&1 &); nft add table ip f10trace; nft flush table ip f10trace; nft "add chain ip f10trace pre { type filter hook prerouting priority -350; policy accept; }"; nft "add rule ip f10trace pre ip daddr 10.99.0.2 tcp dport 8000 meta nftrace set 1"' 
B=$(docker exec k8n-f10-tools sh -c 'nft list chain ip tunnex forward | grep -oE "packets [0-9]+ bytes [0-9]+ comment \"tunnex_default_drop\""')
( docker exec k8n-f10-tools timeout 8 tcpdump -nli wg0 -c 4 'tcp port 8000' > $o.wg0 2>/dev/null & ); ( docker exec k8n-f10-tools timeout 8 nft monitor trace > $o.trace 2>&1 & ); sleep 1
POD=$(kubectl --kubeconfig ${F10_DIR:-.}/kubeconfig get pod -l app=web -o name)
R=$(kubectl --kubeconfig ${F10_DIR:-.}/kubeconfig exec $POD -- /agnhost connect 10.99.0.2:8000 --timeout 3s 2>&1; echo "exit=$?")
sleep 7
A=$(docker exec k8n-f10-tools sh -c 'nft list chain ip tunnex forward | grep -oE "packets [0-9]+ bytes [0-9]+ comment \"tunnex_default_drop\""')
{ echo "=== $cfg: pod web (10.244.0.35) -> device 10.99.0.2:8000"; echo "agnhost connect: $R"; echo "tunnex_default_drop before: $B"; echo "tunnex_default_drop after:  $A"; echo "--- tcpdump wg0"; cat $o.wg0; echo "--- nft trace (prerouting -350, daddr 10.99.0.2 dport 8000), tunnex lines:"; grep -E 'ip tunnex' $o.trace | head -4; echo "trace lines: $(grep -c 'trace id' $o.trace)"; } > $o; rm $o.wg0 $o.trace; cat $o
