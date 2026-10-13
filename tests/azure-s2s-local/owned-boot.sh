#!/usr/bin/env bash
set -euo pipefail
[[ $(hostname) == tunnex-peer ]] || exit 1
for name in tunnex-azure-cloud-postgres tunnex-azure-cloud-redis tunnex-azure-cloud-api tunnex-azure-cloud-netns tunnex-azure-private-ui tunnex-azure-cloud-gateway; do
 [[ $(docker inspect -f '{{index .Config.Labels "tunnex.owner"}}' "$name") == azure-s2s-01a12505 ]] || exit 1
done
# Ubuntu clears /tmp at boot; restore the same source binary from durable storage.
api=/home/ubuntu/tunnex-azure-lab/binaries/tunnex-api
[[ -f "$api" && ! -L "$api" && $(stat -c %u "$api") == 0 ]]
install -d -m755 /tmp/azure-s2s-build
if [[ -d /tmp/azure-s2s-build/tunnex-api ]]; then rmdir /tmp/azure-s2s-build/tunnex-api;fi
install -m755 "$api" /tmp/azure-s2s-build/tunnex-api
for name in tunnex-azure-cloud-postgres tunnex-azure-cloud-redis tunnex-azure-cloud-api; do docker start "$name" >/dev/null; done
healthy=false
for attempt in $(seq 1 30); do if curl --fail --silent http://127.0.0.1:48083/healthz >/dev/null; then healthy=true;break;fi;sleep 1;done
[[ "$healthy" == true ]] || exit 1
docker start tunnex-azure-cloud-netns >/dev/null
pid=$(docker inspect -f '{{.State.Pid}}' tunnex-azure-cloud-netns)
[[ $pid -gt 1 ]]
if ip netns list | cut -d ' ' -f1 | grep -qx azure-s2s-client; then exit 1;fi
ip netns add azure-s2s-client
ip link add az-s2s-lan type veth peer name az-s2s-client
ip link set az-s2s-client netns azure-s2s-client
ip -n azure-s2s-client address add 10.233.10.2/24 dev az-s2s-client
ip -n azure-s2s-client link set az-s2s-client up
ip -n azure-s2s-client link set lo up
ip -n azure-s2s-client route add default via 10.233.10.1
ip link set az-s2s-lan netns "$pid"
nsenter -t "$pid" -n ip address add 10.233.10.1/24 dev az-s2s-lan
nsenter -t "$pid" -n ip link set az-s2s-lan up
docker start tunnex-azure-private-ui >/dev/null
# Initial recovery intentionally leaves the node stopped for exact receipt assembly.
if [[ ! -e /var/lib/tunnex-azure-owned-boot/keep-agent-stopped ]]; then docker start tunnex-azure-cloud-gateway >/dev/null;fi
