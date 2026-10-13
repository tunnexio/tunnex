#!/bin/sh
set -eu
cd "$(dirname "$0")"
umask 077
./ownership.py
arch=$(./docker-local.sh info --format '{{.Architecture}}')
case "$arch" in aarch64|arm64) arch=arm64 ;; x86_64|amd64) arch=amd64 ;; *) exit 1 ;; esac
root=$(cd ../.. && pwd)
. ./toolchain.sh
(cd "$root/apps/api" && GOTOOLCHAIN=local GOFLAGS=-mod=readonly CGO_ENABLED=0 GOOS=linux GOARCH="$arch" "$local_go" build -trimpath -o "$root/tests/ipsec-bgp-local/.runtime/bin/tunnex-api.next" ./cmd/server)
(cd "$root/apps/node" && GOTOOLCHAIN=local GOFLAGS=-mod=readonly CGO_ENABLED=0 GOOS=linux GOARCH="$arch" "$local_go" build -trimpath -o "$root/tests/ipsec-bgp-local/.runtime/bin/tunnex-node.next" ./cmd/agent)
mv .runtime/bin/tunnex-api.next .runtime/bin/tunnex-api
mv .runtime/bin/tunnex-node.next .runtime/bin/tunnex-node
{ git -C "$root" rev-parse HEAD; git -C "$root" branch --show-current; printf 'architecture=%s\n' "$arch"; sed -n '/^BGPLOCAL_NODE_IMAGE=/p' .runtime/env; shasum -a 256 .runtime/bin/tunnex-api .runtime/bin/tunnex-node; } > .runtime/build.txt
./run.sh restart api
tries=0
until curl --fail --silent http://127.0.0.1:18283/healthz >/dev/null; do
 tries=$((tries + 1))
 [ "$tries" -lt 60 ] || { echo 'Owned API did not become healthy' >&2; exit 1; }
 sleep 1
done
./run.sh restart gateway
