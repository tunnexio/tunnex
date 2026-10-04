#!/bin/sh
set -eu
cd "$(dirname "$0")"
umask 077
mkdir -p .runtime/bin
if [ ! -f .runtime/env ]; then
  token=$(openssl rand -hex 32)
  hash=$(printf '%s' "$token" | shasum -a 256 | awk '{print $1}')
  password=$(openssl rand -hex 24)
  printf 'AA0_JOIN_TOKEN=%s\nAA0_JOIN_HASH=%s\nAA0_DB_PASSWORD=%s\n' "$token" "$hash" "$password" > .runtime/env
fi
if ! rg -q '^AA0_CHECKOUT=' .runtime/env; then
  printf 'AA0_CHECKOUT=%s\n' "$(pwd -P)" >> .runtime/env
fi
./ownership.py
python3 ./prepare-resources.py
arch=$(./docker-local.sh info --format '{{.Architecture}}')
case "$arch" in aarch64|arm64) arch=arm64 ;; x86_64|amd64) arch=amd64 ;; *) exit 1 ;; esac
root=$(cd ../.. && pwd)
(cd "$root/apps/api" && GOFLAGS=-mod=readonly CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -o "$root/tests/app-access-local/.runtime/bin/tunnex-api" ./cmd/server)
(cd "$root/apps/node" && GOFLAGS=-mod=readonly CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -o "$root/tests/app-access-local/.runtime/bin/tunnex-node" ./cmd/agent)
(cd "$root/apps/api" && GOFLAGS=-mod=readonly CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -o "$root/tests/app-access-local/.runtime/origin-fixture" "$root/tests/app-access-local/origin-fixture/main.go")

{ git -C "$root" rev-parse HEAD; shasum -a 256 .runtime/bin/tunnex-api .runtime/bin/tunnex-node; } > .runtime/build.txt
