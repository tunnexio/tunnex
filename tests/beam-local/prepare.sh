#!/bin/sh
set -eu
cd "$(dirname "$0")"
umask 077
mkdir -p .runtime/bin .runtime/app-restore
sh prepare-tls.sh
if [ ! -f .runtime/env ]; then
  token=$(openssl rand -hex 32)
  hash=$(printf '%s' "$token" | shasum -a 256 | awk '{print $1}')
  password=$(openssl rand -hex 24)
  printf 'BEAM_JOIN_TOKEN=%s\nBEAM_JOIN_HASH=%s\nBEAM_DB_PASSWORD=%s\n' "$token" "$hash" "$password" > .runtime/env
fi
root=$(cd ../.. && pwd)
task_go=${BEAM_LOCAL_GO:-/Users/pawangupta/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.26.9.darwin-arm64/bin/go}
[ -x "$task_go" ] || { echo 'Go 1.26.9 required' >&2; exit 1; }
arch=$(sh ./docker-local.sh info --format '{{.Architecture}}')
case "$arch" in aarch64|arm64) arch=arm64 ;; x86_64|amd64) arch=amd64 ;; *) exit 1 ;; esac
for pair in 'api server' 'node agent'; do
  set -- $pair
  (cd "$root/apps/$1" && GOTOOLCHAIN=local GOFLAGS=-mod=readonly CGO_ENABLED=0 GOOS=linux GOARCH="$arch" "$task_go" build -trimpath -o "$root/tests/beam-local/.runtime/bin/tunnex-$1" "./cmd/$2")
done
(cd "$root/apps/api" && GOTOOLCHAIN=local GOFLAGS=-mod=readonly CGO_ENABLED=0 GOOS=linux GOARCH="$arch" "$task_go" build -trimpath -o "$root/tests/beam-local/.runtime/bin/backupctl" ./cmd/backupctl)
(cd "$root/apps/app-proxy" && GOTOOLCHAIN=local GOFLAGS=-mod=readonly CGO_ENABLED=0 GOOS=linux GOARCH="$arch" "$task_go" build -trimpath -o "$root/tests/beam-local/.runtime/bin/beam-proxy" ./cmd/beam-proxy)
{ git -C "$root" rev-parse HEAD; shasum -a 256 .runtime/bin/tunnex-api .runtime/bin/tunnex-node .runtime/bin/backupctl .runtime/bin/beam-proxy; } > .runtime/build.txt
