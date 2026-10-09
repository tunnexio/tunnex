#!/bin/sh
set -eu
cd "$(dirname "$0")"
umask 077
mkdir -p .runtime/bin .runtime/app-restore .runtime/recording-volume .runtime/azurite
if [ ! -f .runtime/env ]; then
 token=$(openssl rand -hex 32)
 hash=$(printf '%s' "$token" | shasum -a 256 | awk '{print $1}')
 password=$(openssl rand -hex 24)
 printf 'AA0_JOIN_TOKEN=%s\nAA0_JOIN_HASH=%s\nAA0_DB_PASSWORD=%s\n' "$token" "$hash" "$password" > .runtime/env
fi
if ! awk '/^SA_RECORDING_AZURITE_ACCOUNT=/ {found=1} END {exit !found}' .runtime/env; then
 recording_key=$(openssl rand -base64 32)
 printf 'SA_RECORDING_AZURITE_ACCOUNT=sa0store:%s\n' "$recording_key" >> .runtime/env
fi
root=$(cd ../.. && pwd)
task_go=${SA0_GO:-/Users/pawangupta/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.26.9.darwin-arm64/bin/go}
[ -x "$task_go" ] || { echo "Cached Go 1.26.9 required; no download attempted" >&2; exit 1; }
arch=$(./docker-local.sh info --format '{{.Architecture}}')
case "$arch" in aarch64|arm64) arch=arm64 ;; x86_64|amd64) arch=amd64 ;; *) exit 1 ;; esac
(cd "$root/apps/api" && GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOFLAGS=-mod=readonly CGO_ENABLED=0 GOOS=linux GOARCH="$arch" "$task_go" build -o "$root/tests/server-access-local/.runtime/bin/tunnex-api" ./cmd/server)
(cd "$root/apps/node" && GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOFLAGS=-mod=readonly CGO_ENABLED=0 GOOS=linux GOARCH="$arch" "$task_go" build -o "$root/tests/server-access-local/.runtime/bin/tunnex-node" ./cmd/agent)
{ git -C "$root" rev-parse HEAD; shasum -a 256 .runtime/bin/tunnex-api .runtime/bin/tunnex-node; } > .runtime/build.txt
