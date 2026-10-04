#!/bin/sh
set -eu
cd "$(dirname "$0")"
./ownership.py
root=$(cd ../.. && pwd)
arch=$(./docker-local.sh info --format '{{.Architecture}}')
case "$arch" in aarch64|arm64) arch=arm64 ;; x86_64|amd64) arch=amd64 ;; *) exit 1 ;; esac
(cd "$root/apps/api" && GOFLAGS=-mod=readonly CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go test -c -o "$root/tests/app-access-local/.runtime/registry.test" ./internal/appaccess)
# The test DSN is fixed to postgres on this exact owned network. It creates,
# migrates and removes its own random child DB; aa0's CP schema is untouched.
./docker-local.sh run --rm --pull never --network tunnex-app-access-aa0-1003_default --env-file .runtime/env -e APP_ACCESS_LOCAL_INTEGRATION=1 -v "$root/tests/app-access-local/.runtime/registry.test:/registry.test:ro" alpine:3.23 /registry.test -test.v
