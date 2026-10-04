#!/bin/sh
set -eu
cd "$(dirname "$0")"
umask 077
./ownership.py
owner=$(pwd -P)
[ "$owner" = /Users/pawangupta/tunnex/tests/app-access-local ] || { echo 'Unexpected proxy fixture checkout' >&2; exit 1; }
fixture_name=tunnex-app-access-proxy-fixture-1003
if [ "${1:-}" = --stop ]; then
 process=$(./docker-local.sh container inspect --format '{{.Id}}' "$fixture_name")
 project=$(./docker-local.sh container inspect --format '{{index .Config.Labels "com.docker.compose.project"}}' "$process")
 checkout=$(./docker-local.sh container inspect --format '{{index .Config.Labels "com.docker.compose.project.working_dir"}}' "$process")
 fixture=$(./docker-local.sh container inspect --format '{{index .Config.Labels "app-access.fixture"}}' "$process")
 [ "$project" = tunnex-app-access-aa0-1003 ] && [ "$checkout" = "$owner" ] && [ "$fixture" = aa6-proxy ] || { echo 'Proxy fixture ownership refused' >&2; exit 1; }
 exec ./docker-local.sh stop --timeout 10 "$process"
fi
[ "$#" -eq 0 ] || { echo 'Supported mode: --stop or no arguments' >&2; exit 1; }
[ ! -L .runtime/app-restore ] || { echo 'Restore guard directory cannot be a symlink' >&2; exit 1; }
mkdir -p .runtime/app-restore
chmod 700 .runtime/app-restore
[ "$(cd .runtime/app-restore && pwd -P)" = "$owner/.runtime/app-restore" ] || { echo 'Unexpected restore guard directory' >&2; exit 1; }
[ -f .runtime/app-proxy-fixture.test ] && [ -f .runtime/aa6-proxy/proxy-credential ] && [ -f .runtime/aa6-proxy/ca-cert.pem ] || { echo 'Build and prepare the owned proxy fixture first' >&2; exit 1; }
if ./docker-local.sh container inspect "$fixture_name" >/dev/null 2>&1; then
 echo 'Proxy fixture exists; inspect ownership before cleanup' >&2; exit 1
fi
exec ./docker-local.sh run --rm --pull never --name "$fixture_name" \
 --label com.docker.compose.project=tunnex-app-access-aa0-1003 \
 --label "com.docker.compose.project.working_dir=$owner" \
 --label app-access.fixture=aa6-proxy \
 --network tunnex-app-access-aa0-1003_default --network-alias app-proxy-fixture \
 -e APP_ACCESS_PROXY_FIXTURE=1 \
 -e APP_ACCESS_PROXY_FIXTURE_CONSOLE \
 -e APP_ACCESS_OWNED_PROJECT=tunnex-app-access-aa0-1003 \
 -e TUNNEX_APP_ACCESS_RESTORE_MARKER=/owned-app-restore/app-access.pending.json \
 -v "$owner/.runtime/app-restore:/owned-app-restore:ro" \
 -e "APP_ACCESS_OWNED_CHECKOUT=$owner" \
 -p 127.0.0.1:443:443 \
 -p 127.0.0.1:18449:18449 \
 -v "$owner/.runtime/app-proxy-fixture.test:/proxy-fixture.test:ro" \
 -v "$owner/.runtime/aa6-proxy:/owned-aa6-proxy:ro" \
 alpine:3.23 /proxy-fixture.test -test.v -test.timeout=0 -test.run '^TestOwnedLocalProxyFixture$'
