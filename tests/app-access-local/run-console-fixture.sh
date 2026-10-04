#!/bin/sh
set -eu
cd "$(dirname "$0")"
umask 077
./ownership.py
owner=$(pwd -P)
[ "$owner" = /Users/pawangupta/tunnex/tests/app-access-local ] || { echo 'Unexpected console fixture checkout' >&2; exit 1; }
fixture_name=tunnex-app-access-console-fixture-1003
if [ "${1:-}" = --stop ]; then
 process=$(./docker-local.sh container inspect --format '{{.Id}}' "$fixture_name")
 project=$(./docker-local.sh container inspect --format '{{index .Config.Labels "com.docker.compose.project"}}' "$process")
 checkout=$(./docker-local.sh container inspect --format '{{index .Config.Labels "com.docker.compose.project.working_dir"}}' "$process")
 fixture=$(./docker-local.sh container inspect --format '{{index .Config.Labels "app-access.fixture"}}' "$process")
 [ "$project" = tunnex-app-access-aa0-1003 ] && [ "$checkout" = "$owner" ] && [ "$fixture" = aa6-console ] || { echo 'Console fixture ownership refused' >&2; exit 1; }
 exec ./docker-local.sh stop --timeout 10 "$process"
fi
[ "$#" -eq 0 ] || { echo 'Supported mode: --stop or no arguments' >&2; exit 1; }
[ -f .runtime/console-fixture ] && [ -f .runtime/aa6-proxy/console-cert.pem ] && [ -f .runtime/aa6-proxy/console-key.pem ] && [ -f ../../apps/web/dist/index.html ] || { echo 'Build the web bundle and owned console fixture first' >&2; exit 1; }
if ./docker-local.sh container inspect "$fixture_name" >/dev/null 2>&1; then
 echo 'Console fixture exists; inspect ownership before cleanup' >&2; exit 1
fi
exec ./docker-local.sh run --rm --pull never --name "$fixture_name" \
 --label com.docker.compose.project=tunnex-app-access-aa0-1003 \
 --label "com.docker.compose.project.working_dir=$owner" \
 --label app-access.fixture=aa6-console \
 --network tunnex-app-access-aa0-1003_default --network-alias app-console-fixture \
 -e APP_ACCESS_OWNED_PROJECT=tunnex-app-access-aa0-1003 \
 -e "APP_ACCESS_OWNED_CHECKOUT=$owner" \
 -p 127.0.0.1:15180:15180 \
 -v "$owner/.runtime/console-fixture:/console-fixture:ro" \
 -v "$owner/.runtime/aa6-proxy:/fixture:ro" \
 -v "$owner/../../apps/web/dist:/web:ro" \
 alpine:3.23 /console-fixture
