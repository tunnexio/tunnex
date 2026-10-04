#!/bin/sh
set -eu
cd "$(dirname "$0")"
umask 077
./ownership.py
owner=$(pwd -P)
[ "$owner" = /Users/pawangupta/tunnex/tests/app-access-local ] || { echo 'Unexpected SSO console checkout' >&2; exit 1; }
fixture_name=tunnex-app-access-sso-console-fixture-1003
if [ "${1:-}" = --stop ]; then
 process=$(./docker-local.sh container inspect --format '{{.Id}}' "$fixture_name")
 project=$(./docker-local.sh container inspect --format '{{index .Config.Labels "com.docker.compose.project"}}' "$process")
 checkout=$(./docker-local.sh container inspect --format '{{index .Config.Labels "com.docker.compose.project.working_dir"}}' "$process")
 fixture=$(./docker-local.sh container inspect --format '{{index .Config.Labels "app-access.fixture"}}' "$process")
 [ "$project" = tunnex-app-access-aa0-1003 ] && [ "$checkout" = "$owner" ] && [ "$fixture" = aa9-sso-console ] || { echo 'SSO console ownership refused' >&2; exit 1; }
 exec ./docker-local.sh stop --timeout 10 "$process"
fi
[ "$#" -eq 0 ] || { echo 'Supported mode: --stop or no arguments' >&2; exit 1; }
[ -f .runtime/aa9-sso-console/console-fixture ] && [ -f .runtime/aa9-sso-console/console-cert.pem ] && [ -f .runtime/aa9-sso-console/console-key.pem ] && [ -f ../../apps/web/dist/index.html ] || { echo 'Build the owned SSO console first' >&2; exit 1; }
if ./docker-local.sh container inspect "$fixture_name" >/dev/null 2>&1; then
 echo 'SSO console fixture exists; inspect ownership before cleanup' >&2; exit 1
fi
exec ./docker-local.sh run --rm --pull never --name "$fixture_name" \
 --label com.docker.compose.project=tunnex-app-access-aa0-1003 \
 --label "com.docker.compose.project.working_dir=$owner" \
 --label app-access.fixture=aa9-sso-console \
 --network tunnex-app-access-aa0-1003_default --network-alias app-sso-console-fixture --network-alias aa9-sso-console \
 -e APP_ACCESS_SSO_CONSOLE_FIXTURE=1 \
 -e APP_ACCESS_OWNED_PROJECT=tunnex-app-access-aa0-1003 \
 -e "APP_ACCESS_OWNED_CHECKOUT=$owner" \
 -p 127.0.0.1:15190:15190 \
 -v "$owner/.runtime/aa9-sso-console/console-fixture:/console-fixture:ro" \
 -v "$owner/.runtime/aa9-sso-console:/fixture:ro" \
 -v "$owner/../../apps/web/dist:/web:ro" \
 alpine:3.23 /console-fixture
