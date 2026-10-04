#!/bin/sh
set -eu
cd "$(dirname "$0")"
umask 077
./ownership.py
fixture_name=tunnex-app-access-aa1-browser-fixture-1003
owner=$(pwd -P)
[ "$owner" = /Users/pawangupta/tunnex/tests/app-access-local ] || { echo 'Unexpected fixture checkout' >&2; exit 1; }
if [ "${1:-}" = --stop ]; then
  process=$(./docker-local.sh container inspect --format '{{.Id}}' "$fixture_name")
  actual_project=$(./docker-local.sh container inspect --format '{{index .Config.Labels "com.docker.compose.project"}}' "$process")
  actual_owner=$(./docker-local.sh container inspect --format '{{index .Config.Labels "com.docker.compose.project.working_dir"}}' "$process")
  actual_fixture=$(./docker-local.sh container inspect --format '{{index .Config.Labels "app-access.fixture"}}' "$process")
  [ "$actual_project" = tunnex-app-access-aa0-1003 ] && [ "$actual_owner" = "$owner" ] && [ "$actual_fixture" = aa1-browser ] || { echo 'Fixture cleanup ownership refused' >&2; exit 1; }
  exec ./docker-local.sh stop --timeout 10 "$process"
fi
[ "$#" -eq 0 ] || { echo 'Supported mode: --stop or no arguments' >&2; exit 1; }
[ ! -L .runtime/app-restore ] || { echo 'Restore guard directory cannot be a symlink' >&2; exit 1; }
mkdir -p .runtime/app-restore
chmod 700 .runtime/app-restore
[ "$(cd .runtime/app-restore && pwd -P)" = "$owner/.runtime/app-restore" ] || { echo 'Unexpected restore guard directory' >&2; exit 1; }
mkdir -p .runtime/aa6-proxy
chmod 700 .runtime/aa6-proxy
[ -f .runtime/ui-fixture.test ] && [ -f .runtime/ui-account.env ] || { echo 'Compile fixture and seed UI account first' >&2; exit 1; }
if ./docker-local.sh container inspect "$fixture_name" >/dev/null 2>&1; then
 echo 'Fixture container exists; inspect ownership before cleanup' >&2
 exit 1
fi
# Only localhost is published; no license installed in native CP. --rm removes
# this ephemeral process only; owned volume data is never removed.
exec ./docker-local.sh run --rm --pull never --name "$fixture_name" \
 --label com.docker.compose.project=tunnex-app-access-aa0-1003 \
 --label "com.docker.compose.project.working_dir=$owner" \
 --label app-access.fixture=aa1-browser \
 --network tunnex-app-access-aa0-1003_default \
 --network-alias app-access-fixture --network-alias tunnex-app-authority \
 --env-file .runtime/env --env-file .runtime/ui-account.env \
 -e APP_ACCESS_BROWSER_FIXTURE=1 \
 -e APP_ACCESS_OWNED_PROJECT=tunnex-app-access-aa0-1003 \
 -e TUNNEX_APP_ACCESS_RESTORE_MARKER=/owned-app-restore/app-access.pending.json \
 -v "$owner/.runtime/app-restore:/owned-app-restore:ro" \
 -e "APP_ACCESS_OWNED_CHECKOUT=$owner" \
 -p 127.0.0.1:18084:18084 \
 -p 127.0.0.1:18447:18447 \
 -p 127.0.0.1:18448:18448 \
 -v tunnex-app-access-aa0-1003_api_state:/owned-api-state:ro \
 -v "$owner/.runtime/ui-fixture.test:/ui-fixture.test:ro" \
 -v "$owner/.runtime/aa6-proxy:/owned-aa6-proxy" \
 alpine:3.23 /ui-fixture.test -test.v -test.timeout=0 -test.run '^TestAppAccessLocalPaidBrowserFixture$'
