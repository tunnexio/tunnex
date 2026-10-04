#!/bin/sh
set -eu
cd "$(dirname "$0")"
umask 077
./ownership.py
owner=$(pwd -P)
[ "$owner" = /Users/pawangupta/tunnex/tests/app-access-local ] || { echo 'Unexpected origin fixture checkout' >&2; exit 1; }
fixture_name=tunnex-app-access-origin-fixture-1003
if [ "${1:-}" = --stop ]; then
  process=$(./docker-local.sh container inspect --format '{{.Id}}' "$fixture_name")
  actual_project=$(./docker-local.sh container inspect --format '{{index .Config.Labels "com.docker.compose.project"}}' "$process")
  actual_owner=$(./docker-local.sh container inspect --format '{{index .Config.Labels "com.docker.compose.project.working_dir"}}' "$process")
  actual_fixture=$(./docker-local.sh container inspect --format '{{index .Config.Labels "app-access.fixture"}}' "$process")
  [ "$actual_project" = tunnex-app-access-aa0-1003 ] && [ "$actual_owner" = "$owner" ] && [ "$actual_fixture" = aa3-origin ] || { echo 'Origin fixture ownership refused' >&2; exit 1; }
  exec ./docker-local.sh stop --timeout 10 "$process"
fi
[ "$#" -eq 0 ] || { echo 'Supported mode: --stop or no arguments' >&2; exit 1; }
[ -f .runtime/origin-fixture ] || { echo 'Build the local origin fixture first' >&2; exit 1; }
mkdir -p .runtime/origin
if ./docker-local.sh container inspect "$fixture_name" >/dev/null 2>&1; then
  echo 'Origin fixture already exists; inspect ownership before cleanup' >&2
  exit 1
fi
# No published ports; only the owned network can reach this test origin.
# Private keys are generated in memory and only the public CA is written.
exec ./docker-local.sh run --rm --pull never --name "$fixture_name" \
  --label com.docker.compose.project=tunnex-app-access-aa0-1003 \
  --label "com.docker.compose.project.working_dir=$owner" \
  --label app-access.fixture=aa3-origin \
  --network tunnex-app-access-aa0-1003_default --network-alias origin-app-fixture \
  -v "$owner/.runtime/origin-fixture:/origin-fixture:ro" \
  -v "$owner/.runtime/origin:/fixture" \
  alpine:3.23 /origin-fixture
