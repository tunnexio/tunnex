#!/bin/sh
set -eu
cd "$(dirname "$0")"
umask 077
owner=$(pwd -P)
expected=/Users/pawangupta/.codex/worktrees/main-app-access-compare/tunnex/tests/server-access-local
[ "$owner" = "$expected" ] || { echo 'Foreign checkout refused' >&2; exit 1; }
project=tunnex-sa0-browser-1005
mode=${1:-sso}
case "$mode" in
 sso) name=tunnex-sa9-sso-identity-1005; testcase=TestServerAccessOwnedSSOIdentityFixture ;;
 enroll) name=tunnex-sa9-identity-enrollment-1005; testcase=TestServerAccessOwnedIdentityEnrollmentFixture ;;
 *) echo 'Unknown owned identity mode' >&2; exit 1 ;;
esac
[ -f .runtime/server-access-identity.test ] || { echo 'Identity fixture binary unavailable' >&2; exit 1; }
[ -d .runtime/app-restore ] && [ ! -L .runtime/app-restore ] || { echo 'Owned restore fence unavailable' >&2; exit 1; }
./run.sh ps >/dev/null
if ./docker-local.sh container inspect "$name" >/dev/null 2>&1; then echo 'Existing identity fixture requires inspection' >&2; exit 1; fi
network=$(./docker-local.sh network inspect --format '{{index .Labels "com.docker.compose.project"}}' "${project}_default")
[ "$network" = "$project" ] || exit 1
backup="$owner/.runtime/identity-sso/$(date -u +%Y%m%dT%H%M%SZ)-$$"
mkdir -p "$backup"
chmod 700 "$backup"
exec ./docker-local.sh run --rm --pull never --name "$name" \
 --label "com.docker.compose.project=$project" \
 --label "com.docker.compose.project.working_dir=$owner" \
 --label server-access.fixture=sa9-sso-identity \
 --network "${project}_default" \
 --env-file .runtime/env -e SERVER_ACCESS_SSO_IDENTITY_FIXTURE=1 -e SERVER_ACCESS_IDENTITY_ENROLL_FIXTURE=1 \
 -e "SERVER_ACCESS_OWNED_PROJECT=$project" -e "SERVER_ACCESS_OWNED_CHECKOUT=$owner" \
 -e TUNNEX_APP_ACCESS_RESTORE_MARKER=/owned-app-restore/app-access.pending.json \
 -v "$owner/.runtime/app-restore:/owned-app-restore:ro" \
 -v "${project}_api_state:/owned-api-state:ro" \
 -v "$backup:/owned-aa9-sso-config" \
 -v "$owner/.runtime/server-access-identity.test:/identity.test:ro" \
 -p 127.0.0.1:15189:15189 -p 127.0.0.1:15187:15187 \
 alpine:3.23 /identity.test -test.v -test.timeout=0 -test.run "^${testcase}$"
