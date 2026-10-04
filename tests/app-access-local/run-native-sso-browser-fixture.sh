#!/bin/sh
set -eu
cd "$(dirname "$0")"
umask 077
./ownership.py
owner=$(pwd -P)
[ "$owner" = /Users/pawangupta/tunnex/tests/app-access-local ] || exit 1
name=tunnex-app-access-aa9-native-sso-1003
[ -f .runtime/native-sso-browser.test ] || { echo 'Native SSO fixture binary missing' >&2; exit 1; }
[ -d .runtime/app-restore ] && [ ! -L .runtime/app-restore ] || exit 1
mkdir -p .runtime/aa9-sso-config
chmod 700 .runtime/aa9-sso-config
if ./docker-local.sh container inspect "$name" >/dev/null 2>&1; then
 echo 'Existing native SSO fixture requires owned inspection' >&2; exit 1
fi
exec ./docker-local.sh run --rm --pull never --name "$name" \
 --label com.docker.compose.project=tunnex-app-access-aa0-1003 \
 --label "com.docker.compose.project.working_dir=$owner" \
 --label app-access.fixture=aa9-native-sso \
 --network tunnex-app-access-aa0-1003_default --network-alias aa8-sso-cp-fixture \
 --env-file .runtime/env -e APP_ACCESS_NATIVE_SSO_BROWSER_FIXTURE=1 \
 -e APP_ACCESS_OWNED_PROJECT=tunnex-app-access-aa0-1003 \
 -e "APP_ACCESS_OWNED_CHECKOUT=$owner" \
 -e TUNNEX_APP_ACCESS_RESTORE_MARKER=/owned-app-restore/app-access.pending.json \
 -v "$owner/.runtime/app-restore:/owned-app-restore:ro" \
 -v tunnex-app-access-aa0-1003_api_state:/owned-api-state:ro \
 -v "$owner/.runtime/aa9-sso-config:/owned-aa9-sso-config" \
 -v "$owner/.runtime/native-sso-browser.test:/native-sso.test:ro" \
 -p 127.0.0.1:15189:15189 -p 127.0.0.1:15187:15187 \
 alpine:3.23 /native-sso.test -test.v -test.timeout=0 -test.run '^TestAppAccessOwnedNativeSSOBrowserFixture$'
