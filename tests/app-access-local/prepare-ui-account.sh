#!/bin/sh
set -eu
cd "$(dirname "$0")"
umask 077
./ownership.py
[ -f .runtime/http-appaccess.test ] || { echo 'Build the HTTP test binary before preparing the UI account' >&2; exit 1; }
if [ ! -f .runtime/ui-account.env ]; then
  secret=$(openssl rand -hex 24)
  printf 'AA1_UI_EMAIL=browser-aa1@example.test\nAA1_UI_PASSWORD=%s\n' "$secret" > .runtime/ui-account.env
fi
# The test asserts the exact local database, bootstrap org and enrolled gateway.
# Credential values stay in ignored mode-0600 files; none are printed.
exec ./docker-local.sh run --rm --pull never \
  --network tunnex-app-access-aa0-1003_default \
  --env-file .runtime/env --env-file .runtime/ui-account.env \
  -e APP_ACCESS_LOCAL_UI_SEED=1 \
  -v "$(pwd -P)/.runtime/http-appaccess.test:/http.test:ro" \
  alpine:3.23 /http.test -test.v -test.run '^TestAppAccessLocalUIAccountSeed$'
