#!/bin/sh
set -eu
unset TUNNEX_DATABASE_URL TUNNEX_DATABASE_URL_FILE TUNNEX_DATABASE_MODE TUNNEX_DATABASE_TLS_SOURCE
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT HUP INT TERM
sed -n '/^# BEGIN BYODB INPUT/,/^# END BYODB INPUT/p' "$ROOT/deploy/install.sh" >"$TMP/input.sh"
run_input() (
  DIR="$TMP/new-install"
  have_tty() { return 1; }
  die() { echo "$*" >&2; exit 1; }
  . "$TMP/input.sh"
  configure_database
  [ "$DB_MODE" = "$EXPECTED_MODE" ]
)
(EXPECTED_MODE=bundled run_input)
(TUNNEX_DATABASE_URL='postgres://u:p$literal@db.internal/cp?sslmode=verify-full' EXPECTED_MODE=external run_input)
printf '%s\n' 'postgres://u:p@db.internal/cp?sslmode=verify-full' >"$TMP/url"
chmod 600 "$TMP/url"
(TUNNEX_DATABASE_URL_FILE="$TMP/url" EXPECTED_MODE=external run_input)
if (TUNNEX_DATABASE_MODE=external run_input) 2>"$TMP/error"; then exit 1; fi
if (TUNNEX_DATABASE_MODE=bundled TUNNEX_DATABASE_URL='postgres://secret@db/cp' run_input) 2>"$TMP/error"; then exit 1; fi
if (TUNNEX_DATABASE_URL="postgres://TOPSECRET'@db/cp" run_input) 2>"$TMP/error"; then exit 1; fi
! grep -q TOPSECRET "$TMP/error"
mkdir "$TMP/new-install"
printf '%s\n' TUNNEX_DATABASE_MODE=external >"$TMP/new-install/.env"
printf '%s\n' "TUNNEX_DATABASE_URL='postgres://u:p@db.internal/cp?sslmode=verify-full'" >>"$TMP/new-install/.env"
(EXPECTED_MODE=external run_input)
(TUNNEX_DATABASE_URL_FILE="$TMP/url" EXPECTED_MODE=external run_input)
if (TUNNEX_DATABASE_MODE=bundled run_input) 2>"$TMP/error"; then exit 1; fi
if (TUNNEX_DATABASE_URL='postgres://replacement@db/cp' run_input) 2>"$TMP/error"; then exit 1; fi

# Parse actual Compose without starting a daemon or touching a project.
export POSTGRES_PASSWORD=fixture DATABASE_URL=postgres://fixture@postgres/tunnex
export APP_BASE_URL=https://vpn.example.test TUNNEX_EDGE_LISTEN=http://:80
export TUNNEX_NODE_ENDPOINT=vpn.example.test:51820
COMPOSE_PROFILES=bundled-db docker compose --project-name tunnex-byodb-contract -f "$ROOT/deploy/tunnex.yml" config --services >"$TMP/bundled"
COMPOSE_PROFILES=external-db docker compose --project-name tunnex-byodb-contract -f "$ROOT/deploy/tunnex.yml" config --services >"$TMP/external"
grep -qx postgres "$TMP/bundled"
! grep -qx postgres "$TMP/external"
grep -qx api "$TMP/external"
echo 'BYODB installer contracts passed: selection, secret file, redaction, rerun preservation and Compose profiles'
