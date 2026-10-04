#!/bin/sh
set -eu
cd "$(dirname "$0")"
# No inherited project names, compose files or env files can redirect this stack.
unset COMPOSE_PROJECT_NAME COMPOSE_FILE COMPOSE_ENV_FILES COMPOSE_PROFILES
./ownership.py
[ ! -L .runtime/app-restore ] || { echo "Restore guard directory cannot be a symlink" >&2; exit 1; }
mkdir -p .runtime/app-restore
chmod 700 .runtime/app-restore
[ "$(cd .runtime/app-restore && pwd -P)" = "$(pwd -P)/.runtime/app-restore" ] || { echo "Unexpected restore guard directory" >&2; exit 1; }
exec ./docker-local.sh compose --project-name tunnex-app-access-aa0-1003 --env-file .runtime/env -f compose.yaml "$@"
