#!/bin/sh
set -eu
cd "$(dirname "$0")"
unset COMPOSE_PROJECT_NAME COMPOSE_FILE COMPOSE_ENV_FILES COMPOSE_PROFILES
./ownership.py
exec ./docker-local.sh compose --project-name tunnexs2sbgplocal1007 --env-file .runtime/env -f compose.yaml "$@"
