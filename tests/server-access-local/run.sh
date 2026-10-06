#!/bin/sh
set -eu
cd "$(dirname "$0")"
unset COMPOSE_PROJECT_NAME COMPOSE_FILE COMPOSE_ENV_FILES COMPOSE_PROFILES
project=tunnex-sa0-browser-1005
owner=$(pwd -P)
# Never adopt containers belonging to another checkout.
for id in $(./docker-local.sh ps -aq --filter "label=com.docker.compose.project=$project"); do
 actual=$(./docker-local.sh inspect --format '{{index .Config.Labels "com.docker.compose.project.working_dir"}}' "$id")
 [ "$actual" = "$owner" ] || { echo 'Foreign checkout/project refused' >&2; exit 1; }
done
# Existing volumes/networks must carry this exact Compose project label.
for name in ${project}_postgres_data ${project}_redis_data ${project}_api_state ${project}_gateway_state ${project}_ssh_state; do
 if ./docker-local.sh volume inspect "$name" >/dev/null 2>&1; then
  actual=$(./docker-local.sh volume inspect --format '{{index .Labels "com.docker.compose.project"}}' "$name")
  [ "$actual" = "$project" ] || { echo 'Foreign volume refused' >&2; exit 1; }
 fi
done
if ./docker-local.sh network inspect "${project}_default" >/dev/null 2>&1; then
 actual=$(./docker-local.sh network inspect --format '{{index .Labels "com.docker.compose.project"}}' "${project}_default")
 [ "$actual" = "$project" ] || { echo 'Foreign network refused' >&2; exit 1; }
fi
case "${1:-}" in up|ps|exec|logs|config) ;; *) echo 'Only owned up/ps/exec/logs/config supported; cleanup needs separate authorization' >&2; exit 1 ;; esac
exec ./docker-local.sh compose --project-name "$project" --env-file .runtime/env -f compose.yaml "$@"
