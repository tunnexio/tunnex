#!/bin/sh
# Entrypoint for platforms that inject secrets as environment variables
# (Amazon ECS with Secrets Manager or SSM, Cloud Run, Nomad, plain Docker).
#
# Expects TUNNEX_WORKLOAD_SERVER and TUNNEX_WORKLOAD_ENROLLMENT_KEY. Writes them
# to owner-only files, removes them from the environment, then starts the app
# under the tunnex workload wrapper. Usage: entrypoint.sh python app.py
set -eu
: "${TUNNEX_WORKLOAD_SERVER:?set TUNNEX_WORKLOAD_SERVER to the Tunnex HTTPS origin}"
: "${TUNNEX_WORKLOAD_ENROLLMENT_KEY:?inject TUNNEX_WORKLOAD_ENROLLMENT_KEY from your secret store}"

secrets=${TUNNEX_WORKLOAD_SECRETS_DIR:-/run/secrets/tunnex}
state=${TUNNEX_WORKLOAD_STATE_DIR:-/var/lib/tunnex-workload}
umask 077
mkdir -p "$secrets" "$state"
chmod 700 "$secrets" "$state"
printf '%s' "$TUNNEX_WORKLOAD_ENROLLMENT_KEY" > "$secrets/enrollment-key"
printf '{"server":"%s","enrollment_key_file":"%s/enrollment-key","state_directory":"%s"}\n' \
  "$TUNNEX_WORKLOAD_SERVER" "$secrets" "$state" > "$secrets/workload.json"
chmod 600 "$secrets/enrollment-key" "$secrets/workload.json"
unset TUNNEX_WORKLOAD_ENROLLMENT_KEY

exec tunnex workload run --config "$secrets/workload.json" -- "$@"
