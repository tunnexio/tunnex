#!/bin/sh
set -eu
unset DOCKER_HOST DOCKER_CONTEXT DOCKER_TLS_VERIFY DOCKER_CERT_PATH
socket=/Users/pawangupta/.colima/default/docker.sock
[ -S "$socket" ] || { echo 'Local Docker socket unavailable' >&2; exit 1; }
exec docker --host "unix://$socket" "$@"
