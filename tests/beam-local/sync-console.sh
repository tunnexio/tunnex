#!/bin/sh
set -eu
cd "$(dirname "$0")"
[ -f ../../apps/web/dist/index.html ] || { echo 'Build @tunnex/web first' >&2; exit 1; }
sh docker-local.sh volume create --label com.docker.compose.project=tunnex-beam-local tunnex-beam-local_console_assets >/dev/null
container=$(sh docker-local.sh create --label com.docker.compose.project=tunnex-beam-local -v tunnex-beam-local_console_assets:/console tunnex-beam-runtime:local /bin/sh -ec 'sleep 300')
trap 'sh docker-local.sh rm -f "$container" >/dev/null' EXIT INT TERM
sh docker-local.sh start "$container" >/dev/null
sh docker-local.sh exec "$container" mkdir -p /console/web
sh docker-local.sh cp ../../apps/web/dist/. "$container:/console/web/"
sh docker-local.sh cp nginx.conf "$container:/console/nginx.conf"
sh docker-local.sh cp .runtime/tls/server-cert.pem "$container:/console/server-cert.pem"
sh docker-local.sh cp .runtime/tls/server-key.pem "$container:/console/server-key.pem"
sh docker-local.sh exec "$container" /bin/sh -ec 'chown -R 101:101 /console; chmod 700 /console; chmod 600 /console/server-key.pem; chmod 644 /console/nginx.conf /console/server-cert.pem; find /console/web -type d -exec chmod 755 {} +; find /console/web -type f -exec chmod 644 {} +'
