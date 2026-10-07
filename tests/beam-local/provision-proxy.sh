#!/bin/sh
set -eu
cd "$(dirname "$0")"
umask 077
mkdir -p .runtime/proxy
sh docker-local.sh exec tunnex-beam-local-api-1 /bin/sh -ec 'mkdir -p /state/beam-local-proxy; chmod 700 /state/beam-local-proxy'
if ! sh docker-local.sh exec tunnex-beam-local-api-1 test -f /state/beam-local-proxy/authority.token; then
  sh docker-local.sh compose --env-file .runtime/env -f compose.yaml -p tunnex-beam-local run --rm -T operator /binaries/backupctl app-proxy-issue --name beam-local-proxy --output /state/beam-local-proxy/authority.token > .runtime/proxy/provision.json
fi
if ! sh docker-local.sh exec tunnex-beam-local-api-1 test -f /state/beam-local-proxy/server/gateway-cert.pem; then
  sh docker-local.sh compose --env-file .runtime/env -f compose.yaml -p tunnex-beam-local run --rm -T operator /binaries/backupctl beam-proxy-certificate --output-dir /state/beam-local-proxy/server > .runtime/proxy/certificate.json
fi
sh docker-local.sh cp tunnex-beam-local-api-1:/state/beam-local-proxy/authority.token .runtime/proxy/authority.token
sh docker-local.sh cp tunnex-beam-local-api-1:/state/beam-local-proxy/server/. .runtime/proxy/
chmod 600 .runtime/proxy/*
sh docker-local.sh volume create --label com.docker.compose.project=tunnex-beam-local tunnex-beam-local_proxy_assets >/dev/null
container=$(sh docker-local.sh create --label com.docker.compose.project=tunnex-beam-local -v tunnex-beam-local_proxy_assets:/proxy tunnex-beam-runtime:local /bin/sh -ec 'sleep 300')
trap 'sh docker-local.sh rm -f "$container" >/dev/null' EXIT INT TERM
sh docker-local.sh start "$container" >/dev/null
sh docker-local.sh cp .runtime/proxy/. "$container:/proxy/"
sh docker-local.sh cp .runtime/tls/server-cert.pem "$container:/proxy/public-cert.pem"
sh docker-local.sh cp .runtime/tls/server-key.pem "$container:/proxy/public-key.pem"
sh docker-local.sh exec "$container" /bin/sh -ec 'chown -R 10001:10001 /proxy; chmod 700 /proxy; chmod 600 /proxy/*'
echo 'Local Beam proxy authority and TLS material provisioned; secrets withheld.'
