#!/bin/sh
set -eu
cd "$(dirname "$0")"
# Docker-managed volume avoids Colima's unshared /private/tmp bind mounts.
sh docker-local.sh volume create --label com.docker.compose.project=tunnex-beam-local tunnex-beam-local_binaries >/dev/null
container=$(sh docker-local.sh create --label com.docker.compose.project=tunnex-beam-local -v tunnex-beam-local_binaries:/binaries tunnex-beam-runtime:local /bin/sh -ec 'sleep 300')
trap 'sh docker-local.sh rm -f "$container" >/dev/null' EXIT INT TERM
sh docker-local.sh start "$container" >/dev/null
for name in tunnex-api tunnex-node backupctl beam-proxy; do
  sh docker-local.sh cp ".runtime/bin/$name" "$container:/binaries/$name.next"
  sh docker-local.sh exec "$container" mv "/binaries/$name.next" "/binaries/$name"
done
# Only this public development root is delivered; its private key stays outside
# the binaries volume and is never trusted by production configuration.
test -f .runtime/tls/ca.pem
sh docker-local.sh cp .runtime/tls/ca.pem "$container:/binaries/beam-public-ca.pem.next"
sh docker-local.sh exec "$container" mv /binaries/beam-public-ca.pem.next /binaries/beam-public-ca.pem
