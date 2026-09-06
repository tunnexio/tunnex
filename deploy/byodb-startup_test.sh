#!/usr/bin/env bash
# Opt-in real Docker startup proof; retains exact named fixtures for inspection.
set -euo pipefail
: "${BYODB_STARTUP_IMAGE:?candidate API image}"
: "${BYODB_STARTUP_NETWORK:?isolated compatibility matrix network}"
: "${BYODB_STARTUP_TLS:?matrix certificate directory}"
: "${BYODB_STARTUP_PROJECT:?fresh explicit project name}"
case "$BYODB_STARTUP_PROJECT" in tunnex-byodb-startup-*) ;; *) exit 2;; esac
case "$BYODB_STARTUP_NETWORK" in tunnex-byodb-matrix-*) ;; *) exit 2;; esac
if docker ps -a --filter "label=com.docker.compose.project=$BYODB_STARTUP_PROJECT" --format '{{.ID}}' | grep -q .; then
  echo 'Refusing to reuse existing startup fixtures' >&2; exit 2
fi
docker network inspect "$BYODB_STARTUP_NETWORK" >/dev/null
scratch=$(mktemp -d "${TMPDIR:-/tmp}/tunnex-byodb-startup.XXXXXX")
chmod 700 "$scratch"
docker exec "$BYODB_STARTUP_NETWORK-pg18" createdb -U postgres startup_cp
cat > "$scratch/compose.yaml" <<'YAML'
services:
  redis:
    image: redis:7-alpine
  api:
    image: ${BYODB_STARTUP_IMAGE}
    platform: linux/amd64
    # Deliberately exceeds the previous 5s grace + 5x10s failure window.
    entrypoint: [sh, -c, 'sleep 75; exec /usr/local/bin/tunnex-api']
    environment:
      TUNNEX_ENV: production
      TUNNEX_DATABASE_URL: postgres://postgres:matrix-only-disposable@pg18/startup_cp?sslmode=verify-full&sslrootcert=/fixture/server.crt&channel_binding=require
      TUNNEX_REDIS_URL: redis://redis:6379/0
      TUNNEX_AUTO_MIGRATE: 'true'
      TUNNEX_SECRETS_DIR: /var/lib/tunnex/secrets
      TUNNEX_RELEASE_UPDATE_CHECK: 'false'
      APP_BASE_URL: https://startup.example.test
    volumes:
      - ${BYODB_STARTUP_TLS}:/fixture:ro
      - secrets:/var/lib/tunnex/secrets
    depends_on: [redis]
  dependent:
    image: ${BYODB_STARTUP_IMAGE}
    platform: linux/amd64
    entrypoint: [sh, -c, 'touch /tmp/ready; sleep 300']
    healthcheck:
      test: [CMD, test, -f, /tmp/ready]
      interval: 1s
    depends_on:
      api:
        condition: service_healthy
  never-ready:
    profiles: [negative]
    image: ${BYODB_STARTUP_IMAGE}
    platform: linux/amd64
    entrypoint: [sh, -c, 'sleep 30']
networks:
  default:
    external: true
    name: ${BYODB_STARTUP_NETWORK}
volumes:
  secrets:
YAML
compose=(docker compose -p "$BYODB_STARTUP_PROJECT" -f "$scratch/compose.yaml")
started=$SECONDS
"${compose[@]}" up -d --wait --wait-timeout 150 api dependent
(( SECONDS - started >= 75 ))
api=$("${compose[@]}" ps -q api)
test "$(docker inspect --format '{{.State.Health.Status}}:{{.RestartCount}}' "$api")" = healthy:0
echo 'Delayed API and dependent startup passed automatically without restarts'
started=$SECONDS
if "${compose[@]}" up -d --wait --wait-timeout 3 never-ready > "$scratch/timeout.log" 2>&1; then
  echo 'Unready service unexpectedly passed readiness' >&2; exit 1
fi
(( SECONDS - started < 15 )) || { echo 'Readiness timeout was not bounded' >&2; exit 1; }
grep -F 'application not healthy after 3s' "$scratch/timeout.log" >/dev/null
negative=$("${compose[@]}" ps -q never-ready)
test "$(docker inspect --format '{{.State.Status}}:{{.State.Health.Status}}' "$negative")" = running:starting
echo "Bounded non-ready refusal passed; retained project $BYODB_STARTUP_PROJECT at $scratch"
