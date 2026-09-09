#!/usr/bin/env bash
# Runs only inside a fresh, private AWS candidate directory containing the six
# explicitly copied binaries. This is source-candidate testing, not installation.
set -euo pipefail
umask 077
fixture=${NAT1_FIXTURE:-nat1-candidate-20260909a}
[[ "$fixture" =~ ^nat1-candidate-20260909[a-z]$ ]] || exit 1
test "$(pwd)" = "/home/ubuntu/$fixture"
for binary in migrate server connectivity-open.test connectivity-enterprise.test http-open.test http-enterprise.test; do
  test -x "./$binary"
done
for name in "$fixture-pg" "$fixture-redis"; do
  if sudo docker container inspect "$name" >/dev/null 2>&1; then
    echo "Refusing to overwrite retained fixture $name" >&2
    exit 1
  fi
done
if sudo docker network inspect "$fixture" >/dev/null 2>&1; then
  echo "Refusing to reuse existing network" >&2
  exit 1
fi
server_pid=
pg_started=false
redis_started=false
cleanup() {
  if [[ -n "$server_pid" ]]; then kill "$server_pid" 2>/dev/null || true; wait "$server_pid" 2>/dev/null || true; fi
  if $redis_started; then sudo docker stop "$fixture-redis" >/dev/null || true; fi
  if $pg_started; then sudo docker stop "$fixture-pg" >/dev/null || true; fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
sudo docker network create "$fixture" >/dev/null
export POSTGRES_PASSWORD
POSTGRES_PASSWORD=$(openssl rand -hex 24)
sudo --preserve-env=POSTGRES_PASSWORD docker run -d --name "$fixture-pg" --network "$fixture" \
  --label tunnex.fixture="$fixture" -e POSTGRES_PASSWORD -e POSTGRES_DB=nat1 \
  -p 127.0.0.1:25439:5432 postgres:17-alpine >/dev/null
pg_started=true
export PGPASSWORD="$POSTGRES_PASSWORD"
database_ready() {
  sudo --preserve-env=PGPASSWORD docker exec -e PGPASSWORD "$fixture-pg" \
    psql -h 127.0.0.1 -U postgres -d nat1 -Atqc 'SELECT 1' >/dev/null 2>&1
}
for attempt in $(seq 1 30); do
  if database_ready; then break; fi
  sleep 1
done
database_ready
export DATABASE_URL="postgres://postgres:$POSTGRES_PASSWORD@127.0.0.1:25439/nat1?sslmode=disable"
export TUNNEX_TEST_DATABASE_URL="$DATABASE_URL"
./migrate up
for edition in open enterprise; do
  "./connectivity-$edition.test" -test.v -test.timeout=90s
  "./http-$edition.test" -test.v -test.timeout=90s -test.run='^TestConnectivityRoutesPostgres$'
done
./migrate down
./migrate up
sudo docker run -d --name "$fixture-redis" --network "$fixture" \
  --label tunnex.fixture="$fixture" -p 127.0.0.1:26379:6379 redis:7-alpine >/dev/null
redis_started=true
export REDIS_URL=redis://127.0.0.1:26379/0
export TUNNEX_ENV=development TUNNEX_API_ADDR=127.0.0.1:28080
export TUNNEX_AGENT_ADDR=127.0.0.1:28443 TUNNEX_METRICS_ADDR=127.0.0.1:29090
export TUNNEX_SECRETS_DIR="$PWD/secrets" APP_BASE_URL=http://127.0.0.1:28080
./server >server.private.log 2>&1 &
server_pid=$!
for attempt in $(seq 1 30); do
  if curl --fail --silent http://127.0.0.1:28080/healthz >/dev/null; then
    echo 'Production server entrypoint health PASS (development configuration; no NAT transport claim)'
    sudo docker inspect --format '{{.Name}} {{.Image}}' "$fixture-pg" "$fixture-redis"
    exit 0
  fi
  kill -0 "$server_pid" 2>/dev/null || { echo 'Server exited; inspect private log locally' >&2; exit 1; }
  sleep 1
done
echo 'Server health timed out' >&2
exit 1
