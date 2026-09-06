#!/usr/bin/env bash
# Opt-in disposable matrix. Explicit namespace required; resources retained for inspection.
set -euo pipefail
: "${BYODB_MATRIX_PROJECT:?set a fresh isolated project name}"
: "${BYODB_MATRIX_IMAGE:?set the locally built candidate API image}"
case "$BYODB_MATRIX_PROJECT" in tunnex-byodb-matrix-*) ;; *) exit 2 ;; esac
if docker network inspect "$BYODB_MATRIX_PROJECT" >/dev/null 2>&1; then
  echo 'Refusing to reuse an existing matrix network' >&2; exit 2
fi
repo=$(cd "$(dirname "$0")/.." && pwd)
scratch=$(mktemp -d "${TMPDIR:-/tmp}/tunnex-byodb-matrix.XXXXXX")
chmod 755 "$scratch"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -keyout "$scratch/server.key" \
  -out "$scratch/server.crt" -subj /CN=byodb-matrix \
  -addext 'subjectAltName=DNS:pg16,DNS:pg17,DNS:pg18' >/dev/null 2>&1
chmod 644 "$scratch/server.crt"
(cd "$repo/apps/api" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOFLAGS=-mod=readonly go test -c -o "$scratch/db.test" ./db)
docker network create --internal "$BYODB_MATRIX_PROJECT" >/dev/null
for major in 16 17 18; do
  host="pg$major"
  container="$BYODB_MATRIX_PROJECT-$host"
  docker run -d --name "$container" --network "$BYODB_MATRIX_PROJECT" --network-alias "$host" \
    -v "$scratch:/fixture:ro" -e POSTGRES_PASSWORD=matrix-only-disposable -e POSTGRES_DB=tunnex \
    --entrypoint sh "postgres:$major-alpine" -c \
    'cp /fixture/server.key /tmp/server.key; cp /fixture/server.crt /tmp/server.crt; chown postgres:postgres /tmp/server.key /tmp/server.crt; chmod 600 /tmp/server.key; exec docker-entrypoint.sh postgres -c ssl=on -c ssl_key_file=/tmp/server.key -c ssl_cert_file=/tmp/server.crt' >/dev/null
  ready=false
  for attempt in $(seq 1 45); do
    if docker exec "$container" pg_isready -U postgres -d tunnex >/dev/null 2>&1; then ready=true; break; fi
    sleep 1
  done
  [ "$ready" = true ] || exit 1
  url="postgres://postgres:matrix-only-disposable@$host/tunnex?sslmode=verify-full&sslrootcert=/fixture/server.crt&channel_binding=require"
  common=(--rm --platform linux/amd64 --network "$BYODB_MATRIX_PROJECT" -v "$scratch:/fixture:ro" -e "TUNNEX_DATABASE_URL=$url")
  docker run "${common[@]}" -e "TUNNEX_COMPAT_DATABASE_URL=$url" --entrypoint /fixture/db.test "$BYODB_MATRIX_IMAGE" -test.run '^(TestBYODBVersionCompatibility|TestMigrationLockCompatibleWithLegacyDriver)$' -test.v
  docker run "${common[@]}" --entrypoint preflight "$BYODB_MATRIX_IMAGE" --database-dump > "$scratch/pg$major.dump"
  docker run -i "${common[@]}" --entrypoint preflight "$BYODB_MATRIX_IMAGE" --database-verify-archive < "$scratch/pg$major.dump" > "$scratch/pg$major.archive.txt"
  docker exec "$container" createdb -U postgres restored
  docker exec -i "$container" pg_restore -U postgres --exit-on-error --no-owner -d restored < "$scratch/pg$major.dump"
  docker exec "$container" psql -U postgres -d restored -Atc 'SELECT version,dirty FROM schema_migrations'
  echo "PG$major required-channel-binding migration/up-down-up/dump/restore PASS"
done
echo "Retained test network: $BYODB_MATRIX_PROJECT; fixtures: $scratch"
