#!/bin/sh
# Behavioural proof for the mutating half of the host upgrade helper. Everything
# external is faked: no network, Docker daemon, database, or root is required.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT HUP INT TERM

mkdir -p "$TMP/tunnex" "$TMP/bin"
cp "$ROOT/deploy/upgrade.sh" "$TMP/tunnex/upgrade.sh"
chmod 0755 "$TMP/tunnex/upgrade.sh"
printf '%s\n' '# old compose' >"$TMP/tunnex/tunnex.yml"
cat >"$TMP/tunnex/.env" <<'ENV'
TUNNEX_RELEASE_PUBLIC_KEY=test-public-key
TUNNEX_RELEASE_CATALOG_URL=https://updates.example.test/release.json
POSTGRES_USER=tunnex
POSTGRES_DB=tunnex
ENV
: >"$TMP/catalog.json"

cat >"$TMP/bin/curl" <<'SH'
#!/bin/sh
set -eu
[ "$1" = -fsSL ]
url=$2
[ "$3" = -o ]
out=$4
case "$url" in
  https://updates.example.test/release.json) cp "$MOCK_CATALOG" "$out" ;;
  https://raw.githubusercontent.com/tunnexio/tunnex/*/deploy/tunnex.yml)
    printf '%s\n' 'services:' '  api:' '    environment:' '      TUNNEX_ENV: production' >"$out"
    ;;
  *) echo "unexpected curl URL: $url" >&2; exit 1 ;;
esac
SH
chmod 0755 "$TMP/bin/curl"

cat >"$TMP/bin/releaseverify" <<'SH'
#!/bin/sh
set -eu
[ "$1" = -manifest ]
[ "$3" = -public-key ]
[ "$4" = test-public-key ]
if [ "${5:-}" = -print-env ]; then
  cat <<'ENV'
TUNNEX_RELEASE_SOURCE_SHA=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
TUNNEX_RELEASE_VERSION=v9.9.9
TUNNEX_RELEASE_SEQUENCE=99
TUNNEX_API_IMAGE=api@sha256:aaa
TUNNEX_WEB_IMAGE=web@sha256:bbb
TUNNEX_NGINX_IMAGE=nginx@sha256:ccc
TUNNEX_NODE_AGENT_IMAGE=node@sha256:ddd
TUNNEX_MIGRATE_IMAGE=migrate@sha256:eee
ENV
fi
SH
chmod 0755 "$TMP/bin/releaseverify"

cat >"$TMP/bin/pg_restore" <<'SH'
#!/bin/sh
set -eu
[ "$1" = --list ]
[ -s "$2" ]
SH
chmod 0755 "$TMP/bin/pg_restore"

cat >"$TMP/bin/docker" <<'SH'
#!/bin/sh
set -eu
printf '%s\n' "$*" >>"$MOCK_DOCKER_LOG"
case "$*" in
  *'api preflight'*) [ "${MOCK_FAIL_STAGE:-}" != preflight ] || exit 42 ;;
  *'exec -T postgres sh -c '*pg_dump*) printf 'PGDMP-test-backup' ;;
  *'api backupctl manifest'*) printf '%s\n' '{"manifest":"test"}' ;;
  *'api backupctl verify'*) cat >/dev/null ;;
  *'exec -T api wget -qO-'*) printf '%s\n' ok ;;
esac
SH
chmod 0755 "$TMP/bin/docker"

STATUS="$TMP/tunnex/status"
(
  cd "$TMP/tunnex"
  PATH="$TMP/bin:$PATH" \
    MOCK_CATALOG="$TMP/catalog.json" \
    MOCK_DOCKER_LOG="$TMP/docker.log" \
    TUNNEX_RELEASEVERIFY="$TMP/bin/releaseverify" \
    TUNNEX_UPGRADE_STATUS_FILE="$STATUS" \
    TUNNEX_UPGRADE_REQUEST_ID=12345678-1234-1234-1234-123456789abc \
    ./upgrade.sh --apply \
      --expected-source-sha aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
      --expected-sequence 99
)

grep -Fq 'state=healthy' "$STATUS"
grep -Fq 'target_version=v9.9.9' "$STATUS"
grep -Fq 'backup_dump=' "$STATUS"
grep -Fq 'backup_manifest=' "$STATUS"
dump=$(sed -n 's/^backup_dump=//p' "$STATUS")
manifest=$(sed -n 's/^backup_manifest=//p' "$STATUS")
[ -s "$TMP/tunnex/backups/$dump" ]
[ -s "$TMP/tunnex/backups/$manifest" ]
grep -Fq 'PGDMP-test-backup' "$TMP/tunnex/backups/$dump"
grep -Fq 'exec -T api backupctl verify' "$TMP/docker.log"
grep -Fq -- '--dump-sha256' "$TMP/docker.log"
grep -Fq 'exec -T -e TUNNEX_PREFLIGHT_BACKUP_CONFIRMED=yes api preflight' "$TMP/docker.log"
grep -Fq 'pull' "$TMP/docker.log"
grep -Fq 'up -d' "$TMP/docker.log"
grep -Fq 'TUNNEX_RELEASE_VERSION=v9.9.9' "$TMP/tunnex/.env"

backup_line=$(grep -n 'exec -T postgres' "$TMP/docker.log" | cut -d: -f1)
pull_line=$(grep -n 'pull' "$TMP/docker.log" | cut -d: -f1 | tail -1)
[ "$backup_line" -lt "$pull_line" ] || {
  echo 'database backup did not precede image mutation' >&2
  exit 1
}

# Any command failure after a request is accepted must leave a terminal result,
# not an intermediate state that makes subsequent UI requests ambiguous.
rm -f "$STATUS"
if (
  cd "$TMP/tunnex"
  PATH="$TMP/bin:$PATH" \
    MOCK_CATALOG="$TMP/catalog.json" \
    MOCK_DOCKER_LOG="$TMP/docker-failed.log" \
    MOCK_FAIL_STAGE=preflight \
    TUNNEX_RELEASEVERIFY="$TMP/bin/releaseverify" \
    TUNNEX_UPGRADE_STATUS_FILE="$STATUS" \
    TUNNEX_UPGRADE_REQUEST_ID=12345678-1234-1234-1234-123456789abc \
    ./upgrade.sh --apply \
      --expected-source-sha aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
      --expected-sequence 99
); then
  echo 'preflight failure unexpectedly succeeded' >&2
  exit 1
fi
grep -Fq 'state=failed' "$STATUS"
grep -Fq 'reason_code=preflight_failed' "$STATUS"

echo 'upgrade apply contract passed'
