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
printf '%s\n' '{"fixture":"signed catalog for stdin transfer"}' >"$TMP/catalog.json"

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
    printf '%s\n' 'services:' '  api:' '    environment:' '      TUNNEX_ENV: production' '      TUNNEX_DATABASE_URL: ${TUNNEX_DATABASE_URL:-}' '# bundled-db' >"$out"
    if [ "${MOCK_AI:-}" = 1 ]; then
      printf '%s\n' '  bifrost:' '    image: ${TUNNEX_AI_ENGINE_IMAGE:?signed}' >>"$out"
    fi
    ;;
  https://raw.githubusercontent.com/tunnexio/tunnex/*/deploy/ai-bootstrap.sh)
    cp "$MOCK_ROOT/deploy/ai-bootstrap.sh" "$out" ;;
  https://raw.githubusercontent.com/tunnexio/tunnex/*/deploy/ai-gateway/config-managed.json)
    cp "$MOCK_ROOT/deploy/ai-gateway/config-managed.json" "$out" ;;
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
if [ "${MOCK_AI_TARGET_VERIFIER:-}" = 1 ]; then
  [ "$#" -eq 7 ]
  [ -s "$2" ]
  cmp -s "$2" "$MOCK_CATALOG"
  [ "$5" = -expected-source-sha ]
  [ "$6" = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ]
  [ "$7" = -print-env ]
  [ "${MOCK_AI_VERIFIER_FAIL:-}" != 1 ] || exit 42
fi
case " $* " in *' -print-env '*)
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
  if [ "${MOCK_AI:-}" = 1 ] && [ "${MOCK_AI_OLD_VERIFIER:-}" != 1 ]; then
    printf '%s\n' 'TUNNEX_AI_ENGINE_IMAGE=ghcr.io/tunnexio/tunnex-ai-engine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
  fi
;; esac
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
  *releaseverify*)
    # The Docker daemon cannot bind the runner's PrivateTmp files. Require the
    # already verified API image to receive the catalog through stdin instead.
    [ "$1" = run ]
    shift
    interactive=false network_none=false shell_entrypoint=false disposable=false
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --rm) disposable=true; shift ;;
        -i|--interactive) interactive=true; shift ;;
        --network) [ "$2" = none ]; network_none=true; shift 2 ;;
        --entrypoint) [ "$2" = sh ]; shell_entrypoint=true; shift 2 ;;
        api@sha256:aaa) shift; break ;;
        *) echo "unexpected target verifier Docker argument: $1" >&2; exit 1 ;;
      esac
    done
    [ "$interactive" = true ] && [ "$network_none" = true ] &&
      [ "$shell_entrypoint" = true ] && [ "$disposable" = true ]
    [ "$1" = -c ]
    container_tmp=$(mktemp -d "${MOCK_DOCKER_LOG}.verifier.XXXXXX")
    trap 'rm -rf "$container_tmp"' EXIT HUP INT TERM
    cat >"$container_tmp/stdin"
    [ -s "$container_tmp/stdin" ]
    cmp -s "$container_tmp/stdin" "$MOCK_CATALOG"
    # Execute the actual container shell command in an isolated fixture /tmp.
    # The verifier validates the resulting file and original key/source args.
    verifier_script=$(printf '%s' "$2" | sed "s|/tmp/|$container_tmp/|g")
    shift 2
    MOCK_AI_TARGET_VERIFIER=1 MOCK_AI_OLD_VERIFIER=0 \
      sh -c "$verifier_script" "$@" <"$container_tmp/stdin" ;;
  *'tar -czf - -C /snapshot config logs'*)
    [ "${MOCK_AI_SNAPSHOT_FAIL:-}" != 1 ] || exit 42
    printf fixture-ai-snapshot ;;
  *'api preflight --database-dump'*) [ "${MOCK_FAIL_STAGE:-}" != backup ] || exit 42; printf 'PGDMP-test-external-backup' ;;
  *'api preflight --database-verify-archive'*) [ "${MOCK_FAIL_STAGE:-}" != archive ] || exit 42; cat >/dev/null ;;
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

# BYODB backs up through the CP connection, never through a bundled DB service.
printf '%s\n' TUNNEX_DATABASE_MODE=external >>"$TMP/tunnex/.env"
for outcome in success backup archive; do
  if (
    cd "$TMP/tunnex"
    PATH="$TMP/bin:$PATH" MOCK_CATALOG="$TMP/catalog.json" \
      MOCK_DOCKER_LOG="$TMP/external-$outcome.log" MOCK_FAIL_STAGE="$outcome" \
      TUNNEX_RELEASEVERIFY="$TMP/bin/releaseverify" TUNNEX_UPGRADE_STATUS_FILE="$STATUS" \
      TUNNEX_UPGRADE_REQUEST_ID="external-$outcome" ./upgrade.sh --apply
  ); then
    [ "$outcome" = success ] || { echo 'backup failure did not block upgrade'; exit 1; }
    grep -Fq 'state=healthy' "$STATUS"
    grep -Fq 'COMPOSE_PROFILES=external-db' "$TMP/tunnex/.env"
  else
    [ "$outcome" != success ] || exit 1
    grep -Fq 'state=failed' "$STATUS"
    ! grep -Fq 'up -d' "$TMP/external-$outcome.log"
  fi
  grep -Fq 'api preflight --database-dump' "$TMP/external-$outcome.log"
  ! grep -Fq 'exec -T postgres' "$TMP/external-$outcome.log"
done

# A legacy installed verifier can authenticate the extra signed image but does
# not export it. The upgrade obtains that pin from the verified target API.
mkdir "$TMP/ai-upgrade"
cp "$ROOT/deploy/upgrade.sh" "$TMP/ai-upgrade/upgrade.sh"
printf '%s\n' '# old compose' >"$TMP/ai-upgrade/tunnex.yml"
cat >"$TMP/ai-upgrade/.env" <<'ENV'
TUNNEX_RELEASE_PUBLIC_KEY=test-public-key
TUNNEX_RELEASE_CATALOG_URL=https://updates.example.test/release.json
COMPOSE_PROJECT_NAME=ai-upgrade
APP_BASE_URL=http://192.0.2.10
ENV
run_ai_upgrade() (
  cd "${1:-$TMP/ai-upgrade}"
  PATH="$TMP/bin:$PATH" MOCK_CATALOG="$TMP/catalog.json" MOCK_AI=1 MOCK_ROOT="$ROOT" \
    MOCK_RELEASEVERIFY="$TMP/bin/releaseverify" MOCK_DOCKER_LOG="$TMP/ai-upgrade.log" \
    TUNNEX_RELEASEVERIFY="$TMP/bin/releaseverify" ./upgrade.sh --apply
)
# Rejection by the target verifier must retain the verified database backup and
# original deployment files, without pulling the Compose stack or restarting it.
mkdir "$TMP/ai-verifier-failure"
cp "$TMP/ai-upgrade/upgrade.sh" "$TMP/ai-verifier-failure/upgrade.sh"
cp "$TMP/ai-upgrade/.env" "$TMP/ai-verifier-failure/.env"
cp "$TMP/ai-upgrade/tunnex.yml" "$TMP/ai-verifier-failure/tunnex.yml"
printf '%s\n' '{"fixture":"installed release"}' >"$TMP/ai-verifier-failure/release.json"
cp "$TMP/ai-verifier-failure/release.json" "$TMP/ai-installed-release.json"
: >"$TMP/ai-upgrade.log"
if (MOCK_AI_OLD_VERIFIER=1 MOCK_AI_VERIFIER_FAIL=1 \
  TUNNEX_UPGRADE_STATUS_FILE="$TMP/ai-verifier-failure/status" \
  TUNNEX_UPGRADE_REQUEST_ID=target-verifier-failure \
  run_ai_upgrade "$TMP/ai-verifier-failure") >"$TMP/ai-verifier-failure-output" 2>&1; then
  echo 'target verifier failure did not block upgrade' >&2; exit 1
fi
grep -Fq 'target release verification failed' "$TMP/ai-verifier-failure-output"
grep -Fxq 'state=failed' "$TMP/ai-verifier-failure/status"
grep -Fxq 'reason_code=pulling_failed' "$TMP/ai-verifier-failure/status"
for file in .env tunnex.yml upgrade.sh; do
  cmp -s "$TMP/ai-upgrade/$file" "$TMP/ai-verifier-failure/$file"
done
cmp -s "$TMP/ai-installed-release.json" "$TMP/ai-verifier-failure/release.json"
[ ! -e "$TMP/ai-verifier-failure/ai-bootstrap.sh" ]
[ ! -e "$TMP/ai-verifier-failure/ai-engine.json" ]
[ ! -e "$TMP/ai-verifier-failure/ai-egress-policy.json" ]
for key in backup_dump backup_manifest; do
  backup=$(sed -n "s/^$key=//p" "$TMP/ai-verifier-failure/status")
  [ -n "$backup" ] && [ -s "$TMP/ai-verifier-failure/backups/$backup" ]
done
grep -Fxq 'pull api@sha256:aaa' "$TMP/ai-upgrade.log"
! grep -Eq '^compose .* (pull|up|stop|start)( |$)' "$TMP/ai-upgrade.log"

: >"$TMP/ai-upgrade.log"
MOCK_AI_OLD_VERIFIER=1 run_ai_upgrade >"$TMP/ai-upgrade-output"
grep -Fq -- '--entrypoint sh' "$TMP/ai-upgrade.log"
grep -qx 'TUNNEX_AI_GATEWAY_URL=' "$TMP/ai-upgrade/.env"
grep -Fq 'real HTTPS public URL' "$TMP/ai-upgrade-output"
[ -f "$TMP/ai-upgrade/ai-engine.json" ]
[ -f "$TMP/ai-upgrade/ai-egress-policy.json" ]
python3 - "$TMP/ai-upgrade" <<'PYTHON'
import json
from pathlib import Path
import sys

installation = Path(sys.argv[1]).resolve()
env = dict(line.split("=", 1) for line in (installation / ".env").read_text().splitlines() if "=" in line)
assert env["TUNNEX_AI_CUSTOM_PROXY_URL"] == "http://{}:{}@ai-egress:8190".format(
    env["TUNNEX_AI_CUSTOM_PROXY_USERNAME"], env["TUNNEX_AI_CUSTOM_PROXY_PASSWORD"])
assert Path(env["TUNNEX_AI_CUSTOM_ENDPOINTS_FILE"]).resolve() == installation / "ai-egress-policy.json"
policy = json.loads((installation / "ai-egress-policy.json").read_text())
assert policy["public_https"] and policy["endpoints"] == [] and policy["denied_cidrs"] == []
assert set(policy["protected_hosts"]) == {"api", "bifrost", "redis", "web", "nginx", "caddy", "ai-egress", "192.0.2.10", "postgres"}
PYTHON
for key in TUNNEX_AI_GATEWAY_ADMIN_USER TUNNEX_AI_GATEWAY_ADMIN_PASSWORD TUNNEX_AI_ENGINE_ENCRYPTION_KEY TUNNEX_AI_CUSTOM_PROXY_USERNAME TUNNEX_AI_CUSTOM_PROXY_PASSWORD TUNNEX_AI_CUSTOM_PROXY_URL; do
  value=$(sed -n "s/^$key=//p" "$TMP/ai-upgrade/.env")
  [ -n "$value" ]
  ! grep -Fq "$value" "$TMP/ai-upgrade-output"
done
cp "$TMP/ai-upgrade/.env" "$TMP/ai-before.env"
cp "$TMP/ai-upgrade/ai-engine.json" "$TMP/ai-before.json"
cp "$TMP/ai-upgrade/ai-egress-policy.json" "$TMP/ai-before-policy.json"
: >"$TMP/ai-upgrade.log"
run_ai_upgrade >"$TMP/ai-upgrade-rerun-output"
cmp -s "$TMP/ai-before.env" "$TMP/ai-upgrade/.env"
cmp -s "$TMP/ai-before.json" "$TMP/ai-upgrade/ai-engine.json"
cmp -s "$TMP/ai-before-policy.json" "$TMP/ai-upgrade/ai-egress-policy.json"
grep -Fq 'stop bifrost' "$TMP/ai-upgrade.log"
grep -Fq 'start bifrost' "$TMP/ai-upgrade.log"
grep -Fq 'ai-upgrade_ai_engine_config:/snapshot/config:ro' "$TMP/ai-upgrade.log"
find "$TMP/ai-upgrade/backups" -name '*.ai.tar.gz' -size +0c | grep -q .
python3 - "$TMP/ai-upgrade/backups" "$TMP/ai-before-policy.json" <<'PYTHON'
from pathlib import Path
import stat
import sys
snapshots = list(Path(sys.argv[1]).glob("*.ai-egress-policy.json"))
assert snapshots
assert any(path.read_bytes() == Path(sys.argv[2]).read_bytes() for path in snapshots)
assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in snapshots)
PYTHON

# Older automatic installs recorded three engine secrets and no egress setup.
# Adding the proxy must retain those existing encrypted-state credentials.
sed '/^TUNNEX_AI_CUSTOM_/d' "$TMP/ai-upgrade/.env" >"$TMP/ai-legacy.env"
cp "$TMP/ai-legacy.env" "$TMP/ai-upgrade/.env"
rm "$TMP/ai-upgrade/ai-egress-policy.json"
run_ai_upgrade >"$TMP/ai-upgrade-legacy-output"
for key in TUNNEX_AI_GATEWAY_ADMIN_USER TUNNEX_AI_GATEWAY_ADMIN_PASSWORD TUNNEX_AI_ENGINE_ENCRYPTION_KEY; do
  grep "^$key=" "$TMP/ai-before.env" >"$TMP/ai-secret-before"
  grep "^$key=" "$TMP/ai-upgrade/.env" >"$TMP/ai-secret-after"
  cmp -s "$TMP/ai-secret-before" "$TMP/ai-secret-after"
done
[ -f "$TMP/ai-upgrade/ai-egress-policy.json" ]

# An explicit operator policy path and exact rules survive upgrades intact.
cat >"$TMP/operator-ai-policy.json" <<'JSON'
{
  "public_https": false,
  "endpoints": [{"name":"Private model","url":"https://models.internal","allowed_cidrs":["10.20.0.0/16"]}],
  "protected_hosts": ["api", "bifrost"],
  "denied_cidrs": ["10.20.1.0/24"]
}
JSON
cp "$TMP/operator-ai-policy.json" "$TMP/operator-ai-policy-before.json"
sed "s|^TUNNEX_AI_CUSTOM_ENDPOINTS_FILE=.*|TUNNEX_AI_CUSTOM_ENDPOINTS_FILE=$TMP/operator-ai-policy.json|" \
  "$TMP/ai-upgrade/.env" >"$TMP/ai-before.env"
cp "$TMP/ai-before.env" "$TMP/ai-upgrade/.env"
run_ai_upgrade >"$TMP/ai-upgrade-custom-policy-output"
cmp -s "$TMP/ai-before.env" "$TMP/ai-upgrade/.env"
cmp -s "$TMP/operator-ai-policy-before.json" "$TMP/operator-ai-policy.json"
python3 - "$TMP/ai-upgrade/backups" "$TMP/operator-ai-policy-before.json" <<'PYTHON'
from pathlib import Path
import stat
import sys
matches = [path for path in Path(sys.argv[1]).glob("*.ai-egress-policy.json")
           if path.read_bytes() == Path(sys.argv[2]).read_bytes()]
assert matches
assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in matches)
PYTHON

mkdir "$TMP/ai-byodb-upgrade"
cp "$ROOT/deploy/upgrade.sh" "$TMP/ai-byodb-upgrade/upgrade.sh"
printf '%s\n' '# old compose' >"$TMP/ai-byodb-upgrade/tunnex.yml"
cat >"$TMP/ai-byodb-upgrade/.env" <<'ENV'
TUNNEX_RELEASE_PUBLIC_KEY=test-public-key
TUNNEX_RELEASE_CATALOG_URL=https://updates.example.test/release.json
COMPOSE_PROJECT_NAME=ai-byodb-upgrade
APP_BASE_URL=https://PREVIEW.TUNNEX.TEST:8443
TUNNEX_TLS_MODE=terminated
TUNNEX_DATABASE_MODE=external
COMPOSE_PROFILES=external-db
TUNNEX_DATABASE_URL='postgres://fixture:byodb-secret@db.internal/cp?sslmode=verify-full'
ENV
run_ai_upgrade "$TMP/ai-byodb-upgrade" >"$TMP/ai-byodb-upgrade-output"
python3 - "$TMP/ai-byodb-upgrade/ai-egress-policy.json" <<'PYTHON'
import json
import sys
policy = json.load(open(sys.argv[1]))
assert "postgres" not in policy["protected_hosts"]
assert "preview.tunnex.test" in policy["protected_hosts"]
assert "caddy" in policy["protected_hosts"]
PYTHON
! grep -Fq byodb-secret "$TMP/ai-byodb-upgrade-output"

for fault in partial duplicate missing-policy operator-proxy; do
  mkdir "$TMP/ai-upgrade-$fault"
  cp "$ROOT/deploy/upgrade.sh" "$TMP/ai-upgrade-$fault/upgrade.sh"
  cp "$TMP/ai-upgrade/tunnex.yml" "$TMP/ai-upgrade-$fault/tunnex.yml"
  cp "$TMP/ai-before.env" "$TMP/ai-fault.env"
  case "$fault" in
    partial)
      expected='AI egress credentials are incomplete'
      sed '/^TUNNEX_AI_CUSTOM_PROXY_PASSWORD=/d' "$TMP/ai-before.env" >"$TMP/ai-fault.env" ;;
    duplicate)
      expected='AI egress configuration contains duplicate entries'
      grep '^TUNNEX_AI_CUSTOM_PROXY_PASSWORD=' "$TMP/ai-before.env" >>"$TMP/ai-fault.env" ;;
    missing-policy)
      expected='configured AI egress policy is missing or unreadable'
      sed "s|^TUNNEX_AI_CUSTOM_ENDPOINTS_FILE=.*|TUNNEX_AI_CUSTOM_ENDPOINTS_FILE=$TMP/no-such-policy.json|" \
        "$TMP/ai-before.env" >"$TMP/ai-fault.env" ;;
    operator-proxy)
      expected='operator-managed AI egress proxy'
      sed 's|^TUNNEX_AI_CUSTOM_PROXY_URL=.*|TUNNEX_AI_CUSTOM_PROXY_URL=http://operator:do-not-print@elsewhere:8190|' \
        "$TMP/ai-before.env" >"$TMP/ai-fault.env" ;;
  esac
  cp "$TMP/ai-fault.env" "$TMP/ai-upgrade-$fault/.env"
  : >"$TMP/ai-upgrade.log"
  if run_ai_upgrade "$TMP/ai-upgrade-$fault" >"$TMP/ai-upgrade-$fault-output" 2>&1; then
    echo "AI upgrade accepted $fault egress configuration" >&2; exit 1
  fi
  grep -Fq "$expected" "$TMP/ai-upgrade-$fault-output"
  cmp -s "$TMP/ai-fault.env" "$TMP/ai-upgrade-$fault/.env"
  ! grep -Fq 'up -d' "$TMP/ai-upgrade.log"
  ! grep -Fq do-not-print "$TMP/ai-upgrade-$fault-output"
  proxy_password=$(sed -n 's/^TUNNEX_AI_CUSTOM_PROXY_PASSWORD=//p' "$TMP/ai-before.env")
  ! grep -Fq "$proxy_password" "$TMP/ai-upgrade-$fault-output"
done

# Snapshot failure restarts the original backend and stops before publishing
# new settings or recreating any control-plane service.
: >"$TMP/ai-upgrade.log"
if MOCK_AI_SNAPSHOT_FAIL=1 run_ai_upgrade >"$TMP/ai-upgrade-failure" 2>&1; then
  echo 'AI snapshot failure did not block upgrade' >&2; exit 1
fi
grep -Fq 'start bifrost' "$TMP/ai-upgrade.log"
! grep -Fq 'up -d' "$TMP/ai-upgrade.log"
cmp -s "$TMP/ai-before.env" "$TMP/ai-upgrade/.env"

echo 'upgrade apply contract passed'
