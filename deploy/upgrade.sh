#!/bin/sh
# Tunnex host-side upgrade gate. No mutation occurs without --apply.
set -eu

# The installer places this helper next to tunnex.yml and .env. Resolve defaults
# from that installation directory so the customer command stays portable.
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
DIR=${TUNNEX_DIR:-$SCRIPT_DIR}
ENV_FILE=${TUNNEX_ENV_FILE:-$DIR/.env}
COMPOSE=${TUNNEX_COMPOSE_FILE:-$DIR/tunnex.yml}

# Read only updater settings from dotenv. Never source deployment configuration as
# shell code: it is operator-controlled input.
dotenv_value() {
  _name=$1
  [ -r "$ENV_FILE" ] || return 0
  sed -n "s/^${_name}=//p" "$ENV_FILE" | head -1
}

file_sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

# An explicit file is the air-gapped/import path. Online installations discover
# the next candidate from the signed catalog; neither path ever falls back to a
# mutable image tag.
MANIFEST=${TUNNEX_RELEASE_MANIFEST:-}
MANIFEST_EXPLICIT=false
if [ -n "$MANIFEST" ]; then MANIFEST_EXPLICIT=true; fi
PUBLIC_KEY=${TUNNEX_RELEASE_PUBLIC_KEY:-}
[ -n "$PUBLIC_KEY" ] || PUBLIC_KEY=$(dotenv_value TUNNEX_RELEASE_PUBLIC_KEY)
CATALOG_URL=${TUNNEX_RELEASE_CATALOG_URL:-}
[ -n "$CATALOG_URL" ] || CATALOG_URL=$(dotenv_value TUNNEX_RELEASE_CATALOG_URL)
COMPOSE_SHA256=${TUNNEX_COMPOSE_SHA256:-}
[ -n "$COMPOSE_SHA256" ] || COMPOSE_SHA256=$(dotenv_value TUNNEX_COMPOSE_SHA256)
PROJECT=${TUNNEX_COMPOSE_PROJECT:-${COMPOSE_PROJECT_NAME:-}}
[ -n "$PROJECT" ] || PROJECT=$(dotenv_value COMPOSE_PROJECT_NAME)
VERIFY=${TUNNEX_RELEASEVERIFY:-}
APPLY=false
AIRGAP=
EXPECTED_SOURCE_SHA=${TUNNEX_UPGRADE_EXPECTED_SOURCE_SHA:-}
EXPECTED_SEQUENCE=${TUNNEX_UPGRADE_EXPECTED_SEQUENCE:-}
STATUS_FILE=${TUNNEX_UPGRADE_STATUS_FILE:-}
REQUEST_ID=${TUNNEX_UPGRADE_REQUEST_ID:-manual}
TARGET_SOURCE_SHA=
TARGET_VERSION=
BACKUP_DUMP=
BACKUP_MANIFEST=
CURRENT_STAGE=
TERMINAL_STATUS=false
usage() { echo "usage: upgrade.sh [--manifest FILE] [--public-key KEY] [--apply] [--airgap DIR] [--expected-source-sha SHA] [--expected-sequence N]" >&2; exit 2; }
while [ "$#" -gt 0 ]; do
  case "$1" in
    --manifest) MANIFEST=${2:-}; MANIFEST_EXPLICIT=true; shift 2;;
    --public-key) PUBLIC_KEY=${2:-}; shift 2;;
    --airgap) AIRGAP=${2:-}; shift 2;;
    --expected-source-sha) EXPECTED_SOURCE_SHA=${2:-}; shift 2;;
    --expected-sequence) EXPECTED_SEQUENCE=${2:-}; shift 2;;
    --apply) APPLY=true; shift;;
    *) usage;;
  esac
done
case "$EXPECTED_SOURCE_SHA" in ''|*[!0-9a-f]*) [ -z "$EXPECTED_SOURCE_SHA" ] || usage ;; esac
[ -z "$EXPECTED_SOURCE_SHA" ] || [ "${#EXPECTED_SOURCE_SHA}" -eq 40 ] || usage
case "$EXPECTED_SEQUENCE" in ''|*[!0-9]*) [ -z "$EXPECTED_SEQUENCE" ] || usage ;; esac
[ -n "$PUBLIC_KEY" ] || { echo "error: trusted release public key is not configured in the deployment environment" >&2; exit 1; }
[ -f "$COMPOSE" ] && [ -f "$ENV_FILE" ] || { echo "error: deployment files not found" >&2; exit 1; }
TARGET_SOURCE_SHA=$EXPECTED_SOURCE_SHA
TMPDIR=$(mktemp -d "${TMPDIR:-/tmp}/tunnex-upgrade.XXXXXX")
trap 'rm -rf "$TMPDIR"' EXIT INT TERM
write_status() {
  [ -n "$STATUS_FILE" ] || return 0
  _state=$1 _reason=${2:-} _next="${STATUS_FILE}.next"
  umask 077
  {
    printf 'request_id=%s\n' "$REQUEST_ID"
    printf 'state=%s\n' "$_state"
    printf 'target_source_sha=%s\n' "$TARGET_SOURCE_SHA"
    printf 'target_version=%s\n' "$TARGET_VERSION"
    printf 'backup_dump=%s\n' "${BACKUP_DUMP##*/}"
    printf 'backup_manifest=%s\n' "${BACKUP_MANIFEST##*/}"
    printf 'reason_code=%s\n' "$_reason"
    printf 'updated_at=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  } >"$_next"
  chmod 0644 "$_next"
  mv "$_next" "$STATUS_FILE"
  CURRENT_STAGE=$_state
  case "$_state" in failed|healthy) TERMINAL_STATUS=true ;; esac
}
finish_upgrade() {
  _status=$?
  trap - EXIT INT TERM
  rm -rf "$TMPDIR"
  if [ "$_status" -ne 0 ] && [ "$APPLY" = true ] && [ "$TERMINAL_STATUS" = false ]; then
    case "$CURRENT_STAGE" in
      verifying|backing_up|preflight|pulling|restarting|health_check) write_status failed "${CURRENT_STAGE}_failed" ;;
      *) write_status failed upgrade_failed ;;
    esac
  fi
  exit "$_status"
}
trap finish_upgrade EXIT INT TERM
if [ "$MANIFEST_EXPLICIT" = true ]; then
  [ -n "$MANIFEST" ] && [ -r "$MANIFEST" ] || { echo "error: signed manifest is required" >&2; exit 1; }
else
  [ -n "$CATALOG_URL" ] || { echo "error: signed release catalog is not configured; use --manifest for an air-gapped bundle" >&2; exit 1; }
  MANIFEST="$TMPDIR/release.json"
  curl -fsSL "$CATALOG_URL" -o "$MANIFEST" || { echo "error: could not fetch the signed release catalog" >&2; exit 1; }
fi
verify_release() {
  fail_verification() {
    # Keep this deliberately generic: the host log may contain the exact parser
    # or signature reason, while operators and the UI should get one safe action.
    echo "error: update blocked; installation verification failed (tampered or incomplete release metadata)" >&2
    exit 13
  }
  if [ -n "$VERIFY" ]; then
    "$VERIFY" -manifest "$MANIFEST" -public-key "$PUBLIC_KEY" || fail_verification
  elif command -v releaseverify >/dev/null 2>&1; then
    releaseverify -manifest "$MANIFEST" -public-key "$PUBLIC_KEY" || fail_verification
  else
    # releaseverify ships in every API image, so no architecture-specific host
    # binary needs to be downloaded or trusted by the installer.
    # Stream the host manifest into the container because the compose file does
    # not mount the deployment directory into the API service.
    compose exec -T api sh -c \
      'cat > /tmp/tunnex-release.json && releaseverify -manifest /tmp/tunnex-release.json -public-key "$1"' \
      sh "$PUBLIC_KEY" < "$MANIFEST" || fail_verification
  fi
}
verify_release_env() {
  fail_verification() {
    echo "error: update blocked; installation verification failed (tampered or incomplete release metadata)" >&2
    exit 13
  }
  if [ -n "$VERIFY" ]; then
    "$VERIFY" -manifest "$MANIFEST" -public-key "$PUBLIC_KEY" -print-env
  elif command -v releaseverify >/dev/null 2>&1; then
    releaseverify -manifest "$MANIFEST" -public-key "$PUBLIC_KEY" -print-env
  else
    compose exec -T api sh -c \
      'cat > /tmp/tunnex-release.json && releaseverify -manifest /tmp/tunnex-release.json -public-key "$1" -print-env' \
      sh "$PUBLIC_KEY" < "$MANIFEST"
  fi || fail_verification
}
compose() {
  if [ -n "$PROJECT" ]; then
    docker compose --project-name "$PROJECT" --env-file "$ENV_FILE" -f "$COMPOSE" "$@"
  else
    docker compose --env-file "$ENV_FILE" -f "$COMPOSE" "$@"
  fi
}
compose_up() {
  case "$(dotenv_value TUNNEX_PORTABLE_CONTROL_PLANE)" in
    true) compose up "$@" --scale node-agent=0 ;;
    *) compose up "$@" ;;
  esac
}
healthcheck() {
  i=0
  while [ "$i" -lt 30 ]; do
    if compose exec -T api wget -qO- http://127.0.0.1:8080/healthz >/dev/null 2>&1; then
      return 0
    fi
    i=$((i + 1))
    sleep 2
  done
  return 1
}
[ -z "$COMPOSE_SHA256" ] || {
  [ "$(file_sha256 "$COMPOSE")" = "$COMPOSE_SHA256" ] || {
    echo "error: update blocked; installed deployment files changed after provisioning" >&2
    exit 13
  }
}
verify_release
RELEASE_ENV=$(verify_release_env)
release_value() {
  _key=$1
  _value=$(printf '%s\n' "$RELEASE_ENV" | sed -n "s/^${_key}=//p" | head -1)
  [ -n "$_value" ] || { echo "error: signed release verifier omitted ${_key}" >&2; exit 13; }
  printf '%s' "$_value"
}
TARGET_SOURCE_SHA=$(release_value TUNNEX_RELEASE_SOURCE_SHA)
TARGET_VERSION=$(release_value TUNNEX_RELEASE_VERSION)
TARGET_SEQUENCE=$(release_value TUNNEX_RELEASE_SEQUENCE)
[ -z "$EXPECTED_SOURCE_SHA" ] || [ "$TARGET_SOURCE_SHA" = "$EXPECTED_SOURCE_SHA" ] || {
  write_status failed approved_release_changed
  echo "error: update blocked; the signed release no longer matches the release approved in the UI" >&2
  exit 13
}
[ -z "$EXPECTED_SEQUENCE" ] || [ "$TARGET_SEQUENCE" = "$EXPECTED_SEQUENCE" ] || {
  write_status failed approved_release_changed
  echo "error: update blocked; the signed release sequence no longer matches the release approved in the UI" >&2
  exit 13
}
write_status verifying
if [ -n "$AIRGAP" ]; then
  [ -d "$AIRGAP" ] || { echo "error: air-gap bundle directory not found" >&2; exit 1; }
  for image in "$AIRGAP"/*.tar; do [ -f "$image" ] || continue; docker load -i "$image"; done
fi
echo "release verified; preflight and backup are required before mutation"
compose_prefix="docker compose"
[ -z "$PROJECT" ] || compose_prefix="$compose_prefix --project-name $PROJECT"
echo "  a PostgreSQL dump and matching key-bound manifest will be retained under $DIR/backups"
echo "  $compose_prefix --env-file $ENV_FILE -f $COMPOSE exec -T -e TUNNEX_PREFLIGHT_BACKUP_CONFIRMED=yes api preflight"
[ "$APPLY" = true ] || { echo "dry run: re-run with --apply after reviewing the commands above"; exit 0; }
BACKUP_DIR=${TUNNEX_UPGRADE_BACKUP_DIR:-$DIR/backups}
umask 077
mkdir -p "$BACKUP_DIR"
chmod 0700 "$BACKUP_DIR"
BACKUP_STAMP=$(date -u '+%Y%m%dT%H%M%SZ')
BACKUP_BASE="tunnex-${BACKUP_STAMP}-${REQUEST_ID}"
BACKUP_DUMP="$BACKUP_DIR/${BACKUP_BASE}.dump"
BACKUP_MANIFEST="$BACKUP_DIR/${BACKUP_BASE}.manifest.json"
write_status backing_up
compose exec -T postgres sh -c 'pg_dump --format=custom --no-owner --username "$POSTGRES_USER" "$POSTGRES_DB"' >"${BACKUP_DUMP}.next" || {
  rm -f "${BACKUP_DUMP}.next"
  write_status failed backup_failed
  echo "error: upgrade blocked; database backup failed" >&2
  exit 13
}
[ -s "${BACKUP_DUMP}.next" ] || {
  rm -f "${BACKUP_DUMP}.next"
  write_status failed backup_failed
  echo "error: upgrade blocked; database backup was empty" >&2
  exit 13
}
mv "${BACKUP_DUMP}.next" "$BACKUP_DUMP"
pg_restore --list "$BACKUP_DUMP" >/dev/null 2>&1 || {
  write_status failed backup_verification_failed
  echo "error: upgrade blocked; database backup is not a valid PostgreSQL archive" >&2
  exit 13
}
DUMP_SHA256=$(file_sha256 "$BACKUP_DUMP")
compose exec -T -e TUNNEX_BACKUP_DUMP_SHA256="$DUMP_SHA256" api backupctl manifest pre-upgrade >"${BACKUP_MANIFEST}.next" || {
  rm -f "${BACKUP_MANIFEST}.next"
  write_status failed backup_failed
  echo "error: upgrade blocked; backup manifest creation failed" >&2
  exit 13
}
compose exec -T api backupctl verify --dump-sha256 "$DUMP_SHA256" <"${BACKUP_MANIFEST}.next" >/dev/null || {
  rm -f "${BACKUP_MANIFEST}.next"
  write_status failed backup_verification_failed
  echo "error: upgrade blocked; backup manifest verification failed" >&2
  exit 13
}
mv "${BACKUP_MANIFEST}.next" "$BACKUP_MANIFEST"
write_status preflight
compose exec -T -e TUNNEX_PREFLIGHT_BACKUP_CONFIRMED=yes api preflight
set_dotenv() {
  _key=$1 _value=$2 _tmp="$ENV_FILE.next"
  # Values originate in a verified descriptor. Reject newlines anyway: dotenv is
  # operator input on every subsequent run and must never become shell syntax.
  case "$_value" in *'\n'*|*'\r'*) echo "error: invalid verified release value" >&2; exit 13;; esac
  awk -F= -v key="$_key" -v value="$_value" '
    $1 == key { print key "=" value; seen=1; next }
    { print }
    END { if (!seen) print key "=" value }
  ' "$ENV_FILE" > "$_tmp"
  mv "$_tmp" "$ENV_FILE"
}
public_url_scheme() {
  case "$1" in https://*) printf '%s' https ;; http://*) printf '%s' http ;; *) return 1 ;; esac
}
public_url_is_ip() {
  _authority=${1#*://}
  case "$_authority" in
    \[*\]*) _host=${_authority%%]*}; _host="${_host}]" ;;
    *) _host=${_authority%%:*} ;;
  esac
  case "$_host" in
    \[*:*\]) return 0 ;;
    *.*.*.*) case "$_host" in *[!0-9.]* | .* | *.) return 1 ;; esac; return 0 ;;
  esac
  return 1
}
ensure_edge_config() {
  # Upgrading a pre-edge install must not fail Compose interpolation. Preserve
  # an explicit operator choice; derive a conservative mode only when absent.
  grep -Fq 'TUNNEX_EDGE_LISTEN' "$COMPOSE" || return 0
  _base=$(dotenv_value APP_BASE_URL)
  _mode=$(dotenv_value TUNNEX_TLS_MODE)
  _scheme=$(public_url_scheme "$_base") || {
    echo "error: upgrade blocked; APP_BASE_URL must be an http:// or https:// URL before the public edge can be configured" >&2
    exit 13
  }
  if [ -z "$_mode" ]; then
    case "$_scheme" in
      http) _mode=http ;;
      https) if public_url_is_ip "$_base"; then _mode=terminated; else _mode=direct; fi ;;
    esac
    set_dotenv TUNNEX_TLS_MODE "$_mode"
  fi
  case "$_mode" in
    direct) _listen=$_base ;;
    terminated|http) _listen=http://:80 ;;
    *) echo "error: upgrade blocked; TUNNEX_TLS_MODE must be direct, terminated, or http" >&2; exit 13 ;;
  esac
  set_dotenv TUNNEX_EDGE_LISTEN "$_listen"
  case "$_scheme" in https) set_dotenv TUNNEX_COOKIE_SECURE true ;; http) set_dotenv TUNNEX_COOKIE_SECURE false ;; esac
}
SOURCE_SHA=$(release_value TUNNEX_RELEASE_SOURCE_SHA)
VERSION=$(release_value TUNNEX_RELEASE_VERSION)
write_status pulling
curl -fsSL "https://raw.githubusercontent.com/tunnexio/tunnex/${SOURCE_SHA}/deploy/tunnex.yml" -o "$TMPDIR/tunnex.yml" || {
  echo "error: could not fetch the deployment manifest bound to the signed release" >&2; exit 13;
}
grep -q 'TUNNEX_ENV: production' "$TMPDIR/tunnex.yml" && ! grep -qi 'mailpit' "$TMPDIR/tunnex.yml" || {
  echo "error: signed release points to a non-production deployment manifest" >&2; exit 13;
}
if [ "${TUNNEX_UPGRADE_PRIVILEGED:-}" = 1 ]; then
  curl -fsSL "https://raw.githubusercontent.com/tunnexio/tunnex/${SOURCE_SHA}/deploy/upgrade.sh" -o "$TMPDIR/upgrade.sh" || {
    echo "error: could not fetch the verified host upgrade helper" >&2; exit 13;
  }
  curl -fsSL "https://raw.githubusercontent.com/tunnexio/tunnex/${SOURCE_SHA}/deploy/upgrade-runner.sh" -o "$TMPDIR/upgrade-runner.sh" || {
    echo "error: could not fetch the verified host upgrade runner" >&2; exit 13;
  }
  sh -n "$TMPDIR/upgrade.sh" && sh -n "$TMPDIR/upgrade-runner.sh" || {
    echo "error: verified host upgrade assets are not valid shell" >&2; exit 13;
  }
  ROOT_UPGRADE_DIR=${TUNNEX_ROOT_UPGRADE_DIR:-/usr/local/lib/tunnex}
  install -d -o root -g root -m 0755 "$ROOT_UPGRADE_DIR"
  install -m 0755 -o root -g root "$TMPDIR/upgrade.sh" "$ROOT_UPGRADE_DIR/upgrade.sh.next"
  install -m 0755 -o root -g root "$TMPDIR/upgrade-runner.sh" "$ROOT_UPGRADE_DIR/upgrade-runner.sh.next"
  mv "$ROOT_UPGRADE_DIR/upgrade.sh.next" "$ROOT_UPGRADE_DIR/upgrade.sh"
  mv "$ROOT_UPGRADE_DIR/upgrade-runner.sh.next" "$ROOT_UPGRADE_DIR/upgrade-runner.sh"
  install -m 0755 "$TMPDIR/upgrade.sh" "$DIR/upgrade.sh.next"
  mv "$DIR/upgrade.sh.next" "$DIR/upgrade.sh"
fi
# Online catalog downloads already land at this destination. Avoid copying a
# file onto itself; GNU cp exits non-zero for that case and would abort the
# upgrade after the preflight/backup gate has passed.
if [ "$MANIFEST" != "$TMPDIR/release.json" ]; then
  cp "$MANIFEST" "$TMPDIR/release.json"
fi
for key in TUNNEX_API_IMAGE TUNNEX_WEB_IMAGE TUNNEX_NGINX_IMAGE TUNNEX_NODE_AGENT_IMAGE TUNNEX_MIGRATE_IMAGE TUNNEX_RELEASE_SEQUENCE; do
  set_dotenv "$key" "$(release_value "$key")"
done
set_dotenv TUNNEX_RELEASE_VERSION "$VERSION"
set_dotenv TUNNEX_RELEASE_SOURCE_SHA "$SOURCE_SHA"
set_dotenv TUNNEX_VERSION "$VERSION"
set_dotenv TUNNEX_SOURCE_REF "$SOURCE_SHA"
set_dotenv TUNNEX_RELEASE_MANIFEST_PATH /var/lib/tunnex/release.json
mv "$TMPDIR/tunnex.yml" "$COMPOSE"
mv "$TMPDIR/release.json" "$DIR/release.json"
# The descriptor is public signed metadata, not a credential. Curl/mktemp commonly
# leave it at 0600, but the API runs as an unprivileged container user and must be
# able to verify this read-only bind mount at every boot.
chmod 0644 "$DIR/release.json"
ensure_edge_config
set_dotenv TUNNEX_COMPOSE_SHA256 "$(file_sha256 "$COMPOSE")"
compose pull
write_status restarting
compose_up -d
compose ps --all
write_status health_check
if ! healthcheck; then
  write_status failed health_check_failed
  echo "error: upgrade health check failed; restore the verified pre-upgrade backup before retrying" >&2
  exit 14
fi
write_status healthy
echo "upgrade health check passed"
echo "upgrade applied; retain the backup manifest and dump for forward-only rollback"
