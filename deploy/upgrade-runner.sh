#!/bin/sh
# Fixed-purpose bridge from one bounded API request file to upgrade.sh.
# It accepts no command text and exposes no listener.
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
DIR=${TUNNEX_DIR:-$SCRIPT_DIR}
STATE_DIR=${TUNNEX_UPGRADE_STATE_DIR:-$DIR/upgrade-state}
REQUEST_FILE=${TUNNEX_UPGRADE_REQUEST_FILE:-$STATE_DIR/requests/request}
STATUS_FILE=${TUNNEX_UPGRADE_STATUS_FILE:-$STATE_DIR/status/status}
LOCK_DIR=$STATE_DIR/runner.lock

write_failure() {
  _request_id=$1 _source=$2 _reason=$3 _next="${STATUS_FILE}.next"
  umask 077
  {
    printf 'request_id=%s\n' "$_request_id"
    printf 'state=failed\n'
    printf 'target_source_sha=%s\n' "$_source"
    printf 'target_version=\n'
    printf 'backup_dump=\n'
    printf 'backup_manifest=\n'
    printf 'reason_code=%s\n' "$_reason"
    printf 'updated_at=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  } >"$_next"
  chmod 0644 "$_next"
  mv "$_next" "$STATUS_FILE"
}

value() {
  sed -n "s/^$1=//p" "$REQUEST_FILE" | head -1
}

[ -f "$REQUEST_FILE" ] || exit 0
mkdir "$LOCK_DIR" 2>/dev/null || exit 0
trap 'rmdir "$LOCK_DIR" 2>/dev/null || true; rm -f "$REQUEST_FILE"' EXIT HUP INT TERM

size=$(wc -c <"$REQUEST_FILE" | tr -d ' ')
case "$size" in ''|*[!0-9]*|0) write_failure unknown '' invalid_request; exit 1 ;; esac
[ "$size" -le 4096 ] || { write_failure unknown '' invalid_request; exit 1; }

if grep -Ev '^(request_id|source_sha|sequence|requested_by|created_at)=[A-Za-z0-9:_.+Z-]*$' "$REQUEST_FILE" | grep -q .; then
  write_failure unknown '' invalid_request
  exit 1
fi
for key in request_id source_sha sequence requested_by created_at; do
  [ "$(grep -c "^${key}=" "$REQUEST_FILE")" -eq 1 ] || {
    write_failure unknown '' invalid_request
    exit 1
  }
done

request_id=$(value request_id)
source_sha=$(value source_sha)
sequence=$(value sequence)
case "$request_id" in ????????-????-????-????-????????????) ;; *) write_failure unknown "$source_sha" invalid_request; exit 1 ;; esac
case "$source_sha" in *[!0-9a-f]*) write_failure "$request_id" '' invalid_request; exit 1 ;; esac
[ "${#source_sha}" -eq 40 ] || { write_failure "$request_id" '' invalid_request; exit 1; }
case "$sequence" in ''|*[!0-9]*) write_failure "$request_id" "$source_sha" invalid_request; exit 1 ;; esac

if ! TUNNEX_UPGRADE_REQUEST_ID="$request_id" \
  TUNNEX_UPGRADE_STATUS_FILE="$STATUS_FILE" \
  "$DIR/upgrade.sh" --apply \
    --expected-source-sha "$source_sha" \
    --expected-sequence "$sequence"; then
  # upgrade.sh writes specific failures once execution begins. Preserve those;
  # only synthesize a generic result for failures before its status seam.
  if [ "$(sed -n 's/^request_id=//p' "$STATUS_FILE" 2>/dev/null | head -1)" != "$request_id" ]; then
    write_failure "$request_id" "$source_sha" upgrade_failed
  fi
  exit 1
fi
