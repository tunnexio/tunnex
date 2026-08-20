#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT HUP INT TERM
mkdir -p "$TMP/tunnex/upgrade-state/requests" "$TMP/tunnex/upgrade-state/status" "$TMP/tunnex/upgrade-state/work"
cp "$ROOT/deploy/upgrade-runner.sh" "$TMP/tunnex/upgrade-runner.sh"
cat >"$TMP/tunnex/upgrade.sh" <<'SH'
#!/bin/sh
set -eu
printf '%s\n' "$*" >"$MOCK_ARGS"
printf '%s\n' "$TUNNEX_UPGRADE_REQUEST_ID" >"$MOCK_REQUEST_ID"
cat >"$TUNNEX_UPGRADE_STATUS_FILE" <<EOF
request_id=$TUNNEX_UPGRADE_REQUEST_ID
state=healthy
target_source_sha=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
target_version=v9.9.9
backup_dump=backup.dump
backup_manifest=backup.manifest.json
reason_code=
updated_at=2026-08-20T00:00:00Z
EOF
SH
chmod 0755 "$TMP/tunnex/upgrade-runner.sh" "$TMP/tunnex/upgrade.sh"

cat >"$TMP/tunnex/upgrade-state/requests/request" <<'REQ'
request_id=12345678-1234-1234-1234-123456789abc
source_sha=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
target_version=v9.9.9
sequence=99
requested_by=87654321-4321-4321-4321-cba987654321
created_at=2026-08-20T00:00:00Z
REQ
MOCK_ARGS="$TMP/args" MOCK_REQUEST_ID="$TMP/request-id" "$TMP/tunnex/upgrade-runner.sh"
grep -Fq -- '--expected-source-sha aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --expected-sequence 99' "$TMP/args"
[ "$(cat "$TMP/request-id")" = 12345678-1234-1234-1234-123456789abc ]
[ ! -e "$TMP/tunnex/upgrade-state/requests/request" ]
find "$TMP/tunnex/upgrade-state/work" -maxdepth 1 -type f | grep -q . && { echo 'runner retained request snapshot' >&2; exit 1; }
grep -Fq 'state=healthy' "$TMP/tunnex/upgrade-state/status/status"

cat >"$TMP/tunnex/upgrade-state/requests/request" <<'REQ'
request_id=not-a-uuid;touch-pwned
source_sha=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
target_version=v9.9.9
sequence=99
requested_by=87654321-4321-4321-4321-cba987654321
created_at=2026-08-20T00:00:00Z
REQ
if MOCK_ARGS="$TMP/args-invalid" MOCK_REQUEST_ID="$TMP/request-id-invalid" "$TMP/tunnex/upgrade-runner.sh"; then
  echo 'invalid request unexpectedly ran' >&2
  exit 1
fi
[ ! -e "$TMP/args-invalid" ]
grep -Fq 'reason_code=invalid_request' "$TMP/tunnex/upgrade-state/status/status"

echo 'upgrade runner contract passed'
