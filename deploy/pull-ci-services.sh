#!/bin/sh
# Retry only registry downloads, never stack startup, migrations or test failures.
set -eu
[ "$#" -gt 0 ] || { echo 'at least one Compose service is required' >&2; exit 2; }
attempt=1
while :; do
  if docker compose pull "$@"; then exit 0; else status=$?; fi
  if [ "$attempt" -ge 3 ]; then exit "$status"; fi
  echo "Registry download failed; retry $attempt/2" >&2
  sleep "$((attempt * 5))"
  attempt=$((attempt + 1))
done
