#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

for prefix in tunnex tunnex-isolation-contract; do
  recipes=$(make -n generate-tokens web-gate GATE_CACHE_PREFIX="$prefix")
  for mount in "$prefix-nm:/w/node_modules" \
    "$prefix-shared-nm:/w/packages/shared/node_modules" \
    "$prefix-web-nm:/w/apps/web/node_modules"; do
    printf '%s\n' "$recipes" | grep -Fq -- "-v $mount"
  done
  if [[ "$prefix" != tunnex ]] && printf '%s\n' "$recipes" | grep -Eq -- '-v tunnex(-shared|-web)?-nm:'; then
    printf 'isolated gate recipe touches a default dependency cache\n' >&2
    exit 1
  fi
done
printf 'gate cache isolation contract: PASS\n'
