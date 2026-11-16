#!/bin/sh
# Run one deterministic round-robin shard of the node IPsec runtime package.
# The package's simulated-cadence suite outgrew a single CI lane; every listed
# test, fuzz seed corpus and example belongs to exactly one shard, and an empty
# inventory or shard refuses instead of passing vacuously. Run from apps/node.
set -eu
shard=${1:-}
shards=${2:-}
case "$shard:$shards" in
  *[!0-9:]*|:*|*:) echo 'usage: ci-node-ipsec-shard.sh <shard> <shards>' >&2; exit 1 ;;
esac
if [ "$shards" -lt 1 ] || [ "$shard" -lt 1 ] || [ "$shard" -gt "$shards" ]; then
  echo "invalid IPsec shard $shard/$shards" >&2
  exit 1
fi
package=./internal/ipsec/
tests=$(go test -list . "$package" | grep -E '^(Test|Fuzz|Example)' | sort) || true
[ -n "$tests" ] || { echo 'empty IPsec test inventory' >&2; exit 1; }
selected=$(printf '%s\n' "$tests" | awk -v s="$shard" -v n="$shards" '(NR - 1) % n == s - 1')
[ -n "$selected" ] || { echo "empty IPsec shard $shard/$shards" >&2; exit 1; }
echo "IPsec shard $shard/$shards: $(printf '%s\n' "$selected" | wc -l | tr -d ' ') of $(printf '%s\n' "$tests" | wc -l | tr -d ' ') tests"
pattern=$(printf '%s\n' "$selected" | paste -sd '|' -)
go test -count=1 -timeout=30m -run "^($pattern)\$" "$package"
