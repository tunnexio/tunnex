#!/bin/sh
# Run from apps/api. Every package belongs to exactly one shard; unknown/new packages
# automatically remain covered by "other". Serial packages still share one isolated DB.
set -eu
edition=${TEST_EDITION:-open}
shard=${API_TEST_SHARD:-all}
case "$edition" in open) set -- ;; enterprise) set -- -tags enterprise ;; *) echo 'invalid TEST_EDITION' >&2; exit 1 ;; esac
case "$shard" in all|db|ipsec|nodes|other) ;; *) echo 'invalid API_TEST_SHARD' >&2; exit 1 ;; esac
: "${TUNNEX_TEST_DATABASE_URL:?explicit test database required}"
# Build every package in both editions, retaining the previous compile acceptance gate.
go build "$@" ./...
packages=$(go list "$@" ./...)
selected=$(printf '%s\n' "$packages" | awk -v shard="$shard" '
  NF {
    group="other"
    if ($0 == "github.com/tunnexio/tunnex/apps/api/db") group="db"
    if ($0 == "github.com/tunnexio/tunnex/apps/api/internal/ipsec") group="ipsec"
    if ($0 == "github.com/tunnexio/tunnex/apps/api/internal/nodes") group="nodes"
    if (shard == "all" || group == shard) print
  }')
[ -n "$selected" ] || { echo "empty API test shard: $shard" >&2; exit 1; }
printf 'API edition=%s shard=%s\n%s\n' "$edition" "$shard" "$selected"
# Import paths cannot contain whitespace/globs. Disable glob expansion explicitly.
set -f
# shellcheck disable=SC2086
exec go test -count=1 -p 1 "$@" $selected
