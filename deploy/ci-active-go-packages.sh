#!/bin/sh
# List active tests in this module. All retained source still builds; only
# exclusive sandbox packages leave standard test lanes while development pauses.
# TODO: docs/S-sandbox-shelved-main-reentry.md.
set -eu
module=${1:-}
case "$module" in
  api|node|cli) root="github.com/tunnexio/tunnex/apps/$module" ;;
  *) echo 'expected active Go module: api, node or cli' >&2; exit 1 ;;
esac
shift
GOFLAGS="${GOFLAGS:-} -mod=readonly"
export GOFLAGS
packages=$(go list "$@" ./...) || exit $?
selected=$(printf '%s\n' "$packages" | awk -v root="$root" -v module="$module" '
  NF {
    if ($0 ~ /[[:space:]]/ || ($0 != root && index($0, root "/") != 1)) {
      print "invalid active Go package inventory" > "/dev/stderr"
      invalid=1
      next
    }
    relative=substr($0, length(root) + 2)
    dormant=0
    if (module == "api" || module == "node") dormant=index(relative, "cmd/tunnex-sandbox-") == 1
    if (module == "cli") dormant=relative == "cmd/tunnex-sandbox-bootstrap"
    if (module == "api") {
      count=split("sandboxes sandboxrunner sandboxruntime sandboxscope", families, " ")
      for (i=1; i<=count; i++) {
        family="internal/" families[i]
        if (relative == family || index(relative, family "/") == 1) dormant=1
      }
    }
    if (module == "node" && (relative == "internal/sandboxnetwork" || index(relative, "internal/sandboxnetwork/") == 1)) dormant=1
    if (!dormant) print
  }
  END { if (invalid) exit 1 }
')
[ -n "$selected" ] || { echo "empty active Go package selection: $module" >&2; exit 1; }
printf '%s\n' "$selected"
