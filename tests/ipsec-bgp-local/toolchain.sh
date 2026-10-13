# Sourced by owned build helpers. Never fall back to the host's default Go.
local_go=${TUNNEX_LOCAL_GO:-/Users/pawangupta/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.26.8.darwin-arm64/bin/go}
[ -x "$local_go" ] || { echo 'Qualified Go 1.26.8 toolchain missing' >&2; exit 1; }
local_go_version=$(GOTOOLCHAIN=local "$local_go" version)
case "$local_go_version" in 'go version go1.26.8 '*) ;; *) echo 'Build helper requires exact Go 1.26.8' >&2; exit 1 ;; esac
