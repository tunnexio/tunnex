module github.com/tunnexio/tunnex/apps/helper

// GUARD: builds/tests use GOFLAGS=-mod=readonly so dependency resolution cannot
// silently rewrite go.mod/go.sum. The module path matches the canonical repository.
//
// The core (protocol / config / auth / state / ipc) is STDLIB-ONLY. Deps are
// platform-only + never in the core test path: golang.org/x/sys (caller-path —
// SO_PEERCRED / LOCAL_PEERPID / GetNamedPipeClientProcessId) and Microsoft/go-winio
// (the Windows SDDL-protected named-pipe listener). Tunnel backends (wireguard-go /
// wireguard-nt) arrive later in build-tagged files. CI cross-compiles CGO_ENABLED=0,
// so any cgo file (e.g. macOS libproc) carries a no-cgo stub sibling.

go 1.25.13

require golang.org/x/sys v0.43.0

require (
	github.com/Microsoft/go-winio v0.6.2
	golang.zx2c4.com/wireguard v0.0.0-20260522210424-ecfc5a8d5446
	golang.zx2c4.com/wireguard/windows v1.0.1
)

require (
	golang.org/x/crypto v0.50.0 // indirect
	golang.org/x/net v0.53.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
)
