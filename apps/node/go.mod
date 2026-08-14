module github.com/tunnexio/tunnex/apps/node

// GUARD: builds/tests use GOFLAGS=-mod=readonly so dependency resolution cannot
// silently rewrite go.mod/go.sum. The module path matches the canonical repository.

go 1.25.13

toolchain go1.25.11

require (
	github.com/florianl/go-conntrack v0.7.0
	github.com/florianl/go-nflog/v2 v2.3.0
	golang.org/x/net v0.50.0
	golang.org/x/sys v0.41.0
)

require (
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/mdlayher/netlink v1.9.1-0.20260312172110-2a932c0fc1ae // indirect
	github.com/mdlayher/socket v0.5.1 // indirect
	golang.org/x/sync v0.19.0 // indirect
)
