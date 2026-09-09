module github.com/tunnexio/tunnex/apps/node

// GUARD: builds/tests use GOFLAGS=-mod=readonly so dependency resolution cannot
// silently rewrite go.mod/go.sum. The module path matches the canonical repository.

go 1.25.13

require (
	github.com/florianl/go-conntrack v0.7.0
	github.com/florianl/go-nflog/v2 v2.3.0
	github.com/mdlayher/netlink v1.9.1-0.20260312172110-2a932c0fc1ae
	golang.org/x/net v0.56.0
	golang.org/x/sys v0.46.0
)

require (
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/mdlayher/socket v0.5.1 // indirect
	github.com/pion/dtls/v3 v3.1.8 // indirect
	github.com/pion/ice/v4 v4.4.2 // indirect
	github.com/pion/logging v0.2.4 // indirect
	github.com/pion/mdns/v2 v2.2.0 // indirect
	github.com/pion/randutil v0.1.0 // indirect
	github.com/pion/stun/v4 v4.0.0 // indirect
	github.com/pion/transport/v4 v4.1.0 // indirect
	github.com/pion/turn/v5 v5.1.0 // indirect
	github.com/wlynxg/anet v0.0.5 // indirect
	golang.org/x/crypto v0.53.0 // indirect
	golang.org/x/sync v0.19.0 // indirect
	golang.org/x/time v0.14.0 // indirect
)
