module github.com/tunnexio/tunnex/apps/cli

// GUARD: builds/tests use GOFLAGS=-mod=readonly so dependency resolution cannot
// silently rewrite go.mod/go.sum. The module path matches the canonical repository.

go 1.25.13

require github.com/oapi-codegen/runtime v1.1.1

require (
	github.com/apapsch/go-jsonmerge/v2 v2.0.0 // indirect
	github.com/google/uuid v1.5.0 // indirect
)
