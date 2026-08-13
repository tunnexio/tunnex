// Package wfp is a PINNED VENDORED copy of golang.zx2c4.com/wireguard/windows/tunnel/firewall
// (v1.0.1, MIT — headers preserved). The diff vs upstream is confined to THREE deltas for the
// S6.7 Windows kill-switch persistence: (1) a NON-dynamic WFP session (so the block survives
// process death), (2) FIXED provider+sublayer GUIDs (the durable key cleanup enumerates by;
// upstream generates random GUIDs per arm, which is why a crashed block was unfindable), and
// (3) an explicit enumerate-and-delete DisableFirewall/cleanup (upstream only closes the
// dynamic session). The FILTER SET (rules.go) is byte-identical. See docs/S6.7-decisions.md and
// VENDOR.md. Upstream-sync obligation: on any wireguard/windows bump, re-diff + re-apply the
// three deltas as a reviewed sync.
//
// This file has NO build tag so the package always has one buildable file on every OS (the real
// implementation is windows-only); without it `go build ./...` on non-windows errors on an
// all-excluded package.
package wfp
