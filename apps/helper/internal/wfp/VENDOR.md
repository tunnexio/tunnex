# Vendored: wireguard/windows/tunnel/firewall

**Source:** `golang.zx2c4.com/wireguard/windows/tunnel/firewall` @ **v1.0.1** (MIT — license
headers preserved in every file).

**Why vendored:** S6.7 needs the WFP block to SURVIVE process death. The session flag + the
provider/sublayer GUIDs are created inside this package's unexported internals, and cleanup needs
delete/enumerate syscalls the package never wrote — none reachable without owning the copy. See
`docs/S6.7-decisions.md`.

## Deltas vs upstream (the ONLY intended differences — audit against these)

Vendoring adaptations (mechanical, no behavior change):
- `package firewall` → `package wfp` (dir name).
- Added `//go:build windows` to the un-suffixed files (`blocker.go`, `helpers.go`, `rules.go`) and
  narrowed the arch tags in `types_windows_32.go` / `types_windows_64.go` to `windows && (…)` — the
  upstream `_64`/`_32` suffixes are NOT valid GOARCH suffixes, so without this the files leak onto
  darwin/arm64 and break `go build ./...`. Added tag-free `doc.go` so the package always has one
  buildable file on non-windows.

Behavioral deltas (S6.7 — the three approved changes; **filter set / `rules.go` is BYTE-IDENTICAL**):
1. **Non-dynamic session** — `createWfpSession` drops `cFWPM_SESSION_FLAG_DYNAMIC` so BFE keeps the
   objects after the engine handle (and the process) closes.
2. **Fixed provider + sublayer GUID** — `registerBaseObjects` uses fixed GUID constants instead of
   `windows.GenerateGUID()` (the durable key cleanup enumerates by).
3. **Enumerate-and-delete cleanup** — `DisableFirewall` deletes our filters (enumerated by provider),
   then the sublayer + provider by key, instead of just closing the session. Adds the FWPM
   delete/enum syscall wrappers upstream never had (`tunnex.go`). `EnableFirewall` cleans first
   (so re-arm self-heals past ALREADY_EXISTS) and CLOSES the session after commit (objects persist);
   the `wfpSession` global + the "already enabled" `errors.New` are removed.
4. **Display names (discoverability, non-logic)** — provider/sublayer/session display data renamed
   `WireGuard*` → `Tunnex*`, and the provider DESCRIPTION carries the literal recovery command so
   `netsh wfp show state` self-documents the escape hatch on a locked-out box. No filter effect.

New Tunnex-only file: `tunnex.go` (fixed GUIDs, the delete/enum syscalls, `removePersistentObjects`,
and the exported `Clean()`). `rules.go` (the filter set) is untouched.

## Upstream-sync obligation
On any bump of `golang.zx2c4.com/wireguard/windows`, re-diff this copy against the new upstream
`firewall` package and re-apply the three behavioral deltas as a SEPARATE reviewed sync. Do not let
this copy drift silently. (Named in the PLAN.)
