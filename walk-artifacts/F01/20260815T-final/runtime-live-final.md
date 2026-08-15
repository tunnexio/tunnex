# F01 connected-agent live proof — 2026-08-15

All scratch paths were under `/Users/pawangupta/tunnex/.f01-live-final-20260815`.
Credentials, tokens, private keys, runtime config, and raw responses were not
retained in this artifact.

## Initial revision and handshake

- Fresh owner login: HTTP 200; cookie mode 0600.
- F01-owned gateway: active; container running; TUN present; WireGuard active.
- F01-owned managed agent bootstrap: active; runtime image
  `tunnex-f04-runtime-current:latest`.
- Runtime container: running; interface `runtime` present.
- Local runtime state: `applied_revision=1`.
- Runtime status: `desired_revision=1`, `applied_revision=1`,
  `connectivity=connected`, `stale=false`.
- Matching gateway peer: present; latest handshake and RX/TX counters
  non-zero. Peer key was compared by a redacted fingerprint only.

## Suspend

- Canonical lifecycle PATCH: HTTP 200.
- Runtime poll: HTTP 401.
- Gateway peer: absent after the reconcile window (20 seconds in this run).
- Runtime: exited with code 1 after its unauthorized shutdown path settled.
- Local interface: absent.

## Resume

- Canonical lifecycle PATCH: HTTP 200.
- Disposable runtime state reset to revision 0, then runtime restarted.
- Runtime state reapplied revision 1.
- Runtime: running; interface `runtime` present.
- Runtime status: `desired_revision=1`, `applied_revision=1`,
  `connectivity=connected`, `stale=false`.
- Matching gateway peer: present; latest handshake and RX/TX counters
  non-zero (`handshake=1786763301`, `rx=180`, `tx=92`).

## Cleanup

Only the F01-owned managed agent, gateway, containers, and disposable artifacts
were removed after capture. The shared stack, root gateway, root agent, and
organization opt-in were retained.
