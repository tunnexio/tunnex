# WF-C — orphaned wg0 / zombie hub — characterization (read-only, held for disposition)

**Origin:** EPIC 8 smooth walk (2026-07-23). `docker stop tunnex-node` killed the agent but wg0
kept forwarding headless — the data plane survived the control plane, so failover (data-plane
driven) never fired on agent death, and a "stopped" gateway stayed a zombie hub. Characterized
by code trace; **NOTHING built** — the class split decides hotfix vs decision-first per the
standing rule.

## Root cause (cited)

- The agent CREATES wg0 via `ip link add dev wg0 type wireguard` — `apps/node/internal/reconcile/
  wgctrl_linux.go:107` (`ensureDevice`). With `--network host` (the compose/prod deploy), wg0
  lives in the HOST netns, NOT the container's.
- On shutdown: SIGTERM/SIGINT → ctx cancel (`cmd/agent/main.go:51`) → `defer egressMgr.Teardown()`
  (`main.go:126`). **Teardown deletes ONLY the nft tables** (`delete table ip tunnex` —
  `internal/egress/egress_linux.go` Teardown), **NOT the wg0 interface.** There is NO `ip link
  del wg0` anywhere in the agent's lifecycle (grep-confirmed).
- Therefore a graceful `docker stop` (SIGTERM) leaves wg0 in the host netns; a hard kill
  (SIGKILL/OOM) skips the defer entirely — either way wg0 persists and keeps forwarding.

## The class split (the disposition question)

**LAYER 1 — graceful-stop wg0 leak → HOTFIX-sized (no kill-switch touch).** Add an `ip link del
wg0` to the agent's Teardown/shutdown so a graceful stop tears the data plane down cleanly. This
does NOT touch any kill-switch — the kill-switch lives on the CLIENT/HELPER (pf/WFP), the
node-agent gateway has none. So per the rule (lifecycle-residue = hotfix), Layer 1 is reds + sha,
no paper. Effect: `docker stop` → wg0 gone → the hub's data plane dies with the agent → failover
fires correctly (the walk's first-attempt confusion — "docker stop didn't trigger failover" —
closes). A new backend method (`Close`/`Down` deleting the interface) called from Teardown.
  Reds: Teardown deletes wg0 (fake `runFn` asserts the `ip link del` call); idempotent (absent
  wg0 → no error); the nft-table teardown still runs (order: tables then link, or link-independent).

**LAYER 2 — hard-crash zombie hub → NOT lifecycle-residue → DECISION-FIRST.** A SIGKILL / OOM /
kernel-panic skips the defer, so wg0 survives regardless of Layer 1. The hub then FORWARDS
HEADLESS (can't reconcile — no new peers/policy) while failover (data-plane-handshake driven)
stays BLIND to it (the WG handshake is still fresh). This is the SAME surface as the failover
liveness model — it asks: should failover ALSO consider agent heartbeat (control-plane liveness),
not only the data-plane handshake? Options (a decide-item, not a patch):
  - **(a) accept-by-design + document:** a crashed-agent-but-live-wg0 hub still carries traffic;
    it is surfaced "offline" (node last_seen) on the site card; failover intentionally does NOT
    fire on a working tunnel. The zombie can't reconcile, but it forwards — degraded-not-dead.
  - **(b) container-netns for wg0:** run wg0 in the container's own netns (not host) so it dies
    with the container on ANY exit. COST: the gateway needs host-LAN forwarding — the whole
    reason `--network host` exists; a netns move is a deploy-architecture change, not small.
  - **(c) failover considers agent heartbeat:** the controller demotes a hub whose AGENT is
    stale (last_seen) even if its data-plane handshake is fresh — a control-plane liveness input
    alongside the data-plane one. COST: touches the failover controller (the reviewed surface)
    + risks demoting a hub that is still forwarding fine (a false demotion churns transit).
  Lean (for the paper, not ruled): (a) document + (c) as a registered follow-up — a headless-
  forwarding hub is degraded-not-dead, and demoting a working tunnel on control-plane staleness
  alone re-introduces the churn the 240s window exists to avoid. But this is the founder's call.

## Disposition needed

- Layer 1: build as a hotfix now (reds + sha)? — my read: yes, it's clean lifecycle hygiene, no
  kill-switch, closes the docker-stop confusion.
- Layer 2: paper it as a failover-liveness decide-item (folds naturally near WF-A/the hub-HA
  surface), or accept-by-design + document? — founder's ruling.

Nothing built. Held.
