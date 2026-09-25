# S2S-3: two-tunnel recovery decision foundation

This increment is a pure internal decision reducer, not connected to the controller. It cannot change routes, grant traffic or report a selected path. Production retains its fixed initial path until integration and native switch tests pass.

## Candidate rules, recorded before implementation

Bind history to the exact policy/configuration/desired revisions, delivery, namespace and ordered tunnel identities. Reset on epoch/current-slot changes, missing authority, unknown/invalid status, stale/duplicate/regressing observations, clock discontinuity or gaps over 10 seconds. Refuse immediately when current path is not Up; hold-down delays switching, never refusal.

Keep a healthy selected path; no automatic failback. Recommend the alternate only after three independent fresh observations spanning at least 10 seconds show current Down and alternate Up. Snapshot age is at most 5 seconds. These candidate constants remain inactive in production.

A recommendation never updates current selection. Future serialized integration must verify refusal, revalidate authority/candidate, replace exact owned routes, read back kernel/daemon/policy agreement, update durable selection and observations, and only then restore a bounded permit. Failure/restart retain refusal.

## Foundation-stage integration constraints (superseded)

Allocation validation, runtime proof, material delivery and status currently assume slot 1. Define a compatible selected-slot journal/delivery/status contract before changing these assumptions. Require crash-at-each-stage and native encrypted-payload switch proof on both architectures. PSK rotation and overlapping rekey remain separate. The deferred full CI failure remains unresolved.

## Foundation verification — 2026-09-25 (before integration)

Pure reducer implemented without production call sites. Full IPsec/control race suites passed; focused recovery race tests passed after independent review added the alternate-loss reset scenario. Four overlay mutants removing authority, epoch, hold-down or clock checks were behaviorally rejected; source was unchanged by mutation runs. Integration proposal is in S-S2S-3-runtime-integration.md and awaits disposition of new persisted authority/journal/status semantics. Automatic failover is not yet implemented or enabled. No publication or CI monitoring occurred.

## Current state

The reducer is now integrated with versioned material, journal v2, exact route switching and independent active-path telemetry. See [integration evidence](S-S2S-3-runtime-integration.md). Initial native ARM64 failover passed; final architecture acceptance and PSK rotation remain open. The foundation-stage statements above record the original boundary rather than current implementation status.
