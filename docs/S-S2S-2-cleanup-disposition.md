# Runtime cleanup disposition required for S2S-2

Status: recommended behavior approved by the user on 2026-09-24 ("go with recommended"). Implement retained safety guard and range reservation; do not reopen this choice. Completion still requires implementation and exact cleanup evidence.

Existing P3 permits finalization after exact assigned-gateway cleanup evidence and forbids timeout/operator force completion. The runtime proposal asks whether retained refusal-only objects count as finalized cleanup. Migration159 currently releases remote range reservations when never-delivered deletion finalizes; that behavior must remain for never-delivered records.

## Recommended runtime behavior

After delivered disable/delete, revoke payload permission first and verify all owned SAs, secrets, connection definitions, forwarding routes and established payload flows are gone. Retain a nonsecret refusal-only guard and its exact node/connection/prefix ownership record; retain range reservations while that guard is owed/present. Expose this separately from active connectivity (e.g. disabled/deleted, guard retained), never as an active tunnel. Never silently release the reservation, declare the host fully cleaned, or let an unrelated successor remove the guard. Reuse of the prefix/gateway requires a separately verified atomic ownership handover. Offline/revoked gateways remain cleanup pending. No TTL or force-complete button. Existing never-delivered delete remains immediate.

This chooses safety over immediate reuse: a previously delivered prefix can remain reserved after tunnel removal until guard handover is implemented/verified. It adds an explicit durable retained-guard ownership state and resource-deletion obligations, so disposition is required before coding this state model.

## Alternative

Require every owned object including refusal guards to be absent before finalization and keep cleanup pending while any guard is necessary. This avoids a separate finalized-with-guard state, but can leave deletion pending indefinitely. Removing guards merely to make deletion finish is not an allowed third option.

Engine adapter and isolated packet-path work can proceed while this lifecycle disposition is pending. Neither option permits broadening shared policy grants or leaking payload over an ordinary route.
