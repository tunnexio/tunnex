# F01 authenticated browser walk

> SUPERSEDED by `walk-artifacts/F01/20260814T165700Z/browser-walk-correction.md` and the subsequent affected-path wire walk. Retained for audit history; its pre-correction member Actions observation is not current evidence.

Date: 2026-08-14 UTC
Environment: isolated `f01-browser` compose project only; retained named volumes
Redaction: credentials, tokens, request IDs, and personal identifiers omitted

## Boundary and tunnel proof

- Colima SSH config reported VM endpoint `127.0.0.1:58372` and VM address `192.168.5.1`.
- Isolated nginx resolved binding: `0.0.0.0:18081 -> nginx:8080`.
- From inside the VM, `curl http://127.0.0.1:18081/healthz` returned HTTP 200.
- Foreground tunnel used: `ssh -i <colima-user-key> -p 58372 ... -N -L 127.0.0.1:18081:127.0.0.1:18081 <colima-user>@127.0.0.1`.
- Host `curl http://127.0.0.1:18081/healthz` returned HTTP 200 through the tunnel.

## Authenticated route observations

- Owner session: `/agents` rendered two seeded agent rows, including `Authorised by` owner attribution and `Remove` actions.
- Unverified admin session: `/agents` rendered the agent list and owner attribution/action controls, while also displaying `Verify your email to unlock all actions.`
- Plain member session: `/agents` rendered the agent rows without `Authorised by` or owner email and without the gateway column values. The current route still rendered `Remove` actions; this is a held product finding, not silently folded here.
- Owner org switch from `Demo Organization` to `Demo EU`: immediately after selection the main content showed `Loading…` and no prior roster rows; after refetch it showed the empty-org state (`No AI agents are enrolled in this organization`). Navigation counts also changed to the target org. This confirms current `rows`/profile/runtime clearing on the live route.

## Cleanup

- The SSH forward was terminated after the walk.
- Only the `f01-browser` containers/network were stopped; named volumes were retained.
- Existing stacks and internal/live control planes were not changed.

This is live authenticated route evidence for the listed observations. Database, lifecycle, rollback, and component tests remain recorded as SUBSTITUTES in `docs/F01-boxwalk.md`; they do not SATISFY the remaining lifecycle/profile-editor wire proof.
