# F01 corrected authenticated browser walk

Date: 2026-08-14 UTC
Environment: rebuilt isolated `f01-browser` compose project with retained volumes; localhost exposed only by foreground Colima SSH forward
Redaction: credentials, tokens, request IDs, and personal identifiers omitted

## Correction diagnosis

- The first rebuilt route expansion was exercised through the new `Open <agent>` disclosure button.
- The profile GETs returned HTTP 404, and isolated DB inspection showed both seeded agent devices lacked `agent_profiles` rows.
- Cause: fixture devices are inserted after migration 0079, so migration backfill cannot create their profiles. The fixture seeder now inserts default empty metadata rows only; canonical owner/status/telemetry remain on their existing tables.
- After rerunning the supported isolated fixture seeder, both profile GETs returned HTTP 200.

## Corrected live route

- Owner: `/agents` rendered the disclosure, profile owner/telemetry, metadata editor, and manager Actions/Remove controls.
- Owner metadata: changed environment to a redacted walk value; PATCH returned HTTP 200 and the route refetched the persisted profile. The request contained metadata only, without lifecycle status.
- Manager lifecycle: expanded the agent owned by the departed user, confirmed Suspend, refetched `Lifecycle: suspended`, confirmed Resume, refetched `Lifecycle: active`.
- Plain member: `/agents` omitted `Actions`, `Remove`, owner attribution, and profile metadata. Expanding an agent did not render profile facts; isolated API logs recorded profile access refusal for the member path.
- Seeded admin: `/agents` rendered `Actions`, `Remove`, owner attribution, and the expanded profile/lifecycle controls. The fixture also displayed its existing `Verify your email to unlock all actions.` guard; no lifecycle mutation was sent from this intentionally unverified account.
- Owner org switch: selecting the second seeded organization immediately rendered `Loading…` with no prior roster rows; refetch rendered the target organization’s empty-agent state.

## Tunnel and cleanup

- Colima VM-local health returned HTTP 200.
- Foreground tunnel: `ssh -i <colima-user-key> -p 58372 ... -N -L 127.0.0.1:18081:127.0.0.1:18081 <colima-user>@127.0.0.1`.
- Host health through the tunnel returned HTTP 200.
- The tunnel and isolated project were terminated after the walk; retained named volumes were preserved.
- Existing stacks and internal/live control planes were not changed.

This artifact is live authenticated route evidence for disclosure, privacy, metadata persistence, lifecycle refetch, member absence, and org-switch clearing. Remaining database/data-plane/rollback evidence remains separately marked SUBSTITUTE in `docs/F01-boxwalk.md`.
