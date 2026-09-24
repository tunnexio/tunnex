# S2S-1 — Site-to-site discovery and method selection

Status: initial development authorized by Founder on 2026-09-24; paper precedes code.

| Decision | Disposition |
| --- | --- |
| D1 Navigation | LOCKED: dedicated /site-to-site page in Network; preserve /sites and existing setup URLs. |
| D2 Reuse | LOCKED for this slice: link to existing Sites topology, network setup, and policy surfaces. No new persistence or synthetic connection records. |
| D3 Topology | LOCKED: describe existing managed overlay; do not promise direct mesh or traffic verification from handshake. |
| D4 Protocol selection | LOCKED: working WireGuard entry; IPsec visibly unavailable with no actionable connect control until runtime support is qualified. |
| D5 Permissions | LOCKED: existing destination pages retain authoritative role/edition checks; landing page reads no secrets and performs no mutations. |
| D6 Remaining epic decisions | DEFERRED to S2S-2 decision paper: connection schema, engine, secrets, licensing, cloud profiles and routing. No such behavior introduced here. |

## Initial acceptance

- Discover Site-to-site from navigation and direct URL.
- Explain which endpoints require Tunnex for each method.
- Existing WireGuard setup and management remain reachable; existing pages keep their gates.
- IPsec cannot be activated and no provider is labeled supported prematurely.
- No backend, database, infrastructure or packet-path change.
- Typecheck, focused UI verification and production build; visual acceptance remains a separate gate before slice completion.

This is the first increment of S2S-1, not completion of the whole epic or a new two-network creation wizard. Endpoint call-site and destructive-action census is unchanged: this increment adds only navigation, no mutating endpoints or destructive verbs.
