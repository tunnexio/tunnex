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

## First increment evidence — 2026-09-24

Implementation branch: `story/site-to-site-connectivity`, fresh from `origin/main` at `1a81f8fc`; approved paper cherry-picked before product edits.

- Added authenticated application route and shared navigation entry; command palette consumes that same navigation registry.
- Reused existing network setup, Sites, access policy and routed range pages. No new APIs, secrets or packet-path changes.
- Self-review corrected overly broad access wording: the landing page asks operators to review policy rather than claiming every edition automatically denies newly added networks.
- TypeScript typecheck passed. Setup, command-palette, navigation-count and navigation-collapse suites: 44 tests passed after updating the site-search expectation for the additional destination.
- Vite production build passed; existing bundle-size warning remains.
- Actual component rendered in local Browser at desktop and 390px mobile; headings, method explanations and links inspected. Mobile document width equaled viewport width (390px); no horizontal overflow. This is a component preview, not authenticated full-application or live-network proof.
- Temporary preview files are not part of the product commit. Full application visual review, independent review and user visual acceptance remain pending; S2S-1 and the epic are not declared complete.

Next increment: existing-network visibility and permission-aware setup entry, preserving current hub/spoke topology; finish S2S-1 review before starting IPsec schema/runtime work.

## Second increment — existing site inventory

Reuse generated Site/Member types and existing organization/auth contexts. Read existing sites and current membership only; no connection records or new endpoints. Withdraw old-org rows synchronously on organization change and discard late replies. Failed site reads show retry, never an empty network list. Unknown membership hides setup action; verified managers retain existing setup entry. The preview uses explicit synthetic data, labeled demo data, with empty/error/member/loading states. It must never claim to show production inventory.

## Third increment — read-only two-network review

LOCKED within existing read-only UI scope: choose two distinct existing sites locally, then read their subnet lists and the organization's gateway list using existing endpoints. Selection does not create a tunnel, edit routes, add a policy, or promise a direct link. Gateway records and approved ranges are configuration facts, not traffic proof. Show failed reads separately from empty results. Limit subnet reads to the selected sites; discard obsolete responses and reset selection on organization/user/retry identity changes. Reuse existing Sites and Access destinations for mutations. Preview uses explicit fixtures with separately marked unavailable data.

Independent review of the second increment reported two P2 findings held for disposition: membership-read errors need an actionable retry distinct from lack of permission; organization discovery failure needs actual provider/page reload rather than local-only retry. No finding is marked resolved until disposition and regression evidence.

Founder disposition (2026-09-24): apply both recovery fixes. Membership read failure retains read-only site inventory with a permission-specific retry; organization discovery failure offers explicit page reload. Regression tests first reproduce both missing recovery paths; verification downgrade must immediately remove setup controls.

## Inventory and pair review evidence — 2026-09-24

- Implemented scoped site/member reads and selected-pair gateway/subnet reads using existing GET endpoints only. No schema, API contract, permission or packet-path change.
- Both approved recovery findings have regression coverage. The original two failing recovery cases passed after the fixes; a further user-switch case checks selector reset and rejection of a previous user's late subnet response.
- Screen census now explicitly accounts for SiteToSite with wiring and failure evidence: 15 covered + 12 pending = 27 accountable screens. No exemption or reduced assertion.
- Final local gates: TypeScript passed; 13 focused tests passed; full Vitest passed 1,559 tests across 131 files; Vite production build passed with the existing large-chunk warning. No backend/DB gate was run for this frontend-only increment.
- Independent static review found no actionable findings in identity isolation, partial failures, destination links, contract mappings and configuration/traffic wording.
- Browser checked synthetic selected-pair configuration, approved/pending ranges, missing gateway, permission retry and actual page reload. Keyboard focus proceeds from the second selector to the gateway link. At 390px, document width equals viewport width; mobile content and path guidance were inspected.
- Preview is synthetic component evidence, not an authenticated control-plane walk or live-network proof. User visual acceptance and full S2S-1 acceptance remain pending. The local `.s2s-preview` fixture is excluded from publication.
