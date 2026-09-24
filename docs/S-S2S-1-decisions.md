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

## Fourth increment — existing reported gateway diagnostics

Within the approved read-only visibility scope, reuse `policyHealthBadge` and `siteLinkNote` from the existing health projection. Show reported degradation and subordinate peer notes next to the recorded gateway identity and last report; do not turn an absent badge into a healthy/connected verdict. Reuse existing badge styling. Revoked gateways retain their revoked state and suppress repair diagnostics, including subordinate notes. No liveness timer, new endpoint, topology inference, permission or persistence change.

Acceptance: active site-link-down and unknown degradation retain existing labels; revoked gateways show no repair diagnosis; demoted-peer note stays separate from the headline; absent diagnostics do not claim health. Preview degraded/revoked/missing-data states and long names at mobile width. Keep the traffic-not-verified statement and the existing site/access destinations.

Review disposition ledger: independent review found one P2, held for Founder disposition — the shared badge no-wrap style lets a long supported diagnosis overflow a nested mobile card. Browser reproduced a 411px document at a 390px viewport using `k8s_endpoints_unavailable`. Proposed correction is wrapping scoped to the new reported-diagnosis badge; shared badge styling elsewhere must remain unchanged. No additional diagnostics correctness findings were reported.

Founder continuation disposition (2026-09-24): continue development and complete the slice. Apply the scoped mobile wrapping correction as part of finishing this slice; this introduces no new state-model or permission choice. Recheck the previously failing 390px case before publication.

Pre-disposition evidence: six diagnostics regression cases added; four failed before implementation. Afterwards, 19 focused tests and all 1,565 tests across 131 files passed, as did TypeScript and Vite build (existing large-chunk warning). Browser verified reported degradation, revoked diagnostic suppression, independent demoted-peer note, partial gateway/subnet failure and configuration retry with synthetic data.

Post-fix evidence: the same long diagnosis now produces 390px document width at a 390px viewport. Independent re-review found no actionable findings; shared badge styling is unchanged. Final affected 19 tests, TypeScript and production build pass. Full 1,565-test run above predates only the scoped CSS-class correction. Founder prioritizes desktop functionality; no further mobile polish is part of this increment. User visual acceptance and authenticated/live-network proof remain separate.

## Fifth increment — reported organization transit hubs

Continue approved read-only WireGuard visibility with the existing member-readable `GET /api/v1/organizations/{orgId}/hub-set`. Fetch alongside the selected pair's node and subnet reads; keep organization/user/pair/retry cancellation and selected-only subnet scope. Use the served primary/standby roles, never elect or infer hubs from gateway names or `is_site_hub` flags. No new persistence, mutation, permission or connection semantics.

Show an organization-wide transit-hub section below the two site cards. Distinguish a failed hub read from a successfully empty hub set and retain other successfully loaded facts. Unknown gateway details retain the served role and node ID with an explicit unavailable explanation. A known revoked gateway must retain the revoked label even if the served hub set still names it. Do not turn missing node details into a removed hub, absence of a persisted set into no topology, or reported roles into a healthy/verified pair path. Existing site links remain the configuration destination. Do not draw inferred pair arrows or reuse a positive linked-state diagram here.

Acceptance: served roles/identities, empty success, hub failure and retry, missing node details, revoked node, and stale organization/pair/user responses. Desktop synthetic preview plus typecheck, focused/full web tests, production build and independent review. No additional mobile-specific work; Founder prioritized desktop users. Authenticated application and live traffic evidence remain outstanding.

Fifth increment evidence: eight added regression cases plus an extended user-switch test produced 9 failures before implementation; all 27 focused tests pass after implementation. Full web suite passes 1,573 tests across 131 files, TypeScript passes, and Vite build passes with the existing large-chunk warning. Independent static review found no actionable findings. Desktop browser verified primary/standby roles, hub-read failure with site ranges retained, configuration retry, empty set, unresolved full node identity and revoked standby. Preview is explicitly synthetic; it does not establish runtime convergence, failover or end-to-end traffic.

## Authenticated local control-plane review — 2026-09-24

Founder requested a running local CP for ongoing UI review. Started isolated project `tunnexs2scp0924` in Docker context `colima-f10-dev`, using cached PostgreSQL 16 and Redis 7 with their own new volumes/network. Existing `tunnex` and `tunnexs205resume0902` services/data were preserved. Dependency ports bind loopback only (54925/63925); the current feature API listens at loopback 8080/8443/19109, and existing Vite 5198 proxies its real API.

Every DB-capable startup command verified project/container/network labels and loopback ports. Explicit migration reached version 157, dirty=false. Repository demo seed plus fixtures ran only after checking the two expected demo organization IDs; fixture counts include four sites and six subnets. Local settings, secrets, logs and guard launcher remain outside Git under `/private/tmp/s2s-local-cp/`. No gateway agent was started and no cloud resource was provisioned.

API `/healthz` returned OK, and Vite-proxied `/api/v1/meta` returned Community/open with setup complete. Signed in through the actual browser UI using the repository's demo owner and opened `/site-to-site`. Verified four site links, selected `us-east-dc` and `eu-lan`, and saw scoped gateways, approved and pending ranges, and primary/standby transit roles from real API responses. The browser is left on this authenticated page with the pair selected. This closes the authenticated local application check; the database contains synthetic fixtures, so live tunnel/traffic/HA evidence remains outstanding. IPsec still correctly reads “Not available yet”.

## Local UX refinement — 2026-09-24

Founder identified the separate Sites and Site-to-site menu entries as confusing, then required the existing app theme and less text with more direct interaction. This supersedes the initial separate-navigation presentation, without changing site ownership or networking behavior.

One sidebar entry, Site-to-site, now contains Networks (`/sites`, existing inventory/topology/management) and Connectivity (`/site-to-site`, pair review). Existing site/gateway/query-string links remain intact; both routes, including the connectivity trailing-slash form, highlight the same sidebar destination. The old site count is omitted from that destination so it cannot be mistaken for a count of connections. Command search has the same single destination.

Connectivity now leads with the two selectors. Selection loads the existing scoped configuration reads; Swap changes their order and Reset clears the review. These controls create no connections and make no writes. Removed the duplicated inventory and long method cards, reduced explanation, and put three setup steps behind a native collapsed Setup guide. IPsec remains a short unavailable status. Existing theme tokens, cards, buttons, typography and tab classes are reused; no theme or global stylesheet changed.

Focused behavior tests cover navigation/current state, existing site wiring, selection withdrawal, swap/reset and stale responses. Final web suite passes 1,587 tests across 133 files, TypeScript and production build pass (existing chunk warning). Browser inspection confirms the real local CP renders both tabs with the original theme; pair selection, Swap, Reset and Setup guide were exercised. User visual acceptance remains separate from these checks. Changes remain local under Founder's new no-push instruction.
