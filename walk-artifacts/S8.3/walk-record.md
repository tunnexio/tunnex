# S8.3 site-management UI — box-walk RECORD (live, founder-present, Pawan drove)

**Env:** enterprise stack + the S8.2 multi-site topology on `ubuntu@Tunnex-dev-vm`, SPA served by nginx (port 80), browsed via SSH tunnel `localhost:8888`. Branch `story/S8.3-site-ui` @ post-fold HEAD. Org: Demo Organization (owner + member seeded). Topology on screen: **HQ**/demo-gateway (keyless seed → `health unknown`), **Branch** (no gateway), **site-a**/gw-a, **site-b** (no gateway), **site-hub**/demo-gw (**HUB**, `site link down`), **site-c**/gw-d (**agent too old**).

**Nature:** render-truth walk — every badge/count/list traced to its wire source (D6). 7/8 legs proven LIVE, Leg 6 a named substitute.

| # | leg | result | evidence |
|---|---|---|---|
| 1 | topology render-truth | **PASS** | `leg1-topology.png` |
| 2 | member read-only (D5, review #2 fold) | **PASS** | `leg2-member-readonly.png` |
| 3 | `site_link_down` badge (Slice-1 enum fold, live) | **PASS** | `leg1-topology.png` (demo-gw) |
| 4 | approve → audit | **PASS** | `leg4-both-pending.png`, `leg4-approve-audit.png` |
| 5 | refusal verbatim (D3) → audit | **PASS** | `leg5-refusal-verbatim.png` |
| 6 | CW crossing confirm | **SUBSTITUTE** | `leg1-topology.png` (gw-d "agent too old") |
| 7 | delete name-typed + present-tense preview + real-count audit (D4) | **PASS** | `leg7-delete-cascade.png` |
| 8 | Access polish — summary line + fieldset panels | **PASS** | `leg8-access-summary.png`, `leg8-addrule-panels.png` |

## Per-leg observed

- **Leg 1 — PASS.** 6 site cards; gateway rendered as a **list row** (list-of-one, CH held); **HUB** badge on **demo-gw only** (backend `is_site_hub`); healthy gw-a no badge; subnets show real status (`10.1.0.0/24` approved grey vs Branch `10.20.0.0/24 · pending` amber); `0.1.0 · policy v5` on demo-gw; gateway-less sites STATED ("No gateway bound"), not hidden; "Register site" + pending queue visible (owner). Every element traced to a wire field, no decorative telemetry.
- **Leg 2 — PASS (review #2 fold LIVE).** As `member@demo`, the topology **renders** (member reads via `org:view` — a 403/retry here would be the pre-fold bug), and **every mutation affordance is ABSENT**: no "Register site", **no pending-approval queue**, no Advertise/Bind/Unbind/Delete. Exactly D5.
- **Leg 3 — PASS (Slice-1 enum fold LIVE).** `demo-gw` renders **"site link down"** (`site_link_down`) — the S8.2 kind that previously fell through to "degraded". Surviving API → TS union → badge. (Also live: `desync_unknown` "health unknown" on the keyless seed node — absence rendered honestly.)
- **Leg 4 — PASS.** Advertised `10.60.0.0/24` on Branch → appeared pending → **Approve** → flipped approved; **audit** `site.subnet_approved · {"cidr":"10.60.0.0/24"}`. Via the audited endpoint.
- **Leg 5 — PASS.** Approving Branch's `10.20.0.0/24` (collides with HQ's approved `10.20.0.0/24`) → the UI rendered the API message **verbatim**: *"this subnet overlaps the site_subnet range 10.20.0.0/24; approval refused"* — class + colliding range from the server, no client re-check; subnet **stayed pending**. Audit `site.subnet_approval_refused · {"overlap_class":"site_subnet","overlaps":"10.20.0.0/24"}` (outcome-not-error).
- **Leg 6 — SUBSTITUTE.** The CW v5-crossing confirm fires only at the single→multi-site crossing, which the box passed org-wide long ago (no un-approve endpoint to reset without teardown). **Proven instead:** the live CONSEQUENCE — `gw-d` renders **"agent too old"** (`unsupported_policy_version`, the v4 gateway refusing v5, deny-all) — plus the crossing-gate + naming logic unit-proven (`crossesMultiSiteThreshold` 4 ordering reds; `subCeilingGateways` absence-below; ceiling from `meta.protocol_version`). **NAMED SUBSTITUTE — trigger = the EPIC-8-close founder walk after S8.5** (its fresh-org journey register → first site → second site fires the CW confirm live as a natural leg; the substitute discharges THERE).
- **Leg 7 — PASS.** Delete-"site-a" modal: **present-tense** cascade preview *"…cascades what currently references it: **1** rule and **1** subnet; the gateway is unbound"* (real counts — the site→site rule + `10.1.0.0/24`); **"Type the site name to confirm"** with **Delete site greyed/dead** until exact match (cancelled — topology preserved). Earlier `site.deleted · {"rules_deleted":0,"subnets_released":1}` audit confirms the path records ACTUAL cascade counts.
- **Leg 8 — PASS.** Access summary line **"1 rule — default-deny active."** (enforcing+N copy); rule row renders the site→site grant with **site labels**; the Add-rule modal shows **SOURCE** and **DESTINATION** as two labeled bordered **fieldset panels** (the layout fold). No behavior change to create/edit.

## Walk-found (founder-found, ledgered — does not block)
- **Stale Add-rule button after group-add:** adding a group in "Groups & resources" doesn't re-enable the Rules section's Add-rule button (gated on `groups.length===0`) until a page refresh — a **pre-existing** cross-section staleness (separate components, separate `groups` state loaded on mount; S7.4a structure, NOT an S8.3 change). Ledgered to ride **S8.5 or the epic-close fold, whichever lands first** (founder-walk finds don't age). A fix lifts `groups` to the parent / fires a RulesSection reload on group-add — a refactor of the proven Access page, deliberately not folded mid-walk.

## Verdict
**S8.3 site-management UI PROVEN on the live wire.** 7/8 legs PASS (topology render-truth · member read-only · `site_link_down` badge · approve+audit · refusal verbatim · delete name-typed+cascade+real-count audit · Access polish); the two review folds proven live (#2 member-read-only via `org:view`; the Slice-1 enum path surviving all layers). Leg 6 a named substitute (trigger = epic-close walk after S8.5). One pre-existing UX papercut ledgered. Every on-screen badge/count/list traced to its wire source — the render-floor law held.
