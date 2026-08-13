# WF-B — site-link health: name the peer + subordinate the demoted-dead link — commit-one

**Origin:** EPIC 8 smooth walk (2026-07-23, Test A) + the Deck-B rematch finding-2 + the Deck-D
harvest item (badge-names-which-peer). During a live failover, azure-gw showed a bare
**"site link down"** while transit was healthy via the promoted hub — the badge flagged the DEAD
DEMOTED aws-gw-1 keepalive peer as if the SITE were down, and never named which peer. Two truths
were collapsed into one misleading headline. **ONE paper** (founder-ruled): the naming half and
the subordination half share the SAME CP-side per-peer computation — splitting them ships the
data-model change twice.

## Current state (cited)

- `siteLinkDown := caps.SiteLinkStale` (`apps/api/internal/nodes/service.go:1364`) — an
  AGENT-REPORTED BOOL. Carries NO peer identity, NO demoted-flag. It is a THIRD freshness signal,
  independent of the failover controller's.
- The failover controller ALREADY derives per-member liveness: `latestByPubKey(ListNodePeer
  StatusForOrg)` (spoke-observed handshake freshness) ⋂ `deriveActive(configured, demoted)`
  (hub-set membership / who's demoted) — `apps/api/internal/nodes/failover.go` (failoverOrg +
  Step). This is the ONE liveness truth.
- Health kind: `KindSiteLinkDown` ranked as a site HEADLINE, above the policy apply/desync kinds
  (`apps/api/internal/nodes/policyhealth.go:148-150`, transitionTable :119).
- Web badge: bare "site link down" / danger tone (`apps/web/src/lib/healthview.ts:33-34`),
  rendered on the site card (`apps/web/src/lib/sitesview.ts`).

## D-WFB-1 (LEAD — founder-RULED) — the per-peer liveness SOURCE

**RULED (founder, strong prior): WF-B's per-peer health MUST consume the failover controller's
EXISTING liveness derivation (spoke-observed freshness ⋂ hub-set membership — the one-truth
census the controller already reads). It must NEVER compute a third freshness.** A health badge
disagreeing with the controller about who is stale is the two-truths class at the worst seam
(the failover surface). The agent-reported `caps.SiteLinkStale` bool is retired as the site-link
health source, OR demoted to a corroborating-only signal — the AUTHORITATIVE per-peer verdict is
the controller's.

Sub-item (the HOW) — **RULED (founder): (a) shared PURE function.** The controller AND the health
surface both call the ONE derivation (spoke-observed freshness ⋂ hub-set membership) at their own
read moments — NO persisted verdict (that would make the badge as stale as the tick interval AND
add a second writer to org_hub_set's territory — the writer-partition law forbids it). A pure
function called twice can't disagree with itself — the whole point of the lead ruling.
**CONDITION:** the function is the SAME SYMBOL both call — NOT two functions with a "MUST match"
comment claiming equivalence (that comment class died in the S8.6 reduce; do not resurrect it).
**GREP-RED:** no freshness computation exists outside the shared function.

## D-WFB-1b (surfaced at slice-1 handoff) — the agent bool's disposition

Slice 2 replaces `caps.SiteLinkStale` (the AGENT's own view of "my site-link is stale") with the
CP-derived per-peer verdict. A field that is reported-but-no-longer-consumed is the DORMANT-DATA
cousin of dormant machinery — the reviewer WILL ask what becomes of it. **RULED (founder lean):
the CP derivation REPLACES it as the one truth** — the agent bool is structurally weaker (it
cannot name peers, cannot know demotion). Disposition: RETIRE the field from consumption; either
drop it from the capabilities payload OR mark it **vestigial-until-agent-vN** with a one-line
comment at its read site (so a future agent-side use is a deliberate re-adoption, not a silent
resurrection). State the chosen form in the slice-2 build; a bool left reported-but-dead is a
finding.

## D-WFB-2 (RULED) — the data-model change

`SiteLinkDown bool` → must carry the DOWN-PEER IDENTITY + a DEMOTED flag, threaded
`KindInput` → the API health payload (OpenAPI codegen) → the web badge. Decide the wire shape:
- **(a)** a structured `site_link_status` sub-object: `{ down_peer_name, down_peer_demoted,
  transit_healthy }` — explicit, extensible.
- **(b)** flat fields on the existing health payload: `site_link_down_peer` (string, "" = none) +
  `site_link_down_peer_demoted` (bool).
**RULED (founder): (b) flat fields.** The structured sub-object is speculative generality for a
payload with exactly ONE consumer (the badge render); if a second consumer ever needs structure,
that refactor is mechanical. Flat fields keep the codegen diff minimal + the render-floor mapping
obvious. The render CITES the fields it consumes (render-floor law).

## D-WFB-3 (RULED) — subordination precedence

**RULED (founder), stated as a PRINCIPLE for the paper: a link's health ranks by its CONSEQUENCE
for the site's transit.** A demoted member's dead link has ZERO transit consequence (traffic
rides the active primary — the walk proved it at 0% loss), so it renders as a named line item
BELOW a healthy headline. An active primary's link failure has TOTAL consequence and IS the
headline. `degradedKind` (policyhealth.go) drops a DEMOTED-member-only link-down below
`KindHealthy` for the site headline; a non-demoted (active-primary) link-down STAYS the headline.
**BOTH cases are reds** (see Reds 1 + 3): the walk's exact state AND the inverse. The inverse
matters as much — subordination must NEVER accidentally bury a real transit failure, which would
be the reassuring-green class rebuilt at the precedence tier. Honest-by-design disposition from
Deck-B finding-2, with the legibility fix it was owed.

## D-WFB-4 (RULED direction) — naming

The badge names the specific peer: **"site link down: aws-gw-1 (demoted)"** not a bare
site-level alarm. The Deck-D harvest item (badge-names-which-peer) folds in here — SAME render,
one fix. The `(demoted)` qualifier is the disambiguator that tells the operator "expected, this
is the failed-over-past member" vs "a live peer's link is actually down."

## Reds

1. **ACCEPTANCE (the walk's exact state):** promotion-in-effect + demoted-dead peer → the site
   shows a **transit-healthy headline** AND a **named-peer-down line item** ("aws-gw-1 (demoted)"),
   both truths DISTINCT and both TRUE.
2. **One-truth (the two-truths red):** the badge's "who is stale" == the failover controller's
   verdict for the same org/tick — they can NEVER disagree (D-WFB-1). A test drives a state where
   the retired agent-bool would have said otherwise and asserts the badge follows the controller.
3. **A real failure is NOT subordinated:** the ACTIVE primary's link dead (not a demoted member) →
   the site headline still reads site-link-down (D-WFB-3's guard).
4. **Naming:** the badge text carries the specific peer name + the demoted qualifier (D-WFB-4).
5. **Fixture fidelity:** the health test-double must not out-capability the substrate (the S8.2
   law) — it carries the same per-peer freshness + membership shape the controller reads.

## Review fold F1+F2 (2026-07-23) — SILENCE YIELDS NOTHING (the class)

The health-surface review caught the inverse-red's principle ("no witness → no verdict") being
UNDER-applied: it guarded the HEADLINE but not the SUBORDINATE. A subordinate note asserts
"transit is fine, only this dead demoted link is down" — and an UNOBSERVED primary is exactly the
state where we cannot assert transit is fine. A reassuring subordinate on primary-silence is the
reassuring-green class rebuilt ONE TIER DOWN. **CLASS (paper it): silence yields nothing — no
headline, no subordinate, no reassurance.** Fixed at `siteLinkVerdictFrom` (guard: primary
unobserved → (false, Nil) before the demoted loop); the silence red now asserts the FULL tuple +
carries the exact combo (unobserved primary WHILE a demoted member stale). F2's lesson: a red that
asserts only half the return value cannot fail on the other half — assert the whole tuple. Fold
`3a19e00`, re-review waived (guard + red, not feature-sized).

## Reds — RULED addition to #3 (the inverse)

3 (as stated) + **3-inverse: active-primary-stale → the site headline IS degraded (site-link-down).**
Subordination must never bury a real transit failure — the reassuring-green class at the
precedence tier. This red carries equal weight to the walk's case.

**Sequence (RULED — WF-B builds FIRST, then WF-A):** this paper (fully ruled) → build (shared
pure liveness function + KindInput flat fields + API/codegen + web badge) → gates → targeted
review on the health surface (S7.4b/S8.2 most-reviewed class, UNDISCOUNTED) → [WF-C characterize
rides the gap, read-only] → WF-A build → its review → the COMBINED box-walk: ONE hub-kill, TWO
acceptances — WF-B's badge shows transit-healthy + named-demoted-peer WHILE WF-A's device
re-homes on the stopwatch. Own story, not a hotfix.
