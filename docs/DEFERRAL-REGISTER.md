# THE DEFERRAL REGISTER — one line per deferral, each with a NAMED TRIGGER.

**Split out of `docs/CUT-REGISTER.md` on 2026-08-02, founder-ordered, on that file's own founding rationale:
a register works because a grep is cheap, and it stops working when it holds two different questions.**

> ## **A CUT ANSWERS "IS THIS IN SCOPE?". A DEFERRAL ANSWERS "WHEN DOES THIS HAPPEN?".**
> ## **A DEFERRAL WITHOUT A TRIGGER IS NOT DEFERRED. IT IS DROPPED, SLOWLY.**

**HOW TO USE IT:** `grep -i '<name>' docs/DEFERRAL-REGISTER.md` before assuming something is unbuilt by
choice. **HOW TO ADD:** the deferral, its trigger, why it is deferred, **where it was FOUND, and whether it
has been REVIEWED.** Provenance is part of the entry — an item whose origin nobody can name gets re-litigated
from scratch.

---

| deferral | trigger | why deferred | **found where** | **reviewed?** |
|---|---|---|---|---|
| **`site_id` on `RoutedRange`** | **an org crosses ~50 sites**, OR any story that revisits what `/routed-ranges` may carry | `/routed-ranges` is a **device-facing projection** — *ranges only, no keys, endpoints, pool or policy*. Adding an org-structure field needs a decision about whether a DEVICE should learn site topology, which is not a screen's call. Until then attribution is a per-visit fan-out | S14.7 commit-one, endpoint census | **NO** — paper only, not yet reviewed |
| **The ~50-site fan-out tripwire** (Routed Ranges `SITE` column) | **51 requests / ~9 waves at 6-per-origin.** Fires when an org's site count approaches 50 | The fan-out is correct and cheap at realistic N. It is recorded as a **THRESHOLD, not a limit**, so the next reader inherits the number instead of rediscovering it at a customer | S14.7 commit-one, after the founder asked what happens at 50 | **NO** — paper only |
| **`Modal` has no Escape / focus-trap / initial-focus / focus-return** | the next slice that touches `Modal`, or S14.8 | shared primitive, 20 call sites, and it DECLARES `aria-modal="true"` while implementing none of it | S14.5, founder-ordered measurement after I reported only *"no Escape"* from a single grep. All four behaviours then measured | **NO — REGISTERED, NEVER REVIEWED.** Not fixed, not looked at on a screen |
| **`site_link_down` is an org-level headline printed per row** | the next control-plane story touching site-link health | suppressing a server-owned verdict client-side is the one-truth violation already swept off Sites | S14.5 Sites map (N=1, meaningless), evidence upgraded S14.6 Gateways (N=6, four rows incl. the hub) | **Founder SAW it** on both screens and ruled *register, do not resolve* — the DEFECT is reviewed, the FIX is unruled |
| **The peer/device count column** (Gateways) | its own slice | spec + codegen ×3 + drift guard + both editions + query-lint + sqlc | S14.6 commit-one; founder corrected my "one cheap query" estimate | **Founder ruled it its own slice.** Scope reviewed, not built |
| **`Histogram` has no shipping consumer** | EPIC 14 close | Access Events moved REDESIGN → BUILD, so the clock got LONGER — which is how a deferral becomes permanent | S14.3 build (named Access Events as consumer); flagged S14.5 when the nav audit moved Access Events REDESIGN → BUILD | **NO** — never reviewed; the component exists only in the gallery |
| **Access screen's em-dashes** | the Access section pass | **MEASURED S14.7:** `policyview.ts:436` *"Rule status unavailable — refresh."* and `:442` *"Policy not enforced — open mesh."*, both asserted in `accesswiring.test.tsx:103,144`. **Those two assertions WILL break when that section clears its em-dashes — known in advance rather than discovered** | S14.7, censusing the em-dash blast radius across the component tier | **NO** — measured, not looked at |
| **Overview layout reflow (10th card leaves System Health alone on row 4)** | **the next Overview-touching slice, or EPIC 14 close, whichever is first** | Layout regression on a MERGED, founder-approved screen — 9 panels filled 3 exact rows; the 10th leaves System Health alone on the last row. Measured after founder acceptance (never accepted, only reported). Fix is 1 line: Kubernetes card goes last. Visual leg is advisory & Overview baselines dropped at viewport leg so nothing notices. 390 behavior UNMEASURED (checked at lg only). **That is now three Overview defects held in prose alone (65px header overflow, Menu button over <h1>, 10th card reflow), with no artifact behind any of them — that sentence is the finding, not the individual items.** | S14.8 Kubernetes card reflow measurement | **Founder-ruled, deliberately deferred.** Measured post-acceptance, registered not fixed. |
| **Global em-dash sweep & CI lint rule** | **EPIC 14 close or dedicated polish sweep** | The per-section obligation "each section clears its own em-dashes" proved decorative in practice (163→19 burn-down occurred in S14.6 global sweep while per-screen passes preserved them for test assertions). Discharged by a final global sweep clearing remaining 19 em-dashes alongside an ESLint/CI regression rule preventing re-introduction | S14.10 audit finding | **REGISTERED** — per-section rule acknowledged decorative |
| **Device fabric graph** (online / idle / blocked node graph) | **its own slice** | Center node's "1000 peers" count is blocked on the exact same gap that made PEERS its own slice at S14.6 (DB `devices WHERE node_id` count vs gateway WireGuard peer graph). Requires a dedicated peer graph query + codegen slice | S14.10 element extraction | **REGISTERED** — deferred to its own slice |
| **`TUNNEL` column (`split` / `full`) on Devices table** | **its own slice / spec update** | `full_tunnel` exists on `CreateDeviceRequest` but is **NOT emitted on the `Device` response schema** in `openapi.yaml`. Displaying tunnel mode on list items requires spec + codegen + SQL select update | S14.10 element extraction | **REGISTERED** — absent endpoint schema field |

---

## ⛔ THE "`ON CONFLICT … DO NOTHING` ON A TIME-RELATIVE FIXTURE" CLASS — its own line, because it made every device freshness state false

> ### **A FIXTURE FOR A LIVE SYSTEM WRITES `now() - interval '3 minutes'`. THAT IS THREE MINUTES AGO ONCE,**
> ### **AND THEN AGES FOREVER. WITH `DO NOTHING`, EVERY RE-SEED REPORTS SUCCESS AND CHANGES NOTHING.**

**S14.10. Two tables, both silent, and the consequence was total:**

| table | what aged | what the screen showed |
|---|---|---|
| `device_health` | `reported_at` drifted past `HealthStaleTTL` (30 min) | `health_state: unknown` for devices seeded as compliant/noncompliant, **and the sweep correctly cleared `health_blocked`** — so the device named `blocked-device` was not blocked |
| `device_status` | `last_handshake_at` | every device drifted OFFLINE |

**SO ANY SECTION REVIEWED AGAINST A RE-SEEDED STACK SAW STALE TIMESTAMPS AND NOBODY KNEW.** The seed exited 0
every time.

**⛔ AND THE FIX ALREADY EXISTED IN THE SAME FILE, THREE SECTIONS EARLIER.** `node_peer_status` was converted to
`DO UPDATE` for gateway liveness, carrying the reason verbatim:

> *"A DEMO FIXTURE FOR A LIVE SYSTEM HAS TO BE RE-RUNNABLE INTO FRESHNESS."*

**Device posture and device liveness are that same problem under different names, and never got the treatment.**
A law written down in one block does not protect the block below it.

**FIXED:** both now `DO UPDATE`. **THE STANDING CHECK:** any fixture row whose value is relative to `now()` is
`DO UPDATE`, never `DO NOTHING` — and the test is not "is it idempotent" but **"is it re-runnable INTO the state
it describes."**

---

## ⛔ THE "FIXTURE WRITES A CONTROLLER-OWNED FIELD" CLASS — two instances

> ### **SEED THE INPUTS A CONTROLLER CONSUMES, NEVER THE FIELD IT OWNS. THE RECONCILE LOOP SILENTLY UNDOES**
> ### **THE WRITE, AND THE ROW READS AS APPLIED.**

| # | field | owner | what happened |
|---|---|---|---|
| 1 | `org_hub_set.demoted` | the failover controller (`UpsertOrgHubSetDemoted`) | the fixture declared a demotion; the controller recomputes it every tick. **Seeding it also exposed a permanent wedge** (nil slice → SQL NULL → 23502 forever) |
| 2 | `devices.health_blocked` | the posture evaluator (`ReportHealth`) | the fixture set it `true`; the stale-block sweep cleared it. **`SweepStaleHealthBlocks` can only ever set it FALSE** |

**INSTANCE 2 CARRIES A HARDER CONSEQUENCE: THE INPUT IS AN HTTP REQUEST, NOT A ROW.** `SetDeviceHealthBlocked`
is called from exactly one place, `ReportHealth`, so **no SQL can produce a blocked device.** The seeder now
**registers it through the product** — logs in as the demo owner, POSTs a failing report for one fixed device id
— and counts the **server's own `blocked` verdict** into its census. Same pattern as the k3s cluster.

**REACHABILITY COST, STATED:** the seeder now needs the API up at seed time. Absence is detectable three ways —
a counted `posture_blocked: false` census field, a warning naming the consequence, and `TUNNEX_SEED_STRICT=true`
for a non-zero exit (proven to reject). `seed-fixtures` is **never run in CI** (0 references in either
workflow), so this is a local-stack concern only.

**THE SWEEP:** `fixtures.sql` was read for other controller-owned writes — see the row below.

### THE `fixtures.sql` SWEEP — every write read, three candidates, one latent instance

All 36 writes enumerated. Nine distinct `SET` columns; six are admin-owned (`dns_forwarding`, `hub_priority`,
`ovpn_enabled`, `provisioning_mode`, `revoked_at`, `site_id`) and are safe to seed. **Three are AGENT-written:**

| column | verdict |
|---|---|
| `nodes.capabilities` | ⛔ **INSTANCE 3, LATENT.** The fixture injects `ovpn_health` via `capabilities \|\| '{…}'`. The control plane REBUILDS this column server-side from the agent's typed report on every reconcile. **Measured: the injection survives ONLY because no agent reports as `gw-eu-west`** — `gw-local-1`, which a live agent does report as, carries a server-built `policy_version` and would have the injection overwritten. **One enrolment change from silent loss, with no signal.** |
| `nodes.last_seen_at` | same dependency, benign: the fixture ages `gw-ap-south` deliberately and it stays aged only because no agent reports as it |
| `nodes.endpoint` | written at enrolment, not on a loop — safe |

**NOT FIXED, REGISTERED.** The honest fix mirrors instance 2 — have the agent report `ovpn_health`, or accept
the injection with its dependency stated. **TRIGGER: the next change to which node the compose agent enrols as,
or any slice that needs a SECOND faulting OpenVPN gateway.**

---

## S14.10 DEFERRALS

| deferral | trigger | why deferred | found where | reviewed? |
|---|---|---|---|---|
| **TX/RX columns** (Devices) | **S11.1**, where throughput gets an endpoint | `rx_bytes`/`tx_bytes` are raw gauges since the last handshake — they RESET on re-handshake, so a rate or total would look like throughput and not be throughput. **The same split as Site-Link Traffic**: numbers now, rates when there is a series | S14.10 classification | founder-ruled, not built |
| **Device approval-mode toggle** | **the endpoints existing** | ⛔ `getDeviceApprovalMode` / `setDeviceApprovalMode` are **NOT IN THE SPEC** — measured. The panel was classified as five served endpoints and is THREE (`listPendingDevices`, `approveDevice`, `rejectDevice`). The org-level half is **BUILD + BACKEND, like Operations** | S14.10 scope census | ruled deferred |
| **Device Approval panel** → **S14.10b** | its own commit-one | `rejectDevice` is destructive and irreversible: `pending → revoked, assigned_ip = NULL`, freeing the tunnel address. **A mutation surface with a confirm step, not a column** — folding it into a layout pass is how a confirm dialog gets reviewed as a div. **AND it makes the Modal a11y deferral LIVE** (Escape / focus trap / initial focus / focus return — paper-only, never reviewed) | S14.10 scope question | founder-approved split |
| ~~Served `health_stale` discriminator~~ **MOOT — closed, not deferred** | — | Registered when `unknown` was believed to have THREE causes needing a server-side discriminator. **The third cause cannot occur** (see the spec-defect row), so `unknown` means only no-report or stale, and `health_reported_at` alone separates them. **Nothing is being reconstructed, so there is nothing for the server to say.** Rewritten rather than left standing: a deferral for a problem that no longer exists is a future reader's wasted slice | S14.10 item 1, closed same section | n/a |
| **S7.4c shared-DB leakage** ⚠ **UPDATED** | ⛔ **now** — it has moved an order of magnitude | Registered at `real_orgs=29`, **never revisited. MEASURED TODAY: 298.** All created 2026-08-02, all Go integration-test debris — single-letter names (`O` ×153, `S` ×51, `K` ×44), `MFA Org` ×33, and slug prefixes `wd-` (21 — my own wedge test), `gf-`, `k8s`, `mfa`, `pos`. **CAUSE: runs that PANIC skip `t.Cleanup`**, and this session produced several (the nil-map false red). **CONSEQUENCE: `seed-fixtures` refuses on `realOrgs > 0`, so the review stack now needs `TUNNEX_SEED_FORCE=true` — the guard has been turned into a formality by debris** | S14.10, seeding for review | measured, not cleaned |

---

## ⛔ THE S14.6 FIXTURE DEBT IS STRUCTURAL, NOT AN OVERSIGHT — two of its three states are CONTROLLER-OWNED

**Founder-connected, and it explains why the debt survived two sections.** The S14.6 debt names three states:

| state | field | owner |
|---|---|---|
| `ovpn_enabled: true` | `organizations.ovpn_enabled` | **admin** — seedable, and seeded |
| one OpenVPN fault kind | `nodes.capabilities → ovpn_health` | ⛔ **the agent's report.** Instance 3 of the controller-owned class — LATENT-FRAGILE, surviving only because no agent reports as `gw-eu-west` |
| a demoted hub note | `org_hub_set.demoted` | ⛔ **the failover controller.** Instance 1 |

> ### **TWO OF THREE SIT ON FIELDS A RECONCILE LOOP OWNS. THE DEBT WAS NOT FORGOTTEN — IT WAS UNSEEDABLE**
> ### **BY THE MEANS BEING USED, AND EVERY ATTEMPT LOOKED APPLIED.**

**WHAT ACTUALLY DISCHARGES IT — one of two patterns, per state:**

1. **SEED THE INPUTS THE CONTROLLER CONSUMES.** Done for the demoted note: give the members the capability the
   elector requires, leave one stale, and the controller demotes it ITSELF. Derived, not declared.
2. **REGISTER THROUGH THE PRODUCT.** Done for `posture_blocked`, which is unreachable from SQL at all — the
   seeder logs in and POSTs a real report, then counts the server's own verdict.

**`ovpn_health` HAS NEITHER YET.** Pattern 1 needs the agent to report it (no seam today); pattern 2 needs an
agent-authenticated status POST. **TRIGGER: the next change to which node the compose agent enrols as, or any
slice needing a second faulting OpenVPN gateway.**

---

## ⛔ SPEC DEFECT — `health_state: unknown` claimed a third cause that CANNOT OCCUR

`openapi.yaml` said `unknown = no report, stale report, **or the fact was reported absent**`. **The third
disjunct is impossible**, measured three ways:

```
device_health.evaluated_state   NOT NULL, CHECK (evaluated_state IN ('compliant','noncompliant'))
healthInfoFor                   reaches `unknown` only when evaluatedState is nil / reportedAt is nil / stale
the evaluator                   if f.DiskEncrypted == nil { continue }   // "absence never blocks"
```

A device that reports and cannot determine the fact has the check **SKIPPED**, evaluates **`compliant`**, and is
stored as `compliant`. It never becomes `unknown`. With a row present, `evaluatedState` is never nil.

**COST: a full build-and-revert of a third UI label**, plus five reds that were green against a state production
cannot produce. **CORRECTED IN PLACE** in `openapi.yaml`, same treatment as the `listSiteSubnets` summary and
the `policy_degraded_kind` paragraph.

**HOW IT WAS CAUGHT:** a reachability assertion on the RENDERED PAGE returned 0 matches. Unit tests passed and
the payload looked right. **A test can pin a label production can never produce; only the screen says otherwise.**

| **Derived enums in the `health_state` blind spot** | next spec defect, or EPIC 14 close | `Device.kind`, `Device.mode`, `Member.status` are PROJECTIONS with no column to compare against, so the spec-enum-vs-CHECK sweep cannot see a defect in them — the same blind spot `health_state` hid in, where the instrument said safe and the field was wrong. **The only check is the description's cause-list against the projecting function. NOT RUN** | S14.10 third-axis sweep | ⛔ unchecked |
| **`real_orgs > 0` is always overridden** | **the S7.4c leakage cleanup** | The guard now requires `TUNNEX_SEED_FORCE=true` on every review-stack seed (298 debris orgs), so **the override is habit and the guard is a prompt.** This is the "configured not to matter" class arriving at the one guard that stopped a wrong-stack write at S14.7. Two fixes: clean the debris, or teach `countRealOrgs` a slug-prefix exclusion — **proposed at S7.4c and never built** | S14.10 seeding | measured, unfixed |

| **Audit Log duplicate React keys** | **the S14.11+ Audit Log section pass** (it is a REDESIGN-bucket screen, so this is its own slice) | Seen in vitest output during S14.10 and **never chased**: `Warning: Encountered two children with the same key, '49'` from `AuditLog.tsx:17` via `DataTable` (`ui.tsx:331`). React's own words: *"Non-unique keys may cause children to be duplicated and/or omitted."* ⛔ **OMITTED IS THE WORRYING HALF — on an AUDIT LOG, a silently dropped row is a missing record of who did what.** The key is likely a sequence/index colliding across pages or a `key` derived from something non-unique. **NOT INVESTIGATED**: which field, whether rows are actually dropped, and whether keyset pagination is involved | S14.10, in test output | ⛔ unchecked |
| **Users & Roles shedding has NO DESTINATION** | **the target screens landing** (`CLI Credentials` and `Edition`, both BUILD) | `Users.tsx` was classified a "shedder": machine credentials → CLI Credentials, edition → Edition. **Both targets are BUILD-bucket and neither exists.** Shedding now removes a WORKING surface with nowhere to go — deliberately recreating the S11 finding (`gateway revoke` existed in the API and never in the UI). **RULE: the surface STAYS until its destination exists**, with this row as the trigger. Ruled in the S14.11 commit-one, never shed by default | founder-corrected, S14.11 open | ruled, not built |

| **Direct-to-`main` pointer pushes bypassing the 3 required checks — RUNNING COUNT: 8** | **EPIC 14 close** | Authorized under **Ruling 2** (a process/docs correction whose value is immediate lands on `main` directly) and **reported every single time** — but ONE PER MERGE is a standing MECHANISM, not an exception, and a mechanism that bypasses `gates` / `client (macos-latest)` / `client (windows-latest)` deserves a decision rather than a habit. **The pointer is docs-only, so the bypass buys ~8 min it would otherwise wait for; the ruling due at epic close is whether this STAYS the mechanism or the pointer MOVES somewhere that needs no bypass at all** (a release note, a generated file, or after the `gates` split makes a docs-only run ~1.7 min and the bypass nearly worthless). ⛔ **The split changes the arithmetic of this row, so rule them together** | ⛔ **THE ACT OF REGISTERING THIS ROW INCREMENTED IT.** The push that recorded the count as SIX *was the seventh* — which is the property that makes this a MECHANISM rather than an exception, and the sharpest single piece of evidence for the EPIC 14 close ruling. (The PR #57 CI merge deliberately took NO pointer push, holding the count at 7.) ⛔ **AND THAT DECISION HAS A COST, RECORDED AS A TRADE RATHER THAN LEFT IMPLICIT.** The pointer was deliberately given BOTH halves — a PR number that survives rebase AND a sha telling a fresh session what `main` is. Skipping the push held the count at 7 **and left the sha half stale: the pointer says `331c96f`, `main` is `832e6b0`.** That is the exact failure that cost a session earlier (`a253e5e` read as head when head was `85081b0`). **So the epic-close ruling has TWO questions, not one:** does the sha half TOLERATE lag between story merges — in which case skipping was right and the row should say so — or does it not, in which case the CI merge needed the push and the bypass is not once per STORY but once per MERGE. **I did not resolve it; I took the smaller count and left the staler pointer.** the push that registered this row as SIX **WAS the seventh** -- the count went stale in the act of writing it, and GitHub printed the bypass verbatim (`Bypassed rule violations ... 3 of 3 required status checks are expected`). Corrected on a branch rather than with another `main` push, which would have made it eight.<br><br>⛔ **S14.11 MADE IT EIGHT.** The S14.11 merge itself was a clean ff-only push to `main` **through** the required checks (`622f30b`, 18 success / 4 skipped / 0 failure on that exact sha). But the pointer carried `PENDING-SHA` inside the PR, and correcting it after the merge took a **ninth**… no: an **eighth** direct push (`b846591`), which GitHub reported verbatim: *"Bypassed rule violations for refs/heads/main: 3 of 3 required status checks are expected."* `enforce_admins=false` is why an admin push succeeds at all.<br><br>**AND THE S14.10 QUESTION THIS ROW POSED NOW HAS DATA.** That row asked whether the sha half tolerates lag between merges. **This merge answers it in a new way: because the merge was a TRUE FAST-FORWARD, the in-PR sha and the post-merge sha were IDENTICAL** — the placeholder was unnecessary, and writing `622f30b` directly into the in-PR checkpoint would have needed **no post-merge push at all**. **That looked like a third option the row never considered — and MEASUREMENT REFUTED IT. Recorded because the refutation is the finding:**

⛔ **THE SEPARATION THE FOUNDER ASKED FOR, MEASURED.** For each of the 8 direct pushes, was the merge a fast-forward or a rebase? Compared each PR's `head.sha` against `merge_commit_sha`:

| PR | head | landed | merge |
|---|---|---|---|
| #49 viewport | `f180d02` | `556cfaf` | REBASE |
| #50 S14.5 | `1b91bcd` | `85081b0` | REBASE |
| #51 S14.6 | `acd806b` | `70e4642` | REBASE |
| #52 S14.7 | `0b0f23c` | `fa877ba` | REBASE |
| #53 S14.8 | `6d4d2ff` | `2e67902` | REBASE |
| #54 S14.9 | `96c253b` | `0cda482` | REBASE |
| #56 S14.10 | `ada8784` | `331c96f` | REBASE |
| #58 S14.11 | `622f30b` | `622f30b` | **FAST-FORWARD** |

**7 of 8 rebase, 1 fast-forward** — and the one fast-forward is this story.

⛔ **THEN I TESTED MY OWN CLAIM ON THAT ONE CASE AND IT FAILED.** The S14.11 branch was `9de9406` → `2f12e89` (the PLAN commit) → `622f30b` (laws). main's head after the ff-merge is `622f30b`. For the PLAN commit to have named it, it would have to be written after the commit that follows it — and if the PLAN commit were LAST, it would BE main's head and would have to contain its own hash.

> ## **A COMMIT CANNOT CONTAIN ITS OWN HASH. THE POST-MERGE HEAD SHA IS NOT KNOWABLE BEFORE THE MERGE —**
> ## **for a fast-forward exactly as much as for a rebase. ALL 8 BYPASSES WERE FORCED. ZERO WERE AVOIDABLE.**

**SO THE EPIC-CLOSE RULING IS NOT "ff vs rebase" — IT IS A CHOICE BETWEEN TWO POINTER DEFINITIONS, and only one of them can ever avoid a bypass:**

| the pointer names | knowable pre-merge? | bypass needed |
|---|---|---|
| **`main`'s head sha** (today's rule) | **never** — self-reference | **every merge, forever** |
| **the CONTENT tip** — the last non-pointer commit (`9de9406` here) | **yes** | **never** |

The content tip identifies the merge unambiguously and is one commit behind `main`'s literal head. **That is the actual ruling: does a fresh session need `main`'s literal head, or an unambiguous identifier for the last story merge?** If the latter, the count stops at 8 permanently. | S14.5 to S14.11, one per merge |

| **⛔ THE INVITATION WORKFLOW GAP — a capability reachable in the API and dead in the UI after step one** | **the backend story, if one is cut for this epic — this is the STRONGEST candidate** | Four operations exist and **none of them reads**: `acceptInvitation`, `createInvitation`, `resendInvitation`, `revokeInvitation` (measured at the handlers, not the summaries). `resend` and `revoke` both take **`EmailRequest`** — an email the admin **cannot look up**. So an admin sends an invite and then **has no surface on which that invite exists.** ⛔ **NOT a missing roster column — a BROKEN WORKFLOW.** This is the S11 class (`gateway revoke` existed in the API and never in the UI) **with an extra turn**: the first step IS reachable, which makes the dead end worse because the admin has already acted. **One read endpoint (`listInvitations`) turns three orphaned writes into a workflow** | S14.11 extraction | measured, unbuilt |
| **Machine credentials stay on Users & Roles** | **`CLI Credentials` (BUILD) existing** | The shedding target does not exist. Moving it now removes a WORKING surface with no home — deliberately recreating the S11 finding. **Ruled: it stays until there is somewhere to move it to**, never by default and never because a bucket table said "shedder" | S14.11 commit-one | ruled |
| **Edition surface stays on Users & Roles** | **`Edition` (BUILD) existing** | Same reason, same ruling, separate row so each moves on its own trigger rather than as a pair | S14.11 commit-one | ruled |
| **The tripartite `teamMap` graph (role ↔ user ↔ group)** | **`Groups` (BUILD) landing** | `buildTeamMap()` is THREE columns, not a role hierarchy — `{ roles, users, groups, edges }`. The NODES are served; the EDGES need `listGroupMembers`, which is **`PermPolicyView`** (measured, `policy_handlers.go:129`) — **not `org:view`** — and there is **no per-user reverse lookup**, only per-group. ⛔ **A member viewing the roster is not permitted to see the edges at all**, so this is cut on a PERMISSION BOUNDARY, not a missing field — a different cut from the four column absences and filed separately for that reason | S14.11 extraction | measured |
| **`email_verified` on the roster is an ADDITION over the wireframe** | n/a — shipping in S14.11 | Served, real, and ABSENT FROM THE DESIGN. An unverified member cannot act, and the roster is where an admin looks. **Recorded because additions get the same discipline as cuts:** a silent addition is as hard to audit later as a silent removal, and "the design didn't show it" is the argument that deletes it in six months | S14.11 classification | deliberate |

---

## ⛔ EPIC-LEVEL DEBT DISCOVERED BY S14.11 — EVERY EDITION-GATED RENDER IN THIS EPIC IS UNREVIEWABLE

**Not a Users & Roles cost. Carried silently since S14.1, and this is the FIRST slice where a render decision
depended on it.**

**Edition is a COMPILE-TIME BUILD TAG.** `policyPort` is `nil` in the open binary, so every group handler
returns `403 edition_required`. There is no row to flip: seeing the open-edition side needs a DIFFERENT IMAGE.

> ### **SO THE FOUNDER'S STACK CAN SHOW ONE EDITION AT A TIME, AND MORE EDITION-GATED SCREENS ARE COMING —**
> ### **ACCESS POLICIES, GROUPS, ACCESS EVENTS ARE ALL ENTERPRISE.**

⛔ **AND THE S14.5 HALT WAS AN EDITION DEFECT THAT REACHED A LIVE STACK PRECISELY BECAUSE NOBODY COULD SEE THE
OTHER SIDE** — an upsell shown for a capability the API treated as core. The mechanism that produced it is
still in place.

**RULED (b): a SECOND STACK in open mode** on its own `COMPOSE_PROJECT_NAME`. The `NET` / `SECRETS_VOL`
derivation (fixed S14.7) makes it possible. **IT DOES NOT MAKE IT FREE — the honest cost:**

- a second stack is **a second database**, so it needs **its own `seed-fixtures` pass**
- **minus every enterprise row that would 403 anyway** — and *that subtraction is itself a useful measurement:*
  **what does the open edition's fixture set even look like?** Nobody has asked. `policy_rules`,
  `user_groups`, `group_members`, `access_events` are all enterprise; the open fixture is a different, smaller
  world and no one has seen it
- two stacks means two seeds to keep re-runnable into freshness — and the `DO NOTHING` class already bit once

**TRIGGER: before the next edition-gated section pass** (Access Policies re-touch, Groups, or Access Events),
whichever comes first. **S14.11 ships its open-edition render on a NAMED SUBSTITUTE** — unit-tested three-way
empty state, wire proof deferred to this row.

**S12.1 replaces the build tag with a RUNTIME LICENSE GATE and leads the beta bundle** — at which point this
debt dissolves rather than being paid. That is the argument for a substitute now rather than a permanent
second stack.

| **`sso_configs` IS EMPTY — an unmeasured fixture zero** | **the next slice needing an SSO-dependent state — `Org Settings` (REDESIGN) will hit it** | Measured while settling the AUTH label: **no `sso_configs` row for the demo org.** Consequence is broader than AUTH — the **SSO config UI**, **domain capture** (`createDomainClaim` / `verifyDomainClaim`) and every SSO-dependent state are **unreachable on this stack**. ⛔ **Registered HERE so the next slice finds it rather than discovering it at pre-flight check 2** — which is exactly what cost S14.8 five rounds. Not this slice's work | S14.11 AUTH measurement | measured, unseeded |

| **D1 — the MFA column + `adminResetMfa`'s precondition** | **founder disposition** (paper recommends *both wait*) | `user_totp.confirmed` + `confirmed_at` are **persisted, `NOT NULL`, read by `HasConfirmedTOTP` in the login path** — three fields to project, not a roadmap. The wireframe's `MFA enrolled 5/7` and per-row `TOTP ✓ / Enroll req.` need them. **`Reset 2FA` ships today with its precondition invisible**, which the paper called worse than no action | S14.11 §2.2 | HELD, not built |
| **D1b — the AUTH column** (the twin) | **founder disposition, same breath as D1** — **AND a second, MECHANICAL trigger: see the tripwire row below** | `users.password_hash` makes *has a local password* derivable, but `Member` serves **exactly seven fields** and `additionalProperties: false`. ONE projected boolean. I wrote the view-model FIRST and deleted it under the dormant-machinery law once the payload was measured — **a consumer with no producer** | S14.11 §2.3 | HELD; tripwire armed |

### ⛔ THE D1/D1b TRIPWIRE — WHAT IT IS, WHEN IT FIRES, AND WHAT TO DO, because "satisfy the compiler" is the wrong answer

**WHERE:** `apps/web/test/usersview.test.ts` —

```ts
type UnaccountedMemberField = Exclude<keyof Member,
  "user_id"|"email"|"name"|"role"|"status"|"email_verified"|"joined_at">;
const _memberHasNoAuthField: UnaccountedMemberField extends never ? true : false = true;
```

**FIRES WHEN:** any field is added to `Member` in `openapi/openapi.yaml` — `mfa_confirmed` (D1),
`has_local_password` (D1b), or anything else. `typecheck` goes red with
`Type 'true' is not assignable to type 'false'`. **PROVEN TO FIRE** (baseline 0 errors → one field unaccounted
→ exactly one error at that line → restored → 0).

> ## **⛔ THE WRONG RESPONSE IS TO ADD THE NEW FIELD NAME TO THE `Exclude` LIST AND MOVE ON. That silences the**
> ## **tripwire and ships a projected field NOTHING RENDERS — which is the producer-without-consumer defect**
> ## **this epic has already hit three times.**

**THE WORK TO DO, and it EXISTS — do not reinvent it.** The deleted view-model was:

| deleted symbol | what it did | recover from |
|---|---|---|
| `AuthFact` (type) | `"local-password" \| "no-local-password"` — **two** arms, deliberately not three | commit `d93627b`, `apps/web/src/lib/usersview.ts` |
| `authFact(hasPasswordHash: boolean)` | the pure derivation | same commit |
| `authFactLabel()` | `local password` / `no local password` | same commit |
| its two unit tests | one asserting the label **never matches** `/sso\|entra\|google\|okta\|saml\|oidc/i` | commit `d93627b`, `apps/web/test/usersview.test.ts` |

**AND THE RULING THAT CONSTRAINS THE REBUILD (§2.3, measured, do not re-derive):** the label **STOPS AT THE
FACT**. It must NEVER infer SSO from `sso_configs`, because **237 of 241 users have `password_hash IS NULL` and
the demo org has NO `sso_configs` row** — so *"no password ⇒ SSO"* is disproved by the first org anyone opens.
A user with no password in an org with no provider is **neither**.

**For D1 (MFA) the same discipline applies:** `user_totp.confirmed` is the source; the wireframe's
`MFA enrolled 5/7` is a **number**, and a reader trusts a number more than prose — so it must not be derived
from anything weaker than the confirmed flag.
| **D2 — per-member group edges + the `idp-sync` marker** | **founder disposition**; the paper recommends *cut*, registered against `Groups` landing | Needs `listGroups` **plus `listGroupMembers` PER GROUP** — an N+1, **51 requests at 50 groups** (pre-flight check 1). The panel ships group **access + count from ONE request** instead; the arms (`forbidden` / `edition` / `failed` / `none` / count) are already built and would be reused unchanged | S14.11 §2.4 | HELD; panel ships the 1-request form |

| **`make test-editions` IS RED LOCALLY AGAINST A LIVE-STACK DB — a REQUIRED gate that only passes on a fresh database** | **the next session that runs the gate and cannot tell a real red from this one** — or a CI change that stops provisioning a fresh postgres | **PRE-EXISTING, proven: fails identically at `main` 832e6b0.** One root cause, four packages: the tests share the database with a RUNNING stack. Once the API has minted an agent CA (encrypted with the stack's key) the test's own key cannot decrypt it, and the code **correctly refuses to regenerate** (*"a new CA would orphan every enrolled agent"*). Leader-election tests fail for the sibling reason — the live API holds the lock.<br><br>`agentca` ×3 · `nodes/TestNodeEnrollmentLifecycle` · `devices` ×2 · `ovpn` · leader-election ×2<br><br>**MEASURED CLEAN on a fresh DB (CI's condition — CI runs `docker compose up -d --wait postgres` and never starts the API): open 32 ok, enterprise 35 ok, ZERO failures, both editions.**<br><br>⛔ **WHY THIS IS WORTH A ROW RATHER THAN A SHRUG: `make test-editions` is a REQUIRED gate in CLAUDE.md, and a gate that is always red teaches you to skip reading it.** The next genuine failure in those four packages arrives already camouflaged. Fix is test-side isolation (a per-test schema or a dedicated test database), not a skip — a skip would make it pass while checking nothing, which is the worse failure (the witness-liveness law). | S14.11 gate run | pre-existing, unfixed, NOT mine |

| ⛔⛔ **`CountOwners` COUNTS OWNER *ROWS*, NOT OWNERS WHO CAN SIGN IN — A REACHABLE, UNRECOVERABLE LOCKOUT** | **its own change, with its own red** — server code with a security consequence, deliberately NOT fixed on the S14.11 branch | **PROVEN REACHABLE on a throwaway DB, not read off the code** (`docs/probes/lockout_probe_test.go.txt`, runs in a rolled-back tx):<br><br>`CountOwners` = `SELECT count(*) FROM memberships WHERE org_id=$1 AND role='owner'` — **no join to `users`, so no `status` filter.** `CountOrgsWhereSoleOwner` has the same shape. Login refuses a deactivated account (`403 account_deactivated`, `auth/service.go:148`).<br><br>**BRANCH 1 (demote):** deactivate owner A → allowed (2 owner rows) · `CountOwners = 2` · demote owner B → **allowed** · result **1 owner row, 0 owners who can sign in**. ⛔ **NOT REPORTED AS THE LOCKOUT.** B is now an admin, still holds `member:manage`, and can reactivate A — so there IS a path back. **A capability outage, not a lockout**, and the distinction is load-bearing: reporting branch 1 as a lockout would have inflated the finding, and **an inflated finding costs the next one its credibility** (founder). The finding rests on branch 2 alone.<br>**BRANCH 2 (deactivate both):** deactivate A → allowed · deactivate B → **allowed** · result **2 owner rows satisfy the invariant on paper, 0 accounts can sign in and act.** ⛔ **NO PRODUCT PATH BACK — recovery requires direct database access.**<br><br>**CENSUS of the same shape** — every query counting a privilege-bearing role/membership: **3 total.** `CountOwners` **⛔ no status** · `CountOrgsWhereSoleOwner` **⛔ no status** · `CountMembersByOrg` joins `users` and documents that deactivated are *intentionally* counted (a display count, correct by intent). **No Go-side guard counts exist** — the two SQL guards are the whole set.<br><br>**The client mirrors this deliberately** (`Users.tsx` `ownerCount`) and **must not be fixed independently** — a client that disagreed with the server about who the last owner is would be a second authority. It follows the server fix, in the same change. | S14.11, from the founder's question about the role tally | **PROVEN, unfixed, held** |
| **`Groups` on the Access posture panel — a DELIBERATE ADDITION over the wireframe** | none; it is shipped. The row exists so the addition is auditable, per §2.6 | ⛔ **THE WIREFRAME HAS NO GROUPS STAT.** Its Access posture panel is: title · `role hierarchy · MFA coverage · authentication sources` · `{{ teamMap }}` · legend (`role tiers`, `MFA enrolled 5/7`) · the last-owner copy. Groups appear ONLY as one axis inside `{{ teamMap }}` — the tripartite role↔user↔group graph, which is **D2, held**.<br><br>**REASON IT SHIPS:** it is the honest placeholder for the held graph, and the only thing on this screen that renders the **edition/permission seam** — the four-gate shape the section exists to demonstrate.<br>**WHERE IT LIVES:** its own line, labelled *"The role-and-group map is not built yet; this stands in for it."* **NOT a stat tile** — beside owner/admin/member a group count reads as a fourth role tier. Guarded by a wiring test asserting the `<dl>` holds exactly the three role terms.<br>**WHEN D2 LANDS:** this line is replaced by the graph, not kept alongside it. | S14.11 founder review | shipped, registered |

| ⛔ **MOCK-VERSUS-SCHEMA CENSUS — the unfaithful-double class, swept in BOTH directions** | **direction 1 (`actor_user_id`) — the next AuditLog touch, or S14.10b.** Direction 2's 52 rows — **whenever a screen's mock is next edited**; not a batch fix | **TWO IN ONE SLICE IS A PATTERN, NOT LUCK** (founder): the fixture's empty `name` (a field the population mostly leaves blank) and the mock's phantom `active` (18 occurrences of a field absent from `Member`, while `status` — always sent — was missing). Swept all 40 files in `apps/web/test` against `openapi.yaml` (`docs/probes/mock-schema-census.py`).<br><br>**DIRECTION 1 — INVENTED (a field the mock has, the schema does not). Always a defect. 1 REAL, NOW FIXED:**<br>⛔ `auditlogwiring.test.tsx` sent **`actor_user_id`**; the spec's `ActivityEntry` has **`actor_id`** and is `additionalProperties: false`, so the server can never send it. **MEASURED before changing anything: 34 of 78 live rows carry a populated `actor_id`. THE PAGE WAS RIGHT; ONLY THE MOCK WAS WRONG** — a fixture defect, not a render defect. Fixed, plus a test that asserts an actor **NAME** and was proven to fire.<br>⛔ **But chasing it found a REAL render defect on the same screen — `actor_system` unread. Its own row above.**<br><br>> **THE MOCK AND THE PAGE DISAGREED, THE TEST PASSED, AND THE PASSING BRANCH WAS THE ONE NOBODY WANTED.**<br>> **A FALLBACK THAT IS NEVER EXERCISED DELIBERATELY IS A FALLBACK THAT IS ALWAYS EXERCISED ACCIDENTALLY.**<br><br>**DIRECTION 2 — OMITTED *and read by the page under test*: 51** (full list: `docs/probes/mock-census-output.txt`; **registered, not fixed now** — ruled) (plus **57 omitted-but-never-read**, benign partial fixtures, deliberately NOT reported — a mock carries the fields its test asserts on). Concentrated in `deviceswiring` (`public_key`, `user_id`) and `accesswiring`/`auditlogwiring` (`Member.name`, `.status`, `.email`).<br><br>⛔ **THE CENSUS NEEDED CENSUSING — 3 flagged, 1 real, and I verified each rather than reporting the count.** Two false-positive causes, both now fixed in the script and worth knowing: **(a)** the key scanner read prose inside COMMENTS (`"...stays FALSE here: only ONE..."` became an invented `Device.here`); **(b)** **VIEW-MODEL literals are not wire DTOs** and legitimately have their own shape — camelCase ones are excluded, but `{id,name,status,health}` slipped through because its keys are lowercase single words. A shape-only matcher cannot fully separate the two. | S14.11, founder-directed after the second unfaithful double | swept; 1 real finding held |

| ⛔⛔ **SHIPPED ON A MERGED SCREEN — THE AUDIT LOG DISCARDS EVERY NAMED SYSTEM ACTOR** | **its own change.** Red is written and waiting: `docs/probes/actor_system_unread_probe.test.tsx.txt` | `AuditLog.tsx:213` is `{a.actor_id ? actorName(members, a.actor_id) : "system"}`. **`actor_system` is in the spec, is served, and is read NOWHERE in `apps/web` — zero references.**<br><br>**MEASURED on the review stack**, `GET /audit-logs?limit=100`, 78 rows: **34** `actor_id` (human, named correctly) · **19** `actor_system` — `device-health` ×17, `reconciler` ×2 — ⛔ **all flattened to the word "system"** · **25** neither (`hub_set.promotion` ×13, `failback` ×9, `membership` ×2, `node.enrolled` ×1).<br><br>Each system row also carries its **cause** (`{"actor_system":"device-health","details":{"cause":"noncompliant_report",…}}`) which the page never shows.<br><br>⛔ **DEFEATS A STATED ARCHITECTURE INVARIANT** (CLAUDE.md): *"Audit logs record system actors first-class (`actor_system`) with a cause."* S7.5.2's own note: audited to a **NAMED** system actor *"so a compliance reader sees 'revoked by idp-sync because &lt;cause&gt;'."* **The control plane does exactly that; the screen throws it away.** The WHO-READS-THIS PROBE failing — a producer with no consumer.<br><br>**SECOND, SMALLER QUESTION, deliberately not folded in:** the 25 actor-less rows are genuine automatic events that record **no `actor_system` at all**, so the invariant is unmet on the **WRITE** side for those actions. Rendering them "system" is substantively right; not naming the controller is the gap. That is a control-plane change, not a render change — decide it separately. | S14.11 mock census | **PROVEN, unfixed, red written** |

| ⛔ **`Kubernetes.tsx:403` RE-INTRODUCED THE BANNED PLACEHOLDER GLYPH — a REGRESSION, not a pending sweep** | **its own change** (S14.8 re-touch or the polish sweep). NOT this branch | **FOUNDER-FOUND on the S14.11 review, on a screen whose section pass is DONE.** `{t.value === null ? "—" : t.value}` — and it carries a comment claiming an exemption: *"A LONE DASH IS A NULL MARKER, NOT PROSE — the em-dash sweep leaves it."*<br><br>⛔ **THE LAW ALREADY DECIDED THIS EXACT CASE.** `docs/laws.md` → *WHEN ONE RULE REQUIRES REWRITING THE EXPRESSION OF ANOTHER* (S14.5): `hubsetview` rendered `"—"` as an absent-marker under the honesty rule, the COPY rule bans the em-dash as a placeholder outright, and it **RESOLVED TO `n/a`** — *"an em-dash is not READ as 'we have no value' by anyone who has not been told that it means that. It reads as a dash, as a minus, or as NOTHING AT ALL to a screen reader."*<br><br>**And that law's closing line names the failure exactly: *"the reflex in that moment is to claim an exemption for the older rule."* The Kubernetes comment IS that exemption, written out.**<br><br>**DID S14.8 CLEAR IT? NO.** S14.5 fixed `hubsetview` (`src/lib/hubsetview.ts:8` records the change). S14.8's section pass did not apply the same resolution to the stat tile.<br><br>**CENSUS of placeholder em-dashes still rendering** — `Kubernetes.tsx:403` (**regression, pass done**) · `Access.tsx:304`, `:1599` (pass not run) · `AuditLog.tsx:222` (`target_type ?? "—"`). **Only `hubsetview` is resolved.** All four should become `n/a`, not be swept as prose. | S14.11 founder review | **REGRESSION, unfixed** |
| **`Machine credentials — could not read` on Kubernetes, as OWNER** | its own change; **the API is not the cause** | **MEASURED, all three of the founder's alternatives ruled out on the API side:**<br>`GET /organizations/{org}/machine-credentials` as `owner@` → **`HTTP 200`** with one row (`k8s-operator-us-east`). Handler authorizes `PermMachineManage`, which the owner holds. `/organizations` returns exactly **1** org and it is the demo org, so the page resolves the same `orgId` I curled. `loadOne` maps a 200-with-array to `ok: true`, and the reload path has no early return between the cluster read and `setRaw`.<br><br>**So it is NOT a permission failure and NOT a correct refusal with failure-shaped copy — the read succeeds.** The tile is DESIGNED to say `could not read` when `machineCreds` is `null`, and `null` is only produced by a FAILED request (`loadOne`'s catch or an error envelope).<br><br>⛔ **I PROPOSED A CAUSE AND THE CHECK REFUTED IT.** My hypothesis was that `make up-enterprise` restarted the API mid-review, so a request in flight failed → `loadOne` → `null` → `could not read` — the tile working correctly and reporting my rebuild. **MEASURED on the quiet stack:**

```
tunnex-s141-api-1     Up 8 hours    <- NEVER RESTARTED
tunnex-s141-nginx-1   Up 27 hours   <- never restarted
tunnex-s141-web-1     Up 38 minutes <- the ONLY container my rebuilds replaced
```

`make up-enterprise` rebuilds the **web** container (which is why the bundle hash changed) and leaves the API running. **So the restart my explanation depended on did not happen.** Five consecutive replays of the page's exact read: `HTTP 200`, 1 row, every time.

> **THE CONVENIENT EXPLANATION WAS MINE-AND-HARMLESS, WHICH IS PRECISELY WHY IT NEEDED A CHECK.** It would have closed the row without anyone looking again.

**CURRENT HONEST STATE: the observation is UNEXPLAINED.** The API is not the cause (ruled out four ways: 200 with data, correct permission, correct org, `loadOne` maps it to `ok:true`). The client code path has no early return. **A page reload on this quiet stack settles it** — if the tile shows `1`, it was transient and this row closes as not-a-defect; **if it still reads `could not read`, it is a real client bug and this row becomes a defect.** Not closing it on a refuted hypothesis.<br><br>**The copy itself is fine either way:** `could not read` is honest failure phrasing for a failed read, and the tile deliberately carries `null` rather than collapsing to `0` (*"a zero here would claim 'no operator identity exists', which is a different fact from 'we could not look'"*). | S14.11 founder review | **API cleared; client cause unconfirmed** |

| ⛔ **WHAT ELSE HAS ONLY EVER RUN AGAINST AN ACCUMULATED DATABASE?** | **the next data-path story** — registered, deliberately NOT chased now | S14.12's open-edition stack produced the first FRESH database in months and `fixtures.sql` failed instantly on a FK ordering defect that had been live the whole time (`policy_rules` at line 341 references users inserted at line 384; the primary DB already had them from earlier seeds). **Migrations are covered — CI runs them forward from empty every run.** Nothing else is: **seeds, backfills, and any ordering-sensitive script** may only ever have executed against a database already containing what they assume. **The diagnostic: for any script that writes, ask when it last ran against an EMPTY target.** If never, it has been tested against its own side effects. Candidates to sweep: `cmd/seed`, `cmd/seed-enterprise`, `cmd/seed-fixtures` (now fixed), `cmd/walk-bootstrap`, and any migration carrying a data backfill | S14.12, from the FK failure the new stack exposed | registered |

| ⛔ **WHAT ELSE IS DUPLICATED ACROSS `ci.yml` AND `security.yml` WITH NOTHING ASSERTING AGREEMENT?** | **the next workflow change** — enumerated, deliberately NOT fixed | The `\.sql$` divergence silently skipped `govulncheck` ×5, `gofmt + vet parity` and `Trivy`. **Enumerated now so the next edit starts from a list rather than a surprise:**<br><br>**AGREE TODAY (6, unasserted — any of them can drift the same way):** the diff-classifier regex *(now asserted by `TestClassifierPatternMatchesTheWorkflow`, the only one covered)* · `actions/setup-go@v5` · `actions/checkout@v4` · `GOFLAGS: -mod=readonly` · `fetch-depth: 0` · the `github.event.pull_request.base.sha` expression.<br><br>⛔ **I REPORTED A DIVERGENCE HERE AND THE MEASUREMENT INVERTED IT. Recorded because the correction is the finding.**<br><br>I claimed *"`security.yml` pins nothing, so its jobs take the runner default"* — **my enumeration regex only matched `go-version:` and missed `go-version-file:`.** Measured:<br><br>`security.yml:82,175` → **`go-version-file: <module>/go.mod`** — the version is DERIVED FROM THE MODULE and cannot drift from what that module declares.<br>`ci.yml:176` → **`go-version: '1.25'`**, hardcoded.<br>All five modules declare **`go 1.25.12`**.<br><br>**So they agree today, and the one that can drift is `ci.yml`, not `security.yml`.** The security workflow is the *better*-constructed of the two: it asks the module. **The build is the side pinned by hand.**<br><br>> **AN AGREEMENT THAT HOLDS BY COINCIDENCE IS ONE EDIT FROM NOT HOLDING — and I had the direction of the risk backwards, which is worse than not having looked, because a wrong direction sends the fix to the wrong file.**<br><br>**Recommendation (founder ruled "pin it either way"): change `ci.yml` to `go-version-file: apps/api/go.mod`** so both derive rather than one deriving and one asserting. Small, and it removes the hand-maintained copy instead of adding a second one.<br><br>**The general fix, when it is taken:** a shared `scope` workflow called by both via `workflow_call`, so there is ONE classifier rather than two that agree. | S14.12, from the skipped-security-jobs finding | enumerated, unfixed |

| ⛔⛔ **12 SHIPPED MUTATIONS AN OPERATOR CANNOT REACH — EPIC 14's LARGEST CARRIED FINDING** | **its own story.** Explicitly NOT a fold; S14.12 closes with group membership ONLY, because that one blocks the screen under review | **MEASURED: 80 mutating operations in the spec, 54 actual web call sites, 19 with none** (`api.POST\|PUT\|PATCH\|DELETE("…")`, with `edition.ts` excluded — it is a path MANIFEST, not a caller).<br><br>**NOT THE WEB'S JOB (5, correctly absent):** `enrollAgent` · `cliToken` · `cliDeviceToken` · `cliDeviceStart` · `reportDeviceHealth` — agent/CLI/device callers.<br>**PLAUSIBLY ELSEWHERE, UNVERIFIED (2):** `verifyEmail` · `revokeCliCredential`.<br><br>⛔ **CAPABILITY WITH NO SURFACE (12):**<br>`addGroupMember` · `removeGroupMember` — **being built in S14.12**, the one blocking item<br>`approveDevice` · `rejectDevice` — **cross-link: S14.10b Device Approval**, already registered<br>`resendInvitation` · `revokeInvitation` — **cross-link: S14.11's `listInvitations` workflow gap**, already registered<br>`createDomainClaim` · `verifyDomainClaim` — SSO domain capture; also blocked by the `sso_configs` fixture zero<br>`putIdpSyncConfig` · `mapIdpGroup` · `unmapIdpGroup` · `triggerIdpSync` — ⛔ **IdP-sync is FIVE endpoints with NO surface at all**, the largest single cluster<br><br>**THE CLASS:** the who-reads-this probe failing on a **VERB** rather than a field. A field with no reader shows nothing; **a verb with no caller is a capability the product has and the operator cannot reach.** | S14.12, from the group-membership measurement | **enumerated, 1 of 12 being fixed, 11 carried** |

| ⛔⛔ **`managed_by_machine` IS `SET NULL` — REVOKING A MACHINE CREDENTIAL GRANTS EDIT RIGHTS** | **its own change, ranked with the `CountOwners` lockout.** No revoke control ships over it | **MEASURED:** `k8s_clusters.managed_by_machine`, `k8s_services.managed_by_machine`, `policy_rules.managed_by_machine` — all FK to `machine_credentials` with `ON DELETE SET NULL`.<br><br>**A cascade at least removes the row. This NULLS THE OWNERSHIP MARKER AND LEAVES THE ROW LIVE.** GitOps-managed policy silently becomes hand-editable: the `Managed by GitOps` badge vanishes (`row.managedByOperator` reads that column) and the withheld mutation controls return.<br><br>> ## **A PRIVILEGE CHANGE DISGUISED AS A CLEANUP ACTION.** Revoking a credential *reads as removing access*; it in fact **grants edit rights on three tables to anyone with the UI**. Nothing in the verb's name, the UI, or the 204 says so.<br><br>**Ranked with `CountOwners`:** both are destructive server behaviours reachable from the UI where the operator is told nothing. | S14.13 pre-flight check 7 | **MEASURED, unfixed** |
| ⛔ **THE `settingswiring` HARNESS CANNOT SEE RENDERED OUTPUT — every DOM assertion in that suite is suspect** | ⛔ **FIRST WORK NEXT SESSION, before any feature work** | **TWICE IN TWO STORIES**, `screen` queries missed text that a raw `document.body.textContent` dump proves is rendered. S14.12: the flow-panel assertions (backed out, later re-added after extending the mock). S14.13: both SSO arms — `waitFor`, `findAllByText` with a 3s timeout, all fail on `status unknown` while the dump shows `Single sign-on · google · status unknown`.<br><br>**DIAGNOSIS NARROWED (S14.13), three facts:**<br>1. **Passes in ISOLATION** — a standalone file with the same mock and the same query finds the text immediately. **The query and the component are fine.**<br>2. **Passes in-file with `-t`** (only that test runs). **Fails when the earlier tests in the file run first.** → state crosses the test boundary.<br>3. **Survives an explicit `ssoFail` reset in `beforeEach`.** → **not** the mock-controlling variables.<br><br>⛔ **EXPERIMENT RAN. BOTH HYPOTHESES REFUTED — that is the result, not a failed run.**<br><br>**ELIMINATION TABLE:** mock-controlling variables **ruled out** (explicit `ssoFail` reset in `beforeEach` did not help) · stale tree **ruled out** (`document.body.children.length === 0` after every `cleanup`) · late `api.GET` resolving post-cleanup **ruled out** (zero observed) · passes in ISOLATION and in-file with `-t`, **fails only when earlier tests precede it**.<br><br>**So the leak is NOT in the DOM and NOT in the mock's async.** Remaining candidates: **module-level state in `Settings.tsx` or `AuthProvider` surviving unmount** — a cached promise, a module singleton, or a `useState` initializer reading something set once.<br><br>⚠ **THE PROBE HAD A HOLE FIRST, caught before it was believed:** the flag was reset inside the same `afterEach`, so calls landing after that point were unobservable. **An instrument that cannot observe the window it claims to cover reports absence either way.** Moved to `beforeEach`; the refutation above is from the corrected probe. The instrumentation is COMMITTED so the next session inherits it.<br><br>⛔ **SHUFFLE/REORDER EXPERIMENT RAN — the answer is CUMULATIVE, not a singleton.** The two SSO tests pass alongside ANY SINGLE earlier describe (OpenVPN, pool, machine-credentials, edition, two-factor) and fail ONLY in the full run. **So no one earlier test names the cause; something accumulates across several.** That is consistent with the remaining candidate — module-level state in / that survives unmount and compounds per render.<br><br>⛔ **DIAGNOSIS TIME-BOXED AND CLOSED HERE, founder-ruled: this is its own story, not a tax on every slice.** Three sessions, one panel unbuilt. The probe and the elimination table ship with the branch; the next person starts from a narrowed candidate set, not from zero.<br><br>**THE ENUMERATION WAITS FOR THE MECHANISM.** A count of affected assertions measured against a mechanism nobody can name is a number with no subject, and it would be quoted later as if it meant something.<br><br>*(superseded plan, kept for the trail:)*  instrument `afterEach` to assert **(a)** `document.body.children.length === 0` and **(b)** that no `api.GET` mock call resolves after `cleanup`. **(a) failing = stale tree; (b) failing = late promise.** One run distinguishes them.<br><br>⛔ **AND THE DIRECTION THAT MATTERS MOST IS THE INVISIBLE ONE:** a late promise resolving into the NEXT test's tree can make an assertion **PASS that should fail** — not only fail one that should pass. **The passing assertions on merged screens are the ones nobody can see, and they are exactly what this could have silently validated.**<br><br>**THE AFFECTED CLASS, to enumerate before fixing:** every *render-then-query-without-`waitFor`* assertion in the suite. An assertion guarded by `waitFor` on its own subject is mostly self-correcting; one that renders and queries immediately is at risk. **Report the count and files first — the size decides sweep vs story.**<br><br>⛔ **THE CONSEQUENCE IS NOT ONLY THE FAILING TESTS.** A harness that intermittently cannot see rendered output can also intermittently **see output that should not be there** — **the tests that PASS are as affected as the ones that fail.**<br><br>**Owed with it:** re-add both SSO arms — a non-`sso_not_configured` failure never offers Configure; `sso_not_configured` does. | S14.12 + S14.13 | **BLOCKING next session** |
