# REGISTER — THE SERVER IS RIGHT AND THE USER STILL GETS THE WRONG THING

**Against the CURRENT shipped product. None of these belong to the epic that found them.**

A defect in this register is one where **the server is correct and the user still gets the wrong thing.**
The correct value exists, is computed, is served — and the person in front of the screen does not receive
it. The cause is never in the logic under review, which is why these are invisible to every test that
exercises the logic.
That is why it needs its own file: every other register here asks *is this in scope*, *when does this
happen*, or *what can this principal do*. This one asks **does the correct answer actually arrive**, and
nothing about the code under review can answer it.

**HOW TO USE IT:** `grep -i '<name>' docs/REGISTER-shipped-delivery-defects.md` before concluding that a
deploy reached anyone. **HOW TO ADD:** the defect, its blast radius on the SHIPPED product, before/after
evidence you actually ran, and **how it was found** — the last one is the reusable part.

---

## ⛔ 1 — `index.html` HAD NO `Cache-Control`, SO A CORRECT DEPLOY COULD NOT REACH A RETURNING USER

**Status: FIXED on `story/S15.1-owned-machine-principal` (`12257866`, `deploy/nginx/spa.conf`).
Independent of EPIC 15 — it must not be read as part of that slice.**

### What shipped

```nginx
location /assets/ { expires 1y; add_header Cache-Control "public, immutable"; }
location /        { try_files $uri $uri/ /index.html; }   # ← no cache directive at all
```

The hashed assets are pinned `immutable` for a year — correct, they are content-addressed. The **entry
document carried no `Cache-Control` and no `Expires`**, only an ETag.

With no explicit freshness a cache MAY apply a heuristic (RFC 9111 §4.2.2); the widely-implemented one is
**10% of the time since `Last-Modified`**, served **without revalidating**:

| age of the build the user last loaded | stale SPA served with **zero** network requests |
| --- | --- |
| 1 hour | ~0.1 h |
| 1 day | ~2.4 h |
| 1 week | ~16.8 h |
| 1 month | ~72 h |

### Blast radius on the shipped product

**Every Tunnex upgrade left returning users on the superseded SPA**, and the two directives compounded:
the stale `index.html` names the old bundle, and that bundle is pinned `immutable` for a year, so the
browser reconstructs the previous release **making no requests at all**. Nothing server-side can dislodge
it — not a rebuild, not a restart, not a new release. The user has to know to hard-reload, which means the
recovery path for a delivery defect was *the user already suspecting there was one*.

⚠ **Worse for a self-hosted product**: the operator who upgrades is the same person who then reports that
the new feature is missing, and every server-side check they run says the deploy is fine — because it is.

### Before / after — measured, both directions

The fix is one line: `add_header Cache-Control "no-cache";` on `location /`.
`no-cache`, **not** `no-store` — revalidate before reuse, so the ETag still yields a 304 and a ~700-byte
document is re-sent only when it changed.

⛔ **A HEADER THAT HAS ONLY EVER BEEN PRESENT IS INDISTINGUISHABLE FROM ONE THAT DOES NOTHING**, so it was
removed from the running container and re-measured before being restored:

| state | `Cache-Control` on `/` | conditional GET |
| --- | --- | --- |
| with the fix | `no-cache` | **304** |
| directive deleted, `nginx -s reload` | **absent — header count 0** | (heuristic applies; no revalidation required) |
| restored by **rebuild**, not by re-editing | `no-cache` | **304** |

Restored via `docker compose up -d --build --force-recreate web` deliberately: the image is the source of
truth, and re-editing the live file would have proved the running container agreed with itself.

### ⭐ HOW IT WAS FOUND — the reusable part

The reviewer's browser showed a pre-S15.1b screen. Two causes were proposed, and **both were wrong**:

- **A — the containers were never rebuilt** (the prior S14.13 cause, and the more likely one).
- **B — the fix under way had dropped the feature.**

The founder's instruction was to **measure which, and not to rebuild first** — because *a rebuild fixes the
symptom under either cause and destroys the ability to tell them apart.* That instruction is the entire
finding. Under A the rebuild would have been reported as the fix, the register row would never have been
written, and the defect would have shipped to every user.

What the measurement returned:

| check | result |
| --- | --- |
| branch tip / tree | `bbd5f9c5`, clean |
| served hash, both stacks | `index-B7qQkDXb.js` — the one already reported |
| served bundle: the slice's four strings | 1 each — **present** |
| served bundle: `never used` (the copy the reviewer read) | **0 — absent** |
| web container assets | **only** the current hash |
| three prior hashes over `:80` | **404, 404, 404** |

Every server-side answer was *correct*. Neither hypothesis survived, **and the evidence was still
readable** — it named a third cause neither had considered.

> ## **A CORRECTLY-RUN CHECK AIMED AT THE WRONG SUBJECT, ONE LEVEL UP.** The known instance of that law is a
> ## check run against the wrong object. This is the same error at the level of the HYPOTHESIS SET: both
> ## candidates concerned *what the server holds*, and the defect was in *what the client asks for*. When
> ## every hypothesis is refuted, the next move is not to pick the least-refuted one — it is to notice that
> ## the question was scoped to the wrong layer.

### ⚠ AND THE BUNDLE HASH WAS THE WRONG MEASUREMENT — WRITE THIS DOWN

The founder asked, reasonably, for the served hash to be re-verified as **CHANGED** after the fix. Under
cause A or B that is exactly right. **Under this cause it does not apply: the bundle was never wrong, and
the hash was identical before and after (`index-B7qQkDXb.js`).** The fix is in a response header; the only
thing that can verify it is the header.

> ## **"VERIFY THE HASH CHANGED" TESTS THAT A NEW ARTEFACT WAS BUILT. IT CANNOT TEST WHETHER AN UNCHANGED
> ## ARTEFACT NOW REACHES THE USER.** The next person will be handed that check as a rule. It is a good rule
> ## for the cause it was written for. Producing a changed hash here — by touching the bundle to make the
> ## check pass — would have destroyed the evidence that the bundle was innocent.

### Not covered by this fix

- **A browser that already holds a stale `index.html` will not see the new header** until it revalidates —
  the header cannot reach a client that is not asking. One hard reload, once, per already-affected browser.
- **The Electron client** ships its own copy of the bundle over `app://` and does not go through this nginx
  at all. Whether it has the equivalent problem is **unmeasured** — registered here, not answered.
- **No release-notes or version-mismatch surface.** The app cannot tell a user that it is running an older
  build than the API it is talking to. Separate gap, not opened here.

---

## ⛔ 2 — THERE IS NO ORG SWITCHER, SO A USER IN TWO ORGS CAN ONLY EVER REACH THE OLDEST ONE

**Status: OPEN. Measured at the S15.1 review, not fixed there — this is product scope, not a slice fold.**

### Measured, not inferred

- Every page selects its org the same way: **`orgs?.[0]`** — `Settings.tsx:91`, and the same shape in
  `Dashboard`, `Access`, `Sites`, `Kubernetes`, `AccessEvents`.
- **No switcher exists anywhere in `apps/web/src`.** The sidebar has none; the top bar carries the user
  and *Log out*.
- The list is ordered **`ORDER BY o.created_at`** (`ListOrganizationsForUser`), so "which org you get" is
  "whichever you joined first" — stable, arbitrary, and unexplained on screen.
- ⚠ **It is not in the deferral register either**, so it has been carried as folklore rather than as a
  registered gap.

### ⭐ AND THE LOGIN PAGE ASKS FOR AN ORG — MEASURED, BECAUSE IT LOOKED LIKE THIS WAS BY DESIGN

`localhost/login` shows an **Organization** field (placeholder `acme`). If the org were chosen at login,
`orgs[0]` would be a consequence of a deliberate design and this row would be wrong. **It is not.**

| question | measured |
| --- | --- |
| what the field is | an input **inside the SSO block**, feeding `?org=` to `GET /api/v1/auth/sso/{provider}/start` (`Login.tsx:287-306`) |
| what the server does with it | `s.sso.StartLogin(ctx, req.Params.Org, provider)` — resolves **which org's IdP configuration to use** (`sso_handlers.go:50`) |
| does password login send it | **no** — body is `{email, password}`, and `LoginRequest` is `additionalProperties: false` |
| does the session carry an org | **no** — `session.Session` is `{ID, UserID, CreatedAt, ExpiresAt, AuthMethod}` |
| does the principal | `Roles map[uuid.UUID]string` — **orgID → role, plural.** Explicitly multi-org |
| live multi-org users | **1** (`owner@demo.tunnex.local`, 2 memberships) — ⚠ a fixture this review created, so *demonstrated reachable*, not evidence of field usage |

⛔ **So the field routes an IdP lookup for one SSO handshake and never selects a tenant.** It is real and
submitted — not decorative — but it is **SSO-scoped in the code and reads as global on the screen**, which
is what made this look like tenant selection.

### And single-org was never ruled — the opposite was

**`PLAN.md:12` — "Tenant routing: Single domain (`app.tunnex.io`), org resolved from membership after
login."** *Membership-resolved, explicitly.*

> ## **THE SERVER ALREADY IMPLEMENTS THE LOCKED DECISION CORRECTLY.** The principal is multi-org by
> ## construction, `GET /organizations` already serves every membership, and the session is deliberately
> ## org-less. **Only the client discards what it was handed.** The defect is one layer thick.

⚠ **Three answers to one question:** the login page asks for an org, the API returns all of them, the UI
reads the first. They must agree — and the one that is wrong is the UI's.

### Blast radius

`GET /api/v1/organizations` returns **every** org the user belongs to. The UI reads index zero and
discards the rest. A user in two organizations cannot reach the second one **at all** — not by
navigation, not by URL, not by any control on any screen. There is no error, no empty state, no
indication that another org exists. The product silently behaves as single-org.

> ## **THIS IS THE FIRST ABSENCE QUESTION, ANSWERED THE HARD WAY.** *"What can an operator NOT do on this
> ## screen that the API allows?"* The API allows selecting among N orgs. The screen allows one, chosen for
> ## them, unnamed. A wireframe diff could never have found it — the design depicts one org, and the design
> ## cannot be wrong about what it omits.

### How it was found — a fixture that proved the wrong thing

A second org (`demo-eu`) was seeded so the **all-owned banner** would have a reachable state, since
one unassigned row anywhere in an org suppresses it. The seeding was correct and verified by count in
both databases. **The state was still unreviewable, because no reviewer can navigate to that org.**

> ## **A SEEDED STATE IS NOT A REACHABLE STATE, AND A COVERAGE COUNT CANNOT TELL THEM APART.** The fixture
> ## reported 5 of 5 states seeded. Five were seeded; four were reachable. *Seeded and invisible is worse
> ## than absent* — absent is counted as missing, invisible is counted as done.

⚠ **And the failure was in the APPROACH, not the seed.** No amount of fixture work can make a screen
reviewable when the product has no path to it. The check to run before seeding a state is *can a human get
here*, and it was never asked.

### Review workaround — a procedure, NOT a surface

Ordering is by `created_at`, so which org is `orgs[0]` can be chosen:

```sql
-- show the all-owned org
UPDATE organizations SET created_at = now() - interval '10 years' WHERE slug = 'demo-eu';
-- put the four per-row states back
UPDATE organizations SET created_at = now() - interval '1 hour'   WHERE slug = 'demo-eu';
```

⛔ **This is a review procedure and must never be read as the state being reachable in the product.** It
requires database access, and no user or operator has that path.

### Not decided here — RULING HELD until after S15.1 merges

Three dispositions, measured and held. **Not to be started.**

| | what it means | cost |
| --- | --- | --- |
| **A — login selects the org** | the field becomes real for password login; session carries an org; `GET /organizations` narrows to match | **contradicts `PLAN.md:12`**; switching orgs requires re-login; SSO needs the org *before* auth, so the paths stay asymmetric |
| **B — a switcher** *(recommended)* | `orgs[0]` becomes a **default rather than a ceiling** | UI work; needs a persisted "last used org" or it re-defaults each load |
| **C — org-scoped routes** | org in the URL; deep links work; the current screen is always nameable | largest — every route, link and redirect |

**Recommendation: B**, because it is the only one requiring **no** change to the API or to the locked
decision — the server is already right and only the client is wrong. A and C both change the contract to
match a client limitation. ⚠ **C is the better long-term shape and B does not block it**: a switcher that
sets state becomes a switcher that sets a route.

⛔ **HELD — the founder rules it after S15.1 merges. It must not ride that merge.**

---

## ⚠ 3 — THE REVIEW FIXTURE CARRIES A REAL-LOOKING FAULT A REVIEWER CANNOT DISTINGUISH FROM A REAL ONE

**Status: OPEN, review-environment only. Registered at founder instruction; deliberately NOT fixed during
the S15.1 review.**

**Directory sync — Microsoft Entra** renders **ESCALATED** with `credential: decrypt failed` on the demo
stack. Same class as the agent-CA failure earlier in this session: a row sealed under one
`TUNNEX_SECRET_KEY`, read back after the postgres volume was reset and a new key generated. The ciphertext
is intact and unreadable, which is the correct behaviour — the fault is that the fixture ships it.

⛔ **THE DEFECT IS THE AMBIGUITY, NOT THE ERROR.** A reviewer looking at a demo stack cannot tell a seeded
fault from a live one, so every genuine escalation on that screen is discounted, and a real one would be
too. A review environment that cries wolf trains the reviewer to ignore the alarm — the same failure mode
as the reassuring-empty class, inverted.

⚠ **And it is a second instance of one cause**: the volume reset invalidated every sealed row, not just the
CA. Nothing enumerates what was sealed, so each one surfaces separately, as a surprise, wearing the costume
of a product bug. **What is missing is a named key-mismatch message** — already carried as an open
follow-up — and, beneath it, an inventory of sealed columns so a key change reports its blast radius once
instead of N times.

**Not fixed here** by instruction, and correctly: it is not S15.1's, and fixing it silently would have
removed the evidence for this row.

---

## ⚠ 4 — A FIXTURE PUT ON SCREEN THE EXACT PHRASE THE PRODUCT IS BARRED FROM SAYING

**Status: FIXED (fixture rename, `demo-migrated` → `demo-eu`, `Demo — migration complete` → `Demo EU`).**

The all-owned banner is deliberately a claim about **ownership, not health**, and a test rejects
`migration is complete`, `everything`, `all good/well/fine`, `healthy`. The fixture org created to make
that banner reachable was named **`Demo — migration complete`** — so a reviewer saw *"migration
complete"* twice on the screen, in the org name and the page subtitle, while the banner two lines below
was forbidden from saying it.

⛔ **A FIXTURE IS COPY. IT RENDERS.** The test pinned the component and the fixture walked the phrase in
through the org name — a channel no assertion about the component can see, because it is not the
component's text. The screen said the banned thing; nothing that guards the banner was wrong.

> ## **A CONSTRAINT ENFORCED ON ONE SOURCE OF TEXT IS NOT ENFORCED ON THE SCREEN.** The banner's rule is
> ## about what the product may claim. Every string that lands beside it — org names, page titles, seeded
> ## entity names — is subject to the same rule and is covered by none of the same tests.

⚠ **And it was written by the same person who wrote the ban, in the same session.** The rule was held
about the component and not about the surface.

### Not fixed by the rename

The fixture is also **not reachable in the product** — it is reached by database ordering (row 2). The
rename removes the false claim; it does not make the state reviewable by a user.

---

## ⛔ 5 — `users.deleted_at`: **18 PRE-ARMED GUARDS** ON A COLUMN NOTHING WRITES, FIVE OF THEM DATA-PLANE

**Status: OPEN, MEASURED. Found while measuring D26's reachability, 2026-08-04. Filed with the count,
deliberately not fixed.**

`users.deleted_at` is filtered on by **18 predicates across 18 queries** — and **no query, no Go code, and
no migration ever sets it.** Deactivation is `users.status`; `RemoveMember` removes the *membership*.

> ## **THIS IS NOT A DORMANT COLUMN. IT IS A FLEET OF GUARDS THAT ALL CHANGE MEANING ON THE SAME DAY.**
> ## Every one of the 18 is a no-op today and correct tomorrow, and the transition is a single commit
> ## somewhere else entirely — the one that first writes the column.

### The 18, and what each becomes the day something writes it

| query | today | the day soft-delete exists |
| --- | --- | --- |
| ⛔ `devices.sql:ListActiveWireGuardPeersForNode` | no-op | **a soft-deleted user's peers leave the tunnel** |
| ⛔ `devices.sql:ListActiveOVPNDevicesForNode` | no-op | **same, for OpenVPN** |
| ⛔ `devices.sql:ListActiveFullTunnelDevices` | no-op | **full-tunnel egress set changes** |
| ⛔ `policy.sql:ListActiveDevicesForOrg` | no-op | **the compiled artifact's device set changes** |
| ⛔ `policy.sql:ListGroupMembers` | no-op | **policy subjects disappear from rules** |
| `machine_credentials.sql` ×3 (list · assign · verification) | no-op | ownership + D21's verification gate |
| `users.sql` ×5 (get-by-email · get-by-id · set-password · mark-verified · set-status) | no-op | auth and account paths |
| `organizations.sql` ×2, `memberships.sql`, `invitations.sql`, `idpsync.sql` | no-op | rosters and counts |

⛔ **FIVE OF THE EIGHTEEN ARE DATA-PLANE.** They decide who is a WireGuard or OpenVPN peer and what the
policy artifact contains. **The first write to `users.deleted_at` is therefore a tunnel-affecting change**,
made by whoever implements soft-delete — who will be reading a column definition, not a peer list.

⚠ **And the direction is fail-closed, which is why nobody will notice until it happens.** A soft-deleted
user's tunnels *stop*. That is almost certainly the intent — but it will arrive as a side effect of a
column, not as a decision about a data plane.

### ⭐ AND AN ARMED GUARD IS ENFORCING IT — THE VACUITY CLASS, APPLIED TO THE GUARD INVENTORY

`TestQueriesScopeDeletedAt` (`apps/api/db/querylint_test.go`) scopes four tables: `devices`,
`k8s_services`, `organizations`, **`users`**. For `users` it is **an armed guard requiring a predicate that
does nothing** — it refuses any new query that omits `deleted_at IS NULL`, protecting against a state the
product cannot currently reach.

> ## **A GUARD THAT ENFORCES A NO-OP CANNOT FAIL FOR THE REASON IT EXISTS.** *Could this check have failed?*
> ## — for `users`, not today, and not by any input the product can produce. It is inventory that reads as
> ## coverage.

⚠ **The guard is still RIGHT, and that is what makes it hard to see.** It is pre-arming the fleet, which is
exactly what you would want if soft-delete is coming. **But its greenness is evidence of nothing**, and the
two `lint:allow-deleted` annotations written this epic (`ListMachineCredentialsForOrg`,
`ListNodeOwnerEmails`) argue carefully about soft-deleted users — **a state that has never existed.** The
reasoning is sound and untested by construction, and a reader cannot tell which.

### Not fixed

Whether the column is wired up or removed is a product decision. ⛔ **What this row buys is that the day
someone writes it, the blast radius is already counted: 18 predicates, 5 of them on the data plane.**



---

## ⚠ 6 — CORRECTION: THE "Talking:" ROW NAMED A LOCATION THAT DOES NOT EXIST

**Status: CORRECTED 2026-08-04 at EPIC 15 walk. The item was carried as three claims; none is true of the
current build.**

Carried as: *registered on Gateways* · *seen on Settings* · *absent from source*. Resolved by asking **which
claim is true**, rather than by hunting for the string:

| where | occurrences of `Talking` |
| --- | --- |
| `apps/web/src`, `apps/client/src`, `packages` | **0** |
| the **SERVED** bundle (`index-BnNTvxeh.js`, fetched from the running stack) | **0** |
| the entire repo, excluding `node_modules` / `.git` / `dist` | **0** |

⛔ **IT IS NOT IN THE PRODUCT.** Either a string removed by an earlier change, or **never ours** — a browser,
extension, or other application's chrome seen over the top of the screen.

> ## **A REGISTER ROW THAT NAMES A LOCATION IS A PROMISE THE NEXT PERSON WILL TRY TO KEEP.** "Registered on
> ## Gateways" sends someone to a file to find something that has never been there, and when they fail they
> ## will assume they looked wrong rather than that the row was.

**The honest row: sighted, unlocatable in the current build, cause undetermined.** ⚠ Not closed — a sighting
is evidence of something. What is closed is the claim about *where*.

---

## ⛔ 7 — `GET /api/v1/organizations` RETURNS `[]` FOR A MACHINE PRINCIPAL

**Status: OPEN. Found inside a PASSING leg (EPIC 15 walk Leg 1), 2026-08-04. Registered, not fixed.**

A machine principal authenticates, and the endpoint whose entire purpose is enumerating organizations
returns an **empty array** — while every org-scoped read works normally.

**Measured on the wire, same token, immediately after a successful assignment:**

| call | result |
| --- | --- |
| `GET /api/v1/organizations` | **200 `[]`** |
| `GET /api/v1/organizations/{id}` | 200, real org row |
| `GET /api/v1/organizations/{id}/members` | 200, real roster |
| `GET /api/v1/organizations/{id}/resources` | 200, real resources |

**The cause is a design decision meeting a handler that predates it.** `ListOrganizations` resolves via
`ListOrganizationsForUser(p.UserID)` (`handlers.go:171`), and a machine principal has `UserID == uuid.Nil`
**by design** — D4 keeps a machine out of the identity-binding subject space. Its org membership lives in
`Roles map[orgID]string`, which this handler never consults.

> ## **D4'S SEPARATION PRODUCED A HOLE NOBODY CHOSE.** The decision was right and its consequence at this
> ## handler was never asked about. An operator can read everything *inside* an org it cannot discover it
> ## belongs to — so any client that bootstraps by listing orgs gets an empty list and concludes it has none.

⚠ **AND IT IS THE FIRST ABSENCE QUESTION AGAIN** — *what can this principal not do that the API allows?* —
arriving through a principal kind rather than a screen. Same shape as row 2's `orgs[0]`, different cause.

**Not fixed in the walk.** The obvious repair (resolve from `Roles` when `UserID` is nil) is a handler
change with its own blast radius across every principal kind, and this walk changes no code.

---

## ⛔ 8 — FLOW LOGGING IS OFF BY DEFAULT, AND THE SCREEN CANNOT SAY SO

**Status: OPEN. Found at EPIC 15 walk Leg 3, 2026-08-04. Not EPIC 15's — S7.5.1's surface, measured here.**

**Two halves, and the second is the defect:**

| half | measured |
| --- | --- |
| **the default** | `TUNNEX_FLOWLOG_GROUP` defaults to **0 = OFF** (`apps/node/cmd/agent/main.go:213`). Flow logging is opt-in per gateway. **Unset on both gateways on this rig — including the compose stack's `node-agent`** |
| ⛔ **the absent signal** | Access Events renders an **empty page**, and **nothing anywhere says the gateway is not reporting** |

> ## **AN OPERATOR READING AN EMPTY ACCESS EVENTS PAGE CONCLUDES "NO ACCESS EVENTS". THE TRUE STATEMENT IS
> ## "THIS GATEWAY HAS NEVER REPORTED ONE."** Those are opposite claims about a security surface, and the
> ## screen renders them identically.

⛔ **THE DEFAULT CAN BE ARGUED; THE MISSING SIGNAL CANNOT.** Opt-in is defensible — nflog has a cost, and
S7.5.1 made it per-gateway deliberately. **What is not defensible is a screen that cannot distinguish
"nothing happened" from "nobody is watching."** This is the reassuring-empty class applied to the exact
surface that exists to answer *who reached what*.

⚠ **AND IT IS WORSE THAN AN EMPTY LIST**, because the page is *correct*. A load failure would at least be an
error. A disabled collector produces a page that is accurate, reassuring, and answers a question the operator
did not ask.

### How it was found — and why the deck's ordering mattered

Leg 3's **step 1 was an instrument check ranked above attribution**, and it **failed first**: zero events for
the walk's own traffic, despite an ALLOW whose kernel counter read `packets 1` and three DENYs.

> ## **AN EMPTY LOG READS IDENTICALLY TO A QUIET NETWORK *AND* TO A DISABLED COLLECTOR.** Three states, one
> ## appearance. Without instrument-first, the walk would have reported *"attribution does not work"* about a
> ## subsystem that was never switched on — a confident, specific, wrong finding.

**Not fixed.** The shape of a fix is a per-gateway *reporting* state on the screen ("this gateway is not
reporting flows") — which is a health signal, not a log entry, and belongs to whoever owns that surface.

---

## ⚠ 9 — gofmt REWRITES DOC-COMMENT CONTENT AND MADE A COMMENT FALSE

**Status: FIXED in place; filed because the seam is general. EPIC 15 walk, 2026-08-04.**

A comment explaining the peer-key guard described the old predicate as ``public_key <> ''``. **Go's
doc-comment reflow converted the two single quotes into a typographic `”`**, so a comment *about SQL* came to
read `public_key <> ”` — which is not a thing.

> ## **A FORMATTER THAT REFLOWS PROSE IS EDITING CONTENT, NOT LAYOUT.** `gofmt -w` is safe to apply blind
> ## because it moves whitespace — except in doc comments, where it also normalises quotes and backticks. So
> ## *"just run gofmt"* can silently change what a comment CLAIMS.

⛔ **AND CI CANNOT CATCH IT** — the file is *correctly formatted* afterwards. The only signal is reading the
diff, and the instinct after a `gofmt` red is to run `gofmt -w` and move on. That is what happened the first
time; the second time the diff was read.

⚠ **This is the comment-becomes-code seam crossed a third way.** The first two were a comment that *claimed*
a guarantee the code did not have, and a comment that named a hazard the predicate did not cover. This one is
a comment whose meaning was changed **by a tool**, with no human in the loop at all.

**Practice:** keep raw `''`, `""` and paired backticks out of Go doc comments when they are technical
content — write the meaning in words, or put the snippet in code.

---

## ⛔ 10 — STALE `kind='agent'` DEVICE ROWS ARE **PERMANENTLY AMBIGUOUS**, NOT MERELY UNFIXED

**Status: OPEN, and it cannot be closed by a script. Registered at S15.3, 2026-08-04.**

Before the enrolment marker (`0069`), `allocateAgentDevice` ran on `tok.IssuedBy.Valid` alone — so **every**
gateway enrolled with an issuer-carrying token acquired a `kind='agent'` device row **and a `/32` from the
org pool**.

**The node's kind is now answerable: `nodes.enrolled_kind IS NULL` = UNDETERMINED (ruled, §11.2).** ⛔ **The
device rows are not.**

### Why this is not a cleanup job

| fact | consequence |
| --- | --- |
| the row is **wrong** for a gateway | it should not exist |
| the **address is real** | a running node may be using it; removing it is an outage |
| ⛔ **nothing distinguishes the two cases** | a gateway that got the row by accident and an agent that has it correctly are **identical rows** |

> ## **THE FACT THAT WOULD TELL THEM APART IS THE ONE THAT WAS NEVER RECORDED.** The join token carried the
> ## operator's intent and did not store it; the token is consumed. **There is no predicate to write.**

⚠ **THE NEXT PERSON WILL REACH FOR A CLEANUP SCRIPT.** This row exists to say: *there is nothing to select
on.* Any `WHERE` clause that appears to separate them is separating on something else — creation time,
naming convention, current traffic — none of which is the fact in question, and each of which will be wrong
for some node.

### What is NOT ambiguous

- **Nodes enrolled after `0069`** carry `enrolled_kind` and are unambiguous in both directions.
- **The ambiguity does not grow.** It is a fixed, closed set: nodes enrolled between S15.2 and `0069`.

### Shapes, none picked and none cheap

1. **leave them** — the `/32`s stay allocated to rows that may mean nothing. Pool pressure with no signal.
2. **ask the operator per node** — the only way to recover a fact nobody stored. ⚠ Requires a surface, and
   an answer the operator may not have either.
3. **reconcile from behaviour** — infer from whether the node acts like an agent. ⛔ **Inference, which this
   epic has refused everywhere else**: the label is operator-asserted precisely because the product cannot
   detect what something is.

⛔ **Not folded into the UNDETERMINED ruling.** That ruling describes the **node** and costs nothing. This is
about **rows and addresses**, and every option here has a price.
