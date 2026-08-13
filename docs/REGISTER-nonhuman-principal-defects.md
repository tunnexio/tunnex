# REGISTER — destructive server behaviours reachable by a principal the UI does not describe accurately

**Against the CURRENT product. None of these wait for EPIC 15.**

Three rows, one class. Each is a **server-side destructive or privilege-affecting behaviour**, each is
**reachable by or about a principal the interface misrepresents**, and each was found by reading the grant
table or the FK actions rather than by using the screen.

---

## ⛔ 1 — `operator` HOLDS `PermPolicyManage`, SO A NON-HUMAN PRINCIPAL CAN WRITE ITS OWN ACCESS RULES

**MEASURED** (`rbac.go`, `machine_credentials`): a machine credential's role is **fixed at `operator` at mint**
(D3), and `operator` holds `PermOrgView · PermPolicyView · **PermPolicyManage** · PermMemberList`.

> ## **THE SAME GRANT IS CORRECT FOR A GitOps OPERATOR AND INVERTS THE THREAT MODEL FOR AN AGENT.** A
> ## GitOps operator writing policy IS the product. A principal that can be talked into a request, and
> ## can then write the rule that permits it, is a compromised principal granting itself what it was denied.

### ⛔ RE-RATED 2026-08-04 — THE ENTRY WAS TRUE AND INCOMPLETE. THE EXPOSURE IS THE COMPOUND.

*"A machine principal can author its own access rules"* names ONE property. Measurement found **three, on one
credential**, and the compound is written down nowhere:

| property | measured at |
|---|---|
| can author its own access rules | `apps/api/internal/rbac/rbac.go:141` — `RoleOperator` holds `PermPolicyManage` |
| ⛔ **has NO OWNER** — `machine_credentials` has no `user_id` column at all | live schema: `id · org_id · name · role · token_hash · fingerprint · created_at · last_used_at · revoked_at` |
| **role fixed at mint**, not narrowable | `apps/api/internal/machineauth/service.go:83` |

> ## **A PRINCIPAL THAT CAN REWRITE POLICY, THAT NOTHING ATTRIBUTES TO A PERSON, AND WHOSE ROLE CANNOT BE
> ## NARROWED.** Each property is registered or measurable alone. **The compound is the actual exposure.**

⛔ **AND IT IS NOT ATTRIBUTABLE EVEN IN THE AUDIT LAYER.** `audit_logs` carries `actor_user_id` and
`actor_system` as **parallel columns, not a chain** — an event is attributed to a human OR a subsystem, never
"this system acting for that human". The operator's `X-Tunnex-Cause` (S10.2) supplies **which CR triggered
this**, which is provenance of the TRIGGER; delegation is provenance of the AUTHORITY. **The operator has the
first and not the second**, and the two are easy to conflate in prose.

**CENSUS-THE-MIRROR-SURFACE applies: the instance was found, the SET was not sized.** This entry recorded the
grant and stopped; nobody asked what else was true of the same credential.

⛔ **THE CONSEQUENCE FOR ANY FUTURE AGENT DESIGN, STATED HERE SO IT IS NOT DISCOVERED LATER:** the ownerless
machine principal is **not a design option to be permitted — it is the SHIPPED STATE**. `devices.user_id`
carries the per-user device cap, the "which human launched it" provenance, and any future delegation link;
`machine_credentials` has no equivalent, so a machine principal is outside all three at once.

**Why it is live today, not an EPIC-15 concern:** machine credentials ship now, the UI presents them as an
integration credential, and **nothing on that screen says the holder can author access policy.** S14.13
already registered that no revoke control ships over `managed_by_machine`; this is the other half — the
capability itself is under-described.

**Not fixed here** because splitting the role is a grant-table change with a generated mirror and a drift
guard, and it must not be guessed at in the tail of another story.

---

## ⛔ 2 — `CountOwners` COUNTS OWNER *ROWS*, NOT OWNERS WHO CAN SIGN IN

**PROVEN unrecoverable lockout** (S14.11): deactivate both owners and the last-owner invariant holds on paper
while nobody can sign in. Red written: `docs/probes/lockout_probe_test.go.txt`. The client `ownerCount` mirrors
the server deliberately and **must not be fixed independently**.

---

## ⛔ 3 — `managed_by_machine` IS A PRIVILEGE CHANGE DISGUISED AS A CLEANUP ACTION

Registered S14.13. An inbound FK with **`SET NULL`** means revoking the credential does not cascade-delete —
something referencing it goes null instead. **No revoke control ships over `managed_by_machine`** (founder
ruling) precisely because the blast radius is not described.

---

# WHY THESE THREE SIT TOGETHER

Each is a **server behaviour the UI does not describe**, and in each case the misdescription is about a
**principal or an invariant rather than a widget**:

| row | the principal or invariant | what the UI implies |
|---|---|---|
| `operator` + `PermPolicyManage` | a non-human principal | an integration credential, not a policy author |
| `CountOwners` | the last-owner invariant | that it protects sign-in access; it counts rows |
| `managed_by_machine` | a machine-owned object | that revoking is cleanup, not a privilege change |

> ## **THEY ARE THE SAME DEFECT AT THREE SITES: A CAPABILITY OR A GUARANTEE THAT IS TRUE OF THE DATABASE**
> ## **AND NOT TRUE OF THE SENTENCE THE OPERATOR READS.**

**All three are server changes with generated mirrors or proven reds already written. They belong to one
server story, not to three screens.**

---

# CLAIMS CUT FROM THE LOGIN PAGE — GATED, NOT DELETED

Both were rendered to every visitor before authentication. **A cut claim with no return condition is a claim
someone re-adds later with no argument to defeat**, so each carries the thing that would make it true.

| claim | why it was cut | RETURNS WHEN |
|---|---|---|
| ⛔ **"SOC 2 Type II certified"** | **MEASURED: zero mentions of SOC 2 anywhere in this repository outside the wireframe.** No audit, no report, no auditor. A false compliance claim shown to a stranger who cannot check it. | **there is a named auditor and a report to point at.** Not "when we start the process" — when the report exists. |
| **"SSO + SCIM enterprise ready"** | SSO ships; **SCIM is explicitly OUT of v1, deferred to S7.5.2b** (D4, `S7.5.2-decisions.md:131`). The false half is the specific standard named. | **S7.5.2b ships** (SCIM 2.0 inbound provisioning). SSO alone is already claimed, truthfully, in the current badge set. |

**Guarded mechanically:** `authhero.test.ts` refuses SOC 2 · SCIM · ISO 27001 · HIPAA · FedRAMP · PCI in any
rendered source, comments stripped and no file exempted. **Proven to fail** on a real rendered claim.

---

# ⛔⛔ THE DESKTOP CLIENT IS UNSIGNED — AND THAT BLOCKS DISTRIBUTION, NOT DEVELOPMENT

**Registered S14.20, ABOVE the UI story.** Measured across the whole client build path:

| what | state |
|---|---|
| code signing | **NONE.** `identity: null`, `CSC_IDENTITY_AUTO_DISCOVERY=false`. Ad-hoc (`codesign -s -`) only. |
| notarization | **NO script, no step, nowhere in the tree.** |
| entitlements | **NO file exists.** The only plist is the LaunchDaemon — a different thing, easy to mistake for one. |
| hardened runtime | **impossible without a real signature.** |
| auto-update feed | **none** (`updater.ts` is 19 lines). |

> ## **THIS IS THE ONE ARTEFACT WE SHIP THAT RUNS WITH ELEVATED PRIVILEGES AND INSTALLS A LaunchDaemon —**
> ## **and it is the one artefact nobody has signed.**

**THE FRAMING THAT MATTERS: the client cannot ship to anyone outside the building until it is signed and
notarized, REGARDLESS OF HOW GOOD THE UI IS.** S14.20 can complete in full and change nothing about that.

This is **S6.5b's deferral coming due**. Its named trigger was *public beta OR first outside-circle
distribution*; the trigger has not fired, so the deferral is still valid — but the item is now a **hard
distribution gate** rather than a nicety, and it should be read that way when beta is scheduled. Windows EV
additionally waits on legal-entity formation.

**NOT fixed in S14.20** (founder-directed). Registered so it is impossible to reach a beta date without
meeting it.

## ⚠ WITHDRAWN: the claim that it also blocks DEVELOPMENT

**This section previously said the signing gap stops a new developer running the client at all, on the
strength of a reported SIGKILL. THAT CLAIM IS WITHDRAWN — the SIGKILL was never reproduced.**

It came from a different clone on a ten-story-old branch with no client work and **no `Electron.app`
installed**. The binary was absent, not blocked. **The cause was inferred from the symptom's name**, and a
remedy with working commands was written around it — which reads as evidence and would have become the next
person's starting assumption.

**The DISTRIBUTION gate above is unaffected and stands on its own measurements** (no identity, no
notarization, no entitlements, no hardened runtime). **The development claim needs a reproduction on a
verified tree before it goes back in.**


---

## ⚠ 4 — `devices.user_id` IS `ON DELETE CASCADE` WHILE `machine_credentials.user_id` IS `ON DELETE RESTRICT`

**Status: OPEN, carried KNOWINGLY. Ruled out of S15.2's scope 2026-08-04; registered so it is not discovered
by whoever deletes a user.**

| table | FK action | citation |
| --- | --- | --- |
| `devices` | **`ON DELETE CASCADE`** — *"owner; no unowned peers"* | `0010_devices.up.sql:11` |
| `machine_credentials` | **`ON DELETE RESTRICT`** | `0065_machine_credential_owner.up.sql` |

> ## **THE TWO TABLES ARE NOT PERMITTED TO DISAGREE ABOUT WHAT AN OWNER'S DELETION MEANS.** One says
> ## *deleting a user silently deletes what they owned*; the other says *deleting a user is refused while
> ## they own anything*. Both are defensible. **Holding both is not a position, it is an accident.**

⚠ **The direction is not neutral.** RESTRICT is the deliberate S15.1 choice, made against the S14.12 cascade
class (*we ruled on a delete without asking what cascades*). **`devices` is the one out of step.**

### ⛔ AND S15.2 MAKES IT REACHABLE ON THE DATA PLANE

S15.2 ruled that an **agent is a `devices` row**, so an agent inherits **CASCADE**. **Deleting a user
silently deletes every agent they enrolled** — and an agent is a gateway, so that is **a tunnel that
disappears**, not a credential that stops working.

⚠ **D25 does not cover this and must not be read as covering it.** D25 rules that an agent is never *refused
at use* for an ownership reason. It says nothing about an agent being **deleted out from under a running
tunnel by a `DELETE` on `users`.** **Two different doors; D25 closed one.**

**Not fixed here by ruling** — changing a long-shipped FK on `devices` is its own change with its own blast
radius. Registered so the divergence is carried deliberately.
