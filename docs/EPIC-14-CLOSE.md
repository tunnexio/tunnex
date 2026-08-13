# EPIC 14 — UI redesign. CLOSING ENTRY.

**Most of what came out of this epic was not about the screens.**

---

# 1. SHIPPED

**TWELVE SCREENS:** Sites · Gateways · Routed Ranges · Kubernetes · Devices · Users · Access Policies ·
Org Settings · Directory sync (IdP) · Invitations · Audit Log · Dashboard.

**PRIMITIVES (S14.1–S14.3):** design tokens + theme system · layout shell (nav, responsive grid, breakpoints) ·
command palette + keyboard routing · toasts with undo · semantic table/list primitives · data visualization.

**TEST TIER:** ~730 web tests from ~400, plus the practice that produced them — **every fix ships with a red
proven to fail without it**, and mutation sweeps that report *applied / survived / stale anchors* rather than a
bare pass. Census tests with **vacuity floors** (they caught two of my own broken matchers). Both-arm
assertions on anything with a default.

**CI SPLIT:** the diff classifier was measured and found to be a constant — **17 of 18 runs `go=true`, 16 of
them from `fixtures.sql` alone**, because a cumulative diff makes any classifier sticky. `gates` was 498s with
**382s already conditioned and never skipping**, plus a 59s codegen guard conditioned on nothing. Now narrowed,
with the embed census taught the exemption and the deletion guard that makes it safe.

---

# 2. WHAT STAYS OPEN — one line each, with its register

| item | register | state |
|---|---|---|
| ⛔ **Missing-audit-write class** | `S14.14/S14.16-decisions.md` | **THREE instances.** `UnmapGroup` + `SuspendDomainClaim` FIXED (S14.15); **four writers still unattributed** — `hub_set.promotion`, `hub_set.failback`, `hub_set.membership`, `node.enrolled` use the human insert path with a NULL actor. One server story. |
| ⛔⛔ **Non-human principal, three sites** | `REGISTER-nonhuman-principal-defects.md` | **`operator` + `PermPolicyManage` RANKED FIRST — live today**, presented as an integration credential with nothing saying the holder can author access policy · `CountOwners` counts rows not sign-ins (proven lockout, red written) · `managed_by_machine` is a privilege change disguised as cleanup. |
| **`Kubernetes.tsx:403`** | S14.12 handoff | placeholder-glyph regression; S14.8's pass did not clear it. |
| **51 omitted-and-read mocks** | `docs/probes/mock-census-output.txt` | known false-positive floor recorded. |
| **Remaining unreachable verbs** | `S14.14-decisions.md` §9 | **eleven → one**: `revokeCliCredential`, blocked on its destination screen. |
| **D1 / D1b / D2** | S14.11 | MFA column · AUTH column (type-level tripwire armed) · per-member group edges. |
| **Cascade-preview endpoint** | S14.12 | so a delete confirm can name counts the server owns. |
| ⛔ **S14.12's three items** | `S14.12-decisions.md` | mode toggle as a real switch with blast-radius confirm · two-column layout · `SOURCE · DESTINATION · STATE` headers. **The section is OPEN.** |
| ⛔ **Org Settings' items** | `S14.13-decisions.md` | VERIFIED-is-not-terminal (no surface) · no delete verb + global verified index (cross-tenant) · the write-only-state trio · machine-credentials shed blocked on a destination. |
| **Error-string register sweep** | `S14.15-decisions.md` §2 | probe the register from messages that ASSUME a read exists — `invite_pending` said *"resend or revoke it"* since S1. Not run. |

## ⛔ THE HARNESS — ACCEPTED-PROVISIONAL, **NOT OWED**

**Founder-ruled S14.15, after five deferrals and one withdrawn measurement.** Provisional DOM assertions are
the **accepted position**; the `settingswiring` leak is a **registered limitation**. Artifact grep is the named
instrument and **that is a complete claim**, not shorthand for a debt. The two `it.fails` reds remain the armed
signal. **Nobody schedules it.** Recorded as a decision because a deferral that keeps being renewed is a
decision nobody admits to making.

---

# 3. ⛔ THE POINTER-BYPASS RULING — **CLOSED**

The rule was written mid-epic after archaeology found **8 direct-to-`main` pushes, one per merge, every one
forced by a checkpoint that could not be written before the merge** — *a commit cannot contain its own hash*.

**MEASURED ACROSS THREE MERGES UNDER THE NEW RULE:**

| merge | content tip | bypass count |
|---|---|---|
| S14.13 — PR #61 | `e6e23c2` | **8** |
| S14.14 — PR #62 | `21537de` | **8** |
| S14.15/16 — PR #64 | see PLAN | **8** |

> ## **THREE MERGES, ZERO INCREMENTS. THE RULE IS CLOSED.**

**Nothing is left.** The mechanism is not a convention that needs remembering: the content tip is **knowable
while the PR is open**, so the checkpoint lands inside the PR by construction and there is no path that
requires a push to `main`. **The one thing that recurs is a self-inflicted variant** — writing more content
*after* the checkpoint, which makes the pointer name a commit with content behind it. That happened once
(S14.14) and was corrected in-PR, not by a bypass.

---

# 4. WHAT THE EPIC ACTUALLY PRODUCED

The screens were the occasion. **The findings were mostly about how we check things**, and the ones worth
carrying are in `docs/laws.md`:

- **A design can only be wrong about what it DEPICTS** — and then S14.14 found it can be wrong about a
  **MECHANISM it depicts confidently**: the wireframe's DNS instruction was wrong in both halves, and a
  wireframe diff would have MATCHED it.
- **A correctly-run check aimed at the wrong subject looks like evidence** — the artifact grep proved the
  panels reached *an* artifact, the one nobody was looking at.
- **A cumulative diff makes any classifier sticky.**
- **`needs:` for an output is also a gate on success** — three integration jobs reported *skipped* exactly
  when `gates` went red.
- **A fallback that reuses a meaningful term hides the case it falls back from** — filed in the morning,
  committed by me in the afternoon.
- **A client-invented value where a server fact belongs** — S14.11 invents absence, S14.16 invents presence;
  same mechanism, inverted symptom.
- **When re-testing an old failure, pin the tree it was written against** — a false refutation that reordered
  a founder decision.
- **A number quoted from an old registration outlives the thing it counted** — "eight screens" for several
  stories after it was two.
