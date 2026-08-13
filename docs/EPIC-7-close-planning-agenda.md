# EPIC-7-CLOSE PLANNING SESSION — AGENDA (paper; HOLD until the session)

**Entry state:** EPIC 7 (Zero Trust Access) COMPLETE — S7.1 · S7.2 · S7.3 · S7.4a · S7.4b · S7.4c all MERGED
(S7.4c = PR#21, sha `8ad71cd`; S4.5 + S4.5b flipped SUBSTITUTE→SATISFIED). No new story branch opens until
this session locks the order. **Expected first artifact AFTER the session = S7.5.1 commit-one.**

**Purpose:** turn the accumulated paper (ledger batches 1–3 + the replan proposal) into a LOCKED epic order,
settling the two user-owned decisions. Nothing here is pre-decided; the recommendations are flagged as such.

---

## Part A — Ledger disposition (keep / drop / reshape each)

**Batch 1 — ZTNA coverage + gap ledger** (PLAN.md §"ZTNA COVERAGE + GAP LEDGER", recorded during S7.4b).
Items 1–4 (access-visibility gaps) → SUPERSEDED-BY-INCLUSION into S7.5.1–S7.5.4. Items 6–8 (EPIC 9/10
ZT-coverage guarantees) stand UNCHANGED. **Ask:** confirm the supersede + that 6–8 ride EPIC 9/10.

**Batch 2 — ZTNA competitive scope** (PLAN.md §"LEDGER BATCH 2"; the proposed **EPIC 7.5**).
- S7.5.1 flow/access logs · S7.5.2 IdP-group sync + SCIM · S7.5.3 posture v1 · S7.5.4 per-user + temporary
  grants (**window-extensible**, recorded constraint). Target segment = self-hosted/WireGuard
  (Tailscale · Twingate · NetBird · Headscale), NOT the Zscaler tier. **Ask:** confirm the four S7.5.x scopes +
  that flow-logs-first (S7.5.1) starts first under every path.

**Batch 3 — pre-launch** (PLAN.md §"PRE-LAUNCH LEDGER — BATCH 3", 10 items).
- Named: **MFA/TOTP (STORY-REQUIRED, own story)** · **SIEM export → folds into S7.5.1 DoD** ·
  **mobile clients → EPIC M** · **distribution workstream** (subsumes S6.5b's trigger).
- **6 items to ENUMERATE live** — captured this session, not fabricated. **Ask:** enumerate the balance; place
  each (own story / DoD ride-along / workstream).

---

## Part B — Replan proposal (confirm or flip)

Proposed order:
**EPIC 7 (done) → EPIC 7.5 (ZTNA competitiveness) → BETA BUNDLE → BETA → EPIC 8 (site-to-site) →
EPIC M (mobile) → EPIC 9 (OpenVPN) → EPIC 10 (k8s) → EPIC 11 remainder.**
- **EPIC 12 (licensing) trigger = first paying-customer INTENT** (build-on-intent; supersedes the parked
  "post-beta" note — see [[tunnex-epic12-licensing]]).
- Consequence acknowledged: EPIC 8/9/10 slide right ~one epic; the 9/10 ZT guarantees (batch-1 6–8) unchanged.

---

## Part C — The two USER DECISIONS (session must settle; NOT pre-decided)

1. **Beta timing.** Recommended: beta AFTER Tier 1 / EPIC 7.5. Alternative: beta at EPIC-7-done while building
   7.5 during beta. (Flow-logs-first is common to both, so S7.5.1 starts regardless.) → **user confirms or flips.**
2. **EPIC 7.5 insertion + EPIC M (mobile) confirmation.** Insert 7.5 before EPIC 8? Add EPIC M as a first-class
   epic (iOS/Android WireGuard clients)? → **user confirms.**

---

## Outputs of the session (definition-of-done for planning)
- A LOCKED epic order (Part B resolved via Part C's two decisions).
- Every batch 1–3 item dispositioned: own-story / DoD-ride-along / workstream / dropped.
- Batch 3's remaining 6 items enumerated.
- Green light for the S7.5.1 commit-one as the first post-session artifact (decision-first, per protocol).
