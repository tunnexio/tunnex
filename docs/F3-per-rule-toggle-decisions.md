# Feature 3 — per-rule enable/disable toggle — commit-one (decision-first, HELD for ruling)

**Registered** in `docs/POST-EPIC8-feature-requests.md`; ruled NEXT after the post-EPIC-8 fix lane
merged (`e860268`). A small win: let an admin **disable** a policy rule without deleting it, and
re-enable it later. Nothing built — this paper states the semantic + holds the two decide-items.

## The semantic (LOCKED, founder-stated)

A `disabled` boolean on `policy_rules`. The compiler **SKIPS disabled rules** — it does not delete
them, and it does not emit a deny. Under the **default-deny** model this means:

> **A disabled ALLOW-rule REMOVES its permission — it is "as if the rule weren't there."**
> It is NOT a deny-rule, NOT active blocking. Disabling an allow simply withdraws the grant; whatever
> that rule permitted is now default-denied (unless another enabled rule still permits it).

This is the ONLY honest reading in a default-deny system: there are no deny-rules to disable, so
"disabled" can only mean "this allow no longer contributes." A re-enable restores the grant.

**Load-bearing, not out-of-hash:** disabling a rule changes the compiled artifact (its `AllowEntry`
rows vanish), so the gateway's `CanonicalHash` changes → the new policy pushes → the gateway
reconciles and the flow stops. This is a real policy change that rides the normal push/desync
machinery — NOT out-of-hash plumbing. (Contrast the S8.x out-of-hash fields; the toggle is the
opposite — it MUST move the hash.)

## The seam (cited)

- **Model:** `policy_rules` (migration `0018_zero_trust` + `0030/0033/0035/0039` extensions). Add
  `disabled boolean NOT NULL DEFAULT false`.
- **Compiler:** `apps/api/internal/enterprise/policy/compiler.go` — `Compile(s Snapshot)` iterates
  `Snapshot`'s rules (each a `Rule{ID, SrcKind, DstKind, …}`) into `AllowEntry`s. The skip is ONE
  guard: a disabled rule contributes zero `AllowEntry`s. Cleanest placement = **filter at the query/
  snapshot boundary** (`ListPolicyRules…` excludes disabled) OR **skip in `Compile`** (a `Rule.Disabled`
  field, `if r.Disabled { continue }`). Lead-decide at build: query-filter (compiler never sees a
  disabled rule — the validator-input-filtering law says be careful, but here EXCLUDING a disabled
  rule from compilation is the INTENT, not a bypass) vs compiler-skip (compiler sees all, skips —
  more testable, the `Rule.Disabled` field is explicit in the snapshot). Prefer **compiler-skip** so
  the snapshot stays complete and the skip is a visible, unit-testable predicate.
- **Service:** a `SetPolicyRuleEnabled(ruleID, enabled)` alongside `CreatePolicyRule`/`DeletePolicyRule`,
  RBAC `policy:manage` (the existing rule-management perm — never a new perm for a capability, per the
  RBAC convention). Recompile + push rides the existing rule-mutation path (create/delete already
  trigger it).
- **API:** `PATCH /organizations/{orgId}/policy-rules/{ruleId}` `{enabled: bool}` (OpenAPI-first →
  codegen). RBAC mirror regenerates.
- **Web:** `apps/web/src/pages/Access.tsx` — the toggle affordance (placement = decide-item below);
  a disabled rule renders visibly dimmed/"disabled" so the list never lies about what's enforcing.

## Decide-items — RULED (founder, 2026-07-24)

- **D-F3-1 — audit on toggle: RULED YES, TWO distinct actions** `policy.rule_disabled` /
  `policy.rule_enabled` (NOT one action with an `{enabled}` field). Reasoning: a single toggle action
  with a state field would make "who cut off access at 3am" a METADATA query instead of a FILTER — the
  audit surface's job is answering that in one read. Two actions mirror create/delete, which is exactly
  the class this is (enabling/disabling access is policy-consequential), and the audit-viewer's existing
  action filters get them for free. Actor = the admin (the existing audit actor path).
- **D-F3-2 — placement: RULED the rule ROW, with a confirm on the DISABLE direction ONLY.** Row wins on
  discoverability (the toggle IS the feature; a modal makes it a setting, not an operation) and matches
  the NetBird pattern. But the fat-finger risk is **asymmetric**: DISABLE revokes live access instantly
  (compiler skips it, the push lands in seconds — the whole point), while ENABLE is additive + harmless.
  So: **enable = one click; disable = one click + a confirm that NAMES what it cuts** — e.g. "Disable
  nykaa → aws-server? Traffic matching this rule stops immediately." Destructive-action ceremony scaled
  to the blast radius — lighter than type-the-name (this is reversible), heavier than nothing.

## Hash / version classification (D2-checklist row, argued explicitly)

Disabling a rule changes the compiled artifact's **content** (its `AllowEntry` rows disappear) →
therefore **IN-HASH** → therefore an **ordinary desync-free push** (the gateway sees a new
`CanonicalHash`, reconciles, the flow stops within a push cycle). It rides the SAME machinery as
create/delete — no special path. **NO version bump:** the *shape* of `AllowEntry` is unchanged — only
*which entries exist*. `ProtocolVersion` / `RequiredVersion` are untouched; a disabled rule is not a
new artifact capability, just fewer entries. (Contrast S8.x content-derived version bumps, which added
NEW fields to the artifact; this adds none.)

## Reds (RULED — the acceptance set)

- **compiler:** a disabled rule produces ZERO `AllowEntry`s → the gateway artifact drops those grants →
  default-denied. Red over `Compile`: same snapshot with one rule disabled = the compiled output equals
  the snapshot-minus-that-rule, byte-for-byte.
- **re-enable:** flipping `disabled` back → the `AllowEntry`s reappear → flows restored (equals the
  all-enabled snapshot).
- **hash moves + NO version bump:** disabling changes `CanonicalHash` for the affected node (real policy
  change, in-hash) AND leaves `RequiredVersion`/`ProtocolVersion` unchanged (only which entries exist,
  not the artifact shape). A red on both halves.
- **audit — TWO distinct actions:** disable emits `policy.rule_disabled`, enable emits
  `policy.rule_enabled`; a disable-then-enable cycle leaves two DISTINCT audit events (not one toggle
  action with a flipping field).
- **disable-confirm copy (web):** the confirm renders the rule's OWN subject→destination (no generic
  string) — e.g. "nykaa → aws-server", derived from the rule's src/dst, never a placeholder.
- **RBAC:** a member without `policy:manage` gets 403 on the PATCH (no new perm invented).

## Sequence

This paper (HELD) → founder rules D-F3-1 (audit) + D-F3-2 (placement) → build (migration + compiler
skip + service + PATCH endpoint + web toggle) → gates (both editions; the compiler skip is
edition-relevant — the open build has no policy engine, so the toggle is enterprise-surfaced but the
column + API are edition-independent scaffolding) → targeted review only if it grows past the one-guard
compiler change. Then EPIC 9 (OpenVPN) commit-one, fresh sitting.
