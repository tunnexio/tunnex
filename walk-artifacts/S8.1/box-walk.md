# S8.1 site-to-site — bounded box-walk (live wire)

Box: `ubuntu@Tunnex-dev-vm`, enterprise edition, migration v34, story branch `story/S8.1-site-model` @ `1ee169e` (agent temporarily pinned + reverted for Leg 1).
Org `01900000-0000-7000-8000-000000000001`, owner cookie jar `/tmp/owner.jar` (password-only; MFA reset).

Sites registered: **HQ** `019f6fd3-fb19-7aca-98bf-672a808d7814`, **Branch** `019f6fd3-fb35-7388-8ec7-2022c70c6cd0` (both `link_transport=wireguard`).
Live agent node: **demo-gw** `019f6fda-16e8-72ab-a99d-0998ffbcfdc5` (revived — see Leg 1).

---

## Leg 2 — site registration + binding operator-visibility

- `POST /sites` HQ + Branch → **201** each; `GET /sites` returns both (operator surface at the API).
- `POST /sites/{HQ}/bind {node_id: demo-gateway}` → **204**; `nodes.site_id = HQ` in DB.
- **Bounding recorded:** the node→site binding is **NOT surfaced in the nodes API** (`listNodes` has no `site_id` field — `site_id=<not-in-API>`). The binding is DB-level for S8.1; the operator-visible binding surface is **S8.3's UI**. Honest bound, not a gap in the shipped model.

## Leg 3 — approval + the ONE disjointness validator on the wire (+ negative)

The #1 story-end SECURITY fix (dropped the `a.Cidr != sub.Cidr` bypass) exercised live:

| step | result |
|---|---|
| HQ advertise `10.20.0.0/24` → approve | **204** (disjoint) → `site.subnet_approved` audit |
| Branch advertise **same** `10.20.0.0/24` → approve | **HTTP 409 `subnet_not_disjoint`** — the cross-site duplicate the bypass would have let through, now refused |
| NEGATIVE (refusal edge, first wire-observed) | Branch dup **stays `status='pending'`** — refused-but-still-pending, re-approvable once the conflict clears (design confirmed) |
| audit pair on the wire | `site.subnet_approval_refused` + `site.subnet_approved` (both 0034-minted actions) |

DB after: `10.20.0.0/24 | approved` (HQ) + `10.20.0.0/24 | pending` (Branch).

## Leg 1 — D1 fail-closed ProtocolVersion gate (real agent)

Method: real agent, local `MaxSupported=3` pin against the current v4 stack (per ruled method note).

- **Revive:** minted fresh join token (the agent had been enroll-looping 17h on a used token — `invalid_join_token`, a stale-enrollment box issue, NOT S8.1 and NOT infra). Re-enrolled clean: `agent_enrolled` → `backend:wgctrl` → `agent_ready`. Runtime healthy.
- **ACCEPT-half — PROVEN LIVE:** demo-gw at `MaxSupportedVersion=4` fetched + applied the org's v4-era desired-state → `degraded=False kind=healthy`, `last_seen` advancing. The go-forward accept on the wire.
- Pinned `MaxSupportedVersion=3` + rebuilt: agent stayed `healthy`. **Root cause (decisive):** `policy_surface_test.go:31` — *only ENFORCING nodes get a non-empty pushed policy*. demo-gw is a bare gateway in **no enforcing config** (this stack has no `policies` config; `policy_rules` empty), so `SetPolicy`'s `p != nil && p.Version > max` guard correctly skips. `healthy` = nothing to gate, **not** a gate miss.
- **REFUSE-half — NAMED SUBSTITUTE:** live refuse needs an enforcing node receiving a compiled v4 artifact; standing up enterprise enforcement (policy + rules + enforcement-node assignment + compile) is a separate walk, exceeds the S8.1 bounded budget. Refuse-half unit-pinned **both editions**: `TestInterlockOldMaxAgentRefusesSitesBump` (gated old-max agent + real v4 `Compiled` → deny-all + `RefusedVersion`), `TestUnsupportedPolicyVersionSurfaces` + `policyhealth_test` S8.1 rows (CP surfaces the kind; refused **outranks** apply-error + silent-desync).
- **Owed live-refuse trigger (PINNED):** S8.2's box-walk — S8.2 stands up cross-site route propagation on the wire, where a live gateway carries a compiled v4 enforcement artifact; the real refuse rides that walk. SUBSTITUTES ≠ SATISFIES.
- Box reverted to clean (`git checkout nodepolicy.go` → `MaxSupported=4`, rebuilt) → demo-gw re-accepts v4 (healthy).

---

**Verdict:** sites/subnets/disjointness + the #1 security fix + the refusal-stays-pending edge = LIVE. Version gate accept-half LIVE, refuse-half named-substitute. Walk SUBSTITUTES for the cross-site data-plane transfer (route propagation = S8.2's walk).
