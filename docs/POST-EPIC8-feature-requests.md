# Post-EPIC-8 feature requests (founder, 2026-07-23) — REGISTERED, not started

Queued AFTER the WF-A/WF-B/WF-C work + the combined box-walk. Both decision-first (commit-one
paper before code). UX target: NetBird's modals (founder screenshots). DO NOT START either until
the box-walk is clean.

## Feature 1 — port-scoped resources (custom ports under TCP/UDP, not protocol-all)

Target UX: NetBird's resource modal — protocol TCP/UDP + a multi-port field (e.g. 443, 22).
Completes the 5-tuple precision the S8.7 /32-source work began.

**LEAD VERIFY (read-only, cited — run BEFORE the paper, sizes the story):** does the resource
model + compiler ALREADY carry/emit port-scoped rules? The Access UI's "CIDR : protocol : ports"
label + `policyspec.AllowEntry{PortLow, PortHigh}` (already in the wire) suggest ports exist in
the model — so is this UI-ONLY (surface the existing port grain), or model+compiler+UI? The verify
answer sizes it.

Decide-items to hold: port-LIST vs RANGE vs both · validation (1–65535) · how ports render in the
rule row.

## Feature 2 — per-rule enable/disable toggle

Target UX: NetBird's per-policy switch. Mechanism: a `disabled` boolean; the compiler SKIPS
disabled rules without deleting them.

**SEMANTIC (must be stated explicitly in the paper):** a disabled ALLOW-rule REMOVES its
permission under default-deny — it is NOT a deny-rule, NOT active blocking; disabling = "as if the
rule weren't there."

Decide-items to hold: audit on toggle (founder lean: YES — enabling/disabling access is
policy-consequential, same class as create/delete) · toggle on the ROW vs in the Edit modal.

Reds (for the eventual build): disabled → ZERO emission → default-denied · re-enable → emission
restored → flows · toggle audited.

## Helper-protocol hardening pass (WF-A slice-3 review — deferred defense-in-depth)

Registered from the WF-A undiscounted review (dispositions #4, #6). None is a live defect —
each is guarded upstream AND/OR downstream today. Ride ONE future helper-protocol hardening pass:

- **#4 — `b64ToHex` length check** (`apps/helper/wgcommon.go`): decodes base64 without asserting
  32 bytes. Every caller is `validKey`-guarded upstream (tunnel_up + set_gateway_peer via
  `ValidateRequest`; set_allowed_ips' peer key is the validated Up config) and wireguard-go
  rejects a bad-length key downstream. Add `if len(raw) != 32` as belt-and-suspenders.
- **#6 — `set_allowed_ips` CIDR envelope validation** (`apps/helper/protocol.go` `ValidateRequest`):
  the `AllowedIPs` list is not CIDR-checked at the envelope; invalid CIDRs reach the uapi and are
  rejected there. PRE-EXISTING (S8.5), not WF-A. Add a `netip.ParsePrefix` loop mirroring
  `TunnelConfig.Validate`.

TRIGGER: next helper-protocol change touching the uapi/validation surface (natural home for both).

## CP endpoint carve-out — multi-IP CP (WF-A slice-3, registered)

The D-WFA-4 CP carve-out pins ONE resolved IP (host-route + pf pass), exactly like the WG endpoint.
A CP behind a rotating/multi-IP load balancer could resolve to a different IP than the one pinned
→ the control channel's escape path misses. v1 assumes a single stable CP IP (true for the walk +
single-region deploys). TRIGGER = multi-region CP / CP behind a rotating LB. Fix candidates: pin the
full resolved set, or a CIDR pass for the CP's published range, or a CP-provided stable anycast IP.

## Feature 5 — DEVICE source kind for Access rules (founder-walked, registered 2026-07-24)

Founder tested mobile WireGuard (static config, split + full tunnel, device approval, ZTNA enforcement
— all working) and found **"give THIS specific device access to X" is unexpressible**: source kinds
are Group / User / Site / CIDR only. Workarounds today: User source (ALL of that user's devices) or
CIDR with the device's pool /32 (address-bound — **breaks on re-enrollment**).

**Proposed commit-one shape:** `src_kind='device'` + `src_device_id` on the existing enum seam. NOTE:
`src_device_id` already exists as a **v3 OBSERVABILITY field** (S7.5.4) — verify whether it can carry
the policy meaning or needs a DISTINCT column (observability vs enforcement must not silently merge).

**The design risk that makes this a PAPER, not a quick add:** a device's /32 is **reassignable**
(proven live — a revoked device's address returned to the pool and was re-allocated). So the rule must
bind to **device IDENTITY**, and the compiler must resolve identity→CURRENT-/32 at compile time (the
User-source pattern), **never to a snapshotted address**.

**Reds to spec:** a rule follows the device across a re-enrollment (new address, same device → grant
follows) · a DIFFERENT device inheriting the old address does NOT inherit the grant (the reassignment
trap, immortalized) · a revoked device → grant compiles to nothing.

**Sequencing:** AFTER EPIC 9, alongside the registered policy-granularity family (Feature 2 port-scoped
resources, the per-rule toggle) — same family: making rules say exactly what the operator means.
