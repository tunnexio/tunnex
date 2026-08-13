# Deck D — EPIC 8 close, fresh-eyes UI journey (S7.5.5 founder-walk discipline)

Pawan signs up CLEAN on a fresh org, walks the complete surface as a new customer.
Numbered journey · expected-vs-observed · screenshots · WF-numbered findings ·
NOTHING rationalized as "probably fine." Findings HELD; no fold mid-walk unless
merge-gating. CP at 782d036 (40.65.63.141).

## C-leg carry-ins (recorded before Deck D)

- **C4 (flush-fail visibility) = SUBSTITUTE ACCEPTED.** Live reactive-EPERM induction
  is self-defeating (CAP_NET_ADMIN is shared with wg0/nft → dropping it breaks the
  gateway → a higher-priority kind MASKS conntrack_flush_unavailable, the lowest-
  priority kind; the only clean induction is `rmmod nf_conntrack`, too risky on the
  live cross-cloud topology). Proven instead: the flag→kind + masking/priority
  (unit, policyhealth_test.go), the full wire traced+compile-verified (egress flushErr
  → ConntrackFlushFailing → main.go:311 report → service.go → policyhealth kind → UI),
  the happy path live (C1/C2). Trigger for the reactive induction = first genuinely
  conntrack-restricted / fault-injection-capable env OR a later epic-close walk. The
  ABSENT-WHEN-HEALTHY half is captured live in Leg 7 (no flush-degraded badge).
- **C5 (device-revoke exemption)** rides Deck D **Leg 10** (client connect): revoke a
  device with a live flow → the flow dies by PEER REMOVAL (crypto-death, `wg show`
  loses the peer) — no conntrack semantics, proving the D6 exemption.

## The journey (mandatory legs)

1. **Onboarding** — fresh signup → org creation → landing. Expected: clean signup,
   RequireOrg, empty-states guide to the first action. Observe the first-run funnel.
2. **First gateway** — the EMITTED install command (the zero-touch first impression).
   Expected: dashboard emits a copy-paste enroll command; running it enrolls a gateway.
   WATCH the registered `emitted-enroll-hardcodes-ghcr` finding — is the ghcr image a
   friction for a real new customer? (KEEP-DEFERRED/PROMOTE.)
3. **First site** — register a site, bind the first gateway.
4. **Second site** — register + bind a second gateway → FIRES the **CW v5-upgrade
   confirm LIVE** (S8.3 Leg-6 substitute discharging on its named trigger). Expected:
   the confirm names sub-v5 gateways OR shows clean (a fresh org's gateways are current,
   so likely CLEAN). SCREENSHOT either way — the confirm rendering on the trigger is
   the discharge.
5. **Subnets / approval** — advertise a subnet, approve it. Observe the approval funnel.
6. **Access** — Zero Trust enforcing (default-deny); create rules incl. a SITE rule and
   a CIDR rule (the modal, C3-proven). Observe rule legibility.
7. **Sites topology** — hub badges, health, the L1 byte counters rendering. C4 baseline:
   confirm NO conntrack_flush_unavailable / flush-degraded badge on healthy gateways.
8. **Hub-priority pinning** — the HA opt-in via the FIXED bind UI (D4): bind a 2nd
   gateway to a site (Bind reachable alongside Unbind), pin both → HA hub set forms.
9. **Users / Audit** — user management + audit log legibility (the failover events,
   membership changes readable).
10. **Desktop client connect** (if in scope) — connect a device; establish a live flow;
    run C5: revoke the device → flow dies by peer removal (`wg show` loses the peer).

## Harvest questions — founder-priority verdicts (KEEP-DEFERRED or PROMOTE from Pawan's
## own reaction, not our guess)

- **group-membership-no-UI** — can group membership be managed in the UI at all?
- **resource-no-port-field** — the resource add-form's protocol/port grain.
- **site-link-down-badge-names-which-peer** — the rematch finding 2 residual: does the
  badge say WHICH peer link is down (active hub vs demoted member)?
- **conntrack-kind-needs-a-badge** — does conntrack_flush_unavailable warrant a dedicated
  UI badge (vs a generic degraded state)?
- **standby-stale-flicker UI residue** — any residue of the old 90s flicker? (Should be
  GONE with the 240s window — confirm.)

## Verdict → dispositions → merge train

Deck D verdict + the harvest dispositions → then: re-rebase S8.7 onto the FINAL S8.6
tip (docs-only) → CI both-green per story → Pawan's three words IN ORDER: S8.5 → S8.6
→ S8.7.
