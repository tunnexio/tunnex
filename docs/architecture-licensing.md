# Tunnex — Commercial / Licensing System Architecture

**Status:** PARKED (EPIC 12) — design only, not built until after the public beta.
**Model:** Offline signed license keys. No SaaS in the trust path.
**Markets:** US + India (launch).

---

## 1. The core principle — two trust domains

The single most important line in this architecture is the boundary between what **you** run and what the **customer** runs. That boundary is the entire compliance and sovereignty story, and everything else follows from keeping it clean.

| | **Tunnex-hosted infra** (you run) | **Customer deployment** (they run, self-hosted) |
|---|---|---|
| **Holds** | Billing + license/entitlement data only | ALL VPN traffic, WireGuard keys, device configs, user + org data |
| **Never sees / holds** | VPN traffic, keys, configs, user identities | — |
| **Dependency** | — | NEVER needs your infra to *function* (air-gapped deployments work fully) |

The license key crosses that boundary **exactly once**, by email, and is verified **offline** on the customer side. Your infra never reaches into the customer deployment; the customer deployment never *needs* to reach your infra to run.

> **Why this matters:** the buyers who choose self-hosted (sovereignty-bound EU/India orgs, air-gapped environments, compliance-heavy sectors, MSPs) chose it *specifically to avoid* a vendor's server being able to see or gate their VPN. A call-home validation model would reintroduce exactly the dependency they're fleeing. Offline keys preserve the differentiator — this is what makes Tunnex "the self-hosted Tailscale alternative with a real control plane" rather than a worse-positioned Tailscale.

---

## 2. Side A — Tunnex-hosted infra (the new, minimal piece)

This is the only hosted component in the whole product. It is deliberately small.

**Components:**

- **Landing / pricing page** — presents plans; entry points for "Upgrade to Enterprise" and "Start 30-day trial."
- **Payment** — **Stripe** (US) + **Razorpay** (India). Both markets from launch; Razorpay matters because Stripe's India support is limited.
- **License Issuance Service** — the core. On a paid purchase *or* a validated trial request, it generates a **signed license key** and emails it (support-flow delivery). It holds the **Ed25519 private signing key**, a **trial-per-domain** table, and a small DB of `{email, company_domain, tier, seats, issued_at, expires_at, license_id}`.
- **Renewal reminders / opt-in telemetry** — async, optional, and **non-blocking**. A lost connection here never affects a running customer VPN.

**What it stores:** email, company domain, tier, seat count, issue/expiry dates, license ID, payment records.
**What it never stores or sees:** VPN traffic, WireGuard keys, device configs, user identities, org data.

> **Compliance lever:** that data-minimization is the single biggest compliance win of the design. You cannot leak what you never hold.

**The private signing key is the crown jewel.** It lives only in the issuance service, isolated (ideally KMS/HSM-backed, at minimum an encrypted secret only the service can read). If it leaks, anyone can mint enterprise keys — this is the highest-value secret in the system.

---

## 3. Side B — Customer deployment (mostly what already exists)

This is the existing Tunnex stack — `docker compose` bringing up api, node-agent, web, nginx, Postgres, Redis — plus **one new component** and **one changed property**.

**The one new component — `LicenseManager` (inside the API):**

- Holds the **Ed25519 *public* key**, baked into the binary at build time (verify-only; the private key never leaves your infra).
- Verifies a pasted key's signature **locally / offline** — no network call.
- Checks expiry → **grace period + UI warning**, never a hard cutoff.
- Gates enterprise features **at runtime** (no rebuild, no restart).

**The one changed property — single binary, runtime-gated:**

The API becomes a **single binary with enterprise code compiled in**, gated at runtime by the license — replacing the current build-tag split where enterprise code is compiled *out* of the open binary.

> **This is a superseding decision (S12.1) with an accepted tradeoff.** "Paste a key, no rebuild" is impossible with the build-tag split — enterprise code isn't in the open binary, so there's nothing to unlock. Moving to runtime-gating (the GitLab-EE model) means the enterprise source ships *readable inside* the open binary, and the license check is patchable (it's open source). Piracy isn't prevented; honest commercial compliance is made easy, backed by license law. This invalidates the current `test-editions` "enterprise-not-in-open-binary" guard, which S12.1 replaces with a runtime-gating guard.

The rest of the deployment is unchanged: the node-agent still owns the data plane (wgctrl / WFP / pf, reconcile loop, kill-switch), clients still connect over WireGuard, and all org/user/device data stays on the customer's host.

---

## 4. The upgrade flow — end to end

1. Customer runs the **OPEN build** → clicks "Upgrade to Enterprise" / "Start 30-day trial" in the dashboard.
2. → browser to the Tunnex landing page → **trial:** DNS-TXT domain-ownership proof | **paid:** Stripe / Razorpay.
3. Issuance service checks trial-per-domain, **signs** a key `{domain, tier, seats, expiry}`, and **emails** it.
4. Customer **pastes** the key into the dashboard → `POST /admin/license` (owner-gated, audited, rate-limited).
5. `LicenseManager` verifies the Ed25519 signature **offline** (baked-in public key) + checks expiry.
6. Valid → enterprise features light up **at runtime**. **No restart. No rebuild.**
7. Expiry approaches → UI warning + grace period → lapses to open features. **The VPN keeps running.**

---

## 5. The offline-vs-revocability tension (a real design decision)

Offline verification and revocability pull against each other. Because the customer verifies locally with no call-home, **you cannot remotely kill a license they already hold** (a refund, a fraud, a terms breach).

The standard answer, which **S12.2** should adopt: **short-lived keys with reissuance.** A paid license is (e.g.) a 1-year key, renewed by reissuing; a bad actor simply doesn't get the next key. You trade instant revocation for sovereignty — the right trade for this positioning, but a deliberate decision to record, not an accident.

---

## 6. Security & compliance — US + India launch

- **Data residency (India DPDP Act 2023 / US state privacy law):** the structural win — customer VPN + user data never leaves their host; your infra holds only a small billing/license dataset. Where *your* issuance-service DB lives still matters for Indian customers' billing data under DPDP — a scoped S12.6 legal question.
- **Signing key:** highest-value secret — KMS/HSM-backed, rotation plan, key-compromise playbook.
- **Export control (US EAR):** distributing cryptographic software (WireGuard / OpenVPN) to two countries needs a classification/notification check — flagged for S12.6 legal review, not self-assessment.
- **License endpoint (`POST /admin/license`):** a new privileged surface — owner-gated, audited, rate-limited; auto-arms the existing 401-walk + RBAC guards.
- **Trial abuse:** DNS-TXT domain-ownership proof (reuses the S2.5 domain-capture verifier) makes "one trial per company" real rather than gameable.
- **Positioning guard:** offline verification preserves the "no SaaS in the trust path" differentiator — the reason a sovereignty buyer picks Tunnex over Tailscale.

---

## 7. Proposed epic breakdown (EPIC 12 — parked)

| Story | What it delivers |
|---|---|
| **S12.1** Edition Model refactor | build-tag → runtime license-gate; single binary; `LicenseManager`; replaces the `test-editions` guard. **Decide-before-code; supersedes S1.1.** The load-bearing story. |
| **S12.2** License key format + offline verify | Ed25519 signed key; entitlement schema; offline signature + expiry check; grace period; "paste your key" UI + `POST /admin/license`. Adopts short-lived-key + reissue for revocability. |
| **S12.3** In-app upgrade + trial affordance | "Upgrade to Enterprise" in the open build; "Start 30-day trial" request flow. |
| **S12.4** License issuance service | signing service (guards the private key); issues on paid/validated-trial; emails the key; **trial-per-domain** table. **Decide-before-code:** DNS-TXT proof (recommended, reuses S2.5) vs email best-effort. |
| **S12.5** Landing + payment | pricing/landing page; Stripe (US) + Razorpay (India); purchase → issuance. |
| **S12.6** Compliance pass | India DPDP + US privacy; data-residency review; ToS/privacy; US EAR export-control check. **Needs a real lawyer per market.** |

---

## 8. Sequencing note

**Do not build EPIC 12 until after the public beta.** An issuance service with no users to sell to is effort spent before it can pay off. The near-term path is unchanged: **finish S6.5a (Windows proofs) → S6.6 (zero-build deploy) → public beta → then EPIC 7+ with EPIC 12 inserted when monetization is wanted.** This document exists so that when you reach monetization, the decisions are already made and the sovereignty constraint is locked in.

**Two decisions still to confirm before S12 build:**
1. **Trial gating** — DNS-TXT domain proof (strong, reuses S2.5) vs email-domain best-effort (easy, gameable). *Recommended: DNS-TXT.*
2. **The runtime-gating tradeoff** — accepting that enterprise source ships readable in the open binary and the license check is patchable (the Option A / GitLab-EE model). *Indicated: yes — recorded here so it's owned deliberately.*
