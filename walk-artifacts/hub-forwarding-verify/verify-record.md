# Hub behind-host forwarding — VERIFY-THEN-FIX record (2026-07-19)

**Verdict: CLOSED verified-no-agent-fix-needed.** The registered "Zero-Touch violation / missing agent forward accepts" is EXONERATED. The remainder is policy expressibility (S8.7).

## Trace (cited, read-only)
- **Forward accepts** key on `daddr ∈ Routes`: agent `ip tunnex` chain (`egress_linux.go:345-397`, mesh L368-374) + WF-4 DOCKER-USER accept (`reconcileDockerForward` L633+, forward `daddr∈Routes` + return `saddr∈Routes`).
- **Hub `Routes`** = every OTHER site's subnets (`nodes/service.go:447-466`, skips `mySite`) → for hub+spoke, `{10.0.0.0/16}` (the spoke). The hub's OWN subnet (`172.31.0.0/16` = behind-hub SOURCE) is correctly NOT in Routes; `LocalSubnets` (the D2 src-hint) is not used in any forward accept.
- **The real gate** = the `ip tunnex` forward chain (`policy drop; ct established,related accept; …`). Under enforcing with 0 grants a NEW behind-hub→spoke flow hits `denyDrop` here — ZT working, not a gap.

## Box inspection (live, aws-gw 172.31.28.80)
- WF-4 `tunnex-site-fwd` accepts PRESENT + FIRING: `iifname != wg0 oifname wg0 ip daddr 10.0.0.0/16 … accept` (30 pkts) + the `saddr` return (30 pkts).
- **NO manual iptables rule** — `iptables -S FORWARD | grep ens5|wg0` empty. The registration's "load-bearing manual rule" was NOT present (likely swept by a reboot). No ZT-bypass hazard on this box. Step (a) "remove manual rules" = MOOT.

## Live proof — the fixture-fidelity last-quadrant leg
Genuinely-separate behind-hub host `172.31.17.64` → genuinely-separate behind-spoke host `10.0.0.4` (CP), cross-cloud, ZT enforcing.
1. **Baseline (0 grants):** `172.31.17.64 → 10.0.0.4` = **100% loss** — ZT denying correctly.
2. **Grant created in the modal:** Source type = **Site (a LAN behind a gateway)** → aws-site; Destination = Site → azure-site. "1 rule — default-deny active." *(Confirms the modal DOES expose site-as-source — `Access.tsx:636-640` — the S8.7 walk-read of "Group/User only" was incomplete.)*
3. **Rendered on the hub:** `ip saddr 172.31.0.0/16 ip daddr 10.0.0.0/16 counter accept` in `ip tunnex`.
4. **Re-test:** `172.31.17.64 → 10.0.0.4` = **0% loss, 139ms, ttl 62** (two forwarded hops — hub + spoke, the paper's packet-walk on live iron).

STOP condition (fail-with-grant) NOT triggered. Trace RATIFIED.

## Mesh stance (one sentence, for the record)
Behind-hub transit in **mesh** works grant-free by design (mesh = open); under **enforcing** it requires a grant by design (that's ZT working). The founder's blanket manual rule made enforcing behave like mesh — which is exactly why it must never persist.

## Disposition
- (a) MOOT — no manual rule to remove.
- (b) PROVEN — this leg banks the fixture-fidelity law's LAST uncovered quadrant (a genuinely-separate behind-HUB host originating cross-site). Registered into the S8.5/S8.7 walk inheritance.
- (c) hub-forwarding VERIFY-THEN-FIX CLOSES verified-no-agent-fix-needed; the enforcing-granularity remainder folds into **S8.7** (CIDR-source for /32 precision — site-source already covers the coarse case, live-proven above; second same-day founder demand).

## Spun-off finding (registered → S8.7 policy-lifecycle)
Expired/revoked GRANTS do not terminate ESTABLISHED flows — `ct established,related accept` honors an in-flight flow indefinitely (a chatty sender refreshes its own conntrack entry); only re-establishment is denied (founder-verified live: ping survived the expiry timestamp, a re-started ping was refused). Verify (cited): (a) S7.5.4's paper is SILENT on established-flow semantics (D2 addresses removing the /32 accept, not conntrack); (b) device revocation = PEER REMOVAL (`devices/service.go:496`) — a crypto-layer stop, effective, NOT the same class; the vulnerable class is grant-expiry/rule-deletion where the peer STAYS. The conntrack-kill seam is already RESERVED (flowlog/accesslog `DecisionTerminated` + RuleID) but NEVER built. Fix = scoped conntrack flush keyed on the removed rule's tuple on expiry AND deletion — NEVER a blanket flush.
