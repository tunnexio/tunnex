# EPIC 8 CLOSURE CERTIFICATION (2026-07-23, pre-merge, git-backed)

Certified at branch `story/S8.6-hub-ha` @ **`4c6c0ea`**. The census law's final exercise:
every claim below is git-backed or named as unproven. NO gate language for anything unbuilt.

## 1. Story census

| Story | State | SHA (git-backed) |
|---|---|---|
| S8.1 site model + ProtocolVersion gate | MERGED (PR#27) | `e8f6bef` |
| S8.2 route propagation (site-to-site) | MERGED (PR#28) | `2df19df` |
| S8.2c gateway zero-touch (DOCKER-USER) | MERGED (PR#30) | `b08d17b` |
| S8.3 site-management UI | MERGED (PR#29) | `e3ba76a` |
| S8.4 cross-site DNS | MERGED (PR#31) | `bb844f6` (on main, verified) |
| S8.5 routed subnets | HELD at walk-ready, in the S8.6 stack | rides this branch |
| S8.6 hub-HA + S8.6b transit + A3b | walk-ready + A3b built, THIS branch | `4c6c0ea` tip |
| S8.7 CIDR-src + conntrack-flush | built on its branch; re-rebase PENDING | `782d036` tip (pre-rebase) |

## 2. This-session fold census (all on story/S8.6-hub-ha)

| SHA | What |
|---|---|
| `28956a7` | Deck D Leg 10 walk artifact — C5 revoke PROVEN (peer removal + ping-death + banner); WF-1 wire-characterized; CP substrate census (782d036 re-addressed) |
| `3405b18` | Manual-command census — PD/BWF/entity-gated classes + proposed exclusions (founder-RATIFIED) |
| `a3439d7` → `4b2d3b8` → `6f45281` | A3b commit-one paper → decide-item rulings folded → fork ruling (ii) + D-A3b-1 amendment + P1 reclass |
| `8568416` | A3b build: v6 PoolCIDR + law red · spoke hub-primary pool AllowedIPs (failover-symmetric red) · far-grants both-enforce (2 reds) · relaxed pool Docker class (3 reds incl. key-space census) · PD-4 fabric text |
| `4c6c0ea` | Review F1 fold (hub pre-seeded, lazy admit deleted, nodeSet-seed census red) + WF-2 dashboard refetch on revocation edge |

## 3. Dispositions ledger (founder-ruled, all folded to paper)

- A3b scope FULL, shape (b) widen+far-grants (NOT NAT) — `docs/S8.6-decisions.md` A3b section
- D-A3b-1 (b) pool-CIDR grain + AMENDED condition (ZT-chain darkness, D-transit-3 uniform)
- D-A3b-2 both-enforce (hub + far chains adjudicate)
- D-A3b-3 pool as new key class in the ONE engine + census red; kernel-route rider DISCHARGED
  BY CONSTRUCTION (gateway wg0 addr = pool gateway/prefix → route exists structurally)
- D-A3b-4/5 settled-unobjected · Census RATIFIED (P1 hub-portion reclassified BWF)
- Review F1 FOLD structural (construction-over-convention, 3rd instance) · F2 REGISTER-ONLY
- WF-2 = desktop stale fetch, fold ridden on RevocationMonitor's existing signal
- Sequencing Option A: fix-all → merge train → smooth walk from main

## 4. Open-items ledger

**CLOSED (built + red-pinned, wire proof = the smooth walk):**
- WF-1 device-pool cross-site transit (`8568416` + `4c6c0ea`) — unit reds green; NOT yet
  wire-proven zero-touch (stated plainly; the smooth walk IS the acceptance)
- WF-2 revoked-device dashboard count (`4c6c0ea`) — UI proof rides the walk
- PD-4 fabric teaching text (pool return-route line, `8568416`)

**DEFERRED with named triggers (registered in the A3b paper):**
- Devices-on-SPOKES cross-site (per-device placement on hub's spoke peers — the churn class
  D-A3b-1 rejected). Trigger: first deployment walk with devices enrolled on a spoke.
- Single-site + non-site gateway device↔device Docker-dark (PD-3 residual — pool rides only
  the multi-site artifact, v6 blast-radius guard). Trigger: first non-multi-site
  device↔device walk.
- IPv6 pool (F2): the pool model is v4-by-construction, parity with every existing key class.
  Trigger: a v6-pool story.

**MOVED to the smooth walk (founder-ratified; the walk manifest carries them explicitly):**
Deck D Legs 1–9 · CW v5-confirm discharge (S8.3 Leg-6 substitute, fires on second-site bind)
· five harvest verdicts · Test A (HA failover under device traffic) · Test B (ZTNA enforcing
+ rules) · the census anti-checklist (every BWF/PD row proven dead; ONLY the two named
exceptions may touch a terminal).

**ENTITY-GATED (founder desk, not code):**
- macOS Gatekeeper "Malware Blocked" (unsigned app) — S6.5b signing; entity formation is the
  sole blocker. Recorded known-limitation-confirmed-live in the Leg-10 artifact.

**ENV-HYGIENE ledger (local only; CI clean-DB authoritative):**
- test-editions residuals @ `4c6c0ea`: TestCA*(3) + TestNodeEnrollmentLifecycle + TestOrg*(2)
  (documented seeded-DB class) + TestSessionlessRequestsAre401/UnbindSiteNode-500
  (**bisect-verified pre-existing at `6f45281`**, zero A3b overlap).
- Local migrate skew (DB v39 from an S8.7 checkout vs branch 0038 — superset, non-blocking).
  Both die at the smooth walk: env deploys from merged main, migrations run forward from
  main's chain.

## 5. Gate report @ `4c6c0ea` (sha-first)

generate-check ✓ · build-editions (open + enterprise) ✓ · test-node ✓ (7 pkgs, container,
incl. the 3 pool reds + key-space census) · test-helper ✓ + helper-crosscompile ✓ · web
typecheck ✓ + 143/143 tests ✓ + build ✓ · api suites (policyspec / nodes /
enterprise-policy, both editions) ✓ incl. all 8 new A3b reds + the nodeSet-seed census red ·
test-editions: green except the env-hygiene residuals named above.

## 6. Confidence statement

The A3b design is founder-ruled end to end, built decision-first, red-pinned at every layer
(version law, peer model, grant placement, Docker render, key-space + nodeSet censuses), and
review-folded with the one finding structurally eliminated. Residual risks, plainly:

1. **A3b is wire-unproven until the smooth walk.** Unit reds pin the artifact shapes, not
   packets. The walk's Leg-10-shaped fixture (device → remote-site behind-host, zero manual
   commands, both enforcing faces) is the acceptance — by design, on shipped code.
2. **The v6 interlock bites on upgrade skew:** a pre-A3b agent serving a multi-site org will
   REFUSE the pool-carrying artifact (deny-all, loud, `unsupported_policy_version`) until the
   agent image is released from merged main. Fresh-from-main walk env avoids it entirely;
   existing envs must pull the new agent. This is D1 behaving as ruled, not a defect.
3. **Both-enforce widens hub/far chains** with deduped entries compiled from existing grants —
   no new grant class, no wire-shape change below v6; the far counter is new evidence surface.
4. Deck D Legs 1–9 were never walked pre-merge — moved deliberately, named in the manifest,
   nothing silently dropped.

Certification stands at `4c6c0ea`. Next: S8.7 re-rebase → CI both-green per story →
Pawan's three words in train order (S8.5 → S8.6 → S8.7) → main → the smooth walk.
