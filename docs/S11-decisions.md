# EPIC 11 — Production Hardening — commit-one (decision record)

Paper before product code. Decide-items D1–D5 RULED (this record); nothing builds until the paper is signed.
Re-entered from `main` `c6cf811` (EPIC 10 / S10.2 GitOps operator MERGED).

## Acceptance criterion — BETA-READINESS, not a story count

The question EPIC 11 answers: **what breaks when a stranger runs this in production, unattended, for a month?**
— upgrades, backups, restarts, resource limits, log volume, cert/key rotation, disk exhaustion, clock skew,
partial failures, and the operational surfaces that make those diagnosable. A story list is the means, not the
bar.

## Verify pass — roadmap (S11.1–4, spec'd 2026-07-15) vs shipped

All four roadmap stories are **UNBUILT**: metrics/readiness (only `/healthz` + EPIC-0 structured logging exist;
no `/metrics`, no `/readyz`), backup/restore, rate-limiting + security headers (zero rate-limiting today),
docs+upgrade (Helm NOTES only, no upgrade procedure). **The genuine delta** (the roadmap is thin + a year
stale — the 4th commit-one running to find it):
1. **The CI security-scanning tier is not in the roadmap** (it names only SECURITY.md + an external pentest).
   CodeQL/govulncheck/Trivy/SBOM/cosign are net-new — publishable, cheap, entity-independent. The delta the
   plan misses hardest.
2. **Upgrade is under-scoped as a docs sub-bullet** — a procedure + compatibility contract + tooling, the
   epic's largest item.
3. **Leader election is registered, replicas=1 by ruling** (`tunnex-cp/values.yaml:64`). S10.1 shipped
   replicas=1-deliberate; the fix lands here.
4. **Resource + failure envelopes** — the roadmap names none.
5. **Logging shipped but has a diagnosability hole** — `internal_error` doesn't log the wrapped cause +
   request_id (ledgered S11-class during the audit-nil hotfix). Observability is finishing, not greenfield.

## Standing ledger — triage (the sitting's most valuable artifact)

**HARDENING (folds into EPIC 11):** swallowed-500 logging · audit-action typed registry · WF-OP-3 drift-Event ·
CP-HA/leader-election · SECURITY.md + vuln disclosure · CI scanning tier · rate-limiting + security headers ·
helper-protocol hardening (#4/#6) · audit-helper unification (M1b root) · env-hygiene/devcontainer + restore
the e2e signal · hostNetwork + NAT-traversal deploy notes.

**FEATURE (after beta, trigger-gated — carried explicitly, not silently):** FQDN resources · device-source
rules (Feature 5) · group-membership UI · OVPN liveness telemetry · conntrack-kill on grant change · WF-C L2
zombie auto-demotion · S8.6b Windows full-tunnel re-home · R-3b-2 operator poll→watch · enable/disable audit
human-only (trigger: CR gains `disabled`).

**DEAD (superseded/shipped):** **port-scoped resources (Feature 1) — SHIPPED in S10.3** (`policyspec.PortLow/
PortHigh` + the expose/resource form). Struck on evidence, not built twice — the 4th such catch.

---

## Decide-items — RULED

### D1 — Upgrade path: FORWARD-ONLY, stated in the contract. RULED.

Downgrade is REJECTED — supporting it taxes every schema migration with a tested reverse path and every
artifact version with a backward transform, an enormous ongoing cost for a case customers resolve in practice
by **restoring a backup**. Forward-only + restore-from-backup-as-rollback is coherent and honest, and it makes
**D2 load-bearing** rather than optional. Conditions:
- **N and N-1 agent support is a CONTRACT, not an accident** — and the RED is what makes it true: an N-1
  agent's compiled artifact still compiles/loads against the N control plane (a version-window compile red,
  not a doc claim). The `ProtocolVersion` fail-static (v7) is the FLOOR; the contract is the ceiling.
- **Rolling procedure:** migrate DB → roll the CP → agents reconcile. **Never a flag-day.** (A CP outage
  never kills running tunnels — already true; the upgrade leans on it.)
- **`tunnex preflight`** checks the compatibility window BEFORE the operator commits the roll.
- Largest slice; sequenced LAST (needs D2–D4's surfaces).

### D2 — Backup/restore: the TRUST-AFTER-RESTORE invariant is the whole point. RULED.

Catastrophic case that must be **unreachable by accident**: if the master key is regenerated on restore, every
sealed column is unreadable AND the CA is lost — agents pin the CA, so the entire fleet is orphaned and every
gateway must re-enroll. Therefore:
- The backup artifact **includes the sealed master-key material + the CAs + policy + per-gateway WG
  private-key state** (node-agent state).
- The restore procedure **fails LOUD if the master key doesn't match** — the **"set-but-broken is fatal,
  never regenerate"** law (S10.1) applied at the restore seam. Never silently re-generate.
- **Wire proof (the epic's 2nd-most-important leg, after upgrade):** restore a CP from backup and prove an
  **existing agent still connects, unchanged** (the fleet is not orphaned).

### D3 — Observability floor. CONFIRMED.

- **Metrics DERIVED from the health kinds already shipped** — `apply_failing`, `desync_unknown`,
  `site_link_down`, `unsupported_ver`, `conntrack_flush_unavailable`, `hub_forwarding_not_reconciling` —
  NOT a parallel vocabulary. One truth, two renderings (the pattern this project lands on every time). Fleet
  metrics = the health kinds counted.
- **RED/USE for the CP's HTTP and DB surfaces**; `/metrics` (Prometheus) + `/readyz` on CP + node-agent.
- **Swallowed-500 fix:** the `internal_error` path logs the wrapped cause WITH the request_id
  (diagnosis-from-logs, not from a repro) — small, closes the ledgered hole.
- Log-LEVEL control; the audit-action typed registry; the operator drift-Event (WF-OP-3).

### D4 — Leader election NOW, not defer. RULED.

Replicas=1 is a documented limitation today; it becomes a PRODUCT limitation the moment a customer asks "is
the control plane HA?" and the honest answer is "no, and the fix is registered." The in-process schedulers
(failover tick, CRL rebuild, retention sweep) are the reason; leader election is the unlock, a contained
pattern. Conditions:
- **Only the scheduler loops are leader-gated — request serving stays on ALL replicas** (a follower still
  serves the API; only the ticking is single-writer).
- **Walk leg:** roll the CP under load → tunnels never drop, and **exactly one leader ticking**.

### D5 — Security posture. CONFIRMED, with the CI-blocking split ruled.

- **CI-BLOCKING:** govulncheck · CodeQL (high/critical) · gofmt/lint parity · the **SBOM (syft) + cosign
  publish** steps (a release without provenance is a release you can't attest).
- **ADVISORY:** Trivy image findings from base-image CVEs we don't control · OpenSSF Scorecard.
- **Rule: block on what we can fix; advise on what we inherit.**
- **SECURITY.md + a disclosure contact ship in the same slice.** Rate-limiting + security headers +
  helper-protocol hardening (#4/#6) land under this posture too.

---

## Slice cut (CONFIRMED as proposed)

1. **Security-CI tier + SECURITY.md + e2e-signal-restore + devcontainer.** Fastest, entity-independent. The
   e2e restoration + the devcontainer are a **DELIVERABLE, not housekeeping** — a red CI job and an unrunnable
   local web gate have degraded every gate's signal for three stories (S8.x web-gate-local-env, the S10.3 e2e
   drift, the S10.2 e2e fail). Restoring the signal is the point of the slice, not a side effect.
2. **Observability floor** — `/metrics` + `/readyz` (health-kind-derived) · swallowed-500 logging fix ·
   audit-action typed registry · WF-OP-3 drift-Event.
3. **Resource/failure envelope + leader-election** — scheduler-loops leader-gated · DB/Redis degrade-not-die
   as a public claim · Helm resource requests/limits · log/disk-growth bounds (rotation).
4. **Backup/restore + the trust-after-restore proof** — backup includes sealed material; restore fails-loud
   on master-key mismatch; wire proof an existing agent still connects.
5. **Upgrade path** — forward-only contract · N/N-1 compile red · rolling procedure · `tunnex preflight`.
   Last, largest, needs 1–4's surfaces.
6. **Docs & install/upgrade guide** — folds the hostNetwork + NAT-traversal deploy notes + the quickstart.

## Slice 2 — observability floor: verify pass + D3.1–D3.5 RULED

**Verify pass (the delta from the roadmap's one-line "S11.1 Metrics"):** the node-agent ALREADY serves
`/healthz` + `/readyz` (`apps/node/cmd/agent/main.go:325,328`) — the **CP is the laggard**, with neither
`/readyz` nor any metrics. Neither side has `/metrics`. The `internal_error` seam
(`apierr/apierr.go:42`) returns a generic envelope and logs **no wrapped cause anywhere**. Audit actions are
**18 bare string literals**, no typed registry, no drift guard.

**The count that shaped the rulings:** the advisor named 6 health kinds from memory; the enum has **13**
(`nodes/policyhealth.go`) — the 13th, `k8s_endpoints_unavailable`, was missed even by the assistant's own
first regex and caught only by re-reading completely. That is the NEVER-TRIAGE-FROM-A-TRUNCATED-READ probe
firing on both sides in one sitting, and it is the argument for D3.1: **a hand-maintained metric list drifts
the first time kind #14 lands.**

- **D3.1 — ONE gauge with a `kind` label, DERIVED from the enum, plus a drift RED. RULED.** Gauge-per-kind
  means 13 names to maintain and a 14th that silently never appears — the producer-without-consumer trap at
  the metrics tier. The enum is the SOURCE (the metric ranges over it, so omission is impossible by
  construction), and **the red is the ruling's substance: adding a health kind without a metric path must
  FAIL THE BUILD.** Census red: every value in the kind enum appears in the metric output.
- **D3.2 — separate port, unauthenticated, operator-network-only. RULED.** The Prometheus convention; keeps
  operational data off the public router entirely; composes with k8s (a Service you don't expose) and VMs
  (bind the private interface). **Conditions: the port is configurable and DEFAULTS to localhost/private,
  never `0.0.0.0`** — a metrics endpoint accidentally public on a VM gateway is an information-disclosure
  finding, and the default must make that impossible rather than merely documented against. The exposure
  model is stated in the security-posture doc alongside the gateway's.
- **D3.3 — fleet-level counts by kind only; NO org/node labels in v1. RULED.** Unbounded cardinality is how
  monitoring stacks fall over, and per-node detail already lives in the API + dashboard (one truth, two
  renderings). **Honest limit, stated: the metric answers "how many gateways are apply_failing", not "which
  ones" — the dashboard answers which.** Per-node metrics REGISTERED with trigger = a customer running their
  own Prometheus who asks for it.
- **D3.4 — log at the ONE seam, not eighteen call sites. RULED.** Where an unmapped error becomes
  `internal_error`, log the wrapped cause WITH the request_id. **Condition: verify there is exactly ONE such
  seam and CITE it — if unmapped errors can become 500s by more than one path, that is the finding, and it is
  the guard-not-mirrored class again.**
- **D3.5 — MOVED OUT OF SLICE 2 (S11-7), merged into the audit-surface unification story.** The ruling below
  was made on wrong inputs — it sized the work against **18 actions and one helper shape**; the census found
  **68 actions across 72 sites and fourteen helpers with heterogeneous signatures**. The conversion was
  attempted and REVERTED mid-flight rather than committed half-applied (a half-converted audit path on the
  surface that answers "who changed access, and when" is the worst trade available). **They are the same
  refactor discovered twice:** the vocabulary can't be typed while the helpers are fourteen, and the helpers
  can't be unified without touching every action string — so sequencing them does the same call sites twice
  with a half-typed state in between, while doing them together means one signature makes typing free.
  **Untyped constants + the census red were REFUSED** as the cheap path: they would ship the APPEARANCE of the
  ruling (no bare literals) while the property actually ruled for (a type the compiler enforces) is absent,
  and would need re-touching during the unification anyway — half a fix that must be redone is worse than a
  clean deferral. Inputs preserved in `docs/audit-unification-story.md`. Original ruling, for the record:
- **D3.5 — the audit-action registry RIDES Slice 2. RULED.** An audit trail with inconsistent action names is
  an observability defect, so it belongs here. The typed newtype + `var` block over the 18 is mechanical; the
  **drift red (every action string used in code appears in the registry) is what makes it durable** and is the
  part worth the care. Root already recorded (M1b, two audit helpers of different shapes — guard-not-mirrored).
  **If the refactor touches more than the call sites — e.g. any audit path that builds an action string
  DYNAMICALLY — surface it rather than absorbing it.**

## S11-6 — audit-helper unification RESIZED: own story, post-beta (ledger corrected)

The D3.5 census answered its own question (vocabulary CLOSED — every action originates as a source literal;
the dynamic-looking sites are branch-selected literal PAIRS, incidental, convertible to constants) and then
found something larger. **M1b was diagnosed as "two audit helpers, one taught the machine branch and one
not." There are FOURTEEN**, across nine packages: `policy` (`writeAudit`, `writeAuditAs`,
`writeSystemAudit`), `tenancy` (2 + a bespoke `deactivate`), `mfa` (2), `sites` (2), `k8s`, `ovpn`,
`invites`, `devices`.

**The number is not the finding — the EXPOSURE is.** Any future change to audit behaviour (a new actor kind,
a required field, a redaction rule, a retention constraint) must currently be mirrored **fourteen times**, and
M1b is the proof that mirroring silently fails. That is not abstract debt: it is a demonstrated failure mode
with a known instance.

**RESIZED — its own story, post-beta unless the trigger fires.** A seven-fold sizing error changes the
disposition: it touches nine packages' write paths, and though the refactor is mechanical it sits on the
surface that answers *"who changed access, and when"* for a security product — so it earns a real review, not
a slice's scoped verify. **Trigger, now SPECIFIC rather than vague: the next change to audit behaviour** —
because that change is precisely what would have to be mirrored fourteen times, so whoever picks it up is
forced into the unification anyway and is better off knowing going in.

**Sequencing benefit:** D3.5's typed registry pins the VOCABULARY first, which makes the eventual unification
strictly easier — one fewer moving part when the fourteen collapse.

## Slice 3 — resource envelope + leader election (BUILT)

**D4 mechanism — Postgres SESSION-SCOPED advisory lock (`pg_try_advisory_lock`), argued not assumed.**
A *lease table* needs a TTL compared against wall clocks, so skew (or a leader that stalls past its TTL and
resumes) can produce **two leaders** — a double failover promotion or two concurrent CRL rebuilds. *Kubernetes
Leases* are unavailable by construction: the CP must also run on a VM pair. A session-scoped advisory lock is
granted to exactly one session and **released by Postgres when that session ends** — SIGKILL, panic, dropped
network alike. No TTL, no clock, no stale-lock reaper.

**FAILURE DIRECTION (the property that decided it):** it fails toward **NO leader, never two**. A gap delays
a periodic reconcile; two leaders double-write. The boundary is enforced by Postgres, not by our code being
correct.

**HONEST LIMIT (fourth in this paper):** after a leader dies, takeover takes up to ~10s (the campaign retry)
plus however long Postgres takes to notice the dead session — immediate on a clean process exit, but bounded
by TCP keepalive on a hard partition, which can be **minutes**. Nothing ticks in that window. That is safe
rather than degraded: the schedulers are periodic reconcilers and never sit in the request or data path.

**Scope:** only the three schedulers (failover tick, CRL rebuild, retention sweep) are gated. **Request
serving runs on every replica.** `/readyz` **reports** the role (`ok leader` / `ok follower`) and never
conflates it with health — a follower is READY because it serves, and reporting otherwise would evict healthy
replicas from a load balancer, turning an HA feature into an outage.

**Design consequence:** leadership holds a dedicated pooled connection, so **shutdown order is load-bearing** —
cancel the elector before `pool.Close()`, which blocks on acquired connections. Found by a test that hung on
exactly that.

**PROVEN ON THE WIRE (not asserted):** `leader_acquired` in the CP log · `/readyz` → `ok leader` · with
Postgres stopped: the container stays **running**, `/healthz` still `ok`, `/readyz` → **503 naming the
reason**, and leadership is **released** (campaign retries, no stale claim) · when Postgres returns,
leadership is **re-acquired without a restart** (`leader_acquired` ×2).

**Failure envelope — the claim, and what evidences it.** *The control plane degrades; tunnels survive.* The
CP half is the wire proof above. The data-plane half was **already red** — `TestReconcileFailStaticKeepsStandby`
asserts that a `FetchDesired` error leaves the applied peers unchanged (fail-static, keep-last). Writing a
second red for it would have been duplicate coverage dressed as new work; the honest action was to cite the
existing one. **Redis** carries sessions only: its loss fails API authentication while tunnels and the agent
channel (mTLS, no Redis) are untouched.

**Helm resources:** requests/limits set for api / web / edge, **verified by rendering the chart** rather than
by setting values and trusting the templates. No CPU limit on the api — throttling a control plane mid-compile
turns a slow tick into a failed one, and the request already guarantees its share. `api.replicas` documentation
rewritten: horizontal scaling is now SUPPORTED, the default stays 1 for simplicity rather than safety.

### S11-8 (REGISTERED) — the integration suite and the compose stack share a database but not a master key

Seen **three times** in this epic, each time diagnosed and re-verified from scratch: bringing the compose
stack up (for a wire proof, a walk, or a demo) seals an agent CA with the STACK's master key, after which
`make test-editions` fails in `agentca` and `nodes` with *"agent CA exists but is unusable; refusing to
regenerate"* until the DB is reset. Both halves are behaving correctly — that refusal is D2's
set-but-broken-is-fatal law, and it is the reason a mismatched key can never silently orphan a fleet — but the
cost lands on every session that runs the stack and then the suite.

**It is also free evidence for Slice 4:** this is the catastrophic backup/restore case (mismatched master key
→ unreadable sealed material → orphaned fleet) reproducing itself locally at zero cost. **Slice 4 should use
it as the restore red rather than inventing a fixture.**

**Fix candidates (deferred, not slice-3 scope):** a separate test database, or a test harness that provisions
its own master key per run. **Trigger: Slice 4 (it needs the fixture anyway), or the next time it costs a
session more than one reset.**

## Slice 4 — backup/restore (BUILT; the wire proof rides the epic walk)

**D2 artifact contents — RULED: DB dump + manifest only; the master key SEPARATE.** A backup carrying its own
key is equivalent to no encryption at rest for whoever obtains the file, and backups are the most-copied,
least-guarded artifact in a deployment. The whole purpose of sealing is that possessing the database is not
enough. The manifest instead carries a **KEYED FINGERPRINT** of the master key (HMAC under a subkey derived
from it — the shipped S4.5 proof-of-secret primitive, not a new invention), which converts "total loss on a
lost key" from a silent discovery into a pre-flight answer.

**ROADMAP CORRECTION (5th item struck on evidence).** S11.2 specified *"DB + master key + node-agent state
(WG private keys on each gateway)"*. Those keys have never been CP-side, by deliberate design —
`0009_node_wg`: *"the private key never leaves the node… the control plane stores pubkeys only"*;
`0010_devices`: *"there is deliberately NO private_key column"*. A backup cannot carry what the CP never
holds, and promising it would be a recovery claim the artifact could not honour. **Stated as the property it
is, not as a limitation:** a CP restore recovers the control plane's state, not the fleet's secrets — and does
not need to, because the fleet's secrets never left the fleet. A lost gateway or device simply re-enrols.

**What the master key guards** (all unreadable under a wrong key): the **agent CA private key** — which agents
PIN, so losing it ORPHANS THE FLEET — the OpenVPN CA and every issued profile key, MFA/TOTP secrets, and
SSO/IdP-sync client secrets.

**Fail-loud at the restore seam** (S10.1's set-but-broken-is-fatal law, applied): verification runs BEFORE
anything is written and refuses on mismatch, naming both fingerprints and the consequence. **The catastrophic
outcome is not a failed restore — it is a restore that SUCCEEDS under the wrong key**, producing a CP that
starts, serves, and cannot read its own agent CA, so the fleet is silently orphaned and the operator learns
it later, from the fleet, with the backup already written over the evidence.

**Built:** `internal/backup` (manifest + `Verify`) and `cmd/backupctl` (`manifest` / `verify`), which loads the
master key exactly as the server does — verifying against a differently-loaded key would prove nothing.
`verify` exits **2** on mismatch so `backupctl verify && pg_restore` cannot proceed.

**Reds:** wrong-key refusal (identifiable as `ErrKeyMismatch`, message must name the CA, "orphaned", and both
fingerprints) · **the manifest contains no key material** in raw, hex or base64 form — so a future "helpful"
change that adds the key for restore convenience fails the build rather than silently turning every
historical backup into a full compromise · unverifiable-manifest refusal · round-trip. Guard proven to reject:
disabling the comparison fails the red.

**PROVEN END-TO-END** (not only in unit tests): manifest taken under key A → `verify` with A exits 0 with the
fingerprint; `verify` with key B prints `REFUSING TO RESTORE`, names both fingerprints and the orphaning
consequence, and exits 2.

**Runbook: `docs/backup-restore.md`** — two artifacts, both required, and plainly what happens if either is
lost (dump lost → restore an older one; **key lost → the sealed material is unrecoverable and the whole fleet
must re-enrol**). That sentence is in the runbook, not only the paper, because it is what makes an operator
actually store the key separately.

**OWED — the wire proof** (the slice's acceptance): restore a CP from backup and prove an existing agent
still connects, unchanged, with no re-enrolment. It rides the EPIC 11 box-walk, where a real gateway exists.

## Slice 5 — the upgrade path (D1) BUILT

**Contract: FORWARD-ONLY, with restore-from-backup as the rollback** — stated in adjacent sentences in
`docs/upgrade.md`, because "forward-only" is only reasonable *because* restore is real, and restore is only
real if the operator holds both artifacts (D2's separate master key). Downgrade rejected: every migration
would need a tested reverse path and every artifact version a backward transform, forever, for a case
operators resolve by restoring.

**The rolling procedure's assumption was CENSUSED, then GUARDED (surfaced before designing around it).** "Old
CP keeps working against the new schema" held by LUCK: 2 of 53 shipped migrations violate it (`0013` DROP
COLUMN, `0038` RENAME COLUMN). Now build-enforced — six statement classes rejected in new migrations, the two
historical ones grandfathered BY NAME so they stay visible. Remedy stated: expand/migrate/contract. Proven to
reject a planted `DROP COLUMN`.

**N/N-1 is a MECHANISM, not a promise, and now a red.** `RequiredVersion` is content-derived: an artifact
carries the OLDEST version whose shape covers its content, so an org using no new features keeps receiving an
old-version artifact its N-1 agents apply. `SupportedWindow = 2` moved from the test file into
`policyspec.go` — it is a contract constant, not a fixture. Two reds:
`TestNMinusOneAgentsCanStillApply` (the zero-config artifact must stamp ≤ the oldest supported version — fails
if any change makes every artifact require the newest version, which would silently start a fleet-wide
policy-update outage) and `TestNewContentRaisesRequiredVersion` (the inverse: N-1 support must never be bought
by silence — new content must raise the version so an old agent REFUSES rather than mis-enforces). First
proven to reject: stubbing `RequiredVersion` to always return `ProtocolVersion` fails it with the reasoning.

**`cmd/preflight` — refuses loudly, changes nothing.** Four checks: database reachable · migration state clean
(a DIRTY state means a migration failed part-way; rolling onto it turns a recoverable state into an
unrecoverable one) · **agent version window** (any gateway below N-1 will refuse its artifact post-upgrade and
stop receiving updates — the remedy exists only beforehand) · rollback plan (an explicit acknowledgement,
since preflight cannot see an offsite backup). **A check that cannot be evaluated is UNKNOWN and refuses** —
"I could not tell" and "it is fine" are different answers.

**PROVEN ON A LIVE DATABASE:** preflight ran, reported protocol v7 supporting v6+v7, passed reachability and
migration-state, and REFUSED — exit 1, nothing changed. Its honest-unknown path fired for real when the query
first named a table that does not exist (it refused rather than passing), and again on 186 local nodes that
have never reported a version. Both are the correct direction. The agent ceiling is read from
`nodes.capabilities->>'max_policy_version'` — where it actually is, found by tracing rather than guessing.

## Slice 6 — docs & install guide (BUILT) — the epic's last build slice

**`docs/self-host.md`** is the self-host STORY, not a docs directory: control plane → first gateway → first
device, then the collected honest limits, the operational runbook, and the security posture in one place. It
is linked from the README's deploy section so a stranger lands on it.

**Every procedure carries a verification mark** (✅ verified / 🔶 partially verified / ⚠️ untested), because a
quickstart nobody executed is documentation that reads like a guarantee — artifact-exists ≠ artifact-works at
the documentation tier. What that produced:
- **Compose quickstart: ✅ verified from a CLEAN SLATE** (`make reset` first) — `up` → `migrate` → `seed` →
  HTTP 200 + `protocol_version: 7`, run for this slice rather than recalled.
- **Helm: 🔶 partially verified, and the boundary is stated inline** — the chart renders, all five
  required-value refusals were walked, and it was installed to live k3s in the S10.1/S10.3 walks; *this exact
  command sequence against managed Kubernetes + managed Postgres/Redis has not been run by us.* Marking it
  honestly was the alternative to implying it.
- Gateway/device enrolment, `preflight`, metrics/`readyz`, and degrade-not-die: ✅, each citing the run.

**The honest-limits list is collected in one table** — no relay fleet · per-cloud fabric routes · OVPN
revocation at renegotiation · OVPN failover bounded by connect-timeout × dead remotes · GKE Autopilot
unsupported · revoked-while-agent-down flows persist until they end · Windows full-tunnel re-home ·
cross-site DNS to cluster zones · leader takeover window · posture is self-reported · no third-party audit
yet. **Each was verified against its source paper rather than recalled** (`EPIC10-decisions` for Autopilot and
cross-site DNS, the WF-A runsheet for `rehome_full_tunnel_unsupported`, `S9.1-decisions` for `reneg-sec`) —
a misstated limit is worse than an omitted one.

**The runbook** names what to alert on and why (`unsupported_policy_version > 0` means an agent has stopped
receiving updates; sustained `desync_unknown` means you cannot see the truth, which is its own problem),
explains the three `/readyz` states including why a follower is ready ON PURPOSE, and keeps the two recovery
stories separate: a CP restore recovers the control plane's state, a lost gateway or device simply re-enrols.

## MERGE MODEL — batch, with Slice 1 as a stated EXCEPTION

EPIC 11 runs the **batch model**: build to walk-ready, one walk, then the merge train. **Slice 1 is the
deliberate exception — merged on its own** — on two grounds, recorded so the pattern is not later misread as
drift:
- **(a) It carries real security fixes.** A reachable `crypto/tls` flaw (`GO-2026-5856`) in the toolchain that
  builds *every* binary we ship, plus five more across `chi` (2), `pgx` (1) and `x/net` (2). Holding those on
  a branch means `main` stays known-vulnerable while the fix exists — the one case where batching costs more
  than it saves.
- **(b) It has no walk-shaped debt.** Slice 1's proof is CI green, not a wire leg; there is nothing for the
  epic's box-walk to discharge on its behalf. A slice whose evidence is complete at merge time does not need
  to wait for one that isn't.

Slices 2–6 rebase onto it and ride the batch as normal.

## ASSERT-PRODUCED-RESULTS — the general pattern (S11 O-1, proven on the way out)

`continue-on-error` on a JOB is almost always wrong. It suppresses *setup* failures as well as findings, so a
job that never ran is indistinguishable from one that passed clean. Two instances of the same action pin
proved it inside one slice: `trivy-action@0.28.0` (nonexistent) failed in 3s and reported **green**; after
moving `continue-on-error` to the findings **step** and adding a `test -s *.sarif` assertion, the *corrected*
pin `0.36.0` — still wrong, the tag is `v0.36.0` — failed **visibly** in 4s. **The guard caught the very next
instance of the bug it was built for.**

**The pattern:** advisory means *its findings don't block*, never *the job needn't run*. Put
`continue-on-error` on the findings-producing step only, and make every scanner assert it actually emitted
results. A scan that emits nothing must never read as a scan that found nothing.

## Box-walk teeth (beta-readiness, not "it renders")

- **D2:** restore a CP from backup → an existing agent still connects, unchanged (fleet not orphaned).
- **D4:** roll the CP under load → tunnels never drop, exactly one leader ticking.
- **D5:** a planted vuln (govulncheck/CodeQL) → the gate BLOCKS the build; a signed release verifies with cosign.
- **D1:** an N-1 agent's artifact still compiles against N (the compat-window red) + the rolling procedure on
  the wire, no flag-day.

## The walk's findings, and the one that stings

Full record: `walk-artifacts/S11/walk-record.md`. Five findings, one HIGH (WF-S11-1) folded mid-walk, four LOW
folded on disposition. Both owed debts — trust-after-restore and HA-under-a-roll — discharged on the wire.

**The embarrassing half of WF-S11-1 is worth its own line.** `docs/backup-restore.md` asserted that
trust-after-restore "is verified on real hardware in the EPIC 11 box-walk" — written in Slice 4, before the walk
existed, about a leg that had not run. It was true a few hours later, which is not the same as being true when
written.

That is precisely the overclaim the ✅/🔶/⚠️ verification marks were invented for **one slice later**, in
`self-host.md`, whose whole premise is that "a quickstart nobody executed is documentation that looks like a
guarantee." The marks were introduced in Slice 6 and the unmarked forward-claim was sitting in a neighbouring
file the entire time — the convention was right and its coverage was assumed rather than swept. **The lesson is
not "be more careful": it is that a new honesty convention needs a census of the surface it is supposed to
cover, exactly like a new guard does** (CENSUS-THE-MIRROR-SURFACE, third instance this epic).

Two more conventions came out of the walk itself:

- **A witness must prove it was alive across the window it certifies** — minted as a law (`docs/laws.md`) and a
  standing rule in the runsheet, after a dead ping log returned a clean gap check for a window it never saw.
- **A procedure that can false-pass is a defect in the procedure.** Leg 5's original step used
  `docker compose restart`, which lets the leader reclaim its own lock in ~400ms; the stated criterion ("the
  surviving replica reports `ok leader`") was satisfied *by the restarted leader itself*. The runsheet now stops
  the leader and requires the returning replica to come back a **follower**.

## REGISTERED STORY — **gateway recovery** (BETA-BLOCKING)

One story, because the subject is one question: **how does a gateway come back?** The walk found three separate
walls in front of it, and solving them apart would produce three half-answers.

| wall | finding | state |
|---|---|---|
| **expired cert** — renewal requires the certificate that expired, so a gateway offline >48h can never reconnect | WF-S11-6 (c) | to build |
| **burned name** — `(org_id, name)` was unconditionally unique and there is no delete, so a revoked gateway held its name forever and re-enrolment answered 409 | WF-S11-8 (a) | **SHIPPED as the near-term unblock** (migration 0056) |
| **lost identity** — a rebuilt gateway is a NEW node: new id, orphaned site binding, fresh metrics series, every runbook reference pointing at a dead row | WF-S11-8 (b) | to build — **the actual fix** |
| **discarded token** — an agent handed a valid join token while holding an *unusable* identity prefers the unusable one, silently | WF-S11-11 | to build — **RULED (a)** |
| **stale binding** — a revoked gateway keeps its `site_id` and still reaches the policy compiler as a site binding | WF-S11-14 | to build — **RULED (c)** |

**The argument for the whole epic, in one line:** tonight, recovering a gateway that had merely been **switched
off** cost four hand-run steps, a wrong host, a volume pinned by a container that exited six days earlier, and an
undocumented deletion. `self-host.md` describes it as *"one pasted command."*

### WF-S11-11 — RULED (a), with a condition

Prefer the join token when the stored identity is **unusable**. The stored identity's purpose is preventing
accidental re-enrolment of a *working* node; when it is provably unusable, deferring to it converts a safety
feature into a deadlock.

**Condition: "unusable" must be a DETERMINATION, not an assumption.** The agent must cite what makes it so —
expired (`NotAfter` in the past), unreadable (parse failure), or mismatched (CN ≠ the requested node name) — and
**fail toward the stored identity when uncertain**. An agent that guesses "probably dead" and re-enrols on a
transient read error would turn a diagnostic into a self-inflicted identity change. Log the determination and its
evidence, not just the outcome.

Folds with **WF-S11-11b**: the reuse warning prints the *requested* name rather than the stored certificate's CN,
so the diagnostic that exists to reveal which identity is kept names the one that is not. Read the CN, print
both, escalate when they differ — a mismatch is itself the interesting signal (a reused VM image, or an enrolment
aimed at the wrong host).

### WF-S11-14 — RULED (c), both halves

- **Filter the compiler input** — `ListSiteNodesForOrg` gains `status = 'active'`, matching its sibling at
  `sites.sql:77` whose own comment says revocation must drop a gateway "no blackhole". This is the **shared-seam
  fix**: the revoked node leaking into compiler input is the identity-binding invariant's *fourth* consumer
  problem, and filtering at the input fixes every consumer at once.
- **Unbind on revocation** — `site_id = NULL` joins the revocation sweep, stopping the stale binding at its
  source and making both queries agree by construction.

Both, not either: the filter protects against any future producer of a stale binding, the unbind removes the one
that exists. Needs a fixture red proving a revoked gateway receives **no placement** and is **never designated
hub**, plus a re-run of the site-transit legs.

**(a) fixes the error; (b) fixes the problem.** (a) makes re-enrolment succeed, which is why it shipped now — but
the gateway that comes back is not the gateway that left. Replace-in-place enrolment is what an operator expects:
same node, same site binding, same history, new credential.

### (b)'s security question, papered before it is built

*"A join token pinned to an existing node re-keys that row"* must not become a **credential swap on a live
node**. If anyone holding a valid join token can re-key an arbitrary node, that is a takeover primitive: mint a
token, re-key a healthy production gateway, and the attacker's agent inherits its identity, its site binding and
its policy — while the real gateway is silently displaced.

**The guard: re-key is permitted only against a node whose original is PROVABLY GONE.** Concretely, the target
must be in a state the control plane can verify itself — `revoked`, or cert-expired-and-unreachable
(`cert_not_after < now()`, which since 0054/0055 is CP-recorded rather than inferred). **Never against a node
that is currently reporting.** A live, healthy gateway must be un-re-keyable by any token, which means the check
belongs on the server and cannot be a client-supplied flag.

Two further conditions for the paper when the story opens:

1. **Revocation must still win.** Re-key must not resurrect a node an operator deliberately revoked without that
   being an explicit, audited act — otherwise re-key becomes an un-revoke, and revocation is the product's
   security primitive.
2. **The audit trail must show the succession**, not a mutation: one node whose credential changed, with the
   cause and the actor, so "this gateway was rebuilt on the 4th" is answerable later.

### What shipped now (a), and its census

Migration 0056 replaces the unconditional constraint with `UNIQUE (org_id, name) WHERE revoked_at IS NULL`. The
ruling required the census **before** landing, not after — because duplicate names among revoked rows would
surface any latent name-keyed lookup, and finding those by breakage is the wrong order:

| angle | result |
|---|---|
| name-keyed SQL lookups on `nodes` | **one** — `GetNodeByOrgName`, whose only caller was a test; now filtered to `revoked_at IS NULL` |
| SQL joins on `nodes.name` | none |
| Go-side name maps / by-name resolvers | none |
| `node_join_tokens.node_name` | a **pin** compared at enrolment, not a lookup key |
| identity resolution | `cert_serial`, globally unique — authentication never touches the name |

Kept as a guard (`TestNoAmbiguousNodeNameLookups`), because a by-name lookup is the natural thing to write, it
works in every fixture with one node per name, and it fails only on a deployment that has rebuilt a gateway —
exactly the shape that reaches production.

## REGISTERED LEDGER ITEMS from the walk (both ruled in)

### 1. No component-test tier for the web app — a MEASURED coverage gap

**Four of fifteen walk findings lived in the UI** (WF-S11-1's a11y half, WF-S11-9 gateway revoke absent,
WF-S11-10 + 10c revoked-row badges, and the same-name picker ambiguity). The UI is the surface with the **least**
automated coverage: all nine web test files cover pure view-models (`*view.ts`), and `@testing-library` appears
nowhere in the repo. Two folds this session — the S10.2 machine-credential panel and the gateway-revoke
confirm — shipped with **no test possible at their tier**.

This is a measurement, not a suspicion, and it is the same class as **`apps/cli` having had no CI job at all**
(S11-2): a whole surface outside the gates, discovered by something other than the gates. Registered with the
measurement attached so it is re-checked rather than re-argued.

### 2. The kind-consumer census gap

`TestEveryHealthKindReachesItsMirrorSurfaces` proves a health kind **reaches** the OpenAPI enum and the web
renderer. It does **not** prove each consumer **decides correctly** about it — which is exactly what WF-S11-10
(revoked rows badged), 10b (revoked rows counted in the fleet tally) and 10c (a second component still badging
them) each were. Reaching a surface and being used correctly by that surface are different properties.

A health kind with no consumer is the **producer-without-consumer trap at the observability tier**, and this epic
minted the standing probe for exactly that. The probe needs its stronger form: for each new kind, name every
consumer *and* state each consumer's decision for the edge cases (revoked, never-reported, unbound) — a census of
decisions, not of presence.

## Status

D1–D5 RULED (this paper). Slice cut confirmed. Ledger triaged (hardening folds here; features carry
trigger-gated; Feature-1 struck dead). Slices 1–6 BUILT. **Box-walk run: Legs 0–6, five findings folded;
criterion 6 (N-1 agent on the wire) ruled Option A — power on one AWS gateway — and is the last outstanding
item before gates and the merge train.**
