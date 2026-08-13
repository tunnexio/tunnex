# Tunnex — EPIC 11 & EPIC 13: technical brief for an external reviewer

**Product.** Self-hosted VPN + Zero Trust control plane. Go control plane (chi, sqlc, PostgreSQL, Redis
sessions), Go data-plane agent owning WireGuard via `wgctrl`, OpenVPN as a second transport, React SPA, Electron
desktop client, root privilege helper (macOS pf / Windows WFP kill-switches). Open-core: `internal/enterprise/`
and anything behind the `enterprise` build tag is proprietary; the rest is Apache-2.0, and both editions are
built and tested on every change.

**Two architectural facts that shape everything below:**

1. **The API never touches WireGuard.** The control plane publishes *desired state*; agents reconcile against it
   continuously and never assume they are in sync.
2. **Agents authenticate with short-lived mTLS certificates — 48-hour TTL, issued by an internal agent CA.**
   Revocation is *refusal to renew*, not a CRL. This is the design decision EPIC 13 exists to repair.

**Status of the two epics:**

| | EPIC 11 — Production Hardening | EPIC 13 — Gateway Recovery |
|---|---|---|
| state | **MERGED** to `main` (`fb99dc6`, PR #42) | **NOT merged** — branch `story/S13.1-gateway-recovery` |
| review | story-end review + a 7-leg box-walk on live cloud hosts | **NOT REVIEWED.** The epic-end pass was launched and interrupted before completion |
| wire proof | complete, evidence committed under `walk-artifacts/S11/` | **NOT WALKED.** Runsheet written (`docs/S13-boxwalk.md`); blocked on a 48-hour certificate clock |
| suitability for review | shipped code | **the more interesting target — it adds an unauthenticated, security-critical endpoint** |

Everything is decision-first: `docs/S11-decisions.md` and `docs/S13.1-decisions.md` record every decide-item with
its disposition, including rejected alternatives and the reasoning. `docs/laws.md` holds the cross-cutting rules
those epics minted. A reviewer disagreeing with a *decision* should read the paper; a reviewer attacking the
*implementation* can ignore it.

---

# EPIC 11 — Production Hardening

Acceptance was not a story list. It was: *what breaks when a stranger runs this in production, unattended, for a
month?* Five mechanisms answer that.

## 1. Observability floor

- **One** Prometheus gauge, `tunnex_gateway_policy_health{kind}`, derived from the shipped health-kind enum
  rather than hand-listed — one truth, two renderings (the API surface and the metric). A census test asserts
  every enum member reaches both its mirror surfaces; it was added because one kind
  (`k8s_endpoints_unavailable`) had reached *neither* the OpenAPI spec nor the UI since it was introduced.
- `/metrics` and `/readyz` are served on a **separate, loopback-bound port** (default), so the metrics surface is
  not reachable from the network the API is. Verified on the wire: `000` (connection refused) from the host's own
  LAN address.
- `/readyz` distinguishes `ok leader` from `ok follower`; both return 200, because readiness is about serving
  traffic, not about holding the scheduler lock.

## 2. Leader election

N control-plane replicas serve HTTP; exactly one runs the scheduler loops (reconcile pushes, health sweeps,
failover evaluation, retention).

- **PostgreSQL session-scoped advisory lock** (`pg_try_advisory_lock`). Chosen over a lease table or an external
  coordinator: no new dependency, and the lock dies with the connection.
- A subtlety worth checking: `conn.Release()` does **not** release a session-scoped advisory lock, because
  pgxpool keeps the underlying session alive. The implementation holds a dedicated connection and treats
  `pg_locks` as the only external truth — `ConfirmLeader()` re-verifies leadership against `pg_locks` matching
  the **stored backend PID** *and* the exact lock key before every gated tick. `IsLeader()` is documented as a
  stale pre-filter, not an authority.
- Failure direction: on any doubt the mechanism fails toward **nobody leads**, never toward two leaders. The
  box-walk observed exactly that — an instant with no leader during a rolling restart, and never two across 15
  paired samples; takeover 2.5s.

## 3. Backup and restore

- Backup = a `pg_dump` plus a **manifest**. The manifest records a *keyed fingerprint* of the master key the
  backup was sealed under, and **no key material**. The master key is not in the backup, by construction.
- `backupctl verify` refuses a restore whose manifest fingerprint does not match the control plane's current
  master key: **exit code 2** (distinct from 1, so a wrapper can tell "wrong key" from "cannot parse"), naming
  *both* fingerprints, the words **agent CA**, and the consequence — every enrolled agent would be **orphaned**.
- The invariant under test is **trust after restore**: an existing agent must reconnect unchanged. Proven on the
  wire: four certificate serials byte-identical across a `pg_restore --clean`, no re-enrolment in any agent log,
  and 919 consecutive witness packets with zero gaps across the restore window.
- The negative case is proven too: a wrong-key restore refused, exit 2, and the fleet **verifiably unmutated**
  afterwards. *A refusal that already mutated something is not a refusal.*

## 4. Upgrades

- **Forward-only, with restore-as-rollback.** No down-migration path is offered operationally.
- A guard, `TestMigrationsAreBackwardCompatibleForOneVersion`, fails the build on any migration that would break
  a rolling upgrade — `DROP COLUMN`, `DROP TABLE`, `RENAME COLUMN`, narrowing `ALTER … TYPE`, `SET NOT NULL`.
  The rule it enforces: during a roll, the *previous* control-plane version runs against the *new* schema. Two
  historical violations are grandfathered **by name**, with reasons, rather than by a version cutoff.
- **N/N-1 agent compatibility** is a mechanism, not a promise: the policy artifact carries a content-derived
  `RequiredVersion`, and a `preflight` tool **refuses** an upgrade that would strand agents in the field rather
  than warning about it. Proven with a real released image never built for the test: an N-1 (v6) agent applied an
  artifact from a v7 control plane, refusing nothing.

## 5. Security CI tier

Blocking: `govulncheck` across all five Go modules, CodeQL (high/critical), `gofmt`/`vet`/`actionlint`, and a
toolchain-pin consistency check. Advisory: Trivy, Scorecard. SBOM + cosign on tags.

Its first honest run exited non-zero on a reachable `crypto/tls` flaw **in the pinned toolchain that builds every
shipped binary** — root cause was two toolchain pins that disagreed. Eleven pin sites were aligned and a script
now fails the build on disagreement. CodeQL baseline: **0 alerts, both languages** (recorded with the caveat that
a clean baseline is not an audit).

## What the box-walk found — the finding underneath the findings

Seven legs on live cloud hosts; **15 findings, 6 HIGH.** Five of the six HIGH were **one class**: *a mechanism
that works, a procedure around it that does not, and documentation asserting the procedure.* Three of them
descended from a single sentence in the docs — *"a lost gateway: re-enrol it (one pasted command)"* — which on
the wire cost four hand-run steps, a wrong host, a Docker volume pinned by a container that had exited six days
earlier, and an undocumented deletion, for a machine that had merely been switched off.

Two guards came out of that walk and are worth knowing when reading any test in this repo:

- **A witness must prove it was alive across the window it certifies.** A continuity check over a log that died
  before the event returns *clean*, and fails toward "pass".
- **Could this check have failed?** Three green checks in one session were vacuous: a dead witness, a
  tautological assertion that passed with its own fix removed, and a provenance census that verified the commit
  but not the **build edition** — so four rebuilds silently swapped the open build for the enterprise one
  mid-walk.

---

# EPIC 13 — Gateway Recovery

**This is the part worth attacking.** It adds two unauthenticated HTTP endpoints that can issue a certificate.

## The problem

A gateway went offline past its 48-hour certificate lifetime and could not come back:

- its certificate had expired, so it could not authenticate to the mTLS agent channel;
- `/agent/renew` — the only endpoint that issues a new certificate — **lives behind that channel**;
- Go's `tls.Config.ClientAuth` is a **listener** property with no per-route relaxation, so the renewal endpoint
  cannot be selectively opened.

The recovery path required the credential that had failed. The only escape was an operator minting a join token,
which creates a **new node**: new id, site binding lost, and every device homed on the old node cascade-revoked.

## The design, and the one property everything hangs from

Recovery is **proof of possession** of the keypair the control plane already recorded for that node (migration
0057 records the agent's SPKI at enrol/renew). The agent still holds its private key; the expired certificate
binds the same key. Proving possession **re-attests a grant the control plane already made** rather than creating
a new one.

**D3, the gone-gate — amended mid-build, and the amendment is the security property:**

> **Certificate expiry authorizes re-key. Revocation refuses it.**
> Expiry is an *absence of action*; revocation is the *presence of a decision*. A cryptographic proof may
> overturn the first, never the second — because possession cannot distinguish the legitimate holder from
> whoever took the key.

The first draft had it backwards (revoked looked like the *strongest* evidence a node was gone). The corollary
now in the standing set: *strength-of-evidence-that-it's-gone is not validity-of-authorization-to-return.*

`RekeyAuthorized(status, certNotAfter, known, now)` takes **no liveness parameter and no force parameter**. There
is deliberately **no operator or client override** on this gate: *a guard overridable by the party most motivated
to override it is documentation, not a guard.*

## Wire protocol

Two round trips on the **public** listener:

```
POST /api/v1/agent/rekey/challenge   { cert_serial | key_fingerprint }        -> { nonce }
POST /api/v1/agent/rekey             { identifier, nonce, csr, signature, agent_version }
                                                                              -> { cert_pem, ca_pem }
```

- **Signature**: RSA-PKCS1v15-SHA256 over `(nonce ‖ CSR DER)`, verified against the recorded SPKI.
  *(WireGuard keys are X25519 and cannot sign at all — the identity key is the agent's RSA key, not its WG key.
  That is arithmetic, not policy.)*
- **Binding (hazard 1)**: the signature covers the **new CSR**, so a captured proof cannot be paired with an
  attacker's own CSR. The signed-message constructor is one definition; the agent builds the identical bytes.
- **Replay (hazard 2)**: the nonce is server-issued, 32 bytes, single-use, 2-minute TTL, and bound in the
  database to the **identifier and its kind**. Single use is enforced by the `UPDATE`'s own `WHERE` clause
  (`consumed_at IS NULL`), not by read-then-write, so two concurrent submits cannot both win.
- **The CSR must be self-signed by its own key** — independent of the proof, and still required, or a caller
  could request a certificate over a public key they do not control.

## Ordering, and why it is the security design

1. **Consume** the nonce — even when the attempt then fails, so a probe cannot retry with the same challenge.
2. **Resolve** the node by identifier.
3. **Gate (D3) — before any cryptographic work.** RSA verification is the expensive, timing-visible step; the
   gate is a field comparison. Running verification first would let response latency reveal whether a node is
   alive, turning the endpoint into a **liveness oracle for the fleet**. A source-order test asserts this, with
   comments stripped before matching (the doc comment describes the ordering and would otherwise satisfy the
   guard without the code satisfying the property).
4. **Verify** the proof, bound to this nonce and CSR.
5. **Sign.**
6. **Commit** the identity change and its audited succession in **one transaction** — a re-key that happened
   leaves a record even if the push never lands.
7. **Push** — after the commit, never inside it. A database transaction must not depend on a network call to a
   fleet. The stated window: between commit and push the control plane believes the new key and the fleet has not
   been told; a lost push is a *delayed* convergence, never a lost one.

The identity change (`RekeyNode`) is a compare-and-swap on `(id, current serial, status='active')` and **does not
mention `status` or `revoked_at` at all** — it is *incapable* of un-revoking a node rather than merely forbidden
from it. A test asserts that against the query text.

## Uniform refusal

A live node, an unknown serial, an unknown fingerprint, an **ambiguous** fingerprint, a spent nonce, a malformed
CSR and a wrong key all return the **same** refusal — compared in tests as a *value* (code, message, status), not
merely as "an error". The specific reason goes to the log, where an operator can read it and an attacker cannot.

The challenge endpoint deliberately **does not check that the identifier exists** — a challenge that succeeded
only for real identifiers would make them probeable one request at a time.

Consequently the OpenAPI schema for the identifier fields carries **no pattern and no length constraint**: a
schema violation would answer `400` where an unknown identifier answers `403`, and that difference tells a prober
how far they got. Shape validation happens in the handler and returns the uniform refusal.

## The second identifier (D10)

A re-key whose **response is lost** leaves the control plane holding a serial the agent never received. Retrying
by serial names a row that no longer exists, and the gateway is bricked permanently by one dropped packet.

- The agent may instead identify by **key fingerprint** — SHA-256 over the SPKI DER, lowercase hex, **exact match
  only** (never a prefix: a prefix match is an enumeration primitive that reports *warmer*).
- The rejected alternative was a **grace window on the previous serial**, which reintroduces a time bound of
  exactly the kind D3 removes.
- The fingerprint column is **generated by PostgreSQL** from `cert_public_key`, so it cannot drift from the key
  it names. It is **not unique** — nothing prevents two nodes enrolling with the same key (a copied state
  directory) — so the lookup reads up to two rows and **refuses on more than one**. Ambiguity at the moment
  identity is trusted fails closed.
- The digest exists in **three implementations that cannot import each other** (agent Go, control-plane Go, and a
  SQL expression). They are pinned to one **golden vector** asserted in all three, using a *public* key so no
  private material enters the repository.
- Agent side: the pending keypair is **persisted before the request goes out** and **reused across attempts**, so
  repeated lost responses *converge* on one identity instead of walking it forward.

## Rate limiting and body caps

- A **path-scoped** throttle on the two re-key routes only, registered **above** `middleware.RealIP` — which
  overwrites `RemoteAddr` from client-supplied headers, so a throttle below it keys on a value the caller
  chooses. (That was a real review finding; three tests passed against it because they built bare requests
  outside the middleware chain.)
- The limit, 600/min, is **derived from the worst legitimate case** — a 100-gateway fleet recovering after an
  outage, all sharing one bucket behind an ingress — not chosen for feeling strict.
- **Stated limitations:** behind a proxy or NAT this is a per-*deployment* budget, not per-caller; fixing that
  needs trusted-proxy configuration, which belongs to a general rate-limiting mechanism that **does not exist
  yet**. There is also **no body-size limit anywhere else in the API** — these two routes have one (64 KiB)
  because they are unauthenticated.

## Blast radius: cascade restore

Revoking a gateway cascade-revokes every device homed on it, so recovery without restoring them hands back a
working gateway with **zero users**. Devices now carry a `revoked_cause` (`cascade` vs `deliberate`), and restore:

- returns **only** cascade-revoked devices — a laptop an admin revoked deliberately is never revived by a gateway
  rebuild, enforced by a predicate repeated in the restore statement itself, not by the caller remembering;
- **reclaims the original address when free**, allocating fresh only when genuinely taken, under the same
  org advisory lock device-create uses, reading the single canonical allocation oracle once;
- audits the re-addressed case distinctly, because those users' configs embed the old address and will not
  connect until re-imported. The device surface derives `needs_reexport` from a `provisioned_ip` snapshot for
  **every** provisioning mode, so this is visible and not only auditable.

**A defect found while drafting the walk, and fixed as Slice 7:** the restore had exactly one caller (re-key), and
devices become cascade-revoked in exactly one place (revoke) — and re-key *refuses a revoked node*. The trigger
that created the work put the node into the one state that could never reach the code that undid it. Correct code,
unreachable. The fix is an **operator-initiated restore** (`POST /nodes/{nodeId}/restore-devices`) under a new
`device:restore` permission, audited with the actor, re-homing onto a named live gateway. The lesson is now a
standing rule: **a unit test proves behaviour, never reachability** — name the caller, and prove the trigger can
co-occur with the gate.

## Agent-side recovery

- The decision function `identity.Decide(certPEM, loadErr, requestedName, haveToken, now)` takes **no network
  argument**. That is structural: a failed handshake *cannot* trigger re-key, only the locally observable state
  of the stored certificate can.
- `Recover` is ranked **above** `UseToken`, because a Helm deployment injects `TUNNEX_JOIN_TOKEN` on every pod
  start — without the precedence, an expired gateway took the token path, hit `409 node_exists` against its own
  expired-but-not-revoked row, and crash-looped.
- The agent **never exits** on a refusal: an enrolment refusal is a condition the control plane can resolve, and
  exiting forfeits the reconciliation that would have fixed it. Liveness up, readiness false.
- Credential writes are atomic (temp-then-rename, key written last), so a crash mid-save leaves either the old
  set or the new set, never a mixture.
- Because the control plane's refusals are uniform, the agent reports what it knows **locally** — *my certificate
  expired at T, I attempted re-key, it was refused, here is the remedy* — with backoff from a 30-second floor to
  a one-hour ceiling, and a 429 explicitly distinguished from a refusal.

## Known limitations, stated rather than discovered

| limitation | why it is acceptable / what covers it |
|---|---|
| Nodes enrolled before migration 0057 have **no recorded public key** and cannot recover by proof of possession | absence of verification material is not evidence of possession; those recover by join token, which is why that path is always available. The agent says so in its own log |
| The fingerprint column is not unique | ambiguity refuses; the duplicate node remains recoverable by its own serial |
| Throttle is per raw peer IP | behind a proxy this is per-deployment; general rate limiting is owed and registered |
| No general rate limiting on login, enrolment, or the wider API | registered, unbuilt |
| `node_rekey_challenges.cert_serial` is written but unread for one release | a rolling-upgrade shim (the guard rejected the original `RENAME`); the contract migration is registered with a trigger |
| Audit key fingerprints changed construction (base64 text → SPKI DER) | stated: rows written before the change are not comparable with rows after |

## Test evidence a reviewer can check quickly

- Integration tests run against a **real PostgreSQL**, including the full lost-response scenario end to end
  (commit → response lost → serial refused → fingerprint recovers the same node id).
- Security-relevant properties are **mutation-proven**: the assertion is shown to fail when its subject is
  removed. Where a mutation produced a *build* failure rather than a *test* failure, it was redone — a build
  failure is indistinguishable from a pass under the harness.
- Guards that read source text (query text, middleware ordering, enum-to-surface censuses) exist where there is
  no runtime observable, and strip comments before matching so prose cannot satisfy them.

## What has NOT been done, and should weigh on any conclusion

1. **No completed code review.** The epic-end pass was launched and interrupted; its finder stage finished and
   its ranking, deduplication and completeness stages never ran. Nothing from it has been folded.
2. **No wire proof.** The walk runsheet exists (7 legs, including the two negative legs — a revoked gateway
   refused, and a deliberately-revoked device staying dead through a restore) but has not been run. It is blocked
   on staging two gateways offline for 48 hours, because the certificate TTL is a constant and expiry cannot be
   manufactured.
3. Slice 7 is the newest code and has had no review of any kind.

An external reviewer arriving now is looking at **unreviewed, unwalked code on a branch** — which is the honest
framing, and arguably the most useful moment to look at it.
