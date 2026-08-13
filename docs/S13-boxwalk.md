# EPIC 13 — Gateway Recovery box-walk (RUNSHEET)

Status: **RUNSHEET** (plan). Executes in a walk session, AFTER the epic-end review pass. Walk evidence is committed
DURING the session under `walk-artifacts/S13/`; any scratch key material (device configs, join tokens, agent state
dirs) is **gitignored at creation** — device configs contain private keys.

> ## ⚠ READ `docs/S13-run-plan.md` FIRST — DO NOT RUN THIS SHEET END TO END AT 48h
>
> This file is the LEGS. The RUNS are three, and they buy different things: §A rehearsal #1 (complete at 10m),
> §B rehearsal #2 (10m — the items §A could not cover, plus Legs 7/8 and refusal timing), §C the 48-hour run
> (**narrow: one subject, one recovery**, proving only that the TTL knob did not change behaviour).
>
> Running everything here at 48h spends two days re-proving what §A proved in ten minutes.

## REBASED ON THE FOLDED CODE (2026-07-31) — leg-by-leg verdict

This runsheet was written before review pass 1 and before four fold batches (~20 fixes, migrations 0062–0064).
Every leg was re-read against the code as it now stands.

| leg | verdict | why |
|---|---|---|
| **0** provenance | **NEEDS REWRITE** | schema version is now **64**, not 61, and three new columns must be censused |
| **1** PoP self-recovery | **STILL VALID**, extended | expiry still authorizes; adds an assertion that `cert_delivered` goes FALSE on re-key |
| **2** keyless → token | **NEEDS REWRITE** | the agent now hands over to the token **by itself** after three refusals — the leg's "mint a token and restart" no longer describes what happens |
| **3a** revoked → refused | **STILL VALID** | the revoked check runs first and unconditionally, through both predicate changes |
| **3b** refusal surface (local) | **NEEDS REWRITE** | adds the NUL-serial case (#12: must be 403, not 500) and the removed `maxLength` (#18: no 400) |
| **3c** live node refused | **NEW** | the delivery marker created walkable behaviour that did not exist: a caller holding a live node's own key must be REFUSED |
| **4** operator restore | **NEEDS REWRITE** | Batch C changed four things in the path (#7 node-status guard, #8 prior status, #9 OVPN certs, #14 pool membership) |
| **5** deliberate stays dead | **STILL VALID**, extended | now also: the deliberately-revoked OVPN **certificate** must stay revoked |
| **6** re-addressed says so | **NEEDS REWRITE** | F3 is FIXED, so the leg must test the fix — see its own falsification note |
| **7** lost-response (D10) | **NEEDS REWRITE** | recovery now happens **in-process** (#6), and the CP-side predicate changed twice |
| **8** save-failure retry | **NEW** | claims 7/15: a save failure after the CP committed must recover the SAME node id, not enrol a new one |

**Nothing came out VACUOUS.** Every leg still tests something real; four needed their expectations moved.

---

## What this walk must prove

EPIC 13 exists because of one observed event: **an AWS gateway went offline past its 48-hour certificate lifetime and
could not come back.** Its certificate had expired, so it could not authenticate to the mTLS agent channel — and
`/agent/renew`, the only endpoint that could issue a new certificate, lives *behind* that channel. The recovery path
required the credential that had failed.

So the walk's subject is a recovery that must work **and a recovery that must not**:

1. **A gateway recovers itself** by proof of possession, keeping its node id, its site binding, its history and its
   devices. The leg the epic exists for, and the one the real box failed.
2. **A revoked gateway is REFUSED** the same recovery. D3's security property, and the **most important negative leg
   in the epic**: proof of possession must never overturn a human decision, because it cannot distinguish the
   legitimate holder from whoever took the key.
3. **The coverage limitation is honest** — a gateway whose key the control plane never recorded cannot recover this
   way, and the agent must say so *locally*, in words an operator can act on, because the control plane's refusals
   carry no reason by design.
4. **The user-facing consequences are handled** — cascade-revoked devices come back, deliberately-revoked ones stay
   dead, and a device that comes back on a different address says so instead of silently failing to connect.

**Evidence, not inference.** "The gateway came back" is inference. *"The node id is unchanged, `site_id` is unchanged,
the audit row records a succession with both key fingerprints, and the agent's log says `agent_rekeyed`"* is evidence.

## Two bars that decide pass vs finding

- **ZERO-TOUCH.** The only commands you may hand-run are **diagnostic** — reading logs, audit rows, `wg show`,
  `psql` SELECTs. Anything you must hand-run to make *recovery* work is a **FINDING**: number it and HOLD it. The
  agent is supposed to recover itself; a walk where the operator nudges it has proven nothing.
- **STAGING IS NOT A WORKAROUND, AND IT IS DECLARED.** Three legs need a state that cannot be produced on demand (an
  expired certificate, a node with no recorded key). The `UPDATE` statements that stage them are listed explicitly
  below and are **part of the setup, not part of the procedure**. A staging statement that appears anywhere other
  than a Staging block is a finding.

### STANDING RULE — carried from EPIC 11, and it applies to every negative leg here

**Could this check have failed?** A refusal that already mutated something is not a refusal, so every negative leg
ends by re-reading the row it was supposed to leave alone. And a witness must prove it was alive across the window it
certifies: before the leg, confirm it is replying *now*; after, check its timestamp bounds straddle the leg's own
start and end.

---

## Prerequisites — what Pawan needs staged

### THREE expired gateways, not two — and the reason is the uniform-refusal surface itself

Legs 1, 2 and 3a each need a gateway whose certificate has genuinely expired, and they need **three different
ones**, because the refusals are indistinguishable **by construction**:

| leg | subject | why it must be its OWN host |
|---|---|---|
| **1** PoP self-recovery | **A** | A ends the leg RECOVERED, holding a fresh 48h certificate. It is no longer an expired subject for anything after it |
| **2** keyless → token fallback | **B** | its `cert_public_key` is nulled as declared staging, so PoP is refused *for lack of verification material*. The leg then re-enrols B by token, which issues a fresh certificate — B is no longer expired either |
| **3a** revoked → refused | **C** | refused *because it was revoked* |

**Running 2 and 3a on one host proves neither.** The endpoint returns the SAME refusal for a revoked node and for
a node with no recorded key — that uniformity is D8/D9, deliberate, and the whole point of the surface. So a
single host carrying both conditions produces one refusal attributable to either cause, and the leg cannot
distinguish what it just proved. The evidence that separates them lives in the CP log and in the agent's own
local diagnosis, and each needs a subject in exactly one of the two states.

A third host is cheap to stage and **impossible to add on walk day** — it needs 48 hours it cannot get.

### Staging order — FORCED, and the stop is last

The clock and the device prerequisites are in tension: **a live agent renews every 24h and pushes `not_after`
forward**, so A cannot be live while its clock runs — but the devices Legs 4/5/6 need must be created *and
connected* on A **while A is live**. So the order below is not a preference, it is the only order that works. Do
not spend the 48-hour wait before the prerequisites exist.

| # | step | on | must be true before moving on |
|---|---|---|---|
| 1 | Control plane at this branch, **enterprise**, schema 61 | azure-cp | Leg 0's CP census recorded |
| 2 | Agent image at this branch on **A, B, C** — restart in place where possible | each host | Leg 0's per-host census recorded (sha + edition) |
| 3 | All three enrolled and healthy | azure-cp | a node row per host, `key_recorded = t` for **A** and **C** |
| 4 | **Create the devices on A** — `keeps` and `contended` (Legs 4/6) and `deliberate` (Leg 5) | UI / API | three device rows homed on A |
| 5 | **CONNECT each device and pass traffic** | the device | a handshake and non-zero transfer counters in `wg show` on A |
| 6 | **Revoke the `deliberate` device** as an admin | UI | `revoked_cause = 'deliberate'` on that row |
| 7 | Record identity for A, B, C: serial, `cert_not_after`, fingerprint | azure-cp | `walk-artifacts/S13.1/clock-record.md` filled |
| 8 | **STOP all three agents — LAST** | each host | `docker ps` empty per host; stop timestamp recorded |

Step 5 is not ceremony. Leg 6 asks whether a *user* can tell their config went stale; a device that never
connected cannot demonstrate that it stopped working, and a `needs_reexport` badge on a device nobody ever used
proves the badge renders, not that it warns anyone.

Step 8 last, and **idle is not stopped** — `renewLoop` runs regardless of whether anything is reconciling, and one
renew silently costs another 48 hours.

### The rest

| # | Requirement | Why | Clock? |
|---|---|---|---|
| 1 | **azure-cp up (enterprise edition)** | several legs read audit rows and device state | — |
| 2 | **A live REPLACEMENT gateway for Leg 4** | the operator restore re-homes onto a live node, and the server refuses a revoked or foreign target. **B-after-token-re-enrolment (Leg 2) serves** — it is a fresh live node by then — so no fourth host is needed, but Leg 2 must run BEFORE Leg 4 | none |
| 3 | The **agent logs reachable** on A, B and C | the agent's local diagnosis is the *subject* of Leg 2, not a debugging aid | — |
| 4 | A local stack (`make up-enterprise`) | Legs 0b, 3b and 7 | **CLOCK-FREE — stage any time** |
| 5 | **Dropped-response tooling for Leg 7** — a proxy that forwards `POST /agent/rekey` and kills the connection before the body returns, or a scripted `SIGKILL` of the agent between the CP's commit log line and its own save | Leg 7 has no subject without a way to lose a response | **CLOCK-FREE — stage any time** |

Shell vars: `CP=http://10.0.0.4` · `ORG=<org-uuid>` · on azure-cp, `cd ~/tunnex`.

### Which legs need the rig, and which are local

| leg | where | why |
|---|---|---|
| 0 | both | provenance is per-environment |
| **1** PoP self-recovery — **host A** | **RIG ONLY** | needs a genuinely expired certificate on a real agent (48h clock) |
| **2** keyless → token fallback — **host B** | **RIG ONLY** | same, plus the agent's own log is the evidence |
| **3** revoked → refused — **host C** (3a) | **RIG** (3a) **+ LOCAL** (3b) | 3a is the agent's own behaviour; 3b drives the endpoint directly with `curl` so the *refusal surface* is exercised without spending a 48h gateway |
| 4 operator restore | RIG | needs Leg 2's re-enrolled B as the live target, and Leg 3a's revoked C as the source |
| 5 deliberate revoke stays dead | RIG | rides Leg 4 |
| 6 re-addressed → config out of date | RIG | rides Leg 4 |
| **7** lost-response recovery (D10) | **LOCAL** | the newest code, wire-unproven; drivable against a local CP without burning a 48h gateway |

---

## Leg 0 — provenance census

**A stale image reproduces symptoms that look like defects.** And per EPIC 11's finding: **the edition is half of
provenance, and it must be re-asserted after every rebuild** — `docker compose up -d --build api` silently rebuilds
the OPEN image (`go build -tags ""`), which was missed for several legs last time.

```bash
# [azure-cp]
cd ~/tunnex && git fetch && git checkout main && git pull
SHA=$(git rev-parse --short HEAD) && echo "census sha=$SHA"
sudo make up-enterprise && sudo make migrate
curl -s localhost/api/v1/meta | grep -o '"edition":"[a-z]*"'          # -> enterprise
```

Then the surfaces this epic added, each confirmed present rather than assumed:

```bash
# [azure-cp] schema version and the two columns the recovery path depends on
sudo docker exec tunnex-postgres-1 psql -U tunnex tunnex -c "SELECT version, dirty FROM schema_migrations;"
sudo docker exec tunnex-postgres-1 psql -U tunnex tunnex -c "\d nodes" | grep -E "cert_not_after|cert_public_key|cert_key_fingerprint"
sudo docker exec tunnex-postgres-1 psql -U tunnex tunnex -c "\d devices" | grep -E "provisioned_ip|revoked_cause|revoked_prev_status|provisioned_node_id"
# The delivery marker and its fail-safe default (0063/0064) — the gate's input, and the column whose ABSENT value
# must mean CLOSED. A default of anything but `true` is a fleet-wide fail-open.
sudo docker exec tunnex-postgres-1 psql -U tunnex tunnex -c \
  "SELECT column_default, is_nullable FROM information_schema.columns
   WHERE table_name='nodes' AND column_name='cert_delivered';"          # -> true / NO
sudo docker exec tunnex-postgres-1 psql -U tunnex tunnex -c \
  "SELECT cert_delivered, count(*) FROM nodes WHERE revoked_at IS NULL GROUP BY 1;"   # -> overwhelmingly t

# The re-key routes exist and are UNAUTHENTICATED — a 403 refusal, never a 401 or a 404
curl -s -o /dev/null -w '%{http_code}\n' -X POST $CP/api/v1/agent/rekey/challenge \
  -H 'content-type: application/json' -d '{"cert_serial":"nobody-has-this"}'      # -> 200 (anti-enumeration: a nonce for anything)

# How many gateways can recover by PoP at all? This is the coverage limitation, measured before it matters.
sudo docker exec tunnex-postgres-1 psql -U tunnex tunnex -c \
  "SELECT name, status, cert_not_after < now() AS expired, cert_public_key IS NOT NULL AS key_recorded,
          left(cert_key_fingerprint,12) AS fp FROM nodes ORDER BY enrolled_at;"
```

- **PASS:** `version=61, dirty=f` · all five columns present · challenge returns **200 for a serial nobody has**
  (the anti-enumeration property, observable) · and the census table printed.
- **RECORD the census table verbatim.** It is the walk's baseline *and* the honest statement of coverage: every row
  with `key_recorded=f` is a gateway that can only recover by join token, and Leg 2 is about exactly those.
- **IF `version < 61` → STOP.** Provenance failure, not a code failure.

---

## Leg 1 — A GATEWAY RECOVERS ITSELF (the leg the epic exists for)

**Subject: gateway A** — offline ≥48h, certificate expired, `status=active`, `cert_public_key` recorded.

```bash
# [azure-cp] BEFORE — the identity that must survive, captured as evidence
sudo docker exec tunnex-postgres-1 psql -U tunnex tunnex -c \
  "SELECT id, name, cert_serial, site_id, status, cert_not_after, left(cert_key_fingerprint,12) AS fp
   FROM nodes WHERE name='<A>';"
```

Then **start gateway A and touch nothing else.**

```bash
# [gateway A] the agent's own account of what it did
journalctl -u tunnex-node -f | grep -E 'agent_rekeyed|agent_rekey_refused|agent_rekey_throttled|agent_enrolling'
```

- **PASS — all six, and the first is the whole epic:**
  1. `agent_rekeyed` in the agent log, with `identified_by=cert_serial ...`
  2. **the node id is UNCHANGED** (not a new row with the same name)
  3. **`site_id` is UNCHANGED** — the gateway comes back bound to its site
  4. `cert_serial` and `cert_key_fingerprint` have both MOVED (new credential, same identity)
  5. an audit row `node.rekeyed` carrying `old_cert_serial`, `new_cert_serial`, **both key fingerprints**, and
     `authorized_by` — a *succession*, so "this gateway was rebuilt on the 4th" is answerable later
  6. **zero operator commands** beyond starting the agent
  7. **`cert_delivered` is FALSE immediately after the re-key and TRUE again after the agent's first authenticated
     request.** This is the gate's whole input (D3): re-key clears it in the same statement that replaces the
     serial, and `AuthenticateCert` sets it on first use. Sample it twice — right after `agent_rekeyed`, and after
     the first `/agent/desired-state` — because a marker that never clears makes lost-response recovery
     impossible, and one that never sets leaves the carve-out open on a live node
- **EVIDENCE:** the before/after node rows side by side, the audit row's metadata, the agent log lines.
- **The audit fingerprint is a 12-hex PREFIX of the full identifier** (D10 redefinition) — confirm
  `old_key_fingerprint` matches the `fp` column captured before the leg. If it does not, the audit trail is naming
  keys in a vocabulary nothing else speaks.

---

## Leg 2 — THE COVERAGE LIMITATION, and the agent's local diagnosis

A gateway enrolled before migration 0057 has **no recorded public key**, so there is nothing to verify a proof
against — and "I cannot check" must never resolve to "it is fine". Those gateways recover by join token, which is why
D1(a) keeps it as the always-available manual path.

**Staging (declared):**

```bash
# [azure-cp] STAGING — simulate a pre-0057 node on HOST B ONLY. This is setup, not procedure.
# B is the keyless subject and nothing else: it must NOT also be revoked, or its refusal has two causes and
# proves neither (the endpoint answers identically for both).
sudo docker exec tunnex-postgres-1 psql -U tunnex tunnex -c \
  "UPDATE nodes SET cert_public_key = NULL WHERE name='<B>';"
# Confirm the generated fingerprint went NULL with it — the column is derived, not written
sudo docker exec tunnex-postgres-1 psql -U tunnex tunnex -c \
  "SELECT name, cert_public_key IS NULL AS key_gone, cert_key_fingerprint IS NULL AS fp_gone FROM nodes WHERE name='<B>';"
```

Start gateway B. It will attempt PoP, be refused, and back off.

- **PASS:**
  - `agent_rekey_refused` appears, and **its text is the subject**: it must name the local finding (*this agent's
    certificate has expired*), state that the server gave **no reason and why** (refusals are uniform by design), name
    the most likely cause, and give the remedy — *mint a join token and restart with `TUNNEX_JOIN_TOKEN` set*.
  - The backoff **doubles toward the one-hour ceiling** and the agent **does not exit** — liveness up, readiness
    false. A CrashLoopBackOff here is a finding: an enrolment refusal is a condition the control plane can resolve,
    and exiting forfeits the reconciliation that would have fixed it.
  - `fp_gone = t` — the fingerprint is **generated from the key**, so removing one removes the other. A non-NULL
    fingerprint over a NULL key would match every other keyless node.
> **REWRITTEN (fold Batch B, #5).** The agent no longer waits to be restarted. If `TUNNEX_JOIN_TOKEN` is already
> in its environment, **three consecutive refusals hand over automatically** and it enrols itself. So run this leg
> BOTH ways, and the first way is the one that never worked before:
>
> **2a — token already present.** Start B with the token set. PASS: three `agent_rekey_refused` lines, then
> `agent_rekey_exhausted`, then `agent_falling_back_to_join_token`, with **no operator action between them**. This
> is the finding that made the documented remedy reachable; before the fold the agent looped forever with the
> token unused.
>
> **2b — no token.** Start B with no token. PASS: it keeps retrying and **does not exit** — with nothing to hand
> over to, retrying beats idling. Confirm the backoff escalates toward the ceiling and the process stays up.

- **Then the fallback, per the remedy the agent printed:** mint a join token in the UI, set it, restart.
  - **PASS:** the gateway enrols. **It is a NEW node** — and the agent said so before it happened
    (`agent_falling_back_to_join_token`: *"this creates a NEW node: its site binding must be re-applied and devices
    homed on the old node need re-issuing"*). Confirm the new row's id **differs** from the old, and that the warning
    was printed **before** the enrolment, not after.
- **EVIDENCE:** the full refusal log line (it is the deliverable), the backoff progression, both node ids.

> **This leg is the honest half of the epic.** Recovery does not work for every gateway, and the walk proves the
> product *says so at the only place it is observable* rather than leaving an operator watching a silent agent.

---

## Leg 3 — A REVOKED GATEWAY IS REFUSED (the most important negative leg)

### 3a — on the rig, through the agent

**Subject: gateway C** — expired, and now revoked. NOT B: B is the keyless subject, and a host carrying both
conditions produces a refusal attributable to either, which the uniform-refusal surface makes indistinguishable by
construction. C's `cert_public_key` must still be RECORDED (`key_recorded = t`), so the ONLY reason it can be
refused is the revocation — that is the whole point of the leg.

Revoke it in the UI (Gateways → Revoke), which also **cascades to its devices** — that cascade is Leg 4's premise.

> **Move A's devices to C before this leg, or give C its own.** Leg 4 restores a REVOKED gateway's devices, and C
> is the revoked one. Either home the Leg 4/5/6 devices on C at staging step 4 instead of A, or accept that Leg 4's
> source is C and stage its devices accordingly. **Pin this at staging time** — discovering on walk day that the
> cascade landed on the wrong host costs the leg.

```bash
# [azure-cp] BEFORE: the row that must be UNTOUCHED afterwards, and the cascade
sudo docker exec tunnex-postgres-1 psql -U tunnex tunnex -c \
  "SELECT id, cert_serial, status, revoked_at, cert_public_key IS NOT NULL AS key_recorded FROM nodes WHERE name='<C>';"
sudo docker exec tunnex-postgres-1 psql -U tunnex tunnex -c \
  "SELECT name, status, revoked_cause, assigned_ip FROM devices WHERE node_id='<C-id>' ORDER BY name;"
```

Start gateway C's agent and let it attempt recovery.

- **PASS:**
  - `agent_rekey_refused` — **and the refusal is indistinguishable from every other refusal.** The response carries
    no reason; the agent's log says so explicitly rather than guessing.
  - **The node row is UNCHANGED afterwards** — same `cert_serial`, still revoked. *A refusal that already mutated
    something is not a refusal.*
  - The control plane's own log names the real reason where an operator can read it and an attacker cannot:
    `rekey_refused reason="node is revoked..."`.
- **THIS IS THE PROPERTY THE EPIC WOULD BE UNSAFE WITHOUT.** Expiry is an absence of action; revocation is the
  presence of a decision. A cryptographic proof may overturn the first, never the second — because proof of
  possession cannot distinguish the legitimate holder from whoever took the key.

### 3b — locally, driving the endpoint directly

The uniform-refusal discipline now spans **two identifiers** (D10), and 3a exercises one path through one of them.
Locally, drive the endpoint itself and compare responses **byte for byte**:

```bash
# [local] each must return the SAME status, the SAME error code and the SAME message
for id in '{"cert_serial":"nobody-has-this"}' \
          '{"key_fingerprint":"0000000000000000000000000000000000000000000000000000000000000000"}' \
          '{"cert_serial":"x","key_fingerprint":"0000000000000000000000000000000000000000000000000000000000000000"}' \
          '{"key_fingerprint":"not-hex"}' \
          '{}' ; do
  N=$(curl -s -X POST localhost:8080/api/v1/agent/rekey/challenge -H 'content-type: application/json' -d "$id")
  echo "$id -> $N"
done
```

Add the two cases the fold closed:

```bash
# [local] #12 — a NUL in the serial reached a Postgres text bind and returned 500. Must now be the uniform 403.
curl -s -o /dev/null -w '%{http_code}\n' -X POST localhost:8080/api/v1/agent/rekey/challenge \
  -H 'content-type: application/json' --data-binary $'{"cert_serial":"abc\u0000def"}'    # -> 403, never 500

# [local] #18 — maxLength is gone from both identifier fields, so an over-long value is refused by the HANDLER
# (403) rather than by the schema validator (400). Any 400 here is the oracle the paper says it denies.
curl -s -o /dev/null -w '%{http_code}\n' -X POST localhost:8080/api/v1/agent/rekey/challenge \
  -H 'content-type: application/json' -d "{\"cert_serial\":\"$(python3 -c 'print("a"*5000)')\"}"   # -> 403
```

- **PASS:** a **nonce** for the two well-formed single-identifier cases (anti-enumeration: the challenge never
  confirms existence), and the **identical 403 refusal** for both-identifiers, malformed, and neither — never a 400,
  because a schema violation answering differently from an unknown identifier tells a prober how far they got.
- Then the same comparison on `/agent/rekey` with a garbage signature: unknown serial, unknown fingerprint, live
  node and wrong key must be **the same response**.

---

### 3c — A LIVE NODE, ITS OWN KEY, REFUSED (NEW — the delivery marker made this walkable)

**This behaviour did not exist when the runsheet was written, and the first version of the fix got it WRONG.** The
D3/D10 collision was first closed with a carve-out keyed on *the caller proving the currently-recorded key* — which
a LIVE gateway's key-holder also satisfies. Because re-key replaces `cert_serial`, and the agent channel
authenticates against exactly that column, exercising it **displaced the running gateway**. It needed only the
private key, never the certificate.

The predicate is now **delivery**: a running gateway's certificate has authenticated, so it is marked delivered,
so it cannot be redelivered. The live case is unreachable rather than refused — and this leg proves that on a wire.

**Subject: gateway A after Leg 1**, recovered and running normally.

```bash
# [gateway A] the material an attacker with filesystem access would have — the KEY ALONE, no certificate.
sudo cat /var/lib/tunnex-node/key.pem > /tmp/stolen.key      # gitignore scratch key material AT CREATION
# compute the fingerprint the way the agent does, and drive the endpoint directly from ANOTHER host:
openssl rsa -in /tmp/stolen.key -pubout -outform DER 2>/dev/null | openssl dgst -sha256 -hex
```

```bash
# [azure-cp] the row that must be UNTOUCHED, before and after
sudo docker exec tunnex-postgres-1 psql -U tunnex tunnex -c \
  "SELECT name, cert_serial, cert_delivered FROM nodes WHERE name='<A>';"
```

Then submit a full re-key from a third host using the stolen key: challenge by `key_fingerprint`, sign
`(nonce ‖ CSR DER)` with it, CSR over the same key.

- **PASS:** refused with the uniform 403, `cert_serial` **unchanged**, and gateway A's tunnel never drops.
- **THE FAILING OBSERVATION, NAMED:** if the serial moves, gateway A takes 401 `unknown_agent` on its next
  request and the walk has reproduced the takeover this fix exists to remove.
- **EVIDENCE:** the before/after node row, gateway A's agent log across the window, and the CP log line naming
  which rule refused.
- **Delete `/tmp/stolen.key` when the leg ends**, and never commit it.

---

## Leg 4 — THE OPERATOR RESTORE, walked as a FALSIFICATION ATTEMPT

**Source: gateway C** (revoked in Leg 3a, its devices cascade-revoked with it). **Target: B′** — gateway B after
its token re-enrolment in Leg 2, which is a fresh live node. Leg 2 and Leg 3a must both be done first.

### What this leg is now, and the trap it must not fall into

The leg was written to expose a defect: `RestoreCascadeRevokedDevices` had one caller (`Rekey`), devices are
cascade-revoked in one place (`Revoke`), and `Rekey` refuses a revoked node — so the trigger that created the work
put the node into the one state that could never reach the code that undid it. **Slice 7 was then built to fix
exactly that**, adding the operator-initiated restore.

**So a leg that now walks Slice 7's happy path is a confirmation wearing a falsification's clothes.** The code was
written against this leg; of course the endpoint returns 200. That proves the author and the walker agree, which
is worth nothing.

The claim under test therefore moves one level up, to the thing Slice 7 does **not** self-evidently establish:

> **A restored device is back IN SERVICE — not merely back to `status='active'`.**

That is falsifiable, and it is the claim Wall 6 actually made.

### THE FALSIFYING OBSERVATIONS — write these down before running anything

The leg **FAILS** on any one of these. They are listed first, deliberately, so the result cannot be read backwards
from whatever happens.

| # | observation that FALSIFIES the claim | why it is a real risk, not a formality |
|---|---|---|
| **F1** | the restored device appears in `psql` as `active` on B′, but **`wg show` on B′ does not list its peer** | the restore is a database write plus a push. If the push does not place the peer, the device is "restored" into a config the data plane never learned |
| **F2** | the device is active and peered, but **cannot pass traffic with the config it already holds** | its existing config embeds the **old gateway's endpoint and public key**. Re-homing changes `node_id` in the row; it cannot change a file on the user's laptop |
| **F3** | ~~F2 happens and nothing tells the user~~ — **CONFIRMED AT THE DESK AND SINCE FIXED**; `provisioned_node_id` now carries the gateway and Leg 6 tests the fix | the prediction recorded before the walk was that F3 would fire. It did, from code, at `2c6a314`. The fix is folded; the leg that tests it is Leg 6, with a NEW falsifying condition |

**My prediction, recorded before the walk so it cannot be adjusted after: F3 WILL FIRE.** I can find no code that
compares the issued config's gateway against the device's current node, and the re-home path is new. If the walk
refutes that prediction, the prediction was wrong and the leg passes — which is the point of writing it down.

> **OUTCOME: the prediction held.** Confirmed by reading the code at `2c6a314` (annotation below), fixed in fold
> Batch C. **F3 is therefore no longer a falsifying observation for this leg** — it has been answered. What
> remains open here is F1 and F2, which the desk could not settle.

**F1 and F2 are genuinely open.** I have not traced the push far enough to predict them, and a walk is what
settles that.

> ### ANNOTATION — F3 CONFIRMED FROM CODE, checked at `2c6a314` (2026-07-31, desk, read-only)
>
> The prediction above is left EXACTLY as written; this is appended, not edited. A prediction recorded in advance
> is worthless if it can be rewritten afterwards.
>
> **Outcome: CONFIRMED.** `needs_reexport` derives from five inputs at `internal/http/device_handlers.go:57-58` —
> provisioning mode, the baked ranges snapshot, the org's current routed ranges, `provisioned_ip`, `assigned_ip`
> (`internal/devices/staleprofile.go:48-56`). **Gateway identity is not among them**, no `provisioned_node_id` /
> `_endpoint` / `_public_key` column exists, and no code anywhere compares the gateway baked into an issued config
> against the device's current `node_id`. The config does embed it: `internal/devices/config.go:39-40` writes
> `PublicKey` (the gateway's) and `Endpoint`.
>
> **Refinement the walk should still test — the blast radius is narrower than the prediction implied.** The WF-A
> dial channel can re-point a RUNNING device, but `nodes.NodeDial` (`internal/nodes/service.go:868-874`) derives a
> dial only when the device's node is a **hub-set member**; otherwise it returns `derived=false` and the client
> keeps its baked endpoint. So:
>
> | device | after a re-home | warned? |
> |---|---|---|
> | static export | never polls; keeps the old gateway forever | **no** |
> | managed, target NOT in the hub set | `derived=false`, keeps the baked endpoint | **no** |
> | managed, target IS a hub-set member | swaps peer on the next poll | n/a — follows automatically |
>
> **What the walk must therefore record:** which of the three rows each restored device falls in, because a rig
> whose replacement gateway happens to be a hub-set member would show managed devices reconnecting on their own
> and could be read as "F3 did not fire". It fired; that rig just picked the one row where it does not bite.
>
> Ranked with review pass 1's findings as **desk-found**. NOT fixed here.

If all three hold clean, the leg passes and Wall 6 is closed on the wire. If F3 fires alone, the mechanism works
and the *surface* is incomplete — a finding, held, not fixed here.

### REBASED ON BATCH C — four behaviours in this path changed under the leg

| fold | what to observe HERE |
|---|---|
| **#7** the target node is read `FOR UPDATE` and must be active | restoring onto a **revoked** target is refused. Try it deliberately: name gateway C (the revoked one) as the target and require a refusal, then confirm no device row moved |
| **#8** devices return to the status the cascade FOUND | stage one device as `pending` (never approved) before revoking C. It must come back **pending**, not active. With the org's approval gate ON, this is the difference between a restore and a silent approval |
| **#9** OpenVPN certificates are revived with the device | if any restored device is OVPN, its `ovpn_client_certs.revoked_at` must be NULL afterwards **and the org CRL must have been rebuilt** — otherwise the device is active and the gateway still refuses its credential |
| **#14** an address outside the org's CURRENT pool is not reclaimed | only observable if the pool was shrunk between revoke and restore. Optional on the rig; unit-proven |

```bash
# [azure-cp] #8 — stage the never-approved device BEFORE revoking C
sudo docker exec tunnex-postgres-1 psql -U tunnex tunnex -c \
  "SELECT name, status, revoked_prev_status FROM devices WHERE node_id='<C-id>' ORDER BY name;"
# after the restore, the same query: `was-pending` must read status='pending', revoked_prev_status=NULL
```

### Forcing the re-address case — PINNED: deliberate pre-allocation

Half this leg is the reclaim-first behaviour, and with a roomy pool it never fires: the allocator hands the
restored device a fresh address, the `readdressed` path is never taken, and the leg silently proves half of what it
claims. **Correct code whose trigger never co-occurs — the same shape as the defect this leg exists for.**

**Mechanism (pinned; do not substitute a pool resize):** after C is revoked and before the restore, create a decoy
device on B′ and confirm it took the address the `contended` device held.

```bash
# [azure-cp] 1. the address to contend for — captured BEFORE anything is created
sudo docker exec tunnex-postgres-1 psql -U tunnex tunnex -c \
  "SELECT name, status, revoked_cause, assigned_ip FROM devices WHERE node_id='<C-id>' ORDER BY name;"
#    record: contended = <the assigned_ip of the device named `contended`>

# 2. create a decoy device on B′ in the UI, then CONFIRM it took that exact address
sudo docker exec tunnex-postgres-1 psql -U tunnex tunnex -c \
  "SELECT name, assigned_ip FROM devices WHERE name='decoy-1';"
```

- Cascade-revoked rows **keep** `assigned_ip` but are excluded from `ListActiveDeviceAllocations` (status filter),
  so that address reads as free and the allocator should hand it to the next device created.
- **If `decoy-1` did NOT take it**, create `decoy-2`, `decoy-3` … and check each. **Bound it at five.** If five
  decoys have not taken the address, STOP and record it: the allocator does not behave as assumed, which is itself
  worth knowing, and the pool-resize fallback goes in the record as a deviation rather than being done silently.
- The `keeps` device's address must be left **untouched**, so one device reclaims and one cannot. Both halves in
  one restore is the only way to see the discrimination work.

### Sequence

```bash
# [azure-cp] BEFORE — the cascade, with addresses PRESERVED
sudo docker exec tunnex-postgres-1 psql -U tunnex tunnex -c \
  "SELECT name, status, revoked_cause, assigned_ip FROM devices WHERE node_id='<C-id>' ORDER BY name;"
```

- **PASS criterion 0, independent of everything else:** cascade-revoked devices **keep `assigned_ip`**. Revocation
  preserves what it invalidates; a revoked row that lost its address made the original unreclaimable *in principle*.

Then, in the UI: **Gateways → the revoked C → "Restore devices" → choose B′.** Zero-touch bar applies — if this
needs a `curl` because the affordance is missing or broken, that is a finding.

- **PASS:**
  - `restored=2`, `readdressed=1` — `keeps` reclaims its address, `contended` gets a fresh one;
  - both rows now `active` **and `node_id = B′`**;
  - audit: one `node.devices_restored` naming **the human**, plus per-device `device.restored` /
    `device.restored_readdressed` carrying `previous_node_id`;
  - **F1 checked:** `wg show` on B′ lists both peers;
  - **F2 checked:** the `keeps` device, using **the config it already had**, connects and passes traffic through
    B′ — or does not, which is F2;
  - **F3 checked:** the Devices list shows **`config out of date`** for `contended` (address changed) — and what it
    shows for `keeps`, which is the prediction.

## Leg 5 — A DELIBERATELY-REVOKED DEVICE STAYS DEAD

Rides Leg 4. The third device (prerequisite 4) was revoked **by an admin** before the gateway was, so it carries
`revoked_cause='deliberate'`.

**EXTENDED BY #9.** Revocation is a three-part act, so the discrimination has to hold in all three places. If the
deliberately-revoked device is an OpenVPN one, its **certificate** must also stay revoked and stay on the CRL:

```bash
# [azure-cp] the deliberate device's certificate must survive the restore, revoked
sudo docker exec tunnex-postgres-1 psql -U tunnex tunnex -c \
  "SELECT d.name, d.status, d.revoked_cause, c.revoked_at, c.revoked_cause
   FROM devices d LEFT JOIN ovpn_client_certs c ON c.device_id = d.id
   WHERE d.node_id='<C-id>' ORDER BY d.name;"
```

- **PASS:** after any restore, that device is **still revoked**, still `deliberate`, and **no** `device.restored`
  audit row names it.
- **WHY IT MATTERS MORE THAN IT LOOKS:** a gateway rebuild that quietly revives a laptop an admin revoked is a
  security regression wearing the costume of a convenience. The two-cause discrimination is the whole mechanism, and
  this leg is the only place it is observable end to end.

---

## Leg 6 — THE STALENESS SURFACE, walked for SENSITIVITY **and** SPECIFICITY

**REWRITTEN: F3 was confirmed and fixed, so this leg tests the fix — and it carries the same constraint Leg 4 got.**

The original leg asked whether the surface stays silent when it should speak. It does; that was confirmed at the
desk at `2c6a314` and fixed in Batch C (`provisioned_node_id`, compared for static exports). **A rewrite describing
that fix's happy path would convert a falsification into a confirmation**, which is exactly what this walk must
not do.

### The NEW falsifying condition, and it is a real one

The claim has moved. It is no longer *"does the surface notice a re-home"* — that is now code with a red. It is:

> **The staleness surface is TRUSTWORTHY: it fires when a device's issued config is dead, and stays silent
> otherwise.**

A warning surface has two failure modes and only one of them has ever been tested. Nothing on any wire has
verified the second.

| # | falsifying observation | why it is live, not a formality |
|---|---|---|
| **G1 — insensitive** | a re-homed STATIC export shows nothing | the fix's own claim; a red covers it, so this is the weaker half |
| **G2 — UNSPECIFIC** | a device that was **never re-homed** shows `config out of date`, or a re-homed one keeps showing it **after being re-issued** | **the snapshot is written at issuance by one code path and compared by another.** If `provisioned_node_id` is written wrong, or not written at all for some creation path, every static device in the fleet shows a permanent warning — and a permanent false positive is WORSE than the gap it replaced, because it trains operators to ignore the surface. The unknown-is-not-stale rule exists for exactly this, and nothing has checked it on real data |
| **G3 — the known residual, observed rather than assumed** | a **managed** device re-homed onto a NON-hub-set gateway shows nothing and cannot connect | registered, not fixed. The walk must RECORD which of the three rows each device fell in, because a rig whose replacement gateway happens to be a hub-set member shows managed devices self-healing and could be misread as "no residual" |

**I can write a failing condition for this leg, and G2 is it.** The specificity half has no wire evidence at all.

```bash
# [azure-cp] SPECIFICITY — the whole fleet, before anything is re-homed. Every static device must read false.
sudo docker exec tunnex-postgres-1 psql -U tunnex tunnex -c \
  "SELECT name, provisioning_mode, provisioned_node_id IS NOT NULL AS snap, node_id = provisioned_node_id AS same
   FROM devices WHERE status='active' ORDER BY name;"
```

- **PASS — sensitivity:** the re-homed static device shows **`config out of date`**, and re-importing its new
  config clears the badge AND restores connectivity.
- **PASS — specificity:** every device that was **not** re-homed shows **nothing**, including the one that kept its
  address, and including every device created before the column existed (`snap = f` must render silent).
- **RECORD for G3:** for each restored device, which row of the table above it fell in.
- **NEGATIVE HALF, unchanged and still required:** a device with no snapshot at all shows nothing. Unknown is not
  stale.

---

## Leg 7 — LOST-RESPONSE RECOVERY (D10) — REWRITTEN: it now recovers IN-PROCESS

**Local.** The scenario is unchanged: the control plane commits a re-key and the answer is lost, so it holds a
serial the agent never received. **Two things about it changed under this runsheet.**

1. **The agent recovers without being restarted** (#6). `pendingWasOnDisk` used to be sampled once before the
   retry loop, so the process that suffered the lost response never tried the fingerprint identity that its own
   pending key exists to provide. It is now rebuilt every pass.
2. **The control-plane predicate changed twice.** A lost commit advances `cert_not_after`, so the node reads live
   and the gate refused the very recovery D10 exists for. It is now keyed on **delivery**: that certificate was
   never used, so redelivery is authorized — and a *delivered* certificate is not, which is Leg 3c.

- **PASS:**
  - the CP logs `node_rekeyed` while the agent logs no `agent_rekeyed` (it never saw the answer);
  - `rekey-pending-key.pem` exists in the state dir — written **before** the request went out;
  - **the same process recovers**, with no restart, logging `agent_rekeyed identified_by=key_fingerprint ...`;
  - the node id is unchanged and `cert_delivered` reads FALSE between the commit and the agent's first
    authenticated request;
  - after promotion the pending file is **gone**.
- **CONVERGENCE:** a second lost response must not walk the identity forward — the pending key is reused, so
  repeated failures converge on one identity.

---

## Leg 8 — A SAVE FAILURE AFTER THE COMMIT (NEW — claims 7/15)

**Local.** This behaviour did not exist when the runsheet was written, and the old behaviour destroyed identities.

A `saveCreds` failure **after** the control plane committed used to be terminal: the CP had spent its one
issuance, the agent could not write it, and the loop fell through to the join token — **trading a full disk for
the node's identity, its site binding and every device homed on it.** Under the undelivered predicate that
certificate was never used, so a retry is legal and the loop takes it.

```bash
# [local] fill the state dir's filesystem, or bind-mount it read-only, THEN trigger recovery with a token present.
```

- **PASS:** `agent_save_creds_failed` appears, the agent **does not enrol**, and a later pass recovers **the same
  node id** once the write can succeed.
- **THE FAILING OBSERVATION:** a new node appears in the Gateways list. That is the identity being destroyed by a
  local disk condition, which is the defect.
- **Why a token must be present for this leg:** without one there is nothing to fall through TO, and the leg would
  pass for the wrong reason.

---

## Anti-checklist — every claim proven dead, not assumed

| claim | proven by | not by |
|---|---|---|
| recovery keeps the identity | node id + `site_id` unchanged, audit succession | "the gateway is green again" |
| a revoked gateway cannot recover | the row **unchanged** after the attempt | the attempt returning an error |
| refusals are uniform | responses compared **byte for byte** across six conditions | each one being "a 403" |
| the coverage limitation is honest | the agent's refusal log **read as text** | the code containing a log call |
| devices come back | audit rows + `active` status per device | the gateway having *some* peers |
| a deliberate revoke survives | that device still revoked, **no restore audit row naming it** | the count of restored devices |
| the address change is visible | the badge on a **managed** device | the badge existing for static exports |

## Registered residuals to carry into the walk

- **The Leg 4 premise finding** — surfaced above; a decide-item, not a walk finding.
- **The rolling-upgrade shim (0061)** — `cert_serial` is written but unread this release. The **contract migration**
  (drop it, `identifier NOT NULL`, collapse the `coalesce`) triggers on the release after this one.
- **No general rate limiting** — the re-key routes have their own throttle; login, enrolment and the wider API do
  not. Registered, still owed.
- **Body-size limits** exist only on the two re-key routes.
- **Failover hysteresis counters reset on leadership change** — beta-blocking, owned by the failover story.
