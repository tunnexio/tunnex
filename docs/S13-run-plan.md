# EPIC 13 — RUN PLAN: three distinct runs, three different purposes

**Do not run `docs/S13-boxwalk.md` end to end at a 48-hour TTL.** The legs are one sheet; the *runs* are three,
and they buy different things. Running the full sheet at 48h would spend two days re-proving what §A already
proved at ten minutes.

| run | TTL | purpose | state |
|---|---|---|---|
| **§A** rehearsal #1 | 10m | the epic's mechanics, end to end | **COMPLETE** 2026-07-31 |
| **§B** rehearsal #2 | 10m | the five items §A could not cover, + Legs 7/8, + refusal TIMING | pending |
| **§C** the 48h run | **48h (default)** | **that the shortening knob did not change behaviour** — nothing else | pending |

---

# ⛔ A FIXTURE MUST PRESERVE THE RELATIONSHIP BETWEEN VALUES, NOT THEIR ABSOLUTE MAGNITUDES

**Founder-ruled 2026-08-01, from WF-S13-10. This rule is why §A and §B ran a configuration production has never
run, and it binds every future TTL shortening.**

**Production holds an invariant: `renewEvery` (24h) `<` certificate TTL (48h).** The agent renews at a fixed 24h
tick, comfortably inside a 48h certificate, forever.

**The rig shortened the TTL to `10m` and left `renewEvery` at its 24h default — INVERTING the invariant.** The
agent then renews **exactly once** (its first tick is anchored to the certificate's remaining life) and never
again, because `renewLoop` resets to the fixed interval and never re-anchors to the certificate it just
received. A gateway on this rig therefore dies ~10 minutes after every restart and stays dead for 24 hours.

**THE RULE: when a walk shortens one side of a relationship, it MUST shorten the other side proportionally.**
Shortening TTL to `10m` requires `TUNNEX_AGENT_RENEW_INTERVAL` well below `10m` (the rig uses `2m`). A fixture
that changes one magnitude and not its counterpart is **not a faster production — it is a different system**, and
what it proves does not transfer.

## WHICH LEGS RAN UNDER THE INVERTED INVARIANT — so a reader knows what §A actually proved

**§A (Legs 0-6, 2026-07-31) and §B (steps 1-4, 2026-08-01) both ran at `TTL=10m` with `renewEvery=24h`.**

**UNAFFECTED — these do not depend on renewal at all, and they stand:**
- the PoP re-key path, its refusals, and the uniform-refusal measurement (`403 / 178 bytes` × 8 inputs)
- finding **#5** (three refusals → `exhausted` → fallback) and **#6** (`identities_tried` 1 → 2)
- **F3** in isolation, specificity (`decoy-1` silent), **B1** (`site_id` survives recovery)
- **WF-S11-8a** (the name freed by a revoke), the cascade/restore legs

**AFFECTED — read these knowing the mechanism:** every observation of *"an agent whose certificate expired while
it was running."* On this rig that state was reached because **the renewal timer was 24 hours away**, not because
a renewal was attempted and refused. **WF-S13-6 is NOT invalidated** — boot-only recovery is established by
reading `attemptRekey`'s single caller, and the incident that opened the epic was a real 48h production gateway —
**but instances 2, 3 and 4 are WF-S13-10 reproductions, not WF-S13-6 reproductions.** They prove the agent does
not recover while running; they do not prove how production gets there.

**Second and larger instance of the fixture-fidelity rule pass 1 minted for the `certexpiry` shortcut:** *where a
runsheet manufactures a state, it must say how production reaches that state, and whether the manufactured route
differs.* Here the manufactured route differed, and the difference **was** a defect.

---

# RIG ACCESS — THE STANDING RULE. Founder-ruled 2026-08-01. Read before running anything.

The agent has **direct SSH to the rig** (`azure-cp`, `aws-gw-1`, `aws-gw-2` — aliases in `~/.ssh/config`, keys in
`ssh-agent`). **The split is by EFFECT, not by host.**

## FREELY — no asking. Everything that cannot change fleet or host state.

`psql` SELECTs · `docker logs` · `docker ps` / `inspect` · `wg show` · `git` · file reads · `curl` GETs.

## ASK FIRST — every time, with the EXACT command shown. Anything that MUTATES.

`docker run` / `stop` / `restart` / `rm` · any `psql` INSERT/UPDATE/DELETE · **any API call that creates,
revokes, approves or otherwise does what a UI button does** · `.env` edits · image builds or loads on a rig host.

**Why this is not distrust, and why it must survive into future sessions.** Every fleet mutation before now went
through the founder *because the agent could not execute one* — the `azure-gw` hand-revoke, §A's device revokes,
the option-5 placement. **That gap is where the scaffolding-vs-product-action distinction got recorded**, and it
is the reason the walk record can say honestly which states the product cannot produce. SSH removes the gap by
accident. The rule keeps it **deliberately**.

## Four more rules that ride with it

1. **ALWAYS the SSH host ALIAS, never a raw IP.** The wrong-host paste cost an hour on 2026-08-01 (a credential
   pointed at a decommissioned CP). The alias puts the target inside the command where it can be read.
2. **Before any mutation on a gateway, ECHO the host and its expected ROLE** (A / B′ / A1′ / control). A mutation
   whose target was never stated cannot be audited afterwards.
3. **Timed sequences MAY be scripted end to end** — §B's expiry window, §C's clock. This is where direct access
   genuinely beats pasting: a human-latency gap between steps changes what B6 measures.
4. **RECORD which commands the agent ran directly and which the founder ran.** Provenance of the evidence matters
   as much as the evidence. The walk record marks every block.

---

# §A — REHEARSAL #1 (COMPLETE)

Ran 2026-07-31 at `TUNNEX_AGENT_CERT_TTL=10m`. CP `c417c85`, enterprise, schema 64. Full record:
`walk-artifacts/S13.1/walk-record.md`. **Legs 0, 1, 2a, 2b, 3a, 3b, 4, 5, 6 PASS.**

## Two amendments this run forced, which §B and §C inherit

**1. Two hosts, sequenced — not three hosts.** The sheet asks for three expired subjects. The fleet has **two
usable VM agent hosts**, so **A and C are the same box in different states, run in order**: aws-gw-1 recovers by
PoP (Leg 1), is then revoked, expires again, and becomes Leg 3a's subject. This preserves the sheet's actual
requirement — B's refusal (keyless) must never be conflated with C's (revoked) — because B's key stays unrecorded
while C's is recorded throughout.

**2. `azure-gw` cannot host a second agent.** It runs the node-agent **inside k3s**, serving the `k8s` row with
host networking, owning `wg0`. A second host-network agent contends for the same interface. azure-gw is not a
spare gateway host. (`docs/infra-inventory.md`.)

## What §A proved that the others need not repeat

- Uniform refusal **measured**: `403 / 178 bytes` for eight distinct wrong inputs and for two different internal
  causes, against `200 / 57 bytes` for both well-formed identifiers.
- Finding **#6** on the wire: `identities_tried` 1 → 2 across attempts.
- Finding **#5**: three refusals → `exhausted` → fallback, no operator action.
- **F3 in isolation**: `static-keeps` badged with its address unchanged.
- **Specificity**: `decoy-1` silent.
- Findings raised: **WF-S13-1** (registered), **WF-S13-3** (HIGH, fixed), **WF-S13-4**, **WF-S13-5**;
  **WF-S13-2 withdrawn**.

---

# §B — REHEARSAL #2 (10-minute TTL)

**Purpose: the five items §A could not cover, plus the two local legs, plus refusal timing.** ~30 minutes of wall
clock. Same TTL knob, same rig, one staging cycle.

```bash
# [azure-cp] the knob stays at 10m for this run — confirm it is ACTIVE
grep TUNNEX_AGENT_CERT_TTL .env                    # exactly ONE line, =10m
sudo docker compose logs api 2>&1 | grep agent_cert_ttl_shortened | tail -1   # MUST be present
```

## B0-PRE — B′ IS STUCK. The restart that unblocks staging IS EVIDENCE — record it.

At §B staging, B′ (`aws-gw-2`) was found expired and looping `tls: expired certificate` with **no re-key attempt
of any kind** — WF-S13-6. Staging cannot proceed on a dead gateway, so B′ must be restarted.

**That restart is not housekeeping. It is the manual step the epic exists to remove**, performed by hand, on the
walk that is meant to prove the epic. Record it as a line in the walk record with its timestamp and this reason —
**not silently, and not in a shell you do not narrate.**

```bash
# [aws-gw-2] the manual intervention WF-S13-6 forces. Record the time.
sudo docker restart tunnex-node
sudo docker logs --tail 30 tunnex-node 2>&1 | grep -iE "rekey|recovered|identity"
```

Recovery is expected to succeed **on boot** — that is the path that works.

> ### §B's Leg 1 TESTS THE BOOT PATH ONLY. Say so in the record.
>
> Every §B recovery is a stop-then-start, so §B proves boot-time recovery and **nothing about runtime expiry**.
> It is not a weaker version of the acceptance leg; it is a different leg. **§C's C-LEG-0 is the only place the
> runtime case is proven**, and it does not run until the remedy lands.
>
> **B1–B4, B6 and B7 are CP-side and unaffected by the agent remedy** — they stay valid whatever shape the fix
> takes, which is why §B continues now rather than waiting.

## B0a — PROVENANCE: §B runs the SAME BINARY as §A. Do not rebuild.

Everything committed between §A's run and §B is **documentation plus two dev scripts** (`scripts/mutate.sh`,
`scripts/prove-fix.sh`) — no `apps/` code and **no migrations**. Verify rather than trust:

```bash
# [azure-cp] pull the docs; the image is already correct
cd ~/tunnex && git merge --ff-only origin/story/S13.1-gateway-recovery
git log --oneline -1                                     # 779f1a0 or later
git diff --name-only c417c85..HEAD | grep -vE '^(docs/|walk-artifacts/|scripts/)' | wc -l   # NON-ZERO now — see below
sudo docker exec tunnex-postgres-1 psql -U tunnex tunnex -tAc "SELECT max(version) FROM schema_migrations;"   # 64
```

> ### AMENDED 2026-08-01 — the checkout now contains AGENT CODE, and §B still must not rebuild
>
> When this section was written the checkout was ahead of the image by documentation only, and the provenance
> check printed `DOCS ONLY`. **It no longer does**, and a fresh session reading the old instruction would see a
> list of twelve Go files and reasonably conclude the rig was stale.
>
> **It is not stale — it is deliberately split.** The checkout carries the pass-3 fold (`63afd7e`, `fa35e63`,
> `7d5f7ca`, `b152c27`): the widened identity gate, `identityWatchLoop`, the throttle rotation, the golden
> vector. **None of that is §B's subject.** §B tests CONTROL-PLANE behaviour — site binding survival, the
> `cert_delivered` flip, recorded prior status, F3's residual, refusal timing — against the SAME binary §A used,
> which is what makes the two runs comparable.
>
> **The agent fixes are §C's subject**, and §C is where they get their rebuilt image (see §C PREREQUISITES).
>
> **So: `make up-enterprise` must still NOT run for §B.** The rule is unchanged; only its reason is. It used to be
> "nothing has changed." It is now "what changed belongs to the next run."

**RECORD THREE SHAS, not one.** The running api image is built from **`c417c85`**; the checkout is **`5249aa9`**;
the diff between them is **docs + `scripts/` only — no `apps/` code, no migrations**. All three go in the walk
record. A later reader seeing image ≠ checkout cannot otherwise tell *deliberate* from *stale*, and this session
opened with exactly that shape read the other way: the rig sat on `5cf282f` while local was 24 commits ahead, and
the only thing that caught it was a schema-version mismatch. **Divergence is not evidence of staleness and
sameness is not evidence of currency — the DIFF is the evidence, so record the diff.**

**`make up-enterprise` must NOT run for §B.** Rebuilding would swap the artifact under the walk for no gain, and
it would cost the thing that makes §B worth running: §A and §B execute the *same* binary, so a §B result that
differs from §A is a difference in the **staging**, not in the build. That is what makes the two runs comparable
rather than merely consecutive.

`git fetch` is not `git pull`. On 2026-07-31 the rig ran `fetch`, reported success, and stayed seven commits
behind — the second instance of the standing hazard, in a different disguise from the first. **Read the sha
back after pulling; do not infer it from the command's exit status.**

## B0 — STAGING ORDER (ruled 2026-07-31). Read before touching anything.

**The roles INVERT from §A.** After §A, `aws-gw-1` is revoked — D3 forbids its recovery — so the only live,
key-recorded gateway is **B′** (`aws-gw-2`, node `019fb892…`). B′ is therefore rehearsal #2's **subject**, and a
re-enrolled `aws-gw-1` is the **restore target**.

Two rulings fixed the order:

- **Approval gate: ON for staging, OFF after B3.** A `pending` device cannot connect (no peer), so B4's managed
  device must be **approved** before it is asked to demonstrate anything. Turning the gate off afterwards leaves
  the org as we found it; existing `pending` rows stay pending, which is what B3 needs.
- **B6's timing runs in the window between expiry and recovery**, against B′ itself. That is the only moment the
  wrong-key population exists — expired, active, key-recorded — without a fourth agent host the fleet does not
  have.

| # | step | why here |
|---|---|---|
| 1 | re-enrol **aws-gw-1** — **under its OWN name**, fresh token → new row **A1′** | the restore target for B3/B4; aws-gw-1 is revoked and cannot come back any other way. **See B0b: the name is free** |
| 2 | **bind B′ to a site** (Sites → Bind gateway) | B1's precondition — the claim is that `site_id` SURVIVES recovery, so it must exist first |
| 3 | approval gate **ON** | B3 needs a device that is `pending` and stays that way |
| 4 | create on B′: `b3-pending` (leave unapproved) · `b3-active` (approve) · `b4-managed` (approve, managed) · optionally a static | B3 needs both prior statuses; B4 needs a managed device whose address will be RECLAIMED |
| 5 | **connect** `b3-active` and `b4-managed` | a device that never worked cannot show it stopped working |
| 6 | **stop B′'s agent**, record `cert_not_after` at the stop, wait ~10 min | the clock |
| 7 | **B6 — timing**, N BOUNDED | the only window where B′ is expired + active + key-recorded |
| 7a | **drain the throttle**, confirm | B6 spends the SAME bucket Leg 1 needs — see B6's bound |
| 7b | **B7 — saturate deliberately**, then start the agent | measures finding #4 and the agent's 429 handling in one motion |
| 8 | start **B2's poller**, then start B′'s agent | B1 + B2 + Leg 1 in one motion |
| 9 | **revoke B′** → cascade. Assert `revoked_prev_status` is RECORDED | the column §A found empty (WF-S13-3) |
| 10 | **restore onto A1′** | B3 (pending returns pending) + B4 (managed, address reclaimed, gateway moved → NO badge) |
| 11 | approval gate **OFF** | leave the org as found |
| 12 | **B5 — Legs 7/8** locally | independent of the rig; any time |

### B0b — the name is FREE. An earlier rename instruction was wrong; it is withdrawn.

A draft of step 1 said to enrol as `aws-gw-1b` because *"the old name is taken by a revoked row."* **That was
wrong, and it contradicted §A's own record** (Leg 2b: *"name freed by the revoke (WF-S11-8a)"*). Checked at both
layers rather than argued:

- **Schema.** Migration **0056** replaced the unconditional `nodes_org_id_name_key` with
  `CREATE UNIQUE INDEX nodes_org_id_name_active_key ON nodes (org_id, name) WHERE revoked_at IS NULL`. In schema
  64. A revoked row does not hold its name.
- **Application.** `nodes/service.go:297` raises `409 node_exists` **only** from `pgerr.IsUnique` on
  `CreateNode` — so it fires only for a **non-revoked** duplicate. There is no independent Go-side name check.
- **Lookups.** `GetNodeByOrgName` carries `AND revoked_at IS NULL` (`nodes.sql:65`), and
  `TestNoAmbiguousNodeNameLookups` (`apps/api/db/nodenamecensus_test.go`) is the standing guard.

**So why did §A's enrol refuse `aws-gw-2`?** Because that name was held by an **ACTIVE** row at that moment.
Leg 2's token fallback **creates a new node without revoking the old one** — `019f8e49` was revoked only later.
The 409 was correct and WF-S11-8a was working. The error was mine: I generalised one refusal into a rule about
revoked rows that the evidence never supported, then wrote a workaround for it.

**Both `aws-gw-1` rows are revoked today, so step 1 enrols under the real name — and that is a FREE PROOF.**
§A never exercised WF-S11-8a, because its only name collision was against an active row. Step 1 is the first
time a merged S11 guard is tested on the wire: **if it 409s, that is a regression in a merged fix, found on the
S13 walk — raise it as a finding, do not rename around it.**

**WF-S13-4 will not interfere**: it fires only when a device cannot reclaim and allocates fresh. Stage no decoy,
so every device reclaims and B4's "only the gateway moved" holds.

## B1 — Leg 1 with a SITE-BOUND gateway

§A's Leg 1 asserted *"`site_id` unchanged across recovery"* against a node that **had no site binding** — trivially
true, therefore untested. It is one of the epic's headline claims.

**Before staging:** Sites → `aws-site` → **Bind gateway** → `aws-gw-1`. Confirm `site_id IS NOT NULL`, then run
Leg 1 as written and assert `site_id` is **identical** before and after.

## B2 — catch `cert_delivered` false → true

The window is seconds: re-key clears the marker and the agent authenticates immediately after promotion. §A's
sample landed after the flip. **Start the poller BEFORE starting the agent.**

```bash
# [azure-cp] start this FIRST, then start the agent on aws-gw-1
for i in $(seq 1 600); do
  sudo docker exec tunnex-postgres-1 psql -U tunnex tunnex -tAc \
    "SELECT now()||' '||cert_serial||' delivered='||cert_delivered
     FROM nodes WHERE id='<A-node-id>';"
  sleep 0.2
done | uniq | tee /tmp/delivered-flip.log
```

**PASS:** the log contains a line with the **new** serial and `delivered=f`, followed by one with `delivered=t`.
That transition is the D3 gate's entire input — re-key clears it in the same CAS, `AuthenticateCert` sets it on
first use, and a marker that never clears makes lost-response recovery impossible.

## B3 — #8's recorded-prior-status path (unblocked now WF-S13-3 is fixed)

§A's cascade predates the fix, so those rows carry NULL and the restore took the unknown-prior branch.

1. Settings → turn the org's **device approval gate ON**.
2. Create a device that stays **`pending`** (never approved) on the source gateway, plus one **`active`**.
3. Revoke the gateway → both cascade. **Assert `revoked_prev_status` is now RECORDED** (`pending` / `active`) —
   the column §A found empty.
4. Restore onto the target.

**PASS:** the pending device comes back **`pending`**, the active one **`active`**. A gateway rebuild must not
grant an approval no human granted.

## B4 — F3's residual, observed rather than assumed

> ### PRECONDITION, ASSERTED AND RECORDED: A1′ IS IN NO HUB SET
>
> A replacement gateway that is a **hub-set member** re-points managed devices through the dial channel, so the
> device self-heals and B4 reads "no badge" — the PASS condition — **for the wrong reason**. The leg would then
> prove nothing in either direction, which is worse than failing.
>
> ```bash
> # [azure-cp] BEFORE the restore. Must return zero rows.
> sudo docker exec tunnex-postgres-1 psql -U tunnex tunnex -c \
>   "SELECT org_id, configured, demoted FROM org_hub_set
>    WHERE '<A1-node-id>' = ANY(configured) OR '<A1-node-id>' = ANY(demoted);"
> ```
>
> **Record the empty result in the walk record.** An unasserted precondition is indistinguishable from a
> forgotten one once the run is over. A freshly enrolled node has no site binding and should not be in
> `configured` — *should* is the reason to check, not the reason to skip.

No §A device isolated it: `contended` was managed but had *both* address and gateway changed, so it fired on the
address cause.

Stage **one managed device whose address is reclaimed** — nothing may take it — so **only its gateway moves**.

**PASS:** it shows **no badge**. That is the documented residual (a managed device re-homed onto a non-hub-set
gateway relies on the dial channel, which only re-points hub-set members). **RECORD it as observed**; a rig whose
target happens to be a hub-set member would show self-healing and be misread as "no residual".

## B5 — Legs 7 and 8, local

Both against the local stack, inside the same 10-minute window.

**Leg 7 — lost response.** Point the agent's `TUNNEX_API_URL` at a proxy that forwards `POST /api/v1/agent/rekey`
and kills the connection **after the CP commits, before the body returns**.

**PASS:** CP logs `node_rekeyed` while the agent logs no `agent_rekeyed`; `rekey-pending-key.pem` exists; **the
same process recovers on its next pass** via `identified_by=key_fingerprint`; node id unchanged; pending file
gone after promotion.

**Leg 8 — save failure after commit.** Make the state dir unwritable *to the agent* (a read-only bind mount of a
file over `key.pem`, or a size-0 tmpfs) with a **valid token present**.

**PASS:** `agent_save_creds_failed`, the agent **does not enrol**, and a later pass recovers the **same node id**
once the write can succeed. **FAILING OBSERVATION:** a new node appears in Gateways — that is the identity being
destroyed by a disk condition.

## B6 — TIMING: the third dimension of uniform refusal

> ### BOUND N, AND DRAIN BEFORE LEG 1
>
> Each sample is **challenge + submit = 2 requests**, and the re-key bucket is **600/min**. Three populations at
> 100 samples each is 600 requests — the bucket **exactly** — and Leg 1's recovery would then be throttled and
> read as a failure that is not one.
>
> **It is one bucket, not several.** The throttle keys on the RAW peer address and is registered above
> `middleware.RealIP`; the CP sits behind nginx, so every request arriving through the proxy — the timing curls
> from azure-cp AND the agent's re-key from aws-gw-2 — is attributed to nginx's address. That is finding #4, and
> it is why this section can starve the next one.
>
> **N = 40 per population** (3 × 40 × 2 = **240** requests, 40% of the budget), paced with a short sleep.
>
> **Then confirm the drain before starting the agent:**
>
> ```bash
> sleep 70    # the window is a fixed minute; let it roll over
> curl -s -o /dev/null -w 'drain check = %{http_code}\n' -X POST localhost/api/v1/agent/rekey/challenge \
>   -H 'content-type: application/json' -d '{"cert_serial":"drain-probe"}'      # MUST be 200, not 429
> ```
>
> **Window order, fixed:** stop → expiry → **B6 timing** → **drain confirmed** → B7 → B2 poller started →
> agent started (Leg 1).

### The measurement

§A proved status code and body length are identical. **Timing was never measured**, and finding #16 conceded the
one asymmetry the ordering cannot remove: **wrong-key is the only refusal that pays for a full RSA
verification**, because it passes the gate. Unknown-identifier and revoked-node refusals do not.

**Measure it rather than asserting the residual is small.**

Three populations, N ≥ 50 each, against the **same** control plane in one sitting:

| population | how to produce it | work done before refusal |
|---|---|---|
| **unknown serial** | a serial no row holds | one indexed lookup |
| **revoked node** | the revoked gateway's real serial | lookup + gate |
| **wrong key** | a **live, expired, key-recorded** node's real serial, real nonce, **wrong signature** | lookup + gate + **RSA verify** |

The third requires a node that *passes* the gate, so **stage it before that node is recovered**.

```bash
# [azure-cp] N timed submits per population; each needs its own fresh nonce
timed() {  # $1=label $2=identifier-json
  for i in $(seq 1 50); do
    N=$(curl -s -X POST localhost/api/v1/agent/rekey/challenge -H 'content-type: application/json' \
        -d "$2" | python3 -c 'import sys,json;print(json.load(sys.stdin)["nonce"])')
    curl -s -o /dev/null -w '%{time_total}\n' -X POST localhost/api/v1/agent/rekey \
      -H 'content-type: application/json' \
      -d "{$3,\"nonce\":\"$N\",\"csr\":\"$CSR\",\"signature\":\"$SIG\",\"agent_version\":\"0\"}"
  done | sort -n | awk -v l="$1" '{a[NR]=$1} END{printf "%-16s n=%d  p50=%.4f  p95=%.4f  max=%.4f\n", l, NR, a[int(NR*0.5)], a[int(NR*0.95)], a[NR]}'
}
```

**Report the three distributions.** Then state the residual **with a number**:

- if wrong-key's p50 sits inside the spread of the other two, the residual is **bounded below measurement noise**
  — say so with the figures;
- if it is separable, say **by how much**, and what an attacker learns: only *"this serial belongs to a real,
  expired, key-recorded node"* — which reaching that path already required.

Either way it is **measured, not asserted** — the same standard §A applied to status and body length.

## B7 — THE THROTTLE. REFRAMED 2026-08-01: an ACCEPTANCE TEST, not a throughput check.

> ### ✅ PRECONDITION SATISFIED 2026-08-01 — the throttle fix LANDED (`7d5f7ca`)
>
> B7 is UNGATED. The agent now rotates its identity on a throttled break (#34) and escalates after five
> consecutive 429s without spending the identity (claims 9/14). **B7's PASS condition 3 is narrowed accordingly:**
> a throttle was already structurally unable to spend the join token, so observing the same node id proves the
> ESCALATION and the rotation, not the absence of a fallback that could never have fired.
>
> **What B7 must now show:** saturate → back off → `agent_rekey_throttled_persistently` appears → both identity
> kinds appear across attempts → recovery completes with the SAME node id.
>
> **(Historical, kept because the gating mattered:)** **B7 MUST NOT RUN UNTIL THE THROTTLE FIX LANDS.** As designed, B7 drives the agent into a permanent 429 — and
> that is a **known-broken branch**: pass-3 claims 9/14 plus #34, still owed. The throttled path `continue`s
> without incrementing `refusals`, so an indefinite 429 is an indefinite stall with no escalation and no
> fallback, and #34's `break` leaves the identity loop at the fingerprint every time. Running B7 before the fix
> would confirm a defect already confirmed by reading the code, and would read as a walk failure rather than a
> known gap.
>
> **AFTER the fix, B7 becomes the acceptance test on real infrastructure**, and the PASS condition is a sequence,
> not a number: **saturate the bucket → the agent backs off → it ESCALATES (loudly, and without spending the
> identity) → and it still RECOVERS, with the same node id.**
>
> **It is not a throughput measurement.** The request counts it records exist to bound finding #4 — how many
> requests one unauthenticated caller needs to deny recovery to every gateway behind the proxy, and for how long.
> Reading B7 as "how fast is the endpoint" would miss its entire subject.

## B7 — the measurement, once the fix has landed

Finding **#4** is registered as a bounded limitation **on a code read alone**: *"in every shipped topology the
peer is the edge proxy, so the throttle is one global bucket and any unauthenticated caller can starve fleet-wide
recovery."* Nothing has ever observed it. This costs one minute and settles it.

**Its own line in the record — not folded into B6.**

```bash
# [azure-cp] deliberately exhaust the shared bucket — 700 challenges, past the 600/min ceiling
for i in $(seq 1 700); do
  curl -s -o /dev/null -w '%{http_code} ' -X POST localhost/api/v1/agent/rekey/challenge \
    -H 'content-type: application/json' -d '{"cert_serial":"saturate"}'
done | tr ' ' '\n' | sort | uniq -c
#   EXPECT: ~600 x 200, then 429s. RECORD the counts.

curl -s -D- -o /dev/null -X POST localhost/api/v1/agent/rekey/challenge \
  -H 'content-type: application/json' -d '{"cert_serial":"saturate"}' | grep -iE '^HTTP|retry-after'
#   RECORD the 429 and its Retry-After.

sudo docker compose logs api --since 2m 2>&1 | grep rekey_throttled | tail -3
#   #13's fix: the 429 must leave a SERVER-SIDE line naming the peer. Before Batch D there was none.
```

> **BLAST RADIUS, stated before it is discovered.** B7's failure mode is not confined to B7. If the agent
> miscounts a 429 as a refusal, three of them exhaust into **token enrolment** — and B′ becomes a NEW node,
> destroying **B1's site binding** and **B2's flip subject** along with it. That is the same event as PASS
> condition 3 failing, seen from the staging side. **Accepted at a 10-minute TTL**: re-staging costs ~30 minutes
> and no 48-hour clock is running. It would NOT be acceptable in §C, which is why B7 lives here and not there.

**Then, with the bucket still exhausted, start B′'s agent.** It arrives through the same proxy, so it is throttled
too — which is the point.

**PASS — three things, and the third is the decisive one:**

1. **`agent_rekey_throttled`, NOT `agent_rekey_refused`.** A refusal means *this will never work*; a 429 means
   *not right now*. Conflating them is what made the agent print the destructive "mint a join token" remedy for a
   rate limit.
2. **The server's `Retry-After` is HONOURED**, not merely printed — `retry_in` in the log matches the header
   (Batch B, claims 9/10/14: the value used to be parsed into an error string and discarded while the agent
   retried on its own floor, so the log and the code stated different intervals).
3. **The agent RECOVERS once the window rolls over, with the SAME node id.** Throttles must not count toward the
   three-refusal exhaustion. B′ has a token in its environment, so if they did count, it would fall back and
   enrol as a **NEW node** — decisive in one field, exactly like the precedence check.

**What this measures for #4:** how many requests one unauthenticated caller needs to deny gateway recovery to
every gateway behind that proxy, and how long the denial lasts. Record both numbers. The limitation stays
registered either way — but registered **with measurements** rather than with an inference.

---

# §C — THE RUNTIME-EXPIRY RUN (reframed 2026-07-31 by WF-S13-6)

> ## §C'S PURPOSE CHANGED. It is no longer a re-proof of the TTL knob.
>
> §C was scoped as *"prove the shortening knob did not change behaviour"* — one subject, natural expiry, Leg 1.
> **That design is WF-S13-6's exact trigger**: an agent left running until its certificate expires underneath it.
>
> So §C becomes **the acceptance test for the remedy, in the shape of the original incident.** It is the only
> section that reproduces what happened to `aws-gw-1` — not a manufactured expiry, but a gateway that was up the
> whole time and whose credential died while it worked.
>
> The knob check rides along (the certificate is issued at the default TTL and must be observed to expire when it
> says it will), but it is no longer why §C exists. **§C does not run until the remedy has landed** — before
> that, its result is known in advance, and a run whose outcome is known proves nothing.

## §C STAGING — RULED 2026-08-01. Subject is aws-gw-1, and B7 moves here.

**SUBJECT: `aws-gw-1` (`019fbb50…`), AFTER §B COMPLETES.** The written plan named `k8s`; `k8s` has
`key_recorded=f`, so proof-of-possession recovery is **structurally impossible** for it and C-LEG-0 would have
failed after 48 hours for a reason unrelated to `identityWatchLoop`. `aws-gw-1` has a recorded key, is free once
§B is done, and is the box whose real expiry opened EPIC 13.

**B7 MOVES FROM §B TO §C.** The throttle fix (`7d5f7ca`) is in the tree but deliberately NOT on the rig, which
runs `c417c85` for §B's same-binary provenance. B7 needs the fix, and §C is the run that carries a rebuilt image.

### §C RUN ORDER — the throttle leg runs FIRST, and the reason is the clock

**B7 BEFORE the expiry leg. Not bolted on after.**

```
rebuild + deploy agent image (fa35e63+)   →  confirm agent healthy, cert VALID
  →  B7: saturate the bucket  →  escalation observed  →  DRAIN CONFIRMED (probe returns 200)
  →  ONLY THEN: leave it alone. The clock starts.
  →  ~48h  →  C-LEG-0: expiry underneath a RUNNING agent, no restart, no operator action
```

**Why this order and not the reverse.** B7 deliberately saturates a shared, deployment-wide bucket. Running it
*after* the clock would land it in the middle of C-LEG-0's window, where a throttled re-key is
indistinguishable from the boot-only failure C-LEG-0 exists to detect — the leg would be unreadable in exactly
the direction that matters. Running it first costs one minute and leaves the 48 hours clean.

**The drain gate is mandatory between them** (`sleep 70`, then a challenge probe returning **200**, not 429).
The clock does not start until that probe passes; otherwise the first hours of C-LEG-0 run against a bucket B7
emptied.

## §C's WINDOW CARRIES OTHER WORK — it is WALL-CLOCK, NOT ATTENTION (founder-ruled 2026-08-01)

**48 hours of waiting is not 48 hours of working.** Everything below is local or CP-side, needs no rig, and
costs zero wall-clock because it runs while the clock ticks:

| item | needs the rig? | status |
|---|---|---|
| **the clock itself** (C-LEG-0) | the subject only, untouched | the point of the window |
| **B5 — Legs 7 and 8** | **no**, entirely local | **MOVED HERE** from §B (founder-ruled) |
| **pass 2** — the cascade path, migrations 0054-0064, all of Slice 7 | no | **founder's ruling when the clock is running**, not before |

### B5 — MOVED INTO THIS WINDOW. Staged here so it is not remembered.

Legs 7 and 8 need a LOCAL stack, an enrolled local agent, a proxy that kills the connection after the CP
commits, and a state directory that refuses a write. **None of it touches the rig, so it cannot disturb §C.**

**Both legs already have reds** — `TestPendingKeyIsPersistedBeforeAnySubmit`,
`TestTheLOSTRESPONSECaseUsesTheFingerprintOnItsNEXTPass` (agent-side, in-process, via the fingerprint identity),
`TestLostResponseDoesNotBrickTheGateway` (CP-side undelivered predicate), and
`TestSaveFailureAfterCommitRETRIESRatherThanLosingTheIdentity` (via the `saveCredsFn` seam). **Those SUBSTITUTE
and do not SATISFY** — what B5 buys that they cannot is the part they fake: a real connection dying mid-response
and a real filesystem refusing a write.

**KNOWN BLOCKER, diagnose before staging:** the local Postgres holds an agent CA encrypted under a different
secret (`decrypt CA key: cipher: message authentication failed` across `nodes` and `agentca` tests). Local
enrolment will fail until that is resolved. **It is a local-environment fault, not a product one** — the same
tests pass in CI.

## §C PREREQUISITES — establish these BEFORE the clock, not on the day

**1. THE RIG NEEDS A REBUILT AGENT IMAGE.** §C proves `identityWatchLoop`, which **does not exist** in the
images on the rig — they are built from `c417c85`. §C needs an agent image carrying **`fa35e63` or later**.
This is the one place the same-binary provenance rule is deliberately broken: §A and §B share `c417c85` so they
are comparable; §C tests code neither of them contains.

**2. THE SUBJECT IS `aws-gw-1` (`019fbb50…`), AFTER §B COMPLETES — via `docker load` on the VM.** Deploy the
rebuilt agent image there and restart the container.

> **CORRECTED 2026-08-01. This prerequisite used to read "THE SUBJECT IS THE `k8s` ROW, via Helm" — it
> contradicted the §C STAGING ruling directly above it, and a fresh session reading top-down would have staged
> the wrong host and burned 48 hours before finding out.** The struck text argued that §B stops, revokes and
> restores both aws-gw rows, so neither can hold a 48-hour clock — true *during* §B, false *after* it, which is
> when §C runs. **`k8s` is DISQUALIFIED: `key_recorded = f`**, so proof-of-possession recovery is structurally
> impossible for it and C-LEG-0 would fail for a reason unrelated to `identityWatchLoop`. Kept rather than
> deleted, because the k3s image-import trap below is real and a future in-cluster run still needs it:
> **an image for the `k8s` row must be imported with `k3s ctr images import`, NOT `docker load`**
> (`docs/infra-inventory.md`). `azure-gw` remains unusable as a second agent host (`wg0` contention).

**3. DELETE THE TTL LINE — DO NOT OVERRIDE IT.**

```bash
# [azure-cp] the knob must be GONE, not shadowed by a second line
grep -n TUNNEX_AGENT_CERT_TTL .env          # note the line number
# DELETE that line. Do NOT append TUNNEX_AGENT_CERT_TTL=48h — a later duplicate wins in some loaders and not
# others, and which one wins is exactly the thing this run must not have to reason about.
grep -c TUNNEX_AGENT_CERT_TTL .env          # MUST print 0
make up-enterprise                           # restart the CP so the removal takes effect
```

**4. CONFIRM THE SHORTENING IS ABSENT FROM THE LOG BEFORE THE CLOCK STARTS.**

```bash
# [azure-cp] the knob logs itself when active. Its ABSENCE is the precondition.
sudo docker compose logs api --since 5m 2>&1 | grep -c agent_cert_ttl_shortened   # MUST print 0
```

**A non-zero count means the clock has not started** — whatever the wall clock says. §C's entire subject is that
the shortening knob did not change behaviour, so a §C run at a shortened TTL proves nothing and cannot be
salvaged after the fact.

## C-LEG-0 — THE ACCEPTANCE LEG. No restart. No operator action.

**This leg exists in no other section, and its absence is why the defect shipped.** §A stopped-then-started the
agent every time, which manufactured a boot with an expired certificate — the one path `attemptRekey` sits on.

**Setup:** a gateway, agent **running**, certificate valid, left alone.

**The falsifying condition — the leg FAILS if any of these is true:**

1. the container is restarted, by anyone or anything, at any point;
2. an operator touches the box after setup;
3. the certificate passes `NotAfter` and **no `agent_rekey_attempt` appears** within one renew interval.

**PASS:** the certificate expires under the running process, the agent attempts recovery **on its own**, recovers
**in place** — same node id, same `site_id`, same devices — and the CP shows a new `cert_not_after` with
`cert_delivered` observed flipping `f` → `t`.

## ⛔ C-LEG-0 AMENDMENT — THE SOCKET STATE IS PART OF THE LEG (added 2026-08-01, WF-S13-9)

**Without this the leg cannot distinguish "the remedy worked" from "the connection dropped and we retested the
boot path §A already covered."**

WF-S13-9 established that an expired client certificate **keeps authenticating for as long as its TCP connection
survives** — `tls.RequireAndVerifyClientCert` enforces `NotAfter` at the HANDSHAKE, and HTTP keep-alive never
re-handshakes. B′ was observed calling `DesiredState` continuously 1h51m after its certificate expired.

So a §C run has two very different shapes, and they are **indistinguishable in the CP's record**:

- **connection SURVIVES the expiry** → the agent experiences no failure at all; a recovery here proves
  `identityWatchLoop` fired on **local inputs**, which is the actual claim under test;
- **connection DROPS** (network blip, CP restart, idle timeout) → the next handshake is refused, and recovery
  proves only the reconnect path — **which §A already covered by stopping and starting the agent.**

**CAPTURE `ss -tnpo` AGAINST `:8443` AT THREE POINTS. All three go in the record.**

```bash
# [gateway] at SETUP (cert valid), at EXPIRY (cert_not_after passed), at RECOVERY (agent_rekeyed)
sudo ss -tnpo | grep :8443
```

**Record the socket's local port at setup and compare it at recovery.** A CHANGED port means the connection was
re-established and the leg is the weaker shape; the SAME port through all three means the transport never broke
and the recovery is attributable to the timer alone.

**A §C run without these three captures is INCONCLUSIVE, not a pass** — the same standing rule as a
session-limited review.

**Record the container's start time and the recovery time in the same table.** A restart between them, from any
cause, voids the leg — that is the entire point of it.

## The original §C scope, retained

## §C.0 — DELETE the TTL line. Do not append an override.

```bash
# [azure-cp]
sed -i '/TUNNEX_AGENT_CERT_TTL/d' .env
grep -c TUNNEX_AGENT_CERT_TTL .env                 # MUST print 0
sudo make up-enterprise
sudo docker compose logs api 2>&1 | grep -c agent_cert_ttl_shortened   # MUST print 0
```

**Why deletion and not an override.** Compose takes the **first** value for a repeated key. A line reading
`TUNNEX_AGENT_CERT_TTL=48h` appended *below* an existing `=10m` leaves **10m winning** — and you discover that ten
minutes into a run you believe is forty-eight hours, having already staged and stopped everything.

**The absence of `agent_cert_ttl_shortened` in the API log is the gate.** Its presence means the run is void
before it starts.

## What this run is actually for

**It proves the shortening knob did not change behaviour.**

`TUNNEX_AGENT_CERT_TTL` is **new code, written during staging, with no review pass and no box-walk of its own**.
Everything §A and §B prove is proven *through* it. If the knob altered anything — issuance, the renewal anchor,
the gate's arithmetic — every earlier result inherits the flaw.

So §C is a **differential**, not a second proof of the epic. One subject, natural expiry, one recovery, compared
against §A's result at 10m.

**It is NOT:** a re-run of the leg sheet · a second F3 proof · a second uniform-refusal matrix. Those were proven
at 10m and the knob is the only thing that could invalidate them — which is exactly what this measures.

## §C.1 — the run

1. **One gateway**, site-bound (carry B1's binding), enrolled on the branch build with the knob **absent**.
2. Record: `cert_not_after` **must be ~48h out**, not ten minutes. That single value is the knob's own proof.
3. Devices staged and **connected** on it, as in §A.
4. **Stop it. Wait out the natural expiry.**
5. Start it → **Leg 1 only**: PoP self-recovery.

**PASS — the differential, item by item:**

| | §A (10m) | §C (48h) — must match |
|---|---|---|
| `agent_rekeyed`, `identified_by=cert_serial` | ✅ | must match |
| node id unchanged | ✅ | must match |
| **`site_id` unchanged** | untested in §A | **B1 covers it; §C confirms at the real TTL** |
| serial + fingerprint moved | ✅ | must match |
| audited succession, both fingerprints | ✅ | must match |
| `cert_delivered` false → true | B2 | must match |
| new `cert_not_after` | +10m | **+48h** |
| zero operator commands | ✅ | must match |

**Anything that differs between §A and §C is a defect in the knob**, and that is the finding this run exists to
produce.

## §C.2 — the ceiling, once, cheaply

```bash
# [azure-cp] the knob must refuse to LENGTHEN — unit-proven, confirmed once on a real deployment
echo 'TUNNEX_AGENT_CERT_TTL=720h' >> .env && sudo make up-enterprise
sudo docker compose logs api 2>&1 | grep agent_cert_ttl_clamped | tail -1   # MUST be present
sed -i '/TUNNEX_AGENT_CERT_TTL/d' .env && sudo make up-enterprise
sudo docker compose logs api 2>&1 | grep -c agent_cert_ttl_shortened        # MUST print 0 again
```

A month must clamp to 48h. Revocation here is refusal-to-renew, so the certificate lifetime **is** the window a
revoked agent keeps working — and no environment may extend it.
