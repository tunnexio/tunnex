# §C′ — THE COMPRESSED RIG. **PASS.**

**Ran 2026-08-03 18:02–18:23Z. Twenty-one minutes.** It proves what §C's forty-eight hours could not, and
§C's forty-eight hours prove something this run cannot. **Two runs, two claims, both kept.**

---

## ⛔ WHY §C COULD NOT HAVE WORKED — THE FINDING THAT OPENED THIS

§C waited 48 hours for `aws-gw-1`'s certificate to expire. It never did, and it never could.

`renewLoop` (`apps/node/cmd/agent/main.go:526`) schedules its first tick at **`min(every, left/2)`**, floored at
one minute, and resets to `every` after each success. So while the control plane is reachable, the certificate
is refreshed at **half its remaining life, forever**. §C confirmed `renewEvery 24h < TTL 48h` as an invariant
that *holds* — and that is precisely the invariant guaranteeing the subject never becomes an expired subject.

**Three clean renewals, exactly 24h apart, are the proof it was working as designed:**

```
2026-08-01T08:23:19  agent_cert_renewed
2026-08-02T08:23:19  agent_cert_renewed
2026-08-03T08:23:19  agent_cert_renewed
```

At verification time `cert_not_after` was **2026-08-05 08:23:18** — the certificate had 41 hours left on a run
staged to observe its expiry.

> ## **THE RUN WAS NOT SLOW. IT WAS STRUCTURALLY INCAPABLE OF PRODUCING ITS SUBJECT.**

### The self-invalidating deadline

§C's gate was `cert_not_after + 15 minutes`, computed once at setup and written down as a fixed wall-clock time.
**`cert_not_after` is the field the system under test updates.** Every renewal moved it; the deadline did not
follow. By the time it arrived it referred to a certificate that had been superseded twice.

> **A DEADLINE DERIVED FROM A VALUE THE SUBJECT MUTATES IS NOT A DEADLINE.**

### The general form

> **A TEST THAT WAITS MUST NAME THE EVENT IT IS WAITING FOR AND SHOW THE PATH THAT PRODUCES IT.**
> §C named a *time*, not an event, and no path to the event existed.

### And duration was never the variable

`identityWatchLoop` calls `identity.Decide(st, nodeName, haveToken, time.Now())`, whose expiry test is
`expired := now.After(leaf.NotAfter)` — **a boolean**. `age` is computed only for the log line. There is no
duration threshold anywhere in the verdict, so a certificate expired by one second and one expired by forty-eight
hours are indistinguishable to the code under test. **Elapsed wall-clock is not observable by it; only the state
it produces is.**

The only route to an expired certificate on a *running* agent is **renewal failing** — which is the incident
that opened EPIC 13 ("an AWS gateway went offline past its 48-hour certificate lifetime"). §C's own reasoning
inverted that cause, arguing production reaches expiry *through* renewals rather than through their absence.

---

## THE RIG

| | |
|---|---|
| subject | `aws-gw-1`, node `019fbb50-47c3-7581-a35a-d2825c95a605`, image `tunnex-node-agent:48dd9b0` |
| identity | survives in volume `tunnex_node_state`; `haveToken=true` (**value never recorded — read from the live container at each step, never typed**) |
| M1 | `TUNNEX_AGENT_CERT_TTL=10m` on `azure-cp`, api recreated |
| M2 | agent recreated with `TUNNEX_AGENT_RENEW_INTERVAL=2m`, **staging only**, to pull a short certificate without waiting ~20h for the natural tick |
| M3 | `iptables -I OUTPUT 1 -d 104.45.208.156 -p tcp --dport 8443 -j DROP` — **"offline" as renewal failure, not process death** |

**Blast radius, measured not assumed.** Two nodes were active: the subject and **`k8s`**. `k8s` was a
BYSTANDER — exposed to short certificates while the knob was set, but its next renewal was ~19h away, so it
never renewed inside the window. Proven whole afterwards against its pre-M1 serial (below), not assumed.

### ⚠ M2 destroyed nothing — and the first attempt was halted rather than split

The approved M2 was `docker rm -f` + `docker run`. The permission layer blocked the compound. **It was not
split**: `rm -f` permitted with `run` blocked would have left the subject destroyed and its identity volume
orphaned. **A partial mutation is worse than a halted one.** Re-run as `stop` + `rename` + `run`, which keeps
the original container as a rollback. Both predecessors are still on the box:

```
tunnex-node-preCprime   the original §C container (Exited 0)
tunnex-node-Cprime      the §C′ subject — HOLDS THE RECOVERY LOGS, see Cprime-agent.log
```

---

## THE RUN

| time (Z) | event |
|---|---|
| 18:02:40 | staging boot — `agent_reusing_stored_identity` (**the only boot line in the window**) |
| 18:04:40 | `agent_cert_renewed` → short cert `d8eca770…`, `not_after 18:14:40` |
| 18:05:26 | **M3 applied** — egress to `:8443` dropped |
| 18:07:00 | `agent_renew_failed` — `dial tcp … connect: connection timed out`, `retry_in 15m` |
| **18:14:40** | **certificate expires while the agent runs** |
| **18:17:40** | **`agent_identity_recovery_at_runtime`** — `stored_identity_expired`, *"expired 3m0s ago"* |
| 18:17:41 | `agent_rekeyed` — `identified_by cert_serial d8eca770…` |
| 18:17:41 | **`agent_identity_recovered_in_place`** |
| 18:18:51 | M3 reverted |
| 18:22:36 | `cert_delivered` → `t`; control channel live again on `:8443` |

## ⛔ IT RECOVERED WHILE STILL PARTITIONED — STRONGER EVIDENCE THAN PLANNED

The plan expected the verdict to fire while blocked, the re-key to fail, and success to follow the unblock.
**The re-key succeeded at 18:17:41, with `:8443` still black**, because `attemptRekey` goes to `apiURL`
(port 80, the unauthenticated proof-of-possession endpoint) and the block covered only the mTLS port.

That is the *better* result. The mTLS channel was unreachable for the entire twelve minutes spanning expiry, so
**no network outcome on the control channel could have triggered or assisted the recovery** — which is exactly
what `identityWatchLoop`'s comment claims and what a network-signal-driven design could not claim.

## THE DISCRIMINATOR — boot path vs runtime path

| assertion | baseline (18:02:40) | after recovery | verdict |
|---|---|---|---|
| `RestartCount` | `0` | `0` | ✅ |
| `StartedAt` | `2026-08-03T18:02:40.421848177Z` | identical | ✅ |
| pid | `1272241` | `1272241` | ✅ |
| boot lines after 18:04 | — | none | ✅ |
| CP row | `d8eca770…` | `088e3f2c…`, same node id, `status=active` | ✅ |

### ⚠ THE SOCKET RULE IS DELIBERATELY INVERTED HERE — SAID OUT LOUD SO NOBODY SCORES IT WRONG

§C treated a **socket change as INCONCLUSIVE**: on an idle subject an unexplained reconnect meant the *boot*
path might have done the work. **In §C′ connection loss is the induced condition** — it is the whole mechanism
of "offline" — so a socket change is expected and proves nothing either way.

The boot-vs-runtime discriminator therefore moves to **`RestartCount` / `StartedAt` / pid**, which is what
actually separates the two paths. A reader comparing the two records will see the rule flip; this is why.

---

## REVERTS — EXPLICIT STEPS WITH THEIR OWN VERIFICATION, NOT CLEANUP

**A knob left set on a rig is how the next walk inherits a fixture nobody chose.**

| revert | check 1 — the change | check 2 — **the effect** |
|---|---|---|
| M3 | `iptables -S OUTPUT` → `-P OUTPUT ACCEPT` only | `cert_delivered` → `t`, agent live on `:8443`, **same pid** |
| M1 | `grep -c TUNNEX_AGENT_CERT_TTL .env` → **0**; `agent_cert_ttl_shortened` → **0** | `aws-gw-1` renewed to `e1bc4aeb…`, **`ttl_remaining = 1 day 23:59:39`** |
| M2 | `TUNNEX_AGENT_RENEW_INTERVAL` env → **0** | `agent_renew_scheduled_from_cert cert_expires_in 47h58m first_attempt_in 23h59m` — production shape |

**Both checks were run on every revert.** The file being right does not prove the effect reverted, and this
project keeps finding itself on the wrong side of exactly that pair.

### The bystander, proven whole

```
k8s | active | 7228b5eca33dd5c66e906b4010aeb48f | 2026-08-05 09:32:06 | delivered=t | last_seen 5s ago
```

Serial **identical to the pre-M1 baseline** — it never renewed inside the window, so it was never issued a
short certificate. Live and heartbeating, schedule unchanged.

⚠ **What is NOT claimed:** an *observed* renewal. Its next one is ~19h out. Proven: never short-certed, healthy,
unchanged. Stated rather than rounded up to "renewing normally".

---

## WHAT THIS DOES AND DOES NOT SETTLE

**Settles — merge precondition 1 (WF-S13-6).** A certificate that expired while the agent ran was detected from
local inputs and recovered in place, with no restart and no operator action. That is the defect EPIC 13 opened
for, closed on the wire for the first time.

**Does NOT settle — WF-S13-7, which may outrank it.** The UI's emitted install command pins a published `ghcr`
digest predating S13.1. **A gateway installed by the documented procedure loops forever on expiry no matter
what merges.** This run used a locally-built image — precisely the substitution that hid WF-S13-7 through the
whole of §A. **The mechanism can be perfect and the copy-paste still ship the old one.**

**S13.1 IS NOT MERGEABLE ON THIS RUN ALONE.**
