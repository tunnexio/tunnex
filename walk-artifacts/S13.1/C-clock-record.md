# §C — THE 48-HOUR CLOCK. SELF-CONTAINED RESUME RECORD.

> **A fresh session with no memory of the walk must be able to verify this run FROM THIS FILE ALONE.**
> Everything needed is below: subject, provenance, baseline, the three outcome shapes, and copy-pasteable
> commands. Do not reconstruct any of it from conversation.

**CLOCK STARTED: 2026-08-01 08:38:51Z** (after B7 completed and the drain probe returned 200).

## ⛔ EARLIEST LEGAL VERIFICATION TIME: **2026-08-03 08:38:19 UTC**

`cert_not_after (2026-08-03 08:23:19) + 15 minutes`. **Verifying before this proves nothing** — the certificate
has not lapsed yet, and one renew interval must be allowed to pass after it does.

---

# THE SUBJECT

| field | value |
|---|---|
| host | **`aws-gw-1`** (SSH alias; `15.134.60.253`, private `172.31.1.217`) |
| role | **§C SUBJECT** — the box whose real certificate expiry opened EPIC 13 |
| node id | `019fbb50-47c3-7581-a35a-d2825c95a605` |
| node name | `aws-gw-1` |
| container | `tunnex-node` |

## PROVENANCE — the census, because "it ran" is not "it ran the fix"

| field | value |
|---|---|
| agent image | **`tunnex-node-agent:48dd9b0`** (id `1e71e5be87f4`) |
| built from | git sha **`48dd9b0`**, shipped via `git archive` (tracked files only — the image content IS the sha) |
| **carries `identityWatchLoop`?** | **YES — verified before the build**: `grep -c "func identityWatchLoop"` → `1`. This is `fa35e63`+, i.e. merge precondition #1's code. **§A and §B ran `c417c85`, which does NOT contain it.** |
| agent reported version | `0.1.0` |
| control plane | **enterprise** (`/api/v1/meta` → `"edition":"enterprise"`), schema as deployed 2026-08-01 08:2xZ |

## THE TTL KNOB — DELETED, NOT OVERRIDDEN

| check | result |
|---|---|
| `grep -c TUNNEX_AGENT_CERT_TTL ~/tunnex/.env` on `azure-cp` | **0** (line deleted; backup at `.env.bak-s13c`) |
| `docker compose logs api --since 5m \| grep -c agent_cert_ttl_shortened` | **0** |
| resulting certificate lifetime | **48h, confirmed on the wire**: `ttl_remaining = 1 day 23:59:50` at issuance |

**The knob was DELETED rather than set to `48h`** — a later duplicate wins in some loaders and not others, and which
one wins is exactly what this run must not have to reason about.

## THE RENEWAL INVARIANT — CONFIRMED, NOT CHANGED

| field | value |
|---|---|
| `TUNNEX_AGENT_RENEW_INTERVAL` on A1′ | **NOT SET — the 24h default applies** |
| certificate TTL | 48h |
| invariant `renewEvery < TTL` | **24h < 48h — HOLDS** |

**A1′ deliberately did NOT get the `2m` override that B′ carries.** Overriding it would run a configuration
production does not have — the fixture-fidelity rule WF-S13-10 minted. At 24h the agent renews **roughly twice**
before expiry, and *those successful renewals are what make §C different from §B*: **production reaches expiry
THROUGH renewals, not by sitting idle.**

---

# THE SETUP BASELINE — verification COMPARES against these, it does not assume

## Sockets (`ss -tnpo | grep 8443` on `aws-gw-1`, 08:38:51Z)

```
ESTAB  172.31.1.217:56376 -> 104.45.208.156:8443   pid=579655  fd=6
ESTAB  172.31.1.217:56390 -> 104.45.208.156:8443   pid=579655  fd=9
```

**LOCAL PORTS: `56376` and `56390`. PID: `579655`.**

## Restart baseline (`docker inspect tunnex-node`)

```
RestartCount=0
StartedAt=2026-08-01T08:20:09.727960859Z
Image=tunnex-node-agent:48dd9b0
RestartPolicy=unless-stopped
```

**The policy is `unless-stopped` and is LEFT IN PLACE** — removing it would run a configuration the fleet does
not have. It does not normally fire (the agent never exits on refusal), but **any restart from any cause voids
the leg**, so both values above are recorded to be compared, not assumed.

## Control-plane row at setup

```
name=aws-gw-1  status=active  cert_serial=b8e0e10475ea9e185df2fd6fbba3422a
cert_not_after=2026-08-03 08:23:19.153211+00   cert_delivered=t   site_id=(NULL)   agent_version=0.1.0
```

---

# ⛔ DO NOT TOUCH `aws-gw-1` DURING THE WINDOW

**No restarts. No re-keys. No device placement. No container recreate. No `docker exec` that restarts anything.**
Anything that re-handshakes **resets what is being measured** and converts a PASS into an INCONCLUSIVE.

Reads are fine (`ss`, `docker logs`, `docker inspect`, `psql`) — they do not disturb the connection.

**The agent stays RUNNING for the whole window. That is the point.** It must reach expiry the way production
reaches it: renewals succeeding normally until the certificate lapses — **not a stopped container.**

---

# THE THREE OUTCOME SHAPES — a fresh reader must recognise all three

## ✅ PASS

- **`ss` local ports UNCHANGED across recovery** (`56376` / `56390`, pid `579655`)
- `agent_rekeyed` appears, **same node id** `019fbb50…`
- container uptime shows **no restart** (`RestartCount=0`, `StartedAt` still `2026-08-01T08:20:09`)
- **no operator action anywhere in the window**

## ❌ FAIL

- **no `agent_rekeyed` at all**; the agent sits with an expired certificate past one renew interval
- **WF-S13-6 unremedied. MERGE-BLOCKING.**

## ⚠️ INCONCLUSIVE — AND IT READS LIKE A PASS

- **`ss` local ports CHANGED across recovery**

**The connection dropped and the BOOT path recovered it — which §A already covered by stopping and starting the
agent.** It looks identical to a pass in every other respect: `agent_rekeyed` appears, the node id is the same,
the certificate is renewed.

**WHY IT IS NOT A PASS:** WF-S13-9 established that an expired certificate keeps authenticating for as long as
its TCP connection survives (`tls.RequireAndVerifyClientCert` enforces `NotAfter` at the HANDSHAKE, and
keep-alive never re-handshakes). So if the socket dropped, the recovery proves the **reconnect** path, not
`identityWatchLoop` firing on local inputs — **which is the entire claim under test.**

**A run that lands here MUST BE REPEATED. It is NOT recorded as green.**

---

# VERIFICATION — COPY-PASTEABLE, run at or after 2026-08-03 08:38:19 UTC

```bash
# ── 1. SOCKETS: the decisive check. Compare local ports against 56376 / 56390 and pid 579655.
ssh aws-gw-1 'sudo ss -tnpo | grep 8443'
#    SAME ports + SAME pid  -> the transport never broke; recovery is attributable to the timer  = PASS
#    DIFFERENT ports        -> the connection was re-established                                 = INCONCLUSIVE

# ── 2. NO RESTART: RestartCount must still be 0 and StartedAt must still be 2026-08-01T08:20:09.
ssh aws-gw-1 'sudo docker inspect tunnex-node --format "RestartCount={{.RestartCount}} StartedAt={{.State.StartedAt}} Image={{.Config.Image}}"'

# ── 3. THE RECOVERY ITSELF: agent_rekeyed, same node, no restart line before it.
ssh aws-gw-1 'sudo docker logs --since 2026-08-03T08:00:00Z tunnex-node 2>&1 | grep -v k8s_resolve_begin | tail -30'
#    EXPECT: agent_rekeyed  old_cert_serial=<the serial current at expiry>
#            "recovered by proof of possession — same node, same identity, new key"
#    MUST NOT SEE: agent_stopped / a fresh boot banner before it

# ── 4. CONTROL-PLANE VIEW: same node id, new serial, new not_after, cert_delivered back to t.
ssh azure-cp "sudo docker exec tunnex-postgres-1 psql -U tunnex tunnex -c \"SELECT name,status,cert_serial,cert_not_after,cert_delivered,site_id FROM nodes WHERE id='019fbb50-47c3-7581-a35a-d2825c95a605';\""
#    cert_serial MUST differ from b8e0e10475ea9e185df2fd6fbba3422a
#    node id and name unchanged

# ── 5. THE KNOB IS STILL ABSENT (a re-deploy during the window would silently reinstate it).
ssh azure-cp 'cd ~/tunnex && grep -c TUNNEX_AGENT_CERT_TTL .env'                                  # MUST be 0
ssh azure-cp 'cd ~/tunnex && sudo docker compose logs api --since 48h 2>&1 | grep -c agent_cert_ttl_shortened'  # MUST be 0
```

## ⚠️ THE `site_id` ASSERTION IS VACUOUS ON THIS SUBJECT — do not record it as a pass

**A1′'s `site_id` is NULL and was never bound.** So *"`site_id` unchanged across recovery"* is **trivially true
here and proves nothing** — the same trap §A fell into, where Leg 1 asserted site survival against a node whose
`site_id` was already NULL.

**THE CLAIM IS ALREADY PROVEN ELSEWHERE: §B's B1**, against B′, which was bound to `azure-site`
(`019f8e4b…`) and kept that binding across a recovery. **Cite B1. Do not re-derive it from this run.**

---

# THE MID-WINDOW CHECKPOINT — ~HOUR 25 (2026-08-02 ~09:40Z)

**Why it exists:** at `renewEvery=24h` A1′ renews roughly twice before expiry, and **those successful renewals
are what make §C different from §B.** Production reaches expiry *through* renewals, not by sitting idle.

```bash
# ── renewals must have happened by now
ssh aws-gw-1 'sudo docker logs --since 2026-08-01T08:20:00Z tunnex-node 2>&1 | grep -c agent_cert_renewed'
ssh aws-gw-1 'sudo docker logs --since 2026-08-01T08:20:00Z tunnex-node 2>&1 | grep -E "agent_cert_renewed|agent_renew_scheduled_from_cert" | tail -4'

# ── the certificate should have moved forward
ssh azure-cp "sudo docker exec tunnex-postgres-1 psql -U tunnex tunnex -c \"SELECT cert_serial,cert_not_after,now() FROM nodes WHERE id='019fbb50-47c3-7581-a35a-d2825c95a605';\""

# ── the sockets should be UNCHANGED (56376 / 56390, pid 579655)
ssh aws-gw-1 'sudo ss -tnpo | grep 8443'
```

**IF NO RENEWAL HAS OCCURRED BY HOUR 25:** the run is **already measuring the WF-S13-10 shape** (an agent whose
renewal timer is further away than its certificate's life) **rather than the production path.** **RESTAGE — do
not let it run out.** A §C that reaches expiry without renewing has re-proved §B and burned two days doing it.

---

# B7 — RAN BEFORE THE CLOCK. Result, including what it could NOT show.

**Subject: B′ (`aws-gw-2`, node `019fb892…`), NOT A1′.** A1′ holds a valid 48h certificate by design and will not
attempt a re-key for two days; `k8s` has `key_recorded=f` so proof of possession is structurally impossible for
it. **B′ is the only subject that attempts a re-key under load.** B′ was rebuilt onto `48dd9b0` first — B7 on
pre-fix code drives the known-broken branch and would enter the record as a failure rather than a gap.

## OBSERVED — B7's PASS conditions on this subject

| condition | result |
|---|---|
| saturate → **429 with `Retry-After`** | **YES** — `HTTP/1.1 429`, `Retry-After: 60` |
| the agent treats it as a THROTTLE, not a refusal | **YES** — `agent_rekey_throttled`, *"this is NOT a refusal and says nothing about whether this gateway can recover… the agent cannot tell, and does not claim to"* |
| backoff honoured | **YES** — `retry_in: 1m0s`, next attempt 61s later |
| **BOTH identities tried (#34's rotation)** | **YES** — `identities_tried: 2` on every attempt, and the ORDER visibly rotates: attempts 1-2 tried `key_fingerprint` then `cert_serial`; attempt 4 tried `cert_serial` then `key_fingerprint` |
| escalation rather than an indefinite silent stall (claims 9/14) | **YES** — `consecutive_refusals` climbs 1→2→3 and backoff grows **30s → 1m → 2m**; counters and remedy printed every time |

## NOT OBSERVED, and the reason is structural — NOT a failed leg

**`agent_rekey_throttled_persistently` did not fire.** It requires **5 CONSECUTIVE throttles**
(`rekeyThrottlesBeforeEscalation = 5`), and the counter resets on any non-throttle outcome. **B′ is revoked, so
most of its attempts reach a genuine 403 refusal rather than a 429** — `consecutive_throttles` never got past 1.

**Reaching it needs a NON-REVOKED agent with an expired certificate under sustained saturation — which is A1′ at
expiry, inside §C's window, and deliberately must not be disturbed.** **TRIGGER: the next walk with an expired,
non-revoked, key-recorded gateway available outside a running clock.**

## ⚠️ THE ONE CONDITION (a) CANNOT SHOW — DO NOT READ IT AS A FAILURE

**B′ never recovers, and that is CORRECT.** D3 refuses a revoked node: *expiry authorizes, revocation refuses.*
The agent's own output says so honestly — *"or it was REVOKED, which re-key deliberately cannot undo"* — and
names the right remedy (mint a join token).

**That behaviour was proven at §A Leg 3a. Recovery is OUT OF SCOPE for B7 on this subject, by construction.**
A later reader must not score it as a failed leg.

## The drain gate

`drain probe = 200` at **08:38:42Z**, after the saturator was stopped. **The bucket was clear before the clock
started**, so no part of B7 can be blamed for anything C-LEG-0 observes.

---

# WHAT THIS WINDOW ALSO CARRIES (no rig contact, zero wall-clock cost)

- **B5 — Legs 7 and 8**, entirely local. Staged in `docs/S13-run-plan.md`. **Known blocker:** the local Postgres
  holds an agent CA encrypted under a different secret, so local enrolment fails until that is resolved — a
  local-environment fault, not a product one (the same tests pass in CI).
- **Pass 2** — the cascade path, migrations 0054-0064, and all of Slice 7. **Founder's ruling when the clock is
  running**, not before.
