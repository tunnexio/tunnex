# EPIC 13 walk — CLOCK RECORD

**STATUS: STARTED — REHEARSAL RUN AT `TUNNEX_AGENT_CERT_TTL=10m`. Evidence below is OBSERVED.**
Nothing below the evidence tables has been observed. Do not read a blank row as a pass — the clock has not
started, and until the tables are filled `docs/S13-boxwalk.md` cannot legally run at all.

Branch: `story/S13.1-gateway-recovery` — tip `7c1a127` (the prompt named `120ff0c`; the branch has since advanced
by two DOCS-ONLY commits, `3b40e94` PLAN/memory and `7c1a127` the reviewer brief. No product code differs.)

## Why a clock exists at all

`agentca.CertTTL = 48 * time.Hour` is a **constant** — verified, no environment override, no per-org setting. An
expired agent certificate therefore cannot be manufactured; it can only be waited for. Two facts govern the
staging:

1. **A RUNNING agent never expires.** `renewLoop` renews every 24h (`TUNNEX_AGENT_RENEW_INTERVAL`, default 24h),
   so a live gateway refreshes its certificate at half its lifetime, forever. The agents must be **stopped**, not
   merely idle.
2. **A RESTART DOES NOT RESET `not_after`.** The renew ticker has no immediate first tick, and `identity.Decide`
   takes `UseStored` when the stored certificate is valid — so rebuilding the agent image at this branch and
   restarting **keeps the existing identity and the existing expiry**. Rebuild does not cost a fresh 48 hours;
   only a *re-enrolment* does.

That second point is the difference between waiting ~24h and waiting a full 48h. Prefer restart-in-place unless a
host's identity is unusable.

## The gate

**Earliest legal walk time = the LATEST of the THREE hosts' `cert_not_after`, plus a margin.**

Not "stop time + 48h" — that is the wrong quantity and is always too late. The certificate expires at its own
`not_after`, which was fixed when it was last issued or renewed, possibly long before the stop. A host renewed 20
hours ago expires in 28, not 48.

All THREE hosts must be past their own `not_after` before Legs 1–3 mean anything: Leg 1's subject (A) must be
genuinely unable to authenticate, and so must Leg 2's (B) and Leg 3a's (C). Three subjects, because the refusals
are indistinguishable by construction — a host carrying two conditions proves neither.

---

## Step 1 — PROVENANCE CENSUS, before anything else

**Both halves, per host. The commit alone is half the story.** The S11 walk had four rebuilds silently swap the
OPEN build for the enterprise one; the census verified the sha and not the edition, and the mismatch was visible
only as `go build -tags ""` in a build log nobody was reading. It cost several legs. `docs/laws.md` records this
as *could this check have failed?* — a census that cannot detect the substitution it exists to prevent.

```bash
# [azure-cp] the control plane — must be THIS branch and MUST be enterprise
cd ~/tunnex && git fetch && git checkout story/S13.1-gateway-recovery && git pull
git rev-parse --short HEAD                          # record: CP sha
sudo make up-enterprise && sudo make migrate        # up-enterprise, NOT `compose up --build api`
curl -s localhost/api/v1/meta | grep -o '"edition":"[a-z]*"'   # record: MUST be "enterprise"
sudo docker exec tunnex-postgres-1 psql -U tunnex tunnex -tAc "SELECT version, dirty FROM schema_migrations;"
                                                    # record: MUST be 61 / f
```

```bash
# [each gateway host] the agent image — sha AND edition, per host
sudo docker inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' <agent-image>
sudo docker inspect --format '{{index .Config.Labels "org.opencontainers.image.title"}}'    <agent-image>
# If the image carries no revision label, the sha is UNKNOWN — rebuild from a known tree rather than assuming.
# The agent has no edition tags (open-core gating is control-plane side); record "n/a (agent)" and assert the
# CP's edition instead. Recording "n/a" is the honest entry; leaving the column blank is not.
```

### Evidence — provenance

| host | role | image sha | image edition | CP sha | CP edition | schema version |
|---|---|---|---|---|---|---|
| _(azure-cp)_ | control plane | n/a | n/a | **PENDING** | **PENDING** | **PENDING** |
| _(host A)_ | PoP-recovery subject | **PENDING** | n/a (agent) | — | — | — |
| _(host B)_ | keyless → token fallback subject | **PENDING** | n/a (agent) | — | — | — |
| _(host C)_ | revoked → refused subject | **PENDING** | n/a (agent) | — | — | — |

---

## Step 2 — bring ALL THREE agents up and prove ENROLMENT SUCCEEDED

A running process is not an enrolled agent. The proof is a node row with a certificate, not a container that
started.

```bash
# [each gateway host]
sudo docker logs <agent-container> 2>&1 | grep -E 'agent_enrolled|agent_rekeyed|node_ready|agent_no_usable_identity|agent_unrecoverable'
```

```bash
# [azure-cp] the authoritative check — the CP's own record of each node
sudo docker exec tunnex-postgres-1 psql -U tunnex tunnex -c \
  "SELECT name, status, cert_serial, cert_not_after, last_seen_at,
          cert_public_key IS NOT NULL AS key_recorded,
          left(cert_key_fingerprint,12) AS fp
   FROM nodes WHERE revoked_at IS NULL ORDER BY enrolled_at;"
```

**`key_recorded` must be TRUE for hosts A AND C.** C's refusal must be attributable to its REVOCATION alone; if
its key were also missing, the refusal has two causes and the endpoint answers identically for both.

For host A it is what makes the leg possible at all: proof-of-possession recovery cannot work without it, and
Leg 1 is the leg the epic exists for. (Host B's is deliberately nulled *during* the walk, as declared staging in
Leg 2 — **not now**, or B spends its 48 hours as the wrong subject.)

### Evidence — identity at stop time

| host | node id | cert serial | `cert_not_after` (UTC) | `key_recorded` | fingerprint (12) |
|---|---|---|---|---|---|
| _(host A)_ | **PENDING** | **PENDING** | **PENDING** | **PENDING** | **PENDING** |
| _(host B)_ | **PENDING** | **PENDING** | **PENDING** | **PENDING** | **PENDING** |
| _(host C)_ | **PENDING** | **PENDING** | **PENDING** | **PENDING** | **PENDING** |

---

## Step 3 — STOP all three agents, and prove stopped

```bash
# [each gateway host]
sudo docker stop <agent-container>          # or: sudo systemctl stop tunnex-node
sudo docker ps --filter name=<agent-container>      # must list NOTHING
sudo docker ps -a --filter name=<agent-container> --format '{{.Status}}'   # must read "Exited (…)"
date -u +%FT%TZ                                     # record: stop timestamp
```

Idle is not stopped. An agent that is up but not reconciling still runs `renewLoop`, and a single renew resets
`not_after` and silently costs another 48 hours — discovered, if at all, on walk day.

### Evidence — stop

| host | stopped at (UTC) | `docker ps` empty | exit status |
|---|---|---|---|
| _(host A)_ | **PENDING** | **PENDING** | **PENDING** |
| _(host B)_ | **PENDING** | **PENDING** | **PENDING** |
| _(host C)_ | **PENDING** | **PENDING** | **PENDING** |

---

## Step 4 — the gate

```
EARLIEST LEGAL WALK TIME  =  max(A cert_not_after, B cert_not_after, C cert_not_after) + 15 min margin
```

**PENDING** — cannot be computed until the `cert_not_after` values above are recorded.

Verification on walk day, before Leg 1 (cheap, and the whole walk rests on it):

```bash
sudo docker exec tunnex-postgres-1 psql -U tunnex tunnex -c \
  "SELECT name, cert_not_after, cert_not_after < now() AS expired FROM nodes WHERE revoked_at IS NULL;"
```

**All three subjects must read `expired = t`.** If any reads `f`, the walk **does not start** — that leg would be
exercising a live gateway and would prove nothing about recovery.

---

## The device prerequisites are part of this record, because they cannot be added later

Legs 4/5/6 need devices that were created **and connected** on a gateway while it was live. Once the clock starts
that gateway is stopped, and a device created afterwards has never passed traffic — it can demonstrate that a
badge renders, not that a user was warned.

Per `docs/S13-boxwalk.md`'s staging order, before the stop: three devices on the Leg-4 source gateway
(`keeps`, `contended`, `deliberate`), each **connected with a handshake and non-zero transfer counters**, and
`deliberate` then revoked by an admin so it carries `revoked_cause='deliberate'`.

### Evidence — devices staged before the stop

| device | homed on | assigned_ip | handshake seen | status at stop |
|---|---|---|---|---|
| `keeps` | **PENDING** | **PENDING** | **PENDING** | **PENDING** |
| `contended` | **PENDING** | **PENDING** | **PENDING** | **PENDING** |
| `deliberate` | **PENDING** | **PENDING** | **PENDING** | **PENDING** (must be `revoked` / `deliberate`) |

---

# RUN 1 — REHEARSAL (10-minute TTL). Started 2026-07-31.

> **THIS IS A REHEARSAL.** It exercises the mechanics and the code paths at a shortened certificate lifetime. It
> does NOT exercise the shipped 48-hour behaviour, and a pass here SUBSTITUTES for nothing in the real run. Every
> leg's record must state the TTL it ran under.

## Provenance — OBSERVED

| what | value |
|---|---|
| control-plane binary | **`9f7c56f`** (later commits on the branch are docs-only and do not affect binaries) |
| edition | **enterprise** — `agent_cert_ttl_shortened ttl=10m0s` in the api log |
| schema | **64 / dirty=f** |
| `cert_delivered` DEFAULT | **true** — absence lands CLOSED |
| backfill (0063) | **4 of 4 live nodes = `t`** — condition 2 verified on a real fleet |
| agent artifact | `tunnex-node-agent-9f7c56f.tar.gz`, sha256 **`bae0780def034ca5599ef8c73e88bde282f4a9c06fef68969a7533eacdc05273`** — identical on the CP and on aws-gw-1 |
| loaded image on gateways | `sha256:dd4443ed4df0…` |
| arch | x86_64 on CP and gateways |

**Correction recorded:** the CP's `docker inspect` ID (`737c67a5…`) is a buildx **manifest-list** ID and is NOT
comparable with the loaded single-platform image ID. The artifact hash is the provenance link; loaded IDs compare
gateway-to-gateway only.

## Role assignment — AMENDED from the runsheet

The runsheet specifies three expired subjects on three hosts. The rig has **two usable agent hosts**: `azure-gw`
runs its agent inside k3s (serving the `k8s` node row), so a second host-network agent there would contend for
`wg0`.

**Amendment: A and C are the SAME HOST, sequenced.** The runsheet's reason for three subjects was that B's
refusal (keyless) must not be conflated with C's (revoked) — and that still holds, because B's key stays
unrecorded while C's is recorded throughout.

| role | host | node id |
|---|---|---|
| **A** — PoP recovery (Leg 1) | aws-gw-1 | `019fb18b-ea05-7455-9d3a-b93b0dc1539d` |
| **B** — keyless → token (Leg 2) | aws-gw-2 | `019f8e49-4ca9-7913-945c-25c993f096ea` |
| **C** — revoked → refused (Leg 3a), then Legs 4/5/6 | **aws-gw-1 again**, after Leg 1 recovers it | same row |
| control, untouched | k8s | `019fa205-ab02-76ea-8723-15e1b6028ca4` |

Legs 1 and 3a therefore run against **one node row, sequentially**. A reader must have the ordering to make sense
of "recovered" and "refused" for the same gateway.

## Identity at stop — OBSERVED

| host | node id | cert serial | `cert_not_after` (UTC) | delivered | key recorded | fp |
|---|---|---|---|---|---|---|
| **aws-gw-1** (A/C) | `019fb18b…539d` | `50d033b1189151f13365fff57c8a0c75` | **2026-07-31T14:07:58Z** | t | **t** | `9aac44060b7b` |
| **aws-gw-2** (B) | `019f8e49…96ea` | `7d84d493ca0d9151981dd0c35f446978` | 2026-07-27T06:13:09Z | t | **f** | — |
| azure-gw (unused) | `019f8e46…5e58` | `cb882e06ed84e96fae65556d2f72b20f` | 2026-07-27T06:13:07Z | t | f | — |
| k8s (control) | `019fa205…8ca4` | `a237788ee3b5b79a4e9e9274c29d4695` | 2026-08-02T09:32:06Z | t | f | — |

**aws-gw-1 is the first node in this fleet to carry a recorded public key** — every other row is `f`, which is
the epic's documented coverage limitation observed live at 100% before this run.

## Devices staged on aws-gw-1 — OBSERVED, all CONNECTED

| device | address | mode | `gw_matches` | `ip_matches` | handshake | status at stop |
|---|---|---|---|---|---|---|
| `keeps` | 10.99.0.2 | managed | t | t | ✅ 1.09 KiB rx | active |
| `contended` | 10.99.0.3 | managed | t | t | ✅ 1.09 KiB rx | active |
| `static-keeps` | 10.99.0.5 | **static** | t | t | ✅ 22.43 KiB rx | active |
| `deliberate` | 10.99.0.4 | managed | t | t | — | **revoked / `deliberate`** |

`static-keeps` exists because F3's gateway comparison is **static-only** — the three managed devices cannot
exercise it. Its config carries the baked site routes (`10.0.0.0/16`, `100.64.0.0/16`, `172.31.0.0/16`) and
`DNS = 10.99.0.1`, which a re-home cannot update in a file. It is the sharpest F3 subject: its address is
reclaimed at restore, so the **gateway is the only thing that changes**.

Device private keys were exposed in the working transcript. All four are walk-scratch and **must be deleted when
the run ends**.

## Stop — OBSERVED

| host | stopped at (UTC) | `docker ps` | exit |
|---|---|---|---|
| aws-gw-1 | **2026-07-31T13:58:44Z** | empty ✓ | `Exited (0)` ✓ |
| aws-gw-2 | already down (last seen 2026-07-25) | — | — |

## THE GATE

```
EARLIEST LEGAL WALK = max(aws-gw-1 14:07:58Z, aws-gw-2 2026-07-27) + 2 min margin
                    = 2026-07-31T14:10:00Z
```

Margin shortened from 15 min to 2 for the rehearsal. Both subjects must read `expired = t` before Leg 0.
