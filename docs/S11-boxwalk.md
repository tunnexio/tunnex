# EPIC 11 — Production Hardening box-walk (RUNSHEET)

Status: **RUNSHEET** (plan). Executes in a walk session. Walk evidence is committed DURING the session under
`walk-artifacts/S11/`; scratch key material (the deliberately-wrong master key) is gitignored **at creation**.

## What this walk must prove

EPIC 11's acceptance was never a story list — it was *"what breaks when a stranger runs this in production,
unattended, for a month?"* So the legs are the operational events that answer it, and two of them are **owed
debts** the build phase deliberately did not claim:

1. **Trust after restore** (Slice 4, OWED) — restore a control plane from backup and an **existing agent
   connects unchanged**: no re-enrolment, no new certificates. The mechanism is unit-proven; the invariant on
   real hardware is not.
2. **The catastrophic case proven SAFE** (the negative of the above) — restore with the **wrong** master key
   and it refuses loudly, changing nothing. Worth as much as the happy path, because it is the one an operator
   will actually hit.
3. **HA under a roll** (D4, OWED) — roll the CP under load: **tunnels never drop, exactly one leader ticks
   throughout**, and leadership moves observably.
4. **The upgrade procedure end to end, with gateways in the field** — including an **N-1 agent left
   deliberately un-upgraded**, so the compatibility contract is *proven* rather than asserted.
5. **The new surfaces observed live** — `/metrics` serving the health-kind gauge from the real fleet,
   `/readyz` distinguishing leader from follower, and the metrics port **unreachable from outside the host**.

**Evidence, not inference.** Every leg names what to capture. "The agent still works" is inference; *"the
handshake counter advanced across the restore, and the agent's log shows no re-enrolment"* is evidence.

## Two bars that decide pass vs finding

- **ZERO-TOUCH.** The documented procedures are the walk's subject. The only commands you may hand-run are
  **diagnostic** — reading metrics, `wg show`, counters, logs, audit rows. Anything you must hand-run to make a
  *procedure* work (a missing migration step, a manual restart the runbook doesn't mention, an undocumented
  env var) is a **FINDING**: number it and HOLD it. The docs claim these procedures work; the walk is where
  that claim is tested.
- **THE DOCS ARE UNDER TEST TOO.** Follow `docs/self-host.md`, `docs/backup-restore.md` and
  `docs/upgrade.md` *as written*. If a step is wrong, missing, or in the wrong order, that is a documentation
  finding — and the most valuable kind, because a stranger cannot ask us for the missing step.

### STANDING RULE — a witness must prove it was alive across the window it certifies

**A silent witness is indistinguishable from a clean one, and it fails toward "pass."** This walk's Leg 5 first
attempt shows the whole failure in one move: the ping had died nine minutes *before* the roll, and its
`icmp_seq` gap check returned **clean** — a spotless bill of health for a log that did not cover the event. Had
that been accepted, the leg would have recorded "no data-path loss across the roll" on evidence from before the
roll existed.

So, for every leg that certifies continuity, three checks and never fewer:

1. **Before** the leg: confirm the witness is *replying now* (`tail` it and see fresh timestamps).
2. **After** the leg: check its **timestamp bounds against the leg's own start and end** — `head -1` and
   `tail -1` must straddle the window. A witness that stops mid-leg certifies only what it saw.
3. **Then** the continuity check (sequence gaps, timeouts), and grep **the window explicitly** rather than
   trusting an aggregate over the whole file.

This is PROVE-A-GUARD-REJECTS pointed at evidence-gathering instead of at guards: the question is not "did the
check pass" but "could this check have failed?" A gap detector over a dead log cannot fail, so its pass means
nothing. Same standard, applied to the instrument rather than the subject.

---

## Prerequisites — what Pawan needs staged

| # | Requirement | Why |
|---|---|---|
| 1 | **azure-cp up** (docker-compose control plane) and **azure-gw up** (k3s + gateway) | the rig every leg runs against |
| 2 | **At least one gateway connected with a LIVE TUNNEL** — a device actively passing traffic | "tunnels never drop" and "the agent reconnects unchanged" are unobservable without one |
| 3 | **The CORRECT master key**, exported and readable | every restore leg needs it; it is *not* in the backup |
| 4 | **A deliberately WRONG master key** (32 random bytes, base64) | the negative restore leg. **Gitignore it at creation — it is scratch key material** |
| 5 | A **long-running flow** you can watch (e.g. `ping -i 1` or `curl` in a loop from the client through the tunnel) | the drop/no-drop evidence for the roll leg |
| 6 | An **N-1 agent** — one gateway left on the previous agent build | the compatibility contract's proof; see Leg 5 |

Shell vars used below: `CP=http://10.0.0.4` · `ORG=<org-uuid>` · on azure-cp, `cd ~/tunnex`.

---

## Leg 0 — provenance census + surface check

**A stale image reproduces symptoms that look like defects.** Establish what is actually running before
attributing anything to code.

```bash
# [azure-cp]
cd ~/tunnex && git fetch && git checkout story/S11-slice2 && git pull
SHA=$(git rev-parse --short HEAD) && echo "census sha=$SHA"     # expect 299f248 or later
sudo make up-enterprise          # rebuilds the api image from THIS tree
sudo make migrate

# PROVENANCE: the running CP must be this build. Leader election + the metrics listener only exist
# after 35f3a3a — if these lines are absent, the image is stale and every later leg is meaningless.
sudo docker compose logs api 2>&1 | grep -E 'leader_acquired|metrics_listener_start'
```

- **PASS:** both log lines present. `leader_acquired` proves D4 is in the binary; `metrics_listener_start`
  proves D3.2 is.
- **IF ABSENT → STOP.** It is a provenance failure, not a code failure. Rebuild.

### The EDITION is half of provenance, and this runsheet originally omitted it

```bash
# [azure-cp] — anything other than "enterprise" invalidates every policy-related leg
curl -s localhost/api/v1/meta | grep -o '"edition":"[a-z]*"'
```

This is an **open-core** product and much of what the walk exercises is enterprise-gated, so the right sha is
only half the story. `make up-enterprise` sets `TUNNEX_BUILD_TAGS=enterprise`; a plain
`docker compose up -d --build api` **silently rebuilds the OPEN image** — visible in the build log as
`go build -tags ""` and nowhere else.

During this walk exactly that happened, mid-run, and went unnoticed for several legs: the sha was correct, the
provenance lines were present, and nothing was checking the edition. The open build has **no policy engine at
all**, so a gateway legitimately carries no artifact — which briefly looked like a health-reporting defect
(WF-S11-12) rather than an edition difference.

**Re-check the edition after EVERY rebuild, not once at the start.** The edition is a property of the last build,
not of the branch — so any leg that rebuilds the CP must re-assert it, and a leg whose conclusion depends on the
policy engine must state which edition it ran under.

```bash
# The new surfaces, observed (Leg 5 of the acceptance list):
sudo docker compose exec -T api wget -qO- http://127.0.0.1:9090/readyz          # -> "ok leader"
sudo docker compose exec -T api wget -qO- http://127.0.0.1:9090/metrics | grep -c '^tunnex_gateway_policy_health{'   # -> 13
sudo docker compose exec -T api wget -qO- http://127.0.0.1:9090/metrics | grep 'kind="healthy"'                      # -> the REAL fleet count
curl -sS -m 3 -o /dev/null -w 'from-host:9090 = %{http_code}\n' http://10.0.0.4:9090/metrics                         # -> 000 (unreachable)
```

- **PASS:** `ok leader` · **13** series (one per health kind) · a `healthy` count matching your actual gateway
  count · and **`000` from outside** — the loopback default genuinely isolates rather than being documented to.
- **EVIDENCE:** the census sha, both log lines, the 13-series count, the `healthy` value, the `000`.

---

## Leg 1 — the fleet baseline (what "unchanged" will mean)

Capture the state that the restore must preserve. **This is the leg that makes Leg 3 provable** — without it,
"the agent still works" is inference.

```bash
# [azure-gw] the gateway's identity and its live tunnel
GW=$(sudo kubectl -n tunnex-gw get pods -o jsonpath='{.items[0].metadata.name}')
sudo kubectl -n tunnex-gw exec "$GW" -- wg show    # capture: peer public keys, latest handshake, transfer counters
# [azure-cp] the CA the agent PINS, and the agent's certificate serial
sudo docker exec tunnex-postgres-1 psql -U tunnex tunnex -c \
  "SELECT name, cert_serial, enrolled_at FROM nodes WHERE revoked_at IS NULL ORDER BY enrolled_at;"
```

- **CAPTURE:** the gateway's `cert_serial` + `enrolled_at`, and the tunnel's handshake age + transfer counters.
- **START THE WITNESS FLOW** from the client (prereq 5) and leave it running for the rest of the walk:
  `ping -i 1 <a-host-behind-the-gateway> | ts` (or a `curl` loop). Its output is the drop evidence.

---

## Leg 2 — take a backup, per the runbook as written

Follow `docs/backup-restore.md` exactly. Deviations are documentation findings.

```bash
# [azure-cp]
sudo docker compose exec -T postgres pg_dump --format=custom --no-owner -U tunnex tunnex > /tmp/walk.dump
sudo docker compose exec -T api /usr/local/bin/backupctl manifest "S11 walk" > /tmp/walk.manifest.json
cat /tmp/walk.manifest.json          # a fingerprint, a schema version — and NO key material
sudo docker compose exec -T api /usr/local/bin/backupctl verify < /tmp/walk.manifest.json; echo "exit=$?"
```

- **PASS:** the manifest contains a `master_key_fingerprint` and **no key**; `verify` exits **0** naming the
  fingerprint, the timestamp, and the schema version.
- **NOTE:** if `backupctl` is not on the api image's PATH, that is a **FINDING** (the runbook implies it is
  available where the operator runs it) — record it rather than working around it.

---

## Leg 3 — TRUST AFTER RESTORE (owed debt #1, the epic's headline)

Restore over a working deployment and prove the fleet is **untouched**.

```bash
# [azure-cp] restore per docs/backup-restore.md — verify FIRST, then restore.
sudo docker compose exec -T api /usr/local/bin/backupctl verify < /tmp/walk.manifest.json   # must pass
sudo docker compose exec -T postgres pg_restore --clean --if-exists --no-owner -U tunnex -d tunnex < /tmp/walk.dump
sudo docker compose restart api
```

Then prove *unchanged*, with evidence:

```bash
# [azure-cp] the SAME cert serial — the CA was readable, so no re-issuance happened
sudo docker exec tunnex-postgres-1 psql -U tunnex tunnex -c \
  "SELECT name, cert_serial FROM nodes WHERE revoked_at IS NULL;"
# [azure-gw] the agent did NOT re-enroll (no new key, no new cert)
sudo kubectl -n tunnex-gw logs "$GW" --since=10m | grep -iE 'enroll|re-enroll|certificate' | tail -5
sudo kubectl -n tunnex-gw exec "$GW" -- wg show    # handshake CONTINUING, counters ADVANCING from Leg 1
```

- **PASS, all four:**
  1. `cert_serial` **identical** to Leg 1 — the agent CA was read successfully from the restored, sealed data.
  2. The agent's log shows **no enrolment** in the window.
  3. `wg show` transfer counters have **advanced past** Leg 1's values (the tunnel carried traffic across the
     restore) and the handshake is fresh.
  4. **The witness flow shows no interruption** — or an interruption strictly during the API restart, never in
     the data path.
- **EVIDENCE:** both `cert_serial` outputs side by side, the agent log excerpt, before/after `wg show`, the
  witness-flow output across the window.
- **FAILURE:** a changed serial, any re-enrolment, or a data-path gap. Any of those means the trust-after-
  restore invariant does not hold, and Slice 4's acceptance is unmet.

---

## Leg 4 — the CATASTROPHIC case proven SAFE (the negative)

S11-8 hands this over free: the same mismatch that broke `test-editions` four times is the failure an operator
will actually hit.

```bash
# [azure-cp] a deliberately WRONG key — scratch material, gitignore at creation
head -c 32 /dev/urandom | base64 > /tmp/wrong-master.key    # NEVER commit this
# --entrypoint IS REQUIRED. The image's ENTRYPOINT is tunnex-api, so passing the binary as an
# ARGUMENT runs the SERVER with an ignored argv — it boots, migrates, and dies on its own
# wrong-key guard, which looks like a refusal but is a different one. (Walk error, recorded.)
# -i IS ALSO REQUIRED: without it the container's stdin is closed and the manifest never
# arrives (`read manifest: EOF`). The redirect feeds the docker CLIENT, not the container.
sudo docker run --rm -i --network tunnex_default --entrypoint /usr/local/bin/backupctl \
  -v /tmp/wrong-master.key:/wrong.key:ro \
  -e TUNNEX_MASTER_KEY_FILE=/wrong.key -e TUNNEX_SECRETS_DIR=/tmp/s \
  -e DATABASE_URL="postgres://tunnex:tunnex_dev_password@postgres:5432/tunnex?sslmode=disable" \
  tunnex-api verify < /tmp/walk.manifest.json; echo "exit=$?"
```

Note the other legs invoke these tools via `docker compose exec`, which does **not** apply `ENTRYPOINT` — only
this `docker run` needed the override.

- **PASS:** `REFUSING TO RESTORE`, **exit 2**, the message naming **both fingerprints**, the **agent CA**, and
  the word **orphaned**. And critically: **nothing was written** — re-run Leg 3's `cert_serial` query and
  confirm the fleet is still intact.
- **WHY THIS LEG MATTERS AS MUCH AS LEG 3:** a restore that *succeeds* under the wrong key produces a control
  plane that starts, serves, and cannot read its own agent CA — silently orphaning every gateway, discovered
  later, from the fleet, with the backup already written over the evidence.
- **EVIDENCE:** the refusal text, the exit code, and the post-refusal `cert_serial` proving no mutation.

---

## Leg 5 — HA UNDER A ROLL (owed debt #2)

`api` binds host port 8443, so **`docker compose up --scale api=2` cannot work** (port conflict). Use a second
container on the same network without the host binding — a genuine second replica for election purposes,
because it campaigns for the same Postgres advisory lock.

```bash
# [azure-cp] start replica 2 (no host port binding; same DB, same master key volume)
sudo docker run -d --name tunnex-api-2 --network tunnex_default \
  -v tunnex_tunnex_secrets:/var/lib/tunnex/secrets \
  -e DATABASE_URL="postgres://tunnex:tunnex_dev_password@postgres:5432/tunnex?sslmode=disable" \
  -e REDIS_URL="redis://redis:6379" -e TUNNEX_SECRETS_DIR=/var/lib/tunnex/secrets \
  -e TUNNEX_AUTO_MIGRATE=false -e TUNNEX_METRICS_ADDR=127.0.0.1:9090 \
  tunnex-api

# EXACTLY ONE LEADER — ask BOTH replicas, don't infer from one
sudo docker compose exec -T api  wget -qO- http://127.0.0.1:9090/readyz; echo
sudo docker exec tunnex-api-2    wget -qO- http://127.0.0.1:9090/readyz; echo
```

- **PASS:** one reports `ok leader`, the other `ok follower`. **Both are 200** — a follower is ready on purpose.
- Now **roll**, with the witness flow running:

**`restart` CANNOT PROVE THIS AND WILL FALSE-PASS.** A restarted leader is back in under a second and reclaims
the lock ~400 ms after releasing it — long before the follower's 10-second retry tick — so the takeover path is
never exercised. Worse, the criterion "the surviving replica now reports `ok leader`" is *satisfied* by the
restarted leader itself, so a careless reading records a pass for a leg that proved nothing. Observed on the
first attempt; recorded in the walk record.

**STOP the leader and leave it stopped.** Poll in the SAME command block as the stop — a separately-pasted loop
starts after the event.

```bash
sudo docker compose stop api             # (or `docker stop tunnex-api-2` if IT holds the lock)
for i in $(seq 1 15); do
  a=$(sudo docker compose exec -T api wget -qO- -T2 http://127.0.0.1:9090/readyz 2>/dev/null || echo DOWN)
  b=$(sudo docker exec tunnex-api-2  wget -qO- -T2 http://127.0.0.1:9090/readyz 2>/dev/null || echo DOWN)
  printf '%s  api-1=%-12s api-2=%s\n' "$(date -u +%T)" "$a" "$b"; sleep 2
done
sudo docker logs tunnex-api-2 2>&1 | grep -E 'leader_acquired|leader_released'
sudo docker compose start api             # then confirm it comes back as FOLLOWER
```

The returning replica must come back a **follower** — api-2 holds the lock now, and a second acquirer would mean
the lock is not exclusive.

- **PASS, all three:**
  1. Leadership **moved** — the surviving replica now reports `ok leader`, with `leader_acquired` in its log.
  2. **Never two leaders** at any observation — check repeatedly during the window, because a race that
     resolves to two a second later is still two.
  3. **The witness flow never dropped a packet in the data path.** The control plane rolled; tunnels did not
     care.
- **EVIDENCE:** the paired `/readyz` outputs before and after, the `leader_acquired`/`leader_released` lines,
  and the witness-flow output spanning the roll.

```bash
sudo docker rm -f tunnex-api-2    # cleanup
```

---

## Leg 6 — THE UPGRADE PROCEDURE, with gateways in the field

Follow `docs/upgrade.md` as written. **Leave one gateway on the previous agent build** (prereq 6) — the
compatibility contract is proven by an un-upgraded agent still working, not by a passing unit test.

```bash
# [azure-cp] 1. preflight REFUSES until the rollback plan is acknowledged — that refusal is a PASS
sudo docker compose exec -T api /usr/local/bin/preflight; echo "exit=$?"
# 2. acknowledge (a backup exists from Leg 2) and re-run
sudo docker compose exec -T -e TUNNEX_PREFLIGHT_BACKUP_CONFIRMED=yes api /usr/local/bin/preflight; echo "exit=$?"
# 3. migrate  4. roll the CP  5. agents reconcile on their own
sudo make migrate
sudo docker compose up -d --build api
```

- **PASS:**
  1. The first `preflight` **refuses** (exit 1) naming the unconfirmed rollback plan — the refuse-don't-warn
     direction, observed.
  2. The second reports the **agent version window** against the real fleet: every gateway at v6 or newer, and
     it **names any that are not**. If it says `UNKNOWN`, that is honest-unknown working — investigate before
     rolling.
  3. After the roll: **the N-1 gateway is still `healthy`** in `/metrics` and still passing traffic. It receives
     artifacts because `RequiredVersion` is content-derived — this is the N/N-1 contract on the wire.
  4. **No gateway shows `unsupported_policy_version`** unless you deliberately created that condition.
- **EVIDENCE:** both preflight outputs with exit codes, the health-kind gauge before and after the roll, and
  the N-1 gateway's `wg show` + health kind afterwards.

---

## Anti-checklist — every claim proven dead, not assumed

- [ ] Leg 0: provenance sha confirmed **from the running process**, not from the repo.
- [ ] Leg 0: metrics port **`000` from outside the host** — the security default proven, not documented.
- [ ] Leg 3: `cert_serial` **identical** before and after restore, and **no re-enrolment** in the agent log.
- [ ] Leg 3: `wg show` counters **advanced across** the restore (the tunnel carried traffic, not merely existed).
- [ ] Leg 4: wrong key → **exit 2**, and the fleet **verified unmutated afterwards**.
- [ ] Leg 5: **both** replicas queried at **each** observation — one leader, both ready.
- [ ] Leg 5: witness flow shows **no data-path loss** across the roll.
- [ ] Leg 6: first preflight **refused**; the N-1 agent **still healthy** after the roll.
- [ ] The wrong master key is **gitignored**, and no key material is in `walk-artifacts/`.
- [ ] Every WF finding **numbered and HELD** — no mid-walk fixes; a code fix **re-earns** the leg it touched.

## Registered residuals to carry into the walk

- **S11-8** — running the compose stack poisons the next `test-editions` (sealed CA vs test master key). Expect
  it; reset the DB before gating. Leg 4 is this same mechanism, used deliberately.
- **CodeQL autobuild module coverage** — unverified; not a walk leg.
- **Trivy + Scorecard baselines** — captured on the first `main` run after merge, not here.
- **Slice 6's Helm mark** — this walk exercises the **Compose** path. The 🔶 partially-verified mark on Helm
  stands unless a leg installs the chart to managed Kubernetes; if the walk does not, the mark does not change.
