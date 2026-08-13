# Running infrastructure — reference inventory

The live rig every box-walk runs against. **Recorded 2026-07-31.** Addresses are the founder's; SSH access is
theirs, not the agent's — every command in a runsheet marked `[host]` is run by a human on that host.

Keep this current. A walk that guesses which box plays which role burns a 48-hour clock finding out.

## Hosts

| host | public | private | role |
|---|---|---|---|
| **azure-cp** | `104.45.208.156` | `10.0.0.4` | **control plane** — docker-compose stack (api, web, nginx, postgres, redis). Runs migrations. Never a gateway |
| **azure-gw** | `52.190.140.51` | `10.0.0.5` | **runs k3s.** Its node-agent lives INSIDE the cluster and IS the `k8s` node row (that row's endpoint is `52.190.140.51:51820` — this host's own address). The separate `azure-gw` NODE ROW is a **stale leftover**: `status='active'` in the DB, dead since 2026-07-25, no endpoint ever reported |
| **aws-gw-1** | `15.134.60.253` | `172.31.1.217` | gateway. **The box whose real-world certificate expiry started EPIC 13** |
| **aws-gw-2** | `15.135.130.96` | `172.31.9.62` | gateway |
| **aws-behind-host** | — | `172.31.10.85` | LAN host BEHIND aws-gw. No public address. Exists to prove site transit reaches a machine that is not itself a gateway — not a gateway, never enrolled |

**Cross-cloud:** the AWS boxes and the Azure boxes are in different clouds and different regions, which is what
makes the site-to-site and cross-site DNS walks real rather than a loopback demo (~138ms between them).

## Node rows vs hosts — not one-to-one

The control plane's `nodes` table has carried **four** live rows against **three** gateway VMs, because the
in-cluster Kubernetes gateway (S10.3) is its own node row served by an agent in the k3s cluster, not by a VM's
agent. **Before any walk that stops agents, confirm which host serves which node row** — stopping a VM's agent
does not stop a pod, and vice versa.

```bash
# [azure-cp] the authoritative mapping, always run before assigning walk roles
sudo docker exec tunnex-postgres-1 psql -U tunnex tunnex -c \
  "SELECT name, status, endpoint, last_seen_at, cert_not_after,
          cert_public_key IS NOT NULL AS key_recorded
   FROM nodes WHERE revoked_at IS NULL ORDER BY enrolled_at;"
```

## How the agent runs on a gateway differs by host

Two shapes exist in this fleet and the rebuild command is not the same:

- **compose-managed** (`docker compose up -d node-agent`) — the box has a `~/tunnex` checkout;
- **standalone `docker run`** — the single-line install command the UI emits (S8.2c), with the state directory as
  a named volume.

```bash
# [any gateway] which shape is this box?
sudo docker ps --format '{{.Names}}\t{{.Image}}' | grep -i node
ls -d ~/tunnex 2>/dev/null && echo "compose-managed" || echo "standalone docker run"
```

## azure-gw: one host, one agent, TWO node rows — and only one is real

**Corrected 2026-07-31.** The host `azure-gw` runs **k3s**, and its node-agent runs **inside the cluster**. That
agent is the **`k8s` node row** — confirmed by that row's endpoint, `52.190.140.51:51820`, which is azure-gw's own
public address.

The separate **`azure-gw` node row is STALE**: `status='active'`, last seen 2026-07-25, **no endpoint ever
reported**. Nothing serves it. It is a leftover from a VM-level agent that no longer exists.

### The ambiguity is a WF-S11-10c sighting

EPIC 11's WF-S11-10c was *a surface rendering rows that do not correspond to reality* — health badges on revoked
gateways, a site showing "2 gateways" both dead while the live one was orphaned. **This is the same class:** the
Gateways list shows `azure-gw` **and** `k8s` as two gateways, when there is one host with one agent and one of
those rows has been dead for six days. An operator reading that list cannot tell which is which.

It is also the live evidence under WF-S13-1: that stale row is `active`, so it is a **selectable device target**.

### `wg0` contention — no second host-network agent

The in-cluster agent uses **host networking** and owns `wg0` on azure-gw. A second host-network agent would
contend for the same interface. **azure-gw is not a spare gateway host: one agent slot, and k3s is in it.**

**Found the hard way on 2026-07-31; do not rediscover it.**

Consequences for any walk needing N expired subjects:

- the fleet has **two** usable VM agent hosts (aws-gw-1, aws-gw-2), not three;
- the `k8s` row is a usable subject **only** via `kubectl`/Helm (scale to 0 to stop it, and the image must be
  imported into k3s's containerd with `k3s ctr images import`, not `docker load`);
- where a walk needs more subjects than hosts, **sequence roles on one host** rather than doubling up agents —
  EPIC 13 ran A then C on aws-gw-1, which preserved the reason for separate subjects (B's refusal cause must not
  be conflated with C's) at no cost.

## Walk-role assignment — EPIC 13 (`docs/S13-boxwalk.md`)

The walk needs **three gateways whose certificates have genuinely expired**, and this fleet has **two usable VM
agent hosts** (see the k3s section above). **Corrected 2026-07-31 after the rehearsal** — the original assignment
put C on `azure-gw`, which cannot host a second agent.

**The resolution was to SEQUENCE, not to find a third host.** A and C are the same box in different states, run in
order. That preserves the actual reason the runsheet wanted three subjects — B's refusal (keyless) must never be
conflated with C's (revoked) — because B's key stays unrecorded while C's is recorded throughout.

| walk role | host | why | ends as |
|---|---|---|---|
| **A** — recovers by PoP (Leg 1) | **aws-gw-1** | the box whose real expiry started the epic | recovered, same node id |
| **B** — keyless → token (Leg 2) | **aws-gw-2** | ends as a NEW node, so the destructive outcome sits on the least entangled box | re-enrolled as **B′**, Leg 4's restore target |
| **C** — revoked → refused (Leg 3a), and Legs 4/5/6's devices | **aws-gw-1 again**, after Leg 1 | sequenced; its key is recorded, so its refusal has exactly one cause | revoked |
| control | the **k8s** row | one live node, untouched | unchanged |

**The devices live on C**, which is aws-gw-1 — Leg 4 restores a *revoked* gateway's devices.

**aws-behind-host is not used by the EPIC 13 walk.** It is a site-transit subject, and gateway recovery does not
exercise transit.

## Standing hazards

- **`git pull` reporting "Already up to date" is not proof the rig has the code.** On 2026-07-31 the branch had
  never been pushed; the rig sat 24 commits and five migrations behind, and only the schema-version check caught
  it. **Record the sha AND the schema version, every time.**
- **The edition is half of provenance.** `make up-enterprise`, never `docker compose up -d --build api` — the
  latter silently rebuilds the OPEN image, visible only as `go build -tags ""` in a build log.
- **A running agent renews every 24h and will not expire.** Any walk needing an expired certificate must stop the
  agent, and **idle is not stopped**.
