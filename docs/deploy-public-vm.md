# Deploy Tunnex to a public VM (single-host quickstart)

One VM runs everything: API, web, nginx, Postgres, Redis, and the `tunnex-node`
WireGuard gateway. A client anywhere on the internet signs in, gets a device
config, and connects over the WireGuard subnet.

> **Split-tunnel only (read this first).** The gateway routes traffic to the
> WireGuard subnet (the pool CIDR, default `10.99.0.0/24`) — clients reach the
> gateway and each other. It does **NOT** yet route all client internet traffic:
> `--full-tunnel` / "route everything through the VPN" needs gateway NAT +
> forwarding, which is **not built** (tracked as **S3.7**). Full-tunnel configs
> will connect but their `0.0.0.0/0` internet egress dies at the gateway.

## Prerequisites

- A public VM (2 vCPU / 2 GB is plenty) with Docker + Docker Compose.
- Its **public IP** (or a DNS name pointing at it).
- Ability to edit the cloud **security group / firewall**.

## 1. Open the ports (cloud security group AND host firewall)

Publishing a port in compose is **not** enough — the cloud provider's security
group is a separate layer.

| Port | Proto | Why |
|---|---|---|
| 80 (and 443 if TLS) | TCP | dashboard + API + CLI login |
| **51820** | **UDP** | **WireGuard data plane — the tunnel itself** |

The WireGuard port is **UDP**, not TCP — a TCP-only rule silently blocks every
tunnel while the dashboard looks fine.

## 2. Configure `.env` (endpoint BEFORE you enroll anything)

```sh
cp .env.example .env
```

Set these before first boot:

```sh
# The address CLIENT CONFIGS DIAL. Must be the VM's PUBLIC ip/host + the WG UDP
# port — NOT the compose service name. This is the #1 reason a tunnel "connects"
# in the dashboard but never hands-shakes: the .conf points at an unreachable host.
TUNNEX_NODE_ENDPOINT=YOUR_PUBLIC_IP:51820

# Public base URL for the dashboard, emailed links, and the CLI. Use https once
# TLS is on (below).
APP_BASE_URL=http://YOUR_PUBLIC_IP

# Real SMTP so verification / reset emails actually send.
# SMTP_HOST=... SMTP_PORT=... SMTP_FROM=... SMTP_USERNAME=... SMTP_PASSWORD=...
```

**Ordering that bites people:** `TUNNEX_NODE_ENDPOINT` is baked into every device
config at creation time. Set it **before** you enroll the gateway and create
devices. If you create a device first and fix the endpoint later, that device's
`.conf` still points at the old (wrong) address — you must revoke and recreate it
(configs are one-time and never re-served).

## 3. Boot

```sh
docker compose up -d --build --wait
```

The node-agent already has `NET_ADMIN` + `/dev/net/tun` and publishes
`51820/udp` in compose — leave that as-is. It idles until you give it a join
token (next step).

## 4. TLS + secure cookies (before real use)

For a throwaway test, `http://` works. For anything real:

- Terminate TLS at nginx (real cert; put the domain in `APP_BASE_URL=https://...`).
- Set `TUNNEX_COOKIE_SECURE=true` so the session cookie is only sent over HTTPS.
  Leaving it `false` on a public host means session cookies can traverse plain
  HTTP — do not ship that.

## 5. Create the org, enroll the gateway, connect

1. Browse to `APP_BASE_URL` → sign up → verify email → create your organization.
2. **Devices → Gateways → Enroll gateway.** Name it, generate the join token.
   The ceremony shows the complete line — if you named the gateway it includes
   `TUNNEX_NODE_NAME`:
   ```sh
   TUNNEX_JOIN_TOKEN=… TUNNEX_NODE_NAME="my-gw"
   ```
3. Give that to the node-agent and restart it (compose plumbs both vars):
   ```sh
   TUNNEX_JOIN_TOKEN=…  TUNNEX_NODE_NAME=my-gw  docker compose up -d node-agent
   ```
   The node appears in the dashboard once the agent redeems the token.
4. Create a device — via the dashboard (download the `.conf`) or the CLI:
   ```sh
   tunnex login --server https://YOUR_HOST     # browser or --device
   tunnex device create --name my-laptop        # writes ~/.config/tunnex/device.conf (0600)
   tunnex up                                     # wg-quick up
   ```
5. Verify: `wg show` has a recent handshake; you can reach the gateway
   (`ping 10.99.0.1`) and other peers on the pool CIDR. The dashboard shows the
   device **online** with a last-handshake time.

## Troubleshooting

- **Dashboard shows the device but no handshake / can't ping:** almost always
  `TUNNEX_NODE_ENDPOINT` (wrong/private address) or **UDP 51820 blocked** in the
  cloud security group.
- **`node_not_ready` when creating a device:** the agent hasn't reported its
  endpoint/key yet — confirm it enrolled (`docker compose logs node-agent`) and
  that `TUNNEX_NODE_ENDPOINT` is set.
- **Login works locally but not from the internet:** `APP_BASE_URL` still points
  at localhost, or (with TLS) `TUNNEX_COOKIE_SECURE` mismatched the scheme.
- **"Everything routes through the VPN" doesn't work:** expected — split-tunnel
  only until S3.7 (gateway NAT + forwarding).

---

## Updating a running deployment

⛔ **THIS SECTION EXISTED NOWHERE UNTIL 2026-08-04.** The install steps above were written; the update
steps were carried in one person's head, on the only live rig. It is written here because it was
run — every command below was executed against `azure-cp` moving `3b1f892` → `6e01b33`, and the
verifications are the ones that actually ran.

### ⛔ FIRST: THE EDITION SELECTOR IS A BUILD ARG AND IT IS NOT IN `.env` BY DEFAULT

`docker-compose.yml` builds the API with `TUNNEX_BUILD_TAGS: ${TUNNEX_BUILD_TAGS:-}` — **empty builds
the OPEN image.** `make up-enterprise` passes it on the command line and does not persist it, so a
host brought up as enterprise has the tag in **shell history, not in configuration.**

> **A plain `docker compose up -d --build` on an enterprise host silently rebuilds it as OPEN.**
> Policy, device posture, MFA enforcement and IdP sync begin returning `403 edition_required`, and
> nothing about the deploy looks like it failed.

**Persist it before the first rebuild:**

```bash
grep -q '^TUNNEX_BUILD_TAGS=' .env || printf 'TUNNEX_BUILD_TAGS=enterprise\n' >> .env
```

### Before you change anything

```bash
cd ~/tunnex
git rev-parse --short HEAD && git rev-parse --abbrev-ref HEAD   # THE ROLLBACK POINT — write it down
cp .env .env.bak-predeploy
curl -sS http://127.0.0.1/api/v1/meta                            # the pre-state you will compare against
sudo docker exec tunnex-postgres-1 psql -U tunnex tunnex -tAc 'SELECT version,dirty FROM schema_migrations;'
```

**Check the migration delta before deciding this is routine.** No delta means the database is not
touched and rollback is free; a delta means rollback is no longer a checkout:

```bash
git ls-tree --name-only origin/main apps/api/db/migrations/ | grep -c up.sql   # compare with HEAD's count
```

Check `ProtocolVersion` on both sides too (`apps/api/internal/policyspec/policyspec.go`). **A bump
refuses enrolled gateways** — the gate is fail-closed by design.

### Update

```bash
git fetch origin main && git checkout -B main origin/main
sudo TUNNEX_BUILD_TAGS=enterprise docker compose up -d --build --wait
```

⚠ **`api`, `web`, `nginx` AND `node-agent` restart. `node-agent` on this host IS A GATEWAY and drops
for the duration of the rebuild** (~30s observed). Gateways on *other* hosts keep their tunnels: the
data plane is independent of the control plane, and a CP outage surfaces as `agent_renew_failed`
plus a retry. `postgres` and `redis` are not rebuilt and do not restart.

⚠ **`.env` is gitignored, so it survives the checkout** — including a digest pin in
`TUNNEX_NODE_AGENT_IMAGE`. **Prove it survived rather than assuming it: the verification below reads
the pin back out of the running API.**

### Verify — all five, and none of them optional

```bash
curl -sS http://127.0.0.1/api/v1/meta
#   "edition"          -> enterprise      the build-arg trap above
#   "node_agent_image" -> the digest you pinned, unchanged
#   "protocol_version" -> unchanged
sudo docker compose ps --format "{{.Service}} {{.Status}}"           # every service healthy
sudo docker exec tunnex-postgres-1 psql -U tunnex tunnex -c \
  "SELECT name,status,cert_serial,now()-last_seen_at AS since_seen FROM nodes WHERE status='active';"
#   serials UNCHANGED and last_seen recent -> enrolled gateways reconnected with their identities
sudo docker exec tunnex-postgres-1 psql -U tunnex tunnex -tAc 'SELECT version,dirty FROM schema_migrations;'
#   unchanged, and dirty MUST be f
```

**Abort condition:** if `edition` is wrong after the rebuild, roll back before doing anything else.
Do not run further work against a downgraded control plane.

### Rollback

Free when there is no migration delta — the database is never touched:

```bash
cd ~/tunnex
git checkout <the branch or sha recorded above>
sudo TUNNEX_BUILD_TAGS=enterprise docker compose up -d --build --wait
```

Then re-run the verification block. **If migrations DID run, this is not a rollback** — reverting the
code leaves the schema ahead of it, and that case needs a down-migration decided in advance.
