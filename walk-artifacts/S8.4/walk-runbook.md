# S8.4 cross-site DNS — box-walk runbook

Topology (reuse the S8.2c cross-cloud pair):
- **AWS hub** — dialable, public IP. Gateway `aws-gw`. Behind-host `aws-behind`.
- **Azure spoke** — NAT'd. Gateway `azure-gw`. Behind-host `azure-behind` — ALSO runs the site resolver.
- Zone under test: `corp.internal` → answered by `azure-behind`'s resolver.

Fill these before starting:
- `<CP_HOST>` — the control-plane box (git checkout).
- `<AWS_GW_WG>` — aws-gw's wg address (from its agent log / `wg show`, e.g. `10.99.0.2`).
- `<AZURE_SUBNET>` = `10.30.0.0/24` (Azure site approved subnet). `<AZURE_BEHIND_IP>` = `10.30.0.10`.
- `<WG_POOL>` = the org pool CIDR (Overview → pool, e.g. `10.99.0.0/24`).

---

## Phase 0 — CP: pull S8.4, rebuild, republish the agent image

On `<CP_HOST>`:

```bash
cd ~/tunnex                     # the git checkout dir
git fetch origin
git checkout story/S8.4-dns
git pull origin story/S8.4-dns

# rebuild + restart the control plane (enterprise edition) + run migrations
TUNNEX_BUILD_TAGS=enterprise docker compose up -d --build migrate api web nginx
docker compose logs --tail=20 migrate     # expect migrate_up_complete

# publish the S8.4 node-agent image so gateways get the forwarder (open data plane, no build tags)
gh auth refresh -s write:packages -h github.com   # once, if the token lacks write:packages
gh auth token | docker login ghcr.io -u iotunnex --password-stdin
docker buildx use tnxbuild 2>/dev/null || docker buildx create --name tnxbuild --use
docker buildx build --platform linux/amd64,linux/arm64 \
  -f deploy/docker/node.Dockerfile \
  -t ghcr.io/iotunnex/tunnex-node-agent:latest --push .

# RECOMMENDED (WF-2): pin the digest so gateways can't cache a stale :latest
DIGEST=$(docker buildx imagetools inspect ghcr.io/iotunnex/tunnex-node-agent:latest \
  --format '{{.Manifest.Digest}}')
echo "agent digest: $DIGEST"
# set it on the CP so the emitted enroll command bakes the digest, then restart api
export TUNNEX_NODE_AGENT_IMAGE="ghcr.io/iotunnex/tunnex-node-agent@$DIGEST"
TUNNEX_BUILD_TAGS=enterprise docker compose up -d api
```

Gate: the dashboard is reachable, edition = enterprise, migrations at latest.

---

## Phase 1 — Gateways: re-pull the new agent (zero-touch re-paste)

The emitted `docker run` uses no `--pull`, so force the new image on EACH gateway VM
(`aws-gw`, `azure-gw`). The `tunnex_node_state` volume is KEPT — same node identity, no re-enroll.

```bash
# on aws-gw AND azure-gw:
docker pull ghcr.io/iotunnex/tunnex-node-agent:latest      # or the @sha256 digest from Phase 0
docker rm -f tunnex-node
# re-paste the SAME dashboard command (Gateways → the gateway → its docker run), unchanged
<PASTE THE EMITTED docker run COMMAND>
docker logs -f tunnex-node        # expect agent_ready + a policy fetch
```

Gate: both gateway cards are green (or honest-degraded), no `site subnet unreachable`.

---

## Phase 2 — Site resolver + DNS forward config

**2a. Azure resolver** — on `azure-behind` (10.30.0.10), serve the zone:

```bash
# a minimal dnsmasq answering corp.internal; binds :53 on the behind-host's LAN IP
docker run -d --name res --network host --cap-add NET_ADMIN entrypoint... \
  # simplest: install dnsmasq and run:
sudo apt-get install -y dnsmasq
sudo tee /etc/dnsmasq.d/corp.conf <<'EOF'
address=/nas.corp.internal/10.30.0.10
address=/corp.internal/10.30.0.10
EOF
sudo systemctl restart dnsmasq
dig @127.0.0.1 nas.corp.internal +short      # expect 10.30.0.10
```

**2b. Declare the forward in the UI** (dashboard → Sites → the Azure site card →
"Cross-site DNS forwarding"):
- domain = `corp.internal`, resolver_ip = `10.30.0.10`.
- Expect: accepted (10.30.0.10 ∈ the site's approved `10.30.0.0/24`).

---

## Phase 3 — AWS behind-host points DNS at its gateway forwarder

Cloud fabric (AWS console, the ONE guided visit — same as S8.2c):
- `aws-gw` ENI: **Source/Dest check = disabled**.
- `aws-behind` subnet route table: add `<AZURE_SUBNET>` → target `aws-gw` ENI (data plane),
  AND `<WG_POOL>` → target `aws-gw` ENI (so aws-behind can reach the gateway's wg address).

On `aws-behind`:
```bash
# point DNS at the AWS gateway's wg-facing forwarder address
sudo resolvectl dns <IFACE> <AWS_GW_WG>       # or: echo "nameserver <AWS_GW_WG>" | sudo tee /etc/resolv.conf
```

---

## The legs (run on the boxes noted; capture output into this dir)

**Leg 1 — cross-site name resolution from a genuinely-separate behind-host.** On `aws-behind`:
```bash
dig @<AWS_GW_WG> nas.corp.internal +short     # EXPECT 10.30.0.10 (relayed over the tunnel)
ping -c3 10.30.0.10                            # data plane: the resolved host is reachable
```
Fixture-fidelity: `aws-behind` is a SEPARATE VM, not the gateway.

**Leg 2 — negative-scope (split-horizon).** On `aws-behind`:
```bash
dig @<AWS_GW_WG> www.google.com               # EXPECT status: REFUSED (out-of-zone, not answered)
```

**Leg 3 — fail-static (DNS-down ≠ tunnel-down).** On `azure-behind`, stop the resolver:
```bash
sudo systemctl stop dnsmasq
```
Then on `aws-behind`:
```bash
dig @<AWS_GW_WG> nas.corp.internal            # EXPECT status: SERVFAIL (honest failure)
ping -c3 10.30.0.10                            # EXPECT still reachable — the TUNNEL survived
```
Restart: `sudo systemctl start dnsmasq` on azure-behind.

**Leg 4 — stopped-gateway → card OFFLINE (VERIFY-0 rider).** Stop `azure-gw`:
```bash
docker stop tunnex-node        # on azure-gw
```
In the dashboard → Sites → the Azure card: within ~90s the gateway shows **OFFLINE** + a
last-seen age. Screenshot. Then `docker start tunnex-node` → card returns to not-offline.

**Leg 5 — bind-scope (no open resolver).** On `aws-gw` host:
```bash
sudo ss -ulpn | grep ':53'     # EXPECT the forwarder bound to <AWS_GW_WG> ONLY, never 0.0.0.0 or the public IP
```
And from OUTSIDE (your laptop): `dig @<aws-gw PUBLIC IP> nas.corp.internal` → must TIME OUT
(not answered on the public interface).

**Leg 6 — config surface (typed refusals + sweep).** In the dashboard, on the Azure site card:
- add domain `corp.internal` again with resolver_ip `10.99.9.9` (outside the subnet) →
  EXPECT the VERBATIM refusal `the resolver 10.99.9.9 must be inside one of this site's approved subnets`.
- add `corp.internal` on a SECOND site → EXPECT `... already forwarded by another site; a domain forwards to one resolver`.
- Advertise-remove the Azure `10.30.0.0/24` subnet → the confirm NAMES `corp.internal` as a
  dependent forward it will also remove. Cancel (don't actually remove) unless proving the sweep.

---

## Walk note (feeds the hub-forwarding VERIFY item)
During the behind-host legs, RECORD any manual `iptables` currently present on `aws-gw`
(`sudo iptables -S FORWARD`). If a manual `-i ens5 -o wg0 -j ACCEPT` (or reverse) is needed for
`aws-behind` to reach the spoke, that is the registered hub forwarding gap — note it, do not fix here.

## Zero-Touch bar
Zero SSH to a gateway for tunnel/networking config after its join paste. Docker image update
(Phase 1) is a deploy action, not gateway config — still, note it; a productized agent
self-update is a separate ledger item, not an S8.4 blocker.
