# Deploying a Tunnex gateway on a cloud VM (remote gateway)

The dashboard emits the **one true install command** (Devices → Enroll gateway → Generate join token). Paste it on the cloud VM — Docker installed, nothing else. It brings the agent up on real WireGuard with **zero edits** (`--network host`, `wgctrl`, `/dev/net/tun`, the public control-plane URLs, and the token are all baked in). That is the whole gateway-side story — **zero SSH to the gateway after the paste** (the Zero-Touch Gateway Law, `docs/laws.md`).

## The endpoint field (D4a)
At token creation, set **Public endpoint (ip:port)** to the VM's public `ip:51820` if this gateway should be **dialable** (a hub, or any reachable gateway). Leave it blank for a **NAT'd spoke** (it dials the hub; peers can't dial it). The emitted command includes `TUNNEX_NODE_ENDPOINT` iff you set it.

## The ONE unavoidable cloud-console step (Zero-Touch Law boundary clause)
The gateway VM is zero-touch after the paste — but the **cloud fabric** needs one route so a host *behind* the gateway can reach a remote site, and so the gateway can forward. This is un-codeable (it lives in the cloud provider's SDN), so it's a **named, guided visit** — one per side.

### AWS
- **Disable Source/Dest check** on the gateway instance's ENI (a gateway forwards traffic not addressed to itself; AWS drops it otherwise).
- **Route table:** for the subnet whose hosts should reach a remote site (`<REMOTE_CIDR>`), add a route `<REMOTE_CIDR>` → target = the gateway instance/ENI.
- **Security group:** allow **UDP 51820** inbound to a hub's public IP (from the peer side); allow the app traffic you intend (e.g. ICMP for a ping proof).

### Azure
- **Enable IP forwarding** on the gateway VM's NIC (Networking → the NIC → IP forwarding = On).
- **User-Defined Route (UDR):** on the route table attached to the behind-hosts' subnet, add `<REMOTE_CIDR>` → next hop type **Virtual appliance** → the gateway VM's private IP. *(Without this, Azure SDN silently drops a VM's packet whose destination isn't in the VNet — the exact failure the cross-cloud demo hit: `10.0.0.4 → 172.31.x` never reached the gateway.)*
- **NSG:** allow the return/app traffic (intra-VNet is allowed by default).

## What the gateway detects for you
If a gateway advertises a subnet it isn't actually on (bridge-trapped, or the wrong CIDR), the dashboard shows **`site subnet unreachable`** on its card (S8.2c D3) — never a false green. If its site link has no fresh handshake it shows `site link down`; if it advertised routes but the org has no hub, `site hub down`. The gateway is honest about what it can and can't reach.

## Co-located install (advanced)
If the gateway runs on the SAME host as the control plane, use the compose form instead: `docker compose up -d node-agent` in your install folder (the `tunnex.yml` directory). The remote `docker run` above is for a gateway on its own VM.
