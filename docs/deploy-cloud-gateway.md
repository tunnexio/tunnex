# Deploying a Tunnex gateway on a cloud VM (remote gateway)

The dashboard emits the **one true install command** (Devices → Enroll gateway → Generate join token). Paste it on the cloud VM — Docker installed, nothing else. It brings the agent up on real WireGuard with **zero edits** (`--network host`, `wgctrl`, `/dev/net/tun`, the public control-plane URLs, NFLOG group, and the token are all baked in). Routine operation requires no interactive gateway edits (the Zero-Touch Gateway Law, `docs/laws.md`).

The emitted `docker run` is not a self-updater. Roll out a new gateway image with
your VM automation, one gateway at a time, using the newly emitted command shape
and preserving the `tunnex_node_state` volume. Capture the current image digest
and container configuration first. A replacement briefly interrupts that
gateway's WireGuard datapath; validate its control heartbeat, collector state,
and policy hash before moving to the next gateway. To disable only access-event
observation, recreate it with `TUNNEX_FLOWLOG_GROUP=0`; this does not change the
allow/drop rules' verdicts.

## The endpoint field (D4a)
At token creation, set **Public endpoint (ip:port)** to the VM's public `ip:51820` if this gateway should be **dialable** (a hub, or any reachable gateway). Leave it blank for a **NAT'd spoke** (it dials the hub; peers can't dial it). The emitted command includes `TUNNEX_NODE_ENDPOINT` iff you set it.

## The ONE unavoidable cloud-console step (Zero-Touch Law boundary clause)
The gateway VM is zero-touch after the paste — but the **cloud fabric** needs one route so a host *behind* the gateway can reach a remote site, and so the gateway can forward. This is un-codeable (it lives in the cloud provider's SDN), so it's a **named, guided visit** — one per side.

### AWS
- **Disable Source/Dest check** on the gateway instance's ENI (a gateway forwards traffic not addressed to itself; AWS drops it otherwise).
- **Route table:** for the subnet whose hosts should reach a remote site (`<REMOTE_CIDR>`), add a route `<REMOTE_CIDR>` → target = the gateway instance/ENI.
- **Security group:** allow **UDP 51820** inbound to a WireGuard hub only from its peers. For AWS IPsec, permit the actual outside peers and required UDP500/4500 (and ESP when applicable). These underlay rules do not admit forwarded application traffic. On the gateway ENI, separately allow each intended application protocol/port from the actual behind-host source IP or approved source CIDR; verify restricted egress toward the intended destination. On the target ENI, allow the same application port from the original customer source, with corresponding restricted source egress. For example, TCP8080 permission does not cover a new TCP8081 resource: add the separately reviewed TCP8081 rule from the intended client /32 rather than opening all ports.
- **Forwarding path:** verify the source subnet route targets the correct gateway ENI, Source/Dest check is disabled there, and the return subnet has the correct VGW/TGW/customer route. Check subnet NACLs in both directions, including required TCP return ephemeral ports, and the host/container forwarding firewall. SGs are stateful; NACLs are stateless. A cloud rule permits delivery to the appliance; an explicit Tunnex grant and current lease still govern application access. For middlebox paths, use actual endpoint IP/CIDR rules; a source SG reference is not a substitute. [AWS middlebox SG guidance](https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html), [AWS middlebox routing](https://docs.aws.amazon.com/vpc/latest/userguide/middlebox-routing-console.html).

If the client stays in SYN-SENT and a bounded gateway capture sees no SYN for that exact source/destination/port, first inspect routes, gateway ENI SG ingress, source egress and NACLs. Independently confirm the target listener through a management path. Do not diagnose MTU or change MSS from this symptom alone: an application SYN must reach the gateway before its IPsec/NFT/MSS handling can be assessed. If the SYN reaches the gateway, correlate its protected-rule counter within the same rule-handle epoch, current Tunnex grant/lease, forwarding firewall and encrypted CHILD counters. Refresh replaces rule counters, so a later zero counter does not prove that the earlier SYN was allowed.

### Azure
- **Enable IP forwarding** on the gateway VM's NIC (Networking → the NIC → IP forwarding = On).
- **User-Defined Route (UDR):** on the route table attached to the behind-hosts' subnet, add `<REMOTE_CIDR>` → next hop type **Virtual appliance** → the gateway VM's private IP. *(Without this, Azure SDN silently drops a VM's packet whose destination isn't in the VNet — the exact failure the cross-cloud demo hit: `10.0.0.4 → 172.31.x` never reached the gateway.)*
- **NSG:** allow the return/app traffic (intra-VNet is allowed by default).

## What the gateway detects for you
If a gateway advertises a subnet it isn't actually on (bridge-trapped, or the wrong CIDR), the dashboard shows **`site subnet unreachable`** on its card (S8.2c D3) — never a false green. If its site link has no fresh handshake it shows `site link down`; if it advertised routes but the org has no hub, `site hub down`. The gateway is honest about what it can and can't reach.

## Co-located install (advanced)
If the gateway runs on the SAME host as the control plane, use the compose form instead: `docker compose up -d node-agent` in your install folder (the `tunnex.yml` directory). The remote `docker run` above is for a gateway on its own VM.
