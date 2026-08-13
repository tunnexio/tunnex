# Cross-cloud site-to-site demo — AWS Sydney ↔ Azure West US (founder demo)

**The real thing:** two gateways in two clouds, two different clouds' private subnets, joined by a Tunnex site-to-site tunnel through the existing control plane — a host in AWS's VPC reaches a host in Azure's VNet, under enforcing Zero Trust. **Runs AFTER the S8.3 merge, on `main`.** Pawan at both cloud consoles; I drive leg-by-leg.

## Cast
| role | host | public IP | private | notes |
|---|---|---|---|---|
| **Control plane** | existing box | `40.65.63.141` | — | the CP + web (enterprise); enroll both gateways against its PUBLIC API |
| **Gateway A (hub)** | `tunnex-aws-vm` (AWS, Sydney) | `15.134.231.13` | `172.31.24.206` | VPC `172.31.0.0/16` · **hub** (public UDP endpoint) |
| **Gateway B (spoke)** | `tunnex-azure-vm` (Azure, West US) | `172.184.125.139` | `<AZURE_PRIV_IP>` | VNet `<AZURE_VNET_PREFIX>` — **fill from Pawan's first paste** |

**Hub designation is deliberate:** the hub = the endpoint-bearing gateway (`electSiteHub` picks the one with a public UDP endpoint). We make **Gateway A the hub** by opening UDP 51820 to it and advertising its endpoint; the Azure spoke dials the hub. (If BOTH have public UDP open, the lower node-id wins — so designate ONE on purpose to avoid ambiguity.)

**Architecture note (honesty, LOG-EVERY-STEP):** both agents install on the cloud VMs directly against the CP's PUBLIC API — the SAME enrollment path as any customer gateway (no docker-compose stack cloud-side, just the `tunnex-node` container). **The container→host-LAN routing question applies HERE too:** the VPC/VNet subnet lives behind the host's NIC, NOT inside the container, so the gateway container must route+NAT to the host subnet. Every such command is **docs/S8.5 input** — S8.5 compiles routed ranges → forward rules automatically; today it's manual.

---

## UI-FIRST constraint (founder-directed) + gap protocol
Every step that CAN be done in the dashboard IS — Pawan clicks, screenshots as evidence (S8.3 walk convention). Terminal only where inherent: the agent `docker run` on the cloud VMs (with the exact line surfaced from the UI's join-token screen), the ping/tcpdump proof legs, and the two cloud consoles. **If a step has no UI surface → HALT the leg, log a UI-GAP FINDING (S8.4/S8.5 input), give the workaround (API/CLI), continue.**

### UI-gaps found at scoping (logged)
- **GAP-1 — no in-session org creation for an existing owner** (`/create-org` is `RequireNoOrg`-gated). Workaround: **fresh-account signup** (new email → mailpit verify → create-org). Scripted below.
- **GAP-2 — no site policy-grant in the rule builder** (the Access Add-rule modal is `group/user → group/resource` only; `src_kind=site`/`dst_kind=site` CANNOT be created in the UI). **HALTS the ZT-grant leg → workaround = API.** The headline gap S8.5 / a site-policy UI must close.
- **GAP-3 (minor) — node endpoint not shown in the UI.** The **HUB badge** (Sites card, post-bind) is the admin proxy for "has a public endpoint"; `· policy vN` shows version-readiness. Log, proceed by badge.

## Pre-flight (UI-first where possible — screenshots as evidence; STOP on any surprise)
**Cloud-fabric (each step LOGGED as S8.5/deploy input):**
1. **AWS security group:** allow **UDP 51820** inbound to `15.134.231.13` (from the Azure public IP, or 0.0.0.0/0 for the demo). Allow ICMP for the ping proof.
2. **AWS source/dest check OFF** on the AWS instance ENI (a gateway forwards traffic not addressed to itself — AWS drops it otherwise). Log it.
3. **Azure IP-forwarding ON** on the Azure VM NIC (same reason, Azure side). Log it.
4. **Azure NSG:** allow ICMP + the return path; the spoke dials out so no inbound UDP needed on Azure.
5. Confirm reachability: from Azure `ping -c1 15.134.231.13` (hub public) succeeds.

**Leg 0a — fresh org (UI; GAP-1 workaround).** Sign up a fresh account (new email) → verify via mailpit → **create-org `cross-cloud`**. Screenshot the empty org. (An existing owner has no "new org" button — GAP-1.)

**Leg 0b — join tokens (UI).** Devices page → **Generate join token** ×2 (pin names `gw-aws`, `gw-azure`). The screen shows the **exact enroll command** — copy each. Screenshot.

**Leg 0c — enroll (terminal, inherent — cloud VMs).** On each VM run its copied command against the **public CP** (`40.65.63.141`). NOTE: the UI emits a `docker compose -f tunnex.yml … node-agent` line assuming a compose install; a bare cloud VM running just the `tunnex-node` container needs the token as `TUNNEX_JOIN_TOKEN` env on `docker run` instead — **if the compose line doesn't fit the cloud VM, that's a deploy-shape note (S8.5/deploy input); adapt to `docker run` and LOG it.** Paste each enroll result.

**Leg 0d — verify (UI-first).** Devices page (new org) shows **exactly two** nodes (`gw-aws`, `gw-azure`, no `demo-gw` — the clean-org check, screenshot). Endpoint isn't shown pre-bind (GAP-3) → the hub verification is the **HUB badge on gw-aws on the Sites card AFTER Leg-1 bind** (screenshot). Only if the badge is wrong/ambiguous, fall back to `curl …/nodes | jq '.[]|{name,is_site_hub,endpoint}'` as the workaround (log it).
Pre-flight PASS = both agents enrolled + reporting; **gw-aws takes the HUB badge**, gw-azure does not.

---

## Setup
**Leg 1 — register + bind (UI, Sites page).** Register `site-aws` + `site-azure`; **Bind gateway** gw-aws → site-aws, gw-azure → site-azure. Screenshot. **Hub verify:** gw-aws takes the **HUB** badge (Leg-0d verification lands here).
**Leg 2 — advertise + approve subnets (UI, Sites page + queue).**
- `site-aws`: `172.31.0.0/16` (or `/24` around `172.31.24.206`).
- `site-azure`: `10.0.0.0/24` (**NOTE: contains the CP `10.0.0.4` + the Azure gw `10.0.0.5`** — deliberate).
- **Disjointness (validator being right):** vs the org's device pool — if the pool overlaps `10.0.0.0/24` or `172.31.x`, **Approve fires the typed `subnet_not_disjoint` refusal** (screenshot it — that's a real leg). Renumber the pool (Settings, UI) or scope site-azure to `10.0.0.4/30`, then re-approve. Screenshot approved.
**Leg 3 — gateway container→host routing/NAT (terminal, inherent — LOG EACH as S8.5 input).** On each VM, the gateway container must forward + masquerade to its host subnet (`net.ipv4.ip_forward=1`; masquerade out the host NIC for the peer subnet; route to the host LAN). **No UI surface — every command is S8.5 scope evidence** (S8.5 compiles routed-range → forward rules; today it's manual).

## Proof legs
1. **Routed-but-dropped (ordering — BEFORE the grant; terminal ping):** enforcing, NO grant → from an AWS host `ping <azure-host-in-10.0.0.0/24>` → WG-carried to the hub, **DROPPED** at the forward chain (routing ≠ permission). Capture the hub `default_drop` counter.
2. **Grant → cross-cloud ping. ⚠ GAP-2 HALT: the site policy-grant has NO UI.** The Access Add-rule modal cannot create `src_kind=site → dst_kind=site`. **Log the finding, then workaround via API** (`POST …/policies {src_kind:site, src_site_id:<site-aws>, dst_kind:site, dst_site_id:<site-azure>}`) — the SAME ping now **replies**. **pcap BOTH sides** (tcpdump AWS egress + Azure ingress) — the first cross-CLOUD packet. *(This gap is the demo's loudest S8.5/site-policy-UI input.)*
3. **`site_link_down` live (UI):** stop the hub/spoke link (terminal) → after the staleness window the Sites card flips to **`site_link_down`**/`site_hub_down` (screenshot); restart → clears. Keepalive keeps a healthy idle link warm (S8.3 Slice-0) so the badge means a REAL dead link.
4. **Un-NAT'd invariant (terminal):** site-to-site traffic keeps its real LAN source (masquerade scoped `oifname != wg0`) — the transit accept matches the real VPC/VNet source, not a NAT'd address.
5. **BONUS — AWS reaches the CP privately (`10.0.0.4`):** since `10.0.0.0/24` now routes AWS→tunnel→Azure gateway→its local VNet, `ping 10.0.0.4` from AWS reaches the CP/dev-VM over the site tunnel (the Azure gw forwards to its neighbor). **Route-loop watch:** the CP is reached for CONTROL over its PUBLIC IP (`40.65.63.141`, default route) — the tunnel carries only the DATA-plane `10.0.0.4`; if the hub shows any route-loop for the CP address, SURFACE it, don't improvise.

## Verdict + S8.5 input
- Record: did AWS Sydney reach Azure West US through the tunnel (ping + pcap both sides)? drop-then-grant flipped on exactly the grant? `site_link_down` live?
- **The manual-step list** (SG/source-dest-check/IP-forwarding/container-NAT/routes) IS S8.5's scope evidence — S8.5 automates the routed-range → forward-rule compilation so a customer never runs these by hand.

---
*Fill `<AZURE_PRIV_IP>` + `<AZURE_VNET_PREFIX>` from Pawan's first paste at pre-flight. Screenshots/pcaps → this dir. Runs post-merge on main.*
